use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::Connector;
use tokio_tungstenite::tungstenite::Message;

use crate::store::ClipboardEntry;

/// Messages sent from client to server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ClientMessage {
    /// A new clipboard entry to sync.
    #[serde(rename = "clipboard_entry")]
    ClipboardEntry(ClipboardEntry),

    /// Request recent history from the server on connect.
    #[serde(rename = "sync_request")]
    SyncRequest { limit: usize },

    /// Client authentication with password.
    #[serde(rename = "auth")]
    Auth { password: String },

    /// Keepalive.
    #[serde(rename = "ping")]
    Ping,
}

/// Messages sent from server to client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    /// A clipboard entry broadcast from another client.
    #[serde(rename = "clipboard_entry")]
    ClipboardEntry(ClipboardEntry),

    /// Response to sync_request: batch of recent entries.
    #[serde(rename = "sync_response")]
    SyncResponse { entries: Vec<ClipboardEntry> },

    /// Authentication result.
    #[serde(rename = "auth_result")]
    AuthResult { success: bool, message: String },

    /// Server-side error.
    #[serde(rename = "error")]
    Error { message: String },

    /// Keepalive response.
    #[serde(rename = "pong")]
    Pong,
}

/// Connection status reported back to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
}

/// Events sent from the sync task to the main thread.
pub enum SyncEvent {
    /// A clipboard entry received from the remote server.
    RemoteEntry(ClipboardEntry),
    /// A batch of entries from sync_response.
    SyncBatch(Vec<ClipboardEntry>),
    /// Connection status changed.
    StatusChanged(ConnectionStatus),
}

/// Build a TLS connector for `wss://` URLs.
fn build_tls_connector(accept_invalid_certs: bool) -> Connector {
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if accept_invalid_certs {
        // For self-signed certificates on LAN deployments
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification));
    }

    Connector::Rustls(Arc::new(config))
}

/// Dummy certificate verifier that accepts all certificates.
/// Only used when `accept_invalid_certs` is enabled for LAN/self-signed setups.
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

/// Run the WebSocket sync loop. This should be spawned on a tokio runtime.
///
/// On each successful connection, immediately sends a `sync_request` to fetch
/// recent history from the server, then enters the normal send/receive loop.
pub async fn run_sync(
    url: String,
    accept_invalid_certs: bool,
    password: Option<String>,
    mut outbound_rx: mpsc::UnboundedReceiver<ClipboardEntry>,
    event_tx: std::sync::mpsc::Sender<SyncEvent>,
    reconnect_notify: Arc<Notify>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    // Build the appropriate connector based on URL scheme
    let connector = if url.starts_with("wss://") {
        Some(build_tls_connector(accept_invalid_certs))
    } else {
        None
    };

    loop {
        let _ = event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Connecting));
        tracing::info!("connecting to sync server: {url}");

        let connect_result = match &connector {
            Some(tls) => {
                tokio_tungstenite::connect_async_tls_with_config(
                    &url,
                    None,
                    false,
                    Some(tls.clone()),
                )
                .await
            }
            None => tokio_tungstenite::connect_async(&url).await,
        };

        match connect_result {
            Ok((ws_stream, _)) => {
                tracing::info!("connected to sync server");
                backoff = Duration::from_secs(1);

                let (mut sink, mut stream) = ws_stream.split();

                // Authenticate if password is configured
                if let Some(ref pwd) = password {
                    if !pwd.is_empty() {
                        let auth_msg = ClientMessage::Auth {
                            password: pwd.clone(),
                        };
                        if let Ok(json) = serde_json::to_string(&auth_msg) {
                            if let Err(e) = sink.send(Message::Text(json.into())).await {
                                tracing::warn!("failed to send auth: {e}");
                                let _ = event_tx
                                    .send(SyncEvent::StatusChanged(ConnectionStatus::Disconnected));
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(max_backoff);
                                continue;
                            }
                        }

                        // Wait for auth result
                        match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
                            Ok(Some(Ok(Message::Text(text)))) => {
                                match serde_json::from_str::<ServerMessage>(&text) {
                                    Ok(ServerMessage::AuthResult { success, message }) => {
                                        if !success {
                                            tracing::error!("auth failed: {message}");
                                            let _ = event_tx.send(SyncEvent::StatusChanged(
                                                ConnectionStatus::Disconnected,
                                            ));
                                            tokio::time::sleep(backoff).await;
                                            backoff = (backoff * 2).min(max_backoff);
                                            continue;
                                        }
                                        tracing::info!("auth succeeded");
                                    }
                                    _ => {
                                        tracing::error!("unexpected response during auth");
                                        let _ = event_tx.send(SyncEvent::StatusChanged(
                                            ConnectionStatus::Disconnected,
                                        ));
                                        tokio::time::sleep(backoff).await;
                                        backoff = (backoff * 2).min(max_backoff);
                                        continue;
                                    }
                                }
                            }
                            _ => {
                                tracing::error!("auth timeout or connection error");
                                let _ = event_tx
                                    .send(SyncEvent::StatusChanged(ConnectionStatus::Disconnected));
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(max_backoff);
                                continue;
                            }
                        }
                    }
                }

                let _ = event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Connected));

                // Send initial sync request to get recent history
                let sync_req = ClientMessage::SyncRequest { limit: 200 };
                if let Ok(json) = serde_json::to_string(&sync_req) {
                    if let Err(e) = sink.send(Message::Text(json.into())).await {
                        tracing::warn!("failed to send sync_request: {e}");
                        let _ =
                            event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Disconnected));
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                    tracing::info!("sent sync_request for recent history");
                }

                // Normal send/receive loop
                loop {
                    tokio::select! {
                        // Send outbound entries
                        Some(entry) = outbound_rx.recv() => {
                            let msg = ClientMessage::ClipboardEntry(entry);
                            match serde_json::to_string(&msg) {
                                Ok(json) => {
                                    if let Err(e) = sink.send(Message::Text(json.into())).await {
                                        tracing::warn!("ws send error: {e}");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("failed to serialize sync message: {e}");
                                }
                            }
                        }
                        // Receive inbound messages
                        msg = stream.next() => {
                            match msg {
                                Some(Ok(Message::Text(text))) => {
                                    handle_server_message(&text, &event_tx);
                                }
                                Some(Ok(Message::Close(_))) | None => {
                                    tracing::info!("ws connection closed");
                                    break;
                                }
                                Some(Ok(_)) => {} // binary, ping, pong
                                Some(Err(e)) => {
                                    tracing::warn!("ws receive error: {e}");
                                    break;
                                }
                            }
                        }
                        // Manual reconnect requested
                        _ = reconnect_notify.notified() => {
                            tracing::info!("manual reconnect requested");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("failed to connect to sync server: {e}");
            }
        }

        let _ = event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Disconnected));
        tracing::info!("reconnecting in {}s...", backoff.as_secs());
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {
                backoff = (backoff * 2).min(max_backoff);
            }
            _ = reconnect_notify.notified() => {
                tracing::info!("manual reconnect requested during backoff");
                backoff = Duration::from_secs(1);
            }
        }
    }
}

fn handle_server_message(text: &str, event_tx: &std::sync::mpsc::Sender<SyncEvent>) {
    match serde_json::from_str::<ServerMessage>(text) {
        Ok(ServerMessage::ClipboardEntry(entry)) => {
            let _ = event_tx.send(SyncEvent::RemoteEntry(entry));
        }
        Ok(ServerMessage::SyncResponse { entries }) => {
            tracing::info!("received sync_response with {} entries", entries.len());
            let _ = event_tx.send(SyncEvent::SyncBatch(entries));
        }
        Ok(ServerMessage::AuthResult { .. }) => {
            // Auth result outside handshake phase, ignore
        }
        Ok(ServerMessage::Error { message }) => {
            tracing::warn!("server error: {message}");
        }
        Ok(ServerMessage::Pong) => {}
        Err(e) => {
            tracing::debug!("ignoring unknown ws message: {e}");
        }
    }
}
