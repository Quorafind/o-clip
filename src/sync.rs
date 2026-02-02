use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
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

/// Run the WebSocket sync loop. This should be spawned on a tokio runtime.
///
/// On each successful connection, immediately sends a `sync_request` to fetch
/// recent history from the server, then enters the normal send/receive loop.
pub async fn run_sync(
    url: String,
    mut outbound_rx: mpsc::UnboundedReceiver<ClipboardEntry>,
    event_tx: std::sync::mpsc::Sender<SyncEvent>,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);

    loop {
        let _ = event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Connecting));
        tracing::info!("connecting to sync server: {url}");

        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws_stream, _)) => {
                let _ = event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Connected));
                tracing::info!("connected to sync server");
                backoff = Duration::from_secs(1);

                let (mut sink, mut stream) = ws_stream.split();

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
                    }
                }
            }
            Err(e) => {
                tracing::warn!("failed to connect to sync server: {e}");
            }
        }

        let _ = event_tx.send(SyncEvent::StatusChanged(ConnectionStatus::Disconnected));
        tracing::info!("reconnecting in {}s...", backoff.as_secs());
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
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
        Ok(ServerMessage::Error { message }) => {
            tracing::warn!("server error: {message}");
        }
        Ok(ServerMessage::Pong) => {}
        Err(e) => {
            tracing::debug!("ignoring unknown ws message: {e}");
        }
    }
}
