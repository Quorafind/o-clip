use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use subtle::ConstantTimeEq;
use tokio::sync::broadcast;

use crate::config::ServerConfig;
use crate::protocol::{ClientMessage, ClipboardEntry, ServerMessage};
use crate::rate_limit::{RateLimitResult, RateLimiter};
use crate::store::Store;

/// Shared application state passed to each WebSocket handler.
pub struct AppState {
    pub store: Store,
    pub rate_limiter: RateLimiter,
    pub broadcast_tx: broadcast::Sender<BroadcastEvent>,
    pub config: ServerConfig,
}

/// An event broadcast to all connected clients.
#[derive(Debug, Clone)]
pub struct BroadcastEvent {
    /// The entry to broadcast.
    pub entry: ClipboardEntry,
    /// The client address that originated this entry (to avoid echo).
    pub origin: String,
}

/// Handle a single WebSocket connection.
pub async fn handle_socket(socket: WebSocket, addr: SocketAddr, state: Arc<AppState>) {
    let client_id = addr.to_string();
    tracing::info!("client connected: {client_id}");

    let (mut sink, mut stream): (SplitSink<WebSocket, Message>, SplitStream<WebSocket>) =
        socket.split();

    // Authentication gate: if server has a password configured, require auth first
    if let Some(ref expected) = state.config.password {
        if !expected.is_empty() {
            let authed = match tokio::time::timeout(Duration::from_secs(5), stream.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(ClientMessage::Auth { password }) => {
                            let pwd_bytes = password.as_bytes();
                            let exp_bytes = expected.as_bytes();
                            // Constant-time comparison to prevent timing attacks
                            pwd_bytes.len() == exp_bytes.len() && pwd_bytes.ct_eq(exp_bytes).into()
                        }
                        _ => false,
                    }
                }
                _ => false,
            };

            if !authed {
                tracing::warn!("auth failed from {client_id}");
                let msg = ServerMessage::AuthResult {
                    success: false,
                    message: "authentication failed".to_string(),
                };
                let _ = send_msg(&mut sink, &msg).await;
                return;
            }

            tracing::info!("auth succeeded for {client_id}");
            let msg = ServerMessage::AuthResult {
                success: true,
                message: "authenticated".to_string(),
            };
            let _ = send_msg(&mut sink, &msg).await;
        }
    }

    let mut broadcast_rx = state.broadcast_tx.subscribe();

    loop {
        tokio::select! {
            // Inbound: messages from this client
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_client_message(
                            &text,
                            &client_id,
                            &state,
                            &mut sink,
                        ).await;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::info!("client disconnected: {client_id}");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = sink.send(Message::Pong(data)).await;
                    }
                    Some(Ok(_)) => {} // binary, pong
                    Some(Err(e)) => {
                        tracing::warn!("ws error from {client_id}: {e}");
                        break;
                    }
                }
            }

            // Outbound: broadcast events from other clients
            Ok(event) = broadcast_rx.recv() => {
                // Don't echo back to the origin client
                if event.origin == client_id {
                    continue;
                }
                let msg = ServerMessage::ClipboardEntry(event.entry);
                if let Ok(json) = serde_json::to_string(&msg) {
                    if sink.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_client_message(
    text: &str,
    client_id: &str,
    state: &Arc<AppState>,
    sink: &mut SplitSink<WebSocket, Message>,
) {
    // Rate limit check on raw payload size
    let rate_result = state.rate_limiter.check(client_id, text.len());
    match rate_result {
        RateLimitResult::Ok => {}
        RateLimitResult::MessageTooLarge { size, max } => {
            let err = ServerMessage::Error {
                message: format!("message too large: {size} bytes (max {max})"),
            };
            let _ = send_msg(sink, &err).await;
            return;
        }
        RateLimitResult::TooManyMessages { count, max } => {
            let err = ServerMessage::Error {
                message: format!("rate limit: {count}/{max} messages in window, slow down"),
            };
            let _ = send_msg(sink, &err).await;
            return;
        }
        RateLimitResult::TooManyBytes { bytes, max } => {
            let err = ServerMessage::Error {
                message: format!("bandwidth limit: {bytes}/{max} bytes in window"),
            };
            let _ = send_msg(sink, &err).await;
            return;
        }
    }

    // Parse the message
    let client_msg: ClientMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!("invalid message from {client_id}: {e}");
            let err = ServerMessage::Error {
                message: format!("invalid message: {e}"),
            };
            let _ = send_msg(sink, &err).await;
            return;
        }
    };

    match client_msg {
        ClientMessage::ClipboardEntry(mut entry) => {
            // Preserve the client-computed hash (pixel-based, format-independent)
            // before overwriting with the server hash.
            let client_hash = std::mem::take(&mut entry.client_hash);

            // Server recomputes hash and byte_size to prevent client-side forgery
            entry.hash = entry.compute_server_hash();
            entry.byte_size = entry.content.len() as i64;

            // Validate entry size against server limit
            if entry.byte_size > state.config.max_entry_bytes as i64 {
                let err = ServerMessage::Error {
                    message: format!(
                        "entry too large: {} bytes (max {})",
                        entry.byte_size, state.config.max_entry_bytes
                    ),
                };
                let _ = send_msg(sink, &err).await;
                return;
            }

            // Store in server DB.
            // ON CONFLICT bumps created_at to the top without creating a duplicate row,
            // so repeated copies of the same content just resurface the existing entry.
            match state.store.insert(&entry, client_id, &client_hash) {
                Ok(true) => {
                    tracing::info!(
                        "stored entry from {client_id}: [{}] {}",
                        entry.content_type,
                        truncate(&entry.preview, 60)
                    );
                }
                Ok(false) => {
                    tracing::debug!("entry already existed (hash conflict) from {client_id}");
                }
                Err(e) => {
                    tracing::warn!("failed to store entry from {client_id}: {e}");
                    let err = ServerMessage::Error {
                        message: "internal storage error".to_string(),
                    };
                    let _ = send_msg(sink, &err).await;
                    return;
                }
            }

            // Enforce server-side storage limit
            let _ = state.store.enforce_limit(state.config.max_entries);

            // Broadcast to other connected clients
            let _ = state.broadcast_tx.send(BroadcastEvent {
                entry,
                origin: client_id.to_string(),
            });
        }

        ClientMessage::SyncRequest { limit } => {
            let capped = limit.min(state.config.max_sync_batch);
            match state.store.recent(capped, state.config.max_sync_batch) {
                Ok(entries) => {
                    let total = entries.len();
                    tracing::info!(
                        "sync_request from {client_id}: sending {total} entries in chunks of {}",
                        state.config.sync_chunk_size
                    );
                    let chunk_size = state.config.sync_chunk_size.max(1);
                    let mut chunks = entries.chunks(chunk_size).peekable();

                    // Handle empty result
                    if total == 0 {
                        let resp = ServerMessage::SyncResponse {
                            entries: vec![],
                            done: true,
                        };
                        let _ = send_msg(sink, &resp).await;
                    } else {
                        while let Some(chunk) = chunks.next() {
                            let is_last = chunks.peek().is_none();
                            let resp = ServerMessage::SyncResponse {
                                entries: chunk.to_vec(),
                                done: is_last,
                            };
                            if send_msg(sink, &resp).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("failed to query recent entries: {e}");
                    let err = ServerMessage::Error {
                        message: "failed to retrieve history".to_string(),
                    };
                    let _ = send_msg(sink, &err).await;
                }
            }
        }

        ClientMessage::Auth { .. } => {
            // Auth after initial handshake is ignored
        }

        ClientMessage::Ping => {
            let _ = send_msg(sink, &ServerMessage::Pong).await;
        }
    }
}

async fn send_msg(
    sink: &mut SplitSink<WebSocket, Message>,
    msg: &ServerMessage,
) -> Result<(), axum::Error> {
    if let Ok(json) = serde_json::to_string(msg) {
        sink.send(Message::Text(json.into())).await.map_err(|e| {
            tracing::warn!("failed to send ws message: {e}");
            e
        })
    } else {
        Ok(())
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..s.floor_char_boundary(max)]
    } else {
        s
    }
}
