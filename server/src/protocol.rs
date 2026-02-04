use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Metadata for a file stored on the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRef {
    /// Server-assigned ID (SHA-256 hash of file content).
    pub file_id: String,
    /// Original filename (basename only).
    pub filename: String,
    /// File size in bytes.
    pub size: u64,
    /// MIME type (best-effort detection).
    pub mime_type: String,
}

/// A clipboard entry exchanged between client and server.
/// This mirrors the client's `ClipboardEntry` but is self-contained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    /// Client-assigned id (0 if from server).
    #[serde(default)]
    pub id: i64,
    pub content_type: String,
    /// Serialized clipboard content (JSON).
    pub content: String,
    /// Short display preview.
    pub preview: String,
    /// SHA-256 content hash for deduplication.
    pub hash: String,
    #[serde(default)]
    pub byte_size: i64,
    #[serde(default)]
    pub synced: bool,
    pub created_at: DateTime<Utc>,
    /// Client-computed content hash (pixel-based for images, format-independent).
    /// Used by the server for cross-format dedup alongside the server-computed hash.
    #[serde(default)]
    pub client_hash: String,
}

impl ClipboardEntry {
    /// Recompute the content hash server-side from `content_type` + `content`.
    ///
    /// This ensures dedup works even if the client sends a wrong or forged hash.
    /// The hash is deterministic: same (content_type, content) always yields the
    /// same hash, matching the client's algorithm for text/url/files/image.
    pub fn compute_server_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.content_type.as_bytes());
        hasher.update(b":");
        hasher.update(self.content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Messages sent from client to server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ClientMessage {
    /// A new clipboard entry from the client.
    #[serde(rename = "clipboard_entry")]
    ClipboardEntry(ClipboardEntry),

    /// Client requests recent history on connect.
    /// Contains the number of entries desired (capped server-side).
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum ServerMessage {
    /// A clipboard entry broadcast to other clients.
    #[serde(rename = "clipboard_entry")]
    ClipboardEntry(ClipboardEntry),

    /// Response to sync_request: a batch of recent entries.
    /// When `done` is true, this is the last chunk of the sync.
    #[serde(rename = "sync_response")]
    SyncResponse {
        entries: Vec<ClipboardEntry>,
        #[serde(default)]
        done: bool,
    },

    /// Authentication result.
    #[serde(rename = "auth_result")]
    AuthResult { success: bool, message: String },

    /// Server-side error / rate limit notification.
    #[serde(rename = "error")]
    Error { message: String },

    /// Keepalive response.
    #[serde(rename = "pong")]
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(content_type: &str, content: &str) -> ClipboardEntry {
        ClipboardEntry {
            id: 0,
            content_type: content_type.to_string(),
            content: content.to_string(),
            preview: content.chars().take(20).collect(),
            hash: String::new(),
            byte_size: content.len() as i64,
            synced: false,
            created_at: Utc::now(),
            client_hash: String::new(),
        }
    }

    #[test]
    fn hash_is_deterministic() {
        let e1 = make_entry("text", "hello world");
        let e2 = make_entry("text", "hello world");
        assert_eq!(e1.compute_server_hash(), e2.compute_server_hash());
    }

    #[test]
    fn hash_differs_for_different_content() {
        let e1 = make_entry("text", "hello");
        let e2 = make_entry("text", "world");
        assert_ne!(e1.compute_server_hash(), e2.compute_server_hash());
    }

    #[test]
    fn hash_differs_for_different_content_type() {
        let e1 = make_entry("text", "hello");
        let e2 = make_entry("url", "hello");
        assert_ne!(e1.compute_server_hash(), e2.compute_server_hash());
    }

    #[test]
    fn hash_is_hex_sha256() {
        let entry = make_entry("text", "test");
        let hash = entry.compute_server_hash();
        // SHA-256 hex is 64 characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn client_message_serialization_roundtrip() {
        let entry = make_entry("text", "clipboard data");
        let msg = ClientMessage::ClipboardEntry(entry);
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::ClipboardEntry(e) => {
                assert_eq!(e.content, "clipboard data");
                assert_eq!(e.content_type, "text");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn sync_request_serialization() {
        let msg = ClientMessage::SyncRequest { limit: 50 };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("sync_request"));
        let parsed: ClientMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            ClientMessage::SyncRequest { limit } => assert_eq!(limit, 50),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_error_serialization() {
        let msg = ServerMessage::Error {
            message: "rate limit exceeded".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("rate limit exceeded"));
    }

    #[test]
    fn ping_pong_serialization() {
        let ping_json = serde_json::to_string(&ClientMessage::Ping).unwrap();
        assert!(ping_json.contains("ping"));
        let pong_json = serde_json::to_string(&ServerMessage::Pong).unwrap();
        assert!(pong_json.contains("pong"));
    }
}
