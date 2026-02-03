use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use o_clip_server::config::ServerConfig;
use o_clip_server::protocol::{ClientMessage, ClipboardEntry, ServerMessage};
use o_clip_server::rate_limit::{RateLimitConfig, RateLimiter};
use o_clip_server::store::Store;
use o_clip_server::ws::{AppState, handle_socket};

/// Spin up a real axum+WebSocket server on a random port.
async fn start_test_server(config: ServerConfig, rate_config: RateLimitConfig) -> SocketAddr {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let store = Store::open(&db_path).unwrap();
    let (broadcast_tx, _) = broadcast::channel(256);
    let rate_limiter = RateLimiter::new(rate_config);

    let state = Arc::new(AppState {
        store,
        rate_limiter,
        broadcast_tx,
        config,
    });

    async fn ws_handler(
        ws: WebSocketUpgrade,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        State(state): State<Arc<AppState>>,
    ) -> impl IntoResponse {
        ws.on_upgrade(move |socket| handle_socket(socket, addr, state))
    }

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Keep temp dir alive by leaking it (tests are short-lived)
    std::mem::forget(dir);

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

fn default_test_config() -> ServerConfig {
    ServerConfig {
        max_entries: 1000,
        max_entry_bytes: 1024 * 1024,
        max_sync_batch: 50,
        sync_chunk_size: 200, // large chunk so existing tests get a single response
        ..Default::default()
    }
}

fn default_rate_config() -> RateLimitConfig {
    RateLimitConfig {
        max_messages_per_window: 60,
        max_bytes_per_window: 10 * 1024 * 1024,
        max_message_size: 1024 * 1024,
        window_duration: Duration::from_secs(60),
    }
}

fn make_entry(content: &str) -> ClipboardEntry {
    let mut entry = ClipboardEntry {
        id: 0,
        content_type: "text".to_string(),
        content: content.to_string(),
        preview: content.chars().take(30).collect(),
        hash: String::new(),
        byte_size: content.len() as i64,
        synced: false,
        created_at: Utc::now(),
        client_hash: String::new(),
    };
    entry.hash = entry.compute_server_hash();
    entry
}

async fn connect(
    addr: SocketAddr,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{addr}/ws");
    let (ws, _) = connect_async(&url).await.expect("failed to connect");
    ws
}

fn text_msg(s: String) -> Message {
    Message::Text(s.into())
}

fn entry_msg(entry: &ClipboardEntry) -> Message {
    text_msg(serde_json::to_string(&ClientMessage::ClipboardEntry(entry.clone())).unwrap())
}

fn sync_msg(limit: usize) -> Message {
    text_msg(serde_json::to_string(&ClientMessage::SyncRequest { limit }).unwrap())
}

fn ping_msg() -> Message {
    text_msg(serde_json::to_string(&ClientMessage::Ping).unwrap())
}

fn parse_server_msg(text: &str) -> ServerMessage {
    serde_json::from_str(text).unwrap()
}

/// Read the next text message from the WS stream, with a timeout.
async fn recv_text<S>(ws: &mut S) -> String
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let msg = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("timeout waiting for ws message")
        .unwrap()
        .unwrap();
    match msg {
        Message::Text(t) => t.to_string(),
        other => panic!("expected Text message, got {:?}", other),
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn single_entry_stored_and_synced() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    let entry = make_entry("hello from test");
    ws.send(entry_msg(&entry)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    ws.send(sync_msg(10)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].content, "hello from test");
            assert_eq!(entries[0].content_type, "text");
            assert!(entries[0].synced);
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn sync_response_is_chunked() {
    let config = ServerConfig {
        max_entries: 1000,
        max_entry_bytes: 1024 * 1024,
        max_sync_batch: 50,
        sync_chunk_size: 3, // small chunks for testing
        ..Default::default()
    };
    let addr = start_test_server(config, default_rate_config()).await;
    let mut ws = connect(addr).await;

    // Insert 7 entries
    for i in 0..7 {
        let entry = make_entry(&format!("chunk_entry_{i}"));
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    ws.send(sync_msg(100)).await.unwrap();

    // Should receive 3 chunks: [3, 3, 1] with done=false, false, true
    let mut all_entries = Vec::new();
    let mut chunk_count = 0;
    loop {
        let text = recv_text(&mut ws).await;
        match parse_server_msg(&text) {
            ServerMessage::SyncResponse { entries, done } => {
                chunk_count += 1;
                all_entries.extend(entries);
                if done {
                    break;
                }
            }
            other => panic!("expected SyncResponse, got {:?}", other),
        }
    }

    assert_eq!(
        all_entries.len(),
        7,
        "all 7 entries should arrive across chunks"
    );
    assert!(
        chunk_count >= 2,
        "should have multiple chunks, got {chunk_count}"
    );
}

#[tokio::test]
async fn dedup_prevents_duplicate_storage() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    let entry = make_entry("duplicate content");
    for _ in 0..5 {
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    ws.send(sync_msg(100)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(
                entries.len(),
                1,
                "dedup should collapse 5 identical sends to 1"
            );
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn multiple_unique_entries_all_stored() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    for i in 0..10 {
        let entry = make_entry(&format!("unique entry {i}"));
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    ws.send(sync_msg(100)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(entries.len(), 10);
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn broadcast_to_other_client() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;

    let mut ws1 = connect(addr).await;
    let mut ws2 = connect(addr).await;

    let entry = make_entry("broadcast test");
    ws1.send(entry_msg(&entry)).await.unwrap();

    let text = recv_text(&mut ws2).await;
    match parse_server_msg(&text) {
        ServerMessage::ClipboardEntry(e) => {
            assert_eq!(e.content, "broadcast test");
        }
        other => panic!("expected ClipboardEntry broadcast, got {:?}", other),
    }
}

#[tokio::test]
async fn no_echo_to_sender() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    let entry = make_entry("no echo test");
    ws.send(entry_msg(&entry)).await.unwrap();

    let result = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        result.is_err(),
        "sender should not receive echo of own entry"
    );
}

#[tokio::test]
async fn ping_pong() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    ws.send(ping_msg()).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::Pong => {}
        other => panic!("expected Pong, got {:?}", other),
    }
}

#[tokio::test]
async fn invalid_json_returns_error() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    ws.send(Message::Text("this is not valid json".into()))
        .await
        .unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::Error { message } => {
            assert!(message.contains("invalid message"));
        }
        other => panic!("expected Error, got {:?}", other),
    }
}

#[tokio::test]
async fn rate_limit_too_many_messages() {
    let rate_config = RateLimitConfig {
        max_messages_per_window: 5,
        max_bytes_per_window: 10 * 1024 * 1024,
        max_message_size: 1024 * 1024,
        window_duration: Duration::from_secs(60),
    };

    let addr = start_test_server(default_test_config(), rate_config).await;
    let mut ws = connect(addr).await;

    // Send 5 entries (should all succeed, consumed by rate limiter)
    for i in 0..5 {
        let entry = make_entry(&format!("rate test {i}"));
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 6th should trigger rate limit error
    let entry = make_entry("rate limit exceeded");
    ws.send(entry_msg(&entry)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("rate limit") || message.contains("messages in window"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected rate limit Error, got {:?}", other),
    }
}

#[tokio::test]
async fn rate_limit_message_too_large() {
    let rate_config = RateLimitConfig {
        max_messages_per_window: 100,
        max_bytes_per_window: 100 * 1024 * 1024,
        max_message_size: 500,
        window_duration: Duration::from_secs(60),
    };

    let addr = start_test_server(default_test_config(), rate_config).await;
    let mut ws = connect(addr).await;

    let big_content = "x".repeat(1000);
    let entry = make_entry(&big_content);
    ws.send(entry_msg(&entry)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::Error { message } => {
            assert!(message.contains("too large"), "unexpected error: {message}");
        }
        other => panic!("expected too large Error, got {:?}", other),
    }
}

#[tokio::test]
async fn entry_too_large_for_server_config() {
    let config = ServerConfig {
        max_entry_bytes: 100,
        ..default_test_config()
    };
    let rate_config = RateLimitConfig {
        max_messages_per_window: 100,
        max_bytes_per_window: 100 * 1024 * 1024,
        max_message_size: 100 * 1024 * 1024,
        window_duration: Duration::from_secs(60),
    };

    let addr = start_test_server(config, rate_config).await;
    let mut ws = connect(addr).await;

    let big_content = "x".repeat(200);
    let entry = make_entry(&big_content);
    ws.send(entry_msg(&entry)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::Error { message } => {
            assert!(
                message.contains("entry too large"),
                "unexpected error: {message}"
            );
        }
        other => panic!("expected entry too large Error, got {:?}", other),
    }
}

#[tokio::test]
async fn sync_request_returns_entries_newest_first() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    for i in 0..5 {
        let mut entry = make_entry(&format!("ordered entry {i}"));
        entry.created_at = Utc::now() + chrono::Duration::milliseconds(i as i64 * 100);
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    ws.send(sync_msg(3)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(entries.len(), 3);
            assert!(entries[0].content.contains("4"));
            assert!(entries[1].content.contains("3"));
            assert!(entries[2].content.contains("2"));
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn sync_batch_capped_by_server() {
    let config = ServerConfig {
        max_sync_batch: 3,
        ..default_test_config()
    };

    let addr = start_test_server(config, default_rate_config()).await;
    let mut ws = connect(addr).await;

    for i in 0..10 {
        let entry = make_entry(&format!("batch cap {i}"));
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    ws.send(sync_msg(100)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(entries.len(), 3);
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn server_recomputes_hash() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    let mut entry = make_entry("hash recompute test");
    entry.hash = "totally_fake_hash_value".to_string();
    ws.send(entry_msg(&entry)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    ws.send(sync_msg(10)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(entries.len(), 1);
            assert_ne!(entries[0].hash, "totally_fake_hash_value");
            let expected = entries[0].compute_server_hash();
            assert_eq!(entries[0].hash, expected);
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rapid_copy_burst_with_dedup() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    // 30 sends, only 10 unique contents (each repeated 3 times)
    let entries: Vec<ClipboardEntry> = (0..30)
        .map(|i| make_entry(&format!("rapid content {}", i % 10)))
        .collect();

    for e in &entries {
        ws.send(entry_msg(e)).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    ws.send(sync_msg(100)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(
                entries.len(),
                10,
                "dedup should collapse 30 sends to 10 unique"
            );
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn two_clients_rapid_fire_interleaved() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;

    let mut ws1 = connect(addr).await;
    let mut ws2 = connect(addr).await;

    let h1 = tokio::spawn(async move {
        for i in 0..15 {
            let entry = make_entry(&format!("client1 entry {i}"));
            ws1.send(entry_msg(&entry)).await.unwrap();
        }
        ws1
    });
    let h2 = tokio::spawn(async move {
        for i in 0..15 {
            let entry = make_entry(&format!("client2 entry {i}"));
            ws2.send(entry_msg(&entry)).await.unwrap();
        }
        ws2
    });

    let mut ws1 = h1.await.unwrap();
    let _ws2 = h2.await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain any broadcast messages ws1 may have received from ws2
    loop {
        match tokio::time::timeout(Duration::from_millis(100), ws1.next()).await {
            Ok(Some(Ok(_))) => continue,
            _ => break,
        }
    }

    ws1.send(sync_msg(100)).await.unwrap();
    let text = recv_text(&mut ws1).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(entries.len(), 30, "30 unique entries from 2 clients");
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn empty_sync_request() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    ws.send(sync_msg(10)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert!(entries.is_empty());
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn different_content_types_not_deduped() {
    let addr = start_test_server(default_test_config(), default_rate_config()).await;
    let mut ws = connect(addr).await;

    let mut text_entry = make_entry("https://example.com");
    text_entry.content_type = "text".to_string();
    text_entry.hash = text_entry.compute_server_hash();

    let mut url_entry = make_entry("https://example.com");
    url_entry.content_type = "url".to_string();
    url_entry.hash = url_entry.compute_server_hash();

    ws.send(entry_msg(&text_entry)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    ws.send(entry_msg(&url_entry)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    ws.send(sync_msg(10)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert_eq!(
                entries.len(),
                2,
                "different content_type = different hash = 2 entries"
            );
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}

#[tokio::test]
async fn rate_limit_bytes_exceeded() {
    let rate_config = RateLimitConfig {
        max_messages_per_window: 1000,
        max_bytes_per_window: 2000,
        max_message_size: 5000,
        window_duration: Duration::from_secs(60),
    };

    let addr = start_test_server(default_test_config(), rate_config).await;
    let mut ws = connect(addr).await;

    // Each entry_msg is ~200+ bytes of JSON. Send enough to exceed 2000 bytes.
    let mut got_error = false;
    for i in 0..20 {
        let entry = make_entry(&format!("bytes_test_{i}_padding_to_make_it_bigger"));
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Drain and look for a bandwidth limit error
    loop {
        match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let t = t.to_string();
                if let ServerMessage::Error { message } = parse_server_msg(&t) {
                    if message.contains("bandwidth") || message.contains("bytes") {
                        got_error = true;
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    assert!(got_error, "should have received a bandwidth limit error");
}

#[tokio::test]
async fn storage_limit_enforced() {
    let config = ServerConfig {
        max_entries: 5,
        ..default_test_config()
    };

    let addr = start_test_server(config, default_rate_config()).await;
    let mut ws = connect(addr).await;

    for i in 0..10 {
        let entry = make_entry(&format!("limit entry {i}"));
        ws.send(entry_msg(&entry)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    ws.send(sync_msg(100)).await.unwrap();
    let text = recv_text(&mut ws).await;

    match parse_server_msg(&text) {
        ServerMessage::SyncResponse { entries, .. } => {
            assert!(
                entries.len() <= 5,
                "enforce_limit should cap at 5, got {}",
                entries.len()
            );
        }
        other => panic!("expected SyncResponse, got {:?}", other),
    }
}
