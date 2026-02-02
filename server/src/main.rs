mod config;
mod protocol;
mod rate_limit;
mod store;
mod ws;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use tokio::sync::broadcast;
use tower_http::cors::CorsLayer;

use config::ServerConfig;
use rate_limit::{RateLimitConfig, RateLimiter};
use store::Store;
use ws::{AppState, handle_socket};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Load config
    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("server.toml"));

    ServerConfig::write_default_if_missing(&config_path);
    let config = ServerConfig::load(&config_path);
    tracing::info!("loaded config from {}", config_path.display());
    tracing::info!("listen: {}", config.listen);
    tracing::info!("db: {}", config.db_path().display());
    tracing::info!(
        "limits: max_entries={}, max_entry_bytes={}, max_sync_batch={}",
        config.max_entries,
        config.max_entry_bytes,
        config.max_sync_batch
    );
    tracing::info!(
        "rate: {}/min messages, {} bytes/min, {} max msg size",
        config.rate_limit_messages,
        config.rate_limit_bytes,
        config.rate_limit_max_message_size
    );

    // Open store
    let db_path = config.db_path();
    let store = Store::open(&db_path).expect("failed to open database");
    let entry_count = store.count().unwrap_or(0);
    let total_bytes = store.total_bytes().unwrap_or(0);
    tracing::info!(
        "database opened: {entry_count} entries, {:.1} MB",
        total_bytes as f64 / (1024.0 * 1024.0)
    );

    // Create broadcast channel (capacity 256; lagging receivers drop old messages)
    let (broadcast_tx, _) = broadcast::channel(256);

    // Rate limiter
    let rate_limiter = RateLimiter::new(RateLimitConfig {
        max_messages_per_window: config.rate_limit_messages,
        max_bytes_per_window: config.rate_limit_bytes,
        max_message_size: config.rate_limit_max_message_size,
        window_duration: Duration::from_secs(60),
    });

    let state = Arc::new(AppState {
        store,
        rate_limiter,
        broadcast_tx,
        config: config.clone(),
    });

    // Background task: periodic cleanup of rate limiter state + DB pruning
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                state.rate_limiter.cleanup_stale();
                if let Err(e) = state.store.enforce_limit(state.config.max_entries) {
                    tracing::warn!("periodic prune failed: {e}");
                } else {
                    let count = state.store.count().unwrap_or(0);
                    tracing::debug!("periodic prune done, {count} entries remain");
                }
            }
        });
    }

    // Build router
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Bind and serve
    let addr: SocketAddr = config.listen.parse().expect("invalid listen address");

    #[cfg(feature = "tls")]
    if let Some((cert_path, key_path)) = config.tls_paths() {
        tracing::info!(
            "TLS enabled: cert={}, key={}",
            cert_path.display(),
            key_path.display()
        );
        tracing::info!("o-clip-server listening on {addr} (wss)");

        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .expect("failed to load TLS cert/key");

        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("server error");

        tracing::info!("server shut down");
        return;
    }

    tracing::info!("o-clip-server listening on {addr} (ws, no TLS)");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");

    tracing::info!("server shut down");
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    tracing::info!("ws upgrade request from {addr}");
    ws.on_upgrade(move |socket| handle_socket(socket, addr, state))
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let count = state.store.count().unwrap_or(0);
    let bytes = state.store.total_bytes().unwrap_or(0);
    format!("{{\"status\":\"ok\",\"entries\":{count},\"bytes\":{bytes}}}")
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("ctrl+c received, shutting down...");
}
