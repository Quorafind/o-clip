mod app;
mod clipboard;
mod config;
mod error;
mod file_transfer;
mod store;
mod sync;
mod tui;
#[cfg(target_os = "windows")]
mod window;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use app::{App, Mode};
use clap::Parser;
use clipboard::ClipboardEvent;
#[cfg(target_os = "windows")]
use clipboard::ClipboardMonitor;
use config::{Cli, Config};
use file_transfer::FileTransferClient;
use store::{ClipboardEntry, EntrySource, Store};
use sync::SyncEvent;

/// Request from main thread to tokio runtime for file operations.
enum FileRequest {
    /// Upload local files to server, then send the resulting SyncedFiles entry via WS.
    Upload {
        entry: ClipboardEntry,
        paths: Vec<std::path::PathBuf>,
    },
    /// Download SyncedFiles from server.
    Download { refs: Vec<clipboard::FileRef> },
}

/// Response from tokio runtime back to main thread.
enum FileResponse {
    /// Files downloaded successfully; set these local paths on the clipboard.
    Downloaded(Vec<std::path::PathBuf>),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments and load configuration
    let cli = Cli::parse();
    let config = Config::load(cli.config.as_deref());
    // Only write default config if no custom path was specified
    if cli.config.is_none() {
        Config::write_default_if_missing(&Config::config_path());
    }

    // Set up file-based logging (TUI owns stdout)
    let log_dir = directories::ProjectDirs::from("", "", "o-clip")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    let log_file = std::fs::File::create(log_dir.join("o-clip.log")).ok();
    if let Some(file) = log_file {
        tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .init();
    }

    // Open SQLite store
    let db_path = config.db_path();
    let store = Store::open(&db_path)?;
    tracing::info!("database opened at {}", db_path.display());

    // Create clipboard event channel
    let (clip_tx, clip_rx) = std::sync::mpsc::channel::<ClipboardEvent>();

    // Spawn clipboard monitor thread (platform-specific)
    let monitor_handle = spawn_clipboard_monitor(clip_tx);

    // Set up WebSocket sync channels
    let (ws_outbound_tx, ws_outbound_rx) = tokio::sync::mpsc::unbounded_channel::<ClipboardEntry>();
    let (ws_event_tx, ws_event_rx) = std::sync::mpsc::channel::<SyncEvent>();

    // Sync size limit: entries larger than this are stored locally only
    let max_sync_size = config.server.max_sync_size;

    // File transfer channels (main thread <-> tokio runtime)
    let (file_req_tx, mut file_req_rx) = tokio::sync::mpsc::unbounded_channel::<FileRequest>();
    let (file_resp_tx, file_resp_rx) = std::sync::mpsc::channel::<FileResponse>();

    // Spawn tokio runtime for WebSocket sync + file transfer
    let ws_url = config.server.url.clone();
    let accept_invalid_certs = config.server.accept_invalid_certs;
    let ws_password = config.server.password.clone();
    let has_server = config.has_server() && config.server.auto_connect;
    let max_file_sync_size = config.server.max_file_sync_size;
    let download_dir = config.download_dir();
    let reconnect_notify = Arc::new(tokio::sync::Notify::new());
    let reconnect_notify_sync = reconnect_notify.clone();
    let ws_outbound_tx_clone = ws_outbound_tx.clone();
    let _rt_handle = std::thread::spawn(move || {
        if !has_server {
            return;
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("failed to build tokio runtime");

        // Create file transfer client
        let file_client = Arc::new(FileTransferClient::new(
            &ws_url,
            ws_password.clone(),
            accept_invalid_certs,
            max_file_sync_size,
            download_dir,
        ));

        // Spawn file transfer request handler
        let fc = file_client.clone();
        let ws_tx = ws_outbound_tx_clone;
        let resp_tx = file_resp_tx;
        rt.spawn(async move {
            while let Some(req) = file_req_rx.recv().await {
                match req {
                    FileRequest::Upload { mut entry, paths } => {
                        match fc.upload_files(&paths).await {
                            Ok(file_refs) => {
                                // Replace content with SyncedFiles
                                let synced = clipboard::ClipboardContent::SyncedFiles(file_refs);
                                let content_json =
                                    serde_json::to_string(&synced).unwrap_or_default();
                                entry.content = content_json;
                                entry.hash = synced.content_hash();
                                entry.byte_size = synced.byte_size() as i64;
                                entry.preview = synced.preview(120);
                                let _ = ws_tx.send(entry);
                                tracing::info!("file upload complete, sent SyncedFiles entry");
                            }
                            Err(e) => {
                                tracing::warn!("file upload failed: {e}");
                            }
                        }
                    }
                    FileRequest::Download { refs } => match fc.download_files(&refs).await {
                        Ok(local_paths) => {
                            let _ = resp_tx.send(FileResponse::Downloaded(local_paths));
                        }
                        Err(e) => {
                            tracing::warn!("file download failed: {e}");
                        }
                    },
                }
            }
        });

        rt.block_on(sync::run_sync(
            ws_url,
            accept_invalid_certs,
            ws_password,
            ws_outbound_rx,
            ws_event_tx,
            reconnect_notify_sync,
        ));
    });

    // Query the terminal for graphics protocol support (must happen before
    // alternate screen so the response can be read from stdio).
    // Fall back to font-size based picker if query fails (common on Windows Terminal).
    let picker = ratatui_image::picker::Picker::from_query_stdio()
        .unwrap_or_else(|_| ratatui_image::picker::Picker::from_fontsize((8, 16)));
    let picker = Some(picker);

    // Set up terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(store, config.storage.max_entries, picker);
    app.reconnect_notify = Some(reconnect_notify);

    // Register Ctrl+C handler for graceful shutdown
    setup_ctrlc_handler();

    // Dedup cache: tracks content hashes of recently auto-copied remote entries.
    // When the clipboard monitor captures content that matches a recent auto-copy,
    // we skip sending it back to the server (preventing echo loops).
    // Maps pixel-based content_hash -> Instant when it was auto-copied.
    let mut recent_remote_hashes: HashMap<String, Instant> = HashMap::new();
    const REMOTE_HASH_TTL: Duration = Duration::from_secs(10);

    // Main event loop
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        // Render
        terminal.draw(|frame| tui::render(frame, &mut app))?;

        // Poll for crossterm events
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                // Clear status message on any keypress
                app.status_message = None;

                match app.mode {
                    Mode::Normal => match key.code {
                        KeyCode::Char('q') => {
                            app.should_quit = true;
                        }
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            app.should_quit = true;
                        }
                        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
                        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
                        KeyCode::Char('g') => app.select_first(),
                        KeyCode::Char('G') => app.select_last(),
                        KeyCode::Enter => app.copy_selected_to_clipboard(),
                        KeyCode::Char('d') => app.delete_selected(),
                        KeyCode::Char('p') => app.toggle_pin_selected(),
                        KeyCode::Char('/') => app.enter_search(),
                        KeyCode::Char('r') => {
                            if let Some(ref notify) = app.reconnect_notify {
                                notify.notify_one();
                                app.status_message = Some("Reconnecting...".to_string());
                            }
                        }
                        _ => {}
                    },
                    Mode::Search => match key.code {
                        KeyCode::Esc => app.exit_search(),
                        KeyCode::Enter => {
                            app.mode = Mode::Normal;
                        }
                        KeyCode::Backspace => {
                            let mut q = app.search_query.clone();
                            q.pop();
                            app.update_search(q);
                        }
                        KeyCode::Char(c) => {
                            let mut q = app.search_query.clone();
                            q.push(c);
                            app.update_search(q);
                        }
                        _ => {}
                    },
                }
            }
        }

        // Process clipboard events (non-blocking)
        while let Ok(event) = clip_rx.try_recv() {
            let content_hash = event.content.content_hash();
            let entry = ClipboardEntry::from_content(&event.content);

            // Check if this content was recently auto-copied from a remote entry.
            // If so, skip sending it back to the server (prevents echo loops where
            // the same image bounces between clients in different formats).
            let is_echo = recent_remote_hashes.remove(&content_hash).is_some();

            if is_echo {
                tracing::debug!(
                    "skipping outbound sync for recently auto-copied remote content: {}",
                    &content_hash[..16]
                );
            } else if !event.no_cloud {
                // Check if this is a Files entry that should be uploaded
                let is_files = matches!(&event.content, clipboard::ClipboardContent::Files(_));
                if is_files {
                    // Extract paths and send to file upload handler
                    if let clipboard::ClipboardContent::Files(paths) = &event.content {
                        let _ = file_req_tx.send(FileRequest::Upload {
                            entry: entry.clone(),
                            paths: paths.clone(),
                        });
                        tracing::info!("queued {} file(s) for upload", paths.len());
                    }
                } else if (entry.byte_size as usize) <= max_sync_size {
                    let _ = ws_outbound_tx.send(entry.clone());
                } else {
                    tracing::debug!(
                        "skipping sync for large entry: {} bytes (limit {})",
                        entry.byte_size,
                        max_sync_size
                    );
                }
            }
            app.on_new_entry(entry);
        }

        // Expire old entries from the remote hash dedup cache
        recent_remote_hashes.retain(|_, ts| ts.elapsed() < REMOTE_HASH_TTL);

        // Process WebSocket events (non-blocking)
        while let Ok(ws_event) = ws_event_rx.try_recv() {
            match ws_event {
                SyncEvent::RemoteEntry(mut entry) => {
                    entry.source = EntrySource::Remote;

                    // Remember the pixel-based content hash so the clipboard
                    // monitor won't re-send this content back to the server.
                    if let Some(content) = entry.to_clipboard_content() {
                        let pixel_hash = content.content_hash();
                        recent_remote_hashes.insert(pixel_hash, Instant::now());

                        // If this is a SyncedFiles entry, trigger async download
                        if let clipboard::ClipboardContent::SyncedFiles(refs) = &content {
                            let _ = file_req_tx.send(FileRequest::Download { refs: refs.clone() });
                            tracing::info!("queued {} file(s) for download", refs.len());
                        }
                    }

                    // Recompute client-side hash so the local DB dedup works
                    // correctly across image formats (PNG vs DibV5).
                    normalize_entry_hash(&mut entry);

                    // Auto-copy remote entry to local clipboard (without re-uploading)
                    auto_copy_to_clipboard(&entry);
                    app.on_new_entry(entry);
                }
                SyncEvent::SyncBatch(entries) => {
                    for mut entry in entries {
                        entry.source = EntrySource::Remote;
                        normalize_entry_hash(&mut entry);
                        app.on_new_entry(entry);
                    }
                }
                SyncEvent::StatusChanged(status) => {
                    app.ws_status = status;
                }
            }
        }

        // Process file download responses (non-blocking)
        while let Ok(resp) = file_resp_rx.try_recv() {
            match resp {
                FileResponse::Downloaded(local_paths) => {
                    tracing::info!("files downloaded: {} file(s)", local_paths.len());
                    // Remember hash to prevent echo
                    let content = clipboard::ClipboardContent::Files(local_paths.clone());
                    let hash = content.content_hash();
                    recent_remote_hashes.insert(hash, Instant::now());

                    // Defense in depth: on macOS, set_clipboard_files writes
                    // paths as plain text, so also remember the text hash the
                    // clipboard monitor will actually read back.
                    #[cfg(target_os = "macos")]
                    {
                        let text = local_paths
                            .iter()
                            .map(|p| p.to_string_lossy().to_string())
                            .collect::<Vec<_>>()
                            .join("\n");
                        let text_content = clipboard::content::classify_text(text);
                        let text_hash = text_content.content_hash();
                        recent_remote_hashes.insert(text_hash, Instant::now());
                    }

                    // Set clipboard
                    clipboard::mark_self_write();
                    if app::set_clipboard_files_public(&local_paths) {
                        let dir_display = local_paths
                            .first()
                            .and_then(|p| p.parent())
                            .map(|d| d.to_string_lossy().to_string())
                            .unwrap_or_default();
                        app.status_message = Some(format!(
                            "Downloaded {} file(s) -> {}",
                            local_paths.len(),
                            dir_display,
                        ));
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    // Cleanup
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    io::stdout().execute(Clear(ClearType::All))?;

    // Signal the clipboard monitor to stop (Windows-specific)
    signal_monitor_stop();

    let _ = monitor_handle.join();
    tracing::info!("o-clip shutdown complete");
    Ok(())
}

// ---------------------------------------------------------------------------
// Recompute the entry hash using the client-side pixel-based algorithm.
// Server entries use a different hash (content_type:content_json) which
// produces different hashes for the same image in different formats (PNG vs
// DibV5). By normalizing to the client hash, the local DB's UNIQUE(hash)
// constraint correctly deduplicates cross-format images.
// ---------------------------------------------------------------------------

fn normalize_entry_hash(entry: &mut ClipboardEntry) {
    if let Some(content) = entry.to_clipboard_content() {
        entry.hash = content.content_hash();
    }
}

// ---------------------------------------------------------------------------
// Auto-copy a remote entry to the local clipboard.
// Uses mark_self_write() so the clipboard monitor ignores the change and
// the entry is NOT re-uploaded to the server.
// ---------------------------------------------------------------------------

fn auto_copy_to_clipboard(entry: &ClipboardEntry) {
    use crate::clipboard::ClipboardContent;

    let Some(content) = entry.to_clipboard_content() else {
        return;
    };

    // Only mark_self_write() when we actually write to the clipboard.
    // Calling it without a subsequent clipboard write would cause the monitor
    // to incorrectly skip the next *real* clipboard change.
    match &content {
        ClipboardContent::Text(t) => {
            clipboard::mark_self_write();
            app::set_clipboard_text_public(t);
        }
        ClipboardContent::Url(u) => {
            clipboard::mark_self_write();
            app::set_clipboard_text_public(u);
        }
        ClipboardContent::Files(paths) => {
            clipboard::mark_self_write();
            app::set_clipboard_files_public(paths);
        }
        ClipboardContent::SyncedFiles(_) => {
            // SyncedFiles are downloaded asynchronously via the file transfer channel.
            // Don't set clipboard here — it will be set when the download completes.
            // Do NOT call mark_self_write() since we're not writing to the clipboard.
        }
        ClipboardContent::Image(info) => {
            clipboard::mark_self_write();
            app::set_clipboard_image_public(info);
        }
        ClipboardContent::Empty => {}
    }
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard monitor spawning
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn spawn_clipboard_monitor(
    clip_tx: std::sync::mpsc::Sender<ClipboardEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Err(e) = ClipboardMonitor::run(clip_tx) {
            tracing::error!("clipboard monitor error: {e}");
        }
    })
}

#[cfg(target_os = "macos")]
fn spawn_clipboard_monitor(
    clip_tx: std::sync::mpsc::Sender<ClipboardEvent>,
) -> std::thread::JoinHandle<()> {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    // The stop flag is stored globally so the Ctrl+C handler can set it.
    static MAC_STOP: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();
    let stop = MAC_STOP
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();

    std::thread::spawn(move || {
        clipboard::monitor_mac::run_mac_monitor(clip_tx, stop);
    })
}

// ---------------------------------------------------------------------------
// Platform-specific monitor stop signal
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn signal_monitor_stop() {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

    if let Some(hwnd) = clipboard::monitor::get_monitor_hwnd() {
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }
}

#[cfg(target_os = "macos")]
fn signal_monitor_stop() {
    // The macOS monitor checks an AtomicBool; it will exit on next poll cycle.
    // Nothing to do here — the stop flag is set by the ctrlc handler.
}

// ---------------------------------------------------------------------------
// Platform-specific Ctrl+C handler
// ---------------------------------------------------------------------------

fn setup_ctrlc_handler() {
    let _ = std::thread::spawn(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = ctrlc_signal(tx);
        let _ = rx.recv();

        // Try to restore terminal before exit
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
        let _ = io::stdout().execute(Clear(ClearType::All));

        signal_monitor_stop();

        // On macOS the SIGINT handler intercepts Ctrl+C before crossterm
        // can deliver it as a key event, so the main loop never sees it.
        // Exit the process directly after cleanup.
        std::process::exit(0);
    });
}

#[cfg(target_os = "windows")]
fn ctrlc_signal(tx: std::sync::mpsc::Sender<()>) -> Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::Console::{CTRL_C_EVENT, SetConsoleCtrlHandler};

    static TX: std::sync::OnceLock<std::sync::mpsc::Sender<()>> = std::sync::OnceLock::new();
    TX.get_or_init(|| tx);

    unsafe extern "system" fn handler(ctrl_type: u32) -> windows::core::BOOL {
        if ctrl_type == CTRL_C_EVENT {
            if let Some(tx) = TX.get() {
                let _ = tx.send(());
            }
        }
        true.into()
    }

    unsafe {
        SetConsoleCtrlHandler(Some(handler), true)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ctrlc_signal(tx: std::sync::mpsc::Sender<()>) -> Result<(), Box<dyn std::error::Error>> {
    // On macOS, use a simple signal handler via libc
    use std::sync::OnceLock;
    static TX: OnceLock<std::sync::mpsc::Sender<()>> = OnceLock::new();
    TX.get_or_init(|| tx);

    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as libc::sighandler_t);
    }

    extern "C" fn sigint_handler(_: libc::c_int) {
        if let Some(tx) = TX.get() {
            let _ = tx.send(());
        }
    }

    Ok(())
}
