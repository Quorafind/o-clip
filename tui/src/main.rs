mod app;
mod config;
mod tui;

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

use clap::Parser;
use tokio::sync::Notify;

use crate::app::{App, Mode};
use crate::config::{Cli, Config};
use o_clip_core::clipboard::ClipboardEvent;
use o_clip_core::file_transfer::{FileRequest, FileResponse, FileTransferClient};
use o_clip_core::store::{ClipboardEntry, EntrySource, Store};
use o_clip_core::sync::{SyncCommand, SyncEvent};

#[cfg(target_os = "windows")]
use o_clip_core::clipboard::ClipboardMonitor;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments and load configuration.
    let cli = Cli::parse();
    let config = Config::load(cli.config.as_deref());
    // Only write default config if no custom path was specified.
    if cli.config.is_none() {
        Config::write_default_if_missing(&Config::config_path());
    }

    // Set up file-based logging (TUI owns stdout).
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

    // Open SQLite store.
    let db_path = config.db_path();
    let store = Store::open(&db_path)?;
    tracing::info!("database opened at {}", db_path.display());

    // Create clipboard event channel.
    let (clip_tx, clip_rx) = std::sync::mpsc::channel::<ClipboardEvent>();

    // Spawn clipboard monitor thread (platform-specific).
    let monitor_handle = spawn_clipboard_monitor(clip_tx);

    // Set up WebSocket sync channels.
    let (ws_outbound_tx, ws_outbound_rx) = tokio::sync::mpsc::unbounded_channel::<SyncCommand>();
    let (ws_event_tx, ws_event_rx) = std::sync::mpsc::channel::<SyncEvent>();

    // Sync size limit: entries larger than this are stored locally only.
    let max_sync_size = config.server.max_sync_size;
    // Image inline threshold: images smaller than this sync as base64, larger use file transfer.
    let image_inline_threshold = config.server.image_inline_threshold;

    // File transfer channels (main thread <-> tokio runtime).
    let (file_req_tx, mut file_req_rx) = tokio::sync::mpsc::unbounded_channel::<FileRequest>();
    let (file_resp_tx, file_resp_rx) = std::sync::mpsc::channel::<FileResponse>();

    // Spawn tokio runtime for WebSocket sync + file transfer.
    let ws_url = config.server.url.clone();
    let accept_invalid_certs = config.server.accept_invalid_certs;
    let ws_password = config.server.password.clone();
    let has_server = config.has_server() && config.server.auto_connect;
    let max_file_sync_size = config.server.max_file_sync_size;
    let download_dir = config.download_dir();
    let reconnect_notify = Arc::new(Notify::new());
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

        // Create file transfer client.
        let file_client = Arc::new(FileTransferClient::new(
            &ws_url,
            ws_password.clone(),
            accept_invalid_certs,
            max_file_sync_size,
            download_dir,
        ));

        // Spawn file transfer request handler.
        let fc = file_client.clone();
        let ws_tx = ws_outbound_tx_clone;
        let resp_tx = file_resp_tx;
        rt.spawn(async move {
            while let Some(req) = file_req_rx.recv().await {
                match req {
                    FileRequest::Upload { mut entry, paths } => match fc.upload_files(&paths).await
                    {
                        Ok(file_refs) => {
                            // Replace content with SyncedFiles.
                            let synced =
                                o_clip_core::clipboard::ClipboardContent::SyncedFiles(file_refs);
                            let content_json = serde_json::to_string(&synced).unwrap_or_default();
                            entry.content = content_json;
                            entry.hash = synced.content_hash();
                            entry.byte_size = synced.byte_size() as i64;
                            entry.preview = synced.preview(120);
                            let _ = ws_tx.send(SyncCommand::SendEntry(entry));
                            tracing::info!("file upload complete, sent SyncedFiles entry");
                        }
                        Err(e) => {
                            tracing::warn!("file upload failed: {e}");
                        }
                    },
                    FileRequest::Download { refs } => match fc.download_files(&refs).await {
                        Ok(local_paths) => {
                            let _ = resp_tx.send(FileResponse::Downloaded(local_paths));
                        }
                        Err(e) => {
                            tracing::warn!("file download failed: {e}");
                        }
                    },
                    FileRequest::UploadImage { mut entry, info } => {
                        match fc.upload_image(&info).await {
                            Ok(img_ref) => {
                                // Replace content with SyncedImage.
                                let synced =
                                    o_clip_core::clipboard::ClipboardContent::SyncedImage(img_ref);
                                let content_json =
                                    serde_json::to_string(&synced).unwrap_or_default();
                                entry.content = content_json;
                                entry.hash = synced.content_hash();
                                entry.byte_size = synced.byte_size() as i64;
                                entry.preview = synced.preview(120);
                                let _ = ws_tx.send(SyncCommand::SendEntry(entry));
                                tracing::info!("image upload complete, sent SyncedImage entry");
                            }
                            Err(e) => {
                                tracing::warn!("image upload failed: {e}");
                            }
                        }
                    }
                    FileRequest::DownloadImage { img_ref } => {
                        match fc.download_image(&img_ref).await {
                            Ok(info) => {
                                let _ = resp_tx.send(FileResponse::ImageDownloaded(info));
                            }
                            Err(e) => {
                                tracing::warn!("image download failed: {e}");
                            }
                        }
                    }
                }
            }
        });

        rt.block_on(o_clip_core::sync::run_sync(
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

    // Set up terminal.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state.
    let mut app = App::new(store, config.storage.max_entries, picker);
    app.reconnect_notify = Some(reconnect_notify);

    // Register Ctrl+C handler for graceful shutdown.
    setup_ctrlc_handler();

    // Dedup cache: tracks content hashes of recently auto-copied remote entries.
    // When the clipboard monitor captures content that matches a recent auto-copy,
    // we skip sending it back to the server (preventing echo loops).
    // Maps pixel-based content_hash -> Instant when it was auto-copied.
    let mut recent_remote_hashes: HashMap<String, Instant> = HashMap::new();
    const REMOTE_HASH_TTL: Duration = Duration::from_secs(10);

    // Main event loop.
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();

    loop {
        // Render.
        terminal.draw(|frame| tui::render(frame, &mut app))?;

        // Poll for crossterm events.
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                // Clear status message on any keypress.
                app.manager.status_message = None;

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
                        KeyCode::Char('f') => {
                            if let Some(req) = app.refetch_selected_files() {
                                let _ = file_req_tx.send(req);
                            }
                        }
                        KeyCode::Char('/') => app.enter_search(),
                        KeyCode::Char('r') => {
                            if let Some(ref notify) = app.reconnect_notify {
                                notify.notify_one();
                                app.manager.status_message = Some("Reconnecting...".to_string());
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
                            let mut q = app.manager.search_query.clone();
                            q.pop();
                            app.update_search(q);
                        }
                        KeyCode::Char(c) => {
                            let mut q = app.manager.search_query.clone();
                            q.push(c);
                            app.update_search(q);
                        }
                        _ => {}
                    },
                }
            }
        }

        // Process clipboard events (non-blocking).
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
                // Check if this is a Files entry that should be uploaded.
                let is_files = matches!(
                    &event.content,
                    o_clip_core::clipboard::ClipboardContent::Files(_)
                );
                // Check if this is an Image entry that should be uploaded.
                let is_image = matches!(
                    &event.content,
                    o_clip_core::clipboard::ClipboardContent::Image(_)
                );

                if is_files {
                    // Extract paths and send to file upload handler.
                    if let o_clip_core::clipboard::ClipboardContent::Files(paths) = &event.content {
                        let _ = file_req_tx.send(FileRequest::Upload {
                            entry: entry.clone(),
                            paths: paths.clone(),
                        });
                        tracing::info!("queued {} file(s) for upload", paths.len());
                    }
                } else if is_image {
                    // Extract ImageInfo and decide: inline (small) vs file transfer (large).
                    if let o_clip_core::clipboard::ClipboardContent::Image(info) = &event.content {
                        if info.raw_data.is_none() {
                            tracing::debug!("skipping image sync: no raw_data");
                        } else if info.data_size <= image_inline_threshold {
                            // Small image: sync inline as base64 (faster for screenshots).
                            if (entry.byte_size as usize) <= max_sync_size {
                                let _ = ws_outbound_tx.send(SyncCommand::SendEntry(entry.clone()));
                                tracing::info!(
                                    "syncing small image inline: {}x{} ({} bytes)",
                                    info.width,
                                    info.height,
                                    info.data_size
                                );
                            }
                        } else {
                            // Large image: use file transfer.
                            let _ = file_req_tx.send(FileRequest::UploadImage {
                                entry: entry.clone(),
                                info: info.clone(),
                            });
                            tracing::info!(
                                "queued large image for upload: {}x{} ({} bytes)",
                                info.width,
                                info.height,
                                info.data_size
                            );
                        }
                    }
                } else if (entry.byte_size as usize) <= max_sync_size {
                    let _ = ws_outbound_tx.send(SyncCommand::SendEntry(entry.clone()));
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

        // Expire old entries from the remote hash dedup cache.
        recent_remote_hashes.retain(|_, ts| ts.elapsed() < REMOTE_HASH_TTL);

        // Process WebSocket events (non-blocking).
        while let Ok(ws_event) = ws_event_rx.try_recv() {
            match ws_event {
                SyncEvent::RemoteEntry(mut entry) => {
                    entry.source = EntrySource::Remote;

                    // Normalize hash first so we can check local DB.
                    o_clip_core::normalize_entry_hash(&mut entry);

                    // Check if this entry already exists in our local DB.
                    // If so, skip download and auto-copy to prevent echo loops
                    // when multiple clients (GUI + TUI) share the same clipboard.
                    let already_exists = app.manager.store().has_hash(&entry.hash);

                    if !already_exists {
                        if let Some(content) = entry.to_clipboard_content() {
                            let pixel_hash = content.content_hash();
                            recent_remote_hashes.insert(pixel_hash, Instant::now());

                            if let o_clip_core::clipboard::ClipboardContent::SyncedFiles(refs) =
                                &content
                            {
                                let _ =
                                    file_req_tx.send(FileRequest::Download { refs: refs.clone() });
                                tracing::info!("queued {} file(s) for download", refs.len());
                            }

                            if let o_clip_core::clipboard::ClipboardContent::SyncedImage(img_ref) =
                                &content
                            {
                                let _ = file_req_tx.send(FileRequest::DownloadImage {
                                    img_ref: img_ref.clone(),
                                });
                                tracing::info!(
                                    "queued image for download: {}x{}",
                                    img_ref.width,
                                    img_ref.height
                                );
                            }
                        }

                        // Auto-copy remote entry to local clipboard (without re-uploading).
                        o_clip_core::auto_copy_to_clipboard(&entry);
                    } else {
                        tracing::debug!(
                            "skipping auto-copy/download for existing entry: {}",
                            &entry.hash[..entry.hash.len().min(16)]
                        );
                    }

                    app.on_new_entry(entry);
                }
                SyncEvent::SyncBatch(entries) => {
                    let batch: Vec<ClipboardEntry> = entries
                        .into_iter()
                        .map(|mut e| {
                            e.source = EntrySource::Remote;
                            o_clip_core::normalize_entry_hash(&mut e);
                            e
                        })
                        .collect();
                    app.on_new_entries_batch(batch);
                }
                SyncEvent::StatusChanged(status) => {
                    app.manager.ws_status = status;
                }
                SyncEvent::ClearAll => {
                    app.manager.delete_all();
                }
            }
        }

        // Process file download responses (non-blocking).
        while let Ok(resp) = file_resp_rx.try_recv() {
            match resp {
                FileResponse::Downloaded(local_paths) => {
                    tracing::info!("files downloaded: {} file(s)", local_paths.len());
                    // Remember hash to prevent echo.
                    let content =
                        o_clip_core::clipboard::ClipboardContent::Files(local_paths.clone());
                    let hash = content.content_hash();
                    recent_remote_hashes.insert(hash, Instant::now());

                    // Set clipboard.
                    o_clip_core::clipboard::mark_self_write();
                    if o_clip_core::clipboard::writer::set_clipboard_files(&local_paths) {
                        let dir_display = local_paths
                            .first()
                            .and_then(|p| p.parent())
                            .map(|d| d.to_string_lossy().to_string())
                            .unwrap_or_default();
                        app.manager.status_message = Some(format!(
                            "Downloaded {} file(s) -> {}",
                            local_paths.len(),
                            dir_display,
                        ));
                    }
                }
                FileResponse::ImageDownloaded(info) => {
                    tracing::info!(
                        "image downloaded: {}x{} {:?}",
                        info.width,
                        info.height,
                        info.format
                    );

                    // Remember hash to prevent echo.
                    let content = o_clip_core::clipboard::ClipboardContent::Image(info.clone());
                    let hash = content.content_hash();
                    recent_remote_hashes.insert(hash, Instant::now());

                    // Set clipboard.
                    o_clip_core::clipboard::mark_self_write();
                    if o_clip_core::clipboard::writer::set_clipboard_image(&info) {
                        app.manager.status_message = Some(format!(
                            "Image synced: {}x{} {:?}",
                            info.width, info.height, info.format
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

    // Cleanup.
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    io::stdout().execute(Clear(ClearType::All))?;

    // Signal the clipboard monitor to stop (Windows-specific).
    signal_monitor_stop();

    let _ = monitor_handle.join();
    tracing::info!("o-clip shutdown complete");
    Ok(())
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
        o_clip_core::clipboard::monitor_mac::run_mac_monitor(clip_tx, stop);
    })
}

// ---------------------------------------------------------------------------
// Platform-specific monitor stop signal
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn signal_monitor_stop() {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};

    if let Some(hwnd) = o_clip_core::clipboard::monitor::get_monitor_hwnd() {
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0));
        }
    }
}

#[cfg(target_os = "macos")]
fn signal_monitor_stop() {
    // The macOS monitor checks an AtomicBool; it will exit on next poll cycle.
    // Nothing to do here; the stop flag is set by the ctrlc handler.
}

// ---------------------------------------------------------------------------
// Platform-specific Ctrl+C handler
// ---------------------------------------------------------------------------

fn setup_ctrlc_handler() {
    let _ = std::thread::spawn(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = ctrlc_signal(tx);
        let _ = rx.recv();

        // Try to restore terminal before exit.
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
