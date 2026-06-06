#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tao::dpi::{LogicalSize, PhysicalPosition};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::window::WindowBuilder;
use tray_icon::TrayIconBuilder;
use wry::WebViewBuilder;

use o_clip_core::clipboard::{self, ClipboardContent, ClipboardEvent};
use o_clip_core::config::Config;
use o_clip_core::entry_manager::EntryManager;
use o_clip_core::file_transfer::{
    FileRequest, FileResponse, FileTransferClient, download_files_key, download_image_key,
};
use o_clip_core::store::{ClipboardEntry, EntrySource, Store};
use o_clip_core::sync::{ConnectionStatus, SyncCommand, SyncEvent};

#[cfg(target_os = "windows")]
use o_clip_core::clipboard::ClipboardMonitor;

const FILE_DOWNLOAD_DEDUP_TTL: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Custom events for the tao event loop
// ---------------------------------------------------------------------------

enum AppEvent {
    Clipboard(ClipboardEvent),
    Sync(SyncEvent),
    File(FileResponse),
    Ipc(String),
    /// Image encoded on background thread, ready to push to WebView.
    ImageReady {
        id: i64,
        data_url: String,
    },
    /// Entries loaded from DB on background thread.
    EntriesLoaded {
        entries: Vec<ClipboardEntry>,
        total: usize,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup logging.
    let log_dir = directories::ProjectDirs::from("", "", "o-clip")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    let log_file = std::fs::File::create(log_dir.join("o-clip-app.log")).ok();
    if let Some(file) = log_file {
        tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .init();
    }

    // Load config.
    let config = Config::load(None);
    Config::write_default_if_missing(&Config::config_path());

    // ---- System tray (appears instantly) ----------------------------------
    let (_tray, tray_menu_ids) = create_tray_icon()?;

    // ---- Event loop + window + WebView ------------------------------------
    let event_loop = EventLoopBuilder::<AppEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // ---- Window + WebView ---------------------------------------------------
    let window = WindowBuilder::new()
        .with_title("o-clip")
        .with_visible(false)
        .with_decorations(false)
        .with_inner_size(LogicalSize::new(720.0, 520.0))
        .with_always_on_top(true)
        .with_resizable(false)
        .build(&event_loop)?;

    #[cfg(target_os = "windows")]
    {
        use tao::platform::windows::WindowExtWindows;
        let _ = window.set_skip_taskbar(true);
    }

    let ipc_proxy = proxy.clone();
    let webview = WebViewBuilder::new(&window)
        .with_html(include_str!("ui.html"))
        .with_ipc_handler(move |msg| {
            let _ = ipc_proxy.send_event(AppEvent::Ipc(msg.body().to_string()));
        })
        .with_devtools(cfg!(debug_assertions))
        .build()?;

    // ---- Database (no queries on main thread) --------------------------------
    let db_path = config.db_path();
    let store = Store::open(&db_path)?;
    tracing::info!("database opened at {}", db_path.display());
    let mut manager = EntryManager::new_lazy(store, config.storage.max_entries);
    let bg_store = Arc::new(Mutex::new(Store::open(&db_path)?));

    // ---- Clipboard monitor ------------------------------------------------
    let (clip_tx, clip_rx) = std::sync::mpsc::channel::<ClipboardEvent>();
    let _monitor_handle = spawn_clipboard_monitor(clip_tx);

    // Bridge: clipboard channel -> event loop proxy.
    let clip_proxy = proxy.clone();
    std::thread::spawn(move || {
        while let Ok(event) = clip_rx.recv() {
            let _ = clip_proxy.send_event(AppEvent::Clipboard(event));
        }
    });

    // ---- WebSocket sync + file transfer -----------------------------------
    let (ws_outbound_tx, ws_outbound_rx) = tokio::sync::mpsc::unbounded_channel::<SyncCommand>();
    let (ws_event_tx, ws_event_rx) = std::sync::mpsc::channel::<SyncEvent>();
    let (file_req_tx, file_req_rx) = tokio::sync::mpsc::unbounded_channel::<FileRequest>();
    let (file_resp_tx, file_resp_rx) = std::sync::mpsc::channel::<FileResponse>();
    let reconnect_notify = Arc::new(tokio::sync::Notify::new());

    spawn_sync_runtime(
        &config,
        ws_outbound_rx,
        ws_outbound_tx.clone(),
        ws_event_tx,
        file_req_rx,
        file_resp_tx,
        reconnect_notify.clone(),
    );

    // Bridge: WS events -> event loop.
    let ws_proxy = proxy.clone();
    std::thread::spawn(move || {
        while let Ok(event) = ws_event_rx.recv() {
            let _ = ws_proxy.send_event(AppEvent::Sync(event));
        }
    });

    // Bridge: file responses -> event loop.
    let file_proxy = proxy.clone();
    std::thread::spawn(move || {
        while let Ok(resp) = file_resp_rx.recv() {
            let _ = file_proxy.send_event(AppEvent::File(resp));
        }
    });

    // ---- State for the event loop -----------------------------------------
    let mut window_visible = false;
    let mut webview_ready = false; // true after JS sends 'init'
    let mut recent_remote_hashes: HashMap<String, Instant> = HashMap::new();
    let max_sync_size = config.server.max_sync_size;
    let image_inline_threshold = config.server.image_inline_threshold;
    let mut last_tray_toggle = Instant::now() - Duration::from_secs(10);
    let mut last_show_time = Instant::now() - Duration::from_secs(10);

    // ---- Main event loop --------------------------------------------------
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        // Expire old dedup hashes.
        recent_remote_hashes.retain(|_, ts| ts.elapsed() < Duration::from_secs(10));

        // Drain all tray events.
        while let Ok(tray_event) = tray_icon::TrayIconEvent::receiver().try_recv() {
            if let ClickEvent::Left = classify_tray_event(&tray_event) {
                let now = Instant::now();
                if now.duration_since(last_tray_toggle) > Duration::from_millis(300) {
                    last_tray_toggle = now;
                    window_visible = !window_visible;
                    if window_visible {
                        position_window(&window, &tray_event);
                        window.set_visible(true);
                        window.set_focus();
                        last_show_time = Instant::now();
                        if webview_ready {
                            let _ = webview.evaluate_script("onShow()");
                        }
                    } else {
                        window.set_visible(false);
                    }
                }
            }
        }

        // Drain all menu events.
        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if event.id == tray_menu_ids.quit_id {
                signal_monitor_stop();
                std::process::exit(0);
            } else if event.id == tray_menu_ids.autostart_id {
                let currently_enabled = is_autostart_enabled();
                let new_state = !currently_enabled;
                if set_autostart(new_state) {
                    let msg = if new_state {
                        "Auto-start enabled"
                    } else {
                        "Auto-start disabled"
                    };
                    push_status(&webview, msg);
                    let _ = webview.evaluate_script(&format!("onAutostart({})", new_state));
                } else {
                    push_status(&webview, "Failed to change auto-start setting");
                }
            }
        }

        match event {
            Event::UserEvent(app_event) => match app_event {
                AppEvent::Ipc(msg) => {
                    handle_ipc(
                        &msg,
                        &mut manager,
                        &webview,
                        &window,
                        &ws_outbound_tx,
                        &file_req_tx,
                        &reconnect_notify,
                        &mut window_visible,
                        &proxy,
                        &mut webview_ready,
                        &bg_store,
                    );
                }
                AppEvent::Clipboard(event) => {
                    handle_clipboard_event(
                        event,
                        &mut manager,
                        &webview,
                        &ws_outbound_tx,
                        &file_req_tx,
                        &mut recent_remote_hashes,
                        max_sync_size,
                        image_inline_threshold,
                        &bg_store,
                    );
                }
                AppEvent::Sync(event) => {
                    handle_sync_event(
                        event,
                        &mut manager,
                        &webview,
                        &file_req_tx,
                        &mut recent_remote_hashes,
                        &bg_store,
                    );
                }
                AppEvent::File(resp) => {
                    handle_file_response(resp, &mut manager, &webview, &mut recent_remote_hashes);
                }
                AppEvent::EntriesLoaded { entries, total } => {
                    manager.entries = entries;
                    manager.total_count = total;
                    if manager.selected >= manager.entries.len() && !manager.entries.is_empty() {
                        manager.selected = manager.entries.len() - 1;
                    }
                    push_entries(&webview, &mut manager);
                }
                AppEvent::ImageReady { id, data_url } => {
                    let js = format!(
                        "onImageData({},{})",
                        id,
                        serde_json::to_string(&data_url).unwrap_or_default()
                    );
                    let _ = webview.evaluate_script(&js);
                }
            },
            Event::WindowEvent {
                event: WindowEvent::Focused(false),
                ..
            } => {
                // Ignore focus-lost within 500ms of showing — avoids the
                // window flashing and disappearing during show/focus race.
                if last_show_time.elapsed() > Duration::from_millis(500) {
                    window.set_visible(false);
                    window_visible = false;
                }
            }
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                window.set_visible(false);
                window_visible = false;
            }
            _ => {}
        }
    });
}

// ---------------------------------------------------------------------------
// Tray event helper — normalise platform differences
// ---------------------------------------------------------------------------

enum ClickEvent {
    Left,
    Other,
}

fn classify_tray_event(event: &tray_icon::TrayIconEvent) -> ClickEvent {
    match event {
        tray_icon::TrayIconEvent::Click {
            button: tray_icon::MouseButton::Left,
            ..
        } => ClickEvent::Left,
        _ => ClickEvent::Other,
    }
}

// ---------------------------------------------------------------------------
// IPC handler
// ---------------------------------------------------------------------------

fn handle_ipc(
    msg: &str,
    manager: &mut EntryManager,
    webview: &wry::WebView,
    window: &tao::window::Window,
    ws_tx: &tokio::sync::mpsc::UnboundedSender<SyncCommand>,
    file_tx: &tokio::sync::mpsc::UnboundedSender<FileRequest>,
    reconnect: &Arc<tokio::sync::Notify>,
    visible: &mut bool,
    proxy: &tao::event_loop::EventLoopProxy<AppEvent>,
    webview_ready: &mut bool,
    bg_store: &Arc<Mutex<Store>>,
) {
    let _ = (ws_tx, file_tx); // used later for refetch
    let cmd: serde_json::Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(_) => return,
    };

    let cmd_type = cmd["cmd"].as_str().unwrap_or("");

    match cmd_type {
        "init" => {
            *webview_ready = true;
            let autostart = is_autostart_enabled();
            let _ = webview.evaluate_script(&format!("onAutostart({})", autostart));
            spawn_load_entries(bg_store, proxy, None);
        }
        "show" => {
            // Push cached entries instantly, refresh from DB in background.
            if !manager.entries.is_empty() {
                push_entries(webview, manager);
            }
            spawn_load_entries(bg_store, proxy, None);
        }
        "list" => {
            spawn_load_entries(bg_store, proxy, None);
        }
        "load_more" => {
            // No-op with virtual scroll — all entries already loaded.
        }
        "toggle_autostart" => {
            let currently_enabled = is_autostart_enabled();
            let new_state = !currently_enabled;
            if set_autostart(new_state) {
                let msg = if new_state {
                    "Auto-start enabled"
                } else {
                    "Auto-start disabled"
                };
                push_status(webview, msg);
                let _ = webview.evaluate_script(&format!("onAutostart({})", new_state));
            } else {
                push_status(webview, "Failed to change auto-start setting");
            }
        }
        "search" => {
            let query = cmd["query"].as_str().unwrap_or("").to_string();
            manager.search_query = query.clone();
            manager.selected = 0;
            spawn_load_entries(bg_store, proxy, Some(query));
        }
        "clear_search" => {
            manager.search_query.clear();
            manager.selected = 0;
            spawn_load_entries(bg_store, proxy, None);
        }
        "get_content" => {
            let id = cmd["id"].as_i64().unwrap_or(-1);
            // Find entry, load content, push to webview.
            if let Some(idx) = manager.entries.iter().position(|e| e.id == id) {
                manager.selected = idx;
                manager.ensure_selected_content_loaded();
                let entry = &manager.entries[idx];
                let response = build_content_json(entry);
                let _ = webview.evaluate_script(&format!("onContent({})", response));
            }
        }
        "get_image" => {
            let id = cmd["id"].as_i64().unwrap_or(-1);
            if let Some(idx) = manager.entries.iter().position(|e| e.id == id) {
                manager.selected = idx;
                manager.ensure_selected_content_loaded();
                let entry = &manager.entries[idx];
                if let Some(ClipboardContent::Image(info)) = entry.to_clipboard_content() {
                    if info.raw_data.is_some() {
                        let proxy = proxy.clone();
                        // Encode on background thread to avoid blocking UI.
                        std::thread::spawn(move || {
                            if let Some(data_url) = encode_image_data_url(&info) {
                                let _ = proxy.send_event(AppEvent::ImageReady { id, data_url });
                            }
                        });
                    }
                }
            }
        }
        "copy" => {
            let id = cmd["id"].as_i64().unwrap_or(-1);
            if let Some(idx) = manager.entries.iter().position(|e| e.id == id) {
                manager.selected = idx;
                copy_selected_to_clipboard(manager, webview);
            }
        }
        "delete" => {
            let id = cmd["id"].as_i64().unwrap_or(-1);
            if let Some(idx) = manager.entries.iter().position(|e| e.id == id) {
                manager.selected = idx;
                manager.delete_selected();
                push_entries(webview, manager);
                push_status(webview, "Entry deleted");
            }
        }
        "pin" => {
            let id = cmd["id"].as_i64().unwrap_or(-1);
            if let Some(idx) = manager.entries.iter().position(|e| e.id == id) {
                manager.selected = idx;
                manager.toggle_pin_selected();
                push_entries(webview, manager);
            }
        }
        "refetch" => {
            let id = cmd["id"].as_i64().unwrap_or(-1);
            if let Some(idx) = manager.entries.iter().position(|e| e.id == id) {
                manager.selected = idx;
                manager.ensure_selected_content_loaded();
                if let Some(content) = manager.get_selected_content() {
                    match content {
                        ClipboardContent::SyncedFiles(refs) => {
                            let n = refs.len();
                            let _ = file_tx.send(FileRequest::Download { refs });
                            push_status(webview, &format!("Re-downloading {n} file(s)..."));
                        }
                        ClipboardContent::SyncedImage(img_ref) => {
                            let _ = file_tx.send(FileRequest::DownloadImage { img_ref });
                            push_status(webview, "Re-downloading image...");
                        }
                        _ => {
                            push_status(webview, "Not a synced entry");
                        }
                    }
                }
            }
        }
        "hide" => {
            window.set_visible(false);
            *visible = false;
        }
        "reconnect" => {
            reconnect.notify_one();
            push_status(webview, "Reconnecting...");
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Clipboard event handler
// ---------------------------------------------------------------------------

fn handle_clipboard_event(
    event: ClipboardEvent,
    manager: &mut EntryManager,
    webview: &wry::WebView,
    ws_tx: &tokio::sync::mpsc::UnboundedSender<SyncCommand>,
    file_tx: &tokio::sync::mpsc::UnboundedSender<FileRequest>,
    recent_hashes: &mut HashMap<String, Instant>,
    max_sync_size: usize,
    image_inline_threshold: usize,
    bg_store: &Arc<Mutex<Store>>,
) {
    let content_hash = event.content.content_hash();
    let entry = ClipboardEntry::from_content(&event.content);

    let is_echo = recent_hashes.remove(&content_hash).is_some();

    if is_echo {
        tracing::debug!(
            "skipping echo: {}",
            &content_hash[..16.min(content_hash.len())]
        );
    } else if !event.no_cloud {
        match &event.content {
            ClipboardContent::Files(paths) => {
                let _ = file_tx.send(FileRequest::Upload {
                    entry: entry.clone(),
                    paths: paths.clone(),
                });
            }
            ClipboardContent::Image(info) => {
                if info.raw_data.is_some() {
                    if info.data_size <= image_inline_threshold {
                        if (entry.byte_size as usize) <= max_sync_size {
                            let _ = ws_tx.send(SyncCommand::SendEntry(entry.clone()));
                        }
                    } else {
                        let _ = file_tx.send(FileRequest::UploadImage {
                            entry: entry.clone(),
                            info: info.clone(),
                        });
                    }
                }
            }
            _ => {
                if (entry.byte_size as usize) <= max_sync_size {
                    let _ = ws_tx.send(SyncCommand::SendEntry(entry.clone()));
                }
            }
        }
    }

    // Prepend to in-memory list immediately (no DB, no reload).
    manager.entries.insert(0, entry.clone());
    manager.total_count += 1;
    push_new_entry(webview, manager);

    // DB write on background thread.
    let store = bg_store.clone();
    let max_entries = manager.max_entries();
    std::thread::spawn(move || {
        let store = store.lock().unwrap();
        if let Err(e) = store.insert(&entry) {
            tracing::warn!("bg insert failed: {e}");
        }
        let _ = store.enforce_limit(max_entries);
    });
}

// ---------------------------------------------------------------------------
// Sync event handler
// ---------------------------------------------------------------------------

fn handle_sync_event(
    event: SyncEvent,
    manager: &mut EntryManager,
    webview: &wry::WebView,
    file_tx: &tokio::sync::mpsc::UnboundedSender<FileRequest>,
    recent_hashes: &mut HashMap<String, Instant>,
    bg_store: &Arc<Mutex<Store>>,
) {
    match event {
        SyncEvent::RemoteEntry(mut entry) => {
            entry.source = EntrySource::Remote;
            o_clip_core::normalize_entry_hash(&mut entry);

            let already_exists = manager.store().has_hash(&entry.hash);

            if !already_exists {
                if let Some(content) = entry.to_clipboard_content() {
                    let pixel_hash = content.content_hash();
                    recent_hashes.insert(pixel_hash, Instant::now());

                    match &content {
                        ClipboardContent::SyncedFiles(refs) => {
                            let _ = file_tx.send(FileRequest::Download { refs: refs.clone() });
                        }
                        ClipboardContent::SyncedImage(img_ref) => {
                            let _ = file_tx.send(FileRequest::DownloadImage {
                                img_ref: img_ref.clone(),
                            });
                        }
                        _ => {}
                    }
                }
                o_clip_core::auto_copy_to_clipboard(&entry);
            }

            // Prepend to in-memory list immediately.
            manager.entries.insert(0, entry.clone());
            manager.total_count += 1;
            push_new_entry(webview, manager);

            // DB write on background thread.
            let store = bg_store.clone();
            let max_entries = manager.max_entries();
            std::thread::spawn(move || {
                let store = store.lock().unwrap();
                if let Err(e) = store.insert(&entry) {
                    tracing::warn!("bg sync insert failed: {e}");
                }
                let _ = store.enforce_limit(max_entries);
            });
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

            // Prepend to in-memory list immediately.
            let count = batch.len();
            for e in batch.iter().rev() {
                manager.entries.insert(0, e.clone());
            }
            manager.total_count += count;
            push_entries(webview, manager);

            // DB write on background thread.
            let store = bg_store.clone();
            let max_entries = manager.max_entries();
            std::thread::spawn(move || {
                let store = store.lock().unwrap();
                if let Err(e) = store.insert_batch(&batch) {
                    tracing::warn!("bg batch insert failed: {e}");
                }
                let _ = store.enforce_limit(max_entries);
            });
        }
        SyncEvent::StatusChanged(status) => {
            manager.ws_status = status;
            let s = match status {
                ConnectionStatus::Connected => "connected",
                ConnectionStatus::Connecting => "connecting",
                ConnectionStatus::Disconnected => "disconnected",
            };
            let _ = webview.evaluate_script(&format!("onWsStatus('{s}')"));
        }
        SyncEvent::ClearAll => {
            // Clear in-memory immediately.
            manager.entries.clear();
            manager.total_count = 0;
            manager.selected = 0;
            push_entries(webview, manager);
            // DB clear on background thread.
            let store = bg_store.clone();
            std::thread::spawn(move || {
                let store = store.lock().unwrap();
                let _ = store.delete_all();
            });
        }
    }
}

// ---------------------------------------------------------------------------
// File response handler
// ---------------------------------------------------------------------------

fn handle_file_response(
    resp: FileResponse,
    _manager: &mut EntryManager,
    webview: &wry::WebView,
    recent_hashes: &mut HashMap<String, Instant>,
) {
    match resp {
        FileResponse::Downloaded(local_paths) => {
            let content = ClipboardContent::Files(local_paths.clone());
            recent_hashes.insert(content.content_hash(), Instant::now());

            clipboard::mark_self_write();
            if clipboard::writer::set_clipboard_files(&local_paths) {
                push_status(
                    webview,
                    &format!("Downloaded {} file(s)", local_paths.len()),
                );
            }
        }
        FileResponse::ImageDownloaded(info) => {
            let content = ClipboardContent::Image(info.clone());
            recent_hashes.insert(content.content_hash(), Instant::now());

            clipboard::mark_self_write();
            if clipboard::writer::set_clipboard_image(&info) {
                push_status(
                    webview,
                    &format!("Image synced: {}x{}", info.width, info.height),
                );
            } else {
                let _ = clipboard::take_self_write();
                push_status(webview, "Failed to set clipboard image");
            }
        }
        FileResponse::Error(message) => {
            push_status(webview, &message);
        }
    }
}

// ---------------------------------------------------------------------------
// Copy selected entry to system clipboard
// ---------------------------------------------------------------------------

fn copy_selected_to_clipboard(manager: &mut EntryManager, webview: &wry::WebView) {
    manager.ensure_selected_content_loaded();
    let Some(content) = manager.get_selected_content() else {
        push_status(webview, "Cannot restore this content type");
        return;
    };

    match &content {
        ClipboardContent::Text(t) => {
            clipboard::mark_self_write();
            if clipboard::writer::set_clipboard_text(t) {
                push_status(webview, "Copied to clipboard");
            } else {
                push_status(webview, "Failed to set clipboard");
            }
        }
        ClipboardContent::Url(u) => {
            clipboard::mark_self_write();
            if clipboard::writer::set_clipboard_text(u) {
                push_status(webview, "Copied URL to clipboard");
            } else {
                push_status(webview, "Failed to set clipboard");
            }
        }
        ClipboardContent::Files(paths) => {
            clipboard::mark_self_write();
            if clipboard::writer::set_clipboard_files(paths) {
                push_status(webview, &format!("Copied {} file(s)", paths.len()));
            } else {
                push_status(webview, "Failed to set files");
            }
        }
        ClipboardContent::SyncedFiles(refs) => {
            push_status(
                webview,
                &format!("{} synced file(s) - press f to download", refs.len()),
            );
        }
        ClipboardContent::Image(info) => {
            if info.raw_data.is_none() {
                push_status(webview, "Image data not stored");
            } else {
                clipboard::mark_self_write();
                if clipboard::writer::set_clipboard_image(info) {
                    push_status(webview, "Copied image to clipboard");
                } else {
                    push_status(webview, "Failed to set image");
                }
            }
        }
        ClipboardContent::SyncedImage(r) => {
            push_status(
                webview,
                &format!("Synced image {}x{} - on server", r.width, r.height),
            );
        }
        ClipboardContent::Empty => {
            push_status(webview, "Nothing to copy");
        }
    }
}

// ---------------------------------------------------------------------------
// Push data to WebView
// ---------------------------------------------------------------------------

/// Spawn a background thread to load entries from DB.
fn spawn_load_entries(
    bg_store: &Arc<Mutex<Store>>,
    proxy: &tao::event_loop::EventLoopProxy<AppEvent>,
    search: Option<String>,
) {
    let store = bg_store.clone();
    let proxy = proxy.clone();
    std::thread::spawn(move || {
        let store = store.lock().unwrap();
        let entries = if let Some(ref q) = search {
            if q.is_empty() {
                store.list_metadata(500, 0).unwrap_or_default()
            } else {
                store.search_metadata(q).unwrap_or_default()
            }
        } else {
            store.list_metadata(500, 0).unwrap_or_default()
        };
        let total = store.count().unwrap_or(0);
        let _ = proxy.send_event(AppEvent::EntriesLoaded { entries, total });
    });
}

/// Push a page of entries to the WebView.
/// `offset == 0` means fresh load (replace); `offset > 0` means append more.
fn push_entries(webview: &wry::WebView, manager: &mut EntryManager) {
    let all: Vec<serde_json::Value> = manager
        .entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "content_type": e.content_type,
                "preview": e.preview,
                "byte_size": e.byte_size,
                "created_at": e.created_at.to_rfc3339(),
                "source": match e.source {
                    EntrySource::Local => "local",
                    EntrySource::Remote => "remote",
                },
                "pinned": e.pinned,
            })
        })
        .collect();

    let data = serde_json::json!({
        "entries": all,
        "total": manager.total_count,
        "ws_status": match manager.ws_status {
            ConnectionStatus::Connected => "connected",
            ConnectionStatus::Connecting => "connecting",
            ConnectionStatus::Disconnected => "disconnected",
        },
    });

    let _ = webview.evaluate_script(&format!("onEntries({})", data));
}

/// Push just the newest entry to the WebView (prepend without full rebuild).
fn push_new_entry(webview: &wry::WebView, manager: &EntryManager) {
    let Some(entry) = manager.entries.first() else {
        return;
    };
    let data = serde_json::json!({
        "id": entry.id,
        "content_type": entry.content_type,
        "preview": entry.preview,
        "byte_size": entry.byte_size,
        "created_at": entry.created_at.to_rfc3339(),
        "source": match entry.source {
            EntrySource::Local => "local",
            EntrySource::Remote => "remote",
        },
        "pinned": entry.pinned,
        "total": manager.total_count,
    });
    let _ = webview.evaluate_script(&format!("onNewEntry({})", data));
}

fn push_status(webview: &wry::WebView, msg: &str) {
    let escaped = msg.replace('\\', "\\\\").replace('\'', "\\'");
    let _ = webview.evaluate_script(&format!("onStatus('{escaped}')"));
}

// ---------------------------------------------------------------------------
// Build content JSON for preview
// ---------------------------------------------------------------------------

fn build_content_json(entry: &ClipboardEntry) -> String {
    let content = entry.to_clipboard_content();
    let mut resp = serde_json::json!({
        "id": entry.id,
        "content_type": entry.content_type,
        "byte_size": entry.byte_size,
    });

    // Cap text to 100KB to avoid pushing huge payloads to WebView.
    const MAX_PREVIEW_TEXT: usize = 100_000;
    let truncate = |s: String| -> String {
        if s.len() > MAX_PREVIEW_TEXT {
            let end = s.floor_char_boundary(MAX_PREVIEW_TEXT);
            format!("{}...\n\n(truncated, {} bytes total)", &s[..end], s.len())
        } else {
            s
        }
    };

    match content {
        Some(ClipboardContent::Text(t)) => {
            resp["text"] = serde_json::Value::String(truncate(t));
        }
        Some(ClipboardContent::Url(u)) => {
            resp["text"] = serde_json::Value::String(u);
        }
        Some(ClipboardContent::Files(paths)) => {
            let files: Vec<serde_json::Value> = paths
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "path": p.to_string_lossy(),
                        "exists": p.exists(),
                    })
                })
                .collect();
            resp["files"] = serde_json::Value::Array(files);
        }
        Some(ClipboardContent::SyncedFiles(refs)) => {
            let files: Vec<serde_json::Value> = refs
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "filename": r.filename,
                        "size": r.size,
                    })
                })
                .collect();
            resp["synced_files"] = serde_json::Value::Array(files);
        }
        Some(ClipboardContent::Image(info)) => {
            resp["image"] = serde_json::json!({
                "width": info.width,
                "height": info.height,
                "format": format!("{:?}", info.format),
                "size": info.data_size,
                "bits_per_pixel": info.bits_per_pixel,
                "has_data": info.raw_data.is_some(),
            });
            // Image data is loaded lazily via "get_image" IPC to avoid blocking.
        }
        Some(ClipboardContent::SyncedImage(r)) => {
            resp["synced_image"] = serde_json::json!({
                "width": r.width,
                "height": r.height,
                "format": format!("{:?}", r.format),
                "size": r.size,
                "image_id": r.image_id,
            });
        }
        _ => {
            resp["text"] = serde_json::Value::String("(empty)".to_string());
        }
    }

    serde_json::to_string(&resp).unwrap_or_default()
}

/// Encode image to PNG data URL (expensive — run on background thread).
fn encode_image_data_url(info: &o_clip_core::clipboard::content::ImageInfo) -> Option<String> {
    let img = info.to_dynamic_image()?;
    let mut buf = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut buf);
    use image::ImageEncoder;
    encoder
        .write_image(
            img.to_rgba8().as_raw(),
            img.width(),
            img.height(),
            image::ExtendedColorType::Rgba8,
        )
        .ok()?;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
    Some(format!("data:image/png;base64,{b64}"))
}

// ---------------------------------------------------------------------------
// System tray
// ---------------------------------------------------------------------------

/// Tray menu item IDs for event handling.
struct TrayMenuIds {
    autostart_id: tray_icon::menu::MenuId,
    quit_id: tray_icon::menu::MenuId,
}

fn create_tray_icon() -> Result<(tray_icon::TrayIcon, TrayMenuIds), Box<dyn std::error::Error>> {
    use tray_icon::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};

    // Generate a simple 32x32 clipboard icon (blue body + lighter clip).
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            let in_body = x >= 6 && x < 26 && y >= 8 && y < 30;
            let in_clip = x >= 11 && x < 21 && y >= 3 && y < 12;
            if in_body {
                rgba[i] = 89;
                rgba[i + 1] = 180;
                rgba[i + 2] = 250;
                rgba[i + 3] = 255;
            } else if in_clip {
                rgba[i] = 180;
                rgba[i + 1] = 210;
                rgba[i + 2] = 255;
                rgba[i + 3] = 255;
            }
        }
    }
    let icon = tray_icon::Icon::from_rgba(rgba, size, size)?;

    let autostart_enabled = is_autostart_enabled();
    let autostart = CheckMenuItem::new("Start on Boot", true, autostart_enabled, None);
    let quit = MenuItem::new("Quit", true, None);

    let menu = Menu::new();
    menu.append(&autostart)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&quit)?;

    let ids = TrayMenuIds {
        autostart_id: autostart.id().clone(),
        quit_id: quit.id().clone(),
    };

    let tray = TrayIconBuilder::new()
        .with_tooltip("o-clip")
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .build()?;

    Ok((tray, ids))
}

// ---------------------------------------------------------------------------
// Position window near tray icon
// ---------------------------------------------------------------------------

fn position_window(window: &tao::window::Window, event: &tray_icon::TrayIconEvent) {
    let (pos, rect) = match event {
        tray_icon::TrayIconEvent::Click { position, rect, .. } => (position, rect),
        _ => return,
    };

    let win_size = window.inner_size();

    let win_w = win_size.width as f64;
    let win_h = win_size.height as f64;

    #[cfg(target_os = "windows")]
    {
        // Place above the tray icon area.
        let x: f64 = rect.position.x - win_w / 2.0 + rect.size.width as f64 / 2.0;
        let y: f64 = rect.position.y - win_h;
        window.set_outer_position(PhysicalPosition::new(x.max(0.0), y.max(0.0)));
    }

    #[cfg(target_os = "macos")]
    {
        // Place below the menu bar item.
        let x: f64 = pos.x - win_w / 2.0;
        let y: f64 = pos.y + 8.0;
        window.set_outer_position(PhysicalPosition::new(x.max(0.0), y));
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let _ = (pos, rect, win_w, win_h);
    }
}

// ---------------------------------------------------------------------------
// Spawn clipboard monitor
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
    use std::sync::atomic::AtomicBool;
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::spawn(move || {
        o_clip_core::clipboard::monitor_mac::run_mac_monitor(clip_tx, stop);
    })
}

// ---------------------------------------------------------------------------
// Spawn tokio runtime for WS sync + file transfer
// ---------------------------------------------------------------------------

fn spawn_sync_runtime(
    config: &Config,
    ws_outbound_rx: tokio::sync::mpsc::UnboundedReceiver<SyncCommand>,
    ws_outbound_tx: tokio::sync::mpsc::UnboundedSender<SyncCommand>,
    ws_event_tx: std::sync::mpsc::Sender<SyncEvent>,
    mut file_req_rx: tokio::sync::mpsc::UnboundedReceiver<FileRequest>,
    file_resp_tx: std::sync::mpsc::Sender<FileResponse>,
    reconnect_notify: Arc<tokio::sync::Notify>,
) {
    if !config.has_server() || !config.server.auto_connect {
        return;
    }

    let ws_url = config.server.url.clone();
    let accept_invalid_certs = config.server.accept_invalid_certs;
    let ws_password = config.server.password.clone();
    let max_file_sync_size = config.server.max_file_sync_size;
    let download_dir = config.download_dir();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("failed to build tokio runtime");

        let file_client = Arc::new(FileTransferClient::new(
            &ws_url,
            ws_password.clone(),
            accept_invalid_certs,
            max_file_sync_size,
            download_dir,
        ));

        let fc = file_client.clone();
        let ws_tx = ws_outbound_tx;
        let resp_tx = file_resp_tx;
        rt.spawn(async move {
            let mut recent_downloads: HashMap<String, Instant> = HashMap::new();
            while let Some(req) = file_req_rx.recv().await {
                match req {
                    FileRequest::Upload { mut entry, paths } => {
                        match fc.upload_files(&paths).await {
                            Ok(file_refs) => {
                                let synced = ClipboardContent::SyncedFiles(file_refs);
                                entry.content = serde_json::to_string(&synced).unwrap_or_default();
                                entry.hash = synced.content_hash();
                                entry.byte_size = synced.byte_size() as i64;
                                entry.preview = synced.preview(120);
                                let _ = ws_tx.send(SyncCommand::SendEntry(entry));
                            }
                            Err(e) => tracing::warn!("file upload failed: {e}"),
                        }
                    }
                    FileRequest::Download { refs } => {
                        let key = download_files_key(&refs);
                        recent_downloads.retain(|_, ts| ts.elapsed() < FILE_DOWNLOAD_DEDUP_TTL);
                        if recent_downloads.contains_key(&key) {
                            tracing::debug!("skipping duplicate file download: {key}");
                            continue;
                        }
                        recent_downloads.insert(key.clone(), Instant::now());
                        match fc.download_files(&refs).await {
                            Ok(local_paths) => {
                                let _ = resp_tx.send(FileResponse::Downloaded(local_paths));
                            }
                            Err(e) => {
                                recent_downloads.remove(&key);
                                tracing::warn!("file download failed: {e}");
                                let _ = resp_tx.send(FileResponse::Error(format!(
                                    "File download failed: {e}"
                                )));
                            }
                        }
                    }
                    FileRequest::UploadImage { mut entry, info } => {
                        match fc.upload_image(&info).await {
                            Ok(img_ref) => {
                                let synced = ClipboardContent::SyncedImage(img_ref);
                                entry.content = serde_json::to_string(&synced).unwrap_or_default();
                                entry.hash = synced.content_hash();
                                entry.byte_size = synced.byte_size() as i64;
                                entry.preview = synced.preview(120);
                                let _ = ws_tx.send(SyncCommand::SendEntry(entry));
                            }
                            Err(e) => tracing::warn!("image upload failed: {e}"),
                        }
                    }
                    FileRequest::DownloadImage { img_ref } => {
                        let key = download_image_key(&img_ref);
                        recent_downloads.retain(|_, ts| ts.elapsed() < FILE_DOWNLOAD_DEDUP_TTL);
                        if recent_downloads.contains_key(&key) {
                            tracing::debug!("skipping duplicate image download: {key}");
                            continue;
                        }
                        recent_downloads.insert(key.clone(), Instant::now());
                        match fc.download_image(&img_ref).await {
                            Ok(info) => {
                                let _ = resp_tx.send(FileResponse::ImageDownloaded(info));
                            }
                            Err(e) => {
                                recent_downloads.remove(&key);
                                tracing::warn!("image download failed: {e}");
                                let _ = resp_tx.send(FileResponse::Error(format!(
                                    "Image download failed: {e}"
                                )));
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
            reconnect_notify,
        ));
    });
}

// ---------------------------------------------------------------------------
// Platform-specific cleanup
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
    // macOS monitor checks AtomicBool; process exit will stop it.
}

// ---------------------------------------------------------------------------
// Auto-start on boot
// ---------------------------------------------------------------------------

const APP_NAME: &str = "o-clip";

#[cfg(target_os = "windows")]
fn is_autostart_enabled() -> bool {
    use windows::Win32::System::Registry::*;
    use windows::core::HSTRING;

    let key_path = HSTRING::from("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let mut hkey = HKEY::default();

    let result =
        unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, &key_path, Some(0), KEY_READ, &mut hkey) };
    if result.is_err() {
        return false;
    }

    let value_name = HSTRING::from(APP_NAME);
    let result = unsafe { RegQueryValueExW(hkey, &value_name, None, None, None, None) };
    let _ = unsafe { RegCloseKey(hkey) };
    result.is_ok()
}

#[cfg(target_os = "windows")]
fn set_autostart(enable: bool) -> bool {
    use windows::Win32::System::Registry::*;
    use windows::core::HSTRING;

    let key_path = HSTRING::from("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let mut hkey = HKEY::default();

    let result = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            &key_path,
            Some(0),
            KEY_SET_VALUE,
            &mut hkey,
        )
    };
    if result.is_err() {
        tracing::warn!("failed to open registry key for autostart");
        return false;
    }

    let value_name = HSTRING::from(APP_NAME);
    let success = if enable {
        // Get the path to the current executable.
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => {
                let _ = unsafe { RegCloseKey(hkey) };
                return false;
            }
        };
        let exe_str = exe_path.to_string_lossy();
        // Write as REG_SZ (wide string, null-terminated).
        let wide: Vec<u16> = exe_str.encode_utf16().chain(std::iter::once(0)).collect();
        let data =
            unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
        let result = unsafe { RegSetValueExW(hkey, &value_name, Some(0), REG_SZ, Some(data)) };
        result.is_ok()
    } else {
        let result = unsafe { RegDeleteValueW(hkey, &value_name) };
        result.is_ok()
    };

    let _ = unsafe { RegCloseKey(hkey) };
    success
}

#[cfg(target_os = "macos")]
fn is_autostart_enabled() -> bool {
    let plist_path = macos_launch_agent_path();
    plist_path.exists()
}

#[cfg(target_os = "macos")]
fn set_autostart(enable: bool) -> bool {
    let plist_path = macos_launch_agent_path();

    if enable {
        let exe_path = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return false,
        };
        if let Some(parent) = plist_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let plist_content = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.o-clip.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>"#,
            exe_path.display()
        );
        std::fs::write(&plist_path, plist_content).is_ok()
    } else {
        std::fs::remove_file(&plist_path).is_ok()
    }
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    std::path::PathBuf::from(home).join("Library/LaunchAgents/com.o-clip.app.plist")
}
