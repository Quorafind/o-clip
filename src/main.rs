mod app;
mod clipboard;
mod config;
mod error;
mod store;
mod sync;
mod tui;
#[cfg(target_os = "windows")]
mod window;

use std::io;
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
#[cfg(target_os = "windows")]
use clipboard::ClipboardMonitor;
use clipboard::monitor::ClipboardEvent;
use config::{Cli, Config};
use store::{ClipboardEntry, EntrySource, Store};
use sync::SyncEvent;

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

    // Spawn tokio runtime for WebSocket sync
    let ws_url = config.server.url.clone();
    let accept_invalid_certs = config.server.accept_invalid_certs;
    let has_server = config.has_server() && config.server.auto_connect;
    let _rt_handle = std::thread::spawn(move || {
        if !has_server {
            return;
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(1)
            .build()
            .expect("failed to build tokio runtime");
        rt.block_on(sync::run_sync(
            ws_url,
            accept_invalid_certs,
            ws_outbound_rx,
            ws_event_tx,
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

    // Register Ctrl+C handler for graceful shutdown
    setup_ctrlc_handler();

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
                        KeyCode::Char('/') => app.enter_search(),
                        KeyCode::Char('r') => {
                            app.status_message = Some(
                                "WebSocket reconnect not yet supported via keybind".to_string(),
                            );
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
            let entry = ClipboardEntry::from_content(&event.content);
            // Send to WebSocket if: connected, not cloud-restricted, and within size limit
            if !event.no_cloud && (entry.byte_size as usize) <= max_sync_size {
                let _ = ws_outbound_tx.send(entry.clone());
            } else if (entry.byte_size as usize) > max_sync_size {
                tracing::debug!(
                    "skipping sync for large entry: {} bytes (limit {})",
                    entry.byte_size,
                    max_sync_size
                );
            }
            app.on_new_entry(entry);
        }

        // Process WebSocket events (non-blocking)
        while let Ok(ws_event) = ws_event_rx.try_recv() {
            match ws_event {
                SyncEvent::RemoteEntry(mut entry) => {
                    entry.source = EntrySource::Remote;
                    // Auto-copy remote entry to local clipboard (without re-uploading)
                    auto_copy_to_clipboard(&entry);
                    app.on_new_entry(entry);
                }
                SyncEvent::SyncBatch(entries) => {
                    for mut entry in entries {
                        entry.source = EntrySource::Remote;
                        app.on_new_entry(entry);
                    }
                }
                SyncEvent::StatusChanged(status) => {
                    app.ws_status = status;
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
// Auto-copy a remote entry to the local clipboard.
// Uses mark_self_write() so the clipboard monitor ignores the change and
// the entry is NOT re-uploaded to the server.
// ---------------------------------------------------------------------------

fn auto_copy_to_clipboard(entry: &ClipboardEntry) {
    use crate::clipboard::ClipboardContent;

    let Some(content) = entry.to_clipboard_content() else {
        return;
    };

    clipboard::mark_self_write();

    match &content {
        ClipboardContent::Text(t) => {
            app::set_clipboard_text_public(t);
        }
        ClipboardContent::Url(u) => {
            app::set_clipboard_text_public(u);
        }
        ClipboardContent::Files(paths) => {
            app::set_clipboard_files_public(paths);
        }
        ClipboardContent::Image(info) => {
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
