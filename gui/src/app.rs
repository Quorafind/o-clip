use native_windows_derive::NwgUi;
use native_windows_gui as nwg;
use nwg::NativeUi;

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use chrono::Local;
use o_clip_core::clipboard::{self, ClipboardContent, ClipboardEvent};
use o_clip_core::config::Config;
use o_clip_core::entry_manager::EntryManager;
use o_clip_core::file_transfer::{FileRequest, FileResponse, FileTransferClient};
use o_clip_core::store::{ClipboardEntry, EntrySource, Store};
use o_clip_core::sync::{ConnectionStatus, SyncCommand, SyncEvent};

use crate::theme;

#[cfg(target_os = "windows")]
use o_clip_core::clipboard::ClipboardMonitor;

const PADDING: i32 = 8;
const GAP: i32 = 8;
const SEARCH_H: i32 = 28;
const STATUS_MIN_H: u32 = 24;

const CHANNEL_TICK_MS: u64 = 100;
const REMOTE_HASH_TTL: Duration = Duration::from_secs(10);

const SETTINGS_PAD: i32 = 12;
const SETTINGS_ROW_H: i32 = 28;
const SETTINGS_ROW_GAP: i32 = 8;
const SETTINGS_ROW: i32 = SETTINGS_ROW_H + SETTINGS_ROW_GAP;
const SETTINGS_LABEL_W: i32 = 180;
const SETTINGS_INPUT_H: i32 = 24;
const SETTINGS_INPUT_W: i32 = 320;
const SETTINGS_INPUT_X: i32 = SETTINGS_PAD + SETTINGS_LABEL_W + GAP;

/// Keyboard shortcut actions posted from raw event handlers.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum KeyAction {
    FocusSearch,
    Quit,
    Pin,
    Reconnect,
    Settings,
    Delete,
    CopySelected,
    Refetch,
}

#[derive(Default)]
struct AppState {
    config: Option<Config>,
    manager: Option<EntryManager>,
    row_entry_ids: Vec<i64>,
    suppress_events: bool,

    // Background channels (drained by the GUI thread on a timer tick)
    clip_rx: Option<std::sync::mpsc::Receiver<ClipboardEvent>>,
    ws_event_rx: Option<std::sync::mpsc::Receiver<SyncEvent>>,
    file_resp_rx: Option<std::sync::mpsc::Receiver<FileResponse>>,

    // Keyboard action queue (from raw event handlers)
    key_rx: Option<std::sync::mpsc::Receiver<KeyAction>>,

    // Senders into the tokio runtime thread
    ws_outbound_tx: Option<tokio::sync::mpsc::UnboundedSender<SyncCommand>>,
    file_req_tx: Option<tokio::sync::mpsc::UnboundedSender<FileRequest>>,
    reconnect_notify: Option<Arc<Notify>>,

    // Dedup cache: pixel-based content hash -> Instant when it was auto-copied.
    recent_remote_hashes: HashMap<String, Instant>,
}

#[derive(Default, NwgUi)]
pub struct App {
    // ---- Fonts -------------------------------------------------------------
    #[nwg_resource(family: "Segoe UI", size: 18)]
    font_normal: nwg::Font,

    #[nwg_resource(family: "Consolas", size: 17)]
    font_preview: nwg::Font,

    #[nwg_control(size: (1000, 700), position: (200, 200), title: "o-clip", flags: "WINDOW|VISIBLE")]
    #[nwg_events(OnInit: [App::init], OnResize: [App::layout], OnWindowClose: [App::on_main_window_close(SELF, EVT_DATA)])]
    window: nwg::Window,

    // ---- Menu bar ---------------------------------------------------------
    #[nwg_control(parent: window, text: "&File")]
    file_menu: nwg::Menu,

    #[nwg_control(parent: file_menu, text: "&Settings...\tCtrl+,")]
    #[nwg_events(OnMenuItemSelected: [App::show_settings])]
    file_settings: nwg::MenuItem,

    #[nwg_control(parent: file_menu)]
    file_sep: nwg::MenuSeparator,

    #[nwg_control(parent: file_menu, text: "E&xit\tCtrl+Q")]
    #[nwg_events(OnMenuItemSelected: [App::exit])]
    file_exit: nwg::MenuItem,

    #[nwg_control(parent: window, text: "&Edit")]
    edit_menu: nwg::Menu,

    #[nwg_control(parent: edit_menu, text: "&Copy\tEnter")]
    #[nwg_events(OnMenuItemSelected: [App::copy_selected])]
    edit_copy: nwg::MenuItem,

    #[nwg_control(parent: edit_menu, text: "&Delete\tDel")]
    #[nwg_events(OnMenuItemSelected: [App::delete_selected])]
    edit_delete: nwg::MenuItem,

    #[nwg_control(parent: edit_menu, text: "&Pin\tCtrl+P")]
    #[nwg_events(OnMenuItemSelected: [App::pin_selected])]
    edit_pin: nwg::MenuItem,

    #[nwg_control(parent: edit_menu)]
    edit_sep: nwg::MenuSeparator,

    #[nwg_control(parent: edit_menu, text: "&Search\tCtrl+F")]
    #[nwg_events(OnMenuItemSelected: [App::focus_search])]
    edit_search: nwg::MenuItem,

    #[nwg_control(parent: edit_menu)]
    edit_sep2: nwg::MenuSeparator,

    #[nwg_control(parent: edit_menu, text: "Clear &All")]
    #[nwg_events(OnMenuItemSelected: [App::clear_all])]
    edit_clear_all: nwg::MenuItem,

    #[nwg_control(parent: window, text: "&Connection")]
    conn_menu: nwg::Menu,

    #[nwg_control(parent: conn_menu, text: "&Reconnect\tCtrl+R")]
    #[nwg_events(OnMenuItemSelected: [App::reconnect])]
    conn_reconnect: nwg::MenuItem,

    // ---- Tray -------------------------------------------------------------
    #[nwg_resource(source_system: Some(nwg::OemIcon::Information))]
    tray_icon: nwg::Icon,

    #[nwg_control(parent: window, icon: Some(&data.tray_icon), tip: Some("o-clip"))]
    #[nwg_events(MousePressLeftUp: [App::tray_restore], OnContextMenu: [App::tray_show_menu])]
    tray: nwg::TrayNotification,

    #[nwg_control(parent: window, popup: true)]
    tray_menu: nwg::Menu,

    #[nwg_control(parent: tray_menu, text: "Show")]
    #[nwg_events(OnMenuItemSelected: [App::tray_restore])]
    tray_menu_show: nwg::MenuItem,

    #[nwg_control(parent: tray_menu, text: "Exit")]
    #[nwg_events(OnMenuItemSelected: [App::exit])]
    tray_menu_exit: nwg::MenuItem,

    // ---- Background polling timer -----------------------------------------
    #[nwg_control(parent: window, interval: std::time::Duration::from_millis(CHANNEL_TICK_MS), active: false)]
    #[nwg_events(OnTimerTick: [App::on_timer_tick])]
    timer: nwg::AnimationTimer,

    // ---- Search bar -------------------------------------------------------
    #[nwg_control(parent: window, text: "Search:", position: (PADDING, PADDING + 4), size: (60, 20))]
    search_label: nwg::Label,

    #[nwg_control(parent: window, font: Some(&data.font_normal), placeholder_text: Some("Type to filter..."), position: (PADDING + 60 + GAP, PADDING), size: (400, SEARCH_H))]
    #[nwg_events(OnTextInput: [App::on_search_input])]
    search_input: nwg::TextInput,

    // ---- Main split: list + preview --------------------------------------
    #[nwg_control(
        parent: window,
        position: (PADDING, PADDING + SEARCH_H + PADDING),
        size: (380, 520),
        focus: true,
        list_style: nwg::ListViewStyle::Detailed,
        ex_flags: nwg::ListViewExFlags::GRID | nwg::ListViewExFlags::FULL_ROW_SELECT,
        flags: "VISIBLE|SINGLE_SELECTION|ALWAYS_SHOW_SELECTION"
    )]
    #[nwg_events(
        OnListViewItemChanged: [App::on_list_view_item_changed(SELF, EVT_DATA)],
        OnListViewItemActivated: [App::on_list_view_item_activated(SELF, EVT_DATA)],
        OnListViewRightClick: [App::on_list_view_right_click(SELF, EVT_DATA)]
    )]
    list_view: nwg::ListView,

    #[nwg_control(
        parent: window,
        position: (PADDING + 380 + GAP, PADDING + SEARCH_H + PADDING),
        size: (560, 520),
        font: Some(&data.font_preview),
        flags: "VISIBLE|VSCROLL|AUTOVSCROLL",
        readonly: true
    )]
    preview_text: nwg::RichTextBox,

    #[nwg_control(
        parent: window,
        position: (PADDING + 380 + GAP, PADDING + SEARCH_H + PADDING),
        size: (560, 520)
    )]
    preview_image: nwg::ImageFrame,

    // ---- Status bar (Label for dark-theme support) -------------------------
    #[nwg_control(parent: window, text: "  WS: Disconnected", font: Some(&data.font_normal), position: (0, 670), size: (1000, 24))]
    status: nwg::Label,

    // ---- Context menu (ListView) -----------------------------------------
    #[nwg_control(parent: window, popup: true)]
    list_menu: nwg::Menu,

    #[nwg_control(parent: list_menu, text: "Copy")]
    #[nwg_events(OnMenuItemSelected: [App::copy_selected])]
    list_menu_copy: nwg::MenuItem,

    #[nwg_control(parent: list_menu, text: "Delete")]
    #[nwg_events(OnMenuItemSelected: [App::delete_selected])]
    list_menu_delete: nwg::MenuItem,

    #[nwg_control(parent: list_menu, text: "Pin")]
    #[nwg_events(OnMenuItemSelected: [App::pin_selected])]
    list_menu_pin: nwg::MenuItem,

    // ---- Settings dialog ---------------------------------------------------
    #[nwg_control(size: (640, 420), title: "Settings", flags: "WINDOW", center: true)]
    #[nwg_events(OnWindowClose: [App::on_settings_window_close(SELF, EVT_DATA)])]
    settings_window: nwg::Window,

    #[nwg_resource(title: "Select download directory", action: nwg::FileDialogAction::OpenDirectory)]
    download_dir_dialog: nwg::FileDialog,

    #[nwg_control(parent: settings_window, text: "Server URL:", position: (SETTINGS_PAD, SETTINGS_PAD + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_url_label: nwg::Label,
    #[nwg_control(parent: settings_window, position: (SETTINGS_INPUT_X, SETTINGS_PAD), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_url_input: nwg::TextInput,

    #[nwg_control(parent: settings_window, text: "Password:", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_password_label: nwg::Label,
    #[nwg_control(parent: settings_window, password: Some('*'), position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_password_input: nwg::TextInput,

    #[nwg_control(parent: settings_window, text: "Auto-connect", position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 2), size: (160, SETTINGS_INPUT_H))]
    settings_auto_connect: nwg::CheckBox,
    #[nwg_control(parent: settings_window, text: "Accept invalid certs", position: (SETTINGS_INPUT_X + 170, SETTINGS_PAD + SETTINGS_ROW * 2), size: (200, SETTINGS_INPUT_H))]
    settings_accept_invalid_certs: nwg::CheckBox,

    #[nwg_control(parent: settings_window, text: "Max sync size (bytes):", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW * 3 + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_max_sync_size_label: nwg::Label,
    #[nwg_control(parent: settings_window, position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 3), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_max_sync_size: nwg::TextInput,

    #[nwg_control(parent: settings_window, text: "Max file sync size (bytes):", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW * 4 + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_max_file_sync_size_label: nwg::Label,
    #[nwg_control(parent: settings_window, position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 4), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_max_file_sync_size: nwg::TextInput,

    #[nwg_control(parent: settings_window, text: "Image inline threshold (bytes):", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW * 5 + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_image_inline_threshold_label: nwg::Label,
    #[nwg_control(parent: settings_window, position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 5), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_image_inline_threshold: nwg::TextInput,

    #[nwg_control(parent: settings_window, text: "Max entries:", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW * 6 + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_max_entries_label: nwg::Label,
    #[nwg_control(parent: settings_window, position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 6), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_max_entries: nwg::TextInput,

    #[nwg_control(parent: settings_window, text: "Download dir:", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW * 7 + 4), size: (SETTINGS_LABEL_W, 20))]
    settings_download_dir_label: nwg::Label,
    #[nwg_control(parent: settings_window, position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 7), size: (SETTINGS_INPUT_W, SETTINGS_INPUT_H))]
    settings_download_dir: nwg::TextInput,
    #[nwg_control(parent: settings_window, text: "Browse...", position: (SETTINGS_INPUT_X + SETTINGS_INPUT_W + GAP, SETTINGS_PAD + SETTINGS_ROW * 7), size: (96, SETTINGS_INPUT_H))]
    #[nwg_events(OnButtonClick: [App::browse_download_dir])]
    settings_download_dir_browse: nwg::Button,

    #[nwg_control(parent: settings_window, text: "Save", position: (SETTINGS_INPUT_X, SETTINGS_PAD + SETTINGS_ROW * 8), size: (96, 28))]
    #[nwg_events(OnButtonClick: [App::save_settings])]
    settings_save: nwg::Button,
    #[nwg_control(parent: settings_window, text: "Cancel", position: (SETTINGS_INPUT_X + 110, SETTINGS_PAD + SETTINGS_ROW * 8), size: (96, 28))]
    #[nwg_events(OnButtonClick: [App::cancel_settings])]
    settings_cancel: nwg::Button,

    #[nwg_control(parent: settings_window, text: "Note: Connection changes require restart.", position: (SETTINGS_PAD, SETTINGS_PAD + SETTINGS_ROW * 9), size: (620, 20))]
    settings_note: nwg::Label,

    state: RefCell<AppState>,

    // Raw event handler for keyboard shortcuts (must be stored to keep it alive).
    raw_handler: RefCell<Option<nwg::RawEventHandler>>,

    // Theme raw event handlers (dark mode).
    theme_handler: RefCell<Option<nwg::RawEventHandler>>,
    settings_theme_handler: RefCell<Option<nwg::RawEventHandler>>,
}

impl App {
    fn init(&self) {
        self.preview_image.set_visible(false);

        // Remove the sunken 3D border (WS_EX_CLIENTEDGE) from the preview panel.
        Self::remove_client_edge(&self.preview_text.handle);

        self.apply_theme();
        self.init_list_view();
        self.layout();

        if let Err(msg) = self.init_core_state() {
            nwg::modal_error_message(&self.window, "o-clip", &msg);
            self.exit();
            return;
        }

        self.init_keyboard_shortcuts();

        self.refresh_list(None);
        self.timer.start();
    }

    fn init_list_view(&self) {
        if self.list_view.column_len() == 0 {
            self.list_view.insert_column(nwg::InsertListViewColumn {
                index: Some(0),
                fmt: Some(nwg::ListViewColumnFlags::CENTER),
                width: Some(36),
                text: Some("Pin".to_string()),
            });
            self.list_view.insert_column(nwg::InsertListViewColumn {
                index: Some(1),
                fmt: Some(nwg::ListViewColumnFlags::LEFT),
                width: Some(80),
                text: Some("Time".to_string()),
            });
            self.list_view.insert_column(nwg::InsertListViewColumn {
                index: Some(2),
                fmt: Some(nwg::ListViewColumnFlags::CENTER),
                width: Some(30),
                text: Some("S".to_string()),
            });
            self.list_view.insert_column(nwg::InsertListViewColumn {
                index: Some(3),
                fmt: Some(nwg::ListViewColumnFlags::CENTER),
                width: Some(50),
                text: Some("Type".to_string()),
            });
            self.list_view.insert_column(nwg::InsertListViewColumn {
                index: Some(4),
                fmt: Some(nwg::ListViewColumnFlags::LEFT),
                width: Some(420),
                text: Some("Content".to_string()),
            });
            self.list_view.set_headers_enabled(true);
        }
    }

    fn init_keyboard_shortcuts(&self) {
        use windows::Win32::UI::WindowsAndMessaging::WM_KEYDOWN;

        let (key_tx, key_rx) = std::sync::mpsc::channel::<KeyAction>();
        self.state.borrow_mut().key_rx = Some(key_rx);

        let handler = nwg::bind_raw_event_handler(
            &self.window.handle,
            0xFFFF + 1,
            move |_hwnd, msg, wparam, _lparam| {
                if msg == WM_KEYDOWN {
                    let vk = wparam as u16;
                    let ctrl = unsafe {
                        windows::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState(
                            windows::Win32::UI::Input::KeyboardAndMouse::VK_CONTROL.0 as i32,
                        )
                    } < 0;

                    let action = match (ctrl, vk) {
                        (true, 0x46) => Some(KeyAction::FocusSearch), // Ctrl+F
                        (true, 0x51) => Some(KeyAction::Quit),        // Ctrl+Q
                        (true, 0x50) => Some(KeyAction::Pin),         // Ctrl+P
                        (true, 0x52) => Some(KeyAction::Reconnect),   // Ctrl+R
                        (true, 0xBC) => Some(KeyAction::Settings),    // Ctrl+,
                        (false, 0x2E) => Some(KeyAction::Delete),     // Del
                        (false, 0x74) => Some(KeyAction::Refetch),    // F5
                        _ => None,
                    };

                    if let Some(action) = action {
                        let _ = key_tx.send(action);
                    }
                }
                None
            },
        );

        if let Ok(h) = handler {
            *self.raw_handler.borrow_mut() = Some(h);
        }
    }

    fn process_key_actions(&self) {
        let key_rx = self.state.borrow_mut().key_rx.take();
        if let Some(rx) = key_rx.as_ref() {
            while let Ok(action) = rx.try_recv() {
                match action {
                    KeyAction::FocusSearch => self.focus_search(),
                    KeyAction::Quit => self.exit(),
                    KeyAction::Pin => self.pin_selected(),
                    KeyAction::Reconnect => self.reconnect(),
                    KeyAction::Settings => self.show_settings(),
                    KeyAction::Delete => self.delete_selected(),
                    KeyAction::CopySelected => self.copy_selected(),
                    KeyAction::Refetch => self.refetch_selected_files(),
                }
            }
        }
        self.state.borrow_mut().key_rx = key_rx;
    }

    fn layout(&self) {
        let (w, h) = self.window.size();
        let w = w as i32;
        let h = h as i32;

        let search_y = PADDING;
        let search_label_w = 60;
        let search_x = PADDING;
        let search_input_x = search_x + search_label_w + GAP;
        let search_input_w = (w - search_input_x - PADDING).max(120);

        self.search_label.set_position(search_x, search_y + 4);
        self.search_label.set_size(search_label_w as u32, 20);
        self.search_input.set_position(search_input_x, search_y);
        self.search_input
            .set_size(search_input_w as u32, SEARCH_H as u32);

        let main_y = search_y + SEARCH_H + PADDING;
        let main_h = (h - main_y - (STATUS_MIN_H as i32) - PADDING).max(100);

        let list_w = ((w as f32) * 0.40) as i32;
        let list_w = list_w.clamp(260, (w - 260).max(260));
        let preview_x = PADDING + list_w + GAP;
        let preview_w = (w - preview_x - PADDING).max(200);

        self.list_view.set_position(PADDING, main_y);
        self.list_view.set_size(list_w as u32, main_h as u32);

        self.preview_text.set_position(preview_x, main_y);
        self.preview_text.set_size(preview_w as u32, main_h as u32);

        self.preview_image.set_position(preview_x, main_y);
        self.preview_image.set_size(preview_w as u32, main_h as u32);

        if self.list_view.column_len() >= 5 {
            let pin_w = 36;
            let time_w = 80;
            let src_w = 30;
            let ty_w = 50;
            let other_w = pin_w + time_w + src_w + ty_w;
            let content_w = (list_w - other_w - 24).max(80);

            self.list_view.set_column_width(0, pin_w as isize);
            self.list_view.set_column_width(1, time_w as isize);
            self.list_view.set_column_width(2, src_w as isize);
            self.list_view.set_column_width(3, ty_w as isize);
            self.list_view.set_column_width(4, content_w as isize);
        }

        // Status label at the bottom
        let status_h = STATUS_MIN_H as i32;
        let status_y = h - status_h;
        self.status.set_position(0, status_y);
        self.status.set_size(w as u32, status_h as u32);
    }

    /// Remove WS_EX_CLIENTEDGE from a control to eliminate the sunken 3D border.
    fn remove_client_edge(handle: &nwg::ControlHandle) {
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::WindowsAndMessaging::{
            GWL_EXSTYLE, GetWindowLongW, SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER,
            SetWindowLongW, SetWindowPos, WS_EX_CLIENTEDGE,
        };

        let Some(hwnd) = handle.hwnd() else { return };
        let hwnd = HWND(hwnd as _);
        unsafe {
            let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE);
            let new_style = ex_style & !(WS_EX_CLIENTEDGE.0 as i32);
            if new_style != ex_style {
                SetWindowLongW(hwnd, GWL_EXSTYLE, new_style);
                let _ = SetWindowPos(
                    hwnd,
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER,
                );
            }
        }
    }

    // ── Dark theme ──────────────────────────────────────────────────────

    fn apply_theme(&self) {
        use windows::Win32::Foundation::{HWND, LPARAM, RECT, WPARAM};
        use windows::Win32::Graphics::Gdi::{
            CreateSolidBrush, FillRect, HBRUSH, HDC, SetBkColor, SetBkMode, SetTextColor,
            TRANSPARENT,
        };
        use windows::Win32::UI::WindowsAndMessaging::{
            SendMessageW, WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_ERASEBKGND,
            WM_NOTIFY,
        };

        // --- Dark title bar ---
        if let Some(hwnd) = self.window.handle.hwnd() {
            theme::set_dark_title_bar(hwnd as isize);
        }

        // --- ListView: dark explorer theme + colors + row height ---
        if let Some(hwnd) = self.list_view.handle.hwnd() {
            theme::set_dark_explorer_theme(hwnd as isize);
            let hwnd = HWND(hwnd as _);
            unsafe {
                SendMessageW(
                    hwnd,
                    theme::LVM_SETBKCOLOR,
                    Some(WPARAM(0)),
                    Some(LPARAM(theme::BG_WINDOW.0 as isize)),
                );
                SendMessageW(
                    hwnd,
                    theme::LVM_SETTEXTBKCOLOR,
                    Some(WPARAM(0)),
                    Some(LPARAM(theme::BG_WINDOW.0 as isize)),
                );
                SendMessageW(
                    hwnd,
                    theme::LVM_SETTEXTCOLOR,
                    Some(WPARAM(0)),
                    Some(LPARAM(theme::FG_PRIMARY.0 as isize)),
                );

                // Header control dark theme
                let header =
                    SendMessageW(hwnd, theme::LVM_GETHEADER, Some(WPARAM(0)), Some(LPARAM(0)));
                if header.0 != 0 {
                    theme::set_dark_explorer_theme(header.0);
                }

                // Increase row height via image list trick
                let himl =
                    theme::ImageList_Create(1, theme::LIST_ROW_HEIGHT, theme::ILC_COLOR32, 1, 0);
                if himl != 0 {
                    SendMessageW(
                        hwnd,
                        theme::LVM_SETIMAGELIST,
                        Some(WPARAM(theme::LVSIL_SMALL)),
                        Some(LPARAM(himl)),
                    );
                }
            }
        }

        // --- RichTextBox: dark background + scrollbars ---
        if let Some(hwnd) = self.preview_text.handle.hwnd() {
            theme::set_dark_explorer_theme(hwnd as isize);
            let hwnd = HWND(hwnd as _);
            unsafe {
                SendMessageW(
                    hwnd,
                    theme::EM_SETBKGNDCOLOR,
                    Some(WPARAM(0)),
                    Some(LPARAM(theme::BG_WINDOW.0 as isize)),
                );
                // Set default character format (text color for new text)
                let cf = theme::make_charformat_color(theme::FG_PRIMARY);
                SendMessageW(
                    hwnd,
                    theme::EM_SETCHARFORMAT,
                    Some(WPARAM(theme::SCF_DEFAULT)),
                    Some(LPARAM(cf.as_ptr() as isize)),
                );
            }
        }

        // --- Dark mode for the window + flush menus ---
        if let Some(hwnd) = self.window.handle.hwnd() {
            theme::allow_dark_mode_for_window(hwnd as isize);
        }
        theme::flush_menu_themes();

        // --- Raw event handler: WM_ERASEBKGND + WM_CTLCOLOR* + NM_CUSTOMDRAW ---
        let brush_window: HBRUSH = unsafe { CreateSolidBrush(theme::BG_WINDOW) };
        let brush_input: HBRUSH = unsafe { CreateSolidBrush(theme::BG_INPUT) };
        let lv_hwnd_val: isize = self
            .list_view
            .handle
            .hwnd()
            .map(|h| h as isize)
            .unwrap_or(0);

        let handler = nwg::bind_raw_event_handler(
            &self.window.handle,
            0xFFFF + 2,
            move |_hwnd, msg, wparam, lparam| {
                match msg {
                    x if x == WM_ERASEBKGND => {
                        let hdc = HDC(wparam as *mut _);
                        let rc = RECT {
                            left: 0,
                            top: 0,
                            right: 32000,
                            bottom: 32000,
                        };
                        unsafe { FillRect(hdc, &rc, brush_window) };
                        Some(1)
                    }
                    x if x == WM_CTLCOLORSTATIC => {
                        let hdc = HDC(wparam as *mut _);
                        unsafe {
                            SetTextColor(hdc, theme::FG_PRIMARY);
                            SetBkMode(hdc, TRANSPARENT);
                        }
                        Some(brush_window.0 as isize)
                    }
                    x if x == WM_CTLCOLOREDIT => {
                        let hdc = HDC(wparam as *mut _);
                        unsafe {
                            SetTextColor(hdc, theme::FG_PRIMARY);
                            SetBkColor(hdc, theme::BG_INPUT);
                        }
                        Some(brush_input.0 as isize)
                    }
                    x if x == WM_CTLCOLORBTN => {
                        let hdc = HDC(wparam as *mut _);
                        unsafe {
                            SetTextColor(hdc, theme::FG_PRIMARY);
                            SetBkMode(hdc, TRANSPARENT);
                        }
                        Some(brush_window.0 as isize)
                    }
                    x if x == WM_NOTIFY => {
                        let nmhdr = unsafe { &*(lparam as *const theme::NmHdr) };
                        if nmhdr.hwnd_from == lv_hwnd_val && nmhdr.code == theme::NM_CUSTOMDRAW_CODE
                        {
                            let cd = unsafe { &mut *(lparam as *mut theme::NmLvCustomDraw) };
                            match cd.nmcd.draw_stage {
                                theme::CDDS_PREPAINT => Some(theme::CDRF_NOTIFYITEMDRAW),
                                theme::CDDS_ITEMPREPAINT => {
                                    let row = cd.nmcd.item_spec;
                                    if cd.nmcd.item_state & theme::CDIS_SELECTED != 0 {
                                        cd.clr_text = theme::FG_BRIGHT.0;
                                        cd.clr_text_bk = theme::BG_SELECTION.0;
                                    } else if row % 2 == 1 {
                                        cd.clr_text = theme::FG_PRIMARY.0;
                                        cd.clr_text_bk = theme::BG_LIST_ALT.0;
                                    } else {
                                        cd.clr_text = theme::FG_PRIMARY.0;
                                        cd.clr_text_bk = theme::BG_WINDOW.0;
                                    }
                                    Some(theme::CDRF_NEWFONT)
                                }
                                _ => Some(0), // CDRF_DODEFAULT
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            },
        );

        if let Ok(h) = handler {
            *self.theme_handler.borrow_mut() = Some(h);
        }
    }

    fn apply_settings_theme(&self) {
        use windows::Win32::Foundation::RECT;
        use windows::Win32::Graphics::Gdi::{
            CreateSolidBrush, FillRect, HBRUSH, HDC, SetBkColor, SetBkMode, SetTextColor,
            TRANSPARENT,
        };
        use windows::Win32::UI::WindowsAndMessaging::{
            WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_ERASEBKGND,
        };

        // Dark title bar
        if let Some(hwnd) = self.settings_window.handle.hwnd() {
            theme::set_dark_title_bar(hwnd as isize);
        }

        // Only install the handler once
        if self.settings_theme_handler.borrow().is_some() {
            return;
        }

        let brush_window: HBRUSH = unsafe { CreateSolidBrush(theme::BG_WINDOW) };
        let brush_input: HBRUSH = unsafe { CreateSolidBrush(theme::BG_INPUT) };

        let handler = nwg::bind_raw_event_handler(
            &self.settings_window.handle,
            0xFFFF + 3,
            move |_hwnd, msg, wparam, _lparam| match msg {
                x if x == WM_ERASEBKGND => {
                    let hdc = HDC(wparam as *mut _);
                    let rc = RECT {
                        left: 0,
                        top: 0,
                        right: 32000,
                        bottom: 32000,
                    };
                    unsafe { FillRect(hdc, &rc, brush_window) };
                    Some(1)
                }
                x if x == WM_CTLCOLORSTATIC => {
                    let hdc = HDC(wparam as *mut _);
                    unsafe {
                        SetTextColor(hdc, theme::FG_PRIMARY);
                        SetBkMode(hdc, TRANSPARENT);
                    }
                    Some(brush_window.0 as isize)
                }
                x if x == WM_CTLCOLOREDIT => {
                    let hdc = HDC(wparam as *mut _);
                    unsafe {
                        SetTextColor(hdc, theme::FG_PRIMARY);
                        SetBkColor(hdc, theme::BG_INPUT);
                    }
                    Some(brush_input.0 as isize)
                }
                x if x == WM_CTLCOLORBTN => {
                    let hdc = HDC(wparam as *mut _);
                    unsafe {
                        SetTextColor(hdc, theme::FG_PRIMARY);
                        SetBkMode(hdc, TRANSPARENT);
                    }
                    Some(brush_window.0 as isize)
                }
                _ => None,
            },
        );

        if let Ok(h) = handler {
            *self.settings_theme_handler.borrow_mut() = Some(h);
        }
    }

    /// Re-apply preview text color after setting text content.
    fn apply_preview_text_color(&self) {
        use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

        let Some(hwnd) = self.preview_text.handle.hwnd() else {
            return;
        };
        let cf = theme::make_charformat_color(theme::FG_PRIMARY);
        unsafe {
            SendMessageW(
                HWND(hwnd as _),
                theme::EM_SETCHARFORMAT,
                Some(WPARAM(theme::SCF_ALL)),
                Some(LPARAM(cf.as_ptr() as isize)),
            );
        }
    }

    fn exit(&self) {
        self.set_preview_hbitmap(None);
        // Unbind raw event handler before stopping.
        if let Some(handler) = self.raw_handler.borrow_mut().take() {
            let _ = nwg::unbind_raw_event_handler(&handler);
        }
        if let Some(handler) = self.theme_handler.borrow_mut().take() {
            let _ = nwg::unbind_raw_event_handler(&handler);
        }
        if let Some(handler) = self.settings_theme_handler.borrow_mut().take() {
            let _ = nwg::unbind_raw_event_handler(&handler);
        }
        signal_monitor_stop();
        nwg::stop_thread_dispatch();
    }

    fn on_main_window_close(&self, data: &nwg::EventData) {
        if let nwg::EventData::OnWindowClose(d) = data {
            // Keep the process running; just hide to tray.
            d.close(false);
        }
        self.window.set_visible(false);
    }

    fn show_settings(&self) {
        self.populate_settings_dialog();
        self.apply_settings_theme();
        self.settings_window.set_visible(true);
        self.settings_window.restore();
        self.settings_window.set_focus();
    }

    fn reconnect(&self) {
        let (notify, cfg) = {
            let state = self.state.borrow();
            (state.reconnect_notify.clone(), state.config.clone())
        };

        let Some(cfg) = cfg else {
            self.update_status_bar(Some("WS not configured"));
            return;
        };

        if !cfg.has_server() {
            self.update_status_bar(Some("WS not configured"));
            return;
        }

        if !cfg.server.auto_connect {
            self.update_status_bar(Some("WS auto-connect disabled"));
            return;
        }

        if let Some(n) = notify {
            n.notify_one();
            self.update_status_bar(Some("Reconnecting..."));
        } else {
            self.update_status_bar(Some("Reconnect not available"));
        }
    }

    fn focus_search(&self) {
        self.search_input.set_focus();
    }

    fn tray_restore(&self) {
        self.window.set_visible(true);
        self.window.restore();
        self.window.set_focus();
    }

    fn tray_show_menu(&self) {
        let (x, y) = nwg::GlobalCursor::position();
        self.tray_menu.popup(x, y);
    }

    fn on_settings_window_close(&self, data: &nwg::EventData) {
        if let nwg::EventData::OnWindowClose(d) = data {
            d.close(false);
        }
        self.settings_window.set_visible(false);
    }

    fn populate_settings_dialog(&self) {
        let cfg = {
            let state = self.state.borrow();
            state.config.clone()
        }
        .unwrap_or_else(|| Config::load(None));

        self.settings_url_input.set_text(&cfg.server.url);
        self.settings_password_input
            .set_text(cfg.server.password.as_deref().unwrap_or(""));

        self.settings_auto_connect
            .set_check_state(if cfg.server.auto_connect {
                nwg::CheckBoxState::Checked
            } else {
                nwg::CheckBoxState::Unchecked
            });

        self.settings_accept_invalid_certs
            .set_check_state(if cfg.server.accept_invalid_certs {
                nwg::CheckBoxState::Checked
            } else {
                nwg::CheckBoxState::Unchecked
            });

        self.settings_max_sync_size
            .set_text(&cfg.server.max_sync_size.to_string());
        self.settings_max_file_sync_size
            .set_text(&cfg.server.max_file_sync_size.to_string());
        self.settings_image_inline_threshold
            .set_text(&cfg.server.image_inline_threshold.to_string());
        self.settings_max_entries
            .set_text(&cfg.storage.max_entries.to_string());
        self.settings_download_dir
            .set_text(&cfg.server.download_dir);
    }

    fn browse_download_dir(&self) {
        if self.download_dir_dialog.run(Some(&self.settings_window)) {
            if let Ok(item) = self.download_dir_dialog.get_selected_item() {
                self.settings_download_dir.set_text(&item.to_string_lossy());
            }
        }
    }

    fn cancel_settings(&self) {
        self.settings_window.set_visible(false);
    }

    fn save_settings(&self) {
        let mut cfg = {
            let state = self.state.borrow();
            state.config.clone()
        }
        .unwrap_or_else(|| Config::load(None));

        cfg.server.url = self.settings_url_input.text();

        let pwd = self.settings_password_input.text();
        cfg.server.password = if pwd.trim().is_empty() {
            None
        } else {
            Some(pwd)
        };

        cfg.server.auto_connect =
            self.settings_auto_connect.check_state() == nwg::CheckBoxState::Checked;
        cfg.server.accept_invalid_certs =
            self.settings_accept_invalid_certs.check_state() == nwg::CheckBoxState::Checked;

        let parse_usize = |name: &str, raw: String| -> Option<usize> {
            raw.trim().parse::<usize>().ok().or_else(|| {
                nwg::modal_error_message(
                    &self.settings_window,
                    "Settings",
                    &format!("{name} must be a number"),
                );
                None
            })
        };

        let parse_u64 = |name: &str, raw: String| -> Option<u64> {
            raw.trim().parse::<u64>().ok().or_else(|| {
                nwg::modal_error_message(
                    &self.settings_window,
                    "Settings",
                    &format!("{name} must be a number"),
                );
                None
            })
        };

        let Some(max_sync_size) = parse_usize("Max sync size", self.settings_max_sync_size.text())
        else {
            return;
        };
        let Some(max_file_sync_size) = parse_u64(
            "Max file sync size",
            self.settings_max_file_sync_size.text(),
        ) else {
            return;
        };
        let Some(image_inline_threshold) = parse_usize(
            "Image inline threshold",
            self.settings_image_inline_threshold.text(),
        ) else {
            return;
        };
        let Some(max_entries) = parse_usize("Max entries", self.settings_max_entries.text()) else {
            return;
        };

        cfg.server.max_sync_size = max_sync_size;
        cfg.server.max_file_sync_size = max_file_sync_size;
        cfg.server.image_inline_threshold = image_inline_threshold;
        cfg.storage.max_entries = max_entries;
        cfg.server.download_dir = self.settings_download_dir.text();

        let path = Config::config_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match toml::to_string_pretty(&cfg) {
            Ok(toml_str) => {
                if let Err(e) = std::fs::write(&path, toml_str) {
                    nwg::modal_error_message(
                        &self.settings_window,
                        "Settings",
                        &format!("Failed to write config: {e}"),
                    );
                    return;
                }
            }
            Err(e) => {
                nwg::modal_error_message(
                    &self.settings_window,
                    "Settings",
                    &format!("Failed to serialize config: {e}"),
                );
                return;
            }
        }

        {
            let mut state = self.state.borrow_mut();
            state.config = Some(cfg);
            if let Some(manager) = state.manager.as_mut() {
                manager.status_message =
                    Some("Settings saved. Restart to apply connection changes.".to_string());
            }
        }

        self.settings_window.set_visible(false);
        self.update_status_bar(None);
    }

    fn on_search_input(&self) {
        let query = self.search_input.text();
        let keep_id = self.selected_entry_id();

        {
            let mut state = self.state.borrow_mut();
            let Some(manager) = state.manager.as_mut() else {
                return;
            };
            if query.is_empty() {
                manager.clear_search();
            } else {
                manager.update_search(query);
            }
        }

        self.refresh_list(keep_id);
    }

    fn on_list_view_item_changed(&self, data: &nwg::EventData) {
        let (row, _col, selected) = data.on_list_view_item_changed();
        if !selected || self.suppressing_events() {
            return;
        }
        self.set_selected_row(row);
        self.update_preview_from_manager();
        self.update_status_bar(None);
    }

    fn set_selected_row(&self, row: usize) {
        let mut state = self.state.borrow_mut();
        let Some(manager) = state.manager.as_mut() else {
            return;
        };
        if manager.entries.is_empty() {
            manager.selected = 0;
        } else {
            manager.selected = row.min(manager.entries.len() - 1);
        }
    }

    fn on_list_view_item_activated(&self, _data: &nwg::EventData) {
        self.copy_selected();
    }

    fn on_list_view_right_click(&self, data: &nwg::EventData) {
        let (row, _col) = data.on_list_view_item_index();
        self.list_view.select_item(row, true);
        if !self.suppressing_events() {
            self.set_selected_row(row);
            self.update_preview_from_manager();
        }

        let (x, y) = nwg::GlobalCursor::position();
        self.list_menu.popup(x, y);
    }

    fn update_preview_from_manager(&self) {
        // Ensure the selected entry's content is loaded from DB (lazy).
        {
            let mut state = self.state.borrow_mut();
            if let Some(manager) = state.manager.as_mut() {
                manager.ensure_selected_content_loaded();
            }
        }

        let entry = {
            let state = self.state.borrow();
            state
                .manager
                .as_ref()
                .and_then(|m| m.selected_entry().cloned())
        };

        let Some(entry) = entry else {
            self.preview_image.set_visible(false);
            self.set_preview_hbitmap(None);
            self.preview_text.set_visible(true);
            self.preview_text.set_text("");
            return;
        };

        let content = entry.to_clipboard_content();

        // Try image preview (only for reasonably sized images to avoid blocking).
        if let Some(ref content) = content {
            match content {
                ClipboardContent::Image(info) => {
                    // Skip huge images (> 2MB raw data) to avoid blocking the GUI.
                    if info.data_size <= 2 * 1024 * 1024 {
                        if let Some(img) = info.to_dynamic_image() {
                            if self.try_show_image_preview(img) {
                                return;
                            }
                        }
                    }
                }
                ClipboardContent::Files(paths) => {
                    if let Some(img) = o_clip_core::entry_manager::load_image_from_file_paths(paths)
                    {
                        if self.try_show_image_preview(img) {
                            return;
                        }
                    }
                }
                _ => {}
            }
        }

        // Text fallback
        let local_time = entry.created_at.with_timezone(&Local);
        let title = format!(
            "Time: {}  Source: {}  Type: {}",
            local_time.format("%Y-%m-%d %H:%M:%S"),
            match entry.source {
                EntrySource::Local => "Local",
                EntrySource::Remote => "Remote",
            },
            entry.content_type
        );

        let body = match content {
            Some(ClipboardContent::Text(t)) => t,
            Some(ClipboardContent::Url(u)) => u,
            Some(ClipboardContent::Files(paths)) => {
                let mut lines = Vec::new();
                for p in &paths {
                    let path_str = p.to_string_lossy().to_string();
                    if p.exists() {
                        lines.push(path_str);
                    } else {
                        lines.push(format!("{path_str}  [FILE DELETED]"));
                    }
                }
                let any_deleted = paths.iter().any(|p| !p.exists());
                let mut s = lines.join("\n");
                if any_deleted {
                    s.push_str("\n\n(Local files deleted, cannot re-fetch)");
                }
                s
            }
            Some(ClipboardContent::SyncedFiles(refs)) => {
                let mut s = String::new();
                s.push_str("Synced files:\n\n");
                for r in &refs {
                    s.push_str(&format!("{} ({} bytes)\n", r.filename, r.size));
                }
                s.push_str("\nPress F5 to re-download");
                s
            }
            Some(ClipboardContent::Image(info)) => format!(
                "Image: {}x{} {:?} ({:.1} KB)",
                info.width,
                info.height,
                info.format,
                info.data_size as f64 / 1024.0
            ),
            Some(ClipboardContent::SyncedImage(img)) => format!(
                "Synced image: {}x{} {:?} ({:.1} KB)",
                img.width,
                img.height,
                img.format,
                img.size as f64 / 1024.0
            ),
            Some(ClipboardContent::Empty) => "Empty".to_string(),
            None => entry.content,
        };

        self.preview_image.set_visible(false);
        self.set_preview_hbitmap(None);
        self.preview_text.set_visible(true);
        self.preview_text
            .set_text_unix2dos(&format!("{title}\n\n{body}"));
        self.apply_preview_text_color();
    }

    fn try_show_image_preview(&self, img: image::DynamicImage) -> bool {
        let (max_w, max_h) = self.preview_image.size();
        let Some(hbitmap) = crate::controls::dynamic_image_to_hbitmap(&img, max_w, max_h) else {
            return false;
        };

        self.preview_text.set_visible(false);
        self.preview_text.set_text("");
        self.preview_image.set_visible(true);
        self.set_preview_hbitmap(Some(hbitmap));
        true
    }

    fn set_preview_hbitmap(&self, hbitmap: Option<windows::Win32::Graphics::Gdi::HBITMAP>) {
        use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
        use windows::Win32::Graphics::Gdi::{DeleteObject, HGDIOBJ};
        use windows::Win32::UI::WindowsAndMessaging::{IMAGE_BITMAP, STM_SETIMAGE, SendMessageW};

        let Some(hwnd) = self.preview_image.handle.hwnd() else {
            return;
        };
        let hwnd = HWND(hwnd as _);

        let new_handle = hbitmap.map(|b| b.0).unwrap_or_else(std::ptr::null_mut);
        let prev = unsafe {
            SendMessageW(
                hwnd,
                STM_SETIMAGE,
                Some(WPARAM(IMAGE_BITMAP.0 as usize)),
                Some(LPARAM(new_handle as isize)),
            )
        };

        if prev.0 != 0 {
            unsafe {
                let _ = DeleteObject(HGDIOBJ(prev.0 as *mut _));
            }
        }
    }

    fn copy_selected(&self) {
        // Ensure the selected entry's content is loaded from DB (lazy).
        {
            let mut state = self.state.borrow_mut();
            if let Some(manager) = state.manager.as_mut() {
                manager.ensure_selected_content_loaded();
            }
        }

        let content = {
            let state = self.state.borrow();
            let Some(manager) = state.manager.as_ref() else {
                return;
            };
            manager.get_selected_content()
        };

        let Some(content) = content else {
            self.update_status_bar(Some("Nothing selected"));
            return;
        };

        let ok = match content {
            ClipboardContent::Text(t) => {
                clipboard::mark_self_write();
                let ok = clipboard::writer::set_clipboard_text(&t);
                if !ok {
                    let _ = clipboard::take_self_write();
                }
                ok
            }
            ClipboardContent::Url(u) => {
                clipboard::mark_self_write();
                let ok = clipboard::writer::set_clipboard_text(&u);
                if !ok {
                    let _ = clipboard::take_self_write();
                }
                ok
            }
            ClipboardContent::Files(paths) => {
                clipboard::mark_self_write();
                let ok = clipboard::writer::set_clipboard_files(&paths);
                if !ok {
                    let _ = clipboard::take_self_write();
                }
                ok
            }
            ClipboardContent::Image(info) => {
                clipboard::mark_self_write();
                let ok = clipboard::writer::set_clipboard_image(&info);
                if !ok {
                    let _ = clipboard::take_self_write();
                }
                ok
            }
            ClipboardContent::SyncedFiles(_) | ClipboardContent::SyncedImage(_) => false,
            ClipboardContent::Empty => false,
        };

        if ok {
            self.update_status_bar(Some("Copied to clipboard"));
        } else {
            self.update_status_bar(Some("Copy failed (unsupported or not wired)"));
        }
    }

    fn delete_selected(&self) {
        {
            let mut state = self.state.borrow_mut();
            let Some(manager) = state.manager.as_mut() else {
                return;
            };
            manager.delete_selected();
        }
        self.refresh_list(None);
        self.update_status_bar(Some("Entry deleted"));
    }

    fn clear_all(&self) {
        // Confirm with the user
        let params = nwg::MessageParams {
            title: "Clear All",
            content: "Delete all entries on this client AND the server?",
            buttons: nwg::MessageButtons::YesNo,
            icons: nwg::MessageIcons::Warning,
        };
        if nwg::modal_message(&self.window, &params) != nwg::MessageChoice::Yes {
            return;
        }
        {
            let mut state = self.state.borrow_mut();
            if let Some(manager) = state.manager.as_mut() {
                manager.delete_all();
            }
            // Send ClearAll to server
            if let Some(tx) = state.ws_outbound_tx.as_ref() {
                let _ = tx.send(SyncCommand::ClearAll);
            }
        }
        self.refresh_list(None);
        self.update_status_bar(Some("All data cleared"));
    }

    fn pin_selected(&self) {
        let keep_id = self.selected_entry_id();
        {
            let mut state = self.state.borrow_mut();
            let Some(manager) = state.manager.as_mut() else {
                return;
            };
            manager.toggle_pin_selected();
        }
        self.refresh_list(keep_id);
        self.update_status_bar(None);
    }

    fn refetch_selected_files(&self) {
        {
            let mut state = self.state.borrow_mut();
            if let Some(manager) = state.manager.as_mut() {
                manager.ensure_selected_content_loaded();
            }
        }

        let content = {
            let state = self.state.borrow();
            let Some(manager) = state.manager.as_ref() else {
                return;
            };
            manager.get_selected_content()
        };

        let Some(content) = content else {
            self.update_status_bar(Some("Nothing selected"));
            return;
        };

        match content {
            ClipboardContent::SyncedFiles(refs) => {
                let state = self.state.borrow();
                if let Some(tx) = state.file_req_tx.as_ref() {
                    let n = refs.len();
                    let _ = tx.send(FileRequest::Download { refs });
                    drop(state);
                    self.update_status_bar(Some(&format!("Re-downloading {n} file(s)...")));
                } else {
                    drop(state);
                    self.update_status_bar(Some("File transfer not available"));
                }
            }
            ClipboardContent::Files(paths) => {
                let any_missing = paths.iter().any(|p| !p.exists());
                if any_missing {
                    self.update_status_bar(Some(
                        "Local files deleted - no server copy available for re-fetch",
                    ));
                } else {
                    self.update_status_bar(Some("All files exist"));
                }
            }
            _ => {
                self.update_status_bar(Some("Not a file entry"));
            }
        }
    }

    fn on_timer_tick(&self) {
        // Process keyboard shortcuts first (minimal latency).
        self.process_key_actions();

        let mut needs_refresh = false;
        let mut needs_status = false;

        // Time budget per tick: avoid blocking the GUI thread for too long.
        let tick_deadline = Instant::now() + Duration::from_millis(50);

        let (
            max_sync_size,
            image_inline_threshold,
            manager,
            mut recent_remote_hashes,
            clip_rx,
            ws_event_rx,
            file_resp_rx,
            ws_outbound_tx,
            file_req_tx,
        ) = {
            let mut state = self.state.borrow_mut();
            let max_sync_size = state
                .config
                .as_ref()
                .map(|c| c.server.max_sync_size)
                .unwrap_or(0);
            let image_inline_threshold = state
                .config
                .as_ref()
                .map(|c| c.server.image_inline_threshold)
                .unwrap_or(0);
            (
                max_sync_size,
                image_inline_threshold,
                state.manager.take(),
                std::mem::take(&mut state.recent_remote_hashes),
                state.clip_rx.take(),
                state.ws_event_rx.take(),
                state.file_resp_rx.take(),
                state.ws_outbound_tx.clone(),
                state.file_req_tx.clone(),
            )
        };

        let Some(mut manager) = manager else {
            return;
        };

        // Expire old entries from the remote hash dedup cache.
        recent_remote_hashes.retain(|_, ts| ts.elapsed() < REMOTE_HASH_TTL);

        // Process clipboard events (non-blocking, max 20 per tick).
        if let Some(rx) = clip_rx.as_ref() {
            let mut count = 0;
            loop {
                if count >= 20 || Instant::now() > tick_deadline {
                    break;
                }
                match rx.try_recv() {
                    Ok(event) => {
                        count += 1;
                        let content_hash = event.content.content_hash();
                        let entry = ClipboardEntry::from_content(&event.content);

                        let is_echo = recent_remote_hashes.remove(&content_hash).is_some();
                        if is_echo {
                            tracing::debug!(
                                "skipping outbound sync for recently auto-copied remote content: {}",
                                &content_hash[..content_hash.len().min(16)]
                            );
                        } else if !event.no_cloud {
                            let is_files = matches!(&event.content, ClipboardContent::Files(_));
                            let is_image = matches!(&event.content, ClipboardContent::Image(_));

                            if is_files {
                                if let ClipboardContent::Files(paths) = &event.content {
                                    if let Some(tx) = file_req_tx.as_ref() {
                                        let _ = tx.send(FileRequest::Upload {
                                            entry: entry.clone(),
                                            paths: paths.clone(),
                                        });
                                    }
                                }
                            } else if is_image {
                                if let ClipboardContent::Image(info) = &event.content {
                                    if info.raw_data.is_none() {
                                        tracing::debug!("skipping image sync: no raw_data");
                                    } else if info.data_size <= image_inline_threshold {
                                        if (entry.byte_size as usize) <= max_sync_size {
                                            if let Some(tx) = ws_outbound_tx.as_ref() {
                                                let _ = tx.send(SyncCommand::SendEntry(entry.clone()));
                                            }
                                        }
                                    } else if let Some(tx) = file_req_tx.as_ref() {
                                        let _ = tx.send(FileRequest::UploadImage {
                                            entry: entry.clone(),
                                            info: info.clone(),
                                        });
                                    }
                                }
                            } else if (entry.byte_size as usize) <= max_sync_size {
                                if let Some(tx) = ws_outbound_tx.as_ref() {
                                    let _ = tx.send(SyncCommand::SendEntry(entry.clone()));
                                }
                            }
                        }

                        manager.on_new_entry(entry);
                        needs_refresh = true;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }
        }

        // Process WebSocket events (non-blocking).
        // Accumulate all entries (remote + sync batches) into a single Vec,
        // then batch-insert once at the end to avoid repeated DB reloads.
        if let Some(rx) = ws_event_rx.as_ref() {
            let mut pending_entries: Vec<ClipboardEntry> = Vec::new();
            loop {
                if Instant::now() > tick_deadline {
                    break;
                }
                match rx.try_recv() {
                    Ok(ws_event) => {
                        match ws_event {
                            SyncEvent::RemoteEntry(mut entry) => {
                                entry.source = EntrySource::Remote;

                                // Normalize hash first so we can check local DB.
                                o_clip_core::normalize_entry_hash(&mut entry);

                                // Check if this entry already exists in our local DB.
                                // If so, skip download and auto-copy to prevent echo loops
                                // when multiple clients (GUI + TUI) share the same clipboard.
                                let already_exists = manager.store().has_hash(&entry.hash);

                                if !already_exists {
                                    if let Some(content) = entry.to_clipboard_content() {
                                        let dedup_hash = content.content_hash();
                                        recent_remote_hashes.insert(dedup_hash, Instant::now());

                                        if let ClipboardContent::SyncedFiles(refs) = &content {
                                            if let Some(tx) = file_req_tx.as_ref() {
                                                let _ = tx.send(FileRequest::Download {
                                                    refs: refs.clone(),
                                                });
                                            }
                                        }

                                        if let ClipboardContent::SyncedImage(img_ref) = &content {
                                            if let Some(tx) = file_req_tx.as_ref() {
                                                let _ = tx.send(FileRequest::DownloadImage {
                                                    img_ref: img_ref.clone(),
                                                });
                                            }
                                        }
                                    }

                                    o_clip_core::auto_copy_to_clipboard(&entry);
                                } else {
                                    tracing::debug!(
                                        "skipping auto-copy/download for existing entry: {}",
                                        &entry.hash[..entry.hash.len().min(16)]
                                    );
                                }

                                pending_entries.push(entry);
                                needs_refresh = true;
                            }
                            SyncEvent::SyncBatch(entries) => {
                                let n = entries.len();
                                pending_entries.extend(entries.into_iter().map(|mut e| {
                                    e.source = EntrySource::Remote;
                                    o_clip_core::normalize_entry_hash(&mut e);
                                    e
                                }));
                                tracing::info!("collected sync batch of {n} entries");
                                needs_refresh = true;
                            }
                            SyncEvent::StatusChanged(status) => {
                                manager.ws_status = status;
                                needs_status = true;
                            }
                            SyncEvent::ClearAll => {
                                manager.delete_all();
                                needs_refresh = true;
                                needs_status = true;
                            }
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }
            // Single batch insert + reload for all entries collected this tick.
            if !pending_entries.is_empty() {
                let n = pending_entries.len();
                manager.on_new_entries_batch(pending_entries);
                tracing::info!("batch-inserted {n} WS entries this tick");
            }
        }

        // Process file download responses (non-blocking, max 5 per tick).
        if let Some(rx) = file_resp_rx.as_ref() {
            let mut count = 0;
            loop {
                if count >= 5 || Instant::now() > tick_deadline {
                    break;
                }
                match rx.try_recv() {
                    Ok(resp) => {
                        count += 1;
                        match resp {
                            FileResponse::Downloaded(local_paths) => {
                                let content = ClipboardContent::Files(local_paths.clone());
                                let hash = content.content_hash();
                                recent_remote_hashes.insert(hash, Instant::now());

                                clipboard::mark_self_write();
                                let ok = clipboard::writer::set_clipboard_files(&local_paths);
                                if !ok {
                                    let _ = clipboard::take_self_write();
                                    manager.status_message =
                                        Some("Failed to set clipboard files".to_string());
                                } else {
                                    let dir_display = local_paths
                                        .first()
                                        .and_then(|p| p.parent())
                                        .map(|d| d.to_string_lossy().to_string())
                                        .unwrap_or_default();
                                    manager.status_message = Some(format!(
                                        "Downloaded {} file(s) -> {}",
                                        local_paths.len(),
                                        dir_display
                                    ));
                                }
                                needs_status = true;
                            }
                            FileResponse::ImageDownloaded(info) => {
                                let content = ClipboardContent::Image(info.clone());
                                let hash = content.content_hash();
                                recent_remote_hashes.insert(hash, Instant::now());

                                clipboard::mark_self_write();
                                let ok = clipboard::writer::set_clipboard_image(&info);
                                if !ok {
                                    let _ = clipboard::take_self_write();
                                    manager.status_message =
                                        Some("Failed to set clipboard image".to_string());
                                } else {
                                    manager.status_message = Some(format!(
                                        "Image synced: {}x{} {:?}",
                                        info.width, info.height, info.format
                                    ));
                                }
                                needs_status = true;
                            }
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                }
            }
        }

        {
            let mut state = self.state.borrow_mut();
            state.manager = Some(manager);
            state.recent_remote_hashes = recent_remote_hashes;
            state.clip_rx = clip_rx;
            state.ws_event_rx = ws_event_rx;
            state.file_resp_rx = file_resp_rx;
        }

        if needs_refresh {
            self.refresh_list(None);
        } else if needs_status {
            self.update_status_bar(None);
        }
    }

    fn init_core_state(&self) -> Result<(), String> {
        let cfg_path = Config::config_path();
        Config::write_default_if_missing(&cfg_path);
        let cfg = Config::load(None);

        let db_path = cfg.db_path();
        let store = Store::open(&db_path)
            .map_err(|e| format!("Failed to open DB at {}: {e}", db_path.display()))?;

        let manager = EntryManager::new(store, cfg.storage.max_entries);

        // Create clipboard event channel and spawn monitor thread.
        let (clip_tx, clip_rx) = std::sync::mpsc::channel::<ClipboardEvent>();
        let _monitor_handle = spawn_clipboard_monitor(clip_tx);

        // Set up WebSocket sync channels.
        let (ws_outbound_tx, ws_outbound_rx) =
            tokio::sync::mpsc::unbounded_channel::<SyncCommand>();
        let (ws_event_tx, ws_event_rx) = std::sync::mpsc::channel::<SyncEvent>();

        // File transfer channels (GUI thread <-> tokio runtime).
        let (file_req_tx, mut file_req_rx) = tokio::sync::mpsc::unbounded_channel::<FileRequest>();
        let (file_resp_tx, file_resp_rx) = std::sync::mpsc::channel::<FileResponse>();

        // Spawn tokio runtime for WebSocket sync + file transfer.
        let ws_url = cfg.server.url.clone();
        let accept_invalid_certs = cfg.server.accept_invalid_certs;
        let ws_password = cfg.server.password.clone();
        let has_server = cfg.has_server() && cfg.server.auto_connect;
        let max_file_sync_size = cfg.server.max_file_sync_size;
        let download_dir = cfg.download_dir();
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

            let file_client = Arc::new(FileTransferClient::new(
                &ws_url,
                ws_password.clone(),
                accept_invalid_certs,
                max_file_sync_size,
                download_dir,
            ));

            let fc = file_client.clone();
            let ws_tx = ws_outbound_tx_clone;
            let resp_tx = file_resp_tx;
            rt.spawn(async move {
                while let Some(req) = file_req_rx.recv().await {
                    match req {
                        FileRequest::Upload { mut entry, paths } => {
                            match fc.upload_files(&paths).await {
                                Ok(file_refs) => {
                                    let synced = ClipboardContent::SyncedFiles(file_refs);
                                    let content_json =
                                        serde_json::to_string(&synced).unwrap_or_default();
                                    entry.content = content_json;
                                    entry.hash = synced.content_hash();
                                    entry.byte_size = synced.byte_size() as i64;
                                    entry.preview = synced.preview(120);
                                    let _ = ws_tx.send(SyncCommand::SendEntry(entry));
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
                        FileRequest::UploadImage { mut entry, info } => {
                            match fc.upload_image(&info).await {
                                Ok(img_ref) => {
                                    let synced = ClipboardContent::SyncedImage(img_ref);
                                    let content_json =
                                        serde_json::to_string(&synced).unwrap_or_default();
                                    entry.content = content_json;
                                    entry.hash = synced.content_hash();
                                    entry.byte_size = synced.byte_size() as i64;
                                    entry.preview = synced.preview(120);
                                    let _ = ws_tx.send(SyncCommand::SendEntry(entry));
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

        let mut state = self.state.borrow_mut();
        state.config = Some(cfg);
        state.manager = Some(manager);
        state.row_entry_ids.clear();
        state.clip_rx = Some(clip_rx);
        state.ws_event_rx = Some(ws_event_rx);
        state.file_resp_rx = Some(file_resp_rx);
        state.ws_outbound_tx = Some(ws_outbound_tx);
        state.file_req_tx = Some(file_req_tx);
        state.reconnect_notify = Some(reconnect_notify);
        Ok(())
    }

    fn suppressing_events(&self) -> bool {
        self.state.borrow().suppress_events
    }

    fn selected_entry_id(&self) -> Option<i64> {
        let state = self.state.borrow();
        state
            .manager
            .as_ref()
            .and_then(|m| m.selected_entry().map(|e| e.id))
    }

    fn refresh_list(&self, keep_selected_id: Option<i64>) {
        let (rows, selected_id, fallback_selected, total_count, ws_status) = {
            let mut state = self.state.borrow_mut();
            state.suppress_events = true;
            let Some(manager) = state.manager.as_mut() else {
                return;
            };

            let selected_id = keep_selected_id.or_else(|| manager.selected_entry().map(|e| e.id));

            let rows: Vec<(i64, [String; 5])> = manager
                .entries
                .iter()
                .map(|e| {
                    let pinned = if e.pinned { "\u{2605}" } else { "" }.to_string();
                    let local_time = e.created_at.with_timezone(&Local);
                    let time_str = local_time.format("%H:%M:%S").to_string();
                    let src = match e.source {
                        o_clip_core::store::EntrySource::Local => "L",
                        o_clip_core::store::EntrySource::Remote => "R",
                    }
                    .to_string();
                    let ty = match e.content_type.as_str() {
                        "text" => "TXT",
                        "url" => "URL",
                        "files" => "FILE",
                        "image" => "IMG",
                        "empty" => "EMPTY",
                        other => other,
                    }
                    .to_string();
                    let preview = e.preview.replace('\n', " ");
                    (e.id, [pinned, time_str, src, ty, preview])
                })
                .collect();

            (
                rows,
                selected_id,
                manager.selected,
                manager.total_count,
                manager.ws_status,
            )
        };

        self.list_view.set_redraw(false);
        self.list_view.clear();

        {
            let mut state = self.state.borrow_mut();
            state.row_entry_ids.clear();
            for (id, _) in &rows {
                state.row_entry_ids.push(*id);
            }
        }

        for (_id, cols) in rows {
            self.list_view.insert_items_row(None, &cols);
        }
        self.list_view.set_redraw(true);

        let row_to_select = {
            let state = self.state.borrow();
            selected_id
                .and_then(|id| state.row_entry_ids.iter().position(|x| *x == id))
                .unwrap_or_else(|| {
                    if self.list_view.len() == 0 {
                        0
                    } else {
                        fallback_selected.min(self.list_view.len() - 1)
                    }
                })
        };

        if self.list_view.len() > 0 {
            self.list_view.select_item(row_to_select, true);
        } else {
            self.preview_text.set_text("");
        }

        {
            let mut state = self.state.borrow_mut();
            if let Some(manager) = state.manager.as_mut() {
                if manager.entries.is_empty() {
                    manager.selected = 0;
                } else {
                    manager.selected = row_to_select.min(manager.entries.len() - 1);
                }
            }
            state.suppress_events = false;
        }

        self.update_preview_from_manager();
        self.update_status_bar_with(ws_status, total_count, None);
    }

    fn update_status_bar(&self, message: Option<&str>) {
        let (ws_status, total_count) = {
            let state = self.state.borrow();
            let Some(manager) = state.manager.as_ref() else {
                return;
            };
            (manager.ws_status, manager.total_count)
        };
        self.update_status_bar_with(ws_status, total_count, message);
    }

    fn update_status_bar_with(
        &self,
        ws_status: ConnectionStatus,
        total_count: usize,
        message: Option<&str>,
    ) {
        let (shown, query, status_message) = {
            let state = self.state.borrow();
            let Some(manager) = state.manager.as_ref() else {
                return;
            };
            (
                manager.entries.len(),
                manager.search_query.clone(),
                manager.status_message.clone(),
            )
        };

        let ws = match ws_status {
            ConnectionStatus::Disconnected => "Disconnected",
            ConnectionStatus::Connecting => "Connecting",
            ConnectionStatus::Connected => "Connected",
        };

        let mut s = String::new();
        s.push_str(&format!("WS: {ws}"));
        if let Some(m) = message {
            if !m.is_empty() {
                s.push_str(&format!(" | {m}"));
            }
        } else if let Some(m) = status_message {
            if !m.is_empty() {
                s.push_str(&format!(" | {m}"));
            }
        } else if !query.is_empty() {
            s.push_str(&format!(" | Search: {query}"));
        }
        s.push_str(&format!(" | {shown}/{total_count} entries"));
        self.status.set_text(&format!("  {s}"));
    }
}

pub fn run() {
    nwg::init().expect("failed to init native-windows-gui");
    let _ = nwg::Font::set_global_family("Segoe UI");

    // Must be called before any window is created so that menus and
    // shell-themed controls pick up the dark palette.
    theme::enable_dark_mode_for_app();

    init_logging();

    let _ui = App::build_ui(Default::default()).expect("failed to build UI");
    nwg::dispatch_thread_events();
}

fn init_logging() {
    let log_dir = directories::ProjectDirs::from("", "", "o-clip")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    let log_file = std::fs::File::create(log_dir.join("o-clip-gui.log")).ok();
    if let Some(file) = log_file {
        let _ = tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .try_init();
    }
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard monitor spawning + stop signal
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

#[cfg(not(target_os = "windows"))]
fn spawn_clipboard_monitor(
    _clip_tx: std::sync::mpsc::Sender<ClipboardEvent>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

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

#[cfg(not(target_os = "windows"))]
fn signal_monitor_stop() {}
