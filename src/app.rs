use ratatui_image::picker::Picker;
use ratatui_image::protocol::StatefulProtocol;

use crate::clipboard::ClipboardContent;
use crate::store::{ClipboardEntry, Store};
use crate::sync::ConnectionStatus;

/// TUI application modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
}

/// Core application state.
pub struct App {
    /// All displayed entries (loaded from DB).
    pub entries: Vec<ClipboardEntry>,
    /// Currently selected index in the list.
    pub selected: usize,
    /// Current mode.
    pub mode: Mode,
    /// Search input buffer.
    pub search_query: String,
    /// WebSocket connection status.
    pub ws_status: ConnectionStatus,
    /// Total entry count (may differ from entries.len() if search is active).
    pub total_count: usize,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Status message shown temporarily.
    pub status_message: Option<String>,
    /// Database store.
    store: Store,
    /// Max entries config.
    max_entries: usize,
    /// Terminal graphics protocol picker for image rendering.
    picker: Option<Picker>,
    /// Cached image preview protocol state (for the currently selected image entry).
    pub image_preview: Option<StatefulProtocol>,
    /// Entry ID that `image_preview` was generated for (cache key).
    image_preview_for: Option<i64>,
}

impl App {
    pub fn new(store: Store, max_entries: usize, picker: Option<Picker>) -> Self {
        let entries = store.list(500, 0).unwrap_or_default();
        let total_count = store.count().unwrap_or(0);
        let mut app = Self {
            entries,
            selected: 0,
            mode: Mode::Normal,
            search_query: String::new(),
            ws_status: ConnectionStatus::Disconnected,
            total_count,
            should_quit: false,
            status_message: None,
            store,
            max_entries,
            picker,
            image_preview: None,
            image_preview_for: None,
        };
        app.update_image_preview();
        app
    }

    /// Reload entries from the database.
    pub fn reload_entries(&mut self) {
        if self.search_query.is_empty() {
            self.entries = self.store.list(500, 0).unwrap_or_default();
        } else {
            self.entries = self.store.search(&self.search_query).unwrap_or_default();
        }
        self.total_count = self.store.count().unwrap_or(0);
        // Clamp selected index
        if !self.entries.is_empty() && self.selected >= self.entries.len() {
            self.selected = self.entries.len() - 1;
        }
        self.update_image_preview();
    }

    /// Rebuild the cached image preview if the selected entry changed.
    fn update_image_preview(&mut self) {
        let current_id = self.entries.get(self.selected).map(|e| e.id);

        // Already cached for this entry.
        if current_id == self.image_preview_for && self.image_preview.is_some() {
            return;
        }

        self.image_preview = None;
        self.image_preview_for = current_id;

        let picker = match &mut self.picker {
            Some(p) => p,
            None => return,
        };

        let entry = match self.entries.get(self.selected) {
            Some(e) => e,
            None => return,
        };

        let dyn_img = match entry.to_clipboard_content() {
            Some(ClipboardContent::Image(info)) => info.to_dynamic_image(),
            Some(ClipboardContent::Files(paths)) => load_image_from_file_paths(&paths),
            _ => None,
        };

        if let Some(img) = dyn_img {
            let proto = picker.new_resize_protocol(img);
            self.image_preview = Some(proto);
        }
    }

    /// Handle a new clipboard entry (from monitor or remote sync).
    pub fn on_new_entry(&mut self, entry: ClipboardEntry) {
        if let Err(e) = self.store.insert(&entry) {
            tracing::warn!("failed to store clipboard entry: {e}");
            return;
        }
        // Enforce storage limit
        let _ = self.store.enforce_limit(self.max_entries);
        self.reload_entries();
    }

    /// Move selection up.
    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            self.update_image_preview();
        }
    }

    /// Move selection down.
    pub fn select_next(&mut self) {
        if !self.entries.is_empty() && self.selected < self.entries.len() - 1 {
            self.selected += 1;
            self.update_image_preview();
        }
    }

    /// Jump to top.
    pub fn select_first(&mut self) {
        self.selected = 0;
        self.update_image_preview();
    }

    /// Jump to bottom.
    pub fn select_last(&mut self) {
        if !self.entries.is_empty() {
            self.selected = self.entries.len() - 1;
            self.update_image_preview();
        }
    }

    /// Delete the currently selected entry.
    pub fn delete_selected(&mut self) {
        if let Some(entry) = self.entries.get(self.selected) {
            let id = entry.id;
            if let Err(e) = self.store.delete(id) {
                tracing::warn!("failed to delete entry {id}: {e}");
                return;
            }
            self.reload_entries();
            self.status_message = Some("Entry deleted".to_string());
        }
    }

    /// Copy the selected entry's content back to the system clipboard.
    pub fn copy_selected_to_clipboard(&mut self) {
        let Some(entry) = self.entries.get(self.selected) else {
            return;
        };
        let Some(content) = entry.to_clipboard_content() else {
            self.status_message = Some("Cannot restore this content type".to_string());
            return;
        };

        match &content {
            crate::clipboard::ClipboardContent::Text(t) => {
                crate::clipboard::mark_self_write();
                if set_clipboard_text(t) {
                    self.status_message = Some("Copied to clipboard".to_string());
                } else {
                    self.status_message = Some("Failed to set clipboard".to_string());
                }
            }
            crate::clipboard::ClipboardContent::Url(u) => {
                crate::clipboard::mark_self_write();
                if set_clipboard_text(u) {
                    self.status_message = Some("Copied URL to clipboard".to_string());
                } else {
                    self.status_message = Some("Failed to set clipboard".to_string());
                }
            }
            crate::clipboard::ClipboardContent::Files(paths) => {
                crate::clipboard::mark_self_write();
                if set_clipboard_files(paths) {
                    self.status_message =
                        Some(format!("Copied {} file(s) to clipboard", paths.len()));
                } else {
                    self.status_message = Some("Failed to set files on clipboard".to_string());
                }
            }
            crate::clipboard::ClipboardContent::Image(info) => {
                if info.raw_data.is_none() {
                    self.status_message =
                        Some("Image too large, raw data was not stored".to_string());
                } else if matches!(info.format, crate::clipboard::content::ImageFormat::Png) {
                    // PNG registered format is not recognised by most Windows
                    // apps.  New captures use DIB; old entries may be PNG.
                    self.status_message =
                        Some("Legacy PNG entry, cannot restore (recopy the image)".to_string());
                } else {
                    crate::clipboard::mark_self_write();
                    if set_clipboard_image(info) {
                        self.status_message = Some("Copied image to clipboard".to_string());
                    } else {
                        self.status_message = Some("Failed to set image on clipboard".to_string());
                    }
                }
            }
            crate::clipboard::ClipboardContent::Empty => {
                self.status_message = Some("Nothing to copy".to_string());
            }
        }
    }

    /// Enter search mode.
    pub fn enter_search(&mut self) {
        self.mode = Mode::Search;
        self.search_query.clear();
    }

    /// Exit search mode and show all entries.
    pub fn exit_search(&mut self) {
        self.mode = Mode::Normal;
        self.search_query.clear();
        self.selected = 0;
        self.reload_entries();
    }

    /// Update search query and refresh results.
    pub fn update_search(&mut self, query: String) {
        self.search_query = query;
        self.selected = 0;
        self.reload_entries();
    }

    /// Get the currently selected entry (if any).
    pub fn selected_entry(&self) -> Option<&ClipboardEntry> {
        self.entries.get(self.selected)
    }

    /// Mark an entry as synced. Used by sync protocol.
    #[allow(dead_code)]
    pub fn mark_synced(&mut self, id: i64) {
        let _ = self.store.mark_synced(id);
    }

    /// Access the store directly.
    #[allow(dead_code)]
    pub fn store(&self) -> &Store {
        &self.store
    }
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard write: files (CF_HDROP)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn set_clipboard_files(paths: &[std::path::PathBuf]) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::CF_HDROP;

    // DROPFILES structure:
    //   DWORD pFiles;   // offset to file list
    //   POINT pt;       // drop point (unused, 0)
    //   BOOL  fNC;      // non-client area (FALSE)
    //   BOOL  fWide;    // TRUE for wide chars
    // = 20 bytes total
    const DROPFILES_SIZE: usize = 20;

    // Build the wide-char file list: each path null-terminated, double-null at end
    let mut file_data: Vec<u16> = Vec::new();
    for path in paths {
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        file_data.extend_from_slice(&wide);
        file_data.push(0); // null terminator for this path
    }
    file_data.push(0); // final double-null terminator

    let total_size = DROPFILES_SIZE + file_data.len() * 2;

    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }
        let _ = EmptyClipboard();

        let hmem = match GlobalAlloc(GMEM_MOVEABLE, total_size) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseClipboard();
                return false;
            }
        };

        let ptr = GlobalLock(hmem) as *mut u8;
        if ptr.is_null() {
            let _ = CloseClipboard();
            return false;
        }

        // Zero out the DROPFILES header
        std::ptr::write_bytes(ptr, 0, DROPFILES_SIZE);
        // pFiles: offset to file list (= size of DROPFILES)
        *(ptr as *mut u32) = DROPFILES_SIZE as u32;
        // fWide: TRUE (1) at offset 16
        *((ptr as *mut u32).add(4)) = 1;

        // Copy file list after the header
        std::ptr::copy_nonoverlapping(
            file_data.as_ptr() as *const u8,
            ptr.add(DROPFILES_SIZE),
            file_data.len() * 2,
        );

        let _ = GlobalUnlock(hmem);
        let result = SetClipboardData(CF_HDROP.0 as u32, Some(HANDLE(hmem.0)));
        let _ = CloseClipboard();
        result.is_ok()
    }
}

#[cfg(target_os = "macos")]
fn set_clipboard_files(paths: &[std::path::PathBuf]) -> bool {
    // On macOS, set file URLs on the pasteboard
    // For simplicity, fall back to setting paths as text
    let text: String = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    set_clipboard_text(&text)
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn set_clipboard_files(_paths: &[std::path::PathBuf]) -> bool {
    tracing::warn!("clipboard file write not supported on this platform");
    false
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard write: image
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn set_clipboard_image(info: &crate::clipboard::content::ImageInfo) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::{CF_DIB, CF_DIBV5};

    let raw_b64 = match &info.raw_data {
        Some(d) => d,
        None => return false,
    };
    let bytes = match BASE64.decode(raw_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Only DIB formats are supported for restore; PNG entries are rejected
    // by the caller because most Windows apps cannot paste from registered
    // "PNG" format.
    let format: u32 = match info.format {
        crate::clipboard::content::ImageFormat::DibV5 => CF_DIBV5.0 as u32,
        crate::clipboard::content::ImageFormat::Dib
        | crate::clipboard::content::ImageFormat::Bitmap => CF_DIB.0 as u32,
        crate::clipboard::content::ImageFormat::Png => return false,
    };

    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }
        let _ = EmptyClipboard();

        let hmem = match GlobalAlloc(GMEM_MOVEABLE, bytes.len()) {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseClipboard();
                return false;
            }
        };

        let ptr = GlobalLock(hmem) as *mut u8;
        if ptr.is_null() {
            let _ = CloseClipboard();
            return false;
        }

        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        let _ = GlobalUnlock(hmem);

        let result = SetClipboardData(format, Some(HANDLE(hmem.0)));
        let _ = CloseClipboard();
        result.is_ok()
    }
}

#[cfg(target_os = "macos")]
fn set_clipboard_image(_info: &crate::clipboard::content::ImageInfo) -> bool {
    // TODO: implement macOS image clipboard write via NSPasteboard
    tracing::warn!("clipboard image write not yet supported on macOS");
    false
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn set_clipboard_image(_info: &crate::clipboard::content::ImageInfo) -> bool {
    tracing::warn!("clipboard image write not supported on this platform");
    false
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard write: text
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn set_clipboard_text(text: &str) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }

        let _ = EmptyClipboard();

        // Convert to UTF-16 with null terminator
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = wide.len() * 2;

        let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
        if hmem.is_err() {
            let _ = CloseClipboard();
            return false;
        }
        let hmem = hmem.unwrap();

        let ptr = GlobalLock(hmem);
        if ptr.is_null() {
            let _ = CloseClipboard();
            return false;
        }

        std::ptr::copy_nonoverlapping(wide.as_ptr() as *const u8, ptr as *mut u8, byte_len);
        let _ = GlobalUnlock(hmem);

        let result = SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hmem.0)));
        let _ = CloseClipboard();
        result.is_ok()
    }
}

#[cfg(target_os = "macos")]
fn set_clipboard_text(text: &str) -> bool {
    // Use NSPasteboard to set string content
    use std::ffi::CString;
    unsafe {
        let pasteboard: objc2::rc::Retained<objc2::runtime::AnyObject> =
            objc2::msg_send![objc2::class!(NSPasteboard), generalPasteboard];
        let _: () = objc2::msg_send![&*pasteboard, clearContents];

        let cstr = match CString::new(text) {
            Ok(c) => c,
            Err(_) => return false,
        };
        let nsstring: objc2::rc::Retained<objc2::runtime::AnyObject> = objc2::msg_send![
            objc2::class!(NSString),
            stringWithUTF8String: cstr.as_ptr()
        ];
        let pasteboard_type: objc2::rc::Retained<objc2::runtime::AnyObject> = objc2::msg_send![objc2::class!(NSString), stringWithUTF8String: b"public.utf8-plain-text\0".as_ptr()];
        let result: bool =
            objc2::msg_send![&*pasteboard, setString: &*nsstring, forType: &*pasteboard_type];
        result
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn set_clipboard_text(_text: &str) -> bool {
    tracing::warn!("clipboard write not supported on this platform");
    false
}

// ---------------------------------------------------------------------------
// Image file detection & loading for file-type entries
// ---------------------------------------------------------------------------

const IMAGE_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "webp", "ico", "tiff", "tif",
];

/// Check if a file path looks like an image based on its extension.
pub fn is_image_file(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| IMAGE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Try to load a `DynamicImage` from a list of file paths.
/// Returns the first successfully loaded image if any path points to a valid image file.
fn load_image_from_file_paths(paths: &[std::path::PathBuf]) -> Option<image::DynamicImage> {
    for path in paths {
        if is_image_file(path) && path.exists() {
            if let Ok(img) = image::open(path) {
                return Some(img);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public wrappers for clipboard write (used by auto-copy from remote)
// ---------------------------------------------------------------------------

pub fn set_clipboard_text_public(text: &str) -> bool {
    set_clipboard_text(text)
}

pub fn set_clipboard_files_public(paths: &[std::path::PathBuf]) -> bool {
    set_clipboard_files(paths)
}

pub fn set_clipboard_image_public(info: &crate::clipboard::content::ImageInfo) -> bool {
    set_clipboard_image(info)
}
