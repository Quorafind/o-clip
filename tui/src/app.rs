use std::sync::Arc;

use ratatui_image::picker::Picker;
use ratatui_image::protocol::StatefulProtocol;
use tokio::sync::Notify;

use o_clip_core::clipboard::{self, ClipboardContent};
use o_clip_core::entry_manager::{self, EntryManager};
use o_clip_core::file_transfer::FileRequest;
use o_clip_core::store::{ClipboardEntry, Store};

/// TUI application modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
}

/// TUI application state (wraps shared core logic).
pub struct App {
    pub manager: EntryManager,
    pub mode: Mode,
    pub should_quit: bool,

    /// Terminal graphics protocol picker for image rendering.
    picker: Option<Picker>,
    /// Cached image preview protocol state (for the currently selected image entry).
    pub image_preview: Option<StatefulProtocol>,
    /// Entry ID that `image_preview` was generated for (cache key).
    image_preview_for: Option<i64>,

    /// Notify handle to trigger manual WS reconnect.
    pub reconnect_notify: Option<Arc<Notify>>,
}

impl App {
    pub fn new(store: Store, max_entries: usize, picker: Option<Picker>) -> Self {
        let mut app = Self {
            manager: EntryManager::new(store, max_entries),
            mode: Mode::Normal,
            should_quit: false,
            picker,
            image_preview: None,
            image_preview_for: None,
            reconnect_notify: None,
        };
        app.update_image_preview();
        app
    }

    /// Reload entries from the database.
    pub fn reload_entries(&mut self) {
        self.manager.reload_entries();
        self.update_image_preview();
    }

    /// Rebuild the cached image preview if the selected entry changed.
    fn update_image_preview(&mut self) {
        let current_id = self
            .manager
            .entries
            .get(self.manager.selected)
            .map(|e| e.id);

        // Already cached for this entry.
        if current_id == self.image_preview_for && self.image_preview.is_some() {
            return;
        }

        self.image_preview = None;
        self.image_preview_for = current_id;

        // Load content on demand (needed for both image and text preview).
        self.manager.ensure_selected_content_loaded();

        let picker = match &mut self.picker {
            Some(p) => p,
            None => return,
        };

        let entry = match self.manager.entries.get(self.manager.selected) {
            Some(e) => e,
            None => return,
        };

        let dyn_img = match entry.to_clipboard_content() {
            Some(ClipboardContent::Image(info)) => info.to_dynamic_image(),
            Some(ClipboardContent::Files(paths)) => {
                entry_manager::load_image_from_file_paths(&paths)
            }
            // SyncedImage: image data is on the server, no local preview available
            // without downloading. Skip for now to avoid blocking the UI.
            Some(ClipboardContent::SyncedImage(_)) => None,
            _ => None,
        };

        if let Some(img) = dyn_img {
            let proto = picker.new_resize_protocol(img);
            self.image_preview = Some(proto);
        }
    }

    /// Handle a new clipboard entry (from monitor or remote sync).
    pub fn on_new_entry(&mut self, entry: ClipboardEntry) {
        self.manager.on_new_entry(entry);
        self.update_image_preview();
    }

    /// Handle a batch of new entries (e.g. from sync). Uses single DB reload.
    pub fn on_new_entries_batch(&mut self, entries: Vec<ClipboardEntry>) {
        self.manager.on_new_entries_batch(entries);
        self.update_image_preview();
    }

    pub fn select_prev(&mut self) {
        self.manager.select_prev();
        self.update_image_preview();
    }

    pub fn select_next(&mut self) {
        self.manager.select_next();
        self.update_image_preview();
    }

    pub fn select_first(&mut self) {
        self.manager.select_first();
        self.update_image_preview();
    }

    pub fn select_last(&mut self) {
        self.manager.select_last();
        self.update_image_preview();
    }

    pub fn toggle_pin_selected(&mut self) {
        self.manager.toggle_pin_selected();
        self.update_image_preview();
    }

    pub fn delete_selected(&mut self) {
        self.manager.delete_selected();
        self.update_image_preview();
    }

    /// Copy the selected entry's content back to the system clipboard.
    pub fn copy_selected_to_clipboard(&mut self) {
        self.manager.ensure_selected_content_loaded();
        let Some(content) = self.manager.get_selected_content() else {
            self.manager.status_message = Some("Cannot restore this content type".to_string());
            return;
        };

        match &content {
            ClipboardContent::Text(t) => {
                clipboard::mark_self_write();
                if o_clip_core::clipboard::writer::set_clipboard_text(t) {
                    self.manager.status_message = Some("Copied to clipboard".to_string());
                } else {
                    self.manager.status_message = Some("Failed to set clipboard".to_string());
                }
            }
            ClipboardContent::Url(u) => {
                clipboard::mark_self_write();
                if o_clip_core::clipboard::writer::set_clipboard_text(u) {
                    self.manager.status_message = Some("Copied URL to clipboard".to_string());
                } else {
                    self.manager.status_message = Some("Failed to set clipboard".to_string());
                }
            }
            ClipboardContent::Files(paths) => {
                clipboard::mark_self_write();
                if o_clip_core::clipboard::writer::set_clipboard_files(paths) {
                    self.manager.status_message =
                        Some(format!("Copied {} file(s) to clipboard", paths.len()));
                } else {
                    self.manager.status_message =
                        Some("Failed to set files on clipboard".to_string());
                }
            }
            ClipboardContent::SyncedFiles(refs) => {
                self.manager.status_message = Some(format!(
                    "{} synced file(s) - select and download first",
                    refs.len()
                ));
            }
            ClipboardContent::Image(info) => {
                if info.raw_data.is_none() {
                    self.manager.status_message =
                        Some("Image too large, raw data was not stored".to_string());
                } else {
                    clipboard::mark_self_write();
                    if o_clip_core::clipboard::writer::set_clipboard_image(info) {
                        self.manager.status_message = Some("Copied image to clipboard".to_string());
                    } else {
                        self.manager.status_message =
                            Some("Failed to set image on clipboard".to_string());
                    }
                }
            }
            ClipboardContent::SyncedImage(img_ref) => {
                // SyncedImage data is on the server; cannot restore directly from history.
                // The image was already written to clipboard when it was synced.
                self.manager.status_message = Some(format!(
                    "Synced image {}x{} - data stored on server",
                    img_ref.width, img_ref.height
                ));
            }
            ClipboardContent::Empty => {
                self.manager.status_message = Some("Nothing to copy".to_string());
            }
        }
    }

    /// Re-download synced files for the selected entry.
    /// Returns a FileRequest if re-fetch is possible.
    pub fn refetch_selected_files(&mut self) -> Option<FileRequest> {
        self.manager.ensure_selected_content_loaded();
        let content = self.manager.get_selected_content()?;
        match content {
            ClipboardContent::SyncedFiles(refs) => {
                let n = refs.len();
                self.manager.status_message = Some(format!("Re-downloading {n} file(s)..."));
                Some(FileRequest::Download { refs })
            }
            ClipboardContent::Files(paths) => {
                let any_missing = paths.iter().any(|p| !p.exists());
                if any_missing {
                    self.manager.status_message =
                        Some("Local files deleted - no server copy for re-fetch".to_string());
                } else {
                    self.manager.status_message = Some("All files exist".to_string());
                }
                None
            }
            _ => {
                self.manager.status_message = Some("Not a file entry".to_string());
                None
            }
        }
    }

    pub fn enter_search(&mut self) {
        self.mode = Mode::Search;
        self.manager.search_query.clear();
    }

    pub fn exit_search(&mut self) {
        self.mode = Mode::Normal;
        self.manager.clear_search();
        self.update_image_preview();
    }

    pub fn update_search(&mut self, query: String) {
        self.manager.update_search(query);
        self.update_image_preview();
    }

    pub fn selected_entry(&self) -> Option<&ClipboardEntry> {
        self.manager.selected_entry()
    }
}
