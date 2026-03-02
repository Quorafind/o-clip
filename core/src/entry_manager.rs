use crate::clipboard::ClipboardContent;
use crate::store::{ClipboardEntry, Store};
use crate::sync::ConnectionStatus;

/// Shared business logic for UI frontends.
///
/// This keeps "what to do" (store/search/select/pin/delete) in one place,
/// while UIs handle "how to present" (TUI rendering, GUI widgets, etc).
pub struct EntryManager {
    /// All displayed entries (loaded from DB).
    pub entries: Vec<ClipboardEntry>,
    /// Currently selected index in the list.
    pub selected: usize,
    /// Search input buffer.
    pub search_query: String,
    /// WebSocket connection status.
    pub ws_status: ConnectionStatus,
    /// Total entry count (may differ from entries.len() if search is active).
    pub total_count: usize,
    /// Status message shown temporarily.
    pub status_message: Option<String>,
    /// Database store.
    store: Store,
    /// Max entries config.
    max_entries: usize,
}

impl EntryManager {
    pub fn new(store: Store, max_entries: usize) -> Self {
        let entries = store.list_metadata(500, 0).unwrap_or_default();
        let total_count = store.count().unwrap_or(0);
        Self {
            entries,
            selected: 0,
            search_query: String::new(),
            ws_status: ConnectionStatus::Disconnected,
            total_count,
            status_message: None,
            store,
            max_entries,
        }
    }

    /// Reload entries from the database (metadata only, content loaded on demand).
    pub fn reload_entries(&mut self) {
        if self.search_query.is_empty() {
            self.entries = self.store.list_metadata(500, 0).unwrap_or_default();
        } else {
            self.entries = self
                .store
                .search_metadata(&self.search_query)
                .unwrap_or_default();
        }
        self.total_count = self.store.count().unwrap_or(0);

        // Clamp selected index.
        if !self.entries.is_empty() && self.selected >= self.entries.len() {
            self.selected = self.entries.len() - 1;
        }
    }

    /// Ensure the currently selected entry has its `content` field loaded from
    /// the database. This is a no-op if the content is already present.
    pub fn ensure_selected_content_loaded(&mut self) {
        if let Some(entry) = self.entries.get_mut(self.selected) {
            if entry.content.is_empty() {
                if let Ok(Some(content)) = self.store.get_content(entry.id) {
                    entry.content = content;
                }
            }
        }
    }

    /// Handle a new clipboard entry (from monitor or remote sync).
    pub fn on_new_entry(&mut self, entry: ClipboardEntry) {
        if let Err(e) = self.store.insert(&entry) {
            tracing::warn!("failed to store clipboard entry: {e}");
            return;
        }
        // Enforce storage limit.
        let _ = self.store.enforce_limit(self.max_entries);
        self.reload_entries();
    }

    /// Handle a batch of new entries (e.g. from sync). Inserts all entries in a
    /// single transaction, then does one reload. This avoids the O(n²) problem
    /// of reloading after every insert.
    pub fn on_new_entries_batch(&mut self, entries: Vec<ClipboardEntry>) {
        if entries.is_empty() {
            return;
        }
        if let Err(e) = self.store.insert_batch(&entries) {
            tracing::warn!("batch insert failed: {e}");
        }
        let _ = self.store.enforce_limit(self.max_entries);
        self.reload_entries();
    }

    /// Move selection up.
    pub fn select_prev(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down.
    pub fn select_next(&mut self) {
        if !self.entries.is_empty() && self.selected < self.entries.len() - 1 {
            self.selected += 1;
        }
    }

    /// Jump to top.
    pub fn select_first(&mut self) {
        self.selected = 0;
    }

    /// Jump to bottom.
    pub fn select_last(&mut self) {
        if !self.entries.is_empty() {
            self.selected = self.entries.len() - 1;
        }
    }

    /// Toggle pin on the currently selected entry.
    pub fn toggle_pin_selected(&mut self) {
        if let Some(entry) = self.entries.get(self.selected) {
            let id = entry.id;
            match self.store.toggle_pin(id) {
                Ok(pinned) => {
                    self.status_message = Some(if pinned {
                        "Entry pinned".to_string()
                    } else {
                        "Entry unpinned".to_string()
                    });
                    self.reload_entries();
                }
                Err(e) => {
                    tracing::warn!("failed to toggle pin for entry {id}: {e}");
                }
            }
        }
    }

    /// Delete all entries from the database.
    pub fn delete_all(&mut self) {
        if let Err(e) = self.store.delete_all() {
            tracing::warn!("failed to delete all entries: {e}");
            return;
        }
        self.reload_entries();
        self.status_message = Some("All entries deleted".to_string());
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

    /// Update search query and refresh results.
    pub fn update_search(&mut self, query: String) {
        self.search_query = query;
        self.selected = 0;
        self.reload_entries();
    }

    /// Clear search and show all entries.
    pub fn clear_search(&mut self) {
        self.search_query.clear();
        self.selected = 0;
        self.reload_entries();
    }

    /// Get the currently selected entry (if any).
    pub fn selected_entry(&self) -> Option<&ClipboardEntry> {
        self.entries.get(self.selected)
    }

    /// Deserialize the selected entry into a ClipboardContent (if possible).
    pub fn get_selected_content(&self) -> Option<ClipboardContent> {
        self.selected_entry()?.to_clipboard_content()
    }

    /// Access the store directly.
    #[allow(dead_code)]
    pub fn store(&self) -> &Store {
        &self.store
    }
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
pub fn load_image_from_file_paths(paths: &[std::path::PathBuf]) -> Option<image::DynamicImage> {
    for path in paths {
        if is_image_file(path) && path.exists() {
            // Skip files larger than 10MB to avoid blocking UI.
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.len() > 10 * 1024 * 1024 {
                    tracing::debug!("skipping large image file: {}", path.display());
                    continue;
                }
            }
            if let Ok(img) = image::open(path) {
                return Some(img);
            }
        }
    }
    None
}
