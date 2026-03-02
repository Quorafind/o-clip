pub mod clipboard;
pub mod config;
pub mod entry_manager;
pub mod error;
pub mod file_transfer;
pub mod store;
pub mod sync;
#[cfg(target_os = "windows")]
pub mod window;

use crate::clipboard::ClipboardContent;
use crate::store::ClipboardEntry;

// ---------------------------------------------------------------------------
// Helpers shared across UI frontends
// ---------------------------------------------------------------------------

/// Recompute the entry hash using the client-side pixel-based algorithm.
///
/// Server entries use a different hash (content_type:content_json) which produces
/// different hashes for the same image in different formats (PNG vs DibV5).
/// By normalizing to the client hash, the local DB's UNIQUE(hash) constraint can
/// deduplicate cross-format images.
pub fn normalize_entry_hash(entry: &mut ClipboardEntry) {
    if let Some(content) = entry.to_clipboard_content() {
        entry.hash = content.content_hash();
    }
}

/// Auto-copy a remote entry to the local clipboard.
///
/// Uses `mark_self_write()` so the clipboard monitor ignores the change and the
/// entry is NOT re-uploaded to the server.
pub fn auto_copy_to_clipboard(entry: &ClipboardEntry) {
    let Some(content) = entry.to_clipboard_content() else {
        return;
    };

    // Only mark_self_write() when we actually write to the clipboard.
    // Calling it without a subsequent clipboard write would cause the monitor
    // to incorrectly skip the next real clipboard change.
    match &content {
        ClipboardContent::Text(t) => {
            clipboard::mark_self_write();
            let _ = clipboard::writer::set_clipboard_text(t);
        }
        ClipboardContent::Url(u) => {
            clipboard::mark_self_write();
            let _ = clipboard::writer::set_clipboard_text(u);
        }
        ClipboardContent::Files(paths) => {
            clipboard::mark_self_write();
            let _ = clipboard::writer::set_clipboard_files(paths);
        }
        ClipboardContent::SyncedFiles(_) => {
            // SyncedFiles are downloaded asynchronously via the file transfer channel.
            // Don't set clipboard here; it will be set when the download completes.
            // Do NOT call mark_self_write() since we're not writing to the clipboard.
        }
        ClipboardContent::Image(info) => {
            // Local images are uploaded and converted to SyncedImage before sync.
            // This branch handles legacy inline images if any remain in the DB.
            clipboard::mark_self_write();
            let _ = clipboard::writer::set_clipboard_image(info);
        }
        ClipboardContent::SyncedImage(_) => {
            // SyncedImage is downloaded asynchronously via the file transfer channel.
            // Don't set clipboard here; it will be set when the download completes.
            // Do NOT call mark_self_write() since we're not writing to the clipboard.
        }
        ClipboardContent::Empty => {}
    }
}
