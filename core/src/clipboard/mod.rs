pub mod content;
#[cfg(target_os = "windows")]
pub mod monitor;
#[cfg(target_os = "macos")]
pub mod monitor_mac;
#[cfg(target_os = "windows")]
pub mod reader;
pub mod writer;

pub use content::{ClipboardContent, FileRef};
#[cfg(target_os = "windows")]
pub use monitor::ClipboardMonitor;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Event sent from the clipboard monitor to the main thread.
#[derive(Debug)]
pub struct ClipboardEvent {
    pub content: ClipboardContent,
    /// Whether this content should NOT be synced to the cloud/server.
    pub no_cloud: bool,
}

/// Flag to tell the clipboard monitor to skip the next change event.
/// Set this before programmatic clipboard writes to avoid recapturing our own output.
static SKIP_NEXT: AtomicBool = AtomicBool::new(false);

/// Mark that the next clipboard change is self-initiated and should be ignored.
pub fn mark_self_write() {
    SKIP_NEXT.store(true, Ordering::Release);
}

/// Check and clear the self-write flag. Returns `true` if the flag was set.
pub fn take_self_write() -> bool {
    SKIP_NEXT.swap(false, Ordering::AcqRel)
}

pub(crate) fn is_remote_clipboard_placeholder_path(path: &Path) -> bool {
    if path
        .to_string_lossy()
        .to_ascii_lowercase()
        .contains("com.netease.uuremote.server/clipboard/")
    {
        return true;
    }

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_remote_clipboard_placeholder_name)
}

pub(crate) fn is_remote_clipboard_placeholder_text(text: &str) -> bool {
    let text = text.trim().trim_matches(['"', '\'']);
    if text.is_empty() || text.lines().count() != 1 {
        return false;
    }

    if text
        .to_ascii_lowercase()
        .contains("com.netease.uuremote.server/clipboard/")
    {
        return true;
    }

    let name = text.rsplit(['/', '\\']).next().unwrap_or(text).trim();
    is_remote_clipboard_placeholder_name(name)
}

pub(crate) fn all_remote_clipboard_placeholders(paths: &[PathBuf]) -> bool {
    !paths.is_empty()
        && paths
            .iter()
            .all(|path| is_remote_clipboard_placeholder_path(path))
}

pub(crate) fn usable_clipboard_file_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter(|path| path.exists() && !is_remote_clipboard_placeholder_path(path))
        .collect()
}

fn is_remote_clipboard_placeholder_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with(".uuremote_")
        || name.starts_with(".1-sunloginclient")
        || name.starts_with(".sunloginclient")
        || name.contains("sunloginclient")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_remote_clipboard_placeholder_names() {
        assert!(is_remote_clipboard_placeholder_text(
            ".uuremote_aeaws06603548674402"
        ));
        assert!(is_remote_clipboard_placeholder_text(
            "/tmp/Downloads/.1-sunloginclient304844C3-928F-4770-A602-9AD8B58733ED"
        ));
        assert!(is_remote_clipboard_placeholder_text(
            "/tmp/Library/Application Support/com.netease.uuremote.server/Clipboard/.uuremote_x"
        ));
        assert!(!is_remote_clipboard_placeholder_text("normal-file.png"));
        assert!(!is_remote_clipboard_placeholder_text("hello\n.uuremote_x"));
    }
}
