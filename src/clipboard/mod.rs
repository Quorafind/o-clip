pub mod content;
#[cfg(target_os = "windows")]
pub mod monitor;
#[cfg(target_os = "macos")]
pub mod monitor_mac;
#[cfg(target_os = "windows")]
pub mod reader;

pub use content::{ClipboardContent, FileRef};
#[cfg(target_os = "windows")]
pub use monitor::ClipboardMonitor;

/// Event sent from the clipboard monitor to the main thread.
#[derive(Debug)]
pub struct ClipboardEvent {
    pub content: ClipboardContent,
    /// Whether this content should NOT be synced to the cloud/server.
    pub no_cloud: bool,
}

use std::sync::atomic::{AtomicBool, Ordering};

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
