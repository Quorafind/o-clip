use std::sync::mpsc::Sender;

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, GetClipboardSequenceNumber, RemoveClipboardFormatListener,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyWindow, DispatchMessageW, GetMessageW, MSG, PostQuitMessage, TranslateMessage,
    WM_CLIPBOARDUPDATE, WM_DESTROY,
};

use crate::clipboard::ClipboardEvent;
use crate::clipboard::content::ClipboardContent;
use crate::clipboard::reader::ClipboardGuard;
use crate::error::{ClipboardError, Result};
use crate::window;

/// Monitors the Windows clipboard for changes using AddClipboardFormatListener.
pub struct ClipboardMonitor {
    hwnd: HWND,
}

impl ClipboardMonitor {
    /// Creates the monitor, registers the clipboard listener, and enters the
    /// message loop. This function **blocks** the calling thread until the
    /// window is destroyed (e.g. via Ctrl+C handler posting WM_CLOSE).
    ///
    /// Clipboard events are sent through the `tx` channel. Sensitive content
    /// (from password managers, etc.) is automatically filtered out.
    pub fn run(tx: Sender<ClipboardEvent>) -> Result<()> {
        let mut last_seq: u32 = 0;
        let mut last_hash = String::new();

        // Install the window procedure handler
        window::set_handler(Box::new(
            move |hwnd: HWND, msg: u32, _wparam: WPARAM, _lparam: LPARAM| -> Option<LRESULT> {
                match msg {
                    WM_CLIPBOARDUPDATE => {
                        // Skip self-initiated clipboard writes from the app
                        if crate::clipboard::take_self_write() {
                            tracing::debug!("clipboard: skipping self-initiated write");
                            return Some(LRESULT(0));
                        }

                        // Deduplicate: skip if sequence number unchanged
                        let seq = unsafe { GetClipboardSequenceNumber() };
                        if seq != 0 && seq == last_seq {
                            return Some(LRESULT(0));
                        }
                        last_seq = seq;

                        match ClipboardGuard::open() {
                            Ok(guard) => {
                                // Check sensitivity before reading content
                                let sensitivity = guard.check_sensitivity();
                                if sensitivity.exclude {
                                    tracing::debug!(
                                        "clipboard: skipping sensitive content (password manager, etc.)"
                                    );
                                    return Some(LRESULT(0));
                                }

                                let content = guard.read_content();
                                drop(guard); // close clipboard before further processing

                                // Skip empty content
                                if matches!(&content, ClipboardContent::Empty) {
                                    return Some(LRESULT(0));
                                }

                                // Content-hash based dedup (catches same content
                                // arriving via different sequence numbers)
                                let hash = content.content_hash();
                                if hash == last_hash {
                                    tracing::debug!(
                                        "clipboard: skipping duplicate content (same hash)"
                                    );
                                    return Some(LRESULT(0));
                                }
                                last_hash = hash;

                                let event = ClipboardEvent {
                                    content,
                                    no_cloud: sensitivity.no_cloud,
                                };

                                if tx.send(event).is_err() {
                                    tracing::warn!("clipboard event channel closed");
                                }
                            }
                            Err(e) => {
                                tracing::warn!("clipboard open failed (locked?): {e}");
                            }
                        }
                        Some(LRESULT(0))
                    }
                    WM_DESTROY => {
                        unsafe {
                            let _ = RemoveClipboardFormatListener(hwnd);
                            PostQuitMessage(0);
                        }
                        Some(LRESULT(0))
                    }
                    _ => None, // let DefWindowProcW handle it
                }
            },
        ));

        let hwnd = window::create_hidden_window()?;
        let monitor = ClipboardMonitor { hwnd };

        unsafe {
            AddClipboardFormatListener(hwnd).map_err(ClipboardError::ListenerRegistrationFailed)?;
        }

        tracing::info!("clipboard monitor started, listening for changes...");

        // Store HWND in a global so Ctrl+C handler can post WM_CLOSE
        set_monitor_hwnd(hwnd);

        // Message loop
        unsafe {
            let mut msg = MSG::default();
            while GetMessageW(&mut msg, None, 0, 0).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        drop(monitor);
        tracing::info!("clipboard monitor stopped");
        Ok(())
    }
}

impl Drop for ClipboardMonitor {
    fn drop(&mut self) {
        unsafe {
            let _ = RemoveClipboardFormatListener(self.hwnd);
            let _ = DestroyWindow(self.hwnd);
        }
        window::clear_handler();
    }
}

// Global HWND for the Ctrl+C handler to signal shutdown
static MONITOR_HWND: std::sync::atomic::AtomicIsize = std::sync::atomic::AtomicIsize::new(0);

fn set_monitor_hwnd(hwnd: HWND) {
    MONITOR_HWND.store(hwnd.0 as isize, std::sync::atomic::Ordering::Release);
}

/// Retrieve the monitor HWND (for signaling shutdown from another thread).
pub fn get_monitor_hwnd() -> Option<HWND> {
    let val = MONITOR_HWND.load(std::sync::atomic::Ordering::Acquire);
    if val == 0 {
        None
    } else {
        Some(HWND(val as *mut core::ffi::c_void))
    }
}
