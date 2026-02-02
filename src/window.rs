use std::panic::{self, AssertUnwindSafe};
use std::sync::atomic::{AtomicPtr, Ordering};

use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, HMENU, HWND_MESSAGE, RegisterClassW, WINDOW_STYLE, WNDCLASSW,
    WS_EX_NOACTIVATE,
};
use windows::core::w;

use crate::error::{ClipboardError, Result};

const CLASS_NAME: windows::core::PCWSTR = w!("FastCopyClipboardMonitor");

type WndProcHandler = dyn FnMut(HWND, u32, WPARAM, LPARAM) -> Option<LRESULT>;

/// Global handler pointer. Managed via AtomicPtr to avoid `static mut` (edition 2024).
/// SAFETY: Only accessed from the single-threaded Win32 message loop thread.
static HANDLER_PTR: AtomicPtr<Box<WndProcHandler>> = AtomicPtr::new(std::ptr::null_mut());

/// Set the window procedure handler. The caller must ensure the Box lives
/// long enough (until `clear_handler` is called).
pub fn set_handler(handler: Box<WndProcHandler>) {
    let ptr = Box::into_raw(Box::new(handler));
    let old = HANDLER_PTR.swap(ptr, Ordering::Release);
    if !old.is_null() {
        // Drop the old handler
        unsafe {
            drop(Box::from_raw(old));
        }
    }
}

/// Clear the handler and free its memory.
pub fn clear_handler() {
    let old = HANDLER_PTR.swap(std::ptr::null_mut(), Ordering::Release);
    if !old.is_null() {
        unsafe {
            drop(Box::from_raw(old));
        }
    }
}

pub unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Catch panics to prevent UB from unwinding across FFI boundary
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        let ptr = HANDLER_PTR.load(Ordering::Acquire);
        if !ptr.is_null() {
            // SAFETY: ptr is valid, and we're on the single message-loop thread.
            let handler = unsafe { &mut **ptr };
            if let Some(lr) = handler(hwnd, msg, wparam, lparam) {
                return lr;
            }
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }));

    match result {
        Ok(lr) => lr,
        Err(payload) => {
            let msg_str = if let Some(s) = payload.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic".to_string()
            };
            tracing::error!("panic caught in wnd_proc: {msg_str}");
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
    }
}

/// Creates an invisible message-only window for receiving clipboard notifications.
pub fn create_hidden_window() -> Result<HWND> {
    unsafe {
        let hinstance = GetModuleHandleW(None).map_err(ClipboardError::WindowCreationFailed)?;

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: hinstance.into(),
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };

        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            WS_EX_NOACTIVATE,
            CLASS_NAME,
            w!("FastCopy Clipboard Monitor"),
            WINDOW_STYLE::default(),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            Some(HMENU::default()),
            Some(hinstance.into()),
            None,
        )
        .map_err(ClipboardError::WindowCreationFailed)?;

        Ok(hwnd)
    }
}
