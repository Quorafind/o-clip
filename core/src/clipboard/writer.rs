//! Platform-specific clipboard write helpers.
//!
//! UIs should generally call `crate::clipboard::mark_self_write()` before writing
//! so the clipboard monitor doesn't immediately recapture the programmatic write.

use std::path::PathBuf;

use super::content::ImageInfo;

// ---------------------------------------------------------------------------
// Platform-specific clipboard write: files (CF_HDROP / NSPasteboard)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn set_clipboard_files(paths: &[PathBuf]) -> bool {
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

    // Build the wide-char file list: each path null-terminated, double-null at end.
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

        // Zero out the DROPFILES header.
        std::ptr::write_bytes(ptr, 0, DROPFILES_SIZE);
        // pFiles: offset to file list (= size of DROPFILES).
        *(ptr as *mut u32) = DROPFILES_SIZE as u32;
        // fWide: TRUE (1) at offset 16.
        *((ptr as *mut u32).add(4)) = 1;

        // Copy file list after the header.
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
pub fn set_clipboard_files(paths: &[PathBuf]) -> bool {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{class, msg_send};
    use objc2_foundation::NSString;

    if paths.is_empty() {
        return false;
    }

    unsafe {
        // Get the general pasteboard.
        let pasteboard: Retained<AnyObject> = msg_send![class!(NSPasteboard), generalPasteboard];

        // Clear the pasteboard.
        let _: i64 = msg_send![&*pasteboard, clearContents];

        // Create an NSMutableArray to hold file URLs.
        let file_urls: Retained<AnyObject> = msg_send![class!(NSMutableArray), array];

        for path in paths {
            // Convert path to absolute path string.
            let abs_path = if path.is_absolute() {
                path.to_string_lossy().to_string()
            } else {
                std::env::current_dir()
                    .map(|cwd| cwd.join(path))
                    .unwrap_or_else(|_| path.to_path_buf())
                    .to_string_lossy()
                    .to_string()
            };

            // Create NSURL from file path.
            let path_nsstring: Retained<NSString> = NSString::from_str(&abs_path);
            let file_url: Option<Retained<AnyObject>> =
                msg_send![class!(NSURL), fileURLWithPath: &*path_nsstring];

            if let Some(url) = file_url {
                let _: () = msg_send![&*file_urls, addObject: &*url];
            }
        }

        // Check if we have any URLs.
        let count: usize = msg_send![&*file_urls, count];
        if count == 0 {
            return false;
        }

        // Write file URLs to pasteboard.
        // writeObjects: expects an array of objects conforming to NSPasteboardWriting.
        // NSURL conforms to this protocol.
        let success: bool = msg_send![&*pasteboard, writeObjects: &*file_urls];

        if success {
            tracing::debug!("set {} file URL(s) on macOS pasteboard", count);
        } else {
            tracing::warn!("failed to write file URLs to macOS pasteboard");
        }

        success
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn set_clipboard_files(_paths: &[PathBuf]) -> bool {
    tracing::warn!("clipboard file write not supported on this platform");
    false
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard write: image
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn png_to_dib(png_bytes: &[u8]) -> Option<Vec<u8>> {
    use image::GenericImageView;
    let img = image::load_from_memory(png_bytes).ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = img.dimensions();

    // Build BITMAPINFOHEADER (40 bytes) + bottom-up BGRA pixel data.
    let row_size = (w as usize) * 4;
    let pixel_data_size = row_size * (h as usize);
    let header_size: u32 = 40;
    let mut dib = Vec::with_capacity(header_size as usize + pixel_data_size);

    // BITMAPINFOHEADER
    dib.extend_from_slice(&header_size.to_le_bytes()); // biSize
    dib.extend_from_slice(&(w as i32).to_le_bytes()); // biWidth
    dib.extend_from_slice(&(h as i32).to_le_bytes()); // biHeight (positive = bottom-up)
    dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    dib.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
    dib.extend_from_slice(&(pixel_data_size as u32).to_le_bytes()); // biSizeImage
    dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
    dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
    dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    // Pixel data: bottom-up rows, BGRA order.
    for y in (0..h).rev() {
        for x in 0..w {
            let px = rgba.get_pixel(x, y);
            dib.push(px[2]); // B
            dib.push(px[1]); // G
            dib.push(px[0]); // R
            dib.push(px[3]); // A
        }
    }

    Some(dib)
}

#[cfg(target_os = "windows")]
pub fn set_clipboard_image(info: &ImageInfo) -> bool {
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

    // For PNG entries (e.g. from macOS), convert to DIB so Windows apps can paste.
    let (format, dib_bytes): (u32, std::borrow::Cow<[u8]>) = match info.format {
        super::content::ImageFormat::DibV5 => (CF_DIBV5.0 as u32, std::borrow::Cow::Borrowed(&bytes)),
        super::content::ImageFormat::Dib | super::content::ImageFormat::Bitmap => {
            (CF_DIB.0 as u32, std::borrow::Cow::Borrowed(&bytes))
        }
        super::content::ImageFormat::Png => match png_to_dib(&bytes) {
            Some(dib) => (CF_DIB.0 as u32, std::borrow::Cow::Owned(dib)),
            None => {
                tracing::warn!("failed to convert PNG to DIB for clipboard");
                return false;
            }
        },
    };

    unsafe {
        if OpenClipboard(None).is_err() {
            return false;
        }
        let _ = EmptyClipboard();

        let hmem = match GlobalAlloc(GMEM_MOVEABLE, dib_bytes.len()) {
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

        std::ptr::copy_nonoverlapping(dib_bytes.as_ptr(), ptr, dib_bytes.len());
        let _ = GlobalUnlock(hmem);

        let result = SetClipboardData(format, Some(HANDLE(hmem.0)));
        let _ = CloseClipboard();
        result.is_ok()
    }
}

#[cfg(target_os = "macos")]
pub fn set_clipboard_image(info: &ImageInfo) -> bool {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let raw_b64 = match &info.raw_data {
        Some(d) => d,
        None => return false,
    };
    let png_bytes = match BASE64.decode(raw_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // For non-PNG formats, convert via the `image` crate to PNG bytes first.
    let png_data = match info.format {
        super::content::ImageFormat::Png => png_bytes,
        _ => {
            let dyn_img = match info.to_dynamic_image() {
                Some(img) => img,
                None => return false,
            };
            let mut buf = Vec::new();
            if dyn_img
                .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
                .is_err()
            {
                return false;
            }
            buf
        }
    };

    unsafe {
        let pasteboard: objc2::rc::Retained<objc2::runtime::AnyObject> =
            objc2::msg_send![objc2::class!(NSPasteboard), generalPasteboard];
        let _: () = objc2::msg_send![&*pasteboard, clearContents];

        // Create NSData from PNG bytes.
        let nsdata: objc2::rc::Retained<objc2::runtime::AnyObject> = objc2::msg_send![
            objc2::class!(NSData),
            dataWithBytes: png_data.as_ptr(),
            length: png_data.len()
        ];

        // Set as public.png.
        let png_type: objc2::rc::Retained<objc2::runtime::AnyObject> = objc2::msg_send![
            objc2::class!(NSString),
            stringWithUTF8String: b"public.png\0".as_ptr()
        ];
        let result: bool =
            objc2::msg_send![&*pasteboard, setData: &*nsdata, forType: &*png_type];
        result
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn set_clipboard_image(_info: &ImageInfo) -> bool {
    tracing::warn!("clipboard image write not supported on this platform");
    false
}

// ---------------------------------------------------------------------------
// Platform-specific clipboard write: text
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn set_clipboard_text(text: &str) -> bool {
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

        // Convert to UTF-16 with null terminator.
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
pub fn set_clipboard_text(text: &str) -> bool {
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
        let pasteboard_type: objc2::rc::Retained<objc2::runtime::AnyObject> = objc2::msg_send![
            objc2::class!(NSString),
            stringWithUTF8String: b"public.utf8-plain-text\0".as_ptr()
        ];
        let result: bool =
            objc2::msg_send![&*pasteboard, setString: &*nsstring, forType: &*pasteboard_type];
        result
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn set_clipboard_text(_text: &str) -> bool {
    tracing::warn!("clipboard write not supported on this platform");
    false
}
