use std::path::PathBuf;
use std::sync::OnceLock;

use windows::Win32::Foundation::{HANDLE, HGLOBAL};
use windows::Win32::Graphics::Gdi::BITMAPINFOHEADER;
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    RegisterClipboardFormatW,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
use windows::Win32::System::Ole::{CF_DIB, CF_DIBV5, CF_HDROP, CF_UNICODETEXT};
use windows::Win32::UI::Shell::{DragQueryFileW, HDROP};
use windows::core::w;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::clipboard::content::{ClipboardContent, ImageFormat, ImageInfo, classify_text};
use crate::error::{ClipboardError, Result};

/// Maximum raw image data size we'll store (10 MB). Larger images get metadata only.
const MAX_IMAGE_STORE_SIZE: usize = 10 * 1024 * 1024;

/// Cached registered format IDs for sensitive content detection.
struct SensitiveFormats {
    exclude_from_monitor: u32,
    can_include_in_history: u32,
    can_upload_to_cloud: u32,
}

/// Sensitivity check result.
#[derive(Debug, Clone, Copy)]
pub struct SensitivityInfo {
    /// Content should not be recorded at all.
    pub exclude: bool,
    /// Content should not be synced to cloud/server.
    pub no_cloud: bool,
}

static SENSITIVE_FORMATS: OnceLock<SensitiveFormats> = OnceLock::new();

fn get_sensitive_formats() -> &'static SensitiveFormats {
    SENSITIVE_FORMATS.get_or_init(|| unsafe {
        SensitiveFormats {
            exclude_from_monitor: RegisterClipboardFormatW(w!(
                "ExcludeClipboardContentFromMonitorProcessing"
            )),
            can_include_in_history: RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory")),
            can_upload_to_cloud: RegisterClipboardFormatW(w!("CanUploadToCloudClipboard")),
        }
    })
}

/// RAII guard that opens the clipboard on creation and closes it on drop.
pub struct ClipboardGuard {
    _private: (),
}

impl ClipboardGuard {
    /// Opens the clipboard associated with the current task's window.
    pub fn open() -> Result<Self> {
        unsafe {
            OpenClipboard(None).map_err(ClipboardError::OpenFailed)?;
        }
        Ok(Self { _private: () })
    }

    /// Check whether the current clipboard content is marked as sensitive.
    ///
    /// Password managers (1Password, etc.) and Windows itself set special
    /// clipboard formats to signal that monitors should not record the data.
    pub fn check_sensitivity(&self) -> SensitivityInfo {
        let fmts = get_sensitive_formats();
        let mut info = SensitivityInfo {
            exclude: false,
            no_cloud: false,
        };

        // If ExcludeClipboardContentFromMonitorProcessing is present, skip entirely.
        if fmts.exclude_from_monitor != 0 {
            if unsafe { IsClipboardFormatAvailable(fmts.exclude_from_monitor).is_ok() } {
                info.exclude = true;
                return info;
            }
        }

        // CanIncludeInClipboardHistory: if present with DWORD value 0, exclude.
        if fmts.can_include_in_history != 0 {
            if unsafe { IsClipboardFormatAvailable(fmts.can_include_in_history).is_ok() } {
                if let Some(val) = self.read_dword_format(fmts.can_include_in_history) {
                    if val == 0 {
                        info.exclude = true;
                        return info;
                    }
                }
            }
        }

        // CanUploadToCloudClipboard: if present with DWORD value 0, don't sync.
        if fmts.can_upload_to_cloud != 0 {
            if unsafe { IsClipboardFormatAvailable(fmts.can_upload_to_cloud).is_ok() } {
                if let Some(val) = self.read_dword_format(fmts.can_upload_to_cloud) {
                    if val == 0 {
                        info.no_cloud = true;
                    }
                }
            }
        }

        info
    }

    /// Read a DWORD value from a registered clipboard format.
    fn read_dword_format(&self, format: u32) -> Option<u32> {
        unsafe {
            let handle = GetClipboardData(format).ok()?;
            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal);
            if ptr.is_null() {
                return None;
            }
            let size = GlobalSize(hglobal);
            let val = if size >= 4 {
                Some(*(ptr as *const u32))
            } else {
                None
            };
            let _ = GlobalUnlock(hglobal);
            val
        }
    }

    /// Reads the current clipboard content, probing formats in priority order:
    /// CF_HDROP (files) > image formats (DIB/DIBV5/PNG) > CF_UNICODETEXT (text/URL)
    pub fn read_content(&self) -> ClipboardContent {
        // 1. Check for files (CF_HDROP) first
        if unsafe { IsClipboardFormatAvailable(CF_HDROP.0 as u32).is_ok() } {
            match self.read_files() {
                Ok(paths) if !paths.is_empty() => return ClipboardContent::Files(paths),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("failed to read CF_HDROP: {e}");
                }
            }
        }

        // 2. Check for images (PNG > CF_DIBV5 > CF_DIB)
        if let Some(content) = self.try_read_image() {
            return content;
        }

        // 3. Check for Unicode text
        if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok() } {
            match self.read_text() {
                Ok(text) if !text.is_empty() => return classify_text(text),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("failed to read CF_UNICODETEXT: {e}");
                }
            }
        }

        ClipboardContent::Empty
    }

    /// Try reading an image from clipboard.
    ///
    /// Priority: CF_DIBV5 > CF_DIB > PNG.
    /// DIB formats are preferred because nearly every Windows application
    /// understands CF_DIB when pasting, and Windows auto-synthesizes
    /// CF_BITMAP from it.  The registered "PNG" format is only recognised
    /// by a few apps (browsers, some editors), so restoring a clipboard
    /// entry that was captured as PNG would silently fail in most programs.
    fn try_read_image(&self) -> Option<ClipboardContent> {
        // Try CF_DIBV5 first (extended DIB with alpha channel)
        if unsafe { IsClipboardFormatAvailable(CF_DIBV5.0 as u32).is_ok() } {
            match self.read_dib(CF_DIBV5.0 as u32, ImageFormat::DibV5) {
                Ok(info) => return Some(ClipboardContent::Image(info)),
                Err(e) => tracing::warn!("failed to read CF_DIBV5: {e}"),
            }
        }

        // Try CF_DIB (standard device-independent bitmap)
        if unsafe { IsClipboardFormatAvailable(CF_DIB.0 as u32).is_ok() } {
            match self.read_dib(CF_DIB.0 as u32, ImageFormat::Dib) {
                Ok(info) => return Some(ClipboardContent::Image(info)),
                Err(e) => tracing::warn!("failed to read CF_DIB: {e}"),
            }
        }

        // Fallback: try PNG registered format
        let png_format = unsafe { RegisterClipboardFormatW(w!("PNG")) };
        if png_format != 0 {
            if unsafe { IsClipboardFormatAvailable(png_format).is_ok() } {
                match self.read_png(png_format) {
                    Ok(info) => return Some(ClipboardContent::Image(info)),
                    Err(e) => tracing::warn!("failed to read PNG format: {e}"),
                }
            }
        }

        None
    }

    /// Read a DIB/DIBV5 format image from clipboard.
    /// The data starts with a BITMAPINFOHEADER (or BITMAPV5HEADER for DIBV5).
    fn read_dib(&self, format: u32, img_format: ImageFormat) -> Result<ImageInfo> {
        unsafe {
            let handle: HANDLE =
                GetClipboardData(format).map_err(|_| ClipboardError::DataUnavailable(format))?;

            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal);
            if ptr.is_null() {
                return Err(ClipboardError::GlobalLockFailed);
            }

            let data_size = GlobalSize(hglobal);

            // Read BITMAPINFOHEADER (first 40 bytes, shared by both DIB and DIBV5)
            let header = if data_size >= size_of::<BITMAPINFOHEADER>() {
                &*(ptr as *const BITMAPINFOHEADER)
            } else {
                let _ = GlobalUnlock(hglobal);
                return Err(ClipboardError::DataUnavailable(format));
            };

            let raw_data = if data_size <= MAX_IMAGE_STORE_SIZE {
                let bytes = std::slice::from_raw_parts(ptr as *const u8, data_size);
                Some(BASE64.encode(bytes))
            } else {
                None
            };

            let info = ImageInfo {
                width: header.biWidth as u32,
                height: header.biHeight.unsigned_abs(),
                bits_per_pixel: header.biBitCount,
                data_size,
                format: img_format,
                raw_data,
            };

            let _ = GlobalUnlock(hglobal);
            Ok(info)
        }
    }

    /// Read a PNG format image from clipboard (registered format).
    /// PNG data is raw bytes -- we parse the IHDR chunk for dimensions.
    fn read_png(&self, format: u32) -> Result<ImageInfo> {
        unsafe {
            let handle: HANDLE =
                GetClipboardData(format).map_err(|_| ClipboardError::DataUnavailable(format))?;

            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal) as *const u8;
            if ptr.is_null() {
                return Err(ClipboardError::GlobalLockFailed);
            }

            let data_size = GlobalSize(hglobal);
            let data = std::slice::from_raw_parts(ptr, data_size);

            let raw_data = if data_size <= MAX_IMAGE_STORE_SIZE {
                Some(BASE64.encode(data))
            } else {
                None
            };

            // PNG IHDR: 8-byte signature + 4-byte chunk length + 4-byte "IHDR" + 4-byte width + 4-byte height + 1 bit depth + ...
            // Minimum 24 bytes needed to read width and height
            let info = if data_size >= 24 {
                // Width at offset 16, height at offset 20 (big-endian u32)
                let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
                // Bit depth at offset 24 if available
                let bit_depth = if data_size > 24 { data[24] } else { 0 };
                // Color type at offset 25
                let color_type = if data_size > 25 { data[25] } else { 0 };
                let channels: u16 = match color_type {
                    0 => 1, // grayscale
                    2 => 3, // RGB
                    4 => 2, // grayscale + alpha
                    6 => 4, // RGBA
                    _ => 1,
                };

                ImageInfo {
                    width,
                    height,
                    bits_per_pixel: bit_depth as u16 * channels,
                    data_size,
                    format: ImageFormat::Png,
                    raw_data,
                }
            } else {
                ImageInfo {
                    width: 0,
                    height: 0,
                    bits_per_pixel: 0,
                    data_size,
                    format: ImageFormat::Png,
                    raw_data,
                }
            };

            let _ = GlobalUnlock(hglobal);
            Ok(info)
        }
    }

    fn read_files(&self) -> Result<Vec<PathBuf>> {
        unsafe {
            let handle: HANDLE = GetClipboardData(CF_HDROP.0 as u32)
                .map_err(|_| ClipboardError::DataUnavailable(CF_HDROP.0 as u32))?;

            let hdrop = HDROP(handle.0);
            let count = DragQueryFileW(hdrop, 0xFFFFFFFF, None);

            let mut paths = Vec::with_capacity(count as usize);
            for i in 0..count {
                let len = DragQueryFileW(hdrop, i, None);
                let mut buf = vec![0u16; (len + 1) as usize];
                DragQueryFileW(hdrop, i, Some(&mut buf));
                let path = String::from_utf16_lossy(&buf[..len as usize]);
                paths.push(PathBuf::from(path));
            }

            Ok(paths)
        }
    }

    fn read_text(&self) -> Result<String> {
        unsafe {
            let handle: HANDLE = GetClipboardData(CF_UNICODETEXT.0 as u32)
                .map_err(|_| ClipboardError::DataUnavailable(CF_UNICODETEXT.0 as u32))?;

            let hglobal = HGLOBAL(handle.0);
            let ptr = GlobalLock(hglobal) as *const u16;
            if ptr.is_null() {
                return Err(ClipboardError::GlobalLockFailed);
            }

            // Find null terminator
            let mut len = 0;
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(ptr, len);
            let text = String::from_utf16_lossy(slice);

            let _ = GlobalUnlock(hglobal);

            Ok(text)
        }
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseClipboard();
        }
    }
}
