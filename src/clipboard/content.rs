use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClipboardContent {
    /// One or more file paths copied via Explorer (CF_HDROP).
    Files(Vec<PathBuf>),

    /// An image copied to the clipboard (CF_DIB / CF_BITMAP / PNG).
    Image(ImageInfo),

    /// A URL/link detected from text content.
    Url(String),

    /// Plain text that is not a URL.
    Text(String),

    /// Clipboard was cleared or contains an unsupported format.
    Empty,
}

impl ClipboardContent {
    /// Compute a SHA-256 hash of the content for deduplication.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        match self {
            Self::Text(text) => {
                hasher.update(b"text:");
                hasher.update(text.as_bytes());
            }
            Self::Url(url) => {
                hasher.update(b"url:");
                hasher.update(url.as_bytes());
            }
            Self::Files(paths) => {
                hasher.update(b"files:");
                let mut sorted: Vec<_> = paths
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect();
                sorted.sort();
                for p in &sorted {
                    hasher.update(p.as_bytes());
                    hasher.update(b"\0");
                }
            }
            Self::Image(info) => {
                hasher.update(b"image:");
                // Decode to pixels so the hash is format-independent.
                // PNG and DIB of the same image will produce the same hash.
                if let Some(img) = info.to_dynamic_image() {
                    let rgba = img.to_rgba8();
                    hasher.update(info.width.to_le_bytes());
                    hasher.update(info.height.to_le_bytes());
                    hasher.update(rgba.as_raw());
                } else if let Some(raw) = &info.raw_data {
                    hasher.update(raw.as_bytes());
                } else {
                    hasher.update(info.width.to_le_bytes());
                    hasher.update(info.height.to_le_bytes());
                    hasher.update(info.bits_per_pixel.to_le_bytes());
                    hasher.update(info.data_size.to_le_bytes());
                }
            }
            Self::Empty => {
                hasher.update(b"empty");
            }
        }
        format!("{:x}", hasher.finalize())
    }

    /// Short preview string for display in the TUI list.
    pub fn preview(&self, max_len: usize) -> String {
        match self {
            Self::Text(text) => {
                let line = text.lines().next().unwrap_or("");
                if line.len() > max_len {
                    format!("{}...", &line[..line.floor_char_boundary(max_len)])
                } else {
                    line.to_string()
                }
            }
            Self::Url(url) => {
                if url.len() > max_len {
                    format!("{}...", &url[..url.floor_char_boundary(max_len)])
                } else {
                    url.to_string()
                }
            }
            Self::Files(paths) => {
                if paths.len() == 1 {
                    let name = paths[0]
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| paths[0].to_string_lossy().to_string());
                    name
                } else {
                    format!("{} files", paths.len())
                }
            }
            Self::Image(info) => {
                format!("{}x{} {:?}", info.width, info.height, info.format)
            }
            Self::Empty => "Empty".to_string(),
        }
    }

    /// Content type tag for storage.
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Url(_) => "url",
            Self::Files(_) => "files",
            Self::Image(_) => "image",
            Self::Empty => "empty",
        }
    }

    /// Byte size estimate for the content.
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Text(t) => t.len(),
            Self::Url(u) => u.len(),
            Self::Files(paths) => paths.iter().map(|p| p.to_string_lossy().len()).sum(),
            Self::Image(info) => info.data_size,
            Self::Empty => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Bits per pixel (e.g. 24, 32).
    pub bits_per_pixel: u16,
    /// Raw image data size in bytes.
    pub data_size: usize,
    /// The clipboard format the image was read from.
    pub format: ImageFormat,
    /// Base64-encoded raw image data. `None` if the image was too large to store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum ImageFormat {
    Dib,
    DibV5,
    Png,
    Bitmap,
}

impl ImageInfo {
    /// Decode the stored raw image data into a [`image::DynamicImage`].
    ///
    /// Returns `None` if `raw_data` is absent or decoding fails.
    pub fn to_dynamic_image(&self) -> Option<image::DynamicImage> {
        use base64::Engine;
        let raw_b64 = self.raw_data.as_ref()?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
            .ok()?;

        match self.format {
            ImageFormat::Png => image::load_from_memory(&raw).ok(),
            ImageFormat::Dib | ImageFormat::DibV5 | ImageFormat::Bitmap => {
                // The raw data is a DIB: BITMAPINFOHEADER + optional palette + pixels.
                // Prepend a 14-byte BMP file header to make it a valid BMP file.
                if raw.len() < 4 {
                    return None;
                }
                let header_size = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                let file_size = (14u32).wrapping_add(raw.len() as u32);
                let pixel_offset = 14u32.wrapping_add(header_size);

                let mut bmp = Vec::with_capacity(14 + raw.len());
                bmp.extend_from_slice(b"BM");
                bmp.extend_from_slice(&file_size.to_le_bytes());
                bmp.extend_from_slice(&0u32.to_le_bytes()); // reserved
                bmp.extend_from_slice(&pixel_offset.to_le_bytes());
                bmp.extend_from_slice(&raw);

                image::load_from_memory(&bmp).ok()
            }
        }
    }
}

impl fmt::Display for ClipboardContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Files(paths) => {
                write!(f, "Files({} item(s))", paths.len())?;
                for p in paths {
                    write!(f, "\n  {}", p.display())?;
                }
                Ok(())
            }
            Self::Image(info) => {
                write!(
                    f,
                    "Image({}x{}, {}bpp, {:.1}KB, {:?})",
                    info.width,
                    info.height,
                    info.bits_per_pixel,
                    info.data_size as f64 / 1024.0,
                    info.format,
                )
            }
            Self::Url(url) => write!(f, "Url({url})"),
            Self::Text(text) => {
                let preview = if text.len() > 100 {
                    &text[..text.floor_char_boundary(100)]
                } else {
                    text
                };
                write!(f, "Text({preview})")
            }
            Self::Empty => write!(f, "Empty"),
        }
    }
}

/// Classify a text string as either a URL or plain text.
pub fn classify_text(text: String) -> ClipboardContent {
    let trimmed = text.trim();
    if let Ok(parsed) = url::Url::parse(trimmed) {
        if matches!(parsed.scheme(), "http" | "https" | "ftp" | "ftps" | "file") {
            return ClipboardContent::Url(trimmed.to_string());
        }
    }
    ClipboardContent::Text(text)
}
