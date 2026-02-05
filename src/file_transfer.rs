use std::path::{Path, PathBuf};

use reqwest::Client;
use serde::Deserialize;

use crate::clipboard::FileRef;
use crate::clipboard::content::{ImageFormat, ImageInfo, ImageRef};

#[derive(Deserialize)]
struct UploadResponse {
    files: Vec<FileRef>,
}

/// HTTP client for uploading/downloading files to/from the sync server.
pub struct FileTransferClient {
    http_client: Client,
    base_url: String,
    password: Option<String>,
    max_file_size: u64,
    download_dir: PathBuf,
}

impl FileTransferClient {
    /// Create a new FileTransferClient.
    /// Derives the HTTP base URL from the WebSocket URL.
    pub fn new(
        ws_url: &str,
        password: Option<String>,
        accept_invalid_certs: bool,
        max_file_size: u64,
        download_dir: PathBuf,
    ) -> Self {
        let base_url = ws_url_to_http(ws_url);

        let http_client = Client::builder()
            .danger_accept_invalid_certs(accept_invalid_certs)
            .build()
            .unwrap_or_else(|_| Client::new());

        let _ = std::fs::create_dir_all(&download_dir);

        Self {
            http_client,
            base_url,
            password,
            max_file_size,
            download_dir,
        }
    }

    /// Upload files to the server. Returns FileRef list for successfully uploaded files.
    pub async fn upload_files(&self, paths: &[PathBuf]) -> Result<Vec<FileRef>, String> {
        let mut form = reqwest::multipart::Form::new();
        let mut has_files = false;

        for path in paths {
            let metadata = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("cannot read file {}: {e}", path.display());
                    continue;
                }
            };

            if !metadata.is_file() {
                tracing::debug!("skipping non-file: {}", path.display());
                continue;
            }

            if metadata.len() > self.max_file_size {
                tracing::warn!(
                    "file too large, skipping: {} ({} > {})",
                    path.display(),
                    metadata.len(),
                    self.max_file_size
                );
                continue;
            }

            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!("failed to read file {}: {e}", path.display());
                    continue;
                }
            };

            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unnamed".to_string());

            let part = reqwest::multipart::Part::bytes(data)
                .file_name(filename.clone())
                .mime_str(
                    &mime_guess::from_path(path)
                        .first_or_octet_stream()
                        .to_string(),
                )
                .map_err(|e| format!("mime error: {e}"))?;

            form = form.part("file", part);
            has_files = true;
        }

        if !has_files {
            return Err("no valid files to upload".to_string());
        }

        let url = format!("{}/files/upload", self.base_url);
        let mut req = self.http_client.post(&url).multipart(form);

        if let Some(ref pwd) = self.password {
            if !pwd.is_empty() {
                req = req.bearer_auth(pwd);
            }
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("upload failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!("upload failed with status: {}", resp.status()));
        }

        let body: UploadResponse = resp
            .json()
            .await
            .map_err(|e| format!("failed to parse upload response: {e}"))?;

        Ok(body.files)
    }

    /// Download files from the server. Returns local paths of downloaded files.
    pub async fn download_files(&self, refs: &[FileRef]) -> Result<Vec<PathBuf>, String> {
        let mut local_paths = Vec::new();

        for file_ref in refs {
            let url = format!("{}/files/{}", self.base_url, file_ref.file_id);
            let mut req = self.http_client.get(&url);

            if let Some(ref pwd) = self.password {
                if !pwd.is_empty() {
                    req = req.bearer_auth(pwd);
                }
            }

            let resp = req
                .send()
                .await
                .map_err(|e| format!("download failed for {}: {e}", file_ref.filename))?;

            if !resp.status().is_success() {
                tracing::warn!(
                    "download failed for {} with status: {}",
                    file_ref.filename,
                    resp.status()
                );
                continue;
            }

            let data = resp
                .bytes()
                .await
                .map_err(|e| format!("failed to read response body: {e}"))?;

            // Save to download_dir with conflict handling
            let local_path = unique_path(&self.download_dir, &file_ref.filename);
            std::fs::write(&local_path, &data)
                .map_err(|e| format!("failed to write file {}: {e}", local_path.display()))?;

            tracing::info!(
                "downloaded: {} -> {}",
                file_ref.filename,
                local_path.display()
            );
            local_paths.push(local_path);
        }

        if local_paths.is_empty() {
            return Err("no files downloaded".to_string());
        }

        Ok(local_paths)
    }

    /// Get the download directory path.
    pub fn download_dir(&self) -> &Path {
        &self.download_dir
    }

    /// Upload image data to the server. Returns ImageRef on success.
    pub async fn upload_image(&self, info: &ImageInfo) -> Result<ImageRef, String> {
        use base64::Engine;

        let raw_b64 = info.raw_data.as_ref().ok_or("no raw_data in ImageInfo")?;

        let data = base64::engine::general_purpose::STANDARD
            .decode(raw_b64)
            .map_err(|e| format!("base64 decode error: {e}"))?;

        if data.len() as u64 > self.max_file_size {
            return Err(format!(
                "image too large: {} > {}",
                data.len(),
                self.max_file_size
            ));
        }

        // Determine filename extension based on format
        let ext = match info.format {
            ImageFormat::Png => "png",
            ImageFormat::Dib | ImageFormat::DibV5 | ImageFormat::Bitmap => "bmp",
        };
        let filename = format!("image.{ext}");

        let mime_type = match info.format {
            ImageFormat::Png => "image/png",
            _ => "image/bmp",
        };

        let part = reqwest::multipart::Part::bytes(data.clone())
            .file_name(filename)
            .mime_str(mime_type)
            .map_err(|e| format!("mime error: {e}"))?;

        let form = reqwest::multipart::Form::new().part("file", part);

        let url = format!("{}/files/upload", self.base_url);
        let mut req = self.http_client.post(&url).multipart(form);

        if let Some(ref pwd) = self.password {
            if !pwd.is_empty() {
                req = req.bearer_auth(pwd);
            }
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("image upload failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!(
                "image upload failed with status: {}",
                resp.status()
            ));
        }

        let body: UploadResponse = resp
            .json()
            .await
            .map_err(|e| format!("failed to parse upload response: {e}"))?;

        let file_ref = body
            .files
            .into_iter()
            .next()
            .ok_or("no file in upload response")?;

        Ok(ImageRef {
            image_id: file_ref.file_id,
            width: info.width,
            height: info.height,
            bits_per_pixel: info.bits_per_pixel,
            format: info.format,
            size: file_ref.size,
        })
    }

    /// Download image by ImageRef and return reconstructed ImageInfo with raw data.
    pub async fn download_image(&self, img_ref: &ImageRef) -> Result<ImageInfo, String> {
        use base64::Engine;

        let url = format!("{}/files/{}", self.base_url, img_ref.image_id);
        let mut req = self.http_client.get(&url);

        if let Some(ref pwd) = self.password {
            if !pwd.is_empty() {
                req = req.bearer_auth(pwd);
            }
        }

        let resp = req
            .send()
            .await
            .map_err(|e| format!("image download failed: {e}"))?;

        if !resp.status().is_success() {
            return Err(format!(
                "image download failed with status: {}",
                resp.status()
            ));
        }

        let data = resp
            .bytes()
            .await
            .map_err(|e| format!("failed to read image response body: {e}"))?;

        let raw_data = base64::engine::general_purpose::STANDARD.encode(&data);

        Ok(ImageInfo {
            width: img_ref.width,
            height: img_ref.height,
            bits_per_pixel: img_ref.bits_per_pixel,
            data_size: data.len(),
            format: img_ref.format,
            raw_data: Some(raw_data),
        })
    }
}

/// Convert a WebSocket URL to an HTTP URL.
/// ws://host:port/ws -> http://host:port
/// wss://host:port/ws -> https://host:port
fn ws_url_to_http(ws_url: &str) -> String {
    let url = ws_url
        .replace("wss://", "https://")
        .replace("ws://", "http://");
    // Strip trailing /ws path if present
    url.trim_end_matches("/ws").to_string()
}

/// Generate a unique file path in dir, appending _1, _2 etc. if needed.
fn unique_path(dir: &Path, filename: &str) -> PathBuf {
    let path = dir.join(filename);
    if !path.exists() {
        return path;
    }

    let stem = Path::new(filename)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| filename.to_string());
    let ext = Path::new(filename)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    for i in 1..1000 {
        let candidate = dir.join(format!("{stem}_{i}{ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }

    // Fallback: use UUID
    dir.join(format!("{stem}_{}{ext}", uuid::Uuid::new_v4()))
}
