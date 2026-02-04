use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Manages on-disk file storage with content-hash-based deduplication.
pub struct FileStore {
    base_dir: PathBuf,
}

impl FileStore {
    /// Create a new FileStore, ensuring the base directory exists.
    pub fn new(base_dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    /// Store file data on disk. Returns (file_id, relative_disk_path).
    /// file_id is the SHA-256 hex hash of the content.
    /// If a file with the same hash already exists, returns the existing ID without overwriting.
    pub fn store(&self, filename: &str, data: &[u8]) -> std::io::Result<(String, String)> {
        let file_id = Self::hash_content(data);
        let dir = self.base_dir.join(&file_id[..2]).join(&file_id);

        // Check if already exists (dedup)
        if dir.exists() {
            if let Some(existing) = Self::find_file_in_dir(&dir) {
                let rel = Self::relative_path(&self.base_dir, &existing);
                return Ok((file_id, rel));
            }
        }

        std::fs::create_dir_all(&dir)?;
        let safe_name = sanitize_filename(filename);
        let file_path = dir.join(&safe_name);
        std::fs::write(&file_path, data)?;
        let rel = Self::relative_path(&self.base_dir, &file_path);
        Ok((file_id, rel))
    }

    /// Read a file by its file_id. Returns (filename, data).
    pub fn read(&self, file_id: &str) -> std::io::Result<(String, Vec<u8>)> {
        if file_id.len() < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid file_id",
            ));
        }
        let dir = self.base_dir.join(&file_id[..2]).join(file_id);
        let file_path = Self::find_file_in_dir(&dir)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"))?;
        let filename = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let data = std::fs::read(&file_path)?;
        Ok((filename, data))
    }

    /// Get the absolute file path for a file_id (for streaming).
    pub fn file_path(&self, file_id: &str) -> Option<PathBuf> {
        if file_id.len() < 2 {
            return None;
        }
        let dir = self.base_dir.join(&file_id[..2]).join(file_id);
        Self::find_file_in_dir(&dir)
    }

    /// Delete a file by its file_id.
    pub fn delete(&self, file_id: &str) -> std::io::Result<()> {
        if file_id.len() < 2 {
            return Ok(());
        }
        let dir = self.base_dir.join(&file_id[..2]).join(file_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        // Try to remove the parent prefix dir if empty
        let prefix_dir = self.base_dir.join(&file_id[..2]);
        if prefix_dir.exists() {
            let _ = std::fs::remove_dir(&prefix_dir); // only succeeds if empty
        }
        Ok(())
    }

    /// Compute SHA-256 hex hash of content.
    pub fn hash_content(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Find the first file in a directory (skipping subdirs).
    fn find_file_in_dir(dir: &Path) -> Option<PathBuf> {
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }

    /// Compute a relative path string from base to target.
    fn relative_path(base: &Path, target: &Path) -> String {
        target
            .strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| target.to_string_lossy().to_string())
    }
}

/// Sanitize a filename to remove path separators and dangerous characters.
fn sanitize_filename(name: &str) -> String {
    let name = name.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let name = name.trim_start_matches('.');
    if name.is_empty() {
        "unnamed".to_string()
    } else {
        name.to_string()
    }
}
