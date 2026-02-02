use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address (e.g. "0.0.0.0:8080").
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Database file path. Empty = clipboard_server.db next to the config file.
    #[serde(default)]
    pub db_path: String,

    /// Maximum stored entries (oldest pruned when exceeded).
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,

    /// Maximum bytes for a single entry payload.
    #[serde(default = "default_max_entry_bytes")]
    pub max_entry_bytes: usize,

    /// Maximum entries returned in a sync_request response.
    #[serde(default = "default_max_sync_batch")]
    pub max_sync_batch: usize,

    /// Rate limit: max messages per 60s window per client.
    #[serde(default = "default_rate_msg")]
    pub rate_limit_messages: u32,

    /// Rate limit: max bytes per 60s window per client.
    #[serde(default = "default_rate_bytes")]
    pub rate_limit_bytes: u64,

    /// Rate limit: max single message size in bytes.
    #[serde(default = "default_max_msg_size")]
    pub rate_limit_max_message_size: usize,

    /// Path to TLS certificate PEM file. When both `tls_cert` and `tls_key`
    /// are set, the server listens with TLS (wss://). Otherwise plain ws://.
    #[serde(default)]
    pub tls_cert: Option<String>,

    /// Path to TLS private key PEM file.
    #[serde(default)]
    pub tls_key: Option<String>,

    /// Resolved directory of the config file (not serialized).
    #[serde(skip)]
    pub config_dir: PathBuf,
}

fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}
fn default_max_entries() -> usize {
    50000
}
fn default_max_entry_bytes() -> usize {
    5 * 1024 * 1024 // 5 MB — matches client default max_sync_size
}
fn default_max_sync_batch() -> usize {
    200
}
fn default_rate_msg() -> u32 {
    60
}
fn default_rate_bytes() -> u64 {
    10 * 1024 * 1024
}
fn default_max_msg_size() -> usize {
    6 * 1024 * 1024 // 6 MB — slightly above max_entry_bytes to account for JSON overhead
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            db_path: String::new(),
            max_entries: default_max_entries(),
            max_entry_bytes: default_max_entry_bytes(),
            max_sync_batch: default_max_sync_batch(),
            rate_limit_messages: default_rate_msg(),
            rate_limit_bytes: default_rate_bytes(),
            rate_limit_max_message_size: default_max_msg_size(),
            tls_cert: None,
            tls_key: None,
            config_dir: PathBuf::from("."),
        }
    }
}

impl ServerConfig {
    /// Load config from a TOML file, falling back to defaults.
    /// The config file's parent directory is remembered so `db_path()`
    /// can resolve relative paths next to the config file.
    pub fn load(path: &Path) -> Self {
        let config_dir = path
            .parent()
            .map(|p| {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            })
            .unwrap_or_else(|| PathBuf::from("."));

        let mut cfg = if path.exists() {
            match std::fs::read_to_string(path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        eprintln!("warning: failed to parse config {}: {e}", path.display());
                        Self::default()
                    }
                },
                Err(e) => {
                    eprintln!("warning: failed to read config {}: {e}", path.display());
                    Self::default()
                }
            }
        } else {
            Self::default()
        };

        cfg.config_dir = config_dir;
        cfg
    }

    /// Resolve the database path.
    /// When `db_path` is empty, places `clipboard_server.db` in the same
    /// directory as the config file. This ensures the DB lands inside the
    /// Docker volume when running with `/app/data/server.toml`.
    pub fn db_path(&self) -> PathBuf {
        if self.db_path.is_empty() {
            self.config_dir.join("clipboard_server.db")
        } else {
            PathBuf::from(&self.db_path)
        }
    }

    /// Resolve TLS cert and key paths. Returns `Some((cert, key))` when both are configured.
    pub fn tls_paths(&self) -> Option<(PathBuf, PathBuf)> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(cert), Some(key)) => {
                let resolve = |p: &str| {
                    let path = PathBuf::from(p);
                    if path.is_absolute() {
                        path
                    } else {
                        self.config_dir.join(path)
                    }
                };
                Some((resolve(cert), resolve(key)))
            }
            _ => None,
        }
    }

    /// Write default config to a file if it doesn't exist.
    pub fn write_default_if_missing(path: &Path) {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let toml_str = toml::to_string_pretty(&ServerConfig::default()).unwrap_or_default();
            let _ = std::fs::write(path, toml_str);
        }
    }
}
