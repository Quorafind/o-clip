use std::path::{Path, PathBuf};

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "o-clip", about = "Clipboard manager with intranet sync")]
pub struct Cli {
    /// Path to config file (overrides default location)
    #[arg(short, long)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// WebSocket URL for the intranet sync server. Empty means no sync.
    /// Example: "ws://192.168.1.100:9217/ws"
    #[serde(default)]
    pub url: String,
    /// Whether to automatically connect on startup.
    #[serde(default = "default_true")]
    pub auto_connect: bool,
    /// Maximum content size (in bytes) that will be synced to the server.
    /// Entries larger than this are stored locally only. Default: 5 MB.
    /// This prevents multi-GB file copies from being transmitted over the network.
    #[serde(default = "default_max_sync_size")]
    pub max_sync_size: usize,
    /// Accept invalid/self-signed TLS certificates when using `wss://`.
    /// Only enable this for LAN deployments with self-signed certificates.
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Maximum number of entries to keep in the database.
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Custom database path. Empty means use platform default.
    #[serde(default)]
    pub db_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            auto_connect: true,
            max_sync_size: default_max_sync_size(),
            accept_invalid_certs: false,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            db_path: String::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_sync_size() -> usize {
    5 * 1024 * 1024 // 5 MB
}

fn default_max_entries() -> usize {
    10000
}

impl Config {
    /// Load config from the given path (or the standard path if `None`).
    /// Returns defaults if the file does not exist or cannot be parsed.
    pub fn load(override_path: Option<&Path>) -> Self {
        let path = match override_path {
            Some(p) => p.to_path_buf(),
            None => Self::config_path(),
        };
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => match toml::from_str(&contents) {
                    Ok(cfg) => return cfg,
                    Err(e) => {
                        tracing::warn!("failed to parse config at {}: {e}", path.display());
                    }
                },
                Err(e) => {
                    tracing::warn!("failed to read config at {}: {e}", path.display());
                }
            }
        }
        Self::default()
    }

    /// The standard config file path: %APPDATA%/o-clip/config.toml
    pub fn config_path() -> PathBuf {
        directories::ProjectDirs::from("", "", "o-clip")
            .map(|dirs| dirs.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("config.toml")
    }

    /// Resolve the database path (uses platform data dir if not configured).
    pub fn db_path(&self) -> PathBuf {
        if !self.storage.db_path.is_empty() {
            return PathBuf::from(&self.storage.db_path);
        }
        directories::ProjectDirs::from("", "", "o-clip")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("clipboard.db")
    }

    /// Whether WebSocket sync is configured.
    pub fn has_server(&self) -> bool {
        !self.server.url.is_empty()
    }

    /// Write the default config to disk if it doesn't exist.
    pub fn write_default_if_missing(path: &Path) {
        if !path.exists() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let default_toml = toml::to_string_pretty(&Config::default()).unwrap_or_default();
            let _ = std::fs::write(path, default_toml);
        }
    }
}
