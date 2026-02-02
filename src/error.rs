use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[cfg(target_os = "windows")]
    #[error("failed to open clipboard: {0}")]
    OpenFailed(windows::core::Error),

    #[error("clipboard data unavailable for format {0}")]
    DataUnavailable(u32),

    #[error("failed to lock global memory")]
    GlobalLockFailed,

    #[cfg(target_os = "windows")]
    #[error("failed to register clipboard listener: {0}")]
    ListenerRegistrationFailed(windows::core::Error),

    #[cfg(target_os = "windows")]
    #[error("failed to create hidden window: {0}")]
    WindowCreationFailed(windows::core::Error),

    #[cfg(target_os = "windows")]
    #[error("windows API error: {0}")]
    Windows(#[from] windows::core::Error),
}

pub type Result<T> = std::result::Result<T, ClipboardError>;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error("clipboard error: {0}")]
    Clipboard(#[from] ClipboardError),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
