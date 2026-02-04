use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::protocol::FileRef;
use crate::ws::AppState;

#[derive(Serialize)]
pub struct UploadResponse {
    pub files: Vec<FileRef>,
}

/// Validate authorization header against configured password.
fn check_auth(headers: &HeaderMap, password: &Option<String>) -> Result<(), StatusCode> {
    let expected = match password {
        Some(p) if !p.is_empty() => p,
        _ => return Ok(()), // no password configured
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let auth_bytes = auth.as_bytes();
    let exp_bytes = expected.as_bytes();
    if auth_bytes.len() == exp_bytes.len() && auth_bytes.ct_eq(exp_bytes).into() {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// POST /files/upload — multipart file upload.
pub async fn file_upload_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.config.password)?;

    let max_file_size = state.config.max_file_size;
    let max_total = state.config.max_total_file_storage;

    // Check total storage before accepting uploads
    let current_total = state.store.total_file_bytes().unwrap_or(0) as u64;
    if current_total >= max_total {
        tracing::warn!("file storage full: {current_total} >= {max_total}");
        return Err(StatusCode::INSUFFICIENT_STORAGE);
    }

    let mut uploaded: Vec<FileRef> = Vec::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let filename = field.file_name().unwrap_or("unnamed").to_string();

        let data = match field.bytes().await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("failed to read multipart field: {e}");
                continue;
            }
        };

        if data.len() > max_file_size {
            tracing::warn!(
                "file too large: {} ({} > {})",
                filename,
                data.len(),
                max_file_size
            );
            continue;
        }

        // Check total storage again
        let current_total = state.store.total_file_bytes().unwrap_or(0) as u64;
        if current_total + data.len() as u64 > max_total {
            tracing::warn!("file storage would exceed limit, skipping {filename}");
            continue;
        }

        let mime_type = mime_guess::from_path(&filename)
            .first_or_octet_stream()
            .to_string();

        // Store file on disk
        let (file_id, disk_path) = match state.file_store.store(&filename, &data) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("failed to store file {filename}: {e}");
                continue;
            }
        };

        // Insert/update DB record
        if let Err(e) = state.store.insert_file(
            &file_id,
            &filename,
            &disk_path,
            data.len() as i64,
            &mime_type,
        ) {
            tracing::warn!("failed to insert file record: {e}");
            continue;
        }

        tracing::info!(
            "stored file: {filename} ({} bytes, id={file_id})",
            data.len()
        );

        uploaded.push(FileRef {
            file_id,
            filename,
            size: data.len() as u64,
            mime_type,
        });
    }

    if uploaded.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Json(UploadResponse { files: uploaded }))
}

/// GET /files/{file_id} — download a file.
pub async fn file_download_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.config.password)?;

    // Look up in DB
    let record = state
        .store
        .get_file(&file_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Read file from disk
    let (_, data) = state
        .file_store
        .read(&file_id)
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let mut resp_headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&record.mime_type) {
        resp_headers.insert("content-type", v);
    }
    let disposition = format!(
        "attachment; filename=\"{}\"",
        record.filename.replace('"', "'")
    );
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        resp_headers.insert("content-disposition", v);
    }

    Ok((resp_headers, Body::from(data)))
}
