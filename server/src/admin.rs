use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::ws::{self, AppState, BroadcastEvent};

/// Query params for listing entries.
#[derive(Deserialize)]
pub struct ListParams {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_limit")]
    limit: usize,
}

fn default_page() -> usize {
    1
}
fn default_limit() -> usize {
    50
}

#[derive(Serialize)]
struct EntryResponse {
    id: i64,
    content_type: String,
    preview: String,
    byte_size: i64,
    created_at: String,
}

#[derive(Serialize)]
struct ListResponse {
    entries: Vec<EntryResponse>,
    total: usize,
    page: usize,
    limit: usize,
    total_bytes: i64,
    file_bytes: i64,
}

#[derive(Serialize)]
struct DeleteResponse {
    deleted: bool,
}

#[derive(Serialize)]
struct ClearResponse {
    cleared: bool,
}

#[derive(Deserialize)]
pub struct DeleteBeforeParams {
    days: u64,
}

#[derive(Serialize)]
struct DeleteBeforeResponse {
    deleted: usize,
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

/// GET /admin — Serve the admin HTML page.
pub async fn admin_page_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Pass password requirement info to the page
    let needs_auth = state
        .config
        .password
        .as_ref()
        .is_some_and(|p| !p.is_empty());
    let html = ADMIN_HTML.replace("__NEEDS_AUTH__", if needs_auth { "true" } else { "false" });
    Html(html)
}

/// GET /api/entries — List entries (paginated).
pub async fn list_entries_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.config.password)?;

    let limit = params.limit.min(200).max(1);
    let page = params.page.max(1);
    let offset = (page - 1) * limit;

    let entries = state
        .store
        .list_entries(limit, offset)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total = state
        .store
        .count()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let total_bytes = state.store.total_bytes().unwrap_or(0);
    let file_bytes = state.store.total_file_bytes().unwrap_or(0);

    let entries: Vec<EntryResponse> = entries
        .into_iter()
        .map(|e| EntryResponse {
            id: e.id,
            content_type: e.content_type,
            preview: e.preview,
            byte_size: e.byte_size,
            created_at: e.created_at.to_rfc3339(),
        })
        .collect();

    let resp = ListResponse {
        entries,
        total,
        page,
        limit,
        total_bytes,
        file_bytes,
    };

    Ok(Json(resp))
}

/// DELETE /api/entries/{id} — Delete a single entry.
pub async fn delete_entry_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.config.password)?;

    let deleted = state
        .store
        .delete_entry(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(DeleteResponse { deleted }))
}

/// DELETE /api/entries — Clear all entries and files.
pub async fn clear_all_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.config.password)?;

    tracing::info!("clear_all requested via admin API");

    if let Err(e) = state.store.clear_all() {
        tracing::warn!("failed to clear entries: {e}");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    if let Err(e) = state.file_store.clear_all() {
        tracing::warn!("failed to clear files: {e}");
    }

    // Broadcast to all connected WS clients
    let _ = state.broadcast_tx.send(BroadcastEvent::ClearAll {
        origin: "admin".to_string(),
    });

    Ok(Json(ClearResponse { cleared: true }))
}

/// DELETE /api/entries/before?days=7 — Delete entries older than N days.
pub async fn delete_before_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<DeleteBeforeParams>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &state.config.password)?;

    let cutoff = chrono::Utc::now() - chrono::Duration::days(params.days as i64);
    let cutoff_str = cutoff.to_rfc3339();

    tracing::info!(
        "delete_before requested via admin API: entries older than {} days (before {})",
        params.days,
        cutoff_str
    );

    let (deleted, to_delete) = state
        .store
        .delete_before(&cutoff_str)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Clean up associated files for deleted entries.
    for (_id, content_type, content) in &to_delete {
        if content_type == "files" {
            ws::extract_and_cleanup_file_refs(content, &state);
        }
    }

    tracing::info!("deleted {deleted} entries older than {} days", params.days);

    Ok(Json(DeleteBeforeResponse { deleted }))
}

const ADMIN_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>o-clip Admin</title>
<style>
  :root { --bg: #1e1e2e; --surface: #282840; --border: #3a3a5c; --text: #cdd6f4; --dim: #6c7086; --accent: #89b4fa; --danger: #f38ba8; --success: #a6e3a1; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 1.5rem; margin-bottom: 8px; }
  .stats { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
  .stat { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; min-width: 140px; }
  .stat-value { font-size: 1.3rem; font-weight: 700; color: var(--accent); }
  .stat-label { font-size: 0.8rem; color: var(--dim); margin-top: 2px; }
  .toolbar { display: flex; gap: 8px; margin-bottom: 16px; align-items: center; flex-wrap: wrap; }
  button { background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 16px; cursor: pointer; font-size: 0.9rem; transition: background 0.15s; }
  button:hover { background: var(--border); }
  button.danger { border-color: var(--danger); color: var(--danger); }
  button.danger:hover { background: var(--danger); color: var(--bg); }
  button.selected-action { border-color: var(--accent); color: var(--accent); }
  button.selected-action:hover { background: var(--accent); color: var(--bg); }
  button.warn { border-color: #fab387; color: #fab387; }
  button.warn:hover { background: #fab387; color: var(--bg); }
  input[type=password], input[type=number] { background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 0.9rem; }
  input[type=password] { width: 200px; }
  input[type=number] { width: 64px; text-align: center; }
  input[type=password]::placeholder, input[type=number]::placeholder { color: var(--dim); }
  .age-group { display: flex; gap: 6px; align-items: center; font-size: 0.9rem; color: var(--dim); }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--surface); color: var(--dim); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; position: sticky; top: 0; }
  tr:hover { background: rgba(137,180,250,0.05); }
  td.preview { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: 'Consolas', 'Fira Code', monospace; font-size: 0.85rem; }
  td.type { color: var(--accent); font-size: 0.85rem; }
  td.size { color: var(--dim); font-size: 0.85rem; white-space: nowrap; }
  td.time { color: var(--dim); font-size: 0.85rem; white-space: nowrap; }
  td.actions button { padding: 4px 10px; font-size: 0.8rem; }
  .cb { width: 20px; text-align: center; }
  .cb input { cursor: pointer; }
  .pagination { display: flex; justify-content: center; align-items: center; gap: 12px; margin-top: 16px; }
  .pagination button { padding: 6px 14px; }
  .pagination span { color: var(--dim); font-size: 0.9rem; }
  .empty { text-align: center; color: var(--dim); padding: 60px 0; font-size: 1.1rem; }
  .auth-box { display: flex; gap: 8px; align-items: center; }
  #status { margin-left: auto; font-size: 0.85rem; color: var(--dim); }
  .sel-count { font-size: 0.85rem; color: var(--accent); }
</style>
</head>
<body>
<div class="container">
  <h1>o-clip Admin</h1>
  <div class="stats" id="stats"></div>
  <div class="toolbar">
    <div class="auth-box" id="auth-box">
      <input type="password" id="password" placeholder="Password">
    </div>
    <button onclick="load()">Refresh</button>
    <button class="selected-action" id="btn-delete-selected" onclick="deleteSelected()" style="display:none">Delete Selected (<span id="sel-count">0</span>)</button>
    <span class="age-group">
      <span>Older than</span>
      <input type="number" id="days-input" value="7" min="1" max="3650">
      <span>days</span>
      <button class="warn" onclick="deleteBefore()">Delete</button>
    </span>
    <button class="danger" onclick="clearAll()">Clear All</button>
    <span id="status"></span>
  </div>
  <table>
    <thead>
      <tr>
        <th class="cb"><input type="checkbox" id="select-all" onchange="toggleAll(this.checked)"></th>
        <th>Type</th>
        <th>Preview</th>
        <th>Size</th>
        <th>Time</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div class="pagination" id="pagination"></div>
</div>

<script>
const NEEDS_AUTH = __NEEDS_AUTH__;
let currentPage = 1;
const pageSize = 50;
let selectedIds = new Set();

if (!NEEDS_AUTH) {
  document.getElementById('auth-box').style.display = 'none';
}

function getHeaders() {
  const h = { 'Content-Type': 'application/json' };
  const pwd = document.getElementById('password').value;
  if (pwd) h['Authorization'] = 'Bearer ' + pwd;
  return h;
}

function fmt(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function fmtTime(iso) {
  const d = new Date(iso);
  const now = new Date();
  const diff = (now - d) / 1000;
  if (diff < 60) return Math.floor(diff) + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function updateSelectionUI() {
  const btn = document.getElementById('btn-delete-selected');
  const cnt = document.getElementById('sel-count');
  cnt.textContent = selectedIds.size;
  btn.style.display = selectedIds.size > 0 ? '' : 'none';
}

function toggleAll(checked) {
  document.querySelectorAll('.row-cb').forEach(cb => {
    cb.checked = checked;
    const id = parseInt(cb.dataset.id);
    if (checked) selectedIds.add(id); else selectedIds.delete(id);
  });
  updateSelectionUI();
}

function toggleOne(cb) {
  const id = parseInt(cb.dataset.id);
  if (cb.checked) selectedIds.add(id); else selectedIds.delete(id);
  updateSelectionUI();
}

async function load() {
  const status = document.getElementById('status');
  status.textContent = 'Loading...';
  try {
    const res = await fetch('/api/entries?page=' + currentPage + '&limit=' + pageSize, { headers: getHeaders() });
    if (res.status === 401) { status.textContent = 'Auth failed'; return; }
    const data = await res.json();

    // Stats
    document.getElementById('stats').innerHTML =
      `<div class="stat"><div class="stat-value">${data.total}</div><div class="stat-label">Entries</div></div>` +
      `<div class="stat"><div class="stat-value">${fmt(data.total_bytes)}</div><div class="stat-label">Entry Storage</div></div>` +
      `<div class="stat"><div class="stat-value">${fmt(data.file_bytes)}</div><div class="stat-label">File Storage</div></div>`;

    // Table
    const tbody = document.getElementById('tbody');
    if (data.entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty">No entries</td></tr>';
    } else {
      tbody.innerHTML = data.entries.map(e => {
        const checked = selectedIds.has(e.id) ? 'checked' : '';
        return `<tr>
          <td class="cb"><input type="checkbox" class="row-cb" data-id="${e.id}" ${checked} onchange="toggleOne(this)"></td>
          <td class="type">${escHtml(e.content_type)}</td>
          <td class="preview" title="${escHtml(e.preview)}">${escHtml(e.preview)}</td>
          <td class="size">${fmt(e.byte_size)}</td>
          <td class="time" title="${e.created_at}">${fmtTime(e.created_at)}</td>
          <td class="actions"><button class="danger" onclick="deleteOne(${e.id})">Del</button></td>
        </tr>`;
      }).join('');
    }

    // Pagination
    const totalPages = Math.ceil(data.total / pageSize) || 1;
    document.getElementById('pagination').innerHTML =
      `<button ${currentPage <= 1 ? 'disabled' : ''} onclick="currentPage--;load()">Prev</button>` +
      `<span>Page ${currentPage} / ${totalPages}</span>` +
      `<button ${currentPage >= totalPages ? 'disabled' : ''} onclick="currentPage++;load()">Next</button>`;

    status.textContent = '';
    document.getElementById('select-all').checked = false;
  } catch (e) {
    status.textContent = 'Error: ' + e.message;
  }
}

async function deleteOne(id) {
  try {
    await fetch('/api/entries/' + id, { method: 'DELETE', headers: getHeaders() });
    selectedIds.delete(id);
    load();
  } catch (e) {
    alert('Delete failed: ' + e.message);
  }
}

async function deleteSelected() {
  if (selectedIds.size === 0) return;
  if (!confirm('Delete ' + selectedIds.size + ' selected entries?')) return;
  const ids = [...selectedIds];
  for (const id of ids) {
    await fetch('/api/entries/' + id, { method: 'DELETE', headers: getHeaders() });
  }
  selectedIds.clear();
  updateSelectionUI();
  load();
}

async function deleteBefore() {
  const days = parseInt(document.getElementById('days-input').value);
  if (!days || days < 1) { alert('Please enter a valid number of days.'); return; }
  if (!confirm('Delete all entries older than ' + days + ' day(s)?')) return;
  const status = document.getElementById('status');
  try {
    const res = await fetch('/api/entries/before?days=' + days, { method: 'DELETE', headers: getHeaders() });
    if (res.status === 401) { status.textContent = 'Auth failed'; return; }
    const data = await res.json();
    status.textContent = 'Deleted ' + data.deleted + ' entries';
    selectedIds.clear();
    updateSelectionUI();
    load();
  } catch (e) {
    alert('Delete failed: ' + e.message);
  }
}

async function clearAll() {
  if (!confirm('Delete ALL entries and files on the server? This cannot be undone.')) return;
  try {
    const res = await fetch('/api/entries', { method: 'DELETE', headers: getHeaders() });
    if (res.status === 401) { document.getElementById('status').textContent = 'Auth failed'; return; }
    selectedIds.clear();
    updateSelectionUI();
    load();
  } catch (e) {
    alert('Clear failed: ' + e.message);
  }
}

// Auto-load on page open
document.addEventListener('DOMContentLoaded', load);
// Enter key in password field triggers reload
document.getElementById('password').addEventListener('keydown', e => { if (e.key === 'Enter') load(); });
</script>
</body>
</html>
"##;
