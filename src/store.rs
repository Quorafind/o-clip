use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::clipboard::ClipboardContent;

/// Where a clipboard entry originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntrySource {
    Local,
    Remote,
}

impl Default for EntrySource {
    fn default() -> Self {
        Self::Local
    }
}

impl EntrySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "remote" => Self::Remote,
            _ => Self::Local,
        }
    }
}

/// A stored clipboard history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub id: i64,
    pub content_type: String,
    /// Serialized content (JSON for structured types, raw string for text/url).
    pub content: String,
    /// Short preview for TUI list display.
    pub preview: String,
    /// SHA-256 hash for deduplication.
    pub hash: String,
    pub byte_size: i64,
    /// Whether this entry has been synced to the remote server.
    pub synced: bool,
    pub created_at: DateTime<Utc>,
    /// Where this entry came from (local clipboard or remote sync).
    #[serde(default)]
    pub source: EntrySource,
    /// Whether this entry is pinned (protected from auto-deletion).
    #[serde(default)]
    pub pinned: bool,
    /// Client-computed content hash (pixel-based for images, format-independent).
    /// Sent to the server for cross-format dedup.
    #[serde(default)]
    pub client_hash: String,
}

impl ClipboardEntry {
    /// Create a new entry from clipboard content.
    pub fn from_content(content: &ClipboardContent) -> Self {
        let content_json = serde_json::to_string(content).unwrap_or_default();
        let hash = content.content_hash();
        Self {
            id: 0,
            content_type: content.content_type().to_string(),
            content: content_json,
            preview: content.preview(120),
            client_hash: hash.clone(),
            hash,
            byte_size: content.byte_size() as i64,
            synced: false,
            created_at: Utc::now(),
            source: EntrySource::Local,
            pinned: false,
        }
    }

    /// Deserialize the stored content back into a ClipboardContent.
    pub fn to_clipboard_content(&self) -> Option<ClipboardContent> {
        serde_json::from_str(&self.content).ok()
    }
}

/// SQLite-backed clipboard history store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (or create) the database at the given path.
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                content_type TEXT NOT NULL,
                content     TEXT NOT NULL,
                preview     TEXT NOT NULL,
                hash        TEXT NOT NULL,
                byte_size   INTEGER NOT NULL DEFAULT 0,
                synced      INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                source      TEXT NOT NULL DEFAULT 'local',
                UNIQUE(hash)
            );
            CREATE INDEX IF NOT EXISTS idx_entries_created ON entries(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries(hash);",
        )?;

        // Migration: add source column to existing databases.
        let has_source: bool = self
            .conn
            .prepare("SELECT source FROM entries LIMIT 0")
            .is_ok();
        if !has_source {
            self.conn.execute_batch(
                "ALTER TABLE entries ADD COLUMN source TEXT NOT NULL DEFAULT 'local';",
            )?;
        }

        // Migration: add pinned column to existing databases.
        let has_pinned: bool = self
            .conn
            .prepare("SELECT pinned FROM entries LIMIT 0")
            .is_ok();
        if !has_pinned {
            self.conn.execute_batch(
                "ALTER TABLE entries ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;",
            )?;
        }

        Ok(())
    }

    /// Insert a new entry. If a duplicate hash exists, bump its timestamp instead.
    /// Returns the row id.
    pub fn insert(&self, entry: &ClipboardEntry) -> rusqlite::Result<i64> {
        // Try insert; on conflict update created_at to bring it to the top.
        self.conn.execute(
            "INSERT INTO entries (content_type, content, preview, hash, byte_size, synced, created_at, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(hash) DO UPDATE SET created_at = excluded.created_at, source = excluded.source",
            params![
                entry.content_type,
                entry.content,
                entry.preview,
                entry.hash,
                entry.byte_size,
                entry.synced as i32,
                entry.created_at.to_rfc3339(),
                entry.source.as_str(),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// List entries ordered by most recent first.
    pub fn list(&self, limit: usize, offset: usize) -> rusqlite::Result<Vec<ClipboardEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content_type, content, preview, hash, byte_size, synced, created_at, source, pinned
             FROM entries ORDER BY pinned DESC, created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            Ok(ClipboardEntry {
                id: row.get(0)?,
                content_type: row.get(1)?,
                content: row.get(2)?,
                preview: row.get(3)?,
                hash: row.get(4)?,
                byte_size: row.get(5)?,
                synced: row.get::<_, i32>(6)? != 0,
                created_at: parse_datetime(row.get::<_, String>(7)?),
                source: EntrySource::from_str(&row.get::<_, String>(8).unwrap_or_default()),
                pinned: row.get::<_, i32>(9)? != 0,
                client_hash: String::new(),
            })
        })?;
        rows.collect()
    }

    /// Get a single entry by id. Used by sync protocol.
    #[allow(dead_code)]
    pub fn get(&self, id: i64) -> rusqlite::Result<Option<ClipboardEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content_type, content, preview, hash, byte_size, synced, created_at, source, pinned
             FROM entries WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map(params![id], |row| {
            Ok(ClipboardEntry {
                id: row.get(0)?,
                content_type: row.get(1)?,
                content: row.get(2)?,
                preview: row.get(3)?,
                hash: row.get(4)?,
                byte_size: row.get(5)?,
                synced: row.get::<_, i32>(6)? != 0,
                created_at: parse_datetime(row.get::<_, String>(7)?),
                source: EntrySource::from_str(&row.get::<_, String>(8).unwrap_or_default()),
                pinned: row.get::<_, i32>(9)? != 0,
                client_hash: String::new(),
            })
        })?;
        match rows.next() {
            Some(Ok(entry)) => Ok(Some(entry)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Delete an entry by id.
    pub fn delete(&self, id: i64) -> rusqlite::Result<()> {
        self.conn
            .execute("DELETE FROM entries WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Search entries by preview text (case-insensitive LIKE).
    pub fn search(&self, query: &str) -> rusqlite::Result<Vec<ClipboardEntry>> {
        let pattern = format!("%{query}%");
        let mut stmt = self.conn.prepare(
            "SELECT id, content_type, content, preview, hash, byte_size, synced, created_at, source, pinned
             FROM entries WHERE preview LIKE ?1 OR content LIKE ?1
             ORDER BY pinned DESC, created_at DESC LIMIT 200",
        )?;
        let rows = stmt.query_map(params![pattern], |row| {
            Ok(ClipboardEntry {
                id: row.get(0)?,
                content_type: row.get(1)?,
                content: row.get(2)?,
                preview: row.get(3)?,
                hash: row.get(4)?,
                byte_size: row.get(5)?,
                synced: row.get::<_, i32>(6)? != 0,
                created_at: parse_datetime(row.get::<_, String>(7)?),
                source: EntrySource::from_str(&row.get::<_, String>(8).unwrap_or_default()),
                pinned: row.get::<_, i32>(9)? != 0,
                client_hash: String::new(),
            })
        })?;
        rows.collect()
    }

    /// Total entry count.
    pub fn count(&self) -> rusqlite::Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
    }

    /// Enforce a maximum number of stored entries by deleting the oldest.
    /// Pinned entries are never deleted by this limit.
    pub fn enforce_limit(&self, max_entries: usize) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM entries WHERE pinned = 0 AND id NOT IN (
                SELECT id FROM entries WHERE pinned = 0 ORDER BY created_at DESC LIMIT ?1
            )",
            params![max_entries as i64],
        )?;
        Ok(())
    }

    /// Toggle the pinned state of an entry. Returns the new pinned value.
    pub fn toggle_pin(&self, id: i64) -> rusqlite::Result<bool> {
        self.conn.execute(
            "UPDATE entries SET pinned = CASE WHEN pinned = 0 THEN 1 ELSE 0 END WHERE id = ?1",
            params![id],
        )?;
        let pinned: bool = self.conn.query_row(
            "SELECT pinned FROM entries WHERE id = ?1",
            params![id],
            |row| Ok(row.get::<_, i32>(0)? != 0),
        )?;
        Ok(pinned)
    }

    /// Mark an entry as synced. Used by sync protocol.
    #[allow(dead_code)]
    pub fn mark_synced(&self, id: i64) -> rusqlite::Result<()> {
        self.conn
            .execute("UPDATE entries SET synced = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Get un-synced entries for initial sync on connect.
    #[allow(dead_code)]
    pub fn unsynced(&self, limit: usize) -> rusqlite::Result<Vec<ClipboardEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content_type, content, preview, hash, byte_size, synced, created_at, source, pinned
             FROM entries WHERE synced = 0 ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ClipboardEntry {
                id: row.get(0)?,
                content_type: row.get(1)?,
                content: row.get(2)?,
                preview: row.get(3)?,
                hash: row.get(4)?,
                byte_size: row.get(5)?,
                synced: row.get::<_, i32>(6)? != 0,
                created_at: parse_datetime(row.get::<_, String>(7)?),
                source: EntrySource::from_str(&row.get::<_, String>(8).unwrap_or_default()),
                pinned: row.get::<_, i32>(9)? != 0,
                client_hash: String::new(),
            })
        })?;
        rows.collect()
    }
}

fn parse_datetime(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}
