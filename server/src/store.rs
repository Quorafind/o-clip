use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::protocol::ClipboardEntry;

/// A record in the `files` table.
#[derive(Debug, Clone)]
pub struct FileRecord {
    pub file_id: String,
    pub filename: String,
    pub disk_path: String,
    pub size: i64,
    pub mime_type: String,
    pub ref_count: i64,
    pub created_at: String,
}

/// Server-side SQLite store. Thread-safe via internal Mutex.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;

        // Performance tuning for server workload
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;",
        )?;

        let store = Self {
            conn: Mutex::new(conn),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS entries (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id    TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL,
                content      TEXT NOT NULL,
                preview      TEXT NOT NULL,
                hash         TEXT NOT NULL,
                byte_size    INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL,
                UNIQUE(hash)
            );
            CREATE INDEX IF NOT EXISTS idx_entries_created ON entries(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_entries_hash ON entries(hash);",
        )?;

        // Migration: add client_hash column for cross-format image dedup.
        // The client computes a pixel-based hash that is format-independent
        // (PNG and DibV5 of the same image produce the same hash).
        let has_client_hash: bool = conn
            .prepare("SELECT client_hash FROM entries LIMIT 0")
            .is_ok();
        if !has_client_hash {
            conn.execute_batch(
                "ALTER TABLE entries ADD COLUMN client_hash TEXT NOT NULL DEFAULT '';
                 CREATE INDEX IF NOT EXISTS idx_entries_client_hash ON entries(client_hash);",
            )?;
        }

        // Migration: add files table for on-disk file storage
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files (
                file_id    TEXT PRIMARY KEY,
                filename   TEXT NOT NULL,
                disk_path  TEXT NOT NULL,
                size       INTEGER NOT NULL,
                mime_type  TEXT NOT NULL DEFAULT '',
                ref_count  INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at);",
        )?;

        Ok(())
    }

    /// Insert an entry. Returns true if actually inserted (not a duplicate).
    /// On hash conflict, bumps created_at to the top.
    pub fn insert(
        &self,
        entry: &ClipboardEntry,
        client_id: &str,
        client_hash: &str,
    ) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changes = conn.execute(
            "INSERT INTO entries (client_id, content_type, content, preview, hash, byte_size, created_at, client_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(hash) DO UPDATE SET created_at = excluded.created_at",
            params![
                client_id,
                entry.content_type,
                entry.content,
                entry.preview,
                entry.hash,
                entry.byte_size,
                entry.created_at.to_rfc3339(),
                client_hash,
            ],
        )?;
        Ok(changes > 0)
    }

    /// Get recent entries for sync_request. Capped at `max_limit`.
    pub fn recent(&self, limit: usize, max_limit: usize) -> rusqlite::Result<Vec<ClipboardEntry>> {
        let actual_limit = limit.min(max_limit);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_type, content, preview, hash, byte_size, created_at
             FROM entries ORDER BY created_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![actual_limit as i64], |row| {
            Ok(ClipboardEntry {
                id: row.get(0)?,
                content_type: row.get(1)?,
                content: row.get(2)?,
                preview: row.get(3)?,
                hash: row.get(4)?,
                byte_size: row.get(5)?,
                synced: true,
                created_at: parse_datetime(row.get::<_, String>(6)?),
                client_hash: String::new(),
            })
        })?;
        rows.collect()
    }

    /// Check if a hash already exists (server-computed hash).
    pub fn has_hash(&self, hash: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE hash = ?1",
            params![hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Check if a client-computed hash already exists.
    /// This catches cross-format duplicates (e.g. PNG vs DibV5 of the same image)
    /// because the client hash is pixel-based and format-independent.
    pub fn has_client_hash(&self, client_hash: &str) -> rusqlite::Result<bool> {
        if client_hash.is_empty() {
            return Ok(false);
        }
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE client_hash = ?1",
            params![client_hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Enforce a maximum number of entries by deleting the oldest.
    pub fn enforce_limit(&self, max_entries: usize) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM entries WHERE id NOT IN (
                SELECT id FROM entries ORDER BY created_at DESC LIMIT ?1
            )",
            params![max_entries as i64],
        )?;
        Ok(deleted)
    }

    /// Total entry count.
    pub fn count(&self) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
    }

    /// Total storage size (sum of byte_size).
    pub fn total_bytes(&self) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COALESCE(SUM(byte_size), 0) FROM entries",
            [],
            |row| row.get(0),
        )
    }

    // -----------------------------------------------------------------------
    // File storage methods
    // -----------------------------------------------------------------------

    /// Insert a file record. If the file_id already exists, increment ref_count.
    /// Returns true if a new record was created.
    pub fn insert_file(
        &self,
        file_id: &str,
        filename: &str,
        disk_path: &str,
        size: i64,
        mime_type: &str,
    ) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let changes = conn.execute(
            "INSERT INTO files (file_id, filename, disk_path, size, mime_type, ref_count, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
             ON CONFLICT(file_id) DO UPDATE SET ref_count = ref_count + 1",
            params![
                file_id,
                filename,
                disk_path,
                size,
                mime_type,
                Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(changes > 0)
    }

    /// Look up a file by ID.
    pub fn get_file(&self, file_id: &str) -> rusqlite::Result<Option<FileRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT file_id, filename, disk_path, size, mime_type, ref_count, created_at
             FROM files WHERE file_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![file_id], |row| {
            Ok(FileRecord {
                file_id: row.get(0)?,
                filename: row.get(1)?,
                disk_path: row.get(2)?,
                size: row.get(3)?,
                mime_type: row.get(4)?,
                ref_count: row.get(5)?,
                created_at: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(Ok(record)) => Ok(Some(record)),
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }

    /// Decrement ref_count for a file. Returns true if ref_count reached 0
    /// (caller should delete from disk).
    pub fn dec_file_ref(&self, file_id: &str) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE files SET ref_count = ref_count - 1 WHERE file_id = ?1",
            params![file_id],
        )?;
        let remaining: i64 = conn
            .query_row(
                "SELECT ref_count FROM files WHERE file_id = ?1",
                params![file_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if remaining <= 0 {
            conn.execute("DELETE FROM files WHERE file_id = ?1", params![file_id])?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Total stored file size (bytes).
    pub fn total_file_bytes(&self) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COALESCE(SUM(size), 0) FROM files", [], |row| {
            row.get(0)
        })
    }

    /// Get IDs of entries that will be deleted by enforce_limit.
    /// Returns (id, content_type, content) tuples.
    pub fn entries_to_prune(
        &self,
        max_entries: usize,
    ) -> rusqlite::Result<Vec<(i64, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, content_type, content FROM entries WHERE id NOT IN (
                SELECT id FROM entries ORDER BY created_at DESC LIMIT ?1
            )",
        )?;
        let rows = stmt.query_map(params![max_entries as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        rows.collect()
    }
}

fn parse_datetime(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ClipboardEntry;
    use chrono::Utc;
    use tempfile::TempDir;

    fn temp_store() -> (Store, TempDir) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let store = Store::open(&db_path).unwrap();
        (store, dir)
    }

    fn make_entry(content: &str) -> ClipboardEntry {
        let mut entry = ClipboardEntry {
            id: 0,
            content_type: "text".to_string(),
            content: content.to_string(),
            preview: content.chars().take(30).collect(),
            hash: String::new(),
            byte_size: content.len() as i64,
            synced: false,
            created_at: Utc::now(),
            client_hash: String::new(),
        };
        entry.hash = entry.compute_server_hash();
        entry
    }

    #[test]
    fn insert_and_count() {
        let (store, _dir) = temp_store();
        assert_eq!(store.count().unwrap(), 0);

        let entry = make_entry("hello world");
        let inserted = store.insert(&entry, "client-1", "").unwrap();
        assert!(inserted);
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn dedup_by_hash() {
        let (store, _dir) = temp_store();

        let entry = make_entry("duplicate content");
        store.insert(&entry, "client-1", "").unwrap();
        store.insert(&entry, "client-2", "").unwrap();

        // Should still be 1 entry (hash-based dedup via ON CONFLICT)
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn has_hash_works() {
        let (store, _dir) = temp_store();

        let entry = make_entry("check hash");
        assert!(!store.has_hash(&entry.hash).unwrap());

        store.insert(&entry, "c1", "").unwrap();
        assert!(store.has_hash(&entry.hash).unwrap());

        assert!(!store.has_hash("nonexistent_hash").unwrap());
    }

    #[test]
    fn has_client_hash_works() {
        let (store, _dir) = temp_store();

        let entry = make_entry("client hash test");
        let client_hash = "pixel_based_hash_abc123";
        assert!(!store.has_client_hash(client_hash).unwrap());

        store.insert(&entry, "c1", client_hash).unwrap();
        assert!(store.has_client_hash(client_hash).unwrap());

        // Empty client hash should always return false
        assert!(!store.has_client_hash("").unwrap());
    }

    #[test]
    fn recent_returns_newest_first() {
        let (store, _dir) = temp_store();

        for i in 0..5 {
            let mut entry = make_entry(&format!("entry_{i}"));
            entry.created_at = Utc::now() + chrono::Duration::seconds(i as i64);
            store.insert(&entry, "c1", "").unwrap();
        }

        let recent = store.recent(3, 200).unwrap();
        assert_eq!(recent.len(), 3);
        // Newest first
        assert!(recent[0].content.contains("entry_4"));
        assert!(recent[1].content.contains("entry_3"));
        assert!(recent[2].content.contains("entry_2"));
    }

    #[test]
    fn recent_respects_max_limit() {
        let (store, _dir) = temp_store();

        for i in 0..10 {
            let mut entry = make_entry(&format!("item_{i}"));
            entry.created_at = Utc::now() + chrono::Duration::seconds(i as i64);
            store.insert(&entry, "c1", "").unwrap();
        }

        // Client requests 100, but max_limit is 5
        let recent = store.recent(100, 5).unwrap();
        assert_eq!(recent.len(), 5);
    }

    #[test]
    fn enforce_limit_deletes_oldest() {
        let (store, _dir) = temp_store();

        for i in 0..10 {
            let mut entry = make_entry(&format!("limit_test_{i}"));
            entry.created_at = Utc::now() + chrono::Duration::seconds(i as i64);
            store.insert(&entry, "c1", "").unwrap();
        }
        assert_eq!(store.count().unwrap(), 10);

        let deleted = store.enforce_limit(3).unwrap();
        assert_eq!(deleted, 7);
        assert_eq!(store.count().unwrap(), 3);

        // Remaining should be the 3 newest
        let remaining = store.recent(10, 10).unwrap();
        assert!(remaining[0].content.contains("limit_test_9"));
        assert!(remaining[1].content.contains("limit_test_8"));
        assert!(remaining[2].content.contains("limit_test_7"));
    }

    #[test]
    fn total_bytes_sums_correctly() {
        let (store, _dir) = temp_store();

        let e1 = make_entry("aaa");
        let e2 = make_entry("bbbbbb");
        store.insert(&e1, "c1", "").unwrap();
        store.insert(&e2, "c1", "").unwrap();

        let total = store.total_bytes().unwrap();
        assert_eq!(total, e1.byte_size + e2.byte_size);
    }

    #[test]
    fn dedup_bumps_created_at() {
        let (store, _dir) = temp_store();

        let mut entry = make_entry("bump test");
        let old_time = Utc::now() - chrono::Duration::hours(1);
        entry.created_at = old_time;
        store.insert(&entry, "c1", "").unwrap();

        // Insert same hash with a newer timestamp
        let mut entry2 = make_entry("bump test");
        entry2.created_at = Utc::now();
        store.insert(&entry2, "c1", "").unwrap();

        // Should still be 1 entry but with updated timestamp
        assert_eq!(store.count().unwrap(), 1);
        let recent = store.recent(1, 10).unwrap();
        assert!(recent[0].created_at > old_time);
    }

    #[test]
    fn many_inserts_stress() {
        let (store, _dir) = temp_store();

        for i in 0..500 {
            let entry = make_entry(&format!("stress_entry_{i}"));
            store.insert(&entry, "c1", "").unwrap();
        }

        assert_eq!(store.count().unwrap(), 500);
        store.enforce_limit(100).unwrap();
        assert_eq!(store.count().unwrap(), 100);
    }

    #[test]
    fn different_content_types_different_hashes() {
        let (store, _dir) = temp_store();

        let mut e1 = make_entry("same content");
        e1.content_type = "text".to_string();
        e1.hash = e1.compute_server_hash();

        let mut e2 = make_entry("same content");
        e2.content_type = "url".to_string();
        e2.hash = e2.compute_server_hash();

        store.insert(&e1, "c1", "").unwrap();
        store.insert(&e2, "c1", "").unwrap();

        // Different content_type -> different hash -> 2 entries
        assert_eq!(store.count().unwrap(), 2);
    }
}
