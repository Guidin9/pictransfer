//! Settings and transfer history in SQLite (architecture §7). Item names, paths
//! and inline-text previews are encrypted with the device history key, so the
//! database file holds no plaintext names. Opened on demand, closed when idle.

use std::path::Path;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::keys::{self, EndpointId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Db,
    Crypto,
    Rng,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Db
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In = 0,
    Out = 1,
}

/// One history row (decrypted view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: i64,
    pub ts: u64,
    pub direction: Direction,
    pub peer: EndpointId,
    pub kind: u64,
    pub size: u64,
    pub ok: bool,
    pub name: Option<String>,
    pub path: Option<String>,
    pub text: Option<String>,
}

/// Retention (architecture §8 default: 30 days or 200 items).
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub max_age_ms: u64,
    pub max_items: u64,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            max_age_ms: 30 * 24 * 3600 * 1000,
            max_items: 200,
        }
    }
}

pub struct Store {
    db: Connection,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store(<redacted>)")
    }
}

const FIELD_NAME: u8 = 1;
const FIELD_PATH: u8 = 2;
const FIELD_TEXT: u8 = 3;

impl Store {
    pub fn open(path: &Path, history_key: &[u8; 32]) -> Result<Self, StoreError> {
        let db = Connection::open(path)?;
        Self::init(db, history_key)
    }

    pub fn open_in_memory(history_key: &[u8; 32]) -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, history_key)
    }

    fn init(db: Connection, key: &[u8; 32]) -> Result<Self, StoreError> {
        // Small cache, no WAL side files lingering at idle (resource budget §2.9).
        db.execute_batch(
            "PRAGMA cache_size = -256;
             PRAGMA journal_mode = DELETE;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL, dir INTEGER NOT NULL, peer BLOB NOT NULL,
                kind INTEGER NOT NULL, size INTEGER NOT NULL, ok INTEGER NOT NULL,
                name BLOB, path BLOB, text BLOB);
             CREATE INDEX IF NOT EXISTS history_ts ON history(ts);",
        )?;
        Ok(Self {
            db,
            key: Zeroizing::new(*key),
        })
    }

    fn seal(&self, id: i64, field: u8, pt: &str) -> Result<Vec<u8>, StoreError> {
        let mut nonce = [0u8; 12];
        keys::random(&mut nonce).map_err(|_| StoreError::Rng)?;
        let aad = [&id.to_be_bytes()[..], &[field]].concat();
        let ct = ChaCha20Poly1305::new(&(*self.key).into())
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: pt.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| StoreError::Crypto)?;
        Ok([&nonce[..], &ct].concat())
    }

    fn open_field(
        &self,
        id: i64,
        field: u8,
        blob: Option<Vec<u8>>,
    ) -> Result<Option<String>, StoreError> {
        let Some(b) = blob else { return Ok(None) };
        let (nonce, ct) = b.split_at_checked(12).ok_or(StoreError::Crypto)?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| StoreError::Crypto)?;
        let aad = [&id.to_be_bytes()[..], &[field]].concat();
        let pt = ChaCha20Poly1305::new(&(*self.key).into())
            .decrypt(&nonce.into(), Payload { msg: ct, aad: &aad })
            .map_err(|_| StoreError::Crypto)?;
        String::from_utf8(pt)
            .map(Some)
            .map_err(|_| StoreError::Crypto)
    }

    /// Inserts a row (encrypting name/path/text) and applies retention.
    #[allow(clippy::too_many_arguments)]
    pub fn add(
        &mut self,
        ts: u64,
        direction: Direction,
        peer: &EndpointId,
        kind: u64,
        size: u64,
        ok: bool,
        name: Option<&str>,
        path: Option<&str>,
        text: Option<&str>,
        keep: Retention,
    ) -> Result<i64, StoreError> {
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO history (ts, dir, peer, kind, size, ok) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ts as i64,
                direction as i64,
                &peer.0[..],
                kind as i64,
                size as i64,
                ok
            ],
        )?;
        let id = tx.last_insert_rowid();
        drop(tx.commit());
        // Fields are bound to their row id through the AAD, so rows cannot be swapped.
        let n = name.map(|v| self.seal(id, FIELD_NAME, v)).transpose()?;
        let p = path.map(|v| self.seal(id, FIELD_PATH, v)).transpose()?;
        let t = text.map(|v| self.seal(id, FIELD_TEXT, v)).transpose()?;
        self.db.execute(
            "UPDATE history SET name = ?1, path = ?2, text = ?3 WHERE id = ?4",
            params![n, p, t, id],
        )?;
        let cutoff = ts.saturating_sub(keep.max_age_ms) as i64;
        self.db
            .execute("DELETE FROM history WHERE ts < ?1", params![cutoff])?;
        self.db.execute(
            "DELETE FROM history WHERE id NOT IN (SELECT id FROM history ORDER BY ts DESC, id DESC LIMIT ?1)",
            params![keep.max_items as i64],
        )?;
        Ok(id)
    }

    /// Newest first, optionally before `before_ts`.
    pub fn list(&self, before_ts: Option<u64>, limit: u32) -> Result<Vec<Entry>, StoreError> {
        let mut stmt = self.db.prepare(
            "SELECT id, ts, dir, peer, kind, size, ok, name, path, text FROM history
             WHERE ts < ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
        )?;
        let before = before_ts.map_or(i64::MAX, |t| t as i64);
        let rows = stmt.query_map(params![before, i64::from(limit.min(200))], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
                r.get::<_, bool>(6)?,
                r.get::<_, Option<Vec<u8>>>(7)?,
                r.get::<_, Option<Vec<u8>>>(8)?,
                r.get::<_, Option<Vec<u8>>>(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, ts, dir, peer, kind, size, ok, n, p, t) = row?;
            let peer: [u8; 32] = peer.as_slice().try_into().map_err(|_| StoreError::Db)?;
            out.push(Entry {
                id,
                ts: ts as u64,
                direction: if dir == 0 {
                    Direction::In
                } else {
                    Direction::Out
                },
                peer: EndpointId(peer),
                kind: kind as u64,
                size: size as u64,
                ok,
                name: self.open_field(id, FIELD_NAME, n)?,
                path: self.open_field(id, FIELD_PATH, p)?,
                text: self.open_field(id, FIELD_TEXT, t)?,
            });
        }
        Ok(out)
    }

    pub fn get(&self, id: i64) -> Result<Option<Entry>, StoreError> {
        Ok(self.list(None, 200)?.into_iter().find(|e| e.id == id))
    }

    pub fn delete(&self, id: i64) -> Result<(), StoreError> {
        self.db
            .execute("DELETE FROM history WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Settings are opaque CBOR blobs keyed by name (no secrets stored here).
    pub fn set_setting(&self, k: &str, v: &[u8]) -> Result<(), StoreError> {
        self.db.execute("INSERT INTO settings (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v])?;
        Ok(())
    }

    pub fn setting(&self, k: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .db
            .query_row("SELECT v FROM settings WHERE k = ?1", params![k], |r| {
                r.get(0)
            })
            .optional()?)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_retention_and_no_plaintext_on_disk() {
        let dir = std::env::temp_dir().join(format!("warpshot-hist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.sqlite3");
        let _ = std::fs::remove_file(&path);
        let peer = EndpointId([7; 32]);
        {
            let mut s = Store::open(&path, &[9; 32]).unwrap();
            let keep = Retention {
                max_age_ms: 1000,
                max_items: 3,
            };
            for i in 0..5u64 {
                s.add(
                    10_000 + i,
                    Direction::In,
                    &peer,
                    3,
                    10,
                    true,
                    Some("gizli-rapor.pdf"),
                    Some("C:\\Users\\x\\Downloads\\gizli-rapor.pdf"),
                    None,
                    keep,
                )
                .unwrap();
            }
            s.add(
                10_010,
                Direction::Out,
                &peer,
                1,
                5,
                true,
                None,
                None,
                Some("parola-ipucu"),
                keep,
            )
            .unwrap();
            let rows = s.list(None, 50).unwrap();
            assert_eq!(rows.len(), 3, "max_items applied");
            assert_eq!(rows[0].text.as_deref(), Some("parola-ipucu"));
            assert_eq!(rows[1].name.as_deref(), Some("gizli-rapor.pdf"));
            // Old rows are pruned by age.
            s.add(
                20_000,
                Direction::In,
                &peer,
                2,
                1,
                true,
                Some("x.png"),
                None,
                None,
                keep,
            )
            .unwrap();
            assert_eq!(s.list(None, 50).unwrap().len(), 1);
            s.set_setting("hotkey", b"Ctrl+Alt+Shift+S").unwrap();
            assert_eq!(s.setting("hotkey").unwrap().unwrap(), b"Ctrl+Alt+Shift+S");
        }
        let raw = std::fs::read(&path).unwrap();
        for needle in [&b"gizli-rapor"[..], b"parola-ipucu", b"Downloads", b"x.png"] {
            assert!(
                !raw.windows(needle.len()).any(|w| w == needle),
                "plaintext found in the db file"
            );
        }
        // A wrong key cannot read names.
        let s = Store::open(&path, &[1; 32]).unwrap();
        assert_eq!(s.list(None, 10).unwrap_err(), StoreError::Crypto);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fields_are_bound_to_their_row() {
        let mut s = Store::open_in_memory(&[3; 32]).unwrap();
        let peer = EndpointId([1; 32]);
        let a = s
            .add(
                1,
                Direction::In,
                &peer,
                3,
                1,
                true,
                Some("a.txt"),
                None,
                None,
                Retention::default(),
            )
            .unwrap();
        let b = s
            .add(
                2,
                Direction::In,
                &peer,
                3,
                1,
                true,
                Some("b.txt"),
                None,
                None,
                Retention::default(),
            )
            .unwrap();
        // Swap the encrypted names between rows: decryption must fail.
        s.db.execute_batch(&format!(
            "UPDATE history SET name = (SELECT name FROM history WHERE id = {b}) WHERE id = {a};"
        ))
        .unwrap();
        assert_eq!(s.list(None, 10).unwrap_err(), StoreError::Crypto);
    }
}
