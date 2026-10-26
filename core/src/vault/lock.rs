//! The write lock `TIJORI/.lock` (spec §9.2): plain text, created with
//! exclusive-create, holding a random lock ID, the writer ID and a timestamp.

use std::sync::Arc;

use super::{LOCK_PATH, hex, now_secs};
use crate::crypto::random_array;
use crate::error::{Error, Result, StorageError};
use crate::storage::Storage;

/// A lock older than this with no live process may be broken (spec §9.2).
pub const STALE_AFTER_SECS: u64 = 10 * 60;

/// Who holds the lock, as recorded in the lock file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    pub lock_id: String,
    pub writer_id: String,
    /// Unix seconds of the last refresh.
    pub timestamp: u64,
    pub pid: Option<u32>,
}

impl LockInfo {
    fn render(&self) -> String {
        let mut s = format!(
            "tijori-lock v1\nlock_id={}\nwriter_id={}\ntimestamp={}\n",
            self.lock_id, self.writer_id, self.timestamp
        );
        if let Some(pid) = self.pid {
            s.push_str(&format!("pid={pid}\n"));
        }
        s
    }

    pub fn parse(data: &[u8]) -> Option<LockInfo> {
        let text = std::str::from_utf8(data).ok()?;
        let field = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .map(str::to_string)
        };
        Some(LockInfo {
            lock_id: field("lock_id")?,
            writer_id: field("writer_id")?,
            timestamp: field("timestamp")?.parse().ok()?,
            pid: field("pid").and_then(|p| p.parse().ok()),
        })
    }

    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.timestamp)
    }

    /// Older than 10 minutes. Breaking it still needs the user's consent.
    pub fn is_stale(&self) -> bool {
        self.age_secs() > STALE_AFTER_SECS
    }

    /// Whether this device wrote the lock.
    pub fn is_from_writer(&self, writer_id: &[u8; 16]) -> bool {
        self.writer_id == hex(writer_id)
    }
}

/// A held lock; released by [`WriteLock::release`] or on drop.
pub(crate) struct WriteLock {
    storage: Arc<dyn Storage>,
    info: LockInfo,
    released: bool,
}

pub(crate) enum Acquire {
    Acquired(WriteLock),
    HeldBy(Option<LockInfo>),
}

impl WriteLock {
    pub(crate) fn acquire(storage: Arc<dyn Storage>, writer_id: &[u8; 16]) -> Result<Acquire> {
        let info = LockInfo {
            lock_id: hex(&random_array::<16>()),
            writer_id: hex(writer_id),
            timestamp: now_secs(),
            pid: Some(std::process::id()),
        };
        match storage.create_exclusive(LOCK_PATH, info.render().as_bytes()) {
            Ok(()) => {
                let _ = storage.neutralize_times(LOCK_PATH);
                Ok(Acquire::Acquired(WriteLock {
                    storage,
                    info,
                    released: false,
                }))
            }
            Err(StorageError::AlreadyExists(_)) => {
                let holder = storage
                    .read(LOCK_PATH)
                    .ok()
                    .and_then(|d| LockInfo::parse(&d));
                Ok(Acquire::HeldBy(holder))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Updates the timestamp so a long session is not mistaken for a stale
    /// lock. Fails if someone else has taken the lock meanwhile.
    pub(crate) fn refresh(&mut self) -> Result<()> {
        self.check_ours()?;
        self.info.timestamp = now_secs();
        self.storage
            .write_atomic(LOCK_PATH, self.info.render().as_bytes())?;
        let _ = self.storage.neutralize_times(LOCK_PATH);
        Ok(())
    }

    fn check_ours(&self) -> Result<()> {
        let current = self
            .storage
            .read(LOCK_PATH)
            .ok()
            .and_then(|d| LockInfo::parse(&d));
        match current {
            Some(i) if i.lock_id == self.info.lock_id => Ok(()),
            _ => Err(Error::Locked(
                "the vault lock was broken by another writer".into(),
            )),
        }
    }

    pub(crate) fn release(mut self) -> Result<()> {
        self.released = true;
        if self.check_ours().is_ok() {
            self.storage.remove(LOCK_PATH)?;
        }
        Ok(())
    }
}

impl Drop for WriteLock {
    fn drop(&mut self) {
        if !self.released && self.check_ours().is_ok() {
            let _ = self.storage.remove(LOCK_PATH);
        }
    }
}

/// Removes a lock left by another writer. Only after the user confirms.
pub fn break_lock(storage: &dyn Storage) -> Result<()> {
    match storage.remove(LOCK_PATH) {
        Ok(()) | Err(StorageError::NotFound(_)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Reads the current lock, if any.
pub fn read_lock(storage: &dyn Storage) -> Result<Option<LockInfo>> {
    match storage.read(LOCK_PATH) {
        Ok(d) => Ok(LockInfo::parse(&d)),
        Err(StorageError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
