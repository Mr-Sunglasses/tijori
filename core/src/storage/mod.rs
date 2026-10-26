//! The only way the core touches a drive.
//!
//! Paths are relative to the root of the drive (the exFAT volume), use `/`
//! as separator and are ASCII only, for example `TIJORI/vault.header`. The
//! vault lives in `TIJORI/`; the drive root also holds `README-TIJORI.txt`.

mod fs;
mod mem;

use std::io::{Read, Write};

pub use fs::StdFsStorage;
pub use mem::{Fault, MemStorage};

use crate::error::StorageError;

/// A file being written. Nothing is visible at the target path until
/// [`AtomicWriter::commit`] succeeds.
pub trait AtomicWriter: Write + Send {
    /// Flushes, syncs and renames the temporary file onto the target.
    fn commit(self: Box<Self>) -> Result<(), StorageError>;
}

pub trait Storage: Send + Sync {
    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError>;

    fn open_read(&self, path: &str) -> Result<Box<dyn Read + Send>, StorageError>;

    /// Size in bytes, used to refuse oversized files before reading them.
    fn len(&self, path: &str) -> Result<u64, StorageError>;

    /// Writes `<path>.tmp`, flushes and syncs it, renames it to `path` and
    /// syncs the parent folder. If the platform cannot rename over an
    /// existing file it deletes the target first; the A/B root scheme
    /// tolerates the gap.
    fn write_atomic(&self, path: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Streaming variant of [`Storage::write_atomic`] for large objects.
    fn create_writer(&self, path: &str) -> Result<Box<dyn AtomicWriter>, StorageError>;

    /// Creates `path` only if it does not exist (the write lock).
    fn create_exclusive(&self, path: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Names (not paths) of the entries in a folder. A missing folder is empty.
    fn list(&self, dir: &str) -> Result<Vec<String>, StorageError>;

    fn exists(&self, path: &str) -> Result<bool, StorageError>;

    fn remove(&self, path: &str) -> Result<(), StorageError>;

    fn mkdir_all(&self, dir: &str) -> Result<(), StorageError>;

    /// Best effort: set modified and accessed time to 2000-01-01T00:00:00Z.
    fn neutralize_times(&self, path: &str) -> Result<(), StorageError>;
}

/// Rejects anything but plain relative ASCII paths.
pub fn check_path(path: &str) -> Result<(), StorageError> {
    let ok = !path.is_empty()
        && path.is_ascii()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    if ok {
        Ok(())
    } else {
        Err(StorageError::InvalidPath(path.to_string()))
    }
}

pub(crate) fn tmp_path(path: &str) -> String {
    format!("{path}.tmp")
}

/// 2000-01-01T00:00:00Z as Unix seconds (spec §11).
pub const NEUTRAL_TIME: u64 = 946_684_800;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_rules() {
        for ok in ["TIJORI/vault.header", "a", "TIJORI/objects/3f/x.tjo"] {
            assert!(check_path(ok).is_ok(), "{ok}");
        }
        for bad in ["", "/abs", "a/../b", "a//b", "a/", "./a", "a\\b", "é"] {
            assert!(check_path(bad).is_err(), "{bad}");
        }
    }
}
