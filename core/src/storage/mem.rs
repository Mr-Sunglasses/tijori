//! In-memory `Storage` for tests, with crash injection.
//!
//! A crash is armed at the N-th mutating operation (`write_atomic`, writer
//! `commit`, `remove`, `create_exclusive`). That operation fails, tears or
//! deletes its target as configured, and every operation after it fails, as
//! if the machine lost power. [`MemStorage::reboot`] then gives a fresh
//! storage with whatever had reached the "disk".

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use super::{AtomicWriter, Storage, check_path, tmp_path};
use crate::error::StorageError;

/// What happens to the operation that crashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The operation does not happen.
    Fail,
    /// The target ends up holding the first half of the new data.
    Tear,
    /// The target is deleted but the new data never arrives (a crash
    /// between delete and rename on file systems without atomic rename).
    Delete,
}

#[derive(Default)]
struct State {
    files: BTreeMap<String, Vec<u8>>,
    ops: usize,
    crash_at: Option<(usize, Fault)>,
    crashed: bool,
}

/// Shared, cloneable in-memory drive.
#[derive(Clone, Default)]
pub struct MemStorage {
    state: Arc<Mutex<State>>,
}

fn dead() -> StorageError {
    StorageError::Other("storage is gone (simulated crash)".into())
}

impl MemStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arms a crash at mutating operation number `n` (0-based, counted from now).
    pub fn crash_at(&self, n: usize, fault: Fault) {
        let mut s = self.state.lock().unwrap();
        s.ops = 0;
        s.crash_at = Some((n, fault));
    }

    /// Number of mutating operations since creation or the last `crash_at`.
    pub fn ops(&self) -> usize {
        self.state.lock().unwrap().ops
    }

    pub fn crashed(&self) -> bool {
        self.state.lock().unwrap().crashed
    }

    /// A working storage holding what survived.
    pub fn reboot(&self) -> MemStorage {
        let files = self.state.lock().unwrap().files.clone();
        MemStorage {
            state: Arc::new(Mutex::new(State {
                files,
                ..State::default()
            })),
        }
    }

    pub fn files(&self) -> Vec<String> {
        self.state.lock().unwrap().files.keys().cloned().collect()
    }

    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.state.lock().unwrap().files.get(path).cloned()
    }

    /// Direct manipulation for tamper tests.
    pub fn put(&self, path: &str, data: Vec<u8>) {
        self.state
            .lock()
            .unwrap()
            .files
            .insert(path.to_string(), data);
    }

    pub fn delete(&self, path: &str) {
        self.state.lock().unwrap().files.remove(path);
    }

    /// Runs one mutating operation, applying an armed crash.
    fn mutate(&self, path: &str, new: Option<&[u8]>, exclusive: bool) -> Result<(), StorageError> {
        check_path(path)?;
        let mut s = self.state.lock().unwrap();
        if s.crashed {
            return Err(dead());
        }
        let n = s.ops;
        s.ops += 1;
        if exclusive && s.files.contains_key(path) {
            return Err(StorageError::AlreadyExists(path.to_string()));
        }
        if new.is_none() && !s.files.contains_key(path) {
            return Err(StorageError::NotFound(path.to_string()));
        }
        if let Some((at, fault)) = s.crash_at
            && at == n
        {
            s.crashed = true;
            match (fault, new) {
                (Fault::Fail, _) => {}
                (Fault::Tear, Some(data)) => {
                    s.files
                        .insert(path.to_string(), data[..data.len() / 2].to_vec());
                }
                (Fault::Tear, None) | (Fault::Delete, _) => {
                    s.files.remove(path);
                }
            }
            return Err(dead());
        }
        match new {
            Some(data) => s.files.insert(path.to_string(), data.to_vec()),
            None => s.files.remove(path),
        };
        Ok(())
    }
}

struct MemWriter {
    storage: MemStorage,
    path: String,
    buf: Vec<u8>,
}

impl Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.storage.crashed() {
            return Err(io::Error::other("storage is gone (simulated crash)"));
        }
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AtomicWriter for MemWriter {
    fn commit(self: Box<Self>) -> Result<(), StorageError> {
        self.storage.mutate(&self.path, Some(&self.buf), false)
    }
}

impl Storage for MemStorage {
    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        check_path(path)?;
        let s = self.state.lock().unwrap();
        if s.crashed {
            return Err(dead());
        }
        s.files
            .get(path)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(path.to_string()))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn Read + Send>, StorageError> {
        Ok(Box::new(Cursor::new(self.read(path)?)))
    }

    fn len(&self, path: &str) -> Result<u64, StorageError> {
        Ok(self.read(path)?.len() as u64)
    }

    fn write_atomic(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        check_path(&tmp_path(path))?;
        self.mutate(path, Some(data), false)
    }

    fn create_writer(&self, path: &str) -> Result<Box<dyn AtomicWriter>, StorageError> {
        check_path(path)?;
        if self.crashed() {
            return Err(dead());
        }
        Ok(Box::new(MemWriter {
            storage: self.clone(),
            path: path.to_string(),
            buf: Vec::new(),
        }))
    }

    fn create_exclusive(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        self.mutate(path, Some(data), true)
    }

    fn list(&self, dir: &str) -> Result<Vec<String>, StorageError> {
        check_path(dir)?;
        let s = self.state.lock().unwrap();
        if s.crashed {
            return Err(dead());
        }
        let prefix = format!("{dir}/");
        let mut names: Vec<String> = s
            .files
            .keys()
            .filter_map(|k| k.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or(rest).to_string())
            .collect();
        names.dedup();
        Ok(names)
    }

    fn exists(&self, path: &str) -> Result<bool, StorageError> {
        check_path(path)?;
        let s = self.state.lock().unwrap();
        let prefix = format!("{path}/");
        Ok(s.files.contains_key(path) || s.files.keys().any(|k| k.starts_with(&prefix)))
    }

    fn remove(&self, path: &str) -> Result<(), StorageError> {
        self.mutate(path, None, false)
    }

    fn mkdir_all(&self, dir: &str) -> Result<(), StorageError> {
        check_path(dir)?;
        if self.crashed() {
            return Err(dead());
        }
        Ok(())
    }

    fn neutralize_times(&self, path: &str) -> Result<(), StorageError> {
        check_path(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_modes() {
        for (fault, expect) in [
            (Fault::Fail, Some(b"old".to_vec())),
            (Fault::Tear, Some(b"ne".to_vec())),
            (Fault::Delete, None),
        ] {
            let s = MemStorage::new();
            s.write_atomic("f", b"old").unwrap();
            s.crash_at(0, fault);
            assert!(s.write_atomic("f", b"new!").is_err());
            assert!(s.read("f").is_err(), "everything fails after a crash");
            let after = s.reboot();
            assert_eq!(after.get("f"), expect, "{fault:?}");
            after.write_atomic("g", b"ok").unwrap();
        }
    }

    #[test]
    fn list_returns_direct_children() {
        let s = MemStorage::new();
        s.write_atomic("T/objects/ab/1.tjo", b"").unwrap();
        s.write_atomic("T/objects/cd/2.tjo", b"").unwrap();
        s.write_atomic("T/vault.header", b"").unwrap();
        assert_eq!(s.list("T").unwrap(), vec!["objects", "vault.header"]);
        assert_eq!(s.list("T/objects").unwrap(), vec!["ab", "cd"]);
    }
}
