//! `Storage` over `std::fs`, for desktop systems.

use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use super::{AtomicWriter, NEUTRAL_TIME, Storage, check_path, tmp_path};
use crate::error::StorageError;

/// Storage rooted at a drive's mount point (or any folder, for tests).
#[derive(Debug, Clone)]
pub struct StdFsStorage {
    root: PathBuf,
}

fn map_err(path: &str, e: io::Error) -> StorageError {
    match e.kind() {
        io::ErrorKind::NotFound => StorageError::NotFound(path.to_string()),
        io::ErrorKind::AlreadyExists => StorageError::AlreadyExists(path.to_string()),
        _ => StorageError::io(path, e),
    }
}

/// Syncs a folder so a rename inside it is durable. Not every platform or
/// file system supports this, so failures are ignored.
fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

fn rename_over(tmp: &Path, target: &Path) -> io::Result<()> {
    match fs::rename(tmp, target) {
        Ok(()) => Ok(()),
        Err(e) if target.exists() && e.kind() != io::ErrorKind::NotFound => {
            // Some file systems cannot rename over an existing file.
            fs::remove_file(target)?;
            fs::rename(tmp, target)
        }
        Err(e) => Err(e),
    }
}

impl StdFsStorage {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        StdFsStorage { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn full(&self, path: &str) -> Result<PathBuf, StorageError> {
        check_path(path)?;
        Ok(self.root.join(path))
    }
}

struct FsWriter {
    file: File,
    tmp: PathBuf,
    target: PathBuf,
    path: String,
    done: bool,
}

impl Write for FsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AtomicWriter for FsWriter {
    fn commit(mut self: Box<Self>) -> Result<(), StorageError> {
        let path = self.path.clone();
        self.file.flush().map_err(|e| map_err(&path, e))?;
        self.file.sync_all().map_err(|e| map_err(&path, e))?;
        rename_over(&self.tmp, &self.target).map_err(|e| map_err(&path, e))?;
        if let Some(parent) = self.target.parent() {
            sync_dir(parent);
        }
        self.done = true;
        Ok(())
    }
}

impl Drop for FsWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

impl Storage for StdFsStorage {
    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        fs::read(self.full(path)?).map_err(|e| map_err(path, e))
    }

    fn open_read(&self, path: &str) -> Result<Box<dyn Read + Send>, StorageError> {
        let f = File::open(self.full(path)?).map_err(|e| map_err(path, e))?;
        Ok(Box::new(BufReader::with_capacity(128 * 1024, f)))
    }

    fn len(&self, path: &str) -> Result<u64, StorageError> {
        Ok(fs::metadata(self.full(path)?)
            .map_err(|e| map_err(path, e))?
            .len())
    }

    fn write_atomic(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let mut w = self.create_writer(path)?;
        w.write_all(data).map_err(|e| map_err(path, e))?;
        w.commit()
    }

    fn create_writer(&self, path: &str) -> Result<Box<dyn AtomicWriter>, StorageError> {
        let target = self.full(path)?;
        let tmp = self.full(&tmp_path(path))?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| map_err(path, e))?;
        Ok(Box::new(FsWriter {
            file,
            tmp,
            target,
            path: path.to_string(),
            done: false,
        }))
    }

    fn create_exclusive(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let full = self.full(path)?;
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&full)
            .map_err(|e| map_err(path, e))?;
        f.write_all(data)
            .and_then(|()| f.sync_all())
            .map_err(|e| map_err(path, e))?;
        if let Some(parent) = full.parent() {
            sync_dir(parent);
        }
        Ok(())
    }

    fn list(&self, dir: &str) -> Result<Vec<String>, StorageError> {
        let rd = match fs::read_dir(self.full(dir)?) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(map_err(dir, e)),
        };
        let mut names = Vec::new();
        for entry in rd {
            let entry = entry.map_err(|e| map_err(dir, e))?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    fn exists(&self, path: &str) -> Result<bool, StorageError> {
        self.full(path)?.try_exists().map_err(|e| map_err(path, e))
    }

    fn remove(&self, path: &str) -> Result<(), StorageError> {
        fs::remove_file(self.full(path)?).map_err(|e| map_err(path, e))
    }

    fn mkdir_all(&self, dir: &str) -> Result<(), StorageError> {
        fs::create_dir_all(self.full(dir)?).map_err(|e| map_err(dir, e))
    }

    fn neutralize_times(&self, path: &str) -> Result<(), StorageError> {
        let t = UNIX_EPOCH + Duration::from_secs(NEUTRAL_TIME);
        let f = OpenOptions::new()
            .write(true)
            .open(self.full(path)?)
            .map_err(|e| map_err(path, e))?;
        f.set_times(FileTimes::new().set_accessed(t).set_modified(t))
            .map_err(|e| map_err(path, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_and_list() {
        let dir = tempfile::tempdir().unwrap();
        let s = StdFsStorage::new(dir.path());
        s.mkdir_all("TIJORI/objects/ab").unwrap();
        s.write_atomic("TIJORI/x", b"one").unwrap();
        s.write_atomic("TIJORI/x", b"two").unwrap();
        assert_eq!(s.read("TIJORI/x").unwrap(), b"two");
        assert_eq!(s.len("TIJORI/x").unwrap(), 3);
        assert_eq!(s.list("TIJORI").unwrap(), vec!["objects", "x"]);
        assert!(s.list("TIJORI/missing").unwrap().is_empty());
        s.neutralize_times("TIJORI/x").unwrap();
        let mtime = fs::metadata(dir.path().join("TIJORI/x"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(mtime, UNIX_EPOCH + Duration::from_secs(NEUTRAL_TIME));
        s.create_exclusive("TIJORI/.lock", b"l").unwrap();
        assert!(matches!(
            s.create_exclusive("TIJORI/.lock", b"l"),
            Err(StorageError::AlreadyExists(_))
        ));
        s.remove("TIJORI/.lock").unwrap();
        assert!(matches!(
            s.read("TIJORI/.lock"),
            Err(StorageError::NotFound(_))
        ));
    }

    #[test]
    fn dropped_writer_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = StdFsStorage::new(dir.path());
        let mut w = s.create_writer("f").unwrap();
        w.write_all(b"partial").unwrap();
        drop(w);
        assert!(!s.exists("f").unwrap());
        assert!(!s.exists("f.tmp").unwrap());
    }
}
