//! The mounted file system, independent of the FUSE binding: path-based
//! operations over a [`Vault`], with errors as `errno` values.
//!
//! Writes are buffered in memory (never on the host disk) and encrypted into
//! the vault when the file is flushed or closed. Commits are coalesced: at
//! most one every [`COMMIT_INTERVAL`], plus one at unmount.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tijori_core::{EntryKind, Error, FileMeta, Vault, VaultPath};
use zeroize::Zeroizing;

pub type FsResult<T> = Result<T, i32>;

/// Commit at most this often while files are being saved.
pub const COMMIT_INTERVAL: Duration = Duration::from_secs(2);
/// Files up to this size are read into memory on first access, so random
/// reads are cheap. Larger files stream.
const READ_CACHE_MAX: u64 = 16 * 1024 * 1024;
/// Files are edited in memory; refuse to open bigger ones for writing.
pub const MAX_EDIT_SIZE: u64 = 1024 * 1024 * 1024;

/// Names the mount refuses to create: OS metadata that would otherwise end
/// up encrypted in the vault and travel to other devices.
pub fn is_refused_name(name: &str) -> bool {
    name.starts_with("._") || name == ".DS_Store" || name == ".metadata_never_index"
}

pub fn errno(e: &Error) -> i32 {
    match e {
        Error::NotFound(_) => libc::ENOENT,
        Error::AlreadyExists(_) => libc::EEXIST,
        Error::NotADirectory(_) => libc::ENOTDIR,
        Error::IsADirectory(_) => libc::EISDIR,
        Error::NotEmpty(_) => libc::ENOTEMPTY,
        Error::ReadOnly(_) | Error::Locked(_) => libc::EROFS,
        Error::InvalidInput(_) => libc::EINVAL,
        Error::Cancelled => libc::EINTR,
        _ => libc::EIO,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr {
    pub kind: EntryKind,
    pub size: u64,
    pub mtime_ms: i64,
    pub executable: bool,
}

impl Attr {
    pub fn mtime(&self) -> SystemTime {
        if self.mtime_ms >= 0 {
            UNIX_EPOCH + Duration::from_millis(self.mtime_ms as u64)
        } else {
            UNIX_EPOCH - Duration::from_millis(self.mtime_ms.unsigned_abs())
        }
    }

    /// Owner-only permissions (Plan Milestone 4: mode 0700).
    pub fn perm(&self) -> u16 {
        match (self.kind, self.executable) {
            (EntryKind::Dir, _) | (_, true) => 0o700,
            _ => 0o600,
        }
    }
}

struct ReadHandle {
    path: VaultPath,
    size: u64,
    cache: Option<Zeroizing<Vec<u8>>>,
    reader: Option<tijori_core::vault::FileReader>,
    pos: u64,
}

struct WriteHandle {
    path: VaultPath,
    data: Zeroizing<Vec<u8>>,
    dirty: bool,
    executable: bool,
    /// The file was deleted while open: do not write it back.
    unlinked: bool,
}

enum Handle {
    Read(Box<ReadHandle>),
    Write(WriteHandle),
    /// An empty, read-only file the mount shows but the vault does not hold.
    Synthetic,
}

struct Inner {
    vault: Option<Vault>,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    last_commit: Instant,
    last_activity: Instant,
    last_error: Option<String>,
}

pub struct VaultFs {
    inner: Mutex<Inner>,
    /// Empty read-only files shown in the root, such as `.metadata_never_index`.
    synthetic: Vec<String>,
    drive: PathBuf,
}

fn vpath(p: &str) -> FsResult<VaultPath> {
    VaultPath::parse(p).map_err(|_| libc::EINVAL)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Inner {
    fn vault(&mut self) -> FsResult<&mut Vault> {
        self.last_activity = Instant::now();
        self.vault.as_mut().ok_or(libc::EIO)
    }

    fn fail(&mut self, e: Error) -> i32 {
        let code = errno(&e);
        if code == libc::EIO {
            self.last_error = Some(e.to_string());
        }
        code
    }

    fn write_handle_for(&self, path: &VaultPath) -> Option<&WriteHandle> {
        self.handles.values().find_map(|h| match h {
            Handle::Write(w) if &w.path == path && !w.unlinked => Some(w),
            _ => None,
        })
    }

    /// Encrypts a dirty write handle into the vault.
    fn persist(&mut self, fh: u64) -> FsResult<()> {
        let Some(Handle::Write(w)) = self.handles.get_mut(&fh) else {
            return Ok(());
        };
        if !w.dirty || w.unlinked {
            return Ok(());
        }
        let path = w.path.clone();
        let data = std::mem::take(&mut w.data);
        let meta = FileMeta {
            mtime_ms: now_ms(),
            executable: w.executable,
        };
        let result = self.vault()?.write_bytes(&path, &data, meta);
        if let Some(Handle::Write(w)) = self.handles.get_mut(&fh) {
            w.data = data;
            if result.is_ok() {
                w.dirty = false;
            }
        }
        result.map_err(|e| self.fail(e))?;
        self.maybe_commit(false);
        Ok(())
    }

    /// Commits if there are changes and the last commit is old enough (or `force`).
    fn maybe_commit(&mut self, force: bool) {
        let due = force || self.last_commit.elapsed() >= COMMIT_INTERVAL;
        let Some(v) = self.vault.as_mut() else { return };
        if due && v.is_writable() && v.has_pending_changes() {
            match v.commit() {
                Ok(()) => self.last_commit = Instant::now(),
                Err(e) => {
                    self.fail(e);
                }
            }
        }
    }
}

impl VaultFs {
    pub fn new(vault: Vault, drive: PathBuf, synthetic: Vec<String>) -> Self {
        VaultFs {
            inner: Mutex::new(Inner {
                vault: Some(vault),
                handles: HashMap::new(),
                next_fh: 1,
                last_commit: Instant::now(),
                last_activity: Instant::now(),
                last_error: None,
            }),
            synthetic,
            drive,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn drive(&self) -> &PathBuf {
        &self.drive
    }

    pub fn is_writable(&self) -> bool {
        self.lock().vault.as_ref().is_some_and(Vault::is_writable)
    }

    fn is_synthetic(&self, p: &VaultPath) -> bool {
        p.components().len() == 1 && self.synthetic.iter().any(|s| s == &p.components()[0])
    }

    pub fn getattr(&self, path: &str) -> FsResult<Attr> {
        let p = vpath(path)?;
        if self.is_synthetic(&p) {
            return Ok(Attr {
                kind: EntryKind::File,
                size: 0,
                mtime_ms: 0,
                executable: false,
            });
        }
        let mut inner = self.lock();
        if let Some(w) = inner.write_handle_for(&p) {
            return Ok(Attr {
                kind: EntryKind::File,
                size: w.data.len() as u64,
                mtime_ms: now_ms(),
                executable: w.executable,
            });
        }
        match inner.vault()?.stat(&p) {
            Ok(e) => Ok(Attr {
                kind: e.kind,
                size: e.size,
                mtime_ms: e.mtime_ms,
                executable: e.executable,
            }),
            Err(e) => Err(inner.fail(e)),
        }
    }

    /// Names and kinds in a folder, including files being created.
    pub fn readdir(&self, path: &str) -> FsResult<Vec<(String, EntryKind)>> {
        let p = vpath(path)?;
        let mut inner = self.lock();
        let entries = inner.vault()?.list(&p).map_err(|e| inner.fail(e))?;
        let mut out: Vec<(String, EntryKind)> =
            entries.into_iter().map(|e| (e.name, e.kind)).collect();
        for h in inner.handles.values() {
            if let Handle::Write(w) = h
                && !w.unlinked
                && w.path.parent().as_ref() == Some(&p)
                && let Some(name) = w.path.name()
                && !out.iter().any(|(n, _)| n == name)
            {
                out.push((name.to_string(), EntryKind::File));
            }
        }
        if p.is_root() {
            out.extend(self.synthetic.iter().map(|s| (s.clone(), EntryKind::File)));
        }
        Ok(out)
    }

    fn add_handle(inner: &mut Inner, h: Handle) -> u64 {
        let fh = inner.next_fh;
        inner.next_fh += 1;
        inner.handles.insert(fh, h);
        fh
    }

    pub fn open(&self, path: &str, write: bool, truncate: bool) -> FsResult<u64> {
        let p = vpath(path)?;
        let mut inner = self.lock();
        if self.is_synthetic(&p) {
            return if write {
                Err(libc::EACCES)
            } else {
                Ok(Self::add_handle(&mut inner, Handle::Synthetic))
            };
        }
        let pending = inner
            .write_handle_for(&p)
            .map(|w| (w.data.clone(), w.executable));
        let (size, executable) = match &pending {
            Some((d, x)) => (d.len() as u64, *x),
            None => {
                let e = inner.vault()?.stat(&p).map_err(|e| inner.fail(e))?;
                if e.kind == EntryKind::Dir {
                    return Err(libc::EISDIR);
                }
                (e.size, e.executable)
            }
        };
        if !write {
            if let Some((data, _)) = pending {
                return Ok(Self::add_handle(
                    &mut inner,
                    Handle::Read(Box::new(ReadHandle {
                        path: p,
                        size,
                        cache: Some(data),
                        reader: None,
                        pos: 0,
                    })),
                ));
            }
            return Ok(Self::add_handle(
                &mut inner,
                Handle::Read(Box::new(ReadHandle {
                    path: p,
                    size,
                    cache: None,
                    reader: None,
                    pos: 0,
                })),
            ));
        }
        if !inner.vault()?.is_writable() {
            return Err(libc::EROFS);
        }
        let data = if truncate {
            Zeroizing::new(Vec::new())
        } else if let Some((d, _)) = pending {
            d
        } else {
            if size > MAX_EDIT_SIZE {
                return Err(libc::EFBIG);
            }
            Zeroizing::new(
                inner
                    .vault()?
                    .read_to_vec(&p, MAX_EDIT_SIZE)
                    .map_err(|e| inner.fail(e))?,
            )
        };
        Ok(Self::add_handle(
            &mut inner,
            Handle::Write(WriteHandle {
                path: p,
                data,
                dirty: truncate,
                executable,
                unlinked: false,
            }),
        ))
    }

    pub fn create(&self, path: &str, executable: bool) -> FsResult<u64> {
        let p = vpath(path)?;
        let name = p.name().ok_or(libc::EINVAL)?;
        if is_refused_name(name) {
            return Err(libc::EACCES);
        }
        let mut inner = self.lock();
        let v = inner.vault()?;
        if !v.is_writable() {
            return Err(libc::EROFS);
        }
        let parent = p.parent().ok_or(libc::EINVAL)?;
        match v.stat(&parent) {
            Ok(e) if e.kind == EntryKind::Dir => {}
            Ok(_) => return Err(libc::ENOTDIR),
            Err(e) => return Err(inner.fail(e)),
        }
        if let Ok(e) = inner.vault()?.stat(&p)
            && e.kind == EntryKind::Dir
        {
            return Err(libc::EISDIR);
        }
        Ok(Self::add_handle(
            &mut inner,
            Handle::Write(WriteHandle {
                path: p,
                data: Zeroizing::new(Vec::new()),
                dirty: true,
                executable,
                unlinked: false,
            }),
        ))
    }

    pub fn read(&self, fh: u64, offset: u64, size: usize) -> FsResult<Vec<u8>> {
        let mut inner = self.lock();
        inner.last_activity = Instant::now();
        let Inner { handles, vault, .. } = &mut *inner;
        let vault = vault.as_mut().ok_or(libc::EIO)?;
        match handles.get_mut(&fh).ok_or(libc::EBADF)? {
            Handle::Synthetic => Ok(Vec::new()),
            Handle::Write(w) => {
                let start = (offset as usize).min(w.data.len());
                let end = start.saturating_add(size).min(w.data.len());
                Ok(w.data[start..end].to_vec())
            }
            Handle::Read(r) => {
                if r.cache.is_none() && r.size <= READ_CACHE_MAX {
                    r.cache = Some(Zeroizing::new(
                        vault
                            .read_to_vec(&r.path, READ_CACHE_MAX)
                            .map_err(|e| errno(&e))?,
                    ));
                }
                if let Some(c) = &r.cache {
                    let start = (offset as usize).min(c.len());
                    let end = start.saturating_add(size).min(c.len());
                    return Ok(c[start..end].to_vec());
                }
                // Large file: stream, reopening only to go backwards.
                if r.reader.is_none() || offset < r.pos {
                    r.reader = Some(vault.read_file(&r.path).map_err(|e| errno(&e))?);
                    r.pos = 0;
                }
                let reader = r.reader.as_mut().expect("opened above");
                let mut skip = vec![0u8; 64 * 1024];
                while r.pos < offset {
                    let want = ((offset - r.pos) as usize).min(skip.len());
                    let n =
                        std::io::Read::read(reader, &mut skip[..want]).map_err(|_| libc::EIO)?;
                    if n == 0 {
                        return Ok(Vec::new());
                    }
                    r.pos += n as u64;
                }
                let mut out = vec![0u8; size];
                let mut got = 0;
                while got < size {
                    let n = std::io::Read::read(reader, &mut out[got..]).map_err(|_| libc::EIO)?;
                    if n == 0 {
                        break;
                    }
                    got += n;
                }
                r.pos += got as u64;
                out.truncate(got);
                Ok(out)
            }
        }
    }

    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> FsResult<usize> {
        let mut inner = self.lock();
        inner.last_activity = Instant::now();
        match inner.handles.get_mut(&fh).ok_or(libc::EBADF)? {
            Handle::Write(w) => {
                let end = offset.checked_add(data.len() as u64).ok_or(libc::EFBIG)?;
                if end > MAX_EDIT_SIZE {
                    return Err(libc::EFBIG);
                }
                if w.data.len() < end as usize {
                    w.data.resize(end as usize, 0);
                }
                w.data[offset as usize..end as usize].copy_from_slice(data);
                w.dirty = true;
                Ok(data.len())
            }
            _ => Err(libc::EBADF),
        }
    }

    /// Changes a file's size: through an open handle if one exists,
    /// otherwise by rewriting the file.
    pub fn truncate(&self, path: &str, size: u64, fh: Option<u64>) -> FsResult<()> {
        if size > MAX_EDIT_SIZE {
            return Err(libc::EFBIG);
        }
        let p = vpath(path)?;
        let mut inner = self.lock();
        let mut resized = false;
        for (id, h) in inner.handles.iter_mut() {
            if let Handle::Write(w) = h
                && (Some(*id) == fh || w.path == p)
                && !w.unlinked
            {
                w.data.resize(size as usize, 0);
                w.dirty = true;
                resized = true;
            }
        }
        if resized {
            return Ok(());
        }
        let v = inner.vault()?;
        let e = v.stat(&p).map_err(|e| errno(&e))?;
        if e.kind == EntryKind::Dir {
            return Err(libc::EISDIR);
        }
        if e.size == size {
            return Ok(());
        }
        let mut data = Zeroizing::new(if size == 0 {
            Vec::new()
        } else {
            v.read_to_vec(&p, MAX_EDIT_SIZE).map_err(|e| errno(&e))?
        });
        data.resize(size as usize, 0);
        let meta = FileMeta {
            mtime_ms: now_ms(),
            executable: e.executable,
        };
        let r = inner.vault()?.write_bytes(&p, &data, meta);
        r.map_err(|e| inner.fail(e))?;
        inner.maybe_commit(false);
        Ok(())
    }

    pub fn flush(&self, fh: u64) -> FsResult<()> {
        self.lock().persist(fh)
    }

    pub fn release(&self, fh: u64) -> FsResult<()> {
        let mut inner = self.lock();
        let r = inner.persist(fh);
        inner.handles.remove(&fh);
        r
    }

    fn mutate(&self, f: impl FnOnce(&mut Vault) -> Result<(), Error>) -> FsResult<()> {
        let mut inner = self.lock();
        let r = f(inner.vault()?);
        r.map_err(|e| inner.fail(e))?;
        inner.maybe_commit(false);
        Ok(())
    }

    pub fn mkdir(&self, path: &str) -> FsResult<()> {
        let p = vpath(path)?;
        if p.name().is_some_and(is_refused_name) {
            return Err(libc::EACCES);
        }
        self.mutate(|v| v.mkdir(&p))
    }

    pub fn unlink(&self, path: &str) -> FsResult<()> {
        let p = vpath(path)?;
        if self.is_synthetic(&p) {
            return Err(libc::EACCES);
        }
        let mut inner = self.lock();
        let mut had_pending = false;
        for h in inner.handles.values_mut() {
            if let Handle::Write(w) = h
                && w.path == p
            {
                had_pending |= !w.unlinked;
                w.unlinked = true;
            }
        }
        match inner.vault()?.stat(&p) {
            Ok(e) if e.kind == EntryKind::Dir => Err(libc::EISDIR),
            Ok(_) => {
                let r = inner.vault()?.remove(&p, false);
                r.map_err(|e| inner.fail(e))?;
                inner.maybe_commit(false);
                Ok(())
            }
            // A file that only existed in an open handle.
            Err(Error::NotFound(_)) if had_pending => Ok(()),
            Err(e) => Err(inner.fail(e)),
        }
    }

    pub fn rmdir(&self, path: &str) -> FsResult<()> {
        let p = vpath(path)?;
        let mut inner = self.lock();
        match inner.vault()?.stat(&p) {
            Ok(e) if e.kind != EntryKind::Dir => return Err(libc::ENOTDIR),
            Ok(_) => {}
            Err(e) => return Err(inner.fail(e)),
        }
        let r = inner.vault()?.remove(&p, false);
        r.map_err(|e| inner.fail(e))?;
        inner.maybe_commit(false);
        Ok(())
    }

    pub fn rename(&self, from: &str, to: &str) -> FsResult<()> {
        let (from, to) = (vpath(from)?, vpath(to)?);
        if to.name().is_some_and(is_refused_name) || self.is_synthetic(&from) {
            return Err(libc::EACCES);
        }
        let mut inner = self.lock();
        // Write back open files first so the vault holds what is renamed.
        let ids: Vec<u64> = inner.handles.keys().copied().collect();
        for id in ids {
            let under = matches!(inner.handles.get(&id), Some(Handle::Write(w)) if w.path.starts_with(&from));
            if under {
                inner.persist(id)?;
            }
        }
        let r = inner.vault()?.rename(&from, &to);
        r.map_err(|e| inner.fail(e))?;
        for h in inner.handles.values_mut() {
            let path = match h {
                Handle::Write(w) => &mut w.path,
                Handle::Read(r) => &mut r.path,
                Handle::Synthetic => continue,
            };
            if path.starts_with(&from) {
                let rest = &path.components()[from.components().len()..];
                let mut new = to.clone();
                for c in rest {
                    new = new.join(c).map_err(|_| libc::EINVAL)?;
                }
                *path = new;
            }
        }
        inner.maybe_commit(false);
        Ok(())
    }

    pub fn set_meta(
        &self,
        path: &str,
        mtime_ms: Option<i64>,
        executable: Option<bool>,
    ) -> FsResult<()> {
        let p = vpath(path)?;
        if self.is_synthetic(&p) {
            return Ok(());
        }
        let mut inner = self.lock();
        let mut pending = false;
        for h in inner.handles.values_mut() {
            if let (Handle::Write(w), Some(x)) = (h, executable)
                && w.path == p
            {
                w.executable = x;
                pending = true;
            }
        }
        if pending && inner.vault()?.stat(&p).is_err() {
            return Ok(());
        }
        let r = inner.vault()?.set_meta(&p, mtime_ms, executable);
        r.map_err(|e| inner.fail(e))?;
        inner.maybe_commit(false);
        Ok(())
    }

    /// Commits changes that have waited at least [`COMMIT_INTERVAL`].
    /// Returns the time since the last file system call, for the idle timeout.
    pub fn tick(&self) -> Duration {
        let mut inner = self.lock();
        inner.maybe_commit(false);
        inner.last_activity.elapsed()
    }

    pub fn take_error(&self) -> Option<String> {
        self.lock().last_error.take()
    }

    /// Writes back every open file, commits and locks the vault.
    pub fn shutdown(&self) -> Result<(), Error> {
        let mut inner = self.lock();
        let ids: Vec<u64> = inner.handles.keys().copied().collect();
        for id in ids {
            let _ = inner.persist(id);
        }
        inner.handles.clear();
        match inner.vault.take() {
            Some(v) => v.lock(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tijori_core::Password;
    use tijori_core::storage::MemStorage;
    use tijori_core::vault::{ArgonChoice, CreateOptions};

    fn fs() -> (VaultFs, MemStorage) {
        let s = MemStorage::new();
        let mut opts =
            CreateOptions::new(Password::new("orbit lantern cactus velvet mango thunder"));
        opts.argon = ArgonChoice::minimum();
        let (v, _) = Vault::create(Arc::new(s.clone()), opts).unwrap();
        (
            VaultFs::new(v, PathBuf::from("/"), vec![".metadata_never_index".into()]),
            s,
        )
    }

    #[test]
    fn create_write_read_rename_delete() {
        let (fs, _) = fs();
        let fh = fs.create("/notes.txt", false).unwrap();
        assert_eq!(fs.write(fh, 0, b"hello").unwrap(), 5);
        assert_eq!(fs.write(fh, 10, b"!").unwrap(), 1);
        assert_eq!(
            fs.getattr("/notes.txt").unwrap().size,
            11,
            "visible before close"
        );
        assert!(
            fs.readdir("/")
                .unwrap()
                .iter()
                .any(|(n, _)| n == "notes.txt")
        );
        fs.release(fh).unwrap();
        let fh = fs.open("/notes.txt", false, false).unwrap();
        assert_eq!(fs.read(fh, 0, 100).unwrap(), b"hello\0\0\0\0\0!");
        fs.release(fh).unwrap();

        // Edit in place without truncating.
        let fh = fs.open("/notes.txt", true, false).unwrap();
        fs.write(fh, 0, b"J").unwrap();
        fs.release(fh).unwrap();
        fs.truncate("/notes.txt", 5, None).unwrap();
        let fh = fs.open("/notes.txt", false, false).unwrap();
        assert_eq!(fs.read(fh, 0, 100).unwrap(), b"Jello");
        fs.release(fh).unwrap();

        fs.mkdir("/docs").unwrap();
        fs.rename("/notes.txt", "/docs/n.txt").unwrap();
        assert_eq!(fs.getattr("/notes.txt"), Err(libc::ENOENT));
        assert_eq!(fs.rmdir("/docs"), Err(libc::ENOTEMPTY));
        fs.unlink("/docs/n.txt").unwrap();
        fs.rmdir("/docs").unwrap();
        fs.shutdown().unwrap();
    }

    #[test]
    fn metadata_files_are_refused_and_synthetic_files_shown() {
        let (fs, _) = fs();
        assert_eq!(fs.create("/._notes.txt", false), Err(libc::EACCES));
        assert_eq!(fs.create("/.DS_Store", false), Err(libc::EACCES));
        assert_eq!(fs.mkdir("/._x"), Err(libc::EACCES));
        assert!(
            fs.readdir("/")
                .unwrap()
                .iter()
                .any(|(n, _)| n == ".metadata_never_index")
        );
        assert_eq!(fs.getattr("/.metadata_never_index").unwrap().size, 0);
        assert_eq!(
            fs.open("/.metadata_never_index", true, false),
            Err(libc::EACCES)
        );
    }

    #[test]
    fn changes_survive_shutdown_and_unlinked_open_files_vanish() {
        let (fs, s) = fs();
        let fh = fs.create("/keep.txt", false).unwrap();
        fs.write(fh, 0, b"kept").unwrap();
        let gone = fs.create("/gone.txt", false).unwrap();
        fs.write(gone, 0, b"x").unwrap();
        fs.unlink("/gone.txt").unwrap();
        fs.release(gone).unwrap();
        fs.shutdown().unwrap(); // keep.txt is still open: written back here
        let (mut v, _) = Vault::unlock(
            Arc::new(s),
            &tijori_core::UnlockSecret::password("orbit lantern cactus velvet mango thunder"),
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            v.read_to_vec(&VaultPath::parse("/keep.txt").unwrap(), 100)
                .unwrap(),
            b"kept"
        );
        assert!(!v.exists(&VaultPath::parse("/gone.txt").unwrap()).unwrap());
    }

    #[test]
    fn large_files_stream_with_seeks() {
        let (fs, _) = fs();
        let data: Vec<u8> = (0..(READ_CACHE_MAX as usize + 300_000))
            .map(|i| (i % 251) as u8)
            .collect();
        {
            let mut inner = fs.lock();
            inner
                .vault()
                .unwrap()
                .write_bytes(&VaultPath::parse("/big").unwrap(), &data, FileMeta::now())
                .unwrap();
        }
        let fh = fs.open("/big", false, false).unwrap();
        let tail = data.len() as u64 - 1000;
        assert_eq!(fs.read(fh, tail, 4096).unwrap(), &data[tail as usize..]);
        assert_eq!(
            fs.read(fh, 5, 10).unwrap(),
            &data[5..15],
            "backwards reopens"
        );
        assert_eq!(
            fs.read(fh, 15, 10).unwrap(),
            &data[15..25],
            "sequential continues"
        );
        fs.release(fh).unwrap();
    }

    #[test]
    fn commits_are_coalesced() {
        let (fs, _) = fs();
        let rev = |fs: &VaultFs| fs.lock().vault.as_ref().unwrap().rev();
        let start = rev(&fs);
        for i in 0..5 {
            let fh = fs.create(&format!("/f{i}"), false).unwrap();
            fs.release(fh).unwrap();
        }
        assert!(rev(&fs) <= start + 1, "no commit storm");
        fs.lock().last_commit = Instant::now() - COMMIT_INTERVAL;
        fs.tick();
        assert!(rev(&fs) > start);
        assert!(!fs.lock().vault.as_ref().unwrap().has_pending_changes());
    }
}
