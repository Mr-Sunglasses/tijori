//! Linux backend: `fuser` with its pure-Rust mount (`fusermount3`), mapping
//! inode numbers to vault paths for the path-based [`VaultFs`].

use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fuser::{
    BackgroundSession, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};
use tijori_core::EntryKind;

use crate::fs::{Attr, VaultFs};

const TTL: Duration = Duration::from_secs(1);

struct Inodes {
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next: u64,
}

impl Inodes {
    fn path(&self, ino: INodeNo) -> Option<String> {
        self.by_ino.get(&ino.0).cloned()
    }

    fn ino(&mut self, path: &str) -> u64 {
        if let Some(i) = self.by_path.get(path) {
            return *i;
        }
        let i = self.next;
        self.next += 1;
        self.by_ino.insert(i, path.to_string());
        self.by_path.insert(path.to_string(), i);
        i
    }

    fn forget_path(&mut self, path: &str) {
        if let Some(i) = self.by_path.remove(path) {
            self.by_ino.remove(&i);
        }
    }

    /// Moves `from` and everything under it to `to`.
    fn rename(&mut self, from: &str, to: &str) {
        self.forget_path(to);
        let prefix = format!("{from}/");
        let moved: Vec<(String, u64)> = self
            .by_path
            .iter()
            .filter(|(p, _)| *p == from || p.starts_with(&prefix))
            .map(|(p, i)| (p.clone(), *i))
            .collect();
        for (old, i) in moved {
            let new = format!("{to}{}", &old[from.len()..]);
            self.by_path.remove(&old);
            self.by_path.insert(new.clone(), i);
            self.by_ino.insert(i, new);
        }
    }
}

struct LinuxFs {
    fs: Arc<VaultFs>,
    inodes: Mutex<Inodes>,
    uid: u32,
    gid: u32,
}

fn join(parent: &str, name: &OsStr) -> Option<String> {
    let name = name.to_str()?;
    Some(if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    })
}

fn err(e: i32) -> Errno {
    Errno::from_i32(e)
}

impl LinuxFs {
    fn inodes(&self) -> std::sync::MutexGuard<'_, Inodes> {
        self.inodes.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn file_attr(&self, ino: u64, a: &Attr) -> FileAttr {
        let t = a.mtime();
        FileAttr {
            ino: INodeNo(ino),
            size: a.size,
            blocks: a.size.div_ceil(512),
            atime: t,
            mtime: t,
            ctime: t,
            crtime: t,
            kind: if a.kind == EntryKind::Dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: a.perm(),
            nlink: if a.kind == EntryKind::Dir { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 65536,
            flags: 0,
        }
    }

    fn path_of(&self, ino: INodeNo) -> Result<String, Errno> {
        self.inodes().path(ino).ok_or(Errno::ENOENT)
    }

    fn child(&self, parent: INodeNo, name: &OsStr) -> Result<String, Errno> {
        join(&self.path_of(parent)?, name).ok_or(Errno::EINVAL)
    }

    fn entry(&self, path: &str, reply: ReplyEntry) {
        match self.fs.getattr(path) {
            Ok(a) => {
                let ino = self.inodes().ino(path);
                reply.entry(&TTL, &self.file_attr(ino, &a), Generation(0));
            }
            Err(e) => reply.error(err(e)),
        }
    }
}

fn empty(r: Result<(), i32>, reply: ReplyEmpty) {
    match r {
        Ok(()) => reply.ok(),
        Err(e) => reply.error(err(e)),
    }
}

impl Filesystem for LinuxFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.child(parent, name) {
            Ok(p) => self.entry(&p, reply),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let r = self
            .path_of(ino)
            .and_then(|p| self.fs.getattr(&p).map_err(err));
        match r {
            Ok(a) => reply.attr(&TTL, &self.file_attr(ino.0, &a)),
            Err(e) => reply.error(e),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let path = match self.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let r = (|| {
            if let Some(size) = size {
                self.fs.truncate(&path, size, fh.map(|f| f.0))?;
            }
            let mtime_ms = mtime.map(|t| {
                let t = match t {
                    TimeOrNow::SpecificTime(t) => t,
                    TimeOrNow::Now => std::time::SystemTime::now(),
                };
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0)
            });
            let exec = mode.map(|m| m & 0o100 != 0);
            if mtime_ms.is_some() || exec.is_some() {
                self.fs.set_meta(&path, mtime_ms, exec)?;
            }
            self.fs.getattr(&path)
        })();
        match r {
            Ok(a) => reply.attr(&TTL, &self.file_attr(ino.0, &a)),
            Err(e) => reply.error(err(e)),
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.child(parent, name) {
            Ok(p) => match self.fs.mkdir(&p) {
                Ok(()) => self.entry(&p, reply),
                Err(e) => reply.error(err(e)),
            },
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.child(parent, name) {
            Ok(p) => {
                let r = self.fs.unlink(&p);
                if r.is_ok() {
                    self.inodes().forget_path(&p);
                }
                empty(r, reply)
            }
            Err(e) => reply.error(e),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.child(parent, name) {
            Ok(p) => {
                let r = self.fs.rmdir(&p);
                if r.is_ok() {
                    self.inodes().forget_path(&p);
                }
                empty(r, reply)
            }
            Err(e) => reply.error(e),
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (from, to) = match (self.child(parent, name), self.child(newparent, newname)) {
            (Ok(f), Ok(t)) => (f, t),
            (Err(e), _) | (_, Err(e)) => return reply.error(e),
        };
        if flags.contains(RenameFlags::RENAME_EXCHANGE) {
            return reply.error(Errno::EINVAL);
        }
        if flags.contains(RenameFlags::RENAME_NOREPLACE) && self.fs.getattr(&to).is_ok() {
            return reply.error(Errno::EEXIST);
        }
        let r = self.fs.rename(&from, &to);
        if r.is_ok() {
            self.inodes().rename(&from, &to);
        }
        empty(r, reply)
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let bits = flags.0;
        let r = self.path_of(ino).and_then(|p| {
            let write = bits & libc::O_ACCMODE != libc::O_RDONLY;
            self.fs
                .open(&p, write, bits & libc::O_TRUNC != 0)
                .map_err(err)
        });
        match r {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(e),
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let r = self.child(parent, name).and_then(|p| {
            let fh = self.fs.create(&p, mode & 0o111 != 0).map_err(err)?;
            let a = self.fs.getattr(&p).map_err(err)?;
            Ok((self.inodes().ino(&p), a, fh))
        });
        match r {
            Ok((ino, a, fh)) => reply.created(
                &TTL,
                &self.file_attr(ino, &a),
                Generation(0),
                FileHandle(fh),
                FopenFlags::empty(),
            ),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.fs.read(fh.0, offset, size as usize) {
            Ok(d) => reply.data(&d),
            Err(e) => reply.error(err(e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.fs.write(fh.0, offset, data) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(err(e)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        empty(self.fs.flush(fh.0), reply)
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        empty(self.fs.release(fh.0), reply)
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        empty(self.fs.flush(fh.0), reply)
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.path_of(ino) {
            Ok(p) => p,
            Err(e) => return reply.error(e),
        };
        let entries = match self.fs.readdir(&path) {
            Ok(e) => e,
            Err(e) => return reply.error(err(e)),
        };
        let parent = Path::new(&path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("/")
            .to_string();
        let mut all: Vec<(u64, FileType, String)> = vec![
            (ino.0, FileType::Directory, ".".into()),
            (self.inodes().ino(&parent), FileType::Directory, "..".into()),
        ];
        for (name, kind) in entries {
            let Some(child) = join(&path, OsStr::new(&name)) else {
                continue;
            };
            let kind = if kind == EntryKind::Dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            all.push((self.inodes().ino(&child), kind, name));
        }
        for (i, (ino, kind, name)) in all.into_iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(ino), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match crate::drive_space(self.fs.drive()) {
            Some(s) => reply.statfs(
                s.blocks,
                s.bfree,
                s.bavail,
                0,
                0,
                s.bsize as u32,
                255,
                s.bsize as u32,
            ),
            None => reply.error(Errno::EIO),
        }
    }
}

pub fn available() -> Result<(), String> {
    if Path::new("/dev/fuse").exists() {
        Ok(())
    } else {
        Err("FUSE is not available (/dev/fuse is missing; install fuse3)".into())
    }
}

pub struct Session {
    bg: Arc<Mutex<Option<BackgroundSession>>>,
    finished: Arc<std::sync::atomic::AtomicBool>,
}

impl Session {
    pub fn start(
        fs: Arc<VaultFs>,
        mountpoint: &Path,
        label: &str,
        read_only: bool,
    ) -> std::io::Result<Session> {
        let md = std::fs::metadata(mountpoint)?;
        let lfs = LinuxFs {
            fs,
            inodes: Mutex::new(Inodes {
                by_ino: HashMap::from([(1, "/".to_string())]),
                by_path: HashMap::from([("/".to_string(), 1)]),
                next: 2,
            }),
            uid: md.uid(),
            gid: md.gid(),
        };
        let mut config = Config::default();
        config.mount_options = vec![
            MountOption::FSName(format!("tijori:{label}")),
            MountOption::Subtype("tijori".into()),
            MountOption::DefaultPermissions,
            MountOption::NoDev,
            MountOption::NoSuid,
            MountOption::NoAtime,
            if read_only {
                MountOption::RO
            } else {
                MountOption::RW
            },
        ];
        let bg = fuser::spawn_mount(lfs, mountpoint, &config)?;
        Ok(Session {
            bg: Arc::new(Mutex::new(Some(bg))),
            finished: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    pub fn is_finished(&self) -> bool {
        if self.finished.load(std::sync::atomic::Ordering::Relaxed) {
            return true;
        }
        let guard = self.bg.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref().is_none_or(|b| b.guard.is_finished())
    }

    pub fn stop(self) {
        let bg = self.bg.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(bg) = bg {
            if bg.guard.is_finished() {
                let _ = bg.join();
            } else {
                let _ = bg.umount_and_join();
            }
        }
        self.finished
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}
