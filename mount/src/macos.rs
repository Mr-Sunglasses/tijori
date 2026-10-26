//! macOS backend: macFUSE 5 (FSKit backend) through libfuse 3's high-level
//! API. The C side is `macos_shim.c`; these are the callbacks it calls.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use tijori_core::EntryKind;

use crate::fs::{FsResult, VaultFs};

#[repr(C)]
pub struct TjAttr {
    kind: u32,
    perm: u32,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
}

#[repr(C)]
pub struct TjStatfs {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    bsize: u64,
}

type AddFn = unsafe extern "C" fn(ctx: *mut c_void, name: *const c_char, kind: u32) -> c_int;

unsafe extern "C" {
    fn tj_fuse_available() -> c_int;
    fn tj_mount(
        mountpoint: *const c_char,
        options: *const c_char,
        fs: *const c_void,
    ) -> *mut c_void;
    fn tj_loop(f: *mut c_void) -> c_int;
    fn tj_exit(f: *mut c_void);
    fn tj_unmount_destroy(f: *mut c_void);
}

/// Runs `f` with the file system and a UTF-8 path, mapping panics to EIO.
/// `fs` and `path` come from the shim, which passes the pointer given to
/// `tj_mount` (kept alive by `Session`) and a NUL-terminated path from libfuse.
fn with_path(
    fs: *const c_void,
    path: *const c_char,
    f: impl FnOnce(&VaultFs, &str) -> FsResult<()>,
) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `fs` is the `Arc<VaultFs>` pointer given to `tj_mount`; the
        // session holds that Arc until the FUSE loop has stopped.
        let fs = unsafe { &*(fs as *const VaultFs) };
        // SAFETY: libfuse passes a valid NUL-terminated path for the call's duration.
        let path = unsafe { CStr::from_ptr(path) }
            .to_str()
            .map_err(|_| libc::EINVAL)?;
        f(fs, path)
    }));
    match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => e,
        Err(_) => libc::EIO,
    }
}

fn with_fs<T>(fs: *const c_void, fail: T, f: impl FnOnce(&VaultFs) -> T) -> T {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: as in `with_path`.
        let fs = unsafe { &*(fs as *const VaultFs) };
        f(fs)
    }))
    .unwrap_or(fail)
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_getattr(fs: *const c_void, path: *const c_char, out: *mut TjAttr) -> c_int {
    with_path(fs, path, |fs, p| {
        let a = fs.getattr(p)?;
        let d = a
            .mtime()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        // SAFETY: `out` points to a `struct tj_attr` on the shim's stack.
        unsafe {
            *out = TjAttr {
                kind: if a.kind == EntryKind::Dir { 2 } else { 1 },
                perm: u32::from(a.perm()),
                size: a.size,
                mtime_sec: d.as_secs() as i64,
                mtime_nsec: i64::from(d.subsec_nanos()),
            };
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_readdir(
    fs: *const c_void,
    path: *const c_char,
    ctx: *mut c_void,
    add: AddFn,
) -> c_int {
    with_path(fs, path, |fs, p| {
        for (name, kind) in fs.readdir(p)? {
            let Ok(c) = CString::new(name) else { continue };
            let k = if kind == EntryKind::Dir { 2 } else { 1 };
            // SAFETY: `add` and `ctx` come from the shim's readdir and are
            // valid until this callback returns.
            if unsafe { add(ctx, c.as_ptr(), k) } != 0 {
                break;
            }
        }
        Ok(())
    })
}

fn set_fh(out: *mut u64, fh: u64) {
    // SAFETY: `out` points to a `uint64_t` on the shim's stack.
    unsafe { *out = fh };
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_open(
    fs: *const c_void,
    path: *const c_char,
    flags: c_int,
    out: *mut u64,
) -> c_int {
    with_path(fs, path, |fs, p| {
        let write = flags & libc::O_ACCMODE != libc::O_RDONLY;
        let fh = fs.open(p, write, flags & libc::O_TRUNC != 0)?;
        set_fh(out, fh);
        Ok(())
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_create(
    fs: *const c_void,
    path: *const c_char,
    mode: u32,
    out: *mut u64,
) -> c_int {
    with_path(fs, path, |fs, p| {
        let fh = fs.create(p, mode & 0o111 != 0)?;
        set_fh(out, fh);
        Ok(())
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_read(
    fs: *const c_void,
    fh: u64,
    buf: *mut c_char,
    size: usize,
    off: i64,
) -> c_long {
    with_fs(fs, -(libc::EIO as c_long), |fs| {
        match fs.read(fh, off.max(0) as u64, size) {
            Ok(data) => {
                // SAFETY: libfuse's buffer holds `size` bytes and `data.len() <= size`.
                unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, data.len()) };
                data.len() as c_long
            }
            Err(e) => -(e as c_long),
        }
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_write(
    fs: *const c_void,
    fh: u64,
    buf: *const c_char,
    size: usize,
    off: i64,
) -> c_long {
    with_fs(fs, -(libc::EIO as c_long), |fs| {
        // SAFETY: libfuse passes `size` readable bytes at `buf`.
        let data = unsafe { std::slice::from_raw_parts(buf as *const u8, size) };
        match fs.write(fh, off.max(0) as u64, data) {
            Ok(n) => n as c_long,
            Err(e) => -(e as c_long),
        }
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_truncate(
    fs: *const c_void,
    path: *const c_char,
    size: i64,
    has_fh: c_int,
    fh: u64,
) -> c_int {
    with_path(fs, path, |fs, p| {
        fs.truncate(p, size.max(0) as u64, (has_fh != 0).then_some(fh))
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_flush(fs: *const c_void, fh: u64) -> c_int {
    with_fs(fs, libc::EIO, |fs| fs.flush(fh).err().unwrap_or(0))
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_release(fs: *const c_void, fh: u64) -> c_int {
    with_fs(fs, libc::EIO, |fs| fs.release(fh).err().unwrap_or(0))
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_mkdir(fs: *const c_void, path: *const c_char) -> c_int {
    with_path(fs, path, |fs, p| fs.mkdir(p))
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_unlink(fs: *const c_void, path: *const c_char) -> c_int {
    with_path(fs, path, |fs, p| fs.unlink(p))
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_rmdir(fs: *const c_void, path: *const c_char) -> c_int {
    with_path(fs, path, |fs, p| fs.rmdir(p))
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_rename(
    fs: *const c_void,
    from: *const c_char,
    to: *const c_char,
    exclusive: c_int,
) -> c_int {
    with_path(fs, from, |fs, from| {
        // SAFETY: libfuse passes a valid NUL-terminated path.
        let to = unsafe { CStr::from_ptr(to) }
            .to_str()
            .map_err(|_| libc::EINVAL)?;
        if exclusive != 0 && fs.getattr(to).is_ok() {
            return Err(libc::EEXIST);
        }
        fs.rename(from, to)
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_utimens(fs: *const c_void, path: *const c_char, sec: i64, nsec: i64) -> c_int {
    with_path(fs, path, |fs, p| {
        fs.set_meta(p, Some(sec * 1000 + nsec / 1_000_000), None)
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_chmod(fs: *const c_void, path: *const c_char, mode: u32) -> c_int {
    with_path(fs, path, |fs, p| {
        fs.set_meta(p, None, Some(mode & 0o100 != 0))
    })
}

#[unsafe(no_mangle)]
extern "C" fn tj_rs_statfs(fs: *const c_void, out: *mut TjStatfs) -> c_int {
    with_fs(fs, libc::EIO, |fs| match crate::drive_space(fs.drive()) {
        Some(s) => {
            // SAFETY: `out` points to a `struct tj_statfs` on the shim's stack.
            unsafe {
                *out = TjStatfs {
                    blocks: s.blocks,
                    bfree: s.bfree,
                    bavail: s.bavail,
                    bsize: s.bsize,
                }
            };
            0
        }
        None => libc::EIO,
    })
}

pub fn available() -> Result<(), String> {
    // SAFETY: a plain query of whether the weak-linked library was loaded.
    if unsafe { tj_fuse_available() } != 0 {
        Ok(())
    } else {
        Err("macFUSE 5 or newer is not installed (https://macfuse.github.io)".into())
    }
}

/// The libfuse handle, moved to the loop thread.
struct FuseHandle(*mut c_void);
// SAFETY: libfuse's `struct fuse` may be used from another thread; the loop
// thread is the only user until `tj_unmount_destroy`, and `tj_exit` only
// sets a flag.
unsafe impl Send for FuseHandle {}

pub struct Session {
    fuse: *mut c_void,
    thread: Option<JoinHandle<()>>,
    mountpoint: std::path::PathBuf,
    _fs: Arc<VaultFs>,
}

// SAFETY: see `FuseHandle`; `Session` only calls `tj_exit` on the pointer.
unsafe impl Send for Session {}

impl Session {
    pub fn start(
        fs: Arc<VaultFs>,
        mountpoint: &Path,
        label: &str,
        read_only: bool,
    ) -> std::io::Result<Session> {
        available().map_err(std::io::Error::other)?;
        let volname: String = label.chars().filter(|c| *c != ',' && *c != '=').collect();
        let mut opts = format!(
            "backend=fskit,fsname=tijori,volname={},noappledouble,noapplexattr,default_permissions",
            if volname.is_empty() {
                "Tijori"
            } else {
                &volname
            }
        );
        if read_only {
            opts.push_str(",ro");
        }
        let mp = CString::new(mountpoint.as_os_str().to_string_lossy().as_bytes())
            .map_err(std::io::Error::other)?;
        let opts = CString::new(opts).map_err(std::io::Error::other)?;
        let ptr = Arc::as_ptr(&fs) as *const c_void;
        // SAFETY: valid C strings; `ptr` stays alive in `Session::_fs`.
        let fuse = unsafe { tj_mount(mp.as_ptr(), opts.as_ptr(), ptr) };
        if fuse.is_null() {
            return Err(std::io::Error::other(
                "macFUSE could not mount the vault (is its file system extension enabled in System Settings?)",
            ));
        }
        let handle = FuseHandle(fuse);
        let thread = std::thread::spawn(move || {
            let h = handle;
            // SAFETY: `h.0` is the live handle from `tj_mount`; only this thread uses it.
            unsafe {
                tj_loop(h.0);
                tj_unmount_destroy(h.0);
            }
        });
        Ok(Session {
            fuse,
            thread: Some(thread),
            mountpoint: mountpoint.to_path_buf(),
            _fs: fs,
        })
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Unmounts, which ends the FUSE loop, then waits for the loop thread.
    ///
    /// The loop must keep serving while the volume unmounts: FSKit sends
    /// final requests, and a stopped loop would deadlock `umount`. So
    /// `fuse_exit` is only a last resort.
    pub fn stop(mut self) {
        let attempts: [(&str, &[&str]); 2] = [
            ("/sbin/umount", &[]),
            ("/usr/sbin/diskutil", &["unmount", "force"]),
        ];
        for (cmd, args) in attempts {
            if self.is_finished() {
                break;
            }
            run_with_timeout(cmd, args, &self.mountpoint, Duration::from_secs(10));
            self.wait_finished(Duration::from_secs(5));
        }
        if !self.is_finished() {
            // SAFETY: the handle is live until the loop thread finishes.
            unsafe { tj_exit(self.fuse) };
            self.wait_finished(Duration::from_secs(5));
        }
        // A loop that still has not ended would block forever; leave it to
        // process exit rather than hang the caller.
        if self.is_finished()
            && let Some(t) = self.thread.take()
        {
            let _ = t.join();
        }
    }

    fn wait_finished(&self, timeout: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.is_finished() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }
}

/// Runs an unmount command, killing it if it hangs.
fn run_with_timeout(cmd: &str, args: &[&str], mountpoint: &Path, timeout: Duration) {
    let Ok(mut child) = std::process::Command::new(cmd)
        .args(args)
        .arg(mountpoint)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return;
    };
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}
