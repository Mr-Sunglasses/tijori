//! Mounts an unlocked Tijori vault as a folder, for the current user only,
//! with host hardening (Plan Milestone 4).
//!
//! - Linux: `fuser` (pure-Rust mount through `fusermount3`), mounted under
//!   `$XDG_RUNTIME_DIR/tijori/<label>`, which desktop indexers do not crawl.
//! - macOS: macFUSE 5 with its FSKit backend (no kernel extension), mounted
//!   under `/Volumes/<label>`, with `.metadata_never_index`, Spotlight off,
//!   a Time Machine exclusion, and the Quick Look cache cleared at unmount.
//!
//! Writes are buffered in memory, never on the host disk. The vault is
//! committed at most every 2 s while files change, and locked at unmount.
//! A supervisor unmounts on request, on idle timeout, when the drive goes
//! away, or when the user ejects the volume.

pub mod fs;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "macos", tijori_macfuse))]
mod macos;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tijori_core::{Error, Vault};

#[cfg(target_os = "linux")]
use linux::Session;
#[cfg(all(target_os = "macos", tijori_macfuse))]
use macos::Session;

pub use fs::VaultFs;

/// Default idle timeout (Plan Milestone 4).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub bsize: u64,
}

/// Free space on the drive, shown as the mounted volume's free space.
#[cfg(target_os = "macos")]
pub fn drive_space(drive: &Path) -> Option<Space> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(drive.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `c` is a valid C string and `st` points to writable memory of
    // the right type for `statfs` to fill.
    if unsafe { libc::statfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statfs` returned 0, so it initialised `st`.
    let st = unsafe { st.assume_init() };
    Some(Space {
        blocks: st.f_blocks,
        bfree: st.f_bfree,
        bavail: st.f_bavail,
        bsize: u64::from(st.f_bsize),
    })
}

/// Free space on the drive, shown as the mounted volume's free space.
#[cfg(not(target_os = "macos"))]
pub fn drive_space(drive: &Path) -> Option<Space> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(drive.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: `c` is a valid C string and `st` points to writable memory of
    // the right type for `statvfs` to fill.
    if unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `statvfs` returned 0, so it initialised `st`.
    let st = unsafe { st.assume_init() };
    // The field types differ between architectures (u32 on some 32-bit ones).
    #[allow(clippy::unnecessary_cast)]
    Some(Space {
        blocks: st.f_blocks as u64,
        bfree: st.f_bfree as u64,
        bavail: st.f_bavail as u64,
        bsize: st.f_frsize as u64,
    })
}

/// Whether mounting can work on this machine, with the reason if not.
pub fn available() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return linux::available();
    #[cfg(all(target_os = "macos", tijori_macfuse))]
    return macos::available();
    #[allow(unreachable_code)]
    Err("this build of Tijori cannot mount vaults on this system; use private mode".into())
}

fn safe_label(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| {
            if c == '/' || c == '\0' || c == ':' {
                '-'
            } else {
                c
            }
        })
        .collect();
    let s = s.trim().trim_start_matches('.').to_string();
    if s.is_empty() { "Tijori".into() } else { s }
}

/// Where a vault with this label is mounted by default.
pub fn default_mountpoint(label: &str) -> Result<PathBuf, Error> {
    let name = safe_label(label);
    if cfg!(target_os = "macos") {
        // FSKit mounts must live in /Volumes; macFUSE creates the folder.
        let mut candidate = PathBuf::from("/Volumes").join(&name);
        let mut n = 2;
        while candidate.exists() {
            candidate = PathBuf::from("/Volumes").join(format!("{name} {n}"));
            n += 1;
        }
        Ok(candidate)
    } else {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| {
                Error::invalid("XDG_RUNTIME_DIR is not set; choose a mount point explicitly")
            })?;
        Ok(runtime.join("tijori").join(name))
    }
}

#[derive(Debug, Clone)]
pub struct MountOptions {
    /// `None` picks [`default_mountpoint`].
    pub mountpoint: Option<PathBuf>,
    /// Unmount after this long without file system activity. `None` disables it.
    pub idle_timeout: Option<Duration>,
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            mountpoint: None,
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmountReason {
    Requested,
    /// The user ejected or unmounted the volume.
    External,
    DriveRemoved,
    IdleTimeout,
}

/// Asks a mount to unmount and lock; usable from signal handlers and other
/// threads (sleep, screen lock and logout notifications in the desktop app).
#[derive(Clone)]
pub struct Stopper(Arc<AtomicBool>);

impl Stopper {
    pub fn request_unmount(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

pub struct Mount {
    mountpoint: PathBuf,
    stop: Arc<AtomicBool>,
    supervisor: JoinHandle<(UnmountReason, Result<(), Error>)>,
    warnings: Vec<String>,
    read_only: bool,
}

impl Mount {
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Hardening steps that could not be applied.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn stopper(&self) -> Stopper {
        Stopper(self.stop.clone())
    }

    pub fn is_finished(&self) -> bool {
        self.supervisor.is_finished()
    }

    /// Waits until the mount ends. The vault is locked when this returns.
    pub fn wait(self) -> Result<UnmountReason, Error> {
        let (reason, result) = self
            .supervisor
            .join()
            .map_err(|_| Error::Other("the mount supervisor crashed".into()))?;
        result.map(|()| reason)
    }

    pub fn unmount(self) -> Result<UnmountReason, Error> {
        self.stop.store(true, Ordering::SeqCst);
        self.wait()
    }
}

fn run(cmd: &str, args: &[&OsStrRef]) -> Result<(), String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

type OsStrRef = std::ffi::OsStr;

fn output(cmd: &str, args: &[&OsStrRef]) -> String {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_default()
}

/// Keeps Spotlight and Time Machine away from the mounted vault. The tools'
/// exit codes are unreliable here (`mdutil` fails while succeeding; `tmutil`
/// rejects volumes it would never back up), so the resulting state is checked.
fn harden(mountpoint: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    if cfg!(target_os = "macos") {
        let mp = mountpoint.as_os_str();
        let _ = run(
            "/usr/bin/mdutil",
            &[OsStrRef::new("-i"), OsStrRef::new("off"), mp],
        );
        if !output("/usr/bin/mdutil", &[OsStrRef::new("-s"), mp]).contains("disabled") {
            warnings
                .push("Spotlight indexing could not be turned off for the mounted vault".into());
        }
        if run("/usr/bin/tmutil", &[OsStrRef::new("addexclusion"), mp]).is_err()
            && !output("/usr/bin/tmutil", &[OsStrRef::new("isexcluded"), mp]).contains("[Excluded]")
        {
            warnings.push("the mounted vault could not be excluded from Time Machine".into());
        }
    } else if let Some(home) = std::env::var_os("HOME")
        && mountpoint.starts_with(home)
    {
        warnings.push(
            "the mount point is inside your home folder, where desktop search may index it".into(),
        );
    }
    warnings
}

fn after_unmount(mountpoint: &Path, created_dir: bool) {
    if cfg!(target_os = "macos") {
        // Drop thumbnails and previews Quick Look made of vault files.
        let _ = run(
            "/usr/bin/qlmanage",
            &[OsStrRef::new("-r"), OsStrRef::new("cache")],
        );
    }
    if created_dir {
        let _ = std::fs::remove_dir(mountpoint);
    }
}

/// Prepares a Linux mount point: an empty folder only the user can enter.
#[cfg(not(target_os = "macos"))]
fn prepare_mountpoint(mp: &Path) -> Result<bool, Error> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let created = !mp.exists();
    if created {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(mp)
            .map_err(|e| Error::from_io(e, "creating the mount point"))?;
    } else {
        let empty = std::fs::read_dir(mp)
            .map_err(|e| Error::from_io(e, "reading the mount point"))?
            .next()
            .is_none();
        if !empty {
            return Err(Error::invalid(format!("{} is not empty", mp.display())));
        }
    }
    std::fs::set_permissions(mp, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::from_io(e, "securing the mount point"))?;
    Ok(created)
}

#[cfg(target_os = "macos")]
fn prepare_mountpoint(mp: &Path) -> Result<bool, Error> {
    if mp.exists()
        && std::fs::read_dir(mp)
            .map(|mut d| d.next().is_some())
            .unwrap_or(true)
    {
        return Err(Error::invalid(format!("{} is in use", mp.display())));
    }
    Ok(false)
}

/// Mounts `vault` (which lives on `drive`) and starts the supervisor.
pub fn mount(vault: Vault, drive: &Path, opts: MountOptions) -> Result<Mount, Error> {
    available().map_err(Error::Other)?;
    if vault.settings().private_only {
        return Err(Error::invalid(
            "this vault is set to private mode only, so it cannot be mounted; open it in the app instead",
        ));
    }
    let label = vault.settings().label.clone();
    let mountpoint = match opts.mountpoint {
        Some(m) => m,
        None => default_mountpoint(&label)?,
    };
    let created_dir = prepare_mountpoint(&mountpoint)?;
    let read_only = !vault.is_writable();
    let synthetic = if cfg!(target_os = "macos") {
        vec![".metadata_never_index".to_string()]
    } else {
        Vec::new()
    };
    let fs = Arc::new(VaultFs::new(vault, drive.to_path_buf(), synthetic));
    start(
        fs,
        drive.to_path_buf(),
        mountpoint,
        created_dir,
        read_only,
        &label,
        opts.idle_timeout,
    )
}

/// A mount point is live once it is on a different device than its parent.
fn is_mounted(mp: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(mp), mp.parent().map(std::fs::metadata)) {
        (Ok(m), Some(Ok(p))) => m.dev() != p.dev(),
        _ => false,
    }
}

#[cfg(any(target_os = "linux", all(target_os = "macos", tijori_macfuse)))]
fn wait_until_mounted(mp: &Path, failed: impl Fn() -> bool) -> Result<(), Error> {
    let hint = if cfg!(target_os = "macos") {
        " If macOS said the file system extension is not enabled, turn on macFUSE in System Settings → \
         General → Login Items & Extensions → File System Extensions, then try again."
    } else {
        ""
    };
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(20) {
        if is_mounted(mp) {
            return Ok(());
        }
        if failed() {
            return Err(Error::Other(format!("the mount did not start.{hint}")));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(Error::Other(format!(
        "the mount did not appear within 20 seconds.{hint}"
    )))
}

#[cfg(any(target_os = "linux", all(target_os = "macos", tijori_macfuse)))]
fn start(
    fs: Arc<VaultFs>,
    drive: PathBuf,
    mountpoint: PathBuf,
    created_dir: bool,
    read_only: bool,
    label: &str,
    idle_timeout: Option<Duration>,
) -> Result<Mount, Error> {
    let session = match Session::start(fs.clone(), &mountpoint, &safe_label(label), read_only) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs.shutdown();
            after_unmount(&mountpoint, created_dir);
            return Err(Error::Other(format!("could not mount: {e}")));
        }
    };
    // Some backends report the mount as started before it actually exists.
    if let Err(e) = wait_until_mounted(&mountpoint, || session.is_finished()) {
        session.stop();
        let _ = fs.shutdown();
        after_unmount(&mountpoint, created_dir);
        return Err(e);
    }
    let warnings = harden(&mountpoint);
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let mp = mountpoint.clone();
    let supervisor = std::thread::spawn(move || {
        let reason = loop {
            std::thread::sleep(Duration::from_millis(250));
            if stop2.load(Ordering::SeqCst) {
                break UnmountReason::Requested;
            }
            if session.is_finished() {
                break UnmountReason::External;
            }
            if !drive.join("TIJORI").is_dir() {
                break UnmountReason::DriveRemoved;
            }
            let idle = fs.tick();
            if idle_timeout.is_some_and(|t| idle >= t) {
                break UnmountReason::IdleTimeout;
            }
        };
        session.stop();
        let result = fs.shutdown();
        after_unmount(&mp, created_dir);
        // With the drive gone nothing more can be written; the keys are wiped either way.
        let result = if reason == UnmountReason::DriveRemoved {
            Ok(())
        } else {
            result
        };
        (reason, result)
    });
    Ok(Mount {
        mountpoint,
        stop,
        supervisor,
        warnings,
        read_only,
    })
}

#[cfg(not(any(target_os = "linux", all(target_os = "macos", tijori_macfuse))))]
fn start(
    fs: Arc<VaultFs>,
    _drive: PathBuf,
    _mountpoint: PathBuf,
    _created_dir: bool,
    _read_only: bool,
    _label: &str,
    _idle_timeout: Option<Duration>,
) -> Result<Mount, Error> {
    let _ = fs.shutdown();
    Err(Error::Other(available().err().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_become_safe_folder_names() {
        assert_eq!(safe_label(""), "Tijori");
        assert_eq!(safe_label("a/b:c"), "a-b-c");
        assert_eq!(safe_label("..hidden"), "hidden");
        assert_eq!(safe_label("Family Photos"), "Family Photos");
    }

    #[test]
    fn drive_space_reads_the_host() {
        let s = drive_space(Path::new("/")).unwrap();
        assert!(s.blocks > 0 && s.bsize > 0);
    }
}
