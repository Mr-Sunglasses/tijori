//! `put` and `get`: copying files and folders in and out of a vault.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use indicatif::ProgressBar;
use tijori_core::{EntryKind, Error, FileMeta, Vault, VaultPath};

use crate::error::{CliError, Result};
use crate::output;

#[derive(Default)]
pub struct Totals {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped: u64,
}

fn mtime_ms(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn is_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_: &fs::Metadata) -> bool {
    false
}

/// Bytes in regular files under `path`, for the progress bar.
fn local_size(path: &Path) -> u64 {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() => m.len(),
        Ok(m) if m.is_dir() => fs::read_dir(path)
            .map(|rd| rd.flatten().map(|e| local_size(&e.path())).sum())
            .unwrap_or(0),
        _ => 0,
    }
}

/// Progress across many files: the bar shows bytes of the whole batch.
struct Batch {
    bar: ProgressBar,
    base: u64,
}

fn put_one(
    vault: &mut Vault,
    src: &Path,
    dest_dir: &VaultPath,
    t: &mut Totals,
    batch: &mut Batch,
) -> Result<()> {
    let Some(name) = src.file_name().and_then(|n| n.to_str()) else {
        eprintln!("Skipping {}: the name is not valid UTF-8.", src.display());
        t.skipped += 1;
        return Ok(());
    };
    let meta = fs::symlink_metadata(src)?;
    let dest = match dest_dir.join(name) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Skipping {}: {e}", src.display());
            t.skipped += 1;
            return Ok(());
        }
    };
    if meta.file_type().is_symlink() {
        eprintln!("Skipping {}: symbolic links are not stored.", src.display());
        t.skipped += 1;
    } else if meta.is_dir() {
        match vault.stat(&dest) {
            Ok(e) if e.kind == EntryKind::Dir => {}
            Ok(_) => return Err(Error::AlreadyExists(dest.to_string()).into()),
            Err(Error::NotFound(_)) => vault.mkdir(&dest)?,
            Err(e) => return Err(e.into()),
        }
        t.dirs += 1;
        let mut children: Vec<PathBuf> = fs::read_dir(src)?.flatten().map(|e| e.path()).collect();
        children.sort();
        for child in children {
            put_one(vault, &child, &dest, t, batch)?;
        }
    } else if meta.is_file() {
        let mut f = File::open(src)?;
        let len = meta.len();
        let file_meta = FileMeta {
            mtime_ms: mtime_ms(&meta),
            executable: is_executable(&meta),
        };
        let (bar, base) = (batch.bar.clone(), batch.base);
        vault.import_with_progress(&mut f, &dest, len, file_meta, &mut |p| {
            bar.set_position(base + p.done);
            true
        })?;
        batch.base += len;
        t.files += 1;
        t.bytes += len;
    } else {
        eprintln!("Skipping {}: not a regular file or folder.", src.display());
        t.skipped += 1;
    }
    Ok(())
}

/// Adds local files and folders into `dest_dir` (created if missing) and commits.
pub fn put(vault: &mut Vault, sources: &[PathBuf], dest_dir: &VaultPath) -> Result<Totals> {
    vault.mkdir_all(dest_dir)?;
    let total: u64 = sources.iter().map(|s| local_size(s)).sum();
    let mut batch = Batch {
        bar: output::byte_bar(total, "Encrypting"),
        base: 0,
    };
    let mut t = Totals::default();
    for src in sources {
        if fs::symlink_metadata(src).is_err() {
            return Err(CliError::other(format!("{} does not exist", src.display())));
        }
        put_one(vault, src, dest_dir, &mut t, &mut batch)?;
    }
    batch.bar.finish_and_clear();
    vault.commit()?;
    Ok(t)
}

/// A name in `dir` that does not exist yet: `name`, then `name (1).ext`, ...
/// Never overwrites, and also avoids clashes on case-insensitive folders.
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if fs::symlink_metadata(&first).is_err() {
        return first;
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (1..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| fs::symlink_metadata(p).is_err())
        .expect("some name is free")
}

fn export_file(
    vault: &mut Vault,
    src: &VaultPath,
    target: &Path,
    mtime_ms: i64,
    exec: bool,
    bar: &ProgressBar,
) -> Result<u64> {
    let mut reader = vault.read_file(src)?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let tmp = target.with_file_name(format!(".{name}.tijori-partial"));
    let result = (|| -> Result<u64> {
        let mut out = File::create(&tmp)?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut n_total = 0u64;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| Error::from_io(e, "reading from the vault"))?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            n_total += n as u64;
            bar.inc(n as u64);
        }
        out.flush()?;
        let t = if mtime_ms >= 0 {
            UNIX_EPOCH + Duration::from_millis(mtime_ms as u64)
        } else {
            UNIX_EPOCH - Duration::from_millis(mtime_ms.unsigned_abs())
        };
        let _ = out.set_modified(t);
        #[cfg(unix)]
        if exec {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = out.metadata()?.permissions();
            perms.set_mode(perms.mode() | ((perms.mode() & 0o444) >> 2));
            out.set_permissions(perms)?;
        }
        #[cfg(not(unix))]
        let _ = exec;
        Ok(n_total)
    })();
    match result {
        Ok(n) => {
            fs::rename(&tmp, target)?;
            Ok(n)
        }
        Err(e) => {
            // Never leave partly decrypted data behind.
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn get_one(
    vault: &mut Vault,
    src: &VaultPath,
    local_dir: &Path,
    t: &mut Totals,
    bar: &ProgressBar,
) -> Result<()> {
    let entry = vault.stat(src)?;
    let name = if src.is_root() {
        "vault"
    } else {
        entry.name.as_str()
    };
    let target = free_name(local_dir, name);
    if target.file_name() != Some(std::ffi::OsStr::new(name)) {
        eprintln!(
            "{} already exists here; saving as {}.",
            name,
            target.file_name().unwrap_or_default().to_string_lossy()
        );
    }
    match entry.kind {
        EntryKind::File => {
            t.bytes += export_file(vault, src, &target, entry.mtime_ms, entry.executable, bar)?;
            t.files += 1;
        }
        EntryKind::Dir => {
            fs::create_dir(&target)?;
            t.dirs += 1;
            for child in vault.list(src)? {
                get_one(vault, &src.join(&child.name)?, &target, t, bar)?;
            }
        }
    }
    Ok(())
}

fn vault_size(vault: &mut Vault, path: &VaultPath) -> u64 {
    match vault.stat(path) {
        Ok(e) if e.kind == EntryKind::File => e.size,
        Ok(_) => vault
            .list(path)
            .map(|es| {
                es.iter()
                    .filter_map(|e| path.join(&e.name).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .map(|p| vault_size(vault, &p))
            .sum(),
        Err(_) => 0,
    }
}

/// Copies vault files and folders into `local_dir`. Existing local files are
/// never overwritten: clashing names get a visible ` (n)` suffix.
pub fn get(vault: &mut Vault, sources: &[VaultPath], local_dir: &Path) -> Result<Totals> {
    if !local_dir.is_dir() {
        return Err(CliError::other(format!(
            "{} is not a folder",
            local_dir.display()
        )));
    }
    let total: u64 = sources.iter().map(|s| vault_size(vault, s)).sum();
    let bar = output::byte_bar(total, "Decrypting");
    let mut t = Totals::default();
    for src in sources {
        get_one(vault, src, local_dir, &mut t, &bar)?;
    }
    bar.finish_and_clear();
    Ok(t)
}

/// Streams a vault file to standard output.
pub fn cat(vault: &mut Vault, path: &VaultPath) -> Result<()> {
    let mut reader = vault.read_file(path)?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error::from_io(e, "reading from the vault"))?;
        if n == 0 {
            break;
        }
        match out.write_all(&buf[..n]) {
            // The reader went away (e.g. `| head`): stop quietly.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => return Ok(()),
            r => r?,
        }
    }
    match out.flush() {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}
