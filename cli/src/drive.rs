//! Finding the drive that holds a vault.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{CliError, Result};

const VAULT_DIR: &str = "TIJORI";

fn has_vault(drive: &Path) -> bool {
    drive.join(VAULT_DIR).join("vault.header").is_file()
        || drive.join(VAULT_DIR).join("vault.header.bak").is_file()
}

/// Folders where removable drives are mounted on this system.
pub fn mount_roots() -> Vec<PathBuf> {
    let mut parents: Vec<PathBuf> = Vec::new();
    if cfg!(target_os = "macos") {
        parents.push("/Volumes".into());
    } else {
        if let Some(user) = std::env::var_os("USER") {
            parents.push(Path::new("/media").join(&user));
            parents.push(Path::new("/run/media").join(&user));
        }
        parents.push("/media".into());
        parents.push("/mnt".into());
    }
    let mut out = Vec::new();
    for p in parents {
        let Ok(rd) = fs::read_dir(&p) else { continue };
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() && !out.contains(&path) {
                out.push(path);
            }
        }
    }
    out
}

/// Mounted drives that hold a vault.
pub fn find_vaults() -> Vec<PathBuf> {
    mount_roots().into_iter().filter(|d| has_vault(d)).collect()
}

/// The drive root for `--vault` (a drive or its TIJORI folder), or the only
/// mounted vault.
pub fn resolve(arg: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = arg {
        if p.file_name().is_some_and(|n| n == VAULT_DIR)
            && let Some(parent) = p.parent()
            && has_vault(parent)
        {
            return Ok(parent.to_path_buf());
        }
        if has_vault(p) {
            return Ok(p.to_path_buf());
        }
        return Err(CliError::other(format!(
            "no Tijori vault at {}",
            p.display()
        )));
    }
    let found = find_vaults();
    match found.len() {
        0 => Err(CliError::other(
            "no mounted drive holds a Tijori vault; name one with --vault",
        )),
        1 => Ok(found.into_iter().next().expect("one")),
        _ => {
            let list: Vec<String> = found.iter().map(|p| format!("  {}", p.display())).collect();
            Err(CliError::other(format!(
                "several drives hold a Tijori vault; pick one with --vault:\n{}",
                list.join("\n")
            )))
        }
    }
}
