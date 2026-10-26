//! Unlocking a vault for one command or one shell session.

use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use tijori_core::host::Host;
use tijori_core::rollback::RollbackStatus;
use tijori_core::storage::StdFsStorage;
use tijori_core::vault::{ArgonChoice, LockInfo, ReadOnlyReason, UnlockOptions, UnlockReport};
use tijori_core::{Keyfile, OpenMode, UnlockSecret, Vault};

use crate::GlobalArgs;
use crate::drive;
use crate::error::{CliError, Result};
use crate::prompt::Input;

pub struct Session {
    pub vault: Vault,
    pub drive: PathBuf,
    pub report: UnlockReport,
}

pub fn host() -> Result<Host> {
    let host = Host::init()?;
    for w in &host.warnings {
        eprintln!("Warning: {w}");
    }
    Ok(host)
}

/// Argon2id choice for new password slots. `TIJORI_TEST_FAST_KDF=1` selects
/// the weakest allowed parameters, for automated tests only.
pub fn argon_choice() -> ArgonChoice {
    if std::env::var_os("TIJORI_TEST_FAST_KDF").is_some() {
        eprintln!("WARNING: TIJORI_TEST_FAST_KDF is set: using test-only weak key derivation.");
        ArgonChoice::minimum()
    } else {
        ArgonChoice::desktop()
    }
}

pub fn open_keyfile(path: &std::path::Path) -> Result<Keyfile> {
    let f = File::open(path)
        .map_err(|e| CliError::other(format!("cannot read keyfile {}: {e}", path.display())))?;
    Ok(Keyfile::from_reader(f)?)
}

fn read_secret(global: &GlobalArgs, input: &mut Input) -> Result<UnlockSecret> {
    if global.with_recovery {
        return Ok(UnlockSecret::Recovery(input.recovery_phrase()?));
    }
    let password = input.password()?;
    let keyfile = global
        .with_keyfile
        .as_deref()
        .map(open_keyfile)
        .transpose()?;
    Ok(UnlockSecret::Password { password, keyfile })
}

pub fn describe_lock(info: &Option<LockInfo>, writer_id: &[u8; 16]) -> String {
    let Some(info) = info else {
        return "the vault is in use by another Tijori (its lock file is unreadable). If nothing else is using \
                this drive, run `tijori break-lock`."
            .into();
    };
    let who = if info.is_from_writer(writer_id) {
        "another Tijori on this computer"
    } else {
        "Tijori on another device"
    };
    let mins = info.age_secs() / 60;
    format!(
        "the vault is in use by {who} (lock refreshed {mins} minute{} ago). If nothing else is using this drive, \
         run `tijori break-lock`.",
        if mins == 1 { "" } else { "s" }
    )
}

pub fn open(global: &GlobalArgs, input: &mut Input, mode: OpenMode) -> Result<Session> {
    let drive = drive::resolve(global.vault.as_deref())?;
    let host = host()?;
    let secret = read_secret(global, input)?;
    let opts = UnlockOptions {
        mode,
        writer_id: host.writer_id,
        rollback: Some(host.rollback),
    };
    let (mut vault, report) = Vault::unlock(Arc::new(StdFsStorage::new(&drive)), &secret, opts)?;
    drop(secret);
    if report.used_backup_header {
        eprintln!("Note: the main header could not be used; the backup copy opened the vault.");
    }
    if report.other_root_slot_invalid {
        eprintln!(
            "Note: one of the two root pointers is unreadable (often an interrupted write); opened revision {}.",
            report.rev
        );
    }
    for w in vault.take_warnings() {
        eprintln!("Warning: {w}");
    }
    match &report.read_only {
        Some(ReadOnlyReason::LockedBy(info)) if mode == OpenMode::ReadWrite => {
            return Err(CliError::Locked(describe_lock(info, &vault.writer_id())));
        }
        Some(ReadOnlyReason::Rollback { seen_rev } | ReadOnlyReason::Fork { seen_rev }) => {
            let kind = if matches!(report.rollback, RollbackStatus::Fork { .. }) {
                format!(
                    "this drive's revision {} differs from the revision {seen_rev} this computer saw",
                    report.rev
                )
            } else {
                format!(
                    "this drive is at revision {}, older than revision {seen_rev} this computer has seen",
                    report.rev
                )
            };
            eprintln!("Warning: {kind}. Someone may have restored an old copy of the drive.");
            if input.is_interactive() {
                let answer = input.line(
                    "Continue [r]ead-only, [a]ccept this state as current, or [c]ancel? [r/a/c] ",
                )?;
                match answer.trim() {
                    "a" | "A" => vault.accept_current_state()?,
                    "c" | "C" => return Err(CliError::other("cancelled")),
                    _ => eprintln!("Continuing read-only."),
                }
            } else {
                eprintln!("Continuing read-only. Run interactively to accept this state.");
            }
        }
        _ => {}
    }
    Ok(Session {
        vault,
        drive,
        report,
    })
}
