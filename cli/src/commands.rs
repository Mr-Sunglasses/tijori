//! The commands.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use tijori_core::format::SlotKind;
use tijori_core::storage::StdFsStorage;
use tijori_core::vault::{
    CreateOptions, NewSlot, PASSWORD_CHANGE_NOTE, ReadOnlyReason, break_lock as core_break_lock,
    read_lock,
};
use tijori_core::{EntryKind, OpenMode, Vault, VaultPath};

use crate::error::{CliError, Result};
use crate::output::{self, print_recovery_phrase};
use crate::prompt::Input;
use crate::session::{self, Session, argon_choice, open_keyfile};
use crate::{GlobalArgs, KeyslotAction, VaultCommand, transfer};

const UNDERSTAND: &str = "I UNDERSTAND";

fn vp(s: &str) -> Result<VaultPath> {
    Ok(VaultPath::parse(s)?)
}

/// "2 files (4.9 KiB) and 1 folder", leaving out zero folders.
fn counts(files: u64, bytes: u64, dirs: u64) -> String {
    let mut s = format!(
        "{files} file{} ({})",
        if files == 1 { "" } else { "s" },
        output::size(bytes)
    );
    if dirs > 0 {
        s.push_str(&format!(
            " and {dirs} folder{}",
            if dirs == 1 { "" } else { "s" }
        ));
    }
    s
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

pub fn init(
    input: &mut Input,
    drive: &Path,
    padding: bool,
    label: Option<String>,
    keyfile: Option<PathBuf>,
) -> Result<()> {
    if !drive.is_dir() {
        return Err(CliError::other(format!(
            "{} is not a folder or mounted drive",
            drive.display()
        )));
    }
    if ["vault.header", "vault.header.bak"]
        .iter()
        .any(|f| drive.join("TIJORI").join(f).exists())
    {
        return Err(CliError::other(format!(
            "{} already has a Tijori vault",
            drive.display()
        )));
    }
    let host = session::host()?;
    let label = label.unwrap_or_default();
    eprintln!("Creating a Tijori vault on {}.", drive.display());
    let password = input.new_password(&[label.as_str(), "tijori"])?;
    let mut opts = CreateOptions::new(password);
    opts.keyfile = keyfile.as_deref().map(open_keyfile).transpose()?;
    opts.argon = argon_choice();
    opts.settings.padding = padding;
    opts.settings.label = label;
    opts.writer_id = host.writer_id;
    opts.rollback = Some(host.rollback);
    if std::env::var_os("TIJORI_TEST_FAST_KDF").is_none() {
        eprintln!("Tuning the key derivation to take about a second on this computer...");
    }
    let (vault, phrase) = Vault::create(Arc::new(StdFsStorage::new(drive)), opts)?;
    println!();
    print_recovery_phrase(&phrase.words());
    println!();
    drop(phrase);
    input.confirm_typed(&format!("Type {UNDERSTAND} to continue: "), UNDERSTAND)?;
    vault.lock()?;
    println!("Vault created on {}.", drive.display());
    Ok(())
}

impl VaultCommand {
    /// Whether the command needs the write lock.
    fn writes(&self) -> bool {
        match self {
            VaultCommand::Ls { .. }
            | VaultCommand::Get { .. }
            | VaultCommand::Cat { .. }
            | VaultCommand::Verify
            | VaultCommand::Info => false,
            VaultCommand::Keyslot {
                action: KeyslotAction::List,
            } => false,
            VaultCommand::Settings {
                padding,
                private_only,
                label,
            } => padding.is_some() || private_only.is_some() || label.is_some(),
            _ => true,
        }
    }
}

pub fn run_once(global: &GlobalArgs, input: &mut Input, cmd: VaultCommand) -> Result<()> {
    let mode = if cmd.writes() {
        OpenMode::ReadWrite
    } else {
        OpenMode::ReadOnly
    };
    let mut s = session::open(global, input, mode)?;
    let result = execute(&mut s, global, input, cmd);
    let locked = s.vault.lock();
    result?;
    Ok(locked?)
}

#[derive(Parser)]
#[command(multicall = true, disable_help_flag = true)]
struct ShellLine {
    #[command(subcommand)]
    cmd: ShellCommand,
}

#[derive(clap::Subcommand)]
enum ShellCommand {
    #[command(flatten)]
    Vault(VaultCommand),
    /// Lock the vault and leave the shell.
    #[command(alias = "quit")]
    Exit,
}

pub fn shell(global: &GlobalArgs, input: &mut Input) -> Result<()> {
    let mut s = match session::open(global, input, OpenMode::ReadWrite) {
        Ok(s) => s,
        Err(CliError::Locked(msg)) => {
            eprintln!("Opening read-only: {msg}");
            session::open(global, input, OpenMode::ReadOnly)?
        }
        Err(e) => return Err(e),
    };
    let interactive = io::stdin().is_terminal();
    eprintln!("Vault unlocked. Type `help` for commands, `exit` to lock.");
    let mut last_err = None;
    loop {
        if interactive {
            eprint!("tijori> ");
            io::stderr().flush()?;
        }
        let mut line = String::new();
        if io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let Some(words) = shlex::split(line.trim()) else {
            eprintln!("Unbalanced quotes.");
            continue;
        };
        if words.is_empty() {
            continue;
        }
        match ShellLine::try_parse_from(&words) {
            Err(e) => {
                let _ = e.print();
            }
            Ok(ShellLine {
                cmd: ShellCommand::Exit,
            }) => break,
            Ok(ShellLine {
                cmd: ShellCommand::Vault(cmd),
            }) => {
                if let Err(e) = execute(&mut s, global, input, cmd) {
                    eprintln!("tijori: {e}");
                    last_err = Some(e);
                }
            }
        }
    }
    s.vault.lock()?;
    eprintln!("Vault locked.");
    // In scripts, report the last failure through the exit code.
    match last_err {
        Some(e) if !interactive => Err(CliError::Reported(e.exit_code())),
        _ => Ok(()),
    }
}

pub fn break_lock(global: &GlobalArgs, input: &mut Input, force: bool) -> Result<()> {
    let drive = crate::drive::resolve(global.vault.as_deref())?;
    let storage = StdFsStorage::new(&drive);
    let Some(info) = read_lock(&storage)? else {
        println!("The vault is not locked.");
        return Ok(());
    };
    if !info.is_stale() && !force {
        return Err(CliError::Locked(format!(
            "the lock was refreshed {} minutes ago, so a Tijori may still be writing. If you are sure nothing else \
             is using this drive, run `tijori break-lock --force`.",
            info.age_secs() / 60
        )));
    }
    eprintln!(
        "Breaking the lock while another Tijori is writing can lose that writer's latest changes."
    );
    input.confirm_typed("Type BREAK to remove the lock: ", "BREAK")?;
    core_break_lock(&storage)?;
    println!("Lock removed.");
    Ok(())
}

fn print_entries(entries: &[tijori_core::Entry], long: bool) {
    for e in entries {
        let slash = if e.kind == EntryKind::Dir { "/" } else { "" };
        if long {
            let kind = match (e.kind, e.executable) {
                (EntryKind::Dir, _) => 'd',
                (_, true) => 'x',
                _ => '-',
            };
            let size = if e.kind == EntryKind::Dir {
                "-".to_string()
            } else {
                e.size.to_string()
            };
            println!(
                "{kind} {size:>12}  {}  {}{slash}",
                output::utc_minutes(e.mtime_ms),
                e.name
            );
        } else {
            println!("{}{slash}", e.name);
        }
    }
}

fn slot_description(
    kind: Option<SlotKind>,
    slot_type: u8,
    argon: Option<tijori_core::format::ArgonParams>,
) -> String {
    let base = match kind {
        Some(k) => k.to_string(),
        None => format!("type {slot_type} (needs a newer Tijori)"),
    };
    match argon {
        Some(p) => format!("{base}, Argon2id {} MiB, t={}", p.mem_kib / 1024, p.ops),
        None => base,
    }
}

fn print_settings(v: &Vault) {
    let s = v.settings();
    println!(
        "Label:        {}",
        if s.label.is_empty() {
            "(none)"
        } else {
            &s.label
        }
    );
    println!("Padding:      {}", on_off(s.padding));
    println!("Private only: {}", on_off(s.private_only));
}

fn show_new_phrase(input: &mut Input, words: &str) -> Result<()> {
    println!();
    print_recovery_phrase(words);
    println!();
    input.confirm_typed(&format!("Type {UNDERSTAND} to continue: "), UNDERSTAND)
}

fn execute(
    s: &mut Session,
    global: &GlobalArgs,
    input: &mut Input,
    cmd: VaultCommand,
) -> Result<()> {
    let v = &mut s.vault;
    match cmd {
        VaultCommand::Ls { path, long } => {
            let path = vp(path.as_deref().unwrap_or("/"))?;
            let entries = v.list(&path)?;
            print_entries(&entries, long);
        }
        VaultCommand::Put { mut paths } => {
            let dest = vp(&paths.pop().expect("clap requires 2 paths"))?;
            let sources: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).collect();
            let t = transfer::put(v, &sources, &dest)?;
            println!("Added {} to {dest}.", counts(t.files, t.bytes, t.dirs));
            if t.skipped > 0 {
                println!(
                    "Skipped {} item{}.",
                    t.skipped,
                    if t.skipped == 1 { "" } else { "s" }
                );
            }
        }
        VaultCommand::Get { mut paths } => {
            let local = PathBuf::from(paths.pop().expect("clap requires 2 paths"));
            let sources = paths.iter().map(|p| vp(p)).collect::<Result<Vec<_>>>()?;
            let t = transfer::get(v, &sources, &local)?;
            println!(
                "Copied {} to {}.",
                counts(t.files, t.bytes, t.dirs),
                local.display()
            );
        }
        VaultCommand::Mkdir { path, parents } => {
            let path = vp(&path)?;
            if parents {
                v.mkdir_all(&path)?
            } else {
                v.mkdir(&path)?
            }
            v.commit()?;
            println!("Created {path}");
        }
        VaultCommand::Mv { from, to } => {
            let (from, mut to) = (vp(&from)?, vp(&to)?);
            if let Ok(e) = v.stat(&to)
                && e.kind == EntryKind::Dir
                && let Some(name) = from.name()
            {
                to = to.join(name)?;
            }
            v.rename(&from, &to)?;
            v.commit()?;
            println!("Moved {from} to {to}");
        }
        VaultCommand::Rm { path, recursive } => {
            let path = vp(&path)?;
            v.remove(&path, recursive)?;
            v.commit()?;
            println!("Deleted {path}");
        }
        VaultCommand::Cat { path } => transfer::cat(v, &vp(&path)?)?,
        VaultCommand::Passwd { slot } => {
            let slots = v.keyslots();
            let is_pw = |i: usize| {
                slots
                    .iter()
                    .any(|k| k.index == i && k.kind.is_some_and(SlotKind::uses_argon))
            };
            let index = match slot {
                Some(i) => i,
                None if is_pw(s.report.slot_index) => s.report.slot_index,
                None => slots
                    .iter()
                    .find(|k| k.kind.is_some_and(SlotKind::uses_argon))
                    .map(|k| k.index)
                    .ok_or_else(|| {
                        CliError::other(
                            "this vault has no password slot; add one with `keyslot add`",
                        )
                    })?,
            };
            let needs_keyfile = slots
                .iter()
                .any(|k| k.index == index && k.kind == Some(SlotKind::PasswordKeyfile));
            let keyfile = match (&global.with_keyfile, needs_keyfile) {
                (Some(p), true) => Some(open_keyfile(p)?),
                (None, true) => {
                    return Err(CliError::other(format!(
                        "keyslot {index} also needs its keyfile: pass it with --with-keyfile"
                    )));
                }
                _ => None,
            };
            let label = v.settings().label.clone();
            let password = input.new_password(&[label.as_str(), "tijori"])?;
            v.change_password(index, password, keyfile)?;
            println!("Changed the password of keyslot {index}.");
            println!("{PASSWORD_CHANGE_NOTE}");
        }
        VaultCommand::Keyslot { action } => match action {
            KeyslotAction::List => {
                println!("Slot  Type");
                for k in v.keyslots() {
                    let used = if k.index == s.report.slot_index {
                        "  (used to unlock)"
                    } else {
                        ""
                    };
                    println!(
                        "{:>4}  {}{used}",
                        k.index,
                        slot_description(k.kind, k.slot_type, k.argon)
                    );
                }
            }
            KeyslotAction::Add { keyfile, recovery } => {
                if recovery {
                    let (index, phrase) = v.add_keyslot(NewSlot::Recovery)?;
                    let phrase = phrase.expect("recovery slots return a phrase");
                    println!("Added a recovery phrase in keyslot {index}.");
                    show_new_phrase(input, &phrase.words())?;
                } else {
                    let keyfile = keyfile.as_deref().map(open_keyfile).transpose()?;
                    let label = v.settings().label.clone();
                    let password = input.new_password(&[label.as_str(), "tijori"])?;
                    let with_kf = keyfile.is_some();
                    let (index, _) = v.add_keyslot(NewSlot::Password {
                        password,
                        keyfile,
                        argon: argon_choice(),
                    })?;
                    println!(
                        "Added a {} in keyslot {index}.",
                        if with_kf {
                            "password + keyfile"
                        } else {
                            "password"
                        }
                    );
                }
            }
            KeyslotAction::Remove { index } => {
                v.remove_keyslot(index)?;
                println!("Removed keyslot {index}.");
                if index == s.report.slot_index {
                    println!("That was the keyslot you unlocked with; use another one next time.");
                }
            }
        },
        VaultCommand::Rekey => {
            println!(
                "Re-keying re-encrypts every file under a new master key. Afterwards the vault has exactly"
            );
            println!(
                "one password and one new recovery phrase; other keyslots and the old recovery phrase stop working."
            );
            let label = v.settings().label.clone();
            let password = input.new_password(&[label.as_str(), "tijori"])?;
            let slots = vec![
                NewSlot::Password {
                    password,
                    keyfile: None,
                    argon: argon_choice(),
                },
                NewSlot::Recovery,
            ];
            let bar = output::byte_bar(0, "Re-encrypting");
            let phrase = v.rekey(slots, &mut |p| {
                bar.set_length(p.total);
                bar.set_position(p.done);
                true
            })?;
            bar.finish_and_clear();
            println!("Re-keyed: revision {}.", v.rev());
            if let Some(p) = phrase {
                show_new_phrase(input, &p.words())?;
            }
        }
        VaultCommand::Verify => {
            let bar = output::byte_bar(0, "Verifying");
            let report = v.verify(&mut |p| {
                bar.set_length(p.total);
                bar.set_position(p.done);
                true
            })?;
            bar.finish_and_clear();
            println!(
                "Checked {} folder{} and {} file{} ({}).",
                report.dirs,
                if report.dirs == 1 { "" } else { "s" },
                report.files,
                if report.files == 1 { "" } else { "s" },
                output::size(report.bytes)
            );
            if report.is_ok() {
                println!("No problems found.");
            } else {
                for p in &report.problems {
                    println!(
                        "{} {}: {}",
                        p.class.vector_name().to_uppercase(),
                        p.path,
                        p.message
                    );
                }
                let worst = report
                    .problems
                    .iter()
                    .map(|p| p.class)
                    .min_by_key(|c| match c {
                        tijori_core::ErrorClass::Tampered => 0,
                        tijori_core::ErrorClass::Damaged => 1,
                        _ => 2,
                    })
                    .expect("problems exist");
                return Err(match worst {
                    tijori_core::ErrorClass::Tampered => tijori_core::Error::Tampered(format!(
                        "{} problem(s) found",
                        report.problems.len()
                    )),
                    _ => tijori_core::Error::Damaged(format!(
                        "{} problem(s) found",
                        report.problems.len()
                    )),
                }
                .into());
            }
        }
        VaultCommand::Gc => {
            let r = v.gc()?;
            println!(
                "Removed {} unused object{} ({}); {} in use.",
                r.removed,
                if r.removed == 1 { "" } else { "s" },
                output::size(r.freed_bytes),
                r.kept
            );
        }
        VaultCommand::Info => {
            let (major, minor) = v.format_version();
            println!("Drive:        {}", s.drive.display());
            println!("Format:       {major}.{minor}");
            println!("Vault ID:     {}", output::uuid(&v.vault_uuid()));
            println!("Revision:     {}", v.rev());
            println!(
                "Last written: {} UTC",
                output::utc_minutes(v.last_written() as i64 * 1000)
            );
            print_settings(v);
            let slots: Vec<String> = v
                .keyslots()
                .iter()
                .map(|k| {
                    format!(
                        "{}: {}",
                        k.index,
                        slot_description(k.kind, k.slot_type, k.argon)
                    )
                })
                .collect();
            println!("Keyslots:     {}", slots.join("; "));
            let mode = match v.read_only_reason() {
                None => "read-write".to_string(),
                Some(ReadOnlyReason::Requested) => "read-only".to_string(),
                Some(r) => format!("read-only ({r:?})"),
            };
            println!("Opened:       {mode}");
        }
        VaultCommand::Settings {
            padding,
            private_only,
            label,
        } => {
            let changing = padding.is_some() || private_only.is_some() || label.is_some();
            if changing {
                let mut new = v.settings().clone();
                if let Some(p) = padding {
                    new.padding = p == "on";
                }
                if let Some(p) = private_only {
                    new.private_only = p == "on";
                }
                if let Some(l) = label {
                    new.label = l;
                }
                v.set_settings(new)?;
                v.commit()?;
                println!("Settings saved. Padding applies to files added from now on.");
            }
            print_settings(v);
        }
    }
    Ok(())
}
