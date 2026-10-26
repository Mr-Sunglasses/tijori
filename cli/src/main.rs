//! `tijori`: create and use encrypted vaults on USB drives.

#[macro_use]
mod output;
mod cancel;
mod commands;
mod drive;
mod error;
mod prompt;
mod session;
mod transfer;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use error::CliError;

#[derive(Parser)]
#[command(
    name = "tijori",
    version,
    about = "Encrypted vaults on USB drives",
    long_about = "Tijori turns a USB drive into an encrypted vault that opens on macOS, Linux and Android.\n\n\
                  Exit codes: 0 ok, 1 other error, 2 wrong password/keyfile/phrase, 3 tampered, \
                  4 damaged, 5 needs a newer Tijori, 6 locked by another writer."
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone, Default)]
pub struct GlobalArgs {
    /// The drive, or its TIJORI folder. Found automatically when exactly one
    /// vault is mounted.
    #[arg(long, global = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,
    /// Unlock with the 24-word recovery phrase instead of the password.
    #[arg(long, global = true)]
    pub with_recovery: bool,
    /// Unlock a password + keyfile slot with this keyfile.
    #[arg(long, global = true, value_name = "PATH")]
    pub with_keyfile: Option<PathBuf>,
    /// Read passwords, phrases and confirmations from standard input, one
    /// per line, instead of prompting on the terminal.
    #[arg(long, global = true)]
    pub password_stdin: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create a vault on a drive.
    Init {
        /// The drive's mount point (an exFAT volume).
        drive: PathBuf,
        /// Store exact file sizes instead of padding them (padding hides sizes).
        #[arg(long)]
        no_padding: bool,
        /// A name for the vault, up to 64 bytes.
        #[arg(long)]
        label: Option<String>,
        /// Also require this keyfile, together with the password.
        #[arg(long, value_name = "PATH")]
        keyfile: Option<PathBuf>,
    },
    /// Unlock once and run several commands; lock on exit.
    Shell {
        /// The drive (or use --vault).
        drive: Option<PathBuf>,
    },
    /// Show the vault as a folder in Finder or your file manager until you
    /// press Ctrl+C, eject it, or leave it idle.
    Mount {
        /// The drive (or use --vault).
        drive: Option<PathBuf>,
        /// Where to mount (default: /Volumes/<label> on macOS,
        /// $XDG_RUNTIME_DIR/tijori/<label> on Linux).
        mountpoint: Option<PathBuf>,
        /// Lock after this many idle minutes; 0 never locks for idleness.
        #[arg(long, default_value_t = 15)]
        idle_minutes: u64,
    },
    #[command(flatten)]
    Vault(VaultCommand),
    /// Copy a backup onto a drive, so the drive holds the backup's state.
    /// Only what differs is copied.
    Restore {
        /// The backup: a folder or drive made with `tijori backup`.
        backup: PathBuf,
        /// The drive to restore onto (an exFAT volume).
        drive: PathBuf,
        /// Overwrite the drive's vault even if it has changes the backup
        /// does not have.
        #[arg(long)]
        force: bool,
    },
    /// Print a completion script for your shell, for example
    /// `tijori completions zsh > ~/.zfunc/_tijori`.
    Completions {
        /// Your shell.
        shell: clap_complete::Shell,
    },
    /// Remove a lock left behind by a Tijori that is no longer running.
    BreakLock {
        /// Break the lock even if it was refreshed in the last 10 minutes.
        #[arg(long)]
        force: bool,
    },
}

/// Commands that work on an unlocked vault, also available in `tijori shell`.
#[derive(Subcommand, Clone)]
pub enum VaultCommand {
    /// List a folder.
    Ls {
        /// Folder in the vault (default: the top folder).
        path: Option<String>,
        /// Show kind, size and modification time.
        #[arg(short = 'l')]
        long: bool,
    },
    /// Add files and folders (recursively) to a vault folder.
    #[command(override_usage = "tijori put [OPTIONS] <LOCAL>... <VAULT_DIR>")]
    Put {
        /// Local files or folders, then the vault folder to put them in.
        #[arg(required = true, num_args = 2.., value_name = "PATH")]
        paths: Vec<String>,
    },
    /// Copy files and folders out of the vault into a local folder.
    #[command(override_usage = "tijori get [OPTIONS] <VAULT_PATH>... <LOCAL_DIR>")]
    Get {
        /// Vault paths, then the local folder to put them in.
        #[arg(required = true, num_args = 2.., value_name = "PATH")]
        paths: Vec<String>,
    },
    /// Create a folder.
    Mkdir {
        /// The new folder, for example /photos/2026.
        path: String,
        /// Create missing parent folders too.
        #[arg(short = 'p')]
        parents: bool,
    },
    /// Move or rename a file or folder.
    Mv {
        /// What to move.
        from: String,
        /// The new path, or an existing folder to move it into.
        to: String,
    },
    /// Delete a file, or a folder with -r.
    Rm {
        /// The file or folder to delete.
        path: String,
        /// Delete a folder and everything in it.
        #[arg(short = 'r')]
        recursive: bool,
    },
    /// Print a file to standard output.
    Cat {
        /// The file to print.
        path: String,
    },
    /// Change the password of a password slot.
    Passwd {
        /// Keyslot to change (default: the one you unlocked with, or the first password slot).
        #[arg(long)]
        slot: Option<usize>,
    },
    /// List, add or remove keyslots.
    Keyslot {
        #[command(subcommand)]
        action: KeyslotAction,
    },
    /// Re-encrypt everything under a new master key. Old copies of the
    /// header, and every old password, stop working.
    Rekey,
    /// Check every hash and decrypt every chunk.
    Verify,
    /// Delete encrypted objects nothing refers to any more.
    Gc,
    /// Copy the whole vault, still encrypted, to another folder or drive.
    /// Run it again to bring the copy up to date; only changes are copied.
    Backup {
        /// Folder or drive to hold the copy (created if missing).
        dest: PathBuf,
        /// Overwrite a copy that has changes this vault does not have.
        #[arg(long)]
        force: bool,
    },
    /// Show format version, settings, keyslots and revision.
    Info,
    /// Show or change vault settings.
    Settings {
        /// Pad file sizes (on) or store them exactly (off).
        #[arg(long, value_parser = ["on", "off"])]
        padding: Option<String>,
        /// Refuse to mount; use the vault only inside the app.
        #[arg(long, value_parser = ["on", "off"])]
        private_only: Option<String>,
        /// A name for the vault, up to 64 bytes.
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
pub enum KeyslotAction {
    /// Show the keyslots in use.
    List,
    /// Add a password slot (optionally with a keyfile), or a recovery phrase.
    Add {
        /// Require this keyfile together with the new password.
        #[arg(long, value_name = "PATH", conflicts_with = "recovery")]
        keyfile: Option<PathBuf>,
        /// Add a new 24-word recovery phrase instead of a password.
        #[arg(long)]
        recovery: bool,
    },
    /// Remove a keyslot. The last one can never be removed.
    Remove {
        /// The slot number, as `keyslot list` shows it.
        index: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut input = prompt::Input::new(cli.global.password_stdin);
    let result = match cli.command {
        Command::Init {
            drive,
            no_padding,
            label,
            keyfile,
        } => commands::init(&mut input, &drive, !no_padding, label, keyfile),
        Command::Shell { drive } => {
            let global = GlobalArgs {
                vault: drive.or(cli.global.vault.clone()),
                ..cli.global.clone()
            };
            commands::shell(&global, &mut input)
        }
        Command::Mount {
            drive,
            mountpoint,
            idle_minutes,
        } => {
            // With --vault naming the drive, a lone argument is the mount point.
            let (drive, mountpoint) = match (&cli.global.vault, drive, mountpoint) {
                (Some(_), Some(only), None) => (None, Some(only)),
                (_, d, m) => (d, m),
            };
            let global = GlobalArgs {
                vault: drive.or(cli.global.vault.clone()),
                ..cli.global.clone()
            };
            commands::mount(&global, &mut input, mountpoint, idle_minutes)
        }
        Command::Restore {
            backup,
            drive,
            force,
        } => {
            let global = GlobalArgs {
                vault: Some(backup),
                ..cli.global.clone()
            };
            commands::restore(&global, &mut input, &drive, force)
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut <Cli as clap::CommandFactory>::command(),
                "tijori",
                &mut std::io::stdout(),
            );
            Ok(())
        }
        Command::BreakLock { force } => commands::break_lock(&cli.global, &mut input, force),
        Command::Vault(cmd) => commands::run_once(&cli.global, &mut input, cmd),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if !matches!(e, CliError::Reported(_)) {
                eprintln!("tijori: {e}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
