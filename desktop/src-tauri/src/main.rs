//! Tijori desktop app backend. The Tauri 2 shell, commands, drive watcher and
//! RAM disk arrive in Milestone 5.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "tijori-desktop {}: pre-alpha, the desktop app is not implemented yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
