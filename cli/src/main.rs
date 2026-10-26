//! The `tijori` command-line tool. Commands arrive in Milestone 3.

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!(
        "tijori {}: pre-alpha, no commands are implemented yet",
        env!("CARGO_PKG_VERSION")
    );
    ExitCode::FAILURE
}
