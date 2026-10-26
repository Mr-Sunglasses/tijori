//! CLI errors and exit codes (Plan Milestone 3).

use std::fmt;

use tijori_core::{Error, ErrorClass};

pub enum CliError {
    Core(Error),
    /// Another writer holds the lock (exit code 6).
    Locked(String),
    Other(String),
    /// Already shown to the user; only the exit code is left to report.
    Reported(u8),
}

pub type Result<T, E = CliError> = std::result::Result<T, E>;

impl CliError {
    pub fn other(msg: impl Into<String>) -> Self {
        CliError::Other(msg.into())
    }

    /// 0 ok, 2 wrong secret, 3 tampered, 4 damaged, 5 unsupported, 6 locked, 1 other.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Core(e) => match e.class() {
                ErrorClass::WrongSecret => 2,
                ErrorClass::Tampered => 3,
                ErrorClass::Damaged => 4,
                ErrorClass::Unsupported => 5,
                ErrorClass::Locked => 6,
                _ => 1,
            },
            CliError::Locked(_) => 6,
            CliError::Other(_) => 1,
            CliError::Reported(code) => *code,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Core(e) => write!(f, "{e}"),
            CliError::Locked(m) | CliError::Other(m) => f.write_str(m),
            CliError::Reported(code) => write!(f, "exit code {code}"),
        }
    }
}

impl From<Error> for CliError {
    fn from(e: Error) -> Self {
        CliError::Core(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Core(Error::from_io(e, "I/O"))
    }
}
