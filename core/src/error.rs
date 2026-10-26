//! Errors. Every error belongs to one user-facing class (Plan §5.3); the
//! classes are deliberately distinct so attacks are never reported as a
//! simple typo.

use std::fmt;

/// The user-facing error classes, also used by the test vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorClass {
    /// No keyslot opened with what the user entered.
    WrongSecret,
    /// A keyslot opened, but the header MAC, a hash or an AEAD tag failed.
    Tampered,
    /// Structure is unreadable without a sign of tampering.
    Damaged,
    /// Newer format version or unknown required feature.
    Unsupported,
    /// Another writer holds the lock.
    Locked,
    /// The underlying storage failed.
    Io,
    /// Anything else: invalid input, missing paths, cancelled operations.
    Other,
}

impl ErrorClass {
    /// The name used in the test vectors (`wrong_secret`, `tampered`, ...).
    pub fn vector_name(self) -> &'static str {
        match self {
            ErrorClass::WrongSecret => "wrong_secret",
            ErrorClass::Tampered => "tampered",
            ErrorClass::Damaged => "damaged",
            ErrorClass::Unsupported => "unsupported",
            ErrorClass::Locked => "locked",
            ErrorClass::Io => "io",
            ErrorClass::Other => "other",
        }
    }
}

/// A storage failure: drive removed, full, read-only, missing file.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("invalid storage path: {0}")]
    InvalidPath(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

impl StorageError {
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        StorageError::Io {
            context: context.into(),
            source,
        }
    }

    pub fn is_not_found(&self) -> bool {
        match self {
            StorageError::NotFound(_) => true,
            StorageError::Io { source, .. } => source.kind() == std::io::ErrorKind::NotFound,
            _ => false,
        }
    }
}

/// Every error the core returns. Messages never contain secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong password, keyfile or recovery phrase")]
    WrongSecret,
    #[error("the vault has been tampered with: {0}")]
    Tampered(String),
    #[error("the vault is damaged: {0}")]
    Damaged(String),
    #[error("this vault needs a newer version of Tijori: {0}")]
    Unsupported(String),
    #[error("another Tijori writer holds the vault lock: {0}")]
    Locked(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("{0}")]
    InvalidInput(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    #[error("not a folder: {0}")]
    NotADirectory(String),
    #[error("is a folder: {0}")]
    IsADirectory(String),
    #[error("folder is not empty: {0}")]
    NotEmpty(String),
    #[error("the vault is open read-only: {0}")]
    ReadOnly(String),
    #[error("cancelled")]
    Cancelled,
    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn class(&self) -> ErrorClass {
        match self {
            Error::WrongSecret => ErrorClass::WrongSecret,
            Error::Tampered(_) => ErrorClass::Tampered,
            Error::Damaged(_) => ErrorClass::Damaged,
            Error::Unsupported(_) => ErrorClass::Unsupported,
            Error::Locked(_) => ErrorClass::Locked,
            Error::Storage(_) => ErrorClass::Io,
            _ => ErrorClass::Other,
        }
    }

    pub(crate) fn tampered(what: impl fmt::Display) -> Self {
        Error::Tampered(what.to_string())
    }

    pub(crate) fn damaged(what: impl fmt::Display) -> Self {
        Error::Damaged(what.to_string())
    }

    pub(crate) fn unsupported(what: impl fmt::Display) -> Self {
        Error::Unsupported(what.to_string())
    }

    pub(crate) fn invalid(what: impl fmt::Display) -> Self {
        Error::InvalidInput(what.to_string())
    }

    /// Wraps this error for APIs that must return `std::io::Error`
    /// (`std::io::Read` implementations). [`Error::from_io`] recovers it.
    pub fn into_io(self) -> std::io::Error {
        match self {
            Error::Storage(StorageError::Io { source, .. }) => source,
            other => std::io::Error::other(other),
        }
    }

    /// Recovers an [`Error`] from an `std::io::Error` produced by this crate,
    /// or wraps a plain I/O error as a storage error.
    pub fn from_io(err: std::io::Error, context: &str) -> Self {
        if err.get_ref().is_some_and(|e| e.is::<Error>()) {
            match err.into_inner().map(|e| e.downcast::<Error>()) {
                Some(Ok(e)) => return *e,
                _ => unreachable!("checked above"),
            }
        }
        Error::Storage(StorageError::io(context, err))
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
