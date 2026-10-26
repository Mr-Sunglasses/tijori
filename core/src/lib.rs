//! Tijori core: vault format, cryptography and vault engine.
//!
//! This crate knows nothing about the operating system. It reaches the drive
//! only through the `Storage` trait, and every frontend (CLI, mount, desktop,
//! Android) goes through the `Vault` API rather than touching crypto directly.
//!
//! The on-disk format is defined in `spec/SPEC.md`; if this code and the spec
//! disagree, the code is wrong.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod format;
pub mod keys;
pub mod names;
pub mod padding;
pub mod recovery;
pub mod strength;

pub use error::{Error, ErrorClass, Result, StorageError};
pub use keys::{Keyfile, Password, UnlockSecret};
pub use recovery::RecoveryPhrase;
