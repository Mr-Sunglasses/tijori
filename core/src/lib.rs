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
