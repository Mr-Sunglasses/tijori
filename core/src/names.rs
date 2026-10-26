//! File and folder names (spec §11): NFC, 1-255 bytes, no `/` or NUL, not
//! `.` or `..`, unique within a folder by NFC bytes, case-sensitive.

use unicode_normalization::{UnicodeNormalization, is_nfc};

use crate::error::{Error, Result};

pub const MAX_NAME_LEN: usize = 255;

/// Why a name is not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameProblem {
    Empty,
    TooLong,
    Slash,
    Nul,
    Dot,
    NotNfc,
}

impl std::fmt::Display for NameProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NameProblem::Empty => "name is empty",
            NameProblem::TooLong => "name is longer than 255 bytes",
            NameProblem::Slash => "name contains '/'",
            NameProblem::Nul => "name contains a NUL character",
            NameProblem::Dot => "name cannot be '.' or '..'",
            NameProblem::NotNfc => "name is not in Unicode NFC form",
        })
    }
}

fn check_rules(name: &str) -> Option<NameProblem> {
    if name.is_empty() {
        Some(NameProblem::Empty)
    } else if name.len() > MAX_NAME_LEN {
        Some(NameProblem::TooLong)
    } else if name.contains('/') {
        Some(NameProblem::Slash)
    } else if name.contains('\0') {
        Some(NameProblem::Nul)
    } else if name == "." || name == ".." {
        Some(NameProblem::Dot)
    } else {
        None
    }
}

/// Normalizes a user-supplied name to NFC and checks the rules.
pub fn normalize(name: &str) -> Result<String> {
    let nfc: String = name.nfc().collect();
    match check_rules(&nfc) {
        None => Ok(nfc),
        Some(p) => Err(Error::invalid(format!("{p}: {name:?}"))),
    }
}

/// Checks a name read from a vault. It must already be NFC.
pub fn check_stored(name: &str) -> Result<(), NameProblem> {
    if let Some(p) = check_rules(name) {
        return Err(p);
    }
    if !is_nfc(name) {
        return Err(NameProblem::NotNfc);
    }
    Ok(())
}

/// NFC-normalizes a password (spec §1).
pub fn normalize_password(password: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(password.nfc().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfd_becomes_nfc() {
        let nfd = "cafe\u{301}.txt";
        assert_eq!(normalize(nfd).unwrap(), "caf\u{e9}.txt");
        assert_eq!(check_stored(nfd), Err(NameProblem::NotNfc));
        assert_eq!(check_stored("caf\u{e9}.txt"), Ok(()));
    }

    #[test]
    fn rules() {
        for bad in ["", ".", "..", "a/b", "a\0b"] {
            assert!(normalize(bad).is_err(), "{bad:?}");
        }
        assert!(normalize(&"n".repeat(255)).is_ok());
        assert!(normalize(&"n".repeat(256)).is_err());
        // 85 three-byte characters = 255 bytes; 86 is too long.
        assert!(normalize(&"\u{0915}".repeat(85)).is_ok());
        assert!(normalize(&"\u{0915}".repeat(86)).is_err());
        assert!(normalize("...").is_ok());
        assert!(normalize("Notes.txt").is_ok());
    }
}
