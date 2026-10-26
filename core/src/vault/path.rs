//! Paths inside a vault: `/` for the root, `/Docs/notes.txt` for a file.

use std::fmt;

use crate::error::{Error, Result};
use crate::names;

/// Spec §12: the tree is at most 256 levels deep, counting the root.
pub const MAX_DEPTH: usize = 255;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VaultPath {
    comps: Vec<String>,
}

impl VaultPath {
    pub fn root() -> Self {
        VaultPath::default()
    }

    /// Parses `/a/b` (the leading `/` is optional). Each component is
    /// normalized to NFC and checked against the name rules.
    pub fn parse(s: &str) -> Result<Self> {
        let mut comps = Vec::new();
        for c in s.split('/').filter(|c| !c.is_empty()) {
            comps.push(names::normalize(c)?);
        }
        if comps.len() > MAX_DEPTH {
            return Err(Error::invalid(format!(
                "paths can be at most {MAX_DEPTH} levels deep"
            )));
        }
        Ok(VaultPath { comps })
    }

    pub fn join(&self, name: &str) -> Result<Self> {
        if self.comps.len() >= MAX_DEPTH {
            return Err(Error::invalid(format!(
                "paths can be at most {MAX_DEPTH} levels deep"
            )));
        }
        let mut comps = self.comps.clone();
        comps.push(names::normalize(name)?);
        Ok(VaultPath { comps })
    }

    pub fn is_root(&self) -> bool {
        self.comps.is_empty()
    }

    pub fn parent(&self) -> Option<VaultPath> {
        let (_, rest) = self.comps.split_last()?;
        Some(VaultPath {
            comps: rest.to_vec(),
        })
    }

    pub fn name(&self) -> Option<&str> {
        self.comps.last().map(String::as_str)
    }

    pub fn components(&self) -> &[String] {
        &self.comps
    }

    /// True if `self` is `other` or inside it.
    pub fn starts_with(&self, other: &VaultPath) -> bool {
        self.comps.starts_with(&other.comps)
    }
}

impl fmt::Display for VaultPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.comps.is_empty() {
            return f.write_str("/");
        }
        for c in &self.comps {
            write!(f, "/{c}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        assert!(VaultPath::parse("/").unwrap().is_root());
        assert!(VaultPath::parse("").unwrap().is_root());
        let p = VaultPath::parse("Docs//cafe\u{301}.txt/").unwrap();
        assert_eq!(p.to_string(), "/Docs/caf\u{e9}.txt");
        assert_eq!(p.name(), Some("caf\u{e9}.txt"));
        assert_eq!(p.parent().unwrap().to_string(), "/Docs");
        assert!(p.starts_with(&VaultPath::parse("/Docs").unwrap()));
        assert!(
            !VaultPath::parse("/Docsx")
                .unwrap()
                .starts_with(&VaultPath::parse("/Docs").unwrap())
        );
        assert!(VaultPath::parse("/a/../b").is_err());
        assert!(VaultPath::parse(&"/a".repeat(256)).is_err());
    }
}
