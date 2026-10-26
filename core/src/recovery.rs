//! 24-word recovery phrase (English BIP-39, 256-bit entropy; spec §4 type 3).

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::crypto::random_bytes;
use crate::error::{Error, Result};

pub const WORDS: usize = 24;

/// The 32 bytes of entropy behind a recovery phrase.
pub struct RecoveryPhrase {
    entropy: Zeroizing<[u8; 32]>,
}

impl RecoveryPhrase {
    pub fn generate() -> Self {
        let mut entropy = Zeroizing::new([0u8; 32]);
        random_bytes(&mut entropy[..]);
        RecoveryPhrase { entropy }
    }

    pub fn from_entropy(entropy: [u8; 32]) -> Self {
        RecoveryPhrase {
            entropy: Zeroizing::new(entropy),
        }
    }

    /// Parses 24 English words. Case and spacing are ignored.
    pub fn parse(phrase: &str) -> Result<Self> {
        let words: Zeroizing<Vec<String>> = Zeroizing::new(
            phrase
                .split_whitespace()
                .map(|w| w.to_lowercase())
                .collect(),
        );
        if words.len() != WORDS {
            return Err(Error::invalid(format!(
                "a recovery phrase has {WORDS} words, this one has {}",
                words.len()
            )));
        }
        let wordlist = Language::English.word_list();
        if let Some((i, _)) = words
            .iter()
            .enumerate()
            .find(|(_, w)| !wordlist.contains(&w.as_str()))
        {
            return Err(Error::invalid(format!(
                "word {} of the recovery phrase is not in the word list",
                i + 1
            )));
        }
        let joined = Zeroizing::new(words.join(" "));
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &joined).map_err(|_| {
            Error::invalid("the recovery phrase checksum is wrong; check the words and their order")
        })?;
        let (bytes, len) = mnemonic.to_entropy_array();
        let bytes = Zeroizing::new(bytes);
        if len != 32 {
            return Err(Error::invalid("the recovery phrase must encode 256 bits"));
        }
        let mut entropy = Zeroizing::new([0u8; 32]);
        entropy.copy_from_slice(&bytes[..32]);
        Ok(RecoveryPhrase { entropy })
    }

    /// The 24 words, space-separated.
    pub fn words(&self) -> Zeroizing<String> {
        let m = Mnemonic::from_entropy_in(Language::English, &self.entropy[..])
            .expect("32 bytes is valid entropy");
        Zeroizing::new(m.words().collect::<Vec<_>>().join(" "))
    }

    pub(crate) fn entropy(&self) -> &[u8; 32] {
        &self.entropy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy_is_abandon_art() {
        let p = RecoveryPhrase::from_entropy([0; 32]);
        let words = p.words();
        assert!(words.starts_with("abandon abandon"));
        assert!(words.ends_with(" art"));
        assert_eq!(words.split(' ').count(), 24);
    }

    #[test]
    fn round_trip_and_normalization() {
        let p = RecoveryPhrase::generate();
        let words = p.words();
        let messy = format!("  {}  ", words.to_uppercase().replace(' ', "\n "));
        let back = RecoveryPhrase::parse(&messy).unwrap();
        assert_eq!(back.entropy(), p.entropy());
    }

    #[test]
    fn rejects_bad_phrases() {
        let words = RecoveryPhrase::from_entropy([0; 32]).words();
        let short: Vec<&str> = words.split(' ').take(23).collect();
        assert!(RecoveryPhrase::parse(&short.join(" ")).is_err());
        let wrong_checksum = words.replace(" art", " abandon");
        assert!(RecoveryPhrase::parse(&wrong_checksum).is_err());
        let unknown = words.replacen("abandon", "tijori", 1);
        assert!(RecoveryPhrase::parse(&unknown).is_err());
    }
}
