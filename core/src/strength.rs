//! Password strength policy (spec §14: writers MUST require zxcvbn score >= 3).

/// Minimum zxcvbn score for a new password.
pub const MIN_SCORE: u8 = 3;

/// zxcvbn gets slow on very long inputs and gains nothing from them.
const MAX_CHECKED_CHARS: usize = 100;

const PASSPHRASE_TIP: &str = "Try a passphrase of 6 or more random words, like \"orbit lantern cactus velvet mango thunder\".";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrengthReport {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
    /// Whether the score meets [`MIN_SCORE`].
    pub acceptable: bool,
    pub warning: Option<String>,
    pub suggestions: Vec<String>,
    /// Rough time to guess it offline at high speed, e.g. "3 centuries".
    pub crack_time: String,
}

/// Rates a password. `context` holds words the password should not be built
/// from, such as the vault label.
pub fn check(password: &str, context: &[&str]) -> StrengthReport {
    let checked: String = password.chars().take(MAX_CHECKED_CHARS).collect();
    let entropy = zxcvbn::zxcvbn(&checked, context);
    let score = u8::from(entropy.score());
    let acceptable = score >= MIN_SCORE;
    let (warning, mut suggestions) = match entropy.feedback() {
        Some(f) => (
            f.warning().map(|w| w.to_string()),
            f.suggestions()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ),
        None => (None, Vec::new()),
    };
    if !acceptable {
        suggestions.push(PASSPHRASE_TIP.to_string());
    }
    StrengthReport {
        score,
        acceptable,
        warning,
        suggestions,
        crack_time: entropy
            .crack_times()
            .offline_slow_hashing_1e4_per_second()
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_and_strong() {
        let weak = check("password1", &[]);
        assert!(!weak.acceptable);
        assert!(weak.suggestions.iter().any(|s| s.contains("6 or more")));
        let strong = check("orbit lantern cactus velvet mango thunder", &[]);
        assert!(strong.acceptable, "{strong:?}");
        assert!(strong.score >= MIN_SCORE);
    }

    #[test]
    fn context_words_count_against() {
        let with = check("tijorifamily2024", &["tijori", "family"]);
        let without = check("tijorifamily2024", &[]);
        assert!(with.score <= without.score);
    }

    #[test]
    fn very_long_input_is_fast() {
        let long = "a".repeat(100_000);
        let _ = check(&long, &[]);
    }
}
