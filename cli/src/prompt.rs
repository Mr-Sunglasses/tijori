//! Reading passwords, phrases and confirmations. Secrets are never echoed.

use std::io::{self, BufRead, IsTerminal, Write};

use tijori_core::strength;
use tijori_core::{Password, RecoveryPhrase};
use zeroize::Zeroizing;

use crate::error::{CliError, Result};

pub struct Input {
    stdin_mode: bool,
}

impl Input {
    pub fn new(stdin_mode: bool) -> Self {
        Input { stdin_mode }
    }

    pub fn is_interactive(&self) -> bool {
        !self.stdin_mode && io::stdin().is_terminal()
    }

    /// One line from standard input, without the line ending.
    fn stdin_line(&mut self) -> Result<Zeroizing<String>> {
        let mut line = Zeroizing::new(String::new());
        let n = io::stdin().lock().read_line(&mut line)?;
        if n == 0 {
            return Err(CliError::other(
                "standard input ended before all answers were given",
            ));
        }
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        Ok(line)
    }

    pub fn secret(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        if self.stdin_mode {
            return self.stdin_line();
        }
        Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
    }

    /// A visible answer, such as a confirmation.
    pub fn line(&mut self, prompt: &str) -> Result<String> {
        if !self.stdin_mode {
            eprint!("{prompt}");
            io::stderr().flush()?;
        }
        Ok(self.stdin_line()?.to_string())
    }

    pub fn password(&mut self) -> Result<Password> {
        Ok(Password::new(self.secret("Password: ")?.as_str()))
    }

    pub fn recovery_phrase(&mut self) -> Result<RecoveryPhrase> {
        let words = self.secret("Recovery phrase (24 words): ")?;
        Ok(RecoveryPhrase::parse(&words)?)
    }

    /// Asks for a new password until it is strong enough and typed twice
    /// the same way. With --password-stdin, one line and no retries.
    pub fn new_password(&mut self, context: &[&str]) -> Result<Password> {
        loop {
            let p = self.secret("New password: ")?;
            let report = strength::check(&p, context);
            if !report.acceptable {
                let mut msg = String::from("This password is too easy to guess.");
                if let Some(w) = &report.warning {
                    msg.push_str(&format!(" {}.", w.trim_end_matches('.')));
                }
                for s in &report.suggestions {
                    msg.push_str(&format!("\n  {s}"));
                }
                if self.stdin_mode {
                    return Err(CliError::other(msg));
                }
                eprintln!("{msg}");
                continue;
            }
            if !self.stdin_mode {
                let again = self.secret("Repeat the new password: ")?;
                if *again != *p {
                    eprintln!("The two passwords differ. Try again.");
                    continue;
                }
            }
            return Ok(Password::new(p.as_str()));
        }
    }

    /// Waits for the user to type `expected` exactly.
    pub fn confirm_typed(&mut self, prompt: &str, expected: &str) -> Result<()> {
        loop {
            let answer = self.line(prompt)?;
            if answer.trim() == expected {
                return Ok(());
            }
            if self.stdin_mode {
                return Err(CliError::other(format!("expected \"{expected}\"")));
            }
        }
    }
}
