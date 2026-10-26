//! Formatting for terminal output.

use std::io::IsTerminal;

use indicatif::{ProgressBar, ProgressStyle};

/// `1.5 MiB` style sizes.
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut unit = "B";
    for u in UNITS {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        unit = u;
    }
    format!("{v:.1} {unit}")
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// `2026-01-01 12:30` in UTC.
pub fn utc_minutes(unix_ms: i64) -> String {
    let secs = unix_ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        rem / 3600,
        rem % 3600 / 60
    )
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A vault UUID as 8-4-4-4-12.
pub fn uuid(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

pub const RECOVERY_WARNING: &str = "If you lose both your password and this recovery phrase, your files cannot be recovered by anyone.";

/// Prints the recovery phrase as 6 rows of 4 numbered words, with the warning.
pub fn print_recovery_phrase(words: &str) {
    let words: Vec<&str> = words.split(' ').collect();
    println!(
        "Your recovery phrase. Write it down and keep it somewhere safe; it is shown only once:"
    );
    println!();
    for row in words.chunks(4).enumerate() {
        let cells: Vec<String> = row
            .1
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:>2}. {w:<9}", row.0 * 4 + i + 1))
            .collect();
        println!("  {}", cells.join("  ").trim_end());
    }
    println!();
    println!("{RECOVERY_WARNING}");
}

/// A byte progress bar on stderr, hidden when stderr is not a terminal.
pub fn byte_bar(total: u64, msg: &str) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::with_template("{msg} [{bar:30}] {bytes}/{total_bytes} ({eta})")
            .expect("valid template")
            .progress_chars("=> "),
    );
    bar.set_message(msg.to_string());
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_sizes() {
        assert_eq!(utc_minutes(0), "1970-01-01 00:00");
        assert_eq!(utc_minutes(1_767_225_600_000), "2026-01-01 00:00");
        assert_eq!(utc_minutes(951_782_400_000), "2000-02-29 00:00");
        assert_eq!(utc_minutes(-86_400_000), "1969-12-31 00:00");
        assert_eq!(size(5), "5 B");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(3 * 1024 * 1024 * 1024), "3.0 GiB");
        assert_eq!(uuid(&[0xab; 16]), "abababab-abab-abab-abab-abababababab");
    }
}
