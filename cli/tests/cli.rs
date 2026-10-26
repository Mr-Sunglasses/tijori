//! Snapshot tests of every `tijori` command's output and exit code.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use tempfile::TempDir;

const PW: &str = "orbit lantern cactus velvet mango thunder";
const PW2: &str = "quartz pelican harbor midnight saffron tundra";

struct Env {
    _dir: TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        for d in ["drive", "data", "src/sub", "out"] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        let fixed = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        for (path, content) in [
            ("src/hello.txt", &b"hello tijori\n"[..]),
            ("src/sub/data.bin", &[7u8; 5000][..]),
        ] {
            let p = root.join(path);
            fs::write(&p, content).unwrap();
            fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(fixed)
                .unwrap();
        }
        Env { _dir: dir, root }
    }

    fn path(&self, p: &str) -> String {
        self.root.join(p).to_string_lossy().into_owned()
    }

    fn drive(&self) -> PathBuf {
        self.root.join("drive")
    }

    /// Runs `tijori` with `stdin` lines; returns a normalized transcript.
    fn run(&self, args: &[&str], stdin: &str) -> String {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tijori"))
            .args(args)
            .env("TIJORI_DATA_DIR", self.root.join("data"))
            .env("TIJORI_NO_KEYRING", "1")
            .env("TIJORI_TEST_FAST_KDF", "1")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        let text = format!(
            "exit: {}\n--- stdout\n{}--- stderr\n{}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        text.replace(&self.root.to_string_lossy().to_string(), "[TMP]")
    }

    /// Runs a vault command with `--vault` and `--password-stdin`.
    fn vault(&self, args: &[&str], stdin: &str) -> String {
        let drive = self.drive().to_string_lossy().into_owned();
        let mut all = vec!["--vault", drive.as_str(), "--password-stdin"];
        all.extend_from_slice(args);
        self.run(&all, stdin)
    }

    fn init(&self) -> String {
        let drive = self.drive().to_string_lossy().into_owned();
        self.run(
            &["init", &drive, "--label", "Family", "--password-stdin"],
            &format!("{PW}\nI UNDERSTAND\n"),
        )
    }
}

fn pw() -> String {
    format!("{PW}\n")
}

macro_rules! snap {
    ($name:expr, $value:expr) => {
        insta::with_settings!({
            filters => vec![
                (r"(?m)^ +\d+\. [a-z]+ .*$", "  [recovery phrase row]"),
                (r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "[UUID]"),
                (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", "[DATETIME]"),
                (r"refreshed \d+ minutes? ago", "refreshed [N] minutes ago"),
            ],
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!($name, $value);
        });
    };
}

#[test]
fn help() {
    let e = Env::new();
    snap!("help", e.run(&["--help"], ""));
    snap!("put_help", e.run(&["put", "--help"], ""));
}

#[test]
fn init_and_file_commands() {
    let e = Env::new();
    snap!("init", e.init());
    assert!(e.drive().join("README-TIJORI.txt").is_file());
    snap!("init_again", e.init());
    snap!("ls_empty", e.vault(&["ls"], &pw()));
    snap!(
        "put",
        e.vault(
            &["put", &e.path("src/hello.txt"), &e.path("src/sub"), "/docs"],
            &pw()
        )
    );
    snap!("ls", e.vault(&["ls", "/docs"], &pw()));
    snap!("ls_long", e.vault(&["ls", "-l", "/docs"], &pw()));
    snap!("cat", e.vault(&["cat", "/docs/hello.txt"], &pw()));
    snap!("get", e.vault(&["get", "/docs", &e.path("out")], &pw()));
    assert_eq!(
        fs::read(e.root.join("out/docs/sub/data.bin")).unwrap(),
        vec![7u8; 5000]
    );
    snap!(
        "get_again_keeps_both",
        e.vault(&["get", "/docs/hello.txt", &e.path("out/docs")], &pw())
    );
    assert!(e.root.join("out/docs/hello (1).txt").is_file());
    snap!("mkdir", e.vault(&["mkdir", "-p", "/a/b"], &pw()));
    snap!("mv", e.vault(&["mv", "/docs/hello.txt", "/a/b"], &pw()));
    snap!("rm_nonempty", e.vault(&["rm", "/docs"], &pw()));
    snap!("rm", e.vault(&["rm", "-r", "/docs"], &pw()));
    snap!("ls_after", e.vault(&["ls", "-l", "/a/b"], &pw()));
    snap!("not_found", e.vault(&["cat", "/missing.txt"], &pw()));
    snap!("verify", e.vault(&["verify"], &pw()));
    snap!("gc", e.vault(&["gc"], &pw()));
    snap!("info", e.vault(&["info"], &pw()));
    snap!("settings", e.vault(&["settings"], &pw()));
    snap!(
        "settings_change",
        e.vault(
            &["settings", "--padding", "off", "--label", "Photos"],
            &pw()
        )
    );
}

#[test]
fn secrets_and_keyslots() {
    let e = Env::new();
    e.init();
    snap!(
        "wrong_password",
        e.vault(&["ls"], "not the right password at all\n")
    );
    snap!("keyslot_list", e.vault(&["keyslot", "list"], &pw()));
    snap!(
        "weak_password",
        e.vault(&["keyslot", "add"], &format!("{PW}\npassword1\n"))
    );
    snap!(
        "keyslot_add",
        e.vault(&["keyslot", "add"], &format!("{PW}\n{PW2}\n"))
    );
    fs::write(e.root.join("keyfile"), b"my keyfile").unwrap();
    snap!(
        "keyslot_add_keyfile",
        e.vault(
            &["keyslot", "add", "--keyfile", &e.path("keyfile")],
            &format!("{PW}\n{PW2}\n")
        )
    );
    snap!(
        "keyslot_add_recovery",
        e.vault(
            &["keyslot", "add", "--recovery"],
            &format!("{PW}\nI UNDERSTAND\n")
        )
    );
    snap!(
        "keyslot_remove",
        e.vault(&["keyslot", "remove", "2"], &format!("{PW2}\n"))
    );
    snap!(
        "unlock_with_keyfile",
        e.vault(
            &["--with-keyfile", &e.path("keyfile"), "keyslot", "list"],
            &format!("{PW2}\n")
        )
    );
    snap!("passwd", e.vault(&["passwd"], &format!("{PW}\n{PW2}\n")));
    snap!("old_password_fails", e.vault(&["ls"], &pw()));
    snap!(
        "rekey",
        e.vault(&["rekey"], &format!("{PW2}\n{PW}\nI UNDERSTAND\n"))
    );
    snap!("after_rekey", e.vault(&["keyslot", "list"], &pw()));
}

fn flip_byte(path: &Path, at_end: bool) {
    let mut data = fs::read(path).unwrap();
    let i = if at_end { data.len() - 1 } else { 0 };
    data[i] ^= 1;
    fs::write(path, data).unwrap();
}

fn objects(drive: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for fan in fs::read_dir(drive.join("TIJORI/objects"))
        .unwrap()
        .flatten()
    {
        out.extend(
            fs::read_dir(fan.path())
                .unwrap()
                .flatten()
                .map(|e| e.path()),
        );
    }
    out.sort();
    out
}

#[test]
fn error_exit_codes() {
    let e = Env::new();
    e.init();
    e.vault(&["put", &e.path("src/hello.txt"), "/"], &pw());

    // Locked (6): another writer's lock.
    let lock = e.drive().join("TIJORI/.lock");
    fs::write(
        &lock,
        "tijori-lock v1\nlock_id=00\nwriter_id=ff\ntimestamp=4102444800\n",
    )
    .unwrap();
    snap!("locked", e.vault(&["mkdir", "/x"], &pw()));
    snap!("locked_read_still_works", e.vault(&["ls"], &pw()));
    snap!("break_lock_fresh", e.vault(&["break-lock"], ""));
    snap!(
        "break_lock_force",
        e.vault(&["break-lock", "--force"], "BREAK\n")
    );

    // Tampered (3): every object of the tree gets one flipped bit in turn.
    let original: Vec<(PathBuf, Vec<u8>)> = objects(&e.drive())
        .into_iter()
        .map(|p| {
            let d = fs::read(&p).unwrap();
            (p, d)
        })
        .collect();
    let mut verify_out = Vec::new();
    for (p, d) in &original {
        flip_byte(p, true);
        verify_out.push(e.vault(&["verify"], &pw()));
        fs::write(p, d).unwrap();
    }
    // The previous commit's root folder is kept for the older root slot but
    // is not part of the current tree, so damaging it changes nothing.
    let tampered = verify_out
        .iter()
        .filter(|o| o.starts_with("exit: 3"))
        .count();
    let clean = verify_out
        .iter()
        .filter(|o| o.starts_with("exit: 0"))
        .count();
    assert_eq!(
        (tampered, clean),
        (original.len() - 1, 1),
        "{verify_out:#?}"
    );
    let file_case = verify_out
        .iter()
        .find(|o| o.contains("TAMPERED /hello.txt"))
        .unwrap();
    snap!("tampered", file_case.clone());

    // Unsupported (5): a header from a future format.
    let header = e.drive().join("TIJORI/vault.header");
    let good = fs::read(&header).unwrap();
    let mut future = good.clone();
    future[4] = 2;
    fs::write(&header, &future).unwrap();
    fs::write(e.drive().join("TIJORI/vault.header.bak"), &future).unwrap();
    snap!("unsupported", e.vault(&["ls"], &pw()));
    fs::write(&header, &good).unwrap();
    fs::write(e.drive().join("TIJORI/vault.header.bak"), &good).unwrap();

    // Damaged (4): both root pointers gone.
    for slot in ["a", "b"] {
        let _ = fs::remove_file(e.drive().join(format!("TIJORI/vault.root.{slot}")));
    }
    snap!("damaged", e.vault(&["ls"], &pw()));
    snap!("no_vault", e.run(&["--vault", &e.path("src"), "ls"], ""));
}

#[test]
fn shell_session() {
    let e = Env::new();
    e.init();
    let script = format!(
        "{PW}\nput {} /\nls\nmkdir docs\nmv hello.txt docs\nls -l docs\ncat docs/hello.txt\nbogus\nrm docs\nexit\n",
        e.path("src/hello.txt")
    );
    snap!("shell", e.vault(&["shell"], &script));
}

/// The 24 words from `init`'s output, in order.
fn phrase_from(init_output: &str) -> String {
    let mut words = Vec::new();
    for line in init_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for pair in parts.chunks(2) {
            if let [num, word] = pair
                && num.ends_with('.')
                && num[..num.len() - 1].parse::<u32>().is_ok()
            {
                words.push(*word);
            }
        }
    }
    assert_eq!(words.len(), 24, "{init_output}");
    words.join(" ")
}

#[test]
fn unlock_with_recovery_phrase() {
    let e = Env::new();
    let phrase = phrase_from(&e.init());
    snap!(
        "with_recovery",
        e.vault(
            &["--with-recovery", "keyslot", "list"],
            &format!("{phrase}\n")
        )
    );
    // A missing word is caught before any key derivation.
    let short: Vec<&str> = phrase.split(' ').take(23).collect();
    snap!(
        "with_recovery_short",
        e.vault(
            &["--with-recovery", "ls"],
            &format!("{}\n", short.join(" "))
        )
    );
}
