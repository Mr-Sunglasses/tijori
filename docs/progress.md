# Progress

## Milestone 0 — Repository and CI (2026-10-26)

**Status:** done. CI green on GitHub (private repo `Mr-Sunglasses/tijori`).

- Cargo workspace (edition 2024, resolver 3) with placeholder crates:
  `tijori-core` (`#![forbid(unsafe_code)]`), `tijori-cli` (binary `tijori`),
  `tijori-mount`, `tijori-ffi`, `tijori-desktop` (`desktop/src-tauri`).
  All crates have `publish = false` and a per-crate licence per Plan §1.
- Placeholder folders: `spec/vectors/`, `spec/generator/`, `desktop/src/`,
  `android/app/`, `android/tijori-core-bindings/`, `fuzz/`.
- `spec/SPEC.md`: Appendix A of `Plan.md`, copied verbatim.
- Licences (`LICENSE-APACHE`, `LICENSE-GPL`, official texts), `README.md` with
  the project icon (`assets/icon.svg`), `SECURITY.md`, `CONTRIBUTING.md`.
- Toolchain pinned to Rust 1.99.0 with `rustfmt` and `clippy`; `rustfmt.toml`.
- Workspace lints: `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks`
  (enforces `// SAFETY:` comments) and `clippy::dbg_macro` all deny.
- `deny.toml`: permissive dependency licences only, crates.io as the only
  source, and HTTP client crates banned (Plan §0 rule 7).
- GitHub Actions (`.github/workflows/ci.yml`): `lint` (fmt, clippy `-D warnings`),
  `test` on `ubuntu-latest` and `macos-latest`, `supply chain` (`cargo deny`,
  `cargo audit`); also runs daily for new advisories.

**Verified locally (macOS, Rust 1.99.0):** `cargo fmt --check`, `cargo clippy
-D warnings`, `cargo test --workspace --locked`, `cargo deny check`,
`cargo audit --deny warnings` and `actionlint` all pass.

**Deferred on purpose**
- The `tauri`, `uniffi`, `fuser` and `clap` dependencies are added in the
  milestones that use them (5, 6, 4, 3), so CI stays dependency-free until then.
- Frontend lint (`eslint`, `tsc`), `npm audit`, fuzz smoke, Android, e2e and
  vector-regeneration CI jobs are added together with their code (Plan §7).

## Milestone 1 — Crypto, format and test vectors (2026-10-26)

**Status:** done.

- `spec/generator/gen.py`: an independent Python implementation (PyNaCl /
  libsodium, `hashlib`, `cbor2`, `mnemonic`) that writes every vector file in
  Appendix A §15, with negative cases and their error classes. CI regenerates
  the deterministic files with PyNaCl and fails on any difference.
- `core/crypto`: typed wrappers over `dryoc` 2.0 (Argon2id, XChaCha20-Poly1305,
  secretstream, BLAKE2b, KDF, CSPRNG). Keys are zeroized newtypes without
  `Debug`/`Clone`; session keys sit in `mlock`ed, guard-paged memory
  (`dryoc::protected`, plus `MADV_DONTDUMP` on Linux), with a zeroizing heap
  fallback when the locked-memory limit is hit.
- `core/format`: header, keyslot, root pointer, directory and object codecs,
  all enforcing §12 limits before allocating or running Argon2id. Objects
  stream in 64 KiB chunks in both directions.
- `padding.rs` (Padmé), `names.rs`, `recovery.rs` (BIP-39), `strength.rs` (zxcvbn).
- Fuzz targets: `header`, `root_pointer`, `dir_cbor`, `object_stream`. The
  last two have a second mode that seals fuzzed plaintext under a fixed key, so
  the fuzzer reaches the parsers behind the AEAD.

**Acceptance**
- Every vector passes, including all negative cases with the exact class.
  `dryoc` matches libsodium for every primitive.
- Property tests: object round trips for random sizes 0–1 MiB plus every chunk
  boundary (0, 1, 65 527 … 131 073); Padmé ≤ 11.7% overhead, monotonic,
  idempotent; CBOR encode/decode round trip; decoder never panics.
- Each fuzz target ran 10 minutes locally (≈ 29 million runs in total), no crashes.

**Decisions to review**
- **CBOR:** a small strict codec of our own instead of `ciborium`. Rejecting
  non-shortest integers, unsorted keys and the like needs the raw encoding,
  which `ciborium` does not expose; the codec is ~300 lines, property-tested
  and fuzzed. Readers also reject unsorted map keys (deterministic CBOR, §1).
- **Error classes** where the spec leaves room (also in `spec/vectors/README.md`):
  failed authentication, truncation and extension are `tampered`; bad
  structure inside authenticated data (bad CBOR, non-zero padding, unexpected
  stream tag, missing field) and out-of-range parameters are `damaged`.
- **Settings label is required** in the root pointer (both writers always
  write it), so that accepted CBOR always re-encodes to the same bytes.
- **Version bytes:** a root pointer or object version above 1 is
  `unsupported` (refuse, never fall back to an older slot, which a newer
  writer might then lose). Version 0 never existed, so it counts as damage.
- Empty keyslots are recognised by `slot_type = 0` alone; their other bytes
  are covered by the header MAC rather than rejected while parsing.

## Milestone 2 — Vault engine (2026-10-26)

**Status:** done.

- `storage/`: the `Storage` trait, `StdFsStorage` (tmp → fsync → rename →
  fsync folder, delete-then-rename fallback) and `MemStorage` with crash
  injection (fail, tear or delete the N-th write, then power loss).
- `vault/`: create (Argon2id calibration to ≈ 1 s, password + recovery slots,
  README), unlock exactly per §6 with backup-header fallback and repair, A/B
  root selection, lazy copy-on-write folder tree, batched `commit`, write lock
  with refresh, keyslot add/replace/remove, password change, re-key, verify,
  GC over both root slots, best-effort timestamp neutralisation.
- `rollback.rs`: §10 comparison, in-memory and encrypted-file stores.
  `host.rs` (feature `host`): data folder, device writer ID, record key in the
  OS keychain via `keyring` (file fallback with a warning).

**Acceptance** (`core/tests/vault.rs`)
- Crash tests: for every write of a multi-file commit followed by GC, a
  failed, torn or deleted write leaves a vault that opens at the old or new
  state and verifies. The same holds for every write of a re-key.
- Tamper tests: flipping any byte of any file (every byte of small files,
  edges plus a stride for large ones) never yields wrong plaintext: unlock
  fails with `tampered`/`wrong_secret`, reading fails with `tampered`, or the
  backup header / older root slot takes over with identical content. Flipping
  both header copies is always rejected.
- Swap tests: swapped objects → `tampered`; swapped root slots → `damaged`
  (spec §6 step 6); a replayed old root slot and a restored drive → rollback
  warning, read-only until the user accepts; forks detected.
- Lock tests: a second writer opens read-only and names the holder; after the
  first releases, it gains write access and builds on the first one's commit.
- The Python generator's sample vaults (including the torn newest root slot)
  open with both password and recovery phrase.
- 2 GiB import + export in 14 s (release) with 76 MiB peak RSS, of which
  64 MiB is the Argon2id run at creation: memory use is flat.

**Decisions to review**
- **`Storage` is rooted at the drive root**, not `TIJORI/`, so `create` can
  write `README-TIJORI.txt` next to the vault folder. Android's tree picker
  returns the drive root too.
- **File reads hash the whole object first** (§8.2: verify the hash before
  decrypting), then decrypt in a second pass. This doubles read I/O for files.
- **GC is explicit** (`tijori gc`, after re-key), not run at every unlock, so
  unlocking stays fast on large vaults.
- **Re-key keeps the vault UUID** (rollback records continue) and needs the
  caller to supply every slot to keep, since other slots' secrets are unknown.
- **Dropped crates:** `directories` (its `option-ext` dependency is MPL-2.0)
  in favour of two known paths; `ciborium` (see Milestone 1).
- **Ignored advisories:** RUSTSEC-2026-0370/0371/0372 (`zvariant`,
  `zbus_names`, `zvariant_derive` marked unmaintained after being merged into
  `zbus`), reached only through `keyring`'s Linux Secret Service store. Not
  vulnerabilities; revisit when `keyring` updates.

## Milestone 3 — CLI (2026-10-26)

**Status:** done, except the optional `tijori format` (not implemented, see below).

- `tijori` with `init`, `shell`, `ls [-l]`, `put`, `get`, `mkdir [-p]`, `mv`,
  `rm [-r]`, `cat`, `passwd`, `keyslot list|add|add --keyfile|add --recovery|remove`,
  `rekey`, `verify`, `gc`, `info`, `settings`, plus `break-lock`.
- Global options: `--vault` (drive or its `TIJORI` folder; auto-detected when
  exactly one vault is mounted under `/Volumes`, `/media/$USER`,
  `/run/media/$USER`, `/media` or `/mnt`), `--with-recovery`,
  `--with-keyfile`, `--password-stdin` (for scripts; passwords are never
  echoed or passed as arguments).
- Read commands open read-only and never take the lock; write commands take
  it and commit once. Exit codes as in the plan.
- `init` prints the phrase as 6 rows of 4 numbered words with the warning and
  waits for `I UNDERSTAND`. New passwords below zxcvbn score 3 are refused
  with the reason and the 6-word passphrase tip.
- `get` never overwrites: clashing names (including case-only clashes on
  case-insensitive folders) get a visible ` (n)` suffix; partial exports are
  deleted on error. `put` skips symlinks and special files with a warning.

**Acceptance**
- `insta` snapshots for every command, every exit code (2 wrong secret,
  3 tampered, 4 damaged, 5 unsupported, 6 locked), the shell and the help.
- `scripts/e2e.sh` creates a real exFAT volume (hdiutil image on macOS, loop
  image on Linux), runs every command, checks round trips byte for byte, the
  executable bit, unplug/replug, re-key revoking the old recovery phrase,
  tamper detection and timestamp neutralisation (vault files show year 2000).
  Passes locally on macOS; runs in CI on macOS and Ubuntu.

**Found by e2e:** macOS writes AppleDouble `._*` files on exFAT (for example
`TIJORI/objects/._07`). GC now looks only at two-hex-digit fan-out folders and
deletes `._*` files inside `TIJORI/`.

**Decisions to review**
- `TIJORI_TEST_FAST_KDF=1` makes new slots use the minimum Argon2id
  parameters (with a loud warning). Tests and e2e only.
- `tijori format <device>` (optional in the plan) is **not implemented**. It
  is destructive and cannot be tested safely here; it needs your go-ahead and
  real hardware to test against.
- `keyslot add --recovery` keeps the plan's name; the global "unlock with the
  recovery phrase" flag is therefore `--with-recovery`.

## Milestone 4 — Mount (FUSE) (2026-10-26)

**Status:** done. Backend decision: macFUSE 5 with its FSKit backend on macOS
(see `docs/macos-fuse.md`), `fuser` on Linux.

- `mount/src/fs.rs`: the file system, shared by both platforms and
  path-based over the `Vault` API. Writes are buffered in memory (never on the
  host disk) and encrypted on flush/close. Commits are coalesced to at most
  one every 2 s, plus one at unmount. `._*`, `.DS_Store` and
  `.metadata_never_index` cannot be created. Extended attributes are accepted
  and discarded (spec §11). Owner-only modes (0700/0600).
- `mount/src/linux.rs`: `fuser` 0.18 with its pure-Rust mount (no libfuse
  needed at build time), mounted under `$XDG_RUNTIME_DIR/tijori/<label>`
  (mode 0700), `default_permissions`, no `allow_other`.
- `mount/src/macos.rs` + `macos_shim.c`: libfuse 3 high-level API. All
  libfuse structs stay in C, compiled against macFUSE's headers. libfuse3 is
  loaded with `dlopen`, so Tijori starts without macFUSE and reports that it
  is missing. Mounts with `backend=fskit` under `/Volumes/<label>`, adds a
  `.metadata_never_index` file and turns Spotlight off (both checked
  afterwards), and clears the Quick Look cache after unmount.
- Supervisor: unmounts and locks on request (`Stopper`, for the desktop app's
  sleep, screen-lock and logout events), on SIGINT/SIGTERM in the CLI, on
  eject, when the drive disappears, and after the idle timeout (default 15 min).
  Mounts are refused for vaults set to private-only, and opened read-only when
  another writer holds the lock.
- CLI: `tijori mount [DRIVE] [MOUNTPOINT] [--idle-minutes N]`.

**Acceptance**
- `scripts/mount-test.sh` runs ordinary tools against the mounted volume:
  write, append, read, `cp` of a 3 MB file, rename, `rm -r`, refusal of
  `._*`/`.DS_Store`, `df`, owner-only modes. Then unmount on signal (vault
  verifies, content persisted), external eject, and removal of the drive
  while mounted (the vault then unlocks and verifies).
  - macOS 27 + macFUSE 5.4 (FSKit): passes, locally and on a real USB stick
    (exFAT, the user's Ventoy drive; only Tijori's own files were created and
    then removed).
  - Linux (Debian, fuse3, in Docker): passes; also runs in CI on Ubuntu.
- Spotlight: after mounting, a file with a unique word could not be found
  by name or content (`mdfind`) after 45 s; `mdutil -s` reports indexing
  disabled. Time Machine reports the volume as excluded.
- Real-drive CLI session (release build, real Argon2id 256 MiB, t=5 on this
  Mac): unlock + list 0.7 s, 50 MB in 6.5 s (the stick's write speed),
  out in 0.9 s, byte-identical, verify clean.

**Found and fixed while testing**
- macOS: `fuse_mount` reports success before FSKit has actually mounted (or
  refused). The mount now waits until the mount point is live, and explains
  how to enable the file system extension if it never appears.
- macOS: calling `fuse_exit` before `umount` deadlocks FSKit's unmount. The
  loop now keeps serving while the volume unmounts, with `fuse_exit` as a
  last resort and timeouts on every external command.
- `cp` failed on macFUSE because it copies extended attributes; they are now
  accepted and discarded.
- `tijori --vault D mount P` treated `P` as the drive.

**Known limits (for `docs/threat-model.md` in Milestone 7)**
- macOS tags every file a process writes with `com.apple.provenance`. On
  exFAT this lands in `._*` files beside vault files and identifies the app
  that wrote them. Processes cannot remove the tag. GC deletes the `._*`
  files inside `TIJORI/`, but new writes recreate them.
- Large files are edited in memory (limit 1 GiB per open-for-write file);
  reads of files over 16 MiB stream and seek forward only, reopening to go back.
- Mount mode on macOS needs macFUSE 5 and a one-time "File System Extensions"
  switch. Private mode needs nothing. Proposed for v1.1: our own FSKit
  extension instead of macFUSE (needs an Apple Developer ID).
