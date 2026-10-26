<p align="center">
  <img src="assets/icon.svg" alt="Tijori icon: a brass strongbox with a combination dial" width="160" height="160">
</p>

<h1 align="center">Tijori</h1>

<p align="center">
  <em>Turn any USB pen drive into a strongly encrypted vault that opens on macOS, Linux and Android.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-pre--alpha-red" alt="Status: pre-alpha">
  <img src="https://img.shields.io/badge/licence-Apache--2.0%20%2F%20GPL--3.0-blue" alt="Licence: Apache-2.0 / GPL-3.0-or-later">
</p>

---

> [!WARNING]
> **Pre-alpha. Do not trust Tijori with real data yet.**
> The format and code have not been audited, and nothing here is stable.

*Tijori* (तिजोरी) is Hindi for "strongbox". Install the app, plug in the drive,
enter your password, and your files are there. Unplug it, and they are not.

## What it does

- **Strong encryption.** Argon2id password hashing, XChaCha20-Poly1305 for every
  file, folder and file name. Built on libsodium-compatible primitives only.
- **Hides structure.** File names, folder layout and (by default) exact file
  sizes are encrypted or padded.
- **Crash safe.** Copy-on-write commits: pull the drive out at any moment and the
  vault opens at either the old or the new state, never a broken mix.
- **Several ways in.** Password, password + keyfile, and a 24-word recovery
  phrase.
- **Works everywhere you need it.** The drive stays exFAT, so the same vault
  opens on macOS, Linux and Android.
- **Two ways to use it.** Mount the vault as a folder in Finder or your file
  manager, or keep everything inside the app (Private mode). On macOS,
  mounting needs [macFUSE](https://macfuse.github.io) 5; Private mode needs
  nothing extra.
- **No network.** No telemetry, no accounts, no cloud. Free and open source.

## Platforms

| Platform | Status | Technology |
|---|---|---|
| macOS | Planned for v1 | Tauri 2 desktop app + `tijori` CLI |
| Linux | Planned for v1 | Tauri 2 desktop app + `tijori` CLI |
| Android | Planned for v1 | Kotlin + Jetpack Compose, Rust core via UniFFI |
| Windows | Later | — |
| iOS | Future | — |

## Repository layout

| Path | What | Licence |
|---|---|---|
| [`spec/`](spec/SPEC.md) | Vault format specification and test vectors | Apache-2.0 |
| `core/` | `tijori-core`: crypto, format and vault engine (Rust) | Apache-2.0 |
| `ffi/` | `tijori-ffi`: UniFFI bindings for Kotlin | Apache-2.0 |
| `cli/` | `tijori` command-line tool | GPL-3.0-or-later |
| `mount/` | `tijori-mount`: FUSE filesystem with host hardening | GPL-3.0-or-later |
| `desktop/` | Tauri 2 desktop app (React + TypeScript) | GPL-3.0-or-later |
| `android/` | Android app (Kotlin) | GPL-3.0-or-later |
| `fuzz/` | `cargo-fuzz` targets | Apache-2.0 |

The build plan lives in [`Plan.md`](Plan.md); progress is tracked in
[`docs/progress.md`](docs/progress.md).

## Building

You need [rustup](https://rustup.rs). The toolchain is pinned in
`rust-toolchain.toml` and is installed automatically.

```sh
cargo build --workspace
cargo test --workspace
```

## Security

Please report vulnerabilities privately; see [`SECURITY.md`](SECURITY.md).

## Licence

Tijori is free and open source:

- `spec/`, `core/`, `ffi/` and `fuzz/` are licensed under the
  [Apache License 2.0](LICENSE-APACHE).
- `cli/`, `mount/`, `desktop/` and `android/` are licensed under the
  [GNU General Public License v3.0 or later](LICENSE-GPL).

Contributions are accepted under the licence of the directory they touch; see
[`CONTRIBUTING.md`](CONTRIBUTING.md).
