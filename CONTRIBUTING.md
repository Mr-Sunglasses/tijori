# Contributing to Tijori

Thank you for helping. Tijori protects people's private files, so the rules
below are strict on purpose.

## Ground rules

1. **The spec wins.** [`spec/SPEC.md`](spec/SPEC.md) defines the on-disk format.
   If code and spec disagree, the code is wrong. A spec change is proposed in an
   issue first, then lands in the same commit as the matching test vectors.
2. **No new cryptography.** Use only the primitives and constructions in the
   spec. If something seems to need a new construction, open an issue instead.
3. **Tests first in `core/`.** Every format and crypto function gets unit tests,
   property tests (`proptest`) and test-vector tests before anything else uses it.
4. **No `unsafe` in `core/`** (it is `#![forbid(unsafe_code)]`). Elsewhere,
   `unsafe` is allowed only where a dependency requires it, with a
   `// SAFETY:` comment.
5. **Secrets hygiene.** Keys, passwords, keyfile bytes and buffers holding keys
   use `zeroize` / `secrecy` types. Never log, print, `Debug`-format or
   serialize a secret. Keys never leave Rust: the desktop frontend and Kotlin
   code receive file lists, contents and status only.
6. **No network access.** No crate, app or script may contact the network at
   runtime. No telemetry and no update checks.
7. **Security bugs go to [`SECURITY.md`](SECURITY.md)**, not to public issues.

## Before you open a pull request

Run the same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo deny --locked check     # cargo install --locked cargo-deny
cargo audit --deny warnings   # cargo install --locked cargo-audit
```

## Commits

Small, reviewable commits with one logical change each, using
[Conventional Commits](https://www.conventionalcommits.org/):

```
feat(core): parse keyslot table
test(core): add header MAC vectors
fix(cli): reject empty keyfile
```

Scopes: `spec`, `core`, `cli`, `mount`, `ffi`, `desktop`, `android`, `fuzz`, `ci`.

## Licensing of contributions

Each directory has its own licence (see the table in [`README.md`](README.md)).
By contributing, you agree that your contribution is licensed under the licence
of the directory it changes: Apache-2.0 for `spec/`, `core/`, `ffi/` and
`fuzz/`; GPL-3.0-or-later for `cli/`, `mount/`, `desktop/` and `android/`.
