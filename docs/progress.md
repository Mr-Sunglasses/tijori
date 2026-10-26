# Progress

## Milestone 0 — Repository and CI (2026-10-26)

**Status:** done locally; waiting for the first CI run on GitHub.

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
