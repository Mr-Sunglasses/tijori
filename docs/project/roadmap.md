# Roadmap

<p class="tj-lead">Tijori is built in milestones. Each one ends with every test passing in CI and a summary in the <a href="../../progress/">progress log</a>.</p>

## Done

- [x] **Milestone 0: repository and CI.** Workspace, licences, lint and
  supply-chain checks.
- [x] **Milestone 1: cryptography, format and test vectors.** Every format
  structure, checked byte for byte against an independent Python and
  libsodium implementation.
- [x] **Milestone 2: vault engine.** Create, unlock, read, write, commit,
  keyslots, re-key, verify, garbage collection and rollback detection, with
  crash testing at every write.
- [x] **Milestone 3: command line tool.** Every operation as a `tijori`
  command, tested on real exFAT volumes on macOS and Linux.
- [x] **Milestone 4: mounting.** The vault as a folder in Finder or a file
  manager, with Spotlight, Time Machine and Quick Look kept out.
- [x] **Backups.** `tijori backup` and `tijori restore`: incremental,
  verified, safe to interrupt.

## Next

- [ ] **Milestone 5: desktop app** for macOS and Linux (Tauri 2). Drive list,
  create and unlock screens, a vault browser with built-in viewers for
  images, PDFs and text, drag and drop, and a switch between mounting and
  Private mode. Locks the moment the drive is removed.
- [ ] **Milestone 6: Android app** (Kotlin, Jetpack Compose). Opens the same
  vaults over USB OTG, with screenshots blocked on vault screens and locking
  when the app goes to the background.
- [ ] **Milestone 7: hardening and release.** Long fuzzing runs, a
  cross-platform test matrix, performance numbers for large vaults, signed
  and reproducible releases, and an external security review before 1.0.

## Ideas for later

- Tijori's own FSKit extension on macOS, so mounting needs no macFUSE.
- Windows and iOS apps.
- Hardware security keys (a keyslot type is already reserved for FIDO2).

## Not planned

Hidden volumes, cloud sync, sharing a vault between people, compression and
deduplication are deliberately out of scope. Each one either leaks
information about your files or adds a large amount of risky complexity.
