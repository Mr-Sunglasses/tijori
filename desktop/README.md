# Tijori desktop app

Tauri 2 app for macOS and Linux.

- `src-tauri/`: Rust backend (commands, session, drive watcher, RAM disk). All
  crypto stays here.
- `src/`: React + TypeScript UI. Never receives keys.

Implemented in Milestone 5; for now `src-tauri/` is a placeholder crate.
