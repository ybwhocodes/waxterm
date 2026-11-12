# Legacy: Bun + shell-SSH implementation

This folder is the previous Waxterm implementation, kept for reference only.
It is **not** part of the current Tauri application.

- `src/` — Bun HTTP server + single-file HTML UI
- `src-rust/` — small Rust helper that spawned the OpenSSH `ssh` binary per command
- `test/` — Bun tests
- `bin/` — CLI launcher

The current app lives at the repository root (`src/` for React, `src-tauri/`
for the Rust backend) and uses `russh` directly, with PTY streaming, TOFU host
key verification, SQLite, and an encrypted vault.
