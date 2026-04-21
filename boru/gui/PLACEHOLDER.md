# GUI — Phase 2 Placeholder

> **Do not implement anything here during Phase 1.**

This directory is reserved for BORU's Tauri-based GUI panel, which will be integrated into the MOMO desktop application in Phase 2.

---

## What Goes Here (Phase 2)

- `src-tauri/` — Tauri backend (Rust)
- `src/` — Frontend (React or Svelte, TBD)
- `package.json`

## GUI Panel Features (Planned)

- Live intercept event feed
- Audit log viewer with filters
- Sandbox status indicator
- Policy toggle (strict / permissive)
- Per-session memory/CPU stats
- ZUNO and SABA status panels (Trinity health view)

---

## Phase Lock Reminder

Adding any Tauri dependency to the root `Cargo.toml` during Phase 1 is a **GATE 5 VIOLATION**.

See `AGENTS.md` → GATE 5.