# Changelog

All notable changes to BORU are documented here.

Format: [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [Unreleased]

### Added
- Initial repository scaffold
- Trinity socket contract stubs (`/tmp/momo/boru.sock`, `/tmp/momo/zuno.sock`, `/tmp/momo/saba.sock`)
- Protocol gates (AGENTS.md) — 7 gates defined
- CLAUDE.md agent instructions
- Architecture documentation

---

## [0.1.0] — TBD

### Planned
- WASM sandbox core (`src/cage/`)
- Syscall intercept layer (`src/intercept/`)
- Unix socket server (`src/socket/`)
- Ratatui TUI dashboard (`src/tui/`)
- Audit log with ring buffer
- CLI: `boru cage --input <file>`
- CLI: `boru daemon` (socket mode)