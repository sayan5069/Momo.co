# Contributing to BORU

BORU is part of Project MOMO — a local-first, zero-bloat AI development suite.

---

## Before You Contribute

Read these first. In order.

1. `README.md` — understand what BORU is
2. `ARCHITECTURE.md` — understand where BORU sits in the Trinity
3. `AGENTS.md` — understand the 7 Protocol Gates
4. `CLAUDE.md` — understand the coding standards

---

## Development Setup

```bash
# Prerequisites
rustup update stable
cargo --version  # 1.75+

# Clone and build
git clone https://github.com/sayan5069/boru
cd boru
cargo build

# Run tests
cargo test

# Check binary size (must be < 10MB release)
cargo build --release && ls -lh target/release/boru
```

---

## Contribution Rules

### Code Standards
- No `unwrap()` in production paths — use `?` and `anyhow`
- Every intercept must write to audit log before returning
- No execution code outside `src/cage/` and `src/intercept/`
- Run `cargo clippy -- -D warnings` before submitting — zero warnings

### Commit Format
```
[BORU] <type>: <short description>

type: feat | fix | refactor | docs | test | chore
```

### Pull Request Checklist
Every PR must include the Gate Checklist from `AGENTS.md`:
- Binary size measured
- All 7 gates checked
- `cargo test` passes
- `cargo clippy` clean

---

## What We Don't Accept

- Dependencies that add network capability
- Tauri/GUI code during Phase 1
- Code that bypasses the WASM sandbox
- Hardcoded socket paths outside `src/socket/config.rs`
- ZUNO or SABA logic (stubs only)

---

## Questions

Open an issue or discuss in the MOMO project channel.