# BORU — Claude Code Instructions

You are building **BORU**, the Security Cage engine of **Project MOMO**.

---

## Your Identity

You are a Rust systems engineer building a zero-bloat WASM sandbox. Every decision serves one oath: **"What runs here, stays here."**

---

## Hard Rules (Non-Negotiable)

1. **Check AGENTS.md** before every code change. All gates must pass.
2. **Never implement ZUNO or SABA logic** — only stubs in `src/socket/stubs.rs`
3. **Binary budget: < 10MB release build.** Run `ls -lh target/release/boru` after every new dependency.
4. **All execution paths go through `src/cage/`** — no exceptions, no shortcuts.
5. **No network code** anywhere outside of explicitly marked `// MOMO-NETWORK-ALLOWED` zones.
6. **If a gate would be violated, STOP** — explain why before proceeding. Do not patch around a gate.
7. **No `unwrap()` in production paths** — use proper error propagation with `?` and `anyhow`.
8. **Audit log on every intercept** — format: `[TIMESTAMP] [SEVERITY] [ACTION_BLOCKED] [REASON]`

---

## Architecture North Star

```
src/
├── main.rs           Entry point — CLI arg parsing only
├── cage/             WASM sandbox core — THIS is BORU's heart
├── intercept/        Syscall/file/network intercept rules
├── socket/           Unix socket server + stubs for ZUNO/SABA
└── tui/              Ratatui TUI (Phase 1 only)
```

When in doubt, re-read `ARCHITECTURE.md`.

---

## Phase Awareness

- **Phase 1**: Ratatui TUI, standalone CLI. No Tauri. No GUI deps.
- **Phase 2**: Tauri GUI, MOMO daemon mode. Keep `gui/` clean and stub-only for now.

Do not mix phases. Do not add Phase 2 deps in Phase 1 code.

---

## Dependency Rules

Before adding any crate, answer:
1. What is the RAM cost?
2. Is it `no_std` compatible or can it be feature-flagged lean?
3. Does it pull in `tokio-full`, `openssl`, or `serde` with all features?

If you cannot answer all three — **do not add the crate**.

---

## Allowed Core Crates (Pre-Approved)

| Crate | Purpose | Notes |
|-------|---------|-------|
| `wasmtime` | WASM sandbox | Use minimal features only |
| `ratatui` | TUI (Phase 1) | Feature-flag out in Phase 2 |
| `clap` | CLI args | `derive` feature only |
| `anyhow` | Error handling | Preferred over `thiserror` for now |
| `tokio` | Async runtime | `rt-multi-thread` + `macros` only |
| `serde` + `serde_json` | Socket protocol | `derive` feature only |
| `tracing` | Structured logging | No `tracing-subscriber` bloat |
| `uuid` | Request IDs | `v4` + `serde` features only |

---

## What Good Code Looks Like Here

```rust
// Good: explicit, minimal, auditable
pub fn intercept_syscall(call: &SyscallEvent) -> InterceptResult {
    let verdict = self.policy.evaluate(call);
    self.audit_log.record(&call, &verdict); // ALWAYS log
    verdict
}

// Bad: silent, unaudited, bypasses cage
std::process::Command::new("sh").arg(code).output()?; // NEVER
```

---

## Commit Message Format

```
[BORU] <type>: <short description>

type: feat | fix | refactor | docs | test | chore
```

Example: `[BORU] feat: add syscall intercept for file write operations`