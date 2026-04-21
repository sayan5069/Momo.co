# BORU Protocol Gates

> These gates are BORU's immune system. Every code change must pass all applicable gates before proceeding.
> If any gate fails — **STOP. Explain. Fix. Then proceed.**

---

## How to Use This File

Before writing or merging any code, run through the relevant gates below. Claude Code must check these automatically. Human contributors must check manually.

Gate status: `✅ PASS` | `❌ BLOCK` | `⚠️ REVIEW`

---

## GATE 1 — Zero Bloat Law

**Trigger:** Any new `[dependencies]` entry in `Cargo.toml`

**Rules:**
- [ ] RAM cost of this crate is documented in the PR/commit
- [ ] Crate is `no_std` compatible OR justification is written in commit message
- [ ] Release binary after adding crate is still **< 10MB** (`ls -lh target/release/boru`)
- [ ] Crate does NOT pull in: `tokio` (full), `openssl`, `serde` (all-features), `hyper` (full)

**BLOCK if:** Binary exceeds 10MB or banned transitive deps appear.

```bash
# Check binary size
cargo build --release && ls -lh target/release/boru

# Check dependency tree for banned deps
cargo tree | grep -E "openssl|hyper|tokio-full"
```

---

## GATE 2 — Sandbox Invariant

**Trigger:** Any code that runs, evaluates, or executes external input

**Rules:**
- [ ] All execution paths originate from `src/cage/`
- [ ] No `std::process::Command`, `exec()`, or raw syscall appears **outside** `src/intercept/`
- [ ] WASM sandbox is initialized before any payload reaches execution

**BLOCK if:** Any execution call exists outside `cage/` or `intercept/` modules.

```bash
# Scan for banned patterns outside allowed modules
grep -rn "Command::new\|std::process::Command\|libc::exec" src/ \
  --exclude-dir=cage --exclude-dir=intercept
# Result must be empty
```

---

## GATE 3 — Socket Contract Freeze

**Trigger:** Any change to `src/socket/` or `/tmp/momo/` path strings

**Rules:**
- [ ] BORU socket path is exactly: `/tmp/momo/boru.sock`
- [ ] ZUNO socket path stub is exactly: `/tmp/momo/zuno.sock`
- [ ] SABA socket path stub is exactly: `/tmp/momo/saba.sock`
- [ ] No socket paths are hardcoded outside `src/socket/config.rs`

**BLOCK if:** Socket paths change or appear as string literals outside the config file.

```bash
# Find hardcoded socket paths outside config
grep -rn "\.sock" src/ | grep -v "src/socket/config.rs"
# Result must be empty
```

---

## GATE 4 — No Network Calls

**Trigger:** Any new async code, HTTP client, or external connection

**Rules:**
- [ ] No `reqwest`, `hyper`, `ureq`, or any HTTP client crate added
- [ ] No TCP `bind()` or `connect()` outside `// MOMO-NETWORK-ALLOWED` zones
- [ ] BORU communicates only via Unix sockets

**BLOCK if:** Any network-capable crate appears in `Cargo.toml`.

```bash
# Scan for network crates
grep -E "reqwest|hyper|ureq|surf|isahc" Cargo.toml Cargo.lock
# Result must be empty
```

---

## GATE 5 — Phase Lock

**Trigger:** Any new dependency or file in `gui/` or Tauri-related code

**Rules:**
- [ ] Phase 1 code contains **zero** Tauri dependencies
- [ ] `gui/` directory contains only `PLACEHOLDER.md` during Phase 1
- [ ] Ratatui TUI code lives exclusively in `src/tui/`
- [ ] No TUI rendering code appears in `src/cage/`, `src/intercept/`, or `src/socket/`

**BLOCK if:** Tauri deps appear in Phase 1 or TUI code bleeds into non-TUI modules.

```bash
# Check for Tauri in Phase 1
grep -i "tauri" Cargo.toml
# Result must be empty during Phase 1
```

---

## GATE 6 — Memory Budget

**Trigger:** Any new feature, data structure, or background task

**Rules:**
- [ ] BORU idle RSS stays **< 20MB** (measure after feature is running)
- [ ] No unbounded `Vec`, `HashMap`, or channel buffers without explicit capacity limits
- [ ] Audit log uses ring buffer (max 10,000 entries) — no unbounded growth

**Measure:**
```bash
# Run BORU daemon, then check RSS
./target/release/boru daemon &
sleep 2
ps aux | grep boru | awk '{print $6}' # RSS in KB, must be < 20480
```

---

## GATE 7 — Intercept Audit Log

**Trigger:** Any change to `src/intercept/` or any new intercept rule

**Rules:**
- [ ] Every blocked action writes to audit log **before** returning verdict
- [ ] Log format: `[TIMESTAMP] [SEVERITY] [ACTION_BLOCKED] [REASON]`
- [ ] Severity levels: `CRITICAL | HIGH | MEDIUM | LOW`
- [ ] No intercept path exists that returns `BLOCKED` without logging

**BLOCK if:** Any intercept fires without a corresponding audit log write.

```rust
// Correct pattern — log BEFORE return
pub fn intercept(&self, event: &Event) -> Verdict {
    let verdict = self.policy.evaluate(event);
    if verdict == Verdict::Blocked {
        self.audit.record(event, &verdict); // MUST happen
    }
    verdict
}
```

---

## Gate Checklist Template

Copy this into your PR description or commit message:

```
## Gate Checklist
- [ ] GATE 1: Zero Bloat Law — binary size: ___MB
- [ ] GATE 2: Sandbox Invariant — no bare exec outside cage/
- [ ] GATE 3: Socket Contract — paths unchanged
- [ ] GATE 4: No Network Calls — no HTTP crates
- [ ] GATE 5: Phase Lock — no Tauri in Phase 1
- [ ] GATE 6: Memory Budget — idle RSS: ___KB
- [ ] GATE 7: Audit Log — all intercepts logged
```