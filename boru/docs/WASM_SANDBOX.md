# BORU WASM Sandbox Design

---

## Why WASM?

WebAssembly gives BORU a capability-based security model for free:
- Code runs in a sandboxed linear memory — cannot access host memory
- Host functions are explicitly imported — nothing is available unless BORU grants it
- WASI (WebAssembly System Interface) controls all OS interaction
- `wasmtime` is a production-grade, audited Rust runtime

This is stricter than container isolation and lighter than a VM.

---

## Sandbox Architecture

```
AI-generated code
       │
       ▼
  [Compiler / WAT]
       │
       ▼
  WASM binary
       │
       ▼
┌─────────────────────────────────┐
│         wasmtime Engine         │
│  ┌───────────────────────────┐  │
│  │     WASM Module           │  │
│  │   (sandboxed memory)      │  │
│  └────────────┬──────────────┘  │
│               │ WASI calls      │
│  ┌────────────▼──────────────┐  │
│  │     BORU Intercept Layer  │  │  ← BORU checks every host call here
│  │   (capability policy)     │  │
│  └────────────┬──────────────┘  │
└───────────────┼─────────────────┘
                │ ALLOWED only
                ▼
         Host OS (minimal)
```

---

## wasmtime Configuration

```rust
// Minimal wasmtime config — only what BORU needs
let mut config = wasmtime::Config::new();
config
    .wasm_memory64(false)          // No 64-bit memory
    .wasm_threads(false)           // No shared memory threads
    .wasm_simd(false)              // No SIMD (attack surface)
    .consume_fuel(true)            // CPU budget enforcement
    .max_wasm_stack(1 << 20);      // 1MB stack limit

let engine = Engine::new(&config)?;
```

---

## WASI Capability Policy

BORU uses a strict deny-by-default WASI policy.

### Granted Capabilities
```rust
// Only these are ever allowed
let mut wasi = WasiCtxBuilder::new()
    .inherit_stdout()                    // Can write to stdout (captured by BORU)
    .inherit_stderr()                    // Can write to stderr (captured by BORU)
    .preopened_dir(                      // Only sandbox workspace
        workspace_dir,
        "/sandbox",
        DirPerms::READ | DirPerms::WRITE,
        FilePerms::READ | FilePerms::WRITE
    )?
    .build();
```

### Denied Capabilities (never granted)
- Network socket creation
- Access to host filesystem outside `/sandbox`
- Environment variable inheritance (except explicit allowlist)
- Process spawning
- Random number generation from host (use WASM-level PRNG)

---

## Fuel System (CPU Budget)

Every sandboxed execution gets a fuel budget to prevent infinite loops and DoS.

```rust
// Default fuel budget
const DEFAULT_FUEL: u64 = 1_000_000_000; // ~1 billion WASM instructions

store.add_fuel(DEFAULT_FUEL)?;
// If fuel runs out → wasmtime returns Trap::OutOfFuel
// BORU treats this as BLOCKED with reason "CPU_BUDGET_EXCEEDED"
```

---

## Memory Limits

```rust
// Hard cap on WASM linear memory
const MAX_WASM_MEMORY: u64 = 64 * 1024 * 1024; // 64MB hard ceiling

// Set via wasmtime MemoryType limits
let memory_type = MemoryType::new(1, Some(1024)); // min 64KB, max 64MB (1024 pages)
```

---

## Intercept Flow

```
WASM syscall attempt
        │
        ▼
InterceptLayer::evaluate(event)
        │
        ├── matches BLOCK rule? ──► AuditLog::record(BLOCKED) ──► return Verdict::Blocked
        │
        └── passes all rules?  ──► AuditLog::record(ALLOWED) ──► return Verdict::Allowed
```

All paths write to audit log. No silent verdicts.

---

## Shell Command Sandboxing (Non-WASM)

For shell commands that cannot be compiled to WASM (Phase 1 fallback):

BORU uses a static analysis pass before execution:
1. Parse command with `shellwords`
2. Check against blocklist (rm -rf, curl, wget, nc, python, etc.)
3. If clean → wrap in `bubblewrap` or `unshare` namespace
4. If blocked → BLOCKED verdict + audit log

This is a **weaker** guarantee than WASM. BORU TUI will display a warning for shell mode.

---

## Crates Used

| Crate | Version | Purpose |
|-------|---------|---------|
| `wasmtime` | latest | WASM runtime + WASI |
| `wasmtime-wasi` | latest | WASI capability model |
| `cap-std` | latest | Capability-based FS access |

Feature flags (keep minimal):
```toml
wasmtime = { version = "x", default-features = false, features = ["cranelift", "runtime"] }
wasmtime-wasi = { version = "x", default-features = false }
```