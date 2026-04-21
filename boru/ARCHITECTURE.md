# BORU Architecture

## Trinity Overview

Project MOMO is powered by three engines communicating over local Unix sockets. No network. No cloud. No leaks.

```
UI / CLI
   │
   └──► SABA  (Go router)          /tmp/momo/saba.sock   [NOT YET IMPLEMENTED]
           │
           ├──► ZUNO  (Rust indexer)    /tmp/momo/zuno.sock   [NOT YET IMPLEMENTED]
           │         context retrieval
           │
           └──► BORU  (Rust cage)       /tmp/momo/boru.sock   [ACTIVE]
                       sandboxed execution
                            │
                            └──► Ollama  localhost:11434
```

---

## BORU's Role

BORU is the **Security Cage**. Every piece of AI-generated code that needs execution passes through BORU first.

### Responsibilities
- Accept execution requests over Unix socket
- Load the code/binary into a WASM sandbox (wasmtime)
- Apply intercept rules (syscall, file, network)
- Return: `ALLOWED` or `BLOCKED` + audit log entry
- Never pass execution to the OS without sandbox clearance

### What BORU Does NOT Do
- Route requests (that's SABA)
- Index code (that's ZUNO)
- Talk to Ollama directly (SABA handles that)
- Make network calls (ever)

---

## Socket Contract

### BORU Socket — `/tmp/momo/boru.sock`

**Request format (JSON over Unix socket):**
```json
{
  "request_id": "uuid-v4",
  "type": "execute",
  "payload": {
    "code": "base64-encoded WASM or shell",
    "format": "wasm | shell",
    "policy": "strict | permissive"
  }
}
```

**Response format:**
```json
{
  "request_id": "uuid-v4",
  "verdict": "ALLOWED | BLOCKED",
  "reason": "string or null",
  "audit_ref": "log entry id"
}
```

---

## Reserved Sockets (Stubs — Do Not Implement Yet)

```rust
// ZUNO: context will arrive here
// Socket: /tmp/momo/zuno.sock
// Expected payload: { "query": "...", "project_path": "..." }
// Expected response: { "context": [...], "token_count": N }

// SABA: execution requests route through this
// Socket: /tmp/momo/saba.sock  
// Expected payload: { "prompt": "...", "context": [...], "model": "..." }
// Expected response: { "code": "...", "explanation": "..." }
```

These stubs live in `src/socket/stubs.rs`. Do not implement logic — only define the types.

---

## Binary Budget

| Engine | RAM Budget | Binary Size |
|--------|-----------|-------------|
| BORU   | < 20MB idle RSS | < 10MB release |
| ZUNO   | < 15MB (target) | TBD |
| SABA   | < 25MB | TBD |

---

## Security Invariant

> **BORU is the last line of defense. Nothing executes without cage clearance.**

This invariant must never be broken. If SABA bypasses BORU for "performance," the entire security model collapses.