# BORU ↔ MOMO Integration (Phase 2)

This document defines BORU's contract with ZUNO and SABA for when all three Trinity engines are running.

> **Status:** Stub — ZUNO and SABA not yet implemented. This document freezes the protocol so all three can be built independently and snap together cleanly.

---

## Socket Map

```
/tmp/momo/
├── boru.sock    ← BORU (Security Cage)      [ACTIVE in Phase 2]
├── zuno.sock    ← ZUNO (Memory/Indexer)     [RESERVED]
└── saba.sock    ← SABA (Router/Conductor)   [RESERVED]
```

Socket directory is created by MOMO host process on startup. Each engine creates its own socket file.

---

## Request Flow (Full Trinity)

```
User prompt
     │
     ▼
  SABA (receives prompt)
     │
     ├──► ZUNO: "Give me context for this prompt"
     │         ZUNO returns: relevant code snippets, file paths
     │
     └──► Ollama: "Here's the prompt + context, generate code"
               Ollama returns: AI-generated code
                    │
                    ▼
               SABA sends to BORU: "Sandbox this code"
                    │
                    ▼
               BORU: sandbox + intercept
                    │
                    ├── BLOCKED ──► SABA logs, returns error to user
                    └── ALLOWED ──► SABA returns result to UI
```

---

## BORU Socket Protocol

### Connection
- Unix domain socket: `/tmp/momo/boru.sock`
- Protocol: newline-delimited JSON (NDJSON)
- Auth: none (local-only, process-level trust)

### Request Schema
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "type": "execute",
  "payload": {
    "code": "<base64-encoded content>",
    "format": "wasm",
    "policy": "strict",
    "fuel": 1000000000,
    "workspace": "/tmp/momo/workspace/session-abc123"
  },
  "metadata": {
    "source": "saba",
    "model": "codellama:7b",
    "session_id": "session-abc123"
  }
}
```

**format values:** `wasm` | `shell` (shell is weaker, emits TUI warning)
**policy values:** `strict` | `permissive`
**type values:** `execute` | `check` (check = static analysis only, no execution)

### Response Schema
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": "ALLOWED",
  "output": "<base64-encoded stdout>",
  "audit_ref": "audit-entry-uuid",
  "stats": {
    "fuel_consumed": 45231890,
    "memory_peak_bytes": 2097152,
    "duration_ms": 142
  }
}
```

**verdict values:** `ALLOWED` | `BLOCKED` | `ERROR` | `TIMEOUT`

### Error Response
```json
{
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": "BLOCKED",
  "reason": "NETWORK_CALL_ATTEMPTED",
  "severity": "CRITICAL",
  "audit_ref": "audit-entry-uuid",
  "blocked_event": {
    "type": "network",
    "detail": "TCP connect attempted to 93.184.216.34:443"
  }
}
```

---

## ZUNO Contract (Stub)

BORU does not call ZUNO. This is here for reference so ZUNO knows what to expect from the shared workspace.

```
ZUNO socket: /tmp/momo/zuno.sock

ZUNO reads from: project source files (read-only)
BORU writes to:  /tmp/momo/workspace/<session_id>/ (execution sandbox)

No direct BORU ↔ ZUNO communication in Phase 2.
```

---

## SABA Contract (Stub)

SABA is BORU's only caller. BORU never initiates contact.

```
SABA socket: /tmp/momo/saba.sock

SABA → BORU: execute/check requests (JSON over boru.sock)
BORU → SABA: verdict responses (JSON)

BORU never calls SABA. BORU never knows what prompt generated the code.
BORU only sees: code bytes + policy. Context-blind by design.
```

---

## Workspace Convention

```
/tmp/momo/workspace/
└── <session_id>/
    ├── input/       ← SABA writes AI code here before sending to BORU
    ├── output/      ← BORU's WASM sandbox writes here (ALLOWED ops only)
    └── audit/       ← Per-session audit log (BORU writes)
```

Session ID format: `session-<8-char-hex>` e.g. `session-a3f7c901`

---

## Versioning

Protocol version is negotiated on socket connect:
```json
{"protocol": "boru/1.0", "capabilities": ["execute", "check", "stream"]}
```

BORU rejects connections from incompatible versions with:
```json
{"error": "PROTOCOL_MISMATCH", "supported": ["boru/1.0"]}
```