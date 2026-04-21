# BORU Threat Model

> BORU assumes the AI model is untrusted. Always.

---

## Threat Actors

### Primary: The Local LLM
The AI model running via Ollama may generate code that attempts to:
- Read sensitive files (`~/.ssh/`, `.env`, API keys)
- Write to system directories
- Spawn subprocesses
- Establish network connections
- Exfiltrate data via covert channels

BORU's position: **Treat every line of AI-generated code as potentially adversarial.**

### Secondary: Malicious WASM Modules
A user may unknowingly run a WASM binary from an untrusted source. BORU sandboxes all WASM execution regardless of origin.

### Out of Scope (Phase 1)
- Kernel-level exploits against the host OS
- Side-channel attacks (timing, cache)
- Attacks against the Ollama daemon itself

---

## Attack Surface

| Surface | Risk | Mitigation |
|---------|------|-----------|
| AI-generated shell commands | HIGH | Blocked unless routed through WASM sandbox |
| AI-generated WASM binaries | HIGH | wasmtime sandbox + capability policy |
| File system access from WASM | HIGH | WASI capability model — explicit allow-list only |
| Network calls from WASM | CRITICAL | Blocked entirely. No WASI network capability granted |
| Unix socket input | MEDIUM | JSON schema validation on every request |
| Audit log tampering | LOW | Append-only ring buffer, no delete API |

---

## What BORU Intercepts

### File System
```
BLOCK: Write to any path not in allowed_paths[]
BLOCK: Read from: ~/.ssh/, ~/.gnupg/, **/.env, **/secrets*, **/credentials*
ALLOW: Read/write to /tmp/momo/workspace/ (explicit sandbox dir)
LOG:   All file operations regardless of verdict
```

### Network
```
BLOCK: All outbound TCP/UDP connections from sandboxed code
BLOCK: All DNS lookups from sandboxed code
BLOCK: Unix socket connections outside /tmp/momo/
LOG:   All attempted network calls
```

### Process
```
BLOCK: exec(), fork(), spawn() from sandboxed code
BLOCK: Signal sending (kill, SIGTERM, etc.)
BLOCK: Environment variable access (except explicitly passed)
LOG:   All process-related syscall attempts
```

### System
```
BLOCK: Clock manipulation
BLOCK: /proc/ and /sys/ access
BLOCK: Loading kernel modules
LOG:   All system call attempts
```

---

## Severity Levels

| Level | Meaning | Example |
|-------|---------|---------|
| `CRITICAL` | Exfiltration or system compromise attempt | Network call, reading SSH keys |
| `HIGH` | Unauthorized file write or process spawn | Write outside workspace |
| `MEDIUM` | Suspicious read or environment probe | Reading `/proc/self/environ` |
| `LOW` | Policy violation, likely unintentional | Accessing a path just outside workspace |

---

## Trust Boundaries

```
UNTRUSTED                    TRUSTED
─────────────────────────────────────
AI model output ──► [BORU CAGE] ──► OS execution
WASM binary     ──► [BORU CAGE] ──► File system
Socket input    ──► [BORU CAGE] ──► Audit log
```

Nothing crosses from UNTRUSTED to TRUSTED without BORU's verdict.