# BORU CLI Usage (Phase 1)

Phase 1: Standalone CLI/TUI tool. No MOMO integration. No daemon. Just BORU and your terminal.

---

## Install

```bash
# From source
git clone https://github.com/sayan5069/boru
cd boru
cargo build --release
cp target/release/boru ~/.local/bin/boru
```

---

## Commands

### `boru cage` — Sandbox a WASM binary
```bash
boru cage --input <file.wasm>
boru cage --input <file.wasm> --policy strict
boru cage --input <file.wasm> --policy permissive --fuel 500000000
```

**Options:**
| Flag | Default | Description |
|------|---------|-------------|
| `--input` | required | Path to WASM binary |
| `--policy` | `strict` | `strict` or `permissive` |
| `--fuel` | `1000000000` | CPU instruction budget |
| `--workspace` | `/tmp/boru/workspace` | Sandbox FS root |
| `--output` | stdout | Where captured output goes |

---

### `boru check` — Static analysis only (no execution)
```bash
boru check --input <file.wasm>
boru check --shell "curl https://example.com"
```

Runs BORU's intercept rules against the input without executing. Returns exit code 0 (ALLOWED) or 1 (BLOCKED).

---

### `boru daemon` — Start socket daemon (Phase 1 preview)
```bash
boru daemon
boru daemon --socket /tmp/momo/boru.sock
boru daemon --log /var/log/boru/audit.log
```

Starts BORU listening on Unix socket. Required for MOMO integration (Phase 2).

---

### `boru tui` — Launch TUI dashboard
```bash
boru tui
boru tui --socket /tmp/momo/boru.sock  # Attach to running daemon
```

Opens the Ratatui terminal dashboard showing:
- Live intercept events
- Audit log stream
- Current policy status
- Memory/CPU usage of sandboxed processes

---

### `boru log` — Audit log viewer
```bash
boru log                        # Show last 50 entries
boru log --tail                 # Follow log in real time
boru log --severity CRITICAL    # Filter by severity
boru log --since "2024-01-01"   # Filter by date
boru log --export audit.json    # Export as JSON
```

---

## TUI Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `↑` / `↓` | Navigate log entries |
| `f` | Filter by severity |
| `c` | Clear log view (does not delete log file) |
| `p` | Pause/resume live feed |
| `?` | Help |

---

## Audit Log Format

```
[2024-01-15T10:23:45Z] [CRITICAL] [NETWORK_CALL] [WASM attempted TCP connect to 93.184.216.34:443]
[2024-01-15T10:23:45Z] [HIGH]     [FILE_WRITE]   [WASM attempted write to /home/user/.ssh/id_rsa]
[2024-01-15T10:23:46Z] [ALLOWED]  [FILE_WRITE]   [WASM wrote to /tmp/boru/workspace/output.txt]
```

Log location: `~/.local/share/boru/audit.log` (default)

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | ALLOWED — execution completed cleanly |
| `1` | BLOCKED — intercept rule triggered |
| `2` | ERROR — BORU internal error |
| `3` | TIMEOUT — fuel/time budget exceeded |