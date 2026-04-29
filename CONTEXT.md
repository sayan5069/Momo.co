# YOMI INDEXER - COMPLETE PROJECT CONTEXT

## 🎯 PROJECT OVERVIEW

**Name:** Yomi (reading/understanding in Japanese)  
**Part of:** momo-ecosystems (local AI sovereignty stack)  
**Owner:** Kshitij (2nd year B.Tech CSE)  
**Status:** Rebuilding from scratch (v1 lost to OS corruption, had 1202 files indexed)  
**Language:** Rust (confirmed)  
**Target Platform:** Linux/macOS first, Windows via WSL2  

## 🏗️ ARCHITECTURE VISION

### Core Concept
Yomi is a **local file indexer** that enables AI agents to understand and navigate codebases without sending data to the cloud. It's the "eyes" of the momo-ecosystems stack.

### Three-Layer Architecture

```
┌─────────────────────────────────────────┐
│         YOMI DAEMON (Background)        │
│  - File tree walking                    │
│  - Content hashing (BLAKE3)             │
│  - Incremental sync via file watching   │
│  - Index storage (SQLite/LMDB)          │
│  - Unix socket IPC server               │
└─────────────────────────────────────────┘
              ↕ Unix Socket/JSON-RPC
    ┌─────────────┴─────────────┐
    ↓                           ↓
┌─────────┐               ┌─────────┐
│ Yomi    │               │ Suji    │
│ CLI     │               │ (Orchestrator)
│ (Skin)  │               │ Boru    │
└─────────┘               │ (Security)│
                          └─────────┘
```

## 👥 TEAM STRUCTURE

- **Kshitij** → Yomi (Indexer) - THIS PROJECT
- **Sayan Ghoshal** → Boru (Sandbox/Security Policy)
- **Hrishikesh** → Suji (Orchestrator/Interface)

## 🔧 TECHNICAL SPECIFICATIONS

### Language & Tooling
- **Language:** Rust 2021 edition
- **Build Tool:** Cargo
- **Package Manager:** Cargo
- **Async Runtime:** Tokio (full features)
- **Target:** x86_64-unknown-linux-gnu (primary)

### Dependencies (Confirmed)

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
tokio-stream = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
ignore = "0.4"  # For .gitignore-aware file walking
notify = "6.1"  # File system watching
blake3 = "1.5"  # Fast content hashing
clap = { version = "4", features = ["derive"] }  # CLI parsing
tracing = "0.1"
tracing-subscriber = "0.3"
ratatui = "0.24"  # TUI (Phase 2)
crossterm = "0.27"  # Terminal backend
sled = "0.34"  # Embedded key-value store (or SQLite)
uuid = { version = "1", features = ["v4"] }
chrono = "0.4"
```

## 🔨 CORE FEATURES

### 1. Indexing Engine
- Recursive directory traversal
- `.gitignore` and `.yomiignore` support
- Content hashing (BLAKE3)
- Metadata extraction (size, mtime, permissions, language)
- Binary file detection and skipping
- Symlink handling (configurable)
- Incremental updates via file watching

### 2. Index Storage

Structure per file:

```json
{
  "path": "/absolute/path/to/file.rs",
  "relative_path": "src/main.rs",
  "hash": "blake3_hash_hex",
  "size_bytes": 4096,
  "mtime_unix": 1714320000,
  "language": "Rust",
  "extension": ".rs",
  "is_binary": false,
  "is_symlink": false,
  "permissions": "644",
  "indexed_at": "2024-04-28T12:00:00Z"
}
```

### 3. Query Engine
- Full-text search across indexed content
- Path-based filtering (glob patterns)
- Language filtering
- Metadata-based filtering (size, mtime range)
- Relevance scoring (TF-IDF or BM25)
- Pagination for large results

### 4. IPC Protocol (Unix Socket)

**Protocol:** JSON-RPC 2.0 over Unix domain socket

**Socket location:** `/tmp/yomi.sock` or `~/.local/run/yomi.sock`

**Example requests:**

```json
{
  "jsonrpc": "2.0",
  "method": "index",
  "params": {
    "path": "/home/user/project",
    "full": false
  },
  "id": 1
}
```

```json
{
  "jsonrpc": "2.0",
  "method": "query",
  "params": {
    "pattern": "database connection",
    "filters": {
      "language": ["Rust", "Python"],
      "max_size": 100000
    },
    "limit": 50
  },
  "id": 2
}
```

```json
{
  "jsonrpc": "2.0",
  "method": "status",
  "params": {},
  "id": 3
}
```

**Example responses:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "files_indexed": 1202,
    "total_size_bytes": 52428800,
    "last_updated": "2024-04-28T12:00:00Z",
    "watching": true
  },
  "id": 3
}
```

### 5. CLI Interface (Phase 1)

**Commands:**

```bash
# Daemon management
yomi daemon start            # Start background daemon
yomi daemon stop             # Stop daemon
yomi daemon status           # Check if running

# Indexing
yomi init                    # Initialize .yomi.toml config
yomi index                   # Full index of current dir
yomi index --path /foo/bar   # Index specific path
yomi index --watch           # Start file watching

# Querying
yomi query "pattern"         # Search index
yomi query "pattern" --json  # Machine-readable output
yomi query "pattern" --lang rust

# Listing & Stats
yomi list                    # List all indexed files
yomi list --lang rust
yomi stats                   # Show index statistics
yomi export > index.json     # Export full index

# Configuration
yomi config show             # Show current config
yomi config set key value    # Update config
```

### 6. Configuration (.yomi.toml)

```toml
[general]
index_path = "/home/user/projects"
ignore_files = [".gitignore", ".yomiignore"]
max_file_size = 10485760  # 10MB
follow_symlinks = false

[ignore]
patterns = [
  "node_modules",
  "target",
  ".git",
  "*.lock",
  "*.log"
]

[languages]
enabled = ["all"]  # or specific list like ["Rust", "Python"]

[daemon]
socket_path = "/tmp/yomi.sock"
log_level = "info"
watch_interval_ms = 1000

[output]
default_format = "human"  # or "json", "ndjson"
```

## 🎨 DESIGN PRINCIPLES

1. **Unix Philosophy:** Do one thing well. Compose with other tools.
2. **Privacy First:** No data leaves the machine. Ever.
3. **Performance:** Index 10k files in <10 seconds. Incremental updates in <100ms.
4. **Correctness:** Never lose index data. Atomic writes. Crash recovery.
5. **Transparency:** User always knows what's indexed, what's skipped, why.
6. **Extensibility:** Plugins/hooks for custom file processors.

## 🔌 INTEGRATION POINTS

### With Suji (Orchestrator)
- Suji calls Yomi via CLI or Unix socket
- Yomi provides context for LLM prompts
- Suji may request specific files/languages
- Yomi returns structured JSON for parsing

### With Boru (Security)
- Boru sits between Yomi and filesystem (optional)
- Boru enforces access policies
- Yomi reports what it's trying to index
- Boru can block sensitive paths

### With Local LLMs (Ollama, llama.cpp)
- Yomi provides RAG (Retrieval-Augmented Generation) context
- Suji orchestrates: query → Yomi → LLM → response
- Yomi can export in LLM-friendly formats

## 📊 CURRENT STATUS

### Lost Work (v1)
- 1202 files indexed
- Basic search functionality
- TUI interface (screenshot exists)
- Language detection for 10+ languages

### Rebuilding (v2) - Checklist
- [ ] Project scaffolding
- [ ] File walker with ignore support
- [ ] Content hashing
- [ ] Index storage
- [ ] Unix socket IPC
- [ ] CLI wrapper
- [ ] File watcher
- [ ] Incremental sync
- [ ] Query engine
- [ ] TUI (Phase 2)

### Timeline
- **Week 1-2:** Core daemon + CLI
- **Week 3-4:** File watching + incremental sync
- **Week 5-6:** Query engine + optimization
- **Week 7-8:** Suji/Boru integration
- **Week 9+:** TUI, polish, docs

## 🧪 TESTING STRATEGY

### Unit Tests (70% coverage target)
- Path parsing and normalization
- Ignore pattern matching
- Hash generation
- Config loading/validation
- JSON serialization

### Integration Tests
- Full index run on test repo
- Incremental update after file change
- Concurrent file mutations during index
- IPC request/response handling

### Performance Benchmarks
- 1k, 5k, 10k, 50k file repos
- Full vs incremental index time
- Memory usage profiling
- Query latency (p50, p95, p99)

### OS Compatibility
- Linux (Ubuntu 22.04) - Primary
- macOS (Darwin) - Secondary
- Windows (WSL2) - Tertiary

## 📦 BUILD & DEPLOYMENT

### Development
```bash
cargo build --debug
cargo run -- index
cargo test
cargo clippy
cargo fmt
```

### Production
```bash
cargo build --release
# Binary at target/release/yomi
# Size: ~5-10MB stripped
```

### Distribution
- Cargo install (Rust users)
- Pre-built binaries (GitHub Releases)
- AUR package (Arch Linux)
- Homebrew tap (macOS)
- Docker image (optional)

## 🚀 PERFORMANCE TARGETS

| Metric | Target | Stretch |
|--------|--------|---------|
| Full index (1k files) | <3s | <1s |
| Full index (10k files) | <15s | <5s |
| Incremental (1 file change) | <100ms | <10ms |
| Query latency (simple) | <50ms | <10ms |
| Memory usage (idle daemon) | <50MB | <20MB |
| Memory usage (indexing) | <500MB | <200MB |

## 🛡️ ERROR HANDLING

### Fatal Errors (Exit non-zero)
- Corrupted index database
- Permission denied on critical path
- Socket already in use

### Non-Fatal Errors (Log & Continue)
- Individual file read failures
- Symlink loops
- Binary files (skip, don't crash)
- Permission denied on subdirectory

### Recovery
- Atomic index writes (write to temp, rename)
- Index corruption detection (checksum)
- Automatic rebuild on corruption
- Graceful degradation (partial index OK)

## 📝 LOGGING & DEBUGGING

### Log Levels
- **ERROR:** Something broke, action needed
- **WARN:** Unexpected but recoverable
- **INFO:** Normal operations
- **DEBUG:** Detailed flow
- **TRACE:** Every file, every hash

### Log Output
- Stderr for CLI commands
- File for daemon (~/.local/share/yomi/yomi.log)
- JSON format option for parsing

### Debug Commands
```bash
yomi debug dump-index      # Print full index
yomi debug verify-hashes   # Re-hash all files, compare
yomi debug profile         # CPU/memory profiling
```

## 🔐 SECURITY CONSIDERATIONS

1. **No Network Calls:** Yomi never phones home
2. **Local-Only:** Unix socket, not TCP (no remote access)
3. **Permission Respect:** Honor file permissions, don't escalate
4. **No Telemetry:** Zero analytics, zero tracking
5. **Sandbox-Ready:** Can run inside Boru's security policy

## 📚 DOCUMENTATION REQUIREMENTS

### Must-Have Files
- `README.md` (hook, install, quickstart)
- `ARCHITECTURE.md` (design decisions, diagrams)
- `USAGE.md` (all commands, examples)
- `OUTPUT_FORMAT.md` (JSON schema)
- `IGNORE_RULES.md` (.gitignore behavior)
- `BENCHMARKS.md` (performance numbers)
- `CONTRIBUTING.md` (how to contribute)
- `CHANGELOG.md` (version history)

### Nice-to-Have
- `TROUBLESHOOTING.md` (common issues)
- `FAQ.md` (questions)
- `API.md` (IPC protocol spec)

## 🎯 SUCCESS METRICS

### Technical
- Index 10k files in <10s
- <100ms incremental updates
- Zero data loss on crash
- <50MB idle memory

### User Experience
- `yomi init && yomi index` works out of box
- Clear error messages
- Helpful documentation
- Fast query results

### Integration
- Suji can query Yomi successfully
- Boru can intercept Yomi's file access
- Works with Ollama/llama.cpp via Suji

## 🔮 FUTURE FEATURES (Post-v1)

- Plugin system for custom file processors
- Embedding generation (for semantic search)
- Git integration (commit-aware indexing)
- Multi-project workspaces
- Remote indexing (SSH into server)
- Web UI for browsing index
- VS Code/Neovim extensions

## ⚠️ CONSTRAINTS & ASSUMPTIONS

### Constraints
- Solo developer (Kshitij)
- Limited time (college student)
- Must work offline
- Must be fast (no slow indexing)

### Assumptions
- Users have Rust toolchain (or can install)
- Users run Linux/macOS (Windows via WSL2)
- Users understand CLI tools
- Users value privacy over convenience

## 🎨 BRANDING & THEME

**Name:** Yomi (reading/understanding)  
**Theme:** Sumi-e (Japanese ink wash painting)  
**Colors:** Black, white, gray (minimalist)  
**Philosophy:** Precision, clarity, sovereignty

## 📞 COMMUNICATION

### Team Sync
- Weekly check-ins with Sayan (Boru) and Hrishikesh (Suji)
- Shared GitHub org: momo-ecosystems
- Discord/Slack for quick questions

### External
- GitHub Issues for bugs
- GitHub Discussions for features
- Twitter/LinkedIn for announcements

---

## 🚨 IMMEDIATE NEXT STEPS

1. **Initialize GitHub repo** (today, no excuses)
2. **Set up WSL2** (if not already)
3. **Scaffold Rust project** with `cargo init`
4. **Implement basic file walker** (ignore crate)
5. **Push to GitHub** (even if incomplete)

**Priority Order:**
1. File walker → 2. Hash generation → 3. Index storage → 4. IPC → 5. CLI

---

## 📌 CONTEXT FOR AI ASSISTANTS (Antigravity/Cursor/Claude)

When helping with Yomi:
- Always assume Rust 2021 edition
- Prefer async/await with Tokio
- Use Unix sockets for IPC (not TCP)
- Optimize for performance, not elegance
- Never suggest cloud services or telemetry
- Respect Unix pipeline philosophy
- Test on Linux first
- Keep dependencies minimal
- Document public APIs
- Handle errors gracefully

### Code Style
- Use `Result<T, Box<dyn Error>>` for simplicity
- Prefer composition over inheritance
- Use traits for extensibility
- Write unit tests for core logic
- Use `tracing` for logging, not `println!`

### When in doubt, ask:
- Does this help Suji/Boru integration?
- Is this Unix-pipeline friendly?
- Will this scale to 50k files?
