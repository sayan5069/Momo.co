BORU 🥊

"What runs here, stays here."

BORU is the Security Cage — the first engine of Project MOMO, a local-first sovereign AI development suite.
Built in Rust. Powered by WASM sandboxing. Zero network calls. Zero trust in AI-generated code until BORU says so.

What BORU Does
BORU intercepts and sandboxes AI-generated code before it ever touches your system. It acts as a security membrane between your local LLM and your file system.

Sandboxes AI output via WASM (wasmtime)
Intercepts unauthorized syscalls, file access, and network calls
Logs every blocked action with full audit trail
Runs as a Unix socket daemon inside Project MOMO
Works standalone as a CLI/TUI tool (Phase 1)


Architecture Position
MOMO Suite
├── BORU  ← You are here (Security Cage)
├── ZUNO  ← Memory / Indexer (coming)
└── SABA  ← Router / Nervous System (coming)
Socket: /tmp/momo/boru.sock

Phases
PhaseDescriptionStatus1Standalone CLI/TUI tool🔨 Active2MOMO-integrated daemon with GUI panel📋 Planned

Quick Start (Linux & macOS)
BORU is built natively for Unix-like environments. Sockets and WASM sandboxing work natively out of the box.

1. Clone & Build
```bash
git clone https://github.com/sayan5069/Momo.co.git
cd Momo.co
cargo build --release
```

2. Run the Tools
```bash
# Start the background socket daemon (/tmp/momo/boru.sock)
./target/release/boru daemon &

# Launch the visual Ratatui dashboard
./target/release/boru tui

# Sandbox a WASM binary natively
./target/release/boru cage --input target.wasm --policy strict
```

3. Verification
```bash
# Check binary size (must stay < 10MB)
ls -lh target/release/boru
```

Gates (Non-Negotiable Rules)
Before any code change, all Protocol Gates must pass. See AGENTS.md.

Project MOMO
BORU is one part of a larger vision. See ARCHITECTURE.md for the full Trinity design.

Name
BORU (ぼる) — Japanese for round, blocky, punchy. Exactly what a security cage should be.