# BORU seccomp-bpf Plan — Linux Kernel Sandboxing (Phase 2)

> **Status: DOCUMENTED ONLY — NOT IMPLEMENTED**
>
> seccomp-bpf is a Linux-specific syscall filtering mechanism.
> This document describes the planned implementation for Phase 2.
> BORU v0.3 does not contain any seccomp code.

---

## What is seccomp-bpf?

`seccomp-bpf` (Secure Computing with Berkeley Packet Filter) is a Linux kernel
feature that allows a process to restrict the system calls it can make.

- **seccomp strict mode**: Only allows `read()`, `write()`, `exit()`, `sigreturn()`
- **seccomp-bpf mode**: Allows BPF programs to filter syscalls with arbitrary logic

BORU would use **seccomp-bpf mode** to create fine-grained syscall policies per
security mode.

---

## Why seccomp-bpf for BORU?

Currently BORU sandboxes via WASM (wasmtime). seccomp-bpf adds a second layer:

1. **Defense in depth**: Even if WASM sandbox breaks, seccomp blocks dangerous syscalls
2. **Native binary support**: WASM can only run .wasm files; seccomp works on native binaries
3. **Kernel-level enforcement**: Cannot be bypassed from userspace
4. **Low overhead**: BPF runs in kernel, ~1μs per syscall check

---

## Planned Architecture

```
┌────────────────────────────┐
│  AI Agent Code             │
├────────────────────────────┤
│  BORU Cage (WASM sandbox)  │  ← Layer 1: wasmtime
├────────────────────────────┤
│  BORU seccomp-bpf filter   │  ← Layer 2: kernel syscall filter
├────────────────────────────┤
│  Linux Kernel              │
└────────────────────────────┘
```

---

## Syscall Policy by Mode

### HARD Mode — Maximum Restriction

```
ALLOW:
  - read(fd) where fd in {0, 1, 2, sandbox_fds}
  - write(fd) where fd in {1, 2}  (stdout/stderr only)
  - exit_group()
  - clock_gettime()
  - mmap(PROT_READ | PROT_WRITE)  (no PROT_EXEC)
  - brk()
  - futex()

BLOCK (with audit):
  - Everything else

KILL:
  - execve(), execveat()
  - fork(), clone() (with CLONE_NEWUSER)
  - ptrace()
  - socket()
  - connect()
  - bind()
  - sendto(), recvfrom()
  - init_module(), finit_module()
  - kexec_load()
```

### MID Mode — Balanced

```
ALLOW:
  - All from HARD mode
  - open(O_RDONLY) for workspace paths
  - stat(), fstat(), lstat()
  - getdents64() for directory listing
  - ioctl() for terminal control only

PROMPT (via BORU intercept):
  - open(O_WRONLY | O_CREAT)
  - unlink(), rename()

BLOCK:
  - socket(), connect(), bind()
  - execve()
  - ptrace()
```

### EASY Mode — Permissive

```
ALLOW:
  - Most filesystem syscalls
  - stdout/stderr
  - mmap (including PROT_EXEC for JIT)

PROMPT:
  - socket(), connect()
  - execve()

BLOCK (absolute invariants):
  - ptrace()
  - init_module()
  - kexec_load()
  - process_vm_writev()
```

---

## Implementation Plan (Phase 2)

### New Files

```
src/seccomp/
├── mod.rs          # Module registration
├── filter.rs       # BPF filter generation
├── policy.rs       # Mode-specific syscall policies
└── notifier.rs     # seccomp user notification (for PROMPT verdicts)
```

### Dependencies

```toml
# Linux-only, behind cfg(target_os = "linux")
[target.'cfg(target_os = "linux")'.dependencies]
seccompiler = "0.4"    # BPF program generation
libc = "0.2"           # Syscall numbers
```

### Key APIs

```rust
/// Generate a seccomp-bpf filter for a security mode
pub fn build_filter(mode: SecurityMode) -> Result<BpfProgram> {
    let mut rules = Vec::new();

    match mode {
        SecurityMode::Hard => {
            // Allowlist-only approach
            rules.push(allow_syscall(SYS_read));
            rules.push(allow_syscall(SYS_write));
            rules.push(allow_syscall(SYS_exit_group));
            // ... everything else is killed
        }
        SecurityMode::Mid => {
            // Use SECCOMP_RET_USER_NOTIF for promptable syscalls
            rules.push(allow_syscall(SYS_read));
            rules.push(notify_syscall(SYS_openat));  // Prompt
            rules.push(kill_syscall(SYS_execve));     // Block
            // ...
        }
        // ...
    }

    compile_bpf(rules)
}

/// Apply seccomp filter to current process
pub fn apply_filter(filter: &BpfProgram) -> Result<()> {
    // prctl(PR_SET_NO_NEW_PRIVS, 1)
    // prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, filter)
}
```

### Integration with BORU Cage

```rust
// In cage/sandbox.rs (Phase 2)
pub fn execute_with_seccomp(input: PathBuf, mode: SecurityMode) -> Result<CageResult> {
    // 1. Build seccomp filter for mode
    let filter = seccomp::build_filter(mode)?;

    // 2. Fork child process
    // 3. In child: apply seccomp filter BEFORE loading code
    // 4. Execute code under dual sandbox (WASM + seccomp)
    // 5. Parent: monitor via seccomp user notification fd
}
```

---

## seccomp User Notification (SECCOMP_RET_USER_NOTIF)

For MID and CUSTOM modes, BORU needs to prompt the user on certain syscalls.
Linux 5.0+ supports `SECCOMP_RET_USER_NOTIF`:

1. Filtered process makes a syscall (e.g., `openat()`)
2. Kernel pauses the process
3. BORU's supervisor reads the notification via `seccomp_notif` fd
4. BORU prompts the user (TUI)
5. BORU responds: ALLOW or BLOCK
6. Kernel resumes or kills the process

This maps perfectly to BORU's PROMPT verdict.

---

## Platform Considerations

- **Linux only**: seccomp is a Linux kernel feature
- **macOS alternative**: `sandbox_init()` / App Sandbox (different API)
- **Windows alternative**: Job Objects / AppContainers
- **Cross-platform**: WASM sandbox remains the primary layer on all platforms

BORU will use conditional compilation:

```rust
#[cfg(target_os = "linux")]
mod seccomp;

#[cfg(not(target_os = "linux"))]
mod seccomp {
    // No-op stubs
    pub fn available() -> bool { false }
}
```

---

## Testing Strategy

1. **Unit tests**: BPF filter generation correctness
2. **Integration tests**: Fork + seccomp + verify blocked syscalls
3. **EICAR-like tests**: Known-bad syscall sequences
4. **Fuzzing**: Random syscall sequences against filter
5. **Kernel version checks**: Graceful degradation on older kernels

---

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| seccomp kills process on violation | Use SECCOMP_RET_TRAP for audit before kill |
| Kernel version too old | Check `uname` at startup, fall back to WASM-only |
| BPF program too complex | Keep per-mode policies under 256 instructions |
| TOCTOU in file path checks | Use fd-based checks, not path-based |
| Thread escape | Apply seccomp before any threads spawn |

---

## Timeline

- **Phase 2 (v0.4)**: Basic seccomp filter for HARD mode
- **Phase 2 (v0.5)**: User notification for MID/CUSTOM modes
- **Phase 3 (v0.6)**: Full integration with TUI prompts
- **Phase 3 (v0.7)**: macOS sandbox_init() parity

---

> **Remember**: This is documentation only. Do not implement seccomp in v0.3.
> The WASM sandbox remains the sole execution sandbox until Phase 2.
