# seccomp-bpf Hardening Plan

Status: PLANNED — implement after WSL2/Linux dev environment confirmed

## Why

bubblewrap is a bridge. seccomp-bpf is the real answer.
Operates at Linux kernel level. No userspace bypass possible.

## Crate

seccompiler (Firecracker's implementation — battle-tested)

## Python syscall allowlist

```
read, write, open, openat, close, fstat, lstat, stat,
mmap, mprotect, munmap, brk, rt_sigaction, rt_sigprocmask,
exit_group, getcwd, getdents64, ioctl
```

## Python syscall blocklist (explicit deny → SIGKILL)

```
socket, connect, bind, listen, accept,
execve, fork, clone, vfork,
ptrace, kill, tkill,
init_module, finit_module,
mount, umount2
```

## Implementation gate

cfg(target_os = "linux") only
Fallback on other OS: current bubblewrap strategy
Do not implement until WSL2/Linux confirmed

## Add stub in src/runner/interpreter.rs

```rust
// TODO: seccomp-bpf hardening — see docs/SECCOMP_PLAN.md
// cfg(target_os = "linux")
// fn apply_seccomp_profile(policy: &SeccompPolicy) -> Result<()> { todo!() }
```

---

## Notes for Future Implementation

### Phase 1: Design (WSL2/Linux confirmed)

1. Define syscall allowlist per interpreter (Python, JS, Lua, etc.)
2. Design SeccompPolicy structure to hold per-runner rules
3. Map runner types to minimal syscall sets

### Phase 2: Integration

1. Add seccompiler crate with `cfg(target_os = "linux")`
2. Implement seccomp profile application in runner::interpreter
3. Ensure graceful fallback on non-Linux platforms

### Phase 3: Testing

1. Verify Python scripts run normally under allowlist
2. Verify blocked syscalls trigger SIGKILL
3. Test on both WSL2 and native Linux

---

## Binary Size Impact

**GATE 1 WARNING**: seccompiler adds ~500KB to binary size.
Must remain under 10MB threshold.
If binary size approaches 9.5MB, consider feature-flagging seccomp.

---

## Security Model

```
┌─────────────────────────────────────────┐
│         BORU Security Layers             │
├─────────────────────────────────────────┤
│  Layer 5: seccomp-bpf (kernel)          │
│  Layer 4: WASM sandbox (execution)      │
│  Layer 3: Cage policy (mode-based)      │
│  Layer 2: Intercept layer (events)      │
│  Layer 1: Absolute invariants (always)  │
└─────────────────────────────────────────┘
```

seccomp-bpf is the outermost layer. Even if all other layers are
bypassed, unauthorized syscalls die at the kernel.
