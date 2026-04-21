//! BORU Cage — WASM sandbox core
//!
//! This module contains the heart of BORU: the WASM sandbox execution engine.
//! All execution paths MUST go through here. No exceptions.
//!
//! GATE 2: Sandbox Invariant — all external input execution originates here.

use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;

pub mod policy;
pub mod verdict;

use policy::SecurityMode;
use verdict::CageResult;

/// Default fuel limit (1 billion instructions)
const DEFAULT_FUEL_LIMIT: u64 = 1_000_000_000;
/// Maximum WASM memory pages (1024 pages × 64KB = 64MB)
const _MEMORY_PAGES_LIMIT: u32 = 1024;
/// Maximum WASM stack size (1MB)
const MAX_WASM_STACK: usize = 1 << 20;
/// Ring buffer capacity for audit entries (GATE 6: bounded data structures)
const AUDIT_RING_BUFFER_CAPACITY: usize = 10_000;

/// Legacy execution verdict (for backwards compatibility)
#[derive(Debug, Clone)]
pub enum Verdict {
    Allowed { output: String },
    Blocked { reason: String },
    Timeout,
}

/// Security policy (legacy - use policy::SecurityMode)
#[derive(Debug, Clone)]
pub enum Policy {
    Strict,
    Permissive,
}

impl From<&str> for Policy {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "permissive" => Policy::Permissive,
            _ => Policy::Strict,
        }
    }
}

/// Audit log entry structure
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct AuditEntry {
    pub timestamp: String,
    pub severity: Severity,
    pub action: String,
    pub reason: String,
    pub request_id: uuid::Uuid,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Ring buffer for audit log entries (GATE 6: bounded, max 10,000 entries)
static AUDIT_RING: Mutex<Option<AuditRingBuffer>> = Mutex::new(None);

struct AuditRingBuffer {
    entries: VecDeque<AuditEntry>,
    capacity: usize,
}

impl AuditRingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, entry: AuditEntry) {
        if self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    #[allow(dead_code)]
    fn entries(&self) -> &VecDeque<AuditEntry> {
        &self.entries
    }

    #[allow(dead_code)]
    fn clear(&mut self) {
        self.entries.clear();
    }
}

fn get_or_init_ring() -> &'static Mutex<Option<AuditRingBuffer>> {
    // Initialize on first access
    let mut guard = AUDIT_RING.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(AuditRingBuffer::new(AUDIT_RING_BUFFER_CAPACITY));
    }
    drop(guard);
    &AUDIT_RING
}

/// Build a hardened wasmtime Config per docs/WASM_SANDBOX.md
fn build_sandbox_config(_policy: &Policy) -> Result<wasmtime::Config> {
    let mut config = wasmtime::Config::new();

    // Parallel compilation for faster module loading
    config.parallel_compilation(true);

    // Security: fuel system for CPU budget enforcement
    config.consume_fuel(true);

    // Security: 1MB stack limit
    config.max_wasm_stack(MAX_WASM_STACK);

    // Security: disable dangerous features to minimize attack surface
    config.wasm_simd(false);       // No SIMD (attack surface)
    config.wasm_relaxed_simd(false); // Must be disabled if wasm_simd is disabled
    config.wasm_memory64(false);   // No 64-bit addressing

    // Permissive mode allows multi-value returns; strict does not
    config.wasm_multi_value(matches!(_policy, Policy::Permissive));

    Ok(config)
}

/// Execute code in the WASM sandbox
///
/// GATE 2: All external input execution originates from here
pub fn execute(input: PathBuf, policy_str: String, fuel: Option<u64>) -> Result<Verdict> {
    let request_id = uuid::Uuid::new_v4();
    let policy = Policy::from(policy_str.as_str());
    let fuel_limit = fuel.unwrap_or(DEFAULT_FUEL_LIMIT);

    tracing::info!(
        "[{}] Starting cage execution: {} with policy {:?}, fuel: {}",
        request_id,
        input.display(),
        policy,
        fuel_limit
    );

    // Validate input exists
    if !input.exists() {
        let reason = format!("Input file not found: {}", input.display());
        log_intercept(Severity::High, "EXECUTE_BLOCKED", &reason, request_id);
        return Ok(Verdict::Blocked { reason });
    }

    // Read WASM bytes
    let wasm_bytes = std::fs::read(&input)
        .with_context(|| format!("Failed to read WASM file: {}", input.display()))?;

    // Validate WASM magic bytes
    if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\0asm" {
        let reason = "Invalid WASM magic bytes".to_string();
        log_intercept(Severity::High, "EXECUTE_BLOCKED", &reason, request_id);
        return Ok(Verdict::Blocked { reason });
    }

    // Build hardened engine config
    let config = build_sandbox_config(&policy)?;
    let engine = wasmtime::Engine::new(&config)?;
    let module = wasmtime::Module::new(&engine, &wasm_bytes)?;

    // Create WASI context with minimal capabilities (Preview 1 / core modules)
    let wasi_ctx = wasmtime_wasi::WasiCtxBuilder::new()
        .inherit_stdout()  // Captured by BORU
        .inherit_stderr()  // Captured by BORU
        // No network. No host FS. No env vars. Deny-by-default.
        .build_p1();

    // Create store with WASI P1 context and fuel budget
    let mut store: wasmtime::Store<wasmtime_wasi::preview1::WasiP1Ctx> =
        wasmtime::Store::new(&engine, wasi_ctx);
    store
        .set_fuel(fuel_limit)
        .context("Failed to set fuel budget")?;

    // Create linker with WASI Preview 1 functions
    let mut linker: wasmtime::Linker<wasmtime_wasi::preview1::WasiP1Ctx> =
        wasmtime::Linker::new(&engine);
    wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |ctx| ctx)
        .context("Failed to add WASI to linker")?;

    // Instantiate and run
    let instance: wasmtime::Instance = match linker.instantiate(&mut store, &module) {
        Ok(inst) => inst,
        Err(e) => {
            let reason = format!("WASM instantiation failed: {}", e);
            log_intercept(Severity::High, "EXECUTE_BLOCKED", &reason, request_id);
            return Ok(Verdict::Blocked { reason });
        }
    };

    // Call _start (WASI command) if it exists, otherwise try to find a callable export
    let result: anyhow::Result<()> =
        if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start") {
            start.call(&mut store, ())
        } else {
            // Try to find any function export
            let exports: Vec<_> = module.exports().collect();
            if let Some(func_export) = exports.iter().find(|e| e.ty().func().is_some()) {
                let name = func_export.name();
                tracing::info!(
                    "[{}] No _start found, calling '{}' instead",
                    request_id,
                    name
                );
                if let Ok(f) = instance.get_typed_func::<(), ()>(&mut store, name) {
                    f.call(&mut store, ())
                } else {
                    tracing::info!(
                        "[{}] No callable exports, treating as data module",
                        request_id
                    );
                    Ok(())
                }
            } else {
                tracing::info!(
                    "[{}] No function exports, treating as data module",
                    request_id
                );
                Ok(())
            }
        };

    // Check fuel consumption
    let fuel_remaining = store.get_fuel().unwrap_or(0);
    let fuel_consumed = fuel_limit.saturating_sub(fuel_remaining);

    match result {
        Ok(()) => {
            tracing::info!(
                "[{}] Execution completed, fuel consumed: {}",
                request_id,
                fuel_consumed
            );
            log_intercept(
                Severity::Low,
                "EXECUTE_ALLOWED",
                &format!("Execution completed, fuel consumed: {}", fuel_consumed),
                request_id,
            );
            Ok(Verdict::Allowed {
                output: "Executed successfully".to_string(),
            })
        }
        Err(e) => {
            // Check if this was a fuel exhaustion (timeout)
            let err_str = format!("{:?}", e);
            if err_str.contains("fuel") || err_str.contains("Fuel") {
                log_intercept(
                    Severity::High,
                    "CPU_BUDGET_EXCEEDED",
                    "Fuel exhausted during execution",
                    request_id,
                );
                Ok(Verdict::Timeout)
            } else {
                let reason = format!("WASM trap: {}", e);
                log_intercept(Severity::High, "EXECUTE_TRAP", &reason, request_id);
                Ok(Verdict::Blocked { reason })
            }
        }
    }
}

/// Run cage execution with new policy system
///
/// This is the enhanced version that uses the 4 security modes
pub fn run_cage(
    input: PathBuf,
    mode: SecurityMode,
    _fuel: Option<u64>,
) -> Result<CageResult> {
    use crate::classifier::FileClassifier;
    use crate::intercept::{InterceptEvent, InterceptLayer};

    let request_id = uuid::Uuid::new_v4();

    tracing::info!(
        "[{}] Starting cage execution: {} with mode {:?}",
        request_id,
        input.display(),
        mode
    );

    // Validate input exists
    if !input.exists() {
        let reason = format!("Input file not found: {}", input.display());
        log_intercept(Severity::High, "EXECUTE_BLOCKED", &reason, request_id);
        return Ok(CageResult::blocked(&reason));
    }

    // Create intercept layer with security mode
    let intercept = InterceptLayer::with_mode(request_id, mode);

    // Classify the file
    let classifier = FileClassifier::new();
    let classification = classifier.classify(&input)?;

    // Check for extension mismatch
    if !classification.extension_matches_magic {
        let event = InterceptEvent::ClassificationMismatch {
            classification: classification.clone(),
            path: input.clone(),
        };

        match intercept.evaluate(&event) {
            crate::intercept::Verdict::Blocked { reason } => {
                return Ok(CageResult::blocked(&reason));
            }
            crate::intercept::Verdict::Quarantined { reason, .. } => {
                return Ok(CageResult::quarantined(&reason));
            }
            _ => {}
        }
    }

    // Route to appropriate runner
    use crate::runner::{RunnerRouter, RunnerVerdict};

    let router = RunnerRouter::new();

    match router.route(&input, &classification) {
        Ok(RunnerVerdict::Success { output }) => {
            log_intercept(Severity::Low, "EXECUTE_ALLOWED", &output, request_id);
            Ok(CageResult::allowed(&output))
        }
        Ok(RunnerVerdict::Blocked { reason }) => {
            log_intercept(Severity::High, "EXECUTE_BLOCKED", &reason, request_id);
            Ok(CageResult::blocked(&reason))
        }
        Ok(RunnerVerdict::Timeout) => {
            log_intercept(
                Severity::High,
                "EXECUTE_TIMEOUT",
                "Fuel exhausted",
                request_id,
            );
            Ok(CageResult::timeout())
        }
        Ok(RunnerVerdict::Unsupported { reason }) => {
            log_intercept(Severity::Medium, "EXECUTE_UNSUPPORTED", &reason, request_id);
            Ok(CageResult::unsupported(&reason))
        }
        Err(e) => {
            let reason = format!("Execution error: {}", e);
            log_intercept(Severity::High, "EXECUTE_ERROR", &reason, request_id);
            Ok(CageResult::error(&reason))
        }
    }
}

/// Static analysis check (dry-run)
pub fn check(input: PathBuf) -> Result<()> {
    use crate::classifier::FileClassifier;
    use crate::runner::RunnerRouter;

    if !input.exists() {
        bail!("Input file not found: {}", input.display());
    }

    // Classify the file
    let classifier = FileClassifier::new();
    let classification = classifier.classify(&input)?;

    println!("✓ File classification:");
    println!("  Extension: {}", classification.claimed_extension);
    println!("  Detected: {:?}", classification.class);
    println!("  Description: {}", crate::classifier::magic::class_description(&classification.class));
    println!("  Size: {} bytes", classification.file_size);
    println!("  Magic match: {}", classification.extension_matches_magic);

    // Check dependencies
    let router = RunnerRouter::new();
    let deps = router.check_all_dependencies();

    println!("\n✓ Dependencies:");
    for (runner_name, statuses) in deps {
        println!("  {}:", runner_name);
        for status in statuses {
            let status_str = if status.available {
                "✓"
            } else {
                "✗"
            };
            println!(
                "    {} {} ({})",
                status_str,
                status.name,
                status.version.as_deref().unwrap_or("unknown")
            );
        }
    }

    Ok(())
}

/// View audit logs
pub fn view_logs(
    _tail: bool,
    severity: Option<String>,
    _since: Option<String>,
    export: Option<PathBuf>,
) -> Result<()> {
    let log_path = get_audit_log_path();

    if !log_path.exists() {
        println!("No audit log found at {}", log_path.display());
        return Ok(());
    }

    let content = std::fs::read_to_string(&log_path)?;
    let lines: Vec<&str> = content.lines().collect();

    for line in &lines {
        // Apply severity filter
        if let Some(ref sev) = severity {
            if !line.contains(sev) {
                continue;
            }
        }
        println!("{}", line);
    }

    if let Some(export_path) = export {
        std::fs::write(&export_path, content)?;
        println!("Exported logs to {}", export_path.display());
    }

    Ok(())
}

/// Clear all audit logs
pub fn clear_logs() -> Result<()> {
    let log_path = get_audit_log_path();

    if log_path.exists() {
        // Truncate the file (clear contents but keep file)
        std::fs::write(&log_path, "")?;
        tracing::info!("Audit log cleared at {}", log_path.display());
    }

    // Also clear the in-memory ring buffer
    let ring = get_or_init_ring();
    if let Ok(mut guard) = ring.lock() {
        if let Some(ref mut buf) = *guard {
            buf.clear();
        }
    }

    Ok(())
}

/// Get the audit log path
pub fn get_audit_log_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("boru")
        .join("audit.log")
}

/// Log an intercept event
///
/// GATE 7: Every intercept MUST write to audit log BEFORE returning verdict
pub fn log_intercept(severity: Severity, action: &str, reason: &str, request_id: uuid::Uuid) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    // Format: [TIMESTAMP] [SEVERITY] [ACTION_BLOCKED] [REASON]
    let log_line = format!(
        "[{}] [{:?}] [{}] [{}]",
        timestamp, severity, action, reason
    );
    tracing::info!("{}", log_line);

    // Write to ring buffer (GATE 6: bounded)
    let entry = AuditEntry {
        timestamp: timestamp.clone(),
        severity,
        action: action.to_string(),
        reason: reason.to_string(),
        request_id,
    };

    let ring = get_or_init_ring();
    if let Ok(mut guard) = ring.lock() {
        if let Some(ref mut buf) = *guard {
            buf.push(entry);
        }
    }

    // Also persist to audit log file (append)
    let log_dir = dirs::data_dir().map(|d| d.join("boru"));
    if let Some(ref dir) = log_dir {
        let _ = std::fs::create_dir_all(dir);
        let log_file = dir.join("audit.log");
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{}", log_line)
            });
    }
}

/// Get all quarantined items
pub fn list_quarantine() -> Result<Vec<crate::intercept::quarantine::QuarantineItem>> {
    crate::intercept::quarantine::list_quarantined()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::policy::SecurityMode;

    #[test]
    fn test_policy_from_str() {
        assert!(matches!(Policy::from("strict"), Policy::Strict));
        assert!(matches!(Policy::from("STRICT"), Policy::Strict));
        assert!(matches!(Policy::from("permissive"), Policy::Permissive));
        assert!(matches!(Policy::from("PERMISSIVE"), Policy::Permissive));
    }

    #[test]
    fn test_security_mode_from_str() {
        assert_eq!(SecurityMode::from("hard"), SecurityMode::Hard);
        assert_eq!(SecurityMode::from("mid"), SecurityMode::Mid);
        assert_eq!(SecurityMode::from("easy"), SecurityMode::Easy);
        assert_eq!(SecurityMode::from("custom"), SecurityMode::Custom);
    }

    #[test]
    fn test_ring_buffer_bounded() {
        let mut ring = AuditRingBuffer::new(3);
        for i in 0..5 {
            ring.push(AuditEntry {
                timestamp: format!("T{}", i),
                severity: Severity::Low,
                action: "TEST".to_string(),
                reason: format!("entry {}", i),
                request_id: uuid::Uuid::new_v4(),
            });
        }
        // Only last 3 entries remain
        assert_eq!(ring.entries().len(), 3);
        assert_eq!(ring.entries()[0].reason, "entry 2");
        assert_eq!(ring.entries()[2].reason, "entry 4");
    }

    #[test]
    fn test_ring_buffer_clear() {
        let mut ring = AuditRingBuffer::new(10);
        ring.push(AuditEntry {
            timestamp: "now".to_string(),
            severity: Severity::Low,
            action: "TEST".to_string(),
            reason: "test".to_string(),
            request_id: uuid::Uuid::new_v4(),
        });
        ring.clear();
        assert!(ring.entries().is_empty());
    }

    #[test]
    fn test_execute_missing_file() {
        let result = execute(
            PathBuf::from("nonexistent.wasm"),
            "strict".to_string(),
            None,
        );
        assert!(result.is_ok());
        match result.unwrap() {
            Verdict::Blocked { reason } => assert!(reason.contains("not found")),
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }

    #[test]
    fn test_execute_invalid_wasm() {
        // Create a temp file with invalid content
        let tmp = std::env::temp_dir().join("boru_test_invalid.wasm");
        std::fs::write(&tmp, b"not wasm bytes").unwrap();
        let result = execute(tmp.clone(), "strict".to_string(), None);
        let _ = std::fs::remove_file(&tmp);
        assert!(result.is_ok());
        match result.unwrap() {
            Verdict::Blocked { reason } => assert!(reason.contains("magic bytes")),
            other => panic!("Expected Blocked, got {:?}", other),
        }
    }
}
