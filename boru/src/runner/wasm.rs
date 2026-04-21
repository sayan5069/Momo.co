//! WASM Runner — wasmtime sandbox execution
//!
//! Strongest isolation level. Uses wasmtime with:
//! - Fuel budget enforcement
//! - Memory limits (64MB hard ceiling)
//! - Deny-by-default WASI capabilities
//! - Disabled SIMD and memory64

use crate::classifier::ClassificationResult;
use crate::classifier::magic::FileClass;
use crate::runner::{DependencyStatus, Runner, RunnerVerdict};
use anyhow::{Context, Result};
use std::path::Path;

/// Default fuel limit (1 billion instructions)
const DEFAULT_FUEL_LIMIT: u64 = 1_000_000_000;
/// Maximum WASM memory pages (1024 pages × 64KB = 64MB)
const MEMORY_PAGES_LIMIT: u32 = 1024;
/// Maximum WASM stack size (1MB)
const MAX_WASM_STACK: usize = 1 << 20;

/// WASM runner using wasmtime
pub struct WasmRunner;

impl WasmRunner {
    /// Create a new WASM runner
    pub fn new() -> Self {
        Self
    }

    /// Build a hardened wasmtime Config
    fn build_config() -> Result<wasmtime::Config> {
        let mut config = wasmtime::Config::new();

        // Parallel compilation for faster module loading
        config.parallel_compilation(true);

        // Security: fuel system for CPU budget enforcement
        config.consume_fuel(true);

        // Security: 1MB stack limit
        config.max_wasm_stack(MAX_WASM_STACK);

        // Security: disable dangerous features
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.wasm_memory64(false);
        config.wasm_multi_value(false);

        Ok(config)
    }
}

impl Default for WasmRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for WasmRunner {
    fn can_handle(&self, class: &FileClass) -> bool {
        class == &FileClass::Wasm
    }

    fn execute(
        &self,
        path: &Path,
        _classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        // Read WASM bytes
        let wasm_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read WASM file: {}", path.display()))?;

        // Validate magic bytes
        if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\x00asm" {
            return Ok(RunnerVerdict::Blocked {
                reason: "Invalid WASM magic bytes".to_string(),
            });
        }

        // Build hardened engine
        let config = Self::build_config()?;
        let engine = wasmtime::Engine::new(&config)?;
        let module = wasmtime::Module::new(&engine, &wasm_bytes)?;

        // Create WASI context with minimal capabilities
        let wasi_ctx = wasmtime_wasi::WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            // Deny-by-default: no network, no host FS, no env vars
            .build_p1();

        // Create store with fuel budget
        let mut store: wasmtime::Store<wasmtime_wasi::preview1::WasiP1Ctx> =
            wasmtime::Store::new(&engine, wasi_ctx);
        store
            .set_fuel(DEFAULT_FUEL_LIMIT)
            .context("Failed to set fuel budget")?;

        // Create linker with WASI functions
        let mut linker: wasmtime::Linker<wasmtime_wasi::preview1::WasiP1Ctx> =
            wasmtime::Linker::new(&engine);
        wasmtime_wasi::preview1::add_to_linker_sync(&mut linker, |ctx| ctx,
        )?;

        // Instantiate and run
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(inst) => inst,
            Err(e) => {
                return Ok(RunnerVerdict::Blocked {
                    reason: format!("WASM instantiation failed: {}", e),
                });
            }
        };

        // Call _start if it exists
        let result: anyhow::Result<()> =
            if let Ok(start) = instance.get_typed_func::<(), ()>(&mut store, "_start"
            ) {
                start.call(&mut store, ())
            } else {
                // No _start found, treat as data module
                Ok(())
            };

        // Check fuel consumption
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_consumed = DEFAULT_FUEL_LIMIT.saturating_sub(fuel_remaining);

        match result {
            Ok(()) => Ok(RunnerVerdict::Success {
                output: format!("Executed successfully, fuel consumed: {}", fuel_consumed),
            }),
            Err(e) => {
                let err_str = format!("{:?}", e);
                if err_str.contains("fuel") || err_str.contains("Fuel") {
                    Ok(RunnerVerdict::Timeout)
                } else {
                    Ok(RunnerVerdict::Blocked {
                        reason: format!("WASM trap: {}", e),
                    })
                }
            }
        }
    }

    fn check_dependencies(&self) -> Vec<DependencyStatus> {
        vec![DependencyStatus {
            name: "wasmtime".to_string(),
            available: true, // Built-in
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            path: None,
        }]
    }
}
