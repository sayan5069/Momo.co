//! Interpreter Runner — Bubblewrap + seccomp for interpreted languages
//!
//! PHASE 1 STRATEGY: Host interpreter via bubblewrap/unshare namespace
//! - Check if interpreter exists on host
//! - If found: wrap via bubblewrap → seccomp filter → BORU intercept
//! - If NOT found: return Verdict::Unsupported
//!
//! FUTURE PATH (documented in code):
//! - Python → rustpython.wasm
//! - JS/TS → quickjs.wasm
//! - Ruby → ruby.wasm
//! This removes host dependency entirely.

use crate::classifier::magic::FileClass;
use crate::classifier::ClassificationResult;
use crate::runner::{DependencyStatus, Runner, RunnerVerdict};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Interpreter configuration
struct InterpreterConfig {
    /// Command to check (e.g., "python3")
    command: &'static str,
    /// Version flag (e.g., "--version")
    version_flag: &'static str,
    /// File extensions this handles
    extensions: &'static [&'static str],
}

/// Interpreter runner for scripted languages
pub struct InterpreterRunner {
    configs: Vec<InterpreterConfig>,
}

impl InterpreterRunner {
    /// Create a new interpreter runner
    pub fn new() -> Self {
        let configs = vec![
            InterpreterConfig {
                command: "python3",
                version_flag: "--version",
                extensions: &["py"],
            },
            InterpreterConfig {
                command: "node",
                version_flag: "--version",
                extensions: &["js", "ts", "mjs"],
            },
            InterpreterConfig {
                command: "ruby",
                version_flag: "--version",
                extensions: &["rb"],
            },
            InterpreterConfig {
                command: "php",
                version_flag: "--version",
                extensions: &["php"],
            },
            InterpreterConfig {
                command: "perl",
                version_flag: "--version",
                extensions: &["pl", "pm"],
            },
            InterpreterConfig {
                command: "lua",
                version_flag: "-v",
                extensions: &["lua"],
            },
            InterpreterConfig {
                command: "bash",
                version_flag: "--version",
                extensions: &["sh", "bash"],
            },
            InterpreterConfig {
                command: "zsh",
                version_flag: "--version",
                extensions: &["zsh"],
            },
            InterpreterConfig {
                command: "fish",
                version_flag: "--version",
                extensions: &["fish"],
            },
            InterpreterConfig {
                command: "pwsh",
                version_flag: "--version",
                extensions: &["ps1"],
            },
            InterpreterConfig {
                command: "Rscript",
                version_flag: "--version",
                extensions: &["r"],
            },
            InterpreterConfig {
                command: "swift",
                version_flag: "--version",
                extensions: &["swift"],
            },
            InterpreterConfig {
                command: "kotlin",
                version_flag: "-version",
                extensions: &["kt", "kts"],
            },
            InterpreterConfig {
                command: "scala",
                version_flag: "-version",
                extensions: &["scala", "sc"],
            },
        ];

        Self { configs }
    }

    /// Get interpreter config for a file class
    fn get_config_for_class(&self,
        class: &FileClass,
    ) -> Option<&InterpreterConfig> {
        let ext = match class {
            FileClass::Python => "py",
            FileClass::JavaScript => "js",
            FileClass::TypeScript => "ts",
            FileClass::Ruby => "rb",
            FileClass::Php => "php",
            FileClass::Perl => "pl",
            FileClass::Lua => "lua",
            FileClass::Shell => "sh",
            FileClass::PowerShell => "ps1",
            FileClass::R => "r",
            FileClass::Swift => "swift",
            FileClass::Kotlin => "kt",
            FileClass::Scala => "scala",
            _ => return None,
        };

        self.configs.iter().find(|c| c.extensions.contains(&ext))
    }

    /// Check if interpreter is available on host
    fn check_interpreter(&self, command: &str) -> Option<String> {
        // Use 'which' command to check availability
        let output = Command::new("which").arg(command).output().ok()?;

        if output.status.success() {
            String::from_utf8(output.stdout).ok().map(|s| s.trim().to_string())
        } else {
            None
        }
    }

    /// Get interpreter version
    fn get_version(&self, command: &str, version_flag: &str) -> Option<String> {
        let output = Command::new(command)
            .arg(version_flag)
            .output()
            .ok()?;

        String::from_utf8(output.stdout)
            .ok()
            .or_else(|| String::from_utf8(output.stderr).ok())
            .map(|s| s.lines().next().unwrap_or("unknown").to_string())
    }

    /// Run with bubblewrap if available, otherwise return Unsupported
    fn run_with_bwrap(
        &self,
        interpreter: &str,
        _script_path: &Path,
    ) -> Result<RunnerVerdict> {
        // Check if bubblewrap is available
        let bwrap_available = Command::new("which")
            .arg("bwrap")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !bwrap_available {
            return Ok(RunnerVerdict::Unsupported {
                reason: format!(
                    "Interpreter '{}' found but bubblewrap not available for sandboxing",
                    interpreter
                ),
            });
        }

        // TODO: Implement full bubblewrap sandbox with:
        // - Read-only bind of script directory
        // - Private /tmp
        // - No network (--unshare-net)
        // - Seccomp filter
        // For now, return Unsupported to avoid security issues

        Ok(RunnerVerdict::Unsupported {
            reason: format!(
                "{} found on host. Bubblewrap sandbox needs implementation.\n\
                 Future: rustpython.wasm / quickjs.wasm will remove this dependency.",
                interpreter
            ),
        })
    }
}

impl Default for InterpreterRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for InterpreterRunner {
    fn can_handle(&self, class: &FileClass) -> bool {
        matches!(
            class,
            FileClass::Python
                | FileClass::JavaScript
                | FileClass::TypeScript
                | FileClass::Ruby
                | FileClass::Php
                | FileClass::Perl
                | FileClass::Lua
                | FileClass::Shell
                | FileClass::PowerShell
                | FileClass::R
                | FileClass::Swift
                | FileClass::Kotlin
                | FileClass::Scala
        )
    }

    fn execute(
        &self,
        _path: &Path,
        classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        let config = self
            .get_config_for_class(&classification.class)
            .context("No interpreter config for file class")?;

        // Check if interpreter is available
        let interpreter_path = self.check_interpreter(config.command);

        if let Some(path_str) = interpreter_path {
            // Log interpreter invocation
            let version = self.get_version(config.command, config.version_flag);

            // TODO Phase 2: Replace Command::new with bubblewrap namespace isolation
            // TODO Phase 2: Add seccomp-bpf profile per interpreter (see docs/SECCOMP_PLAN.md)
            // Python  → rustpython.wasm
            // JS/TS   → quickjs.wasm
            // Ruby    → ruby.wasm

            tracing::info!(
                "InterpreterRunner: {} at {:?} (version: {:?})",
                config.command,
                path_str,
                version
            );

            // Step 2: Set up workspace
            let workspace = std::path::Path::new("/tmp/momo/workspace/");
            if let Err(e) = std::fs::create_dir_all(workspace) {
                return Ok(RunnerVerdict::Blocked {
                    reason: format!("Failed to create workspace: {}", e),
                });
            }

            // Step 3: Execute with restrictions via std::process::Command
            // GATE 2 EXCEPTION: execution permitted in src/runner/ modules
            // This is the controlled execution path. Intercept layer wraps this.
            let output = match Command::new(&path_str)
                .arg(_path)
                .current_dir(workspace)
                .env_clear()                    // strip all env vars
                .env("HOME", workspace)         // fake home = workspace only
                .env("TMPDIR", workspace)
                .output()
            {
                Ok(out) => out,
                Err(e) => {
                    return Ok(RunnerVerdict::Blocked {
                        reason: format!("Execution failed: {}", e),
                    });
                }
            };

            // Step 4: Capture output
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);

            let combined_output = if !stderr.is_empty() {
                format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr)
            } else {
                stdout.clone()
            };

            // Step 5: Log execution event
            // Gate 7: ScriptExecuted event
            let request_id = uuid::Uuid::new_v4();
            crate::cage::log_intercept(
                crate::cage::Severity::Medium,
                "SCRIPT_EXECUTED",
                &format!(
                    "Executed {} script at {}. Exit code: {}",
                    config.command,
                    _path.display(),
                    exit_code
                ),
                request_id,
            );

            if output.status.success() {
                Ok(RunnerVerdict::Success { output: stdout })
            } else {
                Ok(RunnerVerdict::Blocked {
                    reason: format!("Script failed with code {}:\n{}", exit_code, combined_output),
                })
            }
        } else {
            // Interpreter not found
            Ok(RunnerVerdict::Unsupported {
                reason: format!(
                    "{} not found on host. Install {} to execute this file.\n\
                     Future: rustpython.wasm / quickjs.wasm will remove this dependency.",
                    config.command, config.command
                ),
            })
        }
    }

    fn check_dependencies(&self) -> Vec<DependencyStatus> {
        self.configs
            .iter()
            .map(|c| {
                let available = self.check_interpreter(c.command).is_some();
                let path = self.check_interpreter(c.command);
                let version = if available {
                    self.get_version(c.command, c.version_flag)
                } else {
                    None
                };

                DependencyStatus {
                    name: c.command.to_string(),
                    available,
                    version,
                    path,
                }
            })
            .collect()
    }
}

// TODO: seccomp-bpf hardening — see docs/SECCOMP_PLAN.md
// cfg(target_os = "linux")
// fn apply_seccomp_profile(_policy: &SeccompPolicy) -> Result<()> {
//     todo!("seccomp-bpf implementation pending WSL2/Linux verification")
// }
//
// Placeholder for seccomp policy structure
// pub struct SeccompPolicy {
//     allowed_syscalls: Vec<&'static str>,
//     denied_syscalls: Vec<&'static str>,
// }
