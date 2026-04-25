use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

mod cage;
mod classifier;
mod config;
mod iam;
mod intercept;
mod runner;
mod scanner;
mod session;
mod shadow;
mod sinkhole;
mod socket;
mod threat;
mod tui;
mod watchdog;

/// BORU — Security Cage Engine for Project MOMO
/// "What runs here, stays here."
#[derive(Parser)]
#[command(name = "boru")]
#[command(about = "BORU Security Cage — Universal file sandbox")]
#[command(version = "0.3.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute code in the security cage
    Cage {
        /// Input file to execute
        #[arg(short, long)]
        input: PathBuf,

        /// Security mode: hard, mid, easy, audit, custom, audit
        #[arg(long, value_name = "MODE", default_value = "mid")]
        mode: String,

        /// Fuel limit (max WASM instructions)
        #[arg(long, value_name = "N")]
        fuel: Option<u64>,

        /// Load custom rules from config file
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
    },

    /// Static analysis check (dry-run)
    Check {
        /// Input file to analyze
        #[arg(short, long)]
        input: PathBuf,
    },

    /// Start the socket daemon
    Daemon {
        /// Socket path (default uses socket::config::BORU_SOCKET_PATH)
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },

    /// Launch the Ratatui dashboard
    Tui {
        /// Socket path to connect to
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },

    /// View audit logs
    Log {
        /// Tail the log continuously
        #[arg(long)]
        tail: bool,

        /// Filter by severity level
        #[arg(long, value_name = "LEVEL")]
        severity: Option<String>,

        /// Show entries since timestamp
        #[arg(long, value_name = "TIME")]
        since: Option<String>,

        /// Export logs to file
        #[arg(long, value_name = "PATH")]
        export: Option<PathBuf>,

        /// Clear all audit logs (with confirmation)
        #[arg(long)]
        clear: bool,

        /// Verify the tamper chain integrity
        #[arg(long)]
        verify: bool,

        /// Verify a specific entry by sequence number
        #[arg(long, value_name = "N")]
        entry: Option<u64>,
    },

    /// List quarantined files
    Quarantine {
        /// Restore a quarantined file
        #[arg(long, value_name = "ID")]
        restore: Option<String>,

        /// Delete a quarantined file permanently
        #[arg(long, value_name = "ID")]
        delete: Option<String>,

        /// List all quarantined files
        #[arg(long)]
        list: bool,
    },

    /// Show dependency status for all runners
    Deps,

    /// Scan a directory for threats
    Scan {
        /// Path to scan
        #[arg(short, long)]
        path: PathBuf,

        /// Security mode: hard, mid, easy, audit
        #[arg(long, value_name = "MODE", default_value = "mid")]
        mode: String,

        /// Maximum recursion depth
        #[arg(long, value_name = "N")]
        depth: Option<usize>,

        /// Output format: console, markdown
        #[arg(long, value_name = "FORMAT", default_value = "console")]
        format: String,

        /// Export report to file
        #[arg(long, value_name = "PATH")]
        report: Option<PathBuf>,
    },

    /// Start watchdog mode (real-time file monitoring)
    Watch {
        /// Path to watch
        #[arg(short, long)]
        path: PathBuf,

        /// Security mode: hard, mid, easy, audit
        #[arg(long, value_name = "MODE", default_value = "mid")]
        mode: String,

        /// Watch recursively
        #[arg(long, default_value = "true")]
        recursive: bool,

        /// Use polling fallback instead of native events
        #[arg(long)]
        poll: bool,
    },

    /// Manage the hash database
    #[command(name = "db")]
    Db {
        /// Add a hash to the database
        #[arg(long, value_name = "SHA256")]
        add: Option<String>,

        /// Name for the hash entry
        #[arg(long, value_name = "NAME")]
        name: Option<String>,

        /// Family for the hash entry
        #[arg(long, value_name = "FAMILY")]
        family: Option<String>,

        /// Check a file's hash against the database
        #[arg(long, value_name = "PATH")]
        check: Option<PathBuf>,

        /// Remove a hash from the database
        #[arg(long, value_name = "SHA256")]
        remove: Option<String>,

        /// Import hashes from a JSON file
        #[arg(long, value_name = "PATH")]
        import: Option<PathBuf>,

        /// Show database statistics
        #[arg(long)]
        stats: bool,

        /// List all entries
        #[arg(long)]
        list: bool,
    },

    /// Session replay — view execution timelines
    Replay {
        /// Session ID to replay
        #[arg(long, value_name = "ID")]
        session: Option<String>,

        /// List all sessions
        #[arg(long)]
        list: bool,

        /// Export session to file
        #[arg(long, value_name = "PATH")]
        export: Option<PathBuf>,
    },

    /// Filesystem rollback
    Rollback {
        /// Session ID to rollback
        #[arg(long, value_name = "ID")]
        session: Option<String>,

        /// Dry-run (show what would be restored)
        #[arg(long)]
        dry_run: bool,

        /// List all shadow sessions
        #[arg(long)]
        list: bool,

        /// Clear shadow for a session
        #[arg(long, value_name = "ID")]
        clear: Option<String>,
    },

    /// Agent identity management
    Iam {
        /// Create a new agent
        #[arg(long, value_name = "NAME")]
        create_agent: Option<String>,

        /// Agent description
        #[arg(long, value_name = "DESC", default_value = "AI coding agent")]
        description: String,

        /// List all agents
        #[arg(long)]
        list: bool,

        /// Revoke an agent's token
        #[arg(long, value_name = "NAME")]
        revoke: Option<String>,

        /// Show agent details
        #[arg(long, value_name = "NAME")]
        show: Option<String>,
    },
}

fn main() -> ExitCode {
    // Initialize tracing
    let _ = tracing_subscriber::fmt()
        .with_env_filter("boru=info")
        .try_init();

    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Cage {
            input,
            mode,
            fuel,
            config: config_path,
        } => {
            use cage::policy::SecurityMode;

            let security_mode = SecurityMode::from(mode.as_str());

            // Load custom config if provided and mode is CUSTOM
            if security_mode == SecurityMode::Custom {
                if let Some(path) = config_path {
                    let custom_config = config::Config::load_from(&path)?;
                    println!("Loaded custom config from {}", path.display());
                    println!("  Allowed paths: {}", custom_config.allowed_paths.len());
                    println!("  Denied paths: {}", custom_config.denied_paths.len());
                } else {
                    // Try to load default config
                    match config::Config::load() {
                        Ok(custom_config) => {
                            println!("Loaded default custom config");
                            println!(
                                "  Allowed paths: {}",
                                custom_config.allowed_paths.len()
                            );
                            println!(
                                "  Denied paths: {}",
                                custom_config.denied_paths.len()
                            );
                        }
                        Err(_) => {
                            println!("Warning: No custom config loaded. Using defaults.");
                        }
                    }
                }
            }

            // Run with enhanced cage
            let result = cage::run_cage(input, security_mode, fuel)?;

            // Display result
            println!("{}", result);

            // Exit code based on result
            match result.verdict {
                cage::verdict::Verdict::Allowed { .. } => std::process::exit(0),
                cage::verdict::Verdict::Timeout => std::process::exit(3),
                _ => std::process::exit(1),
            }
        }
        Commands::Check { input } => {
            cage::check(input)?;
        }
        Commands::Daemon { socket } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(socket::run_daemon(socket))?;
        }
        Commands::Tui { socket } => {
            tui::run(socket)?;
        }
        Commands::Log {
            tail,
            severity,
            since,
            export,
            clear,
            verify,
            entry,
        } => {
            if clear {
                cage::clear_logs()?;
                println!("Audit log cleared.");
            } else if verify {
                let chain = intercept::audit::TamperChain::load()?;
                if let Some(seq) = entry {
                    // Verify specific entry
                    match chain.verify_entry(seq) {
                        Some(result) => println!("{}", result.message()),
                        None => println!("Entry #{} not found", seq),
                    }
                } else {
                    // Verify entire chain
                    let result = chain.verify();
                    println!("{}", result.message());
                }
            } else {
                cage::view_logs(tail, severity, since, export)?;
            }
        }
        Commands::Quarantine {
            restore,
            delete,
            list,
        } => {
            if list || (restore.is_none() && delete.is_none()) {
                let items = cage::list_quarantine()?;
                if items.is_empty() {
                    println!("No quarantined files.");
                } else {
                    println!("Quarantined files:");
                    for item in items {
                        println!("  Folder: {}", item.folder.display());
                        println!(
                            "    Original: {}",
                            item.metadata.original_path
                        );
                        println!("    Reason: {}", item.metadata.reason);
                        println!(
                            "    Timestamp: {}",
                            item.metadata.timestamp
                        );
                        println!(
                            "    Severity: {}",
                            item.metadata.severity
                        );
                        println!();
                    }
                }
            }

            if let Some(id) = restore {
                let quarantine_dir = std::path::PathBuf::from("/tmp/momo/quarantine").join(id);
                let restored_path = intercept::quarantine::restore_quarantine(&quarantine_dir)?;
                println!("Restored: {}", restored_path.display());
            }

            if let Some(id) = delete {
                let quarantine_dir = std::path::PathBuf::from("/tmp/momo/quarantine").join(&id);
                intercept::quarantine::delete_quarantine(&quarantine_dir)?;
                println!("Deleted quarantine: {}", id);
            }
        }
        Commands::Deps => {
            use runner::RunnerRouter;

            println!("BORU Dependency Status");
            println!("=======================");
            println!();

            let router = RunnerRouter::new();
            let deps = router.check_all_dependencies();

            for (runner_name, statuses) in deps {
                println!("{}:", runner_name);
                for status in statuses {
                    let status_symbol = if status.available { "✓" } else { "✗" };
                    let version_str = status
                        .version
                        .as_deref()
                        .unwrap_or(if status.available { "available" } else { "not found" });
                    let path_str = status
                        .path
                        .as_ref()
                        .map(|p| format!(" at {}", p))
                        .unwrap_or_default();
                    println!(
                        "  {} {} ({}){}", 
                        status_symbol, status.name, version_str, path_str
                    );
                }
                println!();
            }

            println!("Note: Missing interpreters will cause Unsupported errors");
            println!("      for their respective file types.");
        }
        Commands::Scan {
            path,
            mode,
            depth,
            format,
            report,
        } => {
            use cage::policy::SecurityMode;

            let security_mode = SecurityMode::from(mode.as_str());
            let mut dir_scanner = scanner::DirectoryScanner::new(security_mode);

            if let Some(d) = depth {
                dir_scanner = dir_scanner.with_max_depth(d);
            }

            // Try to load hash database
            if let Ok(db) = threat::HashDB::load() {
                dir_scanner = dir_scanner.with_hash_db(db);
            }

            let report_data = dir_scanner.scan(&path)?;

            match format.as_str() {
                "markdown" | "md" => {
                    let md = report_data.to_markdown();
                    if let Some(output_path) = report {
                        std::fs::write(&output_path, &md)?;
                        println!("Report saved to {}", output_path.display());
                    } else {
                        println!("{}", md);
                    }
                }
                _ => {
                    println!("{}", report_data.to_console_output());
                    if let Some(output_path) = report {
                        let md = report_data.to_markdown();
                        std::fs::write(&output_path, &md)?;
                        println!("\nReport saved to {}", output_path.display());
                    }
                }
            }
        }
        Commands::Watch {
            path,
            mode,
            recursive,
            poll,
        } => {
            use cage::policy::SecurityMode;

            let security_mode = SecurityMode::from(mode.as_str());
            let config = watchdog::WatchdogConfig::new(path.clone())
                .with_mode(security_mode)
                .with_recursive(recursive);

            println!("🔍 BORU Watchdog — watching {} ({:?} mode)", path.display(), security_mode);
            println!("Press Ctrl+C to stop.\n");

            let (tx, rx) = std::sync::mpsc::channel();

            // Spawn event printer in background
            let handle = std::thread::spawn(move || {
                while let Ok(event) = rx.recv() {
                    match event {
                        watchdog::WatchdogEvent::FileCreated(p) => {
                            println!("📄 New file: {}", p.display());
                        }
                        watchdog::WatchdogEvent::FileModified(p) => {
                            println!("✏️  Modified: {}", p.display());
                        }
                        watchdog::WatchdogEvent::FileDeleted(p) => {
                            println!("🗑️  Deleted: {}", p.display());
                        }
                        watchdog::WatchdogEvent::ScanCompleted(result) => {
                            println!(
                                "   {} {} (entropy: {:.1})",
                                result.emoji(),
                                result.path.display(),
                                result.entropy.score
                            );
                        }
                        watchdog::WatchdogEvent::FileQuarantined(p, reason) => {
                            println!("🔴 QUARANTINED: {} — {}", p.display(), reason);
                        }
                        watchdog::WatchdogEvent::Error(e) => {
                            eprintln!("❌ Error: {}", e);
                        }
                    }
                }
            });

            if poll {
                let polling = watchdog::PollingWatchdog::new(config);
                polling.watch(tx)?;
            } else {
                watchdog::run_watchdog(config, tx)?;
            }

            let _ = handle.join();
        }
        Commands::Db {
            add,
            name,
            family,
            check,
            remove,
            import,
            stats,
            list,
        } => {
            let mut db = threat::HashDB::load()?;

            if let Some(hash) = add {
                let entry_name = name.unwrap_or_else(|| "unknown".to_string());
                let entry_family = family.unwrap_or_else(|| "unknown".to_string());

                db.add(
                    &hash,
                    threat::HashEntry {
                        name: entry_name.clone(),
                        severity: threat::Severity::Critical,
                        family: entry_family,
                        added: chrono::Utc::now().format("%Y-%m-%d").to_string(),
                    },
                );
                db.save()?;
                println!("Added hash: {} ({})", &hash[..16], entry_name);
            }

            if let Some(path) = check {
                let file_hash = threat::compute_file_hash(&path)?;
                let status = db.check_hash(&file_hash);
                println!("File: {}", path.display());
                println!("SHA-256: {}", file_hash);
                match status {
                    threat::HashStatus::KnownBad(entry) => {
                        println!("🔴 KNOWN BAD: {} (family: {}, severity: {})",
                            entry.name, entry.family, entry.severity);
                    }
                    threat::HashStatus::Clean => {
                        println!("✅ Clean — hash not in database");
                    }
                    threat::HashStatus::Unknown => {
                        println!("⚠️  Unknown — check failed");
                    }
                }
            }

            if let Some(hash) = remove {
                if db.remove(&hash) {
                    db.save()?;
                    println!("Removed hash: {}", &hash[..16.min(hash.len())]);
                } else {
                    println!("Hash not found in database");
                }
            }

            if let Some(import_path) = import {
                let added = db.import_from_file(&import_path)?;
                db.save()?;
                println!("Imported {} new entries", added);
            }

            if stats {
                let s = db.stats();
                println!("Hash Database Statistics:");
                println!("{}", s);
            }

            if list {
                let entries = db.entries_sorted();
                if entries.is_empty() {
                    println!("Hash database is empty.");
                } else {
                    println!("Hash Database Entries ({}):", entries.len());
                    for (hash, entry) in entries {
                        println!(
                            "  {}... | {} | {} | {}",
                            &hash[..16.min(hash.len())],
                            entry.name,
                            entry.severity,
                            entry.family,
                        );
                    }
                }
            }
        }
        Commands::Replay {
            session,
            list,
            export,
        } => {
            if list {
                let sessions = session::Session::list_all()?;
                if sessions.is_empty() {
                    println!("No sessions recorded.");
                } else {
                    println!("Sessions:");
                    for info in sessions {
                        println!(
                            "  {} | {} | {} | {} events ({} blocked)",
                            info.session_id, info.started, info.mode,
                            info.total_events, info.blocked,
                        );
                    }
                }
            } else if let Some(session_id) = session {
                let s = session::Session::load(&session_id)?;
                println!("{}", s.to_timeline());

                if let Some(export_path) = export {
                    let json = s.to_json()?;
                    std::fs::write(&export_path, json)?;
                    println!("\nExported to {}", export_path.display());
                }
            } else {
                println!("Usage: boru replay --list | --session <ID>");
            }
        }
        Commands::Rollback {
            session,
            dry_run,
            list,
            clear,
        } => {
            let manager = shadow::RollbackManager::new()?;

            if list {
                let sessions = manager.list_sessions()?;
                if sessions.is_empty() {
                    println!("No shadow backups found.");
                } else {
                    println!("Shadow Backups:");
                    for info in sessions {
                        println!(
                            "  {} | {} | {} files",
                            info.session_id, info.created, info.file_count,
                        );
                    }
                }
            } else if let Some(ref session_id) = session {
                if dry_run {
                    let files = manager.dry_run(session_id)?;
                    println!("Dry-run rollback for session {}:", session_id);
                    for f in &files {
                        println!("  Would restore: {}", f.display());
                    }
                    println!("\n{} files would be restored.", files.len());
                } else {
                    println!("Rolling back session {}...", session_id);
                    let result = manager.rollback(session_id)?;
                    println!("Restored: {} files", result.success_count());
                    if result.failure_count() > 0 {
                        println!("Failed: {} files", result.failure_count());
                        for (path, reason) in &result.failed {
                            println!("  ✗ {}: {}", path.display(), reason);
                        }
                    }
                }
            } else if let Some(session_id) = clear {
                manager.clear(&session_id)?;
                println!("Cleared shadow for session: {}", session_id);
            } else {
                println!("Usage: boru rollback --list | --session <ID> [--dry-run] | --clear <ID>");
            }
        }
        Commands::Iam {
            create_agent,
            description,
            list,
            revoke,
            show,
        } => {
            let mut manager = iam::AgentManager::new()?;

            if let Some(name) = create_agent {
                let token = manager.create_agent(&name, &description, None)?;
                println!("✅ Agent '{}' created", name);
                println!();
                println!("╔══════════════════════════════════════════════════╗");
                println!("║  SAVE THIS TOKEN — IT WILL NOT BE SHOWN AGAIN   ║");
                println!("╠══════════════════════════════════════════════════╣");
                println!("║  {}  ║", token);
                println!("╚══════════════════════════════════════════════════╝");
                println!();
                println!("The agent must include this token in socket requests.");
            }

            if list {
                let agents = manager.list_agents();
                if agents.is_empty() {
                    println!("No agents registered.");
                } else {
                    println!("Registered Agents:");
                    for agent in agents {
                        let status = if agent.token.revoked { "REVOKED" } else { "ACTIVE" };
                        println!(
                            "  {} | {} | {} | {} requests",
                            agent.name, status, agent.registered, agent.request_count,
                        );
                    }
                }
            }

            if let Some(name) = revoke {
                manager.revoke_agent(&name)?;
                println!("🔴 Agent '{}' token revoked", name);
            }

            if let Some(name) = show {
                let details = manager.show_agent(&name)?;
                println!("{}", details);
            }
        }
    }

    Ok(())
}

// Type aliases for backward compatibility
type Store<T> = wasmtime::Store<T>;
type Linker<T> = wasmtime::Linker<T>;
