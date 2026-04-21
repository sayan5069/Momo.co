//! BORU Watchdog — Real-time file monitoring
//!
//! Monitors a directory continuously.
//! Any new file dropped -> auto-scanned instantly.
//! Like real-time AV protection.

use crate::cage::policy::SecurityMode;
use crate::scanner::{DirectoryScanner, ScanResult, Verdict};
use anyhow::Result;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Watchdog configuration
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    /// Path to watch
    pub watch_path: PathBuf,
    /// Security mode
    pub mode: SecurityMode,
    /// Debounce delay in milliseconds
    pub debounce_ms: u64,
    /// Watch recursively
    pub recursive: bool,
    /// Show desktop notifications (if available)
    pub notify_user: bool,
}

impl WatchdogConfig {
    /// Create new config with defaults
    pub fn new(path: PathBuf) -> Self {
        Self {
            watch_path: path,
            mode: SecurityMode::Mid,
            debounce_ms: 500,
            recursive: true,
            notify_user: false,
        }
    }

    /// Set security mode
    pub fn with_mode(mut self, mode: SecurityMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set debounce delay
    pub fn with_debounce(mut self, ms: u64) -> Self {
        self.debounce_ms = ms;
        self
    }

    /// Set recursive
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Enable notifications
    pub fn with_notify(mut self, notify_user: bool) -> Self {
        self.notify_user = notify_user;
        self
    }
}

/// Watchdog event types
#[derive(Debug, Clone)]
pub enum WatchdogEvent {
    /// New file created
    FileCreated(PathBuf),
    /// File modified
    FileModified(PathBuf),
    /// File deleted (log only)
    FileDeleted(PathBuf),
    /// Scan completed
    ScanCompleted(ScanResult),
    /// File quarantined
    FileQuarantined(PathBuf, String),
    /// Error occurred
    Error(String),
}

/// Watchdog scanner
pub struct Watchdog {
    config: WatchdogConfig,
    scanner: DirectoryScanner,
    processed: Arc<Mutex<HashSet<PathBuf>>>,
    debounce_times: Arc<Mutex<std::collections::HashMap<PathBuf, Instant>>>,
}

impl Watchdog {
    /// Create new watchdog
    pub fn new(config: WatchdogConfig) -> Self {
        let scanner = DirectoryScanner::new(config.mode);

        Self {
            config,
            scanner,
            processed: Arc::new(Mutex::new(HashSet::new())),
            debounce_times: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Start watching (blocking)
    pub fn watch(&self, event_sender: Sender<WatchdogEvent>) -> Result<()> {
        let (tx, rx) = channel();

        let recursive_mode = if self.config.recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        let mut watcher: RecommendedWatcher = Watcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = tx.send(event);
                }
            },
            Config::default(),
        )?;

        watcher.watch(&self.config.watch_path, recursive_mode)?;

        let _ = event_sender.send(WatchdogEvent::FileCreated(
            self.config.watch_path.clone()
        ));

        loop {
            match rx.recv() {
                Ok(event) => {
                    self.handle_event(event, &event_sender)?;
                }
                Err(e) => {
                    let _ = event_sender.send(WatchdogEvent::Error(format!("Watch error: {}", e)));
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a filesystem event
    fn handle_event(
        &self,
        event: Event,
        sender: &Sender<WatchdogEvent>,
    ) -> Result<()> {
        for path in event.paths {
            match event.kind {
                notify::EventKind::Create(_) => {
                    // Wait for file to finish writing (debounce)
                    std::thread::sleep(Duration::from_millis(self.config.debounce_ms));

                    if self.should_process(&path) {
                        let _ = sender.send(WatchdogEvent::FileCreated(path.clone()));
                        self.scan_file(&path, sender)?;
                    }
                }
                notify::EventKind::Modify(_) => {
                    if self.should_process(&path) {
                        let _ = sender.send(WatchdogEvent::FileModified(path.clone()));
                        self.scan_file(&path, sender)?;
                    }
                }
                notify::EventKind::Remove(_) => {
                    let _ = sender.send(WatchdogEvent::FileDeleted(path.clone()));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Check if file should be processed (debounce)
    fn should_process(&self, path: &Path) -> bool {
        // Only process files
        if !path.is_file() {
            return false;
        }

        let mut times = self.debounce_times.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let debounce = Duration::from_millis(self.config.debounce_ms);

        if let Some(last_time) = times.get(path) {
            if now.duration_since(*last_time) < debounce {
                return false;
            }
        }

        times.insert(path.to_path_buf(), now);
        true
    }

    /// Scan a file
    fn scan_file(
        &self,
        path: &Path,
        sender: &Sender<WatchdogEvent>,
    ) -> Result<()> {
        // Mark as processed
        if let Ok(mut processed) = self.processed.lock() {
            processed.insert(path.to_path_buf());
        }

        // Scan the parent directory but filter for this file
        let scan_dir = path.parent().unwrap_or(Path::new("."));
        let scan_result = self.scanner.scan(scan_dir)?;

        // Find result for this specific file
        if let Some(result) = scan_result.results.iter().find(|r| r.path == path) {
            let _ = sender.send(WatchdogEvent::ScanCompleted(result.clone()));

            // Handle critical/known bad
            match result.verdict {
                Verdict::Critical | Verdict::KnownBad => {
                    // In AUDIT mode, just log — don't quarantine
                    if self.config.mode == SecurityMode::Audit {
                        let request_id = uuid::Uuid::new_v4();
                        crate::cage::log_intercept(
                            crate::cage::Severity::High,
                            "WATCHDOG_OBSERVED",
                            &format!("AUDIT mode: Detected {} but not quarantining", result.verdict),
                            request_id,
                        );
                        return Ok(());
                    }

                    // Quarantine the file
                    let reason = result.reason.clone().unwrap_or_else(|| "Watchdog detection".to_string());
                    match crate::intercept::quarantine::quarantine_file(
                        path,
                        "WATCHDOG_DETECT",
                        crate::cage::Severity::Critical,
                        &uuid::Uuid::new_v4().to_string(),
                        &reason,
                        &format!("{:?}", self.config.mode),
                        "AUTO_BLOCKED",
                    ) {
                        Ok(_) => {
                            let _ = sender.send(WatchdogEvent::FileQuarantined(path.to_path_buf(), reason));
                        }
                        Err(e) => {
                            let _ = sender.send(WatchdogEvent::Error(format!("Quarantine failed: {}", e)));
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Get number of processed files
    pub fn processed_count(&self) -> usize {
        self.processed.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Polling-based fallback watchdog (if notify is unavailable or too heavy)
pub struct PollingWatchdog {
    config: WatchdogConfig,
    scanner: DirectoryScanner,
    known_files: Arc<Mutex<HashSet<PathBuf>>>,
}

impl PollingWatchdog {
    /// Create new polling watchdog
    pub fn new(config: WatchdogConfig) -> Self {
        let scanner = DirectoryScanner::new(config.mode);
        Self {
            config,
            scanner,
            known_files: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Start polling (blocking)
    pub fn watch(&self, event_sender: Sender<WatchdogEvent>) -> Result<()> {
        let poll_interval = Duration::from_secs(2);

        let _ = event_sender.send(WatchdogEvent::FileCreated(
            self.config.watch_path.clone()
        ));

        loop {
            self.poll(&event_sender)?;
            std::thread::sleep(poll_interval);
        }
    }

    /// Poll for changes
    fn poll(&self, sender: &Sender<WatchdogEvent>) -> Result<()> {
        let current_files = self.list_files()?;
        let mut known = self.known_files.lock().unwrap_or_else(|e| e.into_inner());

        // Check for new files
        let new_files: Vec<PathBuf> = current_files.iter()
            .filter(|p| !known.contains(*p))
            .cloned()
            .collect();

        for path in new_files {
            std::thread::sleep(Duration::from_millis(self.config.debounce_ms));
            let _ = sender.send(WatchdogEvent::FileCreated(path.clone()));
            known.insert(path);
        }

        // Check for deleted files
        let to_remove: Vec<_> = known
            .iter()
            .filter(|p| !current_files.contains(*p))
            .cloned()
            .collect();

        for path in to_remove {
            known.remove(&path);
            let _ = sender.send(WatchdogEvent::FileDeleted(path));
        }

        Ok(())
    }

    /// List all files in watch path using std::fs (no walkdir dependency)
    fn list_files(&self) -> Result<HashSet<PathBuf>> {
        let mut files = HashSet::new();

        if self.config.recursive {
            Self::collect_files_recursive(&self.config.watch_path, &mut files)?;
        } else {
            for entry in std::fs::read_dir(&self.config.watch_path)? {
                let entry = entry?;
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    files.insert(entry.path());
                }
            }
        }

        Ok(files)
    }

    /// Recursively collect files using std::fs
    fn collect_files_recursive(dir: &Path, files: &mut HashSet<PathBuf>) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                files.insert(path);
            } else if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.') {
                        Self::collect_files_recursive(&path, files)?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// Create and run a watchdog with the appropriate backend
pub fn run_watchdog(
    config: WatchdogConfig,
    sender: Sender<WatchdogEvent>,
) -> Result<()> {
    let watchdog = Watchdog::new(config);
    watchdog.watch(sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_config() {
        let config = WatchdogConfig::new(PathBuf::from("/tmp"))
            .with_mode(SecurityMode::Hard)
            .with_debounce(1000)
            .with_recursive(false)
            .with_notify(true);

        assert_eq!(config.mode, SecurityMode::Hard);
        assert_eq!(config.debounce_ms, 1000);
        assert!(!config.recursive);
        assert!(config.notify_user);
    }
}
