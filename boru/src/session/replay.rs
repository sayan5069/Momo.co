//! BORU Session Replay — Execution timeline reconstruction
//!
//! Reconstructs the full execution timeline from session logs.
//! Shows exactly what AI-generated code tried to do, in order.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Session event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    FileRead,
    FileWrite,
    NetworkCall,
    ProcessSpawn,
    EnvAccess,
    SystemCall,
    ExtensionMismatch,
    UnknownFileType,
    Quarantine,
    ShadowBackup,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::FileRead => write!(f, "FILE_READ"),
            EventType::FileWrite => write!(f, "FILE_WRITE"),
            EventType::NetworkCall => write!(f, "NETWORK_CALL"),
            EventType::ProcessSpawn => write!(f, "PROCESS_SPAWN"),
            EventType::EnvAccess => write!(f, "ENV_ACCESS"),
            EventType::SystemCall => write!(f, "SYSCALL"),
            EventType::ExtensionMismatch => write!(f, "EXT_MISMATCH"),
            EventType::UnknownFileType => write!(f, "UNKNOWN_TYPE"),
            EventType::Quarantine => write!(f, "QUARANTINE"),
            EventType::ShadowBackup => write!(f, "SHADOW_BACKUP"),
        }
    }
}

/// Verdict for an event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventVerdict {
    Allowed,
    Blocked,
    Prompted,
    Quarantined,
}

impl std::fmt::Display for EventVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventVerdict::Allowed => write!(f, "ALLOWED"),
            EventVerdict::Blocked => write!(f, "BLOCKED"),
            EventVerdict::Prompted => write!(f, "PROMPTED"),
            EventVerdict::Quarantined => write!(f, "QUARANTINED"),
        }
    }
}

impl EventVerdict {
    /// Get emoji for display
    pub fn emoji(&self) -> &'static str {
        match self {
            EventVerdict::Allowed => "✅",
            EventVerdict::Blocked => "🚫",
            EventVerdict::Prompted => "❓",
            EventVerdict::Quarantined => "🔴",
        }
    }
}

/// Session event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Sequence number
    pub seq: u64,
    /// Timestamp (ISO-8601)
    pub timestamp: String,
    /// Event type
    pub event_type: EventType,
    /// Event detail (path, destination, etc.)
    pub detail: String,
    /// Verdict
    pub verdict: EventVerdict,
    /// Severity (if applicable)
    pub severity: Option<String>,
}

/// Session summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Total number of events
    pub total_events: usize,
    /// Number of blocked events
    pub blocked: usize,
    /// Number of allowed events
    pub allowed: usize,
    /// Number of quarantined files
    pub quarantined: usize,
}

/// Session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID
    pub session_id: String,
    /// Start time (ISO-8601)
    pub started: String,
    /// End time (ISO-8601)
    pub ended: String,
    /// Security mode
    pub mode: String,
    /// Agent ID (optional)
    pub agent_id: Option<String>,
    /// Events
    pub events: Vec<SessionEvent>,
    /// Summary statistics
    pub summary: SessionSummary,
}

impl Session {
    /// Get default sessions directory
    pub fn sessions_dir() -> PathBuf {
        dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("boru")
            .join("sessions")
    }

    /// Get session file path
    pub fn session_path(&self) -> PathBuf {
        Self::sessions_dir().join(format!("{}.json", self.session_id))
    }

    /// Save session to file
    pub fn save(&self) -> Result<()> {
        let path = self.session_path();

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize session")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write session: {}", path.display()))?;

        Ok(())
    }

    /// Load session from file
    pub fn load(session_id: &str) -> Result<Self> {
        let path = Self::sessions_dir().join(format!("{}.json", session_id));

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Session not found: {}", session_id))?;

        let session: Session = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse session: {}", session_id))?;

        Ok(session)
    }

    /// List all sessions
    pub fn list_all() -> Result<Vec<SessionInfo>> {
        let dir = Self::sessions_dir();

        if !dir.exists() {
            return Ok(vec![]);
        }

        let mut sessions = Vec::new();

        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read sessions directory: {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map_or(false, |e| e == "json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Ok(session) = Self::load(stem) {
                        sessions.push(SessionInfo {
                            session_id: session.session_id,
                            started: session.started,
                            mode: session.mode,
                            total_events: session.summary.total_events,
                            blocked: session.summary.blocked,
                        });
                    }
                }
            }
        }

        // Sort by start time (newest first)
        sessions.sort_by(|a, b| b.started.cmp(&a.started));

        Ok(sessions)
    }

    /// Generate console timeline output
    pub fn to_timeline(&self) -> String {
        let mut lines = vec![
            format!(
                "SESSION: {} | Mode: {} | {}",
                self.session_id, self.mode, self.started
            ),
            "─".repeat(70),
        ];

        for event in &self.events {
            let time = &event.timestamp[11..19]; // Extract HH:MM:SS
            lines.push(format!(
                "{:3}  {}  {:12}  {:40}  {}",
                event.seq,
                time,
                event.event_type.to_string(),
                truncate(&event.detail, 38),
                event.verdict.emoji()
            ));
        }

        lines.push("─".repeat(70));
        lines.push(format!(
            "Summary: {} events | {} blocked | {} allowed | {} quarantined",
            self.summary.total_events,
            self.summary.blocked,
            self.summary.allowed,
            self.summary.quarantined
        ));
        lines.push("[↑↓] Navigate  [f] Filter  [e] Export  [q] Quit".to_string());

        lines.join("\n")
    }

    /// Filter events by verdict
    pub fn filter_by_verdict(&self, verdict: EventVerdict) -> Vec<&SessionEvent> {
        self.events.iter()
            .filter(|e| e.verdict == verdict)
            .collect()
    }

    /// Filter events by type
    pub fn filter_by_type(&self, event_type: EventType) -> Vec<&SessionEvent> {
        self.events.iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    /// Export to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .context("Failed to serialize session")
    }
}

/// Session info for listing
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: String,
    pub started: String,
    pub mode: String,
    pub total_events: usize,
    pub blocked: usize,
}

/// Session builder
pub struct SessionBuilder {
    session_id: String,
    mode: String,
    agent_id: Option<String>,
    events: Vec<SessionEvent>,
    started: String,
}

impl SessionBuilder {
    /// Create new session builder
    pub fn new(mode: &str) -> Self {
        Self {
            session_id: format!("session-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            mode: mode.to_string(),
            agent_id: None,
            events: Vec::new(),
            started: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Set agent ID
    pub fn with_agent_id(mut self, agent_id: &str) -> Self {
        self.agent_id = Some(agent_id.to_string());
        self
    }

    /// Set custom session ID
    pub fn with_session_id(mut self, id: &str) -> Self {
        self.session_id = id.to_string();
        self
    }

    /// Add an event
    pub fn add_event(
        &mut self,
        event_type: EventType,
        detail: &str,
        verdict: EventVerdict,
    ) {
        let seq = self.events.len() as u64 + 1;
        self.events.push(SessionEvent {
            seq,
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type,
            detail: detail.to_string(),
            verdict,
            severity: None,
        });
    }

    /// Add event with severity
    pub fn add_event_with_severity(
        &mut self,
        event_type: EventType,
        detail: &str,
        verdict: EventVerdict,
        severity: &str,
    ) {
        let seq = self.events.len() as u64 + 1;
        self.events.push(SessionEvent {
            seq,
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type,
            detail: detail.to_string(),
            verdict,
            severity: Some(severity.to_string()),
        });
    }

    /// Build the session
    pub fn build(self) -> Session {
        let total = self.events.len();
        let blocked = self.events.iter()
            .filter(|e| matches!(e.verdict, EventVerdict::Blocked))
            .count();
        let allowed = self.events.iter()
            .filter(|e| matches!(e.verdict, EventVerdict::Allowed))
            .count();
        let quarantined = self.events.iter()
            .filter(|e| matches!(e.verdict, EventVerdict::Quarantined))
            .count();

        Session {
            session_id: self.session_id,
            started: self.started,
            ended: chrono::Utc::now().to_rfc3339(),
            mode: self.mode,
            agent_id: self.agent_id,
            events: self.events,
            summary: SessionSummary {
                total_events: total,
                blocked,
                allowed,
                quarantined,
            },
        }
    }
}

/// Replay viewer
pub struct ReplayViewer {
    session: Session,
    filter: Option<EventVerdict>,
    selected_index: usize,
}

impl ReplayViewer {
    /// Create new viewer
    pub fn new(session: Session) -> Self {
        Self {
            session,
            filter: None,
            selected_index: 0,
        }
    }

    /// Set filter
    pub fn set_filter(&mut self, verdict: Option<EventVerdict>) {
        self.filter = verdict;
        self.selected_index = 0;
    }

    /// Get filtered events
    pub fn filtered_events(&self) -> Vec<&SessionEvent> {
        match self.filter {
            Some(ref v) => self.session.filter_by_verdict(v.clone()),
            None => self.session.events.iter().collect(),
        }
    }

    /// Navigate up
    pub fn up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    /// Navigate down
    pub fn down(&mut self) {
        let max = self.filtered_events().len().saturating_sub(1);
        if self.selected_index < max {
            self.selected_index += 1;
        }
    }

    /// Get current selection
    pub fn selected(&self) -> Option<&SessionEvent> {
        self.filtered_events().get(self.selected_index).copied()
    }
}

/// Helper: truncate string
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_builder() {
        let mut builder = SessionBuilder::new("MID");
        builder.add_event(EventType::FileRead, "/tmp/test.txt", EventVerdict::Allowed);
        builder.add_event(EventType::NetworkCall, "example.com", EventVerdict::Blocked);

        let session = builder.build();

        assert_eq!(session.mode, "MID");
        assert_eq!(session.events.len(), 2);
        assert_eq!(session.summary.total_events, 2);
        assert_eq!(session.summary.allowed, 1);
        assert_eq!(session.summary.blocked, 1);
    }

    #[test]
    fn test_event_verdict_emoji() {
        assert_eq!(EventVerdict::Allowed.emoji(), "✅");
        assert_eq!(EventVerdict::Blocked.emoji(), "🚫");
        assert_eq!(EventVerdict::Quarantined.emoji(), "🔴");
    }

    #[test]
    fn test_event_type_display() {
        assert_eq!(EventType::FileRead.to_string(), "FILE_READ");
        assert_eq!(EventType::NetworkCall.to_string(), "NETWORK_CALL");
    }

    #[test]
    fn test_filter_by_verdict() {
        let mut builder = SessionBuilder::new("MID");
        builder.add_event(EventType::FileRead, "/tmp/a.txt", EventVerdict::Allowed);
        builder.add_event(EventType::NetworkCall, "example.com", EventVerdict::Blocked);
        builder.add_event(EventType::FileWrite, "/tmp/b.txt", EventVerdict::Allowed);

        let session = builder.build();
        let blocked = session.filter_by_verdict(EventVerdict::Blocked);
        let allowed = session.filter_by_verdict(EventVerdict::Allowed);

        assert_eq!(blocked.len(), 1);
        assert_eq!(allowed.len(), 2);
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("this is a very long string", 10), "this is...");
    }
}
