//! BORU Session Management — Replay and audit
//!
//! Provides:
//! - Session recording and storage
//! - Replay functionality for audit trails
//! - Timeline reconstruction

pub mod replay;

pub use replay::{
    Session, SessionBuilder, SessionEvent, SessionInfo, SessionSummary,
    EventType, EventVerdict, ReplayViewer,
};
