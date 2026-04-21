//! BORU Agent IAM — Identity and Access Management for AI agents
//!
//! Provides:
//! - Agent registration with capability scoping
//! - Token-based authentication (SHA-256 hashed — never plaintext)
//! - Permission management per agent
//! - Token revocation

pub mod agent;

pub use agent::{
    AgentManager, AgentRecord, AgentPermission, AgentToken,
};
