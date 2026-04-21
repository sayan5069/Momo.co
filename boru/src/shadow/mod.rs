//! BORU Shadow — Filesystem rollback protection
//!
//! Provides:
//! - Shadow backups before file writes
//! - Rollback to previous state
//! - Manifest tracking

pub mod rollback;

pub use rollback::{
    RollbackManager, RollbackResult, ShadowManifest, ShadowFile, ShadowSessionInfo,
    compute_path_hash,
};
