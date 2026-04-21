//! BORU Cage Verdict — Execution results and verdicts
//!
//! This module defines the result types returned from cage execution.

/// Enhanced verdict for the new cage system
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Execution allowed and completed successfully
    Allowed {
        /// Execution output
        output: String,
    },
    /// Execution blocked by policy
    Blocked {
        /// Reason for blocking
        reason: String,
    },
    /// Execution timed out (fuel exhausted)
    Timeout,
    /// File quarantined
    Quarantined {
        /// Reason for quarantine
        reason: String,
    },
    /// File type not supported
    Unsupported {
        /// Reason why not supported
        reason: String,
    },
    /// Execution error
    Error {
        /// Error message
        message: String,
    },
}

/// Complete cage execution result
#[derive(Debug, Clone)]
pub struct CageResult {
    /// The verdict
    pub verdict: Verdict,
    /// Request ID for audit trail
    pub request_id: uuid::Uuid,
    /// Execution time in milliseconds
    pub execution_time_ms: Option<u64>,
    /// Fuel consumed (for WASM)
    pub fuel_consumed: Option<u64>,
}

impl CageResult {
    /// Create a new allowed result
    pub fn allowed(output: &str) -> Self {
        Self {
            verdict: Verdict::Allowed {
                output: output.to_string(),
            },
            request_id: uuid::Uuid::new_v4(),
            execution_time_ms: None,
            fuel_consumed: None,
        }
    }

    /// Create a new blocked result
    pub fn blocked(reason: &str) -> Self {
        Self {
            verdict: Verdict::Blocked {
                reason: reason.to_string(),
            },
            request_id: uuid::Uuid::new_v4(),
            execution_time_ms: None,
            fuel_consumed: None,
        }
    }

    /// Create a new timeout result
    pub fn timeout() -> Self {
        Self {
            verdict: Verdict::Timeout,
            request_id: uuid::Uuid::new_v4(),
            execution_time_ms: None,
            fuel_consumed: None,
        }
    }

    /// Create a new quarantined result
    pub fn quarantined(reason: &str) -> Self {
        Self {
            verdict: Verdict::Quarantined {
                reason: reason.to_string(),
            },
            request_id: uuid::Uuid::new_v4(),
            execution_time_ms: None,
            fuel_consumed: None,
        }
    }

    /// Create a new unsupported result
    pub fn unsupported(reason: &str) -> Self {
        Self {
            verdict: Verdict::Unsupported {
                reason: reason.to_string(),
            },
            request_id: uuid::Uuid::new_v4(),
            execution_time_ms: None,
            fuel_consumed: None,
        }
    }

    /// Create a new error result
    pub fn error(message: &str) -> Self {
        Self {
            verdict: Verdict::Error {
                message: message.to_string(),
            },
            request_id: uuid::Uuid::new_v4(),
            execution_time_ms: None,
            fuel_consumed: None,
        }
    }

    /// Set execution time
    pub fn with_execution_time(mut self, ms: u64) -> Self {
        self.execution_time_ms = Some(ms);
        self
    }

    /// Set fuel consumed
    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel_consumed = Some(fuel);
        self
    }

    /// Check if the result was successful
    pub fn is_success(&self) -> bool {
        matches!(self.verdict, Verdict::Allowed { .. })
    }

    /// Check if the result was blocked
    pub fn is_blocked(&self) -> bool {
        matches!(
            self.verdict,
            Verdict::Blocked { .. } | Verdict::Quarantined { .. }
        )
    }

    /// Check if the result was a timeout
    pub fn is_timeout(&self) -> bool {
        matches!(self.verdict, Verdict::Timeout)
    }

    /// Get output if allowed
    pub fn output(&self) -> Option<&str> {
        match &self.verdict {
            Verdict::Allowed { output } => Some(output),
            _ => None,
        }
    }

    /// Get error reason if blocked/error
    pub fn error_reason(&self) -> Option<&str> {
        match &self.verdict {
            Verdict::Blocked { reason } => Some(reason),
            Verdict::Quarantined { reason } => Some(reason),
            Verdict::Unsupported { reason } => Some(reason),
            Verdict::Error { message } => Some(message),
            _ => None,
        }
    }
}

impl std::fmt::Display for CageResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.verdict {
            Verdict::Allowed { output } => {
                write!(f, "✓ ALLOWED: {}", output)?;
            }
            Verdict::Blocked { reason } => {
                write!(f, "✗ BLOCKED: {}", reason)?;
            }
            Verdict::Timeout => {
                write!(f, "✗ TIMEOUT: Fuel exhausted")?;
            }
            Verdict::Quarantined { reason } => {
                write!(f, "✗ QUARANTINED: {}", reason)?;
            }
            Verdict::Unsupported { reason } => {
                write!(f, "⚠ UNSUPPORTED: {}", reason)?;
            }
            Verdict::Error { message } => {
                write!(f, "✗ ERROR: {}", message)?;
            }
        }

        if let Some(ms) = self.execution_time_ms {
            write!(f, " ({}ms)", ms)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_result() {
        let result = CageResult::allowed("test output");
        assert!(result.is_success());
        assert!(!result.is_blocked());
        assert_eq!(result.output(), Some("test output"));
        assert_eq!(result.error_reason(), None);
    }

    #[test]
    fn test_blocked_result() {
        let result = CageResult::blocked("policy violation");
        assert!(!result.is_success());
        assert!(result.is_blocked());
        assert_eq!(result.output(), None);
        assert_eq!(result.error_reason(), Some("policy violation"));
    }

    #[test]
    fn test_timeout_result() {
        let result = CageResult::timeout();
        assert!(!result.is_success());
        assert!(result.is_timeout());
    }

    #[test]
    fn test_display() {
        let allowed = CageResult::allowed("success");
        assert!(allowed.to_string().contains("ALLOWED"));

        let blocked = CageResult::blocked("denied");
        assert!(blocked.to_string().contains("BLOCKED"));

        let timeout = CageResult::timeout();
        assert!(timeout.to_string().contains("TIMEOUT"));
    }
}
