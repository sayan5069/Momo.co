//! BORU Socket — Unix socket server
//!
//! Handles incoming execution requests from SABA/ZUNO over local Unix sockets.
//! No network code here — Unix sockets only.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Socket configuration (GATE 3: all paths centralized here)
pub mod config;

/// Ecosystem integration (auto-discovery with Nuki/Suji)
pub mod ecosystem;

/// Socket stubs for ZUNO and SABA (Phase 2)
pub mod stubs;

/// Maximum request size: 10MB
const MAX_REQUEST_SIZE: usize = config::MAX_REQUEST_SIZE;

/// Run the socket daemon
///
/// GATE 3: Strict socket contract freeze
/// Run the socket daemon
///
/// GATE 3: Strict socket contract freeze
pub async fn run_daemon(socket_path: Option<PathBuf>) -> Result<()> {
    let path = socket_path.unwrap_or_else(|| PathBuf::from(config::BORU_SOCKET_PATH));

    tracing::info!("Starting BORU socket daemon on {:?}", path);

    #[cfg(unix)]
    {
        run_unix_daemon(path).await
    }

    #[cfg(windows)]
    {
        let _ = path; // used on unix
        // On Windows, use named pipes as a substitute for Unix sockets
        // This maintains the local-only communication requirement
        run_named_pipe_daemon().await
    }
}

#[cfg(unix)]
async fn run_unix_daemon(path: PathBuf) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    // Ensure socket directory exists
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Remove old socket if it exists
    if path.exists() {
        tokio::fs::remove_file(&path)
            .await
            .with_context(|| format!("Failed to remove old socket at {:?}", path))?;
    }

    let listener = UnixListener::bind(&path)?;
    tracing::info!("Socket daemon listening on {:?}", path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(handle_unix_connection(stream));
            }
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
            }
        }
    }
}

#[cfg(unix)]
async fn handle_unix_connection(mut stream: tokio::net::UnixStream) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read request (JSON NDJSON style - newline delimited)
    let mut buffer = vec![0u8; MAX_REQUEST_SIZE];
    let n: usize = stream
        .read(&mut buffer[..])
        .await
        .context("Failed to read from socket")?;

    if n == 0 {
        return Ok(());
    }

    buffer.truncate(n);

    let response = process_request(&buffer).await?;

    // Send response
    let response_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&response_bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    Ok(())
}

#[cfg(windows)]
async fn run_named_pipe_daemon() -> Result<()> {
    // On Windows, use TCP localhost as the closest equivalent to Unix sockets
    // This still maintains local-only communication
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(
        "Socket daemon listening on TCP {} (Windows named pipe substitute)",
        local_addr
    );

    // Write the port to a file so clients can find it
    let info_path = std::env::temp_dir().join("boru").join("socket.info");
    if let Some(parent) = info_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let _ = tokio::fs::write(&info_path, format!("{}", local_addr.port())).await;

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                tokio::spawn(handle_tcp_connection(stream));
            }
            Err(e) => {
                tracing::error!("Failed to accept connection: {}", e);
            }
        }
    }
}

#[cfg(windows)]
async fn handle_tcp_connection(mut stream: tokio::net::TcpStream) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read request
    let mut buffer = vec![0u8; MAX_REQUEST_SIZE];
    let n: usize = stream
        .read(&mut buffer[..])
        .await
        .context("Failed to read from stream")?;

    if n == 0 {
        return Ok(());
    }

    buffer.truncate(n);

    let response = process_request(&buffer).await?;

    // Send response
    let response_bytes = serde_json::to_vec(&response)?;
    stream.write_all(&response_bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    Ok(())
}

/// Process a request and return a response
async fn process_request(buffer: &[u8]) -> Result<ExecuteResponse> {
    // Parse request
    let request: ExecuteRequest = match serde_json::from_slice(buffer) {
        Ok(req) => req,
        Err(e) => {
            return Ok(ExecuteResponse {
                request_id: uuid::Uuid::new_v4(),
                verdict: "BLOCKED".to_string(),
                reason: Some(format!("Invalid request format: {}", e)),
                audit_ref: uuid::Uuid::new_v4().to_string(),
            });
        }
    };

    tracing::info!(
        "Received request {} of type {}",
        request.request_id,
        request.req_type
    );

    // Process based on request type
    let response = match request.req_type.as_str() {
        "execute" => handle_execute(request).await,
        _ => ExecuteResponse {
            request_id: request.request_id,
            verdict: "BLOCKED".to_string(),
            reason: Some(format!("Unknown request type: {}", request.req_type)),
            audit_ref: uuid::Uuid::new_v4().to_string(),
        },
    };
    Ok(response)
}

/// Handle execute request
async fn handle_execute(request: ExecuteRequest) -> ExecuteResponse {
    let audit_id = uuid::Uuid::new_v4();

    // Decode base64 code
    let code_bytes = match decode_base64(&request.payload.code) {
        Ok(bytes) => bytes,
        Err(e) => {
            return ExecuteResponse {
                request_id: request.request_id,
                verdict: "BLOCKED".to_string(),
                reason: Some(format!("Failed to decode base64: {}", e)),
                audit_ref: audit_id.to_string(),
            };
        }
    };

    // Write code to temp file
    let temp_dir = std::env::temp_dir().join("boru").join("workspace");
    let _ = tokio::fs::create_dir_all(&temp_dir).await;
    let temp_file = temp_dir.join(format!("{}.wasm", request.request_id));

    if let Err(e) = tokio::fs::write(&temp_file, &code_bytes).await {
        return ExecuteResponse {
            request_id: request.request_id,
            verdict: "BLOCKED".to_string(),
            reason: Some(format!("Failed to write temp file: {}", e)),
            audit_ref: audit_id.to_string(),
        };
    }

    // Execute in cage (blocking operation, run in spawn_blocking)
    let policy = request.payload.policy.clone();
    let path = temp_file.clone();

    let verdict = tokio::task::spawn_blocking(move || {
        crate::cage::execute(path, policy, None)
    })
    .await
    .unwrap_or_else(|e| Err(anyhow::anyhow!("Execution panicked: {}", e)));

    // Cleanup temp file
    let _ = tokio::fs::remove_file(&temp_file).await;

    match verdict {
        Ok(crate::cage::Verdict::Allowed { .. }) => ExecuteResponse {
            request_id: request.request_id,
            verdict: "ALLOWED".to_string(),
            reason: None,
            audit_ref: audit_id.to_string(),
        },
        Ok(crate::cage::Verdict::Blocked { reason }) => ExecuteResponse {
            request_id: request.request_id,
            verdict: "BLOCKED".to_string(),
            reason: Some(reason),
            audit_ref: audit_id.to_string(),
        },
        Ok(crate::cage::Verdict::Timeout) => ExecuteResponse {
            request_id: request.request_id,
            verdict: "BLOCKED".to_string(),
            reason: Some("Timeout: fuel exhausted".to_string()),
            audit_ref: audit_id.to_string(),
        },
        Err(e) => ExecuteResponse {
            request_id: request.request_id,
            verdict: "BLOCKED".to_string(),
            reason: Some(format!("Execution error: {}", e)),
            audit_ref: audit_id.to_string(),
        },
    }
}

/// Request format (JSON over Unix socket)
#[derive(Debug, serde::Deserialize)]
pub struct ExecuteRequest {
    pub request_id: uuid::Uuid,
    #[serde(rename = "type")]
    pub req_type: String,
    pub payload: ExecutePayload,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExecutePayload {
    /// Base64-encoded code
    pub code: String,
    /// "wasm" | "shell"
    #[allow(dead_code)]
    pub format: String,
    /// "strict" | "permissive"
    pub policy: String,
}

/// Response format
#[derive(Debug, serde::Serialize)]
pub struct ExecuteResponse {
    pub request_id: uuid::Uuid,
    /// "ALLOWED" | "BLOCKED"
    pub verdict: String,
    pub reason: Option<String>,
    /// Log entry ID for audit trail
    pub audit_ref: String,
}

/// Base64 decoding helper (no external crate needed — GATE 1)
fn decode_base64(s: &str) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(s.len() * 3 / 4);
    let chars: Vec<u8> = s.bytes().collect();

    let decode_char = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };

    for chunk in chars.chunks(4) {
        let b0 = chunk.first().copied().ok_or_else(|| anyhow::anyhow!("Invalid base64"))?;
        let b1 = chunk.get(1).copied().ok_or_else(|| anyhow::anyhow!("Invalid base64"))?;

        let b = [
            decode_char(b0).ok_or_else(|| anyhow::anyhow!("Invalid base64 char"))?,
            decode_char(b1).ok_or_else(|| anyhow::anyhow!("Invalid base64 char"))?,
            chunk.get(2).and_then(|c| decode_char(*c)).unwrap_or(0),
            chunk.get(3).and_then(|c| decode_char(*c)).unwrap_or(0),
        ];

        result.push((b[0] << 2) | (b[1] >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push((b[1] << 4) | (b[2] >> 2));
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push((b[2] << 6) | b[3]);
        }
    }

    Ok(result)
}
