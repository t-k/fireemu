//! Runner protocol (spec 12.2): length-prefixed JSON frames over the child's stdin / stdout.
//!
//! ```text
//! <decimal byte length>\n<JSON payload>
//! ```
//!
//! Runtime → runner: `{"type":"invoke", ...}`, `{"type":"shutdown"}`.
//! Runner → runtime: `{"type":"hello","runner":"node","httpPort":N,"manifest":{...}}`,
//! `{"type":"result","invocationId":"...","ok":true|false,"error":"..."}`,
//! `{"type":"log","level":"info","message":"...","fields":{},"invocationId":"...","functionName":"...","user":true}`,
//! `{"type":"heartbeat"}`.

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

/// Maximum accepted frame (an invocation carries at most one document pair plus metadata).
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Encodes one frame.
#[must_use]
pub fn encode_frame(v: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(v).unwrap_or_default();
    let mut out = format!("{}\n", payload.len()).into_bytes();
    out.extend_from_slice(&payload);
    out
}

/// Reads one frame; `Ok(None)` at a clean end of stream.
pub async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<Value>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    let len: usize = line
        .trim()
        .parse()
        .map_err(|_| std::io::Error::other(format!("malformed frame length {:?}", line.trim())))?;
    if len > MAX_FRAME_BYTES {
        return Err(std::io::Error::other(format!(
            "frame of {len} bytes exceeds {MAX_FRAME_BYTES}"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|e| std::io::Error::other(format!("malformed frame JSON: {e}")))
}

/// Writes one frame.
pub async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    v: &Value,
) -> std::io::Result<()> {
    writer.write_all(&encode_frame(v)).await?;
    writer.flush().await
}
