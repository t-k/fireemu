//! Runner protocol (spec 12.2): length-prefixed JSON frames over the child's stdin / stdout.
//!
//! ```text
//! <decimal byte length>\n<JSON payload>
//! ```
//!
//! Runtime → runner: `{"type":"invoke", ...}`, `{"type":"shutdown"}`.
//! Runner → runtime: `{"type":"hello","runner":"node","httpPort":N,"manifest":{...}}`,
//! `{"type":"result","invocationId":"...","ok":true|false,"error":"..."}`,
//! `{"type":"log","level":"info","message":"...","fields":{},"invocationId":"...","functionName":"...","user":true}`.

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Maximum accepted frame (an invocation carries at most one document pair plus metadata).
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_FRAME_LENGTH_DIGITS: usize = 8;

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
    let mut len = 0_usize;
    let mut digits = 0_usize;
    loop {
        let mut byte = [0_u8; 1];
        if reader.read(&mut byte).await? == 0 {
            if digits == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        match byte[0] {
            b'\n' if digits > 0 => break,
            b'0'..=b'9' if digits < MAX_FRAME_LENGTH_DIGITS => {
                len = len * 10 + usize::from(byte[0] - b'0');
                digits += 1;
                if len > MAX_FRAME_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("frame of {len} bytes exceeds {MAX_FRAME_BYTES}"),
                    ));
                }
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "malformed frame length",
                ));
            }
        }
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

#[cfg(test)]
mod tests {
    use std::io::{Cursor, ErrorKind};

    use tokio::io::BufReader;

    use super::{encode_frame, read_frame};

    #[tokio::test]
    async fn length_prefix_rejects_excess_digits_without_reading_the_line() {
        let mut reader = BufReader::with_capacity(1, Cursor::new(vec![b'9'; 1024 * 1024]));
        let error = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(reader.get_ref().position() <= 9);
    }

    #[tokio::test]
    async fn length_prefix_rejects_non_decimal_input_without_reading_the_line() {
        let mut input = vec![b'9'; 1024 * 1024];
        input[1] = b'x';
        let mut reader = BufReader::with_capacity(1, Cursor::new(input));
        let error = read_frame(&mut reader).await.unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        assert!(reader.get_ref().position() <= 2);
    }

    #[tokio::test]
    async fn consecutive_frames_and_clean_eof_remain_readable() {
        let first = serde_json::json!({"type": "first"});
        let second = serde_json::json!({"type": "second"});
        let mut wire = encode_frame(&first);
        wire.extend(encode_frame(&second));
        let mut reader = BufReader::new(wire.as_slice());
        assert_eq!(read_frame(&mut reader).await.unwrap(), Some(first));
        assert_eq!(read_frame(&mut reader).await.unwrap(), Some(second));
        assert_eq!(read_frame(&mut reader).await.unwrap(), None);
    }
}
