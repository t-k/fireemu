//! Percent-encodes the bytes of a request target that hyper refuses but the official emulator
//! accepts, before hyper parses the request line.
//!
//! The Firebase documentation's own curl examples send `orderBy="$key"` with raw quotes;
//! `http` (under hyper) rejects `"` in a query, and `<`, `>` and `` ` `` in a path. The REST
//! layer percent-decodes every path segment and parameter, so encoding these bytes on the way
//! in changes nothing it reads. Only the request line of a connection's first request is
//! rewritten, so the server serves one request per connection.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Where the reader is in the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// The method, before the first space.
    Method,
    /// The request target.
    Target,
    /// The rest of the request line.
    Version,
    /// Everything after the request line, passed through.
    Rest,
}

/// A connection whose first request line has its target escaped.
pub struct TargetEscaper<S> {
    inner: S,
    state: State,
    pending: Vec<u8>,
}

impl<S> TargetEscaper<S> {
    /// Wraps a fresh connection.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: State::Method,
            pending: Vec::new(),
        }
    }

    /// Escapes `input` according to the current state, appending to `pending`.
    fn transform(&mut self, input: &[u8]) {
        for &byte in input {
            match (self.state, byte) {
                (State::Rest, _) => self.pending.push(byte),
                (State::Method, b' ') => {
                    self.state = State::Target;
                    self.pending.push(byte);
                }
                (State::Target, b' ') => {
                    self.state = State::Version;
                    self.pending.push(byte);
                }
                (
                    State::Target,
                    b'"' | b'#' | b'<' | b'>' | b'`' | b'{' | b'}' | b'|' | b'\\' | b'^',
                ) => {
                    self.pending
                        .extend_from_slice(format!("%{byte:02X}").as_bytes());
                }
                (_, b'\n') => {
                    self.state = State::Rest;
                    self.pending.push(byte);
                }
                _ => self.pending.push(byte),
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TargetEscaper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pending.is_empty() {
            if this.state == State::Rest {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut scratch = [0u8; 4096];
            let mut scratch_buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut scratch_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = scratch_buf.filled().to_vec();
                    if filled.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.transform(&filled);
                }
                other => return other,
            }
        }
        let n = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending[..n]);
        this.pending.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TargetEscaper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn escaped(input: &[&[u8]]) -> Vec<u8> {
        let mut escaper = TargetEscaper::new(());
        for chunk in input {
            escaper.transform(chunk);
        }
        escaper.pending
    }

    #[test]
    fn only_the_first_request_target_is_escaped() {
        let out =
            escaped(&[b"GET /a\"b\".json?q=\"x\"&y={} HTTP/1.1\r\nX-H: \"keep\"\r\n\r\nbody\"#"]);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /a%22b%22.json?q=%22x%22&y=%7B%7D HTTP/1.1\r\nX-H: \"keep\"\r\n\r\nbody\"#"
        );
    }

    #[test]
    fn escaping_continues_across_reads() {
        let whole = escaped(&[b"PUT /<a>`|\\^#.json?x=\" HTTP/1.1\r\n\r\n\"" as &[u8]]);
        let split = escaped(&[
            b"PUT /<a",
            b">`|\\",
            b"^#.json?x",
            b"=\" HTTP/1.1\r",
            b"\n\r\n\"",
        ]);
        assert_eq!(whole, split);
        assert_eq!(
            String::from_utf8(whole).unwrap(),
            "PUT /%3Ca%3E%60%7C%5C%5E%23.json?x=%22 HTTP/1.1\r\n\r\n\""
        );
    }
}
