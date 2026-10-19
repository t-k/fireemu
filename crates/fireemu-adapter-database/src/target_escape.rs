//! Percent-encodes the bytes of a request target that hyper refuses but the official emulator
//! accepts, before hyper parses the request line.
//!
//! The Firebase documentation's own curl examples send `orderBy="$key"` with raw quotes;
//! `http` (under hyper) rejects `"` in a query, and `<`, `>` and `` ` `` in a path. The REST
//! layer percent-decodes every path segment and parameter, so encoding these bytes on the way
//! in changes nothing it reads.
//!
//! The escaper follows HTTP/1.1 framing so that every request of a kept-alive connection is
//! escaped: it reads the headers for `Content-Length`, chunked `Transfer-Encoding` and
//! `Upgrade`, passes bodies through untouched, and passes everything after an upgrade
//! request's headers through, since the connection then speaks WebSocket.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Where the reader is in the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// The method, before the first space.
    Method,
    /// The request target, escaped.
    Target,
    /// The protocol version, up to the end of the request line.
    Version,
    /// A header line being read.
    Header(Vec<u8>),
    /// A body with this many bytes left.
    Body(u64),
    /// A chunk-size line being read.
    ChunkSize(Vec<u8>),
    /// Chunk data with this many bytes left.
    ChunkData(u64),
    /// The line end after chunk data, with this many bytes left.
    ChunkEnd(u8),
    /// A trailer line being read after the last chunk.
    Trailer(Vec<u8>),
    /// Everything from here on (after an upgrade) passes through.
    Passthrough,
}

/// What the headers of the current request said about its body.
#[derive(Debug, Clone, Copy, Default)]
struct Framing {
    length: Option<u64>,
    chunked: bool,
    upgrade: bool,
    /// Headers this escaper may read differently from hyper (a repeated or listed
    /// `Content-Length`, a coding list not ending in `chunked`): the rest of the connection
    /// then passes through unescaped and hyper alone decides.
    ambiguous: bool,
}

/// A connection whose request targets are escaped.
pub struct TargetEscaper<S> {
    inner: S,
    state: State,
    framing: Framing,
    pending: Vec<u8>,
}

/// Whether the target byte is escaped.
fn escaped_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'"' | b'#' | b'<' | b'>' | b'`' | b'{' | b'}' | b'|' | b'\\' | b'^'
    )
}

/// A line without its trailing CR.
fn line(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\r").unwrap_or(bytes)
}

impl<S> TargetEscaper<S> {
    /// Wraps a fresh connection.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: State::Method,
            framing: Framing::default(),
            pending: Vec::new(),
        }
    }

    /// Escapes `input` according to the current state, appending to `pending`.
    fn transform(&mut self, input: &[u8]) {
        let mut at = 0;
        while at < input.len() {
            // Bodies pass through in runs, not byte by byte.
            if let State::Body(left) | State::ChunkData(left) = self.state {
                let take = usize::try_from(left)
                    .unwrap_or(usize::MAX)
                    .min(input.len() - at);
                self.pending.extend_from_slice(&input[at..at + take]);
                at += take;
                let left = left - take as u64;
                self.state = match (&self.state, left) {
                    (State::Body(_), 0) => State::Method,
                    (State::Body(_), left) => State::Body(left),
                    (_, 0) => State::ChunkEnd(2),
                    (_, left) => State::ChunkData(left),
                };
                continue;
            }
            if self.state == State::Passthrough {
                self.pending.extend_from_slice(&input[at..]);
                return;
            }
            self.step(input[at]);
            at += 1;
        }
    }

    fn step(&mut self, byte: u8) {
        if self.state == State::Target && escaped_byte(byte) {
            self.pending
                .extend_from_slice(format!("%{byte:02X}").as_bytes());
            return;
        }
        self.pending.push(byte);
        let state = std::mem::replace(&mut self.state, State::Passthrough);
        self.state = match (state, byte) {
            (State::Method, b' ') => State::Target,
            (State::Target, b' ') => State::Version,
            (State::Method | State::Target | State::Version, b'\n') => {
                self.framing = Framing::default();
                State::Header(Vec::new())
            }
            (State::Header(text), b'\n') => self.end_header(&text),
            (State::Header(mut text), other) => {
                text.push(other);
                State::Header(text)
            }
            (State::ChunkSize(text), b'\n') => {
                let size = line(&text).split(|b| *b == b';').next().unwrap_or_default();
                let size = std::str::from_utf8(size)
                    .ok()
                    .and_then(|s| u64::from_str_radix(s.trim(), 16).ok())
                    .unwrap_or(0);
                if size == 0 {
                    State::Trailer(Vec::new())
                } else {
                    State::ChunkData(size)
                }
            }
            (State::ChunkSize(mut text), other) => {
                text.push(other);
                State::ChunkSize(text)
            }
            (State::ChunkEnd(1), _) => State::ChunkSize(Vec::new()),
            (State::ChunkEnd(left), _) => State::ChunkEnd(left - 1),
            (State::Trailer(text), b'\n') if line(&text).is_empty() => State::Method,
            (State::Trailer(_), b'\n') => State::Trailer(Vec::new()),
            (State::Trailer(mut text), other) => {
                text.push(other);
                State::Trailer(text)
            }
            (other, _) => other,
        };
    }

    /// The state after a header line (without its LF).
    fn end_header(&mut self, text: &[u8]) -> State {
        let text = line(text);
        if text.is_empty() {
            return match self.framing {
                Framing { upgrade: true, .. }
                | Framing {
                    ambiguous: true, ..
                } => State::Passthrough,
                Framing { chunked: true, .. } => State::ChunkSize(Vec::new()),
                Framing {
                    length: None | Some(0),
                    ..
                } => State::Method,
                Framing {
                    length: Some(length),
                    ..
                } => State::Body(length),
            };
        }
        let text = String::from_utf8_lossy(text);
        if let Some((name, value)) = text.split_once(':') {
            let value = value.trim();
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => {
                    let digits = !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit());
                    match (
                        self.framing.length,
                        digits.then(|| value.parse().ok()).flatten(),
                    ) {
                        (None, Some(length)) => self.framing.length = Some(length),
                        _ => self.framing.ambiguous = true,
                    }
                }
                "transfer-encoding" => {
                    let last = value.rsplit(',').next().unwrap_or_default().trim();
                    if last.eq_ignore_ascii_case("chunked") {
                        self.framing.chunked = true;
                    } else {
                        self.framing.ambiguous = true;
                    }
                }
                "upgrade" => self.framing.upgrade = true,
                _ => {}
            }
        }
        State::Header(Vec::new())
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
            if this.state == State::Passthrough {
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

    fn escape_target(target: &str) -> String {
        target
            .bytes()
            .map(|b| match b {
                b'"' | b'#' | b'<' | b'>' | b'`' | b'{' | b'}' | b'|' | b'\\' | b'^' => {
                    format!("%{b:02X}")
                }
                other => char::from(other).to_string(),
            })
            .collect()
    }

    #[test]
    fn every_request_of_a_kept_alive_connection_is_escaped() {
        let input = concat!(
            "PUT /a\"1\".json HTTP/1.1\r\nContent-Length: 3\r\n\r\n\"x\"",
            "POST /b\"2\".json HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\"y\r\n1;ext=1\r\n\"\r\n0\r\nX-T: \"t\"\r\n\r\n",
            "GET /c.json?q=\"3\" HTTP/1.1\r\n\r\n",
        );
        let expected = concat!(
            "PUT /a%221%22.json HTTP/1.1\r\nContent-Length: 3\r\n\r\n\"x\"",
            "POST /b%222%22.json HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\"y\r\n1;ext=1\r\n\"\r\n0\r\nX-T: \"t\"\r\n\r\n",
            "GET /c.json?q=%223%22 HTTP/1.1\r\n\r\n",
        );
        assert_eq!(
            String::from_utf8(escaped(&[input.as_bytes()])).unwrap(),
            expected
        );
    }

    #[test]
    fn an_upgrade_passes_everything_after_its_headers_through() {
        let input = b"GET /.ws?v=\"5\" HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /x\" HTTP/1.1\r\n";
        assert_eq!(
            String::from_utf8(escaped(&[input])).unwrap(),
            "GET /.ws?v=%225%22 HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nGET /x\" HTTP/1.1\r\n"
        );
    }

    #[derive(Debug, Clone)]
    struct Request {
        target: String,
        body: Vec<u8>,
        chunked: bool,
        chunk_size: usize,
    }

    impl Request {
        fn wire(&self, target: &str) -> Vec<u8> {
            let mut out = format!("PUT {target} HTTP/1.1\r\nHost: x\r\n").into_bytes();
            if self.chunked {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                for chunk in self.body.chunks(self.chunk_size.max(1)) {
                    out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                    out.extend_from_slice(chunk);
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"0\r\n\r\n");
            } else {
                out.extend_from_slice(
                    format!("Content-Length: {}\r\n\r\n", self.body.len()).as_bytes(),
                );
                out.extend_from_slice(&self.body);
            }
            out
        }
    }

    fn request() -> impl proptest::strategy::Strategy<Value = Request> {
        use proptest::prelude::*;
        (
            "/[a-z\"{}<>|^`#?=&%]{0,12}",
            prop::collection::vec(any::<u8>(), 0..40),
            any::<bool>(),
            1usize..9,
        )
            .prop_map(|(target, body, chunked, chunk_size)| Request {
                target,
                body,
                chunked,
                chunk_size,
            })
    }

    proptest::proptest! {
        #[test]
        fn targets_are_escaped_and_bodies_untouched_whatever_the_reads(
            requests in proptest::collection::vec(request(), 1..5),
            cuts in proptest::collection::vec(1usize..17, 1..40),
        ) {
            let input: Vec<u8> = requests.iter().flat_map(|r| r.wire(&r.target)).collect();
            let expected: Vec<u8> = requests.iter().flat_map(|r| r.wire(&escape_target(&r.target))).collect();
            let mut pieces = Vec::new();
            let mut at = 0;
            for cut in cuts.iter().cycle() {
                if at >= input.len() {
                    break;
                }
                let end = (at + cut).min(input.len());
                pieces.push(&input[at..end]);
                at = end;
            }
            proptest::prop_assert_eq!(escaped(&pieces), expected);
        }
    }

    #[test]
    fn a_chunked_body_that_looks_like_a_request_stays_a_body() {
        // A body whose blank line would end a misread header block and start a misread
        // request line, whose quotes would then be escaped.
        let body = b"GET /\"z\" HTTP/1.1\r\n\r\nP \"q\" H\r\n";
        let mut input = b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        input.extend_from_slice(format!("{:x};name=v\r\n", body.len()).as_bytes());
        input.extend_from_slice(body);
        input.extend_from_slice(b"\r\n0\r\n\r\nGET /\"w\" HTTP/1.1\r\n\r\n");
        let mut expected = input.clone();
        let tail = expected.len() - b"GET /\"w\" HTTP/1.1\r\n\r\n".len();
        expected.truncate(tail);
        expected.extend_from_slice(b"GET /%22w%22 HTTP/1.1\r\n\r\n");
        assert_eq!(escaped(&[&input]), expected);
    }

    #[test]
    fn ambiguous_framing_hands_the_connection_to_hyper_unescaped() {
        for header in [
            "Content-Length: 5, 5",
            "Content-Length: +5",
            "Content-Length: 5\r\nContent-Length: 5",
            "Transfer-Encoding: chunked, gzip",
        ] {
            let input = format!(
                "PUT /a\"b HTTP/1.1\r\n{header}\r\n\r\na \"b\"\r\nGET /\"c\" HTTP/1.1\r\n\r\n"
            );
            let expected = format!(
                "PUT /a%22b HTTP/1.1\r\n{header}\r\n\r\na \"b\"\r\nGET /\"c\" HTTP/1.1\r\n\r\n"
            );
            assert_eq!(
                String::from_utf8(escaped(&[input.as_bytes()])).unwrap(),
                expected,
                "{header}"
            );
        }
        // A last coding of chunked is chunked framing, as hyper reads it.
        let input = "PUT /a HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\na \"\r\n0\r\n\r\nGET /\"c\" HTTP/1.1\r\n\r\n";
        let expected = "PUT /a HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\na \"\r\n0\r\n\r\nGET /%22c%22 HTTP/1.1\r\n\r\n";
        assert_eq!(
            String::from_utf8(escaped(&[input.as_bytes()])).unwrap(),
            expected
        );
    }
}
