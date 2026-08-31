//! Pure RFC 6455 helpers and the `EmulatorLog` bundle builder. Nothing here touches a socket,
//! so every rule is unit-testable.

use base64::Engine as _;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};

/// The GUID RFC 6455 §1.3 appends to the client key before hashing.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Accept`: `base64(SHA-1(key + GUID))`.
#[must_use]
pub fn sec_websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// One field of an `EmulatorLog` frame, before it becomes JSON.
///
/// The daemon fills this from a raw log line plus what it knows about the line's origin. The
/// emulator/function tags land under `data.metadata`, exactly where the official UI's Logs page
/// reads them.
#[derive(Debug, Clone)]
pub struct LogInput {
    /// Severity, any case; lowercased into the frame.
    pub level: String,
    /// Human-readable text; VT/control characters are stripped by [`build_bundle`].
    pub message: String,
    /// Milliseconds since the Unix epoch, from the daemon's virtual clock (so tests are stable).
    pub timestamp_ms: i64,
    /// `data.metadata.emulator.name`, e.g. `functions`.
    pub emulator: Option<String>,
    /// `data.metadata.function.name`, when the line names a function.
    pub function: Option<String>,
    /// Function *user* output: type `USER`, forced to level `info`, as `EmulatorLogger` does.
    pub user: bool,
}

impl LogInput {
    /// A line with just a level and text (no origin tags).
    #[must_use]
    pub fn plain(level: impl Into<String>, message: impl Into<String>, timestamp_ms: i64) -> Self {
        Self {
            level: level.into(),
            message: message.into(),
            timestamp_ms,
            emulator: None,
            function: None,
            user: false,
        }
    }

    /// Tags the line with `data.metadata.emulator.name`.
    #[must_use]
    pub fn for_emulator(mut self, name: impl Into<String>) -> Self {
        self.emulator = Some(name.into());
        self
    }

    /// Tags the line with `data.metadata.function.name` (and the functions emulator).
    #[must_use]
    pub fn for_function(mut self, name: impl Into<String>) -> Self {
        self.function = Some(name.into());
        self
    }
}

/// Builds one `EmulatorLog` frame as the official transport would serialise it.
///
/// The `data.metadata` object carries the emulator/function tags; `USER` output is forced to
/// level `info`. `message` has its control characters stripped (see [`strip_control`]). The
/// bundle never carries a raw control byte, and `serde_json` escapes every string, so no log
/// content can break the frame.
#[must_use]
pub fn build_bundle(input: &LogInput) -> Value {
    let level = if input.user {
        "info".to_owned()
    } else {
        input.level.to_lowercase()
    };
    let mut metadata = serde_json::Map::new();
    if let Some(name) = &input.emulator {
        metadata.insert("emulator".to_owned(), json!({ "name": name }));
    }
    if let Some(name) = &input.function {
        metadata.insert("function".to_owned(), json!({ "name": name }));
    }
    if input.user {
        metadata.insert("type".to_owned(), Value::String("USER".to_owned()));
    }
    let mut data = serde_json::Map::new();
    if !metadata.is_empty() {
        data.insert("metadata".to_owned(), Value::Object(metadata));
    }
    json!({
        "level": level,
        "data": Value::Object(data),
        "timestamp": input.timestamp_ms,
        "message": strip_control(&input.message),
    })
}

/// The exact text of one server frame's payload: [`build_bundle`] serialised.
#[must_use]
pub fn bundle_text(input: &LogInput) -> String {
    build_bundle(input).to_string()
}

/// Removes ANSI/VT escape sequences and every remaining C0/DEL control byte.
///
/// Node's `util.stripVTControlCharacters` removes the terminal control sequences winston colour
/// output emits; this also drops lone control bytes (NUL included), which the security rules
/// forbid in stored/streamed content. Ordinary printable text (including non-ASCII) is
/// untouched.
#[must_use]
pub fn strip_control(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // ESC: skip a CSI (`ESC [ ... final`) or a two-byte escape.
            match chars.peek() {
                Some('[') => {
                    chars.next();
                    // Parameter/intermediate bytes 0x20..=0x3F, then one final 0x40..=0x7E.
                    while let Some(&p) = chars.peek() {
                        chars.next();
                        if ('\u{40}'..='\u{7e}').contains(&p) {
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }
        // Drop C0 controls (0x00..=0x1F) and DEL (0x7F); keep everything printable.
        if (c as u32) < 0x20 || c == '\u{7f}' {
            continue;
        }
        out.push(c);
    }
    out
}

/// The 101 Switching Protocols response for an accepted handshake.
#[must_use]
pub fn handshake_response(key: &str) -> String {
    let accept = sec_websocket_accept(key);
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
}

/// Why a handshake was refused, and the HTTP status to answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Not a `GET` request.
    NotGet,
    /// Missing `Upgrade: websocket`.
    NotUpgrade,
    /// Missing `Sec-WebSocket-Key`.
    NoKey,
    /// The `Host` header is not loopback (DNS-rebinding guard).
    ForeignHost,
    /// The request line/headers were malformed or too large.
    Malformed,
}

impl HandshakeError {
    /// The status line and short body for the refusal.
    #[must_use]
    pub fn response(&self) -> String {
        let (status, msg) = match self {
            Self::NotGet => (
                "405 Method Not Allowed",
                "the Logging emulator accepts GET only",
            ),
            Self::NotUpgrade => ("400 Bad Request", "expected a WebSocket upgrade"),
            Self::NoKey => ("400 Bad Request", "missing Sec-WebSocket-Key"),
            Self::ForeignHost => (
                "403 Forbidden",
                "the Logging emulator answers loopback Hosts only",
            ),
            Self::Malformed => ("400 Bad Request", "malformed handshake"),
        };
        format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{msg}",
            msg.len()
        )
    }
}

/// The parsed handshake request: the client key to echo back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The `Sec-WebSocket-Key` to feed [`sec_websocket_accept`].
    pub key: String,
}

/// Validates the raw HTTP request head of a WebSocket handshake.
///
/// Enforces `GET`, `Upgrade: websocket`, a `Sec-WebSocket-Key`, and the loopback-`Host` guard.
/// The header names are matched case-insensitively (RFC 7230); `Upgrade`/`Connection` values are
/// matched case-insensitively too.
pub fn parse_handshake(head: &str) -> Result<Handshake, HandshakeError> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(HandshakeError::Malformed)?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(HandshakeError::Malformed)?;
    // A path and version must be present, but their values do not matter to us.
    if parts.next().is_none() || parts.next().is_none() {
        return Err(HandshakeError::Malformed);
    }
    if !method.eq_ignore_ascii_case("GET") {
        return Err(HandshakeError::NotGet);
    }
    let mut host: Option<&str> = None;
    let mut upgrade = false;
    let mut key: Option<&str> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or(HandshakeError::Malformed)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            host = Some(value);
        } else if name.eq_ignore_ascii_case("upgrade") {
            if value.eq_ignore_ascii_case("websocket") {
                upgrade = true;
            }
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            key = Some(value);
        }
    }
    if !host_is_loopback(host) {
        return Err(HandshakeError::ForeignHost);
    }
    if !upgrade {
        return Err(HandshakeError::NotUpgrade);
    }
    let key = key.filter(|k| !k.is_empty()).ok_or(HandshakeError::NoKey)?;
    Ok(Handshake {
        key: key.to_owned(),
    })
}

/// Whether a `Host` header names this machine. Mirrors `hub.rs::host_is_local`: an absent Host
/// (HTTP/1.0) is treated as local, and `127.0.0.0/8`, `localhost` and `::1` all pass.
#[must_use]
pub fn host_is_loopback(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return true;
    };
    let name = host.rsplit_once(':').map_or(host, |(h, _)| h);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    matches!(name, "localhost" | "127.0.0.1" | "::1") || name.starts_with("127.")
}

/// A decoded client WebSocket frame that the server acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    /// A data (text/binary/continuation) frame: ignored, but its payload was consumed.
    Data,
    /// A ping; the payload must be echoed in a pong.
    Ping(Vec<u8>),
    /// A pong: ignored.
    Pong,
    /// A close frame; the connection is closed back.
    Close,
}

/// Encodes one unmasked server text frame (server frames are never masked, RFC 6455 §5.1).
#[must_use]
pub fn encode_text_frame(payload: &str) -> Vec<u8> {
    encode_frame(0x1, payload.as_bytes())
}

/// Encodes an unmasked control/data frame with the given opcode.
#[must_use]
pub fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 10);
    frame.push(0x80 | (opcode & 0x0f)); // FIN + opcode
    let len = payload.len();
    if len < 126 {
        #[allow(clippy::cast_possible_truncation)]
        frame.push(len as u8);
    } else if u16::try_from(len).is_ok() {
        frame.push(126);
        #[allow(clippy::cast_possible_truncation)]
        frame.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// An unmasked close frame with a normal (1000) status.
#[must_use]
pub fn close_frame() -> Vec<u8> {
    encode_frame(0x8, &1000u16.to_be_bytes())
}

/// Unmasks a payload in place with the four-byte masking key (RFC 6455 §5.3).
pub fn unmask(payload: &mut [u8], mask: [u8; 4]) {
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[i % 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_matches_the_rfc_example() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            sec_websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn bundle_has_the_official_shape() {
        let input = LogInput::plain("INFO", "hello", 1_700_000_000_000)
            .for_function("makeUppercase")
            .for_emulator("functions");
        let b = build_bundle(&input);
        assert_eq!(b["level"], "info");
        assert_eq!(b["timestamp"], 1_700_000_000_000_i64);
        assert_eq!(b["message"], "hello");
        assert_eq!(b["data"]["metadata"]["emulator"]["name"], "functions");
        assert_eq!(b["data"]["metadata"]["function"]["name"], "makeUppercase");
    }

    #[test]
    fn user_output_is_forced_to_info() {
        let mut input = LogInput::plain("ERROR", "> user log", 1);
        input.user = true;
        let b = build_bundle(&input);
        assert_eq!(b["level"], "info");
        assert_eq!(b["data"]["metadata"]["type"], "USER");
    }

    #[test]
    fn control_characters_are_stripped() {
        // ANSI colour around the word, a NUL, and a bell.
        let dirty = "\u{1b}[31mred\u{1b}[0m\u{0}\u{7}end";
        assert_eq!(strip_control(dirty), "redend");
    }

    #[test]
    fn a_bundle_never_carries_a_control_byte() {
        let input = LogInput::plain("info", "a\u{0}b\u{1b}[0mc\nd", 0);
        let text = bundle_text(&input);
        assert!(!text.contains('\u{0}'));
        assert!(!text.contains('\u{1b}'));
        // The message survived minus its control bytes.
        assert!(text.contains("abcd"));
    }

    #[test]
    fn loopback_guard_matches_the_hub() {
        assert!(host_is_loopback(None));
        assert!(host_is_loopback(Some("127.0.0.1:4500")));
        assert!(host_is_loopback(Some("localhost:4500")));
        assert!(host_is_loopback(Some("[::1]:4500")));
        assert!(host_is_loopback(Some("127.9.9.9")));
        assert!(!host_is_loopback(Some("evil.example.com")));
        assert!(!host_is_loopback(Some("10.0.0.1:4500")));
    }

    #[test]
    fn handshake_requires_upgrade_key_and_loopback() {
        let good = "GET / HTTP/1.1\r\nHost: 127.0.0.1:4500\r\nUpgrade: websocket\r\n\
                    Connection: Upgrade\r\nSec-WebSocket-Key: abc==\r\n\r\n";
        assert_eq!(parse_handshake(good).unwrap().key, "abc==");

        let foreign = good.replace("127.0.0.1:4500", "evil.example.com");
        assert_eq!(parse_handshake(&foreign), Err(HandshakeError::ForeignHost));

        let no_key = "GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n";
        assert_eq!(parse_handshake(no_key), Err(HandshakeError::NoKey));

        let not_get = "POST / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                       Sec-WebSocket-Key: k\r\n\r\n";
        assert_eq!(parse_handshake(not_get), Err(HandshakeError::NotGet));

        let no_upgrade = "GET / HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Key: k\r\n\r\n";
        assert_eq!(parse_handshake(no_upgrade), Err(HandshakeError::NotUpgrade));
    }

    #[test]
    fn text_frame_encoding_is_well_formed() {
        let frame = encode_text_frame("hi");
        assert_eq!(frame[0], 0x81); // FIN + text
        assert_eq!(frame[1], 2); // unmasked, len 2
        assert_eq!(&frame[2..], b"hi");
    }

    #[test]
    fn medium_frame_uses_the_two_byte_length() {
        let payload = "x".repeat(200);
        let frame = encode_text_frame(&payload);
        assert_eq!(frame[0], 0x81);
        assert_eq!(frame[1], 126);
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 200);
    }

    #[test]
    fn unmask_round_trips() {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let mut buf = *b"hello!";
        unmask(&mut buf, mask);
        assert_ne!(&buf, b"hello!");
        unmask(&mut buf, mask);
        assert_eq!(&buf, b"hello!");
    }
}
