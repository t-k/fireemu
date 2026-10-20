//! The long-polling transport (`/.lp`) the browser SDK falls back to, or uses when
//! `forceLongPolling()` is called: the text layer, without sockets.
//!
//! A connection starts with `start=t` (answered with a script that names the connection's id
//! and password and carries the handshake as packet 0). The client then keeps one request
//! open (two while it sends) naming `id`, `pw` and a serial `ser`; a request may carry
//! segments `seg<i>`, `ts<i>` and `d<i>`: a segment number, the number of segments in its
//! packet, and a piece of the packet's web-safe base64 text. Packets are joined in segment
//! order, one message each. The server answers a request with `pRTLPCB(<n>,[<messages>]);`,
//! numbering its answers from 1, at once when it has messages and otherwise when it has
//! some, when the next request arrives, or when the hold time ends (`<!-- -->`). A request
//! for an unknown connection is told to reset and close; `dframe=t` returns a page that
//! sends `disconn=t` when the browser unloads it. Every text follows the official emulator
//! (firebase-database-emulator v4.11.2).

use std::collections::BTreeMap;

use fireemu_core_database::Json;

use crate::json_text::{render, Style};

/// The answer that carries nothing (a held request's hold ended, or a disconnect).
pub const NOTHING: &str = "<!-- -->";

/// A segment of a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Its number in the connection's sequence of segments.
    pub number: u64,
    /// How many segments its packet has.
    pub total: u64,
    /// Its piece of the packet's base64 text.
    pub data: String,
}

/// A long-polling request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LpRequest {
    /// `start=t`: open a connection; the callback number names the page's callbacks.
    Start {
        /// `cb`, when it is a number the official emulator reads (digits, below 2^31).
        callback: Option<i32>,
    },
    /// A poll of the connection `id`, with the segments it carries.
    Poll {
        /// `id`.
        id: String,
        /// `pw`.
        password: String,
        /// The segments, in the order they were sent.
        segments: Vec<Segment>,
    },
    /// `dframe=t`: the page that reports the unload.
    DisconnectFrame {
        /// `id`, read as a 32-bit number.
        id: i32,
        /// `pw`, letters and digits only.
        password: String,
    },
    /// `disconn=t`: the client left.
    Disconnect {
        /// `id`.
        id: String,
        /// `pw`.
        password: String,
    },
    /// A request the official emulator answers with an empty page.
    Refused,
}

/// Reads a long-polling request from its query parameters.
pub fn parse(params: &BTreeMap<String, String>) -> LpRequest {
    let get = |name: &str| params.get(name).cloned().unwrap_or_default();
    if params.contains_key("start") {
        let callback = params.get("cb").and_then(|cb| {
            if cb.is_empty() {
                Some(0)
            } else if cb.bytes().all(|b| b.is_ascii_digit()) {
                cb.parse().ok()
            } else {
                None
            }
        });
        return LpRequest::Start { callback };
    }
    if params.contains_key("dframe") {
        let id = params.get("id").and_then(|id| id.parse::<i32>().ok());
        let password = params
            .get("pw")
            .filter(|pw| pw.bytes().all(|b| b.is_ascii_alphanumeric()));
        return match (id, password) {
            (Some(id), Some(password)) => LpRequest::DisconnectFrame {
                id,
                password: password.clone(),
            },
            _ => LpRequest::Refused,
        };
    }
    if params.contains_key("disconn") {
        return LpRequest::Disconnect {
            id: get("id"),
            password: get("pw"),
        };
    }
    let mut segments = Vec::new();
    for i in 0.. {
        let (Some(number), Some(total), Some(data)) = (
            params.get(&format!("seg{i}")),
            params.get(&format!("ts{i}")),
            params.get(&format!("d{i}")),
        ) else {
            break;
        };
        let (Ok(number), Ok(total)) = (number.parse(), total.parse()) else {
            break;
        };
        segments.push(Segment {
            number,
            total,
            data: data.clone(),
        });
    }
    LpRequest::Poll {
        id: get("id"),
        password: get("pw"),
        segments,
    }
}

/// The answer to `start=t`: the page's callbacks when it named them, the connection, and
/// the handshake as packet 0.
pub fn start_script(callback: Option<i32>, id: &str, password: &str, handshake: &str) -> String {
    format!(
        "{}pLPCommand('start','{id}','{password}');\n{}",
        callbacks(callback),
        packet(0, &[handshake.to_owned()])
    )
}

/// The functions a start answer defines to reach the page's callbacks, when it named them.
pub fn callbacks(callback: Option<i32>) -> String {
    callback.map_or_else(String::new, |cb| {
        format!(
            "\nfunction pLPCommand(c, a1, a2, a3, a4) {{\nparent.window[\"pLPCommand{cb}\"] && parent.window[\"pLPCommand{cb}\"](c, a1, a2, a3, a4);\n}}\nfunction pRTLPCB(pN, data) {{\nparent.window[\"pRTLPCB{cb}\"] && parent.window[\"pRTLPCB{cb}\"](pN, data);\n}}\n         "
        )
    })
}

/// Answer `number` carrying `messages`, each one JSON text.
pub fn packet(number: u64, messages: &[String]) -> String {
    format!("pRTLPCB({number},[{}]);\n", messages.join(","))
}

/// The answer for a request naming no live connection: reset to `host` and close.
pub fn reset(host: &str) -> String {
    let message = format!(
        "{{\"t\":\"c\",\"d\":{{\"t\":\"r\",\"d\":{}}}}}",
        render(&Json::string(host), Style::Compact)
    );
    format!("{}pLPCommand('close');\n", packet(0, &[message]))
}

/// The page that sends `disconn=t` for the connection when the browser unloads it.
pub fn disconnect_frame(id: i32, password: &str) -> String {
    format!(
        "<html><body><script>\nfunction EnvSendPing(destURL) {{\ntry{{\nvar xhr=new XMLHttpRequest();\nxhr.open(\"GET\", destURL, false);\nxhr.send(null);\n}} catch (e) {{ }}\n}}\nfunction EnvDisconnect() {{\nEnvSendPing(\"/.lp?disconn=t&id={id}&pw={password}\");\n}}\nif(window.addEventListener)\nwindow.addEventListener('unload',EnvDisconnect,false);\nelse if(window.attachEvent)\nwindow.attachEvent('onunload',EnvDisconnect);\n</script></body></html>"
    )
}

/// Decodes base64 in the SDK's web-safe form (`-`, `_`, `.` padding); the standard
/// alphabet and `=` padding are read too. Padding may only end the text.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let padding = bytes
        .iter()
        .rev()
        .take_while(|b| matches!(b, b'.' | b'='))
        .count();
    let body = &bytes[..bytes.len() - padding];
    if padding > 2 || (padding > 0 && bytes.len() % 4 != 0) || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0;
    for &byte in body {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xFF).unwrap_or(0));
        }
    }
    Some(out)
}

/// Joins segments into packets, in segment order, decoding each packet into one message.
#[derive(Debug)]
pub struct Reassembler {
    /// The number of the next segment to use.
    next: u64,
    /// Segments that arrived ahead of it.
    waiting: BTreeMap<u64, Segment>,
    /// The base64 bytes waiting, and the most that may wait.
    waiting_bytes: usize,
    limit: usize,
}

/// Segments that cannot be used: bad base64, text that is not UTF-8, or more waiting than
/// the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSegments;

impl Reassembler {
    /// A reassembler holding at most `limit` bytes of waiting segments.
    pub fn new(limit: usize) -> Self {
        Self {
            next: 0,
            waiting: BTreeMap::new(),
            waiting_bytes: 0,
            limit,
        }
    }

    /// Takes the segments of one request; returns the messages they complete, in order.
    pub fn add(&mut self, segments: Vec<Segment>) -> Result<Vec<String>, BadSegments> {
        for segment in segments {
            if segment.number < self.next || self.waiting.contains_key(&segment.number) {
                continue;
            }
            self.waiting_bytes += segment.data.len();
            if self.waiting_bytes > self.limit {
                return Err(BadSegments);
            }
            self.waiting.insert(segment.number, segment);
        }
        let mut messages = Vec::new();
        loop {
            let Some(first) = self.waiting.get(&self.next) else {
                break;
            };
            let total = first.total.max(1);
            let Some(end) = self.next.checked_add(total) else {
                return Err(BadSegments);
            };
            if !(self.next..end).all(|n| self.waiting.contains_key(&n)) {
                break;
            }
            let mut text = String::new();
            for n in self.next..end {
                if let Some(segment) = self.waiting.remove(&n) {
                    self.waiting_bytes -= segment.data.len();
                    text.push_str(&segment.data);
                }
            }
            self.next = end;
            let bytes = decode_base64(&text).ok_or(BadSegments)?;
            messages.push(String::from_utf8(bytes).map_err(|_| BadSegments)?);
        }
        Ok(messages)
    }
}
