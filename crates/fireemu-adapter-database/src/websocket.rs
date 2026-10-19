//! The WebSocket protocol (RFC 6455) as a server speaks it: the opening handshake key, frame
//! decoding and encoding, and message reassembly. Hyper performs the HTTP upgrade; this
//! module handles the bytes after it. No extensions or subprotocols are negotiated.

use fireemu_core_database::hash::{base64, sha1};

/// The GUID RFC 6455 appends to the client key.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `Sec-WebSocket-Accept` value for a `Sec-WebSocket-Key`.
pub fn accept_key(key: &str) -> String {
    base64(&sha1(format!("{}{GUID}", key.trim()).as_bytes()))
}

/// A frame opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A continuation of a fragmented message.
    Continuation,
    /// A UTF-8 text frame.
    Text,
    /// A binary frame.
    Binary,
    /// The closing handshake.
    Close,
    /// A ping.
    Ping,
    /// A pong.
    Pong,
}

impl Opcode {
    fn from_bits(bits: u8) -> Result<Self, ProtocolError> {
        Ok(match bits {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            other => return Err(ProtocolError::UnknownOpcode(other)),
        })
    }

    fn bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// One decoded frame, unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Whether this is the last frame of its message.
    pub fin: bool,
    /// The opcode.
    pub opcode: Opcode,
    /// The payload.
    pub payload: Vec<u8>,
}

/// The result of decoding the start of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// A frame and the number of bytes it used.
    Frame(Frame, usize),
    /// The buffer does not yet hold a whole frame.
    Incomplete,
}

/// A violation that ends the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// A client frame without a mask.
    Unmasked,
    /// Reserved bits set without a negotiated extension.
    ReservedBits,
    /// An opcode RFC 6455 does not define.
    UnknownOpcode(u8),
    /// A control frame that is fragmented or longer than 125 bytes.
    BadControlFrame,
    /// A frame or message longer than the limit.
    TooBig,
    /// A continuation frame with no message to continue.
    UnexpectedContinuation,
    /// A new data frame while a fragmented message is open.
    ExpectedContinuation,
    /// A text message that is not UTF-8.
    InvalidUtf8,
}

/// The close status codes this server sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// 1000.
    Normal,
    /// 1002.
    Protocol,
    /// 1007.
    InvalidData,
    /// 1009.
    TooBig,
}

impl CloseCode {
    /// The numeric code.
    pub fn code(self) -> u16 {
        match self {
            Self::Normal => 1000,
            Self::Protocol => 1002,
            Self::InvalidData => 1007,
            Self::TooBig => 1009,
        }
    }
}

impl ProtocolError {
    /// The close code to answer the violation with.
    pub fn close_code(self) -> CloseCode {
        match self {
            Self::TooBig => CloseCode::TooBig,
            Self::InvalidUtf8 => CloseCode::InvalidData,
            _ => CloseCode::Protocol,
        }
    }
}

/// Decodes the frame at the start of `buffer`; payloads beyond `max_payload` are refused.
pub fn decode(buffer: &[u8], max_payload: usize) -> Result<Decoded, ProtocolError> {
    let [first, second, ..] = *buffer else {
        return Ok(Decoded::Incomplete);
    };
    if first & 0x70 != 0 {
        return Err(ProtocolError::ReservedBits);
    }
    let fin = first & 0x80 != 0;
    let opcode = Opcode::from_bits(first & 0x0F)?;
    if second & 0x80 == 0 {
        return Err(ProtocolError::Unmasked);
    }
    let (length, mut at) = match second & 0x7F {
        126 => match buffer.get(2..4) {
            Some(bytes) => (u64::from(u16::from_be_bytes([bytes[0], bytes[1]])), 4),
            None => return Ok(Decoded::Incomplete),
        },
        127 => match buffer.get(2..10) {
            Some(bytes) => {
                let mut array = [0u8; 8];
                array.copy_from_slice(bytes);
                (u64::from_be_bytes(array), 10)
            }
            None => return Ok(Decoded::Incomplete),
        },
        short => (u64::from(short), 2),
    };
    if opcode.is_control() && (!fin || length > 125) {
        return Err(ProtocolError::BadControlFrame);
    }
    let length = usize::try_from(length).map_err(|_| ProtocolError::TooBig)?;
    if length > max_payload {
        return Err(ProtocolError::TooBig);
    }
    let Some(mask) = buffer.get(at..at + 4) else {
        return Ok(Decoded::Incomplete);
    };
    let mask = [mask[0], mask[1], mask[2], mask[3]];
    at += 4;
    let Some(masked) = buffer.get(at..at + length) else {
        return Ok(Decoded::Incomplete);
    };
    let payload = masked
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ mask[i % 4])
        .collect();
    Ok(Decoded::Frame(
        Frame {
            fin,
            opcode,
            payload,
        },
        at + length,
    ))
}

/// Encodes one final, unmasked server frame.
pub fn encode(opcode: Opcode, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | opcode.bits());
    match payload.len() {
        len @ 0..=125 => out.push(u8::try_from(len).unwrap_or(125)),
        len @ 126..=0xFFFF => {
            out.push(126);
            out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
        }
        len => {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// A complete message or control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping and its payload.
    Ping(Vec<u8>),
    /// A pong.
    Pong,
    /// A close, with its status code if one was sent.
    Close(Option<u16>),
}

/// Reassembles fragmented messages; control frames pass through between fragments.
#[derive(Debug)]
pub struct Assembler {
    max_message: usize,
    open: Option<(Opcode, Vec<u8>)>,
}

impl Assembler {
    /// An assembler refusing messages longer than `max_message` bytes.
    pub fn new(max_message: usize) -> Self {
        Self {
            max_message,
            open: None,
        }
    }

    /// Takes the next frame; returns a message once one is complete.
    pub fn push(&mut self, frame: Frame) -> Result<Option<Message>, ProtocolError> {
        match frame.opcode {
            Opcode::Ping => return Ok(Some(Message::Ping(frame.payload))),
            Opcode::Pong => return Ok(Some(Message::Pong)),
            Opcode::Close => {
                let code = (frame.payload.len() >= 2)
                    .then(|| u16::from_be_bytes([frame.payload[0], frame.payload[1]]));
                return Ok(Some(Message::Close(code)));
            }
            Opcode::Continuation => {
                let Some((_, buffer)) = self.open.as_mut() else {
                    return Err(ProtocolError::UnexpectedContinuation);
                };
                buffer.extend_from_slice(&frame.payload);
                if buffer.len() > self.max_message {
                    return Err(ProtocolError::TooBig);
                }
            }
            Opcode::Text | Opcode::Binary => {
                if self.open.is_some() {
                    return Err(ProtocolError::ExpectedContinuation);
                }
                if frame.payload.len() > self.max_message {
                    return Err(ProtocolError::TooBig);
                }
                self.open = Some((frame.opcode, frame.payload));
            }
        }
        if !frame.fin {
            return Ok(None);
        }
        let Some((opcode, payload)) = self.open.take() else {
            return Ok(None);
        };
        if opcode == Opcode::Binary {
            return Ok(Some(Message::Binary(payload)));
        }
        String::from_utf8(payload)
            .map(|text| Some(Message::Text(text)))
            .map_err(|_| ProtocolError::InvalidUtf8)
    }
}
