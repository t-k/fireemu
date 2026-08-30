//! A hand-written protocol buffer wire reader and writer.
//!
//! The Firestore managed export is written in the legacy `apphosting.datastore.v3`
//! `EntityProto` schema, which is proto2 and uses **groups** (wire type 3 / 4) for the key
//! path elements, the geographical point value and the reference value. `prost` cannot
//! express groups at all, so the codec is written directly against the wire format. That
//! also keeps this crate std-only, like every other `fireemu-core-*` crate.
//!
//! Only the four wire types the format actually uses are supported: varint (0), 64-bit
//! (1), length-delimited (2) and the start / end group pair (3 and 4). A 32-bit field (5)
//! is parsed and skipped so that an unknown field written by a future emulator version does
//! not make a whole export unreadable.

/// What went wrong while decoding a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    /// Byte offset the failure was noticed at.
    pub offset: usize,
    /// What the decoder expected.
    pub expected: &'static str,
}

impl WireError {
    /// A failure at `offset`.
    #[must_use]
    pub fn new(offset: usize, expected: &'static str) -> Self {
        Self { offset, expected }
    }
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "malformed protocol buffer at byte {}: expected {}",
            self.offset, self.expected
        )
    }
}

impl std::error::Error for WireError {}

/// The wire type of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// Wire type 0.
    Varint,
    /// Wire type 1.
    Fixed64,
    /// Wire type 2.
    Delimited,
    /// Wire type 3.
    StartGroup,
    /// Wire type 4.
    EndGroup,
    /// Wire type 5.
    Fixed32,
}

impl WireType {
    fn from_tag(tag: u64) -> Option<Self> {
        match tag & 7 {
            0 => Some(Self::Varint),
            1 => Some(Self::Fixed64),
            2 => Some(Self::Delimited),
            3 => Some(Self::StartGroup),
            4 => Some(Self::EndGroup),
            5 => Some(Self::Fixed32),
            _ => None,
        }
    }

    fn code(self) -> u64 {
        match self {
            Self::Varint => 0,
            Self::Fixed64 => 1,
            Self::Delimited => 2,
            Self::StartGroup => 3,
            Self::EndGroup => 4,
            Self::Fixed32 => 5,
        }
    }
}

/// A cursor over an encoded message.
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Whether every byte was consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// The offset the next read starts at.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Reads the next field header, or `None` at the end of the message.
    ///
    /// An end-group tag is returned like any other field; the caller decides whether it
    /// closes the group it is decoding.
    pub fn field(&mut self) -> Result<Option<(u32, WireType)>, WireError> {
        if self.is_empty() {
            return Ok(None);
        }
        let at = self.pos;
        let tag = self.varint()?;
        let wire = WireType::from_tag(tag).ok_or(WireError::new(at, "a known wire type"))?;
        let number = u32::try_from(tag >> 3).map_err(|_| WireError::new(at, "a field number"))?;
        if number == 0 {
            return Err(WireError::new(at, "a field number above zero"));
        }
        Ok(Some((number, wire)))
    }

    /// Reads a base-128 varint.
    pub fn varint(&mut self) -> Result<u64, WireError> {
        let at = self.pos;
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .bytes
                .get(self.pos)
                .ok_or(WireError::new(at, "more varint bytes"))?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(WireError::new(at, "a varint of at most ten bytes"));
            }
        }
    }

    /// Reads eight little-endian bytes.
    pub fn fixed64(&mut self) -> Result<u64, WireError> {
        let at = self.pos;
        let end = self.pos + 8;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(WireError::new(at, "eight bytes"))?;
        self.pos = end;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice);
        Ok(u64::from_le_bytes(buf))
    }

    /// Reads a length-delimited field's payload.
    pub fn delimited(&mut self) -> Result<&'a [u8], WireError> {
        let at = self.pos;
        let len = usize::try_from(self.varint()?).map_err(|_| WireError::new(at, "a length"))?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or(WireError::new(at, "a length within the message"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or(WireError::new(at, "a length within the message"))?;
        self.pos = end;
        Ok(slice)
    }

    /// Reads a length-delimited field as UTF-8.
    pub fn string(&mut self) -> Result<String, WireError> {
        let at = self.pos;
        let bytes = self.delimited()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::new(at, "UTF-8 text"))
    }

    /// Consumes the body of a group started by `number`, returning its raw bytes (without
    /// the closing end-group tag).
    pub fn group(&mut self, number: u32) -> Result<&'a [u8], WireError> {
        let start = self.pos;
        let mut depth = 1usize;
        loop {
            let at = self.pos;
            let Some((field, wire)) = self.field()? else {
                return Err(WireError::new(at, "an end-group tag"));
            };
            match wire {
                WireType::StartGroup => depth += 1,
                WireType::EndGroup => {
                    depth -= 1;
                    if depth == 0 {
                        if field != number {
                            return Err(WireError::new(at, "the matching end-group tag"));
                        }
                        return Ok(&self.bytes[start..at]);
                    }
                }
                WireType::Varint => {
                    self.varint()?;
                }
                WireType::Fixed64 => {
                    self.fixed64()?;
                }
                WireType::Fixed32 => {
                    let end = self.pos + 4;
                    self.bytes
                        .get(self.pos..end)
                        .ok_or(WireError::new(at, "four bytes"))?;
                    self.pos = end;
                }
                WireType::Delimited => {
                    self.delimited()?;
                }
            }
        }
    }

    /// Skips a field of `wire` whose header was already read.
    pub fn skip(&mut self, number: u32, wire: WireType) -> Result<(), WireError> {
        let at = self.pos;
        match wire {
            WireType::Varint => {
                self.varint()?;
            }
            WireType::Fixed64 => {
                self.fixed64()?;
            }
            WireType::Fixed32 => {
                let end = self.pos + 4;
                self.bytes
                    .get(self.pos..end)
                    .ok_or(WireError::new(at, "four bytes"))?;
                self.pos = end;
            }
            WireType::Delimited => {
                self.delimited()?;
            }
            WireType::StartGroup => {
                self.group(number)?;
            }
            WireType::EndGroup => return Err(WireError::new(at, "no stray end-group tag")),
        }
        Ok(())
    }
}

/// A growable encoded message.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// The encoded bytes so far.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn tag(&mut self, number: u32, wire: WireType) {
        self.varint(u64::from(number) << 3 | wire.code());
    }

    fn varint(&mut self, mut value: u64) {
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap_or(0);
            value >>= 7;
            if value == 0 {
                self.bytes.push(byte);
                return;
            }
            self.bytes.push(byte | 0x80);
        }
    }

    /// Writes a varint field.
    pub fn write_varint(&mut self, number: u32, value: u64) {
        self.tag(number, WireType::Varint);
        self.varint(value);
    }

    /// Writes a signed varint field in two's complement, as proto2 `int64` does.
    ///
    /// The reinterpretation is the encoding: proto2 stores a negative `int64` as the ten-byte
    /// varint of its unsigned two's complement, which is exactly what the cast produces.
    #[allow(clippy::cast_sign_loss)]
    pub fn write_int64(&mut self, number: u32, value: i64) {
        self.write_varint(number, value as u64);
    }

    /// Writes a boolean field.
    pub fn write_bool(&mut self, number: u32, value: bool) {
        self.write_varint(number, u64::from(value));
    }

    /// Writes a 64-bit field.
    pub fn write_fixed64(&mut self, number: u32, value: u64) {
        self.tag(number, WireType::Fixed64);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes an IEEE-754 double field, preserving the exact bit pattern (a NaN payload and
    /// the sign of zero both survive a round trip).
    pub fn write_double(&mut self, number: u32, value: f64) {
        self.write_fixed64(number, value.to_bits());
    }

    /// Writes a length-delimited field.
    pub fn write_bytes(&mut self, number: u32, value: &[u8]) {
        self.tag(number, WireType::Delimited);
        self.varint(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    /// Writes a length-delimited field holding UTF-8 text.
    pub fn write_string(&mut self, number: u32, value: &str) {
        self.write_bytes(number, value.as_bytes());
    }

    /// Writes a nested message built by `body`.
    pub fn write_message(&mut self, number: u32, body: impl FnOnce(&mut Writer)) {
        let mut inner = Writer::new();
        body(&mut inner);
        self.write_bytes(number, inner.as_slice());
    }

    /// Writes a group built by `body`.
    pub fn write_group(&mut self, number: u32, body: impl FnOnce(&mut Writer)) {
        self.tag(number, WireType::StartGroup);
        body(self);
        self.tag(number, WireType::EndGroup);
    }
}

#[cfg(test)]
mod tests {
    use super::{Reader, WireType, Writer};

    #[test]
    fn a_varint_round_trips_through_the_writer_and_the_reader() {
        let mut w = Writer::new();
        w.write_varint(1, 0);
        w.write_varint(2, 300);
        w.write_varint(3, u64::MAX);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let mut seen = Vec::new();
        while let Some((number, wire)) = r.field().expect("a field") {
            assert_eq!(wire, WireType::Varint);
            seen.push((number, r.varint().expect("a value")));
        }
        assert_eq!(seen, vec![(1, 0), (2, 300), (3, u64::MAX)]);
    }

    #[test]
    fn a_negative_int64_is_written_in_twos_complement_like_proto2() {
        let mut w = Writer::new();
        w.write_int64(1, -9_007_199_254_740_991);
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let (_, wire) = r.field().expect("a field").expect("one field");
        assert_eq!(wire, WireType::Varint);
        assert_eq!(r.varint().expect("a value"), 18_437_736_874_454_810_625);
    }

    #[test]
    fn a_group_body_is_returned_without_its_end_tag() {
        let mut w = Writer::new();
        w.write_group(5, |g| {
            g.write_string(2, "cities");
            g.write_string(4, "SF");
        });
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        let (number, wire) = r.field().expect("a field").expect("one field");
        assert_eq!((number, wire), (5, WireType::StartGroup));
        let body = r.group(5).expect("a closed group");
        let mut inner = Reader::new(body);
        let (_, _) = inner.field().expect("a field").expect("one field");
        assert_eq!(inner.string().expect("text"), "cities");
        let (_, _) = inner.field().expect("a field").expect("one field");
        assert_eq!(inner.string().expect("text"), "SF");
        assert!(inner.is_empty());
        assert!(r.is_empty());
    }

    #[test]
    fn a_double_keeps_its_exact_bits() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.0, 7272.5] {
            let mut w = Writer::new();
            w.write_double(4, value);
            let bytes = w.finish();
            let mut r = Reader::new(&bytes);
            r.field().expect("a field").expect("one field");
            assert_eq!(
                f64::from_bits(r.fixed64().expect("bits")).to_bits(),
                value.to_bits()
            );
        }
    }

    #[test]
    fn a_truncated_message_is_refused_rather_than_silently_short() {
        let mut w = Writer::new();
        w.write_string(1, "cities");
        let mut bytes = w.finish();
        bytes.truncate(bytes.len() - 2);
        let mut r = Reader::new(&bytes);
        r.field().expect("a field").expect("one field");
        assert!(r.delimited().is_err());
    }

    #[test]
    fn an_unterminated_group_is_refused() {
        let bytes = vec![0x2b]; // start group 5, nothing else
        let mut r = Reader::new(&bytes);
        r.field().expect("a field").expect("one field");
        assert!(r.group(5).is_err());
    }
}
