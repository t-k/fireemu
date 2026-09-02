//! The `LevelDB` log record framing the Firestore managed export is written in.
//!
//! Every `output-*` file and the `*.overall_export_metadata` file is a sequence of `LevelDB`
//! log records: 32 KiB blocks, each record prefixed by a seven-byte header of a masked
//! CRC-32C over the type byte and the payload (four bytes, little endian), the payload
//! length (two bytes, little endian) and the record type. A record that does not fit in the
//! remainder of a block is split across blocks with the FIRST / MIDDLE / LAST types, and a
//! remainder shorter than a header is zero-filled.
//!
//! The masking is `LevelDB`'s own: a CRC is rotated and offset before it is stored so that a
//! stored CRC is never the CRC of the bytes that follow it.

/// The `LevelDB` block size.
pub const BLOCK_SIZE: usize = 32 * 1024;

/// The size of a record header.
pub const HEADER_SIZE: usize = 7;

/// The record types `LevelDB`'s log writer emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordType {
    Full = 1,
    First = 2,
    Middle = 3,
    Last = 4,
}

/// What went wrong while reading a log file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// A header ran past the end of the file.
    Truncated {
        /// Byte offset of the header.
        offset: usize,
    },
    /// The stored CRC does not match the record.
    Checksum {
        /// Byte offset of the header.
        offset: usize,
    },
    /// A record type outside 1..=4.
    UnknownType {
        /// Byte offset of the header.
        offset: usize,
        /// The type byte that was read.
        found: u8,
    },
    /// A fragment arrived in an order the format does not allow (a MIDDLE without a FIRST,
    /// a FIRST inside an unfinished record, ...).
    Fragmentation {
        /// Byte offset of the header.
        offset: usize,
    },
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated { offset } => {
                write!(f, "the log record at byte {offset} is truncated")
            }
            Self::Checksum { offset } => write!(
                f,
                "the log record at byte {offset} does not match its checksum"
            ),
            Self::UnknownType { offset, found } => write!(
                f,
                "the log record at byte {offset} has the unknown type {found}"
            ),
            Self::Fragmentation { offset } => write!(
                f,
                "the log record fragment at byte {offset} is out of order"
            ),
        }
    }
}

impl std::error::Error for LogError {}

const MASK_DELTA: u32 = 0xa282_ead8;

/// `LevelDB`'s CRC mask.
fn mask(crc: u32) -> u32 {
    crc.rotate_right(15).wrapping_add(MASK_DELTA)
}

pub use fireemu_core_types::hash::crc32c;

/// Appends `records` to a `LevelDB` log file body.
#[must_use]
pub fn write_log(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for record in records {
        write_record(&mut out, record);
    }
    out
}

fn write_record(out: &mut Vec<u8>, payload: &[u8]) {
    let mut rest = payload;
    let mut first = true;
    loop {
        let mut room = BLOCK_SIZE - (out.len() % BLOCK_SIZE);
        if room < HEADER_SIZE {
            out.extend(std::iter::repeat_n(0u8, room));
            room = BLOCK_SIZE;
        }
        let capacity = room - HEADER_SIZE;
        let take = capacity.min(rest.len());
        let last = take == rest.len();
        let kind = match (first, last) {
            (true, true) => RecordType::Full,
            (true, false) => RecordType::First,
            (false, true) => RecordType::Last,
            (false, false) => RecordType::Middle,
        };
        emit(out, kind, &rest[..take]);
        rest = &rest[take..];
        first = false;
        if last {
            return;
        }
    }
}

fn emit(out: &mut Vec<u8>, kind: RecordType, payload: &[u8]) {
    let mut checked = Vec::with_capacity(payload.len() + 1);
    checked.push(kind as u8);
    checked.extend_from_slice(payload);
    let crc = mask(crc32c(&checked));
    out.extend_from_slice(&crc.to_le_bytes());
    let len = u16::try_from(payload.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.push(kind as u8);
    out.extend_from_slice(payload);
}

/// Reads every record of a `LevelDB` log file.
///
/// A malformed file is refused rather than truncated at the first bad record: an import
/// that silently dropped the tail of a Firestore export would be exactly the "silent loss"
/// this format exists to prevent.
pub fn read_log(bytes: &[u8]) -> Result<Vec<Vec<u8>>, LogError> {
    let mut records = Vec::new();
    let mut pending: Option<Vec<u8>> = None;
    let mut pos = 0usize;
    while pos < bytes.len() {
        let block_offset = pos % BLOCK_SIZE;
        if BLOCK_SIZE - block_offset < HEADER_SIZE {
            // The zero-filled remainder of a block.
            pos += BLOCK_SIZE - block_offset;
            continue;
        }
        let header = bytes
            .get(pos..pos + HEADER_SIZE)
            .ok_or(LogError::Truncated { offset: pos })?;
        let stored = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let len = usize::from(u16::from_le_bytes([header[4], header[5]]));
        let kind = header[6];
        if stored == 0 && len == 0 && kind == 0 {
            // Zero padding before the next block.
            pos += BLOCK_SIZE - block_offset;
            continue;
        }
        let payload = bytes
            .get(pos + HEADER_SIZE..pos + HEADER_SIZE + len)
            .ok_or(LogError::Truncated { offset: pos })?;
        let mut checked = Vec::with_capacity(len + 1);
        checked.push(kind);
        checked.extend_from_slice(payload);
        if mask(crc32c(&checked)) != stored {
            return Err(LogError::Checksum { offset: pos });
        }
        match kind {
            1 => {
                if pending.is_some() {
                    return Err(LogError::Fragmentation { offset: pos });
                }
                records.push(payload.to_vec());
            }
            2 => {
                if pending.is_some() {
                    return Err(LogError::Fragmentation { offset: pos });
                }
                pending = Some(payload.to_vec());
            }
            3 => {
                let acc = pending
                    .as_mut()
                    .ok_or(LogError::Fragmentation { offset: pos })?;
                acc.extend_from_slice(payload);
            }
            4 => {
                let mut acc = pending
                    .take()
                    .ok_or(LogError::Fragmentation { offset: pos })?;
                acc.extend_from_slice(payload);
                records.push(acc);
            }
            found => return Err(LogError::UnknownType { offset: pos, found }),
        }
        pos += HEADER_SIZE + len;
    }
    if pending.is_some() {
        return Err(LogError::Truncated {
            offset: bytes.len(),
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::{crc32c, mask, read_log, write_log, BLOCK_SIZE};

    #[test]
    fn the_crc32c_matches_the_published_castagnoli_check_values() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
    }

    #[test]
    fn the_recorded_official_header_of_a_one_byte_record_is_reproduced() {
        // The first record of every `*.overall_export_metadata` the Firestore emulator jar
        // writes: the single byte 0x33 in a FULL record, whose masked CRC is 0x4e446db8.
        let framed = write_log(&[vec![0x33]]);
        assert_eq!(&framed[..7], &[0xb8, 0x6d, 0x44, 0x4e, 0x01, 0x00, 0x01]);
        assert_eq!(framed[7], 0x33);
        assert_eq!(mask(crc32c(&[0x01, 0x33])), 0x4e44_6db8);
    }

    #[test]
    fn records_round_trip_through_the_framing() {
        let records = vec![vec![0x33], b"hello".to_vec(), Vec::new()];
        let framed = write_log(&records);
        assert_eq!(read_log(&framed).expect("a readable log"), records);
    }

    #[test]
    fn a_record_longer_than_a_block_is_split_and_rejoined() {
        let big = vec![7u8; BLOCK_SIZE * 2 + 11];
        let framed = write_log(&[vec![1], big.clone()]);
        assert_eq!(
            read_log(&framed).expect("a readable log"),
            vec![vec![1], big]
        );
    }

    #[test]
    fn a_flipped_byte_is_refused_by_the_checksum() {
        let mut framed = write_log(&[b"payload".to_vec()]);
        let last = framed.len() - 1;
        framed[last] ^= 0xff;
        assert!(matches!(
            read_log(&framed),
            Err(super::LogError::Checksum { .. })
        ));
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_read_short() {
        let mut framed = write_log(&[b"payload".to_vec()]);
        framed.truncate(framed.len() - 3);
        assert!(matches!(
            read_log(&framed),
            Err(super::LogError::Truncated { .. })
        ));
    }
}
