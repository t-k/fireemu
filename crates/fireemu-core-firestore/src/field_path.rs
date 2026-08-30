//! Field paths (`FS-LIMIT-FIELD-NAME`, `FS-LIMIT-FIELD-PATH-BYTES`).
//!
//! Canonical form: segments joined by `.`; a segment that is not a simple identifier
//! (`[A-Za-z_][A-Za-z0-9_]*`) is wrapped in backticks with `` \` `` and `\\` escapes.
//! `__name__` is the only reserved `__.*__` segment that may appear. The path byte limit is
//! measured on raw segment bytes plus `.` separators (quoting overhead excluded); the exact
//! boundary is a conformance item (`FS-LIMIT-FIELD-PATH-BYTES`, boundary-conformance).

use core::fmt;

use fireemu_core_types::ids::MAX_ID_UTF8_BYTES;

/// Maximum UTF-8 bytes of a single field name (`FS-LIMIT-FIELD-NAME`).
pub const MAX_FIELD_NAME_BYTES: usize = MAX_ID_UTF8_BYTES;
/// Maximum UTF-8 bytes of the canonical field path (`FS-LIMIT-FIELD-PATH-BYTES`).
pub const MAX_FIELD_PATH_BYTES: usize = 1_500;

const DOCUMENT_NAME: &str = "__name__";

/// Field path parse / validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldPathError {
    /// Empty path.
    Empty,
    /// An empty segment (`a..b`, leading or trailing dot).
    EmptySegment {
        /// Segment index.
        index: usize,
    },
    /// A backtick-quoted segment is not terminated.
    UnterminatedQuote {
        /// Byte offset of the opening backtick.
        offset: usize,
    },
    /// A character that requires quoting appeared in an unquoted segment.
    UnquotedSpecialCharacter {
        /// Byte offset.
        offset: usize,
    },
    /// A control character (including NUL) appeared.
    ControlCharacter {
        /// Byte offset.
        offset: usize,
    },
    /// A segment matches `__.*__` and is not `__name__`.
    ReservedSegment {
        /// Segment index.
        index: usize,
    },
    /// A segment exceeds the field-name byte limit.
    SegmentTooLong {
        /// Segment index.
        index: usize,
        /// UTF-8 bytes.
        bytes: usize,
        /// Inclusive maximum.
        maximum: usize,
    },
    /// The canonical path exceeds the field-path byte limit.
    PathTooLong {
        /// UTF-8 bytes of the canonical path.
        bytes: usize,
        /// Inclusive maximum.
        maximum: usize,
    },
}

impl fmt::Display for FieldPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("field path is empty"),
            Self::EmptySegment { index } => write!(f, "field path segment {index} is empty"),
            Self::UnterminatedQuote { offset } => {
                write!(f, "unterminated backtick quote at byte {offset}")
            }
            Self::UnquotedSpecialCharacter { offset } => {
                write!(f, "character at byte {offset} must be backtick-quoted")
            }
            Self::ControlCharacter { offset } => write!(f, "control character at byte {offset}"),
            Self::ReservedSegment { index } => {
                write!(f, "segment {index} matches the reserved pattern __.*__")
            }
            Self::SegmentTooLong {
                index,
                bytes,
                maximum,
            } => {
                write!(f, "segment {index} is {bytes} bytes, maximum is {maximum}")
            }
            Self::PathTooLong { bytes, maximum } => {
                write!(f, "field path is {bytes} bytes, maximum is {maximum}")
            }
        }
    }
}

impl std::error::Error for FieldPathError {}

/// A validated field path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldPath {
    segments: Vec<String>,
}

fn is_simple(segment: &str) -> bool {
    let mut chars = segment.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_reserved(segment: &str) -> bool {
    segment.len() >= 4 && segment.starts_with("__") && segment.ends_with("__")
}

fn quote(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len() + 2);
    out.push('`');
    for c in segment.chars() {
        if c == '`' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('`');
    out
}

impl FieldPath {
    /// The reserved `__name__` field path.
    #[must_use]
    pub fn document_name() -> Self {
        Self {
            segments: vec![DOCUMENT_NAME.to_owned()],
        }
    }

    /// Whether this is `__name__`.
    #[must_use]
    pub fn is_document_name(&self) -> bool {
        self.segments.len() == 1 && self.segments[0] == DOCUMENT_NAME
    }

    /// Builds a path from raw segments, validating each one.
    pub fn from_segments<'a>(
        segments: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, FieldPathError> {
        let segments: Vec<String> = segments.into_iter().map(str::to_owned).collect();
        if segments.is_empty() {
            return Err(FieldPathError::Empty);
        }
        let mut canonical_len = segments.len() - 1;
        for (index, s) in segments.iter().enumerate() {
            if s.is_empty() {
                return Err(FieldPathError::EmptySegment { index });
            }
            if let Some((offset, _)) = s.char_indices().find(|(_, c)| c.is_control()) {
                return Err(FieldPathError::ControlCharacter { offset });
            }
            if s.len() > MAX_FIELD_NAME_BYTES {
                return Err(FieldPathError::SegmentTooLong {
                    index,
                    bytes: s.len(),
                    maximum: MAX_FIELD_NAME_BYTES,
                });
            }
            if is_reserved(s) && s != DOCUMENT_NAME {
                return Err(FieldPathError::ReservedSegment { index });
            }
            // Path bytes are counted on the raw segment bytes plus separators; backtick
            // quoting is a client-side notation and does not count toward the limit.
            canonical_len += s.len();
        }
        if canonical_len > MAX_FIELD_PATH_BYTES {
            return Err(FieldPathError::PathTooLong {
                bytes: canonical_len,
                maximum: MAX_FIELD_PATH_BYTES,
            });
        }
        Ok(Self { segments })
    }

    /// Parses the canonical dotted representation.
    pub fn parse(input: &str) -> Result<Self, FieldPathError> {
        if input.is_empty() {
            return Err(FieldPathError::Empty);
        }
        let bytes = input.as_bytes();
        let mut segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut i = 0;
        let mut segment_start = 0;
        let mut quoted_segment = false;
        while i < bytes.len() {
            match bytes[i] {
                b'`' => {
                    if i != segment_start {
                        return Err(FieldPathError::UnquotedSpecialCharacter { offset: i });
                    }
                    let open = i;
                    i += 1;
                    loop {
                        match bytes.get(i) {
                            None => return Err(FieldPathError::UnterminatedQuote { offset: open }),
                            Some(b'\\') => {
                                match bytes.get(i + 1) {
                                    Some(&c @ (b'`' | b'\\')) => current.push(c as char),
                                    _ => {
                                        return Err(FieldPathError::UnquotedSpecialCharacter {
                                            offset: i,
                                        })
                                    }
                                }
                                i += 2;
                            }
                            Some(b'`') => {
                                i += 1;
                                break;
                            }
                            Some(_) => {
                                let c = input[i..].chars().next().unwrap_or('\0');
                                current.push(c);
                                i += c.len_utf8();
                            }
                        }
                    }
                    quoted_segment = true;
                    if !matches!(bytes.get(i), None | Some(b'.')) {
                        return Err(FieldPathError::UnquotedSpecialCharacter { offset: i });
                    }
                }
                b'.' => {
                    if current.is_empty() && !quoted_segment {
                        return Err(FieldPathError::EmptySegment {
                            index: segments.len(),
                        });
                    }
                    segments.push(std::mem::take(&mut current));
                    quoted_segment = false;
                    i += 1;
                    segment_start = i;
                    if i == bytes.len() {
                        return Err(FieldPathError::EmptySegment {
                            index: segments.len(),
                        });
                    }
                }
                _ => {
                    let c = input[i..].chars().next().unwrap_or('\0');
                    if c.is_control() {
                        return Err(FieldPathError::ControlCharacter { offset: i });
                    }
                    let first = i == segment_start;
                    let ok = if first {
                        c.is_ascii_alphabetic() || c == '_'
                    } else {
                        c.is_ascii_alphanumeric() || c == '_'
                    };
                    if !ok {
                        return Err(FieldPathError::UnquotedSpecialCharacter { offset: i });
                    }
                    current.push(c);
                    i += c.len_utf8();
                }
            }
        }
        if current.is_empty() && !quoted_segment {
            return Err(FieldPathError::EmptySegment {
                index: segments.len(),
            });
        }
        segments.push(current);
        Self::from_segments(segments.iter().map(String::as_str))
    }

    /// Segments.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    /// Canonical dotted representation.
    #[must_use]
    pub fn canonical(&self) -> String {
        let parts: Vec<String> = self
            .segments
            .iter()
            .map(|s| if is_simple(s) { s.clone() } else { quote(s) })
            .collect();
        parts.join(".")
    }

    /// Whether `self` is a (non-strict) prefix of `other`.
    #[must_use]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        other.segments.starts_with(&self.segments)
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}
