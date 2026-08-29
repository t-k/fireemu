//! Firestore document path patterns of event triggers: `users/{uid}`, `posts/{id}/comments/*`,
//! `{path=**}` (multi-segment capture), `**` (multi-segment wildcard).

use std::collections::BTreeMap;
use std::fmt;

/// One pattern segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// Literal segment.
    Literal(String),
    /// `*`: any single segment.
    Wildcard,
    /// `**`: zero or more segments (must be last).
    MultiWildcard,
    /// `{name}`: one captured segment.
    Capture(String),
    /// `{name=**}`: zero or more captured segments (must be last).
    MultiCapture(String),
}

/// A parsed document path pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    segments: Vec<Segment>,
    source: String,
}

/// Invalid pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// Empty pattern or empty segment.
    Empty,
    /// A multi-segment wildcard / capture is not the last segment.
    MultiNotLast,
    /// Malformed capture (`{` without `}`, empty name, ...).
    MalformedCapture(String),
    /// The same capture name appears twice.
    DuplicateCapture(String),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("pattern has an empty segment"),
            Self::MultiNotLast => f.write_str("a multi-segment wildcard must be the last segment"),
            Self::MalformedCapture(s) => write!(f, "malformed capture {s:?}"),
            Self::DuplicateCapture(s) => write!(f, "capture {s:?} appears twice"),
        }
    }
}

impl std::error::Error for PatternError {}

impl PathPattern {
    /// Parses a pattern (leading / trailing `/` ignored).
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        let trimmed = pattern.trim_matches('/');
        if trimmed.is_empty() {
            return Err(PatternError::Empty);
        }
        let mut segments = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let parts: Vec<&str> = trimmed.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            let seg = match *part {
                "" => return Err(PatternError::Empty),
                "*" => Segment::Wildcard,
                "**" => Segment::MultiWildcard,
                p if p.starts_with('{') => {
                    let inner = p
                        .strip_prefix('{')
                        .and_then(|s| s.strip_suffix('}'))
                        .ok_or_else(|| PatternError::MalformedCapture(p.to_owned()))?;
                    let (name, multi) = match inner.split_once('=') {
                        Some((n, "**")) => (n, true),
                        Some(_) => return Err(PatternError::MalformedCapture(p.to_owned())),
                        None => (inner, false),
                    };
                    if name.is_empty()
                        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return Err(PatternError::MalformedCapture(p.to_owned()));
                    }
                    if names.iter().any(|n| n == name) {
                        return Err(PatternError::DuplicateCapture(name.to_owned()));
                    }
                    names.push(name.to_owned());
                    if multi {
                        Segment::MultiCapture(name.to_owned())
                    } else {
                        Segment::Capture(name.to_owned())
                    }
                }
                p => Segment::Literal(p.to_owned()),
            };
            let multi = matches!(seg, Segment::MultiWildcard | Segment::MultiCapture(_));
            if multi && !last {
                return Err(PatternError::MultiNotLast);
            }
            segments.push(seg);
        }
        Ok(Self {
            segments,
            source: trimmed.to_owned(),
        })
    }

    /// The pattern text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Segments.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Matches a document path (`users/alice/posts/p1`, relative to `documents/`) and
    /// returns the captured parameters.
    #[must_use]
    pub fn matches(&self, path: &str) -> Option<BTreeMap<String, String>> {
        let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
        let mut params = BTreeMap::new();
        let mut i = 0;
        for seg in &self.segments {
            match seg {
                Segment::MultiWildcard => {
                    return Some(params);
                }
                Segment::MultiCapture(name) => {
                    params.insert(name.clone(), parts[i..].join("/"));
                    return Some(params);
                }
                Segment::Literal(l) => {
                    if parts.get(i) != Some(&l.as_str()) {
                        return None;
                    }
                }
                Segment::Wildcard => {
                    parts.get(i)?;
                }
                Segment::Capture(name) => {
                    let value = parts.get(i)?;
                    params.insert(name.clone(), (*value).to_owned());
                }
            }
            i += 1;
        }
        if i == parts.len() {
            Some(params)
        } else {
            None
        }
    }

    /// Whether the pattern addresses documents (an even number of segments) rather than a
    /// collection.
    #[must_use]
    pub fn is_document_pattern(&self) -> bool {
        match self.segments.last() {
            Some(Segment::MultiWildcard | Segment::MultiCapture(_)) => true,
            _ => self.segments.len() % 2 == 0,
        }
    }
}
