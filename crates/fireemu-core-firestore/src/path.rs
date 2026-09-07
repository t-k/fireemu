//! Document and collection paths (`FS-LIMIT-SUBCOLLECTION-DEPTH`, `FS-LIMIT-DOCUMENT-NAME-BYTES`).

use core::fmt;

use fireemu_core_types::ids::{CollectionId, DatabaseId, DocumentId, IdSyntaxError, ProjectId};

/// Maximum subcollection depth (`FS-LIMIT-SUBCOLLECTION-DEPTH`).
pub const MAX_SUBCOLLECTION_DEPTH: usize = 100;
/// Maximum UTF-8 bytes of a full resource name (`FS-LIMIT-DOCUMENT-NAME-BYTES`, 6 KiB).
pub const MAX_DOCUMENT_NAME_BYTES: usize = 6 * 1024;

/// Path errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// A document path must have an even number of segments (collection/document pairs).
    OddSegmentCount {
        /// Segment count.
        segments: usize,
    },
    /// Empty path.
    Empty,
    /// An invalid segment.
    InvalidSegment {
        /// Segment index.
        index: usize,
        /// Underlying error.
        error: IdSyntaxError,
    },
    /// Too many nested subcollections.
    TooDeep {
        /// Observed depth (number of collection levels).
        depth: usize,
        /// Inclusive maximum.
        maximum: usize,
    },
    /// The full resource name is too long.
    NameTooLong {
        /// UTF-8 bytes.
        bytes: usize,
        /// Inclusive maximum.
        maximum: usize,
    },
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddSegmentCount { segments } => {
                write!(
                    f,
                    "document path has {segments} segments; expected an even number"
                )
            }
            Self::Empty => f.write_str("path is empty"),
            Self::InvalidSegment { index, error } => write!(f, "segment {index}: {error}"),
            Self::TooDeep { depth, maximum } => {
                write!(f, "subcollection depth {depth} exceeds {maximum}")
            }
            Self::NameTooLong { bytes, maximum } => {
                write!(f, "document name is {bytes} bytes, maximum is {maximum}")
            }
        }
    }
}

impl std::error::Error for PathError {}

/// A fully qualified document path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DocumentPath {
    project: ProjectId,
    database: DatabaseId,
    /// Alternating (collection, document) pairs from the root.
    pairs: Vec<(CollectionId, DocumentId)>,
}

impl DocumentPath {
    /// Parses a relative path such as `users/jeff/tasks/my_task_id`.
    pub fn parse(
        project: &ProjectId,
        database: &DatabaseId,
        relative: &str,
    ) -> Result<Self, PathError> {
        if relative.is_empty() {
            return Err(PathError::Empty);
        }
        let segments: Vec<&str> = relative.split('/').collect();
        if segments.len() % 2 != 0 {
            return Err(PathError::OddSegmentCount {
                segments: segments.len(),
            });
        }
        let mut pairs = Vec::with_capacity(segments.len() / 2);
        for (i, pair) in segments.chunks(2).enumerate() {
            let collection =
                CollectionId::try_new(pair[0]).map_err(|error| PathError::InvalidSegment {
                    index: 2 * i,
                    error,
                })?;
            let document =
                DocumentId::try_new(pair[1]).map_err(|error| PathError::InvalidSegment {
                    index: 2 * i + 1,
                    error,
                })?;
            pairs.push((collection, document));
        }
        if pairs.len() > MAX_SUBCOLLECTION_DEPTH {
            return Err(PathError::TooDeep {
                depth: pairs.len(),
                maximum: MAX_SUBCOLLECTION_DEPTH,
            });
        }
        let path = Self {
            project: project.clone(),
            database: database.clone(),
            pairs,
        };
        let bytes = path.resource_name().len();
        if bytes > MAX_DOCUMENT_NAME_BYTES {
            return Err(PathError::NameTooLong {
                bytes,
                maximum: MAX_DOCUMENT_NAME_BYTES,
            });
        }
        Ok(path)
    }

    /// Project.
    #[must_use]
    pub const fn project(&self) -> &ProjectId {
        &self.project
    }

    /// Database.
    #[must_use]
    pub const fn database(&self) -> &DatabaseId {
        &self.database
    }

    /// `(collection, document)` pairs from the root.
    #[must_use]
    pub fn pairs(&self) -> &[(CollectionId, DocumentId)] {
        &self.pairs
    }

    /// Collection ID of the innermost collection.
    #[must_use]
    pub fn collection_id(&self) -> &CollectionId {
        &self.pairs[self.pairs.len() - 1].0
    }

    /// Document ID of the document itself.
    #[must_use]
    pub fn document_id(&self) -> &DocumentId {
        &self.pairs[self.pairs.len() - 1].1
    }

    /// Parent document, if this document lives in a subcollection.
    #[must_use]
    pub fn parent_document(&self) -> Option<Self> {
        if self.pairs.len() < 2 {
            return None;
        }
        Some(Self {
            project: self.project.clone(),
            database: self.database.clone(),
            pairs: self.pairs[..self.pairs.len() - 1].to_vec(),
        })
    }

    /// The ancestor made of the first `pairs` (collection, document) pairs; the path itself
    /// when `pairs` is not smaller than its depth.
    #[must_use]
    pub fn ancestor(&self, pairs: usize) -> Option<Self> {
        (pairs > 0).then(|| Self {
            project: self.project.clone(),
            database: self.database.clone(),
            pairs: self.pairs[..pairs.min(self.pairs.len())].to_vec(),
        })
    }

    /// Exclusive upper bound of every strict descendant of this document in path order: the
    /// same path with the document ID replaced by [`DocumentId::ordered_successor`]. Paths in
    /// `(self, bound)` are exactly the strict descendants; the bound itself is never a stored
    /// path.
    #[must_use]
    pub fn descendants_upper_bound(&self) -> Self {
        let mut pairs = self.pairs.clone();
        if let Some((_, document)) = pairs.last_mut() {
            *document = document.ordered_successor();
        }
        Self {
            project: self.project.clone(),
            database: self.database.clone(),
            pairs,
        }
    }

    /// Relative path `users/jeff/tasks/my_task_id`.
    #[must_use]
    pub fn relative(&self) -> String {
        let mut parts = Vec::with_capacity(self.pairs.len() * 2);
        for (c, d) in &self.pairs {
            parts.push(c.as_str());
            parts.push(d.as_str());
        }
        parts.join("/")
    }

    /// Full resource name `projects/{p}/databases/{d}/documents/{relative}`.
    #[must_use]
    pub fn resource_name(&self) -> String {
        format!(
            "projects/{}/databases/{}/documents/{}",
            self.project.as_str(),
            self.database.as_str(),
            self.relative()
        )
    }

    /// Slash-separated segments of [`Self::resource_name`], without rendering it. Segments
    /// never contain `/` (identifier syntax), so this is exactly what splitting the rendered
    /// name on `/` yields.
    pub fn resource_name_segments(&self) -> impl Iterator<Item = &str> {
        [
            "projects",
            self.project.as_str(),
            "databases",
            self.database.as_str(),
            "documents",
        ]
        .into_iter()
        .chain(
            self.pairs
                .iter()
                .flat_map(|(c, d)| [c.as_str(), d.as_str()]),
        )
    }

    /// Orders two paths the way their resource names order as document references
    /// (segment-wise byte order), without allocating either name.
    #[must_use]
    pub fn cmp_resource_name(&self, other: &Self) -> core::cmp::Ordering {
        self.resource_name_segments()
            .cmp(other.resource_name_segments())
    }

    /// Orders this path against a reference value (`name`), without allocating this path's
    /// resource name.
    #[must_use]
    pub fn cmp_reference(&self, name: &str) -> core::cmp::Ordering {
        self.resource_name_segments().cmp(name.split('/'))
    }
}

impl fmt::Display for DocumentPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.resource_name())
    }
}
