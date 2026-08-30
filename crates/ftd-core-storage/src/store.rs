//! Versioned object store (spec 9.2–9.7): metadata separate from blobs, generation /
//! metageneration with preconditions, namespace listing, resumable upload sessions and an
//! event log for the outbox.

use core::fmt;
use std::collections::BTreeMap;

use ftd_core_types::determinism::{DeterministicRng, SplitMix64};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

use crate::hash::{base64, crc32c, md5};
use crate::name::{BucketName, ObjectName};

/// Largest object accepted (memory-backed test runtime).
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
/// Custom metadata budget (Cloud Storage: 8 KiB of keys and values).
pub const MAX_CUSTOM_METADATA_BYTES: usize = 8 * 1024;
/// Resumable upload sessions expire after a week of virtual time (Cloud Storage: 7 days).
pub const UPLOAD_SESSION_TTL_SECONDS: i64 = 7 * 24 * 3600;
/// Maximum upload sessions still receiving bytes (abandoned sessions expire).
pub const MAX_UPLOAD_SESSIONS: usize = 256;
/// Finished (committed or aborted) sessions kept for status queries; older ones are evicted.
pub const MAX_FINISHED_UPLOAD_SESSIONS: usize = 256;
/// Default listing page size.
pub const DEFAULT_LIST_PAGE_SIZE: usize = 1000;

/// Opaque blob identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobId(u64);

/// Resumable upload identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UploadId(String);

impl UploadId {
    /// Wire form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// From the wire.
    #[must_use]
    pub fn from_str_unchecked(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Settable metadata of an object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewMetadata {
    /// Content type (defaults to `application/octet-stream`).
    pub content_type: Option<String>,
    /// `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// `Content-Language`.
    pub content_language: Option<String>,
    /// `Cache-Control`.
    pub cache_control: Option<String>,
    /// Custom key/value metadata.
    pub custom: BTreeMap<String, String>,
}

/// Metadata patch: `Some(None)` clears a field, `None` keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataPatch {
    /// Content type.
    pub content_type: Option<Option<String>>,
    /// `Content-Disposition`.
    pub content_disposition: Option<Option<String>>,
    /// `Content-Encoding`.
    pub content_encoding: Option<Option<String>>,
    /// `Content-Language`.
    pub content_language: Option<Option<String>>,
    /// `Cache-Control`.
    pub cache_control: Option<Option<String>>,
    /// Custom metadata: keys mapped to `None` are removed; `Some(map)` merges.
    pub custom: Option<BTreeMap<String, Option<String>>>,
}

/// Stored object metadata (one generation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// Bucket.
    pub bucket: BucketName,
    /// Name.
    pub name: ObjectName,
    /// Data generation.
    pub generation: u64,
    /// Metadata generation.
    pub metageneration: u64,
    /// Size in bytes.
    pub size: u64,
    /// Content type.
    pub content_type: String,
    /// `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// `Content-Language`.
    pub content_language: Option<String>,
    /// `Cache-Control`.
    pub cache_control: Option<String>,
    /// Custom metadata.
    pub custom: BTreeMap<String, String>,
    /// MD5 of the data.
    pub md5: [u8; 16],
    /// CRC32C of the data.
    pub crc32c: u32,
    /// Creation time.
    pub time_created: LogicalInstant,
    /// Last update (data or metadata).
    pub updated: LogicalInstant,
    /// Firebase download tokens.
    pub download_tokens: Vec<String>,
    /// Blob.
    pub blob: BlobId,
}

impl ObjectMetadata {
    /// Base64 MD5 (`md5Hash`).
    #[must_use]
    pub fn md5_base64(&self) -> String {
        base64(&self.md5)
    }

    /// Base64 big-endian CRC32C (`crc32c`).
    #[must_use]
    pub fn crc32c_base64(&self) -> String {
        base64(&self.crc32c.to_be_bytes())
    }

    /// Opaque entity tag.
    #[must_use]
    pub fn etag(&self) -> String {
        format!("\"{}-{}\"", self.generation, self.metageneration)
    }
}

/// Write precondition.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Precondition {
    /// `ifGenerationMatch` (0 = the object must not exist).
    pub if_generation_match: Option<u64>,
    /// `ifMetagenerationMatch`.
    pub if_metageneration_match: Option<u64>,
    /// `ifGenerationNotMatch`.
    pub if_generation_not_match: Option<u64>,
    /// `ifMetagenerationNotMatch`.
    pub if_metageneration_not_match: Option<u64>,
}

impl Precondition {
    /// Evaluates the precondition against the current object (`None` = absent). Without a
    /// live object only `ifGenerationMatch = 0` can hold: every other predicate fails.
    pub fn check(self, current: Option<&ObjectMetadata>) -> Result<(), StorageError> {
        let failed = |m: String| Err(StorageError::PreconditionFailed(m));
        let Some(m) = current else {
            return match self {
                Precondition {
                    if_generation_match: Some(0) | None,
                    if_metageneration_match: None,
                    if_generation_not_match: None,
                    if_metageneration_not_match: None,
                } => Ok(()),
                _ => failed("the object does not exist".to_owned()),
            };
        };
        if let Some(expected) = self.if_generation_match {
            if m.generation != expected {
                return failed(format!(
                    "ifGenerationMatch {expected} but the current generation is {}",
                    m.generation
                ));
            }
        }
        if let Some(expected) = self.if_metageneration_match {
            if m.metageneration != expected {
                return failed(format!(
                    "ifMetagenerationMatch {expected} but the current metageneration is {}",
                    m.metageneration
                ));
            }
        }
        if let Some(unexpected) = self.if_generation_not_match {
            if m.generation == unexpected {
                return Err(StorageError::NotModified(format!(
                    "ifGenerationNotMatch {unexpected} names the current generation"
                )));
            }
        }
        if let Some(unexpected) = self.if_metageneration_not_match {
            if m.metageneration == unexpected {
                return Err(StorageError::NotModified(format!(
                    "ifMetagenerationNotMatch {unexpected} names the current metageneration"
                )));
            }
        }
        Ok(())
    }
}

/// Errors (the adapters map them to HTTP codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// No such object.
    NotFound,
    /// Precondition failed.
    PreconditionFailed(String),
    /// Object too large.
    TooLarge,
    /// Custom metadata too large.
    MetadataTooLarge,
    /// Unknown or expired upload session.
    UploadNotFound,
    /// Chunk offset does not match the bytes received so far.
    UploadOffset {
        /// Expected offset.
        expected: u64,
    },
    /// Upload already finalized.
    UploadFinalized,
    /// Upload size differs from the declared total.
    UploadSizeMismatch,
    /// Too many open upload sessions.
    TooManyUploads,
    /// The received bytes do not match the checksum the client declared.
    ChecksumMismatch(String),
    /// A not-match precondition named the current generation / metageneration (reads answer
    /// `304 Not Modified`, writes `412`).
    NotModified(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("object not found"),
            Self::PreconditionFailed(m) => write!(f, "precondition failed: {m}"),
            Self::TooLarge => f.write_str("object too large"),
            Self::MetadataTooLarge => f.write_str("custom metadata too large"),
            Self::UploadNotFound => f.write_str("upload session not found or expired"),
            Self::UploadOffset { expected } => {
                write!(f, "upload offset mismatch, expected {expected}")
            }
            Self::UploadFinalized => f.write_str("upload already finalized"),
            Self::UploadSizeMismatch => f.write_str("upload size differs from the declared total"),
            Self::TooManyUploads => f.write_str("too many open upload sessions"),
            Self::ChecksumMismatch(m) => write!(f, "checksum mismatch: {m}"),
            Self::NotModified(m) => write!(f, "not modified: {m}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Storage events (spec 9.7), appended for the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageEvent {
    /// A new generation was committed.
    Finalized(ObjectMetadata),
    /// A generation was deleted.
    Deleted(ObjectMetadata),
    /// Metadata changed (new metageneration).
    MetadataUpdated(ObjectMetadata),
}

/// Upload state (spec 9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
enum UploadState {
    Receiving,
    Committed(Box<ObjectMetadata>),
    Aborted,
}

#[derive(Debug, Clone)]
struct UploadSession {
    bucket: BucketName,
    name: ObjectName,
    metadata: NewMetadata,
    precondition: Precondition,
    total: Option<u64>,
    /// Credentials the session was started with (the protocol layer re-derives the caller
    /// from them at finalization).
    authorization: Option<String>,
    expected_md5: Option<[u8; 16]>,
    expected_crc32c: Option<u32>,
    received: Vec<u8>,
    state: UploadState,
    started_at: LogicalInstant,
}

/// Options of a resumable upload session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadOptions {
    /// Declared total size, if any.
    pub total: Option<u64>,
    /// Credentials the session is started with (opaque to the store).
    pub authorization: Option<String>,
    /// MD5 the client declared for the whole object.
    pub expected_md5: Option<[u8; 16]>,
    /// CRC32C the client declared for the whole object.
    pub expected_crc32c: Option<u32>,
}

/// The bytes and metadata an upload would commit (authorization before finalization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpload<'a> {
    /// Destination bucket.
    pub bucket: &'a BucketName,
    /// Destination name.
    pub name: &'a ObjectName,
    /// Declared metadata.
    pub metadata: &'a NewMetadata,
    /// Bytes received so far.
    pub bytes: &'a [u8],
    /// Declared total, if any.
    pub total: Option<u64>,
    /// Credentials the session was started with.
    pub authorization: Option<&'a str>,
}

/// Progress of a resumable upload after a chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadProgress {
    /// Bytes received so far.
    pub received: u64,
    /// The committed object once finalized.
    pub committed: Option<ObjectMetadata>,
}

/// One listing page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Objects (name order, bytewise).
    pub items: Vec<ObjectMetadata>,
    /// Common prefixes (when a delimiter was given).
    pub prefixes: Vec<String>,
    /// Token for the next page.
    pub next_page_token: Option<String>,
}

/// All buckets of one session.
#[derive(Debug, Clone)]
pub struct StorageState {
    objects: BTreeMap<(BucketName, ObjectName), ObjectMetadata>,
    blobs: BTreeMap<BlobId, Vec<u8>>,
    uploads: BTreeMap<UploadId, UploadSession>,
    next_blob: u64,
    next_generation: u64,
    next_upload: u64,
    rng: SplitMix64,
    events: Vec<StorageEvent>,
}

fn custom_metadata_size(custom: &BTreeMap<String, String>) -> usize {
    custom.iter().map(|(k, v)| k.len() + v.len()).sum()
}

impl StorageState {
    /// Empty store with a deterministic token generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            objects: BTreeMap::new(),
            blobs: BTreeMap::new(),
            uploads: BTreeMap::new(),
            next_blob: 0,
            next_generation: 0,
            next_upload: 0,
            rng: SplitMix64::new(seed),
            events: Vec::new(),
        }
    }

    /// Drops every object, blob and upload (session reset).
    pub fn clear(&mut self) {
        self.objects.clear();
        self.blobs.clear();
        self.uploads.clear();
        self.events.clear();
    }

    /// Drops every object, blob and upload of one bucket (a project's session reset);
    /// returns how many objects went.
    pub fn remove_bucket(&mut self, bucket: &BucketName) -> usize {
        let gone: Vec<(BucketName, ObjectName)> = self
            .objects
            .keys()
            .filter(|(b, _)| b == bucket)
            .cloned()
            .collect();
        for key in &gone {
            if let Some(m) = self.objects.remove(key) {
                self.blobs.remove(&m.blob);
            }
        }
        self.uploads.retain(|_, u| u.bucket != *bucket);
        gone.len()
    }

    /// Takes the events recorded since the last call.
    pub fn drain_events(&mut self) -> Vec<StorageEvent> {
        std::mem::take(&mut self.events)
    }

    fn token(&mut self) -> String {
        format!("{:016x}{:016x}", self.rng.next_u64(), self.rng.next_u64())
    }

    /// Object metadata.
    #[must_use]
    pub fn get(&self, bucket: &BucketName, name: &ObjectName) -> Option<&ObjectMetadata> {
        self.objects.get(&(bucket.clone(), name.clone()))
    }

    /// Object bytes.
    #[must_use]
    pub fn bytes(&self, meta: &ObjectMetadata) -> &[u8] {
        self.blobs.get(&meta.blob).map_or(&[], Vec::as_slice)
    }

    fn check(current: Option<&ObjectMetadata>, pre: Precondition) -> Result<(), StorageError> {
        pre.check(current)
    }

    /// Writes a new generation of `name` with `bytes` (data replacement bumps the
    /// generation and resets the metageneration).
    pub fn put(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        bytes: Vec<u8>,
        metadata: NewMetadata,
        pre: Precondition,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        if bytes.len() as u64 > MAX_OBJECT_BYTES {
            return Err(StorageError::TooLarge);
        }
        if custom_metadata_size(&metadata.custom) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
        }
        let key = (bucket.clone(), name.clone());
        Self::check(self.objects.get(&key), pre)?;
        self.next_blob += 1;
        let blob = BlobId(self.next_blob);
        self.next_generation += 1;
        let previous_tokens = self
            .objects
            .get(&key)
            .map(|m| m.download_tokens.clone())
            .unwrap_or_default();
        let download_tokens = if previous_tokens.is_empty() {
            vec![self.token()]
        } else {
            previous_tokens
        };
        let meta = ObjectMetadata {
            bucket: bucket.clone(),
            name: name.clone(),
            generation: self.next_generation,
            metageneration: 1,
            size: bytes.len() as u64,
            content_type: metadata
                .content_type
                .unwrap_or_else(|| "application/octet-stream".to_owned()),
            content_disposition: metadata.content_disposition,
            content_encoding: metadata.content_encoding,
            content_language: metadata.content_language,
            cache_control: metadata.cache_control,
            custom: metadata.custom,
            md5: md5(&bytes),
            crc32c: crc32c(&bytes),
            time_created: now,
            updated: now,
            download_tokens,
            blob,
        };
        if let Some(old) = self.objects.insert(key, meta.clone()) {
            self.blobs.remove(&old.blob);
        }
        self.blobs.insert(blob, bytes);
        self.events.push(StorageEvent::Finalized(meta.clone()));
        Ok(meta)
    }

    /// Updates metadata (bumps the metageneration; the data and generation stay).
    pub fn update_metadata(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        patch: &MetadataPatch,
        pre: Precondition,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let key = (bucket.clone(), name.clone());
        Self::check(self.objects.get(&key), pre)?;
        let meta = self.objects.get_mut(&key).ok_or(StorageError::NotFound)?;
        let mut next = patch.apply(meta);
        if custom_metadata_size(&next.custom) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
        }
        next.metageneration += 1;
        next.updated = now;
        *meta = next.clone();
        self.events
            .push(StorageEvent::MetadataUpdated(next.clone()));
        Ok(next)
    }

    /// Adds a Firebase download token.
    pub fn add_download_token(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
    ) -> Result<String, StorageError> {
        let token = self.token();
        let meta = self
            .objects
            .get_mut(&(bucket.clone(), name.clone()))
            .ok_or(StorageError::NotFound)?;
        meta.download_tokens.push(token.clone());
        Ok(token)
    }

    /// Removes a Firebase download token.
    pub fn remove_download_token(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        token: &str,
    ) -> Result<(), StorageError> {
        let meta = self
            .objects
            .get_mut(&(bucket.clone(), name.clone()))
            .ok_or(StorageError::NotFound)?;
        meta.download_tokens.retain(|t| t != token);
        Ok(())
    }

    /// Deletes the current generation.
    pub fn delete(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        pre: Precondition,
    ) -> Result<ObjectMetadata, StorageError> {
        let key = (bucket.clone(), name.clone());
        Self::check(self.objects.get(&key), pre)?;
        let meta = self.objects.remove(&key).ok_or(StorageError::NotFound)?;
        self.blobs.remove(&meta.blob);
        self.events.push(StorageEvent::Deleted(meta.clone()));
        Ok(meta)
    }

    /// Copies (rewrites) an object: the destination gets a new generation, metadata is
    /// copied unless overridden.
    pub fn copy(
        &mut self,
        source: (&BucketName, &ObjectName),
        destination: (&BucketName, &ObjectName),
        metadata: Option<NewMetadata>,
        pre: Precondition,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let (dst_bucket, dst_name) = destination;
        let src = self
            .get(source.0, source.1)
            .cloned()
            .ok_or(StorageError::NotFound)?;
        let bytes = self.bytes(&src).to_vec();
        let metadata = metadata.unwrap_or(NewMetadata {
            content_type: Some(src.content_type.clone()),
            content_disposition: src.content_disposition.clone(),
            content_encoding: src.content_encoding.clone(),
            content_language: src.content_language.clone(),
            cache_control: src.cache_control.clone(),
            custom: src.custom.clone(),
        });
        self.put(dst_bucket, dst_name, bytes, metadata, pre, now)
    }

    /// Lists objects of `bucket` under `prefix`, bytewise by name. With a `delimiter`, names
    /// containing it after the prefix are folded into `prefixes`. Page tokens are the last
    /// name of the previous page.
    #[must_use]
    pub fn list(
        &self,
        bucket: &BucketName,
        prefix: &str,
        delimiter: Option<&str>,
        page_token: Option<&str>,
        max_results: usize,
    ) -> ListPage {
        let max_results = if max_results == 0 {
            DEFAULT_LIST_PAGE_SIZE
        } else {
            max_results
        };
        let mut items = Vec::new();
        let mut prefixes: Vec<String> = Vec::new();
        let mut next_page_token = None;
        let mut entries = 0usize;
        // The token is the last raw object name consumed by the page (an object folded into
        // an already emitted prefix counts as consumed), so the next page resumes after it.
        let mut last_consumed: Option<&str> = None;
        for ((b, name), meta) in &self.objects {
            if b != bucket || !name.as_str().starts_with(prefix) {
                continue;
            }
            if page_token.is_some_and(|t| name.as_str() <= t) {
                continue;
            }
            let rest = &name.as_str()[prefix.len()..];
            let folded = delimiter
                .filter(|d| !d.is_empty())
                .and_then(|d| rest.find(d).map(|i| format!("{prefix}{}{d}", &rest[..i])));
            if let Some(p) = &folded {
                if prefixes.last() == Some(p) {
                    last_consumed = Some(name.as_str());
                    continue;
                }
            }
            if entries >= max_results {
                next_page_token = last_consumed.map(str::to_owned);
                break;
            }
            if let Some(p) = folded {
                prefixes.push(p);
            } else {
                items.push(meta.clone());
            }
            entries += 1;
            last_consumed = Some(name.as_str());
        }
        ListPage {
            items,
            prefixes,
            next_page_token,
        }
    }

    /// Objects of a bucket (name order).
    #[must_use]
    pub fn objects(&self, bucket: &BucketName) -> Vec<&ObjectMetadata> {
        self.objects
            .iter()
            .filter(|((b, _), _)| b == bucket)
            .map(|(_, m)| m)
            .collect()
    }

    /// Starts a resumable upload.
    pub fn begin_upload(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        metadata: NewMetadata,
        precondition: Precondition,
        total: Option<u64>,
        now: LogicalInstant,
    ) -> Result<UploadId, StorageError> {
        self.begin_upload_with(
            bucket,
            name,
            metadata,
            precondition,
            UploadOptions {
                total,
                ..UploadOptions::default()
            },
            now,
        )
    }

    /// Starts a resumable upload with credentials and declared checksums.
    pub fn begin_upload_with(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        metadata: NewMetadata,
        precondition: Precondition,
        options: UploadOptions,
        now: LogicalInstant,
    ) -> Result<UploadId, StorageError> {
        if options.total.is_some_and(|t| t > MAX_OBJECT_BYTES) {
            return Err(StorageError::TooLarge);
        }
        if custom_metadata_size(&metadata.custom) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
        }
        self.sweep_uploads(now);
        let receiving = self
            .uploads
            .values()
            .filter(|u| u.state == UploadState::Receiving)
            .count();
        if receiving >= MAX_UPLOAD_SESSIONS {
            return Err(StorageError::TooManyUploads);
        }
        self.next_upload += 1;
        let sequence = self.next_upload;
        let token = self.token();
        let id = UploadId(format!("upload-{sequence:08}-{token}"));
        self.uploads.insert(
            id.clone(),
            UploadSession {
                bucket: bucket.clone(),
                name: name.clone(),
                metadata,
                precondition,
                total: options.total,
                authorization: options.authorization,
                expected_md5: options.expected_md5,
                expected_crc32c: options.expected_crc32c,
                received: Vec::new(),
                state: UploadState::Receiving,
                started_at: now,
            },
        );
        Ok(id)
    }

    /// Declares (or confirms) the checksums the whole object must have; they are verified
    /// when the upload finalizes.
    pub fn set_upload_hashes(
        &mut self,
        id: &UploadId,
        md5: Option<[u8; 16]>,
        crc32c: Option<u32>,
        now: LogicalInstant,
    ) -> Result<(), StorageError> {
        let u = self.upload_mut(id, now)?;
        if md5.is_some() {
            u.expected_md5 = md5;
        }
        if crc32c.is_some() {
            u.expected_crc32c = crc32c;
        }
        Ok(())
    }

    fn expired(u: &UploadSession, now: LogicalInstant) -> bool {
        now.checked_duration_since(u.started_at)
            .is_none_or(|d| d > LogicalDuration::from_seconds(UPLOAD_SESSION_TTL_SECONDS))
    }

    /// Drops expired sessions; finished sessions beyond the tombstone cap are evicted oldest
    /// first (ids are sequence-ordered).
    fn sweep_uploads(&mut self, now: LogicalInstant) {
        self.uploads.retain(|_, u| !Self::expired(u, now));
        let mut finished = self
            .uploads
            .values()
            .filter(|u| u.state != UploadState::Receiving)
            .count();
        if finished > MAX_FINISHED_UPLOAD_SESSIONS {
            self.uploads.retain(|_, u| {
                if u.state != UploadState::Receiving && finished > MAX_FINISHED_UPLOAD_SESSIONS {
                    finished -= 1;
                    false
                } else {
                    true
                }
            });
        }
    }

    fn upload_mut(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<&mut UploadSession, StorageError> {
        if self.uploads.get(id).is_some_and(|u| Self::expired(u, now)) {
            self.uploads.remove(id);
        }
        self.uploads.get_mut(id).ok_or(StorageError::UploadNotFound)
    }

    /// Bytes received so far and the committed object once finalized (the exact generation
    /// the upload produced, even if the object changed since).
    pub fn upload_status(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<(u64, Option<ObjectMetadata>), StorageError> {
        let u = self.upload_mut(id, now)?;
        Ok(match &u.state {
            UploadState::Committed(m) => (m.size, Some((**m).clone())),
            UploadState::Receiving | UploadState::Aborted => (u.received.len() as u64, None),
        })
    }

    /// Declares (or confirms) the total size of an upload; a different total than the one
    /// already declared is a size mismatch.
    pub fn set_upload_total(
        &mut self,
        id: &UploadId,
        total: u64,
        now: LogicalInstant,
    ) -> Result<(), StorageError> {
        if total > MAX_OBJECT_BYTES {
            return Err(StorageError::TooLarge);
        }
        let u = self.upload_mut(id, now)?;
        match u.total {
            Some(t) if t != total => Err(StorageError::UploadSizeMismatch),
            _ => {
                u.total = Some(total);
                Ok(())
            }
        }
    }

    /// Appends a chunk at `offset` (must equal the bytes received so far; a repeated chunk
    /// is ignored) and returns the bytes received.
    pub fn append_upload(
        &mut self,
        id: &UploadId,
        offset: u64,
        chunk: &[u8],
        now: LogicalInstant,
    ) -> Result<u64, StorageError> {
        let u = self.upload_mut(id, now)?;
        match u.state {
            UploadState::Committed(_) | UploadState::Aborted => {
                return Err(StorageError::UploadFinalized)
            }
            UploadState::Receiving => {}
        }
        let received = u.received.len() as u64;
        let end = offset
            .checked_add(chunk.len() as u64)
            .ok_or(StorageError::TooLarge)?;
        if end <= received {
            // Retried chunk: already received, nothing to append.
        } else if offset > received {
            return Err(StorageError::UploadOffset { expected: received });
        } else {
            let skip = usize::try_from(received - offset).unwrap_or(0);
            if end > MAX_OBJECT_BYTES || u.total.is_some_and(|t| end > t) {
                u.state = UploadState::Aborted;
                u.received = Vec::new();
                return Err(if u.total.is_some_and(|t| end > t) {
                    StorageError::UploadSizeMismatch
                } else {
                    StorageError::TooLarge
                });
            }
            u.received.extend_from_slice(&chunk[skip..]);
        }
        Ok(u.received.len() as u64)
    }

    /// What an upload would commit right now (for authorization before finalization).
    pub fn pending_upload(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<PendingUpload<'_>, StorageError> {
        let u = self.upload_mut(id, now)?;
        match u.state {
            UploadState::Committed(_) | UploadState::Aborted => Err(StorageError::UploadFinalized),
            UploadState::Receiving => Ok(PendingUpload {
                bucket: &u.bucket,
                name: &u.name,
                metadata: &u.metadata,
                bytes: &u.received,
                total: u.total,
                authorization: u.authorization.as_deref(),
            }),
        }
    }

    /// Commits the received bytes as a new generation.
    pub fn finalize_upload(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let (bucket, name, metadata, precondition, bytes) = {
            let u = self.upload_mut(id, now)?;
            match u.state {
                UploadState::Committed(_) | UploadState::Aborted => {
                    return Err(StorageError::UploadFinalized)
                }
                UploadState::Receiving => {}
            }
            if u.total.is_some_and(|t| t != u.received.len() as u64) {
                u.state = UploadState::Aborted;
                u.received = Vec::new();
                return Err(StorageError::UploadSizeMismatch);
            }
            // A checksum failure is terminal: the client has to start a new session.
            let mismatch = match (u.expected_md5, u.expected_crc32c) {
                (Some(expected), _) if md5(&u.received) != expected => Some(format!(
                    "md5 {} declared, {} received",
                    base64(&expected),
                    base64(&md5(&u.received))
                )),
                (_, Some(expected)) if crc32c(&u.received) != expected => Some(format!(
                    "crc32c {} declared, {} received",
                    base64(&expected.to_be_bytes()),
                    base64(&crc32c(&u.received).to_be_bytes())
                )),
                _ => None,
            };
            if let Some(m) = mismatch {
                u.state = UploadState::Aborted;
                u.received = Vec::new();
                return Err(StorageError::ChecksumMismatch(m));
            }
            (
                u.bucket.clone(),
                u.name.clone(),
                u.metadata.clone(),
                u.precondition,
                std::mem::take(&mut u.received),
            )
        };
        let meta = match self.put(&bucket, &name, bytes, metadata, precondition, now) {
            Ok(m) => m,
            Err(e) => {
                if let Some(u) = self.uploads.get_mut(id) {
                    u.state = UploadState::Aborted;
                    u.received = Vec::new();
                }
                return Err(e);
            }
        };
        if let Some(u) = self.uploads.get_mut(id) {
            u.state = UploadState::Committed(Box::new(meta.clone()));
        }
        Ok(meta)
    }

    /// [`Self::append_upload`] followed by [`Self::finalize_upload`] when `finalize` is set.
    pub fn upload_chunk(
        &mut self,
        id: &UploadId,
        offset: u64,
        chunk: &[u8],
        finalize: bool,
        now: LogicalInstant,
    ) -> Result<UploadProgress, StorageError> {
        let received = self.append_upload(id, offset, chunk, now)?;
        if !finalize {
            return Ok(UploadProgress {
                received,
                committed: None,
            });
        }
        let meta = self.finalize_upload(id, now)?;
        Ok(UploadProgress {
            received: meta.size,
            committed: Some(meta),
        })
    }

    /// Cancels an upload.
    pub fn cancel_upload(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<(), StorageError> {
        let u = self.upload_mut(id, now)?;
        u.state = UploadState::Aborted;
        u.received = Vec::new();
        Ok(())
    }
}

impl MetadataPatch {
    /// The object after this patch (metageneration and update time untouched).
    #[must_use]
    pub fn apply(&self, base: &ObjectMetadata) -> ObjectMetadata {
        let mut next = base.clone();
        if let Some(ct) = &self.content_type {
            next.content_type = ct
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_owned());
        }
        if let Some(v) = &self.content_disposition {
            next.content_disposition.clone_from(v);
        }
        if let Some(v) = &self.content_encoding {
            next.content_encoding.clone_from(v);
        }
        if let Some(v) = &self.content_language {
            next.content_language.clone_from(v);
        }
        if let Some(v) = &self.cache_control {
            next.cache_control.clone_from(v);
        }
        if let Some(custom) = &self.custom {
            for (k, v) in custom {
                match v {
                    Some(v) => {
                        next.custom.insert(k.clone(), v.clone());
                    }
                    None => {
                        next.custom.remove(k);
                    }
                }
            }
        }
        next
    }
}
