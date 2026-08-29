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
    Committed(u64),
    Aborted,
}

#[derive(Debug, Clone)]
struct UploadSession {
    bucket: BucketName,
    name: ObjectName,
    metadata: NewMetadata,
    precondition: Precondition,
    total: Option<u64>,
    received: Vec<u8>,
    state: UploadState,
    started_at: LogicalInstant,
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
        if let Some(expected) = pre.if_generation_match {
            let actual = current.map_or(0, |m| m.generation);
            if actual != expected {
                return Err(StorageError::PreconditionFailed(format!(
                    "ifGenerationMatch {expected} but the current generation is {actual}"
                )));
            }
        }
        if let Some(expected) = pre.if_metageneration_match {
            let actual = current.map_or(0, |m| m.metageneration);
            if actual != expected {
                return Err(StorageError::PreconditionFailed(format!(
                    "ifMetagenerationMatch {expected} but the current metageneration is {actual}"
                )));
            }
        }
        Ok(())
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
        patch: MetadataPatch,
        pre: Precondition,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let key = (bucket.clone(), name.clone());
        Self::check(self.objects.get(&key), pre)?;
        let meta = self.objects.get_mut(&key).ok_or(StorageError::NotFound)?;
        let mut next = meta.clone();
        if let Some(ct) = patch.content_type {
            next.content_type = ct.unwrap_or_else(|| "application/octet-stream".to_owned());
        }
        if let Some(v) = patch.content_disposition {
            next.content_disposition = v;
        }
        if let Some(v) = patch.content_encoding {
            next.content_encoding = v;
        }
        if let Some(v) = patch.content_language {
            next.content_language = v;
        }
        if let Some(v) = patch.cache_control {
            next.cache_control = v;
        }
        if let Some(custom) = patch.custom {
            for (k, v) in custom {
                match v {
                    Some(v) => {
                        next.custom.insert(k, v);
                    }
                    None => {
                        next.custom.remove(&k);
                    }
                }
            }
        }
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
        let mut last_emitted_prefix: Option<String> = None;
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
            if entries >= max_results {
                next_page_token = Some(name.as_str().to_owned());
                break;
            }
            if let Some(p) = folded {
                if last_emitted_prefix.as_deref() == Some(p.as_str()) {
                    continue;
                }
                last_emitted_prefix = Some(p.clone());
                prefixes.push(p);
            } else {
                items.push(meta.clone());
            }
            entries += 1;
        }
        // The token must point at the last entry actually returned.
        if next_page_token.is_some() {
            let last_item = items.last().map(|m| m.name.as_str().to_owned());
            let last_prefix = prefixes.last().cloned();
            next_page_token = match (last_item, last_prefix) {
                (Some(i), Some(p)) => Some(if i > p { i } else { p }),
                (Some(i), None) => Some(i),
                (None, Some(p)) => Some(p),
                (None, None) => None,
            };
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
        if total.is_some_and(|t| t > MAX_OBJECT_BYTES) {
            return Err(StorageError::TooLarge);
        }
        if custom_metadata_size(&metadata.custom) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
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
                total,
                received: Vec::new(),
                state: UploadState::Receiving,
                started_at: now,
            },
        );
        Ok(id)
    }

    fn upload_mut(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<&mut UploadSession, StorageError> {
        let expired = self.uploads.get(id).is_some_and(|u| {
            now.checked_duration_since(u.started_at)
                .is_none_or(|d| d > LogicalDuration::from_seconds(UPLOAD_SESSION_TTL_SECONDS))
        });
        if expired {
            self.uploads.remove(id);
        }
        self.uploads.get_mut(id).ok_or(StorageError::UploadNotFound)
    }

    /// Bytes received so far and whether the upload is finished.
    pub fn upload_status(
        &self,
        id: &UploadId,
    ) -> Result<(u64, Option<ObjectMetadata>), StorageError> {
        let u = self.uploads.get(id).ok_or(StorageError::UploadNotFound)?;
        let committed = match u.state {
            UploadState::Committed(_) => self.get(&u.bucket, &u.name).cloned(),
            _ => None,
        };
        Ok((u.received.len() as u64, committed))
    }

    /// Appends a chunk at `offset` (must equal the bytes received so far; a repeated chunk
    /// is ignored) and commits the object when `finalize` is set.
    pub fn upload_chunk(
        &mut self,
        id: &UploadId,
        offset: u64,
        chunk: &[u8],
        finalize: bool,
        now: LogicalInstant,
    ) -> Result<UploadProgress, StorageError> {
        let (bucket, name, metadata, precondition, bytes) = {
            let u = self.upload_mut(id, now)?;
            match u.state {
                UploadState::Committed(_) | UploadState::Aborted => {
                    return Err(StorageError::UploadFinalized)
                }
                UploadState::Receiving => {}
            }
            let received = u.received.len() as u64;
            if offset + chunk.len() as u64 <= received {
                // Retried chunk: already received, nothing to append.
            } else if offset > received {
                return Err(StorageError::UploadOffset { expected: received });
            } else {
                let skip = usize::try_from(received - offset).unwrap_or(0);
                u.received.extend_from_slice(&chunk[skip..]);
                if u.received.len() as u64 > MAX_OBJECT_BYTES {
                    u.state = UploadState::Aborted;
                    return Err(StorageError::TooLarge);
                }
            }
            if !finalize {
                return Ok(UploadProgress {
                    received: u.received.len() as u64,
                    committed: None,
                });
            }
            if u.total.is_some_and(|t| t != u.received.len() as u64) {
                u.state = UploadState::Aborted;
                return Err(StorageError::UploadSizeMismatch);
            }
            (
                u.bucket.clone(),
                u.name.clone(),
                u.metadata.clone(),
                u.precondition,
                std::mem::take(&mut u.received),
            )
        };
        let size = bytes.len() as u64;
        let meta = match self.put(&bucket, &name, bytes, metadata, precondition, now) {
            Ok(m) => m,
            Err(e) => {
                if let Some(u) = self.uploads.get_mut(id) {
                    u.state = UploadState::Aborted;
                }
                return Err(e);
            }
        };
        if let Some(u) = self.uploads.get_mut(id) {
            u.state = UploadState::Committed(meta.generation);
        }
        Ok(UploadProgress {
            received: size,
            committed: Some(meta),
        })
    }

    /// Cancels an upload.
    pub fn cancel_upload(&mut self, id: &UploadId) -> Result<(), StorageError> {
        let u = self
            .uploads
            .get_mut(id)
            .ok_or(StorageError::UploadNotFound)?;
        u.state = UploadState::Aborted;
        u.received.clear();
        Ok(())
    }
}
