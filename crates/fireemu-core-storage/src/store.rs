//! Versioned object store (spec 9.2–9.7): metadata separate from blobs, generation /
//! metageneration with preconditions, namespace listing, resumable upload sessions and an
//! event log for the outbox.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::hash::{base64, crc32c, md5, Crc32c, Md5};
use crate::name::{BucketName, ObjectName};

/// Largest object accepted (memory-backed test runtime).
pub const MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;
/// Custom metadata budget (Cloud Storage: 8 KiB of keys and values).
pub const MAX_CUSTOM_METADATA_BYTES: usize = 8 * 1024;

/// The most download tokens one object may carry. Production keeps a small handful; the cap
/// is a fireemu-only safety bound (the official emulator has none), so an unauthenticated
/// `PATCH` cannot grow an object's token list without limit.
pub const MAX_DOWNLOAD_TOKENS: usize = 32;

/// The longest a single download token may be. fireemu mints 36-character UUIDs; the cap
/// leaves room for the client-supplied tokens the Firebase dialect honours while refusing an
/// oversized one.
pub const MAX_DOWNLOAD_TOKEN_LEN: usize = 128;
/// Resumable upload sessions expire after a week of virtual time (Cloud Storage: 7 days).
pub const UPLOAD_SESSION_TTL_SECONDS: i64 = 7 * 24 * 3600;
/// Maximum upload sessions still receiving bytes (abandoned sessions expire).
pub const MAX_UPLOAD_SESSIONS: usize = 256;
/// Finished (committed or aborted) sessions kept for status queries; older ones are evicted.
pub const MAX_FINISHED_UPLOAD_SESSIONS: usize = 256;
/// Default listing page size.
pub const DEFAULT_LIST_PAGE_SIZE: usize = 1000;
/// Largest generation identity that official import/export artifacts preserve losslessly.
pub const MAX_PERSISTED_IDENTITY: u64 = i64::MAX as u64;

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
    /// Custom key/value metadata. `None` and `Some` of an empty map differ the way they
    /// differ upstream: the Firebase dialect's metadata JSON carries a `metadata` key only
    /// when custom metadata was ever defined, even when it is empty.
    pub custom: Option<BTreeMap<String, String>>,
}

/// What a patch does to custom metadata, mirroring the official emulator's `update()`:
/// `metadata: null` clears everything, an object merges per key (a `null` value removes
/// that key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomMetadataPatch {
    /// `metadata: null`: every custom key goes and the map becomes undefined.
    Clear,
    /// Merge: keys mapped to `None` are removed, others inserted.
    Merge(BTreeMap<String, Option<String>>),
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
    /// Custom metadata change; `None` keeps what is stored.
    pub custom: Option<CustomMetadataPatch>,
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
    /// Whether custom metadata is defined at all: an empty-but-defined map and no map
    /// serialize differently on the Firebase dialect, exactly as upstream keeps
    /// `customMetadata` as `{}` or `undefined`.
    pub custom_defined: bool,
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

/// MD5 and CRC32C computed together for one immutable byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectDigests {
    md5: [u8; 16],
    crc32c: u32,
}

/// Owned object bytes bound to the digests computed from those exact bytes.
///
/// Protocol adapters prepare an upload before exposing its metadata to Security Rules, then
/// consume the same value at commit. The private fields prevent bytes and digests from being
/// accidentally paired across requests.
#[derive(PartialEq, Eq)]
pub struct PreparedObject {
    bytes: Vec<u8>,
    digests: ObjectDigests,
}

impl fmt::Debug for PreparedObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedObject")
            .field("len", &self.bytes.len())
            .field("digests", &self.digests)
            .finish()
    }
}

impl PreparedObject {
    /// Computes the digests and binds them to `bytes`.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let digests = ObjectDigests::new(&bytes);
        Self { bytes, digests }
    }

    /// Byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the object has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Digests bound to the bytes.
    #[must_use]
    pub const fn digests(&self) -> ObjectDigests {
        self.digests
    }
}

impl ObjectDigests {
    /// Computes both Storage object digests.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            md5: md5(bytes),
            crc32c: crc32c(bytes),
        }
    }

    /// MD5 digest.
    #[must_use]
    pub const fn md5(self) -> [u8; 16] {
        self.md5
    }

    /// CRC32C digest.
    #[must_use]
    pub const fn crc32c(self) -> u32 {
        self.crc32c
    }

    /// Both digests in the order used by Storage Rules metadata.
    #[must_use]
    pub const fn values(self) -> ([u8; 16], u32) {
        (self.md5, self.crc32c)
    }
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

/// An object an import artifact recorded, with everything it has to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedObject {
    /// The bucket the object goes into.
    pub bucket: BucketName,
    /// The object name.
    pub name: ObjectName,
    /// The data generation the artifact recorded.
    pub generation: u64,
    /// The metadata generation the artifact recorded.
    pub metageneration: u64,
    /// The content type.
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
    /// Whether the artifact's metadata JSON carried a `customMetadata` member at all (the
    /// official emulator serializes an empty-but-defined map and no map differently).
    pub custom_defined: bool,
    /// The creation time the artifact recorded.
    pub time_created: LogicalInstant,
    /// The update time the artifact recorded.
    pub updated: LogicalInstant,
    /// The Firebase download tokens the artifact recorded; an existing download URL keeps
    /// working only when they come back unchanged.
    pub download_tokens: Vec<String>,
    /// The MD5 the artifact recorded, checked against the bytes when present.
    pub md5: Option<[u8; 16]>,
    /// The CRC-32C the artifact recorded, checked against the bytes when present.
    pub crc32c: Option<u32>,
    /// The size the artifact recorded, checked against the bytes when present.
    pub size: Option<u64>,
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
    /// An imported live object used a reserved generation identity.
    InvalidImportedIdentity(String),
    /// No further losslessly persisted generation identity can be allocated.
    IdentityExhausted,
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
            Self::InvalidImportedIdentity(m) => write!(f, "invalid imported identity: {m}"),
            Self::IdentityExhausted => f.write_str("storage identity space exhausted"),
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
    /// Finalization ran and Security Rules refused it: terminal like `Committed`. Only the
    /// received byte count is kept observable; the bytes themselves are dropped, so a
    /// refused near-limit upload does not sit in memory until its TTL (S-2).
    Denied(u64),
}

/// What a status query observes about a resumable upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadPhase {
    /// Still receiving bytes.
    Active(u64),
    /// Committed; the exact generation the upload produced.
    Finalized(Box<ObjectMetadata>),
    /// Cancelled (or aborted by a failed size or checksum check).
    Cancelled(u64),
    /// Finalized and refused by Security Rules; no object was published.
    Denied(u64),
}

/// The app a resumable upload session was admitted for.
///
/// The store never verifies anything: the protocol layer decides admission and hands over the
/// app identity plus the opaque session-binding value it was admitted under, and asks this type
/// whether a later request belongs to the same session. The binding value is opaque here on
/// purpose — it is an unpredictable credential-shaped value elsewhere, so `Debug` redacts it and
/// the store neither parses nor logs it.
#[derive(Clone, PartialEq, Eq)]
pub struct UploadAdmission {
    app_id: String,
    binding: String,
}

impl UploadAdmission {
    /// The app the initiation was admitted for, and the binding value of that admission.
    #[must_use]
    pub fn new(app_id: impl Into<String>, binding: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            binding: binding.into(),
        }
    }

    /// The admitted app identifier.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.app_id
    }
}

impl fmt::Debug for UploadAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadAdmission")
            .field("app_id", &self.app_id)
            .field("binding", &"[redacted]")
            .finish()
    }
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
    /// The app the session was admitted for, when the initiation captured an enforced App
    /// Check policy. Continuations and the finalization must match it.
    admission: Option<UploadAdmission>,
    expected_md5: Option<[u8; 16]>,
    expected_crc32c: Option<u32>,
    md5: Md5,
    crc32c: Crc32c,
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
    /// The app the initiation was admitted for, when its captured policy enforces App Check.
    pub admission: Option<UploadAdmission>,
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
    /// Digests of the accepted bytes, finalized from the incremental upload state in O(1).
    pub digests: ObjectDigests,
    /// Declared total, if any.
    pub total: Option<u64>,
    /// Credentials the session was started with.
    pub authorization: Option<&'a str>,
    /// The app the session was admitted for, when the initiation captured an enforced policy.
    pub admission: Option<&'a UploadAdmission>,
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
    /// Object data, shared by reference with every snapshot that captured the same blob.
    blobs: BTreeMap<BlobId, Arc<Vec<u8>>>,
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

/// The bytes charged against the custom-metadata budget: the plain custom map plus the
/// download tokens as they serialize back into the `firebaseStorageDownloadTokens` key.
///
/// Download tokens are lifted out of custom metadata before the plain map is measured, so
/// counting the plain map alone would let a caller smuggle unbounded state past the 8 KiB
/// budget through that one key (an unauthenticated `PATCH` can set it, and each `GET` then
/// scans every token in constant time). Charging the tokens here closes that, and does it
/// consistently across `put`, `update_metadata`, `add_download_token` and the resumable
/// start, which used to check inconsistently.
fn metadata_budget_size(custom: &BTreeMap<String, String>, download_tokens: &[String]) -> usize {
    let mut size = custom_metadata_size(custom);
    if !download_tokens.is_empty() {
        size += TOKENS_METADATA_KEY.len();
        size += download_tokens.iter().map(String::len).sum::<usize>();
        // The comma separators of the joined value.
        size += download_tokens.len().saturating_sub(1);
    }
    size
}

/// The custom-metadata key download tokens ride in on, as the official emulator stores them.
const TOKENS_METADATA_KEY: &str = "firebaseStorageDownloadTokens";

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

    /// Drops every object, blob and upload of the buckets `owned` selects (a session
    /// reset); returns how many objects went.
    pub fn remove_buckets_where(&mut self, owned: impl Fn(&str) -> bool) -> usize {
        let gone: Vec<(BucketName, ObjectName)> = self
            .objects
            .keys()
            .filter(|(b, _)| owned(b.as_str()))
            .cloned()
            .collect();
        for key in &gone {
            if let Some(m) = self.objects.remove(key) {
                self.blobs.remove(&m.blob);
            }
        }
        self.uploads.retain(|_, u| !owned(u.bucket.as_str()));
        gone.len()
    }

    /// A copy of the objects, blobs and uploads of the buckets `owned` selects (a session
    /// snapshot); the counters and the token generator are copied as they are.
    #[must_use]
    pub fn capture_buckets(&self, owned: impl Fn(&str) -> bool) -> Self {
        let objects: BTreeMap<(BucketName, ObjectName), ObjectMetadata> = self
            .objects
            .iter()
            .filter(|((b, _), _)| owned(b.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let blobs = objects
            .values()
            .filter_map(|m| self.blobs.get_key_value(&m.blob))
            .map(|(k, v)| (*k, Arc::clone(v)))
            .collect();
        let uploads = self
            .uploads
            .iter()
            .filter(|(_, u)| owned(u.bucket.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Self {
            objects,
            blobs,
            uploads,
            next_blob: self.next_blob,
            next_generation: self.next_generation,
            next_upload: self.next_upload,
            rng: self.rng.clone(),
            events: Vec::new(),
        }
    }

    /// Replaces the buckets `owned` selects with `captured`'s objects, blobs and uploads
    /// (a session restore); the other buckets stay. Global allocators and the credential RNG
    /// never rewind: their identifiers may still be referenced by another scope or client.
    pub fn restore_buckets(&mut self, owned: impl Fn(&str) -> bool, captured: &Self) {
        self.remove_buckets_where(&owned);
        for (k, v) in &captured.objects {
            if owned(k.0.as_str()) {
                if let Some(bytes) = captured.blobs.get(&v.blob) {
                    self.blobs.insert(v.blob, Arc::clone(bytes));
                }
                self.objects.insert(k.clone(), v.clone());
            }
        }
        for (k, v) in &captured.uploads {
            if owned(v.bucket.as_str()) {
                self.uploads.insert(k.clone(), v.clone());
            }
        }
        self.next_blob = self.next_blob.max(captured.next_blob);
        self.next_generation = self.next_generation.max(captured.next_generation);
        self.next_upload = self.next_upload.max(captured.next_upload);
        self.events.retain(|event| {
            let bucket = match event {
                StorageEvent::Finalized(metadata)
                | StorageEvent::Deleted(metadata)
                | StorageEvent::MetadataUpdated(metadata) => &metadata.bucket,
            };
            !owned(bucket.as_str())
        });
    }

    /// Bytes of object data this state retains, each blob counted once (`SNAP-MEM-01`).
    #[must_use]
    pub fn retained_blob_bytes(&self) -> u64 {
        self.blobs.values().map(|b| b.len() as u64).sum()
    }

    /// Bytes of object data shared with `other` by allocation: blobs whose buffer is the
    /// same `Arc` on both sides, so capturing or restoring them copied nothing
    /// (`SNAP-MEM-02`).
    #[must_use]
    pub fn blob_bytes_shared_with(&self, other: &Self) -> u64 {
        self.blobs
            .iter()
            .filter_map(|(id, bytes)| {
                other
                    .blobs
                    .get(id)
                    .filter(|theirs| Arc::ptr_eq(bytes, theirs))
                    .map(|_| bytes.len() as u64)
            })
            .sum()
    }

    /// Takes the events recorded since the last call.
    pub fn drain_events(&mut self) -> Vec<StorageEvent> {
        std::mem::take(&mut self.events)
    }

    /// A download token in the UUID v4 shape the official emulator and production mint
    /// (`crypto.randomUUID()` upstream); here it is drawn from the store's seeded RNG, so a
    /// seeded run reproduces its tokens.
    fn token(&mut self) -> String {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.rng.next_u64().to_be_bytes());
        bytes[8..].copy_from_slice(&self.rng.next_u64().to_be_bytes());
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;
        let h = |r: std::ops::Range<usize>| {
            bytes[r].iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            })
        };
        format!(
            "{}-{}-{}-{}-{}",
            h(0..4),
            h(4..6),
            h(6..8),
            h(8..10),
            h(10..16)
        )
    }

    /// Mints one download token (the caller decides where it goes: the Firebase upload
    /// dialect injects it into the incoming `firebaseStorageDownloadTokens` metadata, as the
    /// official emulator does).
    pub fn mint_download_token(&mut self) -> String {
        self.token()
    }

    /// The generation the next commit will draw, for the `request.resource` a rules
    /// evaluation sees before the commit exists (the official emulator builds the whole
    /// prospective object, generation included, before its rules run).
    pub fn next_generation_preview(&self) -> Result<u64, StorageError> {
        self.next_generation
            .checked_add(1)
            .filter(|generation| *generation <= MAX_PERSISTED_IDENTITY)
            .ok_or(StorageError::IdentityExhausted)
    }

    /// Object metadata.
    #[must_use]
    pub fn get(&self, bucket: &BucketName, name: &ObjectName) -> Option<&ObjectMetadata> {
        self.objects.get(&(bucket.clone(), name.clone()))
    }

    /// Object bytes.
    #[must_use]
    pub fn bytes(&self, meta: &ObjectMetadata) -> &[u8] {
        self.blobs.get(&meta.blob).map_or(&[], |b| b.as_slice())
    }

    /// Object bytes shared with snapshots and response bodies.
    #[must_use]
    pub fn shared_bytes(&self, meta: &ObjectMetadata) -> Arc<Vec<u8>> {
        self.blobs
            .get(&meta.blob)
            .cloned()
            .unwrap_or_else(|| Arc::new(Vec::new()))
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
        self.put_prepared(bucket, name, PreparedObject::new(bytes), metadata, pre, now)
    }

    /// Writes a new generation from bytes already bound to their digests.
    ///
    /// Protocol adapters use this after the same digests have been exposed to Security Rules.
    #[allow(clippy::too_many_arguments)]
    pub fn put_prepared(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        prepared: PreparedObject,
        metadata: NewMetadata,
        pre: Precondition,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let PreparedObject { bytes, digests } = prepared;
        if bytes.len() as u64 > MAX_OBJECT_BYTES {
            return Err(StorageError::TooLarge);
        }
        // Download tokens ride in as the `firebaseStorageDownloadTokens` custom metadata
        // key and are lifted out of it, exactly as the official emulator's
        // `setDownloadTokensFromCustomMetadata` does. A new generation carries only the
        // tokens its own upload declared: the previous generation's tokens die with it.
        let custom_defined = metadata.custom.is_some();
        let mut custom = metadata.custom.unwrap_or_default();
        let download_tokens = extract_download_tokens(&mut custom, Vec::new());
        if metadata_budget_size(&custom, &download_tokens) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
        }
        let key = (bucket.clone(), name.clone());
        Self::check(self.objects.get(&key), pre)?;
        let next_blob = self
            .next_blob
            .checked_add(1)
            .ok_or(StorageError::IdentityExhausted)?;
        let next_generation = self.next_generation_preview()?;
        self.next_blob = next_blob;
        let blob = BlobId(next_blob);
        self.next_generation = next_generation;
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
            custom,
            custom_defined,
            md5: digests.md5,
            crc32c: digests.crc32c,
            time_created: now,
            updated: now,
            download_tokens,
            blob,
        };
        if let Some(old) = self.objects.insert(key, meta.clone()) {
            self.blobs.remove(&old.blob);
        }
        self.blobs.insert(blob, Arc::new(bytes));
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
        // A patch may write `firebaseStorageDownloadTokens`; the key is lifted into the
        // token list (merged with the tokens the object already has), never stored as
        // ordinary custom metadata.
        next.download_tokens =
            extract_download_tokens(&mut next.custom, std::mem::take(&mut next.download_tokens));
        if metadata_budget_size(&next.custom, &next.download_tokens) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
        }
        next.metageneration = next
            .metageneration
            .checked_add(1)
            .filter(|metageneration| *metageneration <= MAX_PERSISTED_IDENTITY)
            .ok_or(StorageError::IdentityExhausted)?;
        next.updated = now;
        *meta = next.clone();
        self.events
            .push(StorageEvent::MetadataUpdated(next.clone()));
        Ok(next)
    }

    /// Adds a Firebase download token. A token is a metadata change: the metageneration is
    /// bumped, `updated` moves, and a `MetadataUpdated` event is recorded, exactly as the
    /// official emulator's `addDownloadToken` behaves.
    pub fn add_download_token(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let key = (bucket.clone(), name.clone());
        let meta = self.objects.get(&key).ok_or(StorageError::NotFound)?;
        // The token-mint route (?create_token=true) has no other size gate, so the count
        // cap is enforced here too: an unauthenticated caller cannot grow the list without
        // limit one token at a time (S-1).
        if meta.download_tokens.len() >= MAX_DOWNLOAD_TOKENS {
            return Err(StorageError::MetadataTooLarge);
        }
        let next_metageneration = meta
            .metageneration
            .checked_add(1)
            .filter(|metageneration| *metageneration <= MAX_PERSISTED_IDENTITY)
            .ok_or(StorageError::IdentityExhausted)?;
        let token = self.token();
        let meta = self.objects.get_mut(&key).ok_or(StorageError::NotFound)?;
        meta.download_tokens.push(token);
        meta.metageneration = next_metageneration;
        meta.updated = now;
        let updated = meta.clone();
        self.events
            .push(StorageEvent::MetadataUpdated(updated.clone()));
        Ok(updated)
    }

    /// Removes a Firebase download token. Removing the last one mints a replacement, any
    /// removal on an object that has tokens bumps the metageneration and records a
    /// `MetadataUpdated` event, and a removal from an object with no tokens changes
    /// nothing, exactly as the official emulator's `deleteDownloadToken` behaves.
    pub fn remove_download_token(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
        token: &str,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let key = (bucket.clone(), name.clone());
        let meta = self.objects.get(&key).ok_or(StorageError::NotFound)?;
        if meta.download_tokens.is_empty() {
            return Ok(meta.clone());
        }
        let replacement_needed = meta
            .download_tokens
            .iter()
            .all(|existing| existing == token);
        let bump = if replacement_needed { 2 } else { 1 };
        let next_metageneration = meta
            .metageneration
            .checked_add(bump)
            .filter(|metageneration| *metageneration <= MAX_PERSISTED_IDENTITY)
            .ok_or(StorageError::IdentityExhausted)?;
        let replacement = replacement_needed.then(|| self.token());
        let meta = self.objects.get_mut(&key).ok_or(StorageError::NotFound)?;
        meta.download_tokens.retain(|t| t != token);
        if meta.download_tokens.is_empty() {
            meta.download_tokens
                .push(replacement.expect("an empty token list requires a replacement"));
            // Upstream's replacement mint is its own (silent) metadata update, so removing
            // the last token moves the metageneration by two while emitting one event.
        }
        meta.metageneration = next_metageneration;
        meta.updated = now;
        let updated = meta.clone();
        self.events
            .push(StorageEvent::MetadataUpdated(updated.clone()));
        Ok(updated)
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
            custom: src.custom_defined.then(|| src.custom.clone()),
        });
        self.put(dst_bucket, dst_name, bytes, metadata, pre, now)
    }

    /// Lists objects of `bucket` under `prefix`, bytewise by name, the way the official
    /// emulator lists them: every folded prefix is returned on every page, only items are
    /// paged, the page token is the name of the first item of the next page (the token
    /// item is included), and a token that names no item restarts from the beginning.
    /// `max_results` caps the items only (`None` is the official default of 1000;
    /// `Some(0)` is an empty page whose token names the first item).
    #[must_use]
    pub fn list(
        &self,
        bucket: &BucketName,
        prefix: &str,
        delimiter: Option<&str>,
        page_token: Option<&str>,
        max_results: Option<usize>,
    ) -> ListPage {
        let max = max_results.unwrap_or(DEFAULT_LIST_PAGE_SIZE);
        let delimiter = delimiter.filter(|delimiter| !delimiter.is_empty());
        let token_is_item = page_token.is_some_and(|token| {
            self.objects
                .get(&(bucket.clone(), ObjectName::range_start(token)))
                .is_some_and(|metadata| {
                    let name = metadata.name.as_str();
                    name.starts_with(prefix)
                        && delimiter
                            .is_none_or(|delimiter| !name[prefix.len()..].contains(delimiter))
                })
        });
        let item_start = page_token.filter(|_| token_is_item).unwrap_or(prefix);
        let lower = (bucket.clone(), ObjectName::range_start(prefix));
        let mut items = Vec::with_capacity(max.min(DEFAULT_LIST_PAGE_SIZE));
        let mut prefixes: Vec<String> = Vec::new();
        let mut next_page_token = None;
        for ((candidate_bucket, name), meta) in self.objects.range(lower..) {
            if candidate_bucket != bucket || !name.as_str().starts_with(prefix) {
                break;
            }
            let rest = &name.as_str()[prefix.len()..];
            let folded =
                delimiter.and_then(|d| rest.find(d).map(|i| format!("{prefix}{}{d}", &rest[..i])));
            if let Some(p) = folded {
                // Names sharing a folded prefix are contiguous in name order, so a
                // duplicate is always adjacent.
                if prefixes.last() != Some(&p) {
                    prefixes.push(p);
                }
            } else if name.as_str() >= item_start && items.len() < max {
                items.push(meta.clone());
            } else if name.as_str() >= item_start && next_page_token.is_none() {
                next_page_token = Some(name.as_str().to_owned());
            }
        }
        ListPage {
            items,
            prefixes,
            next_page_token,
        }
    }

    /// Every bucket that holds an object, in name order.
    ///
    /// The store has no bucket registry: a bucket exists because an object names it. An
    /// export therefore lists exactly the buckets with content, and importing a bucket with
    /// no objects is a no-op.
    #[must_use]
    pub fn buckets(&self) -> Vec<BucketName> {
        let mut out: Vec<BucketName> = Vec::new();
        for (bucket, _) in self.objects.keys() {
            if out.last() != Some(bucket) {
                out.push(bucket.clone());
            }
        }
        out
    }

    /// Every object of every bucket, in (bucket, name) order: what an export walks.
    #[must_use]
    pub fn all_objects(&self) -> Vec<&ObjectMetadata> {
        self.objects.values().collect()
    }

    /// Installs an object from an import artifact, with the generation, metageneration,
    /// times and download tokens the artifact recorded.
    ///
    /// This is deliberately not [`Self::put`]: an import is restoring state that already
    /// existed, so it must not draw a fresh generation, must not stamp the current time on
    /// an object that was written long ago, must not mint a new download token (an existing
    /// URL has to keep working) and must not append a [`StorageEvent`] -- a Functions
    /// trigger firing for every object of an import would be an invented event.
    ///
    /// The digests the artifact recorded are checked against the bytes when it has them, so
    /// a truncated or swapped blob is refused instead of being served with the wrong hash.
    /// `next_generation` moves past the imported one so that a later write cannot reuse it.
    pub fn insert_imported(
        &mut self,
        object: ImportedObject,
        bytes: Vec<u8>,
    ) -> Result<ObjectMetadata, StorageError> {
        if bytes.len() as u64 > MAX_OBJECT_BYTES {
            return Err(StorageError::TooLarge);
        }
        if custom_metadata_size(&object.custom) > MAX_CUSTOM_METADATA_BYTES {
            return Err(StorageError::MetadataTooLarge);
        }
        if object.generation == 0
            || object.generation > MAX_PERSISTED_IDENTITY
            || object.metageneration == 0
            || object.metageneration > MAX_PERSISTED_IDENTITY
        {
            return Err(StorageError::InvalidImportedIdentity(format!(
                "generation and metageneration must both be between 1 and {MAX_PERSISTED_IDENTITY}"
            )));
        }
        let md5 = md5(&bytes);
        if let Some(recorded) = object.md5 {
            if recorded != md5 {
                return Err(StorageError::ChecksumMismatch(format!(
                    "the imported object {} does not match the md5Hash its metadata records",
                    object.name.as_str()
                )));
            }
        }
        let crc = crc32c(&bytes);
        if let Some(recorded) = object.crc32c {
            if recorded != crc {
                return Err(StorageError::ChecksumMismatch(format!(
                    "the imported object {} does not match the crc32c its metadata records",
                    object.name.as_str()
                )));
            }
        }
        if let Some(recorded) = object.size {
            if recorded != bytes.len() as u64 {
                return Err(StorageError::ChecksumMismatch(format!(
                    "the imported object {} is {} bytes, not the {recorded} its metadata records",
                    object.name.as_str(),
                    bytes.len()
                )));
            }
        }
        let next_blob = self
            .next_blob
            .checked_add(1)
            .ok_or(StorageError::IdentityExhausted)?;
        self.next_blob = next_blob;
        let blob = BlobId(next_blob);
        self.next_generation = self.next_generation.max(object.generation);
        let meta = ObjectMetadata {
            bucket: object.bucket.clone(),
            name: object.name.clone(),
            generation: object.generation,
            metageneration: object.metageneration,
            size: bytes.len() as u64,
            content_type: object.content_type,
            content_disposition: object.content_disposition,
            content_encoding: object.content_encoding,
            content_language: object.content_language,
            cache_control: object.cache_control,
            custom: object.custom,
            custom_defined: object.custom_defined,
            md5,
            crc32c: crc,
            time_created: object.time_created,
            updated: object.updated,
            download_tokens: object.download_tokens,
            blob,
        };
        if let Some(old) = self
            .objects
            .insert((object.bucket, object.name), meta.clone())
        {
            self.blobs.remove(&old.blob);
        }
        self.blobs.insert(blob, Arc::new(bytes));
        Ok(meta)
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
        if metadata
            .custom
            .as_ref()
            .is_some_and(|c| custom_metadata_size(c) > MAX_CUSTOM_METADATA_BYTES)
        {
            return Err(StorageError::MetadataTooLarge);
        }
        let next_upload = self
            .next_upload
            .checked_add(1)
            .ok_or(StorageError::IdentityExhausted)?;
        self.sweep_uploads(now);
        let receiving = self
            .uploads
            .values()
            .filter(|u| u.state == UploadState::Receiving)
            .count();
        if receiving >= MAX_UPLOAD_SESSIONS {
            return Err(StorageError::TooManyUploads);
        }
        self.next_upload = next_upload;
        let sequence = next_upload;
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
                admission: options.admission,
                expected_md5: options.expected_md5,
                expected_crc32c: options.expected_crc32c,
                md5: Md5::new(),
                crc32c: Crc32c::new(),
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
            UploadState::Denied(received) => (*received, None),
            UploadState::Receiving | UploadState::Aborted => (u.received.len() as u64, None),
        })
    }

    /// The full lifecycle phase of an upload, for the status queries the protocols answer.
    pub fn upload_phase(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<UploadPhase, StorageError> {
        let u = self.upload_mut(id, now)?;
        Ok(match &u.state {
            UploadState::Receiving => UploadPhase::Active(u.received.len() as u64),
            UploadState::Committed(m) => UploadPhase::Finalized(m.clone()),
            UploadState::Aborted => UploadPhase::Cancelled(u.received.len() as u64),
            UploadState::Denied(received) => UploadPhase::Denied(*received),
        })
    }

    /// Marks an upload whose finalization Security Rules refused: terminal like a commit,
    /// but no object was published, and the received byte count stays observable — the
    /// official emulator answers a repeated finalize of such a session with the refusal it
    /// gave the first time.
    pub fn mark_upload_denied(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<(), StorageError> {
        let u = self.upload_mut(id, now)?;
        if u.state == UploadState::Receiving {
            // Keep the count for a later status query; drop the bytes, exactly as a cancel
            // and a size / checksum abort do (S-2).
            u.state = UploadState::Denied(u.received.len() as u64);
            u.received = Vec::new();
        }
        Ok(())
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
            UploadState::Committed(_) | UploadState::Aborted | UploadState::Denied(_) => {
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
            let appended = &chunk[skip..];
            u.md5.update(appended);
            u.crc32c.update(appended);
            u.received.extend_from_slice(appended);
        }
        Ok(u.received.len() as u64)
    }

    /// [`Self::append_upload`] with an owned chunk: a session that has not received
    /// anything yet adopts the buffer instead of copying it, so an upload that arrives in
    /// one request never holds two copies of its payload. Every limit, offset and state
    /// rule of [`Self::append_upload`] applies unchanged.
    pub fn append_upload_owned(
        &mut self,
        id: &UploadId,
        offset: u64,
        chunk: Vec<u8>,
        now: LogicalInstant,
    ) -> Result<u64, StorageError> {
        let u = self.upload_mut(id, now)?;
        match u.state {
            UploadState::Committed(_) | UploadState::Aborted | UploadState::Denied(_) => {
                return Err(StorageError::UploadFinalized)
            }
            UploadState::Receiving => {}
        }
        if offset == 0 && u.received.is_empty() && !chunk.is_empty() {
            let end = chunk.len() as u64;
            if end > MAX_OBJECT_BYTES || u.total.is_some_and(|t| end > t) {
                let too_large = u.total.is_some_and(|t| end > t);
                u.state = UploadState::Aborted;
                u.received = Vec::new();
                return Err(if too_large {
                    StorageError::UploadSizeMismatch
                } else {
                    StorageError::TooLarge
                });
            }
            u.md5.update(&chunk);
            u.crc32c.update(&chunk);
            u.received = chunk;
            return Ok(u.received.len() as u64);
        }
        self.append_upload(id, offset, &chunk, now)
    }

    /// What an upload would commit right now (for authorization before finalization).
    pub fn pending_upload(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<PendingUpload<'_>, StorageError> {
        let u = self.upload_mut(id, now)?;
        match u.state {
            UploadState::Committed(_) | UploadState::Aborted | UploadState::Denied(_) => {
                Err(StorageError::UploadFinalized)
            }
            UploadState::Receiving => Ok(PendingUpload {
                bucket: &u.bucket,
                name: &u.name,
                metadata: &u.metadata,
                bytes: &u.received,
                digests: ObjectDigests {
                    md5: u.md5.clone().finalize(),
                    crc32c: u.crc32c.finalize(),
                },
                total: u.total,
                authorization: u.authorization.as_deref(),
                admission: u.admission.as_ref(),
            }),
        }
    }

    /// The app a session was admitted for, whatever state the session is in.
    ///
    /// Unlike [`Self::pending_upload`] this answers for a committed or aborted session too, so
    /// the protocol layer can refuse a foreign app before it learns anything else about the
    /// session. `Ok(None)` means the session carries no App Check binding.
    pub fn upload_admission(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<Option<&UploadAdmission>, StorageError> {
        Ok(self.upload_mut(id, now)?.admission.as_ref())
    }

    /// The bucket a session belongs to, whatever state the session is in.
    ///
    /// Like [`Self::upload_admission`] and unlike [`Self::pending_upload`], this answers for a
    /// terminal (committed, aborted or rules-denied) session too, so the protocol layer can
    /// refuse a request that names the wrong bucket before it learns the session's received
    /// byte count or status. A `pending_upload`-only check let a `query` command on one
    /// bucket's URL read a terminal session that belongs to another bucket (and so another
    /// project).
    pub fn upload_bucket(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<&BucketName, StorageError> {
        Ok(&self.upload_mut(id, now)?.bucket)
    }

    /// Commits the received bytes as a new generation.
    pub fn finalize_upload(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<ObjectMetadata, StorageError> {
        let (bucket, name, metadata, precondition, prepared) = {
            let u = self.upload_mut(id, now)?;
            match u.state {
                UploadState::Committed(_) | UploadState::Aborted | UploadState::Denied(_) => {
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
            let received_md5 = u.md5.clone().finalize();
            let received_crc32c = u.crc32c.finalize();
            let mismatch = match (u.expected_md5, u.expected_crc32c) {
                (Some(expected), _) if received_md5 != expected => Some(format!(
                    "md5 {} declared, {} received",
                    base64(&expected),
                    base64(&received_md5)
                )),
                (_, Some(expected)) if received_crc32c != expected => Some(format!(
                    "crc32c {} declared, {} received",
                    base64(&expected.to_be_bytes()),
                    base64(&received_crc32c.to_be_bytes())
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
                PreparedObject {
                    bytes: std::mem::take(&mut u.received),
                    digests: ObjectDigests {
                        md5: received_md5,
                        crc32c: received_crc32c,
                    },
                },
            )
        };
        let meta = match self.put_prepared(&bucket, &name, prepared, metadata, precondition, now) {
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

    /// Cancels an upload. A finalized session (committed, or refused by rules at
    /// finalization) is not cancellable, as the official emulator answers.
    pub fn cancel_upload(
        &mut self,
        id: &UploadId,
        now: LogicalInstant,
    ) -> Result<(), StorageError> {
        let u = self.upload_mut(id, now)?;
        match u.state {
            UploadState::Committed(_) | UploadState::Denied(_) => {
                return Err(StorageError::UploadFinalized)
            }
            UploadState::Receiving | UploadState::Aborted => {}
        }
        u.state = UploadState::Aborted;
        u.received = Vec::new();
        Ok(())
    }

    /// Applies the Firebase dialect's post-commit `contentDisposition: "inline"` default to
    /// a stored object, exactly as the official emulator mutates the stored metadata after
    /// its rules ran and after the finalize event was built: no metageneration bump and no
    /// event. Returns the updated metadata.
    pub fn default_content_disposition_inline(
        &mut self,
        bucket: &BucketName,
        name: &ObjectName,
    ) -> Result<ObjectMetadata, StorageError> {
        let meta = self
            .objects
            .get_mut(&(bucket.clone(), name.clone()))
            .ok_or(StorageError::NotFound)?;
        if meta.content_disposition.is_none() {
            meta.content_disposition = Some("inline".to_owned());
        }
        Ok(meta.clone())
    }
}

/// Lifts the `firebaseStorageDownloadTokens` key out of custom metadata into the token
/// list, merging with `existing` (order kept, duplicates dropped), as the official
/// emulator's `setDownloadTokensFromCustomMetadata` does.
fn extract_download_tokens(
    custom: &mut BTreeMap<String, String>,
    existing: Vec<String>,
) -> Vec<String> {
    let mut tokens = existing;
    if let Some(joined) = custom.remove(TOKENS_METADATA_KEY) {
        for t in joined.split(',') {
            // Every write path funnels through here, so bounding the count and length here
            // is the single place that stops an unauthenticated caller from smuggling
            // unbounded token state past the custom-metadata budget through this one key
            // (S-1). An over-long candidate is dropped whole rather than truncated, so a
            // token is never silently mangled into a different value.
            if t.is_empty() || t.len() > MAX_DOWNLOAD_TOKEN_LEN {
                continue;
            }
            if tokens.len() >= MAX_DOWNLOAD_TOKENS {
                break;
            }
            if !tokens.iter().any(|x| x == t) {
                tokens.push(t.to_owned());
            }
        }
    }
    tokens
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
        match &self.custom {
            None => {}
            Some(CustomMetadataPatch::Clear) => {
                next.custom.clear();
                next.custom_defined = false;
            }
            Some(CustomMetadataPatch::Merge(entries)) => {
                for (k, v) in entries {
                    match v {
                        Some(v) => {
                            next.custom.insert(k.clone(), v.clone());
                        }
                        None => {
                            next.custom.remove(k);
                        }
                    }
                }
                // Upstream drops the map entirely when the merge leaves no keys.
                next.custom_defined = !next.custom.is_empty();
            }
        }
        next
    }
}
