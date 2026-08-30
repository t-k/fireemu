//! `storage_export/`: the bucket list, the object bytes and the object metadata.
//!
//! The Storage emulator writes the section itself (`storage/files.ts` `export`):
//!
//! ```text
//! storage_export/
//!   buckets.json            {"buckets":[{"id":"demo-app.appspot.com"}]}
//!   blobs/<blob id>         the object bytes, byte for byte
//!   metadata/<blob id>.json the object metadata, one file per object
//! ```
//!
//! The blob id is the emulator's internal on-disk file name, a random UUID; nothing in the
//! format requires it to be one, only that the metadata file is named `<blob id>.json` for
//! the blob of the same name (`files.ts` `import` joins them exactly that way). fireemu
//! derives a stable id from the bucket and object name instead of drawing a random one, so
//! that exporting the same state twice produces the same directory.
//!
//! The metadata document is `StoredFileMetadata` with every `_`-prefixed member removed, so
//! it is the emulator's own record rather than an API projection: `generation` and
//! `metageneration` are numbers, `size` is a number, the timestamps are RFC 3339 and the
//! download tokens are an array (the API joins them with commas instead).

use fireemu_core_types::json::{parse, JsonValue};

use crate::json::Json;

/// The bucket list file name.
pub const BUCKETS_FILE: &str = "buckets.json";
/// The directory the object bytes live in.
pub const BLOBS_DIR: &str = "blobs";
/// The directory the object metadata lives in.
pub const METADATA_DIR: &str = "metadata";

/// Why a Storage document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageExportError(pub String);

impl core::fmt::Display for StorageExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StorageExportError {}

fn refuse<T>(message: impl Into<String>) -> Result<T, StorageExportError> {
    Err(StorageExportError(message.into()))
}

/// The parsed `buckets.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BucketsFile {
    /// Every bucket id, in file order.
    pub buckets: Vec<String>,
}

impl BucketsFile {
    /// Parses `buckets.json`.
    pub fn parse(text: &str) -> Result<Self, StorageExportError> {
        let value = parse(text).map_err(|e| StorageExportError(e.to_string()))?;
        let Some(JsonValue::Array(items)) = value.get("buckets") else {
            return refuse("the Storage buckets document has no \"buckets\" array");
        };
        let mut buckets = Vec::with_capacity(items.len());
        for item in items {
            let id = item.get("id").and_then(JsonValue::as_str).ok_or_else(|| {
                StorageExportError("a bucket entry has no string \"id\"".to_owned())
            })?;
            buckets.push(id.to_owned());
        }
        Ok(Self { buckets })
    }

    /// Writes `buckets.json`.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        doc.insert(
            "buckets",
            Json::Array(
                self.buckets
                    .iter()
                    .map(|id| {
                        let mut entry = Json::object();
                        entry.insert("id", Json::string(id));
                        entry
                    })
                    .collect(),
            ),
        );
        doc.to_pretty()
    }
}

/// One object's metadata document.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObjectMetadata {
    /// The object name inside the bucket, `/`-separated.
    pub name: String,
    /// The bucket the object belongs to.
    pub bucket: String,
    /// The object generation.
    pub generation: i64,
    /// The metadata generation.
    pub metageneration: i64,
    /// The content type.
    pub content_type: Option<String>,
    /// The storage class (`STANDARD`).
    pub storage_class: Option<String>,
    /// The download tokens that make the object publicly readable.
    pub download_tokens: Vec<String>,
    /// The entity tag.
    pub etag: Option<String>,
    /// When the object was created, RFC 3339.
    pub time_created: Option<String>,
    /// When the object was last updated, RFC 3339.
    pub updated: Option<String>,
    /// The object size in bytes.
    pub size: u64,
    /// The base64 MD5 digest.
    pub md5_hash: Option<String>,
    /// The CRC-32C, as the decimal string the emulator writes.
    pub crc32c: Option<String>,
    /// `Cache-Control`.
    pub cache_control: Option<String>,
    /// `Content-Disposition`.
    pub content_disposition: Option<String>,
    /// `Content-Encoding`.
    pub content_encoding: Option<String>,
    /// `Content-Language`.
    pub content_language: Option<String>,
    /// The caller-supplied metadata.
    pub custom_metadata: Vec<(String, String)>,
    /// Members this crate does not model, kept so an import cannot lose them.
    pub extra: Vec<(String, Json)>,
}

const KNOWN_OBJECT_MEMBERS: [&str; 18] = [
    "name",
    "bucket",
    "generation",
    "metageneration",
    "contentType",
    "storageClass",
    "downloadTokens",
    "etag",
    "timeCreated",
    "updated",
    "size",
    "md5Hash",
    "crc32c",
    "cacheControl",
    "contentDisposition",
    "contentEncoding",
    "contentLanguage",
    "customMetadata",
];

impl ObjectMetadata {
    /// Parses one `metadata/<blob id>.json`.
    pub fn parse(text: &str) -> Result<Self, StorageExportError> {
        let value = parse(text).map_err(|e| StorageExportError(e.to_string()))?;
        let JsonValue::Object(members) = &value else {
            return refuse("a Storage object metadata document is not a JSON object");
        };
        let name = value
            .get("name")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                StorageExportError(
                    "a Storage object metadata document has no string \"name\"".to_owned(),
                )
            })?
            .to_owned();
        let bucket = value
            .get("bucket")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                StorageExportError(format!("the Storage object {name:?} names no \"bucket\""))
            })?
            .to_owned();
        let size = match value.get("size") {
            Some(JsonValue::Int(i)) if *i >= 0 => u64::try_from(*i).unwrap_or(0),
            Some(JsonValue::String(s)) => s.parse().map_err(|_| {
                StorageExportError(format!(
                    "the Storage object {name:?} has a non-numeric size"
                ))
            })?,
            None => 0,
            Some(_) => {
                return refuse(format!(
                    "the Storage object {name:?} has a size that is not a whole number"
                ))
            }
        };
        let mut download_tokens = Vec::new();
        match value.get("downloadTokens") {
            Some(JsonValue::Array(items)) => {
                for item in items {
                    match item.as_str() {
                        Some(token) => download_tokens.push(token.to_owned()),
                        None => {
                            return refuse(format!(
                                "the Storage object {name:?} has a non-string download token"
                            ))
                        }
                    }
                }
            }
            // The API projection joins them with commas; accept that spelling too.
            Some(JsonValue::String(joined)) => {
                download_tokens.extend(
                    joined
                        .split(',')
                        .filter(|t| !t.is_empty())
                        .map(str::to_owned),
                );
            }
            _ => {}
        }
        let mut custom_metadata = Vec::new();
        if let Some(JsonValue::Object(entries)) = value.get("customMetadata") {
            for (key, item) in entries {
                match item.as_str() {
                    Some(v) => custom_metadata.push((key.clone(), v.to_owned())),
                    None => {
                        return refuse(format!(
                            "the Storage object {name:?} has a non-string customMetadata value for {key:?}"
                        ))
                    }
                }
            }
        }
        let extra = members
            .iter()
            .filter(|(k, _)| !KNOWN_OBJECT_MEMBERS.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), Json::from_value(v)))
            .collect();
        Ok(Self {
            name,
            bucket,
            generation: int_member(&value, "generation").unwrap_or(1),
            metageneration: int_member(&value, "metageneration").unwrap_or(1),
            content_type: string_member(&value, "contentType"),
            storage_class: string_member(&value, "storageClass"),
            download_tokens,
            etag: string_member(&value, "etag"),
            time_created: string_member(&value, "timeCreated"),
            updated: string_member(&value, "updated"),
            size,
            md5_hash: string_member(&value, "md5Hash"),
            crc32c: string_member(&value, "crc32c"),
            cache_control: string_member(&value, "cacheControl"),
            content_disposition: string_member(&value, "contentDisposition"),
            content_encoding: string_member(&value, "contentEncoding"),
            content_language: string_member(&value, "contentLanguage"),
            custom_metadata,
            extra,
        })
    }

    /// Writes one `metadata/<blob id>.json`, in the emulator's member order.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        doc.insert("name", Json::string(&self.name));
        doc.insert("bucket", Json::string(&self.bucket));
        doc.insert("metageneration", Json::Int(self.metageneration));
        doc.insert("generation", Json::Int(self.generation));
        doc.insert_some("contentType", self.content_type.as_ref().map(Json::string));
        doc.insert_some(
            "storageClass",
            self.storage_class.as_ref().map(Json::string),
        );
        doc.insert_some(
            "cacheControl",
            self.cache_control.as_ref().map(Json::string),
        );
        doc.insert_some(
            "contentDisposition",
            self.content_disposition.as_ref().map(Json::string),
        );
        doc.insert_some(
            "contentEncoding",
            self.content_encoding.as_ref().map(Json::string),
        );
        doc.insert_some(
            "contentLanguage",
            self.content_language.as_ref().map(Json::string),
        );
        doc.insert(
            "downloadTokens",
            Json::Array(self.download_tokens.iter().map(Json::string).collect()),
        );
        doc.insert_some("etag", self.etag.as_ref().map(Json::string));
        if !self.custom_metadata.is_empty() {
            let mut custom = Json::object();
            for (key, value) in &self.custom_metadata {
                custom.insert(key.clone(), Json::string(value));
            }
            doc.insert("customMetadata", custom);
        }
        doc.insert_some("timeCreated", self.time_created.as_ref().map(Json::string));
        doc.insert_some("updated", self.updated.as_ref().map(Json::string));
        doc.insert("size", Json::Int(i64::try_from(self.size).unwrap_or(0)));
        doc.insert_some("md5Hash", self.md5_hash.as_ref().map(Json::string));
        doc.insert_some("crc32c", self.crc32c.as_ref().map(Json::string));
        for (key, value) in &self.extra {
            doc.insert(key.clone(), value.clone());
        }
        doc.to_pretty()
    }
}

fn string_member(value: &JsonValue, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
}

fn int_member(value: &JsonValue, key: &str) -> Option<i64> {
    match value.get(key) {
        Some(JsonValue::Int(i)) => Some(*i),
        Some(JsonValue::String(s)) => s.parse().ok(),
        _ => None,
    }
}

/// A stable blob id for an object, so that exporting the same state twice writes the same
/// file names.
///
/// The official emulator uses a random UUID; the format only requires the blob file and the
/// metadata file to share a name, and a name that is a function of the object keeps an
/// export directory diffable. The id is hex, so it is a valid file name whatever the object
/// name holds (a slash, a space, a non-ASCII character, a leading dot).
#[must_use]
pub fn blob_id(bucket: &str, object: &str, generation: i64) -> String {
    // FNV-1a over the three parts, widened to 128 bits by hashing twice with different
    // offsets; collisions inside one export would silently merge two objects, so the id is
    // long enough that an export never relies on luck.
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for offset in [0xcbf2_9ce4_8422_2325u64, 0x9e37_79b9_7f4a_7c15u64] {
        let mut hash = offset;
        for part in [bucket.as_bytes(), &[0][..], object.as_bytes(), &[0][..]] {
            for byte in part {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        for byte in generation.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let _ = write!(out, "{hash:016x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{blob_id, BucketsFile, ObjectMetadata};

    const OFFICIAL: &str = r#"{
  "name": "images/hello.txt",
  "bucket": "demo-export.appspot.com",
  "metageneration": 1,
  "generation": 1788105513194,
  "contentType": "text/plain",
  "storageClass": "STANDARD",
  "cacheControl": "public, max-age=60",
  "downloadTokens": [],
  "etag": "a7sO1JJ2Vz9lWyOmcW8s0Q5L244",
  "customMetadata": { "custom": "value", "n": "1" },
  "timeCreated": "2026-08-30T15:58:33.194Z",
  "updated": "2026-08-30T15:58:33.194Z",
  "size": 14,
  "md5Hash": "DFKqKz9JSntkXcjLkQABSQ==",
  "crc32c": "3688631254"
}"#;

    #[test]
    fn the_recorded_official_object_metadata_parses_into_every_member() {
        let meta = ObjectMetadata::parse(OFFICIAL).expect("the metadata parses");
        assert_eq!(meta.name, "images/hello.txt");
        assert_eq!(meta.bucket, "demo-export.appspot.com");
        assert_eq!(meta.generation, 1_788_105_513_194);
        assert_eq!(meta.metageneration, 1);
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
        assert_eq!(meta.storage_class.as_deref(), Some("STANDARD"));
        assert_eq!(meta.cache_control.as_deref(), Some("public, max-age=60"));
        assert!(meta.download_tokens.is_empty());
        assert_eq!(meta.size, 14);
        assert_eq!(meta.md5_hash.as_deref(), Some("DFKqKz9JSntkXcjLkQABSQ=="));
        assert_eq!(meta.crc32c.as_deref(), Some("3688631254"));
        assert_eq!(
            meta.custom_metadata,
            vec![
                ("custom".to_owned(), "value".to_owned()),
                ("n".to_owned(), "1".to_owned())
            ]
        );
        assert_eq!(
            meta.time_created.as_deref(),
            Some("2026-08-30T15:58:33.194Z")
        );
    }

    #[test]
    fn object_metadata_round_trips_through_the_written_document() {
        let meta = ObjectMetadata::parse(OFFICIAL).expect("the metadata parses");
        let again = ObjectMetadata::parse(&meta.to_json()).expect("the written metadata parses");
        assert_eq!(meta, again);
    }

    #[test]
    fn a_download_token_survives_both_the_array_and_the_joined_spelling() {
        let array =
            ObjectMetadata::parse(r#"{"name":"a","bucket":"b","downloadTokens":["one","two"]}"#)
                .expect("it parses");
        assert_eq!(array.download_tokens, vec!["one", "two"]);
        let joined =
            ObjectMetadata::parse(r#"{"name":"a","bucket":"b","downloadTokens":"one,two"}"#)
                .expect("it parses");
        assert_eq!(joined.download_tokens, array.download_tokens);
    }

    #[test]
    fn a_member_the_model_does_not_know_survives_the_round_trip() {
        let text = r#"{"name":"a","bucket":"b","somethingNewer":{"kept":true}}"#;
        let meta = ObjectMetadata::parse(text).expect("it parses");
        assert!(meta.to_json().contains("somethingNewer"));
        assert_eq!(
            ObjectMetadata::parse(&meta.to_json()).expect("it parses"),
            meta
        );
    }

    #[test]
    fn object_metadata_without_a_name_or_bucket_is_refused() {
        assert!(ObjectMetadata::parse(r#"{"bucket":"b"}"#).is_err());
        assert!(ObjectMetadata::parse(r#"{"name":"a"}"#).is_err());
        assert!(ObjectMetadata::parse("[]").is_err());
        assert!(ObjectMetadata::parse(r#"{"name":"a","bucket":"b","size":{}}"#).is_err());
    }

    #[test]
    fn the_bucket_list_parses_and_round_trips() {
        let text = r#"{"buckets":[{"id":"demo-export.appspot.com"},{"id":"other"}]}"#;
        let file = BucketsFile::parse(text).expect("it parses");
        assert_eq!(file.buckets, vec!["demo-export.appspot.com", "other"]);
        assert_eq!(
            BucketsFile::parse(&file.to_json()).expect("it parses"),
            file
        );
    }

    #[test]
    fn a_bucket_list_without_the_array_is_refused() {
        assert!(BucketsFile::parse("{}").is_err());
        assert!(BucketsFile::parse(r#"{"buckets":[{}]}"#).is_err());
    }

    #[test]
    fn a_blob_id_is_stable_hexadecimal_and_separates_objects() {
        let a = blob_id("demo.appspot.com", "images/hello.txt", 1);
        assert_eq!(a, blob_id("demo.appspot.com", "images/hello.txt", 1));
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, blob_id("demo.appspot.com", "images/hello.txt", 2));
        assert_ne!(a, blob_id("other.appspot.com", "images/hello.txt", 1));
        assert_ne!(a, blob_id("demo.appspot.com", "images/hello.txU", 1));
        // The separator makes a prefix shift a different object.
        assert_ne!(blob_id("a", "b/c", 1), blob_id("a/b", "c", 1));
    }
}
