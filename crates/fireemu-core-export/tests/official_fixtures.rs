//! The codec against the export directories `firebase emulators:export` really wrote.
//!
//! The fixtures under `crates/fireemu/tests/fixtures/export/` were recorded by running the
//! official Local Emulator Suite (`firebase-tools@15.28.2`, Firestore emulator 1.22.0) with
//! `conformance/src/record-export.mjs`. Reading them here is what pins the format: a change
//! that still round-trips through fireemu's own writer but no longer matches the emulator
//! would pass every unit test and fail these.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fireemu_core_export::auth::{AccountsFile, AuthConfig};
use fireemu_core_export::firestore::{
    read_output, write_output, ExportDocument, OverallMetadata, PartitionMetadata,
};
use fireemu_core_export::metadata::{ExportMetadata, Product};
use fireemu_core_export::storage::{BucketsFile, ObjectMetadata};
use fireemu_core_firestore::value::Value;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fireemu/tests/fixtures/export")
        .join(relative)
}

fn read(relative: &str) -> Vec<u8> {
    let path = fixture(relative);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("the fixture {} is readable: {e}", path.display()))
}

fn read_text(relative: &str) -> String {
    String::from_utf8(read(relative)).expect("the fixture is UTF-8")
}

/// Reads every document of a recorded Firestore section, following its own metadata files.
fn documents(fixture_dir: &str) -> Vec<ExportDocument> {
    let manifest = ExportMetadata::parse(&read_text(&format!(
        "{fixture_dir}/firebase-export-metadata.json"
    )))
    .expect("the manifest parses");
    let section = manifest
        .section(Product::Firestore)
        .expect("a firestore section");
    let overall = OverallMetadata::parse(&read(&format!(
        "{fixture_dir}/{}",
        section.metadata_file.as_ref().expect("a metadata file")
    )))
    .expect("the overall metadata parses");
    let partition = PartitionMetadata::parse(&read(&format!(
        "{fixture_dir}/{}/{}",
        section.path, overall.metadata_file
    )))
    .expect("the partition metadata parses");
    let partition_dir = overall
        .metadata_file
        .rsplit_once('/')
        .map_or(String::new(), |(dir, _)| dir.to_owned());
    let mut all = Vec::new();
    for output in &partition.output_files {
        let bytes = read(&format!(
            "{fixture_dir}/{}/{partition_dir}/{output}",
            section.path
        ));
        all.extend(read_output(&bytes).expect("the output file decodes"));
    }
    all
}

#[test]
fn the_recorded_multi_product_export_is_read_section_by_section() {
    let dir = "official-multiproduct";
    let manifest =
        ExportMetadata::parse(&read_text(&format!("{dir}/firebase-export-metadata.json")))
            .expect("the manifest parses");
    assert_eq!(manifest.version, "15.28.2");
    assert!(manifest.deferred().is_empty());

    let accounts = AccountsFile::parse(&read_text(&format!("{dir}/auth_export/accounts.json")))
        .expect("the accounts document parses");
    let ids: Vec<&str> = accounts.users.iter().map(|u| u.local_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "user-anon",
            "user-disabled",
            "user-federated",
            "user-mfa",
            "user-password"
        ]
    );
    let alice = accounts
        .users
        .iter()
        .find(|u| u.local_id == "user-password")
        .expect("the password account");
    assert_eq!(alice.email.as_deref(), Some("alice@example.com"));
    assert_eq!(
        alice.custom_attributes.as_deref(),
        Some(r#"{"role":"admin","tier":3}"#)
    );
    assert_eq!(alice.provider_user_info.len(), 2);
    let disabled = accounts
        .users
        .iter()
        .find(|u| u.local_id == "user-disabled")
        .expect("the disabled account");
    assert!(disabled.disabled);
    let mfa = accounts
        .users
        .iter()
        .find(|u| u.local_id == "user-mfa")
        .expect("the second-factor account");
    assert_eq!(mfa.mfa_info.len(), 1);
    assert_eq!(
        mfa.mfa_info[0].unobfuscated_phone_info.as_deref(),
        Some("+15555550102")
    );

    let config = AuthConfig::parse(&read_text(&format!("{dir}/auth_export/config.json")))
        .expect("the config parses");
    assert_eq!(config, AuthConfig::default());

    let buckets = BucketsFile::parse(&read_text(&format!("{dir}/storage_export/buckets.json")))
        .expect("the bucket list parses");
    assert_eq!(buckets.buckets, vec!["demo-export.appspot.com"]);

    let metadata_dir = fixture(&format!("{dir}/storage_export/metadata"));
    let mut objects = Vec::new();
    for entry in std::fs::read_dir(&metadata_dir).expect("the metadata directory is readable") {
        let path = entry.expect("a directory entry").path();
        let text = std::fs::read_to_string(&path).expect("the metadata file is readable");
        let meta = ObjectMetadata::parse(&text).expect("the object metadata parses");
        let blob = fixture(&format!(
            "{dir}/storage_export/blobs/{}",
            path.file_stem().expect("a blob id").to_string_lossy()
        ));
        let bytes = std::fs::read(&blob).expect("the blob is readable");
        assert_eq!(
            bytes.len() as u64,
            meta.size,
            "the recorded blob of {} is the size its metadata claims",
            meta.name
        );
        objects.push(meta.name.clone());
    }
    objects.sort();
    assert_eq!(
        objects,
        vec![
            "binary/blob.bin",
            "images/hello.txt",
            "nested/deep/path/file.json"
        ]
    );
}

#[test]
fn the_recorded_firestore_section_decodes_into_the_documents_that_were_seeded() {
    let docs = documents("official-multiproduct");
    assert_eq!(docs.len(), 30);
    assert!(docs.iter().all(|d| d.project == "demo-export"));

    let sf = docs
        .iter()
        .find(|d| d.relative_path() == "cities/SF")
        .expect("the SF document");
    assert_eq!(
        sf.fields.get("name"),
        Some(&Value::String("San Francisco".to_owned()))
    );
    assert_eq!(sf.fields.get("capital"), Some(&Value::Boolean(false)));
    assert_eq!(sf.fields.get("population"), Some(&Value::Integer(860_000)));
    assert_eq!(sf.fields.get("density"), Some(&Value::Double(7272.5)));
    assert_eq!(sf.fields.get("nickname"), Some(&Value::Null));
    assert_eq!(
        sf.fields.get("regions"),
        Some(&Value::Array(vec![
            Value::String("west_coast".to_owned()),
            Value::String("norcal".to_owned()),
        ]))
    );
    assert_eq!(
        sf.fields.get("blob"),
        Some(&Value::Bytes(vec![0, 1, 2, 253, 254, 255]))
    );
    assert_eq!(
        sf.fields.get("ref"),
        Some(&Value::Reference(
            "projects/demo-export/databases/(default)/documents/cities/LA".to_owned()
        ))
    );
    let Some(Value::GeoPoint(point)) = sf.fields.get("location") else {
        panic!("the location is a geo point");
    };
    assert!((point.latitude() - 37.7749).abs() < 1e-9);
    assert!((point.longitude() + 122.4194).abs() < 1e-9);
    let Some(Value::Timestamp(founded)) = sf.fields.get("founded") else {
        panic!("the founding date is a timestamp");
    };
    assert_eq!(founded.seconds(), 1_700_000_000);

    let mut deep = BTreeMap::new();
    deep.insert("c".to_owned(), Value::String("deep".to_owned()));
    deep.insert(
        "d".to_owned(),
        Value::Array(vec![
            Value::Integer(1),
            Value::String("two".to_owned()),
            Value::Boolean(true),
        ]),
    );
    let mut nested = BTreeMap::new();
    nested.insert("a".to_owned(), Value::Integer(1));
    nested.insert("b".to_owned(), Value::Map(deep));
    assert_eq!(sf.fields.get("nested"), Some(&Value::Map(nested)));

    // A subcollection under a document that exists, and a bulk collection.
    assert!(docs
        .iter()
        .any(|d| d.relative_path() == "cities/SF/landmarks/golden-gate"));
    assert_eq!(
        docs.iter()
            .filter(|d| d.path.first().map(|(c, _)| c.as_str()) == Some("bulk"))
            .count(),
        25
    );
    let empty = docs
        .iter()
        .find(|d| d.relative_path() == "empty-ish/only-doc")
        .expect("the field-less document");
    assert!(empty.fields.is_empty());
}

#[test]
fn the_recorded_value_corpus_decodes_every_edge_case_the_official_emulator_writes() {
    let docs = documents("official-firestore-values");
    let by_id = |id: &str| {
        docs.iter()
            .find(|d| d.relative_path() == format!("edge/{id}"))
            .unwrap_or_else(|| panic!("the {id} document"))
            .clone()
    };

    assert!(by_id("empty-doc").fields.is_empty());

    let empty_array = by_id("empty-array");
    assert_eq!(
        empty_array.fields.get("arr"),
        Some(&Value::Array(Vec::new())),
        "an empty array is written as an indexed EMPTY_LIST property"
    );
    assert_eq!(empty_array.fields.get("other"), Some(&Value::Integer(1)));

    let empty_map = by_id("empty-map");
    assert_eq!(
        empty_map.fields.get("m"),
        Some(&Value::Map(BTreeMap::new()))
    );

    let specials = by_id("specials");
    let Some(Value::Double(nan)) = specials.fields.get("nan") else {
        panic!("NaN stays a double");
    };
    assert!(nan.is_nan());
    assert_eq!(
        specials.fields.get("inf"),
        Some(&Value::Double(f64::INFINITY))
    );
    assert_eq!(
        specials.fields.get("ninf"),
        Some(&Value::Double(f64::NEG_INFINITY))
    );
    assert_eq!(specials.fields.get("zero"), Some(&Value::Integer(0)));
    let Some(Value::Double(negative_zero)) = specials.fields.get("negzero") else {
        panic!("negative zero stays a double");
    };
    assert!(negative_zero.is_sign_negative() && *negative_zero == 0.0);
    assert_eq!(
        specials.fields.get("maxint"),
        Some(&Value::Integer(9_007_199_254_740_991))
    );
    assert_eq!(
        specials.fields.get("minint"),
        Some(&Value::Integer(-9_007_199_254_740_991))
    );
    assert_eq!(
        specials.fields.get("emptystring"),
        Some(&Value::String(String::new()))
    );

    let times = by_id("times");
    let Some(Value::Timestamp(precise)) = times.fields.get("precise") else {
        panic!("a timestamp stays a timestamp");
    };
    assert_eq!(
        (precise.seconds(), precise.nanos()),
        (1_700_000_000, 123_456_000)
    );
    let Some(Value::Timestamp(epoch)) = times.fields.get("epoch") else {
        panic!("the epoch stays a timestamp");
    };
    assert_eq!((epoch.seconds(), epoch.nanos()), (0, 0));

    assert_eq!(
        by_id("emptybytes").fields.get("b"),
        Some(&Value::Bytes(Vec::new()))
    );

    let nested = by_id("nested-arrays");
    let Some(Value::Array(items)) = nested.fields.get("arr") else {
        panic!("an array of maps stays an array");
    };
    assert_eq!(items.len(), 2);
    assert!(matches!(items[0], Value::Map(_)));

    let deep = docs
        .iter()
        .find(|d| d.relative_path() == "edge/deep/a/1/b/2/c/3")
        .expect("the deeply nested document");
    assert_eq!(deep.fields.get("leaf"), Some(&Value::Boolean(true)));
}

#[test]
fn every_document_the_official_emulator_wrote_survives_a_fireemu_re_encode() {
    // The round trip the format exists for: a document decoded from the emulator's own
    // bytes, encoded again by fireemu and decoded once more is the same document. The
    // comparison goes through `Debug` because a NaN field is never equal to itself and the
    // recorded corpus deliberately holds one.
    for dir in ["official-multiproduct", "official-firestore-values"] {
        for document in documents(dir) {
            let re_encoded = fireemu_core_export::firestore::write_entity(&document)
                .expect("the official document re-encodes");
            let decoded = fireemu_core_export::firestore::read_entity(&re_encoded)
                .expect("the re-encoded entity decodes");
            assert_eq!(
                format!("{decoded:?}"),
                format!("{document:?}"),
                "the document {} of {dir} survives a re-encode",
                document.relative_path()
            );
        }
    }
}

#[test]
fn a_written_output_file_is_read_back_by_the_reader_that_reads_the_official_one() {
    let docs = documents("official-multiproduct");
    let written = write_output(&docs).expect("the output encodes");
    assert_eq!(
        format!("{:?}", read_output(&written).expect("it decodes")),
        format!("{docs:?}")
    );
}

#[test]
fn a_corrupted_official_output_file_is_refused_rather_than_read_short() {
    let mut bytes =
        read("official-multiproduct/firestore_export/all_namespaces/all_kinds/output-0");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    assert!(read_output(&bytes).is_err());
}
