//! Integration tests for spill files.

use std::fs;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicU64, Ordering};

use fireemu_core_storage::spill::SpillDir;
use fireemu_core_storage::store::ObjectDigests;
use proptest::prelude::*;

#[test]
fn creates_missing_directory_and_empty_file() {
    let dir = std::env::temp_dir().join(format!("spill-create-{}", std::process::id()));
    let spill_dir = SpillDir::new(&dir);
    assert!(!dir.exists());
    let file = spill_dir.create_file().unwrap();
    assert!(file.path().is_file());
    assert_eq!(file.len(), 0);
    assert!(file.is_empty());
    drop(file);
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn appends_in_order() {
    let dir = std::env::temp_dir().join(format!("spill-append-{}", std::process::id()));
    let mut file = SpillDir::new(&dir).create_file().unwrap();
    for bytes in [b"first".as_slice(), b"", b"second"] {
        file.append(bytes).unwrap();
    }
    assert_eq!(file.len(), 11);
    assert!(!file.is_empty());
    assert_eq!(file.read_all().unwrap(), b"firstsecond");
    drop(file);
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn reads_ranges_and_rejects_out_of_bounds() {
    let dir = std::env::temp_dir().join(format!("spill-range-{}", std::process::id()));
    let mut file = SpillDir::new(&dir).create_file().unwrap();
    file.append(b"abcdefghij").unwrap();
    assert_eq!(file.read_range(0, 3).unwrap(), b"abc");
    assert_eq!(file.read_range(3, 4).unwrap(), b"defg");
    assert_eq!(file.read_range(7, 3).unwrap(), b"hij");
    assert!(matches!(
        file.read_range(9, 2).unwrap_err().kind(),
        ErrorKind::UnexpectedEof | ErrorKind::InvalidInput
    ));
    assert!(matches!(
        file.read_range(u64::MAX, 2).unwrap_err().kind(),
        ErrorKind::UnexpectedEof | ErrorKind::InvalidInput
    ));
    assert_eq!(file.read_all().unwrap(), b"abcdefghij");
    drop(file);
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn digests_match_at_chunk_boundaries() {
    let dir = std::env::temp_dir().join(format!("spill-digest-{}", std::process::id()));
    let spill_dir = SpillDir::new(&dir);
    for size in [0, 1, 65_535, 65_536, 65_537, 200_000] {
        let bytes: Vec<u8> = (0..size).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let mut file = spill_dir.create_file().unwrap();
        file.append(&bytes).unwrap();
        assert_eq!(file.digests().unwrap(), ObjectDigests::new(&bytes));
    }
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn drop_removes_only_the_file() {
    let dir = std::env::temp_dir().join(format!("spill-drop-{}", std::process::id()));
    let file = SpillDir::new(&dir).create_file().unwrap();
    let path = file.path().to_owned();
    let debug = format!("{file:?}");
    assert!(!debug.contains(&dir.to_string_lossy().to_string()));
    assert!(debug.contains(path.file_name().unwrap().to_str().unwrap()));
    drop(file);
    assert!(!path.exists());
    assert!(dir.is_dir());
    fs::remove_dir(&dir).unwrap();
}

#[test]
fn files_have_distinct_paths() {
    let dir = std::env::temp_dir().join(format!("spill-unique-{}", std::process::id()));
    let spill_dir = SpillDir::new(&dir);
    let first = spill_dir.create_file().unwrap();
    let second = spill_dir.create_file().unwrap();
    assert_ne!(first.path(), second.path());
    drop((first, second));
    fs::remove_dir(&dir).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn random_chunks_and_ranges(chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..=70_000), 0..=16), start in any::<usize>(), length in any::<usize>()) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!("spill-property-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut file = SpillDir::new(&dir).create_file().unwrap();
        let mut expected = Vec::new();
        for chunk in chunks {
            file.append(&chunk).unwrap();
            expected.extend_from_slice(&chunk);
        }
        let start = start % (expected.len() + 1);
        let length = length % (expected.len() - start + 1);
        let actual = file.read_all().unwrap();
        let range = file.read_range(start as u64, length).unwrap();
        drop(file);
        fs::remove_dir(&dir).unwrap();
        prop_assert_eq!(&actual, &expected);
        prop_assert_eq!(range.as_slice(), &expected[start..start + length]);
    }
}

#[cfg(unix)]
#[test]
fn reads_from_original_handle_after_directory_replacement() {
    use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
    let root = std::env::temp_dir().join(format!("spill-replaced-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let dir = root.join("dir");
    let moved = root.join("moved");
    let other = root.join("other");
    let mut file = SpillDir::new(&dir).create_file().unwrap();
    file.append(b"original").unwrap();
    fs::rename(&dir, &moved).unwrap();
    fs::create_dir(&other).unwrap();
    fs::write(other.join(file.path().file_name().unwrap()), b"intruder").unwrap();
    symlink(&other, &dir).unwrap();
    assert_eq!(file.read_all().unwrap(), b"original");
    assert!(file.append(b"x").is_err());
    drop(file);
    fs::remove_dir_all(root).unwrap();
}
