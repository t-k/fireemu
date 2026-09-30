//! Owner-only cache for the deterministic Auth session RSA key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fireemu_adapter_http::signing::RsaSigner;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use fireemu_core_types::hash::{hex_lower, sha256};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use zeroize::Zeroizing;

#[cfg(any(target_os = "linux", target_os = "macos"))]
const CACHE_MAGIC: &[u8; 16] = b"fireemu-rsa-v1\0\0";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CACHE_DOMAIN: &[u8] = b"fireemu/session-rsa/chacha20-rsa2048-e65537/v1\0";
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
const CACHE_MAX_BYTES: u64 = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const CACHE_MAX_BYTES_USIZE: usize = 64 * 1024;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MANAGED_DIRECTORIES: [&str; 3] = ["fireemu", "session-rsa", "v1"];

/// A session signer and whether it came from a validated cache entry.
struct CachedSessionSigner {
    /// The Auth-only deterministic signer.
    signer: Arc<RsaSigner>,
    /// `true` only when an existing entry passed every validation step.
    #[cfg(test)]
    hit: bool,
}

#[derive(Clone, Copy)]
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
struct CacheFileMetadata {
    regular: bool,
    owner: u32,
    mode: u32,
    links: u64,
    size: u64,
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
fn secure_file_metadata(metadata: CacheFileMetadata, effective_uid: u32) -> bool {
    metadata.regular
        && metadata.owner == effective_uid
        && metadata.mode & 0o7777 == 0o600
        && metadata.links == 1
        && metadata.size <= CACHE_MAX_BYTES
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn seed_digest(seed: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(CACHE_DOMAIN.len() + 8);
    input.extend_from_slice(CACHE_DOMAIN);
    input.extend_from_slice(&seed.to_be_bytes());
    sha256(&input)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn entry_name(seed: u64) -> String {
    format!("{}-rsa2048-e65537.pk8", hex_lower(&seed_digest(seed)))
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn cache_entry_path(root: &Path, seed: u64) -> PathBuf {
    MANAGED_DIRECTORIES
        .iter()
        .fold(root.to_owned(), |path, component| path.join(component))
        .join(entry_name(seed))
}

fn absolute_path(value: Option<std::ffi::OsString>) -> Option<PathBuf> {
    let path = PathBuf::from(value?);
    (!path.as_os_str().is_empty() && path.is_absolute()).then_some(path)
}

fn cache_base_for(
    home: Option<std::ffi::OsString>,
    xdg_cache_home: Option<std::ffi::OsString>,
    local_app_data: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let _ = (xdg_cache_home, local_app_data);
        return absolute_path(home).map(|home| home.join("Library/Caches"));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        drop(local_app_data);
        return absolute_path(xdg_cache_home)
            .or_else(|| absolute_path(home).map(|home| home.join(".cache")));
    }
    #[cfg(windows)]
    {
        let _ = (home, xdg_cache_home);
        return absolute_path(local_app_data);
    }
    #[allow(unreachable_code)]
    None
}

fn default_cache_base() -> Option<PathBuf> {
    cache_base_for(
        std::env::var_os("HOME"),
        std::env::var_os("XDG_CACHE_HOME"),
        std::env::var_os("LOCALAPPDATA"),
    )
}

/// Loads or creates the deterministic Auth session signer without exposing cache material.
///
/// Cache access is an optimization. An absent, unavailable, or invalid cache falls back to
/// deterministic in-memory generation without modifying an unsafe existing entry.
pub fn load_or_generate(seed: u64) -> Result<Arc<RsaSigner>, String> {
    let Some(root) = default_cache_base() else {
        return generate(seed).map(|generated| generated.signer);
    };
    load_or_generate_at(&root, seed).map(|generated| generated.signer)
}

fn generate(seed: u64) -> Result<CachedSessionSigner, String> {
    Ok(CachedSessionSigner {
        signer: RsaSigner::from_seed(seed)?,
        #[cfg(test)]
        hit: false,
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_or_generate_at(root: &Path, seed: u64) -> Result<CachedSessionSigner, String> {
    let Ok(directory) = open_cache_directory(root) else {
        return generate(seed);
    };
    let name = entry_name(seed);
    match load_entry(&directory, &name, seed) {
        EntryLoad::Hit(signer) => Ok(CachedSessionSigner {
            signer,
            #[cfg(test)]
            hit: true,
        }),
        EntryLoad::UnsafeOrInvalid => generate(seed),
        EntryLoad::Missing => {
            let generated = generate(seed)?;
            if let Ok(document) = generated.signer.to_pkcs8_der() {
                let envelope = encode_envelope(seed, document.as_bytes());
                publish_entry(&directory, &name, seed, &envelope);
            }
            Ok(generated)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn load_or_generate_at(_root: &Path, seed: u64) -> Result<CachedSessionSigner, String> {
    generate(seed)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn encode_envelope(seed: u64, der: &[u8]) -> Zeroizing<Vec<u8>> {
    let digest = seed_digest(seed);
    let Ok(length) = u32::try_from(der.len()) else {
        return Zeroizing::new(Vec::new());
    };
    let mut envelope = Zeroizing::new(Vec::with_capacity(
        CACHE_MAGIC.len() + digest.len() + 4 + der.len() + 32,
    ));
    envelope.extend_from_slice(CACHE_MAGIC);
    envelope.extend_from_slice(&digest);
    envelope.extend_from_slice(&length.to_be_bytes());
    envelope.extend_from_slice(der);
    let binding = sha256(&envelope);
    envelope.extend_from_slice(&binding);
    envelope
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn decode_envelope(seed: u64, envelope: &[u8]) -> Result<Arc<RsaSigner>, ()> {
    const PREFIX: usize = 16 + 32 + 4;
    const SUFFIX: usize = 32;
    if envelope.len() < PREFIX + SUFFIX || envelope.len() > CACHE_MAX_BYTES_USIZE {
        return Err(());
    }
    if &envelope[..16] != CACHE_MAGIC || envelope[16..48] != seed_digest(seed) {
        return Err(());
    }
    let der_len = u32::from_be_bytes(envelope[48..52].try_into().map_err(|_| ())?) as usize;
    let expected = PREFIX
        .checked_add(der_len)
        .and_then(|n| n.checked_add(SUFFIX));
    if expected != Some(envelope.len()) {
        return Err(());
    }
    let binding_start = PREFIX + der_len;
    if sha256(&envelope[..binding_start]) != envelope[binding_start..] {
        return Err(());
    }
    RsaSigner::from_pkcs8_der(&envelope[PREFIX..binding_start]).map_err(|_| ())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_cache_directory(root: &Path) -> Result<std::fs::File, ()> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let descriptor = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let mut directory = std::fs::File::from(descriptor);
    let base = directory.metadata().map_err(|_| ())?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !base.file_type().is_dir() || base.uid() != effective_uid || base.mode() & 0o022 != 0 {
        return Err(());
    }
    for component in MANAGED_DIRECTORIES {
        match rustix::fs::mkdirat(&directory, component, Mode::RWXU) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(()),
        }
        let descriptor = rustix::fs::openat(
            &directory,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ())?;
        let child = std::fs::File::from(descriptor);
        let metadata = child.metadata().map_err(|_| ())?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != effective_uid
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(());
        }
        #[cfg(target_os = "macos")]
        reject_extended_acl(&child)?;
        directory = child;
    }
    Ok(directory)
}

/// Answers whether the ACL of an opened directory or file has entries.
#[cfg(target_os = "macos")]
type AclReader = fn(std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool>;

/// Accepts an opened cache directory or entry only when its ACL is known to have no entries.
///
/// The cache holds session signing keys, so an ACL entry, which can grant other users
/// access that the owner-only mode does not show, keeps the cache unused. A read that fails
/// refuses the file too, and the caller then generates the key in memory.
///
/// The ACL is read through the opened descriptor (`acl_get_fd_np`), never by path. Reading
/// `/dev/fd/N` by path does not work: Darwin answers `ENOENT` for every descriptor, even when
/// the file has ACL entries, and a reader that takes that for an empty ACL never detects an
/// entry.
#[cfg(target_os = "macos")]
fn reject_extended_acl(file: &std::fs::File) -> Result<(), ()> {
    use std::os::fd::AsFd as _;

    match acl_reader()(file.as_fd()) {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(()),
    }
}

#[cfg(target_os = "macos")]
fn acl_reader() -> AclReader {
    #[cfg(test)]
    if let Some(reader) = tests::ACL_READER.with(std::cell::Cell::get) {
        return reader;
    }
    fireemu_fd_acl::fd_has_extended_acl
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
enum EntryLoad {
    Missing,
    UnsafeOrInvalid,
    Hit(Arc<RsaSigner>),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_entry(directory: &std::fs::File, name: &str, seed: u64) -> EntryLoad {
    use rustix::fs::{Mode, OFlags};
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    let descriptor = match rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return EntryLoad::Missing,
        Err(_) => return EntryLoad::UnsafeOrInvalid,
    };
    let file = std::fs::File::from(descriptor);
    let Ok(metadata) = file.metadata() else {
        return EntryLoad::UnsafeOrInvalid;
    };
    let actual = CacheFileMetadata {
        regular: metadata.file_type().is_file(),
        owner: metadata.uid(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        size: metadata.len(),
    };
    if !secure_file_metadata(actual, rustix::process::geteuid().as_raw()) {
        return EntryLoad::UnsafeOrInvalid;
    }
    #[cfg(target_os = "macos")]
    if reject_extended_acl(&file).is_err() {
        return EntryLoad::UnsafeOrInvalid;
    }
    let capacity = usize::try_from(actual.size).unwrap_or(0);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    if file
        .take(CACHE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 != actual.size
    {
        return EntryLoad::UnsafeOrInvalid;
    }
    decode_envelope(seed, &bytes)
        .map(EntryLoad::Hit)
        .unwrap_or(EntryLoad::UnsafeOrInvalid)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish_entry(directory: &std::fs::File, name: &str, seed: u64, envelope: &[u8]) {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
    use std::io::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    for _ in 0..32 {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".session-rsa-{}-{sequence}.tmp", std::process::id());
        let descriptor = match rustix::fs::openat(
            directory,
            &temporary,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::EXIST) => continue,
            Err(_) => return,
        };
        let mut file = std::fs::File::from(descriptor);
        let Ok(metadata) = file.metadata() else {
            let _ = rustix::fs::unlinkat(directory, &temporary, AtFlags::empty());
            return;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let actual = CacheFileMetadata {
                regular: metadata.file_type().is_file(),
                owner: metadata.uid(),
                mode: metadata.mode(),
                links: metadata.nlink(),
                size: envelope.len() as u64,
            };
            if !secure_file_metadata(actual, rustix::process::geteuid().as_raw()) {
                let _ = rustix::fs::unlinkat(directory, &temporary, AtFlags::empty());
                return;
            }
        }
        let written = file.write_all(envelope).and_then(|()| file.sync_all());
        if written.is_err() {
            let _ = rustix::fs::unlinkat(directory, &temporary, AtFlags::empty());
            return;
        }
        let published = rustix::fs::renameat_with(
            directory,
            &temporary,
            directory,
            name,
            RenameFlags::NOREPLACE,
        );
        if published.is_ok() {
            let _ = rustix::fs::fsync(directory);
        } else {
            let _ = rustix::fs::unlinkat(directory, &temporary, AtFlags::empty());
            let _ = load_entry(directory, name, seed);
        }
        return;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(unix))]
    use std::sync::atomic::{AtomicU64, Ordering};

    use fireemu_core_auth::jwt::IdTokenSigner as _;

    use super::{cache_base_for, load_or_generate_at, secure_file_metadata, CacheFileMetadata};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{cache_entry_path, entry_name, load_entry, open_cache_directory, EntryLoad};
    #[cfg(unix)]
    use crate::import_export::trusted_temp::TrustedTempDir;

    #[cfg(target_os = "macos")]
    thread_local! {
        /// A test's replacement for the descriptor ACL reader, on the calling thread only.
        pub(super) static ACL_READER: std::cell::Cell<Option<super::AclReader>> =
            const { std::cell::Cell::new(None) };
    }

    /// Runs `body` with `reader` in place of the descriptor ACL reader on this thread.
    #[cfg(target_os = "macos")]
    fn with_acl_reader<T>(reader: super::AclReader, body: impl FnOnce() -> T) -> T {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                ACL_READER.with(|slot| slot.set(None));
            }
        }
        ACL_READER.with(|slot| slot.set(Some(reader)));
        let _restore = Restore;
        body()
    }

    /// A reader that fails for every descriptor.
    #[cfg(target_os = "macos")]
    fn unreadable_acl(_: std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool> {
        Err(std::io::Error::other("ACL read failed"))
    }

    /// A reader that fails for regular files and reports no entries for directories.
    #[cfg(target_os = "macos")]
    fn unreadable_file_acl(descriptor: std::os::fd::BorrowedFd<'_>) -> std::io::Result<bool> {
        let stat = rustix::fs::fstat(descriptor)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) == rustix::fs::FileType::RegularFile {
            Err(std::io::Error::other("ACL read failed"))
        } else {
            Ok(false)
        }
    }

    #[cfg(unix)]
    fn scratch(name: &str) -> TrustedTempDir {
        TrustedTempDir::new(&format!("session-rsa-cache-{name}"))
    }

    #[cfg(not(unix))]
    fn scratch(name: &str) -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fireemu-session-rsa-cache-{name}-{}-{sequence}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn cache_base_requires_an_absolute_nonempty_environment_path() {
        let absolute_home =
            std::path::PathBuf::from(std::path::MAIN_SEPARATOR_STR).join("home/test");
        #[cfg(all(unix, not(target_os = "macos")))]
        let absolute_xdg = std::path::PathBuf::from(std::path::MAIN_SEPARATOR_STR).join("cache");

        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                cache_base_for(Some(absolute_home.clone().into()), None, None),
                Some(absolute_home.join("Library/Caches"))
            );
            for home in [None, Some("".into()), Some("relative".into())] {
                assert_eq!(cache_base_for(home, None, None), None);
            }
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            assert_eq!(
                cache_base_for(
                    Some(absolute_home.clone().into()),
                    Some(absolute_xdg.clone().into()),
                    None,
                ),
                Some(absolute_xdg)
            );
            assert_eq!(
                cache_base_for(
                    Some(absolute_home.clone().into()),
                    Some("relative".into()),
                    None,
                ),
                Some(absolute_home.join(".cache"))
            );
            for home in [None, Some("".into()), Some("relative".into())] {
                assert_eq!(cache_base_for(home, Some("relative".into()), None), None);
            }
        }
        #[cfg(windows)]
        {
            let _ = absolute_home;
            for local in [None, Some("".into()), Some("relative".into())] {
                assert_eq!(cache_base_for(None, None, local), None);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn a_cache_miss_publishes_one_owner_only_entry_and_the_next_load_hits_it() {
        let root = scratch("hit");
        let first = load_or_generate_at(&root, 7).unwrap();
        assert!(!first.hit);
        let second = load_or_generate_at(&root, 7).unwrap();
        assert!(second.hit);
        assert_eq!(first.signer.kid(), second.signer.kid());
        let entry = cache_entry_path(&root, 7);
        let metadata = std::fs::metadata(entry).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn unsupported_cache_platforms_generate_without_publishing_or_claiming_hits() {
        let root = scratch("no-persistent-cache");
        let first = load_or_generate_at(&root, 7).unwrap();
        let second = load_or_generate_at(&root, 7).unwrap();
        assert!(!first.hit);
        assert!(!second.hit);
        assert_eq!(first.signer.kid(), second.signer.kid());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    #[ignore = "release-only warm-start performance gate"]
    fn a_warm_cache_adds_less_than_five_milliseconds_to_startup() {
        let root = scratch("warm-performance");
        let first = load_or_generate_at(&root, 0x5eed).unwrap();
        assert!(!first.hit);
        let mut samples = (0..21)
            .map(|_| {
                let started = std::time::Instant::now();
                let cached = load_or_generate_at(&root, 0x5eed).unwrap();
                assert!(cached.hit);
                std::hint::black_box(cached.signer);
                started.elapsed()
            })
            .collect::<Vec<_>>();
        samples.sort_unstable();
        let median = samples[samples.len() / 2];
        eprintln!("warm session RSA cache median: {median:?}");
        assert!(
            median < std::time::Duration::from_millis(5),
            "warm session RSA cache added {median:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn scratch_cache_bases_are_owner_only() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = scratch("owner-only-base");
        let metadata = std::fs::symlink_metadata(&root).unwrap();
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn an_unsafe_cache_base_is_refused_without_modification() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = scratch("unsafe-base");
        let sentinel = root.join("sentinel");
        std::fs::write(&sentinel, b"unchanged").unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o775)).unwrap();

        let result = load_or_generate_at(&root, 70).unwrap();
        assert!(!result.hit);
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        assert!(!root.join("fireemu").exists());

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn an_unsafe_existing_entry_is_ignored_and_never_replaced() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = scratch("unsafe");
        let first = load_or_generate_at(&root, 8).unwrap();
        let entry = cache_entry_path(&root, 8);
        let original = std::fs::read(&entry).unwrap();
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o644)).unwrap();

        let uncached = load_or_generate_at(&root, 8).unwrap();
        assert!(!uncached.hit);
        assert_eq!(first.signer.kid(), uncached.signer.kid());
        assert_eq!(std::fs::read(&entry).unwrap(), original);
        assert_eq!(
            std::fs::metadata(&entry).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_entry_is_ignored_without_touching_its_victim() {
        let root = scratch("symlink");
        let _ = load_or_generate_at(&root, 9).unwrap();
        let entry = cache_entry_path(&root, 9);
        std::fs::remove_file(&entry).unwrap();
        let victim = root.join("victim");
        std::fs::write(&victim, b"must stay unchanged").unwrap();
        std::os::unix::fs::symlink(&victim, &entry).unwrap();

        let result = load_or_generate_at(&root, 9).unwrap();
        assert!(!result.hit);
        assert_eq!(std::fs::read(victim).unwrap(), b"must stay unchanged");
        assert!(std::fs::symlink_metadata(entry)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_hard_linked_and_wrong_seed_entries_are_left_untouched() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = scratch("invalid");
        let _ = load_or_generate_at(&root, 10).unwrap();
        let entry = cache_entry_path(&root, 10);

        std::fs::write(&entry, b"corrupt cache entry").unwrap();
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
        let corrupt = std::fs::read(&entry).unwrap();
        assert!(!load_or_generate_at(&root, 10).unwrap().hit);
        assert_eq!(std::fs::read(&entry).unwrap(), corrupt);

        std::fs::remove_file(&entry).unwrap();
        let _ = load_or_generate_at(&root, 10).unwrap();
        let alias = root.join("hard-link-alias");
        std::fs::hard_link(&entry, &alias).unwrap();
        assert!(!load_or_generate_at(&root, 10).unwrap().hit);
        assert_eq!(std::fs::metadata(&entry).unwrap().nlink(), 2);
        std::fs::remove_file(alias).unwrap();

        let _ = load_or_generate_at(&root, 11).unwrap();
        let other = cache_entry_path(&root, 11);
        let foreign = std::fs::read(other).unwrap();
        std::fs::remove_file(&entry).unwrap();
        std::fs::write(&entry, &foreign).unwrap();
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!load_or_generate_at(&root, 10).unwrap().hit);
        assert_eq!(std::fs::read(&entry).unwrap(), foreign);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_entry_is_rejected_without_blocking() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = scratch("fifo");
        let _ = load_or_generate_at(&root, 12).unwrap();
        let entry = cache_entry_path(&root, 12);
        std::fs::remove_file(&entry).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(&entry)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::set_permissions(&entry, std::fs::Permissions::from_mode(0o600)).unwrap();

        let directory = open_cache_directory(&root).unwrap();
        let started = std::time::Instant::now();
        assert!(matches!(
            load_entry(&directory, &entry_name(12), 12),
            EntryLoad::UnsafeOrInvalid
        ));
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn concurrent_misses_publish_one_complete_entry() {
        let root = scratch("concurrent");
        let root_path = root.path().to_path_buf();
        let workers = (0..4)
            .map(|_| {
                let root = root_path.clone();
                std::thread::spawn(move || {
                    load_or_generate_at(&root, 13)
                        .unwrap()
                        .signer
                        .kid()
                        .to_owned()
                })
            })
            .collect::<Vec<_>>();
        let kids = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert!(kids.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(load_or_generate_at(&root, 13).unwrap().hit);
        let directory = cache_entry_path(&root, 13).parent().unwrap().to_owned();
        let entries = std::fs::read_dir(directory)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Adds one ACL entry to `path` with the system `chmod`.
    #[cfg(target_os = "macos")]
    fn add_acl_entry(path: &std::path::Path, entry: &str) {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(entry)
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "chmod +a {entry:?} {}", path.display());
    }

    /// Removes every ACL entry below and including `path`.
    #[cfg(target_os = "macos")]
    fn clear_acl_entries(path: &std::path::Path) {
        let status = std::process::Command::new("/bin/chmod")
            .arg("-RN")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "chmod -RN {}", path.display());
    }

    /// The `ls -led` listing of `path`, which names its ACL entries.
    #[cfg(target_os = "macos")]
    fn acl_listing(path: &std::path::Path) -> String {
        let output = std::process::Command::new("/bin/ls")
            .arg("-led")
            .arg(path)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_managed_directory_with_an_acl_entry_is_refused() {
        for depth in 1..=super::MANAGED_DIRECTORIES.len() {
            let root = scratch("acl-directory");
            let seed = 20 + depth as u64;
            assert!(!load_or_generate_at(&root, seed).unwrap().hit);
            assert!(load_or_generate_at(&root, seed).unwrap().hit);
            let entry = cache_entry_path(&root, seed);
            let original = std::fs::read(&entry).unwrap();
            let managed = super::MANAGED_DIRECTORIES[..depth]
                .iter()
                .fold(root.to_path_buf(), |path, component| path.join(component));
            add_acl_entry(&managed, "everyone allow read");
            assert!(acl_listing(&managed).contains("everyone allow"));

            assert!(
                open_cache_directory(&root).is_err(),
                "{} carries an ACL entry",
                managed.display()
            );
            let uncached = load_or_generate_at(&root, seed).unwrap();
            assert!(!uncached.hit, "{} carries an ACL entry", managed.display());
            assert_eq!(std::fs::read(&entry).unwrap(), original);

            clear_acl_entries(&root);
            assert!(load_or_generate_at(&root, seed).unwrap().hit);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_entry_file_with_an_acl_entry_is_refused_and_left_untouched() {
        let root = scratch("acl-entry");
        let first = load_or_generate_at(&root, 24).unwrap();
        assert!(!first.hit);
        assert!(load_or_generate_at(&root, 24).unwrap().hit);
        let entry = cache_entry_path(&root, 24);
        let original = std::fs::read(&entry).unwrap();
        add_acl_entry(&entry, "everyone allow read");

        let directory = open_cache_directory(&root).unwrap();
        assert!(matches!(
            load_entry(&directory, &entry_name(24), 24),
            EntryLoad::UnsafeOrInvalid
        ));
        let uncached = load_or_generate_at(&root, 24).unwrap();
        assert!(!uncached.hit);
        assert_eq!(first.signer.kid(), uncached.signer.kid());
        assert_eq!(std::fs::read(&entry).unwrap(), original);
        assert!(acl_listing(&entry).contains("everyone allow read"));

        clear_acl_entries(&root);
        assert!(load_or_generate_at(&root, 24).unwrap().hit);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inheritable_acl_entries_on_the_cache_base_keep_the_cache_unused() {
        let root = scratch("acl-inherited");
        add_acl_entry(
            &root,
            "everyone allow list,search,add_file,add_subdirectory,read,write,file_inherit,directory_inherit",
        );

        let first = load_or_generate_at(&root, 25).unwrap();
        assert!(!first.hit);
        let second = load_or_generate_at(&root, 25).unwrap();
        assert!(!second.hit);
        assert_eq!(first.signer.kid(), second.signer.kid());
        assert!(!cache_entry_path(&root, 25).exists());

        clear_acl_entries(&root);
        assert!(!load_or_generate_at(&root, 25).unwrap().hit);
        assert!(load_or_generate_at(&root, 25).unwrap().hit);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_unreadable_directory_acl_keeps_the_cache_unused() {
        let root = scratch("acl-unreadable-directory");
        with_acl_reader(unreadable_acl, || {
            assert!(open_cache_directory(&root).is_err());
            let first = load_or_generate_at(&root, 26).unwrap();
            assert!(!first.hit);
            let second = load_or_generate_at(&root, 26).unwrap();
            assert!(!second.hit);
            assert_eq!(first.signer.kid(), second.signer.kid());
        });
        assert!(!cache_entry_path(&root, 26).exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_unreadable_entry_acl_refuses_the_entry_without_touching_it() {
        let root = scratch("acl-unreadable-entry");
        let first = load_or_generate_at(&root, 27).unwrap();
        assert!(load_or_generate_at(&root, 27).unwrap().hit);
        let entry = cache_entry_path(&root, 27);
        let original = std::fs::read(&entry).unwrap();

        with_acl_reader(unreadable_file_acl, || {
            let directory = open_cache_directory(&root).unwrap();
            assert!(matches!(
                load_entry(&directory, &entry_name(27), 27),
                EntryLoad::UnsafeOrInvalid
            ));
            let uncached = load_or_generate_at(&root, 27).unwrap();
            assert!(!uncached.hit);
            assert_eq!(first.signer.kid(), uncached.signer.kid());
        });
        assert_eq!(std::fs::read(&entry).unwrap(), original);
        assert!(load_or_generate_at(&root, 27).unwrap().hit);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn opened_file_metadata_must_match_the_owner_only_contract() {
        let valid = CacheFileMetadata {
            regular: true,
            owner: 501,
            mode: 0o600,
            links: 1,
            size: 1_300,
        };
        assert!(secure_file_metadata(valid, 501));
        assert!(!secure_file_metadata(
            CacheFileMetadata {
                owner: 502,
                ..valid
            },
            501
        ));
        assert!(!secure_file_metadata(
            CacheFileMetadata {
                mode: 0o640,
                ..valid
            },
            501
        ));
        assert!(!secure_file_metadata(
            CacheFileMetadata { links: 2, ..valid },
            501
        ));
        assert!(!secure_file_metadata(
            CacheFileMetadata {
                regular: false,
                ..valid
            },
            501
        ));
    }
}
