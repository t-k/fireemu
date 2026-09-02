use std::ffi::{OsStr, OsString};
use std::ops::Deref;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_NAMESPACE: AtomicU64 = AtomicU64::new(0);

pub struct TrustedTempDir {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl TrustedTempDir {
    pub fn new(label: &str) -> Self {
        let base = trusted_user_base();
        let suite = base.join(".fireemu-test-runtime");
        create_or_validate_private_dir(&suite);

        loop {
            let nonce = NEXT_NAMESPACE.fetch_add(1, Ordering::Relaxed);
            let path = suite.join(format!("{label}-{}-{nonce}", std::process::id()));
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    let metadata =
                        std::fs::symlink_metadata(&path).expect("inspect test namespace");
                    return Self {
                        path,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create trusted test namespace: {error}"),
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Deref for TrustedTempDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl AsRef<Path> for TrustedTempDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl AsRef<OsStr> for TrustedTempDir {
    fn as_ref(&self) -> &OsStr {
        self.path.as_os_str()
    }
}

impl Drop for TrustedTempDir {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.dev() == self.device && metadata.ino() == self.inode {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn create_or_validate_private_dir(path: &Path) {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("create trusted test base: {error}"),
    }

    let metadata = std::fs::symlink_metadata(path).expect("inspect trusted test base");
    assert!(
        metadata.file_type().is_dir(),
        "trusted test base must be a directory"
    );
    assert_eq!(
        metadata.uid(),
        rustix::process::geteuid().as_raw(),
        "trusted test base must be owned by the current user"
    );
    assert_eq!(
        metadata.mode() & 0o077,
        0,
        "trusted test base must be owner-only"
    );
}

fn trusted_user_base() -> PathBuf {
    for candidate in trusted_user_base_candidates() {
        let Ok(canonical) = std::fs::canonicalize(candidate) else {
            continue;
        };
        if trusted_ancestor_chain(&canonical) {
            return canonical;
        }
    }
    panic!("no trusted per-user test namespace is available; set XDG_RUNTIME_DIR or HOME to a safe directory");
}

#[cfg(target_os = "macos")]
fn trusted_user_base_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(output) = std::process::Command::new("getconf")
        .arg("DARWIN_USER_TEMP_DIR")
        .output()
    {
        if output.status.success() {
            if let Ok(path) = String::from_utf8(output.stdout) {
                candidates.push(PathBuf::from(path.trim()));
            }
        }
    }
    candidates.extend(environment_candidates());
    candidates
}

#[cfg(not(target_os = "macos"))]
fn trusted_user_base_candidates() -> Vec<PathBuf> {
    let mut candidates = environment_candidates();
    candidates.push(PathBuf::from(format!(
        "/run/user/{}",
        rustix::process::geteuid().as_raw()
    )));
    candidates
}

fn environment_candidates() -> Vec<PathBuf> {
    ["XDG_RUNTIME_DIR", "HOME"]
        .into_iter()
        .filter_map(std::env::var_os)
        .filter(|path| path != &OsString::new())
        .map(PathBuf::from)
        .collect()
}

fn trusted_ancestor_chain(path: &Path) -> bool {
    let effective_uid = rustix::process::geteuid().as_raw();
    path.ancestors().all(|ancestor| {
        std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
            (metadata.uid() == 0 || metadata.uid() == effective_uid) && metadata.mode() & 0o022 == 0
        })
    })
}
