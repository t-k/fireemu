//! Temporary files for object bodies kept outside memory.

use std::fmt;
use std::fs::{self, File, OpenOptions};
#[cfg(not(unix))]
use std::io::Read;
use std::io::{self, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::{Crc32c, Md5};
use crate::store::ObjectDigests;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

macro_rules! spill_io {
    ($operation:literal, $path:expr, $call:expr) => {{
        #[cfg(test)]
        {
            fault_injection::call($operation, $path, || $call)
        }
        #[cfg(not(test))]
        {
            $call
        }
    }};
}

/// Directory in which temporary body files are created.
#[derive(Clone)]
pub struct SpillDir {
    dir: PathBuf,
    owner: Option<Arc<SpillOwner>>,
}

impl SpillDir {
    /// Creates a directory handle without accessing the filesystem.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            owner: None,
        }
    }

    /// Creates the directory if necessary and opens a unique temporary file.
    pub fn create_file(&self) -> io::Result<SpillFile> {
        #[cfg(unix)]
        let uid = {
            let missing = match fs::symlink_metadata(&self.dir) {
                Ok(metadata) if metadata.file_type().is_dir() => false,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "spill path is not a real directory",
                    ))
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                Err(error) => return Err(error),
            };
            if missing {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(&self.dir)?;
                fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700))?;
            }
            let uid = match &self.owner {
                Some(owner) => owner.uid,
                None => probe_uid(&self.dir)?,
            };
            check_dir(&self.dir, uid)?;
            uid
        };
        #[cfg(not(unix))]
        fs::create_dir_all(&self.dir)?;
        loop {
            let counter = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = self
                .dir
                .join(format!("spill-{}-{counter}-{time:x}", std::process::id()));
            // Same-user attackers are out of scope; a race remains between this check and creation.
            #[cfg(unix)]
            check_dir(&self.dir, uid)?;
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match spill_io!("open", &path, options.open(&path)) {
                Ok(file) => {
                    #[cfg(unix)]
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                    return Ok(SpillFile {
                        #[cfg(unix)]
                        uid,
                        #[cfg(not(unix))]
                        read_lock: std::sync::Mutex::new(()),
                        path,
                        file: Some(file),
                        len: 0,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }
}

/// A temporary body file removed when it is dropped.
pub struct SpillFile {
    path: PathBuf,
    file: Option<File>,
    len: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(not(unix))]
    read_lock: std::sync::Mutex<()>,
}

impl fmt::Debug for SpillFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpillFile")
            .field("file_name", &self.path.file_name())
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl SpillFile {
    /// Returns the path of the temporary file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the number of bytes written to the file.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns whether the file contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Appends bytes to the file.
    pub fn append(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        #[cfg(unix)]
        check_dir(
            self.path.parent().expect("spill file has a parent"),
            self.uid,
        )?;
        let file = self.file.as_mut().expect("spill file is open");
        file.seek(SeekFrom::End(0))?;
        while !bytes.is_empty() {
            match spill_io!("write", &self.path, file.write(bytes)) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to append to spill file",
                    ))
                }
                Ok(written) => {
                    self.len += written as u64;
                    bytes = &bytes[written..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Reads a window entirely within the file.
    pub fn read_range(&self, start: u64, len: usize) -> io::Result<Vec<u8>> {
        let length = u64::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "range too large"))?;
        if start.checked_add(length).is_none_or(|end| end > self.len) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "range exceeds spill file",
            ));
        }
        let mut bytes = vec![0; len];
        #[cfg(unix)]
        {
            let file = self.file.as_ref().expect("spill file is open");
            let mut offset = 0;
            while offset < len {
                match spill_io!(
                    "read",
                    &self.path,
                    file.read_at(&mut bytes[offset..], start + offset as u64)
                ) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "spill file shortened",
                        ))
                    }
                    Ok(n) => offset += n,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        }
        #[cfg(not(unix))]
        {
            // Cloned handles may share their cursor, so serialize all reads.
            let _guard = self
                .read_lock
                .lock()
                .map_err(|_| io::Error::other("spill read lock poisoned"))?;
            let mut file = self
                .file
                .as_ref()
                .expect("spill file is open")
                .try_clone()?;
            file.seek(SeekFrom::Start(start))?;
            file.read_exact(&mut bytes)?;
        }
        Ok(bytes)
    }

    /// Reads the entire file.
    pub fn read_all(&self) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file too large"))?;
        self.read_range(0, len)
    }

    /// Computes both digests by streaming the file in 64 KiB chunks.
    pub fn digests(&self) -> io::Result<ObjectDigests> {
        let mut md5 = Md5::new();
        let mut crc32c = Crc32c::new();
        let mut offset = 0;
        while offset < self.len {
            let len = (self.len - offset).min(64 * 1024) as usize;
            let buffer = self.read_range(offset, len)?;
            md5.update(&buffer);
            crc32c.update(&buffer);
            offset += len as u64;
        }
        Ok(ObjectDigests::from_parts(md5.finalize(), crc32c.finalize()))
    }
}

impl Drop for SpillFile {
    fn drop(&mut self) {
        drop(self.file.take());
        #[cfg(unix)]
        if check_dir(
            self.path.parent().expect("spill file has a parent"),
            self.uid,
        )
        .is_err()
        {
            return;
        }
        let _ = fs::remove_file(&self.path);
    }
}

const PREFIX: &str = "fireemu-spill-";

/// Owns a process-specific directory for temporary body files.
pub struct ProcessSpill {
    owner: Arc<SpillOwner>,
}

struct SpillOwner {
    dir: PathBuf,
    #[cfg(unix)]
    uid: u32,
}

impl ProcessSpill {
    /// Removes stale directories and creates a fresh directory for this process.
    #[cfg(unix)]
    pub fn create(root: &Path) -> io::Result<Self> {
        let missing = match spill_io!("metadata", root, fs::symlink_metadata(root)) {
            Ok(_) => false,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => return Err(error),
        };
        if missing {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(root)?;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("root {} is not a real directory", root.display()),
            ));
        }
        if metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "root {} has unsafe mode {:o}",
                    root.display(),
                    metadata.mode() & 0o7777
                ),
            ));
        }
        let uid = probe_uid(root)?;
        check_dir(root, uid)?;
        sweep_stale(root, process_state)?;
        let pid = std::process::id();
        let dir = root.join(format!("{PREFIX}{pid}"));
        let start = match process_state(pid) {
            ProcessState::Running { start } => start,
            _ => "unknown".to_owned(),
        };
        if fs::symlink_metadata(&dir).is_ok() {
            check_dir(&dir, uid)?;
            let marker = read_marker(&dir, pid);
            if start == "unknown" || marker.as_deref() != Some(&start) {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("unverified spill directory {}", dir.display()),
                ));
            }
            check_dir(&dir, uid)?;
            fs::remove_dir_all(&dir)?;
        }
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let result = (|| {
            check_dir(&dir, uid)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join("fireemu-owner"))?;
            marker.set_permissions(fs::Permissions::from_mode(0o600))?;
            writeln!(marker, "fireemu-spill-owner v1\npid {pid}\nstart {start}")?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir_all(&dir);
            return Err(error);
        }
        Ok(Self {
            owner: Arc::new(SpillOwner { dir, uid }),
        })
    }

    #[cfg(not(unix))]
    pub fn create(_root: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process spill is unsupported",
        ))
    }

    /// Returns the process-specific directory path.
    pub fn path(&self) -> &Path {
        &self.owner.dir
    }

    /// Returns a handle for creating temporary files in this directory.
    pub fn spill_dir(&self) -> SpillDir {
        SpillDir {
            dir: self.path().to_owned(),
            owner: Some(Arc::clone(&self.owner)),
        }
    }
}

impl Drop for SpillOwner {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The result of checking a process's start time.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessState {
    /// The process is absent.
    Absent,
    /// A process exists; `start` is its start time as `ps -o lstart=` prints it.
    Running {
        /// The start time text reported by `ps`.
        start: String,
    },
    /// The process state could not be established.
    Unknown,
}

/// Checks a process's start time using ps.
pub fn process_state(pid: u32) -> ProcessState {
    match std::process::Command::new("ps")
        .args(["-o", "lstart=", "-p", &pid.to_string()])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()
    {
        Ok(output) => match std::str::from_utf8(&output.stdout) {
            Ok(value) if !value.trim().is_empty() && output.status.success() => {
                ProcessState::Running {
                    start: value.trim().to_owned(),
                }
            }
            Ok(value)
                if value.trim().is_empty()
                    && !output.status.success()
                    && output.stderr.is_empty() =>
            {
                ProcessState::Absent
            }
            _ => ProcessState::Unknown,
        },
        Err(_) => ProcessState::Unknown,
    }
}

#[cfg(unix)]
fn check_dir(path: &Path, uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "directory {} is not a real directory owned by the current user",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn probe_uid(root: &Path) -> io::Result<u32> {
    loop {
        let n = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!(".fireemu-probe-{}-{n}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                let result = file
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .and_then(|()| file.metadata().map(|m| m.uid()));
                fs::remove_file(&path)?;
                return result;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("cannot probe root {}: {error}", root.display()),
                ))
            }
        }
    }
}

#[cfg(unix)]
fn read_marker(dir: &Path, pid: u32) -> Option<String> {
    let path = dir.join("fireemu-owner");
    if !fs::symlink_metadata(&path).ok()?.file_type().is_file() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "fireemu-spill-owner v1" || lines.next()? != format!("pid {pid}") {
        return None;
    }
    let start = lines.next()?.strip_prefix("start ")?;
    if start.is_empty() || lines.next().is_some() {
        return None;
    }
    Some(start.to_owned())
}

/// Removes directories with verified markers belonging to absent processes.
#[cfg(unix)]
pub fn sweep_stale(root: &Path, state: impl Fn(u32) -> ProcessState) -> io::Result<usize> {
    let entries = match spill_io!("read_dir", root, fs::read_dir(root)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "unsafe root {} mode {:o}",
                root.display(),
                metadata.mode() & 0o7777
            ),
        ));
    }
    let uid = probe_uid(root)?;
    check_dir(root, uid)?;
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(PREFIX))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let path = entry.path();
        if check_dir(&path, uid).is_err() {
            continue;
        }
        let Some(start) = read_marker(&path, pid) else {
            continue;
        };
        if start == "unknown" {
            continue;
        }
        let gone = matches!(state(pid), ProcessState::Absent);
        if gone && check_dir(&path, uid).is_ok() {
            fs::remove_dir_all(path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Process sweeping is unsupported on non-Unix targets.
#[cfg(not(unix))]
pub fn sweep_stale(_root: &Path, _state: impl Fn(u32) -> ProcessState) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "process sweeping is unsupported",
    ))
}

#[cfg(test)]
mod fault_injection {
    use std::cell::RefCell;
    use std::io;
    use std::path::{Path, PathBuf};

    #[derive(Default)]
    struct Fault {
        operation: &'static str,
        error: Option<io::ErrorKind>,
        paths: Vec<PathBuf>,
    }

    thread_local! {
        static FAULT: RefCell<Fault> = RefCell::new(Fault::default());
    }

    pub(super) fn inject(operation: &'static str, error: io::ErrorKind) {
        FAULT.with(|fault| {
            *fault.borrow_mut() = Fault {
                operation,
                error: Some(error),
                paths: Vec::new(),
            }
        });
    }

    pub(super) fn paths() -> Vec<PathBuf> {
        FAULT.with(|fault| fault.borrow().paths.clone())
    }

    pub(super) fn call<T>(
        operation: &str,
        path: &Path,
        call: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let error = FAULT.with(|fault| {
            let mut fault = fault.borrow_mut();
            if fault.operation == operation {
                fault.paths.push(path.to_owned());
                fault.error.take()
            } else {
                None
            }
        });
        match error {
            Some(kind) => Err(io::Error::from(kind)),
            None => call(),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let counter = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "spill-fault-{name}-{}-{counter}",
            std::process::id()
        ))
    }

    #[test]
    fn create_file_retries_collision_with_new_name() {
        let dir = temp_path("collision");
        fault_injection::inject("open", io::ErrorKind::AlreadyExists);
        let file = SpillDir::new(&dir).create_file().unwrap();
        let paths = fault_injection::paths();
        assert_eq!(paths.len(), 2);
        assert_ne!(paths[0], paths[1]);
        assert_eq!(paths[1], file.path());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        drop(file);
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn append_and_digests_retry_interrupted_io() {
        let dir = temp_path("interrupted");
        let mut file = SpillDir::new(&dir).create_file().unwrap();
        fault_injection::inject("write", io::ErrorKind::Interrupted);
        file.append(b"spill contents").unwrap();
        assert_eq!(fault_injection::paths().len(), 2);
        assert_eq!(file.len(), 14);
        fault_injection::inject("read", io::ErrorKind::Interrupted);
        assert_eq!(
            file.digests().unwrap(),
            ObjectDigests::new(b"spill contents")
        );
        assert_eq!(fault_injection::paths().len(), 2);
        assert_eq!(file.read_all().unwrap(), b"spill contents");
        drop(file);
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn missing_process_root_is_created_and_missing_sweep_root_is_ignored() {
        let root = temp_path("missing");
        fault_injection::inject("metadata", io::ErrorKind::NotFound);
        let process = ProcessSpill::create(&root).unwrap();
        assert_eq!(fault_injection::paths(), vec![root.clone()]);
        assert!(process.path().is_dir());
        drop(process);
        fs::remove_dir(&root).unwrap();
        fault_injection::inject("read_dir", io::ErrorKind::NotFound);
        assert_eq!(sweep_stale(&root, |_| ProcessState::Absent).unwrap(), 0);
        assert_eq!(fault_injection::paths(), vec![root]);
    }

    #[test]
    fn other_io_errors_are_not_retried_or_ignored() {
        let root = temp_path("other-errors");
        fault_injection::inject("metadata", io::ErrorKind::PermissionDenied);
        assert_eq!(
            ProcessSpill::create(&root).err().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        fault_injection::inject("read_dir", io::ErrorKind::PermissionDenied);
        assert_eq!(
            sweep_stale(&root, |_| ProcessState::Absent)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fault_injection::inject("open", io::ErrorKind::PermissionDenied);
        assert_eq!(
            SpillDir::new(&root).create_file().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut file = SpillDir::new(&root).create_file().unwrap();
        fault_injection::inject("write", io::ErrorKind::PermissionDenied);
        assert_eq!(
            file.append(b"x").unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        file.append(b"x").unwrap();
        fault_injection::inject("read", io::ErrorKind::PermissionDenied);
        assert_eq!(
            file.digests().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(file);
        fs::remove_dir(&root).unwrap();
    }
}
