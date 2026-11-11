//! Temporary files for object bodies kept outside memory.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::hash::{Crc32c, Md5};
use crate::store::ObjectDigests;

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

/// Directory in which temporary body files are created.
#[derive(Clone)]
pub struct SpillDir {
    dir: PathBuf,
    _owner: Option<Arc<SpillOwner>>,
}

impl SpillDir {
    /// Creates a directory handle without accessing the filesystem.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            _owner: None,
        }
    }

    /// Creates the directory if necessary and opens a unique temporary file.
    pub fn create_file(&self) -> io::Result<SpillFile> {
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
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(SpillFile {
                        path,
                        file: Some(file),
                        len: 0,
                    })
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
        let file = self.file.as_mut().expect("spill file is open");
        file.seek(SeekFrom::End(0))?;
        while !bytes.is_empty() {
            match file.write(bytes) {
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
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = vec![0; len];
        file.read_exact(&mut bytes)?;
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
        let mut file = File::open(&self.path)?;
        let mut md5 = Md5::new();
        let mut crc32c = Crc32c::new();
        let mut buffer = vec![0; 64 * 1024];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    md5.update(&buffer[..n]);
                    crc32c.update(&buffer[..n]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(ObjectDigests::from_parts(md5.finalize(), crc32c.finalize()))
    }
}

impl Drop for SpillFile {
    fn drop(&mut self) {
        drop(self.file.take());
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
}

impl ProcessSpill {
    /// Removes stale directories and creates a fresh directory for this process.
    pub fn create(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        sweep_stale(root, process_is_alive)?;
        let dir = root.join(format!("{PREFIX}{}", std::process::id()));
        match fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir(&dir)?;
        Ok(Self {
            owner: Arc::new(SpillOwner { dir }),
        })
    }

    /// Returns the process-specific directory path.
    pub fn path(&self) -> &Path {
        &self.owner.dir
    }

    /// Returns a handle for creating temporary files in this directory.
    pub fn spill_dir(&self) -> SpillDir {
        SpillDir {
            dir: self.path().to_owned(),
            _owner: Some(Arc::clone(&self.owner)),
        }
    }
}

impl Drop for SpillOwner {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Removes directories belonging to processes that are no longer alive.
pub fn sweep_stale(root: &Path, is_alive: impl Fn(u32) -> bool) -> io::Result<usize> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix(PREFIX))
            .and_then(|suffix| suffix.parse::<u32>().ok())
        else {
            continue;
        };
        if !is_alive(pid) {
            fs::remove_dir_all(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Checks whether a process exists using signal zero.
pub fn process_is_alive(pid: u32) -> bool {
    match std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .output()
    {
        Ok(output) => {
            output.status.success()
                || String::from_utf8_lossy(&output.stderr).contains("Operation not permitted")
        }
        Err(_) => false,
    }
}
