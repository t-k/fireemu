//! Private, atomic endpoint discovery for supervised test worlds.

use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};

/// An owned descriptor is withdrawn before shutdown and on every early return.
pub struct ReadyFile {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl ReadyFile {
    /// Publish without replacing another process's descriptor.
    pub fn publish(path: &Path, descriptor: &Value) -> Result<Self, String> {
        let bytes = serde_json::to_vec(descriptor).map_err(|e| e.to_string())?;
        let temporary = path.with_extension(format!("ready-{}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut created = false;
        let result = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|e| format!("ready file: {e}"))?;
            created = true;
            file.write_all(&bytes)
                .map_err(|e| format!("ready file: {e}"))?;
            file.sync_all().map_err(|e| format!("ready file: {e}"))?;
            std::fs::hard_link(&temporary, path).map_err(|e| format!("ready file: {e}"))?;
            Ok(Self {
                path: path.to_owned(),
                bytes,
            })
        })();
        if created {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
}

impl Drop for ReadyFile {
    fn drop(&mut self) {
        if std::fs::read(&self.path).is_ok_and(|bytes| bytes == self.bytes) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_is_private_atomic_and_withdrawn_without_replacing_an_existing_file() {
        let root = std::env::temp_dir().join(format!("fireemu-ready-test-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("ready.json");
        let descriptor = serde_json::json!({"schemaVersion":1,"pid":std::process::id(),"controlToken":"test-only"});
        let owned = ReadyFile::publish(&path, &descriptor).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&std::fs::read(&path).unwrap()).unwrap(),
            descriptor
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(ReadyFile::publish(&path, &serde_json::json!({"other":true})).is_err());
        drop(owned);
        assert!(!path.exists());
        let owned = ReadyFile::publish(&path, &descriptor).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(owned);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_dir_all(root).unwrap();
    }
}
