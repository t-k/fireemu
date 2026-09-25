//! Functions runtime wiring: runner process, event subscriptions, control hooks.

#[cfg(not(windows))]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(not(windows))]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_http::control::FunctionsHook;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::ids::SessionId;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::config::{CompatibilityProfile, FunctionsCodebase, RuntimeConfig};

/// One Pub/Sub topic and emulator subscription required by a loaded function manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPubSubResource {
    /// The canonical topic name.
    pub topic: fireemu_core_pubsub::TopicName,
    /// The canonical emulator subscription name.
    pub subscription: fireemu_core_pubsub::SubscriptionName,
}

/// Derives the unique Pub/Sub resources required by Pub/Sub and scheduled functions.
pub fn function_pubsub_resources(
    project: &str,
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<Vec<FunctionPubSubResource>, String> {
    use fireemu_core_functions::manifest::Trigger;

    let mut topics: BTreeSet<(String, String)> = BTreeSet::new();
    for function in &manifest.functions {
        match &function.trigger {
            Trigger::PubSub { topic } => {
                topics.insert((topic.clone(), format!("function {:?}", function.name)));
            }
            Trigger::Schedule { .. } => {
                topics.insert((
                    format!("firebase-schedule-{}", function.name),
                    format!("scheduled function {:?}", function.name),
                ));
            }
            _ => {}
        }
    }

    // The same topic may be declared by more than one function. Resource names, not the
    // diagnostics attached to them, define uniqueness.
    let mut seen = BTreeSet::new();
    let mut resources = Vec::new();
    for (topic_id, owner) in topics {
        if !seen.insert(topic_id.clone()) {
            continue;
        }
        let topic = fireemu_core_pubsub::TopicName::new(project, &topic_id).map_err(|error| {
            format!("{owner} requires invalid Pub/Sub topic {topic_id:?}: {error}")
        })?;
        let subscription_id = format!("emulator-sub-{topic_id}");
        let subscription = fireemu_core_pubsub::SubscriptionName::new(project, &subscription_id)
            .map_err(|error| {
                format!(
                    "{owner} requires invalid Pub/Sub subscription {subscription_id:?}: {error}"
                )
            })?;
        resources.push(FunctionPubSubResource {
            topic,
            subscription,
        });
    }
    Ok(resources)
}

/// Creates missing manifest-owned Pub/Sub resources without changing existing compatible ones.
pub fn provision_function_pubsub_resources(
    state: &mut fireemu_core_pubsub::PubSubState,
    resources: &[FunctionPubSubResource],
) -> Result<(), String> {
    use fireemu_core_pubsub::subscription::DEFAULT_ACK_DEADLINE_SECONDS;
    use fireemu_core_pubsub::{Filter, PushConfig, SubscriptionConfig};

    // Check every existing subscription before creating anything. A stale subscription with
    // the expected name but another topic is configuration drift, not an idempotent match.
    for resource in resources {
        if let Ok(existing) = state.subscription_config(&resource.subscription) {
            if existing.topic != resource.topic {
                return Err(format!(
                    "Functions requires subscription {} to target {}, but it already targets {}",
                    resource.subscription.to_full(),
                    resource.topic.to_full(),
                    existing.topic.to_full()
                ));
            }
        }
    }

    for resource in resources {
        if !state.topic_exists(&resource.topic) {
            state
                .create_topic(resource.topic.clone(), BTreeMap::new())
                .map_err(|error| {
                    format!(
                        "could not provision topic {}: {error}",
                        resource.topic.to_full()
                    )
                })?;
        }
        if state.subscription_config(&resource.subscription).is_err() {
            state
                .create_subscription(SubscriptionConfig {
                    name: resource.subscription.clone(),
                    topic: resource.topic.clone(),
                    ack_deadline_seconds: DEFAULT_ACK_DEADLINE_SECONDS,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: None,
                    retry_policy: None,
                    push_config: PushConfig::default(),
                })
                .map_err(|error| {
                    format!(
                        "could not provision subscription {}: {error}",
                        resource.subscription.to_full()
                    )
                })?;
        }
        state
            .mark_function_subscription(&resource.subscription)
            .map_err(|error| {
                format!(
                    "could not provision subscription {}: {error}",
                    resource.subscription.to_full()
                )
            })?;
    }
    Ok(())
}

async fn inspector_endpoint_is_active(port: u16) -> bool {
    const RESPONSE_LIMIT: usize = 64 * 1024;
    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        stream
            .write_all(
                format!(
                    "GET /json/list HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .ok()?;
        let expected = format!("ws://127.0.0.1:{port}/");
        let mut response = Vec::with_capacity(4 * 1024);
        let mut chunk = [0_u8; 4 * 1024];
        while response.len() < RESPONSE_LIMIT {
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..read]);
            let text = String::from_utf8_lossy(&response);
            if (text.starts_with("HTTP/1.1 200 ") || text.starts_with("HTTP/1.0 200 "))
                && text.contains("webSocketDebuggerUrl")
                && text.contains(&expected)
            {
                return Some(true);
            }
        }
        Some(false)
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), probe).await,
        Ok(Some(true))
    )
}

fn ignored_reload_path(relative: &Path, configured: &[String]) -> bool {
    let text = relative.to_string_lossy().replace('\\', "/");
    if relative
        .components()
        .any(|part| matches!(part.as_os_str().to_str(), Some("node_modules" | ".git")))
    {
        return true;
    }
    configured.iter().any(|pattern| {
        let pattern = pattern.trim_start_matches("./").trim_start_matches("**/");
        if let Some(suffix) = pattern.strip_prefix('*') {
            text.ends_with(suffix)
        } else {
            text == pattern || text.starts_with(&format!("{pattern}/"))
        }
    })
}

fn update_watch_hash(hash: u64, byte: u8) -> u64 {
    hash.wrapping_mul(0x100_0000_01b3) ^ u64::from(byte)
}

/// Aggregate sustained read budget for all Functions source supervisors in one daemon.
const MAX_FUNCTIONS_SOURCE_WATCH_BYTES_PER_SECOND: u64 = 64 * 1024 * 1024;
/// Aggregate sustained metadata-walk budget for source trees dominated by small files.
const MAX_FUNCTIONS_SOURCE_WATCH_FILES_PER_SECOND: u64 = 20_000;
/// Maximum number of directory entries one source tree may enumerate per operation.
const MAX_FUNCTIONS_SOURCE_ENTRIES: u64 = 100_000;
/// Maximum bytes one Functions source tree may read or copy per operation.
const MAX_FUNCTIONS_SOURCE_BYTES: u64 = 256 * 1024 * 1024;
const SOURCE_BYTE_BUDGET_ERROR_PREFIX: &str =
    "Functions source tree exceeds the 256 MiB byte budget";
/// Maximum supported source-tree nesting, excluding the source root.
const MAX_FUNCTIONS_SOURCE_DEPTH: usize = 128;

fn rate_pacing_delay(units: u64, units_per_second: u64) -> Duration {
    let nanos = u128::from(units)
        .saturating_mul(1_000_000_000)
        .checked_div(u128::from(units_per_second))
        .unwrap_or(u128::MAX);
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

fn source_scan_pacing_delay(tracked_files: u64, tracked_bytes: u64) -> Duration {
    rate_pacing_delay(tracked_bytes, MAX_FUNCTIONS_SOURCE_WATCH_BYTES_PER_SECOND).max(
        rate_pacing_delay(tracked_files, MAX_FUNCTIONS_SOURCE_WATCH_FILES_PER_SECOND),
    )
}

const SOURCE_IO_BUFFER_BYTES: usize = 64 * 1024;

fn stream_source_chunks(
    reader: &mut impl Read,
    mut consume: impl FnMut(&[u8]) -> std::io::Result<()>,
    mut charge: impl FnMut(u64) -> std::io::Result<()>,
    cancelled: &AtomicBool,
) -> std::io::Result<u64> {
    let mut buffer = vec![0_u8; SOURCE_IO_BUFFER_BYTES].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Functions source work was cancelled",
            ));
        }
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        let read_u64 = u64::try_from(read).unwrap_or(u64::MAX);
        total = total.saturating_add(read_u64);
        charge(read_u64)?;
        if cancelled.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Functions source work was cancelled",
            ));
        }
        consume(&buffer[..read])?;
    }
}

#[derive(Default)]
struct FunctionsSourceEntryBudget {
    entries: u64,
}

#[derive(Default)]
struct FunctionsSourceByteBudget {
    bytes: u64,
    largest: Option<(PathBuf, u64)>,
}

impl FunctionsSourceByteBudget {
    fn claim(&mut self, path: &Path, bytes: u64) -> Result<(), String> {
        if self
            .largest
            .as_ref()
            .is_none_or(|(_, largest)| bytes > *largest)
        {
            self.largest = Some((path.to_path_buf(), bytes));
        }
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > MAX_FUNCTIONS_SOURCE_BYTES {
            let (largest_path, largest_bytes) = self.largest.as_ref().unwrap();
            return Err(format!(
                "{SOURCE_BYTE_BUDGET_ERROR_PREFIX} at {} ({} bytes counted); largest file is {} ({largest_bytes} bytes). Narrow functions.source or move generated files outside it; functions.ignore affects watcher scans but not runtime snapshots",
                path.display(),
                self.bytes,
                largest_path.display()
            ));
        }
        Ok(())
    }
}

impl FunctionsSourceEntryBudget {
    fn claim(&mut self, entries: u64) -> Result<(), String> {
        self.entries = self.entries.saturating_add(entries);
        if self.entries > MAX_FUNCTIONS_SOURCE_ENTRIES {
            return Err(format!(
                "Functions source trees may contain at most {MAX_FUNCTIONS_SOURCE_ENTRIES} entries"
            ));
        }
        Ok(())
    }
}

fn ensure_source_work_active(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        Err("Functions source work was cancelled".to_owned())
    } else {
        Ok(())
    }
}

fn sorted_source_entries(
    directory: &Path,
    operation: &str,
    entry_budget: &mut FunctionsSourceEntryBudget,
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
) -> Result<Vec<std::fs::DirEntry>, String> {
    let entries = std::fs::read_dir(directory)
        .map_err(|error| format!("{operation} {}: {error}", directory.display()))?;
    let mut collected = Vec::new();
    for entry in entries {
        ensure_source_work_active(cancelled)?;
        charge(1, 0)?;
        entry_budget.claim(1)?;
        collected
            .push(entry.map_err(|error| format!("{operation} {}: {error}", directory.display()))?);
    }
    collected.sort_by_key(std::fs::DirEntry::file_name);
    Ok(collected)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FunctionsSourceStamp {
    change_guard: u64,
    content_signature: u64,
    tracked_files: u64,
    tracked_bytes: u64,
}

#[derive(Clone, Copy)]
struct FunctionsSourceFileVersion {
    len: u64,
    modified_nanos: u128,
    changed_seconds: i64,
    changed_nanos: i64,
}

fn functions_source_file_version(metadata: &std::fs::Metadata) -> FunctionsSourceFileVersion {
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    #[cfg(unix)]
    let (changed_seconds, changed_nanos) = {
        use std::os::unix::fs::MetadataExt as _;
        (metadata.ctime(), metadata.ctime_nsec())
    };
    #[cfg(not(unix))]
    let (changed_seconds, changed_nanos) = (0, 0);
    FunctionsSourceFileVersion {
        len: metadata.len(),
        modified_nanos,
        changed_seconds,
        changed_nanos,
    }
}

#[cfg(test)]
fn hash_source_stamp_entry(
    hash: u64,
    relative: &[u8],
    len: u64,
    modified_nanos: u128,
    changed_seconds: i64,
    changed_nanos: i64,
    content: &[u8],
) -> u64 {
    let mut hash = hash_source_stamp_metadata(
        hash,
        relative,
        len,
        modified_nanos,
        changed_seconds,
        changed_nanos,
    );
    for byte in content {
        hash = update_watch_hash(hash, *byte);
    }
    hash
}

fn hash_source_stamp_metadata(
    mut hash: u64,
    relative: &[u8],
    len: u64,
    modified_nanos: u128,
    changed_seconds: i64,
    changed_nanos: i64,
) -> u64 {
    for byte in relative.iter().copied().chain([0]) {
        hash = update_watch_hash(hash, byte);
    }
    for byte in len
        .to_le_bytes()
        .into_iter()
        .chain(modified_nanos.to_le_bytes())
        .chain(changed_seconds.to_le_bytes())
        .chain(changed_nanos.to_le_bytes())
    {
        hash = update_watch_hash(hash, byte);
    }
    hash
}

fn hash_source_file(
    child: &Path,
    relative: &Path,
    version: FunctionsSourceFileVersion,
    stamp: &mut FunctionsSourceStamp,
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
) -> Result<(), String> {
    stamp.change_guard = hash_source_stamp_metadata(
        stamp.change_guard,
        relative.to_string_lossy().as_bytes(),
        version.len,
        version.modified_nanos,
        version.changed_seconds,
        version.changed_nanos,
    );
    for byte in relative.to_string_lossy().bytes().chain([0]) {
        stamp.content_signature = update_watch_hash(stamp.content_signature, byte);
    }
    let mut file = std::fs::File::open(child)
        .map_err(|error| format!("watch {}: {error}", child.display()))?;
    let mut read_bytes = 0_u64;
    stream_source_chunks(
        &mut file,
        |bytes| {
            for byte in bytes {
                stamp.change_guard = update_watch_hash(stamp.change_guard, *byte);
                stamp.content_signature = update_watch_hash(stamp.content_signature, *byte);
            }
            Ok(())
        },
        |bytes| {
            read_bytes = read_bytes.saturating_add(bytes);
            if read_bytes > version.len {
                return Err(std::io::Error::other("source file grew during the scan"));
            }
            charge(0, bytes).map_err(std::io::Error::other)
        },
        cancelled,
    )
    .map_err(|error| format!("watch {}: {error}", child.display()))?;
    stamp.tracked_files = stamp.tracked_files.saturating_add(1);
    stamp.tracked_bytes = stamp.tracked_bytes.saturating_add(version.len);
    Ok(())
}

#[cfg(test)]
fn functions_source_stamp(root: &Path, ignores: &[String]) -> Result<FunctionsSourceStamp, String> {
    functions_source_stamp_with_charge(root, ignores, &mut |_, _| Ok(()), &AtomicBool::new(false))
}

#[cfg(test)]
fn functions_source_stamp_with_file_version(
    root: &Path,
    ignores: &[String],
    file_version: &dyn Fn(&std::fs::Metadata) -> FunctionsSourceFileVersion,
) -> Result<FunctionsSourceStamp, String> {
    functions_source_stamp_with_charge_and_file_version(
        root,
        ignores,
        &mut |_, _| Ok(()),
        &AtomicBool::new(false),
        file_version,
    )
}

struct FunctionsSourceTraversal<'a> {
    root: &'a Path,
    ignores: &'a [String],
    entry_budget: FunctionsSourceEntryBudget,
    byte_budget: FunctionsSourceByteBudget,
    charge: &'a mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &'a AtomicBool,
}

impl FunctionsSourceTraversal<'_> {
    fn entries(
        &mut self,
        directory: &Path,
        operation: &str,
        depth: usize,
    ) -> Result<Vec<std::fs::DirEntry>, String> {
        if depth > MAX_FUNCTIONS_SOURCE_DEPTH {
            return Err(format!(
                "{operation} {}: Functions source trees may be at most {MAX_FUNCTIONS_SOURCE_DEPTH} directories deep",
                directory.display()
            ));
        }
        sorted_source_entries(
            directory,
            operation,
            &mut self.entry_budget,
            self.charge,
            self.cancelled,
        )
    }

    fn scan_directory(
        &mut self,
        directory: &Path,
        stamp: &mut FunctionsSourceStamp,
        depth: usize,
        file_version: &dyn Fn(&std::fs::Metadata) -> FunctionsSourceFileVersion,
    ) -> Result<(), String> {
        for entry in self.entries(directory, "watch", depth)? {
            ensure_source_work_active(self.cancelled)?;
            let child = entry.path();
            let relative = child.strip_prefix(self.root).unwrap_or(&child);
            if ignored_reload_path(relative, self.ignores) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| format!("watch {}: {error}", child.display()))?;
            if kind.is_dir() {
                self.scan_directory(&child, stamp, depth.saturating_add(1), file_version)?;
            } else if kind.is_file() {
                self.hash_file(&entry, &child, relative, stamp, file_version)?;
            } else if kind.is_symlink() {
                return Err(format!(
                    "watch {}: symbolic links outside node_modules are not supported",
                    child.display()
                ));
            }
        }
        Ok(())
    }

    fn hash_file(
        &mut self,
        entry: &std::fs::DirEntry,
        child: &Path,
        relative: &Path,
        stamp: &mut FunctionsSourceStamp,
        file_version: &dyn Fn(&std::fs::Metadata) -> FunctionsSourceFileVersion,
    ) -> Result<(), String> {
        let metadata = entry
            .metadata()
            .map_err(|error| format!("watch {}: {error}", child.display()))?;
        self.byte_budget.claim(child, metadata.len())?;
        hash_source_file(
            child,
            relative,
            file_version(&metadata),
            stamp,
            self.charge,
            self.cancelled,
        )
    }

    fn copy_directory(
        &mut self,
        source: &Path,
        destination: &Path,
        depth: usize,
    ) -> Result<(), String> {
        for entry in self.entries(source, "snapshot", depth)? {
            ensure_source_work_active(self.cancelled)?;
            let path = entry.path();
            let relative = path.strip_prefix(self.root).unwrap_or(&path);
            // Watcher/deploy ignores must not remove files required by the runtime.
            if ignored_reload_path(relative, &[]) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| format!("snapshot {}: {error}", path.display()))?;
            let target = destination.join(relative);
            if kind.is_dir() {
                std::fs::create_dir_all(&target)
                    .map_err(|error| format!("snapshot {}: {error}", target.display()))?;
                self.copy_directory(&path, destination, depth.saturating_add(1))?;
            } else if kind.is_file() {
                self.copy_file(&path, &target)?;
            } else if kind.is_symlink() {
                return Err(format!(
                    "snapshot {}: symbolic links outside node_modules are not supported",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    fn copy_file(&mut self, source: &Path, target: &Path) -> Result<(), String> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("snapshot {}: {error}", parent.display()))?;
        }
        let mut source_file = std::fs::File::open(source)
            .map_err(|error| format!("snapshot {}: {error}", source.display()))?;
        let expected_len = source_file
            .metadata()
            .map_err(|error| format!("snapshot {}: {error}", source.display()))?
            .len();
        self.byte_budget.claim(source, expected_len)?;
        let mut target_file = std::fs::File::create(target)
            .map_err(|error| format!("snapshot {}: {error}", target.display()))?;
        let mut read_bytes = 0_u64;
        stream_source_chunks(
            &mut source_file,
            |bytes| target_file.write_all(bytes),
            |bytes| {
                read_bytes = read_bytes.saturating_add(bytes);
                if read_bytes > expected_len {
                    return Err(std::io::Error::other(
                        "source file grew during the snapshot",
                    ));
                }
                (self.charge)(0, bytes).map_err(std::io::Error::other)
            },
            self.cancelled,
        )
        .map_err(|error| format!("snapshot {}: {error}", source.display()))?;
        Ok(())
    }
}

fn functions_source_stamp_with_charge(
    root: &Path,
    ignores: &[String],
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
) -> Result<FunctionsSourceStamp, String> {
    functions_source_stamp_with_charge_and_file_version(
        root,
        ignores,
        charge,
        cancelled,
        &functions_source_file_version,
    )
}

fn functions_source_stamp_with_charge_and_file_version(
    root: &Path,
    ignores: &[String],
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
    file_version: &dyn Fn(&std::fs::Metadata) -> FunctionsSourceFileVersion,
) -> Result<FunctionsSourceStamp, String> {
    let mut stamp = FunctionsSourceStamp {
        change_guard: 0xcbf2_9ce4_8422_2325,
        content_signature: 0xcbf2_9ce4_8422_2325,
        tracked_files: 0,
        tracked_bytes: 0,
    };
    charge(1, 0)?;
    FunctionsSourceTraversal {
        root,
        ignores,
        entry_budget: FunctionsSourceEntryBudget::default(),
        byte_budget: FunctionsSourceByteBudget::default(),
        charge,
        cancelled,
    }
    .scan_directory(root, &mut stamp, 0, file_version)?;
    Ok(stamp)
}

struct FunctionsSourceScanBudget {
    gate: Arc<tokio::sync::Semaphore>,
}

struct CancelBlockingSourceWork(Arc<AtomicBool>);

impl Drop for CancelBlockingSourceWork {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct BlockingSourceWorkPacer {
    started: Instant,
    entries: u64,
    bytes: u64,
}

impl BlockingSourceWorkPacer {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            entries: 0,
            bytes: 0,
        }
    }

    fn charge(&mut self, entries: u64, bytes: u64, cancelled: &AtomicBool) -> Result<(), String> {
        ensure_source_work_active(cancelled)?;
        self.entries = self.entries.saturating_add(entries);
        self.bytes = self.bytes.saturating_add(bytes);
        let delay = source_scan_pacing_delay(self.entries, self.bytes);
        if let Some(remaining) = delay.checked_sub(self.started.elapsed()) {
            std::thread::sleep(remaining);
        }
        ensure_source_work_active(cancelled)
    }
}

impl FunctionsSourceScanBudget {
    fn new() -> Self {
        Self {
            gate: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    async fn scan(&self, root: &Path, ignores: &[String]) -> Result<FunctionsSourceStamp, String> {
        let permit = Arc::clone(&self.gate)
            .acquire_owned()
            .await
            .map_err(|_| "Functions source scan budget closed".to_owned())?;
        let root = root.to_owned();
        let ignores = ignores.to_owned();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_on_drop = CancelBlockingSourceWork(Arc::clone(&cancelled));
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut pacer = BlockingSourceWorkPacer::new();
            functions_source_stamp_with_charge(
                &root,
                &ignores,
                &mut |entries, bytes| pacer.charge(entries, bytes, &cancelled),
                &cancelled,
            )
        })
        .await
        .map_err(|error| format!("watch worker failed: {error}"))?;
        drop(cancel_on_drop);
        result
    }

    async fn snapshot(
        &self,
        root: &Path,
        ignores: &[String],
    ) -> Result<FunctionsSourceSnapshot, String> {
        let permit = Arc::clone(&self.gate)
            .acquire_owned()
            .await
            .map_err(|_| "Functions source scan budget closed".to_owned())?;
        let root = root.to_owned();
        let ignores = ignores.to_owned();
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancel_on_drop = CancelBlockingSourceWork(Arc::clone(&cancelled));
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut pacer = BlockingSourceWorkPacer::new();
            snapshot_functions_source_with_charge(
                &root,
                &ignores,
                &mut |entries, bytes| pacer.charge(entries, bytes, &cancelled),
                &cancelled,
            )
        })
        .await
        .map_err(|error| format!("snapshot worker failed: {error}"))?;
        drop(cancel_on_drop);
        result
    }
}

#[cfg(unix)]
fn snapshot_directory_name(pid: u32, sequence: u64) -> String {
    let base = format!("fireemu-functions-{pid}-{sequence}");
    #[cfg(target_os = "linux")]
    if let Some(namespace) = pid_namespace_inode() {
        return format!("{base}-n{namespace}");
    }
    base
}

#[cfg(target_os = "linux")]
fn pid_namespace_inode() -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;

    std::fs::metadata("/proc/self/ns/pid")
        .ok()
        .map(|metadata| metadata.ino())
}

#[cfg(unix)]
fn snapshot_owner_pid(name: &str) -> Option<rustix::process::Pid> {
    let suffix = name.strip_prefix("fireemu-functions-")?;
    let (pid, sequence) = suffix.split_once('-')?;
    #[cfg(target_os = "linux")]
    let (sequence, namespace) = sequence.split_once("-n")?;
    if pid.is_empty()
        || sequence.is_empty()
        || (pid.len() > 1 && pid.starts_with('0'))
        || (sequence.len() > 1 && sequence.starts_with('0'))
        || !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let sequence = sequence.parse::<u64>().ok()?;
    let pid = pid.parse::<i32>().ok().filter(|pid| *pid > 0)?;
    #[cfg(target_os = "linux")]
    if namespace != pid_namespace_inode()?.to_string() {
        return None;
    }
    if name != snapshot_directory_name(u32::try_from(pid).ok()?, sequence) {
        return None;
    }
    rustix::process::Pid::from_raw(pid)
}

#[cfg(unix)]
fn snapshot_owned_directory(metadata: &std::fs::Metadata, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o7777 == 0o700
}

#[cfg(unix)]
fn snapshot_owner_is_dead(pid: rustix::process::Pid) -> bool {
    matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

#[cfg(unix)]
fn sweep_orphan_function_snapshots(root: &Path) -> Result<usize, String> {
    use std::os::unix::fs::MetadataExt as _;

    // Shared temp directories can contain many unrelated entries; the scan stays bounded.
    const MAX_ENTRIES: usize = 1_000_000;
    const MAX_REMOVAL_ATTEMPTS: usize = 64;
    let uid = rustix::process::geteuid().as_raw();
    let entries = std::fs::read_dir(root)
        .map_err(|error| format!("orphan snapshot scan {}: {error}", root.display()))?;
    let mut removed = 0;
    let mut removal_attempts = 0;
    let mut failed = 0;
    for entry in entries.take(MAX_ENTRIES) {
        if removal_attempts == MAX_REMOVAL_ATTEMPTS {
            break;
        }
        let Ok(entry) = entry else {
            failed += 1;
            continue;
        };
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(snapshot_owner_pid) else {
            continue;
        };
        if i32::try_from(std::process::id()).ok() == Some(pid.as_raw_pid()) {
            continue;
        }
        let path = entry.path();
        let Ok(before) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !snapshot_owned_directory(&before, uid) || !snapshot_owner_is_dead(pid) {
            continue;
        }
        let Ok(now) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !snapshot_owned_directory(&now, uid)
            || before.dev() != now.dev()
            || before.ino() != now.ino()
            || !snapshot_owner_is_dead(pid)
        {
            continue;
        }
        removal_attempts += 1;
        if std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        } else {
            failed += 1;
        }
    }
    if failed > 0 {
        return Err(format!(
            "orphan snapshot sweep could not inspect or remove {failed} entries"
        ));
    }
    Ok(removed)
}

#[cfg(unix)]
fn schedule_orphan_function_snapshot_sweep(root: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        if let Err(reason) = sweep_orphan_function_snapshots(&root) {
            eprintln!("warning: {reason}");
        }
    })
}

#[derive(Debug)]
struct FunctionsSourceSnapshot {
    cleanup_root: Option<PathBuf>,
    source_path: PathBuf,
}

impl FunctionsSourceSnapshot {
    fn new(cleanup_root: PathBuf, source_path: PathBuf) -> Self {
        Self {
            cleanup_root: Some(cleanup_root),
            source_path,
        }
    }

    fn into_path(mut self) -> PathBuf {
        self.cleanup_root
            .take()
            .expect("a snapshot path is transferred once")
    }

    async fn remove(self) -> Result<(), String> {
        let path = self.into_path();
        tokio::task::spawn_blocking(move || {
            std::fs::remove_dir_all(&path)
                .map_err(|error| format!("snapshot {} cleanup failed: {error}", path.display()))
        })
        .await
        .map_err(|error| format!("snapshot cleanup worker failed: {error}"))?
    }
}

impl std::ops::Deref for FunctionsSourceSnapshot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.source_path
    }
}

impl AsRef<Path> for FunctionsSourceSnapshot {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl Drop for FunctionsSourceSnapshot {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup_root.take() {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
fn snapshot_functions_source(
    root: &Path,
    ignores: &[String],
) -> Result<FunctionsSourceSnapshot, String> {
    snapshot_functions_source_with_charge(
        root,
        ignores,
        &mut |_, _| Ok(()),
        &AtomicBool::new(false),
    )
}

fn snapshot_functions_source_with_charge(
    root: &Path,
    ignores: &[String],
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
) -> Result<FunctionsSourceSnapshot, String> {
    static NEXT_SNAPSHOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let source_root = std::fs::canonicalize(root)
        .map_err(|error| format!("snapshot {}: {error}", root.display()))?;
    // Deployment/watch ignores do not define the runtime generation. Validate every
    // copied input, including local dotenv and secret files, under the same I/O budget.
    let before =
        functions_source_stamp_with_charge(&source_root, &[], charge, cancelled)?.content_signature;
    let sequence = NEXT_SNAPSHOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    #[cfg(unix)]
    let name = snapshot_directory_name(std::process::id(), sequence);
    #[cfg(windows)]
    let name = format!("fireemu-functions-{}-{sequence}", std::process::id());
    let destination = std::env::temp_dir().join(name);
    std::fs::create_dir(&destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))?;
    let dependencies: Vec<_> = source_root
        .ancestors()
        .enumerate()
        .filter_map(|(level, ancestor)| {
            let path = ancestor.join("node_modules");
            path.is_dir().then_some((level, path))
        })
        .collect();
    let mut source_path = destination.clone();
    if let Some((outermost_level, _)) = dependencies.last() {
        for _ in 0..*outermost_level {
            source_path.push("source");
        }
    }
    let snapshot = FunctionsSourceSnapshot::new(destination.clone(), source_path.clone());
    secure_snapshot_directory(&destination)?;
    charge(1, 0)?;
    std::fs::create_dir_all(&source_path)
        .map_err(|error| format!("snapshot {}: {error}", source_path.display()))?;
    FunctionsSourceTraversal {
        root: &source_root,
        ignores,
        entry_budget: FunctionsSourceEntryBudget::default(),
        byte_budget: FunctionsSourceByteBudget::default(),
        charge,
        cancelled,
    }
    .copy_directory(&source_root, &source_path, 0)
    .and_then(|()| {
        for (level, dependencies) in dependencies {
            let ancestor = source_path
                .ancestors()
                .nth(level)
                .expect("the snapshot mirrors each dependency ancestor");
            link_dependency_directory(&dependencies, &ancestor.join("node_modules"))?;
        }
        Ok(())
    })?;
    let copied =
        functions_source_stamp_with_charge(&source_path, &[], charge, cancelled)?.content_signature;
    let after =
        functions_source_stamp_with_charge(&source_root, &[], charge, cancelled)?.content_signature;
    if before != copied || before != after {
        return Err(
            "Functions runtime inputs changed while capturing a reload snapshot".to_owned(),
        );
    }
    Ok(snapshot)
}

#[cfg(unix)]
fn secure_snapshot_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("snapshot {}: {e}", path.display()))
}

#[cfg(windows)]
fn secure_snapshot_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn link_dependency_directory(source: &Path, destination: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(source, destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))
}

#[cfg(windows)]
fn link_dependency_directory(source: &Path, destination: &Path) -> Result<(), String> {
    std::os::windows::fs::symlink_dir(source, destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))
}

#[derive(Clone)]
struct ReloadResources {
    scan_budget: Arc<FunctionsSourceScanBudget>,
    node_probe_cache: Arc<NodeProbeCache>,
}

fn start_reload_supervisors(
    runtime: &Arc<FunctionsRuntime>,
    cfg: &RuntimeConfig,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
    node_probe_cache: &Arc<NodeProbeCache>,
) {
    let resources = ReloadResources {
        scan_budget: Arc::new(FunctionsSourceScanBudget::new()),
        node_probe_cache: node_probe_cache.clone(),
    };
    for codebase in cfg.functions_to_load() {
        tokio::spawn(supervise_codebase_reloads(
            Arc::downgrade(runtime),
            cfg.clone(),
            codebase,
            hosts.clone(),
            runner_secret.to_owned(),
            callable_trusted_protocol,
            resources.clone(),
        ));
    }
}

async fn join_codebase_starts<T: Send + 'static>(
    starts: Vec<(String, tokio::task::JoinHandle<Result<T, String>>)>,
) -> Vec<Result<T, String>> {
    let mut outcomes = Vec::with_capacity(starts.len());
    for (label, start) in starts {
        outcomes.push(match start.await {
            Ok(outcome) => outcome,
            Err(error) => Err(format!(
                "the Functions codebase {label:?}: startup task failed: {error}"
            )),
        });
    }
    outcomes
}

async fn discard_reload_snapshot(snapshot: FunctionsSourceSnapshot, codebase: &str) {
    if let Err(reason) = snapshot.remove().await {
        eprintln!("warning: functions[{codebase}]: {reason}");
    }
}

fn warn_reload_once(last: &mut bool, codebase: &str, operation: &str, reason: &str) -> bool {
    let first = !*last;
    if first {
        eprintln!("warning: functions[{codebase}] reload {operation} failed: {reason}");
    }
    *last = true;
    first
}

fn source_scan_retry_delay(previous: Duration, reason: Option<&str>) -> Duration {
    match reason {
        None => Duration::from_millis(750),
        Some(reason) if reason.starts_with(SOURCE_BYTE_BUDGET_ERROR_PREFIX) => {
            Duration::from_secs(30)
        }
        Some(_) => previous
            .max(Duration::from_millis(750))
            .saturating_mul(2)
            .min(Duration::from_secs(8)),
    }
}

async fn changed_source_stamp(
    root: &Path,
    codebase: &FunctionsCodebase,
    scan_budget: &FunctionsSourceScanBudget,
    observed_stamp: &mut Option<FunctionsSourceStamp>,
    last_scan_error: &mut bool,
    retry_delay: &mut Duration,
) -> Option<FunctionsSourceStamp> {
    let next_stamp = match scan_budget.scan(root, &codebase.ignore).await {
        Ok(stamp) => {
            *last_scan_error = false;
            *retry_delay = source_scan_retry_delay(*retry_delay, None);
            stamp
        }
        Err(reason) => {
            *retry_delay = source_scan_retry_delay(*retry_delay, Some(&reason));
            warn_reload_once(last_scan_error, &codebase.codebase, "scan", &reason);
            return None;
        }
    };
    if *observed_stamp == Some(next_stamp) {
        return None;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let stable_stamp = scan_budget
        .scan(root, &codebase.ignore)
        .await
        .unwrap_or(next_stamp);
    if stable_stamp != next_stamp {
        return None;
    }
    if observed_stamp.is_none() {
        *observed_stamp = Some(stable_stamp);
        return None;
    }
    if observed_stamp.map(|stamp| stamp.content_signature) == Some(stable_stamp.content_signature) {
        *observed_stamp = Some(stable_stamp);
        return None;
    }
    Some(stable_stamp)
}

async fn wait_for_fixed_inspector_port_release(port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                drop(listener);
                return Ok(());
            }
            Err(cause) if tokio::time::Instant::now() >= deadline => {
                return Err(format!(
                    "fixed inspector port {port} did not become available after stopping the previous runner: {cause}"
                ));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}

async fn prepare_fixed_inspector_reload(
    runtime: &Arc<FunctionsRuntime>,
    codebase: &str,
    port: u16,
) -> Result<fireemu_adapter_functions::runtime::RunnerRestartGuard, String> {
    // A fixed inspector port cannot be bound by both generations at once.
    let restart_guard = runtime
        .stop_runner_for_fixed_inspector_reload(codebase)
        .await?;
    wait_for_fixed_inspector_port_release(port, Duration::from_secs(3)).await?;
    Ok(restart_guard)
}

fn report_reload_install(
    result: Result<u64, String>,
    fixed_inspector: bool,
    codebase: &str,
    stable_stamp: FunctionsSourceStamp,
    observed_stamp: &mut Option<FunctionsSourceStamp>,
    last_start_error: &mut bool,
) {
    match result {
        Ok(generation) => {
            *observed_stamp = Some(stable_stamp);
            *last_start_error = false;
            eprintln!("note: functions[{codebase}]: reloaded generation {generation}");
        }
        Err(reason) if fixed_inspector => {
            *observed_stamp = Some(stable_stamp);
            warn_reload_once(
                last_start_error,
                codebase,
                "install after stopping the previous runner",
                &reason,
            );
        }
        Err(reason) => eprintln!("warning: functions[{codebase}]: reload rejected: {reason}"),
    }
}

async fn snapshot_consistent_reload_source(
    root: &Path,
    codebase: &FunctionsCodebase,
    scan_budget: &FunctionsSourceScanBudget,
    stable: u64,
    retry_delay: &mut Duration,
    last_snapshot_error: &mut bool,
) -> Option<FunctionsSourceSnapshot> {
    let snapshot = match scan_budget.snapshot(root, &codebase.ignore).await {
        Ok(snapshot) => {
            *last_snapshot_error = false;
            snapshot
        }
        Err(reason) => {
            *retry_delay = source_scan_retry_delay(*retry_delay, Some(&reason));
            warn_reload_once(last_snapshot_error, &codebase.codebase, "snapshot", &reason);
            return None;
        }
    };
    let (snapshot_stamp, current_stamp) = tokio::join!(
        scan_budget.scan(&snapshot, &codebase.ignore),
        scan_budget.scan(root, &codebase.ignore),
    );
    if snapshot_stamp.as_ref().map(|stamp| stamp.content_signature) != Ok(stable)
        || current_stamp.as_ref().map(|stamp| stamp.content_signature) != Ok(stable)
    {
        discard_reload_snapshot(snapshot, &codebase.codebase).await;
        return None;
    }
    Some(snapshot)
}

async fn supervise_codebase_reloads(
    weak_runtime: std::sync::Weak<FunctionsRuntime>,
    cfg: RuntimeConfig,
    codebase: FunctionsCodebase,
    hosts: EmulatorHosts,
    secret: String,
    callable_trusted_protocol: bool,
    resources: ReloadResources,
) {
    let root = PathBuf::from(&codebase.source);
    let initial_stamp = resources.scan_budget.scan(&root, &codebase.ignore).await;
    let mut observed_stamp = initial_stamp.as_ref().ok().copied();
    let mut last_scan_error = false;
    let mut last_snapshot_error = false;
    let mut last_start_error = false;
    let mut retry_delay = source_scan_retry_delay(
        Duration::from_millis(750),
        initial_stamp.as_ref().err().map(String::as_str),
    );
    if let Err(reason) = initial_stamp {
        warn_reload_once(&mut last_scan_error, &codebase.codebase, "scan", &reason);
    }
    loop {
        tokio::time::sleep(retry_delay).await;
        let Some(runtime) = weak_runtime.upgrade() else {
            return;
        };
        let Some(stable_stamp) = changed_source_stamp(
            &root,
            &codebase,
            &resources.scan_budget,
            &mut observed_stamp,
            &mut last_scan_error,
            &mut retry_delay,
        )
        .await
        else {
            continue;
        };
        let stable = stable_stamp.content_signature;
        let Some(snapshot) = snapshot_consistent_reload_source(
            &root,
            &codebase,
            &resources.scan_budget,
            stable,
            &mut retry_delay,
            &mut last_snapshot_error,
        )
        .await
        else {
            continue;
        };
        let _restart_guard = if let Some(port) = cfg.functions_inspect_port {
            match prepare_fixed_inspector_reload(&runtime, &codebase.codebase, port).await {
                Ok(guard) => Some(guard),
                Err(reason) => {
                    warn_reload_once(&mut last_start_error, &codebase.codebase, "start", &reason);
                    discard_reload_snapshot(snapshot, &codebase.codebase).await;
                    continue;
                }
            }
        } else {
            None
        };
        let mut staged = codebase.clone();
        staged.source = snapshot.to_string_lossy().into_owned();
        match start_codebase(
            &cfg,
            &staged,
            &hosts,
            &secret,
            callable_trusted_protocol,
            &resources.node_probe_cache,
        )
        .await
        {
            Ok(mut spec) => {
                spec.cleanup_dir = Some(snapshot.into_path());
                report_reload_install(
                    runtime.reload_codebase(spec),
                    cfg.functions_inspect_port.is_some(),
                    &codebase.codebase,
                    stable_stamp,
                    &mut observed_stamp,
                    &mut last_start_error,
                );
            }
            Err(reason) => {
                if cfg.functions_inspect_port.is_some() {
                    warn_reload_once(
                        &mut last_start_error,
                        &codebase.codebase,
                        "start after stopping the previous runner",
                        &reason,
                    );
                } else {
                    eprintln!(
                        "warning: functions[{}]: reload failed; keeping the last-known-good generation: {reason}",
                        codebase.codebase
                    );
                }
                discard_reload_snapshot(snapshot, &codebase.codebase).await;
            }
        }
    }
}

/// The debug feature the callable trusted protocol turns on, and nothing else.
///
/// `firebase-functions` reads `FIREBASE_DEBUG_MODE` once when it is first required and
/// re-reads `FIREBASE_DEBUG_FEATURES` per lookup. `skipTokenVerification` makes the callable
/// wrapper decode the App Check and Auth credentials locally instead of calling out to Google,
/// which is only safe because the daemon has already verified and re-inserted both
/// (specification section 13.4). No other feature is enabled: `enableCors`, in particular,
/// would change what the functions themselves answer.
const DEBUG_FEATURES: &str = r#"{"skipTokenVerification":true}"#;

/// `FIREBASE_CONFIG`, with the three members the official emulator puts in it
/// (`functionsEmulator.js:1010-1026` with `constructDefaultAdminSdkConfig`,
/// `adminSdkConfig.js:13`).
///
/// `databaseURL` is present even though fireemu serves no Realtime Database, and points where
/// the official emulator points it when no Database emulator is running:
/// `https://<project>.firebaseio.com`. It is not decoration. `firebase-functions/v1`
/// `database.ref(...)` reads it while the endpoint is being described and throws
/// `Missing expected firebase config value databaseURL` when it is absent, so omitting the
/// key turns a codebase with one v1 Realtime Database trigger into a runner that dies with a
/// stack trace instead of a codebase whose unserved trigger is named.
#[must_use]
pub fn firebase_config(project: &str) -> String {
    serde_json::json!({
        "storageBucket": format!("{project}.appspot.com"),
        "databaseURL": format!("https://{project}.firebaseio.com"),
        "projectId": project,
    })
    .to_string()
}

/// The user environment of one codebase: the dotenv chain, invocation-scoped local secrets
/// and the legacy runtime configuration, with the files each came from.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UserEnvironment {
    /// `.env` chain values, later files having overridden earlier ones.
    pub values: Vec<(String, String)>,
    /// `.secret.local` values. The runner withholds them during discovery and exposes each
    /// value only while a function that declared the corresponding secret is running.
    pub secrets: Vec<(String, String)>,
    /// `CLOUD_RUNTIME_CONFIG`, when the codebase carries a `.runtimeconfig.json`.
    pub runtime_config: Option<String>,
    /// The files that were read, in the order they were applied, for the startup line.
    pub files: Vec<String>,
}

impl std::fmt::Debug for UserEnvironment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserEnvironment")
            .field("values", &"[redacted]")
            .field("secrets", &"[redacted]")
            .field("runtime_config", &"[redacted]")
            .field("files", &self.files)
            .finish()
    }
}

fn redacted_environment_parse_error(error: &str) -> &str {
    if error.starts_with("Invalid dotenv file") {
        "Invalid dotenv file, error on lines: [redacted]"
    } else {
        error
    }
}

/// Parent variables the official CLI would leave on the Functions child, excluding names
/// owned by the emulator and ambient Google credentials. Function code is trusted local code,
/// but these exclusions keep the callable trust boundary and the no-ADC guarantee intact.
fn inheritable_parent_environment() -> Vec<(String, String)> {
    use fireemu_core_functions::env;

    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| {
            env::validate_key(name).is_ok()
                && name != "GOOGLE_APPLICATION_CREDENTIALS"
                && !name.starts_with("CLOUDSDK_")
                && !name.starts_with("FIREEMU_")
        })
        .collect()
}

impl UserEnvironment {
    /// Non-secret values applied while the codebase is loaded.
    #[must_use]
    pub fn applied(&self) -> Vec<(String, String)> {
        let mut out = self.values.clone();
        if let Some(config) = &self.runtime_config {
            out.push(("CLOUD_RUNTIME_CONFIG".to_owned(), config.clone()));
        }
        out
    }
}

/// Reads a codebase's `.env` chain, `.secret.local` and `.runtimeconfig.json`.
///
/// The chain and its refusals are the official ones (`fireemu_core_functions::env`); the two
/// files that are not dotenv chains follow `functionsEmulator.js`:
///
/// - `.secret.local` is parsed strictly and is the *only* source of `defineSecret` values here.
///   The official emulator falls back to Google Cloud Secret
///   Manager for a secret the file does not carry; fireemu has no credentials and never
///   reaches the network, so a missing secret stays missing and the parameter resolves the way
///   an unset environment variable resolves.
/// - `.runtimeconfig.json` becomes `CLOUD_RUNTIME_CONFIG`, as `getRuntimeConfig` makes it. An
///   unreadable or malformed file is reported and treated as absent, which is what that
///   function's empty `catch` does. Note that the pinned `firebase-functions@7.3.2` has
///   *removed* `functions.config()` -- calling it throws `functions.config() has been removed
///   in firebase-functions v7` -- so the variable is passed through for a codebase pinned to
///   v6 or reading it itself, and no supported SDK surface consumes it.
pub fn load_user_environment(
    dir: &Path,
    project_id: &str,
    alias: Option<&str>,
) -> Result<UserEnvironment, String> {
    use fireemu_core_functions::env;
    let mut out = UserEnvironment::default();
    let present = |name: &str| dir.join(name).is_file();
    if let Some(alias) = alias {
        if present(&format!(".env.{project_id}")) && present(&format!(".env.{alias}")) {
            return Err(env::both_project_files_error(project_id, alias));
        }
    }
    for name in env::env_file_order(project_id, alias) {
        let path = dir.join(&name);
        if !path.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to load environment variables from {name}. ({e})"))?;
        let values = env::parse_strict(&text).map_err(|e| {
            format!(
                "Failed to load environment variables from {name}. {}",
                redacted_environment_parse_error(&e)
            )
        })?;
        for (k, v) in values {
            out.values.retain(|(existing, _)| existing != &k);
            out.values.push((k, v));
        }
        out.files.push(name);
    }
    let secrets = dir.join(env::LOCAL_SECRETS_FILE);
    if secrets.is_file() {
        let text = std::fs::read_to_string(&secrets).map_err(|e| {
            format!(
                "Failed to read local secrets file {}: {e}",
                secrets.display()
            )
        })?;
        out.secrets = env::parse_strict(&text)
            .map_err(|e| {
                format!(
                    "Failed to read local secrets file {}: {}",
                    secrets.display(),
                    redacted_environment_parse_error(&e)
                )
            })?
            .into_iter()
            .collect();
        out.values
            .retain(|(name, _)| !out.secrets.iter().any(|(secret, _)| secret == name));
    }
    let runtime_config = dir.join(env::RUNTIME_CONFIG_FILE);
    if runtime_config.is_file() {
        match std::fs::read_to_string(&runtime_config)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        {
            Some(value) => out.runtime_config = Some(value.to_string()),
            // `Found .runtimeconfig.json but the JSON format is invalid.`
            // (`emulatorLogger.js:199`), and the runtime is started without it.
            None => eprintln!(
                "note: found {} but the JSON format is invalid; functions.config() will be empty",
                runtime_config.display()
            ),
        }
    }
    Ok(out)
}

/// What to do with an export whose trigger family belongs to a product fireemu does not
/// serve (`functions.unservedTriggers`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UnservedTriggers {
    /// Fail discovery, naming every such function. The default: a project whose Realtime
    /// Database trigger will never run must not be told the emulator started.
    #[default]
    Refuse,
    /// Print one line per function and carry on, which is what the official emulator does
    /// with a trigger service it has no emulator for.
    Report,
}

impl UnservedTriggers {
    /// Parses the configuration spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "refuse" => Some(Self::Refuse),
            "report" => Some(Self::Report),
            _ => None,
        }
    }
}

/// The line the daemon prints for one ignored export, in the official emulator's shape
/// (`functions[<region>-<name>]: function ignored because ...`, `functionsEmulator.js:501`).
#[must_use]
pub fn ignored_line(f: &fireemu_core_functions::manifest::IgnoredFunction) -> String {
    format!(
        "functions[{}-{}]: function ignored ({}): {}",
        f.region, f.name, f.trigger_type, f.reason
    )
}

/// Applies `policy` to everything the runner discovered and could not serve.
///
/// Nothing is dropped in silence, in either outcome: an unrecognised shape is reported on
/// stderr the way the official emulator reports it and stays in the manifest inventory, while
/// a trigger family that belongs to a product fireemu does not serve fails discovery with
/// every such function named -- unless the configuration asked for it to be reported instead.
pub fn check_ignored(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    policy: UnservedTriggers,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut fatal = Vec::new();
    for f in &manifest.ignored {
        if f.scope.is_product_decision() && policy == UnservedTriggers::Refuse {
            fatal.push(format!("{} ({}): {}", f.name, f.trigger_type, f.reason));
        } else {
            lines.push(ignored_line(f));
        }
    }
    if fatal.is_empty() {
        return Ok(lines);
    }
    Err(format!(
        "the functions codebase exports {} trigger(s) that belong to a product fireemu does \
         not serve, so they would never run: {}. Remove them, or set \
         functions.unservedTriggers = \"report\" to start anyway with each one named",
        fatal.len(),
        fatal.join("; ")
    ))
}

/// Addresses the runner's functions need to reach the daemon. `None` means the service was
/// not selected by `--only`: its variable is then left unset in the runner, so a handler
/// cannot reach a product this run is not serving.
#[derive(Debug, Clone)]
pub struct EmulatorHosts {
    /// Firestore gRPC / REST.
    pub firestore: Option<String>,
    /// Auth REST.
    pub auth: Option<String>,
    /// Storage.
    pub storage: Option<String>,
    /// The Functions HTTP listener.
    pub functions: Option<String>,
    /// The Eventarc HTTP listener. It carries an `http://` prefix in the runner environment.
    pub eventarc: Option<String>,
    /// The Cloud Tasks HTTP listener, exported as a bare host and port.
    pub tasks: Option<String>,
    /// The Logging emulator WebSocket (`FIREBASE_LOGGING_EMULATOR_HOST`), a bare host:port. The
    /// runner's functions inherit it so any Firebase tooling they load can find the log stream.
    pub logging: Option<String>,
    /// Pub/Sub listener, exported as a bare host and port.
    pub pubsub: Option<String>,
    /// Emulator Hub listener, exported as a bare host and port.
    pub hub: Option<String>,
}

/// Where a located runner script came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerSource {
    /// `FIREEMU_RUNNER_NODE` named it.
    Environment,
    /// A `runner-node/` directory shipped beside the binary: the release layout, in which the
    /// platform package holds `bin/fireemu` next to `bin/runner-node/index.mjs`.
    BesideBinary,
    /// `tools/runner-node/` in the workspace this binary was built from (development builds).
    WorkspaceSource,
}

impl RunnerSource {
    /// A short phrase for `doctor` and for error messages.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Environment => "FIREEMU_RUNNER_NODE",
            Self::BesideBinary => "bundled beside the binary",
            Self::WorkspaceSource => "workspace source tree",
        }
    }
}

/// The bundled Node runner as located on this host.
#[derive(Debug, Clone)]
pub struct RunnerScript {
    /// Absolute path of `index.mjs`.
    pub path: PathBuf,
    /// Where it was found.
    pub source: RunnerSource,
}

/// Every place the runner is looked for, in the order they are tried.
///
/// `FIREEMU_RUNNER_NODE` wins outright so a consumer can point the daemon at a runner of its
/// own. Otherwise the release layout is preferred over the source tree: a packaged binary must
/// never reach back into the machine that built it. Two shapes are accepted beside the binary,
/// `<exe dir>/runner-node/` and `<exe dir>/../runner-node/`, so the script can sit either next
/// to the executable or one level up in a package root.
#[must_use]
pub fn runner_candidates() -> Vec<(RunnerSource, PathBuf)> {
    let mut out = Vec::new();
    if let Some(script) = std::env::var_os("FIREEMU_RUNNER_NODE") {
        out.push((RunnerSource::Environment, PathBuf::from(script)));
    }
    if let Ok(exe) = std::env::current_exe() {
        // The executable may be reached through a symlink (npm's `node_modules/.bin`), and the
        // runner lives beside the real file, not beside the link.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(dir) = exe.parent() {
            out.push((
                RunnerSource::BesideBinary,
                dir.join("runner-node").join("index.mjs"),
            ));
            if let Some(up) = dir.parent() {
                out.push((
                    RunnerSource::BesideBinary,
                    up.join("runner-node").join("index.mjs"),
                ));
            }
        }
    }
    if let Some(script) = workspace_runner() {
        out.push((RunnerSource::WorkspaceSource, script));
    }
    out
}

/// How many directories above the executable the workspace walk inspects.
///
/// The deepest supported layout, `target/agent/<session>/<mode>/<profile>/fireemu` (the
/// `scripts/cargo-session` wrapper), puts the workspace root six directories up; a couple of
/// extra levels keep the walk from being one directory short again if a wrapper nests
/// deeper, while still stopping well before the filesystem root.
const WORKSPACE_RUNNER_SEARCH_DEPTH: usize = 8;

/// The runner in the source tree, for a binary that runs out of a cargo `target/` directory.
///
/// The workspace is recognised at run time by walking up from the executable to a directory
/// holding both `Cargo.toml` and `tools/runner-node/index.mjs`; nothing about the build
/// machine is compiled in. (An `env!("CARGO_MANIFEST_DIR")` string here would survive
/// `--remap-path-prefix`, which only rewrites debug info and panic locations, and would make
/// the same commit build to different bytes from different checkouts.) The ancestor walk
/// covers `target/<profile>/`, `target/<triple>/<profile>/` and the session wrapper's
/// `target/agent/<session>/<mode>/<profile>/`, and gives up after
/// [`WORKSPACE_RUNNER_SEARCH_DEPTH`] directories or at the filesystem root, whichever comes
/// first.
fn workspace_runner() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    workspace_runner_from(&exe)
}

/// [`workspace_runner`] for a given executable path, so the search depth can be exercised
/// against a synthetic tree without building a binary at that depth.
fn workspace_runner_from(exe: &Path) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .take(WORKSPACE_RUNNER_SEARCH_DEPTH)
        .find_map(|root| {
            let script = root.join("tools").join("runner-node").join("index.mjs");
            (root.join("Cargo.toml").is_file() && script.is_file()).then_some(script)
        })
}

/// Locates the bundled Node runner, or explains every place that was tried.
///
/// The environment override is reported as missing rather than silently skipped: a consumer
/// that named a runner meant that one, and falling back to another would run different code
/// than it asked for.
pub fn locate_runner() -> Result<RunnerScript, String> {
    let candidates = runner_candidates();
    if let Some((source, path)) = candidates.first() {
        if *source == RunnerSource::Environment && !path.is_file() {
            return Err(format!(
                "FIREEMU_RUNNER_NODE names {}, which is not a readable file",
                path.display()
            ));
        }
    }
    for (source, path) in &candidates {
        if path.is_file() {
            return Ok(RunnerScript {
                path: std::path::absolute(path)
                    .map_err(|error| format!("runner {}: {error}", path.display()))?,
                source: *source,
            });
        }
    }
    Err(format!(
        "the bundled Node runner (runner-node/index.mjs) was not found; tried {}. Set \
         FIREEMU_RUNNER_NODE to an index.mjs, or reinstall the platform package that ships it",
        candidates
            .iter()
            .map(|(_, p)| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(not(windows), test))]
struct NodeInstallation {
    program: PathBuf,
    version: String,
    major: u32,
    minor: u32,
    patch: u32,
    require_module: bool,
}

#[cfg(any(not(windows), test))]
fn parse_node_version(text: &str) -> Option<(String, u32, u32, u32)> {
    let version = text.trim().strip_prefix('v').unwrap_or(text.trim());
    let core = version.split_once('-').map_or(version, |(core, _)| core);
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((version.to_owned(), major, minor, patch))
}

#[cfg(any(not(windows), test))]
fn requirement_parts(text: &str) -> Option<Vec<Option<u32>>> {
    let text = text.trim().trim_start_matches('v');
    if text.is_empty() {
        return None;
    }
    text.split('.')
        .map(|part| match part {
            "x" | "X" | "*" => Some(None),
            _ => part.parse().ok().map(Some),
        })
        .collect()
}

#[cfg(any(not(windows), test))]
fn version_floor(parts: &[Option<u32>]) -> Option<(u32, u32, u32)> {
    Some((
        parts.first().copied().flatten()?,
        parts.get(1).copied().flatten().unwrap_or(0),
        parts.get(2).copied().flatten().unwrap_or(0),
    ))
}

#[cfg(any(not(windows), test))]
fn node_engine_token_matches(token: &str, actual: (u32, u32, u32)) -> Option<bool> {
    for operator in [">=", "<=", ">", "<"] {
        if let Some(version) = token.strip_prefix(operator) {
            let parts = requirement_parts(version)?;
            if parts.first().is_some_and(Option::is_none) {
                return Some(matches!(operator, ">=" | "<="));
            }
            let expected = version_floor(&parts)?;
            let partial_at = parts
                .iter()
                .position(Option::is_none)
                .or((parts.len() < 3).then_some(parts.len()));
            let next_partial = match partial_at {
                Some(1) => Some((expected.0.checked_add(1)?, 0, 0)),
                Some(2) => Some((expected.0, expected.1.checked_add(1)?, 0)),
                _ => None,
            };
            return Some(match operator {
                ">=" => actual >= expected,
                "<=" => next_partial.map_or(actual <= expected, |upper| actual < upper),
                ">" => next_partial.map_or(actual > expected, |upper| actual >= upper),
                "<" => actual < expected,
                _ => unreachable!(),
            });
        }
    }

    if let Some(version) = token.strip_prefix('^') {
        let lower = version_floor(&requirement_parts(version)?)?;
        let upper = if lower.0 > 0 {
            (lower.0.checked_add(1)?, 0, 0)
        } else if lower.1 > 0 {
            (0, lower.1.checked_add(1)?, 0)
        } else {
            (0, 0, lower.2.checked_add(1)?)
        };
        return Some(actual >= lower && actual < upper);
    }
    if let Some(version) = token.strip_prefix('~') {
        let parts = requirement_parts(version)?;
        let lower = version_floor(&parts)?;
        let upper = if parts.len() >= 2 && parts[1].is_some() {
            (lower.0, lower.1.checked_add(1)?, 0)
        } else {
            (lower.0.checked_add(1)?, 0, 0)
        };
        return Some(actual >= lower && actual < upper);
    }

    let token = token.strip_prefix('=').unwrap_or(token);
    let parts = requirement_parts(token)?;
    if parts.first().is_some_and(Option::is_none) {
        return Some(true);
    }
    let lower = version_floor(&parts)?;
    if parts.len() == 1 || parts.get(1).is_some_and(Option::is_none) {
        return Some(actual >= lower && actual < (lower.0.checked_add(1)?, 0, 0));
    }
    if parts.len() == 2 || parts.get(2).is_some_and(Option::is_none) {
        return Some(actual >= lower && actual < (lower.0, lower.1.checked_add(1)?, 0));
    }
    Some(actual == lower)
}

#[cfg(any(not(windows), test))]
fn node_engine_matches(expression: &str, actual: (u32, u32, u32)) -> Result<bool, String> {
    let expression = expression.trim();
    if expression.is_empty() {
        return Err("package.json engines.node is empty".to_owned());
    }
    for alternative in expression.split("||") {
        let normalized = alternative.replace(',', " ");
        let tokens: Vec<&str> = normalized.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(format!(
                "package.json engines.node {expression:?} is not a supported semver expression"
            ));
        }
        if let [lower, "-", upper] = tokens.as_slice() {
            let lower_parts = requirement_parts(lower).ok_or_else(|| {
                format!("package.json engines.node {expression:?} is not supported")
            })?;
            let lower = if lower_parts.first().is_some_and(Option::is_none) {
                None
            } else {
                Some(version_floor(&lower_parts).ok_or_else(|| {
                    format!("package.json engines.node {expression:?} is not supported")
                })?)
            };
            let upper_parts = requirement_parts(upper).ok_or_else(|| {
                format!("package.json engines.node {expression:?} is not supported")
            })?;
            let below_upper = if upper_parts.first().is_some_and(Option::is_none) {
                true
            } else {
                let upper = version_floor(&upper_parts).ok_or_else(|| {
                    format!("package.json engines.node {expression:?} is not supported")
                })?;
                let partial_at = upper_parts
                    .iter()
                    .position(Option::is_none)
                    .or((upper_parts.len() < 3).then_some(upper_parts.len()));
                if partial_at == Some(1) {
                    actual
                        < (
                            upper.0.checked_add(1).ok_or_else(|| {
                                format!("package.json engines.node {expression:?} overflows")
                            })?,
                            0,
                            0,
                        )
                } else if partial_at == Some(2) {
                    actual
                        < (
                            upper.0,
                            upper.1.checked_add(1).ok_or_else(|| {
                                format!("package.json engines.node {expression:?} overflows")
                            })?,
                            0,
                        )
                } else {
                    actual <= upper
                }
            };
            if lower.is_none_or(|lower| actual >= lower) && below_upper {
                return Ok(true);
            }
            continue;
        }
        let mut matches = true;
        for token in tokens {
            let Some(token_matches) = node_engine_token_matches(token, actual) else {
                return Err(format!(
                    "package.json engines.node {expression:?} is not a supported semver expression"
                ));
            };
            matches &= token_matches;
        }
        if matches {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(not(windows), test))]
fn package_node_engine(source: &Path) -> Result<Option<String>, String> {
    let path = source.join("package.json");
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let package: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
    match package.pointer("/engines/node") {
        None => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("{}: engines.node must be a string", path.display())),
    }
}

/// Keeps `candidate` under its own name: version managers install `node` as a symlink to a
/// multi-tool shim that refuses to run when invoked as anything else (Volta exits 126 with
/// "'volta-shim' should not be called directly"). The canonical path only deduplicates
/// entries that resolve to the same file.
fn push_node_candidate(out: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !node_candidate_is_executable(&candidate) {
        return;
    }
    let canonical = std::fs::canonicalize(&candidate).unwrap_or_else(|_| candidate.clone());
    let duplicate = out.iter().any(|existing| {
        std::fs::canonicalize(existing).unwrap_or_else(|_| existing.clone()) == canonical
    });
    if !duplicate {
        out.push(candidate);
    }
}

fn node_candidate_is_executable(candidate: &Path) -> bool {
    if !candidate.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(candidate)
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn path_node_candidates(path: &std::ffi::OsStr) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for directory in std::env::split_paths(path)
        .filter(|directory| directory.is_absolute())
        .take(64)
    {
        #[cfg(not(windows))]
        let candidate = directory.join("node");
        #[cfg(windows)]
        let candidate = directory.join("node.exe");
        if node_candidate_is_executable(&candidate) {
            push_node_candidate(&mut candidates, candidate);
            break;
        }
    }
    candidates
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct NodeProbeKey {
    path: Option<std::ffi::OsString>,
    volta_home: Option<std::ffi::OsString>,
    fireemu_node: Option<std::ffi::OsString>,
}

impl NodeProbeKey {
    fn current() -> Self {
        Self {
            path: std::env::var_os("PATH"),
            volta_home: std::env::var_os("VOLTA_HOME"),
            fireemu_node: std::env::var_os("FIREEMU_NODE"),
        }
    }
}

fn node_candidates(key: &NodeProbeKey) -> Result<(Vec<PathBuf>, bool), String> {
    if let Some(program) = &key.fireemu_node {
        let program = PathBuf::from(program);
        if !program.is_absolute() || !node_candidate_is_executable(&program) {
            return Err(format!(
                "FIREEMU_NODE names {}, which is not an executable file",
                program.display()
            ));
        }
        let mut candidates = Vec::new();
        push_node_candidate(&mut candidates, program);
        return Ok((candidates, true));
    }

    let mut candidates = key
        .path
        .as_ref()
        .map(|path| path_node_candidates(path))
        .unwrap_or_default();
    if let Some(home) = &key.volta_home {
        let root = PathBuf::from(home).join("tools/image/node");
        if root.is_absolute() {
            if let Ok(entries) = std::fs::read_dir(root) {
                let mut entries: Vec<_> = entries.filter_map(Result::ok).take(64).collect();
                entries.sort_by_key(std::fs::DirEntry::file_name);
                for entry in entries {
                    #[cfg(not(windows))]
                    push_node_candidate(&mut candidates, entry.path().join("bin/node"));
                    #[cfg(windows)]
                    push_node_candidate(&mut candidates, entry.path().join("node.exe"));
                }
            }
        }
    }
    candidates.truncate(16);
    Ok((candidates, false))
}

#[cfg(not(windows))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbedNodeCandidates {
    installations: Vec<NodeInstallation>,
    errors: Vec<String>,
    explicit_node: bool,
}

#[derive(Default)]
struct NodeProbeCache {
    #[cfg(not(windows))]
    entries: Mutex<HashMap<NodeProbeKey, NodeProbeEntry>>,
}

#[cfg(not(windows))]
type NodeProbeEntry = Arc<OnceLock<Result<ProbedNodeCandidates, String>>>;

#[cfg(not(windows))]
impl NodeProbeCache {
    fn probed(&self, key: &NodeProbeKey) -> Result<ProbedNodeCandidates, String> {
        let entry = self
            .entries
            .lock()
            .map_err(|_| "Node probe cache lock is poisoned".to_owned())?
            .entry(key.clone())
            .or_default()
            .clone();
        let result = entry.get_or_init(|| probe_node_candidates(key)).clone();
        let successful = result
            .as_ref()
            .is_ok_and(|probed| !probed.installations.is_empty() && probed.errors.is_empty());
        if !successful {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| "Node probe cache lock is poisoned".to_owned())?;
            if entries
                .get(key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                entries.remove(key);
            }
        }
        result
    }
}

#[cfg(not(windows))]
fn probe_node_candidates(key: &NodeProbeKey) -> Result<ProbedNodeCandidates, String> {
    let (candidates, explicit_node) = node_candidates(key)?;
    let mut installations = Vec::new();
    let mut errors = Vec::new();
    for candidate in candidates {
        match probe_node(&candidate) {
            Ok(installation) => {
                installations.push(installation);
                if explicit_node {
                    break;
                }
            }
            Err(error) => errors.push(error),
        }
    }
    Ok(ProbedNodeCandidates {
        installations,
        errors,
        explicit_node,
    })
}

async fn run_node_selection_blocking<F, T>(work: F) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|error| format!("Node selection task failed: {error}"))
}

#[cfg(not(windows))]
fn run_node_probe(program: &Path, arguments: &[&str], label: &str) -> Result<Vec<u8>, String> {
    const MAX_OUTPUT_BYTES: usize = 256;
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start Node {label}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("Node {label} stdout unavailable"))?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(257).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("could not wait for Node {label}: {error}"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            let _ = Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", child.id())])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("Node {label} timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let output = receiver.recv_timeout(remaining).map_err(|_| {
        #[cfg(unix)]
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        format!("Node {label} timed out")
    })?;
    if !status.success() {
        return Err(format!("Node {label} exited with {status}"));
    }
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(format!("Node {label} output exceeded 256 bytes"));
    }
    Ok(output)
}

#[cfg(not(windows))]
fn probe_node(program: &Path) -> Result<NodeInstallation, String> {
    let output = run_node_probe(program, &["--version"], "--version")?;
    let text = String::from_utf8_lossy(&output);
    let (version, major, minor, patch) = parse_node_version(&text)
        .ok_or_else(|| "Node --version returned an unrecognised version".to_owned())?;
    let feature = run_node_probe(
        program,
        &["-p", "String(process.features?.require_module === true)"],
        "loader feature probe",
    )?;
    let require_module = match String::from_utf8_lossy(&feature).trim() {
        "true" => true,
        "false" => false,
        _ => return Err("Node loader feature probe returned an unrecognised value".to_owned()),
    };
    Ok(NodeInstallation {
        program: program.to_path_buf(),
        version,
        major,
        minor,
        patch,
        require_module,
    })
}

#[cfg(any(not(windows), test))]
fn request_prefers_require_module(
    runtime_major: Option<u32>,
    engines: Option<&str>,
    installations: &[NodeInstallation],
) -> Result<bool, String> {
    if let Some(runtime_major) = runtime_major {
        return Ok(runtime_major >= 20);
    }
    let Some(engines) = engines else {
        return Ok(false);
    };
    for installation in installations {
        if installation.major >= 20
            && node_engine_matches(
                engines,
                (installation.major, installation.minor, installation.patch),
            )?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(not(windows), test))]
fn select_node_installation(
    runtime_major: Option<u32>,
    engines: Option<&str>,
    installations: &[NodeInstallation],
) -> Result<usize, String> {
    if installations.is_empty() {
        return Err("no usable Node executable was found on PATH or in VOLTA_HOME".to_owned());
    }
    let engine_matches = installations
        .iter()
        .map(|installation| {
            engines.map_or(Ok(true), |expression| {
                node_engine_matches(
                    expression,
                    (installation.major, installation.minor, installation.patch),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prefer_require_module =
        request_prefers_require_module(runtime_major, engines, installations)?;
    let candidates = installations
        .iter()
        .enumerate()
        .map(
            |(index, installation)| fireemu_adapter_functions::node_selection::NodeCandidate {
                require_module: installation.require_module,
                runtime_matches: runtime_major.is_none_or(|major| installation.major == major),
                engine_matches: engine_matches[index],
            },
        )
        .collect::<Vec<_>>();
    fireemu_adapter_functions::node_selection::select_node_candidate(
        false,
        prefer_require_module,
        &candidates,
    )
    .ok_or_else(|| "no usable Node executable was found on PATH or in VOLTA_HOME".to_owned())
}

#[cfg(windows)]
fn default_runner_for_codebase(
    _codebase: &crate::config::FunctionsCodebase,
    _node_probe_cache: &NodeProbeCache,
) -> Result<Vec<String>, String> {
    let script = locate_runner()?;
    let (candidates, _) = node_candidates(&NodeProbeKey::current())?;
    let program = candidates.first().ok_or_else(|| {
        "no Node executable was found in an absolute PATH directory; set FIREEMU_NODE to an absolute executable or configure functions.runner explicitly".to_owned()
    })?;
    Ok(vec![
        program.display().to_string(),
        script.path.display().to_string(),
    ])
}

#[cfg(not(windows))]
fn default_runner_for_codebase(
    codebase: &crate::config::FunctionsCodebase,
    node_probe_cache: &NodeProbeCache,
) -> Result<Vec<String>, String> {
    let script = locate_runner()?;
    let engines = package_node_engine(Path::new(&codebase.source))?;
    if let Some(expression) = engines.as_deref() {
        let _ = node_engine_matches(expression, (0, 0, 0))?;
    }
    let probed = node_probe_cache.probed(&NodeProbeKey::current())?;
    let ProbedNodeCandidates {
        installations,
        errors: probe_errors,
        explicit_node,
    } = probed;
    let runtime_major = codebase.runtime.as_deref().and_then(|runtime| {
        runtime
            .strip_prefix("nodejs")
            .and_then(|major| major.parse::<u32>().ok())
    });
    if installations.is_empty() {
        let detail = if probe_errors.is_empty() {
            "no Node executable was found".to_owned()
        } else {
            probe_errors.join("; ")
        };
        return Err(format!(
            "the Functions codebase {:?}: {detail}; install Node, set FIREEMU_NODE, or configure functions.runner explicitly",
            codebase.codebase
        ));
    }
    let selected = if explicit_node {
        0
    } else {
        select_node_installation(runtime_major, engines.as_deref(), &installations)?
    };
    let installation = &installations[selected];
    let prefer_require_module =
        request_prefers_require_module(runtime_major, engines.as_deref(), &installations)?;
    if let Some(engines) = &engines {
        let matches_engine = node_engine_matches(
            engines,
            (installation.major, installation.minor, installation.patch),
        )?;
        if matches_engine {
            eprintln!(
                "note: functions[{}]: selected Node v{} for package.json engines.node {:?}{}",
                codebase.codebase,
                installation.version,
                engines,
                runtime_major
                    .filter(|major| *major != installation.major)
                    .map_or_else(String::new, |major| format!(
                        " (firebase runtime nodejs{major} is deployment metadata)"
                    ))
            );
        } else {
            eprintln!(
                "note: functions[{}]: selected Node v{} as a loader-capable local fallback; package.json engines.node {:?}{} does not include it",
                codebase.codebase,
                installation.version,
                engines,
                runtime_major.map_or_else(String::new, |major| format!(
                    " and firebase runtime nodejs{major}"
                ))
            );
        }
    } else if let Some(major) = runtime_major {
        if major != installation.major {
            eprintln!(
                "note: functions[{}]: firebase runtime nodejs{major} differs from local Node v{}; the local emulator uses the first usable Node on PATH",
                codebase.codebase, installation.version
            );
        }
    }
    if !installation.require_module && prefer_require_module {
        eprintln!(
            "note: functions[{}]: Node v{} cannot synchronously require ES modules from CommonJS; install Node 20.19+, Node 22.12+, or a newer release if module loading fails",
            codebase.codebase, installation.version
        );
    }
    Ok(vec![
        installation.program.display().to_string(),
        script.path.display().to_string(),
    ])
}

/// Starts one runner process per configured codebase and the runtime that multiplexes them,
/// and installs it as the backend's synchronous commit observer (Storage events are wired by
/// the caller through [`storage_sink`]).
pub async fn start(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    backend: &Arc<LocalBackend>,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
) -> Result<Arc<FunctionsRuntime>, String> {
    let codebases = cfg.functions_to_load();
    if codebases.is_empty() {
        return Err("functions.source is not configured".to_owned());
    }
    validate_functions_codebase_budget(&codebases)?;
    if codebases.len() > 1 && cfg.functions_inspect_port.is_some() {
        return Err(
            "Cannot debug on a single port with multiple codebases. Use --inspect-functions=true to assign dynamic ports to each codebase"
                .to_owned(),
        );
    }
    if codebases.len() > 1 && cfg.functions_manifest.is_some() {
        return Err(format!(
            "functions.manifest replaces discovery for one codebase, and this run loads {} \
             ({}); name the one to load with --only functions:<codebase> or drop \
             functions.manifest",
            codebases.len(),
            codebases
                .iter()
                .map(|c| c.codebase.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let node_probe_cache = Arc::new(NodeProbeCache::default());
    #[cfg(unix)]
    drop(schedule_orphan_function_snapshot_sweep(std::env::temp_dir()));
    let starts = codebases
        .iter()
        .map(|codebase| {
            let label = codebase.codebase.clone();
            let cfg = (*cfg).clone();
            let codebase = codebase.clone();
            let hosts = hosts.clone();
            let runner_secret = runner_secret.to_owned();
            let node_probe_cache = node_probe_cache.clone();
            let start = tokio::spawn(async move {
                start_codebase(
                    &cfg,
                    &codebase,
                    &hosts,
                    &runner_secret,
                    callable_trusted_protocol,
                    &node_probe_cache,
                )
                .await
            });
            (label, start)
        })
        .collect();
    let outcomes = join_codebase_starts(starts).await;
    if let Some(error) = outcomes.iter().find_map(|outcome| outcome.as_ref().err()) {
        for spec in outcomes.iter().filter_map(|outcome| outcome.as_ref().ok()) {
            spec.runner.kill_now();
        }
        return Err(error.clone());
    }
    let started: Vec<fireemu_adapter_functions::runtime::CodebaseSpec> =
        outcomes.into_iter().filter_map(Result::ok).collect();
    let config = FunctionsConfig {
        project: cfg.auth_project.clone(),
        default_bucket: format!("{}.appspot.com", cfg.auth_project),
        location: "nam5".to_owned(),
        session: SessionId::new(u128::from(cfg.seed)),
        max_running: cfg.functions_max_running,
        debug_mode: cfg.functions_inspect_dynamic || cfg.functions_inspect_port.is_some(),
        retry_attempts: cfg.events_max_attempts,
        max_catch_up_runs: cfg.scheduler_max_catch_up_runs,
        runner_secret: runner_secret.to_owned(),
        overlap: fireemu_adapter_functions::runtime::OverlapPolicy::parse(&cfg.scheduler_overlap)
            .unwrap_or_default(),
        catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::parse(&cfg.scheduler_catch_up)
            .unwrap_or_default(),
        functions_host: hosts.functions.clone(),
    };
    // A function name two codebases both export is fatal here. The runners it collided
    // between are killed rather than left behind a daemon that refuses to serve them.
    let spawned: Vec<Arc<Runner>> = started.iter().map(|c| c.runner.clone()).collect();
    let runtime = match FunctionsRuntime::with_codebases(started, config, clock.clone()) {
        Ok(runtime) => runtime,
        Err(e) => {
            for runner in &spawned {
                runner.kill_now();
            }
            return Err(e);
        }
    };
    tokio::spawn(runtime.clone().dispatch_loop());
    // Commits reserve their complete Functions fan-out before the database publishes and
    // activate that already-built batch before releasing the database critical section.
    backend.set_atomic_change_sink(Arc::new(FunctionsChangeSink(runtime.clone())));
    start_reload_supervisors(
        &runtime,
        cfg,
        hosts,
        runner_secret,
        callable_trusted_protocol,
        &node_probe_cache,
    );
    Ok(runtime)
}

struct FunctionsChangeSink(Arc<FunctionsRuntime>);

struct FunctionsCommitPublication(
    Option<fireemu_adapter_functions::runtime::EventBatchReservation>,
);

impl fireemu_adapter_grpc::local::CommitPublication for FunctionsCommitPublication {
    fn publish(mut self: Box<Self>) {
        if let Some(reservation) = self.0.take() {
            reservation.publish();
        }
    }
}

impl fireemu_adapter_grpc::local::AtomicChangeSink for FunctionsChangeSink {
    fn reserve(
        &self,
        event: &fireemu_adapter_grpc::local::CommitEvent,
    ) -> Result<
        Box<dyn fireemu_adapter_grpc::local::CommitPublication>,
        fireemu_core_types::admission::EventAdmissionError,
    > {
        self.0
            .reserve_commit_events(event)
            .map(|reservation| {
                Box::new(FunctionsCommitPublication(Some(reservation)))
                    as Box<dyn fireemu_adapter_grpc::local::CommitPublication>
            })
            .map_err(functions_event_admission_error)
    }
}

fn functions_event_admission_error(
    error: fireemu_adapter_functions::runtime::SourceEventAdmissionError,
) -> fireemu_core_types::admission::EventAdmissionError {
    use fireemu_adapter_functions::runtime::SourceEventAdmissionError;
    use fireemu_core_types::admission::EventAdmissionError;
    match error {
        SourceEventAdmissionError::Capacity => {
            EventAdmissionError::Capacity("Functions logical event capacity is exhausted".into())
        }
        SourceEventAdmissionError::Unavailable => EventAdmissionError::Unavailable(
            "Functions logical event admission is unavailable".into(),
        ),
        SourceEventAdmissionError::InvalidEvent => EventAdmissionError::InvalidEvent(
            "Functions trigger produced an invalid logical event".into(),
        ),
    }
}

fn validate_functions_codebase_budget(codebases: &[FunctionsCodebase]) -> Result<(), String> {
    if codebases.len() > crate::config::MAX_SELECTED_FUNCTIONS_CODEBASES {
        return Err(format!(
            "{} selected Functions codebases exceed fireemu's local safety budget of {}; use --only functions:<codebase> to start one runner",
            codebases.len(),
            crate::config::MAX_SELECTED_FUNCTIONS_CODEBASES
        ));
    }
    Ok(())
}

/// Starts one codebase's runner, reads its environment and validates what it discovered.
///
/// Every codebase gets its own process, its own dotenv chain (the files live next to its
/// `source`) and its own HTTP server; nothing about one codebase can be observed from another.
#[allow(clippy::too_many_lines)]
async fn start_codebase(
    cfg: &RuntimeConfig,
    codebase: &crate::config::FunctionsCodebase,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
    node_probe_cache: &Arc<NodeProbeCache>,
) -> Result<fireemu_adapter_functions::runtime::CodebaseSpec, String> {
    let source = codebase.source.clone();
    let label = &codebase.codebase;
    if !Path::new(&source).is_dir() {
        return Err(format!(
            "the Functions codebase {label:?}: source {source:?} is not a directory"
        ));
    }
    let source = std::fs::canonicalize(&source)
        .map_err(|e| {
            format!("the Functions codebase {label:?}: cannot resolve source {source:?}: {e}")
        })?
        .to_string_lossy()
        .into_owned();
    let mut command = if let Some(command) = cfg.functions_runner.clone() {
        command
    } else {
        let codebase = codebase.clone();
        let node_probe_cache = node_probe_cache.clone();
        run_node_selection_blocking(move || {
            default_runner_for_codebase(&codebase, &node_probe_cache)
        })
        .await
        .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?
        .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?
    };
    if cfg.functions_inspect_dynamic {
        command.insert(1, "--inspect-publish-uid=http".to_owned());
        command.insert(1, "--inspect=127.0.0.1:0".to_owned());
    } else if let Some(port) = cfg.functions_inspect_port {
        command.insert(1, "--inspect-publish-uid=http".to_owned());
        command.insert(1, format!("--inspect=127.0.0.1:{port}"));
    }
    command.push("--source".to_owned());
    command.push(source.clone());
    command.push("--codebase".to_owned());
    command.push(label.clone());
    // The user environment goes in first: the emulator's own variables override it, exactly as
    // `getRuntimeEnvs` spreads `{...userEnvs, ...systemEnvs, ...emulatorEnvs, FIREBASE_CONFIG}`
    // (`functionsEmulator.js:1027`). The dotenv dialect refuses every reserved key outright, so
    // this ordering is a second line rather than the only one.
    let user_env = load_user_environment(
        Path::new(&source),
        &cfg.auth_project,
        cfg.functions_project_alias.as_deref(),
    )
    .map_err(|e| format!("the Functions codebase {label:?}: {e}"))?;
    if !user_env.files.is_empty() {
        eprintln!(
            "note: functions[{label}]: loaded environment variables from {}",
            user_env.files.join(", ")
        );
    }
    // The official Functions emulator inherits the Firebase CLI process environment before
    // applying dotenv, system and emulator values. The emulator profile preserves that
    // behavior so wrappers such as `dotenv -- firebase emulators:exec` reach function code.
    // The strict profile keeps the runner isolated and receives only the explicit values
    // below. In both profiles, later entries override parent values in the official order.
    let mut env: Vec<(String, String)> = if cfg.profile == CompatibilityProfile::Emulator {
        inheritable_parent_environment()
    } else {
        Vec::new()
    };
    env.extend(user_env.applied());
    if !user_env.secrets.is_empty() {
        let secrets: serde_json::Map<String, serde_json::Value> = user_env
            .secrets
            .iter()
            .map(|(name, value)| (name.clone(), serde_json::Value::String(value.clone())))
            .collect();
        env.push((
            "FIREEMU_LOCAL_SECRETS_JSON".to_owned(),
            serde_json::Value::Object(secrets).to_string(),
        ));
    }
    env.extend([
        // A runner must never reach a metadata server: the official emulator sets this on the
        // child too (`functionsEmulator.js:1117`).
        ("METADATA_SERVER_DETECTION".to_owned(), "none".to_owned()),
        ("GCLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        ("GOOGLE_CLOUD_PROJECT".to_owned(), cfg.auth_project.clone()),
        (
            "GOOGLE_CLOUD_QUOTA_PROJECT".to_owned(),
            cfg.auth_project.clone(),
        ),
        ("FUNCTIONS_EMULATOR".to_owned(), "true".to_owned()),
        (
            "FIREBASE_CONFIG".to_owned(),
            firebase_config(&cfg.auth_project),
        ),
        // The official emulator's process-wide Cloud Run identity fields
        // (`functionsEmulator.js:980-987`). `FUNCTION_TARGET`, `FUNCTION_SIGNATURE_TYPE` and
        // `K_SERVICE` name one function, and the official emulator can set them at spawn
        // because it starts one runtime process per trigger; fireemu serves a whole codebase
        // from one runner, so the runner sets those three per invocation instead.
        ("K_REVISION".to_owned(), "1".to_owned()),
        ("PORT".to_owned(), "80".to_owned()),
        ("TZ".to_owned(), "UTC".to_owned()),
        ("FIREEMU_RUNNER".to_owned(), "1".to_owned()),
        ("FIREEMU_RUNNER_SECRET".to_owned(), runner_secret.to_owned()),
    ]);
    if let Some(host) = &hosts.firestore {
        env.push(("FIRESTORE_EMULATOR_HOST".to_owned(), host.clone()));
        env.push((
            "FIREBASE_FIRESTORE_EMULATOR_ADDRESS".to_owned(),
            host.clone(),
        ));
    }
    if let Some(host) = &hosts.auth {
        env.push(("FIREBASE_AUTH_EMULATOR_HOST".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.storage {
        env.push(("FIREBASE_STORAGE_EMULATOR_HOST".to_owned(), host.clone()));
        env.push(("STORAGE_EMULATOR_HOST".to_owned(), format!("http://{host}")));
    }
    if let Some(host) = &hosts.eventarc {
        env.push((
            "CLOUD_EVENTARC_EMULATOR_HOST".to_owned(),
            format!("http://{host}"),
        ));
    }
    if let Some(host) = &hosts.tasks {
        env.push(("CLOUD_TASKS_EMULATOR_HOST".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.functions {
        env.push(("FIREEMU_FUNCTIONS_HOST".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.pubsub {
        env.push(("PUBSUB_EMULATOR_HOST".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.hub {
        env.push(("FIREBASE_EMULATOR_HUB".to_owned(), host.clone()));
    }
    if let Some(host) = &hosts.logging {
        env.push(("FIREBASE_LOGGING_EMULATOR_HOST".to_owned(), host.clone()));
    }
    // Debug mode is granted only when the daemon is the sole source of both callable
    // credentials. The runner inherits an allowlist that does not contain these names, and
    // `SpawnSpec::env` is applied last, so neither can be shadowed from the host environment.
    if callable_trusted_protocol {
        env.push(("FIREBASE_DEBUG_MODE".to_owned(), "true".to_owned()));
        env.push((
            "FIREBASE_DEBUG_FEATURES".to_owned(),
            DEBUG_FEATURES.to_owned(),
        ));
    }
    let spec = SpawnSpec {
        command,
        cwd: Some(source),
        env,
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Arc::new(
        Runner::spawn_spec(&spec)
            .await
            .map_err(|e| format!("the Functions codebase {label:?}: {e}"))?,
    );
    if cfg.functions_inspect_dynamic || cfg.functions_inspect_port.is_some() {
        let actual = runner.hello().inspector_port;
        let port_matches = cfg
            .functions_inspect_port
            .is_none_or(|expected| actual == Some(expected));
        let endpoint_active = match actual {
            Some(port) => inspector_endpoint_is_active(port).await,
            None => false,
        };
        if !endpoint_active || !port_matches {
            runner.kill_now();
            return Err(match cfg.functions_inspect_port {
                Some(expected) => format!(
                    "the Functions codebase {label:?}: requested debugger port {expected} is not active"
                ),
                None => format!(
                    "the Functions codebase {label:?}: the dynamically assigned debugger port is not active"
                ),
            });
        }
        eprintln!(
            "functions[{label}]: using debug port {}",
            actual.expect("the active inspector port was checked above")
        );
    }
    let configured = (|| {
        let manifest_json = match &cfg.functions_manifest {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("functions manifest {path}: {e}"))?;
                serde_json::from_str(&text)
                    .map_err(|e| format!("functions manifest {path}: {e}"))?
            }
            None => runner
                .hello()
                .manifest
                .clone()
                .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?,
        };
        let mut manifest_json = manifest_json;
        if let Some(tz) = &cfg.scheduler_default_time_zone {
            // Schedules without a zone use the configured default.
            if let Some(functions) = manifest_json
                .get_mut("functions")
                .and_then(serde_json::Value::as_array_mut)
            {
                for f in functions {
                    if let Some(trigger) = f.get_mut("trigger") {
                        if trigger.get("type").and_then(serde_json::Value::as_str)
                            == Some("schedule")
                            && trigger
                                .get("timeZone")
                                .is_none_or(serde_json::Value::is_null)
                        {
                            trigger["timeZone"] = serde_json::Value::String(tz.clone());
                        }
                    }
                }
            }
        }
        let manifest = parse_manifest(&manifest_json)?;
        // Before anything is served: every export the runner could not serve is either named in a
        // refusal or printed, one line each.
        let policy = UnservedTriggers::parse(&cfg.functions_unserved_triggers).unwrap_or_default();
        for line in check_ignored(&manifest, policy)? {
            eprintln!("note: {line}");
        }
        if cfg.functions_manifest.is_some() {
            // A configured manifest replaces discovery outright. Security-sensitive trigger
            // classifications still come from code, so the replacement must reconcile with
            // what the runner discovered instead of being trusted blindly.
            let discovered = runner
                .hello()
                .manifest
                .clone()
                .ok_or_else(|| "the functions runner did not discover a manifest".to_owned())?;
            let discovered = parse_manifest(&discovered)?;
            check_manifest_agrees_on_blocking_auth(&manifest, &discovered)?;
            if callable_trusted_protocol {
                check_manifest_agrees_on_callables(&manifest, &discovered)?;
            }
        }
        check_callable_app_check(
            &manifest,
            runner.hello().app_check.as_ref(),
            callable_trusted_protocol,
        )?;
        Ok(fireemu_adapter_functions::runtime::CodebaseSpec {
            name: label.clone(),
            manifest,
            runner: runner.clone(),
            spawn: Some(spec),
            cleanup_dir: None,
        })
    })();
    if configured.is_err() {
        runner.kill_now();
    }
    configured
}

/// Refuses a configured manifest that removes or changes any discovered Blocking Auth hook.
///
/// Unlike an omitted HTTP endpoint, an omitted blocking hook makes authentication continue
/// without policy. Function name, region and event therefore form a bidirectional ordered
/// contract owned by discovery, even when a custom manifest controls other local options.
/// Order is significant because the runtime selects the first hook for an event.
fn check_manifest_agrees_on_blocking_auth(
    configured: &fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::Trigger;

    let contract = |manifest: &fireemu_core_functions::manifest::FunctionManifest| {
        manifest
            .functions
            .iter()
            .filter_map(|function| match function.trigger {
                Trigger::BlockingAuth {
                    event,
                    token_policy,
                } => Some((
                    function.name.clone(),
                    function.region.clone(),
                    event.as_str(),
                    token_policy,
                )),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let configured = contract(configured);
    let discovered = contract(discovered);
    if configured != discovered {
        let mismatch = (0..configured.len().max(discovered.len()))
            .find(|index| configured.get(*index) != discovered.get(*index))
            .unwrap_or(0);
        return Err(match (discovered.get(mismatch), configured.get(mismatch)) {
            (Some((name, region, event, _)), None) => format!(
                "the configured functions manifest omits discovered Blocking Auth hook {name:?} \
                 in {region} for {event} at position {mismatch}; blocking policy cannot be \
                 bypassed by a custom manifest"
            ),
            (None, Some((name, region, event, _))) => format!(
                "the configured functions manifest invents Blocking Auth hook {name:?} in \
                 {region} for {event} at position {mismatch}; it must match codebase discovery"
            ),
            (Some(discovered), Some(configured)) => format!(
                "the configured functions manifest changes Blocking Auth hook order or identity \
                 at position {mismatch}: codebase discovery has {:?} in {} for {}, configured \
                manifest has {:?} in {} for {} with token policy {:?}; configured manifest has \
                token policy {:?}; blocking policy selection must match exactly",
                discovered.0,
                discovered.1,
                discovered.2,
                configured.0,
                configured.1,
                configured.2,
                discovered.3,
                configured.3,
            ),
            (None, None) => unreachable!("different contracts have a mismatching position"),
        });
    }
    Ok(())
}

/// Refuses a configured manifest that disagrees with discovery about which HTTP functions are
/// callable.
///
/// Only the callable flag is reconciled. Other configured fields deliberately control local
/// routing and admission, but the callable flag decides which side of the trust boundary a
/// request lands on, and the runner is the only thing that actually knows.
fn check_manifest_agrees_on_callables(
    configured: &fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::Trigger;
    let callable_in = |m: &fireemu_core_functions::manifest::FunctionManifest, name: &str| {
        m.functions
            .iter()
            .find(|f| f.name == name)
            .map(|f| matches!(f.trigger, Trigger::Http { callable: true, .. }))
    };
    // The App Check options of a callable are what the runner observed in the code; a
    // manifest may not weaken them (a `consumeAppCheckToken: true` callable written as
    // disabled would run without replay protection, an `enforceAppCheck: true` one as open).
    let app_check_in = |m: &fireemu_core_functions::manifest::FunctionManifest, name: &str| {
        m.functions
            .iter()
            .find(|f| f.name == name)
            .and_then(|f| match &f.trigger {
                Trigger::Http {
                    callable: true,
                    enforce_app_check,
                    consume_app_check_token,
                } => Some((*enforce_app_check, *consume_app_check_token)),
                _ => None,
            })
    };
    for f in &configured.functions {
        if !matches!(f.trigger, Trigger::Http { .. }) {
            continue;
        }
        if let (Some(configured_options), Some(discovered_options)) = (
            app_check_in(configured, &f.name),
            app_check_in(discovered, &f.name),
        ) {
            if configured_options != discovered_options {
                return Err(format!(
                    "the configured functions manifest gives callable {:?} App Check options \
                     (enforceAppCheck / consumeAppCheckToken) that differ from what the \
                     codebase declares; the manifest cannot override them",
                    f.name
                ));
            }
        }
        match callable_in(discovered, &f.name) {
            Some(discovered_callable)
                if discovered_callable
                    == matches!(f.trigger, Trigger::Http { callable: true, .. }) => {}
            Some(_) => {
                return Err(format!(
                    "the configured functions manifest calls {:?} {}, but the codebase declares \
                     the opposite; App Check for callables cannot trust a manifest that \
                     disagrees with the code",
                    f.name,
                    if matches!(f.trigger, Trigger::Http { callable: true, .. }) {
                        "callable"
                    } else {
                        "an onRequest function"
                    }
                ))
            }
            None => {
                return Err(format!(
                    "the configured functions manifest declares the HTTP function {:?}, which \
                     the codebase does not export",
                    f.name
                ))
            }
        }
    }
    Ok(())
}

/// Fails startup when the callable App Check contract cannot be honoured (specification
/// section 13.4).
///
/// Three separate things have to hold, and each of them is fatal in its own way:
///
/// - a callable that declares `consumeAppCheckToken: true` fails discovery outright, whatever
///   else is configured, because replay protection is unimplemented and running such a callable
///   would hand it `alreadyConsumed: false` -- a silently wrong answer;
/// - with App Check enabled, a callable whose value could not be observed fails startup. The
///   value is never guessed as `false`;
/// - with App Check enabled, the runner must have proved that the installed
///   `firebase-functions` reads the debug switches the way the trusted protocol relies on. The
///   daemon turns `skipTokenVerification` on; if that flag does not mean what it is expected to
///   mean, the runner is decoding credentials under rules nobody checked.
fn check_callable_app_check(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    report: Option<&serde_json::Value>,
    callable_trusted_protocol: bool,
) -> Result<(), String> {
    use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
    let mut undetermined: Vec<&str> = Vec::new();
    for f in &manifest.functions {
        let Trigger::Http {
            callable: true,
            consume_app_check_token,
            ..
        } = &f.trigger
        else {
            continue;
        };
        match consume_app_check_token {
            ConsumeAppCheckToken::Enabled => {
                return Err(format!(
                    "callable {:?} declares consumeAppCheckToken: true, which needs limited-use \
                     token consumption (APP_CHECK_REPLAY_UNSUPPORTED); it is not implemented",
                    f.name
                ))
            }
            ConsumeAppCheckToken::Undetermined => undetermined.push(&f.name),
            ConsumeAppCheckToken::Disabled => {}
        }
    }
    if !callable_trusted_protocol {
        return Ok(());
    }
    let report = report.ok_or_else(|| {
        "the functions runner did not report its callable App Check support; App Check cannot \
         be enabled for callables"
            .to_owned()
    })?;
    let text = |key: &str| {
        report
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing")
            .to_owned()
    };
    let instrumentation = text("instrumentation");
    if instrumentation != "ok" {
        return Err(format!(
            "the functions runner could not read the callable App Check options: {instrumentation}"
        ));
    }
    let debug_features = text("debugFeatures");
    if debug_features != "verified" {
        return Err(format!(
            "the installed firebase-functions debug-feature semantics differ from what the \
             trusted callable protocol requires: {debug_features}"
        ));
    }
    // The auth-override fields by their actual values. The proxy strips them by name, so a
    // renamed one would leave the daemon forwarding a channel that overrides v1 callable auth
    // context (`INV-APPCHECK-010`). Refusing to start is the only safe answer: the names are
    // not something the daemon can discover at request time.
    let honoured = report
        .get("authHeaders")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            "the functions runner did not report which auth-override headers the installed \
             firebase-functions honours"
                .to_owned()
        })?;
    for field in honoured {
        let name = field.as_str().unwrap_or_default();
        if name.is_empty()
            || !fireemu_adapter_functions::callable::ALWAYS_STRIPPED
                .iter()
                .any(|stripped| stripped.eq_ignore_ascii_case(name))
        {
            return Err(format!(
                "the installed firebase-functions honours the auth-override header {name:?}, \
                 which the callable proxy does not strip"
            ));
        }
    }
    if !undetermined.is_empty() {
        return Err(format!(
            "consumeAppCheckToken could not be determined for callable(s) {}; App Check for \
             callables fails closed rather than assuming false",
            undetermined.join(", ")
        ));
    }
    Ok(())
}

/// The Storage event observer for `runtime` (called inside the store's critical section).
pub fn storage_sink(
    runtime: &Arc<FunctionsRuntime>,
    tenancy: &fireemu_core_session::tenancy::SharedTenancy,
) -> fireemu_adapter_http::storage::StorageEventSink {
    Arc::new(FunctionsStorageSink {
        runtime: runtime.clone(),
        tenancy: tenancy.clone(),
    })
}

struct FunctionsStorageSink {
    runtime: Arc<FunctionsRuntime>,
    tenancy: fireemu_core_session::tenancy::SharedTenancy,
}

struct FunctionsStoragePublication(
    Option<fireemu_adapter_functions::runtime::EventBatchReservation>,
);

impl fireemu_adapter_http::storage::StorageEventPublication for FunctionsStoragePublication {
    fn publish(mut self: Box<Self>) {
        if let Some(reservation) = self.0.take() {
            reservation.publish();
        }
    }
}

impl fireemu_adapter_http::storage::AtomicStorageEventSink for FunctionsStorageSink {
    fn reserve(
        &self,
        event: &fireemu_core_storage::store::StorageEvent,
    ) -> Result<
        Box<dyn fireemu_adapter_http::storage::StorageEventPublication>,
        fireemu_core_types::admission::EventAdmissionError,
    > {
        use fireemu_core_storage::store::StorageEvent;
        let bucket = match event {
            StorageEvent::Finalized(m)
            | StorageEvent::Deleted(m)
            | StorageEvent::MetadataUpdated(m) => m.bucket.as_str(),
        };
        // The runtime belongs to the default session: other sessions' buckets do not
        // trigger its functions.
        let owned = self
            .tenancy
            .read()
            .map_err(|_| {
                fireemu_core_types::admission::EventAdmissionError::Unavailable(
                    "Storage tenancy is unavailable during event admission".to_owned(),
                )
            })?
            .project_of_bucket(bucket)
            == self.runtime.project();
        let reservation = if owned {
            Some(
                self.runtime
                    .reserve_storage_event(event)
                    .map_err(functions_event_admission_error)?,
            )
        } else {
            None
        };
        Ok(Box::new(FunctionsStoragePublication(reservation)))
    }
}

/// The Auth user event observer for `runtime` (called after each Auth request).
pub fn auth_sink(
    runtime: &Arc<FunctionsRuntime>,
) -> fireemu_adapter_http::identity_toolkit::AuthEventSink {
    let runtime = runtime.clone();
    Arc::new(move |event| runtime.on_user_event(event))
}

/// Identity Platform's synchronous bridge to before-create and before-sign-in functions.
pub struct BlockingAuthBridge {
    runtime: Arc<FunctionsRuntime>,
    deadline: Duration,
    forward_inbound_credentials: bool,
    settings: Arc<RwLock<BlockingAuthSettings>>,
    settings_revision: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlockingAuthSettings {
    selections: fireemu_core_functions::manifest::BlockingAuthSelections,
    /// Optional project-level upper bound for raw token forwarding. `None` preserves the legacy
    /// discovery-only policy; `Some` means every token kind is additionally required to be true
    /// here before it can reach a handler.
    forwarding_restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
}

const BLOCKING_AUTH_DEADLINE: Duration = Duration::from_secs(7);
const MAX_BLOCKING_AUTH_RESPONSE_BYTES: u64 = 64 * 1024;

fn blocking_auth_user_json(
    user: &fireemu_core_auth::store::UserRecord,
    tenant: Option<&str>,
) -> serde_json::Value {
    let provider_data = user
        .federated
        .iter()
        .map(|identity| {
            serde_json::json!({
                "uid": identity.raw_id,
                "displayName": identity.display_name,
                "email": identity.email,
                "photoURL": identity.photo_url,
                "providerId": identity.provider_id,
                "phoneNumber": null,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "uid": user.local_id.as_str(),
        "email": user.email,
        "emailVerified": user.email_verified,
        "displayName": user.display_name,
        "photoURL": user.photo_url,
        "phoneNumber": user.phone_number,
        "disabled": user.disabled,
        "customClaims": serde_json::from_str::<serde_json::Value>(&user.custom_claims.canonical_json()).unwrap_or_else(|_| serde_json::json!({})),
        "tenantId": tenant,
        "metadata": {
            "creationTime": fireemu_core_types::time::LogicalInstant::to_rfc3339(user.created_at).unwrap_or_default(),
            "lastSignInTime": user.last_sign_in_at.and_then(|instant| instant.to_rfc3339().ok()),
        },
        "providerData": provider_data,
    })
}

fn blocking_auth_resource_name(project: &str, tenant: Option<&str>) -> String {
    tenant.map_or_else(
        || format!("projects/{project}"),
        |tenant| format!("projects/{project}/tenants/{tenant}"),
    )
}

fn narrow_blocking_auth_credentials(
    context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    globally_enabled: bool,
    policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
    restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
) -> fireemu_adapter_http::identity_toolkit::AuthBlockingContext {
    let mut narrowed = context.clone();
    let available = context.credential.as_ref().map_or_else(
        fireemu_core_functions::manifest::BlockingAuthCredentialPresence::default,
        |credential| fireemu_core_functions::manifest::BlockingAuthCredentialPresence {
            access_token: credential.access_token.is_some(),
            id_token: credential.id_token.is_some(),
            refresh_token: credential.refresh_token.is_some(),
        },
    );
    let policy =
        effective_blocking_auth_token_policy(policy, globally_enabled, restrictions, available);
    if let Some(credential) = &mut narrowed.credential {
        if !policy.access_token {
            credential.access_token = None;
        }
        if !policy.id_token {
            credential.id_token = None;
        }
        if !policy.refresh_token {
            credential.refresh_token = None;
        }
    }
    narrowed
}

fn restrict_blocking_auth_token_policy(
    policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
    restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
) -> fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
    let Some(restrictions) = restrictions else {
        return policy;
    };
    fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
        access_token: policy.access_token && restrictions.access_token,
        id_token: policy.id_token && restrictions.id_token,
        refresh_token: policy.refresh_token && restrictions.refresh_token,
    }
}

fn effective_blocking_auth_token_policy(
    policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy,
    globally_enabled: bool,
    restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
    available: fireemu_core_functions::manifest::BlockingAuthCredentialPresence,
) -> fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
    restrict_blocking_auth_token_policy(policy.effective(globally_enabled, available), restrictions)
}

fn validate_blocking_auth_forwarding_policy(
    globally_enabled: bool,
    restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
) -> Result<(), String> {
    if !globally_enabled
        && restrictions.is_some_and(fireemu_core_functions::manifest::BlockingAuthTokenPolicy::any)
    {
        return Err(
            "blockingFunctions.forwardInboundCredentials requests token forwarding while the global auth.forwardInboundCredentials switch is disabled".to_owned(),
        );
    }
    Ok(())
}

const BLOCKING_FUNCTIONS_URI_PREFIX: &str = "fireemu://functions/";
const BLOCKING_DISCOVERY_EVENTS_MEMBER: &str = "__fireemuDiscoveryEvents";

fn blocking_auth_selection_uri(
    project: &str,
    selection: &fireemu_core_functions::manifest::BlockingAuthSelection,
    region: &str,
) -> Option<serde_json::Value> {
    match selection {
        fireemu_core_functions::manifest::BlockingAuthSelection::Explicit { function, .. } => {
            Some(serde_json::json!({
                "functionUri": format!("{BLOCKING_FUNCTIONS_URI_PREFIX}{project}/{region}/{function}"),
            }))
        }
        fireemu_core_functions::manifest::BlockingAuthSelection::Disabled => {
            Some(serde_json::Value::Null)
        }
        fireemu_core_functions::manifest::BlockingAuthSelection::Discovery => None,
    }
}

fn blocking_auth_selection_accepts_target(
    selection: &fireemu_core_functions::manifest::BlockingAuthSelection,
    target: Option<(&str, &str)>,
) -> bool {
    match selection {
        fireemu_core_functions::manifest::BlockingAuthSelection::Discovery => target.is_some(),
        fireemu_core_functions::manifest::BlockingAuthSelection::Disabled => false,
        fireemu_core_functions::manifest::BlockingAuthSelection::Explicit { function, region } => {
            let Some((actual_function, actual_region)) = target else {
                return false;
            };
            actual_function == function
                && region
                    .as_deref()
                    .is_none_or(|expected| expected == actual_region)
        }
    }
}

fn blocking_auth_context_json(
    project: &str,
    tenant: Option<&str>,
    event: fireemu_core_functions::manifest::BlockingAuthEvent,
    request: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    event_id: &str,
    timestamp: &str,
) -> serde_json::Value {
    let event_type = match (event, request.sign_in_method.as_deref()) {
        (fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn, Some(method)) => {
            format!("{}:{method}", event.event_type())
        }
        _ => event.event_type().to_owned(),
    };
    let mut context = serde_json::json!({
        "eventId": event_id,
        "eventType": event_type,
        "resource": {
            "service": "identitytoolkit.googleapis.com",
            "name": blocking_auth_resource_name(project, tenant),
        },
        "timestamp": timestamp,
        "params": {},
    });
    if let Some(info) = &request.additional_user_info {
        context["additionalUserInfo"] = serde_json::json!({
            "providerId": info.provider_id,
            "profile": info.profile,
            "isNewUser": info.is_new_user,
        });
    }
    if let Some(credential) = &request.credential {
        let mut value = serde_json::json!({
            "providerId": credential.provider_id,
            "signInMethod": credential.sign_in_method,
        });
        if let Some(claims) = &credential.claims {
            value["claims"] = claims.clone();
        }
        if let Some(access_token) = &credential.access_token {
            value["accessToken"] = serde_json::Value::String(access_token.clone());
        }
        if let Some(id_token) = &credential.id_token {
            value["idToken"] = serde_json::Value::String(id_token.clone());
        }
        if let Some(refresh_token) = &credential.refresh_token {
            value["refreshToken"] = serde_json::Value::String(refresh_token.clone());
        }
        context["credential"] = value;
    }
    context
}

fn with_blocking_auth_project<T, E>(
    runtime_project: &str,
    request_project: &str,
    forward: impl FnOnce() -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    if runtime_project != request_project {
        return Ok(None);
    }
    forward()
}

fn blocking_auth_io_failure(
    error: &std::io::Error,
) -> fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
    } else {
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::unhandled()
    }
}

fn blocking_auth_remaining(
    deadline: Instant,
) -> Result<Duration, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout)
}

fn blocking_auth_write_request(
    stream: &mut TcpStream,
    mut request: &[u8],
    deadline: Instant,
) -> Result<(), fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
    use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

    while !request.is_empty() {
        let remaining = blocking_auth_remaining(deadline)?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        let written = stream
            .write(request)
            .map_err(|error| blocking_auth_io_failure(&error))?;
        if written == 0 {
            return Err(BlockingFunctionFailure::unhandled());
        }
        request = &request[written..];
    }
    Ok(())
}

fn blocking_auth_read_response(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Vec<u8>, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
    use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

    let mut response = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        let remaining = blocking_auth_remaining(deadline)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        let read = stream
            .read(&mut chunk)
            .map_err(|error| blocking_auth_io_failure(&error))?;
        if Instant::now() >= deadline {
            return Err(BlockingFunctionFailure::timeout());
        }
        if read == 0 {
            return Ok(response);
        }
        if response.len().saturating_add(read) as u64 > MAX_BLOCKING_AUTH_RESPONSE_BYTES {
            return Err(BlockingFunctionFailure::unhandled());
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

fn blocking_auth_response_failure(
    status: u16,
    value: &serde_json::Value,
) -> fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure {
    use fireemu_adapter_http::identity_toolkit::{BlockingFunctionCode, BlockingFunctionFailure};

    let parsed = value
        .get("error")
        .and_then(serde_json::Value::as_object)
        .and_then(|error| {
            let code = error
                .get("status")
                .and_then(serde_json::Value::as_str)
                .and_then(BlockingFunctionCode::from_canonical_name)
                .filter(|code| code.function_status() == status)?;
            let message = error.get("message").and_then(serde_json::Value::as_str)?;
            BlockingFunctionFailure::from_function(code, message).ok()
        });
    parsed.unwrap_or_else(BlockingFunctionFailure::unhandled)
}

impl BlockingAuthBridge {
    /// Builds the production bridge with Identity Platform's seven-second deadline.
    #[must_use]
    #[allow(dead_code)]
    pub fn new(runtime: Arc<FunctionsRuntime>) -> Self {
        Self::new_with_selection(
            runtime,
            fireemu_core_functions::manifest::BlockingAuthSelection::Discovery,
            false,
        )
    }

    /// Builds a bridge with the explicit raw credential forwarding policy.
    #[must_use]
    #[allow(dead_code)]
    pub fn new_with_forward_inbound_credentials(
        runtime: Arc<FunctionsRuntime>,
        forward_inbound_credentials: bool,
    ) -> Self {
        if !forward_inbound_credentials {
            return Self::new(runtime);
        }
        Self::try_new_with_forwarding_policy(runtime, forward_inbound_credentials, None)
            .expect("the legacy Blocking Auth bridge forwarding configuration is valid")
    }

    /// Builds a bridge with a project-level per-token forwarding restriction.
    ///
    /// A configured restriction is an upper bound on the discovered function policy. Supplying a
    /// `true` bit while the global switch is disabled is rejected instead of being silently
    /// ignored, because that configuration would claim to enable a capability the daemon has
    /// globally disabled.
    #[allow(dead_code)]
    pub fn try_new_with_forwarding_policy(
        runtime: Arc<FunctionsRuntime>,
        forward_inbound_credentials: bool,
        forwarding_restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
    ) -> Result<Self, String> {
        Self::try_new_with_selections_and_forwarding_policy(
            runtime,
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            forward_inbound_credentials,
            forwarding_restrictions,
        )
    }

    /// Builds a bridge with an explicit local selection for the synchronous Auth hooks.
    ///
    /// The selection must be resolved against the discovered manifest before the bridge is
    /// installed. The bridge repeats the selected target check for every invocation so a source
    /// reload cannot silently switch Auth to another function. The underlying Functions runtime
    /// remains responsible for runner generations and admission.
    #[must_use]
    #[allow(dead_code)]
    pub fn new_with_selections(
        runtime: Arc<FunctionsRuntime>,
        selections: fireemu_core_functions::manifest::BlockingAuthSelections,
        forward_inbound_credentials: bool,
    ) -> Self {
        Self::try_new_with_selections_and_forwarding_policy(
            runtime,
            selections,
            forward_inbound_credentials,
            None,
        )
        .expect("the legacy Blocking Auth bridge forwarding configuration is valid")
    }

    /// Builds a bridge with both per-event target selection and per-token forwarding limits.
    pub fn try_new_with_selections_and_forwarding_policy(
        runtime: Arc<FunctionsRuntime>,
        selections: fireemu_core_functions::manifest::BlockingAuthSelections,
        forward_inbound_credentials: bool,
        forwarding_restrictions: Option<fireemu_core_functions::manifest::BlockingAuthTokenPolicy>,
    ) -> Result<Self, String> {
        validate_blocking_auth_forwarding_policy(
            forward_inbound_credentials,
            forwarding_restrictions,
        )?;
        Ok(Self {
            runtime,
            deadline: BLOCKING_AUTH_DEADLINE,
            forward_inbound_credentials,
            settings: Arc::new(RwLock::new(BlockingAuthSettings {
                selections,
                forwarding_restrictions,
            })),
            settings_revision: AtomicU64::new(0),
        })
    }

    /// Builds a bridge applying the same selection to both supported Auth events.
    ///
    /// Prefer [`Self::new_with_selections`] when `beforeCreate` and `beforeSignIn` differ.
    #[must_use]
    #[allow(dead_code)]
    pub fn new_with_selection(
        runtime: Arc<FunctionsRuntime>,
        selection: fireemu_core_functions::manifest::BlockingAuthSelection,
        forward_inbound_credentials: bool,
    ) -> Self {
        Self::new_with_selections(
            runtime,
            fireemu_core_functions::manifest::BlockingAuthSelections {
                before_create: selection.clone(),
                before_sign_in: selection,
            },
            forward_inbound_credentials,
        )
    }

    #[cfg(test)]
    fn with_deadline(runtime: Arc<FunctionsRuntime>, deadline: Duration) -> Self {
        Self {
            runtime,
            deadline,
            forward_inbound_credentials: false,
            settings: Arc::new(RwLock::new(BlockingAuthSettings {
                selections: fireemu_core_functions::manifest::BlockingAuthSelections::default(),
                forwarding_restrictions: None,
            })),
            settings_revision: AtomicU64::new(0),
        }
    }

    fn selection_for(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
    ) -> fireemu_core_functions::manifest::BlockingAuthSelection {
        // The first version of the local config exposes one trigger map for both supported
        // events through the bridge. Keeping this accessor event-shaped leaves the call site
        // ready for per-event selections without changing the admission boundary.
        self.settings.read().ok().map_or(
            fireemu_core_functions::manifest::BlockingAuthSelection::Disabled,
            |settings| settings.selections.for_event(event).clone(),
        )
    }

    fn selected_function(
        selection: &fireemu_core_functions::manifest::BlockingAuthSelection,
    ) -> Option<&str> {
        match selection {
            fireemu_core_functions::manifest::BlockingAuthSelection::Explicit {
                function, ..
            } => Some(function),
            fireemu_core_functions::manifest::BlockingAuthSelection::Discovery
            | fireemu_core_functions::manifest::BlockingAuthSelection::Disabled => None,
        }
    }

    fn settings_snapshot(&self) -> Result<BlockingAuthSettings, ()> {
        self.settings
            .read()
            .map(|settings| settings.clone())
            .map_err(|_| ())
    }

    fn settings_revision(&self) -> u64 {
        // Keep the settings publication lock while reading the revision. This makes the
        // revision a lock-ordered observation: a reader cannot pass through this method while a
        // settings replacement has published its new value but has not yet published its
        // revision.
        let _settings = self.settings.read().ok();
        self.settings_revision.load(Ordering::SeqCst)
    }

    fn install_settings(&self, settings: BlockingAuthSettings) -> Result<(), String> {
        let mut current = self
            .settings
            .write()
            .map_err(|_| "blocking Auth settings are poisoned".to_owned())?;
        if *current != settings {
            *current = settings;
            self.settings_revision.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn parse_blocking_auth_settings(
        &self,
        value: &serde_json::Value,
    ) -> Result<BlockingAuthSettings, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "blockingFunctions must be an object".to_owned())?;
        if object.keys().any(|key| {
            key != "triggers"
                && key != "forwardInboundCredentials"
                && key != BLOCKING_DISCOVERY_EVENTS_MEMBER
        }) {
            return Err("blockingFunctions contains an unsupported field".to_owned());
        }
        let discovery = match object.get(BLOCKING_DISCOVERY_EVENTS_MEMBER) {
            None => BTreeSet::new(),
            Some(value) => {
                let events = value.as_array().ok_or_else(|| {
                    format!("blockingFunctions.{BLOCKING_DISCOVERY_EVENTS_MEMBER} must be an array")
                })?;
                let mut discovery = BTreeSet::new();
                for event in events {
                    let event = event.as_str().ok_or_else(|| {
                        format!(
                            "blockingFunctions.{BLOCKING_DISCOVERY_EVENTS_MEMBER} must contain event names"
                        )
                    })?;
                    if !matches!(event, "beforeCreate" | "beforeSignIn") {
                        return Err(format!(
                            "blockingFunctions.{BLOCKING_DISCOVERY_EVENTS_MEMBER} contains unsupported event {event:?}"
                        ));
                    }
                    if !discovery.insert(event.to_owned()) {
                        return Err(format!(
                            "blockingFunctions.{BLOCKING_DISCOVERY_EVENTS_MEMBER} contains duplicate event {event:?}"
                        ));
                    }
                }
                discovery
            }
        };
        if !discovery.is_empty() && object.get("triggers").is_none() {
            return Err(format!(
                "blockingFunctions.{BLOCKING_DISCOVERY_EVENTS_MEMBER} requires a triggers object"
            ));
        }
        let selections = match object.get("triggers") {
            None => fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            Some(value) => {
                let triggers = value
                    .as_object()
                    .ok_or_else(|| "blockingFunctions.triggers must be an object".to_owned())?;
                if triggers
                    .keys()
                    .any(|key| key != "beforeCreate" && key != "beforeSignIn")
                {
                    return Err(
                        "blockingFunctions.triggers contains an unsupported event".to_owned()
                    );
                }
                let parse = |event: &str| -> Result<
                    fireemu_core_functions::manifest::BlockingAuthSelection,
                    String,
                > {
                    if discovery.contains(event) {
                        if triggers.contains_key(event) {
                            return Err(format!(
                                "blockingFunctions.{BLOCKING_DISCOVERY_EVENTS_MEMBER} conflicts with blockingFunctions.triggers.{event}"
                            ));
                        }
                        return Ok(
                            fireemu_core_functions::manifest::BlockingAuthSelection::Discovery,
                        );
                    }
                    let Some(value) = triggers.get(event) else {
                        return Ok(
                            fireemu_core_functions::manifest::BlockingAuthSelection::Disabled,
                        );
                    };
                    if value.is_null() {
                        return Ok(
                            fireemu_core_functions::manifest::BlockingAuthSelection::Disabled,
                        );
                    }
                    let object = value.as_object().ok_or_else(|| {
                        format!("blockingFunctions.triggers.{event} must be an object or null")
                    })?;
                    if object.keys().any(|key| key != "functionUri") {
                        return Err(format!(
                            "blockingFunctions.triggers.{event} contains an unsupported field"
                        ));
                    }
                    let uri = object
                        .get("functionUri")
                        .and_then(serde_json::Value::as_str)
                        .filter(|uri| !uri.is_empty())
                        .ok_or_else(|| {
                            format!(
                                "blockingFunctions.triggers.{event}.functionUri must be a non-empty string"
                            )
                        })?;
                    let rest = uri.strip_prefix(BLOCKING_FUNCTIONS_URI_PREFIX).ok_or_else(|| {
                        format!(
                            "blockingFunctions.triggers.{event}.functionUri must reference an owned fireemu function"
                        )
                    })?;
                    let mut parts = rest.split('/');
                    let project = parts.next().filter(|part| !part.is_empty());
                    let region = parts.next().filter(|part| !part.is_empty());
                    let function = parts.next().filter(|part| !part.is_empty());
                    if project != Some(self.runtime.project())
                        || region.is_none()
                        || function.is_none()
                        || parts.next().is_some()
                    {
                        return Err(format!(
                            "blockingFunctions.triggers.{event}.functionUri does not reference this project's owned manifest"
                        ));
                    }
                    Ok(
                        fireemu_core_functions::manifest::BlockingAuthSelection::Explicit {
                            function: function.unwrap_or_default().to_owned(),
                            region: Some(region.unwrap_or_default().to_owned()),
                        },
                    )
                };
                fireemu_core_functions::manifest::BlockingAuthSelections {
                    before_create: parse("beforeCreate")?,
                    before_sign_in: parse("beforeSignIn")?,
                }
            }
        };
        let forwarding_restrictions = match object.get("forwardInboundCredentials") {
            None => None,
            Some(value) => {
                let forwarding = value.as_object().ok_or_else(|| {
                    "blockingFunctions.forwardInboundCredentials must be an object".to_owned()
                })?;
                if forwarding
                    .keys()
                    .any(|key| key != "idToken" && key != "accessToken" && key != "refreshToken")
                {
                    return Err(
                        "blockingFunctions.forwardInboundCredentials contains an unsupported field"
                            .to_owned(),
                    );
                }
                let boolean = |key: &str| -> Result<bool, String> {
                    forwarding
                        .get(key)
                        .map_or(Ok(false), |value| {
                            value.as_bool().ok_or_else(|| {
                                format!(
                                    "blockingFunctions.forwardInboundCredentials.{key} must be a boolean"
                                )
                            })
                        })
                };
                Some(fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
                    id_token: boolean("idToken")?,
                    access_token: boolean("accessToken")?,
                    refresh_token: boolean("refreshToken")?,
                })
            }
        };
        validate_blocking_auth_forwarding_policy(
            self.forward_inbound_credentials,
            forwarding_restrictions,
        )?;
        for (event, selection) in [
            (
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                &selections.before_create,
            ),
            (
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                &selections.before_sign_in,
            ),
        ] {
            self.runtime
                .manifest()
                .blocking_auth_target(event, selection)
                .map_err(|error| format!("blockingFunctions: {error}"))?;
        }
        Ok(BlockingAuthSettings {
            selections,
            forwarding_restrictions,
        })
    }

    fn blocking_auth_settings_value_with_discovery_markers(
        &self,
        preserve_discovery: bool,
    ) -> Result<Option<serde_json::Value>, String> {
        let settings = self
            .settings
            .read()
            .map_err(|_| "blocking Auth settings are poisoned".to_owned())?
            .clone();
        let mut object = serde_json::Map::new();
        let mut triggers = serde_json::Map::new();
        let mut discovery = Vec::new();
        for (event_name, event, selection) in [
            (
                "beforeCreate",
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                &settings.selections.before_create,
            ),
            (
                "beforeSignIn",
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                &settings.selections.before_sign_in,
            ),
        ] {
            match selection {
                fireemu_core_functions::manifest::BlockingAuthSelection::Discovery => {
                    if preserve_discovery {
                        discovery.push(serde_json::Value::String(event_name.to_owned()));
                    }
                }
                fireemu_core_functions::manifest::BlockingAuthSelection::Disabled => {
                    triggers.insert(event_name.to_owned(), serde_json::Value::Null);
                }
                fireemu_core_functions::manifest::BlockingAuthSelection::Explicit { .. } => {
                    let spec = self
                        .runtime
                        .manifest()
                        .blocking_auth_target(event, selection)
                        .map_err(|error| format!("blockingFunctions.{event_name}: {error}"))?
                        .ok_or_else(|| {
                            format!(
                                "blockingFunctions.{event_name}: explicit target is no longer available"
                            )
                        })?;
                    let value = blocking_auth_selection_uri(
                        self.runtime.project(),
                        selection,
                        &spec.region,
                    )
                    .ok_or_else(|| {
                        format!(
                            "blockingFunctions.{event_name}: explicit target has no exportable URI"
                        )
                    })?;
                    triggers.insert(event_name.to_owned(), value);
                }
            }
        }
        if !triggers.is_empty() {
            object.insert("triggers".to_owned(), serde_json::Value::Object(triggers));
            if preserve_discovery && !discovery.is_empty() {
                object.insert(
                    BLOCKING_DISCOVERY_EVENTS_MEMBER.to_owned(),
                    serde_json::Value::Array(discovery),
                );
            }
        }
        if let Some(policy) = settings.forwarding_restrictions {
            object.insert(
                "forwardInboundCredentials".to_owned(),
                serde_json::json!({
                    "idToken": policy.id_token,
                    "accessToken": policy.access_token,
                    "refreshToken": policy.refresh_token,
                }),
            );
        }
        Ok(Some(serde_json::Value::Object(object)))
    }

    fn blocking_auth_settings_value_for_export(&self) -> Result<Option<serde_json::Value>, String> {
        self.blocking_auth_settings_value_with_discovery_markers(true)
    }

    fn blocking_auth_settings_value(&self) -> Option<serde_json::Value> {
        self.blocking_auth_settings_value_with_discovery_markers(false)
            .ok()
            .flatten()
    }

    fn blocking_auth_settings_snapshot_value(&self) -> Result<Option<serde_json::Value>, String> {
        self.blocking_auth_settings_value_for_export()
    }

    fn restore_blocking_auth_settings_snapshot_value(
        &self,
        value: &serde_json::Value,
    ) -> Result<(), String> {
        // The parser validates and applies the private per-event marker as part of the same
        // logical document. Keeping it in the input also rejects marker/trigger conflicts rather
        // than allowing a malformed snapshot to overwrite a concrete selection.
        let settings = self.parse_blocking_auth_settings(value)?;
        for (event, selection) in [
            (
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                &settings.selections.before_create,
            ),
            (
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                &settings.selections.before_sign_in,
            ),
        ] {
            self.runtime
                .manifest()
                .blocking_auth_target(event, selection)
                .map_err(|error| format!("blockingFunctions: {error}"))?;
        }
        self.install_settings(settings)
    }

    /// Validates and atomically replaces the logical project-level blocking settings.
    pub fn replace_blocking_auth_settings(&self, value: &serde_json::Value) -> Result<(), String> {
        let settings = self.parse_blocking_auth_settings(value)?;
        self.install_settings(settings)
    }

    /// Applies only the fields named by an Auth project update mask. A nested update must merge
    /// against the internal selection state so an omitted Discovery event is not rewritten as
    /// Disabled merely because the public projection does not serialize Discovery.
    #[allow(clippy::too_many_lines)]
    pub fn replace_blocking_auth_settings_masked(
        &self,
        value: &serde_json::Value,
        fields: &[String],
    ) -> Result<(), String> {
        let mut next = self
            .settings_snapshot()
            .map_err(|()| "blocking Auth settings are poisoned".to_owned())?;

        let has_complete_replacement = fields.iter().any(|field| field == "blockingFunctions");
        if has_complete_replacement {
            next = self.parse_blocking_auth_settings(value)?;
        } else {
            for field in fields {
                match field.as_str() {
                    "blockingFunctions.triggers" => {
                        let triggers = value
                            .get("triggers")
                            .ok_or_else(|| "blockingFunctions.triggers is missing".to_owned())?;
                        let parsed = self.parse_blocking_auth_settings(
                            &serde_json::json!({ "triggers": triggers }),
                        )?;
                        next.selections = parsed.selections;
                    }
                    "blockingFunctions.triggers.beforeCreate"
                    | "blockingFunctions.triggers.beforeSignIn" => {
                        let event = field
                            .strip_prefix("blockingFunctions.triggers.")
                            .ok_or_else(|| "invalid blocking trigger field".to_owned())?;
                        let trigger = value
                            .get("triggers")
                            .and_then(|triggers| triggers.get(event))
                            .ok_or_else(|| {
                                format!("blockingFunctions.triggers.{event} is missing")
                            })?;
                        let mut trigger_object = serde_json::Map::new();
                        trigger_object.insert(event.to_owned(), trigger.clone());
                        let parsed = self.parse_blocking_auth_settings(&serde_json::json!({
                            "triggers": trigger_object
                        }))?;
                        if event == "beforeCreate" {
                            next.selections.before_create = parsed.selections.before_create;
                        } else {
                            next.selections.before_sign_in = parsed.selections.before_sign_in;
                        }
                    }
                    "blockingFunctions.forwardInboundCredentials" => {
                        let forwarding =
                            value.get("forwardInboundCredentials").ok_or_else(|| {
                                "blockingFunctions.forwardInboundCredentials is missing".to_owned()
                            })?;
                        let parsed = self.parse_blocking_auth_settings(
                            &serde_json::json!({ "forwardInboundCredentials": forwarding }),
                        )?;
                        next.forwarding_restrictions = parsed.forwarding_restrictions;
                    }
                    "blockingFunctions.forwardInboundCredentials.idToken"
                    | "blockingFunctions.forwardInboundCredentials.accessToken"
                    | "blockingFunctions.forwardInboundCredentials.refreshToken" => {
                        let key = field
                            .strip_prefix("blockingFunctions.forwardInboundCredentials.")
                            .ok_or_else(|| "invalid blocking forwarding field".to_owned())?;
                        let forwarding = value
                            .get("forwardInboundCredentials")
                            .and_then(|forwarding| forwarding.get(key))
                            .ok_or_else(|| {
                                format!(
                                    "blockingFunctions.forwardInboundCredentials.{key} is missing"
                                )
                            })?;
                        let enabled = forwarding.as_bool().ok_or_else(|| {
                            format!("blocking forwarding {key} must be a boolean")
                        })?;
                        let mut policy = next.forwarding_restrictions.unwrap_or_default();
                        match key {
                            "idToken" => policy.id_token = enabled,
                            "accessToken" => policy.access_token = enabled,
                            "refreshToken" => policy.refresh_token = enabled,
                            _ => unreachable!("validated blocking forwarding field"),
                        }
                        next.forwarding_restrictions = Some(policy);
                    }
                    _ => {}
                }
            }
        }

        validate_blocking_auth_forwarding_policy(
            self.forward_inbound_credentials,
            next.forwarding_restrictions,
        )?;
        for (event, selection) in [
            (
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                &next.selections.before_create,
            ),
            (
                fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
                &next.selections.before_sign_in,
            ),
        ] {
            self.runtime
                .manifest()
                .blocking_auth_target(event, selection)
                .map_err(|error| format!("blockingFunctions: {error}"))?;
        }
        self.install_settings(next)
    }

    #[allow(clippy::unused_self)]
    fn require_selected_target(
        &self,
        selection: &fireemu_core_functions::manifest::BlockingAuthSelection,
        target: &fireemu_adapter_functions::runtime::BlockingAuthTarget,
    ) -> Result<(), fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
        if !blocking_auth_selection_accepts_target(
            selection,
            Some((&target.function, &target.region)),
        ) {
            return Err(
                fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::unhandled(),
            );
        }
        Ok(())
    }

    fn invoke_for_namespace(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
        context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        with_blocking_auth_project(self.runtime.project(), project, || {
            self.invoke_matching_namespace(project, tenant, event, user, context)
        })
    }

    #[allow(clippy::too_many_lines, clippy::ignored_unit_patterns)]
    fn invoke_matching_namespace(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
        context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

        let settings = self
            .settings_snapshot()
            .map_err(|_| BlockingFunctionFailure::unhandled())?;
        if matches!(
            settings.selections.for_event(event),
            fireemu_core_functions::manifest::BlockingAuthSelection::Disabled
        ) {
            return Ok(None);
        }

        let selection = settings.selections.for_event(event);
        let selected_function = Self::selected_function(selection);
        let deadline = Instant::now() + self.deadline;
        let first_admission = self
            .runtime
            .try_admit_blocking_auth_for(event, selected_function);
        let admitted = if let Ok(admitted) = first_admission {
            admitted
        } else {
            let handle = tokio::runtime::Handle::try_current()
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            handle
                .block_on(async {
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(deadline),
                        self.runtime
                            .recover_blocking_auth_runner_for(event, selected_function),
                    )
                    .await
                })
                .map_err(|_| BlockingFunctionFailure::timeout())?
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            // A recovered runner is healthy even when the caller's admission deadline has
            // expired. Return the local timeout before reserving a slot or recycling it.
            blocking_auth_remaining(deadline)?;
            self.runtime
                .try_admit_blocking_auth_for(event, selected_function)
                .map_err(|_| BlockingFunctionFailure::unhandled())?
        };
        let Some((target, _admission)) = admitted else {
            return if matches!(
                selection,
                fireemu_core_functions::manifest::BlockingAuthSelection::Explicit { .. }
            ) {
                Err(BlockingFunctionFailure::unhandled())
            } else {
                Ok(None)
            };
        };
        self.require_selected_target(selection, &target)?;
        let context = narrow_blocking_auth_credentials(
            context,
            self.forward_inbound_credentials,
            target.token_policy,
            settings.forwarding_restrictions,
        );
        let user_json = blocking_auth_user_json(user, tenant);
        let event_context = blocking_auth_context_json(
            project,
            tenant,
            event,
            &context,
            &format!("fireemu-blocking-{}", self.runtime.trigger_generation()),
            &fireemu_core_types::time::LogicalInstant::to_rfc3339(self.runtime.now())
                .unwrap_or_default(),
        );
        let body = serde_json::json!({
            "data": {
                "user": user_json,
                "context": event_context,
            }
        })
        .to_string();
        let path = format!(
            "/{}/{}/{}",
            self.runtime.project(),
            target.region,
            target.function
        );
        let exchange = (|| {
            let address = target
                .addr
                .parse()
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            let mut stream =
                TcpStream::connect_timeout(&address, blocking_auth_remaining(deadline)?)
                    .map_err(|error| blocking_auth_io_failure(&error))?;
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nX-Fireemu-Runner-Secret: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                target.addr,
                target.secret,
                body.len(),
                body
            );
            blocking_auth_write_request(&mut stream, request.as_bytes(), deadline)?;
            let response = blocking_auth_read_response(&mut stream, deadline)?;
            fireemu_adapter_functions::http::parse_response(&response, "POST")
                .map_err(|_| BlockingFunctionFailure::unhandled())
        })();
        let response = match exchange {
            Ok(response) => response,
            Err(failure) => {
                self.runtime.restart_runner_after_blocking_failure(&target);
                return Err(failure);
            }
        };
        let Ok(value): Result<serde_json::Value, _> = serde_json::from_slice(&response.body) else {
            self.runtime.restart_runner_after_blocking_failure(&target);
            return Err(BlockingFunctionFailure::unhandled());
        };
        if response.status != 200 {
            return Err(blocking_auth_response_failure(response.status, &value));
        }
        if !value.is_object() {
            return Err(BlockingFunctionFailure::unhandled());
        }
        Ok(Some(value))
    }
}

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for BlockingAuthBridge {
    fn blocking_auth_revision(&self) -> u64 {
        self.settings_revision()
    }

    fn request_concurrency_limit(&self) -> usize {
        self.runtime.max_global_concurrency()
    }

    fn handles(&self, event: fireemu_core_functions::manifest::BlockingAuthEvent) -> bool {
        match self.selection_for(event) {
            fireemu_core_functions::manifest::BlockingAuthSelection::Disabled => false,
            fireemu_core_functions::manifest::BlockingAuthSelection::Discovery => {
                self.runtime.handles_blocking_auth(event)
            }
            // Explicit configuration is a fail-closed contract. Invocation turns a missing
            // live target into an error instead of allowing Auth to proceed.
            fireemu_core_functions::manifest::BlockingAuthSelection::Explicit { .. } => true,
        }
    }

    fn forward_inbound_credentials(&self) -> bool {
        let Ok(settings) = self.settings_snapshot() else {
            return false;
        };
        self.forward_inbound_credentials
            && settings
                .forwarding_restrictions
                .is_none_or(fireemu_core_functions::manifest::BlockingAuthTokenPolicy::any)
    }

    fn inbound_credential_policy(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
    ) -> fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
        if self.forward_inbound_credentials {
            let Ok(settings) = self.settings_snapshot() else {
                return fireemu_core_functions::manifest::BlockingAuthTokenPolicy::default();
            };
            let selection = settings.selections.for_event(event);
            if matches!(
                selection,
                fireemu_core_functions::manifest::BlockingAuthSelection::Disabled
            ) {
                return fireemu_core_functions::manifest::BlockingAuthTokenPolicy::default();
            }
            let restrictions = settings.forwarding_restrictions;
            restrict_blocking_auth_token_policy(
                self.runtime
                    .blocking_auth_token_policy_for(event, Self::selected_function(selection)),
                restrictions,
            )
        } else {
            fireemu_core_functions::manifest::BlockingAuthTokenPolicy::default()
        }
    }

    fn blocking_auth_settings(&self) -> Option<serde_json::Value> {
        self.blocking_auth_settings_value()
    }

    fn blocking_auth_settings_for_export(&self) -> Result<Option<serde_json::Value>, String> {
        self.blocking_auth_settings_value_for_export()
    }

    fn blocking_auth_settings_snapshot(&self) -> Result<Option<serde_json::Value>, String> {
        self.blocking_auth_settings_snapshot_value()
    }

    fn restore_blocking_auth_settings_snapshot(
        &self,
        snapshot: &serde_json::Value,
    ) -> Result<(), String> {
        self.restore_blocking_auth_settings_snapshot_value(snapshot)
    }

    fn blocking_auth_project(&self) -> Option<&str> {
        Some(self.runtime.project())
    }

    fn validate_blocking_auth_settings(&self, settings: &serde_json::Value) -> Result<(), String> {
        self.parse_blocking_auth_settings(settings).map(|_| ())
    }

    fn update_blocking_auth_settings(&self, settings: &serde_json::Value) -> Result<(), String> {
        self.replace_blocking_auth_settings(settings)
    }

    fn update_blocking_auth_settings_masked(
        &self,
        settings: &serde_json::Value,
        fields: &[String],
    ) -> Result<(), String> {
        self.replace_blocking_auth_settings_masked(settings, fields)
    }

    fn invoke(
        &self,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<serde_json::Value, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure>
    {
        self.invoke_for_namespace(
            self.runtime.project(),
            None,
            event,
            user,
            &fireemu_adapter_http::identity_toolkit::AuthBlockingContext::default(),
        )
        .map(|value| value.unwrap_or_else(|| serde_json::json!({})))
    }

    fn invoke_for(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        self.invoke_for_namespace(
            project,
            tenant,
            event,
            user,
            &fireemu_adapter_http::identity_toolkit::AuthBlockingContext::default(),
        )
    }

    fn invoke_for_with_context(
        &self,
        project: &str,
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        user: &fireemu_core_auth::store::UserRecord,
        context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        self.invoke_for_namespace(project, tenant, event, user, context)
    }
}

/// The runtime as the control API's hook.
pub struct Hook(pub Arc<FunctionsRuntime>);

impl FunctionsHook for Hook {
    fn on_clock_changed(&self) {
        self.0.on_clock_changed();
    }

    fn run_schedule(&self, function: &str) -> Result<(), String> {
        self.0.run_schedule(function)
    }

    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }

    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        self.0.idle_notify()
    }

    fn status(&self) -> serde_json::Value {
        self.0.status()
    }

    fn publish(&self, topic: &str, messages: &[serde_json::Value]) -> Result<Vec<String>, String> {
        if topic.is_empty() || topic.len() > 255 {
            return Err("topic must be 1..=255 characters".to_owned());
        }
        Ok(self.0.publish(topic, messages))
    }

    fn project(&self) -> String {
        self.0.project().to_owned()
    }
}

/// Bridges the real Pub/Sub broker to the Functions runtime: a message published through the
/// `google.pubsub.v1` wire surface is also delivered to any Cloud Function subscribed to that
/// topic (EVTINFRA-02), through the same `FunctionsRuntime::publish` path the control publish
/// route uses, so the topic-trigger behaviour is unchanged and the new broker state is purely
/// additive.
pub struct PubSubBridge(Arc<FunctionsRuntime>);

impl PubSubBridge {
    /// Wraps the functions runtime.
    #[must_use]
    pub fn new(runtime: Arc<FunctionsRuntime>) -> Self {
        Self(runtime)
    }
}

struct EmptyPubSubReservation;

impl fireemu_adapter_pubsub::TopicDeliveryReservation for EmptyPubSubReservation {
    fn commit(self: Box<Self>) {}
}

struct FunctionsPubSubReservation(
    Option<fireemu_adapter_functions::runtime::EventBatchReservation>,
);

impl fireemu_adapter_pubsub::TopicDeliveryReservation for FunctionsPubSubReservation {
    fn commit(mut self: Box<Self>) {
        if let Some(reservation) = self.0.take() {
            reservation.publish();
        }
    }
}

impl fireemu_adapter_pubsub::TopicDelivery for PubSubBridge {
    fn recovery_notify(&self) -> Option<Arc<tokio::sync::Notify>> {
        Some(self.0.idle_notify())
    }

    fn reserve(
        &self,
        topic: &str,
        messages: &[fireemu_adapter_pubsub::BridgeMessage],
    ) -> Result<
        Box<dyn fireemu_adapter_pubsub::TopicDeliveryReservation>,
        fireemu_adapter_pubsub::TopicDeliveryError,
    > {
        let Some(topic) = owned_pubsub_topic(self.0.project(), topic) else {
            return Ok(Box::new(EmptyPubSubReservation));
        };
        // The runtime consumes the same `{data: <base64>, attributes, orderingKey}` message
        // shape the control publish route produces (`pubsub_event` reads `data` verbatim as the
        // CloudEvent body).
        let values: Vec<serde_json::Value> = messages
            .iter()
            .map(|m| {
                let mut value = serde_json::json!({
                    "messageId": m.message.message_id,
                    "data": base64_encode(&m.message.message.data),
                    "attributes": &m.message.message.attributes,
                });
                if !m.message.message.ordering_key.is_empty() {
                    value["orderingKey"] =
                        serde_json::Value::String(m.message.message.ordering_key.clone());
                }
                value
            })
            .collect();
        self.0
            .reserve_pubsub_events(topic.topic(), &values)
            .map(|reservation| {
                Box::new(FunctionsPubSubReservation(Some(reservation)))
                    as Box<dyn fireemu_adapter_pubsub::TopicDeliveryReservation>
            })
            .map_err(|error| match error {
                fireemu_adapter_functions::runtime::SourceEventAdmissionError::Capacity => {
                    fireemu_adapter_pubsub::TopicDeliveryError::Capacity
                }
                fireemu_adapter_functions::runtime::SourceEventAdmissionError::Unavailable => {
                    fireemu_adapter_pubsub::TopicDeliveryError::Unavailable
                }
                fireemu_adapter_functions::runtime::SourceEventAdmissionError::InvalidEvent => {
                    fireemu_adapter_pubsub::TopicDeliveryError::InvalidEvent
                }
            })
    }
}

fn owned_pubsub_topic(project: &str, resource: &str) -> Option<fireemu_core_pubsub::TopicName> {
    let topic = fireemu_core_pubsub::TopicName::parse(resource).ok()?;
    (topic.project() == project).then_some(topic)
}

/// Standard base64 with padding (the encoding the `PubSub` `CloudEvent` `data` field carries).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::process::Command;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use super::inheritable_parent_environment;
    use super::path_node_candidates;
    #[cfg(unix)]
    use super::probe_node;
    use super::{
        blocking_auth_io_failure, blocking_auth_read_response, blocking_auth_response_failure,
        blocking_auth_write_request, changed_source_stamp, check_callable_app_check,
        function_pubsub_resources, functions_source_stamp, functions_source_stamp_with_charge,
        functions_source_stamp_with_file_version, hash_source_file, hash_source_stamp_entry,
        load_user_environment, node_engine_matches, owned_pubsub_topic, package_node_engine,
        parse_node_version, provision_function_pubsub_resources, select_node_installation,
        snapshot_functions_source, source_scan_pacing_delay, source_scan_retry_delay,
        stream_source_chunks, update_watch_hash, validate_functions_codebase_budget,
        wait_for_fixed_inspector_port_release, warn_reload_once, BlockingAuthBridge,
        FunctionsSourceByteBudget, FunctionsSourceEntryBudget, FunctionsSourceFileVersion,
        FunctionsSourceScanBudget, FunctionsSourceSnapshot, FunctionsSourceStamp,
        FunctionsSourceTraversal, NodeInstallation, PubSubBridge, UserEnvironment,
        BLOCKING_AUTH_DEADLINE, MAX_BLOCKING_AUTH_RESPONSE_BYTES, MAX_FUNCTIONS_SOURCE_BYTES,
        MAX_FUNCTIONS_SOURCE_ENTRIES, MAX_FUNCTIONS_SOURCE_WATCH_BYTES_PER_SECOND,
        MAX_FUNCTIONS_SOURCE_WATCH_FILES_PER_SECOND, SOURCE_IO_BUFFER_BYTES,
    };
    #[cfg(not(windows))]
    use super::{
        push_node_candidate, run_node_probe, run_node_selection_blocking, NodeProbeCache,
        NodeProbeKey,
    };
    #[cfg(unix)]
    use super::{
        schedule_orphan_function_snapshot_sweep, snapshot_directory_name, snapshot_owned_directory,
        snapshot_owner_pid, sweep_orphan_function_snapshots,
    };
    use fireemu_adapter_functions::manifest_json::parse_manifest;
    use fireemu_core_pubsub::{
        Filter, PubSubState, PushConfig, SubscriptionConfig, SubscriptionName, TopicName,
    };
    use fireemu_core_session::clock::VirtualClock;
    use serde_json::json;

    #[tokio::test]
    async fn fixed_inspector_port_wait_reports_a_port_still_in_use() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let error = wait_for_fixed_inspector_port_release(port, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(error.contains(&format!("fixed inspector port {port}")));
        assert!(error.contains("did not become available"));

        drop(listener);
        wait_for_fixed_inspector_port_release(port, Duration::from_millis(50))
            .await
            .unwrap();
    }

    #[test]
    fn user_environment_debug_redacts_all_loaded_values() {
        let environment = UserEnvironment {
            values: vec![("TOKEN".to_owned(), "dotenv-sentinel".to_owned())],
            secrets: vec![("SECRET".to_owned(), "secret-sentinel".to_owned())],
            runtime_config: Some("runtime-config-sentinel".to_owned()),
            files: vec![".env".to_owned()],
        };
        let debug = format!("{environment:?}");
        for value in [
            "dotenv-sentinel",
            "secret-sentinel",
            "runtime-config-sentinel",
        ] {
            assert!(!debug.contains(value), "{debug}");
        }
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn invalid_environment_file_diagnostics_do_not_expose_values() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-redacted-environment-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        for file in [".env", ".secret.local"] {
            std::fs::write(root.join(file), "invalid-line-sentinel\n").unwrap();
            let error = load_user_environment(&root, "demo", None).unwrap_err();
            assert!(error.contains(file), "{error}");
            assert!(!error.contains("invalid-line-sentinel"), "{error}");
            std::fs::remove_file(root.join(file)).unwrap();
        }
        std::fs::remove_dir(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inheritable_parent_environment_skips_non_utf8_values() {
        if std::env::var_os("FIREEMU_TEST_NON_UTF8_CHILD").is_some() {
            let inherited = inheritable_parent_environment();
            assert!(inherited
                .iter()
                .any(|(name, value)| { name == "VOLTA_FN_UTF8_PROBE" && value == "kept" }));
            assert!(!inherited
                .iter()
                .any(|(name, _)| name == "VOLTA_FN_NON_UTF8_PROBE"));
            println!("non-UTF-8 Functions environment probe ran");
            return;
        }

        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("functions::tests::inheritable_parent_environment_skips_non_utf8_values")
            .arg("--nocapture")
            .env("FIREEMU_TEST_NON_UTF8_CHILD", "1")
            .env("VOLTA_FN_UTF8_PROBE", "kept")
            .env("VOLTA_FN_NON_UTF8_PROBE", OsString::from_vec(vec![0xff]))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("non-UTF-8 Functions environment probe ran"),
            "child test did not run: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn source_streaming_bounds_each_read_and_charges_bytes_before_a_late_error() {
        struct ProbeReader {
            reads: usize,
        }

        impl std::io::Read for ProbeReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                assert!(buffer.len() <= SOURCE_IO_BUFFER_BYTES);
                if self.reads == 2 {
                    return Err(std::io::Error::other("late read failure"));
                }
                self.reads += 1;
                buffer.fill(b'x');
                Ok(buffer.len())
            }
        }

        let mut reader = ProbeReader { reads: 0 };
        let mut charged = 0_u64;
        let cancelled = AtomicBool::new(false);
        let error = stream_source_chunks(
            &mut reader,
            |_| Ok(()),
            |bytes| {
                charged = charged.saturating_add(bytes);
                Ok(())
            },
            &cancelled,
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(charged, u64::try_from(2 * SOURCE_IO_BUFFER_BYTES).unwrap());
    }

    #[test]
    fn source_tree_entry_budget_rejects_the_first_entry_past_the_limit() {
        let mut budget = FunctionsSourceEntryBudget::default();
        budget.claim(MAX_FUNCTIONS_SOURCE_ENTRIES).unwrap();

        let error = budget.claim(1).unwrap_err();

        assert!(error.contains("100000 entries"), "{error}");
    }

    #[test]
    fn oversized_sparse_source_is_rejected_before_reading_its_contents() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-byte-budget-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::File::create(root.join("oversized.bin"))
            .unwrap()
            .set_len(300 * 1024 * 1024)
            .unwrap();
        let mut charged = 0_u64;
        let error = functions_source_stamp_with_charge(
            &root,
            &[],
            &mut |_, bytes| {
                charged = charged.saturating_add(bytes);
                if charged >= u64::try_from(SOURCE_IO_BUFFER_BYTES).unwrap() {
                    return Err("test stopped an unbounded read".to_owned());
                }
                Ok(())
            },
            &AtomicBool::new(false),
        )
        .unwrap_err();

        assert!(error.contains("256 MiB byte budget"), "{error}");
        assert!(error.contains("oversized.bin"), "{error}");
        assert_eq!(charged, 0, "the oversized file was read before rejection");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_byte_budget_counts_the_whole_tree_and_names_the_largest_file() {
        let mut budget = FunctionsSourceByteBudget::default();
        budget
            .claim(std::path::Path::new("large.bin"), 200 * 1024 * 1024)
            .unwrap();
        budget
            .claim(std::path::Path::new("small.bin"), 56 * 1024 * 1024)
            .unwrap();

        let error = budget
            .claim(std::path::Path::new("overflow.bin"), 1)
            .unwrap_err();

        assert!(error.contains("256 MiB byte budget"), "{error}");
        assert!(error.contains("large.bin"), "{error}");
        assert!(error.contains("overflow.bin"), "{error}");
    }

    #[test]
    fn reload_warning_is_emitted_once_until_a_successful_scan() {
        let mut warned = false;
        assert!(warn_reload_once(
            &mut warned,
            "alpha",
            "scan",
            "256 MiB exceeded at 300 MiB"
        ));
        assert!(!warn_reload_once(
            &mut warned,
            "alpha",
            "scan",
            "256 MiB exceeded at 301 MiB"
        ));
        warned = false;
        assert!(warn_reload_once(
            &mut warned,
            "alpha",
            "scan",
            "256 MiB exceeded again"
        ));
    }

    #[test]
    fn source_scan_waits_before_retrying_a_budget_exceeded_tree() {
        let mut budget = FunctionsSourceByteBudget::default();
        let reason = budget
            .claim(
                std::path::Path::new("too-large.bin"),
                MAX_FUNCTIONS_SOURCE_BYTES + 1,
            )
            .unwrap_err();
        assert_eq!(
            source_scan_retry_delay(Duration::from_millis(750), Some(&reason)),
            Duration::from_secs(30)
        );
        assert_eq!(
            source_scan_retry_delay(Duration::from_millis(750), Some("permission denied")),
            Duration::from_millis(1500)
        );
        assert_eq!(
            source_scan_retry_delay(Duration::from_secs(8), None),
            Duration::from_millis(750)
        );
    }

    #[tokio::test]
    async fn first_successful_scan_after_startup_failure_sets_a_baseline() {
        let root =
            std::env::temp_dir().join(format!("fireemu-scan-baseline-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.js"), "exports.ok = 1;").unwrap();
        let codebase = crate::config::FunctionsCodebase {
            codebase: "default".to_owned(),
            source: root.display().to_string(),
            runtime: None,
            ignore: Vec::new(),
        };
        let budget = FunctionsSourceScanBudget::new();
        let mut observed = None;
        let mut last_error = true;
        let mut retry_delay = Duration::from_secs(3);

        assert!(changed_source_stamp(
            &root,
            &codebase,
            &budget,
            &mut observed,
            &mut last_error,
            &mut retry_delay
        )
        .await
        .is_none());
        assert!(
            observed.is_some(),
            "the first successful scan is the baseline"
        );
        assert!(!last_error);
        assert_eq!(retry_delay, Duration::from_millis(750));

        std::fs::write(root.join("index.js"), "exports.ok = 2;").unwrap();
        assert!(changed_source_stamp(
            &root,
            &codebase,
            &budget,
            &mut observed,
            &mut last_error,
            &mut retry_delay
        )
        .await
        .is_some());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn repeated_source_scan_errors_back_off_and_release_the_scan_permit() {
        let root = std::env::temp_dir().join(format!("fireemu-scan-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let codebase = crate::config::FunctionsCodebase {
            codebase: "default".to_owned(),
            source: root.display().to_string(),
            runtime: None,
            ignore: Vec::new(),
        };
        let budget = FunctionsSourceScanBudget::new();
        let mut observed = None;
        let mut last_error = false;
        let mut retry_delay = Duration::from_millis(750);

        assert!(changed_source_stamp(
            &root,
            &codebase,
            &budget,
            &mut observed,
            &mut last_error,
            &mut retry_delay
        )
        .await
        .is_none());
        assert!(retry_delay > Duration::from_millis(750));
        assert_eq!(budget.gate.available_permits(), 1);
        let first_delay = retry_delay;
        assert!(changed_source_stamp(
            &root,
            &codebase,
            &budget,
            &mut observed,
            &mut last_error,
            &mut retry_delay
        )
        .await
        .is_none());
        assert!(retry_delay > first_delay);
        assert_eq!(budget.gate.available_permits(), 1);
        for _ in 0..8 {
            assert!(changed_source_stamp(
                &root,
                &codebase,
                &budget,
                &mut observed,
                &mut last_error,
                &mut retry_delay
            )
            .await
            .is_none());
        }
        assert_eq!(retry_delay, Duration::from_secs(8));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.js"), "exports.ok = 1;").unwrap();
        assert!(changed_source_stamp(
            &root,
            &codebase,
            &budget,
            &mut observed,
            &mut last_error,
            &mut retry_delay
        )
        .await
        .is_none());
        assert!(observed.is_some());
        assert!(!last_error);
        assert_eq!(retry_delay, Duration::from_millis(750));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oversized_snapshot_input_is_rejected_before_creating_its_copy() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-snapshot-byte-budget-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("large.bin");
        let target = root.join("copy.bin");
        std::fs::File::create(&source)
            .unwrap()
            .set_len(300 * 1024 * 1024)
            .unwrap();
        let mut charged = 0_u64;
        let mut charge = |_: u64, bytes: u64| {
            charged = charged.saturating_add(bytes);
            Ok(())
        };
        let cancelled = AtomicBool::new(false);
        let mut traversal = FunctionsSourceTraversal {
            root: &root,
            ignores: &[],
            entry_budget: FunctionsSourceEntryBudget::default(),
            byte_budget: FunctionsSourceByteBudget::default(),
            charge: &mut charge,
            cancelled: &cancelled,
        };

        let error = traversal.copy_file(&source, &target).unwrap_err();

        assert!(error.contains("256 MiB byte budget"), "{error}");
        assert!(!target.exists());
        assert_eq!(charged, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn orphan_sweep_removes_only_owned_dead_pid_snapshot_directories() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-orphan-sweep-fixture-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let dead = root.join(snapshot_directory_name(u32::try_from(i32::MAX).unwrap(), 0));
        let live = root.join(snapshot_directory_name(std::process::id(), 1));
        let parent_pid = rustix::process::getppid().unwrap();
        let other_live = root.join(snapshot_directory_name(
            u32::try_from(parent_pid.as_raw_pid()).unwrap(),
            5,
        ));
        let malformed = root.join(format!("fireemu-functions-{}-bad", i32::MAX));
        let permissive = root.join(snapshot_directory_name(u32::try_from(i32::MAX).unwrap(), 3));
        let outside = root.join("outside");
        for path in [&dead, &live, &other_live, &malformed, &permissive, &outside] {
            std::fs::create_dir(path).unwrap();
        }
        for path in [&dead, &live, &other_live, &malformed] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::set_permissions(&permissive, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(outside.join("sentinel"), "keep").unwrap();
        std::os::unix::fs::symlink(&outside, dead.join("node_modules")).unwrap();
        let direct_link = root.join(snapshot_directory_name(u32::try_from(i32::MAX).unwrap(), 2));
        std::os::unix::fs::symlink(&outside, &direct_link).unwrap();
        let regular = root.join(snapshot_directory_name(u32::try_from(i32::MAX).unwrap(), 4));
        std::fs::write(&regular, "keep").unwrap();

        let removed = sweep_orphan_function_snapshots(&root).unwrap();

        assert_eq!(removed, 1);
        assert!(!dead.exists());
        for path in [
            &live,
            &other_live,
            &malformed,
            &permissive,
            &direct_link,
            &regular,
        ] {
            assert!(
                path.symlink_metadata().is_ok(),
                "{} was removed",
                path.display()
            );
        }
        let owner = rustix::process::geteuid().as_raw();
        let metadata = std::fs::symlink_metadata(&live).unwrap();
        assert!(snapshot_owned_directory(&metadata, owner));
        assert!(!snapshot_owned_directory(&metadata, owner.wrapping_add(1)));
        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel")).unwrap(),
            "keep"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn orphan_snapshot_names_require_exact_decimal_pid_and_sequence() {
        assert!(snapshot_owner_pid(&snapshot_directory_name(1, 0)).is_some());
        for invalid in [
            "fireemu-functions-0-0",
            "fireemu-functions-01-0",
            "fireemu-functions-1-00",
            "fireemu-functions-1--1",
            "fireemu-functions-1-0-extra",
            "fireemu-functions-2147483648-0",
            "fireemu-functions-1-18446744073709551616",
            "fireemu-functions-cancelled-snapshot-source-1-0",
        ] {
            assert!(snapshot_owner_pid(invalid).is_none(), "{invalid}");
        }
        #[cfg(target_os = "linux")]
        {
            let other_namespace = format!(
                "fireemu-functions-1-0-n{}",
                super::pid_namespace_inode().unwrap().wrapping_add(1)
            );
            assert!(snapshot_owner_pid(&other_namespace).is_none());
            assert!(snapshot_owner_pid("fireemu-functions-1-0").is_none());
        }
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn startup_schedules_orphan_snapshot_cleanup_off_the_runtime_worker() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-startup-sweep-fixture-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let orphan = root.join(snapshot_directory_name(u32::try_from(i32::MAX).unwrap(), 0));
        std::fs::create_dir(&orphan).unwrap();
        std::fs::set_permissions(&orphan, std::fs::Permissions::from_mode(0o700)).unwrap();

        schedule_orphan_function_snapshot_sweep(root.clone())
            .await
            .unwrap();

        assert!(!orphan.exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_codebase_does_not_hold_the_shared_scan_gate() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-scan-gate-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let oversized = root.join("oversized");
        let small = root.join("small");
        std::fs::create_dir_all(&oversized).unwrap();
        std::fs::create_dir(&small).unwrap();
        std::fs::File::create(oversized.join("large.bin"))
            .unwrap()
            .set_len(300 * 1024 * 1024)
            .unwrap();
        std::fs::write(small.join("index.js"), "module.exports = 1;").unwrap();

        let budget = FunctionsSourceScanBudget::new();
        let (large_result, small_result) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(budget.scan(&oversized, &[]), budget.scan(&small, &[]))
        })
        .await
        .expect("an oversized codebase held the shared scan gate");
        assert!(large_result.unwrap_err().contains("256 MiB byte budget"));
        assert_eq!(small_result.unwrap().tracked_files, 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_budgeted_snapshot_removes_the_partial_copy() {
        static NEXT_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let fixture = NEXT_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-cancelled-snapshot-source-{}-{fixture}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let marker = format!("cancel-{fixture}.js");
        std::fs::File::create(root.join(&marker))
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();
        let prefix = format!("fireemu-functions-{}-", std::process::id());
        let snapshots = || {
            std::fs::read_dir(std::env::temp_dir())
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(&prefix))
                        && path.join(&marker).exists()
                })
                .collect::<BTreeSet<_>>()
        };
        let budget = Arc::new(FunctionsSourceScanBudget::new());
        let task_root = root.clone();
        let task = tokio::spawn(async move { budget.snapshot(&task_root, &[]).await });
        // Readiness is not a latency assertion: hashing and scheduling can exceed
        // the minimum pacing delay under workspace-wide test load.
        let ready = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if !snapshots().is_empty() {
                    return true;
                }
                if task.is_finished() {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        task.abort();
        let _ = task.await;
        let cleaned = tokio::time::timeout(Duration::from_secs(1), async {
            while !snapshots().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            cleaned.is_ok(),
            "cancelling a paced 128 MiB snapshot did not stop and clean up within one second"
        );
        assert!(
            matches!(ready, Ok(true)),
            "the snapshot task did not expose a partial copy before cancellation"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_scan_pacing_charges_every_tracked_byte_to_one_global_rate() {
        assert_eq!(source_scan_pacing_delay(0, 0), Duration::ZERO);
        assert_eq!(
            source_scan_pacing_delay(0, MAX_FUNCTIONS_SOURCE_WATCH_BYTES_PER_SECOND),
            Duration::from_secs(1)
        );
        assert_eq!(
            source_scan_pacing_delay(0, MAX_FUNCTIONS_SOURCE_WATCH_BYTES_PER_SECOND / 4),
            Duration::from_millis(250)
        );
        assert_eq!(
            (0..32)
                .map(|_| source_scan_pacing_delay(0, 2 * 1024 * 1024))
                .sum::<Duration>(),
            Duration::from_secs(1),
            "32 codebases share the same 64 MiB/s budget instead of multiplying it"
        );
        assert_eq!(
            source_scan_pacing_delay(MAX_FUNCTIONS_SOURCE_WATCH_FILES_PER_SECOND, 0),
            Duration::from_secs(1)
        );
        assert_eq!(
            (0..32)
                .map(|_| source_scan_pacing_delay(625, 0))
                .sum::<Duration>(),
            Duration::from_secs(1),
            "many small files share one global metadata-walk budget"
        );
    }

    #[test]
    fn runtime_refuses_too_many_codebases_before_starting_runners() {
        let codebases = (0..33)
            .map(|index| crate::config::FunctionsCodebase {
                codebase: format!("codebase-{index}"),
                source: format!("/must-not-be-opened/codebase-{index}"),
                runtime: None,
                ignore: Vec::new(),
            })
            .collect::<Vec<_>>();

        let error = validate_functions_codebase_budget(&codebases).unwrap_err();
        assert!(error.contains("33 selected Functions codebases"), "{error}");
        assert!(error.contains("local safety budget of 32"), "{error}");
    }

    #[test]
    fn blocking_auth_user_uses_the_functions_sdk_record_shape() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();

        let value = super::blocking_auth_user_json(
            store.user_by_id(uid.as_str()).unwrap(),
            Some("customer"),
        );

        assert_eq!(value["emailVerified"], false);
        assert!(value.get("email_verified").is_none());
        assert!(value.get("displayName").is_some());
        assert!(value.get("photoURL").is_some());
        assert!(value.get("phoneNumber").is_some());
        assert_eq!(value["customClaims"], json!({}));
        assert_eq!(value["tenantId"], "customer");
        assert!(value.get("providerData").is_some());
        assert_eq!(value["metadata"]["creationTime"], "2026-08-29T12:01:00Z");
        assert!(value["metadata"].get("lastSignInTime").is_some());
        assert_eq!(
            super::blocking_auth_resource_name("demo-app", Some("customer")),
            "projects/demo-app/tenants/customer"
        );
        let forwarded = std::cell::Cell::new(false);
        let value = super::with_blocking_auth_project("demo-app", "demo-worker", || {
            forwarded.set(true);
            Ok::<_, ()>(Some(json!({})))
        })
        .unwrap();
        assert!(value.is_none());
        assert!(!forwarded.get());

        let value = super::with_blocking_auth_project("demo-app", "demo-app", || {
            forwarded.set(true);
            Ok::<_, ()>(Some(json!({"accepted": true})))
        })
        .unwrap();
        assert_eq!(value, Some(json!({"accepted": true})));
        assert!(forwarded.get());
    }

    #[test]
    fn blocking_auth_context_uses_the_functions_sdk_shape() {
        use fireemu_adapter_http::identity_toolkit::{
            AuthBlockingAdditionalUserInfo, AuthBlockingContext, AuthBlockingCredential,
        };

        let claims = json!({"roles": ["billing", "support"]});
        let request = AuthBlockingContext {
            credential: Some(AuthBlockingCredential {
                claims: Some(claims.clone()),
                provider_id: "oidc.corp".to_owned(),
                sign_in_method: "oidc.corp".to_owned(),
                access_token: None,
                id_token: None,
                refresh_token: None,
            }),
            additional_user_info: Some(AuthBlockingAdditionalUserInfo {
                provider_id: "oidc.corp".to_owned(),
                profile: Some(claims.clone()),
                is_new_user: false,
            }),
            sign_in_method: Some("oidc.corp".to_owned()),
        };

        let value = super::blocking_auth_context_json(
            "demo-app",
            Some("customer"),
            fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
            &request,
            "event-1",
            "2026-08-29T12:01:00Z",
        );

        assert_eq!(
            value,
            json!({
                "eventId": "event-1",
                "eventType": "providers/cloud.auth/eventTypes/user.beforeSignIn:oidc.corp",
                "resource": {
                    "service": "identitytoolkit.googleapis.com",
                    "name": "projects/demo-app/tenants/customer"
                },
                "timestamp": "2026-08-29T12:01:00Z",
                "params": {},
                "additionalUserInfo": {
                    "providerId": "oidc.corp",
                    "profile": claims,
                    "isNewUser": false
                },
                "credential": {
                    "providerId": "oidc.corp",
                    "signInMethod": "oidc.corp",
                    "claims": {"roles": ["billing", "support"]}
                }
            })
        );
        assert!(value["credential"].get("idToken").is_none());
        assert!(value["credential"].get("accessToken").is_none());

        let raw_request = AuthBlockingContext {
            credential: Some(AuthBlockingCredential {
                claims: None,
                provider_id: "oidc.corp".to_owned(),
                sign_in_method: "oidc.corp".to_owned(),
                access_token: Some("access-sentinel".to_owned()),
                id_token: Some("id-sentinel".to_owned()),
                refresh_token: Some("refresh-sentinel".to_owned()),
            }),
            ..request.clone()
        };
        let raw_value = super::blocking_auth_context_json(
            "demo-app",
            Some("customer"),
            fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSignIn,
            &raw_request,
            "event-raw",
            "2026-08-29T12:01:00Z",
        );
        assert_eq!(
            raw_value["credential"],
            json!({
                "providerId": "oidc.corp",
                "signInMethod": "oidc.corp",
                "accessToken": "access-sentinel",
                "idToken": "id-sentinel",
                "refreshToken": "refresh-sentinel"
            })
        );

        let before_create = super::blocking_auth_context_json(
            "demo-app",
            None,
            fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
            &request,
            "event-2",
            "2026-08-29T12:01:00Z",
        );
        assert_eq!(
            before_create["eventType"],
            "providers/cloud.auth/eventTypes/user.beforeCreate"
        );
    }

    #[test]
    fn blocking_auth_context_is_narrowed_to_the_admitted_targets_token_policy() {
        use fireemu_adapter_http::identity_toolkit::{AuthBlockingContext, AuthBlockingCredential};
        use fireemu_core_functions::manifest::BlockingAuthTokenPolicy;

        let context = AuthBlockingContext {
            credential: Some(AuthBlockingCredential {
                claims: Some(json!({"sub": "provider-user"})),
                provider_id: "oidc.corp".to_owned(),
                sign_in_method: "oidc.corp".to_owned(),
                access_token: Some("access-sentinel".to_owned()),
                id_token: Some("id-sentinel".to_owned()),
                refresh_token: Some("refresh-sentinel".to_owned()),
            }),
            ..AuthBlockingContext::default()
        };
        for bits in 0_u8..8 {
            let narrowed = super::narrow_blocking_auth_credentials(
                &context,
                true,
                BlockingAuthTokenPolicy {
                    access_token: bits & 1 != 0,
                    id_token: bits & 2 != 0,
                    refresh_token: bits & 4 != 0,
                },
                None,
            );
            let credential = narrowed.credential.unwrap();
            assert_eq!(credential.access_token.is_some(), bits & 1 != 0);
            assert_eq!(credential.id_token.is_some(), bits & 2 != 0);
            assert_eq!(credential.refresh_token.is_some(), bits & 4 != 0);
            assert_eq!(credential.claims, Some(json!({"sub": "provider-user"})));
        }

        let mut absent = context.clone();
        absent.credential.as_mut().unwrap().id_token = None;
        let narrowed = super::narrow_blocking_auth_credentials(
            &absent,
            true,
            BlockingAuthTokenPolicy::ALL,
            None,
        );
        let credential = narrowed.credential.unwrap();
        assert!(credential.access_token.is_some());
        assert!(credential.id_token.is_none());
        assert!(credential.refresh_token.is_some());

        let narrowed = super::narrow_blocking_auth_credentials(
            &context,
            false,
            BlockingAuthTokenPolicy::ALL,
            None,
        );
        let credential = narrowed.credential.unwrap();
        assert!(credential.access_token.is_none());
        assert!(credential.id_token.is_none());
        assert!(credential.refresh_token.is_none());
    }

    #[test]
    fn blocking_auth_forwarding_restrictions_intersect_manifest_and_global_policy() {
        use fireemu_core_functions::manifest::{
            BlockingAuthCredentialPresence, BlockingAuthTokenPolicy,
        };

        let manifest_policy = BlockingAuthTokenPolicy::ALL;
        let configured = BlockingAuthTokenPolicy {
            access_token: false,
            id_token: true,
            refresh_token: true,
        };
        let available = BlockingAuthCredentialPresence {
            access_token: true,
            id_token: false,
            refresh_token: true,
        };
        assert_eq!(
            super::effective_blocking_auth_token_policy(
                manifest_policy,
                true,
                Some(configured),
                available,
            ),
            BlockingAuthTokenPolicy {
                access_token: false,
                id_token: false,
                refresh_token: true,
            }
        );

        let global_disabled = super::validate_blocking_auth_forwarding_policy(
            false,
            Some(BlockingAuthTokenPolicy {
                access_token: true,
                id_token: false,
                refresh_token: false,
            }),
        )
        .unwrap_err();
        assert!(global_disabled.contains("global auth.forwardInboundCredentials"));

        super::validate_blocking_auth_forwarding_policy(
            false,
            Some(BlockingAuthTokenPolicy::default()),
        )
        .expect("an all-false project restriction cannot widen a disabled global switch");
    }

    #[test]
    fn blocking_auth_selection_rejects_missing_or_changed_live_target() {
        use fireemu_core_functions::manifest::BlockingAuthSelection;

        let selection = BlockingAuthSelection::Explicit {
            function: "guardSignIn".to_owned(),
            region: Some("europe-west1".to_owned()),
        };
        assert!(super::blocking_auth_selection_accepts_target(
            &selection,
            Some(("guardSignIn", "europe-west1"))
        ));
        assert!(!super::blocking_auth_selection_accepts_target(
            &selection, None
        ));
        assert!(!super::blocking_auth_selection_accepts_target(
            &selection,
            Some(("otherGuard", "europe-west1"))
        ));
        assert!(!super::blocking_auth_selection_accepts_target(
            &selection,
            Some(("guardSignIn", "us-central1"))
        ));
        assert!(!super::blocking_auth_selection_accepts_target(
            &BlockingAuthSelection::Disabled,
            Some(("guardSignIn", "europe-west1"))
        ));
    }

    async fn runtime_with_blocking_auth_policy_order(
        order: &[(&str, bool, bool)],
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        runtime_with_blocking_auth_policy_order_and_env(order, Vec::new()).await
    }

    async fn runtime_with_blocking_auth_policy_order_and_env(
        order: &[(&str, bool, bool)],
        env: Vec<(String, String)>,
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_core_functions::manifest::{BlockingAuthEvent, Trigger};
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::LogicalInstant;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let spec = SpawnSpec {
            command: vec!["python3".to_owned(), script.display().to_string()],
            cwd: None,
            env,
            hello_timeout: Duration::from_secs(60),
        };
        let runner = Runner::spawn_spec(&spec).await.unwrap();
        let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let template = manifest.get("echo").unwrap().clone();
        for (name, access_token, refresh_token) in order {
            let mut function = template.clone();
            function.name = (*name).to_owned();
            function.entry_point = (*name).to_owned();
            function.trigger = Trigger::BlockingAuth {
                event: BlockingAuthEvent::BeforeCreate,
                token_policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
                    access_token: *access_token,
                    refresh_token: *refresh_token,
                    ..Default::default()
                },
            };
            manifest.functions.push(function);
        }
        FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 4,
                debug_mode: false,
                retry_attempts: 1,
                max_catch_up_runs: 1,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            Arc::new(runner),
            Some(spec),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_blocking_auth_prefilter_uses_the_selected_function_policy() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_functions::manifest::{
            BlockingAuthEvent, BlockingAuthSelection, BlockingAuthSelections,
        };

        let runtime = runtime_with_blocking_auth_policy_order(&[
            ("guardA", false, false),
            ("guardB", true, true),
        ])
        .await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Explicit {
                    function: "guardB".to_owned(),
                    region: Some("us-central1".to_owned()),
                },
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            true,
        );
        assert!(bridge.forward_inbound_credentials());
        assert!(
            bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .access_token
        );
        assert!(
            bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .refresh_token
        );
        let (target, admission) = runtime
            .try_admit_blocking_auth_for(BlockingAuthEvent::BeforeCreate, Some("guardB"))
            .unwrap()
            .unwrap();
        assert_eq!(target.function, "guardB");
        assert!(target.token_policy.access_token);
        assert!(target.token_policy.refresh_token);
        drop(admission);

        let global_disabled = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            bridge.settings_snapshot().unwrap().selections,
            false,
        );
        let global_disabled_policy =
            global_disabled.inbound_credential_policy(BlockingAuthEvent::BeforeCreate);
        assert!(!global_disabled_policy.access_token);
        assert!(!global_disabled_policy.refresh_token);

        let restricted = BlockingAuthBridge::try_new_with_selections_and_forwarding_policy(
            runtime.clone(),
            bridge.settings_snapshot().unwrap().selections,
            true,
            Some(fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
                access_token: false,
                id_token: false,
                refresh_token: true,
            }),
        )
        .unwrap();
        let restricted_policy =
            restricted.inbound_credential_policy(BlockingAuthEvent::BeforeCreate);
        assert!(!restricted_policy.access_token);
        assert!(restricted_policy.refresh_token);
        runtime.shutdown().await;

        let runtime = runtime_with_blocking_auth_policy_order(&[
            ("guardB", true, true),
            ("guardA", false, false),
        ])
        .await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Explicit {
                    function: "guardB".to_owned(),
                    region: Some("us-central1".to_owned()),
                },
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            true,
        );
        assert!(
            bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .access_token
        );
        assert!(
            bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .refresh_token
        );
        runtime.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_auth_prefilter_keeps_discovery_and_disabled_policies() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_functions::manifest::{
            BlockingAuthEvent, BlockingAuthSelection, BlockingAuthSelections,
        };

        let runtime = runtime_with_blocking_auth_policy_order(&[
            ("guardA", false, false),
            ("guardB", true, true),
        ])
        .await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Explicit {
                    function: "guardA".to_owned(),
                    region: Some("us-central1".to_owned()),
                },
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            true,
        );
        assert!(
            !bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .access_token
        );
        assert!(
            !bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .refresh_token
        );
        runtime.shutdown().await;

        let runtime = runtime_with_blocking_auth_policy_order(&[
            ("guardA", false, false),
            ("guardB", true, true),
        ])
        .await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Discovery,
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            true,
        );
        assert!(
            !bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .access_token
        );
        assert!(
            !bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .refresh_token
        );
        runtime.shutdown().await;

        let runtime = runtime_with_blocking_auth_policy_order(&[
            ("guardA", false, false),
            ("guardB", true, true),
        ])
        .await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Disabled,
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            true,
        );
        assert!(
            !bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .access_token
        );
        assert!(
            !bridge
                .inbound_credential_policy(BlockingAuthEvent::BeforeCreate)
                .refresh_token
        );
        runtime.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_auth_settings_revision_changes_only_after_successful_updates() {
        let runtime = runtime_with_blocking_auth_policy_order(&[("guardA", true, false)]).await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            true,
        );
        let explicit = json!({
            "triggers": {
                "beforeCreate": {
                    "functionUri": "fireemu://functions/demo-app/us-central1/guardA"
                }
            }
        });

        assert_eq!(bridge.settings_revision(), 0);
        bridge
            .replace_blocking_auth_settings(&explicit)
            .expect("valid replacement");
        assert_eq!(bridge.settings_revision(), 1);
        bridge
            .replace_blocking_auth_settings(&explicit)
            .expect("replacing with the same settings is a no-op");
        assert_eq!(bridge.settings_revision(), 1);

        let error = bridge
            .replace_blocking_auth_settings(&json!({"triggers": []}))
            .expect_err("invalid replacement");
        assert!(error.contains("triggers must be an object"), "{error}");
        assert_eq!(bridge.settings_revision(), 1);

        bridge
            .replace_blocking_auth_settings_masked(
                &json!({"triggers": {"beforeCreate": null}}),
                &["blockingFunctions.triggers.beforeCreate".to_owned()],
            )
            .expect("valid masked replacement");
        assert_eq!(bridge.settings_revision(), 2);

        bridge
            .restore_blocking_auth_settings_snapshot_value(&explicit)
            .expect("valid snapshot restore");
        assert_eq!(bridge.settings_revision(), 3);
        runtime.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_auth_revision_waits_for_settings_publication_lock() {
        let runtime = runtime_with_blocking_auth_policy_order(&[("guardA", true, false)]).await;
        let bridge = Arc::new(BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            true,
        ));
        let settings_guard = bridge.settings.write().expect("settings lock");
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = bridge.clone();
        let thread = std::thread::spawn(move || {
            sender
                .send(reader.settings_revision())
                .expect("revision result");
        });
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        drop(settings_guard);
        assert_eq!(receiver.recv().expect("revision result"), 0);
        thread.join().expect("revision reader");
        runtime.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn explicit_blocking_export_fails_when_its_manifest_target_disappears() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_core_functions::manifest::{BlockingAuthSelection, BlockingAuthSelections};
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::LogicalInstant;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let spec = SpawnSpec {
            command: vec!["python3".to_owned(), script.display().to_string()],
            cwd: None,
            env: Vec::new(),
            hello_timeout: Duration::from_secs(60),
        };
        let runner = Runner::spawn_spec(&spec).await.unwrap();
        let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 1,
                debug_mode: false,
                retry_attempts: 1,
                max_catch_up_runs: 1,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            Arc::new(runner),
            Some(spec),
        );
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Explicit {
                    function: "removedBeforeCreate".to_owned(),
                    region: Some("us-central1".to_owned()),
                },
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            false,
        );

        let error = fireemu_adapter_http::identity_toolkit::AuthBlockingHook::blocking_auth_settings_for_export(&bridge)
            .unwrap_err();
        assert!(error.contains("beforeCreate"), "{error}");
        assert!(error.contains("not discovered"), "{error}");
        runtime.runner().shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_export_round_trips_mixed_discovery_without_runner_details() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_core_functions::manifest::{BlockingAuthSelection, BlockingAuthSelections};
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::LogicalInstant;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let spec = SpawnSpec {
            command: vec!["python3".to_owned(), script.display().to_string()],
            cwd: None,
            env: Vec::new(),
            hello_timeout: Duration::from_secs(60),
        };
        let runner = Runner::spawn_spec(&spec).await.unwrap();
        let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(8),
                max_running: 1,
                debug_mode: false,
                retry_attempts: 1,
                max_catch_up_runs: 1,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            Arc::new(runner),
            Some(spec),
        );
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            BlockingAuthSelections {
                before_create: BlockingAuthSelection::Discovery,
                before_sign_in: BlockingAuthSelection::Disabled,
            },
            false,
        );

        let exported = fireemu_adapter_http::identity_toolkit::AuthBlockingHook::
            blocking_auth_settings_for_export(&bridge)
            .unwrap()
            .expect("blocking settings export");
        assert_eq!(
            exported["triggers"]["beforeSignIn"],
            serde_json::Value::Null
        );
        assert_eq!(
            exported[super::BLOCKING_DISCOVERY_EVENTS_MEMBER],
            serde_json::json!(["beforeCreate"])
        );
        let serialized = exported.to_string();
        assert!(!serialized.contains("127.0.0.1"));
        assert!(!serialized.contains("test-secret"));
        assert!(!serialized.contains("httpPort"));

        bridge
            .replace_blocking_auth_settings(&exported)
            .expect("mixed blocking settings restore");
        let round_tripped = fireemu_adapter_http::identity_toolkit::AuthBlockingHook::
            blocking_auth_settings_for_export(&bridge)
            .unwrap()
            .expect("blocking settings re-export");
        assert_eq!(round_tripped, exported);

        let public =
            fireemu_adapter_http::identity_toolkit::AuthBlockingHook::blocking_auth_settings(
                &bridge,
            )
            .expect("public blocking settings");
        assert!(public
            .get(super::BLOCKING_DISCOVERY_EVENTS_MEMBER)
            .is_none());
        runtime.runner().shutdown().await;
    }

    #[test]
    fn blocking_auth_transport_bounds_and_failure_pairs_are_production_bounded() {
        assert_eq!(BLOCKING_AUTH_DEADLINE, Duration::from_secs(7));
        assert_eq!(MAX_BLOCKING_AUTH_RESPONSE_BYTES, 64 * 1024);
        assert_eq!(
            blocking_auth_io_failure(&std::io::Error::from(std::io::ErrorKind::TimedOut))
                .identity_status(),
            503
        );
        assert_eq!(
            blocking_auth_io_failure(&std::io::Error::from(std::io::ErrorKind::ConnectionReset))
                .identity_status(),
            503
        );

        let permission = json!({
            "error": {"status": "PERMISSION_DENIED", "message": "policy rejected"}
        });
        assert_eq!(
            blocking_auth_response_failure(403, &permission).identity_status(),
            400
        );
        let explicit_deadline = json!({
            "error": {"status": "DEADLINE_EXCEEDED", "message": "explicit deadline"}
        });
        assert_eq!(
            blocking_auth_response_failure(504, &explicit_deadline).identity_status(),
            504
        );

        for (status, value) in [
            (
                418,
                json!({"error": {"status": "PERMISSION_DENIED", "message": "marker"}}),
            ),
            (
                403,
                json!({"error": {"status": "permission_denied", "message": "marker"}}),
            ),
            (
                403,
                json!({"error": {"status": "PERMISSION_DENIED", "message": 1}}),
            ),
            (
                403,
                json!({"error": {"status": "PERMISSION_DENIED", "message": "line\nmarker"}}),
            ),
            (
                403,
                json!({"error": {"status": "PERMISSION_DENIED", "message": "x".repeat(4_097)}}),
            ),
            (
                600,
                json!({"error": {"status": "UNAVAILABLE", "message": "marker"}}),
            ),
            (503, json!({"error": []})),
        ] {
            assert_eq!(
                blocking_auth_response_failure(status, &value).identity_status(),
                503,
                "status={status}, value={value}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_timed_out_blocking_handler_releases_admission_and_recycles_its_runner() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::LogicalInstant;
        use std::sync::Mutex;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let spec = SpawnSpec {
            command: vec!["python3".to_owned(), script.display().to_string()],
            cwd: None,
            env: vec![(
                "FIREEMU_FAKE_BLOCKING_HANG_MS".to_owned(),
                "5000".to_owned(),
            )],
            // Runner startup is setup for this blocking-timeout scenario, rather than the
            // behavior under test. Match the production handshake allowance so a cold macOS
            // Python launch cannot consume the test's unrelated timeout budget.
            hello_timeout: Duration::from_secs(60),
        };
        let replacement_timeout = spec.hello_timeout;
        let runner = Runner::spawn_spec(&spec).await.unwrap();
        let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let mut blocking = parse_manifest(&json!({"functions": [{
            "name": "beforeCreate",
            "generation": 2,
            "trigger": {"type": "blockingAuth", "eventType": "beforeCreate"}
        }]}))
        .unwrap();
        manifest.functions.append(&mut blocking.functions);
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 1,
                debug_mode: false,
                retry_attempts: 1,
                max_catch_up_runs: 1,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
            },
            Arc::new(Mutex::new(VirtualClock::new(now))),
            Arc::new(runner),
            Some(spec),
        );
        let retired = runtime.runner();
        let bridge =
            super::BlockingAuthBridge::with_deadline(runtime.clone(), Duration::from_millis(75));
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();

        let failure = tokio::task::spawn_blocking(move || {
            fireemu_adapter_http::identity_toolkit::AuthBlockingHook::invoke(
                &bridge,
                BlockingAuthEvent::BeforeCreate,
                &user,
            )
        })
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(failure.identity_status(), 503);
        assert!(runtime
            .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
            .is_err());

        // A replacement is a fresh process and owns the same bounded hello handshake as the
        // initial runner. Cold macOS hosts can spend most of that allowance starting Python,
        // so the assertion must cover the declared spawn contract rather than an unrelated
        // three-second scheduler assumption.
        let deadline = tokio::time::Instant::now() + replacement_timeout + Duration::from_secs(1);
        loop {
            let replacement = runtime.runner();
            if !Arc::ptr_eq(&retired, &replacement) && replacement.is_alive() {
                let (_, admission) = runtime
                    .try_admit_blocking_auth(BlockingAuthEvent::BeforeCreate)
                    .unwrap()
                    .unwrap();
                drop(admission);
                replacement.shutdown().await;
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the timed-out Blocking Auth runner was not replaced"
            );
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn first_blocking_auth_request_after_idle_runner_exit_recovers() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let runtime = runtime_with_blocking_auth_policy_order(&[("guardA", false, false)]).await;
        let bridge = BlockingAuthBridge::new(runtime.clone());
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        runtime.runner().kill_now();

        let result = tokio::task::spawn_blocking(move || {
            bridge.invoke(BlockingAuthEvent::BeforeCreate, &user)
        })
        .await
        .unwrap();
        runtime.shutdown().await;

        let value = result.expect("the first request waits for runner recovery");
        assert!(value.is_object());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_auth_runner_recovery_uses_the_existing_timeout_envelope() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let runtime = runtime_with_blocking_auth_policy_order_and_env(
            &[("guardA", false, false)],
            vec![("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "300".to_owned())],
        )
        .await;
        let bridge = BlockingAuthBridge::with_deadline(runtime.clone(), Duration::from_millis(50));
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        runtime.runner().kill_now();

        let result = tokio::task::spawn_blocking(move || {
            bridge.invoke(BlockingAuthEvent::BeforeCreate, &user)
        })
        .await
        .unwrap();
        runtime.shutdown().await;

        let failure = result.expect_err("the slow runner cannot meet the request deadline");
        assert_eq!(failure.identity_status(), 503);
        assert_eq!(
            failure,
            fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
        );
    }

    #[test]
    fn blocking_auth_response_uses_one_absolute_deadline_during_slow_drip() {
        use std::io::Write as _;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
        });
        let mut stream = TcpStream::connect(address).unwrap();
        let started = Instant::now();
        let failure = blocking_auth_read_response(&mut stream, started + Duration::from_millis(75))
            .unwrap_err();
        let elapsed = started.elapsed();
        drop(stream);
        writer.join().unwrap();

        assert_eq!(
            failure,
            fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
        );
        assert!(elapsed >= Duration::from_millis(60), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(300), "{elapsed:?}");
    }

    #[test]
    fn blocking_auth_request_writes_every_byte_before_the_deadline() {
        use std::io::Read as _;
        use std::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let receiver = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            let mut received = [0_u8; 18];
            stream.read_exact(&mut received).map(|()| received)
        });
        let mut stream = TcpStream::connect(address).unwrap();

        blocking_auth_write_request(
            &mut stream,
            b"blocking-auth-body",
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();

        assert_eq!(
            &receiver.join().unwrap().expect("request bytes must arrive"),
            b"blocking-auth-body"
        );
    }

    fn installed_node(version: &str, require_module: bool) -> NodeInstallation {
        let (_, major, minor, patch) = parse_node_version(version).unwrap();
        NodeInstallation {
            program: std::path::PathBuf::from(format!("/opt/node-{major}/bin/node")),
            version: version.trim_start_matches('v').to_owned(),
            major,
            minor,
            patch,
            require_module,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn discarded_reload_snapshot_is_removed() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-discarded-reload-snapshot-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/module.js"), "module.exports = 1;").unwrap();

        FunctionsSourceSnapshot::new(root.clone(), root.clone())
            .remove()
            .await
            .unwrap();

        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn node_probe_does_not_block_a_single_runtime_worker() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("fireemu-node-probe-worker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let program = root.join("node");
        std::fs::write(
            &program,
            "#!/bin/sh\n/bin/sleep 0.4\ncase \"$1\" in --version) echo v22.12.0;; -p) echo true;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();

        let started = Instant::now();
        let heartbeat = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            started.elapsed()
        });
        let installation = run_node_selection_blocking(move || probe_node(&program))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(installation.version, "22.12.0");
        let heartbeat_elapsed = heartbeat.await.unwrap();
        assert!(
            heartbeat_elapsed < Duration::from_millis(250),
            "heartbeat waited {heartbeat_elapsed:?}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn node_probe_cache_reuses_results_until_environment_changes() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("fireemu-node-probe-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let program = root.join("node");
        let calls = root.join("calls");
        let script = format!(
            "#!/bin/sh\necho probe >> '{}'\ncase \"$1\" in --version) echo v22.12.0;; -p) echo true;; esac\n",
            calls.display()
        );
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = NodeProbeKey {
            path: None,
            volta_home: None,
            fireemu_node: Some(program.into_os_string()),
        };
        let cache = NodeProbeCache::default();
        let first = cache.probed(&key).unwrap();
        assert_eq!(cache.probed(&key).unwrap(), first);
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 2);

        let changed = NodeProbeKey {
            path: Some("/another/bin".into()),
            ..key
        };
        assert_eq!(cache.probed(&changed).unwrap(), first);
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 4);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn node_probe_cache_retries_failed_probe_with_same_environment() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-node-probe-retry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let program = root.join("node");
        let calls = root.join("calls");
        std::fs::write(
            &program,
            format!("#!/bin/sh\necho failed >> '{}'\nexit 1\n", calls.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = NodeProbeKey {
            path: None,
            volta_home: None,
            fireemu_node: Some(program.clone().into_os_string()),
        };
        let cache = NodeProbeCache::default();
        let first = cache.probed(&key).unwrap();
        assert!(first.installations.is_empty());
        assert_eq!(first.errors.len(), 1);

        std::fs::write(
            &program,
            format!(
                "#!/bin/sh\necho recovered >> '{}'\ncase \"$1\" in --version) echo v22.12.0;; -p) echo true;; esac\n",
                calls.display()
            ),
        )
        .unwrap();
        let second = cache.probed(&key).unwrap();
        assert_eq!(second.installations.len(), 1);
        assert!(second.errors.is_empty());
        assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 3);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn node_probe_cache_retries_timed_out_probe() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-node-probe-timeout-retry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let program = root.join("node");
        std::fs::write(&program, "#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = NodeProbeKey {
            path: None,
            volta_home: None,
            fireemu_node: Some(program.clone().into_os_string()),
        };
        let cache = NodeProbeCache::default();
        let first = cache.probed(&key).unwrap();
        assert!(first.installations.is_empty());
        assert!(first.errors.iter().any(|error| error.contains("timed out")));

        std::fs::write(
            &program,
            "#!/bin/sh\ncase \"$1\" in --version) echo v22.12.0;; -p) echo true;; esac\n",
        )
        .unwrap();
        let second = cache.probed(&key).unwrap();
        assert_eq!(second.installations.len(), 1);
        assert!(second.errors.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loader_capability_precedes_runtime_and_engine_preferences() {
        let installations = vec![
            installed_node("v22.11.0", false),
            installed_node("v20.19.5", true),
            installed_node("v22.12.0", true),
        ];
        assert_eq!(
            select_node_installation(Some(22), Some("22"), &installations).unwrap(),
            2
        );
        assert_eq!(
            select_node_installation(None, Some("20"), &installations).unwrap(),
            1
        );
        assert_eq!(
            select_node_installation(None, Some(">=20.0.0 <21.0.0"), &installations).unwrap(),
            1
        );
        assert_eq!(
            select_node_installation(Some(22), Some("22"), &installations[..2]).unwrap(),
            1,
            "a capable local fallback wins over an incapable requested major"
        );

        let legacy = vec![
            installed_node("v20.19.5", true),
            installed_node("v18.20.0", false),
        ];
        assert_eq!(
            select_node_installation(Some(18), Some("18"), &legacy).unwrap(),
            1,
            "Node 18 requests retain their runtime semantics"
        );
        assert_eq!(
            select_node_installation(None, Some("18"), &legacy).unwrap(),
            1,
            "a legacy engine constraint does not inherit capability requirements from newer nodes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn automatic_path_discovery_trusts_only_the_first_node_executable() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-node-path-discovery-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let non_executable = root.join("non-executable/node");
        let first = root.join("first/node");
        let second = root.join("second/node");
        for program in [&non_executable, &first, &second] {
            std::fs::create_dir_all(program.parent().unwrap()).unwrap();
            std::fs::write(program, "#!/bin/sh\nexit 0\n").unwrap();
        }
        std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o600)).unwrap();
        for program in [&first, &second] {
            std::fs::set_permissions(program, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = std::env::join_paths([
            root.join("missing"),
            non_executable.parent().unwrap().to_owned(),
            first.parent().unwrap().to_owned(),
            second.parent().unwrap().to_owned(),
        ])
        .unwrap();

        assert_eq!(path_node_candidates(&path), vec![first]);
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A version manager's `node` is a symlink to a multi-tool shim that refuses to run under
    /// any other name (Volta: "'volta-shim' should not be called directly", exit 126). The
    /// candidate keeps the PATH entry's own name; canonical paths serve deduplication only.
    #[cfg(unix)]
    #[test]
    fn node_discovery_runs_a_symlinked_shim_by_its_link_name() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "fireemu-node-shim-discovery-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let shim = root.join("lib/multi-shim");
        let link = root.join("bin/node");
        let other_link = root.join("other/node");
        std::fs::create_dir_all(shim.parent().unwrap()).unwrap();
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::fs::create_dir_all(other_link.parent().unwrap()).unwrap();
        std::fs::write(
            &shim,
            "#!/bin/sh\ncase \"$(basename \"$0\")\" in node) echo v22.0.0;; *) exit 126;; esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&shim, &link).unwrap();
        std::os::unix::fs::symlink(&shim, &other_link).unwrap();

        let mut candidates = Vec::new();
        push_node_candidate(&mut candidates, link.clone());
        push_node_candidate(&mut candidates, other_link);
        assert_eq!(candidates, vec![link.clone()], "one candidate per shim");
        let output = run_node_probe(&link, &["--version"], "--version").unwrap();
        assert_eq!(String::from_utf8_lossy(&output).trim(), "v22.0.0");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn node_engine_parser_checks_ranges_and_alternatives() {
        for expression in [
            "*",
            "x",
            "20",
            "20.x",
            "^20.0.0",
            "~20",
            ">=20 <21",
            "18 || 20",
            "20.0.0 - 22.11.0",
        ] {
            assert!(
                node_engine_matches(expression, (20, 19, 5)).unwrap(),
                "{expression}"
            );
        }
        assert!(node_engine_matches(">=18", (22, 11, 0)).unwrap());
        assert!(!node_engine_matches("20.20.x", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("20.19.5", (20, 19, 5)).unwrap());
        assert!(!node_engine_matches("20.19.5", (20, 19, 6)).unwrap());
        assert!(node_engine_matches("^0.2.3", (0, 2, 9)).unwrap());
        assert!(node_engine_matches("~20.19.0", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("<=20", (20, 19, 5)).unwrap());
        assert!(!node_engine_matches(">20", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("20 - 22", (22, 11, 0)).unwrap());
        assert!(node_engine_matches("<=20.x", (20, 19, 5)).unwrap());
        assert!(!node_engine_matches(">20.x", (20, 19, 5)).unwrap());
        assert!(node_engine_matches("20 - 22.x", (22, 11, 0)).unwrap());
        assert!(node_engine_matches("20 - x", (99, 0, 0)).unwrap());
        assert!(node_engine_matches("x - 22", (1, 0, 0)).unwrap());
        assert!(node_engine_matches("", (20, 19, 5)).is_err());
        assert!(node_engine_matches("not-semver", (20, 19, 5)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn node_probe_times_out_when_a_descendant_keeps_stdout_open() {
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("fireemu-node-probe-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let program = root.join("node");
        let pid_file = root.join("descendant.pid");
        let script = format!(
            "#!/bin/sh\n(/bin/sleep 30) &\necho $! > '{}'\necho v22.11.0\n",
            pid_file.display()
        );
        std::fs::write(&program, script).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();

        let started = Instant::now();
        let error = probe_node(&program).unwrap_err();
        assert!(error.contains("timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(!Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .status()
            .unwrap()
            .success());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_node_discovery_uses_only_absolute_path_candidates() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-windows-node-discovery-{}",
            std::process::id()
        ));
        let current = root.join("current");
        let bin = root.join("bin");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&current).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        let current_node = current.join("node.exe");
        let path_node = bin.join("node.exe");
        std::fs::write(&current_node, b"current directory executable").unwrap();
        std::fs::write(&path_node, b"PATH executable").unwrap();
        let path = std::env::join_paths([&bin]).unwrap();

        let candidates = path_node_candidates(&path);

        assert_eq!(candidates, vec![path_node]);
        assert!(!candidates.contains(&current_node));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn package_node_engine_is_read_without_treating_it_as_an_executable() {
        let root =
            std::env::temp_dir().join(format!("fireemu-node-engine-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"engines":{"node":"20"},"scripts":{"node":"/tmp/not-an-executable"}}"#,
        )
        .unwrap();
        assert_eq!(package_node_engine(&root).unwrap().as_deref(), Some("20"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reload_signature_tracks_build_and_env_files_but_ignores_configured_paths() {
        assert_eq!(
            update_watch_hash(0xcbf2_9ce4_8422_2325, b'a'),
            0xaf63_bd4c_8601_b7be
        );
        let root =
            std::env::temp_dir().join(format!("fireemu-functions-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(root.join("generated")).unwrap();
        std::fs::write(root.join("lib/index.js"), "export const value = 1;").unwrap();
        std::fs::write(root.join(".env"), "VALUE=one\n").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), "ignored").unwrap();
        std::fs::write(root.join("generated/bundle.js"), "ignored output").unwrap();
        let ignores = vec!["generated".to_owned()];
        let first_stamp = functions_source_stamp(&root, &ignores).unwrap();
        let first = first_stamp.content_signature;
        assert_eq!(first_stamp.tracked_files, 2);
        assert_eq!(
            first_stamp.tracked_bytes,
            u64::try_from("export const value = 1;".len() + "VALUE=one\n".len()).unwrap()
        );

        std::fs::write(root.join("node_modules/pkg/index.js"), "still ignored").unwrap();
        std::fs::write(root.join("generated/bundle.js"), "still ignored output").unwrap();
        assert_eq!(
            functions_source_stamp(&root, &ignores).unwrap(),
            first_stamp
        );
        // The stamp hashes content on every platform, so metadata aliasing cannot hide a
        // same-size rewrite.
        std::fs::write(root.join("lib/index.js"), "export const value = 2;").unwrap();
        let build_changed = functions_source_stamp(&root, &ignores)
            .unwrap()
            .content_signature;
        assert_ne!(build_changed, first);
        assert_ne!(
            functions_source_stamp(&root, &ignores).unwrap(),
            first_stamp
        );
        std::fs::write(root.join(".env"), "VALUE=two\n").unwrap();
        assert_ne!(
            functions_source_stamp(&root, &ignores)
                .unwrap()
                .content_signature,
            build_changed
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_stamp_distinguishes_content_when_all_metadata_is_identical() {
        let first = hash_source_stamp_entry(
            0xcbf2_9ce4_8422_2325,
            b"lib/index.js",
            23,
            1_788_123_456_000_000_000,
            1_788_123_456,
            0,
            b"export const value = 1;",
        );
        let second = hash_source_stamp_entry(
            0xcbf2_9ce4_8422_2325,
            b"lib/index.js",
            23,
            1_788_123_456_000_000_000,
            1_788_123_456,
            0,
            b"export const value = 2;",
        );

        assert_ne!(first, second);
    }

    #[test]
    fn source_stamp_reads_real_same_size_rewrites_with_restored_mtime() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-real-metadata-alias-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("index.js");
        std::fs::write(&source, b"before").unwrap();
        let original = std::fs::metadata(&source).unwrap();
        let original_mtime = original.modified().unwrap();
        let first = functions_source_stamp(&root, &[]).unwrap();

        std::fs::write(&source, b"after!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&source)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        let rewritten = std::fs::metadata(&source).unwrap();
        assert_eq!(rewritten.len(), original.len());
        assert_eq!(rewritten.modified().unwrap(), original_mtime);

        let second = functions_source_stamp(&root, &[]).unwrap();
        assert_ne!(second.content_signature, first.content_signature);
        assert_ne!(second, first);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_file_hash_reads_rewritten_bytes_when_every_version_field_is_aliased() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-forced-metadata-alias-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("index.js");
        // POSIX does not expose an API for restoring ctime. Reuse one captured version tuple while
        // the production file hasher reads two real on-disk generations instead.
        let version = FunctionsSourceFileVersion {
            len: 6,
            modified_nanos: 1_788_123_456_000_000_000,
            changed_seconds: 1_788_123_456,
            changed_nanos: 0,
        };
        let scan = || {
            let mut stamp = FunctionsSourceStamp {
                change_guard: 0xcbf2_9ce4_8422_2325,
                content_signature: 0xcbf2_9ce4_8422_2325,
                tracked_files: 0,
                tracked_bytes: 0,
            };
            hash_source_file(
                &source,
                std::path::Path::new("index.js"),
                version,
                &mut stamp,
                &mut |_, _| Ok(()),
                &AtomicBool::new(false),
            )
            .unwrap();
            stamp
        };

        std::fs::write(&source, b"before").unwrap();
        let first = scan();
        std::fs::write(&source, b"after!").unwrap();
        let second = scan();

        assert_eq!(first.tracked_bytes, second.tracked_bytes);
        assert_ne!(first.content_signature, second.content_signature);
        assert_ne!(first.change_guard, second.change_guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn source_traversal_reads_real_rewrites_when_every_version_field_is_aliased() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-traversal-metadata-alias-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let source = root.join("index.js");
        let version = FunctionsSourceFileVersion {
            len: 6,
            modified_nanos: 1_788_123_456_000_000_000,
            changed_seconds: 1_788_123_456,
            changed_nanos: 0,
        };
        let scan = || {
            functions_source_stamp_with_file_version(&root, &[], &|metadata| {
                assert_eq!(metadata.len(), version.len);
                version
            })
            .unwrap()
        };

        std::fs::write(&source, b"before").unwrap();
        let first = scan();
        std::fs::write(&source, b"after!").unwrap();
        let second = scan();

        assert_eq!(first.tracked_files, 1);
        assert_eq!(second.tracked_files, 1);
        assert_eq!(first.tracked_bytes, second.tracked_bytes);
        assert_ne!(first.content_signature, second.content_signature);
        assert_ne!(first.change_guard, second.change_guard);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "release-only Functions source scan performance gate"]
    fn source_stamp_sustains_the_documented_scan_throughput() {
        const FILES: usize = 32;
        const BYTES_PER_FILE: usize = 1024 * 1024;
        const MIN_BYTES_PER_SECOND: u128 = 16 * 1024 * 1024;
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-source-throughput-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let payload = vec![b'x'; BYTES_PER_FILE];
        for index in 0..FILES {
            std::fs::write(root.join(format!("source-{index:03}.js")), &payload).unwrap();
        }
        let expected_bytes = u64::try_from(FILES * BYTES_PER_FILE).unwrap();
        let warm = functions_source_stamp(&root, &[]).unwrap();
        assert_eq!(warm.tracked_bytes, expected_bytes);

        let mut samples = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let stamp = functions_source_stamp(&root, &[]).unwrap();
            samples.push(started.elapsed());
            assert_eq!(stamp, warm);
        }
        samples.sort_unstable();
        let median = samples[samples.len() / 2];
        let bytes_per_second = u128::from(expected_bytes)
            .saturating_mul(1_000_000_000)
            .checked_div(median.as_nanos().max(1))
            .unwrap();
        eprintln!(
            "Functions source stamp: {expected_bytes} bytes in {median:?} ({bytes_per_second} bytes/s)"
        );
        assert!(
            bytes_per_second >= MIN_BYTES_PER_SECOND,
            "source scanning fell below the 16 MiB/s release gate: {bytes_per_second} bytes/s"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reload_snapshot_refuses_ignored_runtime_inputs_changed_during_capture() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-snapshot-ignored-race-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".env.local"), "LOCAL=old").unwrap();
        std::fs::write(root.join(".secret.local"), "SECRET=old").unwrap();
        let mut changed = false;
        let result = super::snapshot_functions_source_with_charge(
            &root,
            &["*.local".to_owned()],
            &mut |_, bytes| {
                if bytes > 0 && !changed {
                    // A buffer from one file has already been read. Replace both live
                    // inputs before the remaining capture work can observe them.
                    changed = true;
                    std::fs::write(root.join(".env.local"), "LOCAL=new").unwrap();
                    std::fs::write(root.join(".secret.local"), "SECRET=new").unwrap();
                }
                Ok(())
            },
            &std::sync::atomic::AtomicBool::new(false),
        );
        assert!(changed, "the mutation must occur within actual source I/O");
        assert!(
            result.is_err(),
            "a mixed runtime generation must not be published"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reload_snapshot_retains_runtime_files_excluded_from_change_detection() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-snapshot-ignored-runtime-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        for (name, value) in [
            ("index.js", "exports.value = 1;"),
            (".env.local", "FX_LOCAL=local"),
            (".secret.local", "FX_SECRET=secret"),
            ("data.json", "{}"),
            (".git/config", "not runtime data"),
        ] {
            std::fs::write(root.join(name), value).unwrap();
        }
        let ignores = vec![
            "node_modules".to_owned(),
            ".git".to_owned(),
            "*.local".to_owned(),
            "data.json".to_owned(),
        ];
        let before = functions_source_stamp(&root, &ignores)
            .unwrap()
            .content_signature;
        let snapshot = snapshot_functions_source(&root, &ignores).unwrap();
        for name in ["index.js", ".env.local", ".secret.local", "data.json"] {
            assert!(
                snapshot.join(name).is_file(),
                "runtime input {name} must survive reload"
            );
            assert_eq!(
                std::fs::read(snapshot.join(name)).unwrap(),
                std::fs::read(root.join(name)).unwrap()
            );
        }
        assert!(!snapshot.join(".git").exists());
        std::fs::write(root.join(".env.local"), "FX_LOCAL=changed").unwrap();
        assert_eq!(
            functions_source_stamp(&root, &ignores)
                .unwrap()
                .content_signature,
            before,
            "configured ignores still control change detection"
        );
        assert_eq!(
            std::fs::read_to_string(snapshot.join(".env.local")).unwrap(),
            "FX_LOCAL=local",
            "the snapshot remains one generation"
        );
        drop(snapshot);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reload_snapshot_keeps_one_exact_source_generation() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-snapshot-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        std::fs::write(root.join("lib/index.js"), "export const value = 'before';").unwrap();
        std::fs::write(root.join("node_modules/pkg/index.js"), "dependency").unwrap();
        let expected = functions_source_stamp(&root, &[])
            .unwrap()
            .content_signature;

        let snapshot = snapshot_functions_source(&root, &[]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&snapshot).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        assert_eq!(
            functions_source_stamp(&snapshot, &[])
                .unwrap()
                .content_signature,
            expected
        );
        std::fs::write(root.join("lib/index.js"), "export const value = 'after';").unwrap();
        assert_eq!(
            functions_source_stamp(&snapshot, &[])
                .unwrap()
                .content_signature,
            expected
        );
        assert_ne!(
            functions_source_stamp(&root, &[])
                .unwrap()
                .content_signature,
            expected
        );

        let snapshot_path = snapshot.to_path_buf();
        drop(snapshot);
        assert!(!snapshot_path.exists());
        assert!(root.join("node_modules/pkg/index.js").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reload_snapshot_resolves_local_and_hoisted_dependencies() {
        let workspace = std::env::temp_dir().join(format!(
            "fireemu-functions-hoisted-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&workspace);
        let source = workspace.join("functions");
        std::fs::create_dir_all(source.join("node_modules/local-pkg")).unwrap();
        std::fs::create_dir_all(workspace.join("node_modules/hoisted-pkg")).unwrap();
        std::fs::write(source.join("index.js"), "module.exports = 1;").unwrap();
        std::fs::write(
            source.join("node_modules/local-pkg/index.js"),
            "module.exports = 'local';",
        )
        .unwrap();
        std::fs::write(
            workspace.join("node_modules/hoisted-pkg/index.js"),
            "module.exports = 'hoisted';",
        )
        .unwrap();

        let snapshot = snapshot_functions_source(&source, &[]).unwrap();
        let script = "const {createRequire} = require('node:module'); const path = require('node:path'); const fromSource = createRequire(path.join(process.argv[1], 'index.js')); console.log(fromSource('local-pkg') + ':' + fromSource('hoisted-pkg'));";
        let output = std::process::Command::new("node")
            .args(["-e", script])
            .arg(snapshot.as_ref())
            .output()
            .expect("Node is required to verify Functions module resolution");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "local:hoisted"
        );

        let snapshot_path = snapshot.to_path_buf();
        drop(snapshot);
        assert!(!snapshot_path.exists());
        assert!(source.join("node_modules/local-pkg/index.js").is_file());
        assert!(workspace
            .join("node_modules/hoisted-pkg/index.js")
            .is_file());
        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reload_snapshot_rejects_source_symlinks_instead_of_silently_omitting_them() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "fireemu-functions-snapshot-symlink-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        std::fs::write(root.join("lib/index.js"), "export const value = 1;").unwrap();
        symlink("index.js", root.join("lib/alias.js")).unwrap();

        let error = snapshot_functions_source(&root, &[]).unwrap_err();
        assert!(error.contains("symbolic link"), "unexpected error: {error}");
        assert!(error.contains("lib/alias.js"), "unexpected error: {error}");

        std::fs::remove_dir_all(root).unwrap();
    }

    /// One callable with the given `consumeAppCheckToken` spelling, or none at all when
    /// `consume` is `None` (an older manifest that does not mention the field).
    fn manifest(consume: Option<&str>) -> fireemu_core_functions::manifest::FunctionManifest {
        let mut trigger = json!({"type": "http", "callable": true, "enforceAppCheck": true});
        if let Some(consume) = consume {
            trigger["consumeAppCheckToken"] = json!(consume);
        }
        parse_manifest(&json!({"functions": [{"name": "guarded", "trigger": trigger}]}))
            .expect("the fixture manifest parses")
    }

    fn report(instrumentation: &str, debug_features: &str) -> serde_json::Value {
        report_with(
            instrumentation,
            debug_features,
            &["x-callable-context-auth", "x-original-auth"],
        )
    }

    fn report_with(
        instrumentation: &str,
        debug_features: &str,
        auth_headers: &[&str],
    ) -> serde_json::Value {
        json!({
            "firebaseFunctionsVersion": "7.3.2",
            "instrumentation": instrumentation,
            "debugFeatures": debug_features,
            "debugMode": true,
            "authHeaders": auth_headers,
        })
    }

    #[test]
    fn pubsub_resources_cover_shared_topics_and_schedules_once() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "workerOne", "trigger": {"type": "pubsub", "topic": "shared-jobs"}},
            {"name": "workerTwo", "trigger": {"type": "pubsub", "topic": "shared-jobs"}, "region": "europe-west1"},
            {"name": "dailyReport", "trigger": {"type": "schedule", "schedule": "0 0 * * *"}},
            {"name": "health", "trigger": {"type": "http"}}
        ]})).unwrap();

        let resources = function_pubsub_resources("demo-app", &manifest).unwrap();
        let actual: Vec<(String, String)> = resources
            .iter()
            .map(|resource| (resource.topic.to_full(), resource.subscription.to_full()))
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    "projects/demo-app/topics/firebase-schedule-dailyReport".to_owned(),
                    "projects/demo-app/subscriptions/emulator-sub-firebase-schedule-dailyReport"
                        .to_owned(),
                ),
                (
                    "projects/demo-app/topics/shared-jobs".to_owned(),
                    "projects/demo-app/subscriptions/emulator-sub-shared-jobs".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn pubsub_bridge_accepts_only_the_runtime_projects_full_topic_resource() {
        assert_eq!(
            owned_pubsub_topic("demo-app", "projects/demo-app/topics/jobs")
                .map(|topic| topic.to_full()),
            Some("projects/demo-app/topics/jobs".to_owned())
        );
        assert!(owned_pubsub_topic("demo-app", "projects/other-project/topics/jobs").is_none());
        assert!(owned_pubsub_topic("demo-app", "jobs").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pubsub_bridge_capacity_refusal_keeps_the_broker_batch_invisible() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_adapter_pubsub::PubSubHandle;
        use fireemu_core_pubsub::{PubsubMessage, SubscriptionConfig};
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::LogicalInstant;
        use std::time::Duration;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let spawn = SpawnSpec {
            command: vec!["python3".to_owned(), script.display().to_string()],
            cwd: None,
            env: Vec::new(),
            hello_timeout: Duration::from_secs(60),
        };
        let runner = Runner::spawn_spec(&spawn).await.unwrap();
        let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let clock = Arc::new(Mutex::new(VirtualClock::new(now)));
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 4,
                debug_mode: false,
                retry_attempts: 4,
                max_catch_up_runs: 1000,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
            },
            clock.clone(),
            Arc::new(runner),
            Some(spawn),
        );
        let topic = TopicName::new("demo-app", "jobs").unwrap();
        let subscription = SubscriptionName::new("demo-app", "jobs-sub").unwrap();
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        {
            let mut state = state.lock().unwrap();
            state.create_topic(topic.clone(), BTreeMap::new()).unwrap();
            state
                .create_subscription(SubscriptionConfig {
                    name: subscription.clone(),
                    topic: topic.clone(),
                    ack_deadline_seconds: 10,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: None,
                    retry_policy: None,
                    push_config: PushConfig::default(),
                })
                .unwrap();
        }
        let bridge = Arc::new(PubSubBridge::new(runtime.clone()));
        let handle = PubSubHandle::new(state.clone(), clock, Some(bridge));
        let mut reservations = Vec::new();
        for index in 0..fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_RECORDS {
            reservations.push(
                runtime
                    .reserve_pubsub_events(
                        "jobs",
                        &[json!({
                            "messageId": format!("held-{index}"),
                            "data": "aA=="
                        })],
                    )
                    .unwrap(),
            );
        }

        let error = handle
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: b"must stay hidden".to_vec(),
                    ..PubsubMessage::default()
                }],
            )
            .unwrap_err();
        assert_eq!(error.code(), fireemu_core_pubsub::Code::ResourceExhausted);
        assert!(state
            .lock()
            .unwrap()
            .pull(&subscription, 10, now)
            .unwrap()
            .is_empty());

        drop(reservations);
        runtime.runner().shutdown().await;
    }

    #[allow(clippy::too_many_lines)] // Keep the real capacity-recovery lifecycle in one scenario.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pubsub_dead_letter_retry_is_woken_by_functions_capacity_recovery() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle};
        use fireemu_core_pubsub::subscription::{DeadLetterPolicy, MIN_DEAD_LETTER_ATTEMPTS};
        use fireemu_core_pubsub::{PubsubMessage, SubscriptionConfig};
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::LogicalInstant;
        use std::time::Duration;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let spawn = SpawnSpec {
            command: vec!["python3".to_owned(), script.display().to_string()],
            cwd: None,
            env: Vec::new(),
            hello_timeout: Duration::from_secs(60),
        };
        let runner = Runner::spawn_spec(&spawn).await.unwrap();
        let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let clock = Arc::new(Mutex::new(VirtualClock::new(now)));
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 4,
                debug_mode: false,
                retry_attempts: 4,
                max_catch_up_runs: 1000,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
            },
            clock.clone(),
            Arc::new(runner),
            Some(spawn),
        );
        let source_topic = TopicName::new("demo-app", "source").unwrap();
        let destination_topic = TopicName::new("demo-app", "jobs").unwrap();
        let source_subscription = SubscriptionName::new("demo-app", "source-sub").unwrap();
        let destination_subscription =
            SubscriptionName::new("demo-app", "destination-sub").unwrap();
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        {
            let mut state = state.lock().unwrap();
            state
                .create_topic(source_topic.clone(), BTreeMap::new())
                .unwrap();
            state
                .create_topic(destination_topic.clone(), BTreeMap::new())
                .unwrap();
            state
                .create_subscription(SubscriptionConfig {
                    name: source_subscription.clone(),
                    topic: source_topic.clone(),
                    ack_deadline_seconds: 10,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: Some(DeadLetterPolicy {
                        dead_letter_topic: destination_topic.clone(),
                        max_delivery_attempts: MIN_DEAD_LETTER_ATTEMPTS,
                    }),
                    retry_policy: None,
                    push_config: PushConfig::default(),
                })
                .unwrap();
            state
                .create_subscription(SubscriptionConfig {
                    name: destination_subscription.clone(),
                    topic: destination_topic.clone(),
                    ack_deadline_seconds: 10,
                    enable_message_ordering: false,
                    filter: Filter::always(),
                    dead_letter_policy: None,
                    retry_policy: None,
                    push_config: PushConfig::default(),
                })
                .unwrap();
        }
        let bridge = Arc::new(PubSubBridge::new(runtime.clone()));
        let handle = PubSubHandle::new(state.clone(), clock, Some(bridge));
        let mut reservations = Vec::new();
        for index in 0..fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_RECORDS {
            reservations.push(
                runtime
                    .reserve_pubsub_events(
                        "jobs",
                        &[json!({
                            "messageId": format!("held-{index}"),
                            "data": "aA=="
                        })],
                    )
                    .unwrap(),
            );
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            let _ = serve_pubsub(listener, server_handle).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        handle
            .publish(
                &source_topic,
                vec![PubsubMessage {
                    data: b"retry after capacity".to_vec(),
                    ..PubsubMessage::default()
                }],
            )
            .unwrap();
        for _ in 0..MIN_DEAD_LETTER_ATTEMPTS {
            let received = handle.pull(&source_subscription, 1).unwrap();
            assert_eq!(received.len(), 1);
            state
                .lock()
                .unwrap()
                .modify_ack_deadline(
                    &source_subscription,
                    std::slice::from_ref(&received[0].ack_id),
                    0,
                    now,
                )
                .unwrap();
        }
        assert!(handle.pull(&source_subscription, 1).unwrap().is_empty());
        assert_eq!(state.lock().unwrap().pending_dead_letters().len(), 1);
        assert!(handle
            .pull(&destination_subscription, 1)
            .unwrap()
            .is_empty());

        drop(reservations);
        let forwarded = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let received = handle.pull(&destination_subscription, 1).unwrap();
                if !received.is_empty() {
                    break received;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Functions capacity recovery must wake the DLQ retry driver");
        assert_eq!(forwarded[0].message.message.data, b"retry after capacity");
        assert!(state.lock().unwrap().pending_dead_letters().is_empty());

        handle.shutdown_push_dispatcher().await;
        server.abort();
        let _ = server.await;
        runtime.shutdown().await;
    }

    #[test]
    fn provisioning_function_pubsub_resources_is_idempotent_and_checks_existing_links() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "worker", "trigger": {"type": "pubsub", "topic": "shared-jobs"}}
        ]}))
        .unwrap();
        let resources = function_pubsub_resources("demo-app", &manifest).unwrap();
        let mut state = PubSubState::new(7);

        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        assert_eq!(state.list_topics("demo-app").len(), 1);
        assert_eq!(state.list_subscriptions("demo-app").len(), 1);

        let mut conflicting = PubSubState::new(8);
        let expected_topic = TopicName::new("demo-app", "shared-jobs").unwrap();
        let other_topic = TopicName::new("demo-app", "other-jobs").unwrap();
        conflicting
            .create_topic(expected_topic, BTreeMap::new())
            .unwrap();
        conflicting
            .create_topic(other_topic.clone(), BTreeMap::new())
            .unwrap();
        conflicting
            .create_subscription(SubscriptionConfig {
                name: SubscriptionName::new("demo-app", "emulator-sub-shared-jobs").unwrap(),
                topic: other_topic,
                ack_deadline_seconds:
                    fireemu_core_pubsub::subscription::DEFAULT_ACK_DEADLINE_SECONDS,
                enable_message_ordering: false,
                filter: Filter::always(),
                dead_letter_policy: None,
                retry_policy: None,
                push_config: PushConfig::default(),
            })
            .unwrap();

        let error = provision_function_pubsub_resources(&mut conflicting, &resources).unwrap_err();
        assert!(error.contains("emulator-sub-shared-jobs"), "{error}");
        assert!(error.contains("other-jobs"), "{error}");
        assert_eq!(conflicting.list_topics("demo-app").len(), 2);
        assert_eq!(conflicting.list_subscriptions("demo-app").len(), 1);
    }

    /// Functions scenario 6: `consumeAppCheckToken: true` fails discovery outright, whether or
    /// not App Check is enabled -- replay protection is unimplemented, and the callable would
    /// otherwise run with `alreadyConsumed: false`.
    #[test]
    fn consume_app_check_token_fails_function_discovery_while_replay_support_is_unavailable() {
        for trusted in [true, false] {
            let e = check_callable_app_check(
                &manifest(Some("enabled")),
                Some(&report("ok", "verified")),
                trusted,
            )
            .expect_err("a callable that consumes tokens cannot be served");
            assert!(e.contains("APP_CHECK_REPLAY_UNSUPPORTED"), "{e}");
            assert!(e.contains("guarded"), "{e}");
        }
    }

    /// An undeterminable value is never guessed as `false`: it fails startup, but only when
    /// App Check is actually enabled for callables.
    #[test]
    fn an_undeterminable_consume_app_check_token_fails_only_with_app_check_enabled() {
        for absent in [None, Some("undetermined")] {
            let e =
                check_callable_app_check(&manifest(absent), Some(&report("ok", "verified")), true)
                    .expect_err("an unobserved option fails closed");
            assert!(e.contains("could not be determined"), "{e}");
            check_callable_app_check(&manifest(absent), None, false)
                .expect("without App Check the callable protocol is inactive");
        }
    }

    /// A configured manifest cannot weaken what the runner observed: writing a token-consuming
    /// callable as disabled would run it without replay protection.
    #[test]
    fn a_manifest_cannot_override_the_app_check_options_the_runner_observed() {
        let e = super::check_manifest_agrees_on_callables(
            &manifest(Some("disabled")),
            &manifest(Some("enabled")),
        )
        .expect_err("the manifest disagrees with the code");
        assert!(e.contains("cannot override"), "{e}");
        super::check_manifest_agrees_on_callables(
            &manifest(Some("enabled")),
            &manifest(Some("enabled")),
        )
        .expect("agreeing manifests reconcile");
    }

    #[test]
    fn a_runner_that_could_not_instrument_the_sdk_fails_startup() {
        let e = check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report(
                "firebase-functions 9.0.0 is outside the supported range",
                "verified",
            )),
            true,
        )
        .expect_err("the callable options cannot be trusted");
        assert!(e.contains("outside the supported range"), "{e}");
    }

    /// The daemon turns `skipTokenVerification` on. If that flag does not mean what it is
    /// expected to mean, the runner would be decoding credentials under rules nobody checked.
    #[test]
    fn unexpected_debug_feature_semantics_fail_startup() {
        let e = check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report(
                "ok",
                "the installed firebase-functions reads skipTokenVerification differently",
            )),
            true,
        )
        .expect_err("the debug switch semantics are part of the trust boundary");
        assert!(e.contains("debug-feature semantics differ"), "{e}");
    }

    /// The proxy strips the auth-override fields by name. A supported minor release that
    /// renamed one would leave the daemon forwarding a channel that overrides v1 callable auth
    /// context, so the mismatch has to be fatal rather than silent (`INV-APPCHECK-010`).
    #[test]
    fn an_auth_override_header_the_proxy_does_not_strip_fails_startup() {
        for honoured in [
            vec!["x-callable-context-auth", "x-firebase-callable-auth"],
            vec!["x-callable-context-auth"],
            vec![],
        ] {
            let e = check_callable_app_check(
                &manifest(Some("disabled")),
                Some(&report_with("ok", "verified", &honoured)),
                true,
            );
            if honoured.iter().all(|h| {
                fireemu_adapter_functions::callable::ALWAYS_STRIPPED
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(h))
            }) {
                // A shorter list is not a mismatch: everything it names is stripped.
                e.expect("every honoured field is stripped");
            } else {
                let e = e.expect_err("an unstripped auth-override field is fatal");
                assert!(e.contains("auth-override header"), "{e}");
            }
        }
    }

    #[test]
    fn a_runner_that_does_not_report_its_auth_override_headers_fails_startup() {
        let mut report = report("ok", "verified");
        report
            .as_object_mut()
            .expect("an object")
            .remove("authHeaders");
        let e = check_callable_app_check(&manifest(Some("disabled")), Some(&report), true)
            .expect_err("no report is no evidence");
        assert!(e.contains("auth-override headers"), "{e}");
    }

    #[test]
    fn a_runner_without_an_app_check_report_fails_startup() {
        let e = check_callable_app_check(&manifest(Some("disabled")), None, true)
            .expect_err("no report is no evidence");
        assert!(e.contains("did not report"), "{e}");
    }

    /// A configured manifest replaces discovery outright, and the callable flag decides which
    /// side of the trust boundary a request lands on. A file that calls a real `onCall` an
    /// `onRequest` would have the proxy forward the raw credentials to a runner that decodes
    /// them without verifying.
    #[test]
    fn a_configured_manifest_that_hides_a_callable_fails_startup() {
        let discovered = manifest(Some("disabled"));
        let hidden = parse_manifest(&json!({
            "functions": [{"name": "guarded", "trigger": {"type": "http", "callable": false}}]
        }))
        .expect("the fixture manifest parses");
        let e = super::check_manifest_agrees_on_callables(&hidden, &discovered)
            .expect_err("a manifest may not reclassify a callable");
        assert!(e.contains("guarded"), "{e}");
        assert!(e.contains("disagrees with the code"), "{e}");

        let invented = parse_manifest(&json!({
            "functions": [{"name": "ghost", "trigger": {"type": "http", "callable": true}}]
        }))
        .expect("the fixture manifest parses");
        let e = super::check_manifest_agrees_on_callables(&invented, &discovered)
            .expect_err("a manifest may not invent an HTTP function");
        assert!(e.contains("does not export"), "{e}");

        super::check_manifest_agrees_on_callables(&discovered, &discovered)
            .expect("an agreeing manifest starts");
    }

    #[test]
    fn a_configured_manifest_cannot_bypass_or_reclassify_blocking_auth() {
        let discovered = parse_manifest(&json!({
            "functions": [
                {"name": "guardCreate", "region": "us-central1", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }},
                {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeSignIn"
                }}
            ]
        }))
        .unwrap();
        for (configured, expected) in [
            (
                json!({"functions": [{"name": "guardCreate", "region": "us-central1", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }}]}),
                "guardSignIn",
            ),
            (
                json!({"functions": [
                    {"name": "guardCreate", "region": "us-central1", "trigger": {
                        "type": "http", "callable": false
                    }},
                    {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeSignIn"
                    }}
                ]}),
                "guardCreate",
            ),
            (
                json!({"functions": [
                    {"name": "guardCreate", "region": "us-central1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeSignIn"
                    }},
                    {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeCreate"
                    }}
                ]}),
                "beforeCreate",
            ),
            (
                json!({"functions": [
                    {"name": "guardCreate", "region": "asia-northeast1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeCreate"
                    }},
                    {"name": "guardSignIn", "region": "europe-west1", "trigger": {
                        "type": "blockingAuth", "eventType": "beforeSignIn"
                    }}
                ]}),
                "us-central1",
            ),
        ] {
            let configured = parse_manifest(&configured).unwrap();
            let error = super::check_manifest_agrees_on_blocking_auth(&configured, &discovered)
                .expect_err("a custom manifest must preserve every discovered blocking hook");
            assert!(error.contains(expected), "{error}");
        }

        super::check_manifest_agrees_on_blocking_auth(&discovered, &discovered)
            .expect("an exact Blocking Auth contract starts");

        let duplicate_event = parse_manifest(&json!({
            "functions": [
                {"name": "firstCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }},
                {"name": "secondCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }}
            ]
        }))
        .unwrap();
        let reordered = parse_manifest(&json!({
            "functions": [
                {"name": "secondCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }},
                {"name": "firstCreateGuard", "trigger": {
                    "type": "blockingAuth", "eventType": "beforeCreate"
                }}
            ]
        }))
        .unwrap();
        let error = super::check_manifest_agrees_on_blocking_auth(&reordered, &duplicate_event)
            .expect_err("custom manifest ordering must not select a different first hook");
        assert!(error.contains("firstCreateGuard"), "{error}");
        assert!(error.contains("secondCreateGuard"), "{error}");
    }

    #[test]
    fn a_configured_manifest_cannot_widen_or_narrow_discovered_token_policy() {
        let manifest = |access_token: bool| {
            parse_manifest(&json!({"functions": [{
                "name": "guardSignIn",
                "trigger": {
                    "type": "blockingAuth",
                    "eventType": "beforeSignIn",
                    "accessToken": access_token
                }
            }]}))
            .unwrap()
        };
        for (configured, discovered, direction) in [
            (manifest(true), manifest(false), "widen"),
            (manifest(false), manifest(true), "narrow"),
        ] {
            let error = super::check_manifest_agrees_on_blocking_auth(&configured, &discovered)
                .unwrap_err();
            assert!(error.contains("token policy"), "{direction}: {error}");
        }
    }

    /// A manifest whose only ignored export is an unrecognised shape starts, with a line
    /// naming it -- the official emulator's carry-on. A product decision does not.
    #[test]
    fn a_product_decision_is_fatal_and_an_unrecognised_shape_is_a_line() {
        let manifest = parse_manifest(&json!({
            "functions": [{"name": "api", "trigger": {"type": "http", "callable": false}}],
            "ignored": [
                {"name": "onRef", "region": "europe-west1", "triggerType": "database",
                 "scope": "deferred", "reason": "deferred: no Realtime Database"},
                {"name": "weird", "region": "us-central1", "triggerType": "unknown",
                 "scope": "unsupported", "reason": "the endpoint declares no trigger"}
            ]
        }))
        .expect("the fixture manifest parses");

        let e = super::check_ignored(&manifest, super::UnservedTriggers::Refuse)
            .expect_err("a deferred product is fatal");
        assert!(e.contains("onRef (database)"), "{e}");
        assert!(!e.contains("weird"), "{e}");

        let lines = super::check_ignored(&manifest, super::UnservedTriggers::Report)
            .expect("reporting starts");
        assert_eq!(
            lines,
            vec![
                "functions[europe-west1-onRef]: function ignored (database): deferred: no \
                 Realtime Database"
                    .to_owned(),
                "functions[us-central1-weird]: function ignored (unknown): the endpoint \
                 declares no trigger"
                    .to_owned(),
            ]
        );
    }

    /// Nothing is dropped in either direction: an ignored export survives the manifest's
    /// round trip through JSON with its scope and its reason.
    #[test]
    fn the_ignored_inventory_round_trips_through_the_manifest_json() {
        let json = json!({
            "functions": [],
            "ignored": [{"name": "onRef", "region": "us-central1", "triggerType": "database",
                         "scope": "notPlanned", "reason": "not planned"}]
        });
        let manifest = parse_manifest(&json).expect("parses");
        assert_eq!(
            fireemu_adapter_functions::manifest_json::manifest_to_json(&manifest)["ignored"],
            json["ignored"]
        );
        let bad = parse_manifest(&json!({
            "functions": [],
            "ignored": [{"name": "onRef", "scope": "invented", "reason": "x"}]
        }))
        .expect_err("an unknown scope is refused rather than guessed");
        assert!(bad.contains("unknown scope"), "{bad}");
    }

    #[test]
    fn a_fully_reported_disabled_callable_starts() {
        check_callable_app_check(
            &manifest(Some("disabled")),
            Some(&report("ok", "verified")),
            true,
        )
        .expect("a callable that does not consume tokens is servable");
    }

    #[tokio::test]
    async fn codebase_start_tasks_run_concurrently_and_report_in_config_order() {
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let first_barrier = barrier.clone();
        let first = tokio::spawn(async move {
            first_barrier.wait().await;
            Ok::<_, String>("first")
        });
        let second = tokio::spawn(async move {
            barrier.wait().await;
            Err::<&str, _>("second failed".to_owned())
        });

        let outcomes = tokio::time::timeout(
            Duration::from_secs(1),
            super::join_codebase_starts(vec![
                ("first".to_owned(), first),
                ("second".to_owned(), second),
            ]),
        )
        .await
        .expect("both tasks reach the barrier because they run concurrently");

        assert_eq!(outcomes, vec![Ok("first"), Err("second failed".to_owned())]);
    }

    #[test]
    fn workspace_runner_is_found_from_the_executable_without_a_compiled_in_path() {
        let candidates = super::runner_candidates();
        let (_, path) = candidates
            .iter()
            .find(|(source, _)| *source == super::RunnerSource::WorkspaceSource)
            .expect("a test binary under target/ sees the workspace runner");
        assert!(path.is_file(), "{} is not a file", path.display());
        assert!(
            !path
                .components()
                .any(|c| c == std::path::Component::ParentDir),
            "the workspace candidate must be resolved at run time, not spelled from the build directory: {}",
            path.display()
        );
        let expected = std::fs::canonicalize(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/runner-node/index.mjs"),
        )
        .unwrap();
        assert_eq!(*path, expected);
    }

    /// Builds `<root>/Cargo.toml` and `<root>/tools/runner-node/index.mjs` under a fresh
    /// temporary directory and returns the root; the caller removes it.
    fn synthetic_workspace(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "fireemu-workspace-runner-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tools/runner-node")).unwrap();
        std::fs::write(root.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(root.join("tools/runner-node/index.mjs"), "").unwrap();
        root
    }

    #[test]
    fn workspace_runner_is_found_from_every_supported_target_layout() {
        let root = synthetic_workspace("layouts");
        let script = root.join("tools/runner-node/index.mjs");
        for layout in [
            "target/debug/fireemu",
            "target/release/fireemu",
            "target/x86_64-unknown-linux-gnu/debug/fireemu",
            // `scripts/cargo-session` puts the binary five directories below the root.
            "target/agent/runner-discovery/normal/debug/fireemu",
            "target/agent/runner-discovery/loom/release/fireemu",
        ] {
            assert_eq!(
                super::workspace_runner_from(&root.join(layout)).as_deref(),
                Some(script.as_path()),
                "layout {layout}"
            );
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn workspace_runner_walk_is_bounded_and_needs_both_markers() {
        let root = synthetic_workspace("bounded");
        let too_deep = (0..super::WORKSPACE_RUNNER_SEARCH_DEPTH)
            .fold(root.clone(), |dir, level| {
                dir.join(format!("level-{level}"))
            })
            .join("fireemu");
        assert_eq!(
            super::workspace_runner_from(&too_deep),
            None,
            "a root {} directories above the executable is out of reach",
            super::WORKSPACE_RUNNER_SEARCH_DEPTH + 1
        );
        let at_bound = too_deep.parent().unwrap().with_file_name("fireemu");
        assert_eq!(
            super::workspace_runner_from(&at_bound).as_deref(),
            Some(root.join("tools/runner-node/index.mjs").as_path()),
            "a root exactly {} directories above the executable is still found",
            super::WORKSPACE_RUNNER_SEARCH_DEPTH
        );
        // A crate directory with its own `Cargo.toml` but no runner is walked past.
        let crate_dir = root.join("crates/fireemu");
        std::fs::create_dir_all(&crate_dir).unwrap();
        std::fs::write(crate_dir.join("Cargo.toml"), "[package]\n").unwrap();
        assert_eq!(
            super::workspace_runner_from(&crate_dir.join("target/debug/fireemu")).as_deref(),
            Some(root.join("tools/runner-node/index.mjs").as_path()),
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
