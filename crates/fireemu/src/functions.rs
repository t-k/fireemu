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

use crate::config::{
    CompatibilityProfile, FunctionsCodebase, FunctionsIsolation, RuntimeConfig, RuntimeLanguage,
};

mod isolation;
mod runner_checks;

pub(crate) use runner_checks::{process_notice, retain_current_cursors};

/// One Pub/Sub topic and emulator subscription required by a loaded function manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPubSubResource {
    /// The canonical topic name.
    pub topic: fireemu_core_pubsub::TopicName,
    /// The canonical emulator subscription name. A first-generation schedule's topic under the strict profile has none:
    /// production creates a topic and no subscription for it.
    pub subscription: Option<fireemu_core_pubsub::SubscriptionName>,
}

/// How the strict and the emulator profile name the subscription of a Pub/Sub function: the strict
/// profile as production does (Eventarc's name, one per 2nd gen function), the emulator profile
/// as the official emulator does (`emulator-sub-<topic>`).
#[must_use]
pub fn subscription_naming(
    profile: CompatibilityProfile,
) -> fireemu_adapter_functions::events::SubscriptionNaming {
    use fireemu_adapter_functions::events::SubscriptionNaming;
    match profile {
        CompatibilityProfile::Strict => SubscriptionNaming::Eventarc,
        CompatibilityProfile::Emulator => SubscriptionNaming::EmulatorTopic,
    }
}

/// How the strict and the emulator profile name the writer of a Firestore event with auth context:
/// the strict profile as production does (`api_key` for an ID-token write, `unknown` for a service
/// credential), the emulator profile as the official emulator does (`unknown` and
/// `fake-auth-id@gmail.com` for every writer).
#[must_use]
pub fn auth_context_naming(
    profile: CompatibilityProfile,
) -> fireemu_adapter_functions::events::AuthContextNaming {
    use fireemu_adapter_functions::events::AuthContextNaming;
    match profile {
        CompatibilityProfile::Strict => AuthContextNaming::Production,
        CompatibilityProfile::Emulator => AuthContextNaming::Official,
    }
}

/// How the strict and the emulator profile shape a Realtime Database trigger event: the strict profile as
/// production delivered it (CV14, recorded 2026-10-27), the emulator profile as it always was.
#[must_use]
pub fn database_event_shape(
    profile: CompatibilityProfile,
) -> fireemu_adapter_functions::events::DatabaseEventShape {
    use fireemu_adapter_functions::events::DatabaseEventShape;
    match profile {
        CompatibilityProfile::Strict => DatabaseEventShape::Production,
        CompatibilityProfile::Emulator => DatabaseEventShape::Official,
    }
}

/// The buckets the Storage triggers of a manifest name explicitly. A trigger without a bucket
/// listens on the project's default buckets, which always exist. The strict profile counts these
/// buckets as existing even when empty: production needs the bucket to deploy the trigger.
#[must_use]
pub fn storage_trigger_buckets(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
) -> BTreeSet<String> {
    use fireemu_core_functions::manifest::Trigger;
    manifest
        .functions
        .iter()
        .filter_map(|function| match &function.trigger {
            Trigger::Storage {
                bucket: Some(bucket),
                ..
            } => Some(bucket.clone()),
            _ => None,
        })
        .collect()
}

/// Derives the unique Pub/Sub resources required by Pub/Sub and scheduled functions.
///
/// Under `SubscriptionNaming::Eventarc` every 2nd gen Pub/Sub function gets its own subscription, so two functions on one
/// topic give two resources; otherwise a topic gets one `emulator-sub-<topic>`.
///
/// The emulator profile follows the official emulator: every scheduled function has the topic
/// `firebase-schedule-<name>` and an emulator subscription. The strict profile follows production: only a
/// first-generation schedule has a topic, `firebase-schedule-<name>-<region>` (the id of its Cloud Scheduler job, runs
/// `156715222b86ea44` and `f123d4fa2d61c5f5`), and no subscription of the emulator's; a second-generation schedule has
/// none.
pub fn function_pubsub_resources(
    project: &str,
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    naming: fireemu_adapter_functions::events::SubscriptionNaming,
    profile: CompatibilityProfile,
) -> Result<Vec<FunctionPubSubResource>, String> {
    use fireemu_adapter_functions::events::function_subscription_id;
    use fireemu_core_functions::manifest::Trigger;

    // (topic, subscription id; `None` for the topic of a schedule that production creates without a subscription) -> the
    // smallest text of the functions that require it, for diagnostics.
    let mut wanted: BTreeMap<(String, Option<String>), String> = BTreeMap::new();
    let mut declare = |topic: String, subscription: Option<String>, owner: String| {
        let entry = wanted
            .entry((topic, subscription))
            .or_insert_with(|| owner.clone());
        if owner < *entry {
            *entry = owner;
        }
    };
    for function in &manifest.functions {
        match &function.trigger {
            Trigger::PubSub { topic } => {
                let subscription = function_subscription_id(naming, project, function, topic);
                declare(
                    topic.clone(),
                    Some(subscription),
                    format!("function {:?}", function.name),
                );
            }
            Trigger::Schedule { .. } if uses_production_scheduler_defaults(profile) => {
                if let Some(topic) = function.schedule_topic() {
                    declare(
                        topic,
                        None,
                        format!("scheduled function {:?}", function.name),
                    );
                }
            }
            Trigger::Schedule { .. } => {
                let topic = format!("firebase-schedule-{}", function.name);
                let subscription = format!("emulator-sub-{topic}");
                declare(
                    topic,
                    Some(subscription),
                    format!("scheduled function {:?}", function.name),
                );
            }
            _ => {}
        }
    }

    // A topic that some function subscribes to keeps its subscription; the subscriptionless declaration of the same topic
    // adds nothing. Resource names, not the diagnostics attached to them, define uniqueness.
    let subscribed: std::collections::BTreeSet<String> = wanted
        .keys()
        .filter(|(_, subscription)| subscription.is_some())
        .map(|(topic, _)| topic.clone())
        .collect();
    let mut resources = Vec::new();
    for ((topic_id, subscription_id), owner) in wanted {
        if subscription_id.is_none() && subscribed.contains(&topic_id) {
            continue;
        }
        let topic = fireemu_core_pubsub::TopicName::new(project, &topic_id).map_err(|error| {
            format!("{owner} requires invalid Pub/Sub topic {topic_id:?}: {error}")
        })?;
        let subscription = subscription_id
            .map(|subscription_id| {
                fireemu_core_pubsub::SubscriptionName::new(project, &subscription_id).map_err(
                    |error| {
                        format!(
                            "{owner} requires invalid Pub/Sub subscription {subscription_id:?}: {error}"
                        )
                    },
                )
            })
            .transpose()?;
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
        let Some(subscription) = &resource.subscription else {
            continue;
        };
        if let Ok(existing) = state.subscription_config(subscription) {
            if existing.topic != resource.topic {
                return Err(format!(
                    "Functions requires subscription {} to target {}, but it already targets {}",
                    subscription.to_full(),
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
        let Some(subscription) = &resource.subscription else {
            continue;
        };
        if state.subscription_config(subscription).is_err() {
            state
                .create_subscription(SubscriptionConfig {
                    labels: std::collections::BTreeMap::new(),
                    expiration_policy: None,
                    retain_acked_messages: false,
                    message_retention_duration: None,
                    name: subscription.clone(),
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
                        subscription.to_full()
                    )
                })?;
        }
        state
            .mark_function_subscription(subscription)
            .map_err(|error| {
                format!(
                    "could not provision subscription {}: {error}",
                    subscription.to_full()
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
    snapshot_functions_source_with_charge_at(
        root,
        ignores,
        charge,
        cancelled,
        &std::env::temp_dir(),
    )
}

fn snapshot_functions_source_with_charge_at(
    root: &Path,
    ignores: &[String],
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
    snapshot_root: &Path,
) -> Result<FunctionsSourceSnapshot, String> {
    snapshot_functions_source_with_charge_at_and_acl_check(
        root,
        ignores,
        charge,
        cancelled,
        snapshot_root,
        secure_snapshot_directory,
    )
}

#[allow(clippy::too_many_lines)] // Keep atomic Windows DACL creation with snapshot setup.
fn snapshot_functions_source_with_charge_at_and_acl_check<F>(
    root: &Path,
    ignores: &[String],
    charge: &mut dyn FnMut(u64, u64) -> Result<(), String>,
    cancelled: &AtomicBool,
    snapshot_root: &Path,
    acl_check: F,
) -> Result<FunctionsSourceSnapshot, String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
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
    let destination = snapshot_root.join(name);
    #[cfg(unix)]
    std::fs::create_dir(&destination)
        .map_err(|e| format!("snapshot {}: {e}", destination.display()))?;
    #[cfg(windows)]
    run_snapshot_acl_checker(
        &destination,
        &windows_powershell_path()?,
        // A later DACL check cannot revoke an attacker's already-open WRITE_DAC handle.
        // Protect the root at creation and let only trusted ACEs propagate to its children.
        r#"
$ErrorActionPreference = 'Stop'
$descriptor = [IntPtr]::Zero
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FireemuSnapshotDirectoryNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr descriptor, IntPtr size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES attributes);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LocalFree(IntPtr memory);
}
'@ -ErrorAction Stop
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = "D:P(A;OICI;FA;;;$userSid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if (-not [FireemuSnapshotDirectoryNative]::ConvertStringSecurityDescriptorToSecurityDescriptorW(
        $sddl, 1, [ref]$descriptor, [IntPtr]::Zero)) {
        throw 'could not construct snapshot DACL'
    }
    $attributes = New-Object FireemuSnapshotDirectoryNative+SECURITY_ATTRIBUTES
    $attributes.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($attributes)
    $attributes.lpSecurityDescriptor = $descriptor
    $attributes.bInheritHandle = 0
    if (-not [FireemuSnapshotDirectoryNative]::CreateDirectoryW(
        $env:FIREEMU_SNAPSHOT_ACL_PATH, [ref]$attributes)) {
        throw 'could not create protected snapshot directory'
    }
} catch { exit 1 } finally {
    if ($descriptor -ne [IntPtr]::Zero) {
        [void][FireemuSnapshotDirectoryNative]::LocalFree($descriptor)
    }
}
exit 0
"#,
        // Add-Type compiles the interop class, which takes seconds on a loaded runner.
        Duration::from_secs(30),
    )?;
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
    acl_check(&destination)?;
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
const WINDOWS_SNAPSHOT_ACL_CHECK: &str = r#"
$ErrorActionPreference = 'Stop'
$native = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class FireemuSnapshotAclNative {
    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfo {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle handle, int informationClass, out FileAttributeTagInfo info, uint size);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint GetSecurityInfo(
        SafeFileHandle handle, int objectType, uint securityInfo,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);

    [DllImport("kernel32.dll", SetLastError = false)]
    private static extern IntPtr LocalFree(IntPtr memory);

    public static SafeFileHandle OpenDirectory(string path) {
        const uint readControl = 0x00020000;
        const uint readAttributes = 0x00000080;
        const uint shareRead = 0x00000001;
        const uint openExisting = 3;
        const uint backupSemantics = 0x02000000;
        const uint openReparsePoint = 0x00200000;
        var handle = CreateFile(path, readControl | readAttributes, shareRead, IntPtr.Zero,
            openExisting, backupSemantics | openReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error);
        }
        return handle;
    }

    public static uint ReadAttributes(SafeFileHandle handle) {
        FileAttributeTagInfo info;
        if (!GetFileInformationByHandleEx(handle, 9, out info,
            (uint)Marshal.SizeOf(typeof(FileAttributeTagInfo))))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return info.FileAttributes;
    }

    public static byte[] ReadOwnerAndDacl(SafeFileHandle handle) {
        IntPtr owner, group, dacl, sacl, descriptor;
        uint result = GetSecurityInfo(handle, 1, 0x00000005,
            out owner, out group, out dacl, out sacl, out descriptor);
        if (result != 0) throw new Win32Exception((int)result);
        try {
            if (descriptor == IntPtr.Zero) throw new InvalidOperationException("missing security descriptor");
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > int.MaxValue)
                throw new InvalidOperationException("invalid security descriptor length");
            byte[] bytes = new byte[checked((int)length)];
            Marshal.Copy(descriptor, bytes, 0, bytes.Length);
            return bytes;
        } finally {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }
}
'@
$handles = New-Object 'System.Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]'
$exitCode = 0
try {
    Add-Type -TypeDefinition $native -ErrorAction Stop
    $path = [Environment]::GetEnvironmentVariable('FIREEMU_SNAPSHOT_ACL_PATH')
    if ([string]::IsNullOrEmpty($path)) { throw 'snapshot path is missing' }
    $userSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $trusted = @($userSid, 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $dangerous = [int64]([System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
    $directories = New-Object 'System.Collections.Generic.List[System.IO.DirectoryInfo]'
    $directory = [System.IO.DirectoryInfo]::new($path)
    while ($null -ne $directory) {
        $directories.Add($directory)
        $directory = $directory.Parent
    }
    for ($index = $directories.Count - 1; $index -ge 0; $index--) {
        $directory = $directories[$index]
        $handle = [FireemuSnapshotAclNative]::OpenDirectory($directory.FullName)
        $handles.Add($handle)
        $descriptor = [FireemuSnapshotAclNative]::ReadOwnerAndDacl($handle)
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorBinaryForm($descriptor)
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($descriptor, 0)
        if ($null -eq $raw.DiscretionaryAcl) { throw 'null DACL' }
        $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -notin $trusted) { throw 'untrusted owner' }
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            $sid = $rule.IdentityReference.Value
            $inheritOnly = ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
            if ($index -lt 2) {
                if ($sid -notin $trusted -and -not ($sid -eq 'S-1-3-0' -and $inheritOnly)) { throw 'untrusted allow ACE' }
            } elseif (-not $inheritOnly -and $sid -notin $trusted -and
                (([int64]$rule.FileSystemRights -band $dangerous) -ne 0)) {
                throw 'untrusted ancestor mutation ACE'
            }
        }
        $attributes = [FireemuSnapshotAclNative]::ReadAttributes($handle)
        if (($attributes -band [uint32][System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            ($attributes -band [uint32][System.IO.FileAttributes]::Directory) -eq 0) { throw 'reparse or non-directory component' }
    }
} catch {
    $exitCode = 1
} finally {
    foreach ($handle in $handles) { $handle.Dispose() }
}
exit $exitCode
"#;

#[cfg(windows)]
fn secure_snapshot_directory(path: &Path) -> Result<(), String> {
    let powershell = windows_powershell_path()?;
    run_snapshot_acl_checker(
        path,
        &powershell,
        WINDOWS_SNAPSHOT_ACL_CHECK,
        Duration::from_secs(5),
    )
}

#[cfg(windows)]
fn windows_powershell_path() -> Result<PathBuf, String> {
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|root| root.is_absolute())
        .ok_or_else(|| "snapshot ACL validation could not locate Windows PowerShell".to_owned())?;
    Ok(system_root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
}

#[cfg(windows)]
fn run_snapshot_acl_checker(
    path: &Path,
    program: &Path,
    script: &str,
    timeout: Duration,
) -> Result<(), String> {
    use process_wrap::tokio::{JobObject, KillOnDrop, TokioCommandWrap};
    use std::process::Stdio;

    if !path.is_absolute() {
        return Err("snapshot ACL validation refused a non-absolute directory".to_owned());
    }
    let path = path.to_owned();
    let program = program.to_owned();
    let script = script.to_owned();
    std::thread::Builder::new()
        .name("fireemu-snapshot-acl".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| {
                    "snapshot ACL validation could not initialize its runtime".to_owned()
                })?;
            runtime.block_on(async move {
                let mut command = tokio::process::Command::new(program);
                command
                    .args([
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        script.as_str(),
                    ])
                    .env("FIREEMU_SNAPSHOT_ACL_PATH", &path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                let mut wrapped = TokioCommandWrap::from(command);
                wrapped.wrap(JobObject).wrap(KillOnDrop);
                let mut child = wrapped.spawn().map_err(|_| {
                    "snapshot ACL validation could not start Windows PowerShell".to_owned()
                })?;
                let status = tokio::time::timeout(timeout, Box::into_pin(child.wait())).await;
                match status {
                    Ok(Ok(status)) if status.success() => Ok(()),
                    Ok(Ok(_)) => Err(format!(
                        "snapshot ACL validation refused directory {}",
                        path.display()
                    )),
                    Ok(Err(_)) | Err(_) => {
                        let _ = child.start_kill();
                        let _ = tokio::time::timeout(timeout, Box::into_pin(child.wait())).await;
                        Err(format!(
                            "snapshot ACL validation timed out or failed for {}",
                            path.display()
                        ))
                    }
                }
            })
        })
        .map_err(|_| "snapshot ACL validation could not start its worker".to_owned())?
        .join()
        .map_err(|_| "snapshot ACL validation worker failed".to_owned())?
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

/// The inspector flags a runner command gets, and whether the request for them is ignored.
struct InspectorArguments {
    /// Inserted after the program, in order.
    arguments: Vec<String>,
    /// `--inspect-functions` was asked for and the runner cannot honour it (a Python codebase).
    ignored: bool,
}

/// What `--inspect-functions` does to a runner command: a Node runner gets the flags (dynamic port
/// first), a Python one gets none and the request is reported as ignored, as firebase-tools does.
fn inspector_arguments(python: bool, dynamic: bool, port: Option<u16>) -> InspectorArguments {
    if !(dynamic || port.is_some()) {
        return InspectorArguments {
            arguments: Vec::new(),
            ignored: false,
        };
    }
    if python {
        return InspectorArguments {
            arguments: Vec::new(),
            ignored: true,
        };
    }
    let address = if dynamic {
        "--inspect=127.0.0.1:0".to_owned()
    } else {
        format!("--inspect=127.0.0.1:{}", port.unwrap_or_default())
    };
    InspectorArguments {
        arguments: vec![address, "--inspect-publish-uid=http".to_owned()],
        ignored: false,
    }
}

/// Whether the daemon offers a runner the Admin SDK App Check channel: it exists for the Node
/// runner's instrumentation of `firebase-admin` and only when App Check answers it.
fn admin_app_check_offered(answers: bool, python: bool) -> bool {
    answers && !python
}

/// Splits the codebases into those whose source changes are reloaded and those that are not.
fn split_reload(
    codebases: Vec<FunctionsCodebase>,
) -> (Vec<FunctionsCodebase>, Vec<FunctionsCodebase>) {
    codebases.into_iter().partition(reload_supervised)
}

/// Whether source changes of the codebase are watched and reloaded. The reload snapshot links
/// `node_modules` only, so it would lack the interpreter of a Python codebase's `venv`: Python reload
/// is a later slice.
fn reload_supervised(codebase: &FunctionsCodebase) -> bool {
    crate::python_functions::codebase_language(codebase) != RuntimeLanguage::Python
}

fn start_reload_supervisors(
    runtime: &Arc<FunctionsRuntime>,
    cfg: &RuntimeConfig,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
    node_probe_cache: &Arc<NodeProbeCache>,
    mut initial_stamps: BTreeMap<String, Result<FunctionsSourceStamp, String>>,
) {
    let resources = ReloadResources {
        scan_budget: Arc::new(FunctionsSourceScanBudget::new()),
        node_probe_cache: node_probe_cache.clone(),
    };
    let (supervised, unsupervised) = split_reload(cfg.functions_to_load());
    for codebase in unsupervised {
        eprintln!(
            "note: functions[{}]: source changes are not reloaded for Python codebases; restart fireemu to pick them up",
            codebase.codebase
        );
    }
    for codebase in supervised {
        let initial_stamp = initial_stamps
            .remove(&codebase.codebase)
            .expect("supervised startup baseline");
        tokio::spawn(supervise_codebase_reloads(
            Arc::downgrade(runtime),
            cfg.clone(),
            codebase,
            hosts.clone(),
            runner_secret.to_owned(),
            callable_trusted_protocol,
            resources.clone(),
            initial_stamp,
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

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn supervise_codebase_reloads(
    weak_runtime: std::sync::Weak<FunctionsRuntime>,
    cfg: RuntimeConfig,
    codebase: FunctionsCodebase,
    hosts: EmulatorHosts,
    secret: String,
    callable_trusted_protocol: bool,
    resources: ReloadResources,
    initial_stamp: Result<FunctionsSourceStamp, String>,
) {
    let root = PathBuf::from(&codebase.source);
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
        match start_codebase_units(
            &cfg,
            &staged,
            &hosts,
            &secret,
            callable_trusted_protocol,
            &resources.node_probe_cache,
            runtime.clock_snapshot(),
        )
        .await
        {
            Ok(mut specs) => {
                let snapshot_path = snapshot.into_path();
                for spec in &mut specs {
                    spec.cleanup_dir = Some(snapshot_path.clone());
                }
                report_reload_install(
                    runtime.reload_codebase_units(specs),
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

/// Debug features selected per profile and callable trust policy.
///
/// `firebase-functions` reads `FIREBASE_DEBUG_MODE` once when it is first required and
/// re-reads `FIREBASE_DEBUG_FEATURES` per lookup. `skipTokenVerification` makes the callable
/// wrapper decode the App Check and Auth credentials locally instead of calling out to Google,
/// which is only safe because the daemon has already verified and re-inserted both
/// (specification section 13.4). The official emulator also enables `enableCors`, which
/// wraps default `onRequest` handlers while preserving an explicit `cors: false`.
const DEBUG_FEATURES_TRUSTED_STRICT: &str = r#"{"skipTokenVerification":true}"#;
const DEBUG_FEATURES_UNTRUSTED_EMULATOR: &str = r#"{"enableCors":true}"#;
const DEBUG_FEATURES_TRUSTED_EMULATOR: &str = r#"{"skipTokenVerification":true,"enableCors":true}"#;

fn runner_debug_features(
    profile: CompatibilityProfile,
    callable_trusted_protocol: bool,
) -> Option<&'static str> {
    match (profile, callable_trusted_protocol) {
        (CompatibilityProfile::Emulator, true) => Some(DEBUG_FEATURES_TRUSTED_EMULATOR),
        (CompatibilityProfile::Emulator, false) => Some(DEBUG_FEATURES_UNTRUSTED_EMULATOR),
        (CompatibilityProfile::Strict, true) => Some(DEBUG_FEATURES_TRUSTED_STRICT),
        (CompatibilityProfile::Strict, false) => None,
    }
}

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

/// Refuses a codebase that declares a parameter nothing gives a value to.
///
/// `firebase deploy` resolves every `defineString`/`defineInt`/... parameter before it deploys:
/// the dotenv chain first, then the declared default, and a non-interactive deploy stops at a
/// parameter that has neither. The runner has already applied the defaults, so what `report`
/// lists as `missing` is exactly what a deploy would stop at.
pub fn check_declared_params(
    report: Option<&serde_json::Value>,
    codebase: &str,
    source: &str,
    project: &str,
    alias: Option<&str>,
) -> Result<(), String> {
    let missing: Vec<String> = report
        .and_then(|r| r.get("missing"))
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let kind = entry
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("string");
            Some(format!("{name} ({kind})"))
        })
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    let project_file = alias.map_or_else(
        || format!(".env.{project}"),
        |alias| format!(".env.{project} or .env.{alias}"),
    );
    Err(format!(
        "the Functions codebase {codebase:?} declares {} parameter(s) with no value and no \
         default: {}. A deploy would stop for each of them. Set a value in {source}/.env, \
         {source}/{project_file} or {source}/.env.local (emulator only), or declare a default, \
         for example defineString(\"NAME\", {{ default: \"value\" }})",
        missing.len(),
        missing.join(", ")
    ))
}

/// The `firebase-functions` majors the callable App Check instrumentation is written for
/// (`tools/runner-node/callable-app-check.mjs`).
const CALLABLE_TRUST_MAJORS: [u64; 2] = [6, 7];

/// Whether the callable trust boundary may be switched on by default for the codebase at
/// `source`: it needs an installed `firebase-functions` whose major version the runner's callable
/// instrumentation supports. Older and newer majors keep working without it (a callable then
/// follows the SDK's own App Check check, as before); only an App Check the configuration asks
/// for refuses to start on them.
///
/// The version is read the way Node resolves the package: `node_modules/firebase-functions` of
/// the source directory or of the nearest ancestor that has one.
pub fn callable_trust_supported(source: &Path) -> Result<(), String> {
    let manifest = source
        .ancestors()
        .map(|dir| dir.join("node_modules/firebase-functions/package.json"))
        .find(|path| path.is_file())
        .ok_or_else(|| "firebase-functions is not installed in the codebase".to_owned())?;
    let version = std::fs::read_to_string(&manifest)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|package| package.get("version")?.as_str().map(str::to_owned))
        .ok_or_else(|| format!("cannot read the version in {}", manifest.display()))?;
    let major = version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u64>().ok());
    if major.is_some_and(|major| CALLABLE_TRUST_MAJORS.contains(&major)) {
        Ok(())
    } else {
        Err(format!(
            "firebase-functions {version} is outside the supported range (6.x and 7.x)"
        ))
    }
}

/// Whether the callable trust boundary may be switched on for `codebase`: the Node SDK
/// instrumentation must be readable ([`callable_trust_supported`]). The Python SDK has no switch for
/// the SDK's own token checks, so a Python codebase never supports it (yet).
///
/// # Errors
///
/// Why it is not available.
pub fn codebase_callable_trust(codebase: &FunctionsCodebase) -> Result<(), String> {
    if crate::python_functions::codebase_language(codebase) == RuntimeLanguage::Python {
        return Err("Python codebases are not supported by it yet".to_owned());
    }
    callable_trust_supported(Path::new(&codebase.source))
}

/// One `functions[...]` warning per secret a function declares that `.secret.local` has no value
/// for. `firebase deploy` checks that a declared secret exists in Secret Manager; here the SDK
/// only logs "No value found for secret parameter" at the first read and answers the empty
/// string, which can hide a missing secret behind a request that happens to work.
#[must_use]
pub fn missing_secret_warnings(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    local_secrets: &[(String, String)],
    codebase: &str,
) -> Vec<String> {
    let mut missing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for function in &manifest.functions {
        for secret in &function.platform_options.secrets {
            if !local_secrets.iter().any(|(name, _)| name == secret) {
                missing.entry(secret).or_default().push(&function.name);
            }
        }
    }
    missing
        .into_iter()
        .map(|(secret, functions)| {
            format!(
                "functions[{codebase}]: secret {secret} (declared by {}) has no value in \
                 .secret.local, so it reads as the empty string; a deploy needs it in Secret \
                 Manager",
                functions.join(", ")
            )
        })
        .collect()
}

/// The location of every local Realtime Database instance, as 2nd-gen trigger events report
/// it, and its DNS suffix. Production delivers a 2nd-gen RTDB event only to functions in the
/// instance's location; a local instance has no configured location, so it is this one, the
/// official emulator's assumption too.
pub const LOCAL_DATABASE_LOCATION: &str = "us-central1";
/// The DNS suffix of [`LOCAL_DATABASE_LOCATION`] instances.
pub const LOCAL_DATABASE_HOST: &str = "firebaseio.com";

/// One `functions[...]` warning per 2nd-gen Realtime Database trigger outside
/// [`LOCAL_DATABASE_LOCATION`] (review S11, 2026-10-25): it never fires locally, as the official
/// emulator warns ("function region is defined outside the database region, will not
/// trigger"), and a test waiting for it would otherwise time out with no explanation.
#[must_use]
pub fn database_region_warnings(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    codebase: &str,
) -> Vec<String> {
    use fireemu_core_functions::manifest::{FunctionGeneration, Trigger};
    manifest
        .functions
        .iter()
        .filter(|function| {
            matches!(function.trigger, Trigger::Database { .. })
                && function.generation == FunctionGeneration::Second
                && function.region != LOCAL_DATABASE_LOCATION
        })
        .map(|function| {
            format!(
                "functions[{codebase}]: {} is a 2nd-gen Realtime Database trigger in {}, but \
                 local Realtime Database instances are in {LOCAL_DATABASE_LOCATION}, so it will \
                 not trigger; in production it fires only for instances located in {}",
                function.name, function.region, function.region
            )
        })
        .collect()
}

/// The stderr lines for every export that will never run, each a `warning:` and followed by one
/// summary line. An export production would deploy and run (a v2 Test Lab trigger, a function
/// whose options fail to resolve) is skipped here, so a test asserting "no side effect" would
/// pass for the wrong reason; the warning is how a developer finds out.
pub fn ignored_warnings(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    policy: UnservedTriggers,
) -> Result<Vec<String>, String> {
    let mut lines: Vec<String> = check_ignored(manifest, policy)?
        .into_iter()
        .map(|line| format!("warning: {line}"))
        .collect();
    if !lines.is_empty() {
        lines.push(format!(
            "warning: functions: {} export(s) are not served and will never run locally, \
             although a deploy may serve them in production",
            lines.len()
        ));
    }
    Ok(lines)
}

/// Addresses the runner's functions need to reach the daemon. `None` means the service was
/// not selected by `--only`: its variable is then left unset in the runner, so a handler
/// cannot reach a product this run is not serving.
#[derive(Debug, Clone)]
pub struct EmulatorHosts {
    /// Public signing keys for Python blocking functions.
    pub blocking_jwks: Option<String>,
    /// App Check on the control listener, independent of whether Auth is selected.
    pub app_check: Option<String>,
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
    /// Answers the Admin SDK App Check questions of every runner, when App Check is enabled.
    /// Its presence is what tells a runner to ask the daemon in place of the SDK's JWKS fetch.
    pub admin_app_check:
        Option<Arc<dyn fireemu_adapter_functions::admin_app_check::AdminAppCheckVerifier>>,
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
    runner_candidates_for("FIREEMU_RUNNER_NODE", "runner-node", "index.mjs")
}

/// [`runner_candidates`] for any bundled runner: the override variable `env`, the directory `dir`
/// beside the binary, and the script `file` in it.
#[must_use]
pub fn runner_candidates_for(
    env: &str,
    runner_dir: &str,
    file: &str,
) -> Vec<(RunnerSource, PathBuf)> {
    let mut out = Vec::new();
    if let Some(script) = std::env::var_os(env) {
        out.push((RunnerSource::Environment, PathBuf::from(script)));
    }
    if let Ok(exe) = std::env::current_exe() {
        // The executable may be reached through a symlink (npm's `node_modules/.bin`), and the
        // runner lives beside the real file, not beside the link.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(beside) = exe.parent() {
            out.push((
                RunnerSource::BesideBinary,
                beside.join(runner_dir).join(file),
            ));
            if let Some(up) = beside.parent() {
                out.push((RunnerSource::BesideBinary, up.join(runner_dir).join(file)));
            }
        }
    }
    if let Some(script) = workspace_runner_for(runner_dir, file) {
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
fn workspace_runner_for(runner_dir: &str, file: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    workspace_runner_from_for(&exe, runner_dir, file)
}

/// [`workspace_runner`] for a given executable path, so the search depth can be exercised
/// against a synthetic tree without building a binary at that depth.
#[cfg(test)]
fn workspace_runner_from(exe: &Path) -> Option<PathBuf> {
    workspace_runner_from_for(exe, "runner-node", "index.mjs")
}

fn workspace_runner_from_for(exe: &Path, runner_dir: &str, file: &str) -> Option<PathBuf> {
    exe.ancestors()
        .skip(1)
        .take(WORKSPACE_RUNNER_SEARCH_DEPTH)
        .find_map(|root| {
            let script = root.join("tools").join(runner_dir).join(file);
            (root.join("Cargo.toml").is_file() && script.is_file()).then_some(script)
        })
}

/// Locates the bundled Node runner, or explains every place that was tried.
///
/// The environment override is reported as missing rather than silently skipped: a consumer
/// that named a runner meant that one, and falling back to another would run different code
/// than it asked for.
pub fn locate_runner() -> Result<RunnerScript, String> {
    locate_runner_for(
        "FIREEMU_RUNNER_NODE",
        "runner-node",
        "index.mjs",
        "the bundled Node runner",
    )
}

/// [`locate_runner`] for any bundled runner (`what` names it in the error).
pub fn locate_runner_for(
    env: &str,
    runner_dir: &str,
    file: &str,
    what: &str,
) -> Result<RunnerScript, String> {
    let candidates = runner_candidates_for(env, runner_dir, file);
    if let Some((source, path)) = candidates.first() {
        if *source == RunnerSource::Environment && !path.is_file() {
            return Err(format!(
                "{env} names {}, which is not a readable file",
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
    let article = if file.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    Err(format!(
        "{what} ({runner_dir}/{file}) was not found; tried {}. Set \
         {env} to {article} {file}, or reinstall the platform package that ships it",
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

/// The interpreter the default Node runner would be started with, and what is worth telling the
/// developer about the choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeRunnerChoice {
    /// The runner command: the Node executable and the bundled runner script.
    pub command: Vec<String>,
    /// The Node executable.
    pub program: PathBuf,
    /// `node --version` without the leading `v`; unknown where Node is not probed (Windows).
    pub version: Option<String>,
    /// The `note:` lines start-up prints about the choice.
    pub notes: Vec<String>,
}

#[cfg(windows)]
fn select_node_runner(
    _codebase: &crate::config::FunctionsCodebase,
    _node_probe_cache: &NodeProbeCache,
) -> Result<NodeRunnerChoice, String> {
    let script = locate_runner()?;
    let (candidates, _) = node_candidates(&NodeProbeKey::current())?;
    let program = candidates.first().ok_or_else(|| {
        "no Node executable was found in an absolute PATH directory; set FIREEMU_NODE to an absolute executable or configure functions.runner explicitly".to_owned()
    })?;
    Ok(NodeRunnerChoice {
        command: vec![
            program.display().to_string(),
            fireemu_adapter_functions::runner::node_path(&script.path.to_string_lossy())
                .into_owned(),
        ],
        program: program.clone(),
        version: None,
        notes: Vec::new(),
    })
}

#[cfg(not(windows))]
fn select_node_runner(
    codebase: &crate::config::FunctionsCodebase,
    node_probe_cache: &NodeProbeCache,
) -> Result<NodeRunnerChoice, String> {
    let script = locate_runner()?;
    let engines = package_node_engine(Path::new(&codebase.source))?;
    if let Some(expression) = engines.as_deref() {
        let _ = node_engine_matches(expression, (0, 0, 0))?;
    }
    let runtime_major = codebase.runtime.as_deref().and_then(|runtime| {
        runtime
            .strip_prefix("nodejs")
            .and_then(|major| major.parse::<u32>().ok())
    });
    let (selected, installations, notes) = select_probed_node(
        node_probe_cache,
        runtime_major,
        engines.as_deref(),
        &format!("the Functions codebase {:?}", codebase.codebase),
        &format!("functions[{}]", codebase.codebase),
    )?;
    let installation = &installations[selected];
    Ok(NodeRunnerChoice {
        command: vec![
            installation.program.display().to_string(),
            script.path.display().to_string(),
        ],
        program: installation.program.clone(),
        version: Some(installation.version.clone()),
        notes,
    })
}

/// Probes the Node candidates and picks one for a codebase's `runtime` major and
/// `engines.node`: the one choice start-up, `up --plan` and `doctor` all make. `subject` opens
/// the error ("the Functions codebase \"x\""), `label` opens each note.
#[cfg(not(windows))]
fn select_probed_node(
    node_probe_cache: &NodeProbeCache,
    runtime_major: Option<u32>,
    engines: Option<&str>,
    subject: &str,
    label: &str,
) -> Result<(usize, Vec<NodeInstallation>, Vec<String>), String> {
    let probed = node_probe_cache.probed(&NodeProbeKey::current())?;
    let ProbedNodeCandidates {
        installations,
        errors: probe_errors,
        explicit_node,
    } = probed;
    if installations.is_empty() {
        let detail = if probe_errors.is_empty() {
            "no Node executable was found".to_owned()
        } else {
            probe_errors.join("; ")
        };
        return Err(format!(
            "{subject}: {detail}; install Node, set FIREEMU_NODE, or configure functions.runner explicitly"
        ));
    }
    let selected = if explicit_node {
        0
    } else {
        select_node_installation(runtime_major, engines, &installations)?
    };
    let installation = &installations[selected];
    let prefer_require_module =
        request_prefers_require_module(runtime_major, engines, &installations)?;
    let mut notes = Vec::new();
    if let Some(engines) = engines {
        let matches_engine = node_engine_matches(
            engines,
            (installation.major, installation.minor, installation.patch),
        )?;
        if matches_engine {
            notes.push(format!(
                "note: {label}: selected Node v{} for package.json engines.node {:?}{}",
                installation.version,
                engines,
                runtime_major
                    .filter(|major| *major != installation.major)
                    .map_or_else(String::new, |major| format!(
                        " (firebase runtime nodejs{major} is deployment metadata)"
                    ))
            ));
        } else {
            notes.push(format!(
                "note: {label}: selected Node v{} as a loader-capable local fallback; package.json engines.node {:?}{} does not include it",
                installation.version,
                engines,
                runtime_major.map_or_else(String::new, |major| format!(
                    " and firebase runtime nodejs{major}"
                ))
            ));
        }
    } else if let Some(major) = runtime_major {
        if major != installation.major {
            notes.push(format!(
                "note: {label}: firebase runtime nodejs{major} differs from local Node v{}; the local emulator uses the first usable Node on PATH",
                installation.version
            ));
        }
    }
    if !installation.require_module && prefer_require_module {
        notes.push(format!(
            "note: {label}: Node v{} cannot synchronously require ES modules from CommonJS; install Node 20.19+, Node 22.12+, or a newer release if module loading fails",
            installation.version
        ));
    }
    Ok((selected, installations, notes))
}

/// The Node executable the Functions runner uses when a codebase constrains nothing (no
/// `runtime`, no `engines.node`): what `doctor` reports. `how` says what chose it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefaultNode {
    pub program: PathBuf,
    pub version: Option<String>,
    pub how: &'static str,
}

/// Selects the default Node by the code a codebase's start-up uses, with nothing to constrain
/// it. `Ok(None)` means there is no Node at all (nothing was asked for and nothing was found);
/// an error means a Node that was asked for (`FIREEMU_NODE`) cannot run.
pub(crate) fn default_node() -> Result<Option<DefaultNode>, String> {
    let key = NodeProbeKey::current();
    let how = if key.fireemu_node.is_some() {
        "FIREEMU_NODE"
    } else {
        "first node on PATH"
    };
    #[cfg(not(windows))]
    {
        let cache = NodeProbeCache::default();
        match select_probed_node(&cache, None, None, "Node", "node") {
            Ok((selected, installations, _)) => {
                let installation = &installations[selected];
                let how = if key.fireemu_node.is_none()
                    && !path_node_candidates(key.path.as_deref().unwrap_or_default())
                        .contains(&installation.program)
                {
                    "VOLTA_HOME"
                } else {
                    how
                };
                Ok(Some(DefaultNode {
                    program: installation.program.clone(),
                    version: Some(installation.version.clone()),
                    how,
                }))
            }
            Err(error) if error.contains("no Node executable was found") => Ok(None),
            Err(error) => Err(error),
        }
    }
    #[cfg(windows)]
    {
        let (candidates, _) = node_candidates(&key)?;
        Ok(candidates.into_iter().next().map(|program| DefaultNode {
            program,
            version: None,
            how,
        }))
    }
}

/// A codebase's runners being started: one for the codebase, or one per function it serves.
type CodebaseStart =
    tokio::task::JoinHandle<Result<Vec<fireemu_adapter_functions::runtime::CodebaseSpec>, String>>;

fn launch_codebases(
    cfg: &RuntimeConfig,
    codebases: &[crate::config::FunctionsCodebase],
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
    node_probe_cache: &Arc<NodeProbeCache>,
    clock_snapshot: fireemu_core_session::clock::ClockSnapshot,
) -> Vec<(String, CodebaseStart)> {
    codebases
        .iter()
        .map(|codebase| {
            let label = codebase.codebase.clone();
            let cfg = (*cfg).clone();
            let codebase = codebase.clone();
            let hosts = hosts.clone();
            let runner_secret = runner_secret.to_owned();
            let node_probe_cache = node_probe_cache.clone();
            let start = tokio::spawn(async move {
                start_codebase_units(
                    &cfg,
                    &codebase,
                    &hosts,
                    &runner_secret,
                    callable_trusted_protocol,
                    &node_probe_cache,
                    clock_snapshot,
                )
                .await
            });
            (label, start)
        })
        .collect()
}

/// The Functions session every event id is derived from: the seed when the configuration named
/// one (a replay gets the same ids every run), else the boot nonce (a restart does not repeat a
/// previous run's ids, so a handler that deduplicates by event id keeps seeing new events).
const fn session_value(seed: u64, pinned: bool, nonce: u64) -> u128 {
    if pinned {
        seed as u128
    } else {
        nonce as u128
    }
}

/// A random value drawn once per daemon boot from the operating system's entropy; the wall
/// clock only if the entropy source fails (the daemon refuses to start without one, so this is a
/// fallback for a library embedding).
fn boot_nonce() -> u64 {
    static NONCE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *NONCE.get_or_init(fresh_nonce)
}

/// One draw of the nonce: the operating system's entropy, else the wall clock.
fn fresh_nonce() -> u64 {
    let mut bytes = [0_u8; 8];
    if fireemu_adapter_support::entropy::fill(&mut bytes).is_ok() {
        u64::from_le_bytes(bytes)
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
    }
}

/// The configuration's defaults for what the discovered manifest does not declare: the scheduler's time zone and,
/// under `functions.taskRetryDefaults` `production`, a task queue's `maxAttempts`.
fn apply_config_defaults(manifest_json: &mut serde_json::Value, cfg: &RuntimeConfig) {
    if let Some(tz) = &cfg.scheduler_default_time_zone {
        apply_default_time_zone(manifest_json, tz);
    }
    if cfg.functions_task_retry_defaults == crate::config::TaskRetryDefaults::Production {
        apply_task_retry_defaults(manifest_json);
    }
}

/// The scheduler's rule for a finished task's name, from `functions.taskNameReuse`.
fn task_name_reuse(
    mode: crate::config::TaskNameReuse,
) -> fireemu_adapter_functions::tasks_production::NameReuse {
    use crate::config::TaskNameReuse;
    use fireemu_adapter_functions::tasks_production::NameReuse;
    match mode {
        TaskNameReuse::Retained => NameReuse::Retained,
        TaskNameReuse::Immediate => NameReuse::Immediate,
        // Production keeps a name for about an hour (documented; its expiry was not observed).
        TaskNameReuse::Production => NameReuse::Window(std::time::Duration::from_secs(3600)),
    }
}

/// The `maxAttempts` Cloud Tasks gave a queue whose function declared none: the default queue read back in both
/// TASK-QUEUE-FUNCTIONS recordings (2026-11-11) had `maxAttempts` 100, `minBackoff` 0.100 s, `maxBackoff` 3600 s and
/// `maxDoublings` 16, so only the number of attempts differs from the official emulator's defaults.
const PRODUCTION_TASK_MAX_ATTEMPTS: u64 = 100;

/// Fills `retryConfig.maxAttempts` of every task queue function that does not declare it (`functions.taskRetryDefaults`
/// `production`). A declared value, `0` included, is kept.
fn apply_task_retry_defaults(manifest: &mut serde_json::Value) {
    let Some(functions) = manifest
        .get_mut("functions")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for function in functions {
        let Some(trigger) = function.get_mut("trigger") else {
            continue;
        };
        if trigger.get("type").and_then(serde_json::Value::as_str) != Some("tasks") {
            continue;
        }
        if !trigger
            .get("retryConfig")
            .is_some_and(serde_json::Value::is_object)
        {
            trigger["retryConfig"] = serde_json::json!({});
        }
        let retry = &mut trigger["retryConfig"];
        if retry
            .get("maxAttempts")
            .is_none_or(serde_json::Value::is_null)
        {
            retry["maxAttempts"] = serde_json::json!(PRODUCTION_TASK_MAX_ATTEMPTS);
        }
    }
}

/// The runtime configuration of the Functions backend for this run: the project, the location, the
/// limits and, by profile, how events are named and shaped.
fn functions_config(
    cfg: &RuntimeConfig,
    functions_host: Option<String>,
    runner_secret: &str,
) -> FunctionsConfig {
    FunctionsConfig {
        project: cfg.auth_project.clone(),
        default_bucket: format!("{}.appspot.com", cfg.auth_project),
        location: match cfg.profile {
            CompatibilityProfile::Strict => cfg.firestore_location.clone(),
            CompatibilityProfile::Emulator => "nam5".to_owned(),
        },
        session: SessionId::new(session_value(cfg.seed, cfg.seed_pinned, boot_nonce())),
        max_running: cfg.functions_max_running,
        debug_mode: cfg.functions_inspect_dynamic || cfg.functions_inspect_port.is_some(),
        retry_attempts: cfg.events_max_attempts,
        max_catch_up_runs: cfg.scheduler_max_catch_up_runs,
        runner_secret: runner_secret.to_owned(),
        overlap: overlap_policy_for(cfg.profile, cfg.scheduler_overlap.as_deref()),
        catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::parse(&cfg.scheduler_catch_up)
            .unwrap_or_default(),
        functions_host,
        clock_policy: cfg.functions_clock,
        // Cloud Tasks holds a task until its scheduleTime; the official emulator dispatches at
        // once, so only the strict profile waits.
        honour_task_schedule_time: cfg.profile == CompatibilityProfile::Strict,
        // How long a finished task's name is refused, and the dispatch deadline of a task that names none:
        // development defaults by profile and `productionExact`, each overridable by its own key
        // (`functions.taskNameReuse`, `functions.taskDispatchDeadlineSeconds`).
        task_default_deadline_seconds: cfg.functions_task_dispatch_deadline_seconds,
        task_retry_production_gaps: cfg.functions_task_retry_backoff
            == crate::config::TaskRetryBackoff::Production,
        task_name_reuse: task_name_reuse(cfg.functions_task_name_reuse),
        clock_start_pinned: cfg.clock_start_pinned,
        subscription_naming: subscription_naming(cfg.profile),
        auth_context: auth_context_naming(cfg.profile),
        database_event_shape: database_event_shape(cfg.profile),
    }
}

/// Starts one runner process per configured codebase and the runtime that multiplexes them,
/// and installs it as the backend's synchronous commit observer (Storage events are wired by
/// the caller through [`storage_sink`]).
#[allow(clippy::too_many_lines)] // Keep schedule profile selection with runtime startup.
pub async fn start(
    cfg: &RuntimeConfig,
    clock: &Arc<Mutex<VirtualClock>>,
    backend: &Arc<LocalBackend>,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
) -> Result<Arc<FunctionsRuntime>, String> {
    cfg.functions_clock
        .bind(&mut *clock.lock().map_err(|_| "clock lock poisoned")?)?;
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
    if cfg.effective_functions_isolation() == FunctionsIsolation::Function
        && cfg.functions_inspect_port.is_some()
    {
        return Err(
            "functions.isolation \"function\" starts several runner processes per codebase, which cannot share one fixed debugger port. Use --inspect-functions=true to assign a dynamic port to each"
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
    // Capture the live watch baseline before loading generation 0, never after it is serving.
    // An edit during startup may conservatively reload, but cannot become a lost baseline.
    // Known limit: A -> B -> A edits entirely within the load can restore the baseline bytes.
    let scan_budget = FunctionsSourceScanBudget::new();
    let mut initial_stamps = BTreeMap::new();
    for codebase in codebases
        .iter()
        .filter(|codebase| reload_supervised(codebase))
    {
        initial_stamps.insert(
            codebase.codebase.clone(),
            scan_budget
                .scan(Path::new(&codebase.source), &codebase.ignore)
                .await,
        );
    }
    #[cfg(unix)]
    drop(schedule_orphan_function_snapshot_sweep(std::env::temp_dir()));
    let starts = launch_codebases(
        cfg,
        &codebases,
        hosts,
        runner_secret,
        callable_trusted_protocol,
        &node_probe_cache,
        clock.lock().expect("clock lock").snapshot(),
    );
    let outcomes = join_codebase_starts(starts).await;
    if let Some(error) = outcomes.iter().find_map(|outcome| outcome.as_ref().err()) {
        for spec in outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().ok())
            .flatten()
        {
            spec.runner.kill_now();
        }
        return Err(error.clone());
    }
    let started: Vec<fireemu_adapter_functions::runtime::CodebaseSpec> = outcomes
        .into_iter()
        .filter_map(Result::ok)
        .flatten()
        .collect();
    let config = functions_config(cfg, hosts.functions.clone(), runner_secret);
    // A function name two codebases both export is fatal here. The runners it collided
    // between are killed rather than left behind a daemon that refuses to serve them.
    let spawned: Vec<Arc<Runner>> = started.iter().map(|c| c.runner.clone()).collect();
    let runtime = match FunctionsRuntime::with_codebases(
        started,
        config,
        clock.clone(),
        match cfg.profile {
            CompatibilityProfile::Strict => {
                fireemu_adapter_functions::http::FunctionsHttpProfile::Strict
            }
            CompatibilityProfile::Emulator => {
                fireemu_adapter_functions::http::FunctionsHttpProfile::Emulator
            }
        },
    ) {
        Ok(runtime) => runtime,
        Err(e) => {
            for runner in &spawned {
                runner.kill_now();
            }
            return Err(e);
        }
    };
    if let Some(verifier) = &hosts.admin_app_check {
        runtime.set_admin_app_check(verifier.clone());
    }
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
        initial_stamps,
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

/// The RTDB source-event bridge. Location and DNS suffix are trusted daemon configuration,
/// not request Host values; capture limits are local event-resource policy, not native quotas.
#[must_use]
pub fn database_sink(
    runtime: &Arc<FunctionsRuntime>,
    daemon_project: &str,
    location: &str,
    host: &str,
) -> Arc<dyn fireemu_adapter_database::changes::ChangeSink> {
    Arc::new(FunctionsDatabaseSink {
        runtime: Arc::clone(runtime),
        daemon_project: daemon_project.to_owned(),
        location: location.to_owned(),
        host: host.to_owned(),
        pending_frame_drops: Mutex::new(0),
    })
}

struct FunctionsDatabaseSink {
    runtime: Arc<FunctionsRuntime>,
    daemon_project: String,
    location: String,
    host: String,
    /// References the last capture left out because their snapshot can never fit a frame,
    /// counted only once the write is admitted (merge review R2-S1).
    pending_frame_drops: Mutex<usize>,
}

impl std::fmt::Debug for FunctionsDatabaseSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionsDatabaseSink")
            .field("daemon_project", &self.daemon_project)
            .field("location", &self.location)
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

struct FunctionsDatabasePublication(
    Option<fireemu_adapter_functions::runtime::EventBatchReservation>,
);

impl fireemu_adapter_database::changes::Publication for FunctionsDatabasePublication {
    fn publish(mut self: Box<Self>) {
        if let Some(reservation) = self.0.take() {
            reservation.publish();
        }
    }
}

impl FunctionsDatabaseSink {
    fn count_frame_drops(&self, namespace: &str, count: usize) {
        for _ in 0..count {
            let _ = self.runtime.drop_database_fanout(
                namespace,
                "one changed reference's snapshot is larger than an invocation frame",
            );
        }
    }

    fn patterns(&self, instance: &str) -> Vec<fireemu_core_functions::manifest::DatabasePattern> {
        let project = crate::database_rules::project_of_instance(instance, &self.daemon_project);
        self.runtime
            .database_capture_patterns(project, instance, &self.location)
    }

    fn triggers(&self, instance: &str) -> Vec<DatabaseTrigger> {
        let project = crate::database_rules::project_of_instance(instance, &self.daemon_project);
        self.runtime
            .database_capture_triggers(project, instance, &self.location)
    }
}

impl fireemu_adapter_database::changes::ChangeSink for FunctionsDatabaseSink {
    fn interested(&self, namespace: &str) -> bool {
        !self.patterns(namespace).is_empty()
    }

    fn affects(&self, namespace: &str, scope: &fireemu_adapter_database::changes::Path) -> bool {
        let scope = scope.to_string();
        self.patterns(namespace)
            .iter()
            .any(|pattern| pattern.overlaps(&scope))
    }

    fn capture_references_within(
        &self,
        namespace: &str,
        before: fireemu_adapter_database::changes::ScopeView<'_>,
        after: &fireemu_adapter_database::changes::Tree,
        scope: &fireemu_adapter_database::changes::Path,
    ) -> Result<
        Option<Vec<fireemu_adapter_database::changes::Path>>,
        fireemu_core_types::admission::EventAdmissionError,
    > {
        use fireemu_adapter_functions::protocol::MAX_FRAME_BYTES;
        use fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_RECORDS;
        match capture_database_references_limited(
            &self.triggers(namespace),
            before,
            after,
            scope,
            MAX_ACTIVE_EVENT_RECORDS,
            MAX_FRAME_BYTES,
            self.runtime.database_event_limit(),
        ) {
            Ok((references, frame_drops)) => {
                if references.is_empty() {
                    // Nothing is reserved, so the write is applied now.
                    self.count_frame_drops(namespace, frame_drops);
                    *self
                        .pending_frame_drops
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = 0;
                } else {
                    *self
                        .pending_frame_drops
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = frame_drops;
                }
                Ok(Some(references))
            }
            // Every changed reference yields at least one event, so more references than the
            // whole event budget can never be admitted; production accepts the write (review
            // S4), so it proceeds without them. Byte sizes are not judged here: the runtime
            // measures the serialized events (merge review M1, 2026-10-26).
            Err(fireemu_core_types::admission::EventAdmissionError::Capacity(_)) => {
                let _ = self.runtime.drop_database_fanout(
                    namespace,
                    "its changed trigger references outnumber the whole local event budget",
                );
                Ok(Some(Vec::new()))
            }
            Err(error) => Err(error),
        }
    }

    fn reserve(
        &self,
        change: &fireemu_adapter_database::changes::CommittedChange,
    ) -> Result<
        Box<dyn fireemu_adapter_database::changes::Publication>,
        fireemu_core_types::admission::EventAdmissionError,
    > {
        use fireemu_adapter_database::changes::ChangeData;
        use fireemu_adapter_functions::events::{
            DatabaseChangeData, DatabaseCommit, DatabaseReferenceChange,
        };
        let data = match &change.data {
            ChangeData::Whole { before, after } => DatabaseChangeData::Whole {
                before: before.clone(),
                after: after.clone(),
            },
            ChangeData::References(references) => DatabaseChangeData::References(
                references
                    .iter()
                    .map(|reference| DatabaseReferenceChange {
                        reference: reference.reference.to_string(),
                        before: reference.before.clone(),
                        after: reference.after.clone(),
                    })
                    .collect(),
            ),
        };
        let project = crate::database_rules::project_of_instance(
            &change.context.namespace,
            &self.daemon_project,
        );
        let commit = DatabaseCommit {
            project: project.to_owned(),
            instance: change.context.namespace.clone(),
            location: self.location.clone(),
            host: self.host.clone(),
            sequence: change.context.sequence,
            time: fireemu_core_types::time::LogicalInstant::from_nanos(
                i128::from(change.context.now_millis) * 1_000_000,
            ),
            data,
            auth_type: change.context.principal.auth_type.clone(),
            auth_id: change.context.principal.auth_id.clone(),
            auth: change.context.principal.auth.clone(),
        };
        let frame_drops = std::mem::take(
            &mut *self
                .pending_frame_drops
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        self.runtime
            .reserve_database_events(&commit)
            .inspect(|_| self.count_frame_drops(&change.context.namespace, frame_drops))
            .map(|reservation| {
                Box::new(FunctionsDatabasePublication(Some(reservation)))
                    as Box<dyn fireemu_adapter_database::changes::Publication>
            })
            .map_err(functions_event_admission_error)
    }
}

// Bounds the references one write selects. Every changed reference yields at least one event,
// so the record budget is a proof that the events can never fit. Byte sizes are left to the
// runtime, which measures the serialized events: a heap-size estimate here dropped events that
// fit (merge review M1, 2026-10-26). The snapshots exported for the selected references are
// bounded by the namespace already in memory times the pattern depth.
//
// A reference whose snapshot alone is provably larger than an invocation frame is left out
// and counted, before anything is exported: building that event cost seconds and gigabytes
// under the database lock only to drop it (merge review R2-M1, 2026-10-26).
struct DatabaseReferenceCapture {
    references: BTreeSet<fireemu_adapter_database::changes::Path>,
    record_limit: usize,
    frame_limit: usize,
    /// The strict profile's event limit: a reference provably over it refuses the write.
    refuse_over: Option<usize>,
    frame_drops: usize,
    /// The event kind the trigger being walked accepts. A reference whose change is of another kind
    /// yields no event for it, so its size is no reason to refuse or drop anything.
    accepts: fireemu_core_functions::manifest::DocumentEvent,
}

/// A deployed Database trigger as the capture sees it: its reference pattern and the event kind it accepts.
type DatabaseTrigger = (
    fireemu_core_functions::manifest::DatabasePattern,
    fireemu_core_functions::manifest::DocumentEvent,
);

impl DatabaseReferenceCapture {
    fn insert(
        &mut self,
        path: &fireemu_adapter_database::changes::Path,
        before: Option<fireemu_adapter_database::changes::NodeView<'_>>,
        after: Option<fireemu_adapter_database::changes::NodeView<'_>>,
    ) -> Result<(), fireemu_core_types::admission::EventAdmissionError> {
        if self.references.contains(path) {
            return Ok(());
        }
        // An event carries `before` as its data and, unless both sides are objects, `after`
        // whole as its delta.
        let objects = |node: Option<fireemu_adapter_database::changes::NodeView<'_>>| {
            matches!(node.map(|node| node.leaf().is_none()), Some(true))
        };
        let limit = self
            .refuse_over
            .map_or(self.frame_limit, |over| over.min(self.frame_limit));
        let mut bound = database_json_lower_bound(before, limit);
        if !(objects(before) && objects(after)) {
            bound = bound.saturating_add(database_json_lower_bound(after, limit));
        }
        if bound > limit {
            // `before` absent is a creation, `after` absent a deletion, anything else an update (the
            // runtime's own rule when it builds the event).
            let actual = if before.is_none() {
                fireemu_core_functions::manifest::DocumentEvent::Created
            } else if after.is_none() {
                fireemu_core_functions::manifest::DocumentEvent::Deleted
            } else {
                fireemu_core_functions::manifest::DocumentEvent::Updated
            };
            if !self.accepts.accepts(actual) {
                return Ok(());
            }
            if self.refuse_over.is_some_and(|over| bound > over) {
                return Err(
                    fireemu_core_types::admission::EventAdmissionError::PayloadTooLarge(
                        "a trigger event is larger than a function can receive".to_owned(),
                    ),
                );
            }
            self.frame_drops += 1;
            return Ok(());
        }
        if self.references.len() >= self.record_limit {
            return Err(
                fireemu_core_types::admission::EventAdmissionError::Capacity(
                    "Functions RTDB capture exceeds the local event-record budget".to_owned(),
                ),
            );
        }
        self.references.insert(path.clone());
        Ok(())
    }
}

/// A lower bound of the compact JSON length of `node`, never allocating: key and string
/// bytes plus the quotes, colons, commas and braces around them; every other leaf counts one
/// byte, and priorities and escapes are left out. It stops counting once past `limit`.
fn database_json_lower_bound(
    node: Option<fireemu_adapter_database::changes::NodeView<'_>>,
    limit: usize,
) -> usize {
    use fireemu_adapter_database::changes::Leaf;
    let Some(node) = node else {
        return 4;
    };
    let mut total = 0usize;
    // Iterator frames, rather than a stack containing every child, bound scratch
    // space by depth even for a very wide ancestor rejected by its frame size.
    let mut next = Some(node);
    let mut children = Vec::new();
    loop {
        if let Some(node) = next.take() {
            match node.leaf() {
                Some(Leaf::String(text)) => total = total.saturating_add(text.len() + 2),
                Some(_) => total = total.saturating_add(1),
                None => {
                    total = total.saturating_add(2 + node.child_count().saturating_sub(1));
                    children.push(node.children().expect("a non-leaf has children"));
                }
            }
        }
        if total > limit {
            break;
        }
        match children.last_mut().and_then(Iterator::next) {
            Some((key, child)) => {
                total = total.saturating_add(key.len() + 3);
                next = Some(child);
            }
            None => {
                if children.pop().is_none() {
                    break;
                }
            }
        }
    }
    total
}

/// The changed trigger references of a write confined to `scope` (see
/// `ChangeSink::capture_references_within`), and how many were left out because their
/// snapshot can never fit `frame_limit`: above `scope` only the branch leading to it is
/// followed, without comparing its unchanged siblings.
#[cfg(test)]
fn capture_database_references<'a>(
    patterns: &[fireemu_core_functions::manifest::DatabasePattern],
    before: impl Into<fireemu_adapter_database::changes::ScopeView<'a>>,
    after: &fireemu_adapter_database::changes::Tree,
    scope: &fireemu_adapter_database::changes::Path,
    record_limit: usize,
    frame_limit: usize,
) -> Result<
    (Vec<fireemu_adapter_database::changes::Path>, usize),
    fireemu_core_types::admission::EventAdmissionError,
> {
    let triggers: Vec<DatabaseTrigger> = patterns
        .iter()
        .map(|pattern| {
            (
                pattern.clone(),
                fireemu_core_functions::manifest::DocumentEvent::Written,
            )
        })
        .collect();
    capture_database_references_limited(
        &triggers,
        before,
        after,
        scope,
        record_limit,
        frame_limit,
        None,
    )
}

/// `capture_database_references` that, given `refuse_over`, refuses the write instead of leaving out a
/// reference whose snapshot is provably larger than that many bytes (the strict profile's event limit).
/// Each trigger carries the event kind it accepts: an oversized reference whose change is of a kind no
/// trigger on it accepts produces no event, and is neither refused nor counted as dropped.
fn capture_database_references_limited<'a>(
    triggers: &[DatabaseTrigger],
    before: impl Into<fireemu_adapter_database::changes::ScopeView<'a>>,
    after: &fireemu_adapter_database::changes::Tree,
    scope: &fireemu_adapter_database::changes::Path,
    record_limit: usize,
    frame_limit: usize,
    refuse_over: Option<usize>,
) -> Result<
    (Vec<fireemu_adapter_database::changes::Path>, usize),
    fireemu_core_types::admission::EventAdmissionError,
> {
    let before = before.into();
    let mut capture = DatabaseReferenceCapture {
        references: BTreeSet::new(),
        record_limit,
        frame_limit,
        refuse_over,
        frame_drops: 0,
        accepts: fireemu_core_functions::manifest::DocumentEvent::Written,
    };
    for (pattern, accepts) in triggers {
        capture.accepts = *accepts;
        let parts: Vec<_> = pattern
            .as_str()
            .trim_matches('/')
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        let mut prefix = String::new();
        let mut prefixes = Vec::new();
        for part in &parts {
            prefix.push('/');
            prefix.push_str(part);
            prefixes.push(
                fireemu_core_functions::manifest::DatabasePattern::parse(&prefix)
                    .expect("a prefix of a validated RTDB reference is valid"),
            );
        }
        walk_database_references(
            &prefixes,
            before.root(),
            after
                .root()
                .map(fireemu_adapter_database::changes::NodeView::Borrowed),
            &fireemu_adapter_database::changes::Path::root(),
            scope,
            &mut capture,
        )?;
    }
    Ok((
        capture.references.into_iter().collect(),
        capture.frame_drops,
    ))
}

fn walk_database_references(
    prefixes: &[fireemu_core_functions::manifest::DatabasePattern],
    before: Option<fireemu_adapter_database::changes::NodeView<'_>>,
    after: Option<fireemu_adapter_database::changes::NodeView<'_>>,
    path: &fireemu_adapter_database::changes::Path,
    scope: &fireemu_adapter_database::changes::Path,
    capture: &mut DatabaseReferenceCapture,
) -> Result<(), fireemu_core_types::admission::EventAdmissionError> {
    // Above the written scope, the node changed exactly when the scope did, which the caller
    // established; comparing would walk every unchanged sibling.
    let above_scope = path.depth() < scope.depth();
    if !above_scope
        && match (before, after) {
            (None, None) => true,
            (Some(before), Some(fireemu_adapter_database::changes::NodeView::Borrowed(after))) => {
                before.equals(after)
            }
            _ => false,
        }
    {
        return Ok(());
    }
    if path.depth() == prefixes.len() {
        return capture.insert(path, before, after);
    }
    let prefix = &prefixes[path.depth()];
    let segment = prefix
        .as_str()
        .rsplit('/')
        .next()
        .expect("a non-root prefix has a segment");
    let mut visit = |key: &str| {
        let child = path.child(key);
        if prefix.matches(&child.to_string()).is_none() {
            return Ok(());
        }
        walk_database_references(
            prefixes,
            before.and_then(|node| node.child(key)),
            after.and_then(|node| node.child(key)),
            &child,
            scope,
            capture,
        )
    };
    if above_scope {
        return visit(&scope.keys()[path.depth()]);
    }
    if !segment.contains(['{', '*']) {
        return visit(segment);
    }
    for (key, _) in before
        .and_then(fireemu_adapter_database::changes::NodeView::children)
        .into_iter()
        .flatten()
    {
        visit(key)?;
    }
    for (key, _) in after
        .and_then(fireemu_adapter_database::changes::NodeView::children)
        .into_iter()
        .flatten()
    {
        if before.and_then(|node| node.child(key)).is_none() {
            visit(key)?;
        }
    }
    Ok(())
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
        SourceEventAdmissionError::PayloadTooLarge => EventAdmissionError::PayloadTooLarge(
            "This request would cause a function payload exceeding the maximum size allowed."
                .into(),
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

/// What every started runner of a codebase must satisfy before it serves: the virtual clock it was
/// asked for (and the clock it is synced to), and a live inspector endpoint when one was requested.
/// A runner that fails is killed here.
async fn check_started_runner(
    cfg: &RuntimeConfig,
    label: &str,
    python: bool,
    runner: &Arc<Runner>,
    clock_snapshot: fireemu_core_session::clock::ClockSnapshot,
) -> Result<(), String> {
    let inspecting = cfg.functions_inspect_dynamic || cfg.functions_inspect_port.is_some();
    if cfg.functions_clock.date_virtual {
        if !runner_checks::supports_virtual_clock(
            runner.hello().clock.as_ref(),
            cfg.functions_clock.timers_virtual,
        ) {
            runner.kill_now();
            return Err(runner_checks::virtual_clock_refusal(label, python));
        }
        if let Err(error) = runner.sync_clock(clock_snapshot).await {
            runner.kill_now();
            return Err(error);
        }
    }
    if inspecting && !python {
        let reported = runner.hello().inspector_port;
        let endpoint_active = match reported {
            Some(port) => inspector_endpoint_is_active(port).await,
            None => false,
        };
        if !runner_checks::debugger_port_is_usable(
            reported,
            cfg.functions_inspect_port,
            endpoint_active,
        ) {
            runner.kill_now();
            return Err(runner_checks::debugger_port_refusal(
                label,
                cfg.functions_inspect_port,
            ));
        }
        eprintln!(
            "functions[{label}]: using debug port {}",
            reported.expect("the active inspector port was checked above")
        );
    }
    Ok(())
}

/// Starts the runners of one codebase: the codebase runner, or with `functions.isolation =
/// "function"` one dedicated runner per function it discovered (see `isolation`).
async fn start_codebase_units(
    cfg: &RuntimeConfig,
    codebase: &crate::config::FunctionsCodebase,
    hosts: &EmulatorHosts,
    runner_secret: &str,
    callable_trusted_protocol: bool,
    node_probe_cache: &Arc<NodeProbeCache>,
    clock_snapshot: fireemu_core_session::clock::ClockSnapshot,
) -> Result<Vec<fireemu_adapter_functions::runtime::CodebaseSpec>, String> {
    let discovery = start_codebase(
        cfg,
        codebase,
        hosts,
        runner_secret,
        callable_trusted_protocol,
        node_probe_cache,
        clock_snapshot,
    )
    .await?;
    if cfg.effective_functions_isolation() != FunctionsIsolation::Function
        || discovery.manifest.functions.is_empty()
    {
        return Ok(vec![discovery]);
    }
    let python = crate::python_functions::codebase_language(codebase) == RuntimeLanguage::Python;
    isolation::isolate_functions(cfg, hosts, python, discovery, clock_snapshot).await
}

/// How one codebase's runner is launched. Start-up and `up --plan` both decide it here, so the
/// plan names the interpreter a start would use.
pub(crate) struct RunnerSelection {
    /// The runner command: interpreter and bundled runner script, or the `functions.runner`
    /// override.
    pub command: Vec<String>,
    /// The Python virtual environment, when the codebase is Python and no override replaces it.
    pub python_environment: Option<crate::python_functions::PythonEnvironment>,
    /// The Node choice, when the default Node runner is used.
    pub node: Option<NodeRunnerChoice>,
}

/// Chooses the runner for `codebase` (`source` is its canonical directory). The venv is
/// checked before anything is spawned, with firebase-tools' wording; a `functions.runner`
/// override replaces the whole launch and is its own responsibility.
async fn select_runner(
    cfg: &RuntimeConfig,
    codebase: &crate::config::FunctionsCodebase,
    source: &str,
    python: bool,
    node_probe_cache: &Arc<NodeProbeCache>,
) -> Result<RunnerSelection, String> {
    let label = &codebase.codebase;
    let python_environment = if python && cfg.functions_runner.is_none() {
        Some(
            crate::python_functions::preflight(Path::new(source), codebase.runtime.as_deref())
                .await
                .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?,
        )
    } else {
        None
    };
    let mut node = None;
    let command = if let Some(command) = cfg.functions_runner.clone() {
        command
    } else if let Some(environment) = &python_environment {
        let script = crate::python_functions::locate_runner()
            .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?;
        crate::python_functions::runner_command(environment, &script)
    } else {
        let codebase = codebase.clone();
        let node_probe_cache = node_probe_cache.clone();
        let choice =
            run_node_selection_blocking(move || select_node_runner(&codebase, &node_probe_cache))
                .await
                .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?
                .map_err(|error| format!("the Functions codebase {label:?}: {error}"))?;
        let command = choice.command.clone();
        node = Some(choice);
        command
    };
    Ok(RunnerSelection {
        command,
        python_environment,
        node,
    })
}

/// The version of the npm package `name` the codebase at `source` resolves, read the way Node
/// resolves it: `node_modules/<name>` of the source directory or of the nearest ancestor that
/// has one.
pub(crate) fn installed_package_version(source: &Path, name: &str) -> Option<String> {
    let manifest = source
        .ancestors()
        .map(|dir| dir.join("node_modules").join(name).join("package.json"))
        .find(|path| path.is_file())?;
    std::fs::read_to_string(manifest)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|package| package.get("version")?.as_str().map(str::to_owned))
}

/// The canonical directory of a codebase's source, or why start-up refuses it.
fn canonical_codebase_source(
    codebase: &crate::config::FunctionsCodebase,
) -> Result<String, String> {
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
    #[cfg(windows)]
    let source = fireemu_adapter_functions::runner::node_path(&source).into_owned();
    Ok(source)
}

/// What a codebase would run on, as `up --plan` reports it: the source and runner start-up
/// would choose, and the SDK versions installed there. `error` is the refusal start-up would
/// give instead.
pub(crate) struct CodebasePlan {
    pub source: Option<String>,
    pub language: &'static str,
    pub runner: Option<RunnerSelection>,
    /// Package or distribution name to installed version.
    pub sdk: BTreeMap<String, String>,
    pub error: Option<String>,
}

/// Decides one codebase the way [`start_codebase`] does, without starting anything. It runs the
/// probes start-up runs: `node --version`, and the codebase's own Python for a Python codebase.
pub(crate) fn plan_codebase(
    cfg: &RuntimeConfig,
    codebase: &crate::config::FunctionsCodebase,
    callable_trusted_protocol: bool,
) -> CodebasePlan {
    let python = crate::python_functions::codebase_language(codebase) == RuntimeLanguage::Python;
    let mut plan = CodebasePlan {
        source: None,
        language: if python { "python" } else { "node" },
        runner: None,
        sdk: BTreeMap::new(),
        error: None,
    };
    let source = match canonical_codebase_source(codebase) {
        Ok(source) => source,
        Err(error) => {
            plan.error = Some(error);
            return plan;
        }
    };
    plan.source = Some(source.clone());
    if python && callable_trusted_protocol {
        plan.error = Some(python_callable_refusal(&codebase.codebase));
        return plan;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            plan.error = Some(format!(
                "cannot build a runtime to probe the interpreter: {error}"
            ));
            return plan;
        }
    };
    let cache = Arc::new(NodeProbeCache::default());
    match runtime.block_on(select_runner(cfg, codebase, &source, python, &cache)) {
        Ok(selection) => {
            if let Some(environment) = &selection.python_environment {
                plan.sdk.insert(
                    "firebase-functions".to_owned(),
                    environment.sdk_version.clone(),
                );
            }
            plan.runner = Some(selection);
        }
        Err(error) => plan.error = Some(error),
    }
    if !python {
        for package in ["firebase-functions", "firebase-admin"] {
            if let Some(version) = installed_package_version(Path::new(&source), package) {
                plan.sdk.insert(package.to_owned(), version);
            }
        }
    }
    plan
}

/// The refusal for a Python codebase when the run enables App Check, which Python callables
/// cannot honour yet.
fn python_callable_refusal(label: &str) -> String {
    format!(
        "the Functions codebase {label:?}: App Check for Python callables is not available yet, \
         and this run enables it; load the Python codebase on its own (--only \
         functions:{label}) or remove the App Check configuration"
    )
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
    clock_snapshot: fireemu_core_session::clock::ClockSnapshot,
) -> Result<fireemu_adapter_functions::runtime::CodebaseSpec, String> {
    let label = &codebase.codebase;
    let source = canonical_codebase_source(codebase)?;
    let python = crate::python_functions::codebase_language(codebase) == RuntimeLanguage::Python;
    if python && callable_trusted_protocol {
        return Err(python_callable_refusal(label));
    }
    let selection = select_runner(cfg, codebase, &source, python, node_probe_cache).await?;
    for note in selection.node.iter().flat_map(|node| &node.notes) {
        eprintln!("{note}");
    }
    let python_environment = selection.python_environment;
    let mut command = selection.command;
    let inspector = inspector_arguments(
        python,
        cfg.functions_inspect_dynamic,
        cfg.functions_inspect_port,
    );
    if inspector.ignored {
        // firebase-tools says the same and goes on (`functionsEmulator.ts:1736-1738`).
        eprintln!(
            "warning: functions[{label}]: --inspect-functions is not supported for Python functions; ignored"
        );
    }
    for (offset, argument) in inspector.arguments.into_iter().enumerate() {
        command.insert(1 + offset, argument);
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
    // These routes belong to this daemon, including when App Check is unavailable.
    let is_app_check_route = |name: &str| {
        matches!(
            name,
            "FIREEMU_APP_CHECK_EMULATOR_HOST"
                | "FIREEMU_APP_CHECK_JWKS_URL"
                | "FIREEMU_APP_CHECK_ADMIN"
                | "FIREEMU_AUTH_BLOCKING_JWKS"
        )
    };
    env.retain(|(name, _)| !is_app_check_route(name));
    if python {
        if let Some(jwks) = &hosts.blocking_jwks {
            env.push(("FIREEMU_AUTH_BLOCKING_JWKS".to_owned(), jwks.clone()));
        }
    }
    if admin_app_check_offered(hosts.admin_app_check.is_some(), python) {
        // The daemon owns the question and the answer; the runner only asks (see
        // `tools/runner-node/admin-app-check.mjs`).
        env.push(("FIREEMU_APP_CHECK_ADMIN".to_owned(), "1".to_owned()));
    }
    if let Some(host) = &hosts.app_check {
        env.push(("FIREEMU_APP_CHECK_EMULATOR_HOST".to_owned(), host.clone()));
        env.push((
            "FIREEMU_APP_CHECK_JWKS_URL".to_owned(),
            format!("http://{host}/v1/jwks"),
        ));
    }
    if !user_env.secrets.is_empty() {
        let secrets: serde_json::Map<String, serde_json::Value> = user_env
            .secrets
            .iter()
            // Secret scoping must neither hide nor overwrite daemon-owned routing.
            .filter(|(name, _)| !is_app_check_route(name))
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
        (
            "FIREEMU_HTTP_PROFILE".to_owned(),
            cfg.profile.as_str().to_owned(),
        ),
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
    // The emulator profile follows the official runtime's CORS feature. The trusted callable
    // protocol separately enables token skipping only after daemon-side credential checks.
    // The runner allowlist excludes these names and `SpawnSpec::env` is applied last.
    let debug_features = runner_debug_features(cfg.profile, callable_trusted_protocol);
    if let Some(debug_features) = debug_features {
        env.push(("FIREBASE_DEBUG_MODE".to_owned(), "true".to_owned()));
        env.push((
            "FIREBASE_DEBUG_FEATURES".to_owned(),
            debug_features.to_owned(),
        ));
    }
    env.push((
        "FIREEMU_CLOCK_JSON".into(),
        cfg.functions_clock
            .runner_options(clock_snapshot)
            .to_string(),
    ));
    if let Some(environment) = &python_environment {
        // What `activate` gives firebase-tools' Python commands: the environment first in PATH.
        env.extend(crate::python_functions::launch_environment(
            environment,
            std::env::var_os("PATH").as_deref(),
        ));
    }
    let spec = SpawnSpec {
        command,
        cwd: Some(source.clone()),
        env,
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Arc::new(
        Runner::spawn_spec_with(&spec, hosts.admin_app_check.clone())
            .await
            .map_err(|e| format!("the Functions codebase {label:?}: {e}"))?,
    );
    if admin_app_check_offered(hosts.admin_app_check.is_some(), python) {
        if let Some(note) = admin_app_check_note(label, runner.hello().admin_app_check.as_ref()) {
            eprintln!("note: {note}");
        }
    }
    check_started_runner(cfg, label, python, &runner, clock_snapshot).await?;
    let configured = (|| {
        check_declared_params(
            runner.hello().params.as_ref(),
            label,
            &source,
            &cfg.auth_project,
            cfg.functions_project_alias.as_deref(),
        )?;
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
        apply_config_defaults(&mut manifest_json, cfg);
        let mut manifest = manifest_for_profile(cfg.profile, &manifest_json, cfg.clock_start)?;
        // Before anything is served: every export the runner could not serve is either named in a
        // refusal or printed, one line each.
        let policy = UnservedTriggers::parse(&cfg.functions_unserved_triggers).unwrap_or_default();
        for line in ignored_warnings(&manifest, policy)? {
            eprintln!("{line}");
        }
        for line in missing_secret_warnings(&manifest, &user_env.secrets, label) {
            eprintln!("warning: {line}");
        }
        for line in database_region_warnings(&manifest, label) {
            eprintln!("warning: {line}");
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
            let mut discovered = if cfg.profile == CompatibilityProfile::Emulator {
                manifest_for_profile(cfg.profile, &discovered, cfg.clock_start)?
            } else {
                parse_manifest(&discovered)?
            };
            serve_blocking_events_for(cfg.profile, &mut discovered);
            check_manifest_agrees_on_blocking_auth(&manifest, &discovered)?;
            // Only the trusted protocol turns on `skipTokenVerification`, so only there can a
            // mislabelled callable reach a wrapper that trusts unverified credentials, and the
            // daemon strips the auth override fields from every request it forwards, tasks
            // included. Without App Check the wrapper's token check is the Auth emulator's, as
            // for any `onTaskDispatched` function reached by a task; the strict profile adds the
            // daemon's Bearer check for a task sent to such a queue (`mark_strict_callable_ingress`).
            // firebase-tools does not compare a configured manifest with the code at all, so the
            // emulator profile must not refuse it (see `runner_debug_features`).
            if callable_trusted_protocol {
                check_manifest_agrees_on_callables(&manifest, &discovered)?;
                clear_on_request_consumption(&mut manifest);
            } else {
                for warning in reconcile_consumption_without_app_check(&mut manifest, &discovered) {
                    eprintln!("warning: {warning}");
                }
                if cfg.profile == CompatibilityProfile::Strict {
                    for name in mark_strict_callable_ingress(&mut manifest, &discovered) {
                        let route = manifest.functions.iter().any(|f| {
                            f.name == name
                                && matches!(
                                    f.trigger,
                                    fireemu_core_functions::manifest::Trigger::Http { .. }
                                )
                        });
                        let (served_as, sent) = if route {
                            ("an onRequest function", "a request")
                        } else {
                            ("a non-HTTP function", "a task")
                        };
                        eprintln!(
                            "warning: the configured functions manifest serves {name:?} as \
                             {served_as}, but the codebase declares it callable; {sent} sent to \
                             it must carry no credential or a Bearer the Auth emulator verifies"
                        );
                    }
                }
            }
        }
        check_callable_app_check(
            &manifest,
            runner.hello().app_check.as_ref(),
            callable_trusted_protocol,
        )?;
        if let Some(note) = consume_app_check_note(&manifest, callable_trusted_protocol) {
            eprintln!("note: {note}");
        }
        Ok(fireemu_adapter_functions::runtime::CodebaseSpec {
            function: None,
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

/// The manifest `profile` serves: the parsed manifest, refused when strict finds a declaration production refuses, with unparseable emulator schedules and unserved blocking functions set aside.
#[allow(clippy::too_many_lines)] // Keep strict schedule normalization and validation together.
fn manifest_for_profile(
    profile: CompatibilityProfile,
    manifest_json: &serde_json::Value,
    now: fireemu_core_types::time::LogicalInstant,
) -> Result<fireemu_core_functions::manifest::FunctionManifest, String> {
    let mut unscheduled = BTreeMap::new();
    let defaulted;
    let document = if uses_production_scheduler_defaults(profile) {
        let mut copy = manifest_json.clone();
        apply_first_generation_default_time_zone(&mut copy);
        // Calendar v6 gr13: synchronized minutes use wall-clock alignment, in both recordings.
        if let Some(functions) = copy
            .get_mut("functions")
            .and_then(serde_json::Value::as_array_mut)
        {
            for function in functions {
                let Some(trigger) = function.get_mut("trigger") else {
                    continue;
                };
                if trigger.get("type").and_then(serde_json::Value::as_str) != Some("schedule") {
                    continue;
                }
                if let Some(text) = trigger.get("schedule").and_then(serde_json::Value::as_str) {
                    let lower = text.to_ascii_lowercase();
                    let words: Vec<&str> = lower.split_whitespace().collect();
                    if let ["every", n, "minutes", "synchronized"] = words.as_slice() {
                        // Only divisors of 60: there `*/n` equals the day-aligned interval; others are unrecorded.
                        if n.parse::<u32>()
                            .is_ok_and(|n| (1..=60).contains(&n) && 60 % n == 0)
                        {
                            trigger["schedule"] =
                                serde_json::Value::String(format!("*/{n} * * * *"));
                        }
                    }
                }
            }
        }
        defaulted = copy;
        &defaulted
    } else {
        let mut copy = manifest_json.clone();
        if let Some(functions) = copy
            .get_mut("functions")
            .and_then(serde_json::Value::as_array_mut)
        {
            for function in functions {
                let Some(name) = function
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                else {
                    continue;
                };
                let Some(trigger) = function.get_mut("trigger") else {
                    continue;
                };
                if trigger.get("type").and_then(serde_json::Value::as_str) != Some("schedule") {
                    continue;
                }
                let Some(text) = trigger.get("schedule").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let zone = trigger
                    .get("timeZone")
                    .and_then(serde_json::Value::as_str)
                    .filter(|z| !z.is_empty());
                let parsed = fireemu_core_functions::cron::Schedule::parse(text)
                    .map_err(|e| format!("schedule: {e}"))
                    .and_then(|_| {
                        fireemu_adapter_functions::zone::resolve(zone)
                            .map_err(|e| format!("time zone: {e}"))
                    });
                if let Err(reason) = parsed {
                    unscheduled.insert(name, reason);
                    // Validate the remaining metadata before moving this export to the ignored inventory.
                    // This temporary trigger never reaches the runtime or creates a job.
                    trigger["schedule"] = serde_json::json!("every 5 minutes");
                    trigger["timeZone"] = serde_json::Value::Null;
                }
            }
        }
        defaulted = copy;
        &defaulted
    };
    let mut manifest = parse_manifest(document)?;
    let ignored = &mut manifest.ignored;
    manifest.functions.retain(|function| {
        let Some(reason) = unscheduled.remove(&function.name) else {
            return true;
        };
        ignored.push(fireemu_core_functions::manifest::IgnoredFunction {
            name: function.name.clone(),
            region: function.region.clone(),
            trigger_type: "schedule".to_owned(),
            scope: fireemu_core_functions::manifest::IgnoredScope::Unsupported,
            reason: format!("no scheduled job: {reason}"),
        });
        false
    });
    if profile == CompatibilityProfile::Strict {
        for function in &mut manifest.functions {
            if let fireemu_core_functions::manifest::Trigger::Eventarc {
                channel, filters, ..
            } = &function.trigger
            {
                // Production refused exact source and subject filters on custom-event channels.
                // Source precedence and subject-only refusal are conservative local policies.
                if channel != fireemu_adapter_functions::eventarc::GOOGLE_CHANNEL
                    && (filters.contains_key("source") || filters.contains_key("subject"))
                {
                    let attribute = if filters.contains_key("source") {
                        "source"
                    } else {
                        "subject"
                    };
                    return Err(format!(
                        "manifest: function {:?}: Cloud Functions refuses this Eventarc trigger (HTTP 400): Validation failed for trigger projects/<project>/locations/{}/triggers/<trigger-id>: The request was invalid: invalid filter '{attribute}' in trigger.event_filters: filter '{attribute}' is not allowed for this trigger",
                        function.name, function.region
                    ));
                }
            }
            let fireemu_core_functions::manifest::Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } = &mut function.trigger
            else {
                continue;
            };
            let text = schedule.as_str();
            let lower = text.to_ascii_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            // Calendar v6 cr11 and gr11: production rejects aliases and weekday prefixes.
            let invalid_weekday = match words.as_slice() {
                ["every", days, time] if time.contains(':') && *days != "day" => {
                    days.split(',').any(|day| {
                        !matches!(
                            day,
                            "sun"
                                | "sunday"
                                | "mon"
                                | "monday"
                                | "tue"
                                | "tuesday"
                                | "wed"
                                | "wednesday"
                                | "thu"
                                | "thursday"
                                | "fri"
                                | "friday"
                                | "sat"
                                | "saturday"
                        )
                    })
                }
                _ => false,
            };
            if text.starts_with('@') || invalid_weekday {
                return Err(format!(
                    "manifest: function {:?}: schedule: The provided schedule or timezone are invalid.",
                    function.name
                ));
            }
            // Calendar v6 cr12: a step on a single numeric value does not extend its range.
            if words.len() == 5 {
                let normalized = text
                    .split_whitespace()
                    .map(|field| {
                        field
                            .split(',')
                            .map(|item| match item.split_once('/') {
                                Some((value, _)) if value.parse::<u32>().is_ok() => value,
                                _ => item,
                            })
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                if normalized != text {
                    *schedule = fireemu_core_functions::cron::Schedule::parse(&normalized)
                        .map_err(|e| {
                            format!("manifest: function {:?}: schedule: {e}", function.name)
                        })?;
                }
            }
            let zone = fireemu_adapter_functions::zone::resolve(time_zone.as_deref())
                .map_err(|e| format!("manifest: function {:?}: time zone: {e}", function.name))?;
            // Calendar v6 cr13 is invalid even without DST; ds01 has no occurrence in its zone.
            if schedule.next_after_in(now, &*zone).is_none() {
                // A bounded search cannot prove impossibility. Only the recorded class (cr13: one numeric
                // day of month, numeric months, any day of week "*") is judged impossible structurally.
                let fields: Vec<&str> = schedule.as_str().split_whitespace().collect();
                let impossible = match fields.as_slice() {
                    [_, _, day, months, "*"] => day.parse::<u32>().is_ok_and(|day| {
                        months
                            .split(',')
                            .map(|month| month.parse::<u32>().ok().filter(|m| (1..=12).contains(m)))
                            .collect::<Option<Vec<_>>>()
                            .is_some_and(|months| {
                                months.iter().all(|month| {
                                    day > match month {
                                        2 => 29,
                                        4 | 6 | 9 | 11 => 30,
                                        _ => 31,
                                    }
                                })
                            })
                    }),
                    _ => false,
                };
                let reason = if impossible {
                    "The provided schedule or timezone are invalid."
                } else {
                    "Cannot find next schedule time."
                };
                return Err(format!(
                    "manifest: function {:?}: schedule: {reason}",
                    function.name
                ));
            }
        }
    }
    check_scheduler_refusals_for(profile, &manifest, manifest_json)?;
    serve_blocking_events_for(profile, &mut manifest);
    Ok(manifest)
}

/// Refuses, under the strict profile, a scheduled function whose job production Cloud Scheduler refuses to create,
/// with production's own message (HTTP 400 `INVALID_ARGUMENT`): `retryCount` 6 or more (run `e0ec2f416f5ea7e8`;
/// 0 to 5 are recorded as accepted, the latter by run `156715222b86ea44`) and a fractional `maxRetrySeconds`
/// (`retryConfig.max_retry_duration.nanos cannot be set`, run `156715222b86ea44`). The official emulator never creates
/// a Scheduler job and reads no retry configuration of a schedule trigger, so the emulator profile refuses nothing
/// here. Per function the retry count is judged first (production's order is not recorded).
fn check_scheduler_refusals_for(
    profile: CompatibilityProfile,
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    manifest_json: &serde_json::Value,
) -> Result<(), String> {
    if !refuses_scheduler_limits(profile) {
        return Ok(());
    }
    let fractional = fireemu_adapter_functions::manifest_json::scheduler_fractional_retry_refusals(
        manifest_json,
    );
    for function in &manifest.functions {
        let why = match &function.trigger {
            fireemu_core_functions::manifest::Trigger::Schedule { retry, .. } => {
                retry.scheduler_refusal().or_else(|| {
                    fractional
                        .iter()
                        .find(|(name, _)| *name == function.name)
                        .map(|(_, why)| *why)
                }).or_else(|| {
                    // Calendar v6 rt05: both recordings refuse the inverted backoff range.
                    (retry.min_backoff_seconds > retry.max_backoff_seconds).then_some(
                        "retryConfig.min_backoff_duration must be less than or equal to retryConfig.max_backoff_duration: invalid argument"
                    )
                })
            }
            _ => None,
        };
        if let Some(why) = why {
            return Err(format!(
                "manifest: function {:?}: Cloud Scheduler refuses this schedule's job (HTTP 400 INVALID_ARGUMENT): {why}",
                function.name
            ));
        }
    }
    Ok(())
}

/// Whether `profile` gives a schedule the time zone production's deploy gives it when none is declared: the strict
/// profile does, as production does; the emulator profile keeps the daemon's own default (UTC unless configured).
pub(crate) const fn uses_production_scheduler_defaults(profile: CompatibilityProfile) -> bool {
    matches!(profile, CompatibilityProfile::Strict)
}

/// Gives a first-generation schedule that names no time zone (absent or `null`) `America/Los_Angeles`, the zone the
/// Firebase CLI writes into its Cloud Scheduler job (`DEFAULT_TIME_ZONE_V1`; read back from production for
/// `schedFailV1` in run `156715222b86ea44`, while the second-generation default, UTC, read back for `schedOkV2`).
/// An explicit zone, and the configured `scheduler.defaultTimeZone` (applied before this), win; a second-generation
/// schedule keeps no zone, which evaluates in UTC.
fn apply_first_generation_default_time_zone(manifest: &mut serde_json::Value) {
    let Some(functions) = manifest
        .get_mut("functions")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for function in functions {
        let first_generation = match function.get("generation") {
            None | Some(serde_json::Value::Null) => true,
            Some(generation) => generation.as_u64() == Some(1),
        };
        let Some(trigger) = function.get_mut("trigger") else {
            continue;
        };
        if first_generation
            && trigger.get("type").and_then(serde_json::Value::as_str) == Some("schedule")
            && trigger
                .get("timeZone")
                .is_none_or(serde_json::Value::is_null)
        {
            trigger["timeZone"] = serde_json::Value::String("America/Los_Angeles".to_owned());
        }
    }
}

/// The overlap policy of schedules: the configured `scheduler.overlap` when set, else the profile's own. The strict
/// profile skips an occurrence while a run of the job is in flight, as production does (the `every 1 minutes` job whose
/// handler ran 100 s started only every 2 to 3 minutes, run `156715222b86ea44`); the emulator profile allows overlap, and
/// the official emulator (firebase-tools 15.28.2) never schedules or skips a run.
pub(crate) fn overlap_policy_for(
    profile: CompatibilityProfile,
    configured: Option<&str>,
) -> fireemu_adapter_functions::runtime::OverlapPolicy {
    use fireemu_adapter_functions::runtime::OverlapPolicy;
    match configured {
        Some(text) => OverlapPolicy::parse(text).unwrap_or_default(),
        None if uses_production_scheduler_defaults(profile) => OverlapPolicy::SkipInFlight,
        None => OverlapPolicy::Allow,
    }
}

/// Whether `profile` refuses what production Cloud Scheduler refuses: the strict profile does, as production does.
pub(crate) const fn refuses_scheduler_limits(profile: CompatibilityProfile) -> bool {
    matches!(profile, CompatibilityProfile::Strict)
}

/// Leaves in service the blocking functions `profile` serves: the strict profile serves every
/// Identity Platform event, the emulator profile the official emulator's two.
fn serve_blocking_events_for(
    profile: CompatibilityProfile,
    manifest: &mut fireemu_core_functions::manifest::FunctionManifest,
) {
    if !serves_send_blocking_events(profile) {
        ignore_send_blocking_events(manifest);
    }
}

/// Whether `profile` serves Identity Platform's email and SMS blocking events: the strict
/// profile does, as production does; the emulator profile does not, as the official emulator
/// does not.
pub(crate) const fn serves_send_blocking_events(profile: CompatibilityProfile) -> bool {
    matches!(profile, CompatibilityProfile::Strict)
}

/// Refuses a selection the manifest cannot serve: an explicit function it does not export, or
/// one that is ambiguous or handles another event.
pub(crate) fn check_blocking_auth_selections(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    selections: &fireemu_core_functions::manifest::BlockingAuthSelections,
) -> Result<(), String> {
    for event in fireemu_core_functions::manifest::BlockingAuthEvent::ALL {
        manifest
            .blocking_auth_target(event, selections.for_event(event))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Keeps Identity Platform's email and SMS blocking functions out of service, as the official
/// emulator does (firebase-tools registers `beforeCreate` and `beforeSignIn` only): they stay in
/// the ignored inventory with the reason the runner gave before the strict profile served them.
fn ignore_send_blocking_events(manifest: &mut fireemu_core_functions::manifest::FunctionManifest) {
    use fireemu_core_functions::manifest::{
        BlockingAuthEvent, IgnoredFunction, IgnoredScope, Trigger,
    };

    let (send, served) = std::mem::take(&mut manifest.functions)
        .into_iter()
        .partition::<Vec<_>, _>(|function| {
            matches!(
                function.trigger,
                Trigger::BlockingAuth {
                    event: BlockingAuthEvent::BeforeSendEmail | BlockingAuthEvent::BeforeSendSms,
                    ..
                }
            )
        });
    manifest.functions = served;
    for function in send {
        let Trigger::BlockingAuth { event, .. } = function.trigger else {
            continue;
        };
        manifest.ignored.push(IgnoredFunction {
            name: function.name,
            region: function.region,
            trigger_type: "blocking".to_owned(),
            scope: IgnoredScope::Unsupported,
            reason: format!(
                "blocking identity event {} is not served",
                event.event_type()
            ),
        });
    }
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
            // The runner serves an export by name whatever trigger the manifest gave it, so a
            // real callable listed as a task queue, a blocking function or an event trigger
            // would reach the onCall wrapper without passing the callable trust boundary.
            if callable_in(discovered, &f.name) == Some(true) {
                return Err(format!(
                    "the configured functions manifest declares {:?} as a non-HTTP function, but \
                     the codebase declares it callable; App Check for callables cannot trust a \
                     manifest that disagrees with the code. List it as an http function with \
                     callable: true and the App Check options the code declares, remove it from \
                     the manifest, or export it with onTaskDispatched if it is meant to be a task \
                     queue",
                    f.name
                ));
            }
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
/// A callable that declares `consumeAppCheckToken: true` is not one of those cases (owner
/// decision 1396): replay protection is unimplemented, but the callable proxy keeps it from
/// being silently wrong per call, and [`consume_app_check_note`] says how at startup. Two
/// things have to hold, and each of them is fatal in its own way:
///
/// - with App Check enabled, a callable whose value could not be observed fails startup. The
///   value is never guessed as `false`: the proxy could not tell which calls need consumption;
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
        if *consume_app_check_token == ConsumeAppCheckToken::Undetermined {
            undetermined.push(&f.name);
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

/// What to tell the user about the Admin SDK `verifyToken` instrumentation of one codebase, when
/// it is not in place. `None` when it is, or when the codebase does not use `firebase-admin`.
///
/// Not being in place is never unsafe: the stock SDK then fetches Google's keys, which no
/// fireemu token verifies against, so `verifyToken` rejects fireemu tokens instead of
/// accepting one it cannot check.
fn admin_app_check_note(label: &str, report: Option<&serde_json::Value>) -> Option<String> {
    let Some(report) = report else {
        return Some(format!(
            "functions[{label}]: the runner did not report the firebase-admin App Check instrumentation; \
             getAppCheck().verifyToken() keeps the SDK's own check and rejects fireemu App Check tokens"
        ));
    };
    let state = report
        .get("instrumentation")
        .and_then(serde_json::Value::as_str)?;
    if state == "ok" || state == "not-installed" {
        return None;
    }
    Some(format!(
        "functions[{label}]: getAppCheck().verifyToken() is not verified by the daemon ({state}); the \
         SDK keeps its own check and rejects fireemu App Check tokens"
    ))
}

/// Marks every entry of a configured manifest that serves as something other than a callable an
/// export the codebase's own discovery declares callable (a task queue, another non-HTTP
/// trigger, or an `onRequest` function), and returns their names.
///
/// This is for the strict profile without App Check, where such a manifest still starts (see the
/// gate in `start_codebase`). A request to a callable passes the daemon's Bearer check there; a
/// task or a plain HTTP request delivered to the same export would not, and the callable
/// wrapper's own check under the Auth emulator does not verify signatures. The marker makes the
/// task path and the HTTP route apply the callable check
/// (`PlatformOptions::strict_callable_ingress`).
fn mark_strict_callable_ingress(
    configured: &mut fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Vec<String> {
    use fireemu_core_functions::manifest::Trigger;
    let callable_in_code = |name: &str| {
        discovered
            .functions
            .iter()
            .any(|d| d.name == name && matches!(d.trigger, Trigger::Http { callable: true, .. }))
    };
    let mut marked = Vec::new();
    for f in &mut configured.functions {
        if !matches!(f.trigger, Trigger::Http { callable: true, .. }) && callable_in_code(&f.name) {
            f.platform_options.strict_callable_ingress = true;
            marked.push(f.name.clone());
        }
    }
    marked
}

/// Reconciles a configured manifest's `consumeAppCheckToken` with the code when App Check is
/// disabled, and returns one warning per contradiction.
///
/// With App Check, [`check_manifest_agrees_on_callables`] refuses a manifest that contradicts
/// the code. Without it the codebase still loads (owner decision 1396), but the proxy decides
/// from the served value whether a token may reach the wrapper, and a manifest must not be able
/// to hide consumption from it: the wrapper would pass the token to the Admin SDK's consuming
/// `verifyToken`, which calls production. So, for every callable the code also declares as a
/// callable:
///
/// - an omitted value, or the explicit spelling `undetermined` (they parse alike), is not a
///   claim and takes what the code declares;
/// - an explicit value that differs from the code is served as `Enabled`, whichever side said
///   `true`, and is reported.
///
/// A configured onRequest function keeps its routing, but if the code exports a callable under
/// that name that consumes tokens or could not be observed, the runner still calls that
/// callable's wrapper: the route is served with `Enabled`, which makes the proxy remove the
/// token, and is reported. Every other configured onRequest route is served with
/// `Undetermined`, which the proxy ignores on an onRequest route, whatever the manifest wrote.
fn reconcile_consumption_without_app_check(
    configured: &mut fireemu_core_functions::manifest::FunctionManifest,
    discovered: &fireemu_core_functions::manifest::FunctionManifest,
) -> Vec<String> {
    use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
    let mut warnings = Vec::new();
    for f in &mut configured.functions {
        let Trigger::Http {
            callable,
            consume_app_check_token: configured_value,
            ..
        } = &mut f.trigger
        else {
            continue;
        };
        let code_value = discovered
            .functions
            .iter()
            .find(|d| d.name == f.name)
            .and_then(|d| match d.trigger {
                Trigger::Http {
                    callable: true,
                    consume_app_check_token,
                    ..
                } => Some(consume_app_check_token),
                _ => None,
            });
        if !*callable {
            // The route stays onRequest, but the runner still calls the onCall wrapper the code
            // exports under this name. `Enabled` on an onRequest route tells the proxy to
            // remove the token; any other value there means nothing.
            *configured_value = ConsumeAppCheckToken::Undetermined;
            if let Some(
                code_value @ (ConsumeAppCheckToken::Enabled | ConsumeAppCheckToken::Undetermined),
            ) = code_value
            {
                warnings.push(format!(
                    "the configured functions manifest serves {:?} as an onRequest function, but \
                     the code declares a callable whose consumeAppCheckToken is {:?}; \
                     X-Firebase-AppCheck is removed before it",
                    f.name,
                    code_value.as_str()
                ));
                *configured_value = ConsumeAppCheckToken::Enabled;
            }
            continue;
        }
        let Some(code_value) = code_value else {
            continue;
        };
        if *configured_value == code_value {
            continue;
        }
        if *configured_value == ConsumeAppCheckToken::Undetermined {
            *configured_value = code_value;
            continue;
        }
        warnings.push(format!(
            "the configured functions manifest gives callable {:?} consumeAppCheckToken {:?}, \
             but the code declares {:?}; it is served as token-consuming, so X-Firebase-AppCheck \
             is removed before it",
            f.name,
            configured_value.as_str(),
            code_value.as_str()
        ));
        *configured_value = ConsumeAppCheckToken::Enabled;
    }
    warnings
}

/// Serves every onRequest route of a configured manifest with `Undetermined`, which the proxy
/// ignores there: only [`reconcile_consumption_without_app_check`] may mark an onRequest route
/// as fronting a token-consuming callable. Used with App Check, where a manifest that calls a
/// code-level callable onRequest is already refused.
fn clear_on_request_consumption(manifest: &mut fireemu_core_functions::manifest::FunctionManifest) {
    use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
    for f in &mut manifest.functions {
        if let Trigger::Http {
            callable: false,
            consume_app_check_token,
            ..
        } = &mut f.trigger
        {
            *consume_app_check_token = ConsumeAppCheckToken::Undetermined;
        }
    }
}

/// The startup note for the callables whose App Check token is not passed through as in
/// production, or `None` when there are none.
///
/// Limited-use consumption (`APPCHECK-REPLAY-1`) is unimplemented, so a callable that declares
/// `consumeAppCheckToken: true` can never run exactly as in production. What it does instead
/// depends on the mode:
///
/// - without App Check, the callable proxy removes `X-Firebase-AppCheck` before the runner, for
///   such a callable and for one whose value could not be observed: no token is verified or
///   consumed, and the handler sees no app context. Forwarding the token would let the
///   installed wrapper hand it to the Admin SDK's consuming `verifyToken`, which calls
///   production. A callable that also enforces App Check therefore answers `401` to every call;
/// - with App Check, the proxy refuses a call that presents a valid token with `501
///   UNIMPLEMENTED` (`APP_CHECK_REPLAY_UNSUPPORTED`), because the trusted wrapper would answer
///   it with `alreadyConsumed: false`. Calls without a valid token need no consumption and run
///   (or get `401` from an enforcing callable). An unobserved value fails startup instead.
///
/// TODO(productionExact): when replay protection exists, the production-exact setting should
/// consume tokens as production does; until then there is no production-exact variant.
fn consume_app_check_note(
    manifest: &fireemu_core_functions::manifest::FunctionManifest,
    callable_trusted_protocol: bool,
) -> Option<String> {
    use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
    let mut names = Vec::new();
    let mut enforcing = Vec::new();
    for f in &manifest.functions {
        let Trigger::Http {
            callable: true,
            enforce_app_check,
            consume_app_check_token,
        } = f.trigger
        else {
            continue;
        };
        let listed = match consume_app_check_token {
            ConsumeAppCheckToken::Enabled => true,
            ConsumeAppCheckToken::Undetermined => !callable_trusted_protocol,
            ConsumeAppCheckToken::Disabled => false,
        };
        if listed {
            names.push(format!("{:?}", f.name));
            if enforce_app_check {
                enforcing.push(format!("{:?}", f.name));
            }
        }
    }
    if names.is_empty() {
        return None;
    }
    let names = names.join(", ");
    Some(if callable_trusted_protocol {
        format!(
            "callable(s) {names} declare consumeAppCheckToken: true, but limited-use token \
             consumption is not implemented (APP_CHECK_REPLAY_UNSUPPORTED); a call that presents \
             a valid App Check token is refused with 501 UNIMPLEMENTED, and calls without one run"
        )
    } else {
        let outcome = if enforcing.is_empty() {
            "they run without App Check".to_owned()
        } else {
            format!(
                "those that set enforceAppCheck: {} therefore answer 401 UNAUTHENTICATED to \
                 every call",
                enforcing.join(", ")
            )
        };
        format!(
            "callable(s) {names} declare consumeAppCheckToken: true or could not be observed; App \
             Check is disabled, so X-Firebase-AppCheck is removed before the handler, no token is \
             consumed and replay protection is not applied; {outcome}"
        )
    })
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
            StorageEvent::Finalized(m) | StorageEvent::MetadataUpdated(m) => m.bucket.as_str(),
            StorageEvent::Deleted { object, .. } | StorageEvent::Archived { object, .. } => {
                object.bucket.as_str()
            }
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
    production_token: Option<Arc<dyn fireemu_core_auth::jwt::IdTokenSigner>>,
    deadline: Duration,
    forward_inbound_credentials: bool,
    settings: Arc<RwLock<BlockingAuthSettings>>,
    settings_revision: AtomicU64,
    /// Whether Identity Platform's email and SMS events are served (the strict profile; the
    /// official emulator serves `beforeCreate` and `beforeSignIn` only).
    send_events: bool,
    /// When each event's trigger last changed ([`BlockingAuthEvent::ALL`](fireemu_core_functions::manifest::BlockingAuthEvent::ALL) order): when the
    /// bridge was built, or when a settings update changed that event's selection.
    trigger_times: RwLock<[fireemu_core_types::time::LogicalInstant; 4]>,
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

/// How long the official Auth emulator waits for a blocking function (firebase-tools 15.28.2
/// `fetchBlockingFunction`, `timeoutMs = 60000`).
const BLOCKING_AUTH_EMULATOR_DEADLINE: Duration = Duration::from_secs(60);

/// The blocking-function deadline of `profile`: Identity Platform's seven seconds in the strict
/// profile, the official emulator's sixty in the emulator profile, so a function the official
/// emulator waits for is not refused there (closure review M1, 2026-09-28).
pub(crate) const fn blocking_auth_deadline(profile: CompatibilityProfile) -> Duration {
    match profile {
        CompatibilityProfile::Strict => BLOCKING_AUTH_DEADLINE,
        CompatibilityProfile::Emulator => BLOCKING_AUTH_EMULATOR_DEADLINE,
    }
}

/// Identity Platform's email and SMS events, which only the strict profile serves.
const fn is_send_event(event: fireemu_core_functions::manifest::BlockingAuthEvent) -> bool {
    matches!(
        event,
        fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSendEmail
            | fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSendSms
    )
}
const MAX_BLOCKING_AUTH_RESPONSE_BYTES: u64 = 64 * 1024;

/// The request values a blocking token names, which fireemu cannot know from a loopback client:
/// the official Auth emulator's fixed values (firebase-tools 15.28.2 `generateBlockingFunctionJwt`).
const BLOCKING_AUTH_USER_AGENT: &str = "NotYetSupportedInFirebaseAuthEmulator";
const BLOCKING_AUTH_IP_ADDRESS: &str = "127.0.0.1";
const BLOCKING_AUTH_LOCALE: &str = "en";

fn epoch_millis(at: fireemu_core_types::time::LogicalInstant) -> serde_json::Value {
    serde_json::json!(i64::try_from(at.as_nanos() / 1_000_000).unwrap_or_default())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockingTokenShape {
    Emulated,
    Production,
}

/// The token's `user_record`: the account's members, with production's absent members left out.
fn blocking_auth_user_record(
    tenant: Option<&str>,
    request: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    user: &fireemu_core_auth::store::UserRecord,
    shape: BlockingTokenShape,
) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::{json, Map, Value};
    let mut record = Map::new();
    record.insert("uid".to_owned(), json!(user.local_id.as_str()));
    if let Some(email) = &user.email {
        record.insert("email".to_owned(), json!(email));
        record.insert("email_verified".to_owned(), json!(user.email_verified));
    }
    if let Some(name) = &user.display_name {
        record.insert("display_name".to_owned(), json!(name));
    }
    if let Some(photo) = &user.photo_url {
        record.insert("photo_url".to_owned(), json!(photo));
    }
    if let Some(phone) = &user.phone_number {
        record.insert("phone_number".to_owned(), json!(phone));
    }
    if shape == BlockingTokenShape::Emulated || user.disabled {
        record.insert("disabled".to_owned(), json!(user.disabled));
    }
    if let Some(claims) = user
        .custom_claims
        .attributes_text()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
    {
        record.insert("custom_claims".to_owned(), claims);
    }
    if let Some(tenant) = tenant {
        record.insert("tenant_id".to_owned(), json!(tenant));
    }
    let optional = |value: &Option<String>| value.as_ref().map_or(Value::Null, |text| json!(text));
    record.insert(
        "provider_data".to_owned(),
        Value::Array(
            request
                .provider_data
                .iter()
                .map(|provider| {
                    let mut entry = Map::new();
                    entry.insert("provider_id".to_owned(), json!(provider.provider_id));
                    entry.insert("uid".to_owned(), json!(provider.uid));
                    for (key, value) in [
                        ("display_name", optional(&provider.display_name)),
                        ("email", optional(&provider.email)),
                        ("photo_url", optional(&provider.photo_url)),
                        ("phone_number", optional(&provider.phone_number)),
                    ] {
                        if !value.is_null() {
                            entry.insert(key.to_owned(), value);
                        }
                    }
                    Value::Object(entry)
                })
                .collect(),
        ),
    );
    if !request.enrolled_factors.is_empty() {
        let factors = request
            .enrolled_factors
            .iter()
            .map(|factor| {
                let mut entry = Map::new();
                entry.insert("uid".to_owned(), json!(factor.uid));
                entry.insert("factor_id".to_owned(), json!(factor.factor_id));
                for (key, value) in [
                    ("display_name", optional(&factor.display_name)),
                    ("enrollment_time", optional(&factor.enrollment_time)),
                    ("phone_number", optional(&factor.phone_number)),
                ] {
                    if !value.is_null() {
                        entry.insert(key.to_owned(), value);
                    }
                }
                Value::Object(entry)
            })
            .collect::<Vec<_>>();
        record.insert(
            "multi_factor".to_owned(),
            json!({"enrolled_factors": factors}),
        );
    }
    let mut metadata = Map::new();
    metadata.insert("creation_time".to_owned(), epoch_millis(user.created_at));
    if let Some(at) = user.last_sign_in_at {
        metadata.insert("last_sign_in_time".to_owned(), epoch_millis(at));
    }
    record.insert("metadata".to_owned(), Value::Object(metadata));
    record
}

/// The claims of the blocking token Identity Platform delivers (`{"data":{"jwt":…}}`), which
/// the function's firebase-functions decodes into its event (AUTH-TENANT-BLOCKING comparison
/// 2026-09-28). The claims follow the official Auth emulator's token, with production's absent
/// members: a member the account does not have is left out, `email_verified` comes with an
/// address, `custom_claims` only when claims are set, and `multi_factor` only with a factor.
#[allow(clippy::too_many_arguments)]
fn blocking_auth_claims(
    project: &str,
    tenant: Option<&str>,
    event: fireemu_core_functions::manifest::BlockingAuthEvent,
    request: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    user: Option<&fireemu_core_auth::store::UserRecord>,
    event_id: &str,
    issued_at: i64,
    audience: &str,
    shape: BlockingTokenShape,
) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::{json, Map, Value};

    let mut claims = Map::new();
    claims.insert(
        "iss".to_owned(),
        json!(format!("https://securetoken.google.com/{project}")),
    );
    claims.insert("aud".to_owned(), json!(audience));
    claims.insert("iat".to_owned(), json!(issued_at));
    // The official emulator's lifetime: the deadline in milliseconds divided by 100.
    claims.insert(
        "exp".to_owned(),
        json!(
            issued_at
                + if shape == BlockingTokenShape::Production {
                    300
                } else {
                    70
                }
        ),
    );
    claims.insert("event_id".to_owned(), json!(event_id));
    claims.insert("event_type".to_owned(), json!(event.as_str()));
    claims.insert("user_agent".to_owned(), json!(BLOCKING_AUTH_USER_AGENT));
    claims.insert("ip_address".to_owned(), json!(BLOCKING_AUTH_IP_ADDRESS));
    claims.insert(
        "locale".to_owned(),
        json!(if shape == BlockingTokenShape::Production {
            "und"
        } else {
            BLOCKING_AUTH_LOCALE
        }),
    );
    // A mail event has no user: its token names the address and the kind of mail instead.
    if let Some(user) = user {
        claims.insert("sub".to_owned(), json!(user.local_id.as_str()));
        claims.insert(
            "user_record".to_owned(),
            Value::Object(blocking_auth_user_record(tenant, request, user, shape)),
        );
    }
    if let Some(email) = &request.email {
        claims.insert("email".to_owned(), json!(email));
    }
    if let Some(email_type) = &request.email_type {
        claims.insert("email_type".to_owned(), json!(email_type));
    }
    if let Some(method) = &request.sign_in_method {
        claims.insert("sign_in_method".to_owned(), json!(method));
    }
    if let Some(profile) = request
        .additional_user_info
        .as_ref()
        .and_then(|info| info.profile.as_ref())
    {
        claims.insert("raw_user_info".to_owned(), json!(profile.to_string()));
    }
    if let Some(tenant) = tenant {
        claims.insert("tenant_id".to_owned(), json!(tenant));
    }
    if let Some(credential) = &request.credential {
        if let Some(attributes) = &credential.claims {
            claims.insert("sign_in_attributes".to_owned(), attributes.clone());
        }
        for (key, value) in [
            ("oauth_access_token", &credential.access_token),
            ("oauth_id_token", &credential.id_token),
            ("oauth_refresh_token", &credential.refresh_token),
        ] {
            if let Some(token) = value {
                claims.insert(key.to_owned(), json!(token));
            }
        }
    }
    claims
}

fn production_blocking_audience(project: &str, region: &str, function: &str) -> String {
    format!("https://{region}-{project}.cloudfunctions.net/{function}")
}

fn signed_blocking_jwt(
    claims: &serde_json::Map<String, serde_json::Value>,
    signer: &dyn fireemu_core_auth::jwt::IdTokenSigner,
) -> String {
    fireemu_core_auth::jwt::encode_payload_with(
        &serde_json::Value::Object(claims.clone()).to_string(),
        Some(signer),
    )
}

/// An unsigned (`alg: none`) JWT of `claims`, as the official Auth emulator sends it.
fn unsigned_jwt(claims: &serde_json::Map<String, serde_json::Value>) -> String {
    let header = serde_json::json!({"alg": "none", "typ": "JWT"}).to_string();
    let payload = serde_json::Value::Object(claims.clone()).to_string();
    format!(
        "{}.{}.",
        fireemu_core_auth::jwt::base64url_encode(header.as_bytes()),
        fireemu_core_auth::jwt::base64url_encode(payload.as_bytes())
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

/// How long a blocking call waits, and whether the function's own timeout is what elapses: a
/// function whose timeout is within Identity Platform's deadline is stopped by its platform
/// first (production run 2026-09-02, a seven-second function sleeping eleven); otherwise the
/// deadline elapses first (AUTH-TENANT-BLOCKING recording 2026-09-28, timeout#*).
fn blocking_auth_wait(timeout_seconds: u32, deadline: Duration) -> (Duration, bool) {
    let own = Duration::from_secs(u64::from(timeout_seconds));
    if timeout_seconds > 0 && own <= deadline {
        (own, true)
    } else {
        (deadline, false)
    }
}

/// The answer to a call whose wait elapsed: the function's own timeout is masked as its
/// platform's 5xx answer is; Identity Platform's deadline answers its own 400.
fn blocking_auth_elapsed(
    failure: fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    own_timeout_first: bool,
) -> fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure {
    if failure.is_deadline() && own_timeout_first {
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::function_timeout()
    } else {
        failure
    }
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
        let runtime_now = runtime.now();
        Ok(Self {
            runtime,
            production_token: None,
            deadline: BLOCKING_AUTH_DEADLINE,
            forward_inbound_credentials,
            settings: Arc::new(RwLock::new(BlockingAuthSettings {
                selections,
                forwarding_restrictions,
            })),
            settings_revision: AtomicU64::new(0),
            send_events: false,
            trigger_times: RwLock::new([runtime_now; 4]),
        })
    }

    /// Signs production-shaped blocking tokens with the in-memory blocking key.
    #[must_use]
    pub fn with_production_token(
        mut self,
        signer: Option<Arc<dyn fireemu_core_auth::jwt::IdTokenSigner>>,
    ) -> Self {
        self.production_token = signer;
        self
    }

    /// Serves Identity Platform's email and SMS events too, as production does (the strict
    /// profile). `beforeSendSms` is listed but never run: no SMS it would gate is recorded.
    #[must_use]
    pub const fn with_send_events(mut self, enabled: bool) -> Self {
        self.send_events = enabled;
        self
    }

    /// Serves the events and waits the deadline of `profile`: what the daemon builds (closure
    /// re-review, 2026-09-28).
    #[must_use]
    pub const fn for_profile(self, profile: CompatibilityProfile) -> Self {
        self.with_send_events(serves_send_blocking_events(profile))
            .with_deadline_for(profile)
    }

    /// Waits for a function as `profile` does ([`blocking_auth_deadline`]).
    #[must_use]
    pub const fn with_deadline_for(mut self, profile: CompatibilityProfile) -> Self {
        self.deadline = blocking_auth_deadline(profile);
        self
    }

    /// The events this bridge serves, in Identity Platform's configuration order.
    fn served_events(
        &self,
    ) -> impl Iterator<Item = fireemu_core_functions::manifest::BlockingAuthEvent> + '_ {
        fireemu_core_functions::manifest::BlockingAuthEvent::ALL
            .into_iter()
            .filter(|event| self.send_events || !is_send_event(*event))
    }

    /// The served event a configuration key names.
    fn served_event_named(
        &self,
        name: &str,
    ) -> Option<fireemu_core_functions::manifest::BlockingAuthEvent> {
        self.served_events().find(|event| event.as_str() == name)
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
                before_sign_in: selection.clone(),
                before_send_email: selection.clone(),
                before_send_sms: selection,
            },
            forward_inbound_credentials,
        )
    }

    #[cfg(test)]
    fn with_deadline(runtime: Arc<FunctionsRuntime>, deadline: Duration) -> Self {
        Self {
            runtime,
            production_token: None,
            deadline,
            forward_inbound_credentials: false,
            settings: Arc::new(RwLock::new(BlockingAuthSettings {
                selections: fireemu_core_functions::manifest::BlockingAuthSelections::default(),
                forwarding_restrictions: None,
            })),
            settings_revision: AtomicU64::new(0),
            send_events: false,
            trigger_times: RwLock::new([fireemu_core_types::time::LogicalInstant::UNIX_EPOCH; 4]),
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
            let now = self.runtime.now();
            if let Ok(mut times) = self.trigger_times.write() {
                for (index, event) in fireemu_core_functions::manifest::BlockingAuthEvent::ALL
                    .into_iter()
                    .enumerate()
                {
                    if current.selections.for_event(event) != settings.selections.for_event(event) {
                        times[index] = now;
                    }
                }
            }
            *current = settings;
            self.settings_revision.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    /// The served events' effective functions, as Identity Platform's configuration lists its
    /// triggers: an explicit selection's function, or the discovered one.
    fn blocking_auth_trigger_list(
        &self,
    ) -> Vec<fireemu_adapter_http::identity_toolkit::BlockingAuthTrigger> {
        let Ok(settings) = self.settings_snapshot() else {
            return Vec::new();
        };
        let times = self
            .trigger_times
            .read()
            .map(|times| *times)
            .unwrap_or([fireemu_core_types::time::LogicalInstant::UNIX_EPOCH; 4]);
        fireemu_core_functions::manifest::BlockingAuthEvent::ALL
            .into_iter()
            .enumerate()
            .filter(|(_, event)| self.served_event_named(event.as_str()).is_some())
            .filter_map(|(index, event)| {
                let spec = self
                    .runtime
                    .manifest()
                    .blocking_auth_target(event, settings.selections.for_event(event))
                    .ok()
                    .flatten()?;
                Some(
                    fireemu_adapter_http::identity_toolkit::BlockingAuthTrigger {
                        event,
                        function: spec.name.clone(),
                        region: spec.region.clone(),
                        update_time: times[index],
                    },
                )
            })
            .collect()
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
                    if self.served_event_named(event).is_none() {
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
                    .any(|key| self.served_event_named(key).is_none())
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
                let mut selections =
                    fireemu_core_functions::manifest::BlockingAuthSelections::default();
                for event in self.served_events() {
                    *selections.for_event_mut(event) = parse(event.as_str())?;
                }
                selections
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
        for event in self.served_events() {
            self.runtime
                .manifest()
                .blocking_auth_target(event, selections.for_event(event))
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
        for event in self.served_events() {
            let event_name = event.as_str();
            let selection = settings.selections.for_event(event);
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
        for event in self.served_events() {
            self.runtime
                .manifest()
                .blocking_auth_target(event, settings.selections.for_event(event))
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
                    trigger_field
                        if trigger_field
                            .strip_prefix("blockingFunctions.triggers.")
                            .and_then(|event| self.served_event_named(event))
                            .is_some() =>
                    {
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
                        let served = self
                            .served_event_named(event)
                            .ok_or_else(|| "invalid blocking trigger field".to_owned())?;
                        *next.selections.for_event_mut(served) =
                            parsed.selections.for_event(served).clone();
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
        for event in self.served_events() {
            self.runtime
                .manifest()
                .blocking_auth_target(event, next.selections.for_event(event))
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
        user: Option<&fireemu_core_auth::store::UserRecord>,
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
        user: Option<&fireemu_core_auth::store::UserRecord>,
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
        // Bounds admission, a runner recovery and the call after a recovery.
        let admission_deadline = Instant::now() + self.deadline;
        let first_admission = self
            .runtime
            .try_admit_blocking_auth_for(event, selected_function);
        let recovered = first_admission.is_err();
        let admitted = if let Ok(admitted) = first_admission {
            admitted
        } else {
            let handle = tokio::runtime::Handle::try_current()
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            handle
                .block_on(async {
                    tokio::time::timeout_at(
                        tokio::time::Instant::from_std(admission_deadline),
                        self.runtime
                            .recover_blocking_auth_runner_for(event, selected_function),
                    )
                    .await
                })
                .map_err(|_| BlockingFunctionFailure::timeout())?
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            // A recovered runner is healthy even when the caller's admission deadline has
            // expired. Return the local timeout before reserving a slot or recycling it.
            blocking_auth_remaining(admission_deadline)?;
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
        let synchronize_date = self.runtime.application_clock_policy().date_virtual;
        if synchronize_date {
            let handle = tokio::runtime::Handle::try_current()
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            handle
                .block_on(tokio::time::timeout_at(
                    tokio::time::Instant::from_std(admission_deadline),
                    self.runtime.sync_blocking_auth_clock(&target),
                ))
                .map_err(|_| BlockingFunctionFailure::timeout())?
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
        }
        let context = narrow_blocking_auth_credentials(
            context,
            self.forward_inbound_credentials,
            target.token_policy,
            settings.forwarding_restrictions,
        );
        let path = format!(
            "/{}/{}/{}",
            self.runtime.project(),
            target.region,
            target.function
        );
        let issued_at = if self.production_token.is_some() {
            i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )
            .unwrap_or_default()
        } else {
            i64::try_from(self.runtime.now().as_nanos() / 1_000_000_000).unwrap_or_default()
        };
        let audience = self.production_token.as_ref().map_or_else(
            || format!("http://{}{path}", target.addr),
            |_| {
                production_blocking_audience(
                    self.runtime.project(),
                    &target.region,
                    &target.function,
                )
            },
        );
        let shape = if self.production_token.is_some() {
            BlockingTokenShape::Production
        } else {
            BlockingTokenShape::Emulated
        };
        let claims = blocking_auth_claims(
            project,
            tenant,
            event,
            &context,
            user,
            &format!("fireemu-blocking-{}", self.runtime.trigger_generation()),
            issued_at,
            &audience,
            shape,
        );
        // The token the function's firebase-functions decodes into its event, as Identity
        // Platform and the official Auth emulator deliver it.
        let (jwt, content_type, user_agent) = match &self.production_token {
            Some(signer) => (
                signed_blocking_jwt(&claims, signer.as_ref()),
                "application/json; charset=utf-8",
                "User-Agent: Google-Firebase\r\n",
            ),
            None => (unsigned_jwt(&claims), "application/json", ""),
        };
        let body = serde_json::json!({"data": {"jwt": jwt}}).to_string();
        // Recovery and virtual-clock acknowledgement share the platform's native deadline.
        // A warm native-clock runner keeps its full budget; a function with an equal own
        // timeout still times out before the platform envelope.
        let budget = if recovered || synchronize_date {
            blocking_auth_remaining(admission_deadline)?
        } else {
            self.deadline
        };
        let (wait, own_timeout_first) = blocking_auth_wait(target.timeout_seconds, budget);
        let deadline = Instant::now() + wait;
        let exchange = (|| {
            let address = target
                .addr
                .parse()
                .map_err(|_| BlockingFunctionFailure::unhandled())?;
            let mut stream =
                TcpStream::connect_timeout(&address, blocking_auth_remaining(deadline)?)
                    .map_err(|error| blocking_auth_io_failure(&error))?;
            let request = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\n{user_agent}X-Fireemu-Runner-Secret: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
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
                return Err(blocking_auth_elapsed(failure, own_timeout_first));
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
        // beforeSendSms is listed, never run (no SMS it would gate is recorded).
        if event == fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSendSms
            || self.served_events().all(|served| served != event)
        {
            return false;
        }
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
            Some(user),
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
            Some(user),
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
        self.invoke_for_namespace(project, tenant, event, Some(user), context)
    }

    fn blocking_auth_triggers(
        &self,
    ) -> Vec<fireemu_adapter_http::identity_toolkit::BlockingAuthTrigger> {
        self.blocking_auth_trigger_list()
    }

    fn invoke_before_send_email(
        &self,
        project: &str,
        context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<
        Option<serde_json::Value>,
        fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure,
    > {
        let event = fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSendEmail;
        if !self.handles(event) {
            return Ok(None);
        }
        self.invoke_for_namespace(project, None, event, None, context)
    }
}

/// Gives every schedule trigger that names no time zone (absent or `null`) the configured
/// default (`scheduler.defaultTimeZone`). An explicit zone wins, and nothing but a schedule
/// trigger is touched.
fn apply_default_time_zone(manifest: &mut serde_json::Value, zone: &str) {
    let Some(functions) = manifest
        .get_mut("functions")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for function in functions {
        let Some(trigger) = function.get_mut("trigger") else {
            continue;
        };
        if trigger.get("type").and_then(serde_json::Value::as_str) == Some("schedule")
            && trigger
                .get("timeZone")
                .is_none_or(serde_json::Value::is_null)
        {
            trigger["timeZone"] = serde_json::Value::String(zone.to_owned());
        }
    }
}

/// The control API's view of a refused manual schedule run: a capacity refusal stays one, so
/// the route can answer 429 instead of 400.
fn run_schedule_error(
    error: fireemu_adapter_functions::runtime::ScheduleRunError,
) -> fireemu_adapter_http::control::RunScheduleError {
    use fireemu_adapter_functions::runtime::ScheduleRunError;
    use fireemu_adapter_http::control::RunScheduleError;
    match error {
        ScheduleRunError::Refused(message) => RunScheduleError::Refused(message),
        ScheduleRunError::Capacity(message) => RunScheduleError::Capacity(message),
    }
}

/// The runtime as the control API's hook.
pub struct Hook(pub Arc<FunctionsRuntime>);

impl FunctionsHook for Hook {
    fn publish_remote_config(
        &self,
        body: &serde_json::Value,
    ) -> Result<usize, fireemu_adapter_http::control::PublishEventError> {
        use fireemu_adapter_functions::runtime::SourceEventAdmissionError;
        use fireemu_adapter_http::control::PublishEventError;
        self.0
            .publish_remote_config(body)
            .map_err(|error| match error {
                SourceEventAdmissionError::InvalidEvent
                | SourceEventAdmissionError::PayloadTooLarge => PublishEventError::Invalid,
                SourceEventAdmissionError::Capacity => PublishEventError::Capacity,
                SourceEventAdmissionError::Unavailable => PublishEventError::Unavailable,
            })
    }

    fn validate_clock_target(
        &self,
        instant: fireemu_core_types::time::LogicalInstant,
    ) -> Result<(), String> {
        self.0.validate_clock(instant)
    }
    fn sync_clock(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(self.0.sync_clock())
    }
    fn run_due(
        &self,
        budget: usize,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<serde_json::Value, String>> + Send + '_>,
    > {
        Box::pin(self.0.run_due(budget))
    }
    fn on_clock_changed(&self) {
        self.0.on_clock_changed();
    }

    fn run_schedule(
        &self,
        function: &str,
    ) -> Result<(), fireemu_adapter_http::control::RunScheduleError> {
        self.0.run_schedule(function).map_err(run_schedule_error)
    }

    fn is_task_queue(&self, function: &str) -> bool {
        self.0.manifest().get(function).is_some_and(|spec| {
            matches!(
                spec.trigger,
                fireemu_core_functions::manifest::Trigger::TaskQueue { .. }
            )
        })
    }

    fn run_tasks_now(&self, function: &str, task: Option<&str>) -> usize {
        self.0.run_tasks_now(function, task)
    }

    fn is_idle(&self) -> bool {
        self.0.is_idle()
    }

    fn is_idle_with_scope(&self, scope: fireemu_adapter_http::control::IdleScope) -> bool {
        self.0
            .is_idle_with_scope(scope == fireemu_adapter_http::control::IdleScope::Runnable)
    }

    fn idle_diagnostics(
        &self,
        _scope: fireemu_adapter_http::control::IdleScope,
    ) -> serde_json::Value {
        self.0.task_idle_diagnostics()
    }

    fn idle_notify(&self) -> Arc<tokio::sync::Notify> {
        self.0.idle_notify()
    }

    fn status(&self) -> serde_json::Value {
        self.0.status()
    }

    fn publish(
        &self,
        topic: &str,
        messages: &[serde_json::Value],
    ) -> Result<Vec<String>, fireemu_adapter_http::control::PublishMessagesError> {
        use fireemu_adapter_functions::runtime::SourceEventAdmissionError;
        use fireemu_adapter_http::control::PublishMessagesError;
        if topic.is_empty() || topic.len() > 255 {
            return Err(PublishMessagesError::Invalid(
                "topic must be 1..=255 characters".to_owned(),
            ));
        }
        self.0
            .publish(topic, messages)
            .map_err(|error| match error {
                SourceEventAdmissionError::Capacity => PublishMessagesError::Capacity,
                SourceEventAdmissionError::Unavailable => PublishMessagesError::Unavailable,
                SourceEventAdmissionError::InvalidEvent
                | SourceEventAdmissionError::PayloadTooLarge => {
                    PublishMessagesError::Invalid("the message cannot become an event".to_owned())
                }
            })
    }

    fn project(&self) -> String {
        self.0.project().to_owned()
    }
}

/// Whether a schedule's message is published to its topic: the strict profile does, as Cloud Scheduler does, when a
/// Pub/Sub broker is served to publish into.
pub(crate) const fn publishes_schedule_messages(
    pubsub_served: bool,
    profile: CompatibilityProfile,
) -> bool {
    pubsub_served && uses_production_scheduler_defaults(profile)
}

/// Publishes the message of a first-generation schedule run to its topic in the Pub/Sub broker, as Cloud Scheduler does
/// in production (strict profile): the message has the attribute `scheduled: "true"` and no data, the id and the publish
/// time the handler's context reports. The runtime still delivers the schedule event to the handler itself, so the
/// topic's subscribers are the only other readers; a publication refusal prevents handler invocation.
pub struct PubSubSchedulePublisher {
    handle: fireemu_adapter_pubsub::PubSubHandle,
    project: String,
}

impl PubSubSchedulePublisher {
    /// Publishes through `handle` into `project`'s topics.
    #[must_use]
    pub fn new(handle: fireemu_adapter_pubsub::PubSubHandle, project: &str) -> Self {
        Self {
            handle,
            project: project.to_owned(),
        }
    }
}

impl fireemu_adapter_functions::runtime::ScheduleTopicPublisher for PubSubSchedulePublisher {
    fn publish(
        &self,
        topic: &str,
        message_id: &str,
        at: fireemu_core_types::time::LogicalInstant,
    ) -> Result<(), String> {
        let topic = fireemu_core_pubsub::TopicName::new(&self.project, topic)
            .map_err(|error| error.to_string())?;
        let message = fireemu_core_pubsub::PubsubMessage {
            data: Vec::new(),
            attributes: BTreeMap::from([("scheduled".to_owned(), "true".to_owned())]),
            ordering_key: String::new(),
        };
        self.handle
            .publish_scheduler_message(&topic, message, message_id.to_owned(), at)
            .map(|_| ())
            .map_err(|error| error.to_string())
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
        self.reserve_publication(topic, messages, false)
    }

    fn reserve_scheduler(
        &self,
        topic: &str,
        messages: &[fireemu_adapter_pubsub::BridgeMessage],
    ) -> Result<
        Box<dyn fireemu_adapter_pubsub::TopicDeliveryReservation>,
        fireemu_adapter_pubsub::TopicDeliveryError,
    > {
        self.reserve_publication(topic, messages, true)
    }
}

impl PubSubBridge {
    fn reserve_publication(
        &self,
        topic: &str,
        messages: &[fireemu_adapter_pubsub::BridgeMessage],
        scheduler: bool,
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
        let reservation = if scheduler {
            self.0
                .reserve_scheduler_pubsub_events(topic.topic(), &values)
        } else {
            self.0.reserve_pubsub_events(topic.topic(), &values)
        };
        reservation
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
                fireemu_adapter_functions::runtime::SourceEventAdmissionError::InvalidEvent
                | fireemu_adapter_functions::runtime::SourceEventAdmissionError::PayloadTooLarge => {
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
        admin_app_check_note, blocking_auth_io_failure, blocking_auth_read_response,
        blocking_auth_response_failure, blocking_auth_write_request, changed_source_stamp,
        check_callable_app_check, clear_on_request_consumption, consume_app_check_note,
        function_pubsub_resources, functions_source_stamp, functions_source_stamp_with_charge,
        functions_source_stamp_with_file_version, hash_source_file, hash_source_stamp_entry,
        load_user_environment, node_engine_matches, owned_pubsub_topic, package_node_engine,
        parse_node_version, provision_function_pubsub_resources,
        reconcile_consumption_without_app_check, select_node_installation,
        snapshot_functions_source, source_scan_pacing_delay, source_scan_retry_delay,
        storage_trigger_buckets, stream_source_chunks, update_watch_hash,
        validate_functions_codebase_budget, wait_for_fixed_inspector_port_release,
        warn_reload_once, BlockingAuthBridge, FunctionsSourceByteBudget,
        FunctionsSourceEntryBudget, FunctionsSourceFileVersion, FunctionsSourceScanBudget,
        FunctionsSourceSnapshot, FunctionsSourceStamp, FunctionsSourceTraversal, NodeInstallation,
        PubSubBridge, PubSubSchedulePublisher, UserEnvironment, BLOCKING_AUTH_DEADLINE,
        MAX_BLOCKING_AUTH_RESPONSE_BYTES, MAX_FUNCTIONS_SOURCE_BYTES, MAX_FUNCTIONS_SOURCE_ENTRIES,
        MAX_FUNCTIONS_SOURCE_WATCH_BYTES_PER_SECOND, MAX_FUNCTIONS_SOURCE_WATCH_FILES_PER_SECOND,
        SOURCE_IO_BUFFER_BYTES,
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
    use crate::config::CompatibilityProfile;
    use fireemu_adapter_functions::manifest_json::parse_manifest;
    use fireemu_core_pubsub::{
        Filter, PubSubState, PushConfig, SubscriptionConfig, SubscriptionName, TopicName,
    };
    use fireemu_core_session::clock::VirtualClock;
    use serde_json::json;

    async fn database_bridge_runtime() -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>
    {
        database_bridge_runtime_with(
            &json!({"functions":[{"name":"databaseChanged","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/users/{uid}"
            }}]}),
        )
        .await
    }

    async fn database_bridge_runtime_with(
        manifest: &serde_json::Value,
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        database_bridge_runtime_shaped(
            manifest,
            fireemu_adapter_functions::events::DatabaseEventShape::default(),
        )
        .await
    }

    /// The emulator profile's runtime: it has no event size limit, so an event larger than a frame (or a
    /// fanout larger than the budget) is dropped and the write applied.
    async fn database_bridge_emulator_runtime_with(
        manifest: &serde_json::Value,
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        database_bridge_runtime_shaped(
            manifest,
            fireemu_adapter_functions::events::DatabaseEventShape::Official,
        )
        .await
    }

    async fn database_bridge_runtime_shaped(
        manifest: &serde_json::Value,
        shape: fireemu_adapter_functions::events::DatabaseEventShape,
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_core_types::time::LogicalInstant;
        // Framing only: these projection/admission tests open no TCP listener.
        let script = r"
import json,sys
value=json.dumps({'type':'hello','runner':'database-bridge-test'}).encode()
sys.stdout.buffer.write(str(len(value)).encode()+b'\n'+value)
sys.stdout.buffer.flush()
while True:
    line=sys.stdin.buffer.readline()
    if not line: break
    value=json.loads(sys.stdin.buffer.read(int(line)))
    if value.get('type')=='shutdown': break
";
        let runner = Runner::spawn_spec(&SpawnSpec {
            command: vec!["python3".to_owned(), "-c".to_owned(), script.to_owned()],
            cwd: None,
            env: Vec::new(),
            hello_timeout: Duration::from_secs(10),
        })
        .await
        .unwrap();
        let manifest = parse_manifest(manifest).unwrap();
        FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                database_event_shape: shape,
                ..FunctionsConfig::for_tests(1000, "test".to_owned())
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(100),
            ))),
            Arc::new(runner),
            None,
        )
    }

    fn database_bridge_write(
        database: &mut fireemu_adapter_database::rest::Database,
        value: &serde_json::Value,
    ) -> u16 {
        use fireemu_adapter_database::rest::{Handled, HttpRequest};
        match database.handle(
            &HttpRequest {
                method: "PUT".to_owned(),
                target: "/.json?ns=demo-app-default-rtdb".to_owned(),
                headers: Vec::new(),
                body: serde_json::to_vec(value).unwrap(),
            },
            100_000,
        ) {
            Handled::Response { response, .. } => response.status,
            Handled::Stream { .. } => panic!("a PUT must not create a stream"),
        }
    }

    fn database_bridge_tree(value: &serde_json::Value) -> fireemu_adapter_database::changes::Tree {
        use fireemu_adapter_database::rest::{Database, RestOptions};
        let mut database = Database::new(RestOptions::default(), 1);
        assert_eq!(database_bridge_write(&mut database, value), 200);
        database.tree("demo-app-default-rtdb").unwrap().clone()
    }

    #[tokio::test]
    async fn database_bridge_scopes_project_fallback_instance_and_region() {
        let runtime = database_bridge_runtime().await;
        let sink = super::database_sink(&runtime, "demo-app", "us-central1", "firebaseio.com");
        assert!(sink.interested("demo-app-default-rtdb"));
        assert!(sink.interested("named-instance"));
        assert!(!sink.interested("another-project-default-rtdb"));
        let other_region = super::database_sink(
            &runtime,
            "demo-app",
            "europe-west1",
            "europe-west1.firebasedatabase.app",
        );
        assert!(!other_region.interested("demo-app-default-rtdb"));
        let empty = database_bridge_tree(&serde_json::Value::Null);
        let after = database_bridge_tree(&json!({"users":{"a":1}}));
        let root = fireemu_adapter_database::changes::Path::root();
        assert!(sink
            .capture_references_within(
                "another-project-default-rtdb",
                (&empty).into(),
                &after,
                &root
            )
            .unwrap()
            .unwrap()
            .is_empty());
        assert!(other_region
            .capture_references_within("demo-app-default-rtdb", (&empty).into(), &after, &root)
            .unwrap()
            .unwrap()
            .is_empty());
        runtime.shutdown().await;
    }

    #[test]
    fn database_bridge_projects_changed_wildcards_and_ancestors_ignoring_large_unrelated_branches()
    {
        use fireemu_core_functions::manifest::DatabasePattern;
        let before = database_bridge_tree(
            &json!({"users":{"a-test":{"v":1},"b":{"keep":true}},"unrelated":"x".repeat(2*1024*1024)}),
        );
        let after = database_bridge_tree(
            &json!({"users":{"a-test":{"v":2},"b":{"keep":true},"c-test":3},"unrelated":"y".repeat(2*1024*1024)}),
        );
        let patterns = ["/users", "/users/{uid=*-test}", "/users/{uid=*-test}"]
            .map(|pattern| DatabasePattern::parse(pattern).unwrap());
        // Three references fit a budget of three records although the unrelated branches are
        // large. Duplicate patterns must not charge twice.
        let (references, _) = super::capture_database_references(
            &patterns,
            &before,
            &after,
            &fireemu_adapter_database::changes::Path::root(),
            3,
            usize::MAX,
        )
        .unwrap();
        assert_eq!(
            references
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["/users", "/users/a-test", "/users/c-test"]
        );
        assert!(super::capture_database_references(
            &patterns,
            &before,
            &before,
            &fireemu_adapter_database::changes::Path::root(),
            0,
            usize::MAX
        )
        .unwrap()
        .0
        .is_empty());
    }

    #[test]
    fn database_bridge_capture_refuses_only_more_references_than_the_record_budget() {
        use fireemu_core_functions::manifest::DatabasePattern;
        use fireemu_core_types::admission::EventAdmissionError;
        let root = fireemu_adapter_database::changes::Path::root();
        let before = database_bridge_tree(&json!({"users":{"a":"before","b":1}}));
        // Large values do not count against the capture: the runtime measures the real events.
        let after = database_bridge_tree(&json!({"users":{"a":"x".repeat(4 * 1024 * 1024),"b":2}}));
        let patterns = [DatabasePattern::parse("/users/{uid}").unwrap()];
        assert!(matches!(
            super::capture_database_references(&patterns, &before, &after, &root, 1, usize::MAX),
            Err(EventAdmissionError::Capacity(_))
        ));
        assert_eq!(
            super::capture_database_references(&patterns, &before, &after, &root, 2, usize::MAX)
                .unwrap(),
            (
                vec![
                    root.child("users").child("a"),
                    root.child("users").child("b")
                ],
                0
            )
        );
        // R2-M1: a snapshot provably larger than the frame is left out and counted, before
        // any export; one at the bound is kept, as its event may still fit.
        // A leaf's event carries `before` ("before": 8 bytes) and `after` whole.
        let at_bound = 8 + 4 * 1024 * 1024 + 2;
        assert_eq!(
            super::capture_database_references(&patterns, &before, &after, &root, 2, at_bound)
                .unwrap()
                .1,
            0
        );
        assert_eq!(
            super::capture_database_references(&patterns, &before, &after, &root, 2, at_bound - 1)
                .unwrap(),
            (vec![root.child("users").child("b")], 1)
        );
    }

    /// Merge review note (2026-11-10): an oversized reference is refused or counted as dropped only for a
    /// trigger that accepts the change's kind (creation: before absent, deletion: after absent, otherwise
    /// an update); `written` accepts all three. A reference no trigger accepts is left out silently.
    #[test]
    fn database_bridge_capture_judges_an_oversized_reference_only_for_triggers_that_accept_its_kind(
    ) {
        use fireemu_core_functions::manifest::{DatabasePattern, DocumentEvent};
        use fireemu_core_types::admission::EventAdmissionError;
        let root = fireemu_adapter_database::changes::Path::root();
        let big = json!("x".repeat(4096));
        // (before, after, the kind of the change)
        let changes = [
            (
                json!({}),
                json!({"users":{"a": big}}),
                DocumentEvent::Created,
            ),
            (
                json!({"users":{"a": big}}),
                json!({}),
                DocumentEvent::Deleted,
            ),
            (
                json!({"users":{"a": big}}),
                json!({"users":{"a":"y"}}),
                DocumentEvent::Updated,
            ),
        ];
        let pattern = DatabasePattern::parse("/users/{uid}").unwrap();
        for (before, after, actual) in &changes {
            let (before, after) = (database_bridge_tree(before), database_bridge_tree(after));
            for declared in [
                DocumentEvent::Created,
                DocumentEvent::Updated,
                DocumentEvent::Deleted,
                DocumentEvent::Written,
            ] {
                let accepted = declared.accepts(*actual);
                let triggers = [(pattern.clone(), declared)];
                let capture = |refuse_over: Option<usize>| {
                    super::capture_database_references_limited(
                        &triggers,
                        &before,
                        &after,
                        &root,
                        8,
                        1024,
                        refuse_over,
                    )
                };
                // dropped for the frame, or refused for the event limit, only when accepted
                assert_eq!(
                    capture(None).unwrap(),
                    (Vec::new(), usize::from(accepted)),
                    "{declared:?} on a {actual:?}"
                );
                assert_eq!(
                    matches!(
                        capture(Some(2048)),
                        Err(EventAdmissionError::PayloadTooLarge(_))
                    ),
                    accepted,
                    "{declared:?} on a {actual:?}"
                );
                if !accepted {
                    assert_eq!(capture(Some(2048)).unwrap(), (Vec::new(), 0));
                }
            }
            // one trigger that accepts is enough, wherever it stands among the others
            for order in [
                [DocumentEvent::Created, DocumentEvent::Deleted],
                [DocumentEvent::Deleted, DocumentEvent::Created],
            ] {
                let triggers = order.map(|declared| (pattern.clone(), declared));
                let refused = super::capture_database_references_limited(
                    &triggers,
                    &before,
                    &after,
                    &root,
                    8,
                    1024,
                    Some(2048),
                )
                .is_err();
                assert_eq!(
                    refused,
                    matches!(actual, DocumentEvent::Created | DocumentEvent::Deleted)
                );
            }
        }
    }

    /// RTDB-TRIGGERS-KINDS-20261108-01 (k13): where the strict profile refuses a write whose event is too
    /// large, the capture refuses it from the same lower bound that otherwise leaves the reference out for
    /// not fitting a frame, before anything is exported.
    #[test]
    fn database_bridge_capture_refuses_a_snapshot_provably_over_the_event_limit_when_asked() {
        use fireemu_core_functions::manifest::DatabasePattern;
        use fireemu_core_types::admission::EventAdmissionError;
        let root = fireemu_adapter_database::changes::Path::root();
        let before = database_bridge_tree(&json!({"users":{"a":"before","b":1}}));
        let after = database_bridge_tree(&json!({"users":{"a":"x".repeat(4 * 1024 * 1024),"b":2}}));
        let patterns = [DatabasePattern::parse("/users/{uid}").unwrap()];
        let written = fireemu_core_functions::manifest::DocumentEvent::Written;
        let triggers = [(patterns[0].clone(), written)];
        let at_bound = 8 + 4 * 1024 * 1024 + 2;
        let capture = |refuse_over: Option<usize>| {
            super::capture_database_references_limited(
                &triggers,
                &before,
                &after,
                &root,
                8,
                usize::MAX,
                refuse_over,
            )
        };
        assert!(matches!(
            capture(Some(at_bound - 1)),
            Err(EventAdmissionError::PayloadTooLarge(_))
        ));
        assert_eq!(capture(Some(at_bound)).unwrap().0.len(), 2);
        assert_eq!(capture(None).unwrap().0.len(), 2);
        // a reference over the frame but not over the event limit is still only left out and counted
        assert_eq!(
            super::capture_database_references_limited(
                &triggers,
                &before,
                &after,
                &root,
                8,
                at_bound - 1,
                Some(at_bound),
            )
            .unwrap(),
            (vec![root.child("users").child("b")], 1)
        );
        // the frame rule is unchanged when nothing is asked: left out and counted
        assert_eq!(
            super::capture_database_references(&patterns, &before, &after, &root, 8, at_bound - 1)
                .unwrap()
                .1,
            1
        );
    }

    #[test]
    fn database_scope_overlay_matches_concrete_before_capture_and_frame_drops() {
        use fireemu_adapter_database::changes::Path;
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_core_functions::manifest::DatabasePattern;
        let patterns = ["/", "/a", "/a/{child}", "/a/{child}/{deep}", "/b"]
            .map(|pattern| DatabasePattern::parse(pattern).unwrap());
        for value in [
            json!(null),
            json!({".value":"leaf",".priority":3}),
            json!({"a":{".value":"leaf",".priority":2},".priority":1}),
            json!({"a":{"x":{".value":1,".priority":3},".priority":2},".priority":1}),
            json!({"a":{"x":1,"y":2},"b":"unchanged"}),
        ] {
            let before = database_bridge_tree(&value);
            for scope in [
                Path::root(),
                Path::from_keys(["a"]),
                Path::from_keys(["a", "x"]),
                Path::from_keys(["a", "x", "deep"]),
            ] {
                for next in [json!(null), json!(9), json!({"z":true})] {
                    let mut database = Database::new(RestOptions::default(), 1);
                    assert_eq!(database_bridge_write(&mut database, &value), 200);
                    let saved = before.save_scope(&scope);
                    let response = database.handle(
                        &HttpRequest {
                            method: "PUT".into(),
                            target: format!("{scope}.json?ns=demo-app-default-rtdb"),
                            headers: Vec::new(),
                            body: serde_json::to_vec(&next).unwrap(),
                        },
                        100_000,
                    );
                    assert!(
                        matches!(response, Handled::Response { response, .. } if response.status == 200)
                    );
                    let after = database.tree("demo-app-default-rtdb").unwrap();
                    if &before == after {
                        continue;
                    }
                    for records in [0, 1, 8] {
                        for frame in [0, 10, 1024] {
                            let expected = super::capture_database_references(
                                &patterns, &before, after, &scope, records, frame,
                            );
                            let actual = super::capture_database_references(
                                &patterns,
                                saved.view(after),
                                after,
                                &scope,
                                records,
                                frame,
                            );
                            assert_eq!(
                                format!("{actual:?}"),
                                format!("{expected:?}"),
                                "scope {scope}, records {records}, frame {frame}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn database_json_lower_bound_counts_the_compact_json_of_keys_strings_and_punctuation() {
        use fireemu_adapter_database::changes::Path;
        let tree =
            database_bridge_tree(&json!({"s":"abc","o":{"a":1,"b":2},"p":{"a":"xx","b":"yy"}}));
        let node = |key: &str| {
            tree.get(&Path::from_keys([key]))
                .map(fireemu_adapter_database::changes::NodeView::Borrowed)
        };
        assert_eq!(super::database_json_lower_bound(None, usize::MAX), 4); // null
        assert_eq!(super::database_json_lower_bound(node("s"), usize::MAX), 5); // "abc"
        assert_eq!(super::database_json_lower_bound(node("o"), usize::MAX), 13); // {"a":1,"b":2}
        assert_eq!(super::database_json_lower_bound(node("p"), usize::MAX), 19); // {"a":"xx","b":"yy"}
                                                                                 // Reaching the limit exactly mid-walk keeps counting; only passing it stops.
        assert!(super::database_json_lower_bound(node("p"), 15) > 15);
    }

    #[test]
    fn database_bridge_frame_bound_adds_the_whole_after_unless_both_sides_are_objects() {
        use fireemu_adapter_database::changes::Path;
        use fireemu_core_functions::manifest::DatabasePattern;
        let root = Path::root();
        let patterns = [DatabasePattern::parse("/users/{uid}").unwrap()];
        // An object replaced by a leaf: the event carries {"x":1} (7) and "ssssssssss" (12).
        let before = database_bridge_tree(&json!({"users":{"a":{"x":1}}}));
        let after = database_bridge_tree(&json!({"users":{"a":"s".repeat(10)}}));
        for (limit, drops) in [(19, 0), (18, 1)] {
            assert_eq!(
                super::capture_database_references(&patterns, &before, &after, &root, 8, limit)
                    .unwrap()
                    .1,
                drops,
                "{limit}"
            );
        }
        // Two objects: only `before` is certain to be carried whole.
        let after = database_bridge_tree(&json!({"users":{"a":{"x":"s".repeat(10)}}}));
        assert_eq!(
            super::capture_database_references(&patterns, &before, &after, &root, 8, 7)
                .unwrap()
                .1,
            0
        );
    }

    #[tokio::test]
    async fn database_bridge_affects_only_writes_that_can_reach_a_trigger_reference() {
        use fireemu_adapter_database::changes::Path;
        let runtime = database_bridge_runtime().await;
        let sink = super::database_sink(&runtime, "demo-app", "us-central1", "firebaseio.com");
        for (keys, expected) in [
            (&[][..], true),
            (&["users"][..], true),
            (&["users", "a"][..], true),
            (&["users", "a", "name"][..], true),
            (&["other"][..], false),
            (&["other", "users", "a"][..], false),
        ] {
            assert_eq!(
                sink.affects(
                    "demo-app-default-rtdb",
                    &Path::from_keys(keys.iter().copied())
                ),
                expected,
                "{keys:?}"
            );
        }
        runtime.shutdown().await;
    }

    use proptest::strategy::Strategy as _;

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Review S3: following only the written branch above the write finds exactly the
        /// references a whole-tree walk finds.
        #[test]
        fn database_bridge_scoped_capture_matches_the_whole_tree_walk(
            seed in proptest::collection::btree_map(
                proptest::sample::select(vec!["users", "other", "a"]),
                proptest::collection::btree_map(
                    proptest::sample::select(vec!["a", "b", "c-test"]),
                    proptest::prelude::prop_oneof![
                        (0i32..3).prop_map(|n| json!(n)),
                        (0i32..3).prop_map(|n| json!({"v": n})),
                    ],
                    0..3,
                ),
                0..3,
            ),
            write in proptest::collection::vec(proptest::sample::select(vec!["users", "other", "a", "b", "c-test", "v"]), 0..4),
            value in proptest::prelude::prop_oneof![
                proptest::prelude::Just(serde_json::Value::Null),
                (0i32..3).prop_map(|n| json!(n)),
                (0i32..3).prop_map(|n| json!({"v": n, "w": n})),
            ],
        ) {
            use fireemu_adapter_database::changes::Path;
            use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
            use fireemu_core_functions::manifest::DatabasePattern;
            let mut database = Database::new(RestOptions::default(), 1);
            proptest::prop_assert_eq!(database_bridge_write(&mut database, &serde_json::to_value(&seed).unwrap()), 200);
            let before = database.tree("demo-app-default-rtdb").cloned().unwrap_or_default();
            let target = format!("/{}.json?ns=demo-app-default-rtdb", write.join("/"));
            let Handled::Response { response, .. } = database.handle(
                &HttpRequest { method: "PUT".to_owned(), target, headers: Vec::new(), body: serde_json::to_vec(&value).unwrap() },
                100_000,
            ) else {
                panic!("a PUT must not create a stream")
            };
            proptest::prop_assert_eq!(response.status, 200);
            let after = database.tree("demo-app-default-rtdb").cloned().unwrap_or_default();
            let scope = Path::from_keys(write.iter().copied());
            // The caller captures only after the write changed its scope.
            if before.get(&scope) == after.get(&scope) {
                return Ok(());
            }
            let patterns = ["/users", "/users/{uid}", "/{top}/{uid=*-test}", "/a/b/v", "/"]
                .map(|pattern| DatabasePattern::parse(pattern).unwrap());
            let whole = super::capture_database_references(&patterns, &before, &after, &Path::root(), usize::MAX, usize::MAX).unwrap().0;
            let scoped = super::capture_database_references(&patterns, &before, &after, &scope, usize::MAX, usize::MAX).unwrap().0;
            proptest::prop_assert_eq!(&scoped, &whole);
            // A write no pattern overlaps (the sink's `affects` is false) changes no reference.
            // ("/" overlaps everything, so the check leaves it out.)
            let narrow = &patterns[..4];
            if !narrow.iter().any(|pattern| pattern.overlaps(&scope.to_string())) {
                let unaffected = super::capture_database_references(narrow, &before, &after, &Path::root(), usize::MAX, usize::MAX).unwrap().0;
                proptest::prop_assert!(unaffected.is_empty(), "{unaffected:?}");
            }
        }
    }

    /// The pairwise table of docs.local/coverage-ledger/pict/review-rtdb-fixes.pict (review
    /// S3, S4 and S11), with its required rows seeded. Each row writes through the real bridge
    /// and compares status, source tree, published events and dropped fanouts with a model
    /// computed from the trees the write produces without a sink.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn database_bridge_pairwise_paths_fanouts_and_regions_match_the_model() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::events::{
            DatabaseChangeData, DatabaseCommit, DatabaseReferenceChange,
        };
        use fireemu_adapter_functions::runtime::{
            DATABASE_FANOUT_DROPPED, MAX_ACTIVE_EVENT_RECORDS,
        };
        const TABLE: &str = "WritePath	Change	Fanout	Region
belowRef	changed	small	usCentral1
root	changed	overBudget	usCentral1
unwatched	changed	none	usCentral1
belowRef	changed	transientFull	usCentral1
atRef	unchanged	none	usCentral1
belowRef	changed	small	europeWest1
ancestor	unchanged	small	firstGen
root	changed	none	firstGen
unwatched	unchanged	overFrame	europeWest1
ancestor	changed	overFrame	usCentral1
unwatched	unchanged	transientFull	firstGen
priority	unchanged	overFrame	firstGen
root	unchanged	overFrame	europeWest1
priority	changed	overBudget	europeWest1
ancestor	changed	none	europeWest1
belowRef	unchanged	overFrame	firstGen
unwatched	unchanged	overBudget	firstGen
unwatched	unchanged	small	europeWest1
ancestor	unchanged	overBudget	europeWest1
root	unchanged	transientFull	europeWest1
atRef	changed	small	firstGen
atRef	unchanged	overFrame	europeWest1
priority	unchanged	transientFull	usCentral1
atRef	unchanged	transientFull	usCentral1
ancestor	changed	transientFull	europeWest1
atRef	unchanged	overBudget	usCentral1
priority	changed	none	europeWest1
priority	unchanged	small	firstGen
belowRef	changed	overBudget	usCentral1
belowRef	changed	none	firstGen
root	unchanged	small	firstGen";
        const NS: &str = "demo-app-default-rtdb";
        fn put(database: &mut Database, path: &str, body: &serde_json::Value) -> u16 {
            let target = if path == "/" {
                format!("/.json?ns={NS}")
            } else {
                format!("{path}.json?ns={NS}")
            };
            let Handled::Response { response, .. } = database.handle(
                &HttpRequest {
                    method: "PUT".to_owned(),
                    target,
                    headers: Vec::new(),
                    body: serde_json::to_vec(body).unwrap(),
                },
                100_000,
            ) else {
                panic!("a PUT must not create a stream")
            };
            response.status
        }
        fn export(database: &mut Database) -> serde_json::Value {
            let Handled::Response { response, .. } = database.handle(
                &HttpRequest {
                    method: "GET".to_owned(),
                    target: format!("/.json?ns={NS}&format=export"),
                    headers: Vec::new(),
                    body: Vec::new(),
                },
                100_000,
            ) else {
                panic!("a GET without SSE must not create a stream")
            };
            assert_eq!(response.status, 200);
            serde_json::from_slice(&response.body).unwrap()
        }
        let seed = json!({"users":{"a":{"v":1},"b":{"v":1}},"other":{"x":1}});
        for row in TABLE.lines().skip(1) {
            let columns: Vec<_> = row.split('\t').collect();
            let [path_kind, change, fanout, region] = columns.as_slice() else {
                panic!("{row}")
            };
            let function = match *region {
                "usCentral1" => json!({"generation":2,"region":"us-central1"}),
                "europeWest1" => json!({"generation":2,"region":"europe-west1"}),
                _ => json!({"generation":1}),
            };
            let mut function = function;
            function["name"] = json!("usersChanged");
            function["trigger"] = json!({"type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/users/{uid}"});
            let runtime =
                database_bridge_emulator_runtime_with(&json!({"functions":[function]})).await;
            let delivering = *region != "europeWest1";
            // The value a changed write puts at /users/a/v.
            let leaf = match *fanout {
                // Two strings below the 10 MB string limit; six times their bytes exceed the
                // 64 MiB capture budget of one reference.
                "overBudget" => {
                    json!({"p": "x".repeat(9 * 1024 * 1024), "q": "y".repeat(9 * 1024 * 1024)})
                }
                "overFrame" => json!("\0".repeat(3 * 1024 * 1024)),
                _ => json!(2),
            };
            let many: serde_json::Map<_, _> = (0..=MAX_ACTIVE_EVENT_RECORDS)
                .map(|n| (format!("id{n}"), json!(n)))
                .collect();
            let mut changed_users = seed["users"].clone();
            changed_users["a"]["v"] = leaf.clone();
            if *fanout == "overBudget" && matches!(*path_kind, "ancestor" | "root") {
                changed_users = serde_json::Value::Object(many.clone());
            }
            let unchanged = *change == "unchanged";
            let (target, body) = match *path_kind {
                "unwatched" => ("/other/x", if unchanged { json!(1) } else { json!(2) }),
                "ancestor" => (
                    "/users",
                    if unchanged {
                        seed["users"].clone()
                    } else {
                        changed_users.clone()
                    },
                ),
                "atRef" => (
                    "/users/a",
                    if unchanged {
                        seed["users"]["a"].clone()
                    } else {
                        changed_users["a"].clone()
                    },
                ),
                "belowRef" => (
                    "/users/a/v",
                    if unchanged { json!(1) } else { leaf.clone() },
                ),
                // A priority is small: it changes one reference whatever the fanout column says.
                "priority" => (
                    "/users/a/.priority",
                    if unchanged {
                        serde_json::Value::Null
                    } else {
                        json!(5)
                    },
                ),
                _ => {
                    let mut root = seed.clone();
                    if !unchanged {
                        if *fanout == "none" {
                            root["other"]["x"] = json!(2);
                        } else {
                            root["users"] = changed_users.clone();
                        }
                    }
                    ("/", root)
                }
            };
            // The model: the same write without a sink.
            let mut plain = Database::new(RestOptions::default(), 1);
            assert_eq!(put(&mut plain, "/", &seed), 200);
            let before = export(&mut plain);
            assert_eq!(put(&mut plain, target, &body), 200, "{row}");
            let after = export(&mut plain);
            let refs = |tree: &serde_json::Value| {
                tree.get("users")
                    .and_then(serde_json::Value::as_object)
                    .cloned()
                    .unwrap_or_default()
            };
            let (old, new) = (refs(&before), refs(&after));
            let changed_refs = old
                .keys()
                .chain(new.keys())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter(|key| old.get(*key) != new.get(*key))
                .count();
            let oversized = changed_refs > MAX_ACTIVE_EVENT_RECORDS
                || (*path_kind != "priority" && matches!(*fanout, "overBudget" | "overFrame"));
            let firing = delivering && changed_refs > 0;
            let refused = firing && !oversized && *fanout == "transientFull";

            let mut database = Database::new(RestOptions::default(), 1);
            assert_eq!(put(&mut database, "/", &seed), 200);
            database.set_change_sink(super::database_sink(
                &runtime,
                "demo-app",
                "us-central1",
                "firebaseio.com",
            ));
            let holding = (*fanout == "transientFull").then(|| {
                runtime
                    .reserve_database_events(&DatabaseCommit {
                        project: "demo-app".to_owned(),
                        instance: NS.to_owned(),
                        location: "us-central1".to_owned(),
                        host: "firebaseio.com".to_owned(),
                        sequence: 0,
                        time: fireemu_core_types::time::LogicalInstant::from_unix_seconds(100),
                        data: DatabaseChangeData::References(
                            (0..MAX_ACTIVE_EVENT_RECORDS)
                                .map(|n| DatabaseReferenceChange {
                                    reference: format!("/users/hold{n}"),
                                    before: serde_json::Value::Null,
                                    after: json!(n),
                                })
                                .collect(),
                        ),
                        auth_type: "ADMIN".to_owned(),
                        auth_id: None,
                        auth: None,
                    })
                    .unwrap()
            });
            let status = put(&mut database, target, &body);
            assert_eq!(status, if refused { 503 } else { 200 }, "{row}");
            assert_eq!(
                export(&mut database),
                if refused {
                    before.clone()
                } else {
                    after.clone()
                },
                "{row}"
            );
            drop(holding);
            let accounting = runtime.source_event_accounting().unwrap();
            let expected = if firing && !oversized && !refused {
                changed_refs
            } else {
                0
            };
            assert_eq!(accounting.published_records, expected, "{row}");
            let dropped = runtime
                .resources(fireemu_core_types::resources::RootBudget::DEFAULT)
                .unwrap()
                .refusals
                .into_iter()
                .find(|refusal| refusal.reason == format!("admission.{DATABASE_FANOUT_DROPPED}"))
                .map_or(0, |refusal| refusal.count);
            assert_eq!(dropped, u64::from(firing && oversized), "{row}");
            runtime.shutdown().await;
        }
    }

    /// Merge review M1 (2026-10-26): a chat room of 20,000 small messages under one trigger
    /// reference (about 0.94 MB of JSON) passed the old heap-size estimate times six and lost
    /// its event; the real event (about 1.9 MB) fits the frame and the budget and is delivered.
    #[tokio::test]
    async fn database_bridge_delivers_a_large_room_event_that_fits() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::runtime::DATABASE_FANOUT_DROPPED;
        let runtime = database_bridge_runtime_with(
            &json!({"functions":[{"name":"roomChanged","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/rooms/{roomId}"
            }}]}),
        )
        .await;
        let mut database = Database::new(RestOptions::default(), 1);
        let messages: serde_json::Map<_, _> = (0..20_000)
            .map(|n| {
                (
                    format!("m{n:05}"),
                    json!({"text":"hello","uid":"u1","ts":123}),
                )
            })
            .collect();
        assert_eq!(
            database_bridge_write(
                &mut database,
                &json!({"rooms":{"r1":{"messages":messages}}})
            ),
            200
        );
        database.set_change_sink(super::database_sink(
            &runtime,
            "demo-app",
            "us-central1",
            "firebaseio.com",
        ));
        let Handled::Response { response, .. } = database.handle(
            &HttpRequest {
                method: "PUT".to_owned(),
                target: "/rooms/r1/messages/new.json?ns=demo-app-default-rtdb".to_owned(),
                headers: Vec::new(),
                body: br#"{"text":"hi"}"#.to_vec(),
            },
            100_000,
        ) else {
            panic!("a PUT must not create a stream")
        };
        assert_eq!(response.status, 200);
        assert_eq!(
            runtime.source_event_accounting().unwrap().published_records,
            1
        );
        let dropped = runtime
            .resources(fireemu_core_types::resources::RootBudget::DEFAULT)
            .unwrap()
            .refusals
            .into_iter()
            .find(|refusal| refusal.reason == format!("admission.{DATABASE_FANOUT_DROPPED}"))
            .map_or(0, |refusal| refusal.count);
        assert_eq!(dropped, 0);
        runtime.shutdown().await;
    }

    /// Merge review round 2 R2-M1 (2026-10-26): under a broad trigger (`/{top}`), a one-value
    /// write into a branch whose JSON is larger than an invocation frame used to export and
    /// serialize the whole branch under the database lock before the event was dropped. A cheap
    /// lower bound of the snapshot's JSON size now proves the event can never fit, so the
    /// write stays fast; the event is counted as dropped.
    /// RTDB-TRIGGERS-KINDS-20261108-01 (k11 to k13), through the real sink and the REST handler: a 100 KiB and a
    /// 600 KiB value are accepted, a 2 MiB one (and, by the documented 1 MB, 1.05 MB) is refused with 400 and the text production sent, and the
    /// data is not written; the emulator profile applies all three.
    #[tokio::test]
    async fn database_bridge_strict_refuses_a_write_with_an_event_over_the_limit_and_the_emulator_applies_it(
    ) {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::events::DatabaseEventShape;
        let manifest = json!({"functions":[{"name":"leafWritten","generation":2,"region":"us-central1","trigger":{
            "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*",
            "ref":"/gl/items/{id}"
        }}]});
        for (shape, strict) in [
            (DatabaseEventShape::Production, true),
            (DatabaseEventShape::Official, false),
        ] {
            let runtime = database_bridge_runtime_shaped(&manifest, shape).await;
            let mut database = Database::new(RestOptions::default(), 1);
            database.set_change_sink(super::database_sink(
                &runtime,
                "demo-app",
                "us-central1",
                "firebaseio.com",
            ));
            let mut put = |id: &str, blob: usize| {
                let Handled::Response { response, .. } = database.handle(
                    &HttpRequest {
                        method: "PUT".to_owned(),
                        target: format!("/gl/items/{id}.json?ns=demo-app-default-rtdb"),
                        headers: Vec::new(),
                        body: serde_json::to_vec(&json!({"blob": "x".repeat(blob), "value": 1}))
                            .unwrap(),
                    },
                    100_000,
                ) else {
                    panic!("a PUT must not create a stream")
                };
                (response.status, String::from_utf8(response.body).unwrap())
            };
            assert_eq!(put("l1", 100 * 1024).0, 200);
            assert_eq!(put("l2", 600 * 1024).0, 200);
            // the packet v2 ladder around the documented 1 MB
            assert_eq!(put("l6", 949_900).0, 200);
            assert_eq!(put("l8", 1_023_900).0, 200, "accepted by production (k24)");
            assert_eq!(put("l7", 1_049_900).0, if strict { 400 } else { 200 });
            let (status, body) = put("l3", 2 * 1024 * 1024);
            if strict {
                assert_eq!(status, 400);
                assert_eq!(
                    body,
                    "{\n  \"error\" : \"This request would cause a function payload exceeding the maximum size allowed.\"\n}\n"
                );
            } else {
                assert_eq!(status, 200, "{body}");
            }
            // an update of an existing object whose delta is large: the capture bound counts only the
            // node before when both sides are objects, so it is the runtime's measure of the event that
            // refuses it
            assert_eq!(put("l4", 10).0, 200);
            let (status, body) = put("l4", 2 * 1024 * 1024);
            if strict {
                assert_eq!(status, 400);
                assert!(body.contains("function payload exceeding the maximum size allowed"));
            } else {
                assert_eq!(status, 200, "{body}");
            }
            let tree = database.tree("demo-app-default-rtdb").unwrap();
            assert_eq!(
                tree.root()
                    .and_then(|root| root.child("gl"))
                    .and_then(|gl| gl.child("items"))
                    .and_then(|items| items.child("l3"))
                    .is_some(),
                !strict,
                "the refused write is not applied"
            );
            // a write no trigger reference can reach is never measured
            let Handled::Response { response, .. } = database.handle(
                &HttpRequest {
                    method: "PUT".to_owned(),
                    target: "/elsewhere.json?ns=demo-app-default-rtdb".to_owned(),
                    headers: Vec::new(),
                    body: serde_json::to_vec(&json!("y".repeat(3 * 1024 * 1024))).unwrap(),
                },
                100_001,
            ) else {
                panic!("a PUT must not create a stream")
            };
            assert_eq!(response.status, 200);
            runtime.shutdown().await;
        }
    }

    /// Merge review note (2026-11-10): the capture used to refuse an oversized reference by path alone, before
    /// asking whether any deployed trigger accepts the change's kind. A write that produces no event is
    /// never refused for an event size (production for this case is unrecorded); one a deployed trigger
    /// would receive still is, at the same limit, through REST PUT, PATCH and POST.
    #[tokio::test]
    async fn database_bridge_strict_refuses_only_writes_whose_event_a_deployed_trigger_receives() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::events::DatabaseEventShape;
        let limit = 1_048_576usize;
        let at_limit = "x".repeat(limit);
        for (event, overwrite_refused, create_refused, delete_refused) in [
            ("created", false, true, false),
            ("updated", true, false, false),
            ("deleted", false, false, true),
            ("written", true, true, true),
        ] {
            let manifest = json!({"functions":[{"name":"leaf","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":format!("google.firebase.database.ref.v1.{event}"),
                "instance":"*","ref":"/users/{uid}"
            }}]});
            let runtime =
                database_bridge_runtime_shaped(&manifest, DatabaseEventShape::Production).await;
            let mut database = Database::new(RestOptions::default(), 1);
            let call = |database: &mut Database,
                        method: &str,
                        target: &str,
                        body: &serde_json::Value,
                        at: i64| {
                let Handled::Response { response, .. } = database.handle(
                    &HttpRequest {
                        method: method.to_owned(),
                        target: format!("{target}?ns=demo-app-default-rtdb"),
                        headers: Vec::new(),
                        body: serde_json::to_vec(body).unwrap(),
                    },
                    at,
                ) else {
                    panic!("a REST write must not create a stream")
                };
                response.status
            };
            // the oversized values are there before the trigger is attached
            assert_eq!(
                call(&mut database, "PUT", "/users/a.json", &json!(at_limit), 1),
                200
            );
            assert_eq!(
                call(&mut database, "PUT", "/users/d.json", &json!(at_limit), 2),
                200
            );
            database.set_change_sink(super::database_sink(
                &runtime,
                "demo-app",
                "us-central1",
                "firebaseio.com",
            ));
            let verdict = |refused: bool| if refused { 400 } else { 200 };
            assert_eq!(
                call(&mut database, "PUT", "/users/a.json", &json!("y"), 3),
                verdict(overwrite_refused),
                "{event}: overwrite of an at-limit value"
            );
            assert_eq!(
                call(&mut database, "PUT", "/users/c.json", &json!(at_limit), 4),
                verdict(create_refused),
                "{event}: creating an at-limit value"
            );
            assert_eq!(
                call(&mut database, "PUT", "/users/d.json", &json!(null), 5),
                verdict(delete_refused),
                "{event}: deleting an at-limit value"
            );
            runtime.shutdown().await;
        }
    }

    /// The strict event limit is exact, and the same on every write route (merge review note, 2026-11-10):
    /// a creation whose event (the `null` before plus the value as the delta) is exactly the limit is
    /// applied, one byte more is refused and nothing is written, through REST PUT, PATCH and POST, and the
    /// realtime put, update and `onDisconnect` writes. The measure is the serialized JSON, so an escaped
    /// quote counts twice and a two-byte UTF-8 character twice, where the capture's lower bound counts raw bytes.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn database_bridge_strict_event_limit_is_exact_on_every_write_route() {
        use fireemu_adapter_database::realtime::{Opened, Session};
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::events::DatabaseEventShape;
        #[derive(Clone, Copy, Debug)]
        enum Route {
            Put,
            Patch,
            Post,
            WsPut,
            WsUpdate,
            OnDisconnect,
        }
        const LIMIT: usize = 1_048_576;
        // the delta's JSON length is the value's length plus two quotes, and the before is `null`
        let ascii = |bytes: usize| "x".repeat(bytes - 6);
        let manifest = json!({"functions":[{"name":"leaf","generation":2,"region":"us-central1","trigger":{
            "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*",
            "ref":"/users/{uid}"
        }}]});
        let runtime =
            database_bridge_runtime_shaped(&manifest, DatabaseEventShape::Production).await;
        let mut database = Database::new(RestOptions::default(), 1);
        database.set_change_sink(super::database_sink(
            &runtime,
            "demo-app",
            "us-central1",
            "firebaseio.com",
        ));
        let mut session = match database
            .open_realtime("/.ws?v=5&ns=demo-app-default-rtdb", None, 100)
            .unwrap()
        {
            Opened::Session(session, _) => session,
            other @ Opened::Shutdown(_) => panic!("unexpected realtime open: {other:?}"),
        };
        let rest =
            |database: &mut Database, method: &str, target: &str, body: &serde_json::Value| {
                let Handled::Response { response, .. } = database.handle(
                    &HttpRequest {
                        method: method.to_owned(),
                        target: format!("{target}?ns=demo-app-default-rtdb"),
                        headers: Vec::new(),
                        body: serde_json::to_vec(body).unwrap(),
                    },
                    1_000,
                ) else {
                    panic!("a REST write must not create a stream")
                };
                response
            };
        let frame = |session: &mut Session,
                     database: &mut Database,
                     action: &str,
                     body: serde_json::Value| {
            let text = json!({"t":"d","d":{"r":1,"a":action,"b":body}}).to_string();
            let received = session.receive(database, &text, 1_000);
            serde_json::from_str::<serde_json::Value>(&received.replies[0]).unwrap()["d"]["b"]["s"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let mut next = 0u32;
        // Writes `value` as a new child of /users by `route`; whether it was applied.
        let mut write = |database: &mut Database,
                         session: &mut Session,
                         route: Route,
                         value: &str|
         -> bool {
            next += 1;
            let key = format!("k{next}");
            let wrote = |database: &Database| {
                database
                    .tree("demo-app-default-rtdb")
                    .unwrap()
                    .root()
                    .and_then(|root| root.child("users"))
                    .and_then(|users| users.child(&key))
                    .is_some()
            };
            match route {
                Route::Put => {
                    let response = rest(
                        database,
                        "PUT",
                        &format!("/users/{key}.json"),
                        &json!(value),
                    );
                    assert!(
                        response.status == 200 || response.status == 400,
                        "{}",
                        response.status
                    );
                    if response.status == 400 {
                        assert_eq!(
                            String::from_utf8(response.body).unwrap(),
                            "{\n  \"error\" : \"This request would cause a function payload exceeding the maximum size allowed.\"\n}\n"
                        );
                    }
                }
                Route::Patch => {
                    let status =
                        rest(database, "PATCH", "/users.json", &json!({ &key: value })).status;
                    assert!(status == 200 || status == 400, "{status}");
                }
                Route::Post => {
                    // a push key is generated, so the write is found by the size of /users instead of by key
                    let before = database
                        .tree("demo-app-default-rtdb")
                        .unwrap()
                        .root()
                        .and_then(|root| root.child("users"))
                        .map_or(0, fireemu_adapter_database::changes::Node::retained_bytes);
                    let status = rest(database, "POST", "/users.json", &json!(value)).status;
                    assert!(status == 200 || status == 400, "{status}");
                    let after = database
                        .tree("demo-app-default-rtdb")
                        .unwrap()
                        .root()
                        .and_then(|root| root.child("users"))
                        .map_or(0, fireemu_adapter_database::changes::Node::retained_bytes);
                    assert_eq!(
                        after > before,
                        status == 200,
                        "a refused push writes nothing"
                    );
                    return status == 200;
                }
                Route::WsPut => {
                    let status = frame(
                        session,
                        database,
                        "p",
                        json!({"p": format!("/users/{key}"), "d": value}),
                    );
                    assert!(status == "ok" || status == "invalid_parameters", "{status}");
                }
                Route::WsUpdate => {
                    let status = frame(
                        session,
                        database,
                        "m",
                        json!({"p": "/users", "d": {&key: value}}),
                    );
                    assert!(status == "ok" || status == "invalid_parameters", "{status}");
                }
                Route::OnDisconnect => {
                    let status = frame(
                        session,
                        database,
                        "o",
                        json!({"p": format!("/users/{key}"), "d": value}),
                    );
                    assert_eq!(status, "ok", "registering is not a write");
                    // The connection ends and the registered write is made at the root; a payload refusal drops it.
                    database.close_realtime(session.client(), 1_000);
                    let fresh = match database
                        .open_realtime("/.ws?v=5&ns=demo-app-default-rtdb", None, 100)
                        .unwrap()
                    {
                        Opened::Session(fresh, _) => fresh,
                        other @ Opened::Shutdown(_) => {
                            panic!("unexpected realtime open: {other:?}")
                        }
                    };
                    *session = fresh;
                }
            }
            wrote(database)
        };
        let routes = [
            Route::Put,
            Route::Patch,
            Route::Post,
            Route::WsPut,
            Route::WsUpdate,
            Route::OnDisconnect,
        ];
        let exact_quotes = "\"".repeat((LIMIT - 6) / 2);
        let exact_utf8 = "\u{e9}".repeat((LIMIT - 6) / 2);
        for route in routes {
            assert!(
                write(&mut database, &mut session, route, &ascii(LIMIT)),
                "{route:?}: exactly the limit"
            );
            assert!(
                !write(&mut database, &mut session, route, &ascii(LIMIT + 1)),
                "{route:?}: one byte over"
            );
        }
        for route in [Route::Put, Route::Patch, Route::WsPut] {
            assert!(
                write(&mut database, &mut session, route, &exact_quotes),
                "{route:?}: escaped quotes, exactly the limit"
            );
            assert!(
                !write(
                    &mut database,
                    &mut session,
                    route,
                    &format!("{exact_quotes}\"")
                ),
                "{route:?}: one more quote is two bytes over, though the capture counts one"
            );
            assert!(
                write(&mut database, &mut session, route, &exact_utf8),
                "{route:?}: two-byte characters, exactly the limit"
            );
            assert!(
                !write(
                    &mut database,
                    &mut session,
                    route,
                    &format!("{exact_utf8}x")
                ),
                "{route:?}: one ASCII byte over"
            );
            assert!(
                !write(
                    &mut database,
                    &mut session,
                    route,
                    &format!("{exact_utf8}\u{e9}")
                ),
                "{route:?}: one character over"
            );
        }
        runtime.shutdown().await;
    }

    /// The strict profile refuses, rather than drops, an event larger than a frame, and does it from the
    /// capture, before any snapshot is exported: a node of about 18 MB that was there before the trigger.
    #[tokio::test]
    async fn database_bridge_strict_refuses_a_frame_sized_snapshot_before_exporting_it() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        let runtime = database_bridge_runtime_with(
            &json!({"functions":[{"name":"topChanged","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/{top}"
            }}]}),
        )
        .await;
        let mut database = Database::new(RestOptions::default(), 1);
        let big: serde_json::Map<_, _> = (0..200_000)
            .map(|n| (format!("k{n:06}"), json!({"v": "x".repeat(70)})))
            .collect();
        assert_eq!(
            database_bridge_write(&mut database, &json!({"big": big})),
            200
        );
        database.set_change_sink(super::database_sink(
            &runtime,
            "demo-app",
            "us-central1",
            "firebaseio.com",
        ));
        let started = std::time::Instant::now();
        let Handled::Response { response, .. } = database.handle(
            &HttpRequest {
                method: "PUT".to_owned(),
                target: "/big/new.json?ns=demo-app-default-rtdb".to_owned(),
                headers: Vec::new(),
                body: b"1".to_vec(),
            },
            100_000,
        ) else {
            panic!("a PUT must not create a stream")
        };
        assert_eq!(response.status, 400);
        assert!(String::from_utf8(response.body)
            .unwrap()
            .contains("function payload exceeding the maximum size allowed"));
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "{:?}",
            started.elapsed()
        );
        let Handled::Response { response, .. } = database.handle(
            &HttpRequest {
                method: "GET".to_owned(),
                target: "/big/new.json?ns=demo-app-default-rtdb".to_owned(),
                headers: Vec::new(),
                body: Vec::new(),
            },
            100_001,
        ) else {
            panic!("a GET without a stream header must not create a stream")
        };
        assert_eq!(
            String::from_utf8(response.body).unwrap().trim(),
            "null",
            "the refused write is not applied"
        );
        assert_eq!(
            runtime.source_event_accounting().unwrap().reserved_records,
            0
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn database_bridge_drops_a_frame_sized_snapshot_without_exporting_it() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::runtime::DATABASE_FANOUT_DROPPED;
        let runtime = database_bridge_emulator_runtime_with(
            &json!({"functions":[{"name":"topChanged","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/{top}"
            }}]}),
        )
        .await;
        let mut database = Database::new(RestOptions::default(), 1);
        // About 18 MB of JSON in 200,000 small objects: more than the 16 MiB frame.
        let big: serde_json::Map<_, _> = (0..200_000)
            .map(|n| (format!("k{n:06}"), json!({"v": "x".repeat(70)})))
            .collect();
        assert_eq!(
            database_bridge_write(&mut database, &json!({"big": big})),
            200
        );
        database.set_change_sink(super::database_sink(
            &runtime,
            "demo-app",
            "us-central1",
            "firebaseio.com",
        ));
        let before = database.tree("demo-app-default-rtdb").unwrap().clone();
        // Only a hang guard: what the test checks is that nothing was exported or built.
        let started = std::time::Instant::now();
        for n in 0..3 {
            let Handled::Response { response, .. } = database.handle(
                &HttpRequest {
                    method: "PUT".to_owned(),
                    target: format!("/big/new{n}.json?ns=demo-app-default-rtdb"),
                    headers: Vec::new(),
                    body: b"1".to_vec(),
                },
                100_000,
            ) else {
                panic!("a PUT must not create a stream")
            };
            assert_eq!(response.status, 200);
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(60),
            "three writes took {elapsed:?}"
        );
        // The capture selects no reference for the over-frame branch (so no snapshot is
        // exported and no event is built) and counts it as one frame drop.
        let after = database.tree("demo-app-default-rtdb").unwrap().clone();
        let patterns =
            [fireemu_core_functions::manifest::DatabasePattern::parse("/{top}").unwrap()];
        assert_eq!(
            super::capture_database_references(
                &patterns,
                &before,
                &after,
                &fireemu_adapter_database::changes::Path::from_keys(["big"]),
                fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_RECORDS,
                fireemu_adapter_functions::protocol::MAX_FRAME_BYTES,
            )
            .unwrap(),
            (Vec::new(), 1)
        );
        let accounting = runtime.source_event_accounting().unwrap();
        assert_eq!(
            (accounting.reserved_records, accounting.published_records),
            (0, 0)
        );
        let dropped = runtime
            .resources(fireemu_core_types::resources::RootBudget::DEFAULT)
            .unwrap()
            .refusals
            .into_iter()
            .find(|refusal| refusal.reason == format!("admission.{DATABASE_FANOUT_DROPPED}"))
            .map_or(0, |refusal| refusal.count);
        assert_eq!(dropped, 3);
        runtime.shutdown().await;
    }

    /// Timing harness for the issue "RTDB trigger events serialize the same snapshot
    /// repeatedly": under `/{top}`, three one-value writes into a branch of 130,000 small
    /// objects (about 7.0 MB of JSON, which fits a frame). Run in release with
    /// `cargo test -p fireemu --release -- --ignored --nocapture large_branch_trigger_write_timing`.
    #[tokio::test]
    #[ignore = "a timing harness, not a contract"]
    async fn large_branch_trigger_write_timing() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        let runtime = database_bridge_runtime_with(
            &json!({"functions":[{"name":"topChanged","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/{top}"
            }}]}),
        )
        .await;
        let mut database = Database::new(RestOptions::default(), 1);
        let big: serde_json::Map<_, _> = (0..130_000)
            .map(|n| (format!("k{n:06}"), json!({"v": "x".repeat(35)})))
            .collect();
        let big = json!({ "big": big });
        eprintln!(
            "branch JSON bytes: {}",
            serde_json::to_vec(&big["big"]).unwrap().len()
        );
        assert_eq!(database_bridge_write(&mut database, &big), 200);
        database.set_change_sink(super::database_sink(
            &runtime,
            "demo-app",
            "us-central1",
            "firebaseio.com",
        ));
        let started = std::time::Instant::now();
        for n in 0..3 {
            let write = std::time::Instant::now();
            let Handled::Response { response, .. } = database.handle(
                &HttpRequest {
                    method: "PUT".to_owned(),
                    target: format!("/big/new{n}.json?ns=demo-app-default-rtdb"),
                    headers: Vec::new(),
                    body: b"1".to_vec(),
                },
                100_000,
            ) else {
                panic!("a PUT must not create a stream")
            };
            assert_eq!(response.status, 200);
            eprintln!("write {n}: {:?}", write.elapsed());
        }
        eprintln!("three writes: {:?}", started.elapsed());
        assert_eq!(
            runtime.source_event_accounting().unwrap().published_records,
            3
        );
        runtime.shutdown().await;
    }

    #[tokio::test]
    async fn database_bridge_oversized_fanout_admits_the_write_and_drops_its_events() {
        use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
        use fireemu_adapter_functions::runtime::{
            DATABASE_FANOUT_DROPPED, MAX_ACTIVE_EVENT_RECORDS,
        };
        let runtime = database_bridge_runtime().await;
        let mut database = Database::new(RestOptions::default(), 1);
        database.set_change_sink(super::database_sink(
            &runtime,
            "demo-app",
            "us-central1",
            "firebaseio.com",
        ));
        // Review S4: production accepts a write of more children than the local event budget
        // under a trigger; refusing it with 503 failed every retry.
        let users: serde_json::Map<_, _> = (0..=MAX_ACTIVE_EVENT_RECORDS)
            .map(|n| (format!("id{n}"), json!(n)))
            .collect();
        assert_eq!(
            database_bridge_write(&mut database, &json!({"users":users})),
            200
        );
        assert!(database
            .tree("demo-app-default-rtdb")
            .unwrap()
            .get(&fireemu_adapter_database::changes::Path::from_keys([
                "users", "id4096"
            ]))
            .is_some());
        let accounting = runtime.source_event_accounting().unwrap();
        assert_eq!(
            (accounting.reserved_records, accounting.published_records),
            (0, 0)
        );
        let dropped = |runtime: &fireemu_adapter_functions::runtime::FunctionsRuntime| {
            runtime
                .resources(fireemu_core_types::resources::RootBudget::DEFAULT)
                .unwrap()
                .refusals
                .into_iter()
                .find(|refusal| refusal.reason == format!("admission.{DATABASE_FANOUT_DROPPED}"))
                .map_or(0, |refusal| refusal.count)
        };
        assert_eq!(dropped(&runtime), 1);
        // A later ordinary write under the trigger still delivers its event.
        let Handled::Response { response, .. } = database.handle(
            &HttpRequest {
                method: "PUT".to_owned(),
                target: "/users/extra.json?ns=demo-app-default-rtdb".to_owned(),
                headers: Vec::new(),
                body: b"1".to_vec(),
            },
            100_000,
        ) else {
            panic!("a PUT must not create a stream")
        };
        assert_eq!(response.status, 200);
        assert_eq!(
            runtime.source_event_accounting().unwrap().published_records,
            1
        );
        assert_eq!(dropped(&runtime), 1);
        runtime.shutdown().await;
    }

    #[test]
    fn runner_debug_features_emulator_trusted_enables_cors_and_verified_token_decoding() {
        let features =
            super::runner_debug_features(crate::config::CompatibilityProfile::Emulator, true)
                .expect("the emulator runtime has debug features");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(features).unwrap(),
            json!({"enableCors": true, "skipTokenVerification": true})
        );
    }

    #[test]
    fn runner_debug_features_emulator_untrusted_enables_cors_without_token_skipping() {
        let features =
            super::runner_debug_features(crate::config::CompatibilityProfile::Emulator, false)
                .expect("the emulator CORS feature does not require callable trust");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(features).unwrap(),
            json!({"enableCors": true})
        );
    }

    #[test]
    fn runner_debug_features_strict_trusted_only_enables_verified_token_decoding() {
        let features =
            super::runner_debug_features(crate::config::CompatibilityProfile::Strict, true)
                .expect("trusted callables use daemon-verified credentials");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(features).unwrap(),
            json!({"skipTokenVerification": true})
        );
    }

    /// `check_manifest_agrees_on_callables` runs only under the callable trusted protocol because
    /// that is the only configuration in which the runner honours unverified credentials
    /// (`skipTokenVerification` makes `firebase-functions` read the `x-callable-context-auth` /
    /// `x-original-auth` override fields and decode tokens without checking them). If another
    /// profile or switch ever enabled it, a manifest could route a callable around the daemon
    /// without App Check and the guard would have to move.
    #[test]
    fn token_skipping_is_enabled_only_by_the_callable_trusted_protocol() {
        for profile in [
            crate::config::CompatibilityProfile::Emulator,
            crate::config::CompatibilityProfile::Strict,
        ] {
            for trusted in [false, true] {
                let skips =
                    super::runner_debug_features(profile, trusted).is_some_and(|features| {
                        serde_json::from_str::<serde_json::Value>(features).unwrap()
                            ["skipTokenVerification"]
                            == json!(true)
                    });
                assert_eq!(skips, trusted, "{profile:?}, trusted: {trusted}");
            }
        }
    }

    #[test]
    fn runner_debug_features_strict_untrusted_does_not_enable_debug_mode() {
        assert_eq!(
            super::runner_debug_features(crate::config::CompatibilityProfile::Strict, false),
            None
        );
    }

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
    async fn first_successful_scan_after_startup_failure_requires_a_reload() {
        let root =
            std::env::temp_dir().join(format!("fireemu-scan-baseline-{}", std::process::id()));
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
        assert!(last_error, "the initial scan actually fails");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.js"), "exports.ok = 1;").unwrap();
        let loaded = snapshot_functions_source(&root, &[]).unwrap();
        std::fs::write(root.join("index.js"), "exports.ok = 2;").unwrap();
        assert_ne!(
            functions_source_stamp(&loaded, &[])
                .unwrap()
                .content_signature,
            functions_source_stamp(&root, &[])
                .unwrap()
                .content_signature
        );
        let changed = changed_source_stamp(
            &root,
            &codebase,
            &budget,
            &mut observed,
            &mut last_error,
            &mut retry_delay,
        )
        .await;
        assert!(
            changed.is_some(),
            "the first successful scan must reload an unknown baseline"
        );
        assert!(
            observed.is_none(),
            "only publication establishes a baseline"
        );
        assert!(!last_error);
        assert_eq!(retry_delay, Duration::from_millis(750));
        observed = changed;
        assert!(
            changed_source_stamp(
                &root,
                &codebase,
                &budget,
                &mut observed,
                &mut last_error,
                &mut retry_delay
            )
            .await
            .is_none(),
            "an unchanged published generation must not reload"
        );
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
        .is_some());
        assert!(observed.is_none());
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
        // Readiness is not a latency assertion. The copy starts only after the whole source
        // has been hashed, which takes the 2 s pacing delay when idle but has no upper bound
        // when the CPU is starved: there the hash alone outlasted a 60 s deadline and the test
        // failed with no copy in sight and the task still running. So the wait ends on one of
        // two observable events, never on a clock: the partial copy appears, or the snapshot
        // task finishes without ever exposing one (which fails below).
        let ready = loop {
            if !snapshots().is_empty() {
                break true;
            }
            if task.is_finished() {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

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
            ready,
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

    #[tokio::test]
    async fn startup_delivers_the_configured_firestore_location_only_under_strict() {
        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::{Actor, CommitEvent, LocalBackend};
        use fireemu_core_firestore::index::{IndexSet, PlanningContext};
        use fireemu_core_firestore::path::DocumentPath;
        use fireemu_core_firestore::store::{CommitVersion, Document, DocumentChange};
        use fireemu_core_types::ids::{DatabaseId, ProjectId};

        let dir =
            std::env::temp_dir().join(format!("fireemu-event-location-{}", std::process::id()));
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, json!({"functions": [{
            "name": "locationProbe", "generation": 2,
            "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "items/{id}"}
        }]}).to_string()).unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        for (profile, firestore, expected) in [
            ("strict", json!({}), "nam5"),
            ("strict", json!({"location": "us-central1"}), "us-central1"),
            ("emulator", json!({}), "nam5"),
            ("emulator", json!({"location": "us-central1"}), "nam5"),
        ] {
            let mut cfg = crate::config::RuntimeConfig::from_json(&json!({
                "schemaVersion": 1, "profile": profile, "firestore": firestore
            }))
            .unwrap();
            cfg.functions_source = Some(source.display().to_string());
            cfg.functions_runner = Some(vec!["python3".to_owned(), script.display().to_string()]);
            cfg.functions_manifest = Some(manifest_path.display().to_string());
            let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
            let backend = Arc::new(LocalBackend::new(
                Gateway {
                    ctx: PlanningContext {
                        edition: cfg.edition,
                        api_mode: cfg.api_mode,
                        policy: cfg.index_policy(),
                    },
                    indexes: IndexSet::default(),
                    enforce_limits: cfg.enforce_limits,
                },
                clock.clone(),
                cfg.seed,
            ));
            let runtime = super::start(&cfg, &clock, &backend, &hosts, "test-secret", false)
                .await
                .unwrap();
            let path = DocumentPath::parse(
                &ProjectId::try_new("demo-app").unwrap(),
                &DatabaseId::default_database(),
                "items/one",
            )
            .unwrap();
            runtime.on_commit(&CommitEvent {
                actor: Actor::system(),
                project: "demo-app".to_owned(),
                database: DatabaseId::DEFAULT.to_owned(),
                version: 1,
                commit_time: Some(cfg.clock_start),
                changes: Arc::from(vec![DocumentChange {
                    path: path.clone(),
                    before: None,
                    after: Some(Arc::new(Document {
                        path,
                        fields: BTreeMap::new(),
                        create_time: cfg.clock_start,
                        update_time: cfg.clock_start,
                        version: CommitVersion::default(),
                    })),
                }]),
            });
            let idle = runtime.await_idle(Duration::from_secs(5)).await;
            let logs = runtime.runner().logs_since(None);
            runtime.shutdown().await;
            idle.unwrap();
            let log = logs
                .lines
                .iter()
                .find(|line| line.function() == Some("locationProbe"))
                .expect("the event reached the runner");
            assert_eq!(log.fields()["location"], expected, "{profile}: {firestore}");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Review M1, path A, end to end: without App Check a configured manifest that omits
    /// `consumeAppCheckToken`, or says `disabled`, for a callable whose code consumes tokens
    /// is served as consuming, so the proxy removes the token before it.
    #[tokio::test]
    async fn without_app_check_a_configured_manifest_cannot_hide_token_consumption() {
        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_firestore::index::{IndexSet, PlanningContext};
        use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};

        let dir =
            std::env::temp_dir().join(format!("fireemu-consume-manifest-{}", std::process::id()));
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            json!({"functions": [
                {"name": "guarded", "trigger": {"type": "http", "callable": true, "enforceAppCheck": true, "consumeAppCheckToken": "disabled"}},
                {"name": "guardedV2", "generation": 2, "trigger": {"type": "http", "callable": true, "enforceAppCheck": true}},
                {"name": "add", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "disabled"}},
            ]})
            .to_string(),
        )
        .unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        for profile in ["emulator", "strict"] {
            let mut cfg = crate::config::RuntimeConfig::from_json(&json!({
                "schemaVersion": 1, "profile": profile
            }))
            .unwrap();
            cfg.functions_source = Some(source.display().to_string());
            cfg.functions_runner = Some(vec![
                "env".to_owned(),
                "FIREEMU_FAKE_CONSUME=enabled".to_owned(),
                "python3".to_owned(),
                script.display().to_string(),
            ]);
            cfg.functions_manifest = Some(manifest_path.display().to_string());
            let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
            let backend = Arc::new(LocalBackend::new(
                Gateway {
                    ctx: PlanningContext {
                        edition: cfg.edition,
                        api_mode: cfg.api_mode,
                        policy: cfg.index_policy(),
                    },
                    indexes: IndexSet::default(),
                    enforce_limits: cfg.enforce_limits,
                },
                clock.clone(),
                cfg.seed,
            ));
            let runtime = super::start(&cfg, &clock, &backend, &hosts, "test-secret", false)
                .await
                .unwrap();
            let served = |name: &str| match runtime.manifest().get(name).map(|f| &f.trigger) {
                Some(Trigger::Http {
                    consume_app_check_token,
                    ..
                }) => *consume_app_check_token,
                other => panic!("{name}: {other:?}"),
            };
            assert_eq!(
                served("guarded"),
                ConsumeAppCheckToken::Enabled,
                "{profile}"
            );
            assert_eq!(
                served("guardedV2"),
                ConsumeAppCheckToken::Enabled,
                "{profile}"
            );
            assert_eq!(served("add"), ConsumeAppCheckToken::Disabled, "{profile}");
            runtime.shutdown().await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Review 2 M1 end to end: without App Check, a configured manifest that calls a
    /// token-consuming (or unobserved) code-level callable an onRequest function still loads,
    /// and the token never reaches the runner, which would call the onCall wrapper anyway. A
    /// non-consuming callable configured the same way keeps receiving the field.
    #[tokio::test]
    async fn without_app_check_a_callable_configured_as_on_request_never_gets_the_token() {
        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_firestore::index::{IndexSet, PlanningContext};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let dir =
            std::env::temp_dir().join(format!("fireemu-consume-on-request-{}", std::process::id()));
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            json!({"functions": [
                {"name": "guarded", "trigger": {"type": "http", "callable": false}},
                {"name": "add", "trigger": {"type": "http", "callable": false}},
            ]})
            .to_string(),
        )
        .unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        for consume in ["enabled", "undetermined"] {
            let mut cfg = crate::config::RuntimeConfig::from_json(&json!({
                "schemaVersion": 1, "profile": "emulator"
            }))
            .unwrap();
            cfg.functions_source = Some(source.display().to_string());
            cfg.functions_runner = Some(vec![
                "env".to_owned(),
                format!("FIREEMU_FAKE_CONSUME={consume}"),
                "FIREEMU_FAKE_GUARDED_ENFORCE=false".to_owned(),
                "python3".to_owned(),
                script.display().to_string(),
            ]);
            cfg.functions_manifest = Some(manifest_path.display().to_string());
            let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
            let backend = Arc::new(LocalBackend::new(
                Gateway {
                    ctx: PlanningContext {
                        edition: cfg.edition,
                        api_mode: cfg.api_mode,
                        policy: cfg.index_policy(),
                    },
                    indexes: IndexSet::default(),
                    enforce_limits: cfg.enforce_limits,
                },
                clock.clone(),
                cfg.seed,
            ));
            let runtime = super::start(&cfg, &clock, &backend, &hosts, "test-secret", false)
                .await
                .expect("the codebase loads");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(fireemu_adapter_functions::http::serve_functions(
                listener,
                runtime.clone(),
                fireemu_adapter_functions::http::HttpAdmission::new(),
            ));
            let project = runtime.project().to_owned();
            for (function, stripped) in [("guarded", true), ("add", false)] {
                let body = br#"{"data":{}}"#;
                let request = format!(
                    "POST /{project}/us-central1/{function} HTTP/1.1\r\nhost: {addr}\r\nx-firebase-appcheck: token\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
                stream.write_all(request.as_bytes()).await.unwrap();
                stream.write_all(body).await.unwrap();
                let mut raw = Vec::new();
                stream.read_to_end(&mut raw).await.unwrap();
                let response = fireemu_adapter_functions::http::parse_response(&raw, "POST")
                    .expect("a well-formed response");
                assert_eq!(response.status, 200, "{consume} {function}");
                let echoed: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
                let forwarded = echoed["headers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|field| field[0] == "x-firebase-appcheck");
                assert_eq!(!forwarded, stripped, "{consume} {function}: {echoed}");
            }
            server.abort();
            runtime.shutdown().await;
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// With App Check, a configured onRequest route that names the callable-only option is
    /// served cleared, so the proxy forwards its raw App Check field as for any onRequest
    /// function.
    #[tokio::test]
    async fn with_app_check_a_configured_on_request_route_is_served_cleared() {
        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_firestore::index::{IndexSet, PlanningContext};
        use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};

        let dir =
            std::env::temp_dir().join(format!("fireemu-consume-cleared-{}", std::process::id()));
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            json!({"functions": [
                {"name": "echo", "trigger": {"type": "http", "callable": false, "consumeAppCheckToken": "enabled"}},
            ]})
            .to_string(),
        )
        .unwrap();
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        let mut cfg = crate::config::RuntimeConfig::from_json(&json!({
            "schemaVersion": 1, "profile": "emulator"
        }))
        .unwrap();
        cfg.functions_source = Some(source.display().to_string());
        cfg.functions_runner = Some(vec!["python3".to_owned(), script.display().to_string()]);
        cfg.functions_manifest = Some(manifest_path.display().to_string());
        let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
        let backend = Arc::new(LocalBackend::new(
            Gateway {
                ctx: PlanningContext {
                    edition: cfg.edition,
                    api_mode: cfg.api_mode,
                    policy: cfg.index_policy(),
                },
                indexes: IndexSet::default(),
                enforce_limits: cfg.enforce_limits,
            },
            clock.clone(),
            cfg.seed,
        ));
        let runtime = super::start(&cfg, &clock, &backend, &hosts, "test-secret", true)
            .await
            .expect("an agreeing manifest loads with App Check");
        let served = match runtime.manifest().get("echo").map(|f| &f.trigger) {
            Some(Trigger::Http {
                callable: false,
                consume_app_check_token,
                ..
            }) => *consume_app_check_token,
            other => panic!("{other:?}"),
        };
        runtime.shutdown().await;
        std::fs::remove_dir_all(dir).unwrap();
        assert_eq!(served, ConsumeAppCheckToken::Undetermined);
    }

    /// The real-SDK codebase, its observation file and a configured manifest that calls both
    /// callables task queues, for the runner-side withholding test.
    #[cfg(unix)]
    fn write_task_token_fixture(
        root: &std::path::Path,
        dir: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let sdk = std::env::var("FE_SOURCE_SDK_ROOT").map_or_else(
            |_| root.join("conformance/node_modules/firebase-functions"),
            std::path::PathBuf::from,
        );
        let node_modules = sdk
            .parent()
            .expect("the SDK lives in a node_modules directory");
        assert!(
            sdk.join("package.json").is_file(),
            "cached real firebase-functions is required at {}",
            sdk.display()
        );
        let _ = std::fs::remove_dir_all(dir);
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        std::os::unix::fs::symlink(node_modules, source.join("node_modules")).unwrap();
        let observed = dir.join("observed.jsonl");
        std::fs::write(source.join("package.json"), r#"{"main":"index.js"}"#).unwrap();
        std::fs::write(
            source.join("index.js"),
            format!(
                r#"const fs = require("node:fs");
const record = (event) => fs.appendFileSync({observed:?}, JSON.stringify(event) + "\n");
const appCheck = require("firebase-admin/app-check");
appCheck.getAppCheck = () => ({{
  verifyToken: async (token, options) => {{
    record({{ event: "verifyToken", consume: options?.consume === true }});
    throw new Error("no production App Check in tests");
  }},
}});
const {{ onCall }} = require("firebase-functions/v2/https");
const observe = (name) => (request) => {{
  record({{ event: "handler", name, header: request.rawRequest.headers["x-firebase-appcheck"] ?? null }});
  return {{ ok: true }};
}};
exports.guarded = onCall({{ consumeAppCheckToken: true }}, observe("guarded"));
exports.add = onCall({{}}, observe("add"));
"#,
                observed = observed.display().to_string()
            ),
        )
        .unwrap();
        let manifest_path = dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            json!({"functions": [
                {"name": "guarded", "generation": 2, "trigger": {"type": "tasks"}},
                {"name": "add", "generation": 2, "trigger": {"type": "tasks"}},
            ]})
            .to_string(),
        )
        .unwrap();
        (source, observed, manifest_path)
    }

    /// Review 3 M1 end to end with the real runner and the real firebase-functions: without
    /// App Check, a task that carries `X-Firebase-AppCheck` to a token-consuming callable which a
    /// configured manifest calls a task queue skips the proxy, and the runner withholds the token
    /// from the onCall wrapper itself. The Admin SDK's `verifyToken` is stubbed to record and
    /// throw, so even a regression never reaches production; the non-consuming near miss still
    /// gets its token (and the stub records its non-consuming verification).
    #[cfg(unix)]
    #[tokio::test]
    async fn without_app_check_the_runner_withholds_a_task_token_from_a_consuming_callable() {
        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_firestore::index::{IndexSet, PlanningContext};

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dir = std::env::temp_dir().join(format!("fireemu-consume-task-{}", std::process::id()));
        let (source, observed, manifest_path) = write_task_token_fixture(&root, &dir);
        let runner = root.join("tools/runner-node/index.mjs");
        let node = std::env::var("FIREEMU_NODE").unwrap_or_else(|_| "node".to_owned());
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: Some("127.0.0.1:5001".to_owned()),
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        let mut cfg = crate::config::RuntimeConfig::from_json(&json!({
            "schemaVersion": 1, "profile": "emulator"
        }))
        .unwrap();
        cfg.functions_source = Some(source.display().to_string());
        cfg.functions_runner = Some(vec![node, runner.display().to_string()]);
        cfg.functions_manifest = Some(manifest_path.display().to_string());
        let clock = Arc::new(Mutex::new(VirtualClock::new(cfg.clock_start)));
        let backend = Arc::new(LocalBackend::new(
            Gateway {
                ctx: PlanningContext {
                    edition: cfg.edition,
                    api_mode: cfg.api_mode,
                    policy: cfg.index_policy(),
                },
                indexes: IndexSet::default(),
                enforce_limits: cfg.enforce_limits,
            },
            clock.clone(),
            cfg.seed,
        ));
        let runtime = super::start(&cfg, &clock, &backend, &hosts, "test-secret", false)
            .await
            .expect("the codebase loads");
        let project = runtime.project().to_owned();
        for queue in ["guarded", "add"] {
            let task = json!({"task": {"httpRequest": {
                "body": super::base64_encode(br#"{"data":{}}"#),
                "headers": {"Content-Type": "application/json", "X-Firebase-AppCheck": "task-token"},
            }}});
            runtime
                .enqueue_task(&project, "us-central1", queue, &task)
                .expect("the task is accepted");
        }
        let idle = runtime.await_idle(Duration::from_secs(30)).await;
        runtime.shutdown().await;
        idle.unwrap();
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&observed)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        let handler = |name: &str| {
            events
                .iter()
                .find(|e| e["event"] == "handler" && e["name"] == name)
                .unwrap_or_else(|| panic!("{name} ran: {events:?}"))["header"]
                .clone()
        };
        assert_eq!(handler("guarded"), serde_json::Value::Null, "{events:?}");
        assert_eq!(handler("add"), json!("task-token"), "{events:?}");
        assert!(
            !events
                .iter()
                .any(|e| e["event"] == "verifyToken" && e["consume"] == true),
            "a consuming verifyToken ran: {events:?}"
        );
    }

    static BLOCKING_TEST_SIGNER: std::sync::OnceLock<
        Arc<fireemu_adapter_http::signing::RsaSigner>,
    > = std::sync::OnceLock::new();
    static OTHER_BLOCKING_TEST_SIGNER: std::sync::OnceLock<
        Arc<fireemu_adapter_http::signing::RsaSigner>,
    > = std::sync::OnceLock::new();

    #[test]
    fn signed_blocking_token_has_a_verifiable_signature() {
        use fireemu_core_auth::jwt::{base64url_decode, IdTokenSigner};
        let signer = BLOCKING_TEST_SIGNER
            .get_or_init(|| fireemu_adapter_http::signing::RsaSigner::from_seed(1).unwrap());
        let other = OTHER_BLOCKING_TEST_SIGNER
            .get_or_init(|| fireemu_adapter_http::signing::RsaSigner::from_seed(2).unwrap());
        let claims = serde_json::json!({"aud": "example"})
            .as_object()
            .unwrap()
            .clone();
        let jwt = super::signed_blocking_jwt(&claims, signer.as_ref());
        let parts: Vec<_> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&base64url_decode(parts[0]).unwrap()).unwrap();
        assert_eq!(
            header,
            serde_json::json!({"alg":"RS256", "kid":signer.kid(), "typ":"JWT"})
        );
        let input = format!("{}.{}", parts[0], parts[1]);
        let mut signature = base64url_decode(parts[2]).unwrap();
        assert!(signer.verify(input.as_bytes(), &signature));
        assert!(!other.verify(input.as_bytes(), &signature));
        let mut altered = input.into_bytes();
        let index = parts[0].len() + 1;
        altered[index] ^= 1;
        assert!(!signer.verify(&altered, &signature));
        signature[0] ^= 1;
        assert!(!signer.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature));
    }

    #[test]
    fn production_blocking_token_claims_and_audience() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::{determinism::SplitMix64, time::LogicalInstant};
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(
                NewUser::email("person@example.test"),
                LogicalInstant::from_unix_seconds(100),
            )
            .unwrap();
        let mut user = store.user_by_id(uid.as_str()).unwrap().clone();
        let context = fireemu_adapter_http::identity_toolkit::AuthBlockingContext {
            sign_in_method: Some("password".to_owned()),
            ..Default::default()
        };
        let audience = super::production_blocking_audience("demo-app", "us-central1", "fn");
        assert_eq!(
            audience,
            "https://us-central1-demo-app.cloudfunctions.net/fn"
        );
        let claims = super::blocking_auth_claims(
            "demo-app",
            None,
            BlockingAuthEvent::BeforeCreate,
            &context,
            Some(&user),
            "event",
            100,
            &audience,
            super::BlockingTokenShape::Production,
        );
        assert_eq!(claims["exp"], 400);
        assert_eq!(claims["locale"], "und");
        assert_eq!(claims["aud"], audience);
        assert!(claims["user_record"].get("disabled").is_none());
        let emulated = super::blocking_auth_claims(
            "demo-app",
            None,
            BlockingAuthEvent::BeforeCreate,
            &context,
            Some(&user),
            "event",
            100,
            &audience,
            super::BlockingTokenShape::Emulated,
        );
        assert_eq!(emulated["exp"], 170);
        assert_eq!(emulated["locale"], "en");
        assert_eq!(emulated["user_record"]["disabled"], false);
        assert_eq!(
            claims.keys().collect::<Vec<_>>(),
            emulated.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            claims.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "aud",
                "event_id",
                "event_type",
                "exp",
                "iat",
                "ip_address",
                "iss",
                "locale",
                "sign_in_method",
                "sub",
                "user_agent",
                "user_record"
            ]
        );
        user.disabled = true;
        let disabled = super::blocking_auth_claims(
            "demo-app",
            None,
            BlockingAuthEvent::BeforeCreate,
            &context,
            Some(&user),
            "event",
            100,
            &audience,
            super::BlockingTokenShape::Production,
        );
        assert_eq!(disabled["user_record"]["disabled"], true);
    }

    proptest::proptest! {
        #[test]
        fn production_audience_preserves_parts(project in "[a-z][a-z0-9-]{0,20}", region in "[a-z][a-z0-9-]{0,20}", function in "[a-z][a-z0-9-]{0,20}") {
            let result = super::production_blocking_audience(&project, &region, &function);
            let suffix = format!(".cloudfunctions.net/{function}");
            proptest::prop_assert!(result.starts_with("https://"));
            proptest::prop_assert!(result.ends_with(&suffix));
            let host = result.strip_prefix("https://").unwrap().strip_suffix(&suffix).unwrap();
            proptest::prop_assert_eq!(host.strip_prefix(&format!("{region}-")), Some(project.as_str()));
        }
    }

    fn claims_for(
        tenant: Option<&str>,
        event: fireemu_core_functions::manifest::BlockingAuthEvent,
        request: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
        user: &fireemu_core_auth::store::UserRecord,
    ) -> serde_json::Value {
        serde_json::Value::Object(super::blocking_auth_claims(
            "demo-app",
            tenant,
            event,
            request,
            Some(user),
            "event-1",
            1_788_004_860,
            "http://127.0.0.1:1/demo-app/us-central1/fn",
            super::BlockingTokenShape::Emulated,
        ))
    }

    /// The token's user record has production's members (AUTH-TENANT-BLOCKING comparison
    /// 2026-09-28): an absent member is left out, not null; `email_verified` comes with an
    /// address, `custom_claims` only when claims are set, `multi_factor` only with a factor.
    #[test]
    fn a_blocking_token_carries_the_account_as_identity_platform_does() {
        use fireemu_adapter_http::identity_toolkit::{
            AuthBlockingContext, AuthBlockingFactor, AuthBlockingProvider,
        };
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        let request = AuthBlockingContext {
            sign_in_method: Some("password".to_owned()),
            provider_data: vec![AuthBlockingProvider {
                provider_id: "password".to_owned(),
                uid: "person@example.test".to_owned(),
                display_name: None,
                email: Some("person@example.test".to_owned()),
                photo_url: None,
                phone_number: None,
            }],
            ..AuthBlockingContext::default()
        };
        let claims = claims_for(None, BlockingAuthEvent::BeforeCreate, &request, &user);
        assert_eq!(claims["event_type"], "beforeCreate");
        assert_eq!(claims["sign_in_method"], "password");
        assert_eq!(claims["sub"], uid.as_str());
        assert_eq!(claims["iss"], "https://securetoken.google.com/demo-app");
        assert_eq!(claims["iat"], 1_788_004_860);
        for key in ["user_agent", "ip_address", "locale"] {
            assert!(claims[key].is_string(), "{key}");
        }
        assert!(claims.get("tenant_id").is_none());
        let record = &claims["user_record"];
        assert_eq!(
            record.as_object().unwrap().keys().collect::<Vec<_>>(),
            [
                "disabled",
                "email",
                "email_verified",
                "metadata",
                "provider_data",
                "uid"
            ]
        );
        assert_eq!(record["email_verified"], false);
        assert_eq!(
            record["provider_data"],
            json!([{"provider_id": "password", "uid": "person@example.test", "email": "person@example.test"}])
        );
        assert_eq!(
            record["metadata"],
            json!({"creation_time": 1_788_004_860_000_i64})
        );

        // A tenant's token names it at the top and in the record; set claims and a factor are
        // carried; a phone account has no address and so no `email_verified`.
        let mut phone = user.clone();
        phone.email = None;
        phone.phone_number = Some("+15555550100".to_owned());
        phone.custom_claims =
            fireemu_core_auth::claims::CustomClaims::parse_attributes(r#"{"role":"a"}"#).unwrap();
        let factor = AuthBlockingContext {
            enrolled_factors: vec![AuthBlockingFactor {
                uid: "factor-1".to_owned(),
                display_name: None,
                enrollment_time: Some("2026-09-28T00:00:00Z".to_owned()),
                phone_number: Some("+15555550100".to_owned()),
                factor_id: "phone".to_owned(),
            }],
            ..request.clone()
        };
        let claims = claims_for(
            Some("customer"),
            BlockingAuthEvent::BeforeSignIn,
            &factor,
            &phone,
        );
        assert_eq!(claims["tenant_id"], "customer");
        let record = &claims["user_record"];
        assert_eq!(record["tenant_id"], "customer");
        assert!(record.get("email").is_none());
        assert!(record.get("email_verified").is_none());
        assert_eq!(record["phone_number"], "+15555550100");
        assert_eq!(record["custom_claims"], json!({"role": "a"}));
        assert_eq!(
            record["multi_factor"],
            json!({"enrolled_factors": [{"uid": "factor-1", "factor_id": "phone",
                "enrollment_time": "2026-09-28T00:00:00Z", "phone_number": "+15555550100"}]})
        );
    }

    #[test]
    fn a_blocking_hook_is_forwarded_only_for_its_own_project() {
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

    /// An identity-provider sign-in carries its profile, attributes and the forwarded tokens,
    /// and the token is the unsigned JWT the official Auth emulator sends.
    #[test]
    fn a_blocking_token_carries_the_provider_sign_in() {
        use fireemu_adapter_http::identity_toolkit::{
            AuthBlockingAdditionalUserInfo, AuthBlockingContext, AuthBlockingCredential,
        };
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        let attributes = json!({"roles": ["billing", "support"]});
        let request = AuthBlockingContext {
            credential: Some(AuthBlockingCredential {
                claims: Some(attributes.clone()),
                provider_id: "oidc.corp".to_owned(),
                sign_in_method: "oidc.corp".to_owned(),
                access_token: Some("access-sentinel".to_owned()),
                id_token: None,
                refresh_token: Some("refresh-sentinel".to_owned()),
            }),
            additional_user_info: Some(AuthBlockingAdditionalUserInfo {
                provider_id: "oidc.corp".to_owned(),
                profile: Some(attributes.clone()),
                is_new_user: false,
            }),
            sign_in_method: Some("oidc.corp".to_owned()),
            ..AuthBlockingContext::default()
        };
        let claims = claims_for(
            Some("customer"),
            BlockingAuthEvent::BeforeSignIn,
            &request,
            &user,
        );
        assert_eq!(claims["sign_in_method"], "oidc.corp");
        assert_eq!(claims["sign_in_attributes"], attributes);
        assert_eq!(claims["raw_user_info"], attributes.to_string());
        assert_eq!(claims["oauth_access_token"], "access-sentinel");
        assert_eq!(claims["oauth_refresh_token"], "refresh-sentinel");
        assert!(claims.get("oauth_id_token").is_none());

        let token = super::unsigned_jwt(claims.as_object().unwrap());
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], "");
        let decode = |part: &str| -> serde_json::Value {
            serde_json::from_slice(&fireemu_core_auth::jwt::base64url_decode(part).unwrap())
                .unwrap()
        };
        assert_eq!(decode(parts[0]), json!({"alg": "none", "typ": "JWT"}));
        assert_eq!(decode(parts[1]), claims);
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
        let targets = order
            .iter()
            .map(|(name, access_token, refresh_token)| {
                (
                    *name,
                    fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                    *access_token,
                    *refresh_token,
                )
            })
            .collect::<Vec<_>>();
        runtime_with_blocking_auth_targets(&targets).await
    }

    async fn runtime_with_blocking_auth_policy_order_and_env(
        order: &[(&str, bool, bool)],
        env: Vec<(String, String)>,
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        let targets = order
            .iter()
            .map(|(name, access_token, refresh_token)| {
                (
                    *name,
                    fireemu_core_functions::manifest::BlockingAuthEvent::BeforeCreate,
                    *access_token,
                    *refresh_token,
                )
            })
            .collect::<Vec<_>>();
        runtime_and_clock_with_blocking_auth_targets_env(&targets, env)
            .await
            .0
    }

    async fn runtime_with_blocking_auth_targets(
        targets: &[(
            &str,
            fireemu_core_functions::manifest::BlockingAuthEvent,
            bool,
            bool,
        )],
    ) -> Arc<fireemu_adapter_functions::runtime::FunctionsRuntime> {
        runtime_and_clock_with_blocking_auth_targets(targets)
            .await
            .0
    }

    async fn runtime_and_clock_with_blocking_auth_targets(
        targets: &[(
            &str,
            fireemu_core_functions::manifest::BlockingAuthEvent,
            bool,
            bool,
        )],
    ) -> (
        Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>,
        Arc<Mutex<VirtualClock>>,
    ) {
        runtime_and_clock_with_blocking_auth_targets_env(targets, Vec::new()).await
    }

    async fn runtime_and_clock_with_blocking_auth_targets_env(
        targets: &[(
            &str,
            fireemu_core_functions::manifest::BlockingAuthEvent,
            bool,
            bool,
        )],
        env: Vec<(String, String)>,
    ) -> (
        Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>,
        Arc<Mutex<VirtualClock>>,
    ) {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_core_functions::manifest::Trigger;
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
        for (name, event, access_token, refresh_token) in targets {
            let mut function = template.clone();
            function.name = (*name).to_owned();
            function.entry_point = (*name).to_owned();
            function.trigger = Trigger::BlockingAuth {
                event: *event,
                token_policy: fireemu_core_functions::manifest::BlockingAuthTokenPolicy {
                    access_token: *access_token,
                    refresh_token: *refresh_token,
                    ..Default::default()
                },
            };
            manifest.functions.push(function);
        }
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )));
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                retry_attempts: 1,
                ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
            },
            clock.clone(),
            Arc::new(runner),
            Some(spec),
        );
        (runtime, clock)
    }

    /// A message published through the control route (the runtime's own path) and one published
    /// through the broker are different messages on one topic, so they must not share a message id
    /// or a `CloudEvent` id: a handler that deduplicates by event id would drop a real message. Both
    /// paths start at their first message here, in a fresh daemon, as they do after a reset.
    #[tokio::test(flavor = "current_thread")]
    async fn a_control_route_publish_and_a_broker_publish_never_give_two_messages_one_id() {
        use fireemu_core_pubsub::{PubSubState, PubsubMessage, TopicName};
        let runtime = runtime_with_blocking_auth_targets(&[]).await;
        let mut broker = PubSubState::new(1);
        let topic = TopicName::new("demo-app", "jobs").unwrap();
        broker.create_topic(topic.clone(), BTreeMap::new()).unwrap();
        let now = fireemu_core_types::time::LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut ids: Vec<String> = Vec::new();
        for round in 0..60_u32 {
            // Interleave the two paths, with a different number of messages per round.
            for _ in 0..=(round % 3) {
                let message = PubsubMessage {
                    data: vec![1],
                    ..PubsubMessage::default()
                };
                let stored = broker.publish_shared(&topic, vec![message], now).unwrap();
                ids.extend(stored.iter().map(|stored| stored.message_id.clone()));
            }
            for _ in 0..=(round % 2) {
                ids.extend(runtime.publish("jobs", &[json!({"data": "YQ=="})]).unwrap());
            }
        }
        assert!(ids.len() > 100, "{}", ids.len());
        for id in &ids {
            assert!(
                id.len() == 17 && id.bytes().all(|byte| byte.is_ascii_digit()),
                "{id}"
            );
        }
        let mut distinct = ids.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            ids.len(),
            "two messages share an id: {ids:?}"
        );
    }

    /// The control hook maps the runtime's publish outcomes onto the control API's: a bad topic
    /// is invalid, a full queue is a capacity refusal that issues no ids, and a publish that
    /// fits answers its message ids.
    #[tokio::test(flavor = "current_thread")]
    async fn the_control_hook_maps_publish_outcomes_to_the_control_errors() {
        use fireemu_adapter_http::control::{FunctionsHook, PublishMessagesError};
        let runtime = runtime_with_blocking_auth_targets(&[]).await;
        let hook = super::Hook(runtime.clone());
        let message = json!({"data": "YQ=="});
        assert!(matches!(
            hook.publish("", std::slice::from_ref(&message)),
            Err(PublishMessagesError::Invalid(_))
        ));
        assert!(matches!(
            hook.publish(&"t".repeat(256), std::slice::from_ref(&message)),
            Err(PublishMessagesError::Invalid(_))
        ));
        let longest = "t".repeat(255);
        assert_eq!(
            hook.publish(&longest, std::slice::from_ref(&message))
                .unwrap()
                .len(),
            1,
            "255 characters is the longest topic"
        );
        assert_eq!(
            hook.publish("nobody", std::slice::from_ref(&message))
                .unwrap()
                .len(),
            1
        );
        // Each publish to `jobs` queues one delivery; reserving every other record fills the queue.
        let queued = || runtime.source_event_accounting().unwrap().published_records;
        let before = queued();
        assert_eq!(
            hook.publish("jobs", std::slice::from_ref(&message))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(queued(), before + 1, "one subscriber of `jobs`");
        let free = fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_RECORDS - queued();
        let others: Vec<serde_json::Value> = (0..free)
            .map(|n| json!({"data": "YQ==", "messageId": format!("m{n}")}))
            .collect();
        let reservation = runtime.reserve_pubsub_events("jobs", &others).unwrap();
        assert_eq!(
            hook.publish("jobs", std::slice::from_ref(&message)),
            Err(PublishMessagesError::Capacity)
        );
        drop(reservation);
        assert_eq!(hook.publish("jobs", &[message]).unwrap().len(), 1);
    }

    /// Identity Platform's email and SMS events are served by the strict profile's bridge only
    /// (the official Auth emulator registers `beforeCreate` and `beforeSignIn` only), and
    /// `beforeSendSms` is listed but never run (AUTH-TENANT-BLOCKING recording 2026-09-28).
    #[tokio::test(flavor = "current_thread")]
    async fn send_events_are_served_by_the_strict_bridge_only() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_functions::manifest::BlockingAuthEvent;

        let runtime = runtime_with_blocking_auth_targets(&[
            (
                "mailGuard",
                BlockingAuthEvent::BeforeSendEmail,
                false,
                false,
            ),
            ("smsGuard", BlockingAuthEvent::BeforeSendSms, false, false),
        ])
        .await;
        let bridge = |send_events: bool| {
            BlockingAuthBridge::new_with_selections(
                runtime.clone(),
                fireemu_core_functions::manifest::BlockingAuthSelections::default(),
                false,
            )
            .with_send_events(send_events)
        };
        let (emulator, strict) = (bridge(false), bridge(true));
        for event in [
            BlockingAuthEvent::BeforeSendEmail,
            BlockingAuthEvent::BeforeSendSms,
        ] {
            assert!(!emulator.handles(event), "{event:?}");
        }
        assert!(strict.handles(BlockingAuthEvent::BeforeSendEmail));
        assert!(!strict.handles(BlockingAuthEvent::BeforeSendSms));

        let explicit = json!({"triggers": {
            "beforeSendEmail": {"functionUri": "fireemu://functions/demo-app/us-central1/mailGuard"},
            "beforeSendSms": {"functionUri": "fireemu://functions/demo-app/us-central1/smsGuard"},
        }});
        let error = emulator
            .replace_blocking_auth_settings(&explicit)
            .expect_err("the emulator profile names no email event");
        assert!(error.contains("unsupported event"), "{error}");
        strict
            .replace_blocking_auth_settings(&explicit)
            .expect("the strict profile serves the email event");
        let projected = strict.blocking_auth_settings_value().unwrap();
        assert_eq!(
            projected["triggers"]["beforeSendEmail"]["functionUri"],
            "fireemu://functions/demo-app/us-central1/mailGuard"
        );
        assert_eq!(
            projected["triggers"]["beforeSendSms"]["functionUri"],
            "fireemu://functions/demo-app/us-central1/smsGuard"
        );
        assert!(projected["triggers"]["beforeCreate"].is_null());
        assert!(!strict.handles(BlockingAuthEvent::BeforeSendSms));

        strict
            .replace_blocking_auth_settings_masked(
                &json!({"triggers": {"beforeSendEmail": null}}),
                &["blockingFunctions.triggers.beforeSendEmail".to_owned()],
            )
            .expect("one email trigger is disabled by its mask");
        assert!(!strict.handles(BlockingAuthEvent::BeforeSendEmail));
        assert_eq!(
            strict.blocking_auth_settings_value().unwrap()["triggers"]["beforeSendSms"]
                ["functionUri"],
            "fireemu://functions/demo-app/us-central1/smsGuard"
        );
        // A whole trigger map replaces every served event's selection.
        strict
            .replace_blocking_auth_settings_masked(
                &json!({"triggers": {
                    "beforeSendEmail": {"functionUri": "fireemu://functions/demo-app/us-central1/mailGuard"}
                }}),
                &["blockingFunctions.triggers".to_owned()],
            )
            .expect("a whole trigger map");
        assert!(strict.handles(BlockingAuthEvent::BeforeSendEmail));
        assert!(
            strict.blocking_auth_settings_value().unwrap()["triggers"]["beforeSendSms"].is_null()
        );
        // The same mask names nothing the emulator profile serves.
        emulator
            .replace_blocking_auth_settings_masked(
                &json!({"triggers": {"beforeSendEmail": null}}),
                &["blockingFunctions.triggers.beforeSendEmail".to_owned()],
            )
            .unwrap();
        assert_eq!(emulator.settings_revision(), 0);

        // Discovery markers round-trip the email events through an export.
        let fresh = bridge(true);
        let exported = fresh
            .blocking_auth_settings_value_with_discovery_markers(true)
            .unwrap()
            .unwrap();
        assert_eq!(exported, json!({}));
        fresh
            .replace_blocking_auth_settings(&json!({"triggers": {"beforeCreate": null}}))
            .unwrap();
        let exported = fresh
            .blocking_auth_settings_value_with_discovery_markers(true)
            .unwrap()
            .unwrap();
        assert_eq!(exported["triggers"]["beforeSendEmail"], json!(null));
        runtime.shutdown().await;
    }

    /// The strict configuration's triggers are the served events' effective functions, and a
    /// trigger's time moves only when its own selection changes (AUTH-TENANT-BLOCKING recording
    /// 2026-09-28, config#config-blocking lists `beforeSendSms` too).
    #[tokio::test(flavor = "current_thread")]
    async fn the_trigger_list_names_effective_functions_and_their_change_times() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

        let (runtime, clock) = runtime_and_clock_with_blocking_auth_targets(&[
            ("createGuard", BlockingAuthEvent::BeforeCreate, false, false),
            (
                "mailGuard",
                BlockingAuthEvent::BeforeSendEmail,
                false,
                false,
            ),
            ("smsGuard", BlockingAuthEvent::BeforeSendSms, false, false),
        ])
        .await;
        let built = LogicalInstant::from_unix_seconds(1_788_004_860);
        let list = |bridge: &BlockingAuthBridge| {
            bridge
                .blocking_auth_triggers()
                .into_iter()
                .map(|trigger| (trigger.event, trigger.function, trigger.update_time))
                .collect::<Vec<_>>()
        };
        let emulator = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            false,
        );
        assert_eq!(
            list(&emulator),
            [(
                BlockingAuthEvent::BeforeCreate,
                "createGuard".to_owned(),
                built
            )]
        );
        let strict = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            false,
        )
        .with_send_events(true);
        assert_eq!(
            list(&strict),
            [
                (
                    BlockingAuthEvent::BeforeCreate,
                    "createGuard".to_owned(),
                    built
                ),
                (
                    BlockingAuthEvent::BeforeSendEmail,
                    "mailGuard".to_owned(),
                    built
                ),
                (
                    BlockingAuthEvent::BeforeSendSms,
                    "smsGuard".to_owned(),
                    built
                ),
            ]
        );
        let later = clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(60))
            .unwrap();
        strict
            .replace_blocking_auth_settings_masked(
                &json!({"triggers": {"beforeSendEmail": null}}),
                &["blockingFunctions.triggers.beforeSendEmail".to_owned()],
            )
            .unwrap();
        strict
            .replace_blocking_auth_settings_masked(
                &json!({"triggers": {"beforeCreate": {
                    "functionUri": "fireemu://functions/demo-app/us-central1/createGuard"
                }}}),
                &["blockingFunctions.triggers.beforeCreate".to_owned()],
            )
            .unwrap();
        assert_eq!(
            list(&strict),
            [
                (
                    BlockingAuthEvent::BeforeCreate,
                    "createGuard".to_owned(),
                    later
                ),
                (
                    BlockingAuthEvent::BeforeSendSms,
                    "smsGuard".to_owned(),
                    built
                ),
            ]
        );
        runtime.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bridge_delivers_production_and_emulated_tokens() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_auth::{
            jwt::base64url_decode,
            mfa::TotpPolicy,
            store::{AuthStore, NewUser},
        };
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::{determinism::SplitMix64, time::LogicalInstant};
        let signer = BLOCKING_TEST_SIGNER
            .get_or_init(|| fireemu_adapter_http::signing::RsaSigner::from_seed(1).unwrap())
            .clone();
        let runtime = runtime_with_blocking_auth_policy_order(&[("guardA", false, false)]).await;
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(
                NewUser::email("person@example.test"),
                LogicalInstant::from_unix_seconds(100),
            )
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        let production =
            BlockingAuthBridge::new(runtime.clone()).with_production_token(Some(signer));
        let emulated = BlockingAuthBridge::new(runtime.clone());
        let runtime_seconds = i64::try_from(runtime.now().as_nanos() / 1_000_000_000).unwrap();
        let before = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let answers = tokio::task::spawn_blocking(move || {
            [
                production
                    .invoke(BlockingAuthEvent::BeforeCreate, &user)
                    .unwrap(),
                emulated
                    .invoke(BlockingAuthEvent::BeforeCreate, &user)
                    .unwrap(),
            ]
        })
        .await
        .unwrap();
        let after = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        assert!(!(before..=after).contains(&runtime_seconds));
        for (answer, production) in answers.iter().zip([true, false]) {
            let body: serde_json::Value =
                serde_json::from_str(answer["body"].as_str().unwrap()).unwrap();
            let parts: Vec<_> = body["data"]["jwt"].as_str().unwrap().split('.').collect();
            let header: serde_json::Value =
                serde_json::from_slice(&base64url_decode(parts[0]).unwrap()).unwrap();
            let claims: serde_json::Value =
                serde_json::from_slice(&base64url_decode(parts[1]).unwrap()).unwrap();
            let headers = answer["headers"].as_array().unwrap();
            let get = |name: &str| {
                headers
                    .iter()
                    .find(|h| h[0] == name)
                    .map(|h| h[1].as_str().unwrap())
            };
            if production {
                assert!((before..=after).contains(&claims["iat"].as_i64().unwrap()));
                assert_eq!(header["alg"], "RS256");
                assert_eq!(
                    claims["aud"],
                    "https://us-central1-demo-app.cloudfunctions.net/guardA"
                );
                assert_eq!(
                    claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
                    300
                );
                assert_eq!(get("content-type"), Some("application/json; charset=utf-8"));
                assert_eq!(get("user-agent"), Some("Google-Firebase"));
            } else {
                assert_eq!(claims["iat"], runtime_seconds);
                assert_eq!(header["alg"], "none");
                assert_eq!(
                    claims["aud"],
                    format!(
                        "http://{}/demo-app/us-central1/guardA",
                        get("host").unwrap()
                    )
                );
                assert_eq!(get("content-type"), Some("application/json"));
                assert_eq!(get("user-agent"), None);
            }
        }
        runtime.shutdown().await;
    }

    /// Each invocation path delivers its event to the selected function and answers what the
    /// function answered (the fake runner echoes the request): the user events carry the
    /// user, the mail event the address, and a bridge without the email event runs nothing.
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::too_many_lines)] // One scenario per invocation path, checked together.
    async fn every_invocation_path_delivers_its_token_and_answers_the_function() {
        use fireemu_adapter_http::identity_toolkit::{AuthBlockingContext, AuthBlockingHook};
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let runtime = runtime_with_blocking_auth_targets(&[
            ("createGuard", BlockingAuthEvent::BeforeCreate, false, false),
            ("signInGuard", BlockingAuthEvent::BeforeSignIn, false, false),
            (
                "mailGuard",
                BlockingAuthEvent::BeforeSendEmail,
                false,
                false,
            ),
        ])
        .await;
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(
                NewUser::email("person@example.test"),
                LogicalInstant::from_unix_seconds(1_788_004_860),
            )
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        let strict = Arc::new(
            BlockingAuthBridge::new_with_selections(
                runtime.clone(),
                fireemu_core_functions::manifest::BlockingAuthSelections::default(),
                false,
            )
            .with_send_events(true),
        );
        let emulator = Arc::new(BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            false,
        ));
        let token = |answer: &serde_json::Value| -> serde_json::Value {
            let body: serde_json::Value =
                serde_json::from_str(answer["body"].as_str().unwrap()).unwrap();
            let jwt = body["data"]["jwt"].as_str().unwrap();
            let payload = jwt.split('.').nth(1).unwrap();
            serde_json::from_slice(&fireemu_core_auth::jwt::base64url_decode(payload).unwrap())
                .unwrap()
        };
        let (answers, none) = tokio::task::spawn_blocking(move || {
            let mail = AuthBlockingContext {
                email: Some("person@example.test".to_owned()),
                email_type: Some("PASSWORD_RESET".to_owned()),
                ..AuthBlockingContext::default()
            };
            let answers = [
                strict
                    .invoke_for("demo-app", None, BlockingAuthEvent::BeforeCreate, &user)
                    .unwrap(),
                strict
                    .invoke_for_with_context(
                        "demo-app",
                        Some("tenant-a"),
                        BlockingAuthEvent::BeforeSignIn,
                        &user,
                        &AuthBlockingContext::default(),
                    )
                    .unwrap(),
                strict.invoke_before_send_email("demo-app", &mail).unwrap(),
            ];
            let none = emulator
                .invoke_before_send_email("demo-app", &mail)
                .unwrap();
            (answers, none)
        })
        .await
        .unwrap();
        assert_eq!(none, None);
        let [create, sign_in, mail] = answers.map(Option::unwrap);
        for (answer, function) in [
            (&create, "createGuard"),
            (&sign_in, "signInGuard"),
            (&mail, "mailGuard"),
        ] {
            assert!(
                answer["path"]
                    .as_str()
                    .unwrap()
                    .ends_with(&format!("/{function}")),
                "{answer}"
            );
        }
        let create = token(&create);
        assert_eq!(create["event_type"], "beforeCreate");
        // Issued at the runtime clock's second (the clock stands at 1_788_004_860).
        assert_eq!(create["iat"], 1_788_004_860);
        assert_eq!(create["sub"], uid.as_str());
        let sign_in = token(&sign_in);
        assert_eq!(sign_in["event_type"], "beforeSignIn");
        assert_eq!(sign_in["tenant_id"], "tenant-a");
        let mail = token(&mail);
        assert_eq!(mail["event_type"], "beforeSendEmail");
        assert_eq!(mail["email"], "person@example.test");
        assert!(mail.get("sub").is_none() && mail.get("tenant_id").is_none());
        runtime.shutdown().await;
    }

    /// The emulator profile waits for a function as long as the official Auth emulator does:
    /// one that answers after eight seconds, past Identity Platform's seven, is served
    /// (closure review M1, 2026-09-28).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_emulator_profile_serves_a_function_slower_than_seven_seconds() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let (runtime, _) = runtime_and_clock_with_blocking_auth_targets_env(
            &[(
                "beforeCreate",
                BlockingAuthEvent::BeforeCreate,
                false,
                false,
            )],
            vec![(
                "FIREEMU_FAKE_BLOCKING_HANG_MS".to_owned(),
                "8000".to_owned(),
            )],
        )
        .await;
        let bridge = BlockingAuthBridge::new_with_selections(
            runtime.clone(),
            fireemu_core_functions::manifest::BlockingAuthSelections::default(),
            false,
        )
        .with_deadline_for(super::CompatibilityProfile::Emulator);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(
                NewUser::email("slow@example.test"),
                LogicalInstant::from_unix_seconds(1_788_004_860),
            )
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        let started = std::time::Instant::now();
        let answer = tokio::task::spawn_blocking(move || {
            bridge.invoke_for("demo-app", None, BlockingAuthEvent::BeforeCreate, &user)
        })
        .await
        .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(8));
        assert!(answer.is_ok_and(|answer| answer.is_some()));
        runtime.shutdown().await;
    }

    /// A mail event's token names the address and the kind of mail and no user
    /// (AUTH-TENANT-BLOCKING recording 2026-09-28, send#reset-mail-echo: `u` null, `au` email
    /// and isNewUser).
    #[test]
    fn a_mail_event_token_names_the_address_and_no_user() {
        let context = fireemu_adapter_http::identity_toolkit::AuthBlockingContext {
            email: Some("a@example.com".to_owned()),
            email_type: Some("PASSWORD_RESET".to_owned()),
            ..Default::default()
        };
        let claims = super::blocking_auth_claims(
            "demo-app",
            None,
            fireemu_core_functions::manifest::BlockingAuthEvent::BeforeSendEmail,
            &context,
            None,
            "event-1",
            1_788_004_860,
            "http://127.0.0.1:1/demo-app/us-central1/fn",
            super::BlockingTokenShape::Emulated,
        );
        assert_eq!(claims["event_type"], "beforeSendEmail");
        assert_eq!(claims["email"], "a@example.com");
        assert_eq!(claims["email_type"], "PASSWORD_RESET");
        for absent in ["sub", "user_record", "tenant_id", "sign_in_method"] {
            assert!(!claims.contains_key(absent), "{absent}");
        }
    }

    /// The daemon's bridge takes its served events and its deadline from the profile
    /// (closure re-review, 2026-09-28).
    #[tokio::test(flavor = "current_thread")]
    async fn the_daemon_bridge_follows_the_profile() {
        let runtime = runtime_with_blocking_auth_targets(&[]).await;
        let bridge = |profile| {
            BlockingAuthBridge::new_with_selections(
                runtime.clone(),
                fireemu_core_functions::manifest::BlockingAuthSelections::default(),
                false,
            )
            .for_profile(profile)
        };
        let strict = bridge(super::CompatibilityProfile::Strict);
        assert!(strict.send_events);
        assert_eq!(strict.deadline, Duration::from_secs(7));
        let emulator = bridge(super::CompatibilityProfile::Emulator);
        assert!(!emulator.send_events);
        assert_eq!(emulator.deadline, Duration::from_secs(60));
        runtime.shutdown().await;
    }

    /// Only the strict profile serves the email and SMS events, and a local selection is
    /// checked against the manifest before the bridge is built.
    #[test]
    fn the_strict_profile_serves_send_events_and_selections_are_checked() {
        use fireemu_core_functions::manifest::{BlockingAuthSelection, BlockingAuthSelections};

        assert!(super::serves_send_blocking_events(
            super::CompatibilityProfile::Strict
        ));
        assert!(!super::serves_send_blocking_events(
            super::CompatibilityProfile::Emulator
        ));
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "create", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeCreate"}},
        ]}))
        .unwrap();
        let explicit = |function: &str| BlockingAuthSelections {
            before_create: BlockingAuthSelection::Explicit {
                function: function.to_owned(),
                region: None,
            },
            ..BlockingAuthSelections::default()
        };
        super::check_blocking_auth_selections(&manifest, &BlockingAuthSelections::default())
            .unwrap();
        super::check_blocking_auth_selections(&manifest, &explicit("create")).unwrap();
        let error =
            super::check_blocking_auth_selections(&manifest, &explicit("missing")).unwrap_err();
        assert!(error.contains("missing"), "{error}");
    }

    #[test]
    fn strict_refuses_eventarc_source_filters_with_the_production_message() {
        for channel in [
            None,
            Some("locations/us-central1/channels/custom"),
            Some("projects/demo-test/locations/us-central1/channels/custom"),
        ] {
            let mut document = json!({"functions": [
                {"name": "accepted", "generation": 2, "trigger": {"type": "http"}},
                {"name": "customSource", "region": "us-central1", "generation": 2, "trigger": {
                    "type": "eventarc", "eventType": "com.example.done",
                    "filters": {"type": "com.example.done", "source": "urn:example:source"}
                }}
            ]});
            if let Some(channel) = channel {
                document["functions"][1]["trigger"]["channel"] = json!(channel);
            }
            let now = crate::config::RuntimeConfig::default().clock_start;
            assert_eq!(
                super::manifest_for_profile(CompatibilityProfile::Strict, &document, now)
                    .unwrap_err(),
                "manifest: function \"customSource\": Cloud Functions refuses this Eventarc trigger (HTTP 400): Validation failed for trigger projects/<project>/locations/us-central1/triggers/<trigger-id>: The request was invalid: invalid filter 'source' in trigger.event_filters: filter 'source' is not allowed for this trigger"
            );
            assert_eq!(
                super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now)
                    .unwrap(),
                parse_manifest(&document).unwrap()
            );
        }
    }

    #[test]
    fn eventarc_type_only_and_unrecorded_filters_remain_accepted_by_both_profiles() {
        for filters in [
            json!({"type": "com.example.done"}),
            json!({"type": "com.example.done", "sourcex": "urn:example:source"}),
            json!({"type": "com.example.done", "Source": "urn:example:source"}),
            json!({"type": "com.example.done", "tenant": "example"}),
            json!({"type": "com.example.done", "subjectx": "example"}),
        ] {
            let document = json!({"functions": [{"name": "custom", "generation": 2,
                "trigger": {"type": "eventarc", "eventType": "com.example.done", "filters": filters}
            }]});
            for profile in [CompatibilityProfile::Strict, CompatibilityProfile::Emulator] {
                assert_eq!(
                    super::manifest_for_profile(
                        profile,
                        &document,
                        crate::config::RuntimeConfig::default().clock_start,
                    )
                    .unwrap(),
                    parse_manifest(&document).unwrap(),
                    "{profile:?}: {filters}"
                );
            }
        }
    }

    #[test]
    fn strict_refuses_eventarc_subject_filters_and_keeps_source_precedence() {
        for channel in [
            None,
            Some("locations/us-central1/channels/custom"),
            Some("projects/demo-test/locations/us-central1/channels/custom"),
        ] {
            for (filters, attribute) in [
                (
                    json!({"tenant": "example", "subject": "example"}),
                    "subject",
                ),
                // Subject-only and combined-filter ordering are conservative local policies.
                (json!({"subject": "example"}), "subject"),
                (
                    json!({"source": "urn:example:source", "subject": "example"}),
                    "source",
                ),
            ] {
                let mut document = json!({"functions": [{"name": "customFilter",
                    "region": "us-central1", "generation": 2, "trigger": {
                        "type": "eventarc", "eventType": "com.example.done", "filters": filters
                    }
                }]});
                if let Some(channel) = channel {
                    document["functions"][0]["trigger"]["channel"] = json!(channel);
                }
                let now = crate::config::RuntimeConfig::default().clock_start;
                assert_eq!(
                    super::manifest_for_profile(CompatibilityProfile::Strict, &document, now)
                        .unwrap_err(),
                    format!(
                        "manifest: function \"customFilter\": Cloud Functions refuses this Eventarc trigger (HTTP 400): Validation failed for trigger projects/<project>/locations/us-central1/triggers/<trigger-id>: The request was invalid: invalid filter '{attribute}' in trigger.event_filters: filter '{attribute}' is not allowed for this trigger"
                    )
                );
                assert_eq!(
                    super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now)
                        .unwrap(),
                    parse_manifest(&document).unwrap()
                );
            }
        }
    }

    #[test]
    fn eventarc_source_refusal_does_not_claim_google_channel_triggers() {
        let document = json!({"functions": [{"name": "alert", "generation": 2,
            "trigger": {"type": "eventarc", "eventType": "google.firebase.firebasealerts.alerts.v1.published",
                "channel": "google", "filters": {"source": "urn:example:source", "subject": "example"}}
        }]});
        assert_eq!(
            super::manifest_for_profile(
                CompatibilityProfile::Strict,
                &document,
                crate::config::RuntimeConfig::default().clock_start,
            )
            .unwrap(),
            parse_manifest(&document).unwrap()
        );
    }

    /// The refusal check over a manifest document: parse it, then ask the profile.
    fn scheduler_check(
        profile: super::CompatibilityProfile,
        document: &serde_json::Value,
    ) -> Result<(), String> {
        let manifest = parse_manifest(document).unwrap();
        super::check_scheduler_refusals_for(profile, &manifest, document)
    }

    const COUNT_TEXT: &str = "invalid retry count. The retry_count must be a positive integer less than 5: invalid argument";
    const NANOS_TEXT: &str = "retryConfig.max_retry_duration.nanos cannot be set: invalid argument";

    fn scheduled_with(retry_config: serde_json::Value) -> serde_json::Value {
        let mut document = json!({"functions": [
            {"name": "job", "trigger": {"type": "schedule", "schedule": "every 1 minutes"}},
        ]});
        document["functions"][0]["trigger"]["retryConfig"] = retry_config;
        document
    }

    /// The production refusal of a Cloud Scheduler job whose `retryCount` is 6 or more (run
    /// `e0ec2f416f5ea7e8`, HTTP 400 `INVALID_ARGUMENT`): the strict profile refuses with production's
    /// text, the emulator profile (the official emulator creates no Scheduler job) refuses nothing.
    #[test]
    fn strict_refuses_a_schedule_whose_retry_count_cloud_scheduler_refuses() {
        // The declaration of the recorded run, with its refused count of 6, for each generation.
        for generation in [1, 2] {
            let document = json!({"functions": [
                {"name": "ok", "generation": generation, "trigger": {"type": "schedule", "schedule": "every 1 minutes"}},
                {"name": "schedRetryV2", "generation": generation, "trigger": {"type": "schedule", "schedule": "every 5 minutes", "timeZone": "Asia/Tokyo",
                    "retryConfig": {"retryCount": 6, "minBackoffSeconds": 4, "maxBackoffSeconds": 50, "maxDoublings": 2}}},
            ]});
            assert_eq!(
                scheduler_check(super::CompatibilityProfile::Strict, &document),
                Err(format!(
                    "manifest: function \"schedRetryV2\": Cloud Scheduler refuses this schedule's job (HTTP 400 INVALID_ARGUMENT): {COUNT_TEXT}"
                )),
                "generation {generation}"
            );
            assert_eq!(
                scheduler_check(super::CompatibilityProfile::Emulator, &document),
                Ok(()),
                "the emulator profile completes what the official emulator completes"
            );
        }
    }

    /// Recorded boundary: 0 (run `e0ec2f416f5ea7e8`, `schedSlowV2`) through 5 (run `156715222b86ea44`, the
    /// `retry5` job answered 200) are accepted by both profiles; 6 and above are refused by strict only.
    #[test]
    fn the_scheduler_retry_count_boundary_is_the_recorded_six() {
        for profile in [
            super::CompatibilityProfile::Strict,
            super::CompatibilityProfile::Emulator,
        ] {
            for count in [json!(0), json!(1), json!(4), json!(5)] {
                assert_eq!(
                    scheduler_check(
                        profile,
                        &scheduled_with(json!({"retryCount": count.clone()}))
                    ),
                    Ok(()),
                    "{count}"
                );
            }
        }
        for count in [json!(6), json!(7), json!(1000)] {
            assert!(
                scheduler_check(
                    super::CompatibilityProfile::Strict,
                    &scheduled_with(json!({"retryCount": count.clone()}))
                )
                .is_err(),
                "{count}"
            );
            assert!(
                scheduler_check(
                    super::CompatibilityProfile::Emulator,
                    &scheduled_with(json!({"retryCount": count.clone()}))
                )
                .is_ok(),
                "{count}"
            );
        }
        let other = json!({"functions": [
            {"name": "h", "trigger": {"type": "http"}},
            {"name": "plain", "trigger": {"type": "schedule", "schedule": "every 1 minutes"}},
        ]});
        assert_eq!(
            scheduler_check(super::CompatibilityProfile::Strict, &other),
            Ok(())
        );
    }

    /// Recorded in run `156715222b86ea44`: a retry configuration whose `maxRetryDuration` is `20.5s` was refused
    /// (HTTP 400 `INVALID_ARGUMENT`); firebase-tools writes `maxRetrySeconds` as `${seconds}s`, so a fractional
    /// `maxRetrySeconds` is refused by strict with that text and accepted by the emulator profile.
    #[test]
    fn strict_refuses_a_fractional_max_retry_duration_and_the_emulator_profile_does_not() {
        let recorded = json!({"retryCount": 3, "maxRetrySeconds": 20.5, "minBackoffSeconds": 2.5, "maxBackoffSeconds": 20, "maxDoublings": 1});
        assert_eq!(
            scheduler_check(
                super::CompatibilityProfile::Strict,
                &scheduled_with(recorded.clone())
            ),
            Err(format!(
                "manifest: function \"job\": Cloud Scheduler refuses this schedule's job (HTTP 400 INVALID_ARGUMENT): {NANOS_TEXT}"
            ))
        );
        assert_eq!(
            scheduler_check(
                super::CompatibilityProfile::Emulator,
                &scheduled_with(recorded)
            ),
            Ok(())
        );
        // Both generations; any fraction, large or small.
        for generation in [1, 2] {
            for seconds in [json!(0.5), json!(30.25), json!(1e-3)] {
                let document = json!({"functions": [
                    {"name": "job", "generation": generation, "trigger": {"type": "schedule", "schedule": "every 1 minutes", "retryConfig": {"maxRetrySeconds": seconds.clone()}}},
                ]});
                assert!(
                    scheduler_check(super::CompatibilityProfile::Strict, &document)
                        .unwrap_err()
                        .ends_with(NANOS_TEXT),
                    "{generation} {seconds}"
                );
            }
        }
    }

    /// Near misses of the fractional rule: whole seconds (written with or without a fraction), zero, a
    /// fractional minimum or maximum backoff (not claimed: the recorded message names only `maxRetryDuration`),
    /// a fractional value on a function that is not scheduled, and a count refusal that wins for its function.
    #[test]
    fn the_fractional_refusal_claims_only_max_retry_seconds_of_a_schedule() {
        for retry in [
            json!({"maxRetrySeconds": 30}),
            json!({"maxRetrySeconds": 30.0}),
            json!({"maxRetrySeconds": 0}),
            json!({"maxBackoffSeconds": 20.5}),
            json!({"minBackoffSeconds": 2.5}),
            json!({"maxDoublings": 1, "retryCount": 5}),
        ] {
            assert_eq!(
                scheduler_check(
                    super::CompatibilityProfile::Strict,
                    &scheduled_with(retry.clone())
                ),
                Ok(()),
                "{retry}"
            );
        }
        let unscheduled = json!({"functions": [
            {"name": "h", "trigger": {"type": "http", "retryConfig": {"maxRetrySeconds": 20.5}}},
        ]});
        assert_eq!(
            scheduler_check(super::CompatibilityProfile::Strict, &unscheduled),
            Ok(())
        );
        let both = scheduled_with(json!({"retryCount": 6, "maxRetrySeconds": 20.5}));
        assert!(scheduler_check(super::CompatibilityProfile::Strict, &both)
            .unwrap_err()
            .ends_with(COUNT_TEXT));
        let second = json!({"functions": [
            {"name": "a", "trigger": {"type": "schedule", "schedule": "every 1 minutes", "retryConfig": {"maxRetrySeconds": 20.5}}},
            {"name": "b", "trigger": {"type": "schedule", "schedule": "every 1 minutes", "retryConfig": {"retryCount": 6}}},
        ]});
        let error = scheduler_check(super::CompatibilityProfile::Strict, &second).unwrap_err();
        assert!(
            error.contains("\"a\"") && error.ends_with(NANOS_TEXT),
            "{error}"
        );
    }

    /// The served manifest is where the refusals are applied: strict fails with production's text, emulator
    /// parses the same declaration, and the blocking-function handling of each profile is unchanged.
    #[test]
    fn the_served_manifest_applies_the_scheduler_refusal_by_profile() {
        let declared = json!({"functions": [
            {"name": "schedRetryV2", "generation": 2, "trigger": {"type": "schedule", "schedule": "every 5 minutes", "retryConfig": {"retryCount": 6}}},
            {"name": "mail", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeSendEmail"}},
        ]});
        let error = super::manifest_for_profile(
            super::CompatibilityProfile::Strict,
            &declared,
            crate::config::RuntimeConfig::default().clock_start,
        )
        .unwrap_err();
        assert!(error.contains("schedRetryV2"), "{error}");
        assert!(error.contains(COUNT_TEXT), "{error}");
        let nanos = scheduled_with(json!({"maxRetrySeconds": 20.5}));
        assert!(super::manifest_for_profile(
            super::CompatibilityProfile::Strict,
            &nanos,
            crate::config::RuntimeConfig::default().clock_start
        )
        .unwrap_err()
        .contains(NANOS_TEXT));
        let emulator = super::manifest_for_profile(
            super::CompatibilityProfile::Emulator,
            &declared,
            crate::config::RuntimeConfig::default().clock_start,
        )
        .unwrap();
        assert_eq!(
            emulator
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["schedRetryV2"],
            "the emulator profile keeps the schedule and sets the send-blocking function aside"
        );
        let accepted = json!({"functions": [
            {"name": "ok", "trigger": {"type": "schedule", "schedule": "every 5 minutes", "retryConfig": {"retryCount": 5}}},
            {"name": "mail", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeSendEmail"}},
        ]});
        let strict = super::manifest_for_profile(
            super::CompatibilityProfile::Strict,
            &accepted,
            crate::config::RuntimeConfig::default().clock_start,
        )
        .unwrap();
        assert_eq!(
            strict.functions.len(),
            2,
            "strict serves the send-blocking function"
        );
    }

    #[test]
    fn calendar_v6_cr11_gr11_rt05_strict_refusals_preserve_emulator_acceptance() {
        use fireemu_core_types::time::LogicalInstant;

        let mut failures = Vec::new();
        for (id, schedule, zone, retry, reason) in [
            ("cr11", "@daily", "UTC", json!({}), "schedule:"),
            ("gr11", "every mond 09:00", "UTC", json!({}), "schedule:"),
            ("rt05", "0 9 * * *", "UTC", json!({"minBackoffSeconds": 100, "maxBackoffSeconds": 50}), "retryConfig.min_backoff_duration must be less than or equal to retryConfig.max_backoff_duration: invalid argument"),
        ] {
            let document = json!({"functions": [{"name": id, "generation": 2, "trigger": {
                "type": "schedule", "schedule": schedule, "timeZone": zone, "retryConfig": retry,
            }}]});
            for anchor in ["2026-10-04T23:49:00Z", "2026-10-05T00:30:00Z"] {
                let now = LogicalInstant::parse_rfc3339(anchor).unwrap();
                let strict = super::manifest_for_profile(CompatibilityProfile::Strict, &document, now);
                match strict {
                    Err(error) if error.contains(reason) => {}
                    other => failures.push(format!("{id}: expected refusal {reason:?}, got {other:?}")),
                }
                assert!(super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now).is_ok(), "{id}: official emulator accepts this declaration");
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn calendar_v6_cr13_returns_the_invalid_schedule_message_in_both_recordings() {
        use fireemu_core_types::time::LogicalInstant;

        let document = json!({"functions": [{"name": "cr13", "generation": 2, "trigger": {
            "type": "schedule", "schedule": "0 0 30 2 *", "timeZone": "UTC",
        }}]});
        for anchor in ["2026-10-04T23:49:19.120Z", "2026-10-05T00:30:30.960Z"] {
            let now = LogicalInstant::parse_rfc3339(anchor).unwrap();
            assert_eq!(super::manifest_for_profile(CompatibilityProfile::Strict, &document, now).unwrap_err(),
                "manifest: function \"cr13\": schedule: The provided schedule or timezone are invalid.");
            assert!(
                super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now).is_ok()
            );
        }
    }

    #[test]
    fn a_rare_valid_schedule_is_not_reported_as_invalid() {
        let document = json!({"functions": [{"name": "rare", "trigger": {
            "type": "schedule", "schedule": "5th mon of feb 00:00", "timeZone": "UTC",
        }}]});
        let now = fireemu_core_types::time::LogicalInstant::parse_rfc3339("2026-10-05T00:30:00Z")
            .unwrap();
        if let Err(error) =
            super::manifest_for_profile(CompatibilityProfile::Strict, &document, now)
        {
            assert_eq!(
                error,
                "manifest: function \"rare\": schedule: Cannot find next schedule time."
            );
        }
    }

    #[test]
    fn calendar_v6_days_exceeding_every_listed_month_are_reported_as_invalid() {
        // The recorded class (cr13) and its numeric generalization get the invalid message;
        // other shapes are unrecorded and keep the generic one.
        for (schedule, reason) in [
            (
                "0 0 30 2 *",
                "The provided schedule or timezone are invalid.",
            ),
            (
                "0 0 31 4,6 *",
                "The provided schedule or timezone are invalid.",
            ),
            ("0 0 30,31 2 *", "Cannot find next schedule time."),
            ("0 0 31 apr,jun *", "Cannot find next schedule time."),
        ] {
            let document = json!({"functions": [{"name": "impossible", "trigger": {
                "type": "schedule", "schedule": schedule, "timeZone": "UTC",
            }}]});
            let error = super::manifest_for_profile(
                CompatibilityProfile::Strict,
                &document,
                crate::config::RuntimeConfig::default().clock_start,
            )
            .unwrap_err();
            assert_eq!(
                error,
                format!("manifest: function \"impossible\": schedule: {reason}"),
                "{schedule}"
            );
        }
    }

    #[test]
    fn calendar_v6_ds01_returns_the_unreachable_schedule_message_in_both_recordings() {
        use fireemu_core_types::time::LogicalInstant;

        let document = json!({"functions": [{"name": "ds01", "generation": 2, "trigger": {
            "type": "schedule", "schedule": "2nd sun of mar 2:30", "timeZone": "America/New_York",
        }}]});
        for anchor in ["2026-10-04T23:50:07.764Z", "2026-10-05T00:31:16.289Z"] {
            let now = LogicalInstant::parse_rfc3339(anchor).unwrap();
            assert_eq!(
                super::manifest_for_profile(CompatibilityProfile::Strict, &document, now)
                    .unwrap_err(),
                "manifest: function \"ds01\": schedule: Cannot find next schedule time."
            );
            assert!(
                super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now).is_ok()
            );
        }
    }

    #[test]
    fn calendar_v6_gr13_strict_accepts_synchronized_minutes_in_both_recordings() {
        use fireemu_core_types::time::LogicalInstant;

        let document = json!({"functions": [{"name": "gr13", "generation": 2, "trigger": {
            "type": "schedule", "schedule": "every 20 minutes synchronized", "timeZone": "UTC",
        }}]});
        let zone = fireemu_adapter_functions::zone::resolve(Some("UTC")).unwrap();
        for (anchor, expected) in [
            ("2026-10-04T23:49:48.953022Z", "2026-10-05T00:00:00Z"),
            ("2026-10-05T00:30:59.848634Z", "2026-10-05T00:40:00Z"),
        ] {
            let now = LogicalInstant::parse_rfc3339(anchor).unwrap();
            let manifest =
                super::manifest_for_profile(CompatibilityProfile::Strict, &document, now)
                    .expect("gr13: both recordings accept synchronized grammar");
            let (_, schedule, _) = manifest.scheduled().next().unwrap();
            assert_eq!(
                schedule.next_after_in(now, &*zone),
                Some(LogicalInstant::parse_rfc3339(expected).unwrap())
            );
        }
        let emulator = super::manifest_for_profile(
            CompatibilityProfile::Emulator,
            &document,
            crate::config::RuntimeConfig::default().clock_start,
        )
        .unwrap();
        assert_eq!(emulator.scheduled().count(), 0);
        assert_eq!(
            super::check_ignored(&emulator, super::UnservedTriggers::Refuse).unwrap(),
            ["functions[us-central1-gr13]: function ignored (schedule): no scheduled job: schedule: unrecognised schedule \"every 20 minutes synchronized\""]
        );
        let unrecorded = json!({"functions": [{"name": "gr13", "generation": 2, "trigger": {
            "type": "schedule", "schedule": "every 7 minutes synchronized", "timeZone": "UTC",
        }}]});
        assert!(super::manifest_for_profile(
            CompatibilityProfile::Strict,
            &unrecorded,
            crate::config::RuntimeConfig::default().clock_start
        )
        .is_err());
    }

    #[test]
    fn calendar_v6_cr12_numeric_slash_is_a_single_value_only_in_strict() {
        use fireemu_core_types::time::LogicalInstant;

        let document = json!({"functions": [{"name": "cr12", "generation": 2, "trigger": {
            "type": "schedule", "schedule": "5/15 * * * *", "timeZone": "UTC",
        }}]});
        let zone = fireemu_adapter_functions::zone::resolve(Some("UTC")).unwrap();
        for (anchor, strict_next, emulator_next) in [
            (
                "2026-10-04T23:49:16.807Z",
                "2026-10-05T00:05:00Z",
                "2026-10-04T23:50:00Z",
            ),
            (
                "2026-10-05T00:30:27.733Z",
                "2026-10-05T01:05:00Z",
                "2026-10-05T00:35:00Z",
            ),
        ] {
            let now = LogicalInstant::parse_rfc3339(anchor).unwrap();
            for (profile, expected) in [
                (CompatibilityProfile::Strict, strict_next),
                (CompatibilityProfile::Emulator, emulator_next),
            ] {
                let manifest = super::manifest_for_profile(profile, &document, now).unwrap();
                let (_, schedule, _) = manifest.scheduled().next().unwrap();
                assert_eq!(
                    schedule.next_after_in(now, &*zone),
                    Some(LogicalInstant::parse_rfc3339(expected).unwrap()),
                    "cr12: {profile:?}"
                );
            }
        }
    }

    #[test]
    fn calendar_v6_gr01_gr07_gr08_accepted_grammar_matches_both_recordings() {
        use fireemu_core_types::time::LogicalInstant;

        let zone = fireemu_adapter_functions::zone::resolve(Some("UTC")).unwrap();
        let mut failures = Vec::new();
        for (id, schedule, observations) in [
            (
                "gr01",
                "every minute",
                [
                    ("2026-10-04T23:49:20.930Z", Some("2026-10-04T23:50:00Z")),
                    ("2026-10-05T00:30:32.330Z", Some("2026-10-05T00:31:00Z")),
                ],
            ),
            (
                "gr07",
                "1,15 of jan,jul 12:34",
                [
                    ("2026-10-04T23:49:36.706Z", Some("2027-01-01T12:34:00Z")),
                    ("2026-10-05T00:30:48.352Z", Some("2027-01-01T12:34:00Z")),
                ],
            ),
            // gr08: creation-minute timing is pinned separately by the runtime tests.
            (
                "gr08",
                "every 25 hours",
                [
                    ("2026-10-04T23:49:39.448Z", None),
                    ("2026-10-05T00:30:50.476Z", None),
                ],
            ),
        ] {
            let document = json!({"functions": [{"name": id, "generation": 2, "trigger": {
                "type": "schedule", "schedule": schedule, "timeZone": "UTC",
            }}]});
            for (anchor, expected) in observations {
                let now = LogicalInstant::parse_rfc3339(anchor).unwrap();
                for profile in [CompatibilityProfile::Strict, CompatibilityProfile::Emulator] {
                    let manifest = match super::manifest_for_profile(profile, &document, now) {
                        Ok(manifest) => manifest,
                        Err(error) => {
                            failures.push(format!("{id}: {profile:?}: {error}"));
                            continue;
                        }
                    };
                    let (_, parsed, _) = manifest.scheduled().next().unwrap();
                    assert_eq!(parsed.as_str(), schedule, "{id}");
                    if let Some(expected) = expected {
                        assert_eq!(
                            parsed.next_after_in(now, &*zone),
                            Some(LogicalInstant::parse_rfc3339(expected).unwrap()),
                            "{id}: {profile:?}"
                        );
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The startup path itself: `start_codebase` applies the profile to the manifest it reads (here a configured
    /// manifest file, with the fake runner), so a strict run refuses to start on a schedule production refuses and
    /// the emulator profile starts the same codebase.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn start_codebase_applies_the_scheduler_refusals_by_profile() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let dir = std::env::temp_dir().join(format!(
            "fireemu-start-codebase-scheduler-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        let manifest_path = dir.join("manifest.json");
        let codebase = crate::config::FunctionsCodebase {
            codebase: "default".to_owned(),
            source: source.display().to_string(),
            runtime: None,
            ignore: Vec::new(),
        };
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        let cache = Arc::new(super::NodeProbeCache::default());
        for (retry, refused_text) in [
            (json!({"retryCount": 6}), Some(COUNT_TEXT)),
            (json!({"maxRetrySeconds": 20.5}), Some(NANOS_TEXT)),
            (json!({"retryCount": 5, "maxRetrySeconds": 20}), None),
        ] {
            std::fs::write(&manifest_path, scheduled_with(retry.clone()).to_string()).unwrap();
            for profile in [
                super::CompatibilityProfile::Strict,
                super::CompatibilityProfile::Emulator,
            ] {
                let cfg = crate::config::RuntimeConfig {
                    profile,
                    functions_runner: Some(vec![
                        "python3".to_owned(),
                        script.display().to_string(),
                    ]),
                    functions_manifest: Some(manifest_path.display().to_string()),
                    ..crate::config::RuntimeConfig::default()
                };
                let started = super::start_codebase(
                    &cfg,
                    &codebase,
                    &hosts,
                    "test-secret",
                    false,
                    &cache,
                    VirtualClock::new(cfg.clock_start).snapshot(),
                )
                .await;
                if let (super::CompatibilityProfile::Strict, Some(text)) = (profile, refused_text) {
                    let error = started.err().unwrap();
                    assert!(error.contains(text), "{retry}: {error}");
                } else {
                    let spec = started.unwrap_or_else(|e| panic!("{retry} {profile:?}: {e}"));
                    spec.runner.kill_now();
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scratch codebase source holding a `requirements.txt` and no `package.json`: a Python one.
    fn python_codebase(name: &str) -> (std::path::PathBuf, crate::config::FunctionsCodebase) {
        let dir = std::env::temp_dir().join(format!(
            "fireemu-python-start-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "firebase-functions\n").unwrap();
        let codebase = crate::config::FunctionsCodebase {
            codebase: "py".to_owned(),
            source: dir.display().to_string(),
            runtime: None,
            ignore: Vec::new(),
        };
        (dir, codebase)
    }

    fn no_hosts() -> super::EmulatorHosts {
        super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        }
    }

    #[tokio::test]
    async fn started_runner_inspector_checks_dynamic_and_fixed_ports_for_node_only() {
        let runner = Arc::new(fireemu_adapter_functions::runner::Runner::unstarted("test"));
        for fixed in [false, true] {
            let cfg = crate::config::RuntimeConfig {
                functions_inspect_dynamic: !fixed,
                functions_inspect_port: fixed.then_some(9229),
                ..Default::default()
            };
            let clock = fireemu_core_session::clock::ClockSnapshot {
                instant: cfg.clock_start,
                elapsed_nanos: 0,
                revision: 0,
            };
            assert!(
                super::check_started_runner(&cfg, "test", false, &runner, clock)
                    .await
                    .is_err()
            );
            assert!(
                super::check_started_runner(&cfg, "test", true, &runner, clock)
                    .await
                    .is_ok()
            );
        }
    }

    #[test]
    fn the_inspector_flags_go_to_a_node_runner_in_order_and_never_to_a_python_one() {
        let flags = |python, dynamic, port| {
            let result = super::inspector_arguments(python, dynamic, port);
            (result.arguments, result.ignored)
        };
        assert_eq!(flags(false, false, None), (vec![], false));
        assert_eq!(flags(true, false, None), (vec![], false));
        assert_eq!(
            flags(false, true, None),
            (
                vec![
                    "--inspect=127.0.0.1:0".to_owned(),
                    "--inspect-publish-uid=http".to_owned()
                ],
                false
            )
        );
        assert_eq!(
            flags(false, false, Some(9229)),
            (
                vec![
                    "--inspect=127.0.0.1:9229".to_owned(),
                    "--inspect-publish-uid=http".to_owned()
                ],
                false
            )
        );
        // A dynamic port wins over a fixed one, as before.
        assert_eq!(flags(false, true, Some(9229)).0[0], "--inspect=127.0.0.1:0");
        assert_eq!(flags(true, true, None), (vec![], true));
        assert_eq!(flags(true, false, Some(9229)), (vec![], true));
    }

    #[test]
    fn the_admin_app_check_channel_needs_an_answering_verifier_and_a_node_runner() {
        assert!(super::admin_app_check_offered(true, false));
        assert!(!super::admin_app_check_offered(true, true));
        assert!(!super::admin_app_check_offered(false, false));
        assert!(!super::admin_app_check_offered(false, true));
    }

    #[test]
    fn the_codebases_are_split_into_reloaded_and_not_reloaded() {
        let (dir, python) = python_codebase("split");
        let node = crate::config::FunctionsCodebase {
            codebase: "node".to_owned(),
            runtime: Some("nodejs20".to_owned()),
            ..python.clone()
        };
        let (supervised, unsupervised) =
            super::split_reload(vec![python.clone(), node.clone(), python.clone()]);
        assert_eq!(supervised, vec![node]);
        assert_eq!(unsupervised, vec![python.clone(), python]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn python_reload_is_not_supervised_and_node_reload_is() {
        let (dir, python) = python_codebase("reload");
        assert!(!super::reload_supervised(&python));
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        assert!(
            super::reload_supervised(&python),
            "a package.json makes it Node"
        );
        let declared = crate::config::FunctionsCodebase {
            runtime: Some("python312".to_owned()),
            ..python
        };
        assert!(
            !super::reload_supervised(&declared),
            "a declared Python runtime wins over package.json"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn callable_trust_is_never_available_for_a_python_codebase() {
        let (dir, python) = python_codebase("trust");
        assert_eq!(
            super::codebase_callable_trust(&python).unwrap_err(),
            "Python codebases are not supported by it yet"
        );
        // A Node codebase is asked about its SDK, which is not installed here.
        let node = crate::config::FunctionsCodebase {
            runtime: Some("nodejs20".to_owned()),
            ..python
        };
        assert!(super::codebase_callable_trust(&node)
            .unwrap_err()
            .contains("firebase-functions"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_python_codebase_is_refused_the_trusted_callable_protocol_and_needs_its_venv() {
        let (dir, codebase) = python_codebase("start");
        let cfg = crate::config::RuntimeConfig::default();
        let cache = Arc::new(super::NodeProbeCache::default());
        let snapshot = VirtualClock::new(cfg.clock_start).snapshot();
        let trusted =
            super::start_codebase(&cfg, &codebase, &no_hosts(), "s", true, &cache, snapshot)
                .await
                .err()
                .unwrap();
        assert!(trusted.starts_with("the Functions codebase \"py\": App Check for Python callables is not available yet"), "{trusted}");
        let untrusted =
            super::start_codebase(&cfg, &codebase, &no_hosts(), "s", false, &cache, snapshot)
                .await
                .err()
                .unwrap();
        let expected = if cfg!(windows) {
            "not supported on Windows"
        } else {
            "Missing virtual environment at venv directory"
        };
        assert!(untrusted.contains(expected), "{untrusted}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--inspect-functions` is ignored for a Python codebase (a warning, as in firebase-tools): no
    /// inspector flag reaches its command and no active inspector is demanded of it.
    #[tokio::test]
    async fn the_inspect_option_is_ignored_for_a_python_codebase() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let (dir, python) = python_codebase("inspect");
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, scheduled_with(json!({})).to_string()).unwrap();
        let cache = Arc::new(super::NodeProbeCache::default());
        for (port, dynamic) in [(Some(5_u16), false), (None, true)] {
            let cfg = crate::config::RuntimeConfig {
                functions_runner: Some(vec!["python3".to_owned(), script.display().to_string()]),
                functions_manifest: Some(manifest_path.display().to_string()),
                functions_inspect_port: port,
                functions_inspect_dynamic: dynamic,
                ..crate::config::RuntimeConfig::default()
            };
            let snapshot = VirtualClock::new(cfg.clock_start).snapshot();
            let started =
                super::start_codebase(&cfg, &python, &no_hosts(), "s", false, &cache, snapshot)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("python, port {port:?}, dynamic {dynamic}: {error}")
                    });
            started.runner.kill_now();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[derive(Debug)]
    struct NeverAsked;

    impl fireemu_adapter_functions::admin_app_check::AdminAppCheckVerifier for NeverAsked {
        fn verify(&self, _: &str, _: &str) -> fireemu_adapter_functions::admin_app_check::Reply {
            fireemu_adapter_functions::admin_app_check::Reply::Unavailable
        }
    }

    /// The Admin SDK App Check channel is a Node mechanism: only a Node runner is told about it.
    #[tokio::test]
    async fn the_admin_app_check_channel_is_offered_to_a_node_runner_and_not_to_a_python_one() {
        let script = r"
import json,os,sys
value=json.dumps({'type':'hello','runner':'probe','manifest':{'functions':[{'name':'job','trigger':{'type':'schedule','schedule':'every 1 minutes'}}]},'adminAppCheck':{'instrumentation':'env:'+os.environ.get('FIREEMU_APP_CHECK_ADMIN','unset')}}).encode()
sys.stdout.buffer.write(str(len(value)).encode()+b'\n'+value)
sys.stdout.buffer.flush()
sys.stdin.buffer.read()
";
        let (dir, python) = python_codebase("admin");
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, scheduled_with(json!({})).to_string()).unwrap();
        let cfg = crate::config::RuntimeConfig {
            functions_runner: Some(vec![
                "python3".to_owned(),
                "-c".to_owned(),
                script.to_owned(),
            ]),
            functions_manifest: Some(manifest_path.display().to_string()),
            ..crate::config::RuntimeConfig::default()
        };
        let mut hosts = no_hosts();
        hosts.admin_app_check = Some(Arc::new(NeverAsked));
        let cache = Arc::new(super::NodeProbeCache::default());
        let snapshot = VirtualClock::new(cfg.clock_start).snapshot();
        let node = crate::config::FunctionsCodebase {
            runtime: Some("nodejs20".to_owned()),
            ..python.clone()
        };
        for (codebase, expected) in [(&python, "env:unset"), (&node, "env:1")] {
            let started =
                super::start_codebase(&cfg, codebase, &hosts, "s", false, &cache, snapshot)
                    .await
                    .unwrap();
            let report = started.runner.hello().admin_app_check.clone().unwrap();
            assert_eq!(report["instrumentation"], expected, "{}", codebase.codebase);
            started.runner.kill_now();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn blocking_jwks_is_owned_by_the_daemon_and_only_sent_to_python() {
        let script = r"
import json,os,sys
value=json.dumps({'type':'hello','runner':'probe','manifest':{'functions':[{'name':'job','trigger':{'type':'schedule','schedule':'every 1 minutes'}}]},'adminAppCheck':{'instrumentation':json.dumps([os.environ.get('FIREEMU_AUTH_BLOCKING_JWKS'), json.loads(os.environ.get('FIREEMU_LOCAL_SECRETS_JSON','{}')).get('FIREEMU_AUTH_BLOCKING_JWKS')])}}).encode()
sys.stdout.buffer.write(str(len(value)).encode()+b'\n'+value)
sys.stdout.buffer.flush()
sys.stdin.buffer.read()
";
        let (dir, python) = python_codebase("blocking-jwks");
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, scheduled_with(json!({})).to_string()).unwrap();
        std::fs::write(dir.join(".env"), "FIREEMU_AUTH_BLOCKING_JWKS=user-value\n").unwrap();
        std::fs::write(
            dir.join(".secret.local"),
            "FIREEMU_AUTH_BLOCKING_JWKS=secret-value\n",
        )
        .unwrap();
        let cfg = crate::config::RuntimeConfig {
            functions_runner: Some(vec![
                "python3".to_owned(),
                "-c".to_owned(),
                script.to_owned(),
            ]),
            functions_manifest: Some(manifest_path.display().to_string()),
            ..crate::config::RuntimeConfig::default()
        };
        let node = crate::config::FunctionsCodebase {
            runtime: Some("nodejs20".to_owned()),
            ..python.clone()
        };
        let cache = Arc::new(super::NodeProbeCache::default());
        let snapshot = VirtualClock::new(cfg.clock_start).snapshot();
        for (codebase, jwks, expected) in [
            (&python, Some("public-jwks"), Some("public-jwks")),
            (&python, None, None),
            (&node, Some("public-jwks"), None),
        ] {
            let mut hosts = no_hosts();
            hosts.blocking_jwks = jwks.map(str::to_owned);
            let started =
                super::start_codebase(&cfg, codebase, &hosts, "s", false, &cache, snapshot)
                    .await
                    .unwrap();
            let report = started.runner.hello().admin_app_check.clone().unwrap();
            let values: serde_json::Value =
                serde_json::from_str(report["instrumentation"].as_str().unwrap()).unwrap();
            assert_eq!(values, json!([expected, null]));
            started.runner.kill_now();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_virtual_date_is_refused_for_a_runner_without_a_clock_and_the_message_names_python() {
        // A runner that says hello and announces no clock capability, as the Python runner does.
        let script = r"
import json,sys
value=json.dumps({'type':'hello','runner':'no-clock'}).encode()
sys.stdout.buffer.write(str(len(value)).encode()+b'\n'+value)
sys.stdout.buffer.flush()
sys.stdin.buffer.read()
";
        let (dir, python) = python_codebase("clock");
        let manifest_path = dir.join("manifest.json");
        std::fs::write(&manifest_path, scheduled_with(json!({})).to_string()).unwrap();
        let mut cfg = crate::config::RuntimeConfig {
            functions_runner: Some(vec![
                "python3".to_owned(),
                "-c".to_owned(),
                script.to_owned(),
            ]),
            functions_manifest: Some(manifest_path.display().to_string()),
            ..crate::config::RuntimeConfig::default()
        };
        cfg.functions_clock.date_virtual = true;
        let cache = Arc::new(super::NodeProbeCache::default());
        let snapshot = VirtualClock::new(cfg.clock_start).snapshot();
        let error = super::start_codebase(&cfg, &python, &no_hosts(), "s", false, &cache, snapshot)
            .await
            .err()
            .unwrap();
        assert!(
            error.ends_with(
                "does not support the requested virtual clock (Python code runs on real time)"
            ),
            "{error}"
        );
        let node = crate::config::FunctionsCodebase {
            runtime: Some("nodejs20".to_owned()),
            ..python
        };
        let error = super::start_codebase(&cfg, &node, &no_hosts(), "s", false, &cache, snapshot)
            .await
            .err()
            .unwrap();
        assert!(
            error.ends_with("does not support the requested virtual clock"),
            "{error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unparseable_emulator_schedules_still_validate_the_remaining_manifest() {
        let now = crate::config::RuntimeConfig::default().clock_start;
        let mut document = json!({"functions": [{"name": "job", "trigger": {
            "type": "schedule", "schedule": "every 0 minutes",
        }}]});
        document["functions"][0]["timeoutSeconds"] = json!(0);
        assert!(
            super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now)
                .unwrap_err()
                .contains("timeoutSeconds")
        );
        document["functions"][0]["timeoutSeconds"] = json!(60);
        document["functions"][0]["trigger"]
            .as_object_mut()
            .unwrap()
            .remove("schedule");
        assert_eq!(
            super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now)
                .unwrap_err(),
            "manifest: function \"job\": schedule is required"
        );
        document["functions"][0]["trigger"]["schedule"] = json!("every 0 minutes");
        let duplicate = document["functions"][0].clone();
        document["functions"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(
            super::manifest_for_profile(CompatibilityProfile::Emulator, &document, now)
                .unwrap_err()
                .contains("declared twice")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)] // Keep the recorded declarations and both profile checks together.
    async fn recorded_unparseable_schedules_start_with_warnings_and_no_jobs_only_in_emulator() {
        use fireemu_core_types::time::LogicalInstant;

        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fireemu-adapter-functions/tests/fake_runner.py");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../target/codex-out/calendar-startup-{}",
            std::process::id()
        ));
        let source = dir.join("src");
        std::fs::create_dir_all(&source).unwrap();
        let manifest_path = dir.join("manifest.json");
        let codebase = crate::config::FunctionsCodebase {
            codebase: "default".to_owned(),
            source: source.display().to_string(),
            runtime: None,
            ignore: Vec::new(),
        };
        let hosts = super::EmulatorHosts {
            blocking_jwks: None,
            app_check: None,
            firestore: None,
            auth: None,
            storage: None,
            functions: None,
            eventarc: None,
            tasks: None,
            logging: None,
            pubsub: None,
            hub: None,
            admin_app_check: None,
        };
        let cache = Arc::new(super::NodeProbeCache::default());
        let mut declarations = vec![
            (
                "c07",
                "0 0 1 4 *",
                "Invalid/Unknown",
                "2026-10-05T00:30:00Z",
                "time zone: unknown time zone \"Invalid/Unknown\"",
            ),
            (
                "c08",
                "0 0 0 1 4 *",
                "UTC",
                "2026-10-05T00:30:00Z",
                "schedule: unrecognised schedule \"0 0 0 1 4 *\"",
            ),
        ];
        // The seven declarations in each calendar-v6 recording, with their dispatch anchors.
        for anchors in [
            [
                "2026-10-04T23:49:09.759Z",
                "2026-10-04T23:49:12.680Z",
                "2026-10-04T23:49:14.058Z",
                "2026-10-04T23:49:42.509Z",
                "2026-10-04T23:49:43.888Z",
                "2026-10-04T23:49:47.812Z",
                "2026-10-04T23:49:57.990Z",
            ],
            [
                "2026-10-05T00:30:22.138Z",
                "2026-10-05T00:30:23.568Z",
                "2026-10-05T00:30:25.004Z",
                "2026-10-05T00:30:52.982Z",
                "2026-10-05T00:30:54.319Z",
                "2026-10-05T00:30:58.776Z",
                "2026-10-05T00:31:08.658Z",
            ],
        ] {
            for ((name, schedule, zone, reason), anchor) in [
                (
                    "cr08",
                    "0 24 * * *",
                    "UTC",
                    "schedule: cron field hour: \"24\" is out of range",
                ),
                (
                    "cr09",
                    "0 0 1 *",
                    "UTC",
                    "schedule: unrecognised schedule \"0 0 1 *\"",
                ),
                (
                    "cr10",
                    "0 0 L * *",
                    "UTC",
                    "schedule: cron field day-of-month: \"L\" is out of range",
                ),
                (
                    "gr09",
                    "every 0 minutes",
                    "UTC",
                    "schedule: unrecognised schedule \"every 0 minutes\"",
                ),
                (
                    "gr10",
                    "32 of month 09:00",
                    "UTC",
                    "schedule: cron field day-of-month: \"32\" is out of range",
                ),
                (
                    "gr13",
                    "every 20 minutes synchronized",
                    "UTC",
                    "schedule: unrecognised schedule \"every 20 minutes synchronized\"",
                ),
                (
                    "tz04",
                    "0 9 * * *",
                    "Asia/Tokio",
                    "time zone: unknown time zone \"Asia/Tokio\"",
                ),
            ]
            .into_iter()
            .zip(anchors)
            {
                declarations.push((name, schedule, zone, anchor, reason));
            }
        }
        assert_eq!(declarations.len(), 16);
        for (name, schedule, zone, anchor, reason) in declarations {
            let document = json!({"functions": [
                {"name": name, "generation": 2, "region": "europe-west1", "trigger": {
                    "type": "schedule", "schedule": schedule, "timeZone": zone,
                }},
                {"name": "parseable", "generation": 2, "trigger": {
                    "type": "schedule", "schedule": "every 5 minutes", "timeZone": "Asia/Tokyo",
                }},
            ]});
            std::fs::write(&manifest_path, document.to_string()).unwrap();
            for profile in [CompatibilityProfile::Emulator, CompatibilityProfile::Strict] {
                let cfg = crate::config::RuntimeConfig {
                    profile,
                    clock_start: LogicalInstant::parse_rfc3339(anchor).unwrap(),
                    functions_runner: Some(if profile == CompatibilityProfile::Emulator {
                        vec![
                            "python3".to_owned(), "-c".to_owned(),
                            "import json,sys\nframe=json.dumps({'type':'hello','runner':'fake','manifest':json.load(open(sys.argv[1],encoding='utf-8'))}).encode()\nsys.stdout.buffer.write(str(len(frame)).encode()+b'\\n'+frame)\nsys.stdout.buffer.flush()\nsys.stdin.read()".to_owned(),
                            manifest_path.display().to_string(),
                        ]
                    } else {
                        vec!["python3".to_owned(), script.display().to_string()]
                    }),
                    functions_manifest: Some(manifest_path.display().to_string()),
                    ..crate::config::RuntimeConfig::default()
                };
                let started = super::start_codebase(
                    &cfg,
                    &codebase,
                    &hosts,
                    "test-secret",
                    false,
                    &cache,
                    VirtualClock::new(cfg.clock_start).snapshot(),
                )
                .await;
                if profile == CompatibilityProfile::Strict && name != "gr13" {
                    assert_eq!(
                        started.err().unwrap(),
                        format!("manifest: function {name:?}: {reason}")
                    );
                    continue;
                }
                let spec =
                    started.unwrap_or_else(|e| panic!("{name} {profile:?} at {anchor}: {e}"));
                spec.runner.kill_now();
                let (_, parsed, time_zone) = spec
                    .manifest
                    .scheduled()
                    .find(|(function, _, _)| function.name == "parseable")
                    .unwrap();
                assert_eq!(parsed.as_str(), "every 5 minutes");
                assert_eq!(time_zone, Some("Asia/Tokyo"));
                if profile == CompatibilityProfile::Emulator {
                    assert_eq!(
                        spec.manifest.scheduled().count(),
                        1,
                        "{name}: no job for the ignored function"
                    );
                    assert_eq!(spec.manifest.ignored.len(), 1);
                    assert_eq!(
                        super::check_ignored(&spec.manifest, super::UnservedTriggers::Refuse).unwrap(),
                        [format!("functions[europe-west1-{name}]: function ignored (schedule): no scheduled job: {reason}")]
                    );
                } else {
                    assert_eq!(spec.manifest.scheduled().count(), 2);
                    assert!(spec.manifest.ignored.is_empty());
                }
            }
        }
        // Windows keeps the directory busy for a moment after the fake runner exits (os error 32); the
        // directory is a per-test temporary, so a failed removal is not a test failure.
        for _ in 0..20 {
            if std::fs::remove_dir_all(&dir).is_ok() || !dir.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// The time zone of a schedule that names none: the strict profile gives a first-generation one Los Angeles (read
    /// back from production for `schedFailV1`), a second-generation one stays zoneless (UTC); an explicit zone and
    /// the configured default win; the emulator profile changes nothing.
    #[test]
    fn strict_gives_a_first_generation_schedule_the_los_angeles_zone() {
        let document = json!({"functions": [
            {"name": "v1none", "trigger": {"type": "schedule", "schedule": "0 9 * * *"}},
            {"name": "v1null", "generation": 1, "trigger": {"type": "schedule", "schedule": "0 9 * * *", "timeZone": null}},
            {"name": "v1tokyo", "generation": 1, "trigger": {"type": "schedule", "schedule": "0 9 * * *", "timeZone": "Asia/Tokyo"}},
            {"name": "v2none", "generation": 2, "trigger": {"type": "schedule", "schedule": "0 9 * * *"}},
            {"name": "v2utc", "generation": 2, "trigger": {"type": "schedule", "schedule": "0 9 * * *", "timeZone": "UTC"}},
            {"name": "http", "generation": 1, "trigger": {"type": "http"}},
        ]});
        let zones = |profile| {
            let manifest = super::manifest_for_profile(
                profile,
                &document,
                crate::config::RuntimeConfig::default().clock_start,
            )
            .unwrap();
            manifest
                .scheduled()
                .map(|(function, _, zone)| (function.name.clone(), zone.map(str::to_owned)))
                .collect::<Vec<_>>()
        };
        let la = Some("America/Los_Angeles".to_owned());
        assert_eq!(
            zones(super::CompatibilityProfile::Strict),
            vec![
                ("v1none".to_owned(), la.clone()),
                ("v1null".to_owned(), la),
                ("v1tokyo".to_owned(), Some("Asia/Tokyo".to_owned())),
                ("v2none".to_owned(), None),
                ("v2utc".to_owned(), Some("UTC".to_owned())),
            ]
        );
        let emulator = zones(super::CompatibilityProfile::Emulator);
        assert_eq!(emulator[0].1, None, "the emulator profile keeps no zone");
        assert_eq!(emulator[1].1, None);
        // The configured default is applied first and wins over the generation default.
        let mut configured = document.clone();
        super::apply_default_time_zone(&mut configured, "Europe/Paris");
        let manifest = super::manifest_for_profile(
            super::CompatibilityProfile::Strict,
            &configured,
            crate::config::RuntimeConfig::default().clock_start,
        )
        .unwrap();
        assert!(manifest
            .scheduled()
            .all(|(_, _, zone)| matches!(zone, Some("Europe/Paris" | "Asia/Tokyo" | "UTC"))));
        // The first run of a Gen1 `0 9 * * *` is 09:00 in Los Angeles: 16:00Z in October (PDT).
        let strict = super::manifest_for_profile(
            super::CompatibilityProfile::Strict,
            &document,
            crate::config::RuntimeConfig::default().clock_start,
        )
        .unwrap();
        let (_, schedule, zone) = strict.scheduled().next().unwrap();
        let rules = fireemu_adapter_functions::zone::resolve(zone).unwrap();
        let now = fireemu_core_types::time::LogicalInstant::parse_rfc3339("2026-10-05T08:00:00Z")
            .unwrap();
        assert_eq!(
            schedule.next_after_in(now, &*rules),
            Some(
                fireemu_core_types::time::LogicalInstant::parse_rfc3339("2026-10-05T16:00:00Z")
                    .unwrap()
            )
        );
    }

    /// The profile switch itself: only strict refuses what Cloud Scheduler refuses.
    #[test]
    fn only_the_strict_profile_uses_production_scheduler_defaults() {
        assert!(super::uses_production_scheduler_defaults(
            super::CompatibilityProfile::Strict
        ));
        assert!(!super::uses_production_scheduler_defaults(
            super::CompatibilityProfile::Emulator
        ));
    }

    /// Recorded (run `156715222b86ea44`): production starts no occurrence of a job while a run of it is in flight. The
    /// strict profile follows; the emulator profile keeps allowing overlap (the official emulator never schedules, so
    /// nothing it completes is dropped). An explicit `scheduler.overlap` wins in both.
    #[test]
    fn the_overlap_policy_defaults_by_profile_and_an_explicit_one_wins() {
        use super::CompatibilityProfile::{Emulator, Strict};
        use fireemu_adapter_functions::runtime::OverlapPolicy::{
            Allow, Queue, Reject, Skip, SkipInFlight,
        };
        assert_eq!(super::overlap_policy_for(Strict, None), SkipInFlight);
        assert_eq!(super::overlap_policy_for(Emulator, None), Allow);
        for (text, policy) in [
            ("allow", Allow),
            ("skip", Skip),
            ("queue", Queue),
            ("reject", Reject),
            ("skip-in-flight", SkipInFlight),
        ] {
            for profile in [Strict, Emulator] {
                assert_eq!(
                    super::overlap_policy_for(profile, Some(text)),
                    policy,
                    "{profile:?} {text}"
                );
            }
        }
    }

    #[test]
    fn only_the_strict_profile_refuses_scheduler_limits() {
        assert!(super::refuses_scheduler_limits(
            super::CompatibilityProfile::Strict
        ));
        assert!(!super::refuses_scheduler_limits(
            super::CompatibilityProfile::Emulator
        ));
    }

    /// The emulator profile keeps the email and SMS functions in the ignored inventory, with
    /// the reason the runner gave before the strict profile served them.
    #[test]
    fn the_emulator_profile_ignores_send_blocking_functions() {
        let mut manifest = parse_manifest(&json!({"functions": [
            {"name": "create", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeCreate"}},
            {"name": "mail", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeSendEmail"}},
            {"name": "sms", "trigger": {"type": "blockingAuth", "eventType": "providers/cloud.auth/eventTypes/user.beforeSendSms"}},
        ]}))
        .unwrap();
        let mut strict = manifest.clone();
        super::serve_blocking_events_for(super::CompatibilityProfile::Strict, &mut strict);
        assert_eq!(strict, manifest);
        super::serve_blocking_events_for(super::CompatibilityProfile::Emulator, &mut manifest);
        assert_eq!(
            manifest
                .functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            ["create"]
        );
        let ignored = manifest
            .ignored
            .iter()
            .map(|f| {
                (
                    f.name.as_str(),
                    f.trigger_type.as_str(),
                    f.scope,
                    f.reason.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ignored,
            [
                (
                    "mail",
                    "blocking",
                    fireemu_core_functions::manifest::IgnoredScope::Unsupported,
                    "blocking identity event providers/cloud.auth/eventTypes/user.beforeSendEmail is not served",
                ),
                (
                    "sms",
                    "blocking",
                    fireemu_core_functions::manifest::IgnoredScope::Unsupported,
                    "blocking identity event providers/cloud.auth/eventTypes/user.beforeSendSms is not served",
                ),
            ]
        );
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
                max_running: 1,
                retry_attempts: 1,
                ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
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
                ..Default::default()
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
                session: SessionId::new(8),
                max_running: 1,
                retry_attempts: 1,
                ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
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
                ..Default::default()
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
    fn a_blocking_call_waits_for_the_timeout_that_elapses_first() {
        use fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure;

        let deadline = Duration::from_secs(7);
        assert_eq!(super::blocking_auth_wait(60, deadline), (deadline, false));
        assert_eq!(super::blocking_auth_wait(8, deadline), (deadline, false));
        assert_eq!(
            super::blocking_auth_wait(7, deadline),
            (Duration::from_secs(7), true)
        );
        assert_eq!(
            super::blocking_auth_wait(3, deadline),
            (Duration::from_secs(3), true)
        );
        // An unset timeout is not a zero wait.
        assert_eq!(super::blocking_auth_wait(0, deadline), (deadline, false));

        // Identity Platform's deadline answers its 400; the function's own timeout the masked
        // 503; any other failure is unchanged.
        let elapsed = |own| super::blocking_auth_elapsed(BlockingFunctionFailure::timeout(), own);
        assert_eq!(elapsed(false).identity_status(), 400);
        assert_eq!(elapsed(true).identity_status(), 503);
        let unhandled = super::blocking_auth_elapsed(BlockingFunctionFailure::unhandled(), true);
        assert_eq!(unhandled, BlockingFunctionFailure::unhandled());
    }

    #[test]
    fn blocking_auth_transport_bounds_and_failure_pairs_are_production_bounded() {
        assert_eq!(BLOCKING_AUTH_DEADLINE, Duration::from_secs(7));
        assert_eq!(
            super::blocking_auth_deadline(super::CompatibilityProfile::Strict),
            Duration::from_secs(7)
        );
        assert_eq!(
            super::blocking_auth_deadline(super::CompatibilityProfile::Emulator),
            Duration::from_secs(60)
        );
        assert_eq!(MAX_BLOCKING_AUTH_RESPONSE_BYTES, 64 * 1024);
        // An elapsed deadline answers production's 400 (recording 2026-09-28, timeout#*).
        assert_eq!(
            blocking_auth_io_failure(&std::io::Error::from(std::io::ErrorKind::TimedOut))
                .identity_status(),
            400
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
        // A function's own 5xx is masked as production's opaque 503.
        assert_eq!(
            blocking_auth_response_failure(504, &explicit_deadline).identity_status(),
            503
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
                max_running: 1,
                retry_attempts: 1,
                ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
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
        assert_eq!(failure.identity_status(), 400);
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

    fn virtual_date_fake_runner_spec(
        snapshot: fireemu_core_session::clock::ClockSnapshot,
    ) -> fireemu_adapter_functions::runner::SpawnSpec {
        use fireemu_adapter_functions::application_clock::ApplicationClockPolicy;
        use fireemu_adapter_functions::runner::SpawnSpec;
        let policy = ApplicationClockPolicy {
            date_virtual: true,
            ..Default::default()
        };
        SpawnSpec {
            command: vec![
                "python3".to_owned(),
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../fireemu-adapter-functions/tests/fake_runner.py")
                    .display()
                    .to_string(),
            ],
            cwd: None,
            env: vec![(
                "FIREEMU_CLOCK_JSON".to_owned(),
                policy.runner_options(snapshot).to_string(),
            )],
            hello_timeout: Duration::from_secs(60),
        }
    }

    #[test]
    fn blocking_auth_synchronizes_a_replacement_loaded_before_the_last_clock_ack() {
        use fireemu_adapter_functions::application_clock::ApplicationClockPolicy;
        use fireemu_adapter_functions::runner::Runner;
        use fireemu_adapter_functions::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::{
            BlockingAuthEvent, BlockingAuthTokenPolicy, Trigger,
        };
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

        let executor = tokio::runtime::Runtime::new().unwrap();
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let policy = ApplicationClockPolicy {
            date_virtual: true,
            ..Default::default()
        };
        let spec = virtual_date_fake_runner_spec(clock.lock().unwrap().snapshot());
        let (initial, replacement, unrelated) = executor.block_on(async {
            (
                Arc::new(Runner::spawn_spec(&spec).await.unwrap()),
                Arc::new(Runner::spawn_spec(&spec).await.unwrap()),
                Arc::new(Runner::spawn_spec(&spec).await.unwrap()),
            )
        });
        let mut manifest = parse_manifest(initial.hello().manifest.as_ref().unwrap()).unwrap();
        let mut guard = manifest.get("echo").unwrap().clone();
        guard.name = "clockGuard".to_owned();
        guard.trigger = Trigger::BlockingAuth {
            event: BlockingAuthEvent::BeforeCreate,
            token_policy: BlockingAuthTokenPolicy::default(),
        };
        manifest.functions.push(guard);
        // Construct outside an entered executor so the observer cannot mask admission sync.
        let runtime = FunctionsRuntime::with_codebases(
            vec![
                CodebaseSpec {
                    function: None,
                    name: "default".to_owned(),
                    manifest,
                    runner: initial,
                    spawn: Some(spec.clone()),
                    cleanup_dir: None,
                },
                CodebaseSpec {
                    function: None,
                    name: "unrelated".to_owned(),
                    manifest: fireemu_core_functions::manifest::FunctionManifest::default(),
                    runner: unrelated.clone(),
                    spawn: None,
                    cleanup_dir: None,
                },
            ],
            FunctionsConfig {
                retry_attempts: 1,
                clock_policy: policy,
                ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
            },
            clock.clone(),
            fireemu_adapter_functions::http::FunctionsHttpProfile::Emulator,
        )
        .unwrap();
        let delta = LogicalDuration::from_millis(1);
        clock.lock().unwrap().advance(delta).unwrap();
        let snapshot = clock.lock().unwrap().snapshot();
        executor
            .block_on(runtime.runner().sync_clock(snapshot))
            .unwrap();
        runtime
            .reload_codebase(CodebaseSpec {
                function: None,
                name: "default".to_owned(),
                manifest: runtime.manifest().clone(),
                runner: replacement,
                spawn: Some(spec),
                cleanup_dir: None,
            })
            .unwrap();
        // A dead sibling with an old clock must not affect this admitted handler.
        unrelated.kill_now();
        let bridge = super::BlockingAuthBridge::new(runtime.clone());
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("clock@example.test"), runtime.now())
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        let result = executor.block_on(async {
            tokio::task::spawn_blocking(move || {
                bridge.invoke(BlockingAuthEvent::BeforeCreate, &user)
            })
            .await
            .unwrap()
        });
        executor.block_on(runtime.shutdown());
        assert_eq!(result.unwrap()["clockNowMillis"], 1);
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
        // Identity Platform's own deadline answers 400 (AUTH-TENANT-BLOCKING recording
        // 2026-09-28, timeout#*).
        assert_eq!(failure.identity_status(), 400);
        assert_eq!(
            failure,
            fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
        );
    }

    /// A runner recovery is fireemu's cold start, which Identity Platform's deadline covers: the
    /// call after it waits only for what is left of the deadline, and running out of it is the
    /// platform's deadline (400), not the function's own timeout.
    #[tokio::test(flavor = "current_thread")]
    async fn a_call_after_a_runner_recovery_waits_only_for_the_rest_of_the_deadline() {
        use fireemu_adapter_http::identity_toolkit::AuthBlockingHook;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser};
        use fireemu_core_functions::manifest::BlockingAuthEvent;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::time::LogicalInstant;

        let (runtime, _) = runtime_and_clock_with_blocking_auth_targets_env(
            &[(
                "beforeCreate",
                BlockingAuthEvent::BeforeCreate,
                false,
                false,
            )],
            vec![
                ("FIREEMU_FAKE_HELLO_DELAY_MS".to_owned(), "600".to_owned()),
                (
                    "FIREEMU_FAKE_BLOCKING_HANG_MS".to_owned(),
                    "5000".to_owned(),
                ),
            ],
        )
        .await;
        let bridge =
            BlockingAuthBridge::with_deadline(runtime.clone(), Duration::from_millis(1_000));
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("person@example.test"), now)
            .unwrap();
        let user = store.user_by_id(uid.as_str()).unwrap().clone();
        runtime.runner().kill_now();

        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            bridge.invoke(BlockingAuthEvent::BeforeCreate, &user)
        })
        .await
        .unwrap();
        let elapsed = started.elapsed();
        runtime.shutdown().await;

        let failure = result.expect_err("the hanging function cannot meet the deadline");
        assert_eq!(
            failure,
            fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure::timeout()
        );
        assert_eq!(failure.identity_status(), 400);
        // The recovery took about 600 ms of the one-second deadline; a fresh deadline after it
        // would answer after about 1.6 s.
        assert!(elapsed < Duration::from_millis(1_450), "{elapsed:?}");
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

    #[cfg(windows)]
    fn grant_windows_test_ace(path: &std::path::Path, rights: &str) {
        use std::process::Command;

        let icacls = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .expect("Windows defines SystemRoot")
            .join(r"System32\icacls.exe");
        let output = Command::new(icacls)
            .arg(path)
            .arg("/grant")
            .arg(format!("*S-1-1-0:{rights}"))
            .output()
            .expect("icacls.exe is available on Windows");
        assert!(
            output.status.success(),
            "failed to add test ACL: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    fn create_windows_junction(link: &std::path::Path, target: &std::path::Path) {
        use std::process::Command;

        let powershell = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .expect("Windows defines SystemRoot")
            .join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let output = Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "New-Item -ItemType Junction -Path $env:FIREEMU_TEST_LINK -Target $env:FIREEMU_TEST_TARGET | Out-Null",
            ])
            .env("FIREEMU_TEST_LINK", link)
            .env("FIREEMU_TEST_TARGET", target)
            .output()
            .expect("Windows PowerShell is available");
        assert!(
            output.status.success(),
            "failed to create junction: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    fn set_windows_null_dacl(path: &std::path::Path) {
        use std::process::Command;

        const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$native = @'
using System;
using System.Runtime.InteropServices;
public static class FireemuNullDaclFixture {
    [DllImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
    private static extern uint SetNamedSecurityInfo(string name, int type, uint info,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
    private static extern uint GetNamedSecurityInfo(string name, int type, uint info,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", EntryPoint = "GetSecurityDescriptorDacl")]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,
        out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("kernel32.dll", EntryPoint = "LocalFree")]
    private static extern IntPtr LocalFree(IntPtr memory);
    public static void SetAndVerify(string path) {
        uint error = SetNamedSecurityInfo(path, 1, 4, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (error != 0) throw new System.ComponentModel.Win32Exception((int)error);
        IntPtr owner, group, dacl, sacl, descriptor;
        error = GetNamedSecurityInfo(path, 1, 5, out owner, out group, out dacl, out sacl, out descriptor);
        if (error != 0) throw new System.ComponentModel.Win32Exception((int)error);
        try {
            bool present, defaulted;
            if (!GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted) ||
                !present || dacl != IntPtr.Zero)
                throw new InvalidOperationException("fixture DACL is not null");
        } finally {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }
}
'@
Add-Type -TypeDefinition $native -ErrorAction Stop
[FireemuNullDaclFixture]::SetAndVerify($env:FIREEMU_TEST_PATH)
"#;

        let powershell = super::windows_powershell_path().expect("Windows PowerShell path");
        let output = Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                SCRIPT,
            ])
            .env("FIREEMU_TEST_PATH", path)
            .output()
            .expect("Windows PowerShell is available to configure the null DACL fixture");
        assert!(
            output.status.success(),
            "failed to set/verify null DACL: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    #[derive(Clone, Copy, Debug)]
    struct WindowsSnapshotAclCase<'a> {
        snapshot_dacl: &'a str,
        parent_dacl: &'a str,
        ancestor_rights: &'a str,
        reparse_position: &'a str,
        checker: &'a str,
    }

    #[cfg(windows)]
    fn windows_snapshot_acl_cases() -> Vec<WindowsSnapshotAclCase<'static>> {
        let mut lines = include_str!("../tests/fixtures/windows_snapshot_acl_cases.tsv").lines();
        assert_eq!(
            lines.next(),
            Some("SnapshotDacl\tParentDacl\tAncestorRights\tReparsePosition\tChecker")
        );
        lines
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                assert_eq!(fields.len(), 5, "malformed PICT row: {line}");
                WindowsSnapshotAclCase {
                    snapshot_dacl: fields[0],
                    parent_dacl: fields[1],
                    ancestor_rights: fields[2],
                    reparse_position: fields[3],
                    checker: fields[4],
                }
            })
            .collect()
    }

    #[cfg(windows)]
    struct WindowsSnapshotAclFixture {
        root: std::path::PathBuf,
        higher: std::path::PathBuf,
        parent: std::path::PathBuf,
        leaf: std::path::PathBuf,
        junctions: Vec<std::path::PathBuf>,
    }

    #[cfg(windows)]
    impl WindowsSnapshotAclFixture {
        fn new(case: WindowsSnapshotAclCase<'_>, index: usize) -> Self {
            let root = std::env::temp_dir().join(format!(
                "fireemu-windows-acl-pict-{}-{index}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            let higher = root.join("higher");
            let parent = higher.join("parent");
            let leaf = parent.join("leaf");
            let mut junctions = Vec::new();
            match case.reparse_position {
                "None" => std::fs::create_dir_all(&leaf).unwrap(),
                "HigherAncestor" => {
                    let target = root.join("higher-target");
                    std::fs::create_dir_all(target.join("parent/leaf")).unwrap();
                    create_windows_junction(&higher, &target);
                    junctions.push(higher.clone());
                }
                "ImmediateParent" => {
                    std::fs::create_dir_all(&higher).unwrap();
                    let target = root.join("parent-target");
                    std::fs::create_dir_all(target.join("leaf")).unwrap();
                    create_windows_junction(&parent, &target);
                    junctions.push(parent.clone());
                }
                "SnapshotLeaf" => {
                    std::fs::create_dir_all(&parent).unwrap();
                    let target = root.join("leaf-target");
                    std::fs::create_dir_all(&target).unwrap();
                    create_windows_junction(&leaf, &target);
                    junctions.push(leaf.clone());
                }
                value => panic!("unexpected reparse position: {value}"),
            }
            Self {
                root,
                higher,
                parent,
                leaf,
                junctions,
            }
        }

        fn apply_acl(&self, case: WindowsSnapshotAclCase<'_>) {
            match case.snapshot_dacl {
                "Private" => {}
                "Permissive" => grant_windows_test_ace(&self.leaf, "F"),
                "Null" => set_windows_null_dacl(&self.leaf),
                value => panic!("unexpected snapshot DACL: {value}"),
            }
            match case.parent_dacl {
                "Private" => {}
                "Permissive" => grant_windows_test_ace(&self.parent, "F"),
                value => panic!("unexpected parent DACL: {value}"),
            }
            match case.ancestor_rights {
                "ReadTraverse" => {}
                "CreateDirectoryOnly" => grant_windows_test_ace(&self.higher, "(AD)"),
                "Mutating" => grant_windows_test_ace(&self.higher, "(DC)"),
                value => panic!("unexpected ancestor rights: {value}"),
            }
        }
    }

    #[cfg(windows)]
    impl Drop for WindowsSnapshotAclFixture {
        fn drop(&mut self) {
            for junction in &self.junctions {
                let _ = std::fs::remove_dir(junction);
            }
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[cfg(windows)]
    fn windows_acl_row_refuses(case: WindowsSnapshotAclCase<'_>) -> bool {
        case.snapshot_dacl != "Private"
            || case.parent_dacl != "Private"
            || case.ancestor_rights == "Mutating"
            || case.reparse_position != "None"
    }

    #[cfg(windows)]
    fn windows_acl_script_with_removed_guards(guards: &[&str]) -> String {
        let mut mutant = super::WINDOWS_SNAPSHOT_ACL_CHECK.to_owned();
        for guard in guards {
            assert_eq!(
                mutant.matches(guard).count(),
                1,
                "guard text must be unique: {guard}"
            );
            mutant = mutant.replacen(guard, "", 1);
        }
        let catch_block = "} catch {\n    $exitCode = 1\n} finally {";
        assert_eq!(
            mutant.matches(catch_block).count(),
            1,
            "checker catch block must be unique"
        );
        let diagnostic_catch =
            "} catch {\n    $checkerError = $_.ToString()\n    $exitCode = 1\n} finally {";
        let mutant = mutant.replacen(catch_block, diagnostic_catch, 1);
        let exit_block = "}\nexit $exitCode\n";
        assert_eq!(
            mutant.matches(exit_block).count(),
            1,
            "checker exit block must be unique"
        );
        let diagnostic_exit = "}\nif ($null -ne $checkerError) {\n    try { [IO.File]::WriteAllText($env:FIREEMU_SNAPSHOT_ACL_PATH + '.checker-error', $checkerError) } catch {}\n}\nexit $exitCode\n";
        mutant.replacen(exit_block, diagnostic_exit, 1)
    }

    #[cfg(windows)]
    fn windows_acl_checker_diagnostic_path(path: &std::path::Path) -> std::path::PathBuf {
        let mut diagnostic = path.as_os_str().to_owned();
        diagnostic.push(".checker-error");
        diagnostic.into()
    }

    #[cfg(windows)]
    fn run_windows_acl_checker_with_diagnostic(
        path: &std::path::Path,
        powershell: &std::path::Path,
        script: &str,
        timeout: Duration,
    ) -> (Result<(), String>, Option<String>) {
        let diagnostic_path = windows_acl_checker_diagnostic_path(path);
        match std::fs::remove_file(&diagnostic_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("failed to clear checker diagnostic sidecar: {error}"),
        }
        let result = super::run_snapshot_acl_checker(path, powershell, script, timeout);
        let diagnostic = match std::fs::read_to_string(diagnostic_path) {
            Ok(value) => Some(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("failed to read checker diagnostic sidecar: {error}"),
        };
        (result, diagnostic)
    }

    #[cfg(windows)]
    fn windows_acl_refusal_oracle(result: &Result<(), String>) -> Result<(), &'static str> {
        if result.is_err() {
            Ok(())
        } else {
            Err("unsafe ACL was accepted")
        }
    }

    #[cfg(windows)]
    fn assert_windows_acl_guard_refusal(
        label: &str,
        result: &Result<(), String>,
        diagnostic: Option<&str>,
        expected_guard: &str,
    ) {
        let error = result.as_ref().expect_err(label);
        assert!(
            error.starts_with("snapshot ACL validation refused directory "),
            "{label}: refusal must be an ACL policy result, got {error:?}"
        );
        assert_eq!(diagnostic, Some(expected_guard), "{label}: checker guard");
        assert_eq!(windows_acl_refusal_oracle(result), Ok(()), "{label}");
    }

    #[cfg(windows)]
    fn windows_acl_safe_case() -> WindowsSnapshotAclCase<'static> {
        WindowsSnapshotAclCase {
            snapshot_dacl: "Private",
            parent_dacl: "Private",
            ancestor_rights: "ReadTraverse",
            reparse_position: "None",
            checker: "Available",
        }
    }

    #[cfg(windows)]
    fn assert_windows_acl_script_accepts_safe_fixture(script: &str, label: &str, index: usize) {
        let safe_case = windows_acl_safe_case();
        let safe = WindowsSnapshotAclFixture::new(safe_case, 1000 + index);
        safe.apply_acl(safe_case);
        let powershell = super::windows_powershell_path().unwrap();
        let (result, diagnostic) = run_windows_acl_checker_with_diagnostic(
            &safe.leaf,
            &powershell,
            script,
            Duration::from_secs(5),
        );
        assert!(result.is_ok(), "{label}: safe control failed: {result:?}");
        assert_eq!(diagnostic, None, "{label}: safe control diagnostic");
    }

    #[cfg(windows)]
    fn assert_windows_acl_singleton_killed(
        label: &str,
        guard: &str,
        expected_guard: &str,
        unsafe_case: WindowsSnapshotAclCase<'static>,
        index: usize,
    ) {
        let mutant = windows_acl_script_with_removed_guards(&[guard]);
        assert_windows_acl_script_accepts_safe_fixture(&mutant, label, index);

        let fixture = WindowsSnapshotAclFixture::new(unsafe_case, 2000 + index);
        fixture.apply_acl(unsafe_case);
        let powershell = super::windows_powershell_path().unwrap();
        let baseline = windows_acl_script_with_removed_guards(&[]);
        let (baseline_result, baseline_diagnostic) = run_windows_acl_checker_with_diagnostic(
            &fixture.leaf,
            &powershell,
            &baseline,
            Duration::from_secs(5),
        );
        assert_windows_acl_guard_refusal(
            &format!("{label}: unchanged baseline"),
            &baseline_result,
            baseline_diagnostic.as_deref(),
            expected_guard,
        );

        let (mutated, diagnostic) = run_windows_acl_checker_with_diagnostic(
            &fixture.leaf,
            &powershell,
            &mutant,
            Duration::from_secs(5),
        );
        assert!(
            mutated.is_ok(),
            "{label}: mutant should admit unsafe fixture; diagnostic: {diagnostic:?}; result: {mutated:?}"
        );
        assert_eq!(diagnostic, None, "{label}: accepted mutant diagnostic");
        assert_eq!(
            windows_acl_refusal_oracle(&mutated),
            Err("unsafe ACL was accepted"),
            "{label}: same refusal oracle must fail for mutant"
        );
    }

    #[cfg(windows)]
    fn assert_windows_acl_null_overlap_and_compound(index: usize) {
        const NULL_GUARD: &str = "throw 'null DACL'";
        const ALLOW_GUARD: &str = "throw 'untrusted allow ACE'";
        const SURVIVOR_LABEL: &str =
            "single/null-dacl: observed survivor, blocked by allow-ACE guard";
        const COMPOUND_LABEL: &str = "compound/null-dacl+allow-ace: killed";
        let null_case = WindowsSnapshotAclCase {
            snapshot_dacl: "Null",
            parent_dacl: "Private",
            ancestor_rights: "ReadTraverse",
            reparse_position: "None",
            checker: "Available",
        };
        let fixture = WindowsSnapshotAclFixture::new(null_case, 3000 + index);
        fixture.apply_acl(null_case);
        let powershell = super::windows_powershell_path().unwrap();
        let baseline = windows_acl_script_with_removed_guards(&[]);
        let (baseline_result, baseline_diagnostic) = run_windows_acl_checker_with_diagnostic(
            &fixture.leaf,
            &powershell,
            &baseline,
            Duration::from_secs(5),
        );
        assert_windows_acl_guard_refusal(
            "null-DACL unchanged baseline",
            &baseline_result,
            baseline_diagnostic.as_deref(),
            "null DACL",
        );

        let singleton = windows_acl_script_with_removed_guards(&[NULL_GUARD]);
        assert_windows_acl_script_accepts_safe_fixture(&singleton, SURVIVOR_LABEL, index);
        let (singleton_result, singleton_diagnostic) = run_windows_acl_checker_with_diagnostic(
            &fixture.leaf,
            &powershell,
            &singleton,
            Duration::from_secs(5),
        );
        assert_windows_acl_guard_refusal(
            SURVIVOR_LABEL,
            &singleton_result,
            singleton_diagnostic.as_deref(),
            "untrusted allow ACE",
        );

        let compound = windows_acl_script_with_removed_guards(&[NULL_GUARD, ALLOW_GUARD]);
        assert_windows_acl_script_accepts_safe_fixture(&compound, COMPOUND_LABEL, index + 1);
        let (compound_result, compound_diagnostic) = run_windows_acl_checker_with_diagnostic(
            &fixture.leaf,
            &powershell,
            &compound,
            Duration::from_secs(5),
        );
        assert!(
            compound_result.is_ok(),
            "{COMPOUND_LABEL}: compound mutant should admit unsafe fixture; diagnostic: {compound_diagnostic:?}; result: {compound_result:?}"
        );
        assert_eq!(compound_diagnostic, None, "{COMPOUND_LABEL}: diagnostic");
        assert_eq!(
            windows_acl_refusal_oracle(&compound_result),
            Err("unsafe ACL was accepted"),
            "{COMPOUND_LABEL}: same refusal oracle must fail"
        );
    }

    #[cfg(windows)]
    fn assert_windows_acl_noop_control(index: usize) {
        const LABEL: &str = "unchanged-script no-op control";
        let script = windows_acl_script_with_removed_guards(&[]);
        assert_windows_acl_script_accepts_safe_fixture(&script, LABEL, index);
        let unsafe_case = WindowsSnapshotAclCase {
            snapshot_dacl: "Permissive",
            parent_dacl: "Private",
            ancestor_rights: "ReadTraverse",
            reparse_position: "None",
            checker: "Available",
        };
        let fixture = WindowsSnapshotAclFixture::new(unsafe_case, 4000 + index);
        fixture.apply_acl(unsafe_case);
        let powershell = super::windows_powershell_path().unwrap();
        let (result, diagnostic) = run_windows_acl_checker_with_diagnostic(
            &fixture.leaf,
            &powershell,
            &script,
            Duration::from_secs(5),
        );
        assert_windows_acl_guard_refusal(
            LABEL,
            &result,
            diagnostic.as_deref(),
            "untrusted allow ACE",
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_acl_pict_matrix_consumes_all_rows() {
        let cases = windows_snapshot_acl_cases();
        assert_eq!(cases.len(), 39, "all generated PICT rows must run");
        let powershell = super::windows_powershell_path().unwrap();
        for (index, case) in cases.into_iter().enumerate() {
            let fixture = WindowsSnapshotAclFixture::new(case, index);
            fixture.apply_acl(case);
            let expected_accept = !windows_acl_row_refuses(case);
            let actual = super::run_snapshot_acl_checker(
                &fixture.leaf,
                &powershell,
                super::WINDOWS_SNAPSHOT_ACL_CHECK,
                Duration::from_secs(5),
            );
            assert_eq!(
                actual.is_ok(),
                expected_accept,
                "ACL policy mismatch for generated row {index}: {case:?}; {actual:?}"
            );
            if case.checker == "Unavailable" {
                let missing = fixture.root.join("missing-powershell.exe");
                let unavailable = super::run_snapshot_acl_checker(
                    &fixture.leaf,
                    &missing,
                    super::WINDOWS_SNAPSHOT_ACL_CHECK,
                    Duration::from_secs(1),
                );
                assert!(unavailable.is_err(), "unavailable checker must fail closed");
            } else {
                assert_eq!(case.checker, "Available");
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_acl_missing_checker_refuses_before_copying_secret() {
        let id = std::process::id();
        let source = std::env::temp_dir().join(format!("fireemu-acl-missing-source-{id}"));
        let snapshot_root = std::env::temp_dir().join(format!("fireemu-acl-missing-root-{id}"));
        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&snapshot_root);
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&snapshot_root).unwrap();
        let secret = b"LOCAL_SECRET=missing-checker";
        std::fs::write(source.join(".secret.local"), secret).unwrap();
        let missing = snapshot_root.join("missing-powershell.exe");
        let mut charged_bytes = 0;
        let result = super::snapshot_functions_source_with_charge_at_and_acl_check(
            &source,
            &[],
            &mut |_, bytes| {
                charged_bytes += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &snapshot_root,
            |path| {
                super::run_snapshot_acl_checker(
                    path,
                    &missing,
                    super::WINDOWS_SNAPSHOT_ACL_CHECK,
                    Duration::from_secs(1),
                )
            },
        );
        assert!(result.unwrap_err().contains("snapshot ACL"));
        assert_eq!(charged_bytes, secret.len() as u64);
        assert_eq!(std::fs::read_dir(&snapshot_root).unwrap().count(), 0);
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(snapshot_root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_acl_timeout_kills_descendant_process() {
        use std::process::Command;

        const SCRIPT: &str = r#"
$childCode = 'Start-Sleep -Seconds 60'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCode))
$child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -WindowStyle Hidden -PassThru `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
[IO.File]::WriteAllText($env:FIREEMU_SNAPSHOT_ACL_PATH, [string]$child.Id)
Start-Sleep -Seconds 60
"#;
        let root = std::env::temp_dir().join(format!("fireemu-acl-timeout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let pid_file = root.join("child.pid");
        let powershell = super::windows_powershell_path().unwrap();
        let result =
            super::run_snapshot_acl_checker(&pid_file, &powershell, SCRIPT, Duration::from_secs(3));
        assert!(result.unwrap_err().contains("timed out"));
        let child_pid = std::fs::read_to_string(&pid_file)
            .expect("PowerShell must record the spawned descendant PID before timeout");
        let tasklist = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .expect("Windows defines SystemRoot")
            .join(r"System32\tasklist.exe");
        let output = Command::new(tasklist)
            .args(["/FO", "CSV", "/NH", "/FI"])
            .arg(format!("PID eq {}", child_pid.trim()))
            .output()
            .expect("tasklist is available on Windows");
        assert!(output.status.success());
        let still_running = String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            line.split(',')
                .nth(1)
                .is_some_and(|pid| pid.trim_matches('"') == child_pid.trim())
        });
        assert!(
            !still_running,
            "JobObject+KillOnDrop left child PID {child_pid} running"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_acl_guard_mutants_violate_oracle() {
        let singleton_kills = [
            (
                "single/allow-ACE: killed",
                "throw 'untrusted allow ACE'",
                "untrusted allow ACE",
                WindowsSnapshotAclCase {
                    snapshot_dacl: "Permissive",
                    parent_dacl: "Private",
                    ancestor_rights: "ReadTraverse",
                    reparse_position: "None",
                    checker: "Available",
                },
            ),
            (
                "single/ancestor-mutation: killed",
                "throw 'untrusted ancestor mutation ACE'",
                "untrusted ancestor mutation ACE",
                WindowsSnapshotAclCase {
                    snapshot_dacl: "Private",
                    parent_dacl: "Private",
                    ancestor_rights: "Mutating",
                    reparse_position: "None",
                    checker: "Available",
                },
            ),
            (
                "single/reparse: killed",
                "throw 'reparse or non-directory component'",
                "reparse or non-directory component",
                WindowsSnapshotAclCase {
                    snapshot_dacl: "Private",
                    parent_dacl: "Private",
                    ancestor_rights: "ReadTraverse",
                    reparse_position: "SnapshotLeaf",
                    checker: "Available",
                },
            ),
        ];
        for (index, (label, guard, expected_guard, case)) in singleton_kills.into_iter().enumerate()
        {
            assert_windows_acl_singleton_killed(label, guard, expected_guard, case, index);
        }
        assert_windows_acl_null_overlap_and_compound(10);
        assert_windows_acl_noop_control(20);
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_is_created_with_a_protected_dacl_before_validation() {
        let id = std::process::id();
        let source = std::env::temp_dir().join(format!("fireemu-atomic-acl-source-{id}"));
        let parent = std::env::temp_dir().join(format!("fireemu-atomic-acl-parent-{id}"));
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&parent).unwrap();
        grant_windows_test_ace(&parent, "(OI)(CI)F");

        let result = super::snapshot_functions_source_with_charge_at_and_acl_check(
            &source,
            &[],
            &mut |_, _| Ok(()),
            &AtomicBool::new(false),
            &parent,
            |path| {
                // Observe creation before validation can change or accept the DACL.
                std::fs::write(path.join("child.txt"), b"fixture").unwrap();
                super::run_snapshot_acl_checker(
                    path,
                    &super::windows_powershell_path().unwrap(),
                    r#"
$ErrorActionPreference = 'Stop'
try {
    $path = $env:FIREEMU_SNAPSHOT_ACL_PATH
    $trusted = @([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
    $rootAcl = Get-Acl -LiteralPath $path
    if (-not $rootAcl.AreAccessRulesProtected) { throw 'root DACL is not protected' }
    foreach ($entry in @($path, (Join-Path $path 'child.txt'))) {
        $acl = Get-Acl -LiteralPath $entry
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ($rules.Count -ne $trusted.Count) { throw 'unexpected ACE count' }
        foreach ($sid in $trusted) {
            $rule = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
            if ($rule.Count -ne 1 -or $rule[0].AccessControlType -ne 'Allow' -or
                $rule[0].FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) {
                throw 'unexpected principal or rights'
            }
            if ($entry -eq $path -and $rule[0].IsInherited) { throw 'root inherited an ACE' }
            if ($entry -ne $path -and -not $rule[0].IsInherited) { throw 'child did not inherit trusted ACE' }
        }
    }
} catch { exit 1 }
exit 0
"#,
                    Duration::from_secs(5),
                )
                .expect("creation must block the permissive parent's inheritable grant");
                super::secure_snapshot_directory(path)
            },
        );
        assert!(
            result.unwrap_err().contains("snapshot ACL"),
            "a protected root must still refuse an unsafe parent"
        );
        assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_reload_snapshot_accepts_private_temp_acl() {
        let root = std::env::temp_dir().join(format!(
            "fireemu-windows-private-snapshot-source-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".secret.local"), "LOCAL_SECRET=value").unwrap();

        let snapshot = snapshot_functions_source(&root, &[]).expect("private TEMP ACL accepted");
        assert_eq!(
            std::fs::read(snapshot.join(".secret.local")).unwrap(),
            b"LOCAL_SECRET=value"
        );
        drop(snapshot);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_reload_snapshot_refuses_permissive_acl_before_copying_secret() {
        let id = std::process::id();
        let source = std::env::temp_dir().join(format!("fireemu-windows-acl-source-{id}"));
        let snapshot_root = std::env::temp_dir().join(format!("fireemu-windows-acl-target-{id}"));
        let _ = std::fs::remove_dir_all(&source);
        let _ = std::fs::remove_dir_all(&snapshot_root);
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir(&snapshot_root).unwrap();
        let secret = b"LOCAL_SECRET=must-not-be-copied";
        std::fs::write(source.join(".secret.local"), secret).unwrap();

        grant_windows_test_ace(&snapshot_root, "(OI)(CI)F");

        let mut charged_bytes = 0;
        let result = super::snapshot_functions_source_with_charge_at(
            &source,
            &[],
            &mut |_, bytes| {
                charged_bytes += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &snapshot_root,
        );
        assert!(
            result
                .as_ref()
                .expect_err("permissive ACL must be refused")
                .contains("snapshot ACL"),
            "the failure should identify snapshot ACL validation"
        );
        assert_eq!(
            charged_bytes,
            secret.len() as u64,
            "only the initial source scan may read secret bytes; snapshot copy must not start"
        );
        assert_eq!(
            std::fs::read_dir(&snapshot_root).unwrap().count(),
            0,
            "a refused snapshot must leave no copied runtime files"
        );

        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(snapshot_root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_reload_snapshot_refuses_a_mutable_grandparent_before_copying_secret() {
        let id = std::process::id();
        let outer = std::env::temp_dir().join(format!("fireemu-windows-acl-outer-{id}"));
        let snapshot_root = outer.join("private-parent");
        let source = std::env::temp_dir().join(format!("fireemu-windows-acl-source-{id}"));
        let _ = std::fs::remove_dir_all(&outer);
        let _ = std::fs::remove_dir_all(&source);
        std::fs::create_dir_all(&snapshot_root).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let secret = b"LOCAL_SECRET=must-not-be-copied";
        std::fs::write(source.join(".secret.local"), secret).unwrap();
        grant_windows_test_ace(&outer, "(DC)");

        let mut charged_bytes = 0;
        let result = super::snapshot_functions_source_with_charge_at(
            &source,
            &[],
            &mut |_, bytes| {
                charged_bytes += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &snapshot_root,
        );
        assert!(
            result
                .as_ref()
                .expect_err("a mutable grandparent must be refused")
                .contains("snapshot ACL"),
            "the failure should identify snapshot ACL validation"
        );
        assert_eq!(
            charged_bytes,
            secret.len() as u64,
            "the runtime secret must not be read for a snapshot copy"
        );
        assert_eq!(std::fs::read_dir(&snapshot_root).unwrap().count(), 0);

        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(outer).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_reload_snapshot_allows_ancestor_create_directory_right_without_delete_child() {
        let id = std::process::id();
        let outer = std::env::temp_dir().join(format!("fireemu-windows-acl-near-miss-{id}"));
        let snapshot_root = outer.join("private-parent");
        let source = std::env::temp_dir().join(format!("fireemu-windows-acl-source-{id}"));
        let _ = std::fs::remove_dir_all(&outer);
        let _ = std::fs::remove_dir_all(&source);
        std::fs::create_dir_all(&snapshot_root).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join(".secret.local"), "LOCAL_SECRET=value").unwrap();
        grant_windows_test_ace(&outer, "(AD)");

        let snapshot = super::snapshot_functions_source_with_charge_at(
            &source,
            &[],
            &mut |_, _| Ok(()),
            &AtomicBool::new(false),
            &snapshot_root,
        )
        .expect("create-directory-only ancestor access cannot replace the protected parent");
        assert_eq!(
            std::fs::read_to_string(snapshot.join(".secret.local")).unwrap(),
            "LOCAL_SECRET=value"
        );
        drop(snapshot);
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(outer).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_reload_snapshot_refuses_reparse_higher_ancestor_before_copying_secret() {
        let id = std::process::id();
        let root = std::env::temp_dir().join(format!("fireemu-windows-junction-ancestor-{id}"));
        let target = root.join("target");
        let link = root.join("redirect");
        let snapshot_target = target.join("private-parent");
        let snapshot_root = link.join("private-parent");
        let source = std::env::temp_dir().join(format!("fireemu-windows-junction-source-{id}"));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&source);
        std::fs::create_dir_all(&snapshot_target).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let secret = b"LOCAL_SECRET=must-not-be-copied";
        std::fs::write(source.join(".secret.local"), secret).unwrap();
        create_windows_junction(&link, &target);

        let mut charged_bytes = 0;
        let result = super::snapshot_functions_source_with_charge_at(
            &source,
            &[],
            &mut |_, bytes| {
                charged_bytes += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &snapshot_root,
        );
        assert!(
            result
                .as_ref()
                .expect_err("a reparse ancestor must be refused")
                .contains("snapshot ACL"),
            "the failure should identify snapshot path validation"
        );
        assert_eq!(charged_bytes, secret.len() as u64);
        assert_eq!(std::fs::read_dir(&snapshot_target).unwrap().count(), 0);

        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_reload_snapshot_refuses_reparse_immediate_parent_before_copying_secret() {
        let id = std::process::id();
        let root = std::env::temp_dir().join(format!("fireemu-windows-junction-parent-{id}"));
        let target = root.join("target");
        let link = root.join("redirect");
        let source = std::env::temp_dir().join(format!("fireemu-windows-junction-source-{id}"));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&source);
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        let secret = b"LOCAL_SECRET=must-not-be-copied";
        std::fs::write(source.join(".secret.local"), secret).unwrap();
        create_windows_junction(&link, &target);

        let mut charged_bytes = 0;
        let result = super::snapshot_functions_source_with_charge_at(
            &source,
            &[],
            &mut |_, bytes| {
                charged_bytes += bytes;
                Ok(())
            },
            &AtomicBool::new(false),
            &link,
        );
        assert!(
            result
                .as_ref()
                .expect_err("a reparse immediate parent must be refused")
                .contains("snapshot ACL"),
            "the failure should identify snapshot path validation"
        );
        assert_eq!(charged_bytes, secret.len() as u64);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);

        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_snapshot_acl_check_refuses_reparse_leaf() {
        let id = std::process::id();
        let root = std::env::temp_dir().join(format!("fireemu-windows-junction-leaf-{id}"));
        let target = root.join("target");
        let link = root.join("redirect");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&target).unwrap();
        create_windows_junction(&link, &target);

        let error = super::secure_snapshot_directory(&link).unwrap_err();
        assert!(error.contains("snapshot ACL"), "{error}");

        std::fs::remove_dir(&link).unwrap();
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
    fn storage_trigger_buckets_are_the_explicit_buckets_of_the_storage_triggers_only() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "onUp", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.finalized", "bucket": "events-bucket"}},
            {"name": "onGone", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.deleted", "bucket": "events-bucket"}},
            {"name": "onDefault", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.finalized"}},
            {"name": "onOther", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.archived", "bucket": "other-bucket"}},
            {"name": "worker", "trigger": {"type": "pubsub", "topic": "not-a-bucket"}},
            {"name": "health", "trigger": {"type": "http"}}
        ]})).unwrap();
        assert_eq!(
            storage_trigger_buckets(&manifest)
                .into_iter()
                .collect::<Vec<_>>(),
            vec!["events-bucket".to_owned(), "other-bucket".to_owned()]
        );
        let none = parse_manifest(&json!({"functions": [
            {"name": "health", "trigger": {"type": "http"}}
        ]}))
        .unwrap();
        assert!(storage_trigger_buckets(&none).is_empty());
    }

    #[test]
    fn pubsub_resources_cover_shared_topics_and_schedules_once() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "workerOne", "trigger": {"type": "pubsub", "topic": "shared-jobs"}},
            {"name": "workerTwo", "trigger": {"type": "pubsub", "topic": "shared-jobs"}, "region": "europe-west1"},
            {"name": "dailyReport", "trigger": {"type": "schedule", "schedule": "0 0 * * *"}},
            {"name": "health", "trigger": {"type": "http"}}
        ]})).unwrap();

        let resources = function_pubsub_resources(
            "demo-app",
            &manifest,
            fireemu_adapter_functions::events::SubscriptionNaming::EmulatorTopic,
            CompatibilityProfile::Emulator,
        )
        .unwrap();
        let actual: Vec<(String, String)> = resources
            .iter()
            .map(|resource| {
                (
                    resource.topic.to_full(),
                    resource.subscription.as_ref().unwrap().to_full(),
                )
            })
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

    /// `eventarc-<region>-<function lowercased>-<6 digits>-sub-<3 digits>` with the two numbers masked.
    fn masked_eventarc_subscription(id: &str) -> Option<String> {
        let rest = id.strip_prefix("eventarc-")?;
        let (head, sub) = rest.rsplit_once("-sub-")?;
        let (head, function_number) = head.rsplit_once('-')?;
        let digits = |text: &str, len: usize| {
            text.len() == len && text.bytes().all(|byte| byte.is_ascii_digit())
        };
        (digits(function_number, 6) && digits(sub, 3))
            .then(|| format!("eventarc-{head}-<6 digits>-sub-<3 digits>"))
    }

    fn mixed_generation_manifest() -> fireemu_core_functions::manifest::FunctionManifest {
        parse_manifest(&json!({"functions": [
            {"name": "workerOne", "generation": 2, "trigger": {"type": "pubsub", "topic": "shared-jobs"}},
            {"name": "workerTwo", "generation": 2, "trigger": {"type": "pubsub", "topic": "shared-jobs"}, "region": "europe-west1"},
            {"name": "legacyWorker", "trigger": {"type": "pubsub", "topic": "shared-jobs"}},
            {"name": "dailyReport", "generation": 2, "trigger": {"type": "schedule", "schedule": "0 0 * * *"}},
            {"name": "health", "trigger": {"type": "http"}}
        ]}))
        .unwrap()
    }

    #[test]
    fn the_profile_chooses_how_a_pubsub_functions_subscription_is_named() {
        use crate::config::CompatibilityProfile;
        use fireemu_adapter_functions::events::SubscriptionNaming;
        assert_eq!(
            super::subscription_naming(CompatibilityProfile::Strict),
            SubscriptionNaming::Eventarc
        );
        assert_eq!(
            super::subscription_naming(CompatibilityProfile::Emulator),
            SubscriptionNaming::EmulatorTopic
        );
    }

    #[test]
    fn strict_gives_each_second_generation_pubsub_function_its_own_eventarc_subscription() {
        use fireemu_adapter_functions::events::{function_subscription_id, SubscriptionNaming};
        let manifest = mixed_generation_manifest();
        let resources = function_pubsub_resources(
            "demo-app",
            &manifest,
            SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        let actual: Vec<(String, String)> = resources
            .iter()
            .map(|resource| {
                (
                    resource.topic.to_full(),
                    resource.subscription.as_ref().unwrap().to_full(),
                )
            })
            .collect();
        // Every second generation Pub/Sub function has a subscription of its own, derived from
        // the function the way the event names it; the first generation function keeps the topic's name; a second
        // generation schedule has no topic under strict, as production creates none for it (runs 156715222b86ea44 and
        // f123d4fa2d61c5f5).
        let derived = |name: &str| {
            let function = manifest.get(name).unwrap();
            format!(
                "projects/demo-app/subscriptions/{}",
                function_subscription_id(
                    SubscriptionNaming::Eventarc,
                    "demo-app",
                    function,
                    "shared-jobs"
                )
            )
        };
        let shared = "projects/demo-app/topics/shared-jobs".to_owned();
        let mut expected = vec![
            (
                shared.clone(),
                "projects/demo-app/subscriptions/emulator-sub-shared-jobs".to_owned(),
            ),
            (shared.clone(), derived("workerOne")),
            (shared, derived("workerTwo")),
        ];
        expected.sort();
        assert_eq!(actual, expected);
        assert!(derived("workerOne").contains("/eventarc-us-central1-workerone-"));
        assert!(derived("workerTwo").contains("/eventarc-europe-west1-workertwo-"));
        // A deployment keeps its names across runs, and a second call derives the same ones.
        let again = function_pubsub_resources(
            "demo-app",
            &manifest,
            SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        assert_eq!(resources.len(), again.len());
        for (a, b) in resources.iter().zip(&again) {
            assert_eq!(a.subscription, b.subscription);
        }
    }

    #[test]
    fn the_emulator_profile_keeps_one_topic_subscription_whatever_the_generation() {
        use fireemu_adapter_functions::events::SubscriptionNaming;
        let resources = function_pubsub_resources(
            "demo-app",
            &mixed_generation_manifest(),
            SubscriptionNaming::EmulatorTopic,
            CompatibilityProfile::Emulator,
        )
        .unwrap();
        let names: Vec<String> = resources
            .iter()
            .map(|resource| resource.subscription.as_ref().unwrap().to_full())
            .collect();
        assert_eq!(
            names,
            vec![
                "projects/demo-app/subscriptions/emulator-sub-firebase-schedule-dailyReport",
                "projects/demo-app/subscriptions/emulator-sub-shared-jobs",
            ]
        );
    }

    /// The two recorded names (FE v5 `a9621bfae74fe9bc` frames 134 to 273 and FE v7
    /// `d3fd61c5b`... `d3fd3faa3e0dc702` frames 136 to 277) have the shape the strict name has: the
    /// numbers are per deployment, so only the shape is compared.
    #[test]
    fn the_strict_subscription_has_the_masked_shape_of_both_recorded_names() {
        use fireemu_adapter_functions::events::{function_subscription_id, SubscriptionNaming};
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "pubsubPublishedV2", "generation": 2, "trigger": {"type": "pubsub", "topic": "fe-events-primary"}}
        ]}))
        .unwrap();
        let ours = function_subscription_id(
            SubscriptionNaming::Eventarc,
            "fireemu-oracle-events",
            manifest.get("pubsubPublishedV2").unwrap(),
            "fe-events-primary",
        );
        let masked = masked_eventarc_subscription(&ours);
        assert_eq!(
            masked.as_deref(),
            Some("eventarc-us-central1-pubsubpublishedv2-<6 digits>-sub-<3 digits>")
        );
        for recorded in [
            "eventarc-us-central1-pubsubpublishedv2-834054-sub-834",
            "eventarc-us-central1-pubsubpublishedv2-293232-sub-576",
        ] {
            assert_eq!(masked_eventarc_subscription(recorded), masked, "{recorded}");
            assert_ne!(
                ours, recorded,
                "the numbers are derived, not copied from one deployment"
            );
        }
        assert_eq!(
            masked_eventarc_subscription("emulator-sub-fe-events-primary"),
            None
        );
    }

    #[test]
    fn eventarc_subscriptions_are_provisioned_listed_deleted_and_reprovisioned_by_name() {
        use fireemu_adapter_functions::events::SubscriptionNaming;
        let resources = function_pubsub_resources(
            "demo-app",
            &mixed_generation_manifest(),
            SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        let mut state = PubSubState::new(7);
        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        // Listing shows every resource once, the Eventarc names among them.
        let listed: Vec<String> = state
            .list_subscriptions("demo-app")
            .iter()
            .map(|subscription| subscription.name.to_full())
            .collect();
        for resource in &resources {
            assert!(
                listed.contains(&resource.subscription.as_ref().unwrap().to_full()),
                "{listed:?}"
            );
        }
        assert_eq!(listed.len(), resources.len());
        assert_eq!(state.list_topics("demo-app").len(), 1);
        // Provisioning again changes nothing; a message published on the topic is not retained by a
        // function's subscription (the Functions bridge delivers it), whatever the subscription's name.
        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        assert_eq!(state.list_subscriptions("demo-app").len(), resources.len());
        // Deleting one function's subscription leaves the others, and provisioning brings it back
        // under the same name.
        let victim = resources
            .iter()
            .find(|resource| {
                resource
                    .subscription
                    .as_ref()
                    .unwrap()
                    .to_full()
                    .contains("eventarc-europe-west1-workertwo-")
            })
            .unwrap();
        state
            .delete_subscription(victim.subscription.as_ref().unwrap())
            .unwrap();
        assert_eq!(
            state.list_subscriptions("demo-app").len(),
            resources.len() - 1
        );
        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        assert!(state
            .subscription_config(victim.subscription.as_ref().unwrap())
            .is_ok());
        assert_eq!(state.list_subscriptions("demo-app").len(), resources.len());
    }

    /// The daemon hands the profile to the Functions runtime: a regression here would silently give the
    /// emulator profile production's event shapes, or the strict profile the official emulator's.
    #[test]
    fn the_functions_config_carries_the_profile_choices_of_the_daemon() {
        use fireemu_adapter_functions::events::{
            AuthContextNaming, DatabaseEventShape, SubscriptionNaming,
        };
        for (profile, shape, naming, subscriptions, location, honours_schedule) in [
            (
                "strict",
                DatabaseEventShape::Production,
                AuthContextNaming::Production,
                SubscriptionNaming::default(),
                "us-central1",
                true,
            ),
            (
                "emulator",
                DatabaseEventShape::Official,
                AuthContextNaming::Official,
                SubscriptionNaming::EmulatorTopic,
                "nam5",
                false,
            ),
        ] {
            let cfg = crate::config::RuntimeConfig::from_json(&json!({
                "schemaVersion": 1, "profile": profile, "firestore": {"location": "us-central1"}
            }))
            .unwrap();
            let config = super::functions_config(&cfg, Some("127.0.0.1:5001".to_owned()), "secret");
            assert_eq!(config.database_event_shape, shape, "{profile}");
            assert_eq!(config.auth_context, naming, "{profile}");
            assert_eq!(config.subscription_naming, subscriptions, "{profile}");
            assert_eq!(config.location, location, "{profile}");
            assert_eq!(
                config.honour_task_schedule_time, honours_schedule,
                "{profile}"
            );
            assert_eq!(config.project, cfg.auth_project);
            assert_eq!(config.functions_host.as_deref(), Some("127.0.0.1:5001"));
            assert_eq!(config.runner_secret, "secret");
            assert!(!config.debug_mode, "{profile}");
            let mut inspected = cfg.clone();
            inspected.functions_inspect_dynamic = true;
            assert!(super::functions_config(&inspected, None, "s").debug_mode);
            let mut inspected = cfg.clone();
            inspected.functions_inspect_port = Some(9229);
            assert!(super::functions_config(&inspected, None, "s").debug_mode);
        }
    }

    /// The development defaults of the Cloud Tasks queue follow the profile, `productionExact` restores production's,
    /// and an explicit key wins over both.
    #[test]
    fn the_task_defaults_follow_the_profile_and_production_exact_restores_production() {
        use fireemu_adapter_functions::tasks_production::NameReuse;
        let hour = std::time::Duration::from_secs(3600);
        for (json, reuse, deadline) in [
            (
                json!({"schemaVersion": 1, "profile": "strict"}),
                NameReuse::Immediate,
                60,
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": false}),
                NameReuse::Immediate,
                60,
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true}),
                NameReuse::Window(hour),
                600,
            ),
            (
                json!({"schemaVersion": 1, "profile": "emulator"}),
                NameReuse::Retained,
                60,
            ),
            // An explicit key wins over productionExact, key by key.
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true,
                       "functions": {"taskNameReuse": "immediate", "taskDispatchDeadlineSeconds": 90}}),
                NameReuse::Immediate,
                90,
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true,
                       "functions": {"taskNameReuse": "retained"}}),
                NameReuse::Retained,
                600,
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict",
                       "functions": {"taskNameReuse": "production", "taskDispatchDeadlineSeconds": 600}}),
                NameReuse::Window(hour),
                600,
            ),
            (
                json!({"schemaVersion": 1, "profile": "emulator", "functions": {"taskNameReuse": "immediate"}}),
                NameReuse::Immediate,
                60,
            ),
        ] {
            let cfg = crate::config::RuntimeConfig::from_json(&json).unwrap();
            let config = super::functions_config(&cfg, None, "s");
            assert_eq!(config.task_name_reuse, reuse, "{json}");
            assert_eq!(config.task_default_deadline_seconds, deadline, "{json}");
        }
    }

    /// The retry defaults and the time zone are applied by the configuration, each by its own key.
    #[test]
    fn the_configuration_applies_its_manifest_defaults_by_key() {
        let manifest = || {
            json!({"functions": [
                {"name": "queue", "trigger": {"type": "tasks"}},
                {"name": "job", "trigger": {"type": "schedule", "schedule": "every 5 minutes"}},
            ]})
        };
        for (config, attempts, zone) in [
            (
                json!({"schemaVersion": 1, "profile": "strict"}),
                json!(null),
                json!(null),
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true}),
                json!(100),
                json!(null),
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true,
                       "functions": {"taskRetryDefaults": "emulated"}}),
                json!(null),
                json!(null),
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "functions": {"taskRetryDefaults": "production"},
                       "scheduler": {"defaultTimeZone": "Asia/Tokyo"}}),
                json!(100),
                json!("Asia/Tokyo"),
            ),
            (
                json!({"schemaVersion": 1, "profile": "emulator", "scheduler": {"defaultTimeZone": "Asia/Tokyo"}}),
                json!(null),
                json!("Asia/Tokyo"),
            ),
        ] {
            let cfg = crate::config::RuntimeConfig::from_json(&config).unwrap();
            let mut document = manifest();
            super::apply_config_defaults(&mut document, &cfg);
            assert_eq!(
                document["functions"][0]["trigger"]["retryConfig"]["maxAttempts"], attempts,
                "{config}"
            );
            assert_eq!(
                document["functions"][1]["trigger"]["timeZone"], zone,
                "{config}"
            );
        }
    }

    /// `functions.taskRetryBackoff` reaches the runtime as the flag the dispatch reads, by profile, `productionExact` and its own key.
    #[test]
    fn the_retry_gaps_follow_production_under_production_exact_unless_the_key_says_declared() {
        for (config, production_gaps) in [
            (json!({"schemaVersion": 1, "profile": "strict"}), false),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true}),
                true,
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "productionExact": true,
                       "functions": {"taskRetryBackoff": "declared"}}),
                false,
            ),
            (
                json!({"schemaVersion": 1, "profile": "strict", "functions": {"taskRetryBackoff": "production"}}),
                true,
            ),
            (json!({"schemaVersion": 1, "profile": "emulator"}), false),
        ] {
            let cfg = crate::config::RuntimeConfig::from_json(&config).unwrap();
            assert_eq!(
                super::functions_config(&cfg, None, "s").task_retry_production_gaps,
                production_gaps,
                "{config}"
            );
        }
    }

    /// `functions.taskRetryDefaults` `production` fills `maxAttempts` of a task queue function that does not declare it
    /// and nothing else: a declared value (zero included), a null, another trigger type and the other retry fields stay.
    #[test]
    fn production_retry_defaults_fill_only_a_missing_max_attempts_of_a_task_queue() {
        let mut manifest = json!({"functions": [
            {"name": "none", "trigger": {"type": "tasks"}},
            {"name": "empty", "trigger": {"type": "tasks", "retryConfig": {}}},
            {"name": "null", "trigger": {"type": "tasks", "retryConfig": null}},
            {"name": "nulled", "trigger": {"type": "tasks", "retryConfig": {"maxAttempts": null, "minBackoffSeconds": 1}}},
            {"name": "partial", "trigger": {"type": "tasks", "retryConfig": {"maxRetrySeconds": 6, "maxDoublings": 1}}},
            {"name": "declared", "trigger": {"type": "tasks", "retryConfig": {"maxAttempts": 2}}},
            {"name": "zero", "trigger": {"type": "tasks", "retryConfig": {"maxAttempts": 0}}},
            {"name": "http", "trigger": {"type": "http"}},
            {"name": "bare"},
        ]});
        super::apply_task_retry_defaults(&mut manifest);
        let attempts = |name: &str| {
            manifest["functions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["name"] == name)
                .unwrap()["trigger"]["retryConfig"]["maxAttempts"]
                .clone()
        };
        for name in ["none", "empty", "null", "nulled", "partial"] {
            assert_eq!(attempts(name), json!(100), "{name}");
        }
        assert_eq!(attempts("declared"), json!(2));
        assert_eq!(attempts("zero"), json!(0));
        assert_eq!(
            manifest["functions"][3]["trigger"]["retryConfig"]["minBackoffSeconds"],
            json!(1)
        );
        assert_eq!(
            manifest["functions"][4]["trigger"]["retryConfig"]["maxRetrySeconds"],
            json!(6)
        );
        assert!(manifest["functions"][7]["trigger"]
            .get("retryConfig")
            .is_none());
        assert!(manifest["functions"][8].get("trigger").is_none());
        // The result parses to production's defaults and keeps the official ones for the other fields.
        let parsed = parse_manifest(&json!({"functions": [{
            "name": "queue", "entryPoint": "queue", "region": "us-central1",
            "trigger": manifest["functions"][0]["trigger"].clone(),
        }]}))
        .unwrap();
        let fireemu_core_functions::manifest::Trigger::TaskQueue { retry, .. } =
            parsed.functions[0].trigger
        else {
            panic!("a task queue")
        };
        assert_eq!(
            (
                retry.max_attempts,
                retry.min_backoff_millis,
                retry.max_backoff_millis,
                retry.max_doublings,
                retry.max_retry_millis
            ),
            (100, 100, 3_600_000, 16, None)
        );
    }

    proptest::proptest! {
        /// E4: a pinned seed ignores the nonce, an unpinned start ignores the seed.
        #[test]
        fn the_session_is_a_function_of_the_seed_or_the_nonce_never_both(
            seed in proptest::prelude::any::<u64>(),
            nonce in proptest::prelude::any::<u64>(),
            other in proptest::prelude::any::<u64>(),
        ) {
            proptest::prop_assert_eq!(super::session_value(seed, true, nonce), u128::from(seed));
            proptest::prop_assert_eq!(super::session_value(seed, true, other), u128::from(seed));
            proptest::prop_assert_eq!(super::session_value(seed, false, nonce), u128::from(nonce));
            proptest::prop_assert_eq!(super::session_value(other, false, nonce), u128::from(nonce));
        }
    }

    /// E1/E2: the Functions session, which every event id is derived from, is the seed only when
    /// the configuration names one. A plain start gets a per-boot session, so a restart does not
    /// repeat the previous run's ids; an explicit seed still gives the documented golden ids.
    #[test]
    fn a_plain_start_does_not_derive_event_ids_from_the_default_seed() {
        use crate::config::RuntimeConfig;
        use fireemu_core_types::ids::SessionId;
        let pinned =
            RuntimeConfig::from_json(&json!({"schemaVersion": 1, "daemon": {"seed": 42}})).unwrap();
        assert!(pinned.seed_pinned);
        assert_eq!(
            super::functions_config(&pinned, None, "s").session,
            SessionId::new(42)
        );
        let plain = RuntimeConfig::from_json(&json!({"schemaVersion": 1})).unwrap();
        assert!(!plain.seed_pinned);
        assert_ne!(
            super::functions_config(&plain, None, "s").session,
            SessionId::new(42),
            "a plain start must not be the seed-42 session"
        );
        // One boot, one session: every codebase and every call sees the same nonce, and it is a
        // draw, not a constant. Two draws differ (the odds of a repeat are 2^-64).
        let again = RuntimeConfig::from_json(&json!({"schemaVersion": 1})).unwrap();
        let session = super::functions_config(&plain, None, "s").session;
        assert_eq!(session, super::functions_config(&again, None, "s").session);
        assert!(
            session.value() > 1,
            "the nonce is drawn, not a small constant"
        );
        assert_eq!(session.value(), u128::from(super::boot_nonce()));
        assert_ne!(super::fresh_nonce(), super::fresh_nonce());
        let other =
            RuntimeConfig::from_json(&json!({"schemaVersion": 1, "daemon": {"seed": 7}})).unwrap();
        assert_eq!(
            super::functions_config(&other, None, "s").session,
            SessionId::new(7)
        );
    }

    #[test]
    fn the_profile_chooses_how_a_database_trigger_event_is_shaped() {
        use crate::config::CompatibilityProfile;
        use fireemu_adapter_functions::events::DatabaseEventShape;
        assert_eq!(
            super::database_event_shape(CompatibilityProfile::Strict),
            DatabaseEventShape::Production
        );
        assert_eq!(
            super::database_event_shape(CompatibilityProfile::Emulator),
            DatabaseEventShape::Official
        );
    }

    #[test]
    fn the_profile_chooses_how_the_writer_of_an_auth_context_event_is_named() {
        use crate::config::CompatibilityProfile;
        use fireemu_adapter_functions::events::AuthContextNaming;
        assert_eq!(
            super::auth_context_naming(CompatibilityProfile::Strict),
            AuthContextNaming::Production
        );
        assert_eq!(
            super::auth_context_naming(CompatibilityProfile::Emulator),
            AuthContextNaming::Official
        );
    }

    /// Strict: only a first-generation schedule has a topic, named like its Cloud Scheduler job, and no emulator
    /// subscription; a second-generation schedule has none; a topic a function subscribes to keeps its subscription.
    #[test]
    fn strict_pubsub_resources_give_a_first_generation_schedule_its_job_topic_and_no_subscription()
    {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "workerOne", "trigger": {"type": "pubsub", "topic": "shared-jobs"}},
            {"name": "dailyReport", "trigger": {"type": "schedule", "schedule": "0 0 * * *"}},
            {"name": "weeklyV2", "generation": 2, "trigger": {"type": "schedule", "schedule": "0 0 * * 0"}},
            {"name": "eastReport", "region": "us-east1", "trigger": {"type": "schedule", "schedule": "0 0 * * *"}},
            {"name": "health", "trigger": {"type": "http"}}
        ]}))
        .unwrap();
        let resources = function_pubsub_resources(
            "demo-app",
            &manifest,
            fireemu_adapter_functions::events::SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        let actual: Vec<(String, Option<String>)> = resources
            .iter()
            .map(|resource| {
                (
                    resource.topic.to_full(),
                    resource
                        .subscription
                        .as_ref()
                        .map(fireemu_core_pubsub::SubscriptionName::to_full),
                )
            })
            .collect();
        assert_eq!(
            actual,
            vec![
                (
                    "projects/demo-app/topics/firebase-schedule-dailyReport-us-central1".to_owned(),
                    None
                ),
                (
                    "projects/demo-app/topics/firebase-schedule-eastReport-us-east1".to_owned(),
                    None
                ),
                (
                    "projects/demo-app/topics/shared-jobs".to_owned(),
                    Some("projects/demo-app/subscriptions/emulator-sub-shared-jobs".to_owned())
                ),
            ]
        );
        // the emulator profile is unchanged: the official name for every schedule, with its subscription
        let emulator = function_pubsub_resources(
            "demo-app",
            &manifest,
            fireemu_adapter_functions::events::SubscriptionNaming::EmulatorTopic,
            CompatibilityProfile::Emulator,
        )
        .unwrap();
        let topics: Vec<String> = emulator.iter().map(|r| r.topic.to_full()).collect();
        assert_eq!(
            topics,
            vec![
                "projects/demo-app/topics/firebase-schedule-dailyReport",
                "projects/demo-app/topics/firebase-schedule-eastReport",
                "projects/demo-app/topics/firebase-schedule-weeklyV2",
                "projects/demo-app/topics/shared-jobs",
            ]
        );
        assert!(emulator.iter().all(|r| r.subscription.is_some()));
    }

    /// A topic that two functions declare is one resource: the diagnostics name the smaller owner whichever comes first,
    /// and the emulator subscribes to it when any declaration is a function's own subscription (a schedule's topic that a
    /// Pub/Sub function also listens on keeps its subscription).
    #[test]
    fn a_topic_declared_twice_keeps_the_smaller_owner_and_a_subscription_if_any_declaration_wants_one(
    ) {
        for names in [["a", "b"], ["b", "a"]] {
            let functions: Vec<_> = names
                .iter()
                .map(|n| json!({"name": n, "trigger": {"type": "pubsub", "topic": "bad topic"}}))
                .collect();
            let manifest = parse_manifest(&json!({ "functions": functions })).unwrap();
            let error = function_pubsub_resources(
                "demo-app",
                &manifest,
                fireemu_adapter_functions::events::SubscriptionNaming::EmulatorTopic,
                CompatibilityProfile::Emulator,
            )
            .unwrap_err();
            assert!(error.starts_with("function \"a\" requires"), "{error}");
        }
        for names in [["tick", "listener"], ["listener", "tick"]] {
            let functions: Vec<_> = names
                .iter()
                .map(|n| {
                    if *n == "tick" {
                        json!({"name": "tick", "trigger": {"type": "schedule", "schedule": "every 5 minutes"}})
                    } else {
                        json!({"name": "listener", "trigger": {"type": "pubsub", "topic": "firebase-schedule-tick-us-central1"}})
                    }
                })
                .collect();
            let manifest = parse_manifest(&json!({ "functions": functions })).unwrap();
            let resources = function_pubsub_resources(
                "demo-app",
                &manifest,
                fireemu_adapter_functions::events::SubscriptionNaming::Eventarc,
                CompatibilityProfile::Strict,
            )
            .unwrap();
            assert_eq!(resources.len(), 1);
            assert!(resources[0].subscription.is_some(), "{names:?}");
        }
    }

    /// The strict profile publishes a schedule's message when a broker is served; the emulator profile never does.
    #[test]
    fn schedule_messages_are_published_by_the_strict_profile_with_a_broker_only() {
        use super::publishes_schedule_messages;
        assert!(publishes_schedule_messages(
            true,
            CompatibilityProfile::Strict
        ));
        assert!(!publishes_schedule_messages(
            false,
            CompatibilityProfile::Strict
        ));
        assert!(!publishes_schedule_messages(
            true,
            CompatibilityProfile::Emulator
        ));
        assert!(!publishes_schedule_messages(
            false,
            CompatibilityProfile::Emulator
        ));
    }

    /// Provisioning a strict schedule topic creates the topic and no subscription.
    #[test]
    fn strict_provisioning_creates_the_schedule_topic_without_a_subscription() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "dailyReport", "trigger": {"type": "schedule", "schedule": "0 0 * * *"}}
        ]}))
        .unwrap();
        let resources = function_pubsub_resources(
            "demo-app",
            &manifest,
            fireemu_adapter_functions::events::SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        let mut state = PubSubState::new(7);
        provision_function_pubsub_resources(&mut state, &resources).unwrap();
        assert_eq!(state.list_topics("demo-app").len(), 1);
        assert!(state.list_subscriptions("demo-app").is_empty());
    }

    /// End to end under the strict profile: an occurrence of a first-generation schedule puts a message with the
    /// recorded shape on the job's topic (attribute `scheduled: "true"`, no data, the id the event names, the time of the
    /// occurrence), a manual run puts another, the function is not delivered a second time through the topic, and a
    /// second-generation schedule puts nothing anywhere.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn a_strict_schedule_publishes_its_message_to_the_job_topic_with_the_id_of_its_event() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
        use fireemu_adapter_pubsub::PubSubHandle;
        use fireemu_core_pubsub::SubscriptionConfig;
        use fireemu_core_types::ids::SessionId;
        use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
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
        let start = LogicalInstant::from_unix_seconds(1_788_004_860);
        let clock = Arc::new(Mutex::new(VirtualClock::new(start)));
        let runtime = FunctionsRuntime::new(
            manifest,
            FunctionsConfig {
                project: "demo-app".to_owned(),
                default_bucket: "demo-app.appspot.com".to_owned(),
                location: "nam5".to_owned(),
                session: SessionId::new(7),
                max_running: 4,
                debug_mode: false,
                retry_attempts: 1,
                max_catch_up_runs: 1000,
                runner_secret: "test-secret".to_owned(),
                overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
                catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
                functions_host: None,
                clock_policy:
                    fireemu_adapter_functions::application_clock::ApplicationClockPolicy::default(),
                honour_task_schedule_time: false,
                task_name_reuse: fireemu_adapter_functions::tasks_production::NameReuse::Retained,
                task_default_deadline_seconds: 60,
                task_retry_production_gaps: false,
                clock_start_pinned: false,
                subscription_naming: fireemu_adapter_functions::events::SubscriptionNaming::default(
                ),
                auth_context: fireemu_adapter_functions::events::AuthContextNaming::default(),
                database_event_shape:
                    fireemu_adapter_functions::events::DatabaseEventShape::default(),
            },
            clock.clone(),
            Arc::new(runner),
            Some(spawn),
        );
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        let resources = function_pubsub_resources(
            "demo-app",
            runtime.manifest(),
            fireemu_adapter_functions::events::SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        provision_function_pubsub_resources(&mut state.lock().unwrap(), &resources).unwrap();
        let topic = TopicName::new("demo-app", "firebase-schedule-tick-us-central1").unwrap();
        let watch = SubscriptionName::new("demo-app", "watch").unwrap();
        state
            .lock()
            .unwrap()
            .create_subscription(SubscriptionConfig {
                labels: std::collections::BTreeMap::new(),
                expiration_policy: None,
                retain_acked_messages: false,
                message_retention_duration: None,
                name: watch.clone(),
                topic,
                ack_deadline_seconds: 10,
                enable_message_ordering: false,
                filter: Filter::always(),
                dead_letter_policy: None,
                retry_policy: None,
                push_config: PushConfig::default(),
            })
            .unwrap();
        let handle = PubSubHandle::new(
            state.clone(),
            clock.clone(),
            Some(Arc::new(PubSubBridge::new(runtime.clone()))),
        );
        runtime.set_schedule_topic_publisher(Arc::new(PubSubSchedulePublisher::new(
            handle.clone(),
            "demo-app",
        )));
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(300))
            .unwrap();
        runtime.on_clock_changed();
        runtime.run_schedule("tick").unwrap();
        let pulled = handle.pull(&watch, 10).unwrap();
        assert_eq!(pulled.len(), 2, "one occurrence and one manual run");
        for received in &pulled {
            let message = &received.message;
            assert!(message.message.data.is_empty());
            assert_eq!(
                message.message.attributes,
                BTreeMap::from([("scheduled".to_owned(), "true".to_owned())])
            );
            assert!(
                message.message_id.len() == 17 && message.message_id.starts_with('2'),
                "{}",
                message.message_id
            );
        }
        assert_ne!(pulled[0].message.message_id, pulled[1].message.message_id);
        // the two runs are the only events: nothing was delivered again through the topic
        let status = runtime.status();
        assert_eq!(
            status["causality"]["events"].as_array().unwrap().len(),
            2,
            "{status}"
        );
        assert_eq!(status["pending"], 2, "{status}");
        // A deleted topic refuses both natural and manual publications, without invoking a handler or retaining its id.
        state
            .lock()
            .unwrap()
            .delete_topic(
                &TopicName::new("demo-app", "firebase-schedule-tick-us-central1").unwrap(),
            )
            .unwrap();
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(300))
            .unwrap();
        runtime.on_clock_changed();
        assert_eq!(runtime.status()["pending"], 2);
        assert_eq!(runtime.dead_letters().len(), 1);
        assert!(runtime.run_schedule("tick").is_err());
        assert_eq!(runtime.status()["pending"], 2);
        assert_eq!(runtime.dead_letters().len(), 2);
        assert_eq!(
            runtime.source_event_accounting().unwrap().published_records,
            2
        );
        let dispatcher = tokio::spawn(runtime.clone().dispatch_loop());
        tokio::time::timeout(Duration::from_secs(10), async {
            while !runtime.is_idle() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            runtime
                .history()
                .iter()
                .filter(|r| r.outcome == "ok")
                .count(),
            2
        );
        assert_eq!(
            runtime
                .history()
                .iter()
                .filter(|r| r.outcome.starts_with("failed:"))
                .count(),
            2
        );
        runtime.shutdown().await;
        dispatcher.await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // Exercise the complete broker-to-Node delivery lifecycle.
    async fn strict_user_schedule_topic_publishes_and_scheduler_runs_deliver_once_per_subscriber() {
        use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
        use fireemu_adapter_functions::runtime::{CodebaseSpec, FunctionsConfig, FunctionsRuntime};
        use fireemu_adapter_pubsub::PubSubHandle;
        use fireemu_core_pubsub::PubsubMessage;
        use fireemu_core_types::time::LogicalInstant;
        use std::time::Duration;

        struct Fixture(std::path::PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let source =
            std::env::temp_dir().join(format!("fireemu-schedule-topic-{}", std::process::id()));
        std::fs::create_dir(&source).unwrap();
        let fixture = Fixture(source);
        std::fs::write(
            fixture.0.join("package.json"),
            r#"{"private":true,"main":"index.cjs"}"#,
        )
        .unwrap();
        std::fs::write(fixture.0.join("index.cjs"), r#"
const { appendFileSync } = require("node:fs");
const { join } = require("node:path");
const handler = name => async (data, context) => appendFileSync(join(__dirname, "calls.jsonl"), JSON.stringify({ name, data, context }) + "\n");
const tick = handler("tick");
tick.__endpoint = { platform: "gcfv1", scheduleTrigger: { schedule: "every 5 minutes" } };
const observer = handler("observer");
observer.__trigger = { eventTrigger: { eventType: "google.pubsub.topic.publish", resource: "projects/demo-app/topics/firebase-schedule-tick-us-central1" } };
module.exports = { tick, observer };
"#).unwrap();
        let spawn = SpawnSpec {
            command: vec![
                std::env::var("FIREEMU_NODE").unwrap_or_else(|_| "node".into()),
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tools/runner-node/index.mjs")
                    .display()
                    .to_string(),
                "--source".into(),
                fixture.0.display().to_string(),
            ],
            cwd: None,
            env: vec![
                ("GCLOUD_PROJECT".into(), "demo-app".into()),
                ("FIREEMU_HTTP_PROFILE".into(), "strict".into()),
            ],
            hello_timeout: Duration::from_secs(60),
        };
        let runner = Arc::new(Runner::spawn_spec(&spawn).await.unwrap());
        let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )));
        let runtime = FunctionsRuntime::with_codebases(
            vec![CodebaseSpec {
                function: None,
                name: "default".into(),
                manifest,
                runner,
                spawn: Some(spawn),
                cleanup_dir: None,
            }],
            FunctionsConfig::for_tests(100, "test-secret".into()),
            clock.clone(),
            fireemu_adapter_functions::http::FunctionsHttpProfile::Strict,
        )
        .unwrap();
        let state = Arc::new(Mutex::new(PubSubState::new(42)));
        let resources = function_pubsub_resources(
            "demo-app",
            runtime.manifest(),
            fireemu_adapter_functions::events::SubscriptionNaming::Eventarc,
            CompatibilityProfile::Strict,
        )
        .unwrap();
        provision_function_pubsub_resources(&mut state.lock().unwrap(), &resources).unwrap();
        let handle = PubSubHandle::new(
            state,
            clock.clone(),
            Some(Arc::new(PubSubBridge::new(runtime.clone()))),
        );
        runtime.set_schedule_topic_publisher(Arc::new(PubSubSchedulePublisher::new(
            handle.clone(),
            "demo-app",
        )));
        let topic = TopicName::new("demo-app", "firebase-schedule-tick-us-central1").unwrap();
        let user = handle
            .publish(
                &topic,
                vec![PubsubMessage {
                    data: b"user message".to_vec(),
                    attributes: BTreeMap::from([
                        ("scheduled".into(), "true".into()),
                        ("custom".into(), "kept".into()),
                    ]),
                    ordering_key: "user-order".into(),
                }],
            )
            .unwrap();
        let pending = runtime.status()["pending"].clone();
        if pending != 2 {
            runtime.shutdown().await;
        }
        assert_eq!(
            pending, 2,
            "the user publish reaches both the schedule and the ordinary subscriber"
        );
        assert!(!user[0].message.data.is_empty());
        runtime.run_schedule("tick").unwrap();
        let manual_pending = runtime.status()["pending"].clone();
        clock
            .lock()
            .unwrap()
            .advance(fireemu_core_types::time::LogicalDuration::from_seconds(300))
            .unwrap();
        runtime.on_clock_changed();
        let natural_pending = runtime.status()["pending"].clone();
        let dispatcher = tokio::spawn(runtime.clone().dispatch_loop());
        let idle = runtime.await_idle(Duration::from_secs(10)).await;
        let history = runtime.history();
        runtime.shutdown().await;
        dispatcher.await.unwrap();
        assert_eq!(
            manual_pending, 4,
            "the manual run reaches each subscriber once"
        );
        assert_eq!(
            natural_pending, 6,
            "a natural occurrence also reaches each subscriber once"
        );
        assert!(idle.is_ok(), "{idle:?}");
        let calls: Vec<serde_json::Value> = std::fs::read_to_string(fixture.0.join("calls.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(calls.len(), 6);
        for function in ["tick", "observer"] {
            let published = calls
                .iter()
                .find(|call| {
                    call["name"] == function && call["context"]["eventId"] == user[0].message_id
                })
                .expect("the user's original message reaches each handler");
            assert_eq!(
                published["data"]["data"],
                super::base64_encode(b"user message")
            );
            assert_eq!(
                published["data"]["attributes"],
                serde_json::json!({"scheduled": "true", "custom": "kept"})
            );
            assert_eq!(published["data"]["orderingKey"], "user-order");
            assert_eq!(published["data"]["messageId"], user[0].message_id);
            assert_eq!(published["context"]["resource"]["name"], topic.to_full());

            assert_eq!(
                history
                    .iter()
                    .filter(|r| r.function == function && r.outcome == "ok")
                    .count(),
                3,
                "{history:?}"
            );
        }
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
                ..FunctionsConfig::for_tests(1000, "test-secret".to_owned())
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
                    labels: std::collections::BTreeMap::new(),
                    expiration_policy: None,
                    retain_acked_messages: false,
                    message_retention_duration: None,
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
                ..FunctionsConfig::for_tests(1000, "test-secret".to_owned())
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
                    labels: std::collections::BTreeMap::new(),
                    expiration_policy: None,
                    retain_acked_messages: false,
                    message_retention_duration: None,
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
                    labels: std::collections::BTreeMap::new(),
                    expiration_policy: None,
                    retain_acked_messages: false,
                    message_retention_duration: None,
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
        let resources = function_pubsub_resources(
            "demo-app",
            &manifest,
            fireemu_adapter_functions::events::SubscriptionNaming::EmulatorTopic,
            CompatibilityProfile::Emulator,
        )
        .unwrap();
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
                labels: std::collections::BTreeMap::new(),
                expiration_policy: None,
                retain_acked_messages: false,
                message_retention_duration: None,
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

    /// Functions scenario 6, revised by owner decision 1396: a callable that declares
    /// `consumeAppCheckToken: true` no longer stops the codebase from loading, with App Check
    /// enabled or not. The per-call answer lives in the callable proxy.
    #[test]
    fn a_token_consuming_callable_loads_whether_or_not_app_check_is_enabled() {
        check_callable_app_check(
            &manifest(Some("enabled")),
            Some(&report("ok", "verified")),
            true,
        )
        .expect("the codebase loads with App Check enabled");
        check_callable_app_check(&manifest(Some("enabled")), None, false)
            .expect("the codebase loads without App Check");
    }

    /// The Admin SDK instrumentation is silent when it is in place or the codebase has no
    /// `firebase-admin`, and names the reason (and what the user gets) in every other case.
    #[test]
    fn the_admin_app_check_note_is_printed_only_when_the_instrumentation_is_not_in_place() {
        use serde_json::json;
        for silent in [
            json!({"instrumentation": "ok", "firebaseAdminVersion": "14.3.0"}),
            json!({"instrumentation": "not-installed", "firebaseAdminVersion": null}),
        ] {
            assert_eq!(
                admin_app_check_note("default", Some(&silent)),
                None,
                "{silent}"
            );
        }
        for (reason, version) in [
            (
                "firebase-admin 15.0.0 is outside the supported range (major 13, 14)",
                "15.0.0",
            ),
            ("daemon-unavailable", "14.3.0"),
            ("disabled", "14.3.0"),
        ] {
            let report = json!({"instrumentation": reason, "firebaseAdminVersion": version});
            let note = admin_app_check_note("api", Some(&report)).expect("a note");
            assert!(note.contains("functions[api]"), "{note}");
            assert!(note.contains(reason), "{note}");
            assert!(note.contains("rejects fireemu App Check tokens"), "{note}");
        }
        let missing = admin_app_check_note("default", None).expect("a note");
        assert!(missing.contains("did not report"), "{missing}");
        // A report without the field says nothing rather than guessing.
        assert_eq!(admin_app_check_note("default", Some(&json!({}))), None);
    }

    /// The one startup note names every token-consuming callable and says what a call to it
    /// gets in the active mode; nothing is printed when no callable consumes tokens.
    #[test]
    fn the_consumption_note_names_the_callables_and_the_mode() {
        let without = consume_app_check_note(&manifest(Some("enabled")), false)
            .expect("a note without App Check");
        assert!(without.contains("\"guarded\""), "{without}");
        assert!(without.contains("App Check is disabled"), "{without}");
        assert!(without.contains("no token is consumed"), "{without}");
        let with = consume_app_check_note(&manifest(Some("enabled")), true)
            .expect("a note with App Check");
        assert!(with.contains("\"guarded\""), "{with}");
        assert!(with.contains("501"), "{with}");
        assert!(with.contains("APP_CHECK_REPLAY_UNSUPPORTED"), "{with}");
        assert_eq!(
            consume_app_check_note(&manifest(Some("disabled")), false),
            None
        );
        for consume in [None, Some("disabled"), Some("undetermined")] {
            assert_eq!(
                consume_app_check_note(&manifest(consume), true),
                None,
                "{consume:?}"
            );
        }
        let two = parse_manifest(&json!({"functions": [
            {"name": "b", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "enabled"}},
            {"name": "plain", "trigger": {"type": "http", "callable": false, "consumeAppCheckToken": "enabled"}},
            {"name": "a", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "enabled"}},
        ]}))
        .expect("the fixture manifest parses");
        let note = consume_app_check_note(&two, false).expect("a note");
        assert!(note.contains("\"b\", \"a\""), "{note}");
        assert!(
            !note.contains("plain"),
            "an onRequest function is not a callable: {note}"
        );
    }

    /// Without App Check a configured manifest still cannot hide consumption from the proxy
    /// (review M1): an explicit value that contradicts the code is served as consuming with a
    /// warning, and an omitted (or `undetermined`) value takes what the code declares.
    #[test]
    fn without_app_check_a_manifest_that_contradicts_the_code_is_served_as_consuming() {
        use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
        let served =
            |m: &fireemu_core_functions::manifest::FunctionManifest| match m.functions[0].trigger {
                Trigger::Http {
                    consume_app_check_token,
                    ..
                } => consume_app_check_token,
                _ => panic!("the fixture is an HTTP function"),
            };
        for (configured, discovered, expected, warns) in [
            (None, "enabled", ConsumeAppCheckToken::Enabled, false),
            (None, "disabled", ConsumeAppCheckToken::Disabled, false),
            (
                None,
                "undetermined",
                ConsumeAppCheckToken::Undetermined,
                false,
            ),
            (
                Some("disabled"),
                "enabled",
                ConsumeAppCheckToken::Enabled,
                true,
            ),
            (
                Some("disabled"),
                "undetermined",
                ConsumeAppCheckToken::Enabled,
                true,
            ),
            (
                Some("enabled"),
                "disabled",
                ConsumeAppCheckToken::Enabled,
                true,
            ),
            (
                Some("undetermined"),
                "disabled",
                ConsumeAppCheckToken::Disabled,
                false,
            ),
            (
                Some("disabled"),
                "disabled",
                ConsumeAppCheckToken::Disabled,
                false,
            ),
            (
                Some("enabled"),
                "enabled",
                ConsumeAppCheckToken::Enabled,
                false,
            ),
        ] {
            let mut serving = manifest(configured);
            let warnings =
                reconcile_consumption_without_app_check(&mut serving, &manifest(Some(discovered)));
            let case = format!("configured={configured:?} discovered={discovered}");
            assert_eq!(served(&serving), expected, "{case}");
            assert_eq!(warnings.len(), usize::from(warns), "{case}: {warnings:?}");
            if warns {
                assert!(warnings[0].contains("\"guarded\""), "{warnings:?}");
                assert!(warnings[0].contains("X-Firebase-AppCheck"), "{warnings:?}");
            }
        }
        // A function the code does not declare as a callable is left alone.
        let mut serving = manifest(Some("disabled"));
        let on_request = parse_manifest(&json!({"functions": [
            {"name": "guarded", "trigger": {"type": "http", "callable": false, "consumeAppCheckToken": "enabled"}},
        ]}))
        .expect("the fixture manifest parses");
        assert!(reconcile_consumption_without_app_check(&mut serving, &on_request).is_empty());
        assert_eq!(served(&serving), ConsumeAppCheckToken::Disabled);
    }

    /// With App Check a configured onRequest route can never be marked as fronting a consuming
    /// callable (startup refuses that manifest), so whatever it wrote is cleared; callables keep
    /// their value.
    #[test]
    fn with_app_check_configured_on_request_routes_are_cleared() {
        use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
        let mut m = parse_manifest(&json!({"functions": [
            {"name": "route", "trigger": {"type": "http", "callable": false, "consumeAppCheckToken": "enabled"}},
            {"name": "call", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "enabled"}},
        ]}))
        .expect("the fixture manifest parses");
        clear_on_request_consumption(&mut m);
        let values: Vec<ConsumeAppCheckToken> = m
            .functions
            .iter()
            .map(|f| match f.trigger {
                Trigger::Http {
                    consume_app_check_token,
                    ..
                } => consume_app_check_token,
                _ => panic!("HTTP fixtures"),
            })
            .collect();
        assert_eq!(
            values,
            vec![
                ConsumeAppCheckToken::Undetermined,
                ConsumeAppCheckToken::Enabled
            ]
        );
    }

    /// Review 2 M1: a configured manifest that calls a code-level callable an onRequest function
    /// keeps its routing, but when that callable consumes tokens or could not be observed, the
    /// route is marked `Enabled` so the proxy removes the token, with a warning. Any other
    /// onRequest route is marked `Undetermined`, which the proxy ignores, whatever the manifest
    /// wrote.
    #[test]
    fn without_app_check_an_on_request_route_for_a_consuming_callable_is_marked() {
        use fireemu_core_functions::manifest::{ConsumeAppCheckToken, Trigger};
        let on_request = |consume: Option<&str>| {
            let mut trigger = json!({"type": "http", "callable": false});
            if let Some(consume) = consume {
                trigger["consumeAppCheckToken"] = json!(consume);
            }
            parse_manifest(&json!({"functions": [{"name": "guarded", "trigger": trigger}]}))
                .expect("the fixture manifest parses")
        };
        let served =
            |m: &fireemu_core_functions::manifest::FunctionManifest| match m.functions[0].trigger {
                Trigger::Http {
                    callable: false,
                    consume_app_check_token,
                    ..
                } => consume_app_check_token,
                _ => panic!("the route stays onRequest"),
            };
        for (configured, code, expected, warns) in [
            (
                None,
                manifest(Some("enabled")),
                ConsumeAppCheckToken::Enabled,
                true,
            ),
            (
                None,
                manifest(Some("undetermined")),
                ConsumeAppCheckToken::Enabled,
                true,
            ),
            (
                Some("disabled"),
                manifest(Some("enabled")),
                ConsumeAppCheckToken::Enabled,
                true,
            ),
            (
                None,
                manifest(Some("disabled")),
                ConsumeAppCheckToken::Undetermined,
                false,
            ),
            (
                Some("enabled"),
                manifest(Some("disabled")),
                ConsumeAppCheckToken::Undetermined,
                false,
            ),
            (
                Some("enabled"),
                on_request(None),
                ConsumeAppCheckToken::Undetermined,
                false,
            ),
            (
                Some("enabled"),
                parse_manifest(&json!({"functions": []})).unwrap(),
                ConsumeAppCheckToken::Undetermined,
                false,
            ),
        ] {
            let mut serving = on_request(configured);
            let warnings = reconcile_consumption_without_app_check(&mut serving, &code);
            let case = format!(
                "configured={configured:?} code={:?}",
                code.functions.first().map(|f| &f.trigger)
            );
            assert_eq!(served(&serving), expected, "{case}");
            assert_eq!(warnings.len(), usize::from(warns), "{case}: {warnings:?}");
            if warns {
                assert!(warnings[0].contains("onRequest"), "{warnings:?}");
                assert!(warnings[0].contains("X-Firebase-AppCheck"), "{warnings:?}");
            }
        }
    }

    /// Without App Check, an undetermined callable is named too, and an enforcing one is said to
    /// answer 401 (review S3).
    #[test]
    fn the_note_without_app_check_names_undetermined_and_enforcing_callables() {
        let m = parse_manifest(&json!({"functions": [
            {"name": "open", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "enabled"}},
            {"name": "unknown", "trigger": {"type": "http", "callable": true}},
            {"name": "strict", "trigger": {"type": "http", "callable": true, "enforceAppCheck": true, "consumeAppCheckToken": "enabled"}},
            {"name": "plain", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "disabled"}},
        ]}))
        .expect("the fixture manifest parses");
        let note = consume_app_check_note(&m, false).expect("a note");
        assert!(note.contains("\"open\", \"unknown\", \"strict\""), "{note}");
        assert!(!note.contains("plain"), "{note}");
        assert!(note.contains("401"), "{note}");
        assert!(note.contains("enforceAppCheck: \"strict\""), "{note}");
        let open_only = parse_manifest(&json!({"functions": [
            {"name": "open", "trigger": {"type": "http", "callable": true, "consumeAppCheckToken": "enabled"}},
        ]}))
        .expect("the fixture manifest parses");
        let note = consume_app_check_note(&open_only, false).expect("a note");
        assert!(!note.contains("401"), "{note}");
        // With App Check an undetermined callable fails startup instead, so it is not named.
        let with = consume_app_check_note(&m, true).expect("a note");
        assert!(!with.contains("unknown"), "{with}");
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

    /// The runner picks an export by name from its own discovery and serves it whatever trigger
    /// the manifest gave it. A real `onCall` written as a task queue or a blocking function would
    /// reach the callable wrapper without passing the callable trust boundary (the wrapper decodes
    /// the credentials and the auth-override fields of the request without verifying them), so
    /// the mismatch is as fatal as calling it an `onRequest` function. A real task queue, or a
    /// queue the code does not export, is not a callable and still loads.
    #[test]
    fn a_configured_manifest_cannot_present_a_callable_as_any_other_trigger() {
        let discovered = parse_manifest(&json!({
            "functions": [
                {"name": "guarded", "generation": 2, "trigger": {"type": "http", "callable": true}},
                {"name": "worker", "generation": 2, "trigger": {"type": "tasks"}}
            ]
        }))
        .expect("the fixture manifest parses");
        for (label, entry) in [
            ("a task queue", json!({"type": "tasks"})),
            (
                "a blocking function",
                json!({"type": "blockingAuth", "eventType": "beforeCreate"}),
            ),
            ("a Pub/Sub trigger", json!({"type": "pubsub", "topic": "t"})),
            (
                "a schedule",
                json!({"type": "schedule", "schedule": "every 5 minutes"}),
            ),
        ] {
            let configured = parse_manifest(&json!({
                "functions": [{"name": "guarded", "generation": 2, "trigger": entry}]
            }))
            .expect("the fixture manifest parses");
            let e = super::check_manifest_agrees_on_callables(&configured, &discovered)
                .expect_err(&format!("{label} may not carry a callable"));
            assert!(e.contains("guarded"), "{label}: {e}");
            assert!(e.contains("callable"), "{label}: {e}");
            assert!(e.contains("callable: true"), "{label}: {e}");
            assert!(e.contains("remove it from the manifest"), "{label}: {e}");
            assert!(e.contains("onTaskDispatched"), "{label}: {e}");
        }
        // A real task queue, and a queue name the code does not export, still load.
        let honest = parse_manifest(&json!({
            "functions": [
                {"name": "worker", "generation": 2, "trigger": {"type": "tasks"}},
                {"name": "ghostQueue", "generation": 2, "trigger": {"type": "tasks"}}
            ]
        }))
        .expect("the fixture manifest parses");
        super::check_manifest_agrees_on_callables(&honest, &discovered)
            .expect("a task queue that is not a callable loads");
    }

    /// Without App Check the strict profile still starts a manifest that serves a callable as a
    /// queue, and marks that entry so a task sent to it passes the callable's Bearer check. A real
    /// queue, a queue the code does not export and the callable's own entry are not marked.
    #[test]
    fn a_callable_served_as_a_queue_is_marked_for_the_strict_bearer_check() {
        let discovered = parse_manifest(&json!({
            "functions": [
                {"name": "guarded", "generation": 2, "trigger": {"type": "http", "callable": true}},
                {"name": "asRoute", "generation": 2, "trigger": {"type": "http", "callable": true}},
                {"name": "worker", "generation": 2, "trigger": {"type": "tasks"}},
                {"name": "page", "generation": 2, "trigger": {"type": "http", "callable": false}}
            ]
        }))
        .expect("the fixture manifest parses");
        let mut configured = parse_manifest(&json!({
            "functions": [
                {"name": "guarded", "generation": 2, "trigger": {"type": "tasks"}},
                {"name": "asRoute", "generation": 2, "trigger": {"type": "http", "callable": false}},
                {"name": "worker", "generation": 2, "trigger": {"type": "tasks"}},
                {"name": "page", "generation": 2, "trigger": {"type": "http", "callable": false}},
                {"name": "ghostQueue", "generation": 2, "trigger": {"type": "tasks"}},
                {"name": "onCreate", "generation": 2, "trigger": {"type": "pubsub", "topic": "t"}}
            ]
        }))
        .expect("the fixture manifest parses");
        assert_eq!(
            super::mark_strict_callable_ingress(&mut configured, &discovered),
            vec!["guarded".to_owned(), "asRoute".to_owned()]
        );
        let marked: Vec<_> = configured
            .functions
            .iter()
            .map(|f| (f.name.as_str(), f.platform_options.strict_callable_ingress))
            .collect();
        assert_eq!(
            marked,
            [
                ("guarded", true),
                ("asRoute", true),
                ("worker", false),
                ("page", false),
                ("ghostQueue", false),
                ("onCreate", false)
            ]
        );
        let mut honest_callable = parse_manifest(&json!({
            "functions": [{"name": "guarded", "generation": 2, "trigger": {"type": "http", "callable": true}}]
        }))
        .expect("the fixture manifest parses");
        assert!(super::mark_strict_callable_ingress(&mut honest_callable, &discovered).is_empty());
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

    /// A declared secret with no `.secret.local` value is named once, with the functions that
    /// declare it; one that has a value, and a function that declares none, are not.
    #[test]
    fn a_second_gen_database_trigger_outside_the_local_location_is_warned_about() {
        let manifest = parse_manifest(&json!({"functions":[
            {"name":"euWritten","generation":2,"region":"europe-west1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/a"}},
            {"name":"usWritten","generation":2,"region":"us-central1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/a"}},
            {"name":"defaultRegion","generation":2,"trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/a"}},
            {"name":"firstGen","generation":1,"region":"europe-west1","trigger":{
                "type":"database","eventType":"google.firebase.database.ref.v1.written","instance":"*","ref":"/a"}},
            {"name":"euDocument","generation":2,"region":"europe-west1","trigger":{
                "type":"firestore","eventType":"google.cloud.firestore.document.v1.written","document":"a/{id}"}}
        ]}))
        .unwrap();
        let lines = super::database_region_warnings(&manifest, "default");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("functions[default]: euWritten "),
            "{lines:?}"
        );
        assert!(lines[0].contains("in europe-west1"), "{lines:?}");
        assert!(lines[0].contains("will not trigger"), "{lines:?}");
    }

    #[test]
    fn a_declared_secret_without_a_local_value_is_warned_about() {
        let manifest = parse_manifest(&json!({"functions": [
            {"name": "a", "trigger": {"type": "http", "callable": false},
             "platformOptions": {"secrets": ["API_KEY", "HAS_VALUE"]}},
            {"name": "b", "trigger": {"type": "http", "callable": false},
             "platformOptions": {"secrets": ["API_KEY"]}},
            {"name": "c", "trigger": {"type": "http", "callable": false}}
        ]}))
        .unwrap();
        let local = vec![("HAS_VALUE".to_owned(), "x".to_owned())];
        let lines = super::missing_secret_warnings(&manifest, &local, "default");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("secret API_KEY (declared by a, b)"),
            "{lines:?}"
        );
        assert!(!lines[0].contains("HAS_VALUE"));
        assert!(
            super::missing_secret_warnings(
                &manifest,
                &[
                    ("API_KEY".to_owned(), String::new()),
                    ("HAS_VALUE".to_owned(), String::new()),
                ],
                "default"
            )
            .is_empty(),
            "an empty value is still a value"
        );
    }

    /// The default callable trust boundary needs a supported `firebase-functions`; it is found
    /// the way Node finds it, in the source directory or an ancestor.
    #[test]
    fn callable_trust_is_supported_only_for_the_instrumented_firebase_functions_majors() {
        let root = std::env::temp_dir().join(format!("fireemu-trust-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let source = root.join("functions");
        std::fs::create_dir_all(&source).unwrap();
        let install = |dir: &std::path::Path, version: &str| {
            let package = dir.join("node_modules/firebase-functions");
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(
                package.join("package.json"),
                format!(r#"{{"name":"firebase-functions","version":"{version}"}}"#),
            )
            .unwrap();
        };
        assert!(super::callable_trust_supported(&source)
            .unwrap_err()
            .contains("not installed"));
        for (version, ok) in [
            ("5.1.1", false),
            ("6.0.0", true),
            ("6.4.2", true),
            ("7.3.2", true),
            ("7.0.0-beta.1", true),
            ("8.0.0", false),
            ("not-a-version", false),
        ] {
            install(&source, version);
            assert_eq!(
                super::callable_trust_supported(&source).is_ok(),
                ok,
                "{version}"
            );
        }
        // An install above the source directory is found, as Node finds it.
        std::fs::remove_dir_all(source.join("node_modules")).unwrap();
        install(&root, "7.3.2");
        assert!(super::callable_trust_supported(&source).is_ok());
        // A nearer install shadows the farther one.
        install(&source, "5.1.1");
        assert!(super::callable_trust_supported(&source)
            .unwrap_err()
            .contains("5.1.1"));
        std::fs::write(
            source.join("node_modules/firebase-functions/package.json"),
            "{",
        )
        .unwrap();
        assert!(super::callable_trust_supported(&source)
            .unwrap_err()
            .contains("cannot read the version"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The refusal for a parameter nothing resolves: it names every such parameter with its
    /// type, says where a value goes, and only fires when the runner reports one missing.
    #[test]
    fn an_unresolved_parameter_refuses_the_codebase_and_names_it() {
        let report = json!({
            "missing": [{"name": "API_URL", "type": "string"}, {"name": "RETRIES", "type": "int"}],
            "defaulted": [{"name": "REGION_NAME", "type": "string"}]
        });
        let error = super::check_declared_params(
            Some(&report),
            "default",
            "/work/functions",
            "demo-app",
            Some("staging"),
        )
        .expect_err("two parameters have no value");
        assert!(error.contains("2 parameter(s)"), "{error}");
        assert!(error.contains("API_URL (string), RETRIES (int)"), "{error}");
        assert!(!error.contains("REGION_NAME"), "{error}");
        for place in [
            "/work/functions/.env",
            ".env.demo-app or .env.staging",
            "/work/functions/.env.local",
        ] {
            assert!(error.contains(place), "{place}: {error}");
        }
        let plain = super::check_declared_params(Some(&report), "default", "/w", "demo-app", None)
            .unwrap_err();
        assert!(plain.contains("/w/.env.demo-app or"), "{plain}");
        assert!(!plain.contains("staging"), "{plain}");
        for quiet in [
            None,
            Some(json!({})),
            Some(json!({"missing": []})),
            Some(json!({"missing": [], "defaulted": [{"name": "A", "type": "string"}]})),
        ] {
            assert!(
                super::check_declared_params(quiet.as_ref(), "default", "/w", "demo-app", None)
                    .is_ok(),
                "{quiet:?}"
            );
        }
    }

    /// An export that will never run is a `warning:` on standard error, never a quiet `note:`,
    /// whatever its trigger family, and the lines end with one summary.
    #[test]
    fn every_ignored_export_is_a_warning_with_a_summary() {
        let manifest = parse_manifest(&json!({
            "functions": [],
            "ignored": [
                {"name": "a", "region": "us-central1", "triggerType": "schedule",
                 "scope": "unsupported", "reason": "r1"},
                {"name": "b", "region": "us-central1", "triggerType": "unknown",
                 "scope": "unsupported", "reason": "r2"}
            ]
        }))
        .expect("parses");
        let lines = super::ignored_warnings(&manifest, super::UnservedTriggers::Refuse)
            .expect("unsupported exports are not fatal");
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(
            lines.iter().all(|l| l.starts_with("warning: ")),
            "{lines:?}"
        );
        assert!(lines[2].contains("2 export(s)"), "{lines:?}");
        let none = parse_manifest(&json!({"functions": [], "ignored": []})).unwrap();
        assert!(
            super::ignored_warnings(&none, super::UnservedTriggers::Refuse)
                .unwrap()
                .is_empty()
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
    fn the_python_runner_is_looked_for_in_its_own_directory_and_never_mistaken_for_the_node_one() {
        let root = synthetic_workspace("python");
        let exe = root.join("target/debug/fireemu");
        // Only the Node runner exists: the Python one is not found, and the Node one still is.
        assert_eq!(
            super::workspace_runner_from_for(&exe, "runner-python", "runner.py"),
            None
        );
        std::fs::create_dir_all(root.join("tools/runner-python")).unwrap();
        std::fs::write(root.join("tools/runner-python/runner.py"), "").unwrap();
        assert_eq!(
            super::workspace_runner_from_for(&exe, "runner-python", "runner.py").as_deref(),
            Some(root.join("tools/runner-python/runner.py").as_path())
        );
        assert_eq!(
            super::workspace_runner_from(&exe).as_deref(),
            Some(root.join("tools/runner-node/index.mjs").as_path())
        );
        // The candidates beside the binary name the directory and the script they were asked for.
        let candidates =
            super::runner_candidates_for("FIREEMU_NO_SUCH_RUNNER", "runner-python", "runner.py");
        assert!(!candidates.is_empty());
        assert!(
            candidates
                .iter()
                .all(|(_, path)| path.ends_with("runner-python/runner.py")),
            "{candidates:?}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_runner_names_the_override_variable_and_the_script() {
        let error = super::locate_runner_for(
            "FIREEMU_NO_SUCH_RUNNER",
            "runner-nowhere",
            "start.py",
            "the test runner",
        )
        .unwrap_err();
        assert!(
            error.starts_with("the test runner (runner-nowhere/start.py) was not found; tried "),
            "{error}"
        );
        assert!(
            error.contains("Set FIREEMU_NO_SUCH_RUNNER to a start.py, or reinstall"),
            "{error}"
        );
        let node = super::locate_runner_for(
            "FIREEMU_NO_SUCH_RUNNER",
            "runner-none",
            "index.mjs",
            "the bundled Node runner",
        )
        .unwrap_err();
        assert!(node.contains("to an index.mjs,"), "{node}");
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

    #[test]
    fn the_default_time_zone_goes_only_to_schedules_that_name_none() {
        use serde_json::json;
        let mut manifest = json!({"functions": [
            {"name": "a", "trigger": {"type": "schedule", "schedule": "0 9 * * *"}},
            {"name": "b", "trigger": {"type": "schedule", "schedule": "0 9 * * *", "timeZone": "UTC"}},
            {"name": "c", "trigger": {"type": "schedule", "schedule": "0 9 * * *", "timeZone": null}},
            {"name": "d", "trigger": {"type": "http"}},
            {"name": "e"},
        ]});
        super::apply_default_time_zone(&mut manifest, "Asia/Tokyo");
        let trigger = |i: usize| &manifest["functions"][i]["trigger"];
        assert_eq!(
            trigger(0)["timeZone"],
            "Asia/Tokyo",
            "a schedule without a zone"
        );
        assert_eq!(trigger(1)["timeZone"], "UTC", "an explicit zone wins");
        assert_eq!(
            trigger(2)["timeZone"],
            "Asia/Tokyo",
            "a null zone is no zone"
        );
        assert!(
            trigger(3).get("timeZone").is_none(),
            "an http trigger is untouched"
        );
        assert!(manifest["functions"][4].get("trigger").is_none());
        let mut without_functions = json!({"endpoints": {}});
        let before = without_functions.clone();
        super::apply_default_time_zone(&mut without_functions, "Asia/Tokyo");
        assert_eq!(without_functions, before);
    }

    #[test]
    fn a_configured_default_time_zone_moves_the_occurrences_of_a_schedule_that_names_none() {
        use fireemu_core_types::time::LogicalInstant;
        const MIDNIGHT_UTC: i64 = 1_791_158_400; // 2026-10-05T00:00:00Z
        let occurrence = |default: Option<&str>| {
            let mut manifest = json!({"functions": [
                {"name": "daily", "generation": 2, "trigger": {"type": "schedule", "schedule": "0 9 * * *"}},
                {"name": "pinned", "generation": 2, "trigger": {"type": "schedule", "schedule": "0 9 * * *", "timeZone": "UTC"}},
            ]});
            if let Some(zone) = default {
                super::apply_default_time_zone(&mut manifest, zone);
            }
            let manifest = parse_manifest(&manifest).unwrap();
            let after = LogicalInstant::from_unix_seconds(MIDNIGHT_UTC - 1);
            manifest
                .scheduled()
                .map(|(function, schedule, zone)| {
                    let zone = fireemu_adapter_functions::zone::resolve(zone).unwrap();
                    (
                        function.name.clone(),
                        schedule.next_after_in(after, &*zone).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let at = |seconds: i64| LogicalInstant::from_unix_seconds(MIDNIGHT_UTC + seconds);
        // 09:00 in Tokyo (UTC+9) is 00:00 UTC; 09:00 UTC is nine hours later.
        assert_eq!(
            occurrence(Some("Asia/Tokyo")),
            [
                ("daily".to_owned(), at(0)),
                ("pinned".to_owned(), at(9 * 3600))
            ],
            "the configured default moves a schedule that names no zone and leaves a named one",
        );
        assert_eq!(
            occurrence(None),
            [
                ("daily".to_owned(), at(9 * 3600)),
                ("pinned".to_owned(), at(9 * 3600))
            ],
            "without a configured default a v2 schedule that names no zone runs in UTC (production's v2 default)",
        );
    }

    #[test]
    fn a_capacity_refusal_reaches_the_control_api_as_one() {
        use fireemu_adapter_functions::runtime::ScheduleRunError;
        use fireemu_adapter_http::control::RunScheduleError;
        assert_eq!(
            super::run_schedule_error(ScheduleRunError::Capacity("full".to_owned())),
            RunScheduleError::Capacity("full".to_owned())
        );
        assert_eq!(
            super::run_schedule_error(ScheduleRunError::Refused("busy".to_owned())),
            RunScheduleError::Refused("busy".to_owned())
        );
    }
}
