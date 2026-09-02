//! Quint Connect driver for the production storage generation allocator.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    ImportedObject, MetadataPatch, NewMetadata, Precondition, StorageState,
};
use fireemu_core_types::time::LogicalInstant;
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

/// Actions exercised through the production store.
pub const MODELED_ACTIONS: [&str; 6] = [
    "PutData",
    "PatchMetadata",
    "Delete",
    "CaptureSnapshot",
    "RestoreSnapshot",
    "ImportData",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

const MAX_GENERATION: u64 = 3;
const MAX_METAGENERATION: u64 = 3;
const IMPORTED_GENERATION: u64 = 2;

/// Observable storage identity state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageGenerationState {
    /// Whether the bounded object currently exists.
    pub exists: bool,
    /// Live production generation, or zero when absent.
    pub generation: u64,
    /// Live production metageneration, or zero when absent.
    pub metageneration: u64,
    /// Production allocator high-water mark.
    pub high_water: u64,
    /// Identities returned by successful production writes and imports.
    pub issued: BTreeSet<u64>,
}

/// Test-only perturbation after production state extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only object existence.
    Exists,
    /// Change only the live generation.
    Generation,
    /// Change only the live metageneration.
    Metageneration,
    /// Change only the allocator high-water mark.
    HighWater,
    /// Change only the observed issued set.
    Issued,
}

impl ProjectionFault {
    /// Returns the serialized field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::Generation => "generation",
            Self::Metageneration => "metageneration",
            Self::HighWater => "highWater",
            Self::Issued => "issued",
        }
    }
}

/// Stateful adapter around one real `StorageState`.
pub struct StorageGenerationDriver {
    store: StorageState,
    snapshot: Option<StorageState>,
    issued: BTreeSet<u64>,
    bucket: BucketName,
    object: ObjectName,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for StorageGenerationDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageGenerationDriver {
    /// Builds an uninitialized bounded store driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: StorageState::new(7),
            snapshot: None,
            issued: BTreeSet::new(),
            bucket: BucketName::try_new("demo-app.appspot.com")
                .expect("fixed verification bucket is valid"),
            object: ObjectName::try_new("object.txt").expect("fixed verification object is valid"),
            projection_fault: None,
            action_recorder: None,
        }
    }

    /// Records every successfully dispatched action.
    #[must_use]
    pub fn with_action_recorder(mut self, recorder: Arc<Mutex<BTreeSet<String>>>) -> Self {
        self.action_recorder = Some(recorder);
        self
    }

    /// Applies one projection-only fault.
    #[must_use]
    pub fn with_projection_fault(mut self, fault: ProjectionFault) -> Self {
        self.projection_fault = Some(fault);
        self
    }

    /// Changes the projection-only fault without mutating the store.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Resets the real store and harness-only issued history.
    pub fn init(&mut self) -> Result {
        self.store = StorageState::new(7);
        self.snapshot = None;
        self.issued.clear();
        Ok(())
    }

    /// Replaces object data through `StorageState::put`.
    pub fn put_data(&mut self) -> Result {
        if self.high_water()? >= MAX_GENERATION {
            return Err(invalid_data("bounded generation space is exhausted"));
        }
        let metadata = self
            .store
            .put(
                &self.bucket,
                &self.object,
                b"data".to_vec(),
                NewMetadata::default(),
                Precondition::default(),
                LogicalInstant::UNIX_EPOCH,
            )
            .map_err(|error| invalid_data(&format!("put failed: {error}")))?;
        self.issued.insert(metadata.generation);
        self.record_action("PutData")
    }

    /// Updates metadata through the production patch API.
    pub fn patch_metadata(&mut self) -> Result {
        let current = self
            .store
            .get(&self.bucket, &self.object)
            .ok_or_else(|| invalid_data("metadata patch requires a live object"))?;
        if current.metageneration >= MAX_METAGENERATION {
            return Err(invalid_data("bounded metageneration space is exhausted"));
        }
        self.store
            .update_metadata(
                &self.bucket,
                &self.object,
                &MetadataPatch::default(),
                Precondition::default(),
                LogicalInstant::UNIX_EPOCH,
            )
            .map_err(|error| invalid_data(&format!("metadata patch failed: {error}")))?;
        self.record_action("PatchMetadata")
    }

    /// Deletes the current object without rewinding the allocator.
    pub fn delete(&mut self) -> Result {
        self.store
            .delete(&self.bucket, &self.object, Precondition::default())
            .map_err(|error| invalid_data(&format!("delete failed: {error}")))?;
        self.record_action("Delete")
    }

    /// Captures the real bucket snapshot once per bounded trace.
    pub fn capture_snapshot(&mut self) -> Result {
        if self.snapshot.is_some() {
            return Err(invalid_data("snapshot is already captured"));
        }
        self.snapshot = Some(self.store.capture_buckets(|_| true));
        self.record_action("CaptureSnapshot")
    }

    /// Restores visible production state while preserving global allocators.
    pub fn restore_snapshot(&mut self) -> Result {
        let snapshot = self
            .snapshot
            .as_ref()
            .ok_or_else(|| invalid_data("restore requires a captured snapshot"))?;
        self.store.restore_buckets(|_| true, snapshot);
        self.record_action("RestoreSnapshot")
    }

    /// Installs a bounded imported generation through `insert_imported`.
    pub fn import_data(&mut self) -> Result {
        if self.high_water()? >= IMPORTED_GENERATION {
            return Err(invalid_data(
                "bounded imported generation is not ahead of high-water",
            ));
        }
        let object = ImportedObject {
            bucket: self.bucket.clone(),
            name: self.object.clone(),
            generation: IMPORTED_GENERATION,
            metageneration: 2,
            content_type: "application/octet-stream".to_owned(),
            content_disposition: None,
            content_encoding: None,
            content_language: None,
            cache_control: None,
            custom: BTreeMap::default(),
            custom_defined: false,
            time_created: LogicalInstant::UNIX_EPOCH,
            updated: LogicalInstant::UNIX_EPOCH,
            download_tokens: Vec::new(),
            md5: None,
            crc32c: None,
            size: None,
        };
        let metadata = self
            .store
            .insert_imported(object, b"imported".to_vec())
            .map_err(|error| invalid_data(&format!("import failed: {error}")))?;
        self.issued.insert(metadata.generation);
        self.record_action("ImportData")
    }

    /// Projects live identity fields from the real store and result-derived issued IDs.
    pub fn project(&self) -> Result<StorageGenerationState> {
        let live = self.store.get(&self.bucket, &self.object);
        let mut projected = StorageGenerationState {
            exists: live.is_some(),
            generation: live.map_or(0, |metadata| metadata.generation),
            metageneration: live.map_or(0, |metadata| metadata.metageneration),
            high_water: self.high_water()?,
            issued: self.issued.clone(),
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::Exists) => projected.exists = !projected.exists,
            Some(ProjectionFault::Generation) => {
                projected.generation = projected.generation.saturating_add(1);
            }
            Some(ProjectionFault::Metageneration) => {
                projected.metageneration = projected.metageneration.saturating_add(1);
            }
            Some(ProjectionFault::HighWater) => {
                projected.high_water = projected.high_water.saturating_add(1);
            }
            Some(ProjectionFault::Issued) => {
                if !projected.issued.remove(&1) {
                    projected.issued.insert(1);
                }
            }
        }
        Ok(projected)
    }

    fn high_water(&self) -> Result<u64> {
        self.store
            .next_generation_preview()
            .map(|next| next - 1)
            .map_err(|error| invalid_data(&format!("cannot observe generation allocator: {error}")))
    }

    fn record_action(&self, action: &str) -> Result {
        if let Some(recorder) = &self.action_recorder {
            recorder
                .lock()
                .map_err(|_| invalid_data("action recorder lock is poisoned"))?
                .insert(action.to_owned());
        }
        Ok(())
    }
}

impl State<StorageGenerationDriver> for StorageGenerationState {
    fn from_driver(driver: &StorageGenerationDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for StorageGenerationDriver {
    type State = StorageGenerationState;

    fn config() -> Config {
        Config {
            state: &["StorageGenerationScenarios::StorageGeneration::observable"],
            nondet: &["StorageGenerationScenarios::StorageGeneration::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            PutData => self.put_data()?,
            PatchMetadata => self.patch_metadata()?,
            Delete => self.delete()?,
            CaptureSnapshot => self.capture_snapshot()?,
            RestoreSnapshot => self.restore_snapshot()?,
            ImportData => self.import_data()?,
        })
    }
}

/// Driver configured for generated traces.
pub struct StorageGenerationConnectDriver {
    inner: StorageGenerationDriver,
}

impl Default for StorageGenerationConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageGenerationConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: StorageGenerationDriver::new(),
        }
    }
}

impl State<StorageGenerationConnectDriver> for StorageGenerationState {
    fn from_driver(driver: &StorageGenerationConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for StorageGenerationConnectDriver {
    type State = StorageGenerationState;

    fn config() -> Config {
        Config {
            state: &["StorageGenerationConnect::StorageGeneration::observable"],
            nondet: &["StorageGenerationConnect::StorageGeneration::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::InvalidData, message))
}
