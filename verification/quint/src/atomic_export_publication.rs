//! Quint Connect driver for the real atomic export publication capability.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use fireemu_export_publication::{CompletePublicationStage, PublicationStage};
use quint_connect::{switch, Config, Driver, Result, State, Step};
use serde::Deserialize;

#[cfg(unix)]
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

#[cfg(unix)]
use trusted_temp::TrustedTempDir;

/// Actions exercised through the production publication capability.
pub const MODELED_ACTIONS: [&str; 7] = [
    "Create",
    "Write",
    "Complete",
    "Swap",
    "SwapStage",
    "Refuse",
    "Publish",
];

/// Reproducible seeds used by generated conformance campaigns.
pub const GENERATED_TRACE_SEEDS: [&str; 4] = ["0x1", "0x2", "0x3", "0x4"];

static NEXT_ROOT_ID: AtomicU64 = AtomicU64::new(1);

/// Filesystem-derived publication state compared after every action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AtomicExportPublicationState {
    /// Capability typestate confirmed against the owned stage directory.
    pub stage_state: String,
    /// Filesystem-derived relationship between the stage pathname and its captured identity.
    pub stage_identity: String,
    /// Whether the captured target has been replaced by the modeled external actor.
    pub target_identity: String,
    /// Artifact marker currently visible at the public target.
    pub public_artifact: String,
    /// Whether the real stage directory is owner-only, or true when absent.
    pub stage_private: bool,
    /// Whether the real public directory and marker are owner-only.
    pub public_private: bool,
    /// Stable classification of the latest capability result.
    pub last_result: String,
}

/// Test-only perturbation after reading production filesystem state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFault {
    /// Change only the stage state.
    StageState,
    /// Change only the stage identity classification.
    StageIdentity,
    /// Change only target identity classification.
    TargetIdentity,
    /// Change only the public artifact marker.
    PublicArtifact,
    /// Change only stage privacy.
    StagePrivate,
    /// Change only public privacy.
    PublicPrivate,
    /// Change only the latest result.
    LastResult,
}

impl ProjectionFault {
    /// Returns the serialized field affected by this fault.
    #[must_use]
    pub const fn field_name(self) -> &'static str {
        match self {
            Self::StageState => "stageState",
            Self::StageIdentity => "stageIdentity",
            Self::TargetIdentity => "targetIdentity",
            Self::PublicArtifact => "publicArtifact",
            Self::StagePrivate => "stagePrivate",
            Self::PublicPrivate => "publicPrivate",
            Self::LastResult => "lastResult",
        }
    }
}

enum Stage {
    Absent,
    Created(PublicationStage),
    Partial(PublicationStage),
    Complete(CompletePublicationStage),
}

/// Stateful adapter whose filesystem writes remain under one owned temporary root.
pub struct AtomicExportPublicationDriver {
    root: OwnedRoot,
    target: PathBuf,
    displaced: PathBuf,
    displaced_stage_count: u64,
    initial_identity: FileIdentity,
    captured_stage_identity: Option<FileIdentity>,
    retained_stage_path: Option<PathBuf>,
    stage: Stage,
    target_changed: bool,
    stage_captured_changed_target: bool,
    last_result: String,
    projection_fault: Option<ProjectionFault>,
    action_recorder: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl Default for AtomicExportPublicationDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicExportPublicationDriver {
    /// Builds a fresh driver under an owned temporary root.
    #[must_use]
    pub fn new() -> Self {
        let (root, target, displaced, initial_identity) = fresh_filesystem()
            .unwrap_or_else(|error| panic!("cannot create bounded publication root: {error}"));
        Self {
            root,
            target,
            displaced,
            displaced_stage_count: 0,
            initial_identity,
            captured_stage_identity: None,
            retained_stage_path: None,
            stage: Stage::Absent,
            target_changed: false,
            stage_captured_changed_target: false,
            last_result: "None".to_owned(),
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

    /// Changes the projection-only fault without mutating the filesystem.
    pub fn set_projection_fault(&mut self, fault: ProjectionFault) {
        self.projection_fault = Some(fault);
    }

    /// Replaces the entire owned filesystem root.
    pub fn init(&mut self) -> Result {
        let (root, target, displaced, initial_identity) = fresh_filesystem()?;
        self.root = root;
        self.target = target;
        self.displaced = displaced;
        self.displaced_stage_count = 0;
        self.initial_identity = initial_identity;
        self.stage = Stage::Absent;
        self.captured_stage_identity = None;
        self.retained_stage_path = None;
        self.target_changed = false;
        self.stage_captured_changed_target = false;
        "None".clone_into(&mut self.last_result);
        Ok(())
    }

    /// Creates a real private publication stage.
    pub fn create(&mut self) -> Result {
        if !matches!(self.stage, Stage::Absent) {
            return Err(invalid_data("publication stage already exists"));
        }
        let stage = PublicationStage::create(&self.target, |_| Ok(()))
            .map_err(|error| invalid_data(&error))?;
        self.captured_stage_identity = Some(file_identity(stage.root())?);
        self.retained_stage_path = None;
        self.stage = Stage::Created(stage);
        self.stage_captured_changed_target = self.target_changed;
        "None".clone_into(&mut self.last_result);
        self.record_action("Create")
    }

    /// Writes the partial marker inside the real owned stage.
    pub fn write(&mut self) -> Result {
        let current = take_stage(&mut self.stage);
        let Stage::Created(stage) = current else {
            self.stage = current;
            return Err(invalid_data("write requires a newly created stage"));
        };
        write_private_file(&stage.root().join("artifact"), b"partial")?;
        self.stage = Stage::Partial(stage);
        self.record_action("Write")
    }

    /// Writes the completion marker and enters the production publishable typestate.
    pub fn complete(&mut self) -> Result {
        let current = take_stage(&mut self.stage);
        let Stage::Partial(stage) = current else {
            self.stage = current;
            return Err(invalid_data("completion requires a partial stage"));
        };
        write_private_file(&stage.root().join("artifact"), b"new")?;
        write_private_file(&stage.root().join("complete"), b"complete")?;
        self.stage = Stage::Complete(stage.complete());
        self.record_action("Complete")
    }

    /// Replaces the target inside the owned root to simulate the real identity race.
    pub fn swap(&mut self) -> Result {
        if matches!(self.stage, Stage::Absent) || self.target_changed {
            return Err(invalid_data("target swap is disabled"));
        }
        let public_artifact = std::fs::read(self.target.join("artifact"))
            .map_err(|error| invalid_data(&format!("cannot capture public artifact: {error}")))?;
        std::fs::rename(&self.target, &self.displaced)
            .map_err(|error| invalid_data(&format!("cannot displace target: {error}")))?;
        create_private_dir(&self.target)?;
        write_private_file(&self.target.join("artifact"), &public_artifact)?;
        self.target_changed = true;
        self.record_action("Swap")
    }

    /// Replaces the stage pathname while retaining the real capability's captured identity.
    pub fn swap_stage(&mut self) -> Result {
        let Some(stage_root) = stage_root(&self.stage).map(Path::to_owned) else {
            return Err(invalid_data("stage swap requires a stage"));
        };
        if self.stage_identity_label()? != "Owned" {
            return Err(invalid_data("stage swap is disabled"));
        }
        let displaced_stage = self
            .root
            .path
            .join(format!("displaced-stage-{}", self.displaced_stage_count));
        std::fs::rename(&stage_root, &displaced_stage)
            .map_err(|error| invalid_data(&format!("cannot displace owned stage: {error}")))?;
        self.displaced_stage_count += 1;
        create_private_dir(&stage_root)?;
        self.record_action("SwapStage")
    }

    /// Drops an ordinary stage or observes real identity refusal for a completed stage.
    pub fn refuse(&mut self) -> Result {
        let stage_root = stage_root(&self.stage).map(Path::to_owned);
        let stage_changed = self.stage_identity_label()? == "Changed";
        let stage = take_stage(&mut self.stage);
        match stage {
            Stage::Absent => return Err(invalid_data("refusal requires a stage")),
            Stage::Complete(complete) if stage_changed => {
                if complete.publish().is_ok() {
                    return Err(invalid_data("changed stage was unexpectedly published"));
                }
            }
            Stage::Complete(complete)
                if self.target_changed && !self.stage_captured_changed_target =>
            {
                if complete.publish().is_ok() {
                    return Err(invalid_data("changed target was unexpectedly published"));
                }
            }
            Stage::Created(stage) | Stage::Partial(stage) => drop(stage),
            Stage::Complete(complete) => drop(complete),
        }
        if stage_changed {
            self.retained_stage_path = stage_root;
        } else {
            self.retained_stage_path = None;
            self.captured_stage_identity = None;
        }
        "Refused".clone_into(&mut self.last_result);
        self.record_action("Refuse")
    }

    /// Publishes only a complete stage against the unchanged captured target.
    pub fn publish(&mut self) -> Result {
        if self.target_changed {
            return Err(invalid_data("publication target identity changed"));
        }
        if self.stage_identity_label()? != "Owned" {
            return Err(invalid_data("publication stage identity changed"));
        }
        let current = take_stage(&mut self.stage);
        let Stage::Complete(complete) = current else {
            self.stage = current;
            return Err(invalid_data("publish requires a complete stage"));
        };
        complete.publish().map_err(|error| invalid_data(&error))?;
        self.initial_identity = file_identity(&self.target)?;
        self.captured_stage_identity = None;
        "Published".clone_into(&mut self.last_result);
        self.record_action("Publish")
    }

    /// Projects only fixed paths below the driver-owned root.
    pub fn project(&self) -> Result<AtomicExportPublicationState> {
        let (stage_state, live_stage_root) = match &self.stage {
            Stage::Absent => ("Absent", None),
            Stage::Created(stage) => ("Created", Some(stage.root())),
            Stage::Partial(stage) => ("Partial", Some(stage.root())),
            Stage::Complete(stage) => ("Complete", Some(stage.root())),
        };
        let observable_stage_root = live_stage_root.or(self.retained_stage_path.as_deref());
        let target_identity = if file_identity(&self.target)? == self.initial_identity {
            "Original"
        } else {
            "Changed"
        };
        let mut projected = AtomicExportPublicationState {
            stage_state: stage_state.to_owned(),
            stage_identity: self.stage_identity_label()?.to_owned(),
            target_identity: target_identity.to_owned(),
            public_artifact: read_artifact(&self.target)?,
            stage_private: observable_stage_root.map_or(Ok(true), is_private_directory)?,
            public_private: is_private_directory(&self.target)?
                && is_private_file(&self.target.join("artifact"))?,
            last_result: self.last_result.clone(),
        };
        match self.projection_fault {
            None => {}
            Some(ProjectionFault::StageState) => "Faulted".clone_into(&mut projected.stage_state),
            Some(ProjectionFault::StageIdentity) => {
                "Faulted".clone_into(&mut projected.stage_identity);
            }
            Some(ProjectionFault::TargetIdentity) => {
                "Faulted".clone_into(&mut projected.target_identity);
            }
            Some(ProjectionFault::PublicArtifact) => {
                "Partial".clone_into(&mut projected.public_artifact);
            }
            Some(ProjectionFault::StagePrivate) => {
                projected.stage_private = !projected.stage_private;
            }
            Some(ProjectionFault::PublicPrivate) => {
                projected.public_private = !projected.public_private;
            }
            Some(ProjectionFault::LastResult) => {
                "Faulted".clone_into(&mut projected.last_result);
            }
        }
        Ok(projected)
    }

    fn stage_identity_label(&self) -> Result<&'static str> {
        let Some(stage_root) = stage_root(&self.stage).or(self.retained_stage_path.as_deref())
        else {
            return Ok("Absent");
        };
        let expected = self
            .captured_stage_identity
            .ok_or_else(|| invalid_data("live stage has no captured identity"))?;
        Ok(if file_identity(stage_root)? == expected {
            "Owned"
        } else {
            "Changed"
        })
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

impl State<AtomicExportPublicationDriver> for AtomicExportPublicationState {
    fn from_driver(driver: &AtomicExportPublicationDriver) -> Result<Self> {
        driver.project()
    }
}

impl Driver for AtomicExportPublicationDriver {
    type State = AtomicExportPublicationState;

    fn config() -> Config {
        Config {
            state: &["AtomicExportPublicationScenarios::AtomicExportPublication::observable"],
            nondet: &["AtomicExportPublicationScenarios::AtomicExportPublication::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        switch!(step {
            init => self.init()?,
            Create => self.create()?,
            Write => self.write()?,
            Complete => self.complete()?,
            Swap => self.swap()?,
            SwapStage => self.swap_stage()?,
            Refuse => self.refuse()?,
            Publish => self.publish()?,
        })
    }
}

/// Driver configured for generated traces.
pub struct AtomicExportPublicationConnectDriver {
    inner: AtomicExportPublicationDriver,
}

impl Default for AtomicExportPublicationConnectDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicExportPublicationConnectDriver {
    /// Builds a fresh generated-trace driver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: AtomicExportPublicationDriver::new(),
        }
    }
}

impl State<AtomicExportPublicationConnectDriver> for AtomicExportPublicationState {
    fn from_driver(driver: &AtomicExportPublicationConnectDriver) -> Result<Self> {
        driver.inner.project()
    }
}

impl Driver for AtomicExportPublicationConnectDriver {
    type State = AtomicExportPublicationState;

    fn config() -> Config {
        Config {
            state: &["AtomicExportPublicationConnect::AtomicExportPublication::observable"],
            nondet: &["AtomicExportPublicationConnect::AtomicExportPublication::actionTaken"],
        }
    }

    fn step(&mut self, step: &Step) -> Result {
        self.inner.step(step)
    }
}

fn take_stage(stage: &mut Stage) -> Stage {
    std::mem::replace(stage, Stage::Absent)
}

fn stage_root(stage: &Stage) -> Option<&Path> {
    match stage {
        Stage::Absent => None,
        Stage::Created(stage) | Stage::Partial(stage) => Some(stage.root()),
        Stage::Complete(stage) => Some(stage.root()),
    }
}

struct OwnedRoot {
    path: PathBuf,
    #[cfg(not(unix))]
    identity: FileIdentity,
    #[cfg(unix)]
    _trusted_namespace: TrustedTempDir,
}

impl Drop for OwnedRoot {
    fn drop(&mut self) {
        #[cfg(not(unix))]
        if file_identity(&self.path).is_ok_and(|identity| identity == self.identity) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

fn fresh_filesystem() -> Result<(OwnedRoot, PathBuf, PathBuf, FileIdentity)> {
    let id = NEXT_ROOT_ID.fetch_add(1, Ordering::Relaxed);
    #[cfg(unix)]
    let trusted_namespace = TrustedTempDir::new("quint-export-publication");
    #[cfg(unix)]
    let path = trusted_namespace.path().join(format!("filesystem-{id}"));
    #[cfg(not(unix))]
    let base = trusted_scratch_base()?;
    #[cfg(not(unix))]
    let path = base.join(format!("fireemu-quint-export-{}-{id}", std::process::id()));
    create_private_dir(&path)?;
    #[cfg(not(unix))]
    let identity = file_identity(&path)?;
    let root = OwnedRoot {
        path,
        #[cfg(not(unix))]
        identity,
        #[cfg(unix)]
        _trusted_namespace: trusted_namespace,
    };
    let target = root.path.join("target");
    let displaced = root.path.join("displaced");
    create_private_dir(&target)?;
    write_private_file(&target.join("artifact"), b"old")?;
    let initial_identity = file_identity(&target)?;
    Ok((root, target, displaced, initial_identity))
}

#[cfg(not(unix))]
fn trusted_scratch_base() -> Result<PathBuf> {
    let path = platform_scratch_base()?;
    std::fs::create_dir_all(&path)
        .map_err(|error| invalid_data(&format!("cannot create trusted scratch base: {error}")))?;
    std::fs::canonicalize(&path)
        .map_err(|error| invalid_data(&format!("cannot resolve trusted scratch base: {error}")))
}

#[cfg(not(unix))]
fn platform_scratch_base() -> Result<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/fireemu-quint-publication"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

fn file_identity(path: &Path) -> Result<FileIdentity> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid_data(&format!("cannot inspect owned path: {error}")))?;
    if !metadata.file_type().is_dir() {
        return Err(invalid_data("owned publication path is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentity {
            modified: metadata.modified().ok(),
        })
    }
}

fn read_artifact(target: &Path) -> Result<String> {
    let bytes = std::fs::read(target.join("artifact"))
        .map_err(|error| invalid_data(&format!("cannot read public artifact: {error}")))?;
    match bytes.as_slice() {
        b"old" => Ok("Old".to_owned()),
        b"new" => Ok("New".to_owned()),
        b"partial" => Ok("Partial".to_owned()),
        _ => Err(invalid_data("unknown public artifact marker")),
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .map_err(|error| invalid_data(&format!("cannot create private directory: {error}")))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result {
    std::fs::create_dir(path)
        .map_err(|error| invalid_data(&format!("cannot create private directory: {error}")))
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| invalid_data(&format!("cannot create private file: {error}")))?;
    file.write_all(bytes)
        .map_err(|error| invalid_data(&format!("cannot write private file: {error}")))
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result {
    std::fs::write(path, bytes)
        .map_err(|error| invalid_data(&format!("cannot write private file: {error}")))
}

#[cfg(unix)]
fn is_private_directory(path: &Path) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid_data(&format!("cannot inspect directory mode: {error}")))?;
    Ok(metadata.file_type().is_dir() && metadata.permissions().mode().trailing_zeros() >= 6)
}

#[cfg(not(unix))]
fn is_private_directory(path: &Path) -> Result<bool> {
    Ok(std::fs::symlink_metadata(path)
        .map_err(|error| invalid_data(&format!("cannot inspect directory: {error}")))?
        .file_type()
        .is_dir())
}

#[cfg(unix)]
fn is_private_file(path: &Path) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| invalid_data(&format!("cannot inspect file mode: {error}")))?;
    Ok(metadata.file_type().is_file() && metadata.permissions().mode().trailing_zeros() >= 6)
}

#[cfg(not(unix))]
fn is_private_file(path: &Path) -> Result<bool> {
    Ok(std::fs::symlink_metadata(path)
        .map_err(|error| invalid_data(&format!("cannot inspect file: {error}")))?
        .file_type()
        .is_file())
}

fn invalid_data(message: &str) -> anyhow::Error {
    anyhow::anyhow!(message.to_owned())
}
