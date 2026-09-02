//! Official Local Emulator Suite import and export, between an export directory and the
//! live daemon.
//!
//! [`fireemu_core_export`] owns the artifact format; this module owns the two seams to a
//! running suite:
//!
//! - **import** ([`prepare`] then [`apply`]) reads every section of the selected products
//!   into memory first and only then installs them, all at once, under the exclusive
//!   [`AdmissionBarrier`](fireemu_core_session::barrier::AdmissionBarrier). Nothing is written until every product has parsed, so a malformed
//!   Storage section cannot leave a suite holding half an Auth import (`DATA-03`);
//! - **export** ([`export`]) walks the live state and writes the directory with owner-only
//!   permissions, because an Auth export carries password material (`DATA-05`).
//!
//! # What crosses the seam
//!
//! Project ids, database ids, bucket names, object bytes and Auth identities are written and
//! read back verbatim. An artifact whose project differs from the one the run serves is
//! imported under the project it names, with a notice: silently rewriting it would make a
//! fixture that the official suite reads one way and fireemu another.
//!
//! # What never crosses it
//!
//! fireemu's own session state -- named snapshots, fault plans, text index definitions --
//! and every App Check secret: debug tokens, the project epochs and the instance signing
//! key. None of them exists in the official format, and an export directory is a file a
//! person copies around.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::local::{FirestoreSnapshot, LocalBackend};
use fireemu_core_auth::claims::CustomClaims;
use fireemu_core_auth::mfa::{PhoneFactor, TotpFactor, TotpSecret};
use fireemu_core_auth::store::{
    AuthRegistry, FederatedIdentity, ImportedUser, ProjectAuthConfig, Provider,
};
use fireemu_core_export::auth::{
    fake_hash, AccountsFile, AuthConfig, MfaEnrollment, ProviderUserInfo, UserRecord,
    ACCOUNTS_FILE, CONFIG_FILE,
};
use fireemu_core_export::firestore::{
    read_output, write_output, ExportDocument, OverallMetadata, PartitionMetadata, EXPORT_NAME,
    OUTPUT_FILE, PARTITION_DIR, PARTITION_METADATA,
};
use fireemu_core_export::metadata::{
    ExportMetadata, Product, Section, AUTH_PATH, FIRESTORE_OVERALL_METADATA, FIRESTORE_PATH,
    METADATA_FILE_NAME, STORAGE_PATH,
};
use fireemu_core_export::storage::{
    blob_id, BucketsFile, ObjectMetadata as ExportedObject, BLOBS_DIR, BUCKETS_FILE, METADATA_DIR,
};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, ImportedDocument};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::ImportedObject;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use fireemu_export_publication::PublicationStage;

use crate::config::Selection;

/// The CLI version an export manifest is stamped with. The official emulator writes the
/// `firebase-tools` version here; fireemu writes the version it is compatible with, so that
/// a directory fireemu produced is accepted by the official CLI's own version checks, and
/// records its own version in the extension section.
pub const COMPATIBLE_CLI_VERSION: &str = "15.28.2";

/// The Firestore emulator version the official manifest names for the Firestore section.
pub const COMPATIBLE_FIRESTORE_VERSION: &str = "1.22.0";

/// The default database, which the official Firestore section carries.
const DEFAULT_DATABASE: &str = "(default)";

const IMPORT_MANIFEST_BYTES_LIMIT: u64 = 4 * 1024 * 1024;
const IMPORT_AUTH_FILE_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
const IMPORT_AUTH_TOTAL_BYTES_LIMIT: u64 = 256 * 1024 * 1024;
const IMPORT_AUTH_FILE_COUNT_LIMIT: u64 = 2_048;
const IMPORT_STORAGE_TOTAL_BYTES_LIMIT: u64 = 1024 * 1024 * 1024;
const IMPORT_STORAGE_OBJECT_COUNT_LIMIT: usize = 10_000;
const IMPORT_STORAGE_ENTRY_COUNT_LIMIT: u64 = 25_000;
const IMPORT_STORAGE_NESTING_DEPTH_LIMIT: u64 = 4;
const IMPORT_METADATA_FILE_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
const EXPORT_UNMANAGED_TOTAL_BYTES_LIMIT: u64 = 1024 * 1024 * 1024;
const EXPORT_UNMANAGED_ENTRY_COUNT_LIMIT: u64 = 25_000;
const EXPORT_UNMANAGED_NESTING_DEPTH_LIMIT: u32 = 64;

/// A failure of one product's section, with the path that caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactError {
    /// The product whose section failed.
    pub product: &'static str,
    /// The file or directory the failure is about.
    pub path: PathBuf,
    /// What went wrong.
    pub message: String,
}

impl ArtifactError {
    fn new(product: &'static str, path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self {
            product,
            path: path.into(),
            message: message.into(),
        }
    }
}

impl core::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: {}: {}",
            self.product,
            self.path.display(),
            self.message
        )
    }
}

impl std::error::Error for ArtifactError {}

/// The live state an import writes into and an export reads from.
pub struct Endpoints<'a> {
    /// Firestore databases.
    pub backend: &'a Arc<LocalBackend>,
    /// The Auth stores, keyed by project.
    pub auth: &'a Arc<AuthRegistry>,
    /// Buckets and objects.
    pub storage: &'a Arc<fireemu_adapter_http::storage::StorageState>,
    /// The virtual clock: an import that carries no time of its own uses it.
    pub clock: &'a Arc<Mutex<VirtualClock>>,
    /// The project the run serves.
    pub project: &'a str,
}

impl Endpoints<'_> {
    fn now(&self) -> LogicalInstant {
        self.clock
            .lock()
            .map_or(LogicalInstant::from_unix_seconds(0), |c| c.now())
    }
}

/// The documents of every database, keyed by `(project, database)`.
type PreparedDatabases = BTreeMap<(String, String), Vec<ImportedDocument>>;

/// The default accounts, project configuration and isolated tenant accounts of the Auth
/// section.
#[derive(Debug, Default)]
struct PreparedAuth {
    users: Vec<ImportedUser>,
    config: ProjectAuthConfig,
    tenants: BTreeMap<String, Vec<ImportedUser>>,
}

/// The objects with their bytes, and the buckets the Storage section listed.
type PreparedStorage = (Vec<(ImportedObject, Vec<u8>)>, Vec<String>);

/// Everything one export directory holds, parsed and ready to install.
#[derive(Debug, Default)]
pub struct Prepared {
    /// The Firestore databases.
    firestore: Option<PreparedDatabases>,
    /// The Auth accounts and the project configuration.
    auth: Option<PreparedAuth>,
    /// The Storage objects and buckets.
    storage: Option<PreparedStorage>,
    /// What the operator should be told before the run starts.
    pub notices: Vec<String>,
}

impl Prepared {
    /// A one-line summary of what will be installed.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(databases) = &self.firestore {
            let documents: usize = databases.values().map(Vec::len).sum();
            parts.push(format!(
                "firestore: {documents} document(s) in {} database(s)",
                databases.len()
            ));
        }
        if let Some(auth) = &self.auth {
            let accounts = auth
                .tenants
                .values()
                .map(Vec::len)
                .fold(auth.users.len(), usize::saturating_add);
            if auth.tenants.is_empty() {
                parts.push(format!("auth: {accounts} account(s)"));
            } else {
                parts.push(format!(
                    "auth: {accounts} account(s) in {} tenant(s)",
                    auth.tenants.len()
                ));
            }
        }
        if let Some((objects, buckets)) = &self.storage {
            parts.push(format!(
                "storage: {} object(s) in {} bucket(s)",
                objects.len(),
                buckets.len()
            ));
        }
        if parts.is_empty() {
            return "nothing to import".to_owned();
        }
        parts.join(", ")
    }
}

/// Which products an import or export covers, from `--only`.
#[derive(Debug, Clone, Copy)]
pub struct Products {
    /// Cloud Firestore.
    pub firestore: bool,
    /// Firebase Authentication.
    pub auth: bool,
    /// Cloud Storage for Firebase.
    pub storage: bool,
}

impl From<&Selection> for Products {
    fn from(only: &Selection) -> Self {
        Self {
            firestore: only.firestore,
            auth: only.auth,
            storage: only.storage,
        }
    }
}

impl Products {
    fn selects(self, product: Product) -> bool {
        match product {
            Product::Firestore => self.firestore,
            Product::Auth => self.auth,
            Product::Storage => self.storage,
            Product::Database | Product::DataConnect => false,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------

/// Reads every section of the selected products into memory. Nothing is installed.
///
/// A section of a product `--only` did not select is skipped with a notice rather than an
/// error: a run that asked for Auth alone should still start from a multi-product fixture.
/// A section of a product fireemu does not serve at all -- Realtime Database, SQL Connect --
/// is a failure, because ignoring it would start a suite that silently holds less state than
/// the artifact recorded.
pub fn prepare(dir: &Path, products: Products, project: &str) -> Result<Prepared, ArtifactError> {
    ensure_directory_inside(dir, dir).map_err(|e| ArtifactError::new("import", dir, e))?;
    let manifest_path = dir.join(METADATA_FILE_NAME);
    let text = read_text_inside_limited(dir, &manifest_path, IMPORT_MANIFEST_BYTES_LIMIT)
        .map_err(|e| ArtifactError::new("import", &manifest_path, e))?;
    let manifest = ExportMetadata::parse(&text)
        .map_err(|e| ArtifactError::new("import", &manifest_path, e.to_string()))?;

    let mut prepared = Prepared::default();
    if let Some(product) = manifest.deferred().first().copied() {
        return Err(ArtifactError::new(
            "import",
            &manifest_path,
            format!(
                "the export carries a {} section, and that product is a deferred gap in fireemu: it serves no Realtime Database or SQL Connect surface, so importing the rest would start a suite holding less state than the artifact records",
                product.cli_name()
            ),
        ));
    }
    for (product, section) in &manifest.sections {
        if !products.selects(*product) {
            prepared.notices.push(format!(
                "the export carries a {} section; --only did not select that product, so it was skipped",
                product.key()
            ));
            continue;
        }
        match product {
            Product::Firestore => {
                let mut databases = BTreeMap::new();
                let mut remaining_bytes = IMPORT_FIRESTORE_BYTES_BUDGET;
                let documents = read_firestore_section(dir, section, &mut remaining_bytes)?;
                collect_documents(
                    &mut databases,
                    documents,
                    DEFAULT_DATABASE,
                    &mut prepared.notices,
                    project,
                )?;
                for (database, named) in manifest.named_databases() {
                    let documents = read_firestore_section(dir, named, &mut remaining_bytes)?;
                    collect_documents(
                        &mut databases,
                        documents,
                        database,
                        &mut prepared.notices,
                        project,
                    )?;
                }
                prepared.firestore = Some(databases);
            }
            Product::Auth => prepared.auth = Some(read_auth_section(dir, section)?),
            Product::Storage => prepared.storage = Some(read_storage_section(dir, section)?),
            Product::Database | Product::DataConnect => unreachable!("refused above"),
        }
    }
    Ok(prepared)
}

/// Installs everything [`prepare`] read, under the exclusive admission barrier.
///
/// The barrier is held for the whole installation, so no request observes a suite that holds
/// the Firestore section but not the Auth one. Each product is still fallible -- a document
/// can violate a Firestore limit, an account can repeat a local id -- and a failure leaves
/// the products applied before it in place; `prepare` is what makes that vanishingly
/// unlikely, and the CLI turns any failure here into a refusal to start at all.
pub fn apply(prepared: &Prepared, endpoints: &Endpoints) -> Result<(), ArtifactError> {
    let now = endpoints.now();
    let barrier = endpoints.backend.barrier();
    let _exclusive = barrier.exclusive();

    if let Some(databases) = &prepared.firestore {
        let mut snapshot = FirestoreSnapshot {
            databases: BTreeMap::new(),
            ids: None,
        };
        for (key, documents) in databases {
            let mut state = FirestoreState::new();
            state
                .import_documents(documents.clone(), now)
                .map_err(|e| {
                    ArtifactError::new(
                        "firestore",
                        PathBuf::from(FIRESTORE_PATH),
                        format!("database {}/{}: {e}", key.0, key.1),
                    )
                })?;
            snapshot.databases.insert(key.clone(), state);
        }
        endpoints.backend.restore_databases(snapshot.databases);
    }

    if let Some(auth) = &prepared.auth {
        apply_auth(auth, endpoints)?;
    }

    if let Some((objects, _)) = &prepared.storage {
        let mut store = endpoints.storage.store.lock().map_err(|_| {
            ArtifactError::new(
                "storage",
                PathBuf::from(STORAGE_PATH),
                "the object store is poisoned",
            )
        })?;
        store.clear();
        for (object, bytes) in objects {
            let name = object.name.as_str().to_owned();
            store
                .insert_imported(object.clone(), bytes.clone())
                .map_err(|e| {
                    ArtifactError::new(
                        "storage",
                        PathBuf::from(STORAGE_PATH).join(BLOBS_DIR),
                        format!("object {name}: {e}"),
                    )
                })?;
        }
        let _ = store.drain_events();
    }
    Ok(())
}

fn apply_auth(auth: &PreparedAuth, endpoints: &Endpoints) -> Result<(), ArtifactError> {
    let store = endpoints.auth.default_store();
    let mut store = store.lock().map_err(|_| {
        ArtifactError::new(
            "auth",
            PathBuf::from(AUTH_PATH),
            "the Auth store is poisoned",
        )
    })?;
    store.clear();
    store.set_config(auth.config);
    for user in &auth.users {
        let id = user.local_id.clone();
        store.import_user(user.clone()).map_err(|e| {
            ArtifactError::new(
                "auth",
                PathBuf::from(AUTH_PATH).join(ACCOUNTS_FILE),
                format!("account {id}: {e}"),
            )
        })?;
    }
    // An import restores accounts that already existed; no Auth trigger fires for them.
    let _ = store.take_user_events();
    drop(store);

    for tenant in endpoints.auth.tenants(endpoints.project) {
        endpoints.auth.delete_tenant(endpoints.project, &tenant);
    }
    for (tenant, users) in &auth.tenants {
        let tenant_store = endpoints
            .auth
            .ensure_tenant(endpoints.project, tenant)
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    PathBuf::from(AUTH_PATH),
                    format!("cannot create tenant {tenant:?}"),
                )
            })?;
        let mut tenant_store = tenant_store.lock().map_err(|_| {
            ArtifactError::new(
                "auth",
                PathBuf::from(AUTH_PATH),
                format!("tenant {tenant:?} store is poisoned"),
            )
        })?;
        tenant_store.clear();
        tenant_store.set_config(auth.config);
        for user in users {
            let id = user.local_id.clone();
            tenant_store.import_user(user.clone()).map_err(|e| {
                ArtifactError::new(
                    "auth",
                    PathBuf::from(AUTH_PATH).join(format!("accounts-{tenant}.json")),
                    format!("account {id}: {e}"),
                )
            })?;
        }
        let _ = tenant_store.take_user_events();
    }
    Ok(())
}

/// Bytes of Firestore output files one import may hold in memory at once.
const IMPORT_FIRESTORE_BYTES_BUDGET: u64 = 1024 * 1024 * 1024;

/// Opens one artifact file relative to a directory descriptor. Every path component is opened
/// without following links, so validation and reading apply to the same file even if a hostile
/// local process replaces directory entries concurrently.
#[cfg(unix)]
fn open_file_inside(root: &Path, path: &Path) -> Result<std::fs::File, String> {
    use rustix::fs::{Mode, OFlags};

    let relative = path
        .strip_prefix(root)
        .map_err(|_| "it is outside the export directory".to_owned())?;
    let components: Vec<_> = relative
        .components()
        .map(|component| match component {
            std::path::Component::Normal(name) => Ok(name),
            _ => Err("its path is not a normal path inside the export directory".to_owned()),
        })
        .collect::<Result<_, _>>()?;
    let (leaf, directories) = components
        .split_last()
        .ok_or_else(|| "it does not name a file inside the export directory".to_owned())?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = rustix::fs::open(root, directory_flags, Mode::empty())
        .map_err(|e| format!("cannot open the export directory: {e}"))?;
    for component in directories {
        directory = rustix::fs::openat(&directory, *component, directory_flags, Mode::empty())
            .map_err(|e| {
                format!("cannot open a containing directory without following links: {e}")
            })?;
    }
    let descriptor = rustix::fs::openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot read it without following links: {e}"))?;
    let file = std::fs::File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect the opened file: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("it is not a regular file".to_owned());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_file_inside(root: &Path, path: &Path) -> Result<std::fs::File, String> {
    let root = std::fs::canonicalize(root).map_err(|e| format!("cannot resolve it: {e}"))?;
    let real = std::fs::canonicalize(path).map_err(|e| format!("cannot read it: {e}"))?;
    if !real.starts_with(&root) {
        return Err("it resolves outside the export directory".to_owned());
    }
    let file = std::fs::File::open(real).map_err(|e| format!("cannot read it: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("cannot inspect the opened file: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("it is not a regular file".to_owned());
    }
    Ok(file)
}

/// Reads at most `limit` bytes from the already validated descriptor. The descriptor length is
/// checked before allocating, and the bounded read catches a file that grows after that check.
fn read_inside_limited(root: &Path, path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let file = open_file_inside(root, path)?;
    let len = file
        .metadata()
        .map_err(|e| format!("cannot inspect the opened file: {e}"))?
        .len();
    if len > limit {
        return Err(format!("it exceeds the {limit} byte per-file import limit"));
    }
    let capacity = usize::try_from(len).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read it: {e}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!("it exceeds the {limit} byte per-file import limit"));
    }
    Ok(bytes)
}

fn read_inside_budgeted(
    root: &Path,
    path: &Path,
    remaining: &mut u64,
    total: u64,
    per_file_limit: u64,
    subject: &str,
) -> Result<Vec<u8>, String> {
    let allowance = (*remaining).min(per_file_limit);
    let bytes = read_inside_limited(root, path, allowance).map_err(|error| {
        if error.contains("byte per-file import limit") && *remaining <= per_file_limit {
            format!("the {subject} exceed the {total} byte cumulative import limit")
        } else {
            error
        }
    })?;
    *remaining = remaining.saturating_sub(bytes.len() as u64);
    Ok(bytes)
}

fn read_text_inside_budgeted(
    root: &Path,
    path: &Path,
    remaining: &mut u64,
    total: u64,
    per_file_limit: u64,
    subject: &str,
) -> Result<String, String> {
    let bytes = read_inside_budgeted(root, path, remaining, total, per_file_limit, subject)?;
    String::from_utf8(bytes).map_err(|_| "it is not UTF-8".to_owned())
}

fn read_text_inside_limited(root: &Path, path: &Path, limit: u64) -> Result<String, String> {
    let bytes = read_inside_limited(root, path, limit)?;
    String::from_utf8(bytes).map_err(|_| "it is not UTF-8".to_owned())
}

fn ensure_directory_inside(root: &Path, path: &Path) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| format!("cannot inspect it: {e}"))?;
    if metadata.file_type().is_symlink() {
        return Err("it is a symlink, which an import never follows".to_owned());
    }
    if !metadata.file_type().is_dir() {
        return Err("it is not a directory".to_owned());
    }
    let root = std::fs::canonicalize(root).map_err(|e| format!("cannot resolve it: {e}"))?;
    let real = std::fs::canonicalize(path).map_err(|e| format!("cannot resolve it: {e}"))?;
    if !real.starts_with(root) {
        return Err("it resolves outside the export directory".to_owned());
    }
    Ok(())
}

fn scan_import_tree(
    artifact_root: &Path,
    section_root: &Path,
    product: &'static str,
    total_bytes_limit: u64,
    entry_count_limit: u64,
    nesting_depth_limit: u64,
    per_file_limit: Option<u64>,
) -> Result<(), ArtifactError> {
    ensure_directory_inside(artifact_root, section_root)
        .map_err(|e| ArtifactError::new(product, section_root, e))?;
    let mut pending = vec![(section_root.to_path_buf(), 0u64)];
    let mut entries_seen = 0u64;
    let mut bytes_seen = 0u64;
    while let Some((directory, depth)) = pending.pop() {
        let entries = std::fs::read_dir(&directory)
            .map_err(|e| ArtifactError::new(product, &directory, format!("cannot read it: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                ArtifactError::new(product, &directory, format!("cannot read an entry: {e}"))
            })?;
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > entry_count_limit {
                return Err(ArtifactError::new(
                    product,
                    section_root,
                    format!(
                        "the section exceeds the {entry_count_limit} directory-entry import limit"
                    ),
                ));
            }
            let path = entry.path();
            let kind = entry.file_type().map_err(|e| {
                ArtifactError::new(product, &path, format!("cannot inspect it: {e}"))
            })?;
            if kind.is_symlink() {
                return Err(ArtifactError::new(
                    product,
                    &path,
                    "it is a symlink, which an import never follows",
                ));
            }
            if kind.is_dir() {
                let child_depth = depth.saturating_add(1);
                if child_depth > nesting_depth_limit {
                    return Err(ArtifactError::new(
                        product,
                        &path,
                        format!("the section exceeds the {nesting_depth_limit} level nesting-depth import limit"),
                    ));
                }
                pending.push((path, child_depth));
                continue;
            }
            if !kind.is_file() {
                return Err(ArtifactError::new(
                    product,
                    &path,
                    "it is not a regular file",
                ));
            }
            let len = entry
                .metadata()
                .map_err(|e| ArtifactError::new(product, &path, format!("cannot inspect it: {e}")))?
                .len();
            if let Some(limit) = per_file_limit {
                if len > limit {
                    return Err(ArtifactError::new(
                        product,
                        &path,
                        format!("it exceeds the {limit} byte per-file import limit"),
                    ));
                }
            }
            bytes_seen = bytes_seen.saturating_add(len);
            if bytes_seen > total_bytes_limit {
                return Err(ArtifactError::new(
                    product,
                    section_root,
                    format!(
                        "the section exceeds the {total_bytes_limit} byte cumulative import limit"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// A directory entry an import may look at: never a symlink.
fn refuse_symlink(product: &'static str, entry: &std::fs::DirEntry) -> Result<(), ArtifactError> {
    let is_symlink = entry.file_type().is_ok_and(|t| t.is_symlink());
    if is_symlink {
        return Err(ArtifactError::new(
            product,
            entry.path(),
            "it is a symlink, which an import never follows",
        ));
    }
    Ok(())
}

fn read_firestore_section(
    dir: &Path,
    section: &Section,
    remaining_bytes: &mut u64,
) -> Result<Vec<ExportDocument>, ArtifactError> {
    let metadata_file = section
        .metadata_file
        .clone()
        .unwrap_or_else(|| format!("{}/{FIRESTORE_OVERALL_METADATA}", section.path));
    let overall_path = dir.join(&metadata_file);
    let bytes = read_inside_limited(dir, &overall_path, IMPORT_METADATA_FILE_BYTES_LIMIT)
        .map_err(|e| ArtifactError::new("firestore", &overall_path, e))?;
    let overall = OverallMetadata::parse(&bytes)
        .map_err(|e| ArtifactError::new("firestore", &overall_path, e.to_string()))?;

    let section_dir = dir.join(&section.path);
    let partition_path = section_dir.join(&overall.metadata_file);
    let bytes = read_inside_limited(dir, &partition_path, IMPORT_METADATA_FILE_BYTES_LIMIT)
        .map_err(|e| ArtifactError::new("firestore", &partition_path, e))?;
    let partition = PartitionMetadata::parse(&bytes)
        .map_err(|e| ArtifactError::new("firestore", &partition_path, e.to_string()))?;

    let partition_dir = partition_path
        .parent()
        .map_or_else(|| section_dir.clone(), Path::to_path_buf);
    let mut documents = Vec::new();
    for output in &partition.output_files {
        let output_path = partition_dir.join(output);
        let bytes = read_inside_budgeted(
            dir,
            &output_path,
            remaining_bytes,
            IMPORT_FIRESTORE_BYTES_BUDGET,
            IMPORT_FIRESTORE_BYTES_BUDGET,
            "output files",
        )
        .map_err(|e| ArtifactError::new("firestore", &output_path, e))?;
        documents.extend(
            read_output(&bytes)
                .map_err(|e| ArtifactError::new("firestore", &output_path, e.to_string()))?,
        );
    }
    Ok(documents)
}

/// Turns the decoded entities into per-database import documents, validating every path.
fn collect_documents(
    databases: &mut BTreeMap<(String, String), Vec<ImportedDocument>>,
    documents: Vec<ExportDocument>,
    database: &str,
    notices: &mut Vec<String>,
    run_project: &str,
) -> Result<(), ArtifactError> {
    let mut foreign = BTreeSet::new();
    for document in documents {
        if document.project != run_project {
            foreign.insert(document.project.clone());
        }
        let project = ProjectId::try_new(document.project.clone()).map_err(|e| {
            ArtifactError::new(
                "firestore",
                PathBuf::from(FIRESTORE_PATH),
                format!("project id {:?}: {e}", document.project),
            )
        })?;
        let database_id = DatabaseId::try_new(database).map_err(|e| {
            ArtifactError::new(
                "firestore",
                PathBuf::from(FIRESTORE_PATH),
                format!("database id {database:?}: {e}"),
            )
        })?;
        let relative = document.relative_path();
        let path = DocumentPath::parse(&project, &database_id, &relative).map_err(|e| {
            ArtifactError::new(
                "firestore",
                PathBuf::from(FIRESTORE_PATH),
                format!("document path {relative:?}: {e}"),
            )
        })?;
        databases
            .entry((document.project.clone(), database.to_owned()))
            .or_default()
            .push(ImportedDocument {
                path,
                fields: document.fields,
                // The official managed export records no document timestamps at all, so an
                // import necessarily stamps them with the commit it installs them in.
                create_time: None,
                update_time: None,
            });
    }
    for project in foreign {
        notices.push(format!(
            "the Firestore export holds documents of the project {project}, not the {run_project} this run serves; they were imported under {project}, so point the SDK at that project to read them"
        ));
    }
    Ok(())
}

fn read_auth_text(
    dir: &Path,
    path: &Path,
    remaining_bytes: &mut u64,
) -> Result<String, ArtifactError> {
    read_text_inside_budgeted(
        dir,
        path,
        remaining_bytes,
        IMPORT_AUTH_TOTAL_BYTES_LIMIT,
        IMPORT_AUTH_FILE_BYTES_LIMIT,
        "Auth files",
    )
    .map_err(|error| ArtifactError::new("auth", path, error))
}

fn read_auth_section(dir: &Path, section: &Section) -> Result<PreparedAuth, ArtifactError> {
    let section_dir = dir.join(&section.path);
    scan_import_tree(
        dir,
        &section_dir,
        "auth",
        IMPORT_AUTH_TOTAL_BYTES_LIMIT,
        IMPORT_AUTH_FILE_COUNT_LIMIT,
        0,
        Some(IMPORT_AUTH_FILE_BYTES_LIMIT),
    )?;
    let mut remaining_bytes = IMPORT_AUTH_TOTAL_BYTES_LIMIT;
    let config_path = section_dir.join(CONFIG_FILE);
    let config = match std::fs::symlink_metadata(&config_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(ArtifactError::new(
                    "auth",
                    &config_path,
                    "the optional config is not a regular no-symlink file",
                ));
            }
            let text = read_auth_text(dir, &config_path, &mut remaining_bytes)?;
            let parsed = AuthConfig::parse(&text)
                .map_err(|e| ArtifactError::new("auth", &config_path, e.to_string()))?;
            ProjectAuthConfig {
                allow_duplicate_emails: parsed.allow_duplicate_emails,
                enable_improved_email_privacy: parsed.enable_improved_email_privacy,
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ProjectAuthConfig::default(),
        Err(e) => {
            return Err(ArtifactError::new(
                "auth",
                &config_path,
                format!("cannot inspect the optional config: {e}"),
            ))
        }
    };

    let mut tenants = BTreeMap::new();
    let entries = std::fs::read_dir(&section_dir)
        .map_err(|e| ArtifactError::new("auth", &section_dir, format!("cannot read it: {e}")))?;
    for entry in entries.flatten() {
        refuse_symlink("auth", &entry)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(tenant) = name
            .strip_prefix("accounts-")
            .and_then(|name| name.strip_suffix(".json"))
        {
            if tenant.is_empty() || tenant.contains('/') || tenant.contains('\\') {
                return Err(ArtifactError::new(
                    "auth",
                    entry.path(),
                    "the tenant accounts filename has an invalid tenant id",
                ));
            }
            let text = read_auth_text(dir, &entry.path(), &mut remaining_bytes)?;
            let accounts = AccountsFile::parse(&text)
                .map_err(|e| ArtifactError::new("auth", entry.path(), e.to_string()))?;
            let mut users = Vec::with_capacity(accounts.users.len());
            for record in &accounts.users {
                if record
                    .tenant_id
                    .as_deref()
                    .is_some_and(|recorded| recorded != tenant)
                {
                    return Err(ArtifactError::new(
                        "auth",
                        entry.path(),
                        format!(
                            "account {:?} names tenant {:?}, not the filename tenant {tenant:?}",
                            record.local_id, record.tenant_id
                        ),
                    ));
                }
                users.push(imported_user(record, &entry.path())?);
            }
            tenants.insert(tenant.to_owned(), users);
        }
    }

    let accounts_path = section_dir.join(ACCOUNTS_FILE);
    let text = read_auth_text(dir, &accounts_path, &mut remaining_bytes)?;
    let accounts = AccountsFile::parse(&text)
        .map_err(|e| ArtifactError::new("auth", &accounts_path, e.to_string()))?;
    let mut users = Vec::with_capacity(accounts.users.len());
    for record in &accounts.users {
        users.push(imported_user(record, &accounts_path)?);
    }
    Ok(PreparedAuth {
        users,
        config,
        tenants,
    })
}

fn millis_instant(text: Option<&str>) -> Option<LogicalInstant> {
    let millis: i64 = text?.parse().ok()?;
    Some(LogicalInstant::from_nanos(i128::from(millis) * 1_000_000))
}

fn seconds_instant(text: Option<&str>) -> Option<LogicalInstant> {
    let seconds: i64 = text?.parse().ok()?;
    Some(LogicalInstant::from_unix_seconds(seconds))
}

fn imported_user(record: &UserRecord, path: &Path) -> Result<ImportedUser, ArtifactError> {
    let refuse = |message: String| ArtifactError::new("auth", path, message);
    let custom_claims = match &record.custom_attributes {
        Some(text) if !text.is_empty() => CustomClaims::parse_attributes(text).map_err(|e| {
            refuse(format!(
                "account {}: customAttributes: {e}",
                record.local_id
            ))
        })?,
        _ => CustomClaims::default(),
    };
    let password = record.password_hash.as_deref().and_then(fake_hash::decode);
    if let (Some(hash), None) = (&record.password_hash, &password) {
        return Err(refuse(format!(
            "account {}: the passwordHash {:?} is not the emulator's own reversible form, so fireemu cannot install a credential a client could sign in with",
            record.local_id,
            hash.chars().take(24).collect::<String>()
        )));
    }
    let created_at = millis_instant(record.created_at.as_deref())
        .unwrap_or(LogicalInstant::from_unix_seconds(0));
    let mut totp_factors = Vec::new();
    let mut phone_factors = Vec::new();
    for (index, enrollment) in record.mfa_info.iter().enumerate() {
        let id = if enrollment.mfa_enrollment_id.is_empty() {
            format!("{}-factor-{index}", record.local_id)
        } else {
            enrollment.mfa_enrollment_id.clone()
        };
        let enrolled_at = rfc3339_instant(enrollment.enrolled_at.as_deref()).unwrap_or(created_at);
        if let Some(secret) = &enrollment.totp_shared_secret_key {
            let bytes = decode_base32(secret).ok_or_else(|| {
                refuse(format!(
                    "account {}: the TOTP shared secret is not base32",
                    record.local_id
                ))
            })?;
            // RFC 4226 asks for at least 128 bits of shared secret; a shorter one lets anyone
            // derive codes, an empty one lets everyone. The upper bound keeps an artifact
            // from installing an unbounded string.
            if !(16..=64).contains(&bytes.len()) {
                return Err(refuse(format!(
                    "account {}: the TOTP shared secret is {} bytes; it must be between 16 and 64",
                    record.local_id,
                    bytes.len()
                )));
            }
            totp_factors.push(TotpFactor {
                mfa_enrollment_id: id,
                display_name: enrollment.display_name.clone(),
                secret: TotpSecret::new(bytes),
                enrolled_at,
                last_accepted_step: None,
            });
            continue;
        }
        let phone = enrollment
            .unobfuscated_phone_info
            .clone()
            .or_else(|| enrollment.phone_info.clone())
            .ok_or_else(|| {
                refuse(format!(
                    "account {}: a second factor is neither a phone nor a TOTP factor",
                    record.local_id
                ))
            })?;
        phone_factors.push(PhoneFactor {
            mfa_enrollment_id: id,
            display_name: enrollment.display_name.clone(),
            phone_number: phone,
            enrolled_at,
        });
    }
    Ok(ImportedUser {
        local_id: record.local_id.clone(),
        email: record.email.clone(),
        email_verified: record.email_verified,
        display_name: record.display_name.clone(),
        photo_url: record.photo_url.clone(),
        phone_number: record.phone_number.clone(),
        disabled: record.disabled,
        provider: provider_of(record),
        custom_claims,
        created_at,
        last_sign_in_at: millis_instant(record.last_login_at.as_deref()),
        tokens_valid_after: seconds_instant(record.valid_since.as_deref()).unwrap_or(created_at),
        federated: record
            .provider_user_info
            .iter()
            .filter(|p| !matches!(p.provider_id.as_str(), "password" | "phone" | "emailLink"))
            .map(federated_identity)
            .collect(),
        password,
        totp_factors,
        phone_factors,
    })
}

/// The sign-in provider an account is attributed to, from the providers the export listed.
fn provider_of(record: &UserRecord) -> Provider {
    let has = |id: &str| {
        record
            .provider_user_info
            .iter()
            .any(|p| p.provider_id == id)
    };
    if record.password_hash.is_some() || has("password") {
        return Provider::Password;
    }
    if has("emailLink") {
        return Provider::EmailLink;
    }
    if let Some(federated) = record
        .provider_user_info
        .iter()
        .find(|p| !matches!(p.provider_id.as_str(), "password" | "phone" | "emailLink"))
    {
        return Provider::Federated(federated.provider_id.clone());
    }
    if has("phone") {
        return Provider::Phone;
    }
    Provider::Anonymous
}

fn federated_identity(provider: &ProviderUserInfo) -> FederatedIdentity {
    FederatedIdentity {
        provider_id: provider.provider_id.clone(),
        raw_id: provider.raw_id.clone(),
        email: provider.email.clone(),
        display_name: provider.display_name.clone(),
        photo_url: provider.photo_url.clone(),
    }
}

/// RFC 4648 base32 without padding, the spelling `otpauth` URIs and the emulator use.
fn decode_base32(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    for ch in text.bytes() {
        if ch == b'=' {
            continue;
        }
        let value = ALPHABET
            .iter()
            .position(|c| *c == ch.to_ascii_uppercase())?;
        bits = (bits << 5) | u32::try_from(value).ok()?;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(out)
}

fn scan_storage_import_tree(dir: &Path, section_dir: &Path) -> Result<(), ArtifactError> {
    scan_import_tree(
        dir,
        section_dir,
        "storage",
        IMPORT_STORAGE_TOTAL_BYTES_LIMIT,
        IMPORT_STORAGE_ENTRY_COUNT_LIMIT,
        IMPORT_STORAGE_NESTING_DEPTH_LIMIT,
        None,
    )
}

fn read_storage_text(
    dir: &Path,
    path: &Path,
    remaining_bytes: &mut u64,
) -> Result<String, ArtifactError> {
    read_text_inside_budgeted(
        dir,
        path,
        remaining_bytes,
        IMPORT_STORAGE_TOTAL_BYTES_LIMIT,
        IMPORT_METADATA_FILE_BYTES_LIMIT,
        "Storage files",
    )
    .map_err(|error| ArtifactError::new("storage", path, error))
}

fn read_storage_blob(
    dir: &Path,
    path: &Path,
    remaining_bytes: &mut u64,
    object: &str,
    expected_size: u64,
) -> Result<Vec<u8>, ArtifactError> {
    let bytes = read_inside_budgeted(
        dir,
        path,
        remaining_bytes,
        IMPORT_STORAGE_TOTAL_BYTES_LIMIT,
        fireemu_core_storage::store::MAX_OBJECT_BYTES,
        "Storage files",
    )
    .map_err(|error| {
        ArtifactError::new(
            "storage",
            path,
            format!("the object {object} names a blob that cannot be read: {error}"),
        )
    })?;
    if bytes.len() as u64 != expected_size {
        return Err(ArtifactError::new(
            "storage",
            path,
            format!(
                "the blob of object {object} does not have the size its metadata records (or exceeds the object limit)"
            ),
        ));
    }
    Ok(bytes)
}

fn read_storage_section(dir: &Path, section: &Section) -> Result<PreparedStorage, ArtifactError> {
    let section_dir = dir.join(&section.path);
    scan_storage_import_tree(dir, &section_dir)?;
    let mut remaining_bytes = IMPORT_STORAGE_TOTAL_BYTES_LIMIT;
    let buckets_path = section_dir.join(BUCKETS_FILE);
    let text = read_storage_text(dir, &buckets_path, &mut remaining_bytes)?;
    let buckets = BucketsFile::parse(&text)
        .map_err(|e| ArtifactError::new("storage", &buckets_path, e.to_string()))?;

    let metadata_dir = section_dir.join(METADATA_DIR);
    let blobs_dir = section_dir.join(BLOBS_DIR);
    let mut objects = Vec::new();
    let entries = match std::fs::read_dir(&metadata_dir) {
        Ok(entries) => entries,
        // A section with buckets but no object at all is legitimate.
        Err(_) if !metadata_dir.exists() => return Ok((objects, buckets.buckets)),
        Err(e) => {
            return Err(ArtifactError::new(
                "storage",
                &metadata_dir,
                format!("cannot read it: {e}"),
            ))
        }
    };
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        refuse_symlink("storage", &entry)?;
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            paths.push(path);
        }
    }
    paths.sort();
    enforce_storage_object_count(paths.len(), &metadata_dir)?;
    let mut identities = BTreeSet::new();
    for path in paths {
        let text = read_storage_text(dir, &path, &mut remaining_bytes)?;
        let meta = ExportedObject::parse(&text)
            .map_err(|e| ArtifactError::new("storage", &path, e.to_string()))?;
        if !identities.insert((meta.bucket.clone(), meta.name.clone())) {
            return Err(ArtifactError::new(
                "storage",
                &path,
                format!(
                    "duplicate storage object {}/{} appears in more than one metadata file",
                    meta.bucket, meta.name
                ),
            ));
        }
        let id = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let blob_path = blobs_dir.join(&id);
        // The size is checked from the file's own metadata before a byte is read, so a
        // blob larger than any object can be (or than its metadata says) never lands in
        // memory, and the message never tells a probing caller how large a file is.
        let blob_meta = std::fs::symlink_metadata(&blob_path).map_err(|e| {
            ArtifactError::new(
                "storage",
                &blob_path,
                format!(
                    "the object {} names a blob that cannot be read: {e}",
                    meta.name
                ),
            )
        })?;
        if blob_meta.file_type().is_symlink() {
            return Err(ArtifactError::new(
                "storage",
                &blob_path,
                "it is a symlink, which an import never follows",
            ));
        }
        if blob_meta.len() > fireemu_core_storage::store::MAX_OBJECT_BYTES
            || blob_meta.len() != meta.size
        {
            return Err(ArtifactError::new(
                "storage",
                &blob_path,
                format!(
                    "the blob of object {} does not have the size its metadata records (or exceeds the object limit)",
                    meta.name
                ),
            ));
        }
        let bytes =
            read_storage_blob(dir, &blob_path, &mut remaining_bytes, &meta.name, meta.size)?;
        objects.push((imported_object(&meta, &path)?, bytes));
    }
    Ok((objects, buckets.buckets))
}

fn enforce_storage_object_count(count: usize, path: &Path) -> Result<(), ArtifactError> {
    if count > IMPORT_STORAGE_OBJECT_COUNT_LIMIT {
        return Err(ArtifactError::new(
            "storage",
            path,
            format!(
                "the section exceeds the {IMPORT_STORAGE_OBJECT_COUNT_LIMIT} object import limit"
            ),
        ));
    }
    Ok(())
}

fn imported_object(meta: &ExportedObject, path: &Path) -> Result<ImportedObject, ArtifactError> {
    let refuse = |message: String| ArtifactError::new("storage", path, message);
    let bucket = BucketName::try_new(meta.bucket.clone())
        .map_err(|e| refuse(format!("bucket {:?}: {e}", meta.bucket)))?;
    let name = ObjectName::try_new(meta.name.clone())
        .map_err(|e| refuse(format!("object name {:?}: {e}", meta.name)))?;
    let generation = u64::try_from(meta.generation)
        .ok()
        .filter(|generation| *generation >= 1)
        .ok_or_else(|| refuse("generation must be at least 1".to_owned()))?;
    let metageneration = u64::try_from(meta.metageneration)
        .ok()
        .filter(|metageneration| *metageneration >= 1)
        .ok_or_else(|| refuse("metageneration must be at least 1".to_owned()))?;
    Ok(ImportedObject {
        bucket,
        name,
        generation,
        metageneration,
        content_type: meta
            .content_type
            .clone()
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
        content_disposition: meta.content_disposition.clone(),
        content_encoding: meta.content_encoding.clone(),
        content_language: meta.content_language.clone(),
        cache_control: meta.cache_control.clone(),
        custom: meta.custom_metadata.iter().cloned().collect(),
        // The export document model keeps custom metadata as a list, so an official
        // artifact's defined-but-empty `customMetadata: {}` imports as undefined; only the
        // Firebase dialect's metadata JSON can observe that difference.
        custom_defined: !meta.custom_metadata.is_empty(),
        time_created: rfc3339_instant(meta.time_created.as_deref())
            .unwrap_or(LogicalInstant::from_unix_seconds(0)),
        updated: rfc3339_instant(meta.updated.as_deref())
            .unwrap_or(LogicalInstant::from_unix_seconds(0)),
        download_tokens: meta.download_tokens.clone(),
        md5: meta.md5_hash.as_deref().and_then(decode_md5),
        crc32c: meta.crc32c.as_deref().and_then(|c| c.parse().ok()),
        size: Some(meta.size),
    })
}

fn decode_md5(base64: &str) -> Option<[u8; 16]> {
    let bytes = decode_base64(base64)?;
    <[u8; 16]>::try_from(bytes.as_slice()).ok()
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for ch in text.bytes() {
        if ch == b'=' {
            continue;
        }
        let value = ALPHABET.iter().position(|c| *c == ch)?;
        bits = (bits << 6) | u32::try_from(value).ok()?;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// `2026-08-30T15:58:33.194Z` -> a logical instant. The emulator writes exactly this shape.
fn rfc3339_instant(text: Option<&str>) -> Option<LogicalInstant> {
    let text = text?;
    let (date, rest) = text.split_once('T')?;
    let time = rest.trim_end_matches('Z');
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let (clock, fraction) = time.split_once('.').unwrap_or((time, "0"));
    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next()?.parse().ok()?;
    let mut nanos: i128 = 0;
    for (index, digit) in fraction.chars().take(9).enumerate() {
        let value = i128::from(digit.to_digit(10)?);
        nanos += value * 10i128.pow(8 - u32::try_from(index).ok()?);
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Some(LogicalInstant::from_nanos(
        i128::from(seconds) * 1_000_000_000 + nanos,
    ))
}

/// Days since the Unix epoch (Howard Hinnant's civil-from-days, inverted).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-08-30T15:58:33.194Z` from a logical instant.
fn rfc3339_text(at: LogicalInstant) -> String {
    let nanos = at.as_nanos();
    // A logical instant is nanoseconds in an i128; the year range the format covers fits an
    // i64 many times over, and a value that somehow did not is clamped rather than wrapped.
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).unwrap_or(i64::MAX);
    let millis = i64::try_from(nanos.rem_euclid(1_000_000_000) / 1_000_000).unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

/// Writes the export directory for the selected products.
///
/// The directory and every file in it are created with owner-only permissions: an Auth
/// export carries password material and, for a fireemu TOTP second factor, a shared secret
/// (`DATA-05`). fireemu's own session snapshots and every App Check secret stay out of it.
pub fn export(
    dir: &Path,
    products: Products,
    endpoints: &Endpoints,
    initiated_by: &str,
) -> Result<(), ArtifactError> {
    let staged = PublicationStage::create(dir, may_overwrite)
        .map_err(|e| ArtifactError::new("export", dir, e))?;
    if staged.target_was_present() {
        copy_unmanaged_entries(dir, staged.root())
            .map_err(|e| ArtifactError::new("export", dir, e))?;
    }
    write_export_tree(staged.root(), products, endpoints, initiated_by)?;
    staged
        .complete()
        .publish()
        .map_err(|e| ArtifactError::new("export", dir, e))
}

fn write_export_tree(
    dir: &Path,
    products: Products,
    endpoints: &Endpoints,
    initiated_by: &str,
) -> Result<(), ArtifactError> {
    let _ = initiated_by;
    create_private_dir(dir).map_err(|e| ArtifactError::new("export", dir, e))?;
    let mut manifest = ExportMetadata::new(COMPATIBLE_CLI_VERSION);

    if products.firestore {
        export_firestore(dir, endpoints, &mut manifest)?;
    }
    if products.auth {
        export_auth(dir, endpoints, &mut manifest)?;
    }
    if products.storage {
        export_storage(dir, endpoints, &mut manifest)?;
    }
    write_private_file(&dir.join(METADATA_FILE_NAME), manifest.to_json().as_bytes())
        .map_err(|e| ArtifactError::new("export", dir.join(METADATA_FILE_NAME), e))?;
    Ok(())
}

fn export_firestore(
    dir: &Path,
    endpoints: &Endpoints,
    manifest: &mut ExportMetadata,
) -> Result<(), ArtifactError> {
    let scope = fireemu_core_session::tenancy::Scope::AllExcept(BTreeSet::new());
    let snapshot = endpoints.backend.snapshot_scope(&scope);
    let now = endpoints.now();
    let micros = u64::try_from(now.as_nanos() / 1_000).unwrap_or(0);
    let mut by_database: BTreeMap<String, Vec<ExportDocument>> = BTreeMap::new();
    for ((project, database), state) in &snapshot.databases {
        let documents: Vec<ExportDocument> = state
            .documents()
            .into_iter()
            .map(|d| ExportDocument {
                project: project.clone(),
                path: d
                    .path
                    .pairs()
                    .iter()
                    .map(|(c, id)| (c.as_str().to_owned(), id.as_str().to_owned()))
                    .collect(),
                fields: d.fields,
            })
            .collect();
        by_database
            .entry(database.clone())
            .or_default()
            .extend(documents);
    }
    // The default database always gets a section, even when it is empty: the official CLI
    // writes one whenever the Firestore emulator runs, and an absent section reads as "this
    // export never covered Firestore".
    by_database.entry(DEFAULT_DATABASE.to_owned()).or_default();

    for (database, documents) in &by_database {
        let path = if database == DEFAULT_DATABASE {
            FIRESTORE_PATH.to_owned()
        } else {
            format!("{FIRESTORE_PATH}_{}", sanitize(database))
        };
        let section_dir = dir.join(&path);
        let partition_dir = section_dir.join(PARTITION_DIR);
        create_private_dir(&partition_dir)
            .map_err(|e| ArtifactError::new("firestore", &partition_dir, e))?;

        let output = write_output(documents);
        let output_path = partition_dir.join(OUTPUT_FILE);
        write_private_file(&output_path, &output)
            .map_err(|e| ArtifactError::new("firestore", &output_path, e))?;

        let partition = PartitionMetadata {
            export_name: EXPORT_NAME.to_owned(),
            start_micros: micros,
            end_micros: micros,
            output_files: vec![OUTPUT_FILE.to_owned()],
        };
        let partition_path = partition_dir.join(PARTITION_METADATA);
        write_private_file(&partition_path, &partition.to_bytes())
            .map_err(|e| ArtifactError::new("firestore", &partition_path, e))?;

        let overall = OverallMetadata {
            metadata_file: format!("{PARTITION_DIR}/{PARTITION_METADATA}"),
            entity_count: documents.len() as u64,
            byte_count: output.len() as u64,
        };
        let overall_path = section_dir.join(FIRESTORE_OVERALL_METADATA);
        write_private_file(&overall_path, &overall.to_bytes())
            .map_err(|e| ArtifactError::new("firestore", &overall_path, e))?;

        let section = Section {
            version: COMPATIBLE_FIRESTORE_VERSION.to_owned(),
            path: path.clone(),
            metadata_file: Some(format!("{path}/{FIRESTORE_OVERALL_METADATA}")),
        };
        if database == DEFAULT_DATABASE {
            manifest.set(Product::Firestore, section);
        } else {
            manifest.set_named_database(env!("CARGO_PKG_VERSION"), database, section);
        }
    }
    Ok(())
}

/// A database id as a directory-name fragment. Firestore database ids are already limited to
/// letters, digits and hyphens, so this only guards against a future relaxation.
fn sanitize(database: &str) -> String {
    database
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn export_auth(
    dir: &Path,
    endpoints: &Endpoints,
    manifest: &mut ExportMetadata,
) -> Result<(), ArtifactError> {
    let section_dir = dir.join(AUTH_PATH);
    create_private_dir(&section_dir).map_err(|e| ArtifactError::new("auth", &section_dir, e))?;
    let store = endpoints.auth.default_store();
    let store = store
        .lock()
        .map_err(|_| ArtifactError::new("auth", &section_dir, "the Auth store is poisoned"))?;
    let mut file = AccountsFile::default();
    for user in store.users_by_creation() {
        file.users.push(exported_account(&store, user, None));
    }
    let accounts_path = section_dir.join(ACCOUNTS_FILE);
    write_private_file(&accounts_path, file.to_json().as_bytes())
        .map_err(|e| ArtifactError::new("auth", &accounts_path, e))?;

    let config = store.config();
    let config_path = section_dir.join(CONFIG_FILE);
    let document = AuthConfig {
        allow_duplicate_emails: config.allow_duplicate_emails,
        enable_improved_email_privacy: config.enable_improved_email_privacy,
    };
    write_private_file(&config_path, document.to_json().as_bytes())
        .map_err(|e| ArtifactError::new("auth", &config_path, e))?;
    drop(store);

    for tenant in endpoints.auth.tenants(endpoints.project) {
        let tenant_store = endpoints
            .auth
            .tenant_store(endpoints.project, &tenant)
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    &section_dir,
                    format!("tenant {tenant:?} disappeared during export"),
                )
            })?;
        let tenant_store = tenant_store.lock().map_err(|_| {
            ArtifactError::new(
                "auth",
                &section_dir,
                format!("tenant {tenant:?} store is poisoned"),
            )
        })?;
        let mut file = AccountsFile::default();
        for user in tenant_store.users_by_creation() {
            file.users
                .push(exported_account(&tenant_store, user, Some(&tenant)));
        }
        let path = section_dir.join(format!("accounts-{tenant}.json"));
        write_private_file(&path, file.to_json().as_bytes())
            .map_err(|e| ArtifactError::new("auth", &path, e))?;
    }

    manifest.set(
        Product::Auth,
        Section {
            version: COMPATIBLE_CLI_VERSION.to_owned(),
            path: AUTH_PATH.to_owned(),
            metadata_file: None,
        },
    );
    Ok(())
}

/// One account as the Identity Toolkit document an export carries.
fn exported_account(
    store: &fireemu_core_auth::store::AuthStore,
    user: &fireemu_core_auth::store::UserRecord,
    tenant_id: Option<&str>,
) -> UserRecord {
    {
        let (password_hash, salt) = match store
            .password_digest(&user.local_id)
            .and_then(fireemu_core_auth::store::PasswordDigest::emulator_form)
        {
            Some((salt, password)) => (
                Some(fake_hash::encode(salt, password)),
                Some(salt.to_owned()),
            ),
            None => (None, None),
        };
        let mut providers = Vec::new();
        if let Some(email) = &user.email {
            providers.push(ProviderUserInfo {
                provider_id: if password_hash.is_some() || store.has_password(&user.local_id) {
                    "password".to_owned()
                } else {
                    "emailLink".to_owned()
                },
                raw_id: email.clone(),
                federated_id: Some(email.clone()),
                email: Some(email.clone()),
                display_name: user.display_name.clone(),
                photo_url: user.photo_url.clone(),
                phone_number: None,
                screen_name: None,
            });
        }
        if let Some(phone) = &user.phone_number {
            providers.push(ProviderUserInfo {
                provider_id: "phone".to_owned(),
                raw_id: phone.clone(),
                phone_number: Some(phone.clone()),
                ..ProviderUserInfo::default()
            });
        }
        for identity in &user.federated {
            providers.push(ProviderUserInfo {
                provider_id: identity.provider_id.clone(),
                raw_id: identity.raw_id.clone(),
                federated_id: Some(identity.raw_id.clone()),
                email: identity.email.clone(),
                display_name: identity.display_name.clone(),
                photo_url: identity.photo_url.clone(),
                phone_number: None,
                screen_name: None,
            });
        }
        let mut mfa_info = Vec::new();
        for factor in user.mfa.phone_factors() {
            mfa_info.push(MfaEnrollment {
                mfa_enrollment_id: factor.mfa_enrollment_id.clone(),
                display_name: factor.display_name.clone(),
                phone_info: Some(factor.phone_number.clone()),
                unobfuscated_phone_info: Some(factor.phone_number.clone()),
                enrolled_at: Some(rfc3339_text(factor.enrolled_at)),
                totp_shared_secret_key: None,
            });
        }
        for factor in user.mfa.totp_factors() {
            mfa_info.push(MfaEnrollment {
                mfa_enrollment_id: factor.mfa_enrollment_id.clone(),
                display_name: factor.display_name.clone(),
                phone_info: None,
                unobfuscated_phone_info: None,
                enrolled_at: Some(rfc3339_text(factor.enrolled_at)),
                totp_shared_secret_key: Some(fireemu_core_auth::base32::encode(
                    factor.secret.expose_for_enrollment(),
                )),
            });
        }
        let claims = user.custom_claims.canonical_json();
        UserRecord {
            local_id: user.local_id.as_str().to_owned(),
            email: user.email.clone(),
            email_verified: user.email_verified,
            display_name: user.display_name.clone(),
            photo_url: user.photo_url.clone(),
            phone_number: user.phone_number.clone(),
            disabled: user.disabled,
            password_hash,
            salt,
            password_updated_at: None,
            valid_since: Some((user.tokens_valid_after.as_nanos() / 1_000_000_000).to_string()),
            created_at: Some((user.created_at.as_nanos() / 1_000_000).to_string()),
            last_login_at: user
                .last_sign_in_at
                .map(|t| (t.as_nanos() / 1_000_000).to_string()),
            last_refresh_at: None,
            custom_attributes: (claims != "{}").then_some(claims),
            tenant_id: tenant_id.map(str::to_owned),
            provider_user_info: providers,
            mfa_info,
            extra: Vec::new(),
        }
    }
}

fn export_storage(
    dir: &Path,
    endpoints: &Endpoints,
    manifest: &mut ExportMetadata,
) -> Result<(), ArtifactError> {
    let section_dir = dir.join(STORAGE_PATH);
    let blobs_dir = section_dir.join(BLOBS_DIR);
    let metadata_dir = section_dir.join(METADATA_DIR);
    create_private_dir(&blobs_dir).map_err(|e| ArtifactError::new("storage", &blobs_dir, e))?;
    create_private_dir(&metadata_dir)
        .map_err(|e| ArtifactError::new("storage", &metadata_dir, e))?;

    let store =
        endpoints.storage.store.lock().map_err(|_| {
            ArtifactError::new("storage", &section_dir, "the object store is poisoned")
        })?;
    let mut buckets: Vec<String> = store
        .buckets()
        .iter()
        .map(|b| b.as_str().to_owned())
        .collect();
    // The bucket the project would use by default is always listed, so that an import into
    // the official suite knows about it even when nothing was written to it yet.
    let default_bucket = format!("{}.appspot.com", endpoints.project);
    if !buckets.contains(&default_bucket) {
        buckets.push(default_bucket);
    }
    buckets.sort();
    buckets.dedup();

    for object in store.all_objects() {
        let generation = i64::try_from(object.generation).map_err(|_| {
            ArtifactError::new(
                "storage",
                &section_dir,
                format!(
                    "object {}/{} has a generation that the official export format cannot preserve",
                    object.bucket.as_str(),
                    object.name.as_str()
                ),
            )
        })?;
        let metageneration = i64::try_from(object.metageneration).map_err(|_| {
            ArtifactError::new(
                "storage",
                &section_dir,
                format!(
                    "object {}/{} has a metageneration that the official export format cannot preserve",
                    object.bucket.as_str(),
                    object.name.as_str()
                ),
            )
        })?;
        let id = blob_id(object.bucket.as_str(), object.name.as_str(), generation);
        let blob_path = blobs_dir.join(&id);
        write_private_file(&blob_path, store.bytes(object))
            .map_err(|e| ArtifactError::new("storage", &blob_path, e))?;
        let document = ExportedObject {
            name: object.name.as_str().to_owned(),
            bucket: object.bucket.as_str().to_owned(),
            generation,
            metageneration,
            content_type: Some(object.content_type.clone()),
            storage_class: Some("STANDARD".to_owned()),
            download_tokens: object.download_tokens.clone(),
            etag: Some(object.etag()),
            time_created: Some(rfc3339_text(object.time_created)),
            updated: Some(rfc3339_text(object.updated)),
            size: object.size,
            md5_hash: Some(object.md5_base64()),
            crc32c: Some(object.crc32c.to_string()),
            cache_control: object.cache_control.clone(),
            content_disposition: object.content_disposition.clone(),
            content_encoding: object.content_encoding.clone(),
            content_language: object.content_language.clone(),
            custom_metadata: object
                .custom
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            extra: Vec::new(),
        };
        let metadata_path = metadata_dir.join(format!("{id}.json"));
        write_private_file(&metadata_path, document.to_json().as_bytes())
            .map_err(|e| ArtifactError::new("storage", &metadata_path, e))?;
    }

    let buckets_path = section_dir.join(BUCKETS_FILE);
    write_private_file(&buckets_path, BucketsFile { buckets }.to_json().as_bytes())
        .map_err(|e| ArtifactError::new("storage", &buckets_path, e))?;

    manifest.set(
        Product::Storage,
        Section {
            version: COMPATIBLE_CLI_VERSION.to_owned(),
            path: STORAGE_PATH.to_owned(),
            metadata_file: None,
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Overwrite protection and permissions
// ---------------------------------------------------------------------------------------

fn export_owns(name: &str) -> bool {
    EXPORT_OWNED_ENTRIES.contains(&name) || name.ends_with(".overall_export_metadata")
}

#[cfg(not(unix))]
fn copy_unmanaged_entries(source: &Path, destination: &Path) -> Result<(), String> {
    let mut budget = UnmanagedCopyBudget::new(
        EXPORT_UNMANAGED_TOTAL_BYTES_LIMIT,
        EXPORT_UNMANAGED_ENTRY_COUNT_LIMIT,
    );
    for entry in
        std::fs::read_dir(source).map_err(|e| format!("cannot read {}: {e}", source.display()))?
    {
        let entry = entry.map_err(|e| format!("cannot read an export entry: {e}"))?;
        let name = entry.file_name();
        let kind = entry
            .file_type()
            .map_err(|e| format!("cannot inspect {}: {e}", entry.path().display()))?;
        if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
            return Err(format!(
                "export entry {} is not a regular file or directory and will not be followed",
                entry.path().display()
            ));
        }
        if name.to_str().is_some_and(export_owns) {
            continue;
        }
        copy_unmanaged_entry(&entry.path(), &destination.join(name), 0, &mut budget)?;
    }
    Ok(())
}

struct UnmanagedCopyBudget {
    bytes_remaining: u64,
    entries_remaining: u64,
    byte_limit: u64,
    entry_limit: u64,
}

impl UnmanagedCopyBudget {
    const fn new(byte_limit: u64, entry_limit: u64) -> Self {
        Self {
            bytes_remaining: byte_limit,
            entries_remaining: entry_limit,
            byte_limit,
            entry_limit,
        }
    }

    fn claim_entry(&mut self, path: &Path) -> Result<(), String> {
        if self.entries_remaining == 0 {
            return Err(format!(
                "unmanaged export entries exceed the {} entry copy limit at {}",
                self.entry_limit,
                path.display()
            ));
        }
        self.entries_remaining -= 1;
        Ok(())
    }

    fn claim_bytes(&mut self, bytes: u64, path: &Path) -> Result<(), String> {
        if bytes > self.bytes_remaining {
            return Err(format!(
                "unmanaged export entries exceed the {} byte cumulative copy limit at {}",
                self.byte_limit,
                path.display()
            ));
        }
        self.bytes_remaining -= bytes;
        Ok(())
    }
}

#[cfg(not(unix))]
fn copy_unmanaged_entry(
    source: &Path,
    destination: &Path,
    depth: u32,
    budget: &mut UnmanagedCopyBudget,
) -> Result<(), String> {
    if depth > EXPORT_UNMANAGED_NESTING_DEPTH_LIMIT {
        return Err(format!(
            "unmanaged export entry {} exceeds the {} level copy depth limit",
            source.display(),
            EXPORT_UNMANAGED_NESTING_DEPTH_LIMIT
        ));
    }
    budget.claim_entry(source)?;
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|e| format!("cannot inspect {}: {e}", source.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "unmanaged export entry {} is a symlink, which an export never follows",
            source.display()
        ));
    }
    if metadata.file_type().is_dir() {
        create_private_dir(destination)?;
        for entry in std::fs::read_dir(source)
            .map_err(|e| format!("cannot read {}: {e}", source.display()))?
        {
            let entry = entry.map_err(|e| format!("cannot read an export entry: {e}"))?;
            copy_unmanaged_entry(
                &entry.path(),
                &destination.join(entry.file_name()),
                depth + 1,
                budget,
            )?;
        }
        return Ok(());
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "unmanaged export entry {} is not a regular file",
            source.display()
        ));
    }
    budget.claim_bytes(metadata.len(), source)?;
    copy_private_file(source, destination, metadata.len())
}

#[cfg(unix)]
fn open_unmanaged_directory(path: &Path) -> Result<std::fs::File, String> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| {
        format!(
            "cannot open {} without following links: {e}",
            path.display()
        )
    })?;
    Ok(std::fs::File::from(descriptor))
}

#[cfg(unix)]
fn copy_unmanaged_entries(source: &Path, destination: &Path) -> Result<(), String> {
    let directory = open_unmanaged_directory(source)?;
    let mut budget = UnmanagedCopyBudget::new(
        EXPORT_UNMANAGED_TOTAL_BYTES_LIMIT,
        EXPORT_UNMANAGED_ENTRY_COUNT_LIMIT,
    );
    copy_unmanaged_directory(&directory, source, destination, 0, true, &mut budget)
}

#[cfg(unix)]
fn copy_unmanaged_directory(
    directory: &std::fs::File,
    source_path: &Path,
    destination: &Path,
    depth: u32,
    top_level: bool,
    budget: &mut UnmanagedCopyBudget,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut entries = rustix::fs::Dir::read_from(directory)
        .map_err(|e| format!("cannot read {}: {e}", source_path.display()))?;
    while let Some(entry) = entries.read() {
        let entry = entry.map_err(|e| format!("cannot read an export entry: {e}"))?;
        let bytes = entry.file_name().to_bytes();
        if matches!(bytes, b"." | b"..") {
            continue;
        }
        let name = std::ffi::OsStr::from_bytes(bytes);
        if top_level && name.to_str().is_some_and(export_owns) {
            continue;
        }
        copy_unmanaged_entry_at(
            directory,
            name,
            &source_path.join(name),
            &destination.join(name),
            depth,
            budget,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn copy_unmanaged_entry_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    source_path: &Path,
    destination: &Path,
    depth: u32,
    budget: &mut UnmanagedCopyBudget,
) -> Result<(), String> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    if depth > EXPORT_UNMANAGED_NESTING_DEPTH_LIMIT {
        return Err(format!(
            "unmanaged export entry {} exceeds the {} level copy depth limit",
            source_path.display(),
            EXPORT_UNMANAGED_NESTING_DEPTH_LIMIT
        ));
    }
    budget.claim_entry(source_path)?;
    let descriptor = rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| {
        format!(
            "export entry {} is not a regular file or directory and will not be followed",
            source_path.display()
        )
    })?;
    let input = std::fs::File::from(descriptor);
    let metadata = input
        .metadata()
        .map_err(|e| format!("cannot inspect {}: {e}", source_path.display()))?;
    if metadata.file_type().is_dir() {
        create_private_dir(destination)?;
        return copy_unmanaged_directory(
            &input,
            source_path,
            destination,
            depth + 1,
            false,
            budget,
        );
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "export entry {} is not a regular file or directory and will not be followed",
            source_path.display()
        ));
    }
    if metadata.nlink() != 1 {
        return Err(format!(
            "export entry {} has multiple hard links and will not be copied",
            source_path.display()
        ));
    }
    budget.claim_bytes(metadata.len(), source_path)?;
    copy_private_file_from(input, source_path, destination, metadata.len())
}

#[cfg(all(unix, test))]
fn copy_unmanaged_entry(
    source: &Path,
    destination: &Path,
    depth: u32,
    budget: &mut UnmanagedCopyBudget,
) -> Result<(), String> {
    let parent_path = source
        .parent()
        .ok_or_else(|| "the unmanaged entry has no parent".to_owned())?;
    let name = source
        .file_name()
        .ok_or_else(|| "the unmanaged entry has no file name".to_owned())?;
    let parent = open_unmanaged_directory(parent_path)?;
    copy_unmanaged_entry_at(&parent, name, source, destination, depth, budget)
}

#[cfg(unix)]
fn copy_private_file_from(
    input: std::fs::File,
    source: &Path,
    destination: &Path,
    byte_limit: u64,
) -> Result<(), String> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .map_err(|e| format!("cannot write {}: {e}", destination.display()))?;
    let copied = std::io::copy(&mut input.take(byte_limit.saturating_add(1)), &mut output)
        .map_err(|e| format!("cannot copy {}: {e}", source.display()))?;
    if copied > byte_limit {
        return Err(format!(
            "unmanaged export entry {} grew while it was copied and exceeded its reserved budget",
            source.display()
        ));
    }
    output
        .flush()
        .map_err(|e| format!("cannot flush {}: {e}", destination.display()))
}

#[cfg(not(unix))]
fn copy_private_file(source: &Path, destination: &Path, byte_limit: u64) -> Result<(), String> {
    use std::io::{Read as _, Write as _};

    let input = std::fs::File::open(source)
        .map_err(|e| format!("cannot read {}: {e}", source.display()))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|e| format!("cannot write {}: {e}", destination.display()))?;
    let copied = std::io::copy(&mut input.take(byte_limit.saturating_add(1)), &mut output)
        .map_err(|e| format!("cannot copy {}: {e}", source.display()))?;
    if copied > byte_limit {
        return Err(format!(
            "unmanaged export entry {} grew while it was copied and exceeded its reserved budget",
            source.display()
        ));
    }
    output
        .flush()
        .map_err(|e| format!("cannot flush {}: {e}", destination.display()))
}

/// Whether `dir` may be overwritten by an export.
///
/// The official CLI refuses a non-empty target unless `--force` or `--export-on-exit` was
/// given (`controller.ts` `exportEmulatorData`). fireemu applies the stricter half of that
/// rule always: a directory is only overwritten when it already holds a
/// `firebase-export-metadata.json`, so `fireemu emulators:export ~/Documents` cannot
/// silently replace a directory that was never an export.
pub fn may_overwrite(dir: &Path) -> Result<(), String> {
    let metadata = match std::fs::symlink_metadata(dir) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot inspect {}: {e}", dir.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink, which an export never follows",
            dir.display()
        ));
    }
    if !metadata.file_type().is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let empty = std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false);
    let manifest_is_file = std::fs::symlink_metadata(dir.join(METADATA_FILE_NAME))
        .is_ok_and(|metadata| metadata.file_type().is_file());
    if empty || manifest_is_file {
        return Ok(());
    }
    Err(format!(
        "{} is not empty and holds no {METADATA_FILE_NAME}, so it is not an export directory; choose an empty or dedicated directory",
        dir.display()
    ))
}

/// Creates `dir` and every parent, owner-only.
///
/// The mode is set **as the directory is created**, not afterwards: a `create` followed by a
/// `chmod` leaves a window in which the directory is readable by everyone, and the whole
/// point of these two functions is that an Auth export is never readable by another user.
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("cannot create it: {e}"))?;
    // `recursive` leaves an existing directory alone, including one this run did not create;
    // an export directory being reused has to end up private too.
    set_mode(dir, 0o700)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create it: {e}"))
}

/// Writes a file owner-only, replacing what was there.
#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    // A file that is already there (or a symlink left in a reused directory) is removed
    // first and the new one created exclusively, so the write never follows a link.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot replace it: {e}")),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot write it: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write it: {e}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("cannot write it: {e}"))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("cannot restrict its permissions: {e}"))
}

/// The entries an export owns inside its directory: the metadata file and the product
/// sections (the official names plus the deferred products' sections).
const EXPORT_OWNED_ENTRIES: &[&str] = &[
    METADATA_FILE_NAME,
    "firestore_export",
    "auth_export",
    "storage_export",
    "database_export",
    "dataconnect_export",
];

#[cfg(test)]
mod tests {
    use super::{
        civil_from_days, days_from_civil, decode_base32, decode_base64,
        enforce_storage_object_count, may_overwrite, read_inside_budgeted, read_inside_limited,
        rfc3339_instant, rfc3339_text, scan_import_tree, UnmanagedCopyBudget,
        IMPORT_STORAGE_OBJECT_COUNT_LIMIT,
    };
    use fireemu_core_types::time::LogicalInstant;
    use fireemu_export_publication::PublicationStage;

    #[cfg(windows)]
    #[test]
    fn export_entry_fails_before_creating_a_destination_on_windows() {
        use std::sync::{Arc, Mutex, RwLock};

        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore};
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_rules::runtime::RulesetSlot;
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Conservative,
            },
            indexes: IndexSet::default(),
        };
        let backend = Arc::new(LocalBackend::new(gateway, clock.clone(), 7));
        let auth_store = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        )));
        let auth = Arc::new(AuthRegistry::new("demo-app", auth_store.clone()));
        let storage = Arc::new(fireemu_adapter_http::storage::StorageState {
            store: Mutex::new(fireemu_core_storage::store::StorageState::new(9)),
            clock: clock.clone(),
            auth: auth.clone(),
            tenancy: None,
            rules: Arc::new(RulesetSlot::default()),
            project: "demo-app".to_owned(),
            events: None,
            barrier: None,
            firestore: None,
            faults: None,
            clock_observer: None,
            app_check_policy: None,
            admin_capability: None,
            token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
        });
        let endpoints = super::Endpoints {
            backend: &backend,
            auth: &auth,
            storage: &storage,
            clock: &clock,
            project: "demo-app",
        };
        let root = std::env::temp_dir().join(format!(
            "fireemu-windows-export-entry-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let target = root.join("export");

        let error = super::export(
            &target,
            super::Products {
                firestore: false,
                auth: false,
                storage: false,
            },
            &endpoints,
            "test",
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("unavailable on Windows"),
            "{error}"
        );
        assert!(!root.exists());
    }

    fn budget_dir(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fireemu-import-budget-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn cumulative_and_per_file_import_limits_hold_at_the_boundary() {
        let root = budget_dir("bytes");
        std::fs::write(root.join("one"), b"12").unwrap();
        std::fs::write(root.join("two"), b"345").unwrap();
        scan_import_tree(&root, &root, "test", 5, 2, 0, Some(3)).unwrap();

        std::fs::write(root.join("two"), b"3456").unwrap();
        let per_file = scan_import_tree(&root, &root, "test", 6, 2, 0, Some(3)).unwrap_err();
        assert!(per_file.message.contains("per-file import limit"));
        let cumulative = scan_import_tree(&root, &root, "test", 5, 2, 0, None).unwrap_err();
        assert!(cumulative.message.contains("cumulative import limit"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn descriptor_bound_reader_refuses_a_sparse_file_before_reading_it() {
        let root = budget_dir("sparse-read");
        let path = root.join("sparse");
        std::fs::File::create(&path).unwrap().set_len(9).unwrap();

        let error = read_inside_limited(&root, &path, 8).unwrap_err();

        assert!(error.contains("8 byte per-file import limit"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn descriptor_bound_budget_is_shared_across_multiple_files() {
        let root = budget_dir("shared-read-budget");
        let first = root.join("first");
        let second = root.join("second");
        std::fs::write(&first, b"123").unwrap();
        std::fs::write(&second, b"456").unwrap();
        let mut remaining = 5;

        assert_eq!(
            read_inside_budgeted(&root, &first, &mut remaining, 5, 5, "output files").unwrap(),
            b"123"
        );
        let error =
            read_inside_budgeted(&root, &second, &mut remaining, 5, 5, "output files").unwrap_err();

        assert!(error.contains("output files exceed the 5 byte cumulative import limit"));
        assert_eq!(remaining, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unmanaged_copy_budget_is_checked_before_copying_the_next_file() {
        let root = budget_dir("unmanaged-copy-budget");
        let source = root.join("source");
        let destination = root.join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(source.join("first"), b"123").unwrap();
        std::fs::write(source.join("second"), b"456").unwrap();
        let mut budget = UnmanagedCopyBudget::new(5, 2);

        super::copy_unmanaged_entry(
            &source.join("first"),
            &destination.join("first"),
            0,
            &mut budget,
        )
        .unwrap();
        let error = super::copy_unmanaged_entry(
            &source.join("second"),
            &destination.join("second"),
            0,
            &mut budget,
        )
        .unwrap_err();

        assert!(error.contains("5 byte cumulative copy limit"));
        assert!(!destination.join("second").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn unmanaged_copy_traverses_the_opened_directory_not_a_replaced_path() {
        use std::os::unix::fs::symlink;

        let root = budget_dir("unmanaged-descriptor-traversal");
        let source = root.join("source");
        let moved = root.join("moved");
        let outside = root.join("outside");
        let destination = root.join("destination");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(source.join("entry"), b"inside").unwrap();
        std::fs::write(outside.join("entry"), b"outside").unwrap();
        let descriptor = super::open_unmanaged_directory(&source).unwrap();
        std::fs::rename(&source, &moved).unwrap();
        symlink(&outside, &source).unwrap();
        let mut budget = UnmanagedCopyBudget::new(64, 4);

        super::copy_unmanaged_directory(&descriptor, &source, &destination, 0, false, &mut budget)
            .unwrap();

        assert_eq!(std::fs::read(destination.join("entry")).unwrap(), b"inside");
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn many_small_files_and_deep_trees_hit_stable_import_limits() {
        let root = budget_dir("shape");
        for name in ["one", "two", "three"] {
            std::fs::write(root.join(name), b"x").unwrap();
        }
        let entries = scan_import_tree(&root, &root, "test", 3, 2, 0, None).unwrap_err();
        assert!(entries.message.contains("directory-entry import limit"));

        for name in ["one", "two", "three"] {
            std::fs::remove_file(root.join(name)).unwrap();
        }
        std::fs::create_dir_all(root.join("one/two")).unwrap();
        let depth = scan_import_tree(&root, &root, "test", 0, 10, 1, None).unwrap_err();
        assert!(depth.message.contains("nesting-depth import limit"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn storage_object_count_accepts_the_boundary_and_rejects_one_more() {
        let path = std::path::Path::new("storage_export/metadata");
        enforce_storage_object_count(IMPORT_STORAGE_OBJECT_COUNT_LIMIT, path).unwrap();
        let error =
            enforce_storage_object_count(IMPORT_STORAGE_OBJECT_COUNT_LIMIT + 1, path).unwrap_err();
        assert!(error.message.contains("object import limit"));
    }

    #[cfg(unix)]
    #[test]
    fn special_files_are_not_import_artifacts() {
        // macOS limits Unix-domain socket paths to roughly one hundred bytes, while its
        // per-user temporary directory is already long. Use the conventional short temp root.
        let root = std::path::PathBuf::from(format!(
            "/tmp/fireemu-import-special-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
        let error = scan_import_tree(&root, &root, "test", 0, 1, 0, None).unwrap_err();
        assert!(error.message.contains("not a regular file"));
        drop(socket);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn an_rfc_3339_timestamp_round_trips_through_the_instant() {
        for text in [
            "1970-01-01T00:00:00.000Z",
            "2026-08-30T15:58:33.194Z",
            "2000-02-29T23:59:59.999Z",
            "1999-12-31T23:59:59.000Z",
        ] {
            let at = rfc3339_instant(Some(text)).expect("it parses");
            assert_eq!(rfc3339_text(at), text, "{text} round trips");
        }
    }

    #[test]
    fn the_civil_calendar_helpers_are_inverses() {
        for days in [-25_000i64, -1, 0, 1, 19_000, 25_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "day {days} round trips");
        }
    }

    #[test]
    fn a_malformed_timestamp_is_not_parsed() {
        assert!(rfc3339_instant(None).is_none());
        assert!(rfc3339_instant(Some("yesterday")).is_none());
        assert!(rfc3339_instant(Some("2026-08-30")).is_none());
    }

    #[test]
    fn base64_and_base32_decode_the_spellings_the_export_uses() {
        assert_eq!(
            decode_base64("DFKqKz9JSntkXcjLkQABSQ==").map(|b| b.len()),
            Some(16)
        );
        assert_eq!(decode_base64(""), Some(Vec::new()));
        assert_eq!(decode_base64("!!!"), None);
        assert_eq!(
            decode_base32("JBSWY3DPEHPK3PXP"),
            Some(b"Hello!\xde\xad\xbe\xef".to_vec())
        );
        assert_eq!(decode_base32("1"), None);
    }

    #[test]
    fn an_instant_before_the_epoch_still_formats() {
        let at = LogicalInstant::from_unix_seconds(-1);
        assert_eq!(rfc3339_text(at), "1969-12-31T23:59:59.000Z");
    }

    #[test]
    fn overwrite_protection_accepts_only_an_absent_empty_or_export_directory() {
        let base = std::env::temp_dir().join(format!("fireemu-export-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        assert!(may_overwrite(&base.join("absent")).is_ok());

        let empty = base.join("empty");
        std::fs::create_dir_all(&empty).expect("the directory is created");
        assert!(may_overwrite(&empty).is_ok());

        let occupied = base.join("occupied");
        std::fs::create_dir_all(&occupied).expect("the directory is created");
        std::fs::write(occupied.join("notes.txt"), "keep me").expect("the file is written");
        assert!(may_overwrite(&occupied).is_err());

        std::fs::write(occupied.join(super::METADATA_FILE_NAME), "{}")
            .expect("the manifest is written");
        assert!(may_overwrite(&occupied).is_ok());

        let file = base.join("a-file");
        std::fs::write(&file, "x").expect("the file is written");
        assert!(may_overwrite(&file).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_authorization_is_bound_to_the_captured_target_identity() {
        let base = budget_dir("overwrite-identity");
        let target = base.join("export");

        let error = PublicationStage::create(&target, |checked| {
            may_overwrite(checked)?;
            std::fs::create_dir(checked).map_err(|error| error.to_string())?;
            std::fs::write(checked.join("notes.txt"), "preserve")
                .map_err(|error| error.to_string())?;
            Ok(())
        })
        .unwrap_err();

        assert!(error.contains("overwrite policy was checked"), "{error}");
        assert_eq!(
            std::fs::read_to_string(target.join("notes.txt")).unwrap(),
            "preserve"
        );
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(base);
    }
}
