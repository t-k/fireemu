//! Official Local Emulator Suite import and export, between an export directory and the
//! live daemon.
//!
//! [`fireemu_core_export`] owns the artifact format; this module owns the two seams to a
//! running suite:
//!
//! - **import** ([`prepare`] then [`apply`]) reads every section of the selected products
//!   into memory first and only then installs them, all at once, under the exclusive
//!   [`AdmissionBarrier`]. Nothing is written until every product has parsed, so a malformed
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
    let manifest_path = dir.join(METADATA_FILE_NAME);
    let text = std::fs::read_to_string(&manifest_path).map_err(|e| {
        ArtifactError::new("import", &manifest_path, format!("cannot read it: {e}"))
    })?;
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
                let documents = read_firestore_section(dir, section)?;
                collect_documents(
                    &mut databases,
                    documents,
                    DEFAULT_DATABASE,
                    &mut prepared.notices,
                    project,
                )?;
                for (database, named) in manifest.named_databases() {
                    let documents = read_firestore_section(dir, named)?;
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

/// Reads a file the artifact names, refusing anything that resolves outside the export
/// directory: a symlink inside a crafted export must never make an import read an arbitrary
/// file on the host (and then serve it as an object).
fn read_inside(root: &Path, path: &Path) -> Result<Vec<u8>, String> {
    // A link inside the export is refused as well: the official CLI never writes one, and a
    // link would let one file be named under many names past the per-name bounds. The
    // canonicalized containment below stays, because this leaf check does not see a link
    // in an intermediate directory component. Hard links and a concurrent swap between the
    // check and the read are outside the threat model (a static, distributed artifact).
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("it is a symlink, which an import never follows".to_owned());
    }
    let root = std::fs::canonicalize(root).map_err(|e| format!("cannot resolve it: {e}"))?;
    let real = std::fs::canonicalize(path).map_err(|e| format!("cannot read it: {e}"))?;
    if !real.starts_with(&root) {
        return Err(
            "it resolves outside the export directory (a symlink?), which an import never follows"
                .to_owned(),
        );
    }
    std::fs::read(&real).map_err(|e| format!("cannot read it: {e}"))
}

fn read_text_inside(root: &Path, path: &Path) -> Result<String, String> {
    let bytes = read_inside(root, path)?;
    String::from_utf8(bytes).map_err(|_| "it is not UTF-8".to_owned())
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
) -> Result<Vec<ExportDocument>, ArtifactError> {
    let metadata_file = section
        .metadata_file
        .clone()
        .unwrap_or_else(|| format!("{}/{FIRESTORE_OVERALL_METADATA}", section.path));
    let overall_path = dir.join(&metadata_file);
    let bytes = read_inside(dir, &overall_path)
        .map_err(|e| ArtifactError::new("firestore", &overall_path, e))?;
    let overall = OverallMetadata::parse(&bytes)
        .map_err(|e| ArtifactError::new("firestore", &overall_path, e.to_string()))?;

    let section_dir = dir.join(&section.path);
    let partition_path = section_dir.join(&overall.metadata_file);
    let bytes = read_inside(dir, &partition_path)
        .map_err(|e| ArtifactError::new("firestore", &partition_path, e))?;
    let partition = PartitionMetadata::parse(&bytes)
        .map_err(|e| ArtifactError::new("firestore", &partition_path, e.to_string()))?;

    let partition_dir = partition_path
        .parent()
        .map_or_else(|| section_dir.clone(), Path::to_path_buf);
    let mut documents = Vec::new();
    let mut read_so_far: u64 = 0;
    for output in &partition.output_files {
        let output_path = partition_dir.join(output);
        let bytes = read_inside(dir, &output_path)
            .map_err(|e| ArtifactError::new("firestore", &output_path, e))?;
        read_so_far = read_so_far.saturating_add(bytes.len() as u64);
        if read_so_far > IMPORT_FIRESTORE_BYTES_BUDGET {
            return Err(ArtifactError::new(
                "firestore",
                &output_path,
                format!("the output files exceed the {IMPORT_FIRESTORE_BYTES_BUDGET} byte import budget"),
            ));
        }
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

fn read_auth_section(dir: &Path, section: &Section) -> Result<PreparedAuth, ArtifactError> {
    let section_dir = dir.join(&section.path);
    let config_path = section_dir.join(CONFIG_FILE);
    let config = match std::fs::symlink_metadata(&config_path)
        .map_err(|e| e.to_string())
        .and_then(|_| read_text_inside(dir, &config_path))
    {
        Ok(text) => {
            let parsed = AuthConfig::parse(&text)
                .map_err(|e| ArtifactError::new("auth", &config_path, e.to_string()))?;
            ProjectAuthConfig {
                allow_duplicate_emails: parsed.allow_duplicate_emails,
                enable_improved_email_privacy: parsed.enable_improved_email_privacy,
            }
        }
        Err(_) => ProjectAuthConfig::default(),
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
            let text = read_text_inside(dir, &entry.path())
                .map_err(|e| ArtifactError::new("auth", entry.path(), e))?;
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
    let text = read_text_inside(dir, &accounts_path)
        .map_err(|e| ArtifactError::new("auth", &accounts_path, e))?;
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

fn read_storage_section(dir: &Path, section: &Section) -> Result<PreparedStorage, ArtifactError> {
    let section_dir = dir.join(&section.path);
    let buckets_path = section_dir.join(BUCKETS_FILE);
    let text = read_text_inside(dir, &buckets_path)
        .map_err(|e| ArtifactError::new("storage", &buckets_path, e))?;
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
    let mut identities = BTreeSet::new();
    for path in paths {
        let text =
            read_text_inside(dir, &path).map_err(|e| ArtifactError::new("storage", &path, e))?;
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
        let bytes = read_inside(dir, &blob_path).map_err(|e| {
            ArtifactError::new(
                "storage",
                &blob_path,
                format!(
                    "the object {} names a blob that cannot be read: {e}",
                    meta.name
                ),
            )
        })?;
        objects.push((imported_object(&meta, &path)?, bytes));
    }
    Ok((objects, buckets.buckets))
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

/// Whether `dir` may be overwritten by an export.
///
/// The official CLI refuses a non-empty target unless `--force` or `--export-on-exit` was
/// given (`controller.ts` `exportEmulatorData`). fireemu applies the stricter half of that
/// rule always: a directory is only overwritten when it already holds a
/// `firebase-export-metadata.json`, so `fireemu emulators:export ~/Documents` cannot
/// silently replace a directory that was never an export.
pub fn may_overwrite(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let empty = std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false);
    if empty || dir.join(METADATA_FILE_NAME).is_file() {
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

/// Removes an existing export's own entries before a new export replaces it, so a document
/// that no longer exists does not survive in the directory. Only the entries an export
/// owns go: a README or a fixture script next to them stays (the official CLI exports over
/// the `--import` directory by default, and that directory is often a checked-in fixture).
pub fn clear_export_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        let owned = entry.file_name().to_str().is_some_and(|n| {
            EXPORT_OWNED_ENTRIES.contains(&n) || n.ends_with(".overall_export_metadata")
        });
        if !owned {
            continue;
        }
        // `symlink_metadata` rather than `is_dir`: a symlink that points at a directory must
        // be unlinked, never descended into. Descending would delete whatever it aims at.
        let kind = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?
            .file_type();
        let result = if kind.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        result.map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        civil_from_days, days_from_civil, decode_base32, decode_base64, may_overwrite,
        rfc3339_instant, rfc3339_text,
    };
    use fireemu_core_types::time::LogicalInstant;

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
}
