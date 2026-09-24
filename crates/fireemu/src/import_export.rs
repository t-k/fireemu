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
use fireemu_core_auth::password_policy::{EnforcementState, PasswordPolicy};
use fireemu_core_auth::signup_quota::{
    QuotaAlgorithm, QuotaMode, SignupQuotaConfig, TemporaryQuota,
};
use fireemu_core_auth::store::{
    AuthNamespaceConfigPatch, AuthRegistry, AuthStore, FederatedIdentity, ImportedUser,
    ProjectAuthConfig, Provider, TenantMetadata,
};
use fireemu_core_export::auth::{
    fake_hash, AccountsFile, AuthConfig, AuthSettings, AuthSettingsNamespace, AuthSettingsRecord,
    BlockingAuthForwardingRecord, BlockingAuthSelectionRecord, BlockingAuthSettingsRecord,
    MfaEnrollment, PasswordPolicies, PasswordPolicyNamespace, PasswordPolicyRecord,
    ProviderUserInfo, QuotaSettingsRecord, TemporaryQuotaRecord, TenantMetadataRecord, UserRecord,
    ACCOUNTS_FILE, AUTH_SETTINGS_FILE, CONFIG_FILE, PASSWORD_POLICIES_FILE,
};
use fireemu_core_export::firestore::{
    for_each_output, write_output_to, ExportDocument, OverallMetadata, PartitionMetadata,
    EXPORT_NAME, OUTPUT_FILE, PARTITION_DIR, PARTITION_METADATA,
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
use fireemu_core_types::time::{civil_from_days, LogicalDuration, LogicalInstant};
use fireemu_export_publication::PublicationStage;

use crate::config::Selection;

#[cfg(all(test, unix))]
#[path = "../../../tests/support/trusted_temp.rs"]
pub(crate) mod trusted_temp;

/// The CLI version an export manifest is stamped with. The official emulator writes the
/// `firebase-tools` version here; fireemu writes the version it is compatible with, so that
/// a directory fireemu produced is accepted by the official CLI's own version checks, and
/// records its own version in the extension section.
pub const COMPATIBLE_CLI_VERSION: &str = "15.28.2";

/// The Firestore emulator version the official manifest names for the Firestore section.
pub const COMPATIBLE_FIRESTORE_VERSION: &str = "1.22.0";

/// The default database, which the official Firestore section carries.
const DEFAULT_DATABASE: &str = DatabaseId::DEFAULT;
const BLOCKING_DISCOVERY_EVENTS_MEMBER: &str = "__fireemuDiscoveryEvents";

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
    /// The optional runtime-owned Blocking Auth bridge. Only its logical project settings cross
    /// the export seam; runner addresses, ports and secrets stay in the live runtime.
    pub blocking: Option<&'a dyn fireemu_adapter_http::identity_toolkit::AuthBlockingHook>,
    /// Adapter-level Auth settings gate shared with project configuration and blocking requests.
    /// Export captures Auth stores and blocking settings while this gate is held, then releases
    /// it before serializing files.
    pub auth_operation_gate: Option<&'a Arc<Mutex<()>>>,
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

struct FirestorePartition {
    overall: OverallMetadata,
    metadata_path: PathBuf,
    metadata: PartitionMetadata,
    directory: PathBuf,
}

/// The default accounts, project configuration and isolated tenant accounts of the Auth
/// section.
#[derive(Debug, Default)]
struct PreparedAuth {
    users: Vec<ImportedUser>,
    /// `passwordUpdatedAt` per imported account and tenant namespace, restored after the account
    /// is imported so a lookup answers what the artifact recorded.
    password_updated_at: BTreeMap<(Option<String>, String), LogicalInstant>,
    config: ProjectAuthConfig,
    /// Whether each client permission was explicitly declared in `config.json`. An old
    /// official artifact must not turn an already configured runtime switch off.
    client_permissions_declared: (bool, bool),
    /// Whether the artifact declared `emailPrivacyConfig.enableImprovedEmailPrivacy`. When it
    /// did not (the official emulator's export without the key, or no config.json at all),
    /// the running store's setting is kept: an import must not switch the protection off.
    email_privacy_declared: bool,
    /// Whether `signIn.allowDuplicateEmails` was explicitly declared in `config.json`.
    allow_duplicate_emails_declared: bool,
    /// The optional fireemu-only password policy sidecar. The official Auth export has no
    /// equivalent, so a missing sidecar leaves the running policy unchanged.
    password_policies: Option<PasswordPolicies>,
    /// Optional fireemu-only namespace settings. The sidecar carries quota configuration and
    /// explicit tenant projections; usage buckets are never serialized.
    auth_settings: Option<AuthSettings>,
    tenants: BTreeMap<String, Vec<ImportedUser>>,
}

#[cfg(test)]
fn preflight_auth_tenant_stores(auth: &AuthRegistry, project: &str) -> Result<(), ArtifactError> {
    for tenant in auth.tenants(project) {
        let Some(tenant_store) = auth.tenant_store(project, &tenant) else {
            return Err(ArtifactError::new(
                "auth",
                PathBuf::from(AUTH_PATH),
                format!("tenant {tenant:?} disappeared during import preflight"),
            ));
        };
        let _tenant_guard = tenant_store.lock().map_err(|_| {
            ArtifactError::new(
                "auth",
                PathBuf::from(AUTH_PATH),
                format!("tenant {tenant:?} store is poisoned"),
            )
        })?;
    }
    Ok(())
}

impl PreparedAuth {
    /// The configuration to install over `current`.
    fn config_over(&self, current: ProjectAuthConfig) -> ProjectAuthConfig {
        ProjectAuthConfig {
            enable_improved_email_privacy: if self.email_privacy_declared {
                self.config.enable_improved_email_privacy
            } else {
                current.enable_improved_email_privacy
            },
            disabled_user_signup: if self.client_permissions_declared.0 {
                self.config.disabled_user_signup
            } else {
                current.disabled_user_signup
            },
            disabled_user_deletion: if self.client_permissions_declared.1 {
                self.config.disabled_user_deletion
            } else {
                current.disabled_user_deletion
            },
            allow_duplicate_emails: if self.allow_duplicate_emails_declared {
                self.config.allow_duplicate_emails
            } else {
                current.allow_duplicate_emails
            },
        }
    }
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
    /// The Firestore time-to-live field configuration, from the fireemu-only sidecar. The
    /// official export format has no equivalent section, so an artifact without the sidecar
    /// leaves the running configuration unchanged.
    firestore_field_config:
        Option<BTreeMap<(String, String), fireemu_core_firestore::ttl::TtlCatalog>>,
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
                read_firestore_section(
                    dir,
                    section,
                    &mut remaining_bytes,
                    &mut databases,
                    DEFAULT_DATABASE,
                    &mut prepared.notices,
                    project,
                )?;
                for (database, named) in manifest.named_databases() {
                    read_firestore_section(
                        dir,
                        named,
                        &mut remaining_bytes,
                        &mut databases,
                        database,
                        &mut prepared.notices,
                        project,
                    )?;
                }
                prepared.firestore = Some(databases);
                prepared.firestore_field_config = read_field_config(dir)?;
            }
            Product::Auth => prepared.auth = Some(read_auth_section(dir, section, project)?),
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
pub fn apply(mut prepared: Prepared, endpoints: &Endpoints) -> Result<(), ArtifactError> {
    let now = endpoints.now();
    let barrier = endpoints.backend.barrier();
    let _exclusive = barrier.exclusive();

    if let Some(databases) = prepared.firestore.take() {
        let mut snapshot = FirestoreSnapshot {
            databases: BTreeMap::new(),
            ids: None,
        };
        for (key, documents) in databases {
            let mut state = FirestoreState::new();
            state.set_index_catalog(
                endpoints
                    .backend
                    .indexes_for_project_database(&key.0, &key.1),
            );
            state.import_documents(documents, now).map_err(|e| {
                ArtifactError::new(
                    "firestore",
                    PathBuf::from(FIRESTORE_PATH),
                    format!("database {}/{}: {e}", key.0, key.1),
                )
            })?;
            snapshot.databases.insert(key.clone(), state);
        }
        endpoints
            .backend
            .restore_databases(snapshot.databases)
            .map_err(|error| {
                ArtifactError::new(
                    "firestore",
                    PathBuf::from(FIRESTORE_PATH),
                    error.to_string(),
                )
            })?;
        if let Some(catalogs) = prepared.firestore_field_config.take() {
            endpoints
                .backend
                .restore_ttl_catalogs(|_project| true, &catalogs);
        }
    }

    if let Some(auth) = prepared.auth.take() {
        apply_auth(&auth, endpoints)?;
    }

    if let Some((objects, _)) = prepared.storage.take() {
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
            store.insert_imported(object, bytes).map_err(|e| {
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

#[allow(clippy::too_many_lines)]
fn apply_auth(auth: &PreparedAuth, endpoints: &Endpoints) -> Result<(), ArtifactError> {
    let policy_path = PathBuf::from(AUTH_PATH).join(PASSWORD_POLICIES_FILE);
    let mut current_tenant_policies = BTreeMap::new();
    for tenant in endpoints.auth.tenants(endpoints.project) {
        let tenant_store = endpoints
            .auth
            .tenant_store(endpoints.project, &tenant)
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    &policy_path,
                    format!("tenant {tenant:?} disappeared during policy preflight"),
                )
            })?;
        let policy = tenant_store
            .lock()
            .map_err(|_| {
                ArtifactError::new(
                    "auth",
                    &policy_path,
                    format!("tenant {tenant:?} store is poisoned"),
                )
            })?
            .password_policy()
            .clone();
        current_tenant_policies.insert(tenant, policy);
    }
    let imported_project_policy = auth
        .password_policies
        .as_ref()
        .filter(|policies| policies.project_id == endpoints.project)
        .map(|policies| imported_password_policy(&policies.project, &policy_path))
        .transpose()?;
    let settings_path = PathBuf::from(AUTH_PATH).join(AUTH_SETTINGS_FILE);
    let imported_project_quota = auth
        .auth_settings
        .as_ref()
        .filter(|settings| settings.project_id == endpoints.project)
        .and_then(|settings| settings.project.quota.as_ref())
        .map(|quota| imported_quota_settings(quota, &settings_path))
        .transpose()?;
    let imported_project_blocking = auth
        .auth_settings
        .as_ref()
        .filter(|settings| settings.project_id == endpoints.project)
        .and_then(|settings| settings.project.blocking.as_ref())
        .map(blocking_settings_json);
    if let Some(settings) = &imported_project_blocking {
        let Some(blocking) = endpoints.blocking else {
            return Err(ArtifactError::new(
                "auth",
                &settings_path,
                "blocking settings require a running owned Functions runtime",
            ));
        };
        blocking
            .validate_blocking_auth_settings(settings)
            .map_err(|error| ArtifactError::new("auth", &settings_path, error))?;
    }
    // Build the replacement in memory first. `import_user_trusted` can still reject a
    // syntactically valid record (for example, duplicate IDs or emails); doing this before
    // clearing the live store keeps the import atomic across all account records.
    let mut default_candidate = {
        let store = endpoints.auth.default_store();
        let store = store.lock().map_err(|_| {
            ArtifactError::new(
                "auth",
                PathBuf::from(AUTH_PATH),
                "the Auth store is poisoned",
            )
        })?;
        let mut candidate = store.clone();
        candidate.clear();
        candidate.set_config(auth.config_over(store.config()));
        if let Some(policy) = &imported_project_policy {
            candidate.set_password_policy(policy.clone());
        }
        if let Some(quota) = &imported_project_quota {
            candidate
                .set_signup_quota_config(quota.clone())
                .map_err(|error| {
                    ArtifactError::new(
                        "auth",
                        &settings_path,
                        format!("the Auth settings quota is invalid: {error:?}"),
                    )
                })?;
        }
        install_auth_users(
            &mut candidate,
            &auth.users,
            &auth.password_updated_at,
            None,
            Path::new(ACCOUNTS_FILE),
        )?;
        candidate
    };
    let default_config = default_candidate.config();
    let mut tenant_candidates = Vec::with_capacity(auth.tenants.len());
    let mut imported_tenant_config_overrides = BTreeMap::new();
    for (tenant, users) in &auth.tenants {
        let mut candidate = endpoints
            .auth
            .tenant_import_candidate(endpoints.project, tenant)
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    PathBuf::from(AUTH_PATH),
                    format!("cannot prepare tenant {tenant:?}"),
                )
            })?;
        candidate.clear();
        candidate.set_config(tenant_config_from_settings(
            settings_for_tenant(auth.auth_settings.as_ref(), endpoints.project, tenant),
            auth.config_over(default_config),
        ));
        let mut metadata =
            settings_for_tenant(auth.auth_settings.as_ref(), endpoints.project, tenant)
                .and_then(|settings| settings.metadata.as_ref())
                .map_or_else(
                    || TenantMetadata {
                        allow_password_signup: true,
                        enable_email_link_signin: true,
                        enable_anonymous_user: true,
                        ..TenantMetadata::default()
                    },
                    imported_tenant_metadata,
                );
        if let Some(settings) =
            settings_for_tenant(auth.auth_settings.as_ref(), endpoints.project, tenant)
        {
            if settings.config_is_explicit {
                if let Some(config) = &settings.settings.config {
                    let config_patch = auth_namespace_config_patch(config);
                    if !config_patch.is_empty() {
                        imported_tenant_config_overrides.insert(tenant.clone(), config_patch);
                    }
                    metadata.disabled_user_signup = config
                        .disabled_user_signup
                        .unwrap_or(metadata.disabled_user_signup);
                    metadata.disabled_user_deletion = config
                        .disabled_user_deletion
                        .unwrap_or(metadata.disabled_user_deletion);
                    metadata.enable_improved_email_privacy = config
                        .enable_improved_email_privacy
                        .unwrap_or(metadata.enable_improved_email_privacy);
                }
            } else {
                // Version 1 sidecars carried an effective tenant projection without recording
                // whether it was an explicit override. Migrate that ambiguous projection as
                // inherited: both the store and metadata must start from the imported project
                // configuration so they cannot disagree until a later project update.
                let inherited = candidate.config();
                metadata.disabled_user_signup = inherited.disabled_user_signup;
                metadata.disabled_user_deletion = inherited.disabled_user_deletion;
                metadata.enable_improved_email_privacy = inherited.enable_improved_email_privacy;
            }
            if let Some(quota) = &settings.settings.quota {
                candidate
                    .set_signup_quota_config(imported_quota_settings(quota, &settings_path)?)
                    .map_err(|error| {
                        ArtifactError::new(
                            "auth",
                            &settings_path,
                            format!("the Auth settings quota is invalid: {error:?}"),
                        )
                    })?;
            }
        }
        let fallback = current_tenant_policies
            .get(tenant)
            .cloned()
            .unwrap_or_default();
        candidate.set_password_policy(password_policy_for_tenant(
            auth.password_policies.as_ref(),
            endpoints.project,
            tenant,
            &fallback,
            &policy_path,
        )?);
        install_auth_users(
            &mut candidate,
            users,
            &auth.password_updated_at,
            Some(tenant),
            Path::new(&format!("accounts-{tenant}.json")),
        )?;
        let _ = candidate.take_user_events();
        tenant_candidates.push((tenant.clone(), candidate, metadata));
    }
    let _ = default_candidate.take_user_events();

    // Blocked Auth settings and imported accounts share one publication boundary. Capture the
    // bridge state before making either side visible so a failure in either commit can restore
    // the other side. Updating the bridge first is important: an update failure must leave the
    // live Auth registry untouched, rather than publishing users and config before discovering
    // that the Functions target cannot accept the imported settings.
    let blocking_snapshot = if imported_project_blocking.is_some() {
        let blocking = endpoints.blocking.ok_or_else(|| {
            ArtifactError::new(
                "auth",
                &settings_path,
                "blocking settings require a running owned Functions runtime",
            )
        })?;
        let snapshot = blocking
            .blocking_auth_settings_snapshot()
            .map_err(|error| ArtifactError::new("auth", &settings_path, error))?
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    &settings_path,
                    "blocking settings cannot be imported without a rollback snapshot",
                )
            })?;
        Some(snapshot)
    } else {
        None
    };
    if let Some(settings) = imported_project_blocking.as_ref() {
        let blocking = endpoints.blocking.ok_or_else(|| {
            ArtifactError::new(
                "auth",
                &settings_path,
                "blocking settings require a running owned Functions runtime",
            )
        })?;
        if let Err(error) = blocking.update_blocking_auth_settings(settings) {
            let restore_error = blocking_snapshot.as_ref().and_then(|snapshot| {
                restore_blocking_settings_if_unchanged(blocking, snapshot, settings).err()
            });
            let message = match restore_error {
                Some(restore_error) => {
                    format!("{error}; restoring previous blocking settings failed: {restore_error}")
                }
                None => error,
            };
            return Err(ArtifactError::new("auth", &settings_path, message));
        }
    }

    if let Err(error) = endpoints.auth.replace_default_scope_with_config_overrides(
        endpoints.project,
        default_candidate,
        tenant_candidates,
        &imported_tenant_config_overrides,
    ) {
        if let (Some(snapshot), Some(blocking)) = (blocking_snapshot.as_ref(), endpoints.blocking) {
            if let Err(restore_error) = restore_blocking_settings_if_unchanged(
                blocking,
                snapshot,
                imported_project_blocking
                    .as_ref()
                    .expect("blocking settings are present when a snapshot is captured"),
            ) {
                return Err(ArtifactError::new(
                    "auth",
                    PathBuf::from(AUTH_PATH),
                    format!(
                        "{error}; restoring previous blocking settings failed: {restore_error}"
                    ),
                ));
            }
        }
        return Err(ArtifactError::new("auth", PathBuf::from(AUTH_PATH), error));
    }
    Ok(())
}

/// Restores an import's previous Blocking Auth projection only while the imported projection is
/// still current. [`AuthBlockingHook`] exposes snapshots and unconditional restore, but no
/// generation or compare-and-swap operation. The comparison avoids overwriting a concurrent
/// settings update in the usual interleaving; a hook implementation needs a generation-aware
/// API to make this boundary fully atomic against a writer that races after the comparison.
fn restore_blocking_settings_if_unchanged(
    blocking: &dyn fireemu_adapter_http::identity_toolkit::AuthBlockingHook,
    snapshot: &serde_json::Value,
    imported: &serde_json::Value,
) -> Result<(), String> {
    let current = blocking
        .blocking_auth_settings_snapshot()?
        .ok_or_else(|| "blocking settings have no rollback snapshot".to_owned())?;
    if current == *snapshot {
        return Ok(());
    }
    if current != *imported {
        return Err(
            "blocking settings changed during import; refusing a stale rollback".to_owned(),
        );
    }
    blocking.restore_blocking_auth_settings_snapshot(snapshot)
}

#[cfg(test)]
mod blocking_rollback_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use fireemu_adapter_http::identity_toolkit::{AuthBlockingHook, BlockingFunctionFailure};
    use serde_json::Value;

    struct MutableBlockingHook {
        settings: Mutex<Value>,
        restore_calls: AtomicUsize,
    }

    impl AuthBlockingHook for MutableBlockingHook {
        fn invoke(
            &self,
            _event: fireemu_core_functions::manifest::BlockingAuthEvent,
            _user: &fireemu_core_auth::store::UserRecord,
        ) -> Result<Value, BlockingFunctionFailure> {
            Err(BlockingFunctionFailure::unhandled())
        }

        fn blocking_auth_settings(&self) -> Option<Value> {
            self.settings.lock().ok().map(|settings| settings.clone())
        }

        fn blocking_auth_settings_snapshot(&self) -> Result<Option<Value>, String> {
            Ok(self.blocking_auth_settings())
        }

        fn restore_blocking_auth_settings_snapshot(&self, snapshot: &Value) -> Result<(), String> {
            self.restore_calls.fetch_add(1, Ordering::Relaxed);
            *self
                .settings
                .lock()
                .map_err(|_| "settings poisoned".to_owned())? = snapshot.clone();
            Ok(())
        }
    }

    #[test]
    fn stale_blocking_rollback_does_not_overwrite_a_concurrent_update() {
        let hook = MutableBlockingHook {
            settings: Mutex::new(serde_json::json!({"version": "concurrent"})),
            restore_calls: AtomicUsize::new(0),
        };
        let snapshot = serde_json::json!({"version": "before-import"});
        let imported = serde_json::json!({"version": "imported"});

        let error = super::restore_blocking_settings_if_unchanged(&hook, &snapshot, &imported)
            .expect_err("a concurrent update must prevent a stale rollback");

        assert!(error.contains("changed during import"), "{error}");
        assert_eq!(
            hook.blocking_auth_settings(),
            Some(serde_json::json!({
                "version": "concurrent"
            }))
        );
        assert_eq!(hook.restore_calls.load(Ordering::Relaxed), 0);
    }
}

fn install_auth_users(
    store: &mut AuthStore,
    users: &[ImportedUser],
    password_updated_at: &BTreeMap<(Option<String>, String), LogicalInstant>,
    tenant: Option<&str>,
    filename: &Path,
) -> Result<(), ArtifactError> {
    for user in users {
        let id = user.local_id.clone();
        let uid = store.import_user_trusted(user.clone()).map_err(|e| {
            ArtifactError::new(
                "auth",
                PathBuf::from(AUTH_PATH).join(filename),
                format!("account {id}: {e}"),
            )
        })?;
        if let Some(at) = password_updated_at.get(&(tenant.map(str::to_owned), id)) {
            store.set_password_updated_at(&uid, *at);
        }
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
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
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

#[allow(clippy::too_many_lines)]
fn read_firestore_section(
    dir: &Path,
    section: &Section,
    remaining_bytes: &mut u64,
    databases: &mut BTreeMap<(String, String), Vec<ImportedDocument>>,
    database: &str,
    notices: &mut Vec<String>,
    run_project: &str,
) -> Result<(), ArtifactError> {
    let metadata_file = section
        .metadata_file
        .clone()
        .unwrap_or_else(|| format!("{}/{FIRESTORE_OVERALL_METADATA}", section.path));
    let overall_path = dir.join(&metadata_file);
    let bytes = read_inside_limited(dir, &overall_path, IMPORT_METADATA_FILE_BYTES_LIMIT)
        .map_err(|e| ArtifactError::new("firestore", &overall_path, e))?;
    let overalls = OverallMetadata::parse_all(&bytes)
        .map_err(|e| ArtifactError::new("firestore", &overall_path, e.to_string()))?;

    let section_dir = dir.join(&section.path);
    let mut references = BTreeMap::new();
    for overall in &overalls {
        if let Some((entity_count, byte_count)) = references.insert(
            overall.metadata_file.clone(),
            (overall.entity_count, overall.byte_count),
        ) {
            let description =
                if entity_count == overall.entity_count && byte_count == overall.byte_count {
                    "more than once".to_owned()
                } else {
                    format!("with conflicting counts ({entity_count} entities, {byte_count} bytes)")
                };
            return Err(ArtifactError::new(
                "firestore",
                &overall_path,
                format!(
                    "the overall export metadata names partition metadata file {:?} {description}",
                    overall.metadata_file,
                ),
            ));
        }
    }

    let mut output_paths = BTreeSet::new();
    let mut partitions = Vec::with_capacity(overalls.len());
    for overall in overalls {
        let metadata_path = section_dir.join(&overall.metadata_file);
        let bytes = read_inside_limited(dir, &metadata_path, IMPORT_METADATA_FILE_BYTES_LIMIT)
            .map_err(|e| ArtifactError::new("firestore", &metadata_path, e))?;
        let metadata = PartitionMetadata::parse(&bytes)
            .map_err(|e| ArtifactError::new("firestore", &metadata_path, e.to_string()))?;
        let directory = metadata_path
            .parent()
            .map_or_else(|| section_dir.clone(), Path::to_path_buf);
        for output in &metadata.output_files {
            let output_path = directory.join(output);
            let identity = normalized_import_path(dir, &output_path)
                .map_err(|e| ArtifactError::new("firestore", &output_path, e))?;
            if !output_paths.insert(identity) {
                return Err(ArtifactError::new(
                    "firestore",
                    &output_path,
                    "the Firestore export references this output file from more than one partition metadata file",
                ));
            }
        }
        partitions.push(FirestorePartition {
            overall,
            metadata_path,
            metadata,
            directory,
        });
    }

    let mut foreign = BTreeSet::new();
    let mut declared_entity_count = 0u64;
    let mut imported_entity_count = 0u64;
    let mut declared_byte_count = 0u64;
    let mut imported_byte_count = 0u64;
    for partition in partitions {
        let overall = &partition.overall;
        declared_entity_count = declared_entity_count
            .checked_add(overall.entity_count)
            .ok_or_else(|| {
                ArtifactError::new(
                    "firestore",
                    &overall_path,
                    "the overall export entity count overflows".to_owned(),
                )
            })?;
        declared_byte_count = declared_byte_count
            .checked_add(overall.byte_count)
            .ok_or_else(|| {
                ArtifactError::new(
                    "firestore",
                    &overall_path,
                    "the overall export byte count overflows".to_owned(),
                )
            })?;

        let (partition_entity_count, partition_byte_count) = read_firestore_partition(
            dir,
            &partition,
            remaining_bytes,
            databases,
            database,
            &mut foreign,
            run_project,
        )?;
        imported_entity_count = imported_entity_count
            .checked_add(partition_entity_count)
            .ok_or_else(|| {
                ArtifactError::new(
                    "firestore",
                    &overall_path,
                    "the imported entity count overflows",
                )
            })?;
        imported_byte_count = imported_byte_count
            .checked_add(partition_byte_count)
            .ok_or_else(|| {
                ArtifactError::new(
                    "firestore",
                    &overall_path,
                    "the imported byte count overflows",
                )
            })?;
    }
    if imported_entity_count != declared_entity_count {
        return Err(ArtifactError::new(
            "firestore",
            &overall_path,
            format!(
                "the imported entity count is {imported_entity_count}, but overall metadata records {declared_entity_count}"
            ),
        ));
    }
    if imported_byte_count != declared_byte_count {
        return Err(ArtifactError::new(
            "firestore",
            &overall_path,
            format!(
                "the imported byte count is {imported_byte_count}, but overall metadata records {declared_byte_count}"
            ),
        ));
    }
    for project in foreign {
        notices.push(format!(
            "the Firestore export holds documents of the project {project}, not the {run_project} this run serves; they were imported under {project}, so point the SDK at that project to read them"
        ));
    }
    Ok(())
}

fn normalized_import_path(root: &Path, path: &Path) -> Result<PathBuf, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "it is outside the export directory".to_owned())?;
    let mut normalized = PathBuf::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(name) => normalized.push(name),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err("it contains a parent path component".to_owned());
            }
            _ => return Err("it is not a normal path inside the export directory".to_owned()),
        }
    }
    Ok(normalized)
}

#[allow(clippy::too_many_arguments)]
fn read_firestore_partition(
    dir: &Path,
    partition: &FirestorePartition,
    remaining_bytes: &mut u64,
    databases: &mut BTreeMap<(String, String), Vec<ImportedDocument>>,
    database: &str,
    foreign: &mut BTreeSet<String>,
    run_project: &str,
) -> Result<(u64, u64), ArtifactError> {
    let mut entity_count = 0u64;
    let mut byte_count = 0u64;
    for output in &partition.metadata.output_files {
        let output_path = partition.directory.join(output);
        let file = open_file_inside(dir, &output_path)
            .map_err(|e| ArtifactError::new("firestore", &output_path, e))?;
        let len = file
            .metadata()
            .map_err(|e| ArtifactError::new("firestore", &output_path, e.to_string()))?
            .len();
        if len > *remaining_bytes {
            return Err(ArtifactError::new(
                "firestore",
                &output_path,
                format!(
                    "the output files exceed the {IMPORT_FIRESTORE_BYTES_BUDGET} byte cumulative import limit"
                ),
            ));
        }
        let mut limited = std::io::Read::take(file, remaining_bytes.saturating_add(1));
        let decoded = for_each_output(&mut limited, |document| {
            collect_document(databases, document, database, foreign, run_project)?;
            entity_count = entity_count.saturating_add(1);
            Ok(())
        });
        let consumed = remaining_bytes
            .saturating_add(1)
            .saturating_sub(limited.limit());
        if consumed > *remaining_bytes {
            return Err(ArtifactError::new(
                "firestore",
                &output_path,
                format!(
                    "the output files exceed the {IMPORT_FIRESTORE_BYTES_BUDGET} byte cumulative import limit"
                ),
            ));
        }
        *remaining_bytes = remaining_bytes.saturating_sub(consumed);
        byte_count = byte_count.saturating_add(consumed);
        decoded.map_err(|e| ArtifactError::new("firestore", &output_path, e.to_string()))??;
    }
    if entity_count != partition.overall.entity_count {
        return Err(ArtifactError::new(
            "firestore",
            &partition.metadata_path,
            format!(
                "the partition entity count is {entity_count}, but its overall metadata records {}",
                partition.overall.entity_count
            ),
        ));
    }
    if byte_count != partition.overall.byte_count {
        return Err(ArtifactError::new(
            "firestore",
            &partition.metadata_path,
            format!(
                "the partition byte count is {byte_count}, but its overall metadata records {}",
                partition.overall.byte_count
            ),
        ));
    }
    Ok((entity_count, byte_count))
}

/// Turns one decoded entity into an import document, validating its project and path.
fn collect_document(
    databases: &mut BTreeMap<(String, String), Vec<ImportedDocument>>,
    document: ExportDocument,
    database: &str,
    foreign: &mut BTreeSet<String>,
    run_project: &str,
) -> Result<(), ArtifactError> {
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
        .entry((document.project, database.to_owned()))
        .or_default()
        .push(ImportedDocument {
            path,
            fields: document.fields,
            // The official managed export records no document timestamps at all, so an
            // import necessarily stamps them with the commit it installs them in.
            create_time: None,
            update_time: None,
        });
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

/// The optional `config.json` of the Auth section and the declaration state of each setting.
fn read_auth_config(
    dir: &Path,
    section_dir: &Path,
    remaining_bytes: &mut u64,
) -> Result<(ProjectAuthConfig, bool, bool, bool, bool), ArtifactError> {
    let config_path = section_dir.join(CONFIG_FILE);
    let (
        config,
        allow_duplicate_emails_declared,
        email_privacy_declared,
        signup_declared,
        deletion_declared,
    ) = match std::fs::symlink_metadata(&config_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(ArtifactError::new(
                    "auth",
                    &config_path,
                    "the optional config is not a regular no-symlink file",
                ));
            }
            let text = read_auth_text(dir, &config_path, remaining_bytes)?;
            let parsed = AuthConfig::parse(&text)
                .map_err(|e| ArtifactError::new("auth", &config_path, e.to_string()))?;
            (
                ProjectAuthConfig {
                    allow_duplicate_emails: parsed.allow_duplicate_emails.unwrap_or(false),
                    enable_improved_email_privacy: parsed
                        .enable_improved_email_privacy
                        .unwrap_or(false),
                    disabled_user_signup: parsed.disabled_user_signup.unwrap_or(false),
                    disabled_user_deletion: parsed.disabled_user_deletion.unwrap_or(false),
                },
                parsed.allow_duplicate_emails.is_some(),
                parsed.enable_improved_email_privacy.is_some(),
                parsed.disabled_user_signup.is_some(),
                parsed.disabled_user_deletion.is_some(),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            (ProjectAuthConfig::default(), false, false, false, false)
        }
        Err(e) => {
            return Err(ArtifactError::new(
                "auth",
                &config_path,
                format!("cannot inspect the optional config: {e}"),
            ))
        }
    };
    Ok((
        config,
        allow_duplicate_emails_declared,
        email_privacy_declared,
        signup_declared,
        deletion_declared,
    ))
}

fn read_auth_settings(
    dir: &Path,
    section_dir: &Path,
    remaining_bytes: &mut u64,
) -> Result<Option<AuthSettings>, ArtifactError> {
    let path = section_dir.join(AUTH_SETTINGS_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ArtifactError::new(
                "auth",
                &path,
                format!("cannot inspect the optional Auth settings sidecar: {error}"),
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ArtifactError::new(
            "auth",
            &path,
            "the optional Auth settings sidecar is not a regular no-symlink file",
        ));
    }
    let text = read_auth_text(dir, &path, remaining_bytes)?;
    AuthSettings::parse(&text)
        .map(Some)
        .map_err(|error| ArtifactError::new("auth", &path, error.to_string()))
}

fn read_auth_password_policies(
    dir: &Path,
    section_dir: &Path,
    remaining_bytes: &mut u64,
) -> Result<Option<PasswordPolicies>, ArtifactError> {
    let path = section_dir.join(PASSWORD_POLICIES_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ArtifactError::new(
                "auth",
                &path,
                format!("cannot inspect the optional password policy sidecar: {error}"),
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ArtifactError::new(
            "auth",
            &path,
            "the optional password policy sidecar is not a regular no-symlink file",
        ));
    }
    let text = read_auth_text(dir, &path, remaining_bytes)?;
    PasswordPolicies::parse(&text)
        .map(Some)
        .map_err(|error| ArtifactError::new("auth", &path, error.to_string()))
}

#[allow(clippy::too_many_lines)]
fn read_auth_section(
    dir: &Path,
    section: &Section,
    target_project: &str,
) -> Result<PreparedAuth, ArtifactError> {
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
    let (
        config,
        allow_duplicate_emails_declared,
        email_privacy_declared,
        signup_declared,
        deletion_declared,
    ) = read_auth_config(dir, &section_dir, &mut remaining_bytes)?;
    let password_policies = read_auth_password_policies(dir, &section_dir, &mut remaining_bytes)?;
    let auth_settings = read_auth_settings(dir, &section_dir, &mut remaining_bytes)?;
    let mut tenants = BTreeMap::new();
    let mut password_updated_at = BTreeMap::new();
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
                note_password_updated_at(&mut password_updated_at, Some(tenant), record);
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
        note_password_updated_at(&mut password_updated_at, None, record);
    }
    if let Some(settings) = &auth_settings {
        if settings.project_id.is_empty() {
            return Err(ArtifactError::new(
                "auth",
                section_dir.join(AUTH_SETTINGS_FILE),
                "the Auth settings sidecar has an empty projectId",
            ));
        }
        settings
            .validate_tenant_metadata_project(target_project)
            .map_err(|error| {
                ArtifactError::new(
                    "auth",
                    section_dir.join(AUTH_SETTINGS_FILE),
                    error.to_string(),
                )
            })?;
        for namespace in &settings.namespaces {
            let tenant = namespace.tenant_id.as_deref().unwrap_or_default();
            if !tenants.contains_key(tenant) {
                return Err(ArtifactError::new(
                    "auth",
                    section_dir.join(AUTH_SETTINGS_FILE),
                    format!(
                        "settings name tenant {tenant:?} has no matching accounts-{tenant}.json"
                    ),
                ));
            }
            if let (Some(metadata), Some(config)) = (
                namespace.metadata.as_ref(),
                namespace.settings.config.as_ref(),
            ) {
                let conflicts = [
                    (
                        "disabledUserSignup",
                        config.disabled_user_signup,
                        metadata.disabled_user_signup,
                    ),
                    (
                        "disabledUserDeletion",
                        config.disabled_user_deletion,
                        metadata.disabled_user_deletion,
                    ),
                    (
                        "enableImprovedEmailPrivacy",
                        config.enable_improved_email_privacy,
                        metadata.enable_improved_email_privacy,
                    ),
                ];
                if conflicts.iter().any(|(_, config_value, metadata_value)| {
                    config_value.is_some_and(|value| value != *metadata_value)
                }) {
                    return Err(ArtifactError::new(
                        "auth",
                        section_dir.join(AUTH_SETTINGS_FILE),
                        format!("tenant metadata conflicts with config for tenant {tenant:?}"),
                    ));
                }
            }
        }
    }
    Ok(PreparedAuth {
        users,
        password_updated_at,
        config,
        allow_duplicate_emails_declared,
        client_permissions_declared: (signup_declared, deletion_declared),
        email_privacy_declared,
        password_policies,
        auth_settings,
        tenants,
    })
}

fn exported_password_policy(policy: &PasswordPolicy) -> PasswordPolicyRecord {
    PasswordPolicyRecord {
        enforcement_state: match policy.enforcement_state {
            EnforcementState::Off => "OFF".to_owned(),
            EnforcementState::Enforce => "ENFORCE".to_owned(),
        },
        force_upgrade_on_signin: policy.force_upgrade_on_signin,
        #[allow(clippy::cast_possible_wrap)]
        min_length: policy.min_length as i64,
        max_length: policy.max_length.map(|value| {
            #[allow(clippy::cast_possible_wrap)]
            {
                value as i64
            }
        }),
        require_uppercase: policy.require_uppercase,
        require_lowercase: policy.require_lowercase,
        require_numeric: policy.require_numeric,
        require_non_alphanumeric: policy.require_non_alphanumeric,
        allowed_non_alphanumeric_characters: policy.allowed_non_alphanumeric.clone(),
    }
}

fn imported_password_policy(
    record: &PasswordPolicyRecord,
    path: &Path,
) -> Result<PasswordPolicy, ArtifactError> {
    let state = match record.enforcement_state.as_str() {
        "OFF" => EnforcementState::Off,
        "ENFORCE" => EnforcementState::Enforce,
        _ => {
            return Err(ArtifactError::new(
                "auth",
                path,
                "the password policy sidecar has an invalid enforcementState",
            ))
        }
    };
    let min_length = usize::try_from(record.min_length).map_err(|_| {
        ArtifactError::new(
            "auth",
            path,
            "the password policy sidecar has an invalid minLength",
        )
    })?;
    let max_length = record
        .max_length
        .map(usize::try_from)
        .transpose()
        .map_err(|_| {
            ArtifactError::new(
                "auth",
                path,
                "the password policy sidecar has an invalid maxLength",
            )
        })?;
    PasswordPolicy::try_new(
        state,
        record.force_upgrade_on_signin,
        min_length,
        max_length,
        record.require_uppercase,
        record.require_lowercase,
        record.require_numeric,
        record.require_non_alphanumeric,
        record.allowed_non_alphanumeric_characters.clone(),
    )
    .map_err(|error| {
        ArtifactError::new(
            "auth",
            path,
            format!("the password policy sidecar is invalid: {error:?}"),
        )
    })
}

fn exported_quota_settings(config: &SignupQuotaConfig) -> QuotaSettingsRecord {
    let temporary = config.temporary.map(|temporary| TemporaryQuotaRecord {
        quota: i64::try_from(temporary.quota).unwrap_or(i64::MAX),
        start_time: rfc3339_text(temporary.start_time),
        quota_duration: protobuf_duration_text(temporary.duration),
    });
    QuotaSettingsRecord {
        mode: match config.mode {
            QuotaMode::Off => "off".to_owned(),
            QuotaMode::Observe => "observe".to_owned(),
            QuotaMode::Enforce => "enforce".to_owned(),
        },
        algorithm: match config.algorithm {
            QuotaAlgorithm::FixedWindowV1 => "fixed-window-v1".to_owned(),
        },
        #[allow(clippy::cast_possible_wrap)]
        default_quota_per_hour: config.default_quota_per_hour as i64,
        #[allow(clippy::cast_possible_wrap)]
        max_tracked_buckets: config.max_tracked_buckets as i64,
        temporary,
    }
}

fn imported_quota_settings(
    record: &QuotaSettingsRecord,
    path: &Path,
) -> Result<SignupQuotaConfig, ArtifactError> {
    let mode = match record.mode.as_str() {
        "off" => QuotaMode::Off,
        "observe" => QuotaMode::Observe,
        "enforce" => QuotaMode::Enforce,
        _ => {
            return Err(ArtifactError::new(
                "auth",
                path,
                "the Auth settings sidecar has an invalid quota mode",
            ))
        }
    };
    if record.algorithm != "fixed-window-v1" {
        return Err(ArtifactError::new(
            "auth",
            path,
            "the Auth settings sidecar has an unsupported quota algorithm",
        ));
    }
    let default_quota_per_hour = u64::try_from(record.default_quota_per_hour).map_err(|_| {
        ArtifactError::new(
            "auth",
            path,
            "the Auth settings sidecar has an invalid defaultQuotaPerHour",
        )
    })?;
    let max_tracked_buckets = usize::try_from(record.max_tracked_buckets).map_err(|_| {
        ArtifactError::new(
            "auth",
            path,
            "the Auth settings sidecar has an invalid maxTrackedBuckets",
        )
    })?;
    let temporary = record
        .temporary
        .as_ref()
        .map(|temporary| {
            let quota = u64::try_from(temporary.quota).map_err(|_| {
                ArtifactError::new(
                    "auth",
                    path,
                    "the Auth settings sidecar has an invalid temporary quota",
                )
            })?;
            let start_time = LogicalInstant::parse_rfc3339(&temporary.start_time).map_err(|e| {
                ArtifactError::new(
                    "auth",
                    path,
                    format!("the Auth settings sidecar has an invalid temporary startTime: {e}"),
                )
            })?;
            let duration = parse_protobuf_duration_text(&temporary.quota_duration, path)?;
            TemporaryQuota::new(quota, start_time, duration).map_err(|e| {
                ArtifactError::new(
                    "auth",
                    path,
                    format!("the Auth settings sidecar has an invalid temporary quota: {e:?}"),
                )
            })
        })
        .transpose()?;
    let config = SignupQuotaConfig {
        mode,
        algorithm: QuotaAlgorithm::FixedWindowV1,
        default_quota_per_hour,
        max_tracked_buckets,
        temporary,
    };
    config.validate().map_err(|e| {
        ArtifactError::new(
            "auth",
            path,
            format!("the Auth settings sidecar has an invalid quota configuration: {e:?}"),
        )
    })?;
    Ok(config)
}

fn blocking_discovery_events_from_json(
    value: &serde_json::Value,
    path: &Path,
) -> Result<BTreeSet<String>, ArtifactError> {
    let events = value.as_array().ok_or_else(|| {
        ArtifactError::new(
            "auth",
            path,
            format!("blocking settings {BLOCKING_DISCOVERY_EVENTS_MEMBER} is not an array"),
        )
    })?;
    let mut discovery = BTreeSet::new();
    for event in events {
        let event = event.as_str().ok_or_else(|| {
            ArtifactError::new(
                "auth",
                path,
                format!(
                    "blocking settings {BLOCKING_DISCOVERY_EVENTS_MEMBER} contains a non-string event"
                ),
            )
        })?;
        if !matches!(event, "beforeCreate" | "beforeSignIn") {
            return Err(ArtifactError::new(
                "auth",
                path,
                format!(
                    "blocking settings {BLOCKING_DISCOVERY_EVENTS_MEMBER} contains unsupported event {event:?}"
                ),
            ));
        }
        if !discovery.insert(event.to_owned()) {
            return Err(ArtifactError::new(
                "auth",
                path,
                format!(
                    "blocking settings {BLOCKING_DISCOVERY_EVENTS_MEMBER} contains duplicate event {event:?}"
                ),
            ));
        }
    }
    Ok(discovery)
}

fn blocking_settings_record_from_json(
    value: &serde_json::Value,
    path: &Path,
) -> Result<BlockingAuthSettingsRecord, ArtifactError> {
    let object = value
        .as_object()
        .ok_or_else(|| ArtifactError::new("auth", path, "blocking settings are not an object"))?;
    let discovery = object.get(BLOCKING_DISCOVERY_EVENTS_MEMBER).map_or_else(
        || Ok(BTreeSet::new()),
        |value| blocking_discovery_events_from_json(value, path),
    )?;
    if !discovery.is_empty() && object.get("triggers").is_none() {
        return Err(ArtifactError::new(
            "auth",
            path,
            format!(
                "blocking settings {BLOCKING_DISCOVERY_EVENTS_MEMBER} requires a triggers object"
            ),
        ));
    }
    let selection = |event: &str| -> Result<BlockingAuthSelectionRecord, ArtifactError> {
        let Some(triggers) = object.get("triggers") else {
            return Ok(BlockingAuthSelectionRecord::Discovery);
        };
        let triggers = triggers.as_object().ok_or_else(|| {
            ArtifactError::new("auth", path, "blocking settings triggers are not an object")
        })?;
        if discovery.contains(event) {
            if triggers.contains_key(event) {
                return Err(ArtifactError::new(
                    "auth",
                    path,
                    format!(
                        "blocking settings {BLOCKING_DISCOVERY_EVENTS_MEMBER} conflicts with triggers.{event}"
                    ),
                ));
            }
            return Ok(BlockingAuthSelectionRecord::Discovery);
        }
        let Some(entry) = triggers.get(event) else {
            return Ok(BlockingAuthSelectionRecord::Disabled);
        };
        if entry.is_null() {
            return Ok(BlockingAuthSelectionRecord::Disabled);
        }
        let uri = entry
            .get("functionUri")
            .and_then(serde_json::Value::as_str)
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    path,
                    format!("blocking settings {event} has no functionUri"),
                )
            })?;
        Ok(BlockingAuthSelectionRecord::Explicit {
            function_uri: uri.to_owned(),
        })
    };
    let forwarding = match object.get("forwardInboundCredentials") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let value = value.as_object().ok_or_else(|| {
                ArtifactError::new("auth", path, "blocking forwarding is not an object")
            })?;
            let boolean = |key: &str| {
                value
                    .get(key)
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| {
                        ArtifactError::new(
                            "auth",
                            path,
                            format!("blocking forwarding {key} is not a boolean"),
                        )
                    })
            };
            Some(BlockingAuthForwardingRecord {
                id_token: boolean("idToken")?,
                access_token: boolean("accessToken")?,
                refresh_token: boolean("refreshToken")?,
            })
        }
    };
    Ok(BlockingAuthSettingsRecord {
        before_create: selection("beforeCreate")?,
        before_sign_in: selection("beforeSignIn")?,
        forwarding,
    })
}

fn blocking_settings_json(record: &BlockingAuthSettingsRecord) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    let mut triggers = serde_json::Map::new();
    let mut discovery = Vec::new();
    let mut write_selection =
        |name: &str,
         selection: &BlockingAuthSelectionRecord,
         triggers: &mut serde_json::Map<String, serde_json::Value>| {
            match selection {
                BlockingAuthSelectionRecord::Discovery => {
                    discovery.push(name.to_owned());
                }
                BlockingAuthSelectionRecord::Disabled => {
                    triggers.insert(name.to_owned(), serde_json::Value::Null);
                }
                BlockingAuthSelectionRecord::Explicit { function_uri } => {
                    triggers.insert(
                        name.to_owned(),
                        serde_json::json!({"functionUri": function_uri}),
                    );
                }
            }
        };
    write_selection("beforeCreate", &record.before_create, &mut triggers);
    write_selection("beforeSignIn", &record.before_sign_in, &mut triggers);
    if !triggers.is_empty() {
        object.insert("triggers".to_owned(), serde_json::Value::Object(triggers));
        if !discovery.is_empty() {
            object.insert(
                BLOCKING_DISCOVERY_EVENTS_MEMBER.to_owned(),
                serde_json::Value::Array(
                    discovery
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }
    if let Some(forwarding) = record.forwarding {
        object.insert(
            "forwardInboundCredentials".to_owned(),
            serde_json::json!({
                "idToken": forwarding.id_token,
                "accessToken": forwarding.access_token,
                "refreshToken": forwarding.refresh_token,
            }),
        );
    }
    serde_json::Value::Object(object)
}

fn protobuf_duration_text(duration: LogicalDuration) -> String {
    let nanos = duration.as_nanos();
    let seconds = nanos.div_euclid(1_000_000_000);
    let fraction = nanos.rem_euclid(1_000_000_000);
    if fraction == 0 {
        format!("{seconds}s")
    } else {
        format!("{seconds}.{fraction:09}s")
            .trim_end_matches('0')
            .to_owned()
    }
}

fn parse_protobuf_duration_text(text: &str, path: &Path) -> Result<LogicalDuration, ArtifactError> {
    let body = text
        .strip_suffix('s')
        .filter(|body| !body.is_empty())
        .ok_or_else(|| {
            ArtifactError::new(
                "auth",
                path,
                "the Auth settings sidecar has an invalid quota duration",
            )
        })?;
    if body.starts_with(['+', '-']) {
        return Err(ArtifactError::new(
            "auth",
            path,
            "the Auth settings sidecar has a negative quota duration",
        ));
    }
    let (seconds, fraction) = body
        .split_once('.')
        .map_or((body, None), |(seconds, fraction)| {
            (seconds, Some(fraction))
        });
    let seconds = seconds.parse::<i128>().map_err(|_| {
        ArtifactError::new(
            "auth",
            path,
            "the Auth settings sidecar has an invalid quota duration seconds value",
        )
    })?;
    let fraction_nanos = match fraction {
        None => 0,
        Some(fraction)
            if !fraction.is_empty()
                && fraction.len() <= 9
                && fraction.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            fraction
                .parse::<i128>()
                .unwrap_or(0)
                .saturating_mul(10_i128.pow(u32::try_from(9 - fraction.len()).unwrap_or(0)))
        }
        Some(_) => {
            return Err(ArtifactError::new(
                "auth",
                path,
                "the Auth settings sidecar has an invalid quota duration fraction",
            ))
        }
    };
    let nanos = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction_nanos))
        .ok_or_else(|| {
            ArtifactError::new(
                "auth",
                path,
                "the Auth settings sidecar quota duration overflows",
            )
        })?;
    Ok(LogicalDuration::from_nanos(nanos))
}

fn auth_config_from_settings(config: &AuthConfig, current: ProjectAuthConfig) -> ProjectAuthConfig {
    ProjectAuthConfig {
        allow_duplicate_emails: config
            .allow_duplicate_emails
            .unwrap_or(current.allow_duplicate_emails),
        enable_improved_email_privacy: config
            .enable_improved_email_privacy
            .unwrap_or(current.enable_improved_email_privacy),
        disabled_user_signup: config
            .disabled_user_signup
            .unwrap_or(current.disabled_user_signup),
        disabled_user_deletion: config
            .disabled_user_deletion
            .unwrap_or(current.disabled_user_deletion),
    }
}

fn tenant_config_from_settings(
    settings: Option<&AuthSettingsNamespace>,
    current: ProjectAuthConfig,
) -> ProjectAuthConfig {
    settings
        .filter(|settings| settings.config_is_explicit)
        .and_then(|settings| settings.settings.config.as_ref())
        .map_or(current, |config| auth_config_from_settings(config, current))
}

fn auth_namespace_config_patch(config: &AuthConfig) -> AuthNamespaceConfigPatch {
    AuthNamespaceConfigPatch {
        allow_duplicate_emails: config.allow_duplicate_emails,
        disabled_user_signup: config.disabled_user_signup,
        disabled_user_deletion: config.disabled_user_deletion,
        enable_improved_email_privacy: config.enable_improved_email_privacy,
    }
}

fn exported_tenant_config_patch(patch: AuthNamespaceConfigPatch) -> AuthConfig {
    AuthConfig {
        allow_duplicate_emails: patch.allow_duplicate_emails,
        enable_improved_email_privacy: patch.enable_improved_email_privacy,
        disabled_user_signup: patch.disabled_user_signup,
        disabled_user_deletion: patch.disabled_user_deletion,
    }
}

fn exported_tenant_metadata(metadata: &TenantMetadata) -> TenantMetadataRecord {
    TenantMetadataRecord {
        display_name: metadata.display_name.clone(),
        allow_password_signup: metadata.allow_password_signup,
        enable_email_link_signin: metadata.enable_email_link_signin,
        enable_anonymous_user: metadata.enable_anonymous_user,
        disable_auth: metadata.disable_auth,
        disabled_user_signup: metadata.disabled_user_signup,
        disabled_user_deletion: metadata.disabled_user_deletion,
        enable_improved_email_privacy: metadata.enable_improved_email_privacy,
    }
}

fn imported_tenant_metadata(metadata: &TenantMetadataRecord) -> TenantMetadata {
    TenantMetadata {
        display_name: metadata.display_name.clone(),
        allow_password_signup: metadata.allow_password_signup,
        enable_email_link_signin: metadata.enable_email_link_signin,
        enable_anonymous_user: metadata.enable_anonymous_user,
        disable_auth: metadata.disable_auth,
        disabled_user_signup: metadata.disabled_user_signup,
        disabled_user_deletion: metadata.disabled_user_deletion,
        enable_improved_email_privacy: metadata.enable_improved_email_privacy,
    }
}

fn settings_for_tenant<'a>(
    settings: Option<&'a AuthSettings>,
    target_project: &str,
    tenant: &str,
) -> Option<&'a AuthSettingsNamespace> {
    settings
        .filter(|settings| settings.project_id == target_project)
        .and_then(|settings| {
            settings
                .namespaces
                .iter()
                .find(|namespace| namespace.tenant_id.as_deref() == Some(tenant))
        })
}

fn password_policy_for_tenant(
    policies: Option<&PasswordPolicies>,
    target_project: &str,
    tenant: &str,
    fallback: &PasswordPolicy,
    path: &Path,
) -> Result<PasswordPolicy, ArtifactError> {
    let Some(policies) = policies.filter(|policies| policies.project_id == target_project) else {
        return Ok(fallback.clone());
    };
    let Some(namespace) = policies
        .namespaces
        .iter()
        .find(|namespace| namespace.tenant_id.as_deref() == Some(tenant))
    else {
        return Ok(PasswordPolicy::default());
    };
    imported_password_policy(&namespace.policy, path)
}

fn millis_instant(text: Option<&str>) -> Option<LogicalInstant> {
    let millis: i64 = text?.parse().ok()?;
    Some(LogicalInstant::from_nanos(i128::from(millis) * 1_000_000))
}

fn seconds_instant(text: Option<&str>) -> Option<LogicalInstant> {
    let seconds: i64 = text?.parse().ok()?;
    Some(LogicalInstant::from_unix_seconds(seconds))
}

/// Remembers the `passwordUpdatedAt` an account record carries (milliseconds), keyed by tenant
/// namespace and account id, for restoration after the account is imported.
fn note_password_updated_at(
    into: &mut BTreeMap<(Option<String>, String), LogicalInstant>,
    tenant_id: Option<&str>,
    record: &UserRecord,
) {
    if let Some(millis) = record.password_updated_at {
        if millis.is_finite() && millis.fract() == 0.0 && millis.abs() < 9.007_199_254_740_992e15 {
            // Guarded above: finite, whole and inside the exactly representable range.
            #[allow(clippy::cast_possible_truncation)]
            let millis = millis as i64;
            into.insert(
                (tenant_id.map(str::to_owned), record.local_id.clone()),
                LogicalInstant::from_nanos(i128::from(millis) * 1_000_000),
            );
        }
    }
}

#[allow(clippy::too_many_lines)]
fn imported_user(record: &UserRecord, path: &Path) -> Result<ImportedUser, ArtifactError> {
    let refuse = |message: String| ArtifactError::new("auth", path, message);
    header_safe_account(record, &refuse)?;
    let mut imported_password = None;
    for (member, value) in &record.extra {
        if member == IMPORTED_PASSWORD_MEMBER && imported_password.is_none() {
            imported_password = Some(imported_password_of(value).ok_or_else(|| {
                refuse(format!(
                    "account {}: {IMPORTED_PASSWORD_MEMBER} is not {{spec, hash, salt}}",
                    record.local_id
                ))
            })?);
            continue;
        }
        return Err(refuse(format!(
            "account {} contains unsupported member {member:?}; fireemu cannot preserve it during import",
            record.local_id
        )));
    }
    if imported_password.is_some() && record.password_hash.is_some() {
        return Err(refuse(format!(
            "account {}: both passwordHash and {IMPORTED_PASSWORD_MEMBER}",
            record.local_id
        )));
    }
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
    if let Some(value) = record.password_updated_at {
        if !(value.is_finite() && value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15) {
            return Err(refuse(format!(
                "account {}: invalid passwordUpdatedAt",
                record.local_id
            )));
        }
    }
    let created_at = match record.created_at.as_deref() {
        Some(value) => millis_instant(Some(value))
            .ok_or_else(|| refuse(format!("account {}: invalid createdAt", record.local_id)))?,
        None => LogicalInstant::from_unix_seconds(0),
    };
    let mut totp_factors = Vec::new();
    let mut phone_factors = Vec::new();
    for (index, enrollment) in record.mfa_info.iter().enumerate() {
        let id = if enrollment.mfa_enrollment_id.is_empty() {
            format!("{}-factor-{index}", record.local_id)
        } else {
            enrollment.mfa_enrollment_id.clone()
        };
        let enrolled_at = match enrollment.enrolled_at.as_deref() {
            Some(value) => rfc3339_instant(Some(value)).ok_or_else(|| {
                refuse(format!(
                    "account {}: invalid mfaInfo.enrolledAt",
                    record.local_id
                ))
            })?,
            None => created_at,
        };
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
        last_sign_in_at: match record.last_login_at.as_deref() {
            Some(value) => Some(millis_instant(Some(value)).ok_or_else(|| {
                refuse(format!("account {}: invalid lastLoginAt", record.local_id))
            })?),
            None => None,
        },
        last_refresh_at: record
            .last_refresh_at
            .as_deref()
            .map(LogicalInstant::parse_rfc3339)
            .transpose()
            .map_err(|e| refuse(format!("invalid lastRefreshAt: {e}")))?,
        tokens_valid_after: match record.valid_since.as_deref() {
            Some(value) => seconds_instant(Some(value)).ok_or_else(|| {
                refuse(format!("account {}: invalid validSince", record.local_id))
            })?,
            None => created_at,
        },
        federated: record
            .provider_user_info
            .iter()
            .filter(|p| !matches!(p.provider_id.as_str(), "password" | "phone" | "emailLink"))
            .map(federated_identity)
            .collect(),
        password,
        imported_password,
        // A restore reproduces a state the runtime held: accounts batchCreate let share an
        // address come back without switching duplicate emails on (external review
        // 2026-09-24).
        allow_shared_email: true,
        totp_factors,
        phone_factors,
    })
}

/// Refuses the control characters an account may carry in the strings the Auth store does not
/// check itself.
///
/// `AuthStore::import_user` already rejects them in the local id, the email, the display name,
/// the photo URL and the phone number. The linked providers and the enrolled second factors go
/// in unchecked, and every one of those strings is rendered back into an account response, a
/// log line and a re-exported artifact, so the artifact boundary applies the same rule to them.
/// The classification is the one predicate both product sections of an artifact use
/// ([`fireemu_core_storage::store::is_header_safe`]), so Auth and Storage cannot drift apart
/// on what a control character is. The refusal names the field and never repeats the value.
fn header_safe_account(
    record: &UserRecord,
    refuse: &impl Fn(String) -> ArtifactError,
) -> Result<(), ArtifactError> {
    let check = |field: &str, value: &str| -> Result<(), ArtifactError> {
        if fireemu_core_storage::store::is_header_safe(value) {
            Ok(())
        } else {
            Err(refuse(format!("{field} contains a control character")))
        }
    };
    for provider in &record.provider_user_info {
        check("providerUserInfo.providerId", &provider.provider_id)?;
        check("providerUserInfo.rawId", &provider.raw_id)?;
        for (field, value) in [
            ("providerUserInfo.federatedId", &provider.federated_id),
            ("providerUserInfo.email", &provider.email),
            ("providerUserInfo.displayName", &provider.display_name),
            ("providerUserInfo.photoUrl", &provider.photo_url),
            ("providerUserInfo.phoneNumber", &provider.phone_number),
            ("providerUserInfo.screenName", &provider.screen_name),
        ] {
            if let Some(value) = value {
                check(field, value)?;
            }
        }
    }
    for enrollment in &record.mfa_info {
        check("mfaInfo.mfaEnrollmentId", &enrollment.mfa_enrollment_id)?;
        for (field, value) in [
            ("mfaInfo.displayName", &enrollment.display_name),
            ("mfaInfo.phoneInfo", &enrollment.phone_info),
            (
                "mfaInfo.unobfuscatedPhoneInfo",
                &enrollment.unobfuscated_phone_info,
            ),
        ] {
            if let Some(value) = value {
                check(field, value)?;
            }
        }
    }
    Ok(())
}

/// The sign-in provider an account is attributed to, from the providers the export listed.
fn provider_of(record: &UserRecord) -> Provider {
    let has = |id: &str| {
        record
            .provider_user_info
            .iter()
            .any(|p| p.provider_id == id)
    };
    if record.email_link_signin && record.password_hash.is_none() {
        return Provider::EmailLink;
    }
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
    header_safe_metadata(meta, &refuse)?;
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
        time_created: imported_instant(meta.time_created.as_deref(), "timeCreated", path)?,
        updated: imported_instant(meta.updated.as_deref(), "updated", path)?,
        download_tokens: meta.download_tokens.clone(),
        md5: meta.md5_hash.as_deref().and_then(decode_md5),
        crc32c: meta.crc32c.as_deref().and_then(|c| c.parse().ok()),
        size: Some(meta.size),
    })
}

/// Refuses, before any object is installed, the metadata strings an artifact may carry that
/// would be served as HTTP header values.
///
/// The store applies the same check, but it does so one object at a time after the previous
/// state has been cleared; refusing here keeps a crafted artifact from clearing the store and
/// installing a prefix of its objects. The refusal names the field and never repeats the
/// value, which is by definition untrusted and carries control characters.
fn header_safe_metadata(
    meta: &ExportedObject,
    refuse: &impl Fn(String) -> ArtifactError,
) -> Result<(), ArtifactError> {
    let check = |field: &str, value: &str| -> Result<(), ArtifactError> {
        if fireemu_core_storage::store::is_header_safe(value) {
            Ok(())
        } else {
            Err(refuse(format!("{field} contains a control character")))
        }
    };
    for (field, value) in [
        ("contentType", &meta.content_type),
        ("contentDisposition", &meta.content_disposition),
        ("contentEncoding", &meta.content_encoding),
        ("contentLanguage", &meta.content_language),
        ("cacheControl", &meta.cache_control),
    ] {
        if let Some(value) = value {
            check(field, value)?;
        }
    }
    for (key, value) in &meta.custom_metadata {
        check("metadata key", key)?;
        check(&format!("metadata.{key}"), value)?;
    }
    for token in &meta.download_tokens {
        check("downloadTokens", token)?;
    }
    Ok(())
}

fn imported_instant(
    text: Option<&str>,
    field: &str,
    path: &Path,
) -> Result<LogicalInstant, ArtifactError> {
    match text {
        None => Ok(LogicalInstant::from_unix_seconds(0)),
        Some(text) => LogicalInstant::parse_rfc3339(text).map_err(|error| {
            ArtifactError::new(
                "storage",
                path,
                format!("{field} is not a valid RFC 3339 timestamp: {error}"),
            )
        }),
    }
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
    text.and_then(|text| LogicalInstant::parse_rfc3339(text).ok())
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

/// One session's Firestore time-to-live catalogs, keyed by project and database.
type FieldConfigCatalogs = BTreeMap<(String, String), fireemu_core_firestore::ttl::TtlCatalog>;

/// The fireemu-only sidecar carrying the Firestore time-to-live field configuration.
///
/// The official export format has no field-configuration section, so this file is additive:
/// official tooling ignores it, and an artifact written by that tooling simply has none.
pub const FIELD_CONFIG_FILE: &str = "fireemu-firestore-field-config.json";

/// Largest field-configuration sidecar an import reads. The catalog is bounded per database
/// by the runtime, so a larger file is a malformed artifact rather than a large session.
const FIELD_CONFIG_BYTES_LIMIT: u64 = 1 << 20;

/// The sidecar version that carries the collection group and the field alone.
const FIELD_CONFIG_VERSION_FIELDS_ONLY: u64 = 1;

/// The sidecar version that may also carry `expirationOffset`.
///
/// The version is what stops an older reader from restoring a policy whose offset it cannot
/// see: dropping the offset would sweep every document of that collection group up to one
/// offset early, silently. A reader that knows only version 1 refuses a version-2 artifact
/// as an unknown version, which is the loud failure that data loss is not.
const FIELD_CONFIG_VERSION_WITH_OFFSETS: u64 = 2;

/// Serializes one session's time-to-live catalogs.
///
/// The version is the lowest one that can carry the configuration: a session that configured
/// no `expirationOffset` writes version 1, byte for byte what earlier fireemu versions wrote,
/// so an artifact only declares the newer format when it actually needs it.
fn field_config_json(catalogs: &FieldConfigCatalogs) -> String {
    let carries_offset = catalogs
        .values()
        .flat_map(fireemu_core_firestore::ttl::TtlCatalog::iter)
        .any(|(_, policy)| policy.expiration_offset.is_some());
    let version = if carries_offset {
        FIELD_CONFIG_VERSION_WITH_OFFSETS
    } else {
        FIELD_CONFIG_VERSION_FIELDS_ONLY
    };
    let databases: Vec<serde_json::Value> = catalogs
        .iter()
        .filter(|(_, catalog)| !catalog.is_empty())
        .map(|((project, database), catalog)| {
            let ttl: Vec<serde_json::Value> = catalog
                .iter()
                .map(|(group, policy)| {
                    let mut entry = serde_json::json!({
                        "collectionGroup": group.as_str(),
                        "field": policy.field.canonical(),
                    });
                    // An unset offset stays absent, so an artifact written by a session that
                    // configured no offset is byte-identical to the one earlier fireemu
                    // versions wrote, and an import of theirs installs the unset offset.
                    if let Some(offset) = policy.expiration_offset {
                        entry["expirationOffset"] = serde_json::json!(
                            fireemu_core_firestore::ttl::format_expiration_offset(offset)
                        );
                    }
                    entry
                })
                .collect();
            serde_json::json!({
                "project": project,
                "database": database,
                "ttlFields": ttl,
            })
        })
        .collect();
    serde_json::json!({
        "version": version,
        "databases": databases,
    })
    .to_string()
}

/// Parses the field-configuration sidecar, refusing anything it cannot install exactly.
fn parse_field_config(text: &str) -> Result<FieldConfigCatalogs, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("invalid JSON: {error}"))?;
    // Version 1 promises that no policy carries an offset, which is what lets a reader that
    // knows only that version install it whole. An artifact that declares 1 and carries one
    // anyway breaks that promise, so it is refused below rather than read as version 2.
    let carries_offsets = match value["version"].as_u64() {
        Some(FIELD_CONFIG_VERSION_FIELDS_ONLY) => false,
        Some(FIELD_CONFIG_VERSION_WITH_OFFSETS) => true,
        _ => {
            return Err("the field configuration sidecar declares an unknown version".to_owned());
        }
    };
    let databases = value["databases"]
        .as_array()
        .ok_or_else(|| "databases must be an array".to_owned())?;
    let mut catalogs = BTreeMap::new();
    for entry in databases {
        let project = entry["project"]
            .as_str()
            .ok_or_else(|| "a database entry has no project".to_owned())?;
        let database = entry["database"]
            .as_str()
            .ok_or_else(|| "a database entry has no database".to_owned())?;
        // The identifiers become catalog keys and are written back on the next export, so
        // they go through the same constructors a request would. An entry the runtime could
        // never address would otherwise read back as ACTIVE through fields.get while no
        // sweep could ever reach it.
        let project = fireemu_core_types::ids::ProjectId::try_new(project)
            .map_err(|error| format!("project {project:?}: {error}"))?;
        let database = fireemu_core_types::ids::DatabaseId::try_new(database)
            .map_err(|error| format!("database {database:?}: {error}"))?;
        let mut catalog = fireemu_core_firestore::ttl::TtlCatalog::new();
        let fields = entry["ttlFields"]
            .as_array()
            .ok_or_else(|| "ttlFields must be an array".to_owned())?;
        for field in fields {
            let group = field["collectionGroup"]
                .as_str()
                .ok_or_else(|| "a TTL entry has no collectionGroup".to_owned())?;
            let path = field["field"]
                .as_str()
                .ok_or_else(|| "a TTL entry has no field".to_owned())?;
            let group = fireemu_core_types::ids::CollectionId::try_new(group)
                .map_err(|error| format!("collection group {group:?}: {error}"))?;
            let path = fireemu_core_firestore::field_path::FieldPath::parse(path)
                .map_err(|error| format!("field path {path:?}: {error}"))?;
            // The offset goes through the same grammar a fields.patch is held to, so a
            // sidecar naming a duration the Admin surface would refuse is a malformed
            // artifact rather than a policy that sweeps at some other instant.
            if !carries_offsets && !field["expirationOffset"].is_null() {
                return Err(format!(
                    "a TTL entry names an expirationOffset, which version \
                     {FIELD_CONFIG_VERSION_FIELDS_ONLY} of the field configuration sidecar \
                     does not carry; version {FIELD_CONFIG_VERSION_WITH_OFFSETS} does"
                ));
            }
            let expiration_offset = match &field["expirationOffset"] {
                serde_json::Value::Null => None,
                serde_json::Value::String(text) => Some(
                    fireemu_core_firestore::ttl::parse_expiration_offset(text).map_err(
                        |error| format!("a TTL entry names an invalid expirationOffset: {error}"),
                    )?,
                ),
                _ => {
                    return Err(
                        "a TTL entry's expirationOffset must be a duration in seconds".to_owned(),
                    )
                }
            };
            catalog
                .enable_with_offset(group, path, expiration_offset)
                .map_err(|error| error.to_string())?;
        }
        catalogs.insert(
            (project.as_str().to_owned(), database.as_str().to_owned()),
            catalog,
        );
    }
    Ok(catalogs)
}

/// Reads the optional field-configuration sidecar from the export root.
fn read_field_config(dir: &Path) -> Result<Option<FieldConfigCatalogs>, ArtifactError> {
    let path = dir.join(FIELD_CONFIG_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ArtifactError::new(
                "firestore",
                &path,
                format!("cannot inspect the optional field configuration sidecar: {error}"),
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ArtifactError::new(
            "firestore",
            &path,
            "the optional field configuration sidecar is not a regular no-symlink file",
        ));
    }
    let text = read_text_inside_limited(dir, &path, FIELD_CONFIG_BYTES_LIMIT)
        .map_err(|error| ArtifactError::new("firestore", &path, error))?;
    parse_field_config(&text)
        .map(Some)
        .map_err(|error| ArtifactError::new("firestore", &path, error))
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
    for ((project, database), state) in snapshot.databases {
        let documents: Vec<ExportDocument> = state
            .into_documents()
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
        by_database.entry(database).or_default().extend(documents);
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

        let output_path = partition_dir.join(OUTPUT_FILE);
        let mut output = std::io::BufWriter::new(
            create_private_file(&output_path)
                .map_err(|e| ArtifactError::new("firestore", &output_path, e))?,
        );
        let output_bytes = write_output_to(documents, &mut output)
            .map_err(|e| ArtifactError::new("firestore", &output_path, e.to_string()))?;
        std::io::Write::flush(&mut output)
            .map_err(|e| ArtifactError::new("firestore", &output_path, e.to_string()))?;

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
            byte_count: output_bytes,
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
    // The field configuration is written only when there is one, so an export of a session
    // that never configured a policy stays byte-identical to what the official CLI writes.
    let catalogs = endpoints.backend.ttl_catalogs();
    if catalogs.values().any(|catalog| !catalog.is_empty()) {
        let path = dir.join(FIELD_CONFIG_FILE);
        write_private_file(&path, field_config_json(&catalogs).as_bytes())
            .map_err(|e| ArtifactError::new("firestore", &path, e))?;
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

#[allow(clippy::too_many_lines)]
fn export_auth(
    dir: &Path,
    endpoints: &Endpoints,
    manifest: &mut ExportMetadata,
) -> Result<(), ArtifactError> {
    let section_dir = dir.join(AUTH_PATH);
    create_private_dir(&section_dir).map_err(|e| ArtifactError::new("auth", &section_dir, e))?;
    // Capture the Auth stores and the logical Blocking Functions projection under the same
    // adapter-level gate used by project configuration PATCH and blocking Auth requests. This
    // prevents an export from combining two settings generations. The gate is released before
    // any file I/O so ordinary Auth requests are not held up by serialization.
    let (snapshot, project_blocking) = {
        let _operation = match endpoints.auth_operation_gate {
            Some(gate) => Some(gate.lock().map_err(|_| {
                ArtifactError::new("auth", &section_dir, "the Auth settings gate is poisoned")
            })?),
            None => None,
        };
        let snapshot = endpoints
            .auth
            .capture_export_snapshot(endpoints.project)
            .map_err(|error| ArtifactError::new("auth", &section_dir, error))?
            .ok_or_else(|| {
                ArtifactError::new(
                    "auth",
                    &section_dir,
                    format!("Auth project {:?} is not available", endpoints.project),
                )
            })?;
        let project_blocking = if let Some(blocking) = endpoints.blocking {
            if blocking
                .blocking_auth_project()
                .is_some_and(|project| project != endpoints.project)
            {
                return Err(ArtifactError::new(
                    "auth",
                    &section_dir,
                    "blocking settings belong to a different project",
                ));
            }
            blocking
                .blocking_auth_settings_for_export()
                .map_err(|error| ArtifactError::new("auth", &section_dir, error))?
                .map(|value| blocking_settings_record_from_json(&value, &section_dir))
                .transpose()?
        } else {
            None
        };
        (snapshot, project_blocking)
    };
    let store = snapshot.default_store();
    let mut file = AccountsFile::default();
    for user in store.users_by_creation() {
        file.users.push(exported_account(store, user, None));
    }
    let accounts_path = section_dir.join(ACCOUNTS_FILE);
    write_private_file(&accounts_path, file.to_json().as_bytes())
        .map_err(|e| ArtifactError::new("auth", &accounts_path, e))?;

    let config = store.config();
    let config_path = section_dir.join(CONFIG_FILE);
    let document = AuthConfig {
        allow_duplicate_emails: Some(config.allow_duplicate_emails),
        enable_improved_email_privacy: Some(config.enable_improved_email_privacy),
        disabled_user_signup: Some(config.disabled_user_signup),
        disabled_user_deletion: Some(config.disabled_user_deletion),
    };
    write_private_file(&config_path, document.to_json().as_bytes())
        .map_err(|e| ArtifactError::new("auth", &config_path, e))?;
    let project_policy = exported_password_policy(store.password_policy());
    let project_quota = store.signup_quota().config().clone();
    let mut tenant_policies = Vec::new();
    let mut tenant_settings = Vec::new();
    for (tenant, tenant_store) in snapshot.tenant_stores() {
        let tenant_metadata = snapshot.tenant_metadata(tenant).ok_or_else(|| {
            ArtifactError::new(
                "auth",
                &section_dir,
                format!("tenant {tenant:?} has no captured authorization metadata"),
            )
        })?;
        let tenant_policy = exported_password_policy(tenant_store.password_policy());
        if tenant_policy != exported_password_policy(&PasswordPolicy::default()) {
            tenant_policies.push(PasswordPolicyNamespace {
                tenant_id: Some(tenant.to_owned()),
                policy: tenant_policy,
            });
        }
        let tenant_quota = tenant_store.signup_quota().config().clone();
        let tenant_config_override = snapshot.tenant_config_override(tenant);
        tenant_settings.push(AuthSettingsNamespace {
            tenant_id: Some(tenant.to_owned()),
            settings: AuthSettingsRecord {
                config: tenant_config_override.map(exported_tenant_config_patch),
                quota: (tenant_quota != SignupQuotaConfig::default())
                    .then(|| exported_quota_settings(&tenant_quota)),
                blocking: None,
            },
            config_is_explicit: tenant_config_override.is_some(),
            metadata: Some(exported_tenant_metadata(tenant_metadata)),
        });
        let mut file = AccountsFile::default();
        for user in tenant_store.users_by_creation() {
            file.users
                .push(exported_account(tenant_store, user, Some(tenant)));
        }
        let path = section_dir.join(format!("accounts-{tenant}.json"));
        write_private_file(&path, file.to_json().as_bytes())
            .map_err(|e| ArtifactError::new("auth", &path, e))?;
    }

    // The official export format has no password-policy member. Keep this state in an
    // explicit fireemu sidecar so ordinary config.json fixtures remain byte-compatible and
    // the official CLI can continue to ignore the extension safely.
    if project_policy != exported_password_policy(&PasswordPolicy::default())
        || !tenant_policies.is_empty()
    {
        let path = section_dir.join(PASSWORD_POLICIES_FILE);
        let policies = PasswordPolicies {
            project_id: endpoints.project.to_owned(),
            project: project_policy,
            namespaces: tenant_policies,
        };
        write_private_file(&path, policies.to_json().as_bytes())
            .map_err(|e| ArtifactError::new("auth", &path, e))?;
    }
    if project_quota != SignupQuotaConfig::default()
        || project_blocking.is_some()
        || !tenant_settings.is_empty()
    {
        let path = section_dir.join(AUTH_SETTINGS_FILE);
        let settings = AuthSettings {
            project_id: endpoints.project.to_owned(),
            project: AuthSettingsRecord {
                config: None,
                quota: (project_quota != SignupQuotaConfig::default())
                    .then(|| exported_quota_settings(&project_quota)),
                blocking: project_blocking,
            },
            namespaces: tenant_settings,
        };
        write_private_file(&path, settings.to_json().as_bytes())
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

/// The fireemu-only account member that carries a foreign hash `accounts:batchCreate`
/// imported (the Identity Toolkit document has no algorithm field for it), so an export and
/// restore keep the credential instead of dropping it (external review 2026-09-24).
const IMPORTED_PASSWORD_MEMBER: &str = "fireemuImportedPassword";

fn imported_password_json(
    hash: &fireemu_core_auth::store::ImportedPasswordHash,
) -> fireemu_core_export::json::Json {
    use fireemu_core_export::json::Json;
    Json::Object(vec![
        ("spec".to_owned(), Json::String(hash.spec.clone())),
        (
            "hash".to_owned(),
            Json::String(fireemu_core_types::hash::base64_standard(&hash.hash)),
        ),
        (
            "salt".to_owned(),
            Json::String(fireemu_core_types::hash::base64_standard(&hash.salt)),
        ),
    ])
}

fn imported_password_of(
    value: &fireemu_core_export::json::Json,
) -> Option<fireemu_core_auth::store::ImportedPasswordHash> {
    use fireemu_core_export::json::Json;
    let Json::Object(members) = value else {
        return None;
    };
    let text = |key: &str| {
        members.iter().find_map(|(name, value)| match value {
            Json::String(text) if name == key => Some(text.as_str()),
            _ => None,
        })
    };
    if members.len() != 3 {
        return None;
    }
    let hash = fireemu_core_auth::store::ImportedPasswordHash {
        spec: text("spec")?.to_owned(),
        hash: decode_base64(text("hash")?)?,
        salt: decode_base64(text("salt")?)?,
    };
    // A restored spec keeps the parameter ranges an import enforces (closure re-review
    // 2026-09-24): an out-of-range spec is refused rather than installed.
    fireemu_adapter_http::identity_toolkit::restorable_imported_hash_spec(&hash.spec, &hash.hash)
        .then_some(hash)
}

/// One account as the Identity Toolkit document an export carries.
fn exported_account(
    store: &fireemu_core_auth::store::AuthStore,
    user: &fireemu_core_auth::store::UserRecord,
    tenant_id: Option<&str>,
) -> UserRecord {
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
    // A foreign hash `accounts:batchCreate` imported travels in the fireemu-only member.
    let imported_extra = store
        .password_digest(&user.local_id)
        .filter(|digest| digest.emulator_form().is_none())
        .and_then(fireemu_core_auth::store::PasswordDigest::imported_hash)
        .map(|hash| {
            vec![(
                IMPORTED_PASSWORD_MEMBER.to_owned(),
                imported_password_json(hash),
            )]
        })
        .unwrap_or_default();
    let has_password = password_hash.is_some() || store.has_password(&user.local_id);
    let email_link_signin =
        user.provider == fireemu_core_auth::store::Provider::EmailLink && !has_password;
    let providers = exported_providers(user, has_password, email_link_signin);
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
        email_link_signin,
        password_hash,
        salt,
        #[allow(clippy::cast_precision_loss)]
        password_updated_at: store
            .password_updated_at(&user.local_id)
            .map(|t| (t.as_nanos() / 1_000_000) as f64),
        valid_since: Some((user.tokens_valid_after.as_nanos() / 1_000_000_000).to_string()),
        created_at: Some((user.created_at.as_nanos() / 1_000_000).to_string()),
        last_login_at: user
            .last_sign_in_at
            .map(|t| (t.as_nanos() / 1_000_000).to_string()),
        last_refresh_at: user
            .last_refresh_at
            .and_then(|t| LogicalInstant::to_rfc3339(t).ok()),
        custom_attributes: (claims != "{}").then_some(claims),
        tenant_id: tenant_id.map(str::to_owned),
        provider_user_info: providers,
        mfa_info,
        extra: imported_extra,
    }
}

fn exported_providers(
    user: &fireemu_core_auth::store::UserRecord,
    has_password: bool,
    email_link_signin: bool,
) -> Vec<ProviderUserInfo> {
    let mut providers = Vec::new();
    if let Some(email) = user.email.as_ref().filter(|_| {
        matches!(&user.provider, Provider::Password) || has_password || email_link_signin
    }) {
        providers.push(ProviderUserInfo {
            provider_id: "password".to_owned(),
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
    providers.extend(user.federated.iter().map(|identity| ProviderUserInfo {
        provider_id: identity.provider_id.clone(),
        raw_id: identity.raw_id.clone(),
        federated_id: Some(identity.raw_id.clone()),
        email: identity.email.clone(),
        display_name: identity.display_name.clone(),
        photo_url: identity.photo_url.clone(),
        phone_number: None,
        screen_name: None,
    }));
    providers
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

    let store = endpoints
        .storage
        .store
        .lock()
        .map_err(|_| ArtifactError::new("storage", &section_dir, "the object store is poisoned"))?
        .capture_buckets(|_| true);
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
fn create_private_file(path: &Path) -> Result<std::fs::File, String> {
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
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot write it: {e}"))
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> Result<std::fs::File, String> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }
    std::fs::File::create(path).map_err(|e| format!("cannot write it: {e}"))
}

/// Writes a file owner-only, replacing what was there.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut file = create_private_file(path)?;
    file.write_all(bytes)
        .map_err(|e| format!("cannot write it: {e}"))?;
    Ok(())
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
    FIELD_CONFIG_FILE,
    "firestore_export",
    "auth_export",
    "storage_export",
    "database_export",
    "dataconnect_export",
];

#[cfg(test)]
mod tests {
    use super::{
        civil_from_days, decode_base32, decode_base64, enforce_storage_object_count,
        field_config_json, imported_instant, may_overwrite, parse_field_config, read_field_config,
        read_inside_budgeted, read_inside_limited, rfc3339_instant, rfc3339_text, scan_import_tree,
        tenant_config_from_settings, UnmanagedCopyBudget, FIELD_CONFIG_BYTES_LIMIT,
        FIELD_CONFIG_FILE, IMPORT_STORAGE_OBJECT_COUNT_LIMIT,
    };
    use fireemu_core_auth::store::{ProjectAuthConfig, TenantMetadata};
    use fireemu_core_export::auth::{AuthConfig, AuthSettingsNamespace, AuthSettingsRecord};
    use fireemu_core_types::time::{days_from_civil, LogicalInstant};
    #[cfg(unix)]
    use fireemu_export_publication::PublicationStage;

    #[cfg(unix)]
    use super::open_file_inside;
    #[cfg(unix)]
    use super::trusted_temp::TrustedTempDir;

    #[cfg(windows)]
    #[test]
    fn export_entry_fails_before_creating_a_destination_on_windows() {
        use std::sync::{Arc, Mutex};

        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore};
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};

        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let gateway = Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
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
            rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
            project: "demo-app".to_owned(),
            events: None,
            barrier: None,
            firestore: None,
            faults: None,
            clock_observer: None,
            app_check_policy: None,
            admin_capability: None,
            token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
            control_token: None,
        });
        let endpoints = super::Endpoints {
            backend: &backend,
            auth: &auth,
            storage: &storage,
            clock: &clock,
            project: "demo-app",
            blocking: None,
            auth_operation_gate: None,
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

    #[cfg(unix)]
    fn budget_dir(name: &str) -> TrustedTempDir {
        TrustedTempDir::new(&format!("import-budget-{name}"))
    }

    #[test]
    fn auth_settings_quota_conversion_preserves_the_config_without_usage() {
        use fireemu_core_auth::signup_quota::{
            QuotaAlgorithm, QuotaMode, SignupQuotaConfig, TemporaryQuota,
        };
        use fireemu_core_types::time::LogicalDuration;

        let config = SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            algorithm: QuotaAlgorithm::FixedWindowV1,
            default_quota_per_hour: 7,
            max_tracked_buckets: 12,
            temporary: Some(
                TemporaryQuota::new(
                    9,
                    LogicalInstant::from_unix_seconds(1_893_456_000),
                    LogicalDuration::from_seconds(90),
                )
                .expect("temporary quota is valid"),
            ),
        };
        let record = super::exported_quota_settings(&config);
        let restored = super::imported_quota_settings(
            &record,
            std::path::Path::new("auth_export/fireemu-auth-settings.json"),
        )
        .expect("quota sidecar parses");
        assert_eq!(restored, config);
    }

    #[test]
    fn blocking_settings_conversion_preserves_mixed_discovery_events() {
        let record = super::BlockingAuthSettingsRecord {
            before_create: super::BlockingAuthSelectionRecord::Discovery,
            before_sign_in: super::BlockingAuthSelectionRecord::Explicit {
                function_uri: "fireemu://functions/demo-app/us-central1/checkSignIn".to_owned(),
            },
            forwarding: None,
        };
        let encoded = super::blocking_settings_json(&record);
        assert_eq!(
            super::blocking_settings_record_from_json(
                &encoded,
                std::path::Path::new("auth_export/fireemu-auth-settings.json")
            )
            .expect("blocking settings parse"),
            record
        );
        assert!(encoded.to_string().contains("__fireemuDiscoveryEvents"));
        assert!(!encoded.to_string().contains("127.0.0.1"));
    }

    #[test]
    fn blocking_settings_conversion_distinguishes_absent_triggers_from_absent_events() {
        let path = std::path::Path::new("auth_export/fireemu-auth-settings.json");

        let absent = super::blocking_settings_record_from_json(&serde_json::json!({}), path)
            .expect("absent triggers select discovery");
        assert_eq!(
            absent.before_create,
            super::BlockingAuthSelectionRecord::Discovery
        );
        assert_eq!(
            absent.before_sign_in,
            super::BlockingAuthSelectionRecord::Discovery
        );

        let empty =
            super::blocking_settings_record_from_json(&serde_json::json!({"triggers": {}}), path)
                .expect("an empty triggers object disables both events");
        assert_eq!(
            empty.before_create,
            super::BlockingAuthSelectionRecord::Disabled
        );
        assert_eq!(
            empty.before_sign_in,
            super::BlockingAuthSelectionRecord::Disabled
        );
    }

    #[test]
    fn auth_settings_conversion_does_not_drop_destination_namespace_values() {
        let destination = ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: false,
            disabled_user_signup: false,
            disabled_user_deletion: true,
        };
        let config = AuthConfig {
            allow_duplicate_emails: None,
            enable_improved_email_privacy: None,
            disabled_user_signup: Some(true),
            disabled_user_deletion: None,
        };
        assert_eq!(
            super::auth_config_from_settings(&config, destination),
            ProjectAuthConfig {
                allow_duplicate_emails: true,
                enable_improved_email_privacy: false,
                disabled_user_signup: true,
                disabled_user_deletion: true,
            }
        );
    }

    #[test]
    fn legacy_tenant_settings_are_migrated_as_inherited_configuration() {
        let current = ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: false,
            disabled_user_signup: false,
            disabled_user_deletion: true,
        };
        let legacy = AuthSettingsNamespace {
            tenant_id: Some("tenant-a".to_owned()),
            settings: AuthSettingsRecord {
                config: Some(AuthConfig {
                    allow_duplicate_emails: Some(false),
                    enable_improved_email_privacy: Some(true),
                    disabled_user_signup: Some(true),
                    disabled_user_deletion: Some(false),
                }),
                quota: None,
                blocking: None,
            },
            config_is_explicit: false,
            metadata: None,
        };
        assert_eq!(
            tenant_config_from_settings(Some(&legacy), current),
            current,
            "an unversioned effective projection must not become a frozen override"
        );

        let mut explicit = legacy;
        explicit.config_is_explicit = true;
        assert_eq!(
            tenant_config_from_settings(Some(&explicit), current),
            ProjectAuthConfig {
                allow_duplicate_emails: false,
                enable_improved_email_privacy: true,
                disabled_user_signup: true,
                disabled_user_deletion: false,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn explicit_tenant_config_equal_to_project_default_survives_export_import() {
        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{
            AuthNamespaceConfigPatch, AuthRegistry, AuthStore, ProjectAuthConfigPatch,
        };
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
        use std::sync::{Arc, Mutex};

        let make_runtime = |auth: Arc<AuthRegistry>, clock: Arc<Mutex<VirtualClock>>, seed: u64| {
            let backend = Arc::new(LocalBackend::new(
                Gateway {
                    enforce_limits: true,
                    ctx: PlanningContext {
                        edition: FirestoreEdition::Standard,
                        api_mode: FirestoreApiMode::Native,
                        policy: IndexValidationPolicy::Production,
                    },
                    indexes: IndexSet::default(),
                },
                clock.clone(),
                seed,
            ));
            let storage = Arc::new(fireemu_adapter_http::storage::StorageState {
                store: Mutex::new(fireemu_core_storage::store::StorageState::new(seed)),
                clock,
                auth,
                tenancy: None,
                rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
                project: "demo-app".to_owned(),
                events: None,
                barrier: None,
                firestore: None,
                faults: None,
                clock_observer: None,
                app_check_policy: None,
                admin_capability: None,
                token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
                control_token: None,
            });
            (backend, storage)
        };

        let source_clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let source_default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let source_auth = Arc::new(AuthRegistry::new("demo-app", source_default));
        source_auth
            .ensure_tenant("demo-app", "tenant-a")
            .expect("source tenant is created");
        source_auth
            .ensure_tenant("demo-app", "tenant-inherited")
            .expect("inherited source tenant is created");
        // Every selected value equals the project/default value. The override's presence, not
        // a value difference, is the state this round trip must preserve.
        assert!(source_auth.register_tenant_config_override(
            "demo-app",
            "tenant-a",
            AuthNamespaceConfigPatch {
                allow_duplicate_emails: Some(false),
                enable_improved_email_privacy: Some(false),
                disabled_user_signup: Some(false),
                disabled_user_deletion: Some(false),
            },
        ));
        let (source_backend, source_storage) =
            make_runtime(source_auth.clone(), source_clock.clone(), 7);
        let source_endpoints = super::Endpoints {
            backend: &source_backend,
            auth: &source_auth,
            storage: &source_storage,
            clock: &source_clock,
            project: "demo-app",
            blocking: None,
            auth_operation_gate: None,
        };

        let export_root = super::trusted_temp::TrustedTempDir::new("tenant-config-roundtrip");
        let export_dir = export_root.join("export");
        super::export(
            &export_dir,
            super::Products {
                firestore: false,
                auth: true,
                storage: false,
            },
            &source_endpoints,
            "test",
        )
        .expect("Auth export succeeds");
        let sidecar = std::fs::read_to_string(
            export_dir
                .join(super::AUTH_PATH)
                .join(super::AUTH_SETTINGS_FILE),
        )
        .expect("Auth settings sidecar exists");
        assert!(sidecar.contains("\"config\""));
        assert!(sidecar.contains("\"allowDuplicateEmails\": false"));
        let sidecar_value: serde_json::Value = serde_json::from_str(&sidecar).unwrap();
        let inherited_entry = sidecar_value["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["tenantId"] == "tenant-inherited")
            .expect("inherited tenant sidecar entry");
        assert!(inherited_entry["settings"]["config"].is_null());

        let destination_clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let destination_default = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(2),
            TotpPolicy::default(),
        )));
        destination_default
            .lock()
            .expect("destination store lock")
            .set_config(fireemu_core_auth::store::ProjectAuthConfig {
                allow_duplicate_emails: true,
                ..fireemu_core_auth::store::ProjectAuthConfig::default()
            });
        let destination_auth = Arc::new(AuthRegistry::new("demo-app", destination_default));
        let (destination_backend, destination_storage) =
            make_runtime(destination_auth.clone(), destination_clock.clone(), 8);
        let destination_endpoints = super::Endpoints {
            backend: &destination_backend,
            auth: &destination_auth,
            storage: &destination_storage,
            clock: &destination_clock,
            project: "demo-app",
            blocking: None,
            auth_operation_gate: None,
        };
        let prepared = super::prepare(
            &export_dir,
            super::Products {
                firestore: false,
                auth: true,
                storage: false,
            },
            "demo-app",
        )
        .expect("Auth export is prepared");
        super::apply(prepared, &destination_endpoints).expect("Auth import succeeds");

        let tenant = destination_auth
            .tenant_store("demo-app", "tenant-a")
            .expect("imported tenant exists");
        let inherited_tenant = destination_auth
            .tenant_store("demo-app", "tenant-inherited")
            .expect("imported inherited tenant exists");
        assert!(
            !tenant
                .lock()
                .expect("imported tenant lock")
                .config()
                .allow_duplicate_emails
        );
        assert!(
            !inherited_tenant
                .lock()
                .expect("inherited tenant lock")
                .config()
                .allow_duplicate_emails
        );

        assert!(destination_auth
            .patch_project_config(
                "demo-app",
                ProjectAuthConfigPatch {
                    allow_duplicate_emails: Some(true),
                    ..ProjectAuthConfigPatch::default()
                },
            )
            .is_some());
        assert!(
            !tenant
                .lock()
                .expect("restored tenant lock")
                .config()
                .allow_duplicate_emails
        );
        assert!(
            inherited_tenant
                .lock()
                .expect("restored inherited tenant lock")
                .config()
                .allow_duplicate_emails
        );
    }

    #[test]
    fn tenant_metadata_export_conversion_preserves_all_authorization_controls() {
        let metadata = TenantMetadata {
            display_name: Some("Tenant A".to_owned()),
            allow_password_signup: false,
            enable_email_link_signin: true,
            enable_anonymous_user: false,
            disable_auth: true,
            disabled_user_signup: true,
            disabled_user_deletion: false,
            enable_improved_email_privacy: true,
        };
        let record = super::exported_tenant_metadata(&metadata);
        assert_eq!(super::imported_tenant_metadata(&record), metadata);
    }

    #[test]
    fn omitted_duplicate_email_setting_preserves_import_destination_value() {
        let destination = ProjectAuthConfig {
            allow_duplicate_emails: true,
            ..ProjectAuthConfig::default()
        };
        let mut omitted = super::PreparedAuth::default();
        omitted.config.allow_duplicate_emails = false;
        assert!(omitted.config_over(destination).allow_duplicate_emails);

        let mut explicit = super::PreparedAuth::default();
        explicit.config.allow_duplicate_emails = false;
        explicit.allow_duplicate_emails_declared = true;
        assert!(!explicit.config_over(destination).allow_duplicate_emails);
    }

    #[cfg(not(unix))]
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

    #[cfg(unix)]
    #[test]
    fn a_fifo_replacing_an_import_file_is_rejected_without_blocking() {
        let root = budget_dir("fifo-leaf");
        let fifo = root.join("output-0");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());

        let started = std::time::Instant::now();
        let error = open_file_inside(&root, &fifo).unwrap_err();

        assert!(error.contains("not a regular file"), "{error}");
        assert!(started.elapsed() < std::time::Duration::from_millis(100));
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
    fn malformed_storage_timestamps_are_positioned_import_errors() {
        let path = std::path::Path::new("storage_export/metadata/object.json");
        let error = imported_instant(Some("yesterday"), "updated", path)
            .expect_err("a present malformed timestamp is rejected");
        assert_eq!(error.product, "storage");
        assert_eq!(error.path, path);
        assert!(error.message.contains("updated"));
        assert!(error.message.contains("RFC 3339"));
        assert_eq!(
            imported_instant(None, "updated", path).unwrap(),
            LogicalInstant::from_unix_seconds(0)
        );
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
    #[test]
    #[allow(clippy::too_many_lines)]
    fn auth_import_blocking_update_failure_preserves_auth_and_blocking_state() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use fireemu_adapter_grpc::gateway::Gateway;
        use fireemu_adapter_grpc::local::LocalBackend;
        use fireemu_adapter_http::identity_toolkit::{AuthBlockingHook, BlockingFunctionFailure};
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
        use fireemu_core_export::auth::{
            AuthSettings, AuthSettingsRecord, BlockingAuthSelectionRecord,
            BlockingAuthSettingsRecord,
        };
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::determinism::SplitMix64;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
        use serde_json::Value;

        struct FailingBlockingHook {
            settings: Mutex<Value>,
            update_calls: AtomicUsize,
            restore_calls: AtomicUsize,
        }

        impl AuthBlockingHook for FailingBlockingHook {
            fn invoke(
                &self,
                _event: fireemu_core_functions::manifest::BlockingAuthEvent,
                _user: &fireemu_core_auth::store::UserRecord,
            ) -> Result<Value, BlockingFunctionFailure> {
                Err(BlockingFunctionFailure::unhandled())
            }

            fn blocking_auth_settings(&self) -> Option<Value> {
                self.settings.lock().ok().map(|settings| settings.clone())
            }

            fn blocking_auth_settings_snapshot(&self) -> Result<Option<Value>, String> {
                Ok(self.blocking_auth_settings())
            }

            fn validate_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
                Ok(())
            }

            fn update_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
                self.update_calls.fetch_add(1, Ordering::Relaxed);
                Err("injected blocking settings update failure".to_owned())
            }

            fn restore_blocking_auth_settings_snapshot(
                &self,
                snapshot: &Value,
            ) -> Result<(), String> {
                self.restore_calls.fetch_add(1, Ordering::Relaxed);
                *self
                    .settings
                    .lock()
                    .map_err(|_| "settings poisoned".to_owned())? = snapshot.clone();
                Ok(())
            }
        }

        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
        let backend = Arc::new(LocalBackend::new(
            Gateway {
                enforce_limits: true,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Standard,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Production,
                },
                indexes: IndexSet::default(),
            },
            clock.clone(),
            7,
        ));
        let default_store = Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let auth = Arc::new(AuthRegistry::new("demo-app", default_store.clone()));
        let original_config = ProjectAuthConfig {
            allow_duplicate_emails: true,
            enable_improved_email_privacy: true,
            disabled_user_signup: false,
            disabled_user_deletion: true,
        };
        let original_uid = {
            let mut store = default_store.lock().unwrap();
            store.set_config(original_config);
            store
                .create_user(
                    NewUser::email("before@example.test"),
                    LogicalInstant::UNIX_EPOCH,
                )
                .unwrap()
        };
        let tenant_store = auth.ensure_tenant("demo-app", "existing").unwrap();
        let original_tenant_config = ProjectAuthConfig {
            allow_duplicate_emails: false,
            enable_improved_email_privacy: true,
            disabled_user_signup: true,
            disabled_user_deletion: false,
        };
        let original_tenant_uid = {
            let mut store = tenant_store.lock().unwrap();
            store.set_config(original_tenant_config);
            store
                .create_user(
                    NewUser::email("tenant@example.test"),
                    LogicalInstant::UNIX_EPOCH,
                )
                .unwrap()
        };
        let original_tenant_metadata = auth.tenant_metadata("demo-app", "existing").unwrap();
        let blocking = FailingBlockingHook {
            settings: Mutex::new(serde_json::json!({
                "triggers": {
                    "beforeCreate": null,
                    "beforeSignIn": null
                }
            })),
            update_calls: AtomicUsize::new(0),
            restore_calls: AtomicUsize::new(0),
        };
        let storage = Arc::new(fireemu_adapter_http::storage::StorageState {
            store: Mutex::new(fireemu_core_storage::store::StorageState::new(9)),
            clock: clock.clone(),
            auth: auth.clone(),
            tenancy: None,
            rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
            project: "demo-app".to_owned(),
            events: None,
            barrier: None,
            firestore: None,
            faults: None,
            clock_observer: None,
            app_check_policy: None,
            admin_capability: None,
            token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
            control_token: None,
        });
        let endpoints = super::Endpoints {
            backend: &backend,
            auth: &auth,
            storage: &storage,
            clock: &clock,
            project: "demo-app",
            blocking: Some(&blocking),
            auth_operation_gate: None,
        };
        let imported_blocking = BlockingAuthSettingsRecord {
            before_create: BlockingAuthSelectionRecord::Disabled,
            before_sign_in: BlockingAuthSelectionRecord::Disabled,
            forwarding: None,
        };
        let prepared = super::PreparedAuth {
            auth_settings: Some(AuthSettings {
                project_id: "demo-app".to_owned(),
                project: AuthSettingsRecord {
                    config: None,
                    quota: None,
                    blocking: Some(imported_blocking),
                },
                namespaces: Vec::new(),
            }),
            ..super::PreparedAuth::default()
        };

        let error = super::apply_auth(&prepared, &endpoints).unwrap_err();

        assert!(
            error
                .message
                .contains("injected blocking settings update failure"),
            "{error:?}"
        );
        assert_eq!(blocking.update_calls.load(Ordering::Relaxed), 1);
        assert_eq!(blocking.restore_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            blocking.blocking_auth_settings(),
            Some(serde_json::json!({
                "triggers": {
                    "beforeCreate": null,
                    "beforeSignIn": null
                }
            }))
        );
        let default = default_store.lock().unwrap();
        assert_eq!(default.config(), original_config);
        assert!(default.user_by_id(original_uid.as_str()).is_some());
        assert_eq!(default.user_count(), 1);
        drop(default);
        assert_eq!(auth.tenants("demo-app"), vec!["existing".to_owned()]);
        assert_eq!(
            auth.tenant_metadata("demo-app", "existing"),
            Some(original_tenant_metadata)
        );
        let tenant = tenant_store.lock().unwrap();
        assert_eq!(tenant.config(), original_tenant_config);
        assert!(tenant.user_by_id(original_tenant_uid.as_str()).is_some());
        assert_eq!(tenant.user_count(), 1);
    }

    #[test]
    fn auth_import_preflight_refuses_poisoned_tenant_before_default_mutation() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
        use fireemu_core_types::determinism::SplitMix64;

        let default = std::sync::Arc::new(std::sync::Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(1),
            TotpPolicy::default(),
        )));
        let uid = default
            .lock()
            .unwrap()
            .create_user(NewUser::anonymous(), LogicalInstant::UNIX_EPOCH)
            .unwrap();
        let registry = AuthRegistry::new("demo-app", default.clone());
        let tenant = registry.ensure_tenant("demo-app", "broken").unwrap();
        let poison = std::thread::spawn(move || {
            let _guard = tenant.lock().unwrap();
            panic!("poison tenant for import preflight");
        });
        assert!(poison.join().is_err());

        let error = super::preflight_auth_tenant_stores(&registry, "demo-app").unwrap_err();
        assert!(error
            .message
            .contains("tenant \"broken\" store is poisoned"));
        assert!(default.lock().unwrap().user_by_id(uid.as_str()).is_some());
    }

    /// Accounts `accounts:batchCreate` let share an address restore from their own export
    /// without switching duplicate emails on (external review 2026-09-24).
    #[test]
    fn imported_accounts_sharing_an_email_restore_from_their_export() {
        use fireemu_core_auth::{mfa::TotpPolicy, store::AuthStore};
        use fireemu_core_export::auth::UserRecord;
        use fireemu_core_types::determinism::SplitMix64;
        let path = std::path::Path::new("offline.json");
        let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        for uid in ["a", "b"] {
            let record = UserRecord {
                local_id: uid.to_owned(),
                email: Some("shared@example.com".to_owned()),
                created_at: Some("100000".to_owned()),
                ..UserRecord::default()
            };
            let mut user = super::imported_user(&record, path).unwrap();
            user.allow_shared_email = true;
            store.import_user(user).unwrap();
        }
        assert!(!store.config().allow_duplicate_emails);
        let mut restored = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
        for uid in ["a", "b"] {
            let exported = super::exported_account(&store, store.user_by_id(uid).unwrap(), None);
            let imported = super::imported_user(&exported, path).unwrap();
            restored.import_user_trusted(imported).unwrap();
        }
        assert_eq!(restored.users_by_email("shared@example.com").len(), 2);
        assert!(!restored.config().allow_duplicate_emails);
    }

    /// A foreign hash imported through `accounts:batchCreate` survives an export and restore
    /// instead of being dropped (external review 2026-09-24).
    #[test]
    fn an_imported_foreign_hash_round_trips_through_export() {
        use fireemu_core_auth::{
            mfa::TotpPolicy,
            store::{AuthStore, ImportedPasswordHash},
        };
        use fireemu_core_export::auth::UserRecord;
        use fireemu_core_types::determinism::SplitMix64;
        let path = std::path::Path::new("offline.json");
        let hash = ImportedPasswordHash {
            spec: r#"{"algorithm":"SHA","family":"SHA256","order":"SALT_AND_PASSWORD","rounds":1}"#
                .to_owned(),
            hash: vec![1, 2, 3, 250],
            salt: vec![4, 5],
        };
        let record = UserRecord {
            local_id: "h".to_owned(),
            email: Some("hashed@example.com".to_owned()),
            created_at: Some("100000".to_owned()),
            ..UserRecord::default()
        };
        let mut user = super::imported_user(&record, path).unwrap();
        user.imported_password = Some(hash.clone());
        let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        store.import_user(user).unwrap();
        let exported = super::exported_account(&store, store.user_by_id("h").unwrap(), None);
        assert!(exported.password_hash.is_none());
        let restored_user = super::imported_user(&exported, path).unwrap();
        assert_eq!(restored_user.imported_password, Some(hash));
        let mut restored = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
        restored.import_user_trusted(restored_user).unwrap();
        let uid = restored.user_by_id("h").unwrap().local_id.clone();
        assert!(restored.password_digest(&uid).is_some());
    }

    /// A restored foreign hash keeps the import's parameter ranges: an out-of-range spec in
    /// `fireemuImportedPassword` refuses the account instead of installing it (closure
    /// re-review 2026-09-24).
    #[test]
    fn a_restored_foreign_hash_outside_the_import_ranges_is_refused() {
        use fireemu_core_export::{auth::UserRecord, json::Json};
        let member = |spec: &str| {
            Json::Object(vec![
                ("spec".to_owned(), Json::String(spec.to_owned())),
                ("hash".to_owned(), Json::String("AQID".to_owned())),
                ("salt".to_owned(), Json::String("BA==".to_owned())),
            ])
        };
        let record = |spec: &str| UserRecord {
            local_id: "r".to_owned(),
            email: Some("restored@example.com".to_owned()),
            created_at: Some("100000".to_owned()),
            extra: vec![(super::IMPORTED_PASSWORD_MEMBER.to_owned(), member(spec))],
            ..UserRecord::default()
        };
        let path = std::path::Path::new("offline.json");
        let crashing =
            r#"{"algorithm":"SCRYPT","key":"AQID","separator":"Bw==","rounds":8,"memoryCost":40}"#;
        assert!(super::imported_user(&record(crashing), path).is_err());
        let bounded =
            r#"{"algorithm":"SCRYPT","key":"AQID","separator":"Bw==","rounds":8,"memoryCost":14}"#;
        assert!(super::imported_user(&record(bounded), path)
            .unwrap()
            .imported_password
            .is_some());
    }

    #[test]
    fn last_token_issuance_round_trips_without_lookup_time_fabrication() {
        use fireemu_core_auth::{
            mfa::TotpPolicy,
            store::{AuthStore, NewUser},
        };
        use fireemu_core_types::determinism::SplitMix64;
        let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        let at = LogicalInstant::from_unix_seconds(100);
        let uid = store.create_user(NewUser::anonymous(), at).unwrap();
        let token = store
            .issue_refresh_session(&uid, at, None, super::CustomClaims::default(), None)
            .unwrap();
        store.record_token_issuance(&token, at);
        let exported = super::exported_account(&store, store.user(&uid).unwrap(), None);
        assert_eq!(
            exported.last_refresh_at.as_deref(),
            Some("1970-01-01T00:01:40Z")
        );
        let imported =
            super::imported_user(&exported, std::path::Path::new("offline.json")).unwrap();
        let mut restored = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
        restored.import_user(imported).unwrap();
        assert_eq!(
            super::exported_account(&restored, restored.user_by_id(uid.as_str()).unwrap(), None)
                .last_refresh_at,
            exported.last_refresh_at
        );
    }

    #[test]
    fn a_hashless_password_provider_with_an_email_stays_password() {
        use fireemu_core_export::auth::{ProviderUserInfo, UserRecord};

        let record = UserRecord {
            email: Some("link@example.com".to_owned()),
            provider_user_info: vec![ProviderUserInfo {
                provider_id: "password".to_owned(),
                raw_id: "link@example.com".to_owned(),
                ..ProviderUserInfo::default()
            }],
            ..UserRecord::default()
        };

        assert_eq!(
            super::provider_of(&record),
            fireemu_core_auth::store::Provider::Password
        );
    }

    #[test]
    fn an_email_link_marker_cannot_relabel_a_password_account() {
        use fireemu_core_export::auth::{ProviderUserInfo, UserRecord};

        let record = UserRecord {
            email: Some("password@example.com".to_owned()),
            email_link_signin: true,
            password_hash: Some("fakeHash:salt=s:password=p".to_owned()),
            provider_user_info: vec![ProviderUserInfo {
                provider_id: "password".to_owned(),
                raw_id: "password@example.com".to_owned(),
                ..ProviderUserInfo::default()
            }],
            ..UserRecord::default()
        };

        assert_eq!(
            super::provider_of(&record),
            fireemu_core_auth::store::Provider::Password
        );
    }

    #[test]
    fn removed_password_provider_is_not_reintroduced_by_export() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, FederatedIdentity, NewUser, Provider};
        use fireemu_core_types::determinism::SplitMix64;

        let mut store = AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default());
        let created_at = LogicalInstant::from_unix_seconds(100);
        let uid = store
            .create_user(NewUser::email("switch@example.com"), created_at)
            .expect("the password account is created");
        store
            .sign_in_with_idp(
                FederatedIdentity {
                    provider_id: "google.com".to_owned(),
                    raw_id: "google-user".to_owned(),
                    email: Some("switch@example.com".to_owned()),
                    display_name: None,
                    photo_url: None,
                },
                true,
                LogicalInstant::from_unix_seconds(101),
            )
            .expect("the verified IdP sign-in succeeds");

        let user = store
            .user(&uid)
            .expect("the account remains after recycling");
        assert_eq!(user.provider, Provider::Federated("google.com".to_owned()));
        assert!(!store.has_password(&uid));
        let exported = super::exported_account(&store, user, None);
        assert!(exported
            .provider_user_info
            .iter()
            .all(|provider| provider.provider_id != "password"));
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "google.com"));

        let imported = super::imported_user(&exported, std::path::Path::new("offline.json"))
            .expect("the exported account is importable");
        let mut restored = AuthStore::new("demo-app", SplitMix64::new(8), TotpPolicy::default());
        let restored_uid = restored.import_user(imported).expect("the account imports");
        let reexported = super::exported_account(
            &restored,
            restored
                .user_by_id(restored_uid.as_str())
                .expect("the imported account exists"),
            None,
        );
        assert!(reexported
            .provider_user_info
            .iter()
            .all(|provider| provider.provider_id != "password"));
    }

    #[test]
    fn hashless_password_provider_with_federated_identity_is_preserved() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::AuthStore;
        use fireemu_core_export::auth::{ProviderUserInfo, UserRecord};
        use fireemu_core_types::determinism::SplitMix64;

        let record = UserRecord {
            local_id: "hashless-linked".to_owned(),
            email: Some("linked@example.com".to_owned()),
            provider_user_info: vec![
                ProviderUserInfo {
                    provider_id: "password".to_owned(),
                    raw_id: "linked@example.com".to_owned(),
                    ..ProviderUserInfo::default()
                },
                ProviderUserInfo {
                    provider_id: "google.com".to_owned(),
                    raw_id: "google-linked".to_owned(),
                    ..ProviderUserInfo::default()
                },
            ],
            ..UserRecord::default()
        };
        let imported = super::imported_user(&record, std::path::Path::new("offline.json"))
            .expect("the hashless account imports");
        let mut store = AuthStore::new("demo-app", SplitMix64::new(10), TotpPolicy::default());
        let uid = store.import_user(imported).expect("the account imports");
        let exported = super::exported_account(
            &store,
            store.user_by_id(uid.as_str()).expect("the account exists"),
            None,
        );
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "password"));
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "google.com"));
    }

    #[test]
    fn hashless_password_provider_with_phone_identity_is_preserved() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::AuthStore;
        use fireemu_core_export::auth::{ProviderUserInfo, UserRecord};
        use fireemu_core_types::determinism::SplitMix64;

        let record = UserRecord {
            local_id: "hashless-phone".to_owned(),
            email: Some("phone@example.com".to_owned()),
            phone_number: Some("+15550000001".to_owned()),
            provider_user_info: vec![ProviderUserInfo {
                provider_id: "password".to_owned(),
                raw_id: "phone@example.com".to_owned(),
                ..ProviderUserInfo::default()
            }],
            ..UserRecord::default()
        };
        let imported = super::imported_user(&record, std::path::Path::new("offline.json"))
            .expect("the hashless account imports");
        let mut store = AuthStore::new("demo-app", SplitMix64::new(11), TotpPolicy::default());
        let uid = store.import_user(imported).expect("the account imports");
        let exported = super::exported_account(
            &store,
            store.user_by_id(uid.as_str()).expect("the account exists"),
            None,
        );
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "password"));
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "phone"));
    }

    #[test]
    fn explicit_email_link_provider_with_linked_identities_is_preserved() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::AuthStore;
        use fireemu_core_export::auth::{ProviderUserInfo, UserRecord};
        use fireemu_core_types::determinism::SplitMix64;

        let record = UserRecord {
            local_id: "email-link-linked".to_owned(),
            email: Some("link-linked@example.com".to_owned()),
            email_link_signin: true,
            phone_number: Some("+15550000003".to_owned()),
            provider_user_info: vec![
                ProviderUserInfo {
                    provider_id: "password".to_owned(),
                    raw_id: "link-linked@example.com".to_owned(),
                    ..ProviderUserInfo::default()
                },
                ProviderUserInfo {
                    provider_id: "google.com".to_owned(),
                    raw_id: "google-link-linked".to_owned(),
                    ..ProviderUserInfo::default()
                },
            ],
            ..UserRecord::default()
        };
        let imported = super::imported_user(&record, std::path::Path::new("offline.json"))
            .expect("the email-link account imports");
        let mut store = AuthStore::new("demo-app", SplitMix64::new(13), TotpPolicy::default());
        let uid = store.import_user(imported).expect("the account imports");
        let exported = super::exported_account(
            &store,
            store.user_by_id(uid.as_str()).expect("the account exists"),
            None,
        );
        assert!(exported.email_link_signin);
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "password"));
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "google.com"));
        assert!(exported
            .provider_user_info
            .iter()
            .any(|provider| provider.provider_id == "phone"));
    }

    #[test]
    fn clear_password_retags_phone_provider_for_export() {
        use fireemu_core_auth::mfa::TotpPolicy;
        use fireemu_core_auth::store::{AuthStore, NewUser, Provider};
        use fireemu_core_types::determinism::SplitMix64;

        let mut store = AuthStore::new("demo-app", SplitMix64::new(12), TotpPolicy::default());
        let uid = store
            .create_user(
                NewUser::email("stale-phone@example.com"),
                LogicalInstant::from_unix_seconds(100),
            )
            .expect("the account is created");
        store
            .set_phone_number(&uid, Some("+15550000002"))
            .expect("the phone is linked");
        store
            .set_password(&uid, "hunter22", LogicalInstant::from_unix_seconds(101))
            .expect("the password is set");
        assert!(store.clear_password(&uid).expect("the password is cleared"));

        let user = store.user(&uid).expect("the account exists");
        assert_eq!(user.provider, Provider::Phone);
        let exported = super::exported_account(&store, user, None);
        assert!(exported
            .provider_user_info
            .iter()
            .all(|provider| provider.provider_id != "password"));
        assert_eq!(exported.provider_user_info[0].provider_id, "phone");
    }

    #[test]
    fn the_field_configuration_sidecar_survives_a_round_trip() {
        let mut catalog = fireemu_core_firestore::ttl::TtlCatalog::new();
        catalog
            .enable(
                fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection"),
                fireemu_core_firestore::field_path::FieldPath::parse("expiresAt").expect("field"),
            )
            .expect("enable");
        let mut catalogs = std::collections::BTreeMap::new();
        catalogs.insert(("demo-app".to_owned(), "(default)".to_owned()), catalog);

        let parsed = parse_field_config(&field_config_json(&catalogs)).expect("parse");
        assert_eq!(parsed, catalogs);
    }

    #[test]
    fn the_expiration_offset_of_a_policy_survives_a_round_trip() {
        let group = fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection");
        let field =
            fireemu_core_firestore::field_path::FieldPath::parse("expiresAt").expect("field");
        for offset in [
            Some(fireemu_core_types::time::LogicalDuration::from_seconds(
                604_800,
            )),
            // An offset spelled as zero is a configuration of its own, distinct from the
            // unset one, so the artifact has to tell them apart.
            Some(fireemu_core_types::time::LogicalDuration::from_seconds(0)),
            None,
        ] {
            let mut catalog = fireemu_core_firestore::ttl::TtlCatalog::new();
            catalog
                .enable_with_offset(group.clone(), field.clone(), offset)
                .expect("enable");
            let mut catalogs = std::collections::BTreeMap::new();
            catalogs.insert(("demo-app".to_owned(), "(default)".to_owned()), catalog);

            let text = field_config_json(&catalogs);
            let parsed = parse_field_config(&text).expect("parse");
            assert_eq!(parsed, catalogs, "{text}");
            assert_eq!(
                parsed[&("demo-app".to_owned(), "(default)".to_owned())]
                    .policy(&group)
                    .expect("policy")
                    .expiration_offset,
                offset,
                "{text}"
            );
        }
    }

    #[test]
    fn a_policy_with_no_offset_is_written_the_way_it_always_was() {
        let mut catalog = fireemu_core_firestore::ttl::TtlCatalog::new();
        catalog
            .enable(
                fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection"),
                fireemu_core_firestore::field_path::FieldPath::parse("expiresAt").expect("field"),
            )
            .expect("enable");
        let mut catalogs = std::collections::BTreeMap::new();
        catalogs.insert(("demo-app".to_owned(), "(default)".to_owned()), catalog);
        assert_eq!(
            field_config_json(&catalogs),
            r#"{"databases":[{"database":"(default)","project":"demo-app","ttlFields":[{"collectionGroup":"sessions","field":"expiresAt"}]}],"version":1}"#
        );
    }

    #[test]
    fn a_sidecar_naming_an_invalid_expiration_offset_is_refused() {
        for offset in [
            r#""1.5s""#,
            r#""-1s""#,
            r#""2147483648s""#,
            r#""604800""#,
            "7",
        ] {
            let text = format!(
                r#"{{"version":2,"databases":[{{"project":"demo-app","database":"(default)","ttlFields":[{{"collectionGroup":"sessions","field":"expiresAt","expirationOffset":{offset}}}]}}]}}"#
            );
            let error = parse_field_config(&text).expect_err("refusal");
            assert!(error.contains("expirationOffset"), "{offset}: {error}");
        }
    }

    #[test]
    fn an_empty_catalog_is_not_written_into_the_sidecar() {
        let mut catalogs = std::collections::BTreeMap::new();
        catalogs.insert(
            ("demo-app".to_owned(), "(default)".to_owned()),
            fireemu_core_firestore::ttl::TtlCatalog::new(),
        );
        let text = field_config_json(&catalogs);
        assert_eq!(text, r#"{"databases":[],"version":1}"#);
    }

    #[test]
    fn a_sidecar_of_an_unknown_version_is_refused() {
        for text in [
            r#"{"version": 3, "databases": []}"#,
            r#"{"version": 0, "databases": []}"#,
            r#"{"version": "2", "databases": []}"#,
            r#"{"databases": []}"#,
        ] {
            let error = parse_field_config(text).expect_err("refusal");
            assert!(error.contains("unknown version"), "{text}: {error}");
        }
    }

    #[test]
    fn a_sidecar_carrying_an_offset_declares_the_version_that_carries_one() {
        let group = fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection");
        let field =
            fireemu_core_firestore::field_path::FieldPath::parse("expiresAt").expect("field");
        let mut catalog = fireemu_core_firestore::ttl::TtlCatalog::new();
        catalog
            .enable_with_offset(
                group.clone(),
                field,
                Some(fireemu_core_types::time::LogicalDuration::from_seconds(
                    604_800,
                )),
            )
            .expect("enable");
        let mut catalogs = std::collections::BTreeMap::new();
        catalogs.insert(("demo-app".to_owned(), "(default)".to_owned()), catalog);

        let text = field_config_json(&catalogs);
        assert_eq!(
            text,
            r#"{"databases":[{"database":"(default)","project":"demo-app","ttlFields":[{"collectionGroup":"sessions","expirationOffset":"604800s","field":"expiresAt"}]}],"version":2}"#
        );
        // The artifact that declares the newer version still round-trips whole.
        let parsed = parse_field_config(&text).expect("parse");
        assert_eq!(parsed, catalogs);
        assert_eq!(
            parsed[&("demo-app".to_owned(), "(default)".to_owned())]
                .policy(&group)
                .expect("policy")
                .expiration_offset,
            Some(fireemu_core_types::time::LogicalDuration::from_seconds(
                604_800
            ))
        );
    }

    #[test]
    fn a_version_one_sidecar_carrying_an_offset_is_refused_rather_than_read_without_it() {
        // An older reader would install this policy with no offset and sweep every document
        // of the collection group up to one week early, without saying so. The version is
        // the promise that there is nothing here to drop, so breaking it is an error.
        let text = r#"{"version":1,"databases":[{"project":"demo-app","database":"(default)","ttlFields":[{"collectionGroup":"sessions","field":"expiresAt","expirationOffset":"604800s"}]}]}"#;
        let error = parse_field_config(text).expect_err("refusal");
        assert!(error.contains("expirationOffset"), "{error}");
        assert!(error.contains("version 1"), "{error}");
    }

    #[test]
    fn a_version_two_sidecar_that_names_no_offset_is_read_as_it_stands() {
        let text = r#"{"version":2,"databases":[{"project":"demo-app","database":"(default)","ttlFields":[{"collectionGroup":"sessions","field":"expiresAt"}]}]}"#;
        let parsed = parse_field_config(text).expect("parse");
        let group = fireemu_core_types::ids::CollectionId::try_new("sessions").expect("collection");
        assert_eq!(
            parsed[&("demo-app".to_owned(), "(default)".to_owned())]
                .policy(&group)
                .expect("policy")
                .expiration_offset,
            None
        );
        // Writing it back drops to the version that can carry it.
        assert!(field_config_json(&parsed).contains(r#""version":1"#));
    }

    #[test]
    fn a_sidecar_naming_an_invalid_field_path_is_refused() {
        let text = r#"{"version":1,"databases":[{"project":"demo-app","database":"(default)","ttlFields":[{"collectionGroup":"sessions","field":"a..b"}]}]}"#;
        let error = parse_field_config(text).expect_err("refusal");
        assert!(error.contains("field path"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_sidecar_larger_than_the_limit_is_refused_and_one_at_the_limit_is_read() {
        let dir = TrustedTempDir::new("field-config-limit");
        let path = dir.path().join(FIELD_CONFIG_FILE);

        // One byte past the limit is refused without the content being parsed.
        let padding = usize::try_from(FIELD_CONFIG_BYTES_LIMIT).expect("a usize limit");
        let oversized = format!(
            "{{\"version\":1,\"note\":\"{}\",\"databases\":[]}}",
            "a".repeat(padding)
        );
        std::fs::write(&path, oversized).expect("write the oversized sidecar");
        let error = read_field_config(dir.path()).expect_err("refusal");
        assert!(error.to_string().contains(FIELD_CONFIG_FILE), "{error}");

        // A sidecar inside the limit is read.
        std::fs::write(&path, r#"{"version":1,"databases":[]}"#).expect("write a small sidecar");
        assert_eq!(
            read_field_config(dir.path()).expect("read"),
            Some(std::collections::BTreeMap::new())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_sidecar_that_is_a_symlink_is_refused() {
        let dir = TrustedTempDir::new("field-config-symlink");
        let target = dir.path().join("elsewhere.json");
        std::fs::write(&target, r#"{"version":1,"databases":[]}"#).expect("write the target");
        std::os::unix::fs::symlink(&target, dir.path().join(FIELD_CONFIG_FILE))
            .expect("create the symlink");
        let error = read_field_config(dir.path()).expect_err("refusal");
        assert!(error.to_string().contains("no-symlink"), "{error}");
    }

    #[test]
    fn a_sidecar_naming_an_invalid_project_is_refused() {
        let text = r#"{"version":1,"databases":[{"project":"Not A Project","database":"(default)","ttlFields":[]}]}"#;
        let error = parse_field_config(text).expect_err("refusal");
        assert!(error.starts_with("project "), "{error}");
    }

    #[test]
    fn a_sidecar_naming_an_invalid_database_is_refused() {
        let text = r#"{"version":1,"databases":[{"project":"demo-app","database":"Invalid_Id","ttlFields":[]}]}"#;
        let error = parse_field_config(text).expect_err("refusal");
        assert!(error.starts_with("database "), "{error}");
    }

    #[test]
    fn a_sidecar_carrying_a_control_character_in_an_identifier_is_refused() {
        let text = "{\"version\":1,\"databases\":[{\"project\":\"demo\\u0000app\",\"database\":\"(default)\",\"ttlFields\":[]}]}";
        let error = parse_field_config(text).expect_err("refusal");
        assert!(error.starts_with("project "), "{error}");
    }

    #[test]
    fn a_sidecar_naming_two_ttl_fields_in_one_collection_group_is_refused() {
        let text = r#"{"version":1,"databases":[{"project":"demo-app","database":"(default)","ttlFields":[{"collectionGroup":"sessions","field":"a"},{"collectionGroup":"sessions","field":"b"}]}]}"#;
        let error = parse_field_config(text).expect_err("refusal");
        assert!(error.contains("at most one TTL field"), "{error}");
    }
}
