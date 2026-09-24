//! The database catalog behind the Firestore Admin API (`FS-CONFIG-LIFECYCLE`).
//!
//! Production creates a named database with `databases.create`, reports it through
//! `databases.get` and `databases.list`, changes a few of its settings with `databases.patch`
//! and removes it with `databases.delete`. A deleted database stays listed under its uid (with
//! `showDeleted=true`) and its id cannot be reused for [`DELETED_ID_COOLDOWN_SECONDS`]. This
//! module keeps that state; it does not touch documents. The data plane asks it, through
//! [`AdminCatalog::data_plane_refusal`], whether a database may be served at all.
//!
//! `(default)` and the databases the configuration declares exist without a create call. They
//! get a record lazily, stamped with the backend's creation instant, the first time the
//! catalog is asked about them, and they can be deleted like any other database.

use std::collections::BTreeMap;
use std::sync::Mutex;

use fireemu_core_types::time::LogicalInstant;

/// How long production refuses to create a database under an id deleted a moment ago
/// ("Database ID '…' is not available in project '…'. Please retry in N seconds."), as
/// measured against production on 2026-09-24: about 300 seconds after the delete.
pub const DELETED_ID_COOLDOWN_SECONDS: i64 = 300;

/// `Database.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseType {
    /// `FIRESTORE_NATIVE`.
    FirestoreNative,
    /// `DATASTORE_MODE`: the Firestore API refuses it.
    DatastoreMode,
}

impl DatabaseType {
    /// The API spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirestoreNative => "FIRESTORE_NATIVE",
            Self::DatastoreMode => "DATASTORE_MODE",
        }
    }
}

/// `Database.databaseEdition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseEdition {
    /// `STANDARD`.
    Standard,
    /// `ENTERPRISE`: created with the MongoDB-compatible data access mode only.
    Enterprise,
}

impl DatabaseEdition {
    /// The API spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "STANDARD",
            Self::Enterprise => "ENTERPRISE",
        }
    }
}

/// `Database.concurrencyMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrencyMode {
    /// `PESSIMISTIC`.
    Pessimistic,
    /// `OPTIMISTIC`.
    Optimistic,
    /// `OPTIMISTIC_WITH_ENTITY_GROUPS`.
    OptimisticWithEntityGroups,
}

impl ConcurrencyMode {
    /// The API spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pessimistic => "PESSIMISTIC",
            Self::Optimistic => "OPTIMISTIC",
            Self::OptimisticWithEntityGroups => "OPTIMISTIC_WITH_ENTITY_GROUPS",
        }
    }
}

/// Everything the Admin API reports about one database, apart from derived values
/// (`earliestVersionTime`, `etag`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseRecord {
    /// Project id.
    pub project: String,
    /// Database id.
    pub database: String,
    /// Server-assigned unique id (a version-4 UUID).
    pub uid: String,
    /// When the database was created.
    pub create_time: LogicalInstant,
    /// When its settings last changed.
    pub update_time: LogicalInstant,
    /// Where it was created.
    pub location_id: String,
    /// Native or Datastore mode.
    pub database_type: DatabaseType,
    /// Standard or Enterprise.
    pub edition: DatabaseEdition,
    /// Transaction concurrency control.
    pub concurrency: ConcurrencyMode,
    /// Whether `databases.delete` is refused.
    pub delete_protection: bool,
    /// Whether the database is the project's free-tier database.
    pub free_tier: bool,
}

/// A deleted database: its record, when it was deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedDatabase {
    /// The record as it stood when it was deleted.
    pub record: DatabaseRecord,
    /// When it was deleted.
    pub delete_time: LogicalInstant,
}

/// What a create asks for, validated by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    /// Project id.
    pub project: String,
    /// Database id.
    pub database: String,
    /// Location.
    pub location_id: String,
    /// Mode.
    pub database_type: DatabaseType,
    /// Edition.
    pub edition: DatabaseEdition,
    /// Concurrency, when the request named one.
    pub concurrency: Option<ConcurrencyMode>,
    /// Delete protection.
    pub delete_protection: bool,
}

/// Why the catalog refused a create or a delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogRefusal {
    /// The id names a live database.
    AlreadyExists,
    /// The id was deleted less than the cooldown ago; the payload is the whole seconds left.
    CoolingDown(i64),
    /// No live database has this id.
    NotFound {
        /// Whether a database under this id was deleted (production's message differs).
        deleted: bool,
    },
    /// Delete protection is enabled.
    Protected,
}

/// Why the data plane refuses a database that exists in the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPlaneRefusal {
    /// The database was deleted (or never created): the ordinary `NOT_FOUND`.
    Missing,
    /// A Datastore-mode database.
    DatastoreMode,
    /// An Enterprise database, created with the Firestore data access mode disabled.
    NativeAccessDisabled,
}

#[derive(Debug, Default)]
struct CatalogState {
    live: BTreeMap<(String, String), DatabaseRecord>,
    deleted: Vec<DeletedDatabase>,
    uid_seed: u64,
}

/// The per-backend database catalog.
pub struct AdminCatalog {
    state: Mutex<CatalogState>,
    operations: super::operations::OperationStore,
    indexes: super::indexes::IndexRegistry,
    fields: super::fields::FieldRegistry,
    managed_storage: std::sync::OnceLock<super::managed::SharedManagedStorage>,
    /// When the backend's configured databases came into being.
    created_at: Mutex<LogicalInstant>,
}

impl std::fmt::Debug for AdminCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminCatalog")
            .field("state", &self.state)
            .field("indexes", &self.indexes)
            .field("managed_storage", &self.managed_storage.get().is_some())
            .finish_non_exhaustive()
    }
}

fn next_uid(seed: &mut u64) -> String {
    // SplitMix64, twice, into the 128 bits of a version-4 RFC 4122 UUID.
    let mut draw = || {
        *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let high = draw();
    let low = draw();
    let high = (high & 0xffff_ffff_ffff_0fff) | 0x0000_0000_0000_4000;
    let low = (low & 0x3fff_ffff_ffff_ffff) | 0x8000_0000_0000_0000;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        high >> 32,
        (high >> 16) & 0xffff,
        high & 0xffff,
        low >> 48,
        low & 0xffff_ffff_ffff
    )
}

impl AdminCatalog {
    /// A catalog whose configured databases were created at `created_at`.
    #[must_use]
    pub fn new(seed: u64, created_at: LogicalInstant) -> Self {
        Self {
            state: Mutex::new(CatalogState {
                uid_seed: seed ^ 0x4144_4d49_4e55_4944,
                ..CatalogState::default()
            }),
            operations: super::operations::OperationStore::default(),
            indexes: super::indexes::IndexRegistry::default(),
            fields: super::fields::FieldRegistry::default(),
            managed_storage: std::sync::OnceLock::new(),
            created_at: Mutex::new(created_at),
        }
    }

    /// Sets when the configured databases came into being (`firestore.databaseCreateTime`).
    pub fn set_created_at(&self, created_at: LogicalInstant) {
        *self
            .created_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = created_at;
    }

    fn created_at(&self) -> LogicalInstant {
        *self
            .created_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CatalogState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn implicit_record(
        &self,
        state: &mut CatalogState,
        project: &str,
        database: &str,
    ) -> DatabaseRecord {
        DatabaseRecord {
            project: project.to_owned(),
            database: database.to_owned(),
            uid: next_uid(&mut state.uid_seed),
            create_time: self.created_at(),
            update_time: self.created_at(),
            location_id: "us-central1".to_owned(),
            database_type: DatabaseType::FirestoreNative,
            edition: DatabaseEdition::Standard,
            concurrency: ConcurrencyMode::Pessimistic,
            delete_protection: false,
            free_tier: database == fireemu_core_types::ids::DatabaseId::DEFAULT,
        }
    }

    /// Whether `database` was deleted in `project` and not created again.
    fn is_deleted(state: &CatalogState, project: &str, database: &str) -> bool {
        !state
            .live
            .contains_key(&(project.to_owned(), database.to_owned()))
            && state
                .deleted
                .iter()
                .any(|d| d.record.project == project && d.record.database == database)
    }

    /// The live record of a database. `exists_unprompted` says whether it exists without a
    /// create call (`(default)` or declared by the configuration); such a database gets its
    /// record here unless it was deleted.
    pub fn get(
        &self,
        project: &str,
        database: &str,
        exists_unprompted: bool,
    ) -> Option<DatabaseRecord> {
        let mut state = self.lock();
        let key = (project.to_owned(), database.to_owned());
        if let Some(record) = state.live.get(&key) {
            return Some(record.clone());
        }
        if !exists_unprompted || Self::is_deleted(&state, project, database) {
            return None;
        }
        let record = self.implicit_record(&mut state, project, database);
        state.live.insert(key, record.clone());
        Some(record)
    }

    /// The live records of `project`, in id order, with the unprompted databases included.
    pub fn list(&self, project: &str, unprompted: &[String]) -> Vec<DatabaseRecord> {
        for database in unprompted {
            self.get(project, database, true);
        }
        self.lock()
            .live
            .values()
            .filter(|r| r.project == project)
            .cloned()
            .collect()
    }

    /// The deleted databases of `project`, oldest first.
    pub fn deleted(&self, project: &str) -> Vec<DeletedDatabase> {
        self.lock()
            .deleted
            .iter()
            .filter(|d| d.record.project == project)
            .cloned()
            .collect()
    }

    /// Creates a database, or says why it cannot.
    ///
    /// # Errors
    ///
    /// [`CatalogRefusal::AlreadyExists`] for a live id (an unprompted database counts),
    /// [`CatalogRefusal::CoolingDown`] for an id deleted less than the cooldown ago.
    pub fn create(
        &self,
        request: CreateRequest,
        exists_unprompted: bool,
        now: LogicalInstant,
    ) -> Result<DatabaseRecord, CatalogRefusal> {
        let mut state = self.lock();
        let key = (request.project.clone(), request.database.clone());
        let deleted = Self::is_deleted(&state, &request.project, &request.database);
        if state.live.contains_key(&key) || (exists_unprompted && !deleted) {
            return Err(CatalogRefusal::AlreadyExists);
        }
        let cooldown_nanos = i128::from(DELETED_ID_COOLDOWN_SECONDS) * 1_000_000_000;
        if let Some(last) = state
            .deleted
            .iter()
            .filter(|d| {
                d.record.project == request.project && d.record.database == request.database
            })
            .map(|d| d.delete_time)
            .max()
        {
            let left = last.as_nanos() + cooldown_nanos - now.as_nanos();
            if left > 0 {
                return Err(CatalogRefusal::CoolingDown(
                    i64::try_from(left / 1_000_000_000).unwrap_or(DELETED_ID_COOLDOWN_SECONDS),
                ));
            }
        }
        let record = DatabaseRecord {
            uid: next_uid(&mut state.uid_seed),
            create_time: now,
            update_time: now,
            location_id: request.location_id,
            database_type: request.database_type,
            edition: request.edition,
            // Production answers OPTIMISTIC for an Enterprise database and PESSIMISTIC for
            // a Standard one when the request does not choose.
            concurrency: request.concurrency.unwrap_or(match request.edition {
                DatabaseEdition::Standard => ConcurrencyMode::Pessimistic,
                DatabaseEdition::Enterprise => ConcurrencyMode::Optimistic,
            }),
            delete_protection: request.delete_protection,
            free_tier: false,
            project: request.project,
            database: request.database,
        };
        state.live.insert(key, record.clone());
        Ok(record)
    }

    /// Applies `change` to a live database and stamps `update_time`.
    ///
    /// # Errors
    ///
    /// [`CatalogRefusal::NotFound`] when no live database has this id.
    pub fn update(
        &self,
        project: &str,
        database: &str,
        exists_unprompted: bool,
        now: LogicalInstant,
        change: impl FnOnce(&mut DatabaseRecord),
    ) -> Result<DatabaseRecord, CatalogRefusal> {
        self.get(project, database, exists_unprompted);
        let mut state = self.lock();
        let deleted = Self::is_deleted(&state, project, database);
        let record = state
            .live
            .get_mut(&(project.to_owned(), database.to_owned()))
            .ok_or(CatalogRefusal::NotFound { deleted })?;
        change(record);
        record.update_time = now;
        Ok(record.clone())
    }

    /// Deletes a live database.
    ///
    /// # Errors
    ///
    /// [`CatalogRefusal::NotFound`] when no live database has this id,
    /// [`CatalogRefusal::Protected`] when delete protection is enabled.
    pub fn delete(
        &self,
        project: &str,
        database: &str,
        exists_unprompted: bool,
        now: LogicalInstant,
    ) -> Result<DeletedDatabase, CatalogRefusal> {
        self.get(project, database, exists_unprompted);
        let mut state = self.lock();
        let key = (project.to_owned(), database.to_owned());
        let deleted = Self::is_deleted(&state, project, database);
        let record = state
            .live
            .get(&key)
            .ok_or(CatalogRefusal::NotFound { deleted })?;
        if record.delete_protection {
            return Err(CatalogRefusal::Protected);
        }
        let record = state
            .live
            .remove(&key)
            .ok_or(CatalogRefusal::NotFound { deleted })?;
        let tombstone = DeletedDatabase {
            record,
            delete_time: now,
        };
        state.deleted.push(tombstone.clone());
        Ok(tombstone)
    }

    /// Why the data plane must refuse `database`, if it must. `exists_unprompted` is whether
    /// the database exists without a create call.
    pub fn data_plane_refusal(
        &self,
        project: &str,
        database: &str,
        exists_unprompted: bool,
    ) -> Option<DataPlaneRefusal> {
        let state = self.lock();
        match state.live.get(&(project.to_owned(), database.to_owned())) {
            Some(record) if record.database_type == DatabaseType::DatastoreMode => {
                Some(DataPlaneRefusal::DatastoreMode)
            }
            Some(record) if record.edition == DatabaseEdition::Enterprise => {
                Some(DataPlaneRefusal::NativeAccessDisabled)
            }
            None if exists_unprompted && Self::is_deleted(&state, project, database) => {
                Some(DataPlaneRefusal::Missing)
            }
            Some(_) | None => None,
        }
    }

    /// Forgets every database and operation of the projects `owned` selects (a session reset).
    pub fn reset(&self, owned: impl Fn(&str) -> bool) {
        let mut state = self.lock();
        state.live.retain(|(project, _), _| !owned(project));
        state.deleted.retain(|d| !owned(&d.record.project));
        drop(state);
        self.indexes.forget(|project, _| owned(project));
        self.fields.forget(|project, _| owned(project));
        self.operations.reset(owned);
    }

    /// Connects managed export and import to the daemon's Cloud Storage. Set once, at start.
    pub fn set_managed_storage(&self, storage: super::managed::SharedManagedStorage) {
        let _ = self.managed_storage.set(storage);
    }

    /// The daemon's Cloud Storage, when it serves one.
    #[must_use]
    pub fn managed_storage(&self) -> Option<&super::managed::SharedManagedStorage> {
        self.managed_storage.get()
    }

    /// The runtime field patches of every database.
    #[must_use]
    pub const fn fields(&self) -> &super::fields::FieldRegistry {
        &self.fields
    }

    /// The Admin-created composite indexes of every database.
    #[must_use]
    pub const fn indexes(&self) -> &super::indexes::IndexRegistry {
        &self.indexes
    }

    /// The Admin operations of every database.
    #[must_use]
    pub const fn operations(&self) -> &super::operations::OperationStore {
        &self.operations
    }

    /// Whether the catalog holds a live, created database of this id (not an unprompted one
    /// it has not been asked about yet).
    pub fn is_live(&self, project: &str, database: &str) -> bool {
        self.lock()
            .live
            .contains_key(&(project.to_owned(), database.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> LogicalInstant {
        LogicalInstant::from_nanos(i128::from(seconds) * 1_000_000_000)
    }

    fn request(database: &str) -> CreateRequest {
        CreateRequest {
            project: "p".to_owned(),
            database: database.to_owned(),
            location_id: "us-central1".to_owned(),
            database_type: DatabaseType::FirestoreNative,
            edition: DatabaseEdition::Standard,
            concurrency: None,
            delete_protection: false,
        }
    }

    #[test]
    fn a_created_database_is_listed_with_a_uuid_and_is_not_the_free_tier() {
        let catalog = AdminCatalog::new(7, at(10));
        let record = catalog.create(request("named"), false, at(20)).unwrap();
        assert_eq!(record.create_time, at(20));
        assert!(!record.free_tier);
        assert_eq!(record.concurrency, ConcurrencyMode::Pessimistic);
        let uid = &record.uid;
        assert_eq!(uid.len(), 36);
        assert_eq!(&uid[14..15], "4", "{uid}");
        assert!(matches!(&uid[19..20], "8" | "9" | "a" | "b"), "{uid}");
        let listed = catalog.list("p", &["(default)".to_owned()]);
        let ids: Vec<_> = listed.iter().map(|r| r.database.as_str()).collect();
        assert_eq!(ids, ["(default)", "named"]);
        assert!(listed[0].free_tier);
        assert_eq!(listed[0].create_time, at(10));
        assert_ne!(listed[0].uid, listed[1].uid);
    }

    #[test]
    fn an_enterprise_database_defaults_to_optimistic_concurrency() {
        let catalog = AdminCatalog::new(7, at(0));
        let record = catalog
            .create(
                CreateRequest {
                    edition: DatabaseEdition::Enterprise,
                    ..request("ent1")
                },
                false,
                at(1),
            )
            .unwrap();
        assert_eq!(record.concurrency, ConcurrencyMode::Optimistic);
    }

    #[test]
    fn a_duplicate_id_is_refused_and_so_is_an_unprompted_one() {
        let catalog = AdminCatalog::new(7, at(0));
        catalog.create(request("dup1"), false, at(1)).unwrap();
        assert_eq!(
            catalog.create(request("dup1"), false, at(2)),
            Err(CatalogRefusal::AlreadyExists)
        );
        assert_eq!(
            catalog.create(request("(default)"), true, at(2)),
            Err(CatalogRefusal::AlreadyExists)
        );
    }

    #[test]
    fn a_deleted_id_cools_down_for_three_hundred_seconds() {
        let catalog = AdminCatalog::new(7, at(0));
        catalog.create(request("gone"), false, at(1)).unwrap();
        let tombstone = catalog.delete("p", "gone", false, at(100)).unwrap();
        assert_eq!(tombstone.delete_time, at(100));
        assert_eq!(catalog.get("p", "gone", false), None);
        assert_eq!(
            catalog.create(request("gone"), false, at(138)),
            Err(CatalogRefusal::CoolingDown(262))
        );
        assert_eq!(
            catalog.create(request("gone"), false, at(399)),
            Err(CatalogRefusal::CoolingDown(1))
        );
        let again = catalog.create(request("gone"), false, at(400)).unwrap();
        assert_ne!(again.uid, tombstone.record.uid);
        assert_eq!(catalog.deleted("p").len(), 1);
    }

    #[test]
    fn delete_protection_and_missing_databases_are_refused() {
        let catalog = AdminCatalog::new(7, at(0));
        catalog
            .create(
                CreateRequest {
                    delete_protection: true,
                    ..request("kept")
                },
                false,
                at(1),
            )
            .unwrap();
        assert_eq!(
            catalog.delete("p", "kept", false, at(2)),
            Err(CatalogRefusal::Protected)
        );
        assert_eq!(
            catalog.delete("p", "never", false, at(2)),
            Err(CatalogRefusal::NotFound { deleted: false })
        );
        catalog
            .update("p", "kept", false, at(3), |r| r.delete_protection = false)
            .unwrap();
        catalog.delete("p", "kept", false, at(4)).unwrap();
        assert_eq!(
            catalog.delete("p", "kept", false, at(5)),
            Err(CatalogRefusal::NotFound { deleted: true })
        );
    }

    #[test]
    fn the_default_database_can_be_deleted_and_the_data_plane_then_refuses_it() {
        let catalog = AdminCatalog::new(7, at(0));
        assert_eq!(catalog.data_plane_refusal("p", "(default)", true), None);
        catalog.delete("p", "(default)", true, at(5)).unwrap();
        assert_eq!(catalog.get("p", "(default)", true), None);
        assert_eq!(
            catalog.data_plane_refusal("p", "(default)", true),
            Some(DataPlaneRefusal::Missing)
        );
        // Another project's (default) is untouched.
        assert!(catalog.get("q", "(default)", true).is_some());
        let again = catalog.create(request("(default)"), true, at(400)).unwrap();
        assert!(!again.free_tier || again.database == "(default)");
        assert_eq!(catalog.data_plane_refusal("p", "(default)", true), None);
    }

    #[test]
    fn datastore_mode_and_enterprise_databases_are_refused_by_the_native_data_plane() {
        let catalog = AdminCatalog::new(7, at(0));
        catalog
            .create(
                CreateRequest {
                    database_type: DatabaseType::DatastoreMode,
                    ..request("dsmode")
                },
                false,
                at(1),
            )
            .unwrap();
        catalog
            .create(
                CreateRequest {
                    edition: DatabaseEdition::Enterprise,
                    ..request("entdb")
                },
                false,
                at(1),
            )
            .unwrap();
        assert_eq!(
            catalog.data_plane_refusal("p", "dsmode", false),
            Some(DataPlaneRefusal::DatastoreMode)
        );
        assert_eq!(
            catalog.data_plane_refusal("p", "entdb", false),
            Some(DataPlaneRefusal::NativeAccessDisabled)
        );
    }
}
