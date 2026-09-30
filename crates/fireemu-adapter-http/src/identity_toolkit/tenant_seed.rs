//! A tenant declared in the configuration file (`auth.tenants[]`) and the project's
//! multi-tenancy switch (`auth.multiTenant.allowTenants`).
//!
//! An entry is an Admin v2 `Tenant` document with the `tenantId` the file chooses. Production
//! generates a tenant's id (its display name, a hyphen and five characters of `[a-z0-9]`), so a
//! file cannot ask for a generated one; the id it names must have that shape, and its display
//! name must be one production takes. The document is read by the code the create route reads
//! one with, so the two validate and default alike. Applying an entry needs no request: it
//! creates the tenant in the registry and writes the members, which lets a reset (holding the
//! admission barrier) create its tenants again.

use std::sync::{Arc, Mutex};

use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewProjectSeed};
use fireemu_core_types::determinism::SplitMix64;
use serde_json::{json, Value};

use super::{
    config_proto, prepare_tenant_create, project_config, tenant_document, with_derived_members,
    with_tenant_store, JsonResponse, PreparedTenantCreate,
};

/// A tenant of the configuration file, validated and ready to create.
#[derive(Clone, Debug)]
pub struct TenantSeed {
    id: String,
    prepared: PreparedTenantCreate,
    emulator: bool,
}

/// The message of a refusal: the API's error message.
fn message(response: &JsonResponse) -> String {
    response
        .body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("refused")
        .to_owned()
}

/// Whether `id` is a display name, a hyphen and five characters of `[a-z0-9]`.
fn id_names(id: &str, display_name: &str) -> bool {
    id.strip_prefix(display_name)
        .and_then(|rest| rest.strip_prefix('-'))
        .is_some_and(|suffix| {
            suffix.len() == 5
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

fn prepare_one(
    document: &Value,
    emulator: bool,
    written_at: Option<String>,
) -> Result<TenantSeed, String> {
    let Some(object) = document.as_object() else {
        return Err("a tenant is an object".to_owned());
    };
    let id = match object.get("tenantId") {
        Some(Value::String(id)) => id.clone(),
        _ => return Err("tenantId is required, a string".to_owned()),
    };
    let mut members = document.clone();
    if let Some(members) = members.as_object_mut() {
        members.remove("tenantId");
    }
    // The members a Tenant has, whichever profile: an unknown one is a mistake in the file, not
    // something the emulator profile ignores as it ignores a request's.
    let parsed =
        config_proto::parse_tenant_body(&members).map_err(|response| message(&response))?;
    if let Some(response) = tenant_document::display_name_refusal(parsed.get("displayName")) {
        return Err(message(&response));
    }
    let display_name = parsed
        .get("displayName")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !id_names(&id, display_name) {
        return Err(format!(
            "tenantId {id:?} is not the display name {display_name:?}, a hyphen and five characters of a-z and 0-9, as production generates one"
        ));
    }
    let prepared = prepare_tenant_create(&members, emulator, written_at)
        .map_err(|response| message(&response))?;
    Ok(TenantSeed {
        id,
        prepared,
        emulator,
    })
}

/// Validates the entries of `auth.tenants`, in order. An error names the entry (`auth.tenants[i]:`).
pub fn prepare_tenant_seeds(
    documents: &[Value],
    emulator: bool,
    written_at: Option<&str>,
) -> Result<Vec<TenantSeed>, String> {
    let mut seeds: Vec<TenantSeed> = Vec::with_capacity(documents.len());
    for (index, document) in documents.iter().enumerate() {
        let seed = prepare_one(document, emulator, written_at.map(str::to_owned))
            .map_err(|error| format!("auth.tenants[{index}]: {error}"))?;
        if seeds.iter().any(|earlier| earlier.id == seed.id) {
            return Err(format!(
                "auth.tenants[{index}]: tenantId {:?} repeats an earlier entry",
                seed.id
            ));
        }
        seeds.push(seed);
    }
    Ok(seeds)
}

impl TenantSeed {
    /// The tenant id the file chose.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Creates the tenant in `project`: as the create route creates one, under the id of the
    /// file. An error when the project is unknown or the id is already in use.
    pub fn apply(&self, registry: &AuthRegistry, project: &str) -> Result<(), String> {
        let PreparedTenantCreate {
            metadata,
            patch,
            password_policy,
            written,
        } = self.prepared.clone();
        if registry
            .create_tenant_with_id(project, &self.id, metadata, patch, password_policy)
            .is_none()
        {
            return Err(format!(
                "cannot create tenant {:?} in project {project:?}: the project is unknown or the id is in use",
                self.id
            ));
        }
        with_tenant_store(registry, project, &self.id, |store| written.apply(store))
            .map_err(|response| message(&response))
    }
}

/// The declared multi-tenancy switch and tenants of a project, applied together: the switch
/// first (strict creates tenants only in a project that allows them), then each tenant.
#[derive(Clone, Debug, Default)]
pub struct TenantSeeding {
    allow_tenants: Option<bool>,
    tenants: Vec<TenantSeed>,
}

impl TenantSeeding {
    /// A declaration: the switch when the file set it, and the validated tenants in file order.
    #[must_use]
    pub fn new(allow_tenants: Option<bool>, tenants: Vec<TenantSeed>) -> Self {
        Self {
            allow_tenants,
            tenants,
        }
    }

    /// Whether the file declared neither the switch nor a tenant.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.allow_tenants.is_none() && self.tenants.is_empty()
    }

    /// Applies the declaration to `project`. The switch is set only when declared, so an
    /// undeclared one keeps whatever the project has. A tenant is created with the id of the
    /// file unless the project already has a tenant of that id: after an `--import` that tenant
    /// is the imported one, which is authoritative for its id.
    pub fn apply(&self, registry: &AuthRegistry, project: &str) -> Result<(), String> {
        if let Some(allow) = self.allow_tenants {
            seed_multi_tenancy(registry, project, allow)?;
        }
        let mut first_error = None;
        for tenant in &self.tenants {
            // A tenant that is there (an imported one, or one another request made) is kept. One
            // refused tenant does not stop the others.
            if registry.tenant_store(project, tenant.id()).is_some() {
                continue;
            }
            if let Err(error) = tenant.apply(registry, project) {
                // An id another request made since the check is a tenant that is there.
                if registry.tenant_store(project, tenant.id()).is_none() {
                    first_error.get_or_insert(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl TenantSeeding {
    /// The ids of declared tenants that `project` already has (after an `--import`) with settings
    /// other than the declared ones: the imported tenant is used, so its declaration is ignored.
    /// The two are compared as the Admin document a read answers, without the members that only
    /// say where a tenant lives or what it takes from its project (`name`, `inheritance`, and the
    /// project's `hashConfig`), so every setting the file can declare is compared.
    #[must_use]
    pub fn shadowed_by_existing(&self, registry: &AuthRegistry, project: &str) -> Vec<String> {
        let mut shadowed = Vec::new();
        for tenant in &self.tenants {
            let Some(present) = tenant.document_in(registry, project) else {
                continue;
            };
            let scratch = AuthRegistry::new(
                project,
                Arc::new(Mutex::new(AuthStore::new(
                    project,
                    SplitMix64::new(0),
                    TotpPolicy::default(),
                ))),
            );
            if tenant.apply(&scratch, project).is_err() {
                continue;
            }
            if tenant.document_in(&scratch, project) != Some(present) {
                shadowed.push(tenant.id().to_owned());
            }
        }
        shadowed
    }
}

impl TenantSeed {
    /// The document `project` answers for this tenant's id, without the members that name a
    /// place or come from the project.
    fn document_in(&self, registry: &AuthRegistry, project: &str) -> Option<Value> {
        let metadata = registry.tenant_metadata(project, &self.id)?;
        let store = registry.tenant_store(project, &self.id)?;
        let store = store.lock().ok()?;
        let mut document = tenant_document::document(
            project,
            project,
            &self.id,
            &metadata,
            &store,
            tenant_document::View::Read,
            self.emulator,
        );
        if let Some(members) = document.as_object_mut() {
            for member in ["name", "inheritance", "hashConfig"] {
                members.remove(member);
            }
        }
        Some(document)
    }
}

/// Sets the project's multi-tenancy switch as the config update sets it: the `multiTenant`
/// member and the private switch the tenant routes read, in one write under the project's gate.
pub fn seed_multi_tenancy(
    registry: &AuthRegistry,
    project: &str,
    allow_tenants: bool,
) -> Result<(), String> {
    let unknown = || format!("cannot set multiTenant.allowTenants: project {project:?} is unknown");
    let store = registry
        .store_for(project)
        .or_else(|| registry.routed_store_for(project))
        .ok_or_else(unknown)?;
    let gate = registry.operation_gate(project, None).ok_or_else(unknown)?;
    let _operation = gate
        .lock()
        .map_err(|_| "the project gate is poisoned".to_owned())?;
    let mut store = store
        .lock()
        .map_err(|_| "the project store is poisoned".to_owned())?;
    let body = json!({"multiTenant": {"allowTenants": allow_tenants}});
    let fields = ["multiTenant.allowTenants".to_owned()];
    let mut members = project_config::apply_stored_members(
        store.stored_config_members(),
        &body,
        &fields,
        project,
    )
    .map_err(|()| "multiTenant.allowTenants is not a valid member".to_owned())?
    .unwrap_or_else(|| store.stored_config_members().clone());
    with_derived_members(&mut members, &body, &fields, false, None);
    store.set_stored_config_members(members);
    Ok(())
}

/// The declaration is what a routed project is seeded with when it is installed.
impl NewProjectSeed for TenantSeeding {
    fn apply(&self, registry: &AuthRegistry, project: &str) -> Result<(), String> {
        TenantSeeding::apply(self, registry, project)
    }
}
