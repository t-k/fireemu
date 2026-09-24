//! The Admin field-configuration surface (`FS-CONFIG-RT-004`):
//! `projects/{project}/databases/{database}/collectionGroups/{group}/fields`.
//!
//! `fields.get` and `fields.list` project the time-to-live policy and the single-field index
//! configuration a later read or query depends on; `fields.patch` sets and clears the
//! time-to-live policy. Production applies a patch through a long-running operation, so the
//! response is one; the local runtime applies the change synchronously, so the operation it
//! returns is already done and its state reads `ACTIVE` at once. That difference is the
//! documented divergence: the intermediate `CREATING` state is never observable locally.
//!
//! Patching `indexConfig` is refused. The local runtime takes single-field exemptions from
//! the project's index configuration, which the readback here reports, but there is no
//! runtime transition for them; a silent acceptance would report an exemption that never
//! took effect.

use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{IndexFieldMode, IndexQueryScope, IndexSet};
use fireemu_core_firestore::ttl::{
    format_expiration_offset, parse_expiration_offset, TtlError, TtlPolicy,
};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::LogicalDuration;
use serde_json::{json, Value};
use tonic::Status;

use super::{not_found_text, ok, single, RestRequest, RestResponse, RestState};
use crate::encode::encode_instant;
use crate::rest::json::timestamp_to_json;
use crate::rules;

/// Largest page `fields.list` returns, and the page size it uses when none is requested.
pub const MAX_FIELDS_PAGE_SIZE: usize = 100;

/// What a field patch changes, and the field's single-field modes before it.
type PatchChange = (
    crate::admin::fields::FieldChange,
    Vec<(IndexQueryScope, IndexFieldMode)>,
);

/// `FieldOperationMetadata`'s type URL.
const FIELD_METADATA_TYPE_URL: &str =
    "type.googleapis.com/google.firestore.admin.v1.FieldOperationMetadata";

/// The wildcard field id that names a collection group's default field settings.
const WILDCARD_FIELD: &str = "*";

/// The collection group under which production reports the database-wide default field.
const DEFAULT_GROUP: &str = "__default__";

/// One parsed `collectionGroups/{group}/fields/{field}` selector.
struct FieldSelector {
    project: String,
    database: String,
    collection_group: CollectionId,
    /// Absent for the wildcard `*`, which names the collection group's default settings.
    field: Option<FieldPath>,
    /// The field id exactly as the request spelled it.
    field_id: String,
}

impl FieldSelector {
    fn resource_name(&self) -> String {
        format!(
            "projects/{}/databases/{}/collectionGroups/{}/fields/{}",
            self.project,
            self.database,
            self.collection_group.as_str(),
            self.field_id
        )
    }
}

fn ancestor_field(project: &str, database: &str) -> String {
    format!("projects/{project}/databases/{database}/collectionGroups/{DEFAULT_GROUP}/fields/{WILDCARD_FIELD}")
}

fn scope_name(scope: IndexQueryScope) -> &'static str {
    match scope {
        IndexQueryScope::Collection => "COLLECTION",
        IndexQueryScope::CollectionGroup => "COLLECTION_GROUP",
    }
}

/// Binds a page token to the listing that issued it.
///
/// Production's page token is opaque and belongs to one listing. Reusing a token across a
/// different collection group, a different database or a different filter is a caller error,
/// not a shortcut into another listing, so the token carries a digest of what it was issued
/// for and a token that does not match is refused.
fn listing_binding(project: &str, database: &str, collection_group: &str, filter: &str) -> [u8; 6] {
    let mut digest = fireemu_core_types::hash::Sha256::new();
    digest.update(b"fireemu:field-listing:");
    for part in [project, database, collection_group, filter] {
        digest.update(part.as_bytes());
        digest.update(b"\x1f");
    }
    let bytes = digest.finalize();
    let mut binding = [0_u8; 6];
    binding.copy_from_slice(&bytes[..6]);
    binding
}

/// The opaque continuation token of one page of a field listing.
fn page_token(binding: [u8; 6], offset: usize) -> String {
    let offset = u32::try_from(offset).unwrap_or(u32::MAX);
    let mut bytes = binding.to_vec();
    bytes.extend_from_slice(&offset.to_be_bytes());
    fireemu_core_types::hash::hex_lower(&bytes)
}

/// Reads a continuation token back, refusing one issued for another listing.
fn page_offset(binding: [u8; 6], token: &str) -> Result<usize, Status> {
    let refuse = || Status::invalid_argument("pageToken is not a page of this listing");
    if token.len() != 20 {
        return Err(refuse());
    }
    let decoded = fireemu_core_types::codec::hex_decode(token).ok_or_else(refuse)?;
    let bytes: [u8; 10] = decoded.try_into().map_err(|_| refuse())?;
    if bytes[..6] != binding {
        return Err(refuse());
    }
    let offset = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
    Ok(offset as usize)
}

fn mode_json(field_id: &str, scope: IndexQueryScope, mode: IndexFieldMode, state: &str) -> Value {
    let mut entry = json!({ "fieldPath": field_id });
    match mode {
        IndexFieldMode::Ascending => entry["order"] = json!("ASCENDING"),
        IndexFieldMode::Descending => entry["order"] = json!("DESCENDING"),
        IndexFieldMode::Contains => entry["arrayConfig"] = json!("CONTAINS"),
        IndexFieldMode::Vector { dimension } => {
            entry["vectorConfig"] = json!({"dimension": dimension, "flat": {}});
        }
    }
    // Production names no single-field index and reports each one's state.
    json!({
        "queryScope": scope_name(scope),
        "fields": [entry],
        "state": state,
    })
}

/// One `IndexConfigDelta` index: the mode without a state.
fn delta_index_json(
    selector: &FieldSelector,
    scope: IndexQueryScope,
    mode: IndexFieldMode,
) -> Value {
    let mut index = mode_json(&selector.field_id, scope, mode, "READY");
    if let Some(object) = index.as_object_mut() {
        object.remove("state");
    }
    index
}

/// The built-in automatic single-field indexes of a field with no override anywhere.
/// The database-wide default (`__default__/fields/*`): the built-in single-field indexes,
/// with no ancestor to inherit from.
fn database_default_json(project: &str, database: &str) -> Value {
    let indexes: Vec<Value> = builtin_modes()
        .into_iter()
        .map(|(scope, mode)| mode_json(WILDCARD_FIELD, scope, mode, "READY"))
        .collect();
    json!({
        "name": ancestor_field(project, database),
        "indexConfig": {"indexes": indexes},
    })
}

fn builtin_modes() -> Vec<(IndexQueryScope, IndexFieldMode)> {
    vec![
        (IndexQueryScope::Collection, IndexFieldMode::Ascending),
        (IndexQueryScope::Collection, IndexFieldMode::Descending),
        (IndexQueryScope::Collection, IndexFieldMode::Contains),
    ]
}

/// The `indexConfig` a readback reports for one field. `creating` lists the modes a pending
/// patch adds, which read back `CREATING` until it is applied.
fn index_config_json(
    selector: &FieldSelector,
    indexes: &IndexSet,
    creating: &[(IndexQueryScope, IndexFieldMode)],
) -> Value {
    let database_default =
        selector.field.is_none() && selector.collection_group.as_str() == DEFAULT_GROUP;
    let (modes, uses_ancestor) = match &selector.field {
        // The wildcard names one collection group's default settings, which are inherited
        // from the database-wide default until the group declares its own.
        None => match indexes.default_single_field_override(&selector.collection_group) {
            Some(modes) => (modes.to_vec(), false),
            None => (builtin_modes(), !database_default),
        },
        Some(field) => (
            indexes.single_field_modes(&selector.collection_group, field),
            indexes
                .single_field_override(&selector.collection_group, field)
                .is_none(),
        ),
    };
    let indexes_json: Vec<Value> = modes
        .into_iter()
        .map(|(scope, mode)| {
            let state = if creating.contains(&(scope, mode)) {
                "CREATING"
            } else {
                "READY"
            };
            mode_json(&selector.field_id, scope, mode, state)
        })
        .collect();
    let mut config = json!({});
    if !indexes_json.is_empty() {
        config["indexes"] = json!(indexes_json);
    }
    // Every field but the database-wide default names the field it would inherit from, and
    // says so only while it does (proto3 JSON leaves the false value out).
    if !database_default {
        config["ancestorField"] = json!(ancestor_field(&selector.project, &selector.database));
    }
    if uses_ancestor {
        config["usesAncestorConfig"] = json!(true);
    }
    config
}

/// What the modes of a field are before and after an index-configuration patch, as
/// `IndexConfigDelta`s: every removed mode, then every added one.
fn index_config_deltas(
    selector: &FieldSelector,
    before: &[(IndexQueryScope, IndexFieldMode)],
    after: &[(IndexQueryScope, IndexFieldMode)],
) -> Vec<Value> {
    let removed = before.iter().filter(|m| !after.contains(m)).map(|(scope, mode)| {
        json!({"changeType": "REMOVE", "index": delta_index_json(selector, *scope, *mode)})
    });
    let added = after.iter().filter(|m| !before.contains(m)).map(|(scope, mode)| {
        json!({"changeType": "ADD", "index": delta_index_json(selector, *scope, *mode)})
    });
    removed.chain(added).collect()
}

/// Reads the modes an `indexConfig` asks for: `None` (absent or null) inherits again.
fn parse_index_config(
    value: &Value,
) -> Result<Option<Vec<(IndexQueryScope, IndexFieldMode)>>, Status> {
    if value.is_null() {
        return Ok(None);
    }
    let mut modes = Vec::new();
    for index in value["indexes"].as_array().into_iter().flatten() {
        let scope = match index["queryScope"].as_str() {
            Some("COLLECTION") | None => IndexQueryScope::Collection,
            Some("COLLECTION_GROUP") => IndexQueryScope::CollectionGroup,
            Some(other) => {
                return Err(Status::invalid_argument(format!(
                    "Invalid value at 'field.index_config.indexes.query_scope', \"{other}\""
                )))
            }
        };
        for field in index["fields"].as_array().into_iter().flatten() {
            let mode = match (field["order"].as_str(), field["arrayConfig"].as_str()) {
                (Some("ASCENDING"), None) => IndexFieldMode::Ascending,
                (Some("DESCENDING"), None) => IndexFieldMode::Descending,
                (None, Some("CONTAINS")) => IndexFieldMode::Contains,
                _ => {
                    return Err(Status::invalid_argument(
                        "index field value_mode must be specified.",
                    ))
                }
            };
            modes.push((scope, mode));
        }
    }
    Ok(Some(modes))
}

impl RestState {
    /// `projects/{p}/databases/{d}/collectionGroups/{cg}/fields[/{field}]`.
    pub(super) fn admin_fields_route(
        &self,
        req: &RestRequest,
        segments: &[&str],
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<RestResponse, Status> {
        if !rules::is_owner_credential(req.authorization.as_deref()) {
            return Err(Status::permission_denied(
                "Admin field configuration requires owner credentials",
            ));
        }
        if self.gateway.ctx.edition != fireemu_core_types::edition::FirestoreEdition::Standard
            || self.gateway.ctx.api_mode != fireemu_core_types::edition::FirestoreApiMode::Native
        {
            return Err(Status::unimplemented(
                "field configuration is supported only for Standard Native databases",
            ));
        }
        let barrier = self.local.barrier();
        let _admitted = barrier.admit();
        match (req.method.as_str(), segments) {
            ("GET", [_, project, _, database, _, group, _]) => {
                self.assert_database(project, database)?;
                self.list_fields(project, database, group, params)
            }
            ("GET", [_, project, _, database, _, group, _, field])
                if *group == DEFAULT_GROUP && *field == WILDCARD_FIELD =>
            {
                self.assert_database(project, database)?;
                Ok(ok(database_default_json(project, database)))
            }
            ("GET", [_, project, _, database, _, group, _, field]) => {
                self.assert_database(project, database)?;
                let selector = Self::selector(project, database, group, field)?;
                Ok(ok(self.field_json(&selector)))
            }
            ("PATCH", [_, project, _, database, _, group, _, field]) => {
                self.assert_database(project, database)?;
                let selector = Self::selector(project, database, group, field)?;
                self.patch_field(&selector, &req.body, params)
            }
            _ => Ok(not_found_text()),
        }
    }

    /// Refuses a database the data plane would answer `NOT_FOUND` for, before any field of
    /// it is described: a field configuration of a database that does not exist is not a
    /// default configuration, it is a missing resource.
    fn assert_database(&self, project: &str, database: &str) -> Result<(), Status> {
        if project.is_empty() || database.is_empty() {
            return Err(Status::invalid_argument(
                "field configuration must name a project and a database",
            ));
        }
        if crate::admin::rest::database_exists(self, project, database) {
            Ok(())
        } else {
            // Production's words for the fields of a database it does not have.
            Err(Status::not_found("Requested database was not found."))
        }
    }

    fn selector(
        project: &str,
        database: &str,
        group: &str,
        field: &str,
    ) -> Result<FieldSelector, Status> {
        let collection_group = CollectionId::try_new(group).map_err(|error| {
            Status::invalid_argument(format!("collection group {group} is not valid: {error}"))
        })?;
        if field.is_empty() {
            return Err(Status::invalid_argument(
                "field configuration must name a field",
            ));
        }
        let parsed = if field == WILDCARD_FIELD {
            None
        } else {
            Some(FieldPath::parse(field).map_err(|error| {
                let refusal = crate::query_messages::property_path_error(field, &error);
                Status::new(refusal.grpc_code(), refusal.to_string())
            })?)
        };
        Ok(FieldSelector {
            project: project.to_owned(),
            database: database.to_owned(),
            collection_group,
            field: parsed,
            field_id: field.to_owned(),
        })
    }

    /// The catalog a field readback reports: the configuration's and every Admin field patch,
    /// pending ones included (production reads back the configuration a patch asks for).
    fn readback_indexes(&self, selector: &FieldSelector) -> IndexSet {
        let mut indexes = self
            .local
            .indexes_for_project_database(&selector.project, &selector.database);
        self.local.admin().fields().overlay(
            &selector.project,
            &selector.database,
            self.local.admin_now(),
            &mut indexes,
            true,
        );
        indexes
    }

    /// The field's latest patch that is still pending, if any.
    fn pending_patch(&self, selector: &FieldSelector) -> Option<crate::admin::fields::FieldPatch> {
        let field = selector.field.as_ref()?;
        let registry = self.local.admin().fields();
        registry
            .of_field(
                &selector.project,
                &selector.database,
                &selector.collection_group,
                field,
            )
            .into_iter()
            .last()
            .filter(|patch| !registry.applied(patch, self.local.admin_now()))
    }

    fn field_json(&self, selector: &FieldSelector) -> Value {
        let indexes = self.readback_indexes(selector);
        let pending = self.pending_patch(selector);
        let creating: Vec<(IndexQueryScope, IndexFieldMode)> = match &pending {
            Some(crate::admin::fields::FieldPatch {
                change: crate::admin::fields::FieldChange::IndexConfig(Some(modes)),
                before,
                ..
            }) => modes
                .iter()
                .filter(|m| !before.contains(m))
                .copied()
                .collect(),
            _ => Vec::new(),
        };
        let mut resource = json!({
            "name": selector.resource_name(),
            "indexConfig": index_config_json(selector, &indexes, &creating),
        });
        if let Some(policy) = self.ttl_policy(selector) {
            let adding = matches!(
                pending.as_ref().map(|p| &p.change),
                Some(crate::admin::fields::FieldChange::TtlAdd)
            );
            let mut config = json!({
                "state": if adding { "CREATING" } else { policy.state.as_str() }
            });
            // An unset `expirationOffset` is absent from the resource rather than reported
            // as zero, so a readback repeats what the patch asked for.
            if let Some(offset) = policy.expiration_offset {
                config["expirationOffset"] = json!(format_expiration_offset(offset));
            }
            resource["ttlConfig"] = config;
        }
        resource
    }

    fn ttl_policy(&self, selector: &FieldSelector) -> Option<TtlPolicy> {
        let field = selector.field.as_ref()?;
        self.local
            .ttl_policy(
                &selector.project,
                &selector.database,
                &selector.collection_group,
            )
            .filter(|policy| &policy.field == field)
    }

    /// An `indexConfig` patch: what it changes, the modes it starts from, and its deltas.
    fn index_config_change(
        &self,
        selector: &FieldSelector,
        field: &FieldPath,
        body: &Value,
    ) -> Result<(PatchChange, Value), Status> {
        // Everything that can refuse this patch is decided before the first state change.
        let target = parse_index_config(&body["indexConfig"])?;
        let before = self
            .readback_indexes(selector)
            .single_field_modes(&selector.collection_group, field);
        let after = target.clone().unwrap_or_else(|| {
            self.local
                .indexes_for_project_database(&selector.project, &selector.database)
                .single_field_modes(&selector.collection_group, field)
        });
        let deltas = index_config_deltas(selector, &before, &after);
        Ok((
            (
                crate::admin::fields::FieldChange::IndexConfig(target),
                before,
            ),
            json!({ "indexConfigDeltas": deltas }),
        ))
    }

    /// A `ttlConfig` patch, applied to the TTL catalog at once, and its delta.
    fn ttl_change(
        &self,
        selector: &FieldSelector,
        field: &FieldPath,
        body: &Value,
    ) -> Result<(PatchChange, Value), Status> {
        let requested = parse_ttl_config(&body["ttlConfig"])?;
        Ok(match requested {
            TtlConfigRequest::Enable { expiration_offset } => {
                self.local
                    .enable_ttl_with_offset(
                        &selector.project,
                        &selector.database,
                        selector.collection_group.clone(),
                        field.clone(),
                        expiration_offset,
                    )
                    .map_err(|error| match error {
                        // Production allows one TTL field per collection group and says
                        // so naming the field the patch asked for.
                        TtlError::ConflictingField { .. } => Status::resource_exhausted(format!(
                            "The collection group '{}' can only have at most '1' field(s) \
                             marked with TTL but already has TTL configurations set on path \
                             '{}'. Please delete at least one and try again.",
                            selector.collection_group.as_str(),
                            selector.field_id
                        )),
                        TtlError::DocumentNameField => Status::invalid_argument(error.to_string()),
                        TtlError::TooManyFields { .. } => {
                            Status::resource_exhausted(error.to_string())
                        }
                    })?;
                (
                    (crate::admin::fields::FieldChange::TtlAdd, Vec::new()),
                    json!({ "ttlConfigDelta": { "changeType": "ADD" } }),
                )
            }
            TtlConfigRequest::Disable => {
                self.local.disable_ttl(
                    &selector.project,
                    &selector.database,
                    &selector.collection_group,
                    field,
                );
                (
                    (crate::admin::fields::FieldChange::TtlRemove, Vec::new()),
                    json!({ "ttlConfigDelta": { "changeType": "REMOVE" } }),
                )
            }
        })
    }

    fn patch_field(
        &self,
        selector: &FieldSelector,
        body: &Value,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<RestResponse, Status> {
        if !body.is_object() && !body.is_null() {
            return Err(Status::invalid_argument(
                "the request body must be a Field resource",
            ));
        }
        let mask: Vec<String> = match single(params, "updateMask")? {
            None => Vec::new(),
            Some(mask) => mask
                .split(',')
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(str::to_owned)
                .collect(),
        };
        if let Some(unknown) = mask
            .iter()
            .find(|path| !matches!(path.as_str(), "ttlConfig" | "indexConfig"))
        {
            // Production's words for a mask path the Field message does not have.
            return Err(Status::invalid_argument(format!(
                "Invalid update field mask: paths: \t \"{unknown}\"\n"
            )));
        }
        let patches_index_config = mask.iter().any(|path| path == "indexConfig")
            || (mask.is_empty() && body.get("indexConfig").is_some());
        let patches_ttl = mask.iter().any(|path| path == "ttlConfig")
            || (mask.is_empty() && body.get("ttlConfig").is_some());
        if !patches_ttl && !patches_index_config {
            return Err(Status::invalid_argument(
                "updateMask must name ttlConfig or indexConfig",
            ));
        }
        let Some(field) = selector.field.clone() else {
            return Err(Status::invalid_argument(
                "the wildcard field names a collection group's default settings and \
                 cannot carry a TTL policy or a single-field index override",
            ));
        };
        let now = self.local.admin_now();
        let (change, delta) = if patches_index_config {
            self.index_config_change(selector, &field, body)?
        } else {
            self.ttl_change(selector, &field, body)?
        };
        let admin = self.local.admin();
        let operation = admin
            .operations()
            .reserve(&selector.project, &selector.database);
        let name = format!(
            "projects/{}/databases/{}/operations/{operation}",
            selector.project, selector.database
        );
        let mut metadata = json!({
            "@type": FIELD_METADATA_TYPE_URL,
            "field": selector.resource_name(),
            "startTime": timestamp_to_json(&encode_instant(now)),
            "state": "INITIALIZING",
        });
        if let (Some(target), Some(extra)) = (metadata.as_object_mut(), delta.as_object()) {
            target.extend(extra.clone());
        }
        let initial = json!({ "name": name, "metadata": metadata });
        admin.fields().record(crate::admin::fields::FieldPatch {
            project: selector.project.clone(),
            database: selector.database.clone(),
            group: selector.collection_group.clone(),
            field,
            change: change.0,
            started: std::time::Instant::now(),
            start_time: now,
            operation: operation.clone(),
            before: change.1,
        });
        admin.operations().record_field(
            &selector.project,
            &selector.database,
            &operation,
            initial.clone(),
        );
        Ok(ok(initial))
    }

    /// What `operations.get` answers for a field patch now: as first answered while it is
    /// pending, and done (with the collection group's document count and the part of the field
    /// it changed) once it is applied.
    pub(crate) fn field_operation_json(
        &self,
        patch: &crate::admin::fields::FieldPatch,
        initial: &Value,
    ) -> Value {
        if !self
            .local
            .admin()
            .fields()
            .applied(patch, self.local.admin_now())
        {
            return initial.clone();
        }
        let selector = FieldSelector {
            project: patch.project.clone(),
            database: patch.database.clone(),
            collection_group: patch.collection_group_id(),
            field: Some(patch.field.clone()),
            field_id: patch.field.canonical(),
        };
        let mut metadata = initial["metadata"].clone();
        metadata["state"] = json!("SUCCESSFUL");
        let end = fireemu_core_types::time::LogicalInstant::from_nanos(
            patch.start_time.as_nanos() + 1_000_000,
        );
        metadata["endTime"] = json!(timestamp_to_json(&encode_instant(end)));
        let documents = crate::admin::managed::group_document_count(
            self,
            &patch.project,
            &patch.database,
            patch.group.as_str(),
        );
        if documents > 0 {
            metadata["progressDocuments"] = json!({
                "estimatedWork": documents.to_string(),
                "completedWork": documents.to_string(),
            });
        }
        let mut response = json!({
            "@type": "type.googleapis.com/google.firestore.admin.v1.Field",
            "name": selector.resource_name(),
        });
        match &patch.change {
            crate::admin::fields::FieldChange::TtlAdd => {
                let mut config = self.field_json(&selector)["ttlConfig"].clone();
                if config.is_object() {
                    config["state"] = json!("ACTIVE");
                    response["ttlConfig"] = config;
                } else {
                    response["ttlConfig"] = json!({ "state": "ACTIVE" });
                }
            }
            crate::admin::fields::FieldChange::TtlRemove => {}
            crate::admin::fields::FieldChange::IndexConfig(_) => {
                // The operation answers the field it wrote: production leaves out
                // usesAncestorConfig there even for a revert to the inherited indexes.
                let mut config = self.field_json(&selector)["indexConfig"].clone();
                if let Some(config) = config.as_object_mut() {
                    config.remove("usesAncestorConfig");
                }
                response["indexConfig"] = config;
            }
        }
        json!({
            "name": initial["name"],
            "metadata": metadata,
            "done": true,
            "response": response,
        })
    }

    fn list_fields(
        &self,
        project: &str,
        database: &str,
        group: &str,
        params: &BTreeMap<String, Vec<String>>,
    ) -> Result<RestResponse, Status> {
        let collection_group = CollectionId::try_new(group).map_err(|error| {
            Status::invalid_argument(format!("collection group {group} is not valid: {error}"))
        })?;
        // Production lists only fields that carry a configuration of their own, and names the
        // two filters that select them. Any other filter is refused rather than silently
        // widened to a listing the caller did not ask for.
        let (ttl_only, ancestor_only) = match single(params, "filter")? {
            Some("indexConfig.usesAncestorConfig:false") => (false, true),
            Some("ttlConfig:*") => (true, false),
            // Production refuses a listing that names neither selection, in its own words.
            _ => {
                return Err(Status::invalid_argument(
                    "ListFieldsRequest.filter must include at least fields that do not use \
                     their ancestor configuration, or fields with TTLs.",
                ))
            }
        };
        let binding = listing_binding(
            project,
            database,
            collection_group.as_str(),
            single(params, "filter")?.unwrap_or_default(),
        );
        let page_size = match single(params, "pageSize")? {
            None => MAX_FIELDS_PAGE_SIZE,
            Some(raw) => {
                let parsed: usize = raw.parse().map_err(|_| {
                    Status::invalid_argument("pageSize must be a non-negative integer")
                })?;
                if parsed == 0 {
                    MAX_FIELDS_PAGE_SIZE
                } else {
                    parsed.min(MAX_FIELDS_PAGE_SIZE)
                }
            }
        };
        let offset = match single(params, "pageToken")? {
            None | Some("") => 0,
            Some(raw) => page_offset(binding, raw)?,
        };
        let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // `indexConfig.usesAncestorConfig:false` selects fields that carry an index
        // configuration of their own. A field that only carries a TTL policy still inherits
        // its indexes, so it does not belong in that listing.
        if !ancestor_only {
            let ttl = self.local.ttl_catalog(project, database);
            if let Some(policy) = ttl.policy(&collection_group) {
                names.insert(policy.field.canonical());
            }
        }
        if !ttl_only {
            let mut indexes = self.local.indexes_for_project_database(project, database);
            self.local.admin().fields().overlay(
                project,
                database,
                self.local.admin_now(),
                &mut indexes,
                true,
            );
            for (collection, segments, _modes) in indexes.single_field_overrides() {
                if collection != collection_group.as_str() {
                    continue;
                }
                if segments.is_empty() {
                    names.insert(WILDCARD_FIELD.to_owned());
                } else if let Ok(path) =
                    FieldPath::from_segments(segments.iter().map(String::as_str))
                {
                    names.insert(path.canonical());
                }
            }
        }
        let total = names.len();
        let page: Vec<Value> = names
            .into_iter()
            .skip(offset)
            .take(page_size)
            .map(|field_id| {
                let selector = FieldSelector {
                    project: project.to_owned(),
                    database: database.to_owned(),
                    collection_group: collection_group.clone(),
                    field: if field_id == WILDCARD_FIELD {
                        None
                    } else {
                        FieldPath::parse(&field_id).ok()
                    },
                    field_id,
                };
                self.field_json(&selector)
            })
            .collect();
        let mut body = json!({ "fields": page });
        let consumed = offset.saturating_add(page_size);
        if consumed < total {
            body["nextPageToken"] = json!(page_token(binding, consumed));
        }
        Ok(ok(body))
    }
}

impl RestState {
    /// `projects/{p}/databases/{d}/operations[/{operation}]`.
    ///
    /// Only the field-configuration operations this runtime produced are reported: every
    /// other long-running operation of the Admin API is managed infrastructure that no local
    /// process performs.
    pub(super) fn admin_operations_route(
        &self,
        req: &RestRequest,
        segments: &[&str],
    ) -> Result<RestResponse, Status> {
        if !rules::is_owner_credential(req.authorization.as_deref()) {
            return Err(Status::permission_denied(
                "Admin operations require owner credentials",
            ));
        }
        if self.gateway.ctx.edition != fireemu_core_types::edition::FirestoreEdition::Standard
            || self.gateway.ctx.api_mode != fireemu_core_types::edition::FirestoreApiMode::Native
        {
            return Err(Status::unimplemented(
                "field-configuration operations are supported only for Standard Native \
                 databases",
            ));
        }
        let barrier = self.local.barrier();
        let _admitted = barrier.admit();
        match segments {
            [_, project, _, database, _] => {
                let prefix = format!("projects/{project}/databases/{database}/operations/");
                let operations: Vec<Value> = self
                    .local
                    .field_operations(project)
                    .into_iter()
                    .filter(|operation| operation.name.starts_with(&prefix))
                    .map(|operation| operation_json(&operation))
                    .collect();
                Ok(ok(json!({ "operations": operations })))
            }
            [_, project, _, database, _, operation] => {
                let name =
                    format!("projects/{project}/databases/{database}/operations/{operation}");
                self.local.field_operation(project, &name).map_or_else(
                    || {
                        Err(Status::not_found(format!(
                            "Operation '{name}' does not exist."
                        )))
                    },
                    |operation| Ok(ok(operation_json(&operation))),
                )
            }
            _ => Ok(not_found_text()),
        }
    }
}

/// What a patch's `ttlConfig` asks for, once it has been read and found well-formed.
enum TtlConfigRequest {
    /// The configuration is absent or null, which clears the policy.
    Disable,
    /// The configuration enables the policy, carrying the offset it named, if any.
    Enable {
        /// The `expirationOffset`, absent for the bare `{}`.
        expiration_offset: Option<LogicalDuration>,
    },
}

/// Reads the `ttlConfig` a patch carries, before anything it names is applied.
///
/// Anything that is not a `google.firestore.admin.v1.Field.TtlConfig` is a caller error: the
/// field is a message, so a boolean, a number, a string and an array are all refused rather
/// than read as a request to enable the policy.
fn parse_ttl_config(value: &Value) -> Result<TtlConfigRequest, Status> {
    if value.is_null() {
        return Ok(TtlConfigRequest::Disable);
    }
    let Some(config) = value.as_object() else {
        return Err(Status::invalid_argument(
            "ttlConfig must be a TtlConfig object; an empty object enables the policy and a \
             null or absent value disables it",
        ));
    };
    for key in config.keys() {
        // `state` is output-only: a caller may echo back the resource it read, and the value
        // it carries is ignored rather than installed. Any other key names nothing the
        // message defines.
        if !matches!(key.as_str(), "state" | "expirationOffset") {
            return Err(Status::invalid_argument(format!(
                "ttlConfig has no field named {key}"
            )));
        }
    }
    let expiration_offset = match config.get("expirationOffset") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(
            parse_expiration_offset(text)
                .map_err(|error| Status::invalid_argument(error.to_string()))?,
        ),
        Some(_) => {
            return Err(Status::invalid_argument(
                "ttlConfig.expirationOffset must be a duration in seconds, such as \"604800s\"",
            ))
        }
    };
    Ok(TtlConfigRequest::Enable { expiration_offset })
}

/// The `google.longrunning.Operation` of one completed field configuration.
pub(crate) fn operation_json(operation: &crate::local::FieldOperation) -> Value {
    let at = timestamp_to_json(&encode_instant(operation.at));
    json!({
        "name": operation.name,
        "metadata": {
            "@type": "type.googleapis.com/google.firestore.admin.v1.FieldOperationMetadata",
            "field": operation.field,
            "startTime": at,
            "endTime": at,
            "state": "SUCCESSFUL",
        },
        "done": true,
        "response": operation.response,
    })
}
