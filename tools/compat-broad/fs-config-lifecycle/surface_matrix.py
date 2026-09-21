"""Classification of the Firestore Admin API v1 management surface for FS-CONFIG-LIFECYCLE.

The denominator is the pinned, credential-free Discovery document already checked into
this repository. Nothing here contacts Google, reads credentials, or observes production.
Each row records one of three classes, an explicit rationale, the data-plane consequence
that survives the classification, and the current local implementation location.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

CASE_ID = "FS-CONFIG-LIFECYCLE-01"
SCHEMA = "fs-config-lifecycle-surface-classification-v1"
DISCOVERY_PATH = "spec/compatibility/upstream/2026-09-09-retry/discovery.json"
SPEC_PATH = "spec/compatibility/fs-config-lifecycle-surfaces.json"
DISCOVERY_ID = "firestore-v1"
EXCLUDED_PREFIX = "firestore.projects.databases.documents."
METHOD_PREFIX = "firestore.projects."

EXCLUDED_RATIONALE = (
    "Document methods are the Firestore data plane itself and are owned by the "
    "FS-DATA-WRITE, FS-QUERY-INDEX, FS-TRANSACTION and FS-LISTEN-SDK rows. They are "
    "listed here so the management denominator is provably the complement of a "
    "published set rather than an unstated selection."
)

DATA_PLANE = "data-plane-contract"
LOCAL_SAFETY = "local-safety-extension"
MANAGED = "managed-infrastructure"
CLASSES = (DATA_PLANE, LOCAL_SAFETY, MANAGED)


def _row(*fields: Any) -> tuple[Any, ...]:
    """Collect one table row; keeps long prose out of a collection literal."""
    return fields


TICKET_OPEN = "OPEN"
TICKET_PARTIAL = "PARTIALLY_FIXED"
TICKET_FIXED = "FIXED"
TICKET_STATES = (TICKET_OPEN, TICKET_PARTIAL, TICKET_FIXED)

# Commits that closed or narrowed a ticket. Cited by full hash so the state is
# checkable with `git show`; the ticket's summary and reproduction stay as the
# historical statement of the gap.
COMMIT_REFUSE_UNCREATED_DATABASE = "cb429f2c4d4ad4065c37c68b5e4f4dcb37679ff7"
COMMIT_PRODUCTION_DATABASE_RESOURCE = "62d8a1d22deedd33b793fa5a160f8bc5fcac4c83"


def _ticket(
    ticket_id: str,
    title: str,
    summary: str,
    reproduction: str,
    citations: tuple[str, ...],
    klass: str,
    status: str = TICKET_OPEN,
    fixed_at: str | None = None,
    resolution: str | None = None,
) -> dict[str, Any]:
    """Collect one repair ticket.

    A ticket is OPEN until a commit closes it; a FIXED or PARTIALLY_FIXED ticket
    names that commit and states what it changed, and keeps its original summary
    and reproduction as the record of the gap. The fix is never applied by the work
    that renders this matrix.
    """
    if status not in TICKET_STATES or (status != TICKET_OPEN) != (fixed_at is not None):
        raise ValueError("a fixed ticket names its commit; an open ticket names none")
    return {
        "id": ticket_id,
        "title": title,
        "summary": summary,
        "reproduction": reproduction,
        "citations": list(citations),
        "class": klass,
        "status": status,
        "fixApplied": status == TICKET_FIXED,
        "fixedAt": fixed_at,
        "resolution": resolution,
    }


_REST = "crates/fireemu-adapter-grpc/src/rest/mod.rs"
_LOCAL = "crates/fireemu-adapter-grpc/src/local.rs"
_CONTROL = "crates/fireemu/src/control.rs"
_INDEX = "crates/fireemu-core-firestore/src/index.rs"
_IMPORT_EXPORT = "crates/fireemu/src/import_export.rs"
_METADATA = "crates/fireemu-core-export/src/metadata.rs"
_EXPORT_FS = "crates/fireemu-core-export/src/firestore.rs"
_IDS = "crates/fireemu-core-types/src/ids.rs"
_FIELDS = "crates/fireemu-adapter-grpc/src/rest/admin_fields.rs"
_TTL = "crates/fireemu-core-firestore/src/ttl.rs"


def _at(path: str, anchor: str) -> str:
    """`file:line` of the one line of `path` containing `anchor`.

    Citations are resolved from the source at build time rather than written as literal line
    numbers, which drift silently every time an unrelated edit moves a function. An anchor
    that no longer appears, or that appears more than once, fails the build instead of
    producing a citation that points at a blank line.
    """
    root = Path(__file__).resolve().parents[3]
    lines = (root / path).read_text(encoding="utf-8").splitlines()
    hits = [index for index, line in enumerate(lines, start=1) if anchor in line]
    if len(hits) != 1:
        raise ValueError(
            f"{path}: anchor {anchor!r} matches {len(hits)} lines, expected exactly one"
        )
    return f"{path}:{hits[0]}"


_NOT_SERVED = "not-implemented"
_IMPLEMENTED = "implemented"
_PARTIAL = "partial"
_EXTENSION = "local-extension-only"

# (method suffix under firestore.projects., class, rationale, data-plane consequence,
#  local status, citations)
_METHODS: tuple[tuple[str, str, str, str, str, tuple[str, ...]], ...] = (
    _row(
        "databases.get",
        DATA_PLANE,
        "Client tooling and the emulator suite read database settings before choosing a "
        "data-plane code path, and several returned fields change what the data plane "
        "accepts, so the projection is part of the contract rather than provisioning.",
        "A wrong concurrencyMode, databaseEdition or versionRetentionPeriod makes a "
        "caller choose transaction, edition and read-time behavior the local runtime "
        "will then refuse or accept differently from production.",
        _PARTIAL,
        (
            _at(_REST, "fn admin_inventory_route("),
            _at(
                _REST,
                "\"Project '{project}' or database '{database}' does not exist.\"",
            ),
            _at(_REST, "fn admin_database_json("),
        ),
    ),
    _row(
        "databases.list",
        DATA_PLANE,
        "Enumeration decides whether a named database exists at all, which is the "
        "precondition every data-plane request on that database depends on.",
        "A database absent in production but present locally lets a caller address a "
        "database that would return NOT_FOUND against the real service.",
        _PARTIAL,
        (
            _at(_REST, "fn admin_inventory_route("),
            _at(_REST, "let databases: Vec<Value> = databases.iter()"),
            _at(_REST, "databases.extend(self.local.declared_databases());"),
        ),
    ),
    _row(
        "databases.create",
        MANAGED,
        "Creation allocates a regional, billed, quota-limited resource with an edition, "
        "location and CMEK binding that no local process can reproduce or account for.",
        "Existence and non-existence remain observable from the data plane, so the "
        "NOT_FOUND boundary for an uncreated database stays a contract obligation even "
        "though the provisioning call itself does not.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.patch",
        MANAGED,
        "Updating delete protection, point-in-time recovery or CMEK changes a billed "
        "managed configuration and runs as a long-running operation.",
        "The patched values are readable through databases.get, so the resulting "
        "projection stays inside the data-plane contract row above.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.delete",
        MANAGED,
        "Deletion destroys a managed resource, is gated by delete protection and "
        "produces a long-running operation with no local analogue.",
        "Post-deletion NOT_FOUND on the data plane remains a contract obligation.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.restore",
        MANAGED,
        "Restore reads a managed backup artifact that only Google retains; the local "
        "runtime has no backup store to restore from.",
        "A restored database must still serve the ordinary data plane, which is covered "
        "by the existing data-plane rows rather than by this method.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.clone",
        MANAGED,
        "Clone depends on point-in-time recovery retention held by the managed service.",
        "The cloned database's data plane is covered by the ordinary data-plane rows.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.bulkDeleteDocuments",
        MANAGED,
        "Bulk delete is an eventually consistent long-running operation whose progress, "
        "partial completion and quota behavior are properties of managed infrastructure.",
        "The final post-state, absence of the deleted documents, is observable from the "
        "data plane; the local emulator wipe route is the local-safety counterpart.",
        _EXTENSION,
        (
            _at(_REST, "fn emulator_route("),
            _at(_REST, "self.local.clear_project_documents(project)?;"),
        ),
    ),
    _row(
        "databases.exportDocuments",
        MANAGED,
        "Export writes to Cloud Storage under a long-running operation with managed "
        "quota, retries and object lifecycle; none of that exists locally.",
        "The written export format is a contract: fireemu's own export and import must "
        "read and write what the official tooling produces, which is already covered by "
        "local format evidence.",
        _EXTENSION,
        (
            _at(_IMPORT_EXPORT, "pub fn export("),
            f"{_EXPORT_FS}:480",
            f"{_METADATA}:142",
        ),
    ),
    _row(
        "databases.importDocuments",
        MANAGED,
        "Import is a long-running operation reading managed Cloud Storage objects, with "
        "server-side validation and quota behavior that is not locally reproducible.",
        "The accepted on-disk format, partition enumeration and refusal of corrupt or "
        "duplicated output references are a contract the local importer already holds.",
        _EXTENSION,
        (f"{_IMPORT_EXPORT}:353", f"{_IMPORT_EXPORT}:1136", f"{_IMPORT_EXPORT}:1168"),
    ),
    _row(
        "databases.collectionGroups.indexes.create",
        DATA_PLANE,
        "Composite index existence decides whether a query is accepted or refused with "
        "FAILED_PRECONDITION, so index creation directly determines data-plane results.",
        "Without this method an index can only be declared through configuration, so a "
        "caller cannot reach the accepted state a production query depends on.",
        _EXTENSION,
        (f"{_CONTROL}:48", f"{_CONTROL}:88"),
    ),
    _row(
        "databases.collectionGroups.indexes.get",
        DATA_PLANE,
        "Index state is how a caller learns that a query will now be accepted; the "
        "CREATING to READY transition is observable from the data plane.",
        "A missing readback leaves index-dependent query acceptance untestable against "
        "the same contract production exposes.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.collectionGroups.indexes.list",
        DATA_PLANE,
        "Enumeration is the denominator for index-merge and index-selection decisions "
        "that the query planner then makes on the data plane.",
        "Local index selection is driven by configuration instead, so the two catalogs "
        "can diverge without any request revealing it.",
        _EXTENSION,
        (f"{_INDEX}:949", f"{_INDEX}:597"),
    ),
    _row(
        "databases.collectionGroups.indexes.delete",
        DATA_PLANE,
        "Deleting an index flips previously accepted queries back to refusal, which is a "
        "data-plane observable transition.",
        "Without deletion the refusal direction of the transition cannot be reached at "
        "runtime.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.collectionGroups.fields.get",
        DATA_PLANE,
        "Field configuration carries the TTL policy and the single-field index exemption, "
        "both of which change document lifetime and query acceptance.",
        "A caller can read back the TTL policy and the single-field index configuration, "
        "so the expiry and refusal behavior each implies is observable locally.",
        _IMPLEMENTED,
        (
            _at(_FIELDS, "pub(super) fn admin_fields_route("),
            _at(_FIELDS, "fn field_json(&self, selector: &FieldSelector)"),
            _at(_FIELDS, "fn index_config_json("),
            _at(_TTL, "pub struct TtlCatalog {"),
        ),
    ),
    _row(
        "databases.collectionGroups.fields.list",
        DATA_PLANE,
        "Enumeration with the ttlConfig and indexConfig filters is how tooling discovers "
        "every non-default field policy affecting the data plane.",
        "Both documented filters are served and any other filter is refused, so an "
        "exemption set and a TTL policy set are each discoverable through a read path.",
        _IMPLEMENTED,
        (
            _at(_FIELDS, "fn list_fields("),
            _at(_FIELDS, "fn page_token("),
            _at(_INDEX, "pub fn single_field_overrides("),
        ),
    ),
    _row(
        "databases.collectionGroups.fields.patch",
        DATA_PLANE,
        "Patching ttlConfig schedules server-side document deletion and patching "
        "indexConfig exempts a field from single-field indexing; both change what later "
        "reads and queries return.",
        "The ttlConfig transition is driven at runtime and an expiry sweep applies it. "
        "The indexConfig transition is refused with UNIMPLEMENTED: the local runtime "
        "still accepts exemptions only from static configuration, so that half of the "
        "surface cannot be driven at runtime.",
        _PARTIAL,
        (
            _at(_FIELDS, "fn patch_field("),
            _at(_TTL, "    pub fn enable("),
            _at(_LOCAL, "fn sweep_ttl("),
            _at(_CONTROL, "fn parse_field_overrides("),
        ),
    ),
    _row(
        "databases.operations.get",
        MANAGED,
        "Long-running operation state belongs to the managed control plane; the local "
        "runtime applies a field configuration synchronously and records the resulting "
        "operation only so the name its patch returned can still be polled.",
        "A campaign that drives fields.patch can poll the operation it was handed, and "
        "it is always already done; every other long-running operation of the Admin API "
        "remains managed infrastructure the runtime does not hold. A campaign must still "
        "bound its own polling, which the collector contract handles.",
        _PARTIAL,
        (
            _at(_FIELDS, "pub(super) fn admin_operations_route("),
            _at(_LOCAL, "pub fn record_field_operation("),
            _at(_LOCAL, "pub fn field_operation(&self, project: &str"),
        ),
    ),
    _row(
        "databases.operations.list",
        MANAGED,
        "Operation enumeration reflects managed scheduling and retention, not any "
        "behavior a local emulator can hold; the local listing reports only the bounded "
        "tail of field-configuration operations this runtime produced.",
        "Enumeration is how an interrupted campaign resumes its cleanup. Locally it "
        "enumerates the field-configuration operations alone, and the record is bounded, "
        "so a campaign must not treat it as the managed operation history.",
        _PARTIAL,
        (
            _at(_FIELDS, "pub(super) fn admin_operations_route("),
            _at(_LOCAL, "pub fn field_operations(&self, project: &str"),
        ),
    ),
    _row(
        "databases.operations.cancel",
        MANAGED,
        "Cancellation is best-effort against managed work already in flight.",
        "Cancellation is part of the abort path of a management campaign, not of any "
        "local data-plane behavior.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.operations.delete",
        MANAGED,
        "Deleting an operation record only prunes managed bookkeeping.",
        "None; no data-plane result depends on operation record retention.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.backupSchedules.create",
        MANAGED,
        "Backup schedules allocate managed retention with a billed storage footprint.",
        "None; scheduled backups are never readable through the data plane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.backupSchedules.get",
        MANAGED,
        "Schedule readback describes managed retention policy only.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.backupSchedules.list",
        MANAGED,
        "Schedule enumeration describes managed retention policy only.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.backupSchedules.patch",
        MANAGED,
        "Changing retention changes a billed managed policy.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.backupSchedules.delete",
        MANAGED,
        "Removing a schedule changes managed retention only.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.create",
        MANAGED,
        "User credentials mint a managed password bound to an IAM-adjacent identity; "
        "issuing real credentials from an emulator would be a local security hazard.",
        "The resulting principal is visible to Security Rules, so principal shape stays "
        "a contract obligation of the Rules lane rather than of this method.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.get",
        MANAGED,
        "Reading a managed credential record describes control-plane state only.",
        "None directly; the principal it names is covered by the Rules lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.list",
        MANAGED,
        "Credential enumeration is managed control-plane state.",
        "None directly; the principals it names are covered by the Rules lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.delete",
        MANAGED,
        "Credential deletion revokes a managed identity.",
        "Revocation is observable through Rules evaluation, which the Rules lane owns.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.enable",
        MANAGED,
        "Enabling a credential toggles managed identity state.",
        "The enabled principal is observable through Rules, owned by the Rules lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.disable",
        MANAGED,
        "Disabling a credential toggles managed identity state.",
        "The disabled principal is observable through Rules, owned by the Rules lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.userCreds.resetPassword",
        MANAGED,
        "Password reset mints new managed secret material.",
        "None directly; secret material must never be emitted by a local emulator.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.changeStreams.create",
        MANAGED,
        "Change streams provision managed retention for a change feed with its own "
        "billing and lifecycle.",
        "The delivered changes overlap the Listen contract, which the listen lane owns.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.changeStreams.get",
        MANAGED,
        "Change stream readback describes managed retention state.",
        "None directly; delivered changes are owned by the listen lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.changeStreams.list",
        MANAGED,
        "Change stream enumeration describes managed retention state.",
        "None directly; delivered changes are owned by the listen lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "databases.changeStreams.delete",
        MANAGED,
        "Deleting a change stream releases managed retention.",
        "None directly; delivered changes are owned by the listen lane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "locations.get",
        MANAGED,
        "Locations describe Google's regional footprint, which no local process defines.",
        "The location a database was created in is echoed by databases.get, so only that "
        "projection field carries a contract.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "locations.list",
        MANAGED,
        "Location enumeration describes Google's regional footprint.",
        "None beyond the locationId field echoed by databases.get.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "locations.backups.get",
        MANAGED,
        "Backups are managed artifacts retained by Google with their own storage cost.",
        "None; backup content is never readable through the data plane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "locations.backups.list",
        MANAGED,
        "Backup enumeration describes managed artifacts.",
        "None; backup content is never readable through the data plane.",
        _NOT_SERVED,
        (),
    ),
    _row(
        "locations.backups.delete",
        MANAGED,
        "Backup deletion releases managed storage.",
        "None; backup content is never readable through the data plane.",
        _NOT_SERVED,
        (),
    ),
)

# (id, class, rationale, data-plane consequence, local status, citations)
_LOCAL_SURFACES: tuple[tuple[str, str, str, str, str, tuple[str, ...]], ...] = (
    _row(
        "emulator.clearFirestoreData",
        LOCAL_SAFETY,
        "The emulator-only wipe route gives a test suite a synchronous reset that no "
        "production API offers; it exists to keep local runs isolated, not to imitate "
        "bulkDeleteDocuments.",
        "Its post-state is ordinary document absence, which the data-plane lanes already "
        "cover; the route itself must never be reachable against production.",
        _IMPLEMENTED,
        (
            _at(_REST, "fn emulator_route("),
            _at(_REST, "self.local.clear_project_documents(project)?;"),
        ),
    ),
    _row(
        "config.firestoreIndexes",
        LOCAL_SAFETY,
        "Composite indexes and field overrides are loaded from the project's index "
        "configuration at startup because the Admin index methods are not served; this "
        "substitutes configuration for a control-plane call.",
        "Query acceptance and refusal are decided from this catalog, so a configuration "
        "loaded differently from production's index set changes data-plane results.",
        _IMPLEMENTED,
        (f"{_CONTROL}:48", f"{_CONTROL}:88", f"{_CONTROL}:148"),
    ),
    _row(
        "config.singleFieldExemption",
        LOCAL_SAFETY,
        "Single-field exemptions, including the wildcard field path, are honored from "
        "configuration; the production equivalent is a fields.patch call.",
        "An exemption changes which single-field queries are refused, so the two paths "
        "must agree on the resulting refusal even though the transition differs.",
        _IMPLEMENTED,
        (f"{_CONTROL}:148", f"{_CONTROL}:215", f"{_INDEX}:133", f"{_INDEX}:157"),
    ),
    _row(
        "cli.exportImport",
        LOCAL_SAFETY,
        "Export and import run as local commands over a directory tree rather than as "
        "long-running operations over Cloud Storage, so a developer can snapshot and "
        "restore a local run without any managed dependency.",
        "The on-disk format must match what official tooling writes, otherwise a real "
        "export cannot be loaded locally.",
        _IMPLEMENTED,
        (
            _at(_IMPORT_EXPORT, "pub fn export("),
            f"{_IMPORT_EXPORT}:353",
            f"{_METADATA}:142",
        ),
    ),
    _row(
        "cli.namedDatabaseExportExtension",
        LOCAL_SAFETY,
        "The named-database export extension records databases beyond the default one in "
        "a metadata extension block; the official format has no such section, so this is "
        "an additive local convenience.",
        "Cross-database reference values must survive a round trip and a malformed "
        "database identity must be refused before any document is published.",
        _IMPLEMENTED,
        (f"{_METADATA}:133", f"{_METADATA}:195", f"{_IMPORT_EXPORT}:1378"),
    ),
    _row(
        "runtime.lazyDatabaseCreation",
        LOCAL_SAFETY,
        "Any syntactically valid database id is materialized on first touch so that a "
        "test does not need a provisioning step; production requires databases.create "
        "first and answers NOT_FOUND until then.",
        "A request against an uncreated named database succeeds locally and fails in "
        "production, which is recorded as an open repair ticket rather than a fix here.",
        _IMPLEMENTED,
        (f"{_LOCAL}:2629", f"{_IDS}:183"),
    ),
    _row(
        "control.textIndexLifecycle",
        LOCAL_SAFETY,
        "fireemu's own control API exposes an Enterprise text-index resource that has no "
        "Firestore Admin v1 counterpart in the pinned discovery input.",
        "It must stay Enterprise-gated so a Standard Native run cannot reach a surface "
        "production would not serve.",
        _IMPLEMENTED,
        ("crates/fireemu-adapter-http/src/control.rs:1346",),
    ),
)

# (field, class, rationale, consequence, status, citations, present in pinned discovery)
_DATABASE_FIELDS: tuple[tuple[str, str, str, str, str, tuple[str, ...], bool], ...] = (
    _row(
        "name",
        DATA_PLANE,
        "The resource name identifies the project and database every data-plane request "
        "addresses.",
        "A mismatched name routes requests to a different database.",
        _IMPLEMENTED,
        (_at(_REST, '"name": format!("projects/{project}/databases/{database}")'),),
        True,
    ),
    _row(
        "type",
        DATA_PLANE,
        "FIRESTORE_NATIVE and DATASTORE_MODE expose different APIs entirely.",
        "A caller that trusts this field picks the wrong API surface.",
        _PARTIAL,
        (_at(_REST, '"type": "FIRESTORE_NATIVE"'),),
        True,
    ),
    _row(
        "databaseEdition",
        DATA_PLANE,
        "Edition decides which methods are served at all; the local inventory route "
        "already refuses non-Standard Native combinations.",
        "The projection reports the configured edition in the API's upper-case "
        "spelling; only Standard reaches the route because every other edition is "
        "refused above it (fixed at 62d8a1d22).",
        _IMPLEMENTED,
        (
            _at(_REST, '"databaseEdition": edition.as_config_str()'),
            _at(_REST, "database inventory is supported only for Standard Native"),
            "crates/fireemu-core-types/src/edition.rs:12",
        ),
        True,
    ),
    _row(
        "concurrencyMode",
        DATA_PLANE,
        "PESSIMISTIC and OPTIMISTIC change when a transaction blocks and when it aborts.",
        "Transaction contention and retry behavior depend on this value.",
        _PARTIAL,
        (_at(_REST, '"concurrencyMode": "PESSIMISTIC"'),),
        True,
    ),
    _row(
        "versionRetentionPeriod",
        DATA_PLANE,
        "Retention bounds how far back a read_time query may address.",
        "A read_time older than the retention window must be refused; a wrong period "
        "moves that boundary.",
        _PARTIAL,
        (_at(_REST, '"versionRetentionPeriod": "3600s"'),),
        True,
    ),
    _row(
        "earliestVersionTime",
        DATA_PLANE,
        "The earliest addressable version time is the concrete lower bound a read_time "
        "request is checked against, and it advances continuously.",
        "It is excluded from settings equality by the database projection because it "
        "moves on its own, but the data-plane bound it expresses is still a contract. "
        "The local projection derives it from the retention window floored at the "
        "database's creation, the bound read_time is checked against (62d8a1d22).",
        _IMPLEMENTED,
        (_at(_REST, '"earliestVersionTime": json::timestamp_to_json'),),
        True,
    ),
    _row(
        "pointInTimeRecoveryEnablement",
        DATA_PLANE,
        "Enabling point-in-time recovery extends the retention window, which widens the "
        "range of accepted read_time values.",
        "The accepted read_time range changes with this setting.",
        _PARTIAL,
        (_at(_REST, '"pointInTimeRecoveryEnablement"'),),
        True,
    ),
    _row(
        "realtimeUpdatesMode",
        DATA_PLANE,
        "Realtime updates decide whether Listen is served for the database.",
        "A disabled mode must refuse Listen; the local projection reports enabled "
        "unconditionally.",
        _PARTIAL,
        (_at(_REST, '"realtimeUpdatesMode"'),),
        True,
    ),
    _row(
        "firestoreDataAccessMode",
        DATA_PLANE,
        "The Firestore data access mode gates whether the Firestore data API is served "
        "for the database at all.",
        "A disabled mode must refuse data-plane requests; the local projection omits the "
        "field.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "mongodbCompatibleDataAccessMode",
        DATA_PLANE,
        "The MongoDB-compatible access mode gates a second data API on the same database.",
        "A caller cannot learn from the local projection whether that API is available.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "locationId",
        MANAGED,
        "The region is fixed by provisioning and cannot be chosen by a local process.",
        "It is echoed to callers, so a hardcoded value must be recognised as declared "
        "rather than observed; the local value is a constant.",
        _PARTIAL,
        (_at(_REST, '"locationId": "us-central1"'),),
        True,
    ),
    _row(
        "appEngineIntegrationMode",
        MANAGED,
        "App Engine integration is a legacy managed binding with no local analogue.",
        "None; the local projection reports DISABLED as a declared constant.",
        _PARTIAL,
        (_at(_REST, '"appEngineIntegrationMode"'),),
        True,
    ),
    _row(
        "deleteProtectionState",
        MANAGED,
        "Delete protection only gates the managed databases.delete call.",
        "None; no data-plane request observes it. It is an abort precondition for any "
        "campaign that creates and deletes a database.",
        _PARTIAL,
        (_at(_REST, '"deleteProtectionState"'),),
        True,
    ),
    _row(
        "uid",
        MANAGED,
        "The server-assigned unique id identifies one provisioning instance.",
        "None, but it is an identity field the database projection requires, so a change "
        "must stop a campaign rather than be normalized away. The local value is "
        "derived deterministically from the project and database ids (62d8a1d22).",
        _IMPLEMENTED,
        (_at(_REST, '"uid": database_uid(project, database)'),),
        True,
    ),
    _row(
        "etag",
        MANAGED,
        "The etag supports optimistic concurrency on managed patch calls.",
        "None; it is excluded from settings equality by the database projection. The "
        "local value is a digest of the projected resource (62d8a1d22).",
        _IMPLEMENTED,
        (_at(_REST, 'resource["etag"] = json!(etag);'),),
        True,
    ),
    _row(
        "freeTier",
        MANAGED,
        "Free tier eligibility is a billing attribute of the managed resource.",
        "None, but it is the precondition that decides whether a second named database "
        "costs anything. The local projection reports true for the default database "
        "and omits the field for any other, as production does (62d8a1d22).",
        _IMPLEMENTED,
        (_at(_REST, 'resource["freeTier"] = json!(true);'),),
        True,
    ),
    _row(
        "createTime",
        MANAGED,
        "Provisioning timestamps describe the managed resource lifecycle.",
        "None; no data-plane result depends on it. The local value is the database's "
        "creation instant on the logical clock (62d8a1d22).",
        _IMPLEMENTED,
        (_at(_REST, '"createTime": created_json,'),),
        True,
    ),
    _row(
        "updateTime",
        MANAGED,
        "Provisioning timestamps describe the managed resource lifecycle.",
        "None; no data-plane result depends on it. The local value equals createTime "
        "because no local call updates the resource (62d8a1d22).",
        _IMPLEMENTED,
        (_at(_REST, '"updateTime": created_json,'),),
        True,
    ),
    _row(
        "deleteTime",
        MANAGED,
        "The deletion timestamp appears only for soft-deleted managed databases.",
        "It is the field that makes showDeleted meaningful; the local inventory accepts "
        "showDeleted but has no deleted state to report.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "keyPrefix",
        MANAGED,
        "The key prefix is a Datastore-era managed identifier.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "cmekConfig",
        MANAGED,
        "Customer-managed encryption keys are a managed KMS binding.",
        "None; encryption is transparent to the data plane.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "tags",
        MANAGED,
        "Resource tags are a Cloud Resource Manager concern.",
        "None; no data-plane result depends on them.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "previousId",
        MANAGED,
        "The previous id records a managed rename or restore lineage.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "sourceInfo",
        MANAGED,
        "Source info records the backup or clone a managed database came from.",
        "None; no data-plane result depends on it.",
        _NOT_SERVED,
        (),
        True,
    ),
    _row(
        "enhancedTextSearchQueryMode",
        DATA_PLANE,
        "This field is absent from the pinned discovery document but is present in the "
        "saved production database response and is emitted by the local projection, so "
        "it is an undocumented surface that must be carried rather than dropped.",
        "It reports whether the enhanced text search query mode is available, which "
        "changes which queries a caller may issue.",
        _PARTIAL,
        (_at(_REST, '"enhancedTextSearchQueryMode"'),),
        False,
    ),
)


_REPAIR_TICKETS: tuple[dict[str, Any], ...] = (
    _ticket(
        "FS-CONFIG-RT-001",
        "A named database is materialized on first touch instead of returning NOT_FOUND",
        "Any syntactically valid database id becomes usable without a create call, so a "
        "request that production refuses with NOT_FOUND succeeds locally.",
        "Start fireemu with only the default database configured, then issue any "
        "Firestore REST read against "
        "projects/{project}/databases/never-created/documents/c/d. The local runtime "
        "creates the database and answers NOT_FOUND for the document; production answers "
        "NOT_FOUND for the database before the document is considered.",
        (
            _at(_LOCAL, "pub const fn with_implicit_database_creation("),
            _at(
                _LOCAL,
                "fn a_database_nothing_created_is_refused_and_is_not_materialized",
            ),
            f"{_IDS}:183",
        ),
        LOCAL_SAFETY,
        status=TICKET_FIXED,
        fixed_at=COMMIT_REFUSE_UNCREATED_DATABASE,
        resolution=(
            "The strict profile answers NOT_FOUND for a database nothing created and "
            "does not materialize it on the refusal; the emulator profile keeps "
            "materializing any database on first touch, as the official emulator does. "
            "Fixed for the strict profile only, by design."
        ),
    ),
    _ticket(
        "FS-CONFIG-RT-002",
        "The database projection reports a constant edition and location",
        "databaseEdition is hardcoded to STANDARD and locationId to us-central1, so the "
        "projection reflects neither the configured edition enum nor any configured "
        "location.",
        "Start fireemu configured for the Enterprise edition and read "
        "projects/{project}/databases/(default) on the Firestore REST port. The response "
        "still reports STANDARD while the same route refuses non-Standard Native traffic "
        "a few lines earlier.",
        (
            _at(_REST, '"databaseEdition": edition.as_config_str()'),
            _at(_REST, "database inventory is supported only for Standard Native"),
            _at(_REST, '"locationId": "us-central1"'),
        ),
        DATA_PLANE,
        status=TICKET_PARTIAL,
        fixed_at=COMMIT_PRODUCTION_DATABASE_RESOURCE,
        resolution=(
            "databaseEdition now comes from the configuration; locationId is still the "
            "constant us-central1. The remaining half is FS-LIFE-003 (database "
            "projection completeness)."
        ),
    ),
    _ticket(
        "FS-CONFIG-RT-003",
        "The database projection omits fields the saved production response carries",
        "uid, freeTier, etag, createTime, updateTime and earliestVersionTime are absent "
        "from the local projection although the saved production response contains them "
        "and the database projection contract requires uid as an identity field.",
        "Compare the local response of projects/{project}/databases/(default) with the "
        "saved offline fixture at "
        "tools/compat-broad/fixtures/database-settings-7be6cf08.json. The local body is a "
        "strict subset and would fail the identity check the batch contract applies.",
        (
            _at(_REST, "fn admin_database_json("),
            "tools/compat-broad/batch_contract.py:230",
            "tools/compat-broad/fixtures/database-settings-7be6cf08.json:1",
        ),
        DATA_PLANE,
        status=TICKET_FIXED,
        fixed_at=COMMIT_PRODUCTION_DATABASE_RESOURCE,
        resolution=(
            "uid, createTime, updateTime, earliestVersionTime, freeTier and etag are "
            "emitted; the local rehearsal record of 2026-09-21 shows the local "
            "projection carrying the same field set as the saved production response, "
            "with local values for uid and the timestamps."
        ),
    ),
    _ticket(
        "FS-CONFIG-RT-004",
        "The indexConfig half of fields.patch has no runtime transition",
        "The field configuration surface is served and the ttlConfig half is complete: "
        "the policy is stored per database, read back as ACTIVE, and an expiry sweep on "
        "the virtual clock deletes documents whose TTL field has elapsed. Patching "
        "indexConfig is refused with UNIMPLEMENTED, because single-field exemptions are "
        "still taken from the project's index configuration at startup and there is no "
        "runtime path that changes them.",
        "Issue PATCH on "
        "projects/{project}/databases/(default)/collectionGroups/{group}/fields/{field} "
        "with updateMask=indexConfig and observe UNIMPLEMENTED, while production applies "
        "the exemption and reports usesAncestorConfig false on the next get.",
        (
            _at(_FIELDS, "fn patch_field("),
            _at(_CONTROL, "fn parse_field_overrides("),
            _at(_INDEX, "pub fn single_field_override("),
        ),
        DATA_PLANE,
    ),
    _ticket(
        "FS-CONFIG-RT-005",
        "An invalid database id is answered NOT_FOUND rather than INVALID_ARGUMENT",
        "A syntactically invalid database id is deliberately mapped to NOT_FOUND on the "
        "data plane. Whether production agrees is exactly one of the error shapes this "
        "lane's campaign is prepared to compare.",
        "Issue a Firestore REST read against "
        "projects/{project}/databases/Invalid_Id/documents/c/d and observe NOT_FOUND "
        "with the message naming the database.",
        (
            _at(
                "crates/fireemu-adapter-grpc/src/decode.rs",
                "DecodeError::UnknownDatabase {",
            ),
            f"{_IDS}:183",
        ),
        DATA_PLANE,
    ),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _pinned_definition() -> dict[str, Any]:
    raw = json.loads((repo_root() / DISCOVERY_PATH).read_text(encoding="utf-8"))
    for definition in raw["definitions"]:
        if definition["id"] == DISCOVERY_ID:
            return definition
    raise ValueError(f"{DISCOVERY_ID} missing from the pinned discovery input")


def pinned_definition() -> dict[str, Any]:
    """The pinned firestore-v1 Discovery definition; no network access."""
    return _pinned_definition()


def discovery_methods() -> list[str]:
    definition = _pinned_definition()
    return sorted(
        surface["locator"]
        for surface in definition["surfaces"]
        if surface["kind"] == "method"
    )


def class_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["class"]] = counts.get(row["class"], 0) + 1
    return dict(sorted(counts.items()))


def build_matrix() -> dict[str, Any]:
    definition = _pinned_definition()
    methods = [
        {
            "locator": f"{METHOD_PREFIX}{suffix}",
            "class": klass,
            "rationale": rationale,
            "dataPlaneConsequence": consequence,
            "local": {"status": status, "citations": list(citations)},
        }
        for suffix, klass, rationale, consequence, status, citations in _METHODS
    ]
    methods.sort(key=lambda row: row["locator"])
    local_surfaces = [
        {
            "id": surface_id,
            "class": klass,
            "rationale": rationale,
            "dataPlaneConsequence": consequence,
            "local": {"status": status, "citations": list(citations)},
        }
        for surface_id, klass, rationale, consequence, status, citations in _LOCAL_SURFACES
    ]
    database_fields = [
        {
            "field": field,
            "class": klass,
            "rationale": rationale,
            "dataPlaneConsequence": consequence,
            "presentInPinnedDiscovery": pinned,
            "local": {"status": status, "citations": list(citations)},
        }
        for field, klass, rationale, consequence, status, citations, pinned in _DATABASE_FIELDS
    ]
    excluded = sorted(
        locator
        for locator in discovery_methods()
        if locator.startswith(EXCLUDED_PREFIX)
    )
    summary = {
        "discoveryMethods": len(discovery_methods()),
        "excludedDataPlaneMethods": len(excluded),
        "classifiedManagementMethods": len(methods),
        "methodsByClass": class_counts(methods),
        "localSurfacesByClass": class_counts(local_surfaces),
        "databaseFieldsByClass": class_counts(database_fields),
        "repairTickets": len(_REPAIR_TICKETS),
        "openRepairTickets": sum(
            1 for ticket in _REPAIR_TICKETS if ticket["status"] == TICKET_OPEN
        ),
        "productionUnobservedConditionsReduced": 0,
    }
    discovery = {
        "path": DISCOVERY_PATH,
        "id": DISCOVERY_ID,
        "revision": definition["revision"],
        "sha256": definition["sha256"],
        "methodListDigest": digest(discovery_methods()),
    }
    return {
        "schema": SCHEMA,
        "caseId": CASE_ID,
        "status": "PREPARATION_ONLY",
        "productionExecuted": False,
        "discovery": discovery,
        "classes": list(CLASSES),
        "excludedPrefix": EXCLUDED_PREFIX,
        "excludedRationale": EXCLUDED_RATIONALE,
        "excluded": excluded,
        "methods": methods,
        "localSurfaces": local_surfaces,
        "databaseFields": database_fields,
        "repairTickets": [json.loads(json.dumps(ticket)) for ticket in _REPAIR_TICKETS],
        "summary": summary,
    }


def validate_matrix(matrix: Any) -> bool:
    if not isinstance(matrix, dict):
        return False
    try:
        expected = build_matrix()
    except (OSError, ValueError, KeyError):
        return False
    if matrix.get("schema") != SCHEMA or matrix.get("status") != "PREPARATION_ONLY":
        return False
    if matrix.get("productionExecuted") is not False:
        return False
    rows = (
        matrix.get("methods", [])
        + matrix.get("localSurfaces", [])
        + matrix.get("databaseFields", [])
    )
    if not all(isinstance(row, dict) and row.get("class") in CLASSES for row in rows):
        return False
    return matrix == expected


def _write() -> int:
    path = repo_root() / SPEC_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build_matrix(), indent=2, sort_keys=True, ensure_ascii=True)
    path.write_text(payload + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(_write() if "--write" in sys.argv else 1)
