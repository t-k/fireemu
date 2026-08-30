//! Control-plane helpers for the binary: index file loading and the capability manifest.

use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
};
use ftd_core_types::ids::CollectionId;
use serde_json::{json, Value};

/// Loads `firestore.text-indexes.json` when `firestore.textIndexDefinitionFile` is set:
/// every entry must validate (FS-TEXT-VAL-1) and the edition must be Enterprise.
pub fn load_text_indexes(
    cfg: &crate::config::RuntimeConfig,
) -> Result<ftd_core_firestore::text_index::TextIndexSet, String> {
    let mut set = ftd_core_firestore::text_index::TextIndexSet::default();
    let Some(path) = &cfg.text_index_file else {
        return Ok(set);
    };
    if cfg.edition != ftd_core_types::edition::FirestoreEdition::Enterprise {
        return Err(format!(
            "{path}: text indexes need firestore.edition = enterprise"
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let json: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    if json.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err(format!("{path}: schemaVersion 1 is required"));
    }
    let entries = json
        .get("indexes")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{path}: indexes must be an array"))?;
    for (i, e) in entries.iter().enumerate() {
        let def = ftd_adapter_http::control::parse_text_index(e)
            .map_err(|m| format!("{path}: indexes[{i}]: {m}"))?;
        let id = def.id.clone();
        let warnings = set
            .add(def)
            .map_err(|e| format!("{path}: indexes[{i}]: {e}"))?;
        for w in warnings {
            eprintln!("[firestore] text index {id}: {w}");
        }
    }
    Ok(set)
}

/// Loads `firestore.indexes.json` (composite indexes and single-field exemptions).
pub fn load_indexes(path: &str) -> Result<IndexSet, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let json: Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let mut set = IndexSet::default();
    for idx in json
        .get("indexes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let collection = idx
            .get("collectionGroup")
            .and_then(Value::as_str)
            .ok_or("index without collectionGroup")?;
        let scope = match idx
            .get("queryScope")
            .and_then(Value::as_str)
            .unwrap_or("COLLECTION")
        {
            "COLLECTION" => IndexQueryScope::Collection,
            "COLLECTION_GROUP" => IndexQueryScope::CollectionGroup,
            other => return Err(format!("unsupported queryScope {other}")),
        };
        let mut fields = Vec::new();
        for f in idx
            .get("fields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let path = f
                .get("fieldPath")
                .and_then(Value::as_str)
                .ok_or("index field without fieldPath")?;
            let mode = match (
                f.get("order").and_then(Value::as_str),
                f.get("arrayConfig").and_then(Value::as_str),
            ) {
                (Some("ASCENDING"), _) => IndexFieldMode::Ascending,
                (Some("DESCENDING"), _) => IndexFieldMode::Descending,
                (_, Some("CONTAINS")) => IndexFieldMode::Contains,
                _ => return Err(format!("index field {path}: order or arrayConfig required")),
            };
            fields.push(IndexField {
                path: FieldPath::parse(path).map_err(|e| e.to_string())?,
                mode,
            });
        }
        set.add_composite(IndexDefinition {
            collection_group: CollectionId::try_new(collection).map_err(|e| e.to_string())?,
            query_scope: scope,
            fields,
        });
    }
    for ov in json
        .get("fieldOverrides")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let collection = ov
            .get("collectionGroup")
            .and_then(Value::as_str)
            .ok_or("fieldOverride without collectionGroup")?;
        let path = ov
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or("fieldOverride without fieldPath")?;
        let disabled = ov
            .get("indexes")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        if disabled {
            for scope in [
                IndexQueryScope::Collection,
                IndexQueryScope::CollectionGroup,
            ] {
                set.add_exemption(&ftd_core_firestore::index::SingleFieldExemption {
                    collection_group: CollectionId::try_new(collection)
                        .map_err(|e| e.to_string())?,
                    field: FieldPath::parse(path).map_err(|e| e.to_string())?,
                    query_scope: scope,
                });
            }
        }
    }
    Ok(set)
}

/// Capability manifest (`GET /v1/capabilities`, spec 4).
#[must_use]
pub fn capabilities_manifest() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": {
            "CTL-1": {"status": "partial", "implemented": ["clock:set", "clock:advance", "clock:advanceTo", "sessions/{s}/reset (exclusive across Firestore, Auth, Storage and functions)", "sessions/{s}/snapshots (POST {name} captures Firestore, Storage, Auth, the clock and both rulesets; GET lists; {name}:restore restores atomically under the reset barrier and resets the functions runtime; DELETE)", "sessions/{s}/faultPlan (PUT the spec 18.2 plan, GET plan + fired history + counters, DELETE)", "sessions/{s}/functions and functions/{name}:run", "sessions/{s}/pubsub/topics/{t}:publish", "sessions/{s}:awaitIdle", "rules load/replace/drop", "health", "capabilities", "limits"], "unimplemented": ["multiple sessions (one session, `default`, per daemon; the name is accepted and echoed)", "snapshot files on disk (snapshots live in memory for the daemon's lifetime)"], "notes": ["fault operations: firestore.commit / read / beginTransaction, storage.upload / read / delete / list, functions.deliver (duplicate), functions.invoke (returnError, timeout, deadLetter, delay, crashRunner); rules match the nth occurrence per operation, or per operation and function when a function is named"]},
            "FS-GW-1": {"status": "implemented", "precision": "conservative", "notes": ["firestore.indexValidationPolicy = emulator serves queries whose composite index is not configured (FS_EMULATOR_INDEX_ASSUMED warning), like the Firebase Emulator Suite; firebase / conservative keep rejecting them with FAILED_PRECONDITION"]},
            "FS-LIM-1": {"status": "partial", "implemented": ["FS-LIMIT-DOCUMENT-BYTES", "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH", "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT", "FS-LIMIT-COLLECTION-ID", "FS-LIMIT-DOCUMENT-ID", "FS-LIMIT-TRANSACTION-TOTAL-TIME", "FS-LIMIT-TRANSACTION-IDLE-TIME"]},
            "FS-RPC-1": {"status": "implemented", "implemented": ["GetDocument", "ListDocuments", "CreateDocument", "UpdateDocument", "DeleteDocument", "BatchGetDocuments", "BeginTransaction", "Commit", "Rollback", "RunQuery", "RunAggregationQuery", "ListCollectionIds", "BatchWrite", "Write", "Listen", "verify writes", "read_time snapshots (microsecond precision, within the past hour)", "read-only transactions at a read_time", "ListDocuments inside transactions"], "unimplemented": ["ExecutePipeline"]},
            "FS-REST-1": {"status": "implemented", "notes": ["served on the Firestore port next to gRPC", "readTime selectors and findNearest are refused explicitly"]},
            "FS-WEB-1": {"status": "implemented", "notes": ["WebChannel v8 transport of the browser web SDK (Listen / Write) on the Firestore port; resume as in FS-LSN-1"]},
            "FS-QRY-1": {"status": "implemented", "notes": ["orderBy on missing fields excludes documents", "range filters are type-restricted"]},
            "FS-TXN-1": {"status": "implemented", "precision": "boundary-conformance", "notes": ["serializable: read sets and executed queries are re-validated at commit"]},
            "FS-LSN-1": {"status": "implemented", "implemented": ["query and document targets", "live diffs after every commit", "once", "resume from a resume token or read time: the state at that version is recomputed from the MVCC history and only the changes since are replayed, followed by an ExistenceFilter with the current count (an undecodable or future token RESETs)", "back-pressure: bounded response channel, commits coalesced into one refresh while the client is slow, 1000 targets per stream (RESOURCE_EXHAUSTED beyond)"], "notes": ["existence filters carry the count only (no bloom filter): the replay is exact, so the client never has to guess"]},
            "FS-PIPE-RPC-1": {"status": "implemented", "precision": "strict-validation-only", "implemented": ["ExecutePipeline / StructuredPipeline decode", "stage identification against the documented registry (collection, collection_group, database, documents, select, add_fields, remove_fields, where, sort, limit, offset, distinct, aggregate, find_nearest, sample, union, unnest, replace_with)", "input stage placement and arity checks", "write stages (update, delete) refused as FS-PIPE-WRITE-0", "unknown stages refused (FS_PIPE_UNSUPPORTED_STAGE), never skipped"], "unimplemented": ["local execution (a valid pipeline is answered with UNIMPLEMENTED FS_PIPE_VALIDATION_ONLY carrying its canonical form)", "proxy / record-only modes"], "notes": ["Standard edition answers FAILED_PRECONDITION FS_PIPE_EDITION", "owner-only while rules are enforced"]},
            "FS-TEXT-VAL-1": {"status": "implemented", "precision": "strict-validation-only", "implemented": ["firestore.textIndexDefinitionFile (schemaVersion 1, Admin API Index subset + xFirebaseTestd) validated at start", "control API: POST firestore/text-indexes:load, POST / GET firestore/text-indexes, GET / DELETE firestore/text-indexes/{id}", "duplicate IDs refused, duplicate shapes warned (FS_TEXT_DUPLICATE_INDEX_DEFINITION), unresolved language override warned, unsupported options refused"], "unimplemented": ["backfill lifecycle (advanceBackfill, completeBackfill, failBuild, repair answer UNIMPLEMENTED without changing state; FS-TEXT-IDX-1)", "posting data and local search (Milestone G)"], "notes": ["Enterprise edition only"]},
            "AUTH-CORE-1": {"status": "implemented", "implemented": ["accounts:signUp (email, anonymous)", "accounts:signInWithPassword", "accounts:signInWithCustomToken", "accounts:lookup", "accounts:update", "accounts:sendOobCode / resetPassword / signInWithEmailLink (PASSWORD_RESET, VERIFY_EMAIL, EMAIL_SIGNIN, VERIFY_AND_CHANGE_EMAIL; applyActionCode through accounts:update)", "accounts:sendVerificationCode / signInWithPhoneNumber", "accounts:createAuthUri", "securetoken token (JSON and form)", "Admin: projects/{p}/accounts create/lookup/update/delete/batchGet, mfaInfo / mfa.enrollments (phone), linkProviderUserInfo / deleteProvider", "Emulator routes: /emulator/v1/projects/{p}/oobCodes, verificationCodes, accounts (DELETE), config"], "notes": ["nothing is mailed or texted: codes are read from the emulator routes and are deterministic from the session seed", "reCAPTCHA tokens are accepted unchecked"]},
            "AUTH-TOKEN-1": {"status": "implemented", "implemented": ["unsigned-emulator (alg none, the Firebase Auth Emulator format)", "session-rsa (RS256 with a 2048-bit key derived from the session seed; JWKS at /.well-known/jwks.json and the securetoken@system.gserviceaccount.com path)"], "notes": ["with session-rsa every surface (Identity Toolkit, Firestore rules, Storage rules) refuses unsigned or foreign-signed tokens", "the Firebase Admin SDK accepts only alg none while FIREBASE_AUTH_EMULATOR_HOST is set, so verifyIdToken through the Admin SDK needs unsigned-emulator"]},
            "AUTH-MFA-TOTP-1": {"status": "implemented", "precision": "boundary-conformance", "notes": ["window and enrollment TTL are local policies"]},
            "AUTH-RULES-1": {"status": "implemented", "notes": ["request.auth from verified ID tokens on every Firestore surface; Bearer owner bypasses"]},
            "AUTH-MFA-SMS-0": {"status": "implemented", "precision": "emulator-parity", "notes": ["phone second factors: mfaEnrollment:start/finalize/withdraw with phoneEnrollmentInfo / phoneVerificationInfo, mfaSignIn:start/finalize with phoneSignInInfo; codes come from /emulator/v1/projects/{p}/verificationCodes; up to five factors per user", "the spec declared SMS out of scope; the user asked for Identity Platform parity"]},
            "AUTH-OAUTH-0": {"status": "implemented", "precision": "fixture-idp", "notes": ["accounts:signInWithIdp trusts the id_token of postBody (a JWT payload or a bare JSON object with sub / email / name / picture) as the provider's assertion, like the Emulator; no OAuth round trip", "an identity whose email belongs to an existing user is linked to it; otherwise a new user is created with a verified email", "ID tokens carry firebase.identities[providerId] and sign_in_provider = providerId"]},
            "RULES-LINT-1": {"status": "implemented"},
            "RULES-BUDGET-1": {"status": "implemented", "implemented": ["RULES-EXPRESSIONS-PER-REQUEST 1000", "RULES-FUNCTION-CALL-DEPTH 20", "RULES-DOC-ACCESS-SINGLE 10 per operation and per query proof (get, exists and getAfter of one path each count once)", "RULES-DOC-ACCESS-MULTI-TOTAL 20 across atomic commits and BatchGetDocuments"]},
            "RULES-1": {"status": "implemented", "precision": "conservative", "implemented": ["get / create / update / delete against the returned snapshot or the staged commit", "list / aggregation / Listen queries proven from equality, in, !=, not-in, array-contains(-any) and inequality (range) constraints plus request.query.limit / offset / orderBy (RULES-QUERY-CONSTRAINTS)", "get() / exists() / getAfter() (getAfter over the state the whole commit leaves behind; fails closed on reads and query proofs)", "timestamp / duration / latlng / math / hashing namespaces, map.diff(), bytes and string conversions", "collection groups need a recursive wildcard rule"], "notes": ["query proofs are sound, not complete: a rule that reads an unconstrained field denies the query", "request.query.orderBy is rendered as \"field ASC, other DESC\" (the Emulator's form; production's rendering is undocumented)", "string.matches()/replace(): RE2-style subset without lookarounds, flags or word boundaries"]},
            "ST-OBJ-1": {"status": "implemented", "implemented": ["Firebase Storage protocol (/v0/b, X-Goog-Upload resumable, download tokens)", "JSON API (/storage/v1, /upload/storage/v1, /download/storage/v1, emulator-style /b paths, Content-Range resumable, rewriteTo)", "generation / metageneration preconditions (match / not-match / source)", "generation selectors (current generation only)", "prefix / delimiter listing", "MD5 / CRC32C (X-Goog-Hash verified before commit)", "Range: bytes=a-b / a- / -n"], "unimplemented": ["object versioning / archived generations", "ACLs and signed URLs", "compose", "notifications", "Storage triggers (FN-EVT-1)"]},
            "FN-HTTP-1": {"status": "implemented", "implemented": ["onRequest / onCall (v2) and v1 HTTPS functions proxied to the runner at /{project}/{region}/{function}"], "notes": ["needs functions.source (or --functions <dir>) and the bundled Node runner; the codebase must have express installed (a dependency of firebase-functions)"]},
            "FN-EVT-1": {"status": "implemented", "implemented": ["Firestore document created / updated / deleted / written triggers (v2, JSON CloudEvents; v1 document handlers)", "Firestore *.withAuthContext variants: authtype / authid of the committing principal (app_user, service_account, unauthenticated, system)", "Storage object finalized / deleted / metadataUpdated triggers (v2 and v1)", "Pub/Sub topic triggers (v2 onMessagePublished, v1 topic().onPublish) fed by POST /v1/sessions/{s}/pubsub/topics/{t}:publish or /v1/projects/{p}/topics/{t}:publish", "Auth user created / deleted events to v1 auth.user() handlers", "retries with virtual-time backoff, dead letters, await-idle"], "unimplemented": ["blocking identity functions (beforeUserCreated / beforeUserSignedIn)", "Realtime Database and Remote Config triggers (no such service in the daemon)", "protobuf CloudEvents payloads (JSON is what firebase-functions consumes)"]},
            "FN-SCH-1": {"status": "implemented", "implemented": ["onSchedule with cron and App Engine schedules driven by the virtual clock (scheduler.catchUp = all | latest | none; all is capped per advance with the remainder kept due)", "manual runs via POST /v1/sessions/{s}/functions/{name}:run", "IANA time zones with daylight-saving rules (chrono-tz; gaps skipped, ambiguous times run once)", "scheduler.overlap = allow | skip | queue | reject"]},
            "CTL-1-AWAIT-IDLE": {"status": "partial", "implemented": ["POST /v1/sessions/{s}:awaitIdle waits for pending / running / retry-waiting events, HTTP invocations and due schedule runs beyond the catch-up cap; events are enqueued inside the commit that produces them"], "unimplemented": ["causal fences across sessions", "Text Index work"], "notes": ["reset holds the session admission barrier exclusively across Firestore, Auth, Storage and the functions runtime; the runner is killed and restarted so handlers still running cannot write into the new session"]},
            "STORAGE-RULES-1": {"status": "implemented", "implemented": ["service firebase.storage: get / list / create / update / delete with request.resource and resource", "resumable uploads are authorized at finalization with the received bytes", "list requires rules_version 2", "Firebase protocol goes through the rules; the JSON API is a privileged surface unless an end-user token is presented", "firestore.get() / firestore.exists() over the latest Firestore state of the project (STORAGE-RULES-FIRESTORE-ACCESS: two per request)"], "notes": ["a JSON API rewrite with an end-user token evaluates the source read and the destination write as two requests, each with its own two-call budget"]},
        }
    })
}
