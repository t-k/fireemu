use std::sync::{Arc, Mutex};

use fireemu_core_auth::{mfa::TotpPolicy, store::AuthStore};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::store::FirestoreState;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use tonic::Code;

use super::{Caller, RestState};
use crate::gateway::Gateway;
use crate::local::LocalBackend;
use crate::rules::{Principal, ReadCheck};

const PICT_ROWS: &str = include_str!("unary_guards.tsv");

fn state() -> RestState {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let local = Arc::new(LocalBackend::new(
        gateway.clone(),
        Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH))),
        7,
    ));
    RestState {
        local,
        gateway: Arc::new(gateway),
        rules: None,
        control_token: None,
        app_check: None,
    }
}

#[test]
fn pict_guard_rows_preserve_local_guards_and_upstream_fallback() {
    let mut rows = PICT_ROWS.lines();
    assert_eq!(rows.next(), Some("Operation\tBackend\tEpoch\tPrincipal"));
    for row in rows {
        let [operation, backend, epoch_kind, principal_kind]: [&str; 4] = row
            .split('\t')
            .collect::<Vec<_>>()
            .try_into()
            .expect("four PICT dimensions");
        let rest = state();
        let start_epoch = rest.local.barrier().epoch();
        if epoch_kind == "stale" {
            drop(rest.local.barrier().exclusive());
        }
        let caller = Caller {
            principal: match principal_kind {
                "owner" => Principal::Owner,
                "anonymous" => Principal::Anonymous,
                other => panic!("unexpected principal {other}"),
            },
            epoch: start_epoch,
        };
        let local = (backend == "local").then(|| rest.local.clone());
        let expected_refusal = backend == "local" && epoch_kind == "stale";
        let db = FirestoreState::new();
        let result = match (operation, backend) {
            ("read", "local") => (rest.read_guard(&caller))(&db, None, ReadCheck::Documents(&[])),
            ("write", "local") => (rest.write_guard(&caller))(&db, &[], LogicalInstant::UNIX_EPOCH),
            ("read", "upstream") => (crate::rules::unary_read_guard(
                None,
                &caller.principal,
                local,
                caller.epoch,
            ))(&db, None, ReadCheck::Documents(&[])),
            ("write", "upstream") => (crate::rules::unary_write_guard(
                None,
                &caller.principal,
                local,
                caller.epoch,
            ))(&db, &[], LogicalInstant::UNIX_EPOCH),
            _ => panic!("unexpected PICT row: {row}"),
        };
        assert_eq!(
            result.as_ref().err().map(tonic::Status::code),
            expected_refusal.then_some(Code::Unavailable),
            "{row}"
        );
    }
}

#[test]
fn local_write_commit_publishes_the_owner_actor() {
    let state = state();
    let actor = Arc::new(Mutex::new(None));
    let observed = actor.clone();
    state.local.set_change_sink(Arc::new(move |event| {
        *observed.lock().unwrap() = Some(event.actor.clone());
    }));
    let response = state.handle(&super::RestRequest {
        method: "POST".to_owned(),
        path: "/v1/projects/demo-app/databases/(default)/documents:commit".to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body: serde_json::json!({
            "writes": [{"update": {"name": "projects/demo-app/databases/(default)/documents/actors/owner"}}]
        }),
        batch_field_order: Vec::new(),
        key_order: crate::rest::json_syntax::KeyOrder::default(),
    });
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(
        *actor.lock().unwrap(),
        Some(crate::local::Actor {
            auth_type: "service_account".to_owned(),
            auth_id: Some("owner".to_owned()),
        })
    );
}

#[test]
fn local_and_upstream_guards_still_run_rules_after_epoch_admission() {
    let state = state();
    let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::UNIX_EPOCH)));
    let rules = Arc::new(crate::rules::RulesEnforcer::new(
        Arc::new(RulesetSlot::new(
            LoadedRules::from_source(
                "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if false; } } }",
            )
            .unwrap(),
        )),
        Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(3),
            TotpPolicy::default(),
        ))),
        clock,
    ));
    let principal = Principal::Anonymous;
    let db = FirestoreState::new();
    let path = fireemu_core_firestore::path::DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        "guard/read",
    )
    .unwrap();
    let local_read = crate::rules::unary_read_guard(
        Some(&rules),
        &principal,
        Some(state.local.clone()),
        state.local.barrier().epoch(),
    );
    assert_eq!(
        local_read(
            &db,
            None,
            ReadCheck::Document {
                path: &path,
                snapshot: None,
            },
        )
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
    let upstream_read = crate::rules::unary_read_guard(Some(&rules), &principal, None, 0);
    assert_eq!(
        upstream_read(
            &db,
            None,
            ReadCheck::Document {
                path: &path,
                snapshot: None,
            },
        )
        .unwrap_err()
        .code(),
        Code::PermissionDenied
    );
}
