//! A named database that nothing declared in `firebase.json` (one created at run time) has no
//! Security Rules until some are set for it, and under `strict` its client requests are refused
//! as production refuses them: a database is governed only by its own `cloud.firestore` release,
//! never by the `(default)` database's (`conformance/fs-rules-production.json`, program
//! `fs-rules/named-database/releases`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::decode::Parent;
use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rules::{LatestReader, Principal, RulesEnforcer, RulesLoadError};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const OPEN: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }";
const CLOSED: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if false; } } }";

struct World {
    enforcer: RulesEnforcer,
    reader: LatestReader,
    project: ProjectId,
}

fn world(refuse_without_ruleset: bool, declared: &[(&str, &str)]) -> World {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway, clock.clone(), 7));
    let auth = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let slots = declared
        .iter()
        .map(|(database, source)| {
            (
                (*database).to_owned(),
                Arc::new(RulesetSlot::new(LoadedRules::from_source(source).unwrap())),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let enforcer = RulesEnforcer::new(
        Arc::new(RulesetSlot::new(LoadedRules::from_source(OPEN).unwrap())),
        auth,
        clock,
    )
    .with_database_rules(slots)
    .with_refusal_without_ruleset(refuse_without_ruleset);
    let project = ProjectId::try_new("demo-app").unwrap();
    let reader = LatestReader {
        backend,
        parent: Parent {
            project: project.clone(),
            database: DatabaseId::default_database(),
            document: None,
        },
    };
    World {
        enforcer,
        reader,
        project,
    }
}

impl World {
    fn anonymous_get(&self, database: &str) -> bool {
        let database = DatabaseId::try_new(database).unwrap();
        let path = DocumentPath::parse(&self.project, &database, "items/a").unwrap();
        self.enforcer
            .authorize_get(&Principal::Anonymous, &path, None, &self.reader)
            .is_ok()
    }

    fn owner_get(&self, database: &str) -> bool {
        let database = DatabaseId::try_new(database).unwrap();
        let path = DocumentPath::parse(&self.project, &database, "items/a").unwrap();
        self.enforcer
            .authorize_get(&Principal::Owner, &path, None, &self.reader)
            .is_ok()
    }
}

#[test]
fn strict_refuses_a_database_that_has_no_rules_of_its_own() {
    let world = world(true, &[]);
    assert!(world.anonymous_get("(default)"));
    assert!(
        !world.anonymous_get("other"),
        "the (default) rules do not govern another database"
    );
    assert!(
        world.owner_get("other"),
        "the owner credential is not governed by rules"
    );
}

#[test]
fn a_database_declared_with_its_own_rules_keeps_them() {
    let world = world(true, &[("staging", CLOSED), ("open-db", OPEN)]);
    assert!(!world.anonymous_get("staging"));
    assert!(world.anonymous_get("open-db"));
    assert!(world.anonymous_get("(default)"));
}

#[test]
fn the_emulator_profile_keeps_the_default_rules_for_every_database() {
    let world = world(false, &[]);
    assert!(world.anonymous_get("other"));
}

#[test]
fn rules_set_for_a_database_apply_to_it_alone() {
    let world = world(true, &[]);
    world
        .enforcer
        .replace_database_source("other", OPEN)
        .unwrap();
    assert!(world.anonymous_get("other"));
    assert!(
        !world.anonymous_get("third"),
        "another database still has none"
    );
    world
        .enforcer
        .replace_database_source("other", CLOSED)
        .unwrap();
    assert!(!world.anonymous_get("other"));
    assert!(world.anonymous_get("(default)"), "(default) is untouched");
}

#[test]
fn rules_set_for_a_declared_database_replace_its_own() {
    let world = world(true, &[("staging", CLOSED)]);
    world
        .enforcer
        .replace_database_source("staging", OPEN)
        .unwrap();
    assert!(world.anonymous_get("staging"));
}

#[test]
fn rules_set_for_the_default_database_replace_the_default_rules() {
    let world = world(true, &[]);
    world
        .enforcer
        .replace_database_source("(default)", CLOSED)
        .unwrap();
    assert!(!world.anonymous_get("(default)"));
}

#[test]
fn a_source_that_does_not_compile_leaves_the_previous_rules_in_force() {
    let world = world(true, &[]);
    world
        .enforcer
        .replace_database_source("other", OPEN)
        .unwrap();
    let error = world
        .enforcer
        .replace_database_source("other", "service cloud.firestore {")
        .unwrap_err();
    assert!(matches!(error, RulesLoadError::Compile(_)));
    assert!(world.anonymous_get("other"));
    // A failed first load does not give the database rules either.
    let error = world
        .enforcer
        .replace_database_source("fresh", "not rules")
        .unwrap_err();
    assert!(matches!(error, RulesLoadError::Compile(_)));
    assert!(!world.anonymous_get("fresh"));
}

#[test]
fn a_deleted_database_gives_up_the_rules_set_for_it() {
    let world = world(true, &[]);
    world
        .enforcer
        .replace_database_source("other", OPEN)
        .unwrap();
    world.enforcer.forget_database_rules("other");
    assert!(!world.anonymous_get("other"));
    // Forgetting never touches the default rules or a declared database.
    world.enforcer.forget_database_rules("(default)");
    assert!(world.anonymous_get("(default)"));
}
