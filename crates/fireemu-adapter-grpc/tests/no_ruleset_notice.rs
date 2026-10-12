//! The first refusal of a client request to a database without a ruleset is reported once per
//! database, while the client keeps receiving production's denial bytes.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::rules::{NoticeEvent, NoticeLimit, Principal, RulesEnforcer};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_rules::eval::NoDocumentAccess;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

const DATABASES: [&str; 3] = ["(default)", "staging", "archive"];
const SUPPRESSED: &str = "<suppressed>";

fn enforcer(refuse: bool, rules: Option<&str>, notices: &Arc<Mutex<Vec<String>>>) -> RulesEnforcer {
    let slot = Arc::new(rules.map_or_else(RulesetSlot::default, |source| {
        RulesetSlot::new(LoadedRules::from_source(source).unwrap())
    }));
    let auth = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(7),
        TotpPolicy::default(),
    )));
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let sink = notices.clone();
    RulesEnforcer::new(slot, auth, clock)
        .with_refusal_without_ruleset(refuse)
        .with_no_ruleset_notice(Arc::new(move |event| {
            sink.lock().unwrap().push(match event {
                NoticeEvent::First(database) => database.to_owned(),
                NoticeEvent::Suppressed => SUPPRESSED.to_owned(),
            });
        }))
}

fn path(database: &str) -> DocumentPath {
    let database = if database == "(default)" {
        DatabaseId::default_database()
    } else {
        DatabaseId::try_new(database).unwrap()
    };
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &database,
        "notes/n1",
    )
    .unwrap()
}

#[test]
fn a_refusal_without_a_ruleset_is_reported_once_per_database() {
    let notices = Arc::new(Mutex::new(Vec::new()));
    let enforcer = enforcer(true, None, &notices);
    for database in ["(default)", "(default)", "staging", "(default)", "staging"] {
        let status = enforcer
            .authorize_get(
                &Principal::Anonymous,
                &path(database),
                None,
                &NoDocumentAccess,
            )
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert_eq!(status.message(), "Missing or insufficient permissions.");
    }
    assert_eq!(*notices.lock().unwrap(), ["(default)", "staging"]);
}

#[test]
fn nothing_is_reported_when_nothing_is_refused() {
    let notices = Arc::new(Mutex::new(Vec::new()));
    // The emulator profile allows every request without a ruleset.
    let open = enforcer(false, None, &notices);
    assert!(open
        .authorize_get(
            &Principal::Anonymous,
            &path("(default)"),
            None,
            &NoDocumentAccess
        )
        .is_ok());
    // The owner is never judged by Security Rules.
    let strict = enforcer(true, None, &notices);
    assert!(strict
        .authorize_get(
            &Principal::Owner,
            &path("(default)"),
            None,
            &NoDocumentAccess
        )
        .is_ok());
    // A denial by loaded rules is not a missing ruleset.
    let deny = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
    let ruled = enforcer(true, Some(deny), &notices);
    assert!(ruled
        .authorize_get(
            &Principal::Anonymous,
            &path("(default)"),
            None,
            &NoDocumentAccess
        )
        .is_err());
    assert!(notices.lock().unwrap().is_empty());
}

proptest! {
    /// Against a reference model: the notices are the distinct databases of the refused
    /// requests, in the order of their first refusal.
    #[test]
    fn notices_match_the_reference_model(
        refuse in any::<bool>(),
        requests in proptest::collection::vec((0..DATABASES.len(), any::<bool>()), 0..24),
    ) {
        let notices = Arc::new(Mutex::new(Vec::new()));
        let enforcer = enforcer(refuse, None, &notices);
        let mut expected: Vec<String> = Vec::new();
        for (database, owner) in requests {
            let database = DATABASES[database];
            let principal = if owner { Principal::Owner } else { Principal::Anonymous };
            let answer =
                enforcer.authorize_get(&principal, &path(database), None, &NoDocumentAccess);
            let refused = refuse && !owner;
            prop_assert_eq!(answer.is_err(), refused);
            if refused && !expected.iter().any(|d| d == database) {
                expected.push(database.to_owned());
            }
        }
        prop_assert_eq!(&*notices.lock().unwrap(), &expected);
    }
}

/// Database IDs reach the enforcer from requests (a strict run with implicit database creation
/// admits new ones), so the reported set is bounded: the limit, then one suppression notice.
#[test]
fn reports_stop_after_the_limit_with_one_suppression_notice() {
    let notices = Arc::new(Mutex::new(Vec::new()));
    let enforcer = enforcer(true, None, &notices);
    for round in 0..2 {
        for i in 0..(NoticeLimit::LIMIT + 10) {
            let status = enforcer
                .authorize_get(
                    &Principal::Anonymous,
                    &path(&format!("db{i}")),
                    None,
                    &NoDocumentAccess,
                )
                .unwrap_err();
            assert_eq!(
                status.message(),
                "Missing or insufficient permissions.",
                "round {round}"
            );
        }
    }
    let notices = notices.lock().unwrap();
    assert_eq!(notices.len(), NoticeLimit::LIMIT + 1);
    assert_eq!(notices[NoticeLimit::LIMIT], SUPPRESSED);
    assert_eq!(notices[0], "db0");
}
