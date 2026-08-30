//! The one transport-neutral admission decision (specification sections 7.4, 12.1 and 12.2).
//!
//! Every adapter asks exactly this function, so the enforcement matrix of section 19 is
//! checked once here over the Cartesian product of mode and credential state, and the
//! per-transport tests then only prove that each adapter reaches this decision and renders it.

mod support;

use std::sync::{Arc, RwLock};

use ftd_core_app_check::admission::{
    AdmissionRequest, AppCheckGate, PrivilegedBypass, ServiceAdmission,
};
use ftd_core_app_check::header::HeaderClassification;
use ftd_core_app_check::limits::{
    MAX_OBSERVED_PROJECTS, MAX_OBSERVED_PROJECT_ID_BYTES, MAX_RETAINED_OBSERVATIONS_PER_PROJECT,
};
use ftd_core_app_check::observe::CredentialCategory;
use ftd_core_app_check::registry::AppCheckRegistry;
use ftd_core_app_check::verify::{AppCheckFailure, BaselineMode};
use ftd_core_types::time::LogicalInstant;

use support::{fixture_registry, seeded_epoch, TestSigner, DEMO_APP_ID};

const NOW: LogicalInstant = LogicalInstant::from_unix_seconds(1_700_000_000);

fn gate(registry: AppCheckRegistry) -> AppCheckGate {
    AppCheckGate::new(
        Arc::new(RwLock::new(registry)),
        Arc::new(TestSigner::new(7)),
    )
}

fn valid_token(gate: &AppCheckGate) -> String {
    let registry = gate.registry().read().expect("the registry is readable");
    let claims = registry
        .issue_claims("demo-app", DEMO_APP_ID, NOW)
        .expect("the fixture app may exchange");
    ftd_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
}

/// A request against the fixture's second project, which shares the registry with the first.
fn other_project_request(operation: &str) -> AdmissionRequest<'_> {
    AdmissionRequest {
        project_id: "demo-other",
        transport: "http",
        operation,
        bypass: PrivilegedBypass::None,
        header: &HeaderClassification::Missing,
        now: NOW,
    }
}

fn request(header: &HeaderClassification, bypass: PrivilegedBypass) -> AdmissionRequest<'_> {
    AdmissionRequest {
        project_id: "demo-app",
        transport: "grpc",
        operation: "Commit",
        bypass,
        header,
        now: NOW,
    }
}

/// `off` is not a policy the runtime evaluates: no service admission exists at all, so no
/// header is ever parsed (specification section 12.1).
#[test]
fn an_off_service_has_no_admission_to_evaluate() {
    let gate = gate(fixture_registry());
    assert!(ServiceAdmission::new(gate, "firestore", BaselineMode::Off).is_none());
}

#[test]
fn enforced_admits_a_valid_token_and_exposes_the_app_identity() {
    let gate = gate(fixture_registry());
    let token = valid_token(&gate);
    let policy = ServiceAdmission::new(gate, "firestore", BaselineMode::Enforced)
        .expect("a non-off mode has an admission");
    let header = HeaderClassification::Present(token);
    let decision = policy.admit(&request(&header, PrivilegedBypass::None));
    assert!(decision.allowed);
    assert_eq!(
        decision.identity().map(|i| i.app_id.as_str()),
        Some(DEMO_APP_ID)
    );
    assert_eq!(decision.reason, None);
}

#[test]
fn enforced_denies_a_missing_token_with_the_required_code() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate, "firestore", BaselineMode::Enforced).expect("mode");
    let decision = policy.admit(&request(
        &HeaderClassification::Missing,
        PrivilegedBypass::None,
    ));
    assert!(!decision.allowed);
    assert_eq!(
        decision.reason,
        Some(ftd_core_app_check::verify::PUBLIC_REQUIRED_REASON)
    );
}

#[test]
fn enforced_denies_every_invalid_credential_with_one_public_code() {
    let gate = gate(fixture_registry());
    let valid = valid_token(&gate);
    let other_project = {
        let registry = gate.registry().read().expect("readable");
        let claims = registry
            .issue_claims("demo-other", support::OTHER_APP_ID, NOW)
            .expect("the second fixture app may exchange");
        ftd_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
    };
    let mut forged = valid.clone();
    forged.pop();
    forged.push(if valid.ends_with('A') { 'B' } else { 'A' });

    let policy = ServiceAdmission::new(gate, "firestore", BaselineMode::Enforced).expect("mode");
    let cases = [
        HeaderClassification::Malformed,
        HeaderClassification::Present("not-a-jwt".to_owned()),
        HeaderClassification::Present(forged),
        HeaderClassification::Present(other_project),
    ];
    for header in &cases {
        let decision = policy.admit(&request(header, PrivilegedBypass::None));
        assert!(!decision.allowed, "{header:?} must not be admitted");
        assert_eq!(
            decision.reason,
            Some(ftd_core_app_check::verify::PUBLIC_DENIAL_REASON),
            "{header:?} collapses to one public code"
        );
    }
}

#[test]
fn unenforced_admits_an_invalid_token_without_creating_an_app_identity() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate, "firestore", BaselineMode::Unenforced).expect("mode");
    for header in [
        HeaderClassification::Missing,
        HeaderClassification::Malformed,
        HeaderClassification::Present("not-a-jwt".to_owned()),
    ] {
        let decision = policy.admit(&request(&header, PrivilegedBypass::None));
        assert!(decision.allowed);
        assert!(decision.identity().is_none());
    }
}

#[test]
fn unenforced_still_exposes_the_identity_of_a_valid_token() {
    let gate = gate(fixture_registry());
    let token = valid_token(&gate);
    let policy = ServiceAdmission::new(gate, "firestore", BaselineMode::Unenforced).expect("mode");
    let header = HeaderClassification::Present(token);
    let decision = policy.admit(&request(&header, PrivilegedBypass::None));
    assert!(decision.allowed);
    assert_eq!(
        decision.identity().map(|i| i.app_id.as_str()),
        Some(DEMO_APP_ID)
    );
}

/// A bypass is an explicit route classification, never a header: an enforced request with no
/// token at all is admitted, and the presented value is not even parsed.
#[test]
fn an_explicit_privileged_bypass_is_admitted_without_parsing_the_header() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate, "firestore", BaselineMode::Enforced).expect("mode");
    let header = HeaderClassification::Present("garbage".to_owned());
    let decision = policy.admit(&request(&header, PrivilegedBypass::FirestoreOwner));
    assert!(decision.allowed);
    assert!(decision.identity().is_none());
    let observed = policy
        .gate()
        .registry()
        .read()
        .expect("readable")
        .observations("demo-app");
    assert_eq!(
        observed.last().map(|o| o.category),
        Some(CredentialCategory::Bypass)
    );
}

#[test]
fn every_classified_request_records_one_secret_free_observation() {
    let gate = gate(fixture_registry());
    let token = valid_token(&gate);
    let policy =
        ServiceAdmission::new(gate.clone(), "storage", BaselineMode::Unenforced).expect("mode");
    let _ = policy.admit(&AdmissionRequest {
        project_id: "demo-app",
        transport: "http",
        operation: "upload",
        bypass: PrivilegedBypass::None,
        header: &HeaderClassification::Present(token.clone()),
        now: NOW,
    });
    let _ = policy.admit(&AdmissionRequest {
        project_id: "demo-app",
        transport: "http",
        operation: "delete",
        bypass: PrivilegedBypass::None,
        header: &HeaderClassification::Malformed,
        now: NOW,
    });
    let observed = gate
        .registry()
        .read()
        .expect("readable")
        .observations("demo-app");
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0].service, "storage");
    assert_eq!(observed[0].category, CredentialCategory::Valid);
    assert_eq!(observed[0].app_id, DEMO_APP_ID);
    assert!(observed[0].admitted);
    assert_eq!(observed[1].category, CredentialCategory::Invalid);
    assert_eq!(observed[1].app_id, "unknown");
    assert_eq!(
        observed[1].privileged_reason(),
        Some(AppCheckFailure::Malformed.code())
    );
    let rendered = format!("{observed:?}");
    assert!(
        !rendered.contains(&token),
        "an observation never carries the raw token"
    );
}

/// `AC-LIFE-001`: an epoch rotation invalidates every token issued before it, and it touches
/// only the projects the filter accepts.
#[test]
fn rotating_an_epoch_invalidates_the_tokens_of_that_project_only() {
    let gate = gate(fixture_registry());
    let demo = valid_token(&gate);
    let other = {
        let registry = gate.registry().read().expect("readable");
        let claims = registry
            .issue_claims("demo-other", support::OTHER_APP_ID, NOW)
            .expect("issued");
        ftd_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
    };

    let rotated: Vec<(String, _)> = gate
        .projects(|project| project == "demo-app")
        .into_iter()
        .enumerate()
        .map(|(i, project)| (project, seeded_epoch(100 + i as u64)))
        .collect();
    assert_eq!(rotated.len(), 1);
    gate.set_epochs(&rotated);

    let firestore =
        ServiceAdmission::new(gate.clone(), "firestore", BaselineMode::Enforced).expect("mode");
    let denied = firestore.admit(&request(
        &HeaderClassification::Present(demo),
        PrivilegedBypass::None,
    ));
    assert!(!denied.allowed, "a pre-rotation token is refused");

    let other_project = ServiceAdmission::new(gate, "firestore", BaselineMode::Enforced)
        .expect("mode")
        .admit(&AdmissionRequest {
            project_id: "demo-other",
            transport: "grpc",
            operation: "Commit",
            bypass: PrivilegedBypass::None,
            header: &HeaderClassification::Present(other),
            now: NOW,
        });
    assert!(
        other_project.allowed,
        "the untouched project keeps its epoch"
    );
}

#[test]
fn a_rotation_bumps_the_policy_generation_of_the_rotated_project() {
    let gate = gate(fixture_registry());
    let before = gate
        .registry()
        .read()
        .expect("readable")
        .policy_generation("demo-app");
    gate.set_epochs(&[("demo-app".to_owned(), seeded_epoch(9))]);
    let after = gate
        .registry()
        .read()
        .expect("readable")
        .policy_generation("demo-app");
    assert!(after > before);
}

/// Section 12.2: every bypass names the credential the route verified, so the table is
/// enumerable rather than a boolean nobody can audit.
#[test]
fn every_bypass_names_the_privileged_credential_it_required() {
    for bypass in [
        PrivilegedBypass::FirestoreOwner,
        PrivilegedBypass::IdentityToolkitAdmin,
        PrivilegedBypass::StorageJsonApi,
        PrivilegedBypass::StorageDownloadToken,
        PrivilegedBypass::ControlApi,
    ] {
        assert!(bypass.is_privileged());
        assert!(!bypass.reason().is_empty());
    }
    assert!(!PrivilegedBypass::None.is_privileged());
}

/// Section 14: a restore replaces the dynamic debug-token registry rather than merging it, so
/// a registration created after the capture disappears and one deleted after it returns.
#[test]
fn restoring_a_capture_replaces_the_dynamic_debug_tokens_of_that_scope() {
    let mut registry = fixture_registry();
    let kept = registry
        .add_debug_token(
            "demo-app",
            DEMO_APP_ID,
            "before",
            support::digest_of(support::DEMO_SECRET),
            NOW,
        )
        .expect("the fixture app takes a dynamic token");
    let untouched = registry
        .add_debug_token(
            "demo-other",
            support::OTHER_APP_ID,
            "other",
            support::digest_of(support::OTHER_SECRET),
            NOW,
        )
        .expect("the second app takes one too");

    let captured = registry.capture_dynamic_debug_tokens(|project| project == "demo-app");
    assert_eq!(captured.app_count(), 1);
    assert_eq!(captured.token_count(), 1);

    registry
        .delete_debug_token("demo-app", DEMO_APP_ID, &kept.id)
        .expect("the captured token is deleted after the capture");
    let after = registry
        .add_debug_token(
            "demo-app",
            DEMO_APP_ID,
            "after",
            support::digest_of(support::OTHER_SECRET),
            NOW,
        )
        .expect("and a new one is created after it");

    registry.restore_dynamic_debug_tokens(|project| project == "demo-app", &captured);
    let restored = registry
        .list_debug_tokens("demo-app", DEMO_APP_ID)
        .expect("the app still exists");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].id, kept.id, "the deleted registration returns");
    assert!(
        restored.iter().all(|r| r.id != after.id),
        "the post-capture registration disappears"
    );
    assert_eq!(
        registry
            .list_debug_tokens("demo-other", support::OTHER_APP_ID)
            .expect("the untouched app still exists")[0]
            .id,
        untouched.id,
        "another scope keeps what it had"
    );
    assert!(
        !format!("{captured:?}").contains("digest"),
        "a capture never renders its digests"
    );
}

/// Section 14: observation counters reset with the project state they describe, and a reset
/// of one project leaves every other project's ring and counters exactly as they were.
#[test]
fn clearing_observations_touches_only_the_named_scope() {
    let gate = gate(fixture_registry());
    let policy =
        ServiceAdmission::new(gate.clone(), "auth", BaselineMode::Unenforced).expect("mode");
    let _ = policy.admit(&request(
        &HeaderClassification::Missing,
        PrivilegedBypass::None,
    ));
    let _ = policy.admit(&other_project_request("accounts:signUp"));
    gate.registry()
        .read()
        .expect("readable")
        .clear_observations(|project| project == "demo-app");
    let registry = gate.registry().read().expect("readable");
    assert!(
        registry.observations("demo-app").is_empty(),
        "the reset project keeps no observation"
    );
    assert!(
        registry.observation_counters("demo-app").is_empty(),
        "and no counter either: counters reset with the project state"
    );
    let left = registry.observations("demo-other");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].project_id, "demo-other");
    assert_eq!(
        registry
            .observation_counters("demo-other")
            .iter()
            .map(|(_, count)| *count)
            .sum::<u64>(),
        1,
        "the untouched project keeps its counters"
    );
    assert_eq!(
        registry.observed_projects(),
        vec!["demo-other".to_owned()],
        "the reset project's ring is gone, not emptied in place"
    );
}

/// A project's ring is created on first use and dropped when its session is deleted: after
/// the drop the project is not observed at all, and a later request opens a fresh ring.
#[test]
fn deleting_a_project_drops_its_ring_and_a_later_request_opens_a_fresh_one() {
    let gate = gate(fixture_registry());
    let policy =
        ServiceAdmission::new(gate.clone(), "auth", BaselineMode::Unenforced).expect("mode");
    assert!(
        gate.registry()
            .read()
            .expect("readable")
            .observed_projects()
            .is_empty(),
        "no request, no ring"
    );
    let _ = policy.admit(&request(
        &HeaderClassification::Missing,
        PrivilegedBypass::None,
    ));
    assert_eq!(
        gate.registry()
            .read()
            .expect("readable")
            .observed_projects(),
        vec!["demo-app".to_owned()]
    );
    gate.clear_observations(|project| project == "demo-app");
    assert!(
        gate.registry()
            .read()
            .expect("readable")
            .observed_projects()
            .is_empty(),
        "deletion drops the ring itself"
    );
    let _ = policy.admit(&request(
        &HeaderClassification::Missing,
        PrivilegedBypass::None,
    ));
    let registry = gate.registry().read().expect("readable");
    assert_eq!(registry.observations("demo-app").len(), 1);
    assert_eq!(
        registry
            .observation_counters("demo-app")
            .iter()
            .map(|(_, count)| *count)
            .sum::<u64>(),
        1,
        "the fresh ring starts its counters from zero"
    );
}

/// The point of the per-project ring: a project that fills its own window many times over
/// evicts nothing but its own history.
#[test]
fn heavy_traffic_to_one_project_never_evicts_another_projects_observations() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate.clone(), "firestore", BaselineMode::Unenforced)
        .expect("unenforced classifies");
    let _ = policy.admit(&other_project_request("first"));
    for _ in 0..(MAX_RETAINED_OBSERVATIONS_PER_PROJECT * 3) {
        let _ = policy.admit(&request(
            &HeaderClassification::Missing,
            PrivilegedBypass::None,
        ));
    }
    let _ = policy.admit(&other_project_request("last"));
    let registry = gate.registry().read().expect("readable");
    let noisy = registry.observations("demo-app");
    assert_eq!(
        noisy.len(),
        MAX_RETAINED_OBSERVATIONS_PER_PROJECT,
        "a project's own ring is still bounded"
    );
    let quiet = registry.observations("demo-other");
    assert_eq!(
        quiet
            .iter()
            .map(|o| o.operation.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "last"],
        "the quiet project keeps both of its observations"
    );
}

/// Counters are not derived from what the ring still holds: an evicted observation is still
/// counted, so a busy project's totals stay honest.
#[test]
fn counters_outlive_the_observations_the_ring_evicted() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate.clone(), "firestore", BaselineMode::Unenforced)
        .expect("unenforced classifies");
    let rounds = MAX_RETAINED_OBSERVATIONS_PER_PROJECT + 10;
    for _ in 0..rounds {
        let _ = policy.admit(&request(
            &HeaderClassification::Missing,
            PrivilegedBypass::None,
        ));
    }
    let registry = gate.registry().read().expect("readable");
    assert_eq!(
        registry.observations("demo-app").len(),
        MAX_RETAINED_OBSERVATIONS_PER_PROJECT
    );
    let counters = registry.observation_counters("demo-app");
    assert_eq!(counters.len(), 1, "one bounded key: {counters:?}");
    let (key, count) = &counters[0];
    assert_eq!(key.service, "firestore");
    assert_eq!(key.app_id, "unknown");
    assert_eq!(key.function, None);
    assert_eq!(key.category, CredentialCategory::Missing);
    assert_eq!(key.outcome(), "admitted");
    assert_eq!(*count, rounds as u64);
}

/// Callable observations are grouped per callable; every other service's operation stays out
/// of the counter key, because only a callable name is a label the daemon itself declared.
#[test]
fn callable_counters_group_by_function_and_other_services_do_not() {
    let gate = gate(fixture_registry());
    let callables = ServiceAdmission::new(gate.clone(), "functions", BaselineMode::Unenforced)
        .expect("unenforced classifies");
    for operation in ["addMessage", "addMessage", "deleteMessage"] {
        let _ = callables.admit(&AdmissionRequest {
            project_id: "demo-app",
            transport: "http",
            operation,
            bypass: PrivilegedBypass::None,
            header: &HeaderClassification::Missing,
            now: NOW,
        });
    }
    let storage = ServiceAdmission::new(gate.clone(), "storage", BaselineMode::Unenforced)
        .expect("unenforced classifies");
    for operation in ["upload", "download"] {
        let _ = storage.admit(&AdmissionRequest {
            project_id: "demo-app",
            transport: "http",
            operation,
            bypass: PrivilegedBypass::None,
            header: &HeaderClassification::Missing,
            now: NOW,
        });
    }
    let counters = gate
        .registry()
        .read()
        .expect("readable")
        .observation_counters("demo-app");
    let functions: Vec<(Option<String>, u64)> = counters
        .iter()
        .filter(|(key, _)| key.service == "functions")
        .map(|(key, count)| (key.function.clone(), *count))
        .collect();
    assert_eq!(
        functions,
        vec![
            (Some("addMessage".to_owned()), 2),
            (Some("deleteMessage".to_owned()), 1)
        ]
    );
    let storage_counters: Vec<(Option<String>, u64)> = counters
        .iter()
        .filter(|(key, _)| key.service == "storage")
        .map(|(key, count)| (key.function.clone(), *count))
        .collect();
    assert_eq!(
        storage_counters,
        vec![(None, 2)],
        "storage operations are not counter labels"
    );
}

/// The table of rings is bounded too, and a project the registry knows is never crowded out
/// of it by traffic naming projects it does not.
#[test]
fn an_unregistered_project_never_displaces_a_registered_ones_ring() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate.clone(), "firestore", BaselineMode::Unenforced)
        .expect("unenforced classifies");
    for i in 0..MAX_OBSERVED_PROJECTS {
        let project = format!("nobody-{i}");
        let _ = policy.admit(&AdmissionRequest {
            project_id: &project,
            transport: "http",
            operation: "get",
            bypass: PrivilegedBypass::None,
            header: &HeaderClassification::Missing,
            now: NOW,
        });
    }
    let observed = gate
        .registry()
        .read()
        .expect("readable")
        .observed_projects();
    assert_eq!(
        observed.len(),
        MAX_OBSERVED_PROJECTS,
        "the table is bounded"
    );
    let _ = policy.admit(&request(
        &HeaderClassification::Missing,
        PrivilegedBypass::None,
    ));
    let registry = gate.registry().read().expect("readable");
    assert_eq!(registry.observations("demo-app").len(), 1);
    assert_eq!(
        registry.observed_projects().len(),
        MAX_OBSERVED_PROJECTS,
        "one unregistered ring made room for the registered one"
    );
}

/// A project ID no session could ever name is never allocated a ring: the observation would
/// be unreachable through the control API, and the table has to stay bounded.
#[test]
fn an_unnameable_project_id_opens_no_ring() {
    let gate = gate(fixture_registry());
    let policy = ServiceAdmission::new(gate.clone(), "firestore", BaselineMode::Unenforced)
        .expect("unenforced classifies");
    let too_long = "d".repeat(MAX_OBSERVED_PROJECT_ID_BYTES + 1);
    for project in ["", too_long.as_str()] {
        let _ = policy.admit(&AdmissionRequest {
            project_id: project,
            transport: "http",
            operation: "get",
            bypass: PrivilegedBypass::None,
            header: &HeaderClassification::Missing,
            now: NOW,
        });
    }
    assert!(gate
        .registry()
        .read()
        .expect("readable")
        .observed_projects()
        .is_empty());
}
