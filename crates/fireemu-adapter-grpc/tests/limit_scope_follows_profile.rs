//! Under the strict profile `firestore.enforceLimits: false` switches the Standard query limits
//! only: the limits on writes, transactions, indexes and the transport follow the compatibility
//! profile (the index policy). Under the emulator profile `enforceLimits: true` still asks for
//! them, as it always has.

// `tonic::Status` is the error type of the backend's own closures.
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::store::LimitScope;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;

const DOCS: &str = "projects/demo-app/databases/(default)/documents";

fn gateway(enforce_limits: bool, policy: IndexValidationPolicy) -> Gateway {
    Gateway {
        enforce_limits,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy,
        },
        indexes: IndexSet::default(),
    }
}

fn scope_of(gateway: Gateway) -> LimitScope {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = LocalBackend::new(gateway, clock, 7);
    let parent = fireemu_adapter_grpc::decode::parse_parent(DOCS).unwrap();
    backend
        .database_handle(&parent)
        .unwrap()
        .with(|state| Ok(state.limit_scope()))
        .unwrap()
}

#[test]
fn observing_query_limits_keeps_production_limits_on_writes() {
    for policy in [
        IndexValidationPolicy::Production,
        IndexValidationPolicy::ProductionReport,
    ] {
        assert_eq!(scope_of(gateway(false, policy)), LimitScope::Production);
        assert_eq!(scope_of(gateway(true, policy)), LimitScope::Production);
    }
}

#[test]
fn the_emulator_profile_asks_for_production_limits_only_with_an_explicit_true() {
    assert_eq!(
        scope_of(gateway(true, IndexValidationPolicy::Emulator)),
        LimitScope::Production
    );
    assert_eq!(
        scope_of(gateway(false, IndexValidationPolicy::Emulator)),
        LimitScope::OfficialEmulator
    );
}
