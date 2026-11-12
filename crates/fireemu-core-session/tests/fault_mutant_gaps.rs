//! Regression tests for fault injection mutation gaps.

use std::sync::Arc;

use fireemu_core_session::fault::{
    decide_for, decide_shared, FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
    FaultState,
};

fn plan(action: FaultAction) -> FaultPlan {
    FaultPlan {
        seed: 7,
        rules: vec![FaultRule {
            matches: FaultMatch {
                operation: "read".into(),
                nth: None,
                function: None,
                event_type: None,
            },
            action,
        }],
    }
}

#[test]
fn registry_routes_and_removes_shared_states() {
    let registry = Arc::new(FaultRegistry::new());
    let default = registry.default_state();
    assert!(Arc::ptr_eq(&default, &registry.for_project("other")));
    let project = registry.register("project");
    assert!(Arc::ptr_eq(&project, &registry.register("project")));
    assert!(Arc::ptr_eq(&project, &registry.for_project("project")));
    assert!(!Arc::ptr_eq(&project, &default));
    project.lock().unwrap().install(plan(FaultAction::Timeout));
    assert_eq!(
        decide_shared(Some(&project), "read", None, None),
        vec![FaultAction::Timeout]
    );
    assert_eq!(
        decide_for(Some(&registry), "project", "read", None, None),
        vec![FaultAction::Timeout]
    );
    registry.remove("project");
    assert!(Arc::ptr_eq(&default, &registry.for_project("project")));
}

#[test]
fn retained_bytes_counts_action_and_string_capacity() {
    let mut empty = FaultState::default();
    assert_eq!(empty.retained_bytes(), 0);
    let p = plan(FaultAction::ReturnError {
        code: "long-error-code".into(),
    });
    empty.install(p.clone());
    assert_eq!(empty.plan(), Some(&p));
    let with_code = empty.retained_bytes();
    let mut no_code = FaultState::default();
    no_code.install(plan(FaultAction::Timeout));
    let code = "long-error-code".to_owned();
    assert_eq!(
        with_code - no_code.retained_bytes(),
        u64::try_from(code.capacity()).unwrap()
    );
    let mut longer_operation = FaultState::default();
    let mut longer_plan = plan(FaultAction::Timeout);
    longer_plan.rules[0].matches.operation = "read-longer".into();
    longer_operation.install(longer_plan);
    assert_eq!(
        longer_operation.retained_bytes() - no_code.retained_bytes(),
        7
    );
}
