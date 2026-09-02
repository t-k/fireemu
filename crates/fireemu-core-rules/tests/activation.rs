//! Atomic ruleset publication and authorization-evaluation snapshot contracts.

use std::sync::Arc;

use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};

const V1: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
const V2: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

#[test]
fn evaluation_snapshot_remains_on_v1_after_v2_activation() {
    let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
    let admitted = slot.snapshot().unwrap();

    assert_eq!(slot.replace_source(V2).unwrap(), 1);

    assert_eq!(admitted.generation(), 0);
    assert_eq!(admitted.source.as_deref(), Some(V1));
    let current = slot.snapshot().unwrap();
    assert_eq!(current.generation(), 1);
    assert_eq!(current.source.as_deref(), Some(V2));
}

#[test]
fn invalid_candidate_preserves_active_snapshot_and_generation() {
    let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
    let before = slot.snapshot().unwrap();

    assert!(slot.replace_source("not rules").is_err());

    let after = slot.snapshot().unwrap();
    assert_eq!(after.generation(), 0);
    assert!(Arc::ptr_eq(&before.loaded(), &after.loaded()));
}

#[test]
fn clear_and_restore_publish_fresh_generations() {
    let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
    let saved = slot.snapshot().unwrap().loaded();

    assert_eq!(slot.clear().unwrap(), 1);
    assert!(!slot.snapshot().unwrap().is_loaded());
    assert_eq!(slot.replace_loaded((*saved).clone()).unwrap(), 2);

    let restored = slot.snapshot().unwrap();
    assert_eq!(restored.generation(), 2);
    assert_eq!(restored.source.as_deref(), Some(V1));
}
