//! Atomic ruleset publication and authorization-evaluation snapshot contracts.

use std::sync::Arc;

use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};

const V1: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
const V2: &str = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

fn oversized_ruleset() -> String {
    let base = "rules_version = '2'; service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }\n// ";
    let mut source = base.to_owned();
    source.push_str(&"x".repeat(262_144 - base.len()));
    source
}

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
fn lint_error_candidate_is_rejected_without_replacing_active_rules() {
    let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
    let before = slot.snapshot().unwrap();

    assert!(slot.replace_source(&oversized_ruleset()).is_err());

    let after = slot.snapshot().unwrap();
    assert_eq!(after.generation(), before.generation());
    assert!(Arc::ptr_eq(&before.loaded(), &after.loaded()));
}

#[test]
fn unknown_rules_version_is_rejected_without_replacing_active_rules() {
    let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
    let before = slot.snapshot().unwrap();
    let source = V1.replace("rules_version = '2'", "rules_version = '3'");

    let error = slot
        .replace_source(&source)
        .expect_err("unknown rules versions must not activate");

    assert!(error.contains("unsupported rules_version"), "{error}");
    let after = slot.snapshot().unwrap();
    assert_eq!(after.generation(), before.generation());
    assert!(Arc::ptr_eq(&before.loaded(), &after.loaded()));
}

#[test]
fn recursive_wildcard_structure_is_validated_before_activation() {
    let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
    let before = slot.snapshot().unwrap();
    let multiple = "rules_version = '2'; service cloud.firestore { match /{a=**}/{b=**} { allow read: if true; } }";
    let non_terminal_v1 = "rules_version = '1'; service cloud.firestore { match /{a=**}/tail { allow read: if true; } }";

    for (source, expected) in [
        (multiple, "at most one recursive wildcard"),
        (non_terminal_v1, "must be the final path segment"),
    ] {
        let error = slot
            .replace_source(source)
            .expect_err("invalid recursive wildcard structure must not activate");
        assert!(error.contains(expected), "{error}");
    }

    let after = slot.snapshot().unwrap();
    assert_eq!(after.generation(), before.generation());
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
