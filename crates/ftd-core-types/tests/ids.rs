//! Identifier newtypes: construction goes through validating constructors only.

use ftd_core_types::ids::{
    CollectionId, DatabaseId, DocumentId, Epoch, IdSyntaxError, ProjectId, MAX_ID_UTF8_BYTES,
};

#[test]
fn project_id_accepts_demo_prefixed_session_routing_key() {
    let id = ProjectId::try_new("demo-ftd-suite42-worker01-session0007").unwrap();
    assert_eq!(id.as_str(), "demo-ftd-suite42-worker01-session0007");
    assert!(id.has_demo_prefix());
}

#[test]
fn project_id_rejects_empty_uppercase_and_edge_hyphens() {
    assert_eq!(ProjectId::try_new(""), Err(IdSyntaxError::Empty));
    assert!(matches!(
        ProjectId::try_new("Demo-App"),
        Err(IdSyntaxError::InvalidCharacter { .. })
    ));
    assert!(matches!(
        ProjectId::try_new("-demo"),
        Err(IdSyntaxError::LeadingOrTrailingHyphen)
    ));
    assert!(matches!(
        ProjectId::try_new("demo-"),
        Err(IdSyntaxError::LeadingOrTrailingHyphen)
    ));
}

#[test]
fn project_id_without_demo_prefix_is_valid_but_flagged() {
    let id = ProjectId::try_new("my-prod-app").unwrap();
    assert!(!id.has_demo_prefix());
}

#[test]
fn database_id_accepts_default_and_named() {
    assert_eq!(DatabaseId::default_database().as_str(), "(default)");
    assert_eq!(
        DatabaseId::try_new("(default)").unwrap(),
        DatabaseId::default_database()
    );
    assert!(DatabaseId::try_new("tenant-a").is_ok());
    assert!(DatabaseId::try_new("").is_err());
    assert!(DatabaseId::try_new("Tenant").is_err());
}

#[test]
fn collection_id_enforces_firestore_syntax_rules() {
    assert!(CollectionId::try_new("users").is_ok());
    assert!(CollectionId::try_new("請求書").is_ok());
    assert_eq!(CollectionId::try_new(""), Err(IdSyntaxError::Empty));
    assert_eq!(
        CollectionId::try_new("a/b"),
        Err(IdSyntaxError::ContainsSlash)
    );
    assert_eq!(CollectionId::try_new("."), Err(IdSyntaxError::DotSegment));
    assert_eq!(CollectionId::try_new(".."), Err(IdSyntaxError::DotSegment));
    assert_eq!(
        CollectionId::try_new("__x__"),
        Err(IdSyntaxError::ReservedDunder)
    );
    assert_eq!(
        CollectionId::try_new("____"),
        Err(IdSyntaxError::ReservedDunder)
    );
    // "__" alone is not of the form __.*__ (needs both prefix and suffix around at least zero
    // chars, so a 4-byte minimum).
    assert!(CollectionId::try_new("__").is_ok());
    assert!(CollectionId::try_new("__a").is_ok());
}

#[test]
fn document_id_byte_limit_is_utf8_bytes_not_chars() {
    // 500 three-byte characters = 1,500 bytes: allowed (inclusive maximum).
    let exactly = "あ".repeat(500);
    assert_eq!(exactly.len(), MAX_ID_UTF8_BYTES);
    assert!(DocumentId::try_new(&exactly).is_ok());
    // 501 characters = 1,503 bytes: rejected even though the char count is far below 1,500.
    let over = "あ".repeat(501);
    assert_eq!(
        DocumentId::try_new(&over),
        Err(IdSyntaxError::TooManyBytes {
            bytes: 1503,
            maximum: MAX_ID_UTF8_BYTES
        })
    );
    let ascii_over = "a".repeat(1501);
    assert!(DocumentId::try_new(&ascii_over).is_err());
}

#[test]
fn epoch_is_monotonic_and_checked() {
    let e = Epoch::initial();
    assert_eq!(e.value(), 0);
    let n = e.next().unwrap();
    assert_eq!(n.value(), 1);
    assert!(n > e);
    assert!(Epoch::new(u64::MAX).next().is_none());
}
