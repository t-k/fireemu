//! Identifier newtypes: construction goes through validating constructors only.

use fireemu_core_types::ids::{
    CollectionId, DatabaseId, DocumentId, Epoch, IdSyntaxError, ProjectId, MAX_ID_UTF8_BYTES,
};

#[test]
fn project_id_accepts_demo_prefixed_session_routing_key() {
    let id = ProjectId::try_new("demo-fireemu-suite42-worker01-session0007").unwrap();
    assert_eq!(id.as_str(), "demo-fireemu-suite42-worker01-session0007");
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

#[test]
fn path_segments_reject_nul_and_control_characters() {
    // Intentional local hardening: the official rule is only "valid UTF-8", but NUL and
    // control characters must never reach traces, JSON or resource names.
    assert_eq!(
        DocumentId::try_new("a\u{0}b"),
        Err(IdSyntaxError::ControlCharacter { offset: 1 })
    );
    assert_eq!(
        CollectionId::try_new("\u{1f}"),
        Err(IdSyntaxError::ControlCharacter { offset: 0 })
    );
    assert_eq!(
        DocumentId::try_new("x\u{7f}"),
        Err(IdSyntaxError::ControlCharacter { offset: 1 })
    );
    // C1 control characters (U+0080..U+009F) are control characters too.
    assert_eq!(
        DocumentId::try_new("é\u{85}"),
        Err(IdSyntaxError::ControlCharacter { offset: 2 })
    );
    // Ordinary whitespace, emoji and combining marks stay valid.
    assert!(DocumentId::try_new("hello world").is_ok());
    assert!(DocumentId::try_new("か\u{3099}").is_ok());
    assert!(DocumentId::try_new("\u{1F600}").is_ok());
}

#[test]
fn project_id_length_boundary_and_messages() {
    assert!(ProjectId::try_new("a".repeat(63)).is_ok());
    assert_eq!(
        ProjectId::try_new("a".repeat(64)),
        Err(IdSyntaxError::TooManyBytes {
            bytes: 64,
            maximum: 63
        })
    );
    assert!(IdSyntaxError::Empty.to_string().contains("empty"));
    assert!(IdSyntaxError::TooManyBytes {
        bytes: 64,
        maximum: 63
    }
    .to_string()
    .contains("64"));
    assert!(IdSyntaxError::InvalidCharacter { offset: 3 }
        .to_string()
        .contains('3'));
    assert!(IdSyntaxError::ControlCharacter { offset: 2 }
        .to_string()
        .contains("control"));
    assert!(IdSyntaxError::ReservedDunder.to_string().contains("__"));
    assert_eq!(Epoch::new(7).to_string(), "7");
}
