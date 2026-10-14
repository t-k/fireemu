//! The shape rules a composite index definition obeys, whether it comes from
//! `firestore.indexes.json` or from `collectionGroups/{g}/indexes.create`.

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    CompositeShapeError, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope,
    MAX_COMPOSITE_INDEX_FIELDS,
};
use fireemu_core_types::ids::CollectionId;
use proptest::prelude::*;

fn field(path: &str, mode: IndexFieldMode) -> IndexField {
    IndexField {
        path: FieldPath::parse(path).unwrap(),
        mode,
    }
}

fn definition(fields: Vec<IndexField>) -> IndexDefinition {
    IndexDefinition {
        collection_group: CollectionId::try_new("g").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields,
    }
}

fn mode() -> impl Strategy<Value = IndexFieldMode> {
    prop_oneof![
        Just(IndexFieldMode::Ascending),
        Just(IndexFieldMode::Descending),
        Just(IndexFieldMode::Contains),
        (1u32..2049).prop_map(|dimension| IndexFieldMode::Vector { dimension }),
    ]
}

fn any_field() -> impl Strategy<Value = IndexField> {
    (
        prop_oneof![Just("a"), Just("b"), Just("c.d"), Just("__name__")],
        mode(),
    )
        .prop_map(|(path, mode)| field(path, mode))
}

proptest! {
    /// The recorded refusal is a definition with fewer than two fields that names neither
    /// `__name__` nor a vector: nothing else is refused as unnecessary.
    #[test]
    fn necessary_agrees_with_the_recorded_shape(fields in proptest::collection::vec(any_field(), 0..5)) {
        let refused = fields.len() < 2
            && fields.iter().all(|f| f.path.canonical() != "__name__")
            && fields.iter().all(|f| !matches!(f.mode, IndexFieldMode::Vector { .. }));
        let result = definition(fields).check_necessary();
        prop_assert_eq!(result, if refused { Err(CompositeShapeError::NotNecessary) } else { Ok(()) });
    }

    #[test]
    fn capacity_agrees_with_the_two_caps(fields in proptest::collection::vec(any_field(), 0..8), extra in 0usize..2) {
        let mut fields = fields;
        if extra == 1 {
            fields.extend((0..MAX_COMPOSITE_INDEX_FIELDS).map(|i| field(&format!("f{i}"), IndexFieldMode::Ascending)));
        }
        let arrays = fields.iter().filter(|f| f.mode == IndexFieldMode::Contains).count();
        let expected = if fields.len() > MAX_COMPOSITE_INDEX_FIELDS {
            Err(CompositeShapeError::TooManyFields)
        } else if arrays > 1 {
            Err(CompositeShapeError::MultipleArrayFields)
        } else {
            Ok(())
        };
        prop_assert_eq!(definition(fields).check_capacity(), expected);
    }
}

#[test]
fn the_field_cap_is_inclusive() {
    for (count, ok) in [(100usize, true), (101, false)] {
        let fields = (0..count)
            .map(|i| field(&format!("f{i}"), IndexFieldMode::Ascending))
            .collect();
        assert_eq!(definition(fields).check_capacity().is_ok(), ok, "{count}");
    }
}

#[test]
fn the_messages_are_the_recorded_and_the_documented_texts() {
    assert_eq!(
        CompositeShapeError::NotNecessary.to_string(),
        "this index is not necessary, configure using single field index controls"
    );
    assert_eq!(
        CompositeShapeError::TooManyFields.to_string(),
        "FS-LIMIT-FIELDS-PER-COMPOSITE-INDEX: maximum 100 fields"
    );
    assert_eq!(
        CompositeShapeError::MultipleArrayFields.to_string(),
        "a composite index may contain only one array field"
    );
}
