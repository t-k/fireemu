//! A crafted output file cannot recurse the entity decoder off the stack.

use std::collections::BTreeMap;

use fireemu_core_export::firestore::{read_output, write_output, ExportDocument, MAX_VALUE_DEPTH};
use fireemu_core_firestore::value::Value;

fn nested(levels: usize) -> Value {
    let mut value = Value::String("leaf".to_owned());
    for _ in 0..levels {
        let mut map = BTreeMap::new();
        map.insert("m".to_owned(), value);
        value = Value::Map(map);
    }
    value
}

fn document(levels: usize) -> ExportDocument {
    let mut fields = BTreeMap::new();
    fields.insert("deep".to_owned(), nested(levels));
    ExportDocument {
        project: "demo-app".to_owned(),
        path: vec![("things".to_owned(), "t1".to_owned())],
        fields,
    }
}

#[test]
fn values_nested_to_the_firestore_limit_decode_and_deeper_ones_are_refused() {
    let ok = write_output(&[document(MAX_VALUE_DEPTH)]);
    assert_eq!(read_output(&ok).expect("the limit itself decodes").len(), 1);
    let too_deep = write_output(&[document(MAX_VALUE_DEPTH + 1)]);
    let err = read_output(&too_deep).expect_err("one level past the limit is refused");
    assert!(err.to_string().contains("nested more than"), "{err}");
    // The decoder stops at the bound, so how deep the file really goes no longer matters
    // (the writer is not the attack surface: it serializes values Firestore's own nesting
    // limit already bounds, so a deeper document is only ever produced here by hand).
    let deeper = write_output(&[document(MAX_VALUE_DEPTH + 40)]);
    assert!(read_output(&deeper).is_err());
}
