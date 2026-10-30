//! Recorded projection behavior for absent nested aliases.

use std::collections::BTreeMap;

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::pipeline_exec::{execute_in, Expr, Row, Stage, Unrecorded};
use fireemu_core_firestore::value::Value;

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    )
}

#[test]
fn missing_alias_parents_follow_recorded_projection_in_both_profiles() {
    // PICT: profile, path depth, sibling, expression value; includes the four seed cases.
    let cases = [
        (true, 2, false, false),
        (true, 3, false, false),
        (true, 2, true, false),
        (false, 2, false, false),
        (false, 2, true, true),
        (true, 1, false, true),
        (false, 1, true, false),
        (false, 3, true, true),
    ];
    for (strict, depth, sibling, present) in cases {
        let alias = match depth {
            1 => "a",
            2 => "a.b",
            3 => "a.b.c",
            _ => unreachable!(),
        };
        let expr = Expr::Field(FieldPath::parse(if present { "top" } else { "missing" }).unwrap());
        let mut aliases = vec![(FieldPath::parse(alias).unwrap(), expr)];
        if sibling {
            let sibling_path = if depth == 1 { "other" } else { "a.z" };
            aliases.push((
                FieldPath::parse(sibling_path).unwrap(),
                Expr::Field(FieldPath::parse("top").unwrap()),
            ));
        }
        let text = Value::String("t".to_owned());
        let expected = match (depth, sibling, present) {
            (1, false, false) => BTreeMap::new(),
            (1, false, true) => [("a".to_owned(), text.clone())].into(),
            (1, true, false) => [("other".to_owned(), text.clone())].into(),
            (1, true, true) => [
                ("a".to_owned(), text.clone()),
                ("other".to_owned(), text.clone()),
            ]
            .into(),
            (2, false, false) => [("a".to_owned(), map(&[]))].into(),
            (2, false, true) => [("a".to_owned(), map(&[("b", text.clone())]))].into(),
            (2, true, false) => [("a".to_owned(), map(&[("z", text.clone())]))].into(),
            (2, true, true) => [(
                "a".to_owned(),
                map(&[("b", text.clone()), ("z", text.clone())]),
            )]
            .into(),
            (3, false, false) => [("a".to_owned(), map(&[("b", map(&[]))]))].into(),
            (3, false, true) => {
                [("a".to_owned(), map(&[("b", map(&[("c", text.clone())]))]))].into()
            }
            (3, true, false) => {
                [("a".to_owned(), map(&[("b", map(&[])), ("z", text.clone())]))].into()
            }
            (3, true, true) => [(
                "a".to_owned(),
                map(&[("b", map(&[("c", text.clone())])), ("z", text.clone())]),
            )]
            .into(),
            _ => unreachable!(),
        };
        let row = Row::derived([("top".to_owned(), text)].into());
        let mode = if strict {
            Unrecorded::Refuse
        } else {
            Unrecorded::OfficialEmulator
        };
        let got = execute_in(vec![Stage::select(aliases)], [row], mode);
        assert_eq!(
            got,
            Ok(vec![expected]),
            "strict={strict} depth={depth} sibling={sibling} present={present}"
        );
    }
}
