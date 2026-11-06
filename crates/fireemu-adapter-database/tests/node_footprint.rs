//! Layout and byte-level export contracts for the stored tree.

#[test]
#[cfg(target_pointer_width = "64")]
fn unprioritized_nodes_fit_forty_bytes() {
    let bytes = std::mem::size_of::<fireemu_core_database::Node>();
    assert!(bytes <= 40, "an unprioritized node occupies {bytes} bytes");
}

use fireemu_adapter_database::rest::{prepare_import, Database, RestOptions};
use proptest::prelude::*;

fn exported(input: &str) -> String {
    let options = RestOptions::default();
    let prepared = prepare_import("demo-footprint", input.to_owned(), &options.limits).unwrap();
    let mut database = Database::new(options, 0);
    database.install_import(prepared, 0).unwrap();
    database.export_texts().remove(0).1
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn export_bytes_preserve_priorities_numbers_and_key_order(
        integer in -10000i64..10000,
        double in any::<bool>(),
        priority in 0usize..4,
        shape in 0usize..3,
    ) {
        let value = if double { format!("{integer}.0") } else { integer.to_string() };
        let priority = match priority {
            0 => String::new(),
            1 => ",\".priority\":2.0".to_owned(),
            2 => ",\".priority\":-0.0".to_owned(),
            _ => ",\".priority\":\"rank\"".to_owned(),
        };
        let (input, expected) = match shape {
            0 if priority.is_empty() => (value.clone(), value),
            0 => {
                let input = format!("{{\".value\":{value}{priority}}}");
                let expected = format!("{{\".value\":{value}{priority}}}");
                (input, expected)
            }
            1 => {
                let input = format!("{{\"1\":{value},\"0\":true{priority}}}");
                let expected = if priority.is_empty() {
                    format!("[true,{value}]")
                } else {
                    format!("{{\"0\":true,\"1\":{value}{priority}}}")
                };
                (input, expected)
            }
            _ => {
                let input = format!("{{\"z\":{value},\"10\":false,\"2\":true,\"a\":\"😀\"{priority}}}");
                let expected = if priority.is_empty() {
                    format!("{{\"2\":true,\"10\":false,\"a\":\"😀\",\"z\":{value}}}")
                } else {
                    format!("{{\"2\":true,\"10\":false,{}{}}}", &priority[1..], format!(",\"a\":\"😀\",\"z\":{value}"))
                };
                (input, expected)
            }
        };
        let actual = exported(&input);
        prop_assert_eq!(actual.as_bytes(), expected.as_bytes());
    }
}
