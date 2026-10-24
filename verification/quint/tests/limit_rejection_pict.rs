//! Generated private PICT cases replayed through the actual commit bridge.

use fireemu_verification_quint::limit_rejection::LimitRejectionDriver;

#[test]
#[ignore = "requires generated PICT rows in FIREEMU_FORMAL_MATRIX_DIR"]
fn generated_pict_rows_drive_actual_commit_refusals_and_successes() {
    let directory = std::env::var("FIREEMU_FORMAL_MATRIX_DIR").expect("PICT fixture directory");
    let table =
        std::fs::read_to_string(std::path::Path::new(&directory).join("limit.tsv")).unwrap();
    let mut count = 0;
    for row in table.lines().skip(1) {
        let fields = row.split('\t').collect::<Vec<_>>();
        let mut driver = LimitRejectionDriver::new();
        driver.init().unwrap();
        match fields[0] {
            "nonempty" => driver.seed().unwrap(),
            "empty" => (),
            value => panic!("unknown prior {value}"),
        }
        let before = driver.project().unwrap();
        driver.begin().unwrap();
        driver.stage(fields[2]).unwrap();
        driver.attempt(fields[1]).unwrap();
        let after = driver.project().unwrap();
        if fields[1] == "valid" {
            assert!(after.published_events > before.published_events, "{row}");
            assert_ne!(after.documents, before.documents, "{row}");
        } else {
            assert_eq!(after.documents, before.documents, "{row}");
            assert_eq!(after.outbox, before.outbox, "{row}");
            assert_eq!(after.reserved_events, before.reserved_events, "{row}");
            assert_eq!(after.published_events, before.published_events, "{row}");
        }
        count += 1;
    }
    assert!(count >= 8);
}
