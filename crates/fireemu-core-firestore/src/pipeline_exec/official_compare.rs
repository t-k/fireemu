// The official emulator's answers to the six comparisons over every pair of operand classes
// (`official_compare.json`), recorded by `tools/sdk-smoke/pipeline-compare-matrix.mjs` against
// firebase-tools 15.28.2 (Firestore emulator 1.22.0, Enterprise): `--write <json>` records it
// again and `--check <json>` fails when the emulator answers differently. Each operator has
// one string per left operand, one cell per right operand: `T` true, `.` false. Design input
// for the emulator profile, not production evidence.

const SOURCE: &str = include_str!("official_compare.json");

/// The recorded matrix.
pub struct Matrix {
    /// Operand class names, in row and column order (`x` is a missing field).
    pub operands: Vec<&'static str>,
    /// Per operator, one row per left operand.
    pub rows: Vec<(&'static str, Vec<&'static str>)>,
}

impl Matrix {
    /// The official answer of `op(left, right)`.
    pub fn cell(&self, op: &str, left: &str, right: &str) -> bool {
        let index = |name: &str| self.operands.iter().position(|o| *o == name).unwrap();
        let (_, rows) = self.rows.iter().find(|(name, _)| *name == op).unwrap();
        rows[index(left)].as_bytes()[index(right)] == b'T'
    }
}

/// Reads the recorded matrix (the generator writes one key per line).
pub fn matrix() -> Matrix {
    let mut operands = Vec::new();
    let mut rows = Vec::new();
    for line in SOURCE.lines() {
        let Some((key, value)) = line.trim().split_once(": ") else {
            continue;
        };
        let key = key.trim_matches('"');
        let value = value.trim_end_matches(',');
        if key == "operands" {
            operands = value.trim_matches('"').split(' ').collect();
        } else if let Some(list) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            rows.push((
                key,
                list.split(", ").map(|row| row.trim_matches('"')).collect(),
            ));
        }
    }
    Matrix { operands, rows }
}

#[test]
fn the_recorded_matrix_is_complete() {
    let m = matrix();
    assert_eq!(m.operands.len(), 31);
    assert_eq!(m.operands[0], "x");
    let ops: Vec<_> = m.rows.iter().map(|(op, _)| *op).collect();
    assert_eq!(
        ops,
        [
            "equal",
            "not_equal",
            "less_than",
            "less_than_or_equal",
            "greater_than",
            "greater_than_or_equal"
        ]
    );
    for (op, rows) in &m.rows {
        assert_eq!(rows.len(), m.operands.len(), "{op}");
        for row in rows {
            assert_eq!(row.len(), m.operands.len(), "{op}");
            assert!(row.bytes().all(|c| c == b'T' || c == b'.'), "{op}: {row}");
        }
    }
}
