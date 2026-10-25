//! Diagnostic expression structure and result histograms. These never decide access.

use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::number::Number;
use crate::Json;

#[derive(Debug, Clone)]
pub(crate) struct Template {
    pub at: usize,
    pub end: usize,
    pub children: Vec<usize>,
}

/// Distinct values one expression's coverage keeps; later new values are only counted.
pub const COVERAGE_VALUES_PER_EXPRESSION: usize = 64;

/// String bytes one expression's kept values may hold, so a few large data values cannot pin
/// unbounded memory; a value past it is only counted.
const COVERAGE_STRING_BYTES_PER_EXPRESSION: usize = 64 * 1024;

/// The results one expression produced. Coverage is collected on every evaluation of a
/// long-lived daemon (review M1, 2026-10-25), so a record costs one hash lookup and the kept
/// values are bounded: past [`COVERAGE_VALUES_PER_EXPRESSION`] distinct values (or the byte
/// budget), a new value is only counted in `omitted`.
#[derive(Debug, Default)]
struct Histogram {
    /// Kept values in first-seen order, as the official emulator lists them.
    entries: Vec<(Json, i64)>,
    /// Entry positions by [`fingerprint`]; equal values (`==`) share a fingerprint.
    index: HashMap<u64, Vec<usize>>,
    string_bytes: usize,
    omitted: i64,
}

impl Histogram {
    fn record(&mut self, value: Json) {
        let fingerprint = fingerprint(&value);
        let positions = self.index.entry(fingerprint).or_default();
        if let Some(position) = positions
            .iter()
            .copied()
            .find(|position| self.entries[*position].0 == value)
        {
            let count = &mut self.entries[position].1;
            *count = count.saturating_add(1);
            return;
        }
        let bytes = string_bytes(&value);
        if self.entries.len() >= COVERAGE_VALUES_PER_EXPRESSION
            || self.string_bytes.saturating_add(bytes) > COVERAGE_STRING_BYTES_PER_EXPRESSION
        {
            if positions.is_empty() {
                self.index.remove(&fingerprint);
            }
            self.omitted = self.omitted.saturating_add(1);
            return;
        }
        positions.push(self.entries.len());
        self.string_bytes += bytes;
        self.entries.push((value, 1));
    }
}

/// A hash consistent with `Json`'s `==`: numbers compare by value across integers and
/// doubles (`1 == 1.0`, `0.0 == -0.0`), so an integral double hashes as its integer.
/// Composite values hash by kind and length only; `==` settles them.
fn fingerprint(value: &Json) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    match value {
        Json::Null => 0u8.hash(&mut hasher),
        Json::Bool(value) => {
            1u8.hash(&mut hasher);
            value.hash(&mut hasher);
        }
        Json::Number(number) => {
            2u8.hash(&mut hasher);
            match integral(*number) {
                Some(integer) => integer.hash(&mut hasher),
                None => number.as_f64().to_bits().hash(&mut hasher),
            }
        }
        Json::String(text) => {
            3u8.hash(&mut hasher);
            text.hash(&mut hasher);
        }
        Json::Array(items) => {
            4u8.hash(&mut hasher);
            items.len().hash(&mut hasher);
        }
        Json::Object(fields) => {
            5u8.hash(&mut hasher);
            fields.len().hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// The integer a number equals, if any.
#[allow(clippy::cast_possible_truncation)]
fn integral(number: Number) -> Option<i64> {
    // 2^63 is exact as a double; every i64 lies in [-2^63, 2^63).
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    match number {
        Number::Int(integer) => Some(integer),
        // Integral and inside the i64 range, so the cast is exact where it is used.
        Number::Double(double) => (double.fract() == 0.0
            && (-TWO_POW_63..TWO_POW_63).contains(&double))
        .then_some(double as i64),
    }
}

fn string_bytes(value: &Json) -> usize {
    match value {
        Json::String(text) => text.len(),
        Json::Array(items) => items.iter().map(string_bytes).sum(),
        Json::Object(fields) => fields
            .iter()
            .map(|(key, value)| key.len() + string_bytes(value))
            .sum(),
        Json::Null | Json::Bool(_) | Json::Number(_) => 0,
    }
}

type Histograms = Vec<Histogram>;

#[derive(Debug)]
struct Collection {
    templates: Vec<Template>,
    text: Vec<char>,
    positions: Vec<(usize, usize)>,
    values: Mutex<Histograms>,
    enabled: AtomicBool,
}

#[derive(Debug, Clone)]
pub(crate) struct Coverage(Arc<Collection>);

impl Coverage {
    pub fn new(text: &str, anchor: (usize, usize), templates: Vec<Template>) -> Self {
        let mut position = (anchor.0.saturating_sub(1), anchor.1.saturating_sub(1));
        let mut positions = Vec::new();
        let text: Vec<char> = text.chars().collect();
        for character in &text {
            positions.push(position);
            if *character == '\n' {
                position = (position.0 + 1, 0);
            } else {
                position.1 += character.len_utf16();
            }
        }
        positions.push(position);
        let values = Mutex::new(
            std::iter::repeat_with(Histogram::default)
                .take(templates.len())
                .collect(),
        );
        Self(Arc::new(Collection {
            templates,
            text,
            positions,
            values,
            enabled: AtomicBool::new(true),
        }))
    }

    pub fn enabled(&self, enabled: bool) {
        self.0.enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn observer(&self) -> Observer<'_> {
        Observer {
            collection: &self.0,
            values: self
                .0
                .values
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            enabled: self.0.enabled.load(Ordering::Relaxed),
            suppressed: 0,
            variables: BTreeMap::new(),
        }
    }

    pub fn report(&self, root: usize) -> Json {
        let values = self
            .0
            .values
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Parser IDs are topological, so even flat authorization chains need no recursive walk.
        let mut built: Vec<Option<Json>> = vec![None; self.0.templates.len()];
        for (id, template) in self.0.templates.iter().enumerate() {
            let (row, column) = self.0.positions[template.at];
            let (end_row, end_column) = self.0.positions[template.end - 1];
            let width = self.0.text[template.end - 1].len_utf16();
            let mut fields = BTreeMap::from([
                (
                    "location-start".to_owned(),
                    Json::string(format!("{row}:{column}")),
                ),
                (
                    "location-end".to_owned(),
                    Json::string(format!("{end_row}:{}", end_column + width - 1)),
                ),
                (
                    "text".to_owned(),
                    Json::String(self.0.text[template.at..template.end].iter().collect()),
                ),
                (
                    "values".to_owned(),
                    Json::Array(
                        values[id]
                            .entries
                            .iter()
                            .map(|(value, count)| {
                                Json::object([
                                    ("value", value.clone()),
                                    ("count", Json::int(*count)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]);
            if values[id].omitted != 0 {
                fields.insert("values-omitted".to_owned(), Json::int(values[id].omitted));
            }
            if !template.children.is_empty() {
                fields.insert(
                    "children".to_owned(),
                    Json::Array(
                        template
                            .children
                            .iter()
                            .map(|child| {
                                built[*child]
                                    .take()
                                    .expect("a diagnostic node has one parent")
                            })
                            .collect(),
                    ),
                );
            }
            built[id] = Some(Json::Object(fields));
        }
        built[root]
            .take()
            .expect("the expression has a diagnostic root")
    }
}

pub(crate) struct Observer<'a> {
    collection: &'a Collection,
    values: MutexGuard<'a, Histograms>,
    enabled: bool,
    pub suppressed: usize,
    variables: BTreeMap<String, Json>,
}

impl Observer<'_> {
    pub fn record(&mut self, id: usize, value: Json) {
        if !self.enabled || self.suppressed != 0 {
            return;
        }
        self.values[id].record(value);
    }

    pub fn member_name(&mut self, id: usize, name: &str) {
        if let Some(name_id) = self.collection.templates[id].children.get(1).copied() {
            self.record(name_id, Json::string(name));
        }
    }

    pub fn opaque(&mut self, variable: Option<&str>) -> Json {
        // Process-local identities represent evaluations, never Firebase object identities.
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let fresh = || Json::string(format!("hash@{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        variable.map_or_else(fresh, |name| {
            self.variables
                .entry(name.to_owned())
                .or_insert_with(fresh)
                .clone()
        })
    }

    pub fn prefixes(&self, root: usize, operands: usize) -> Vec<usize> {
        let mut ids = vec![root];
        for _ in 2..operands {
            ids.push(self.collection.templates[*ids.last().expect("root exists")].children[0]);
        }
        ids.reverse();
        ids
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::{
        Histogram, Number, COVERAGE_STRING_BYTES_PER_EXPRESSION, COVERAGE_VALUES_PER_EXPRESSION,
    };
    use crate::Json;

    /// The histogram as the linear scan of the first implementation kept it, with the cap.
    #[derive(Default)]
    struct Reference {
        entries: Vec<(Json, i64)>,
        bytes: usize,
        omitted: i64,
    }

    impl Reference {
        fn record(&mut self, value: Json) {
            if let Some((_, count)) = self.entries.iter_mut().find(|(seen, _)| *seen == value) {
                *count += 1;
                return;
            }
            let bytes = match &value {
                Json::String(text) => text.len(),
                _ => 0,
            };
            if self.entries.len() >= COVERAGE_VALUES_PER_EXPRESSION
                || self.bytes + bytes > COVERAGE_STRING_BYTES_PER_EXPRESSION
            {
                self.omitted += 1;
            } else {
                self.bytes += bytes;
                self.entries.push((value, 1));
            }
        }
    }

    fn scalar() -> impl Strategy<Value = Json> {
        prop_oneof![
            Just(Json::Null),
            any::<bool>().prop_map(Json::Bool),
            (-100i64..100).prop_map(|value| Json::Number(Number::Int(value))),
            // Integral doubles equal their integers; -0.0 equals 0.
            (-100i32..100).prop_map(|value| Json::Number(Number::Double(f64::from(value)))),
            Just(Json::Number(Number::Double(-0.0))),
            Just(Json::Number(Number::Double(9_223_372_036_854_775_808.0))),
            Just(Json::Number(Number::Int(i64::MIN))),
            Just(Json::Number(Number::Double(-9_223_372_036_854_775_808.0))),
            (-100i32..100).prop_map(|value| Json::Number(Number::Double(f64::from(value) + 0.5))),
            "[a-c]{0,3}".prop_map(Json::String),
            (0usize..3).prop_map(|size| Json::String("x".repeat(size * 20_000))),
            (0usize..3).prop_map(|size| Json::String(format!("hash@{size}"))),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The hashed histogram keeps exactly what the linear scan kept, in the same order,
        /// with the same counts and the same omitted count.
        #[test]
        fn hashed_histogram_matches_the_linear_reference(values in prop::collection::vec(scalar(), 0..300)) {
            let mut histogram = Histogram::default();
            let mut reference = Reference::default();
            for value in values {
                histogram.record(value.clone());
                reference.record(value);
            }
            prop_assert_eq!(histogram.entries.len(), reference.entries.len());
            for ((kept, count), (expected, expected_count)) in histogram.entries.iter().zip(&reference.entries) {
                prop_assert!(kept.same_form(expected), "{:?} != {:?}", kept, expected);
                prop_assert_eq!(count, expected_count);
            }
            prop_assert_eq!(histogram.omitted, reference.omitted);
            prop_assert!(histogram.entries.len() <= COVERAGE_VALUES_PER_EXPRESSION);
            prop_assert!(histogram.string_bytes <= COVERAGE_STRING_BYTES_PER_EXPRESSION);
            prop_assert!(histogram.index.values().map(Vec::len).sum::<usize>() == histogram.entries.len());
        }
    }

    #[test]
    fn the_string_budget_is_64_kib_inclusive() {
        let mut histogram = Histogram::default();
        histogram.record(Json::String("x".repeat(65_536)));
        assert_eq!(histogram.entries.len(), 1, "exactly 64 KiB is kept");
        histogram.record(Json::String("y".to_owned()));
        assert_eq!((histogram.entries.len(), histogram.omitted), (1, 1));
    }

    #[test]
    fn distinct_numbers_land_in_distinct_buckets() {
        // The index is what keeps a record O(1); collapsing numbers into one bucket would
        // bring back the linear scan.
        let mut histogram = Histogram::default();
        for value in [
            Json::Number(Number::Int(1)),
            Json::Number(Number::Int(2)),
            Json::Number(Number::Double(1.5)),
            Json::Number(Number::Double(-7.0)),
        ] {
            histogram.record(value);
        }
        assert_eq!(histogram.index.len(), 4);
    }

    #[test]
    fn object_values_charge_their_keys_and_strings() {
        let value = Json::Object(
            [
                ("ab".to_owned(), Json::String("cde".to_owned())),
                (
                    "f".to_owned(),
                    Json::Array(vec![Json::String("gh".to_owned()), Json::Null]),
                ),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(super::string_bytes(&value), 8);
    }

    #[test]
    fn equal_numbers_of_either_kind_share_one_entry() {
        let mut histogram = Histogram::default();
        for value in [
            Json::Number(Number::Int(1)),
            Json::Number(Number::Double(1.0)),
            Json::Number(Number::Int(0)),
            Json::Number(Number::Double(-0.0)),
            Json::Number(Number::Double(0.0)),
        ] {
            histogram.record(value);
        }
        assert_eq!(histogram.entries.len(), 2);
        assert_eq!(histogram.entries[0].1, 2);
        assert_eq!(histogram.entries[1].1, 3);
    }

    #[test]
    fn values_past_the_caps_are_counted_as_omitted() {
        let mut histogram = Histogram::default();
        for index in 0..=COVERAGE_VALUES_PER_EXPRESSION {
            histogram.record(Json::String(format!("hash@{index}")));
        }
        assert_eq!(histogram.entries.len(), COVERAGE_VALUES_PER_EXPRESSION);
        assert_eq!(histogram.omitted, 1);
        histogram.record(Json::String("hash@0".to_owned()));
        assert_eq!(histogram.entries[0].1, 2, "kept values keep counting");
        let mut large = Histogram::default();
        large.record(Json::String(
            "x".repeat(COVERAGE_STRING_BYTES_PER_EXPRESSION),
        ));
        large.record(Json::String("y".to_owned()));
        large.record(Json::Bool(true));
        assert_eq!(large.entries.len(), 2);
        assert_eq!(large.omitted, 1);
        assert!(
            large.index.len() == 2,
            "an omitted value leaves no index entry"
        );
    }
}
