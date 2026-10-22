use super::*;
use proptest::prelude::*;

// Frozen from 76e22cb9e: never call the optimized helpers from this reference.
mod reference {
    use super::DistanceMeasure;
    fn scaled_norm(values: &[f64]) -> Option<f64> {
        let mut scale = 0.0;
        let mut sum = 0.0;
        for value in values {
            if !value.is_finite() {
                return None;
            }
            let absolute = value.abs();
            if absolute == 0.0 {
                continue;
            }
            if scale == 0.0 {
                scale = absolute;
                sum = 1.0;
            } else if absolute > scale {
                let ratio = scale / absolute;
                sum = 1.0 + sum * ratio * ratio;
                scale = absolute;
            } else {
                let ratio = absolute / scale;
                sum += ratio * ratio;
            }
            if !sum.is_finite() {
                return None;
            }
        }
        let norm = scale * sum.sqrt();
        norm.is_finite().then_some(norm)
    }

    fn normalized_components(values: &[f64]) -> Option<Vec<f64>> {
        if values.iter().any(|value| !value.is_finite()) {
            return None;
        }
        let scale = values.iter().map(|value| value.abs()).fold(0.0, f64::max);
        if scale == 0.0 {
            return None;
        }
        let norm = values
            .iter()
            .map(|value| {
                let scaled = value / scale;
                scaled * scaled
            })
            .sum::<f64>()
            .sqrt();
        if !norm.is_finite() || norm == 0.0 {
            return None;
        }
        values
            .iter()
            .map(|value| {
                let component = (value / scale) / norm;
                component.is_finite().then_some(component)
            })
            .collect()
    }

    fn checked_dot(left: &[f64], right: &[f64]) -> Option<f64> {
        let mut dot = 0.0;
        for (left, right) in left.iter().zip(right) {
            if !left.is_finite() || !right.is_finite() {
                return None;
            }
            let product = left * right;
            if !product.is_finite() {
                return None;
            }
            dot += product;
            if !dot.is_finite() {
                return None;
            }
        }
        Some(dot)
    }

    pub(super) fn vector_distance(
        vector: &[f64],
        query: &[f64],
        measure: DistanceMeasure,
    ) -> Option<f64> {
        if vector.len() != query.len() {
            return None;
        }
        match measure {
            DistanceMeasure::Euclidean => {
                let differences: Option<Vec<f64>> = vector
                    .iter()
                    .zip(query)
                    .map(|(left, right)| {
                        let difference = left - right;
                        difference.is_finite().then_some(difference)
                    })
                    .collect();
                scaled_norm(&differences?)
            }
            DistanceMeasure::Cosine => {
                let left = normalized_components(vector)?;
                let right = normalized_components(query)?;
                let similarity = checked_dot(&left, &right)?;
                Some((1.0 - similarity.clamp(-1.0, 1.0)).clamp(0.0, 2.0))
            }
            DistanceMeasure::DotProduct => checked_dot(vector, query),
        }
    }
}

fn check(left: &[f64], right: &[f64]) {
    for measure in [
        DistanceMeasure::Euclidean,
        DistanceMeasure::Cosine,
        DistanceMeasure::DotProduct,
    ] {
        assert_eq!(
            PreparedVectorDistance::new(right, measure).evaluate(left).map(f64::to_bits),
            reference::vector_distance(left, right, measure).map(f64::to_bits),
            "prepared left={left:?}, right={right:?}, measure={measure:?}"
        );
        assert_eq!(
            vector_distance(left, right, measure).map(f64::to_bits),
            reference::vector_distance(left, right, measure).map(f64::to_bits),
            "left={left:?}, right={right:?}, measure={measure:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn vector_bits_match_frozen_reference(pairs in prop::collection::vec((any::<u64>(), any::<u64>()), 0..129)) {
        let left: Vec<_> = pairs.iter().map(|(a, _)| f64::from_bits(*a)).collect();
        let right: Vec<_> = pairs.iter().map(|(_, b)| f64::from_bits(*b)).collect();
        check(&left, &right);
        check(&left, &left);
        let finite: Vec<_> = pairs.iter().map(|(a, _)| f64::from_bits(*a & 0xffef_ffff_ffff_ffff)).collect();
        check(&finite, &vec![0.0; finite.len()]);
        let dense: Vec<_> = pairs.iter().map(|(a, _)| f64::from_bits((a & 0x800f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000)).collect();
        check(&dense, &vec![0.5; dense.len()]);
        let mut longer = right.clone(); longer.push(f64::MAX);
        check(&left, &longer);
    }
}

#[test]
fn vector_extremes_match_frozen_reference() {
    let cases = [
        vec![],
        vec![0.0, -0.0],
        vec![f64::MAX; 2],
        vec![f64::from_bits(1), f64::MIN_POSITIVE],
        vec![1e-300, 1.0, 1e300],
        vec![1e300, 1.0, 1e-300],
        vec![3.0, 3.0, 3.0],
        vec![f64::NAN, 1.0],
        vec![1.0, f64::INFINITY],
        vec![f64::NEG_INFINITY, 1.0],
        vec![1.000_000_000_000_000_2, 1.0],
        vec![f64::MIN_POSITIVE; 2048],
    ];
    for left in &cases {
        check(left, left);
        check(left, &vec![0.0; left.len()]);
        check(left, &left.iter().map(|x| -*x).collect::<Vec<_>>());
        for right in &cases {
            check(left, right);
        }
    }
    check(&[f64::MAX, 1.0], &[-f64::MAX, 1.0]);
    check(&[1.0, f64::MAX], &[1.0, -f64::MAX]);
    check(&[f64::MAX], &[-f64::MAX, 0.0]);
}

#[test]
fn vector_streaming_norm_accepts_an_iterator() {
    assert_eq!(
        scaled_norm([3.0, 4.0].into_iter()).map(f64::to_bits),
        Some(5.0f64.to_bits())
    );
}

#[test]
fn vector_threshold_adjacent_bits_rank_and_projection() {
    use fireemu_core_types::ids::{DatabaseId, ProjectId};
    let mut state = FirestoreState::new();
    let project = ProjectId::try_new("demo-app").unwrap();
    let left = vec![1e150, 3e149, 7e148];
    let query_vector = vec![0.0; 3];
    let distance =
        reference::vector_distance(&left, &query_vector, DistanceMeasure::Euclidean).unwrap();
    for (id, vector) in [
        ("b", left.clone()),
        ("a", left),
        ("wrong", vec![1.0]),
        ("overflow", vec![f64::MAX; 3]),
        ("invalid", vec![f64::INFINITY; 3]),
    ] {
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: DocumentPath::parse(
                            &project,
                            &DatabaseId::default_database(),
                            &format!("items/{id}"),
                        )
                        .unwrap(),
                        fields: BTreeMap::from([("embedding".to_owned(), Value::Vector(vector))]),
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: vec![],
                }],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .unwrap();
    }
    for (threshold, expected) in [
        (f64::from_bits(distance.to_bits() - 1), 0),
        (distance, 2),
        (f64::from_bits(distance.to_bits() + 1), 2),
    ] {
        let mut query = Query::new(QueryScope::collection(
            None,
            CollectionId::try_new("items").unwrap(),
        ))
        .with_find_nearest(crate::query::FindNearest {
            vector_field: FieldPath::parse("embedding").unwrap(),
            query_vector: query_vector.clone(),
            distance_measure: DistanceMeasure::Euclidean,
            limit: 2,
            distance_result_field: Some(FieldPath::parse("distance").unwrap()),
            distance_threshold: Some(threshold),
        });
        query.projection = Some(vec![FieldPath::parse("distance").unwrap()]);
        let docs = state
            .run_query(&query.clone().canonicalize().unwrap(), None)
            .unwrap();
        assert_eq!(docs.len(), expected);
        for (doc, id) in docs.iter().zip(["a", "b"]) {
            assert_eq!(doc.path.document_id().as_str(), id);
            assert_eq!(doc.fields.len(), 1);
            let Value::Double(actual) = doc.fields["distance"] else {
                panic!("missing distance");
            };
            assert_eq!(actual.to_bits(), distance.to_bits());
        }
        query.find_nearest.as_mut().unwrap().limit = 1;
        let docs = state
            .run_query(&query.canonicalize().unwrap(), None)
            .unwrap();
        assert_eq!(docs.len(), expected.min(1));
        if let Some(doc) = docs.first() {
            assert_eq!(doc.path.document_id().as_str(), "a");
        }
    }
}
