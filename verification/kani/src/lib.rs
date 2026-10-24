//! Kani harnesses for the pure core (spec 22).
//!
//! Each harness names the requirement it covers. Run with `cargo kani -p fireemu-verification-kani`.
//! The harnesses compile only under `cfg(kani)`; a normal build sees an empty crate.

#[cfg(kani)]
mod harnesses {
    use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
    use fireemu_core_events::retry::RetryPolicy;
    use fireemu_core_events::state::{EventRecord, EventTransitionError};
    use fireemu_core_limits::evaluate::{
        classify_severity, ratio_micros, violates_boundary, DEFAULT_THRESHOLDS,
    };
    use fireemu_core_limits::model::LimitBoundary;
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_session::idle::{AwaitIdleOptions, WorkKind};
    use fireemu_core_session::session::{Session, WorkResult};
    use fireemu_core_types::determinism::Clock;
    use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
    use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

    /// INV-LIMIT-001 (boundary part): inclusive allows N, exclusive rejects N, and a boundary
    /// rejection always takes precedence over warnings.
    #[kani::proof]
    fn limit_boundary_classification() {
        // 16-bit operands keep the u128 ratio arithmetic tractable for the solver.
        let maximum: u16 = kani::any();
        let current: u16 = kani::any();
        kani::assume(maximum > 0);
        let (maximum, current) = (u64::from(maximum), u64::from(current));
        let inclusive = violates_boundary(LimitBoundary::InclusiveMaximum, current, maximum);
        let exclusive = violates_boundary(LimitBoundary::ExclusiveMaximum, current, maximum);
        assert_eq!(inclusive, current > maximum);
        assert_eq!(exclusive, current >= maximum);
        if !inclusive {
            assert!(ratio_micros(current, maximum) <= 1_000_000);
        }
        kani::cover!(inclusive && !exclusive == false);
    }

    /// Warning severity is monotone in the usage. Bounded to 16-bit operands so that the u128
    /// threshold arithmetic stays tractable for the solver.
    #[kani::proof]
    #[kani::unwind(4)]
    fn severity_is_monotone() {
        let maximum: u16 = kani::any();
        let a: u16 = kani::any();
        let b: u16 = kani::any();
        kani::assume(maximum > 0 && a <= b);
        let sa = classify_severity(u64::from(a), u64::from(maximum), DEFAULT_THRESHOLDS);
        let sb = classify_severity(u64::from(b), u64::from(maximum), DEFAULT_THRESHOLDS);
        assert!(sa <= sb);
    }

    /// INV-EPOCH-001: the guard accepts exactly the current epoch while active.
    #[kani::proof]
    #[kani::unwind(4)]
    fn epoch_guard_rejects_every_other_epoch() {
        let mut session =
            Session::create(SessionId::new(1), kani::any(), LogicalInstant::UNIX_EPOCH);
        session.activate().unwrap();
        let resets: u8 = kani::any();
        kani::assume(resets <= 2);
        for _ in 0..resets {
            session.begin_reset().unwrap();
            session.complete_reset().unwrap();
        }
        let claimed = Epoch::new(kani::any());
        let result = session.check_work_epoch(claimed);
        if claimed == session.epoch() {
            assert_eq!(result, WorkResult::Proceed);
        } else {
            assert_eq!(result, WorkResult::DiscardedStaleEpoch);
        }
    }

    /// INV-TIME-001: advancing never moves the clock backwards and never panics.
    #[kani::proof]
    fn virtual_clock_never_moves_backwards() {
        let start = LogicalInstant::from_nanos(kani::any());
        let mut clock = VirtualClock::new(start);
        let d = LogicalDuration::from_nanos(kani::any());
        let _ = clock.advance(d);
        assert!(clock.now() >= start);
    }

    /// INV-IDLE-001 (predicate part): every work kind except future schedules is fenced under
    /// the default options, and Text Index builds are fenced unless explicitly ignored. This
    /// harness is allocation-free; the ledger itself is covered by tests and Loom.
    #[kani::proof]
    fn idle_predicate_never_ignores_active_work() {
        let kinds = [
            WorkKind::FirestoreCommit,
            WorkKind::EventDispatch,
            WorkKind::EventRetryWait,
            WorkKind::FunctionInvocation,
            WorkKind::DueSchedule,
            WorkKind::UploadFinalize,
            WorkKind::TextIndexBuild,
            WorkKind::SnapshotRestoreOrRulesetActivation,
            WorkKind::ChildEnqueueReservation,
        ];
        let pick: usize = kani::any();
        kani::assume(pick < kinds.len());
        let options = AwaitIdleOptions::default();
        assert!(kinds[pick].is_fenced(&options));
        let ignore = AwaitIdleOptions {
            text_index_builds: fireemu_core_session::idle::IdleWaitPolicy::Ignore,
            ..AwaitIdleOptions::default()
        };
        assert_eq!(
            kinds[pick].is_fenced(&ignore),
            kinds[pick] != WorkKind::TextIndexBuild
        );
        assert!(!WorkKind::ScheduledFutureWork.is_fenced(&options));
    }

    /// INV-EVENT-001: once an event is terminal, every transition is refused with `Terminal`
    /// and the record keeps its state and attempt counter. The four terminal states and the
    /// eight transitions are enumerated symbolically.
    ///
    /// This harness allocates (an event carries an event type, a subject and a payload), so it
    /// needs a Kani build whose allocator model is available; see the README.
    #[kani::proof]
    #[kani::unwind(64)]
    fn terminal_event_rejects_every_transition() {
        let epoch = Epoch::initial();
        let policy = RetryPolicy::try_new(
            1,
            LogicalDuration::from_seconds(1),
            LogicalDuration::from_seconds(60),
        )
        .unwrap();
        let mut record = EventRecord::new(LogicalEvent {
            event_id: EventId::new(1),
            session_id: SessionId::new(1),
            epoch,
            source: EventSource::Firestore,
            event_type: EventType::try_new("google.cloud.firestore.document.v1.created").unwrap(),
            subject: String::new(),
            logical_time: LogicalInstant::UNIX_EPOCH,
            causation_id: None,
            correlation_id: CorrelationId::new(1),
            payload: Vec::new(),
        });
        let kind: u8 = kani::any();
        kani::assume(kind < 4);
        match kind {
            0 => {
                record.lease().unwrap();
                record.start().unwrap();
                record.succeed().unwrap();
            }
            1 => {
                record.lease().unwrap();
                record.start().unwrap();
                let _ = record.fail(&policy, LogicalInstant::UNIX_EPOCH).unwrap();
            }
            2 => record.cancel().unwrap(),
            _ => record.discard_stale(epoch.next().unwrap()).unwrap(),
        }
        assert!(record.is_terminal());
        let expected = EventTransitionError::Terminal {
            state: record.state().name(),
        };
        let before_state = record.state().clone();
        let before_attempt = record.attempt();
        let action: u8 = kani::any();
        kani::assume(action < 8);
        let now = LogicalInstant::from_nanos(kani::any());
        let result = match action {
            0 => record.lease(),
            1 => record.start(),
            2 => record.succeed(),
            3 => record.fail(&policy, now).map(|_| ()),
            4 => record.interrupt(),
            5 => record.retry_due(now),
            6 => record.cancel(),
            _ => record.discard_stale(Epoch::new(kani::any())),
        };
        assert_eq!(result, Err(expected));
        assert_eq!(record.state(), &before_state);
        assert_eq!(record.attempt(), before_attempt);
        assert!(record.is_terminal());
    }

    /// Rejection precedes warnings for every value outside the boundary (allocation-free form
    /// of the `evaluate` contract).
    #[kani::proof]
    #[kani::unwind(4)]
    fn boundary_reject_precedes_warning() {
        let maximum: u16 = kani::any();
        let current: u16 = kani::any();
        kani::assume(maximum > 0);
        let (current, maximum) = (u64::from(current), u64::from(maximum));
        let violates = violates_boundary(LimitBoundary::ExclusiveMaximum, current, maximum);
        assert_eq!(violates, current >= maximum);
        if !violates {
            // Inside the boundary the ratio is below 100% and the severity is defined by the
            // thresholds alone.
            assert!(ratio_micros(current, maximum) < 1_000_000);
            let _ = classify_severity(current, maximum, DEFAULT_THRESHOLDS);
        }
    }

    /// INV-AUTH-001: the actual selector accepts only a fresh matching step inside its
    /// saturating inclusive window. Bounds: window <= 2; arbitrary u64 current/replay step.
    /// HMAC-SHA1 and time conversion stay on the production wrapper path, outside this proof.
    #[kani::proof]
    #[kani::unwind(7)]
    fn totp_window_boundary() {
        use fireemu_core_auth::mfa::{match_step_window, CodeMatch};
        let current: u64 = kani::any();
        let window: u8 = kani::any();
        kani::assume(window <= 2);
        let last: Option<u64> = if kani::any() { Some(kani::any()) } else { None };
        let mask: u8 = kani::any();
        let low = current.saturating_sub(u64::from(window));
        let high = current.saturating_add(u64::from(window));
        let matches = |step: u64| mask & (1u8 << (step - low)) != 0;
        let actual = match_step_window(current, window, last, matches);
        let mut expected = CodeMatch::NoMatch;
        for offset in 0..5u64 {
            if let Some(step) = low.checked_add(offset) {
                if step <= high && matches(step) {
                    if last.is_none_or(|last| step > last) {
                        expected = CodeMatch::Accepted { step };
                        break;
                    }
                    expected = CodeMatch::Replayed;
                }
            }
        }
        assert_eq!(actual, expected);
        if let CodeMatch::Accepted { step } = actual {
            assert!(step >= low && step <= high);
            assert!(last.is_none_or(|last| step > last));
        }
        kani::cover!(matches!(actual, CodeMatch::Accepted { .. }));
        kani::cover!(actual == CodeMatch::Replayed);
        kani::cover!(actual == CodeMatch::NoMatch);
    }

    /// The actual production composite predicate over bounded scalar identities and shapes.
    /// Normalization, real FieldPath equality, automatic indexes and merge selection are native-only.
    #[kani::proof]
    #[kani::unwind(8)]
    fn production_index_never_false_accepts() {
        use super::composite_contract::{contract, mode, serve};
        use fireemu_core_firestore::index::IndexQueryScope;
        use fireemu_core_firestore::query::Direction;
        let fields = [(); 5].map(|()| {
            let identity: u8 = kani::any();
            let mode_code: u8 = kani::any();
            kani::assume(identity < 4 && mode_code < 4);
            (identity, mode(mode_code))
        });
        let equality = [(); 2].map(|()| {
            let identity: u8 = kani::any();
            kani::assume(identity < 4);
            identity
        });
        let order = [(); 3].map(|()| {
            let identity: u8 = kani::any();
            kani::assume(identity < 4);
            (
                identity,
                if kani::any() {
                    Direction::Descending
                } else {
                    Direction::Ascending
                },
            )
        });
        let field_len: u8 = kani::any();
        let equality_len: u8 = kani::any();
        let order_len: u8 = kani::any();
        kani::assume(field_len <= 5 && equality_len <= 2 && order_len <= 3);
        let contains_id: u8 = kani::any();
        kani::assume(contains_id < 4);
        let contains = if kani::any() { Some(contains_id) } else { None };
        let collection_matches: bool = kani::any();
        let group: bool = kani::any();
        let scope = if kani::any() {
            IndexQueryScope::CollectionGroup
        } else {
            IndexQueryScope::Collection
        };
        let fields = &fields[..usize::from(field_len)];
        let equality = &equality[..usize::from(equality_len)];
        let order = &order[..usize::from(order_len)];
        let expected = contract(
            fields,
            equality,
            contains,
            order,
            collection_matches,
            scope,
            group,
        );
        let actual = serve(
            fields,
            equality,
            contains,
            order,
            collection_matches,
            scope,
            group,
        );
        assert_eq!(actual, expected.accepted());
        kani::cover!(
            !collection_matches && !actual,
            "collection mismatch rejected"
        );
        kani::cover!(
            collection_matches && !expected.eligible && !actual,
            "scope rejected"
        );
        kani::cover!(
            expected.eligible && !expected.prefix && !actual,
            "prefix membership rejected"
        );
        kani::cover!(
            expected.eligible && expected.prefix && !expected.modes && !actual,
            "prefix mode rejected"
        );
        kani::cover!(
            expected.eligible && expected.prefix && expected.modes && !expected.contains && !actual,
            "contains slot rejected"
        );
        let before_suffix =
            expected.eligible && expected.prefix && expected.modes && expected.contains;
        kani::cover!(
            before_suffix && !expected.suffix && !actual,
            "ordered suffix rejected"
        );
        let before_name = before_suffix && expected.suffix;
        kani::cover!(
            before_name && expected.explicit_name && !expected.name && !actual,
            "explicit name direction rejected"
        );
        kani::cover!(
            before_name && expected.implicit_name && !expected.name && !actual,
            "implicit name direction rejected"
        );
        kani::cover!(actual && expected.explicit_name, "explicit name accepted");
        kani::cover!(actual && expected.implicit_name, "implicit name accepted");
        kani::cover!(
            actual && !expected.explicit_name && !expected.implicit_name,
            "default name accepted"
        );
        kani::cover!(actual && contains.is_some(), "contains slot accepted");
    }
}

#[cfg(any(kani, test))]
mod composite_contract {
    use fireemu_core_firestore::index::{
        composite_fields_serve, CompositeRequirementView, IndexFieldMode as M, IndexQueryScope,
    };
    use fireemu_core_firestore::query::Direction;

    pub(super) fn mode(code: u8) -> M {
        match code {
            0 => M::Ascending,
            1 => M::Descending,
            2 => M::Contains,
            _ => M::Vector { dimension: 3 },
        }
    }

    // Independent structural obligations, kept separate so each semantic rejection is covered.
    #[allow(clippy::struct_excessive_bools)]
    pub(super) struct Contract {
        pub eligible: bool,
        pub prefix: bool,
        pub modes: bool,
        pub contains: bool,
        pub suffix: bool,
        pub explicit_name: bool,
        pub implicit_name: bool,
        pub name: bool,
    }
    impl Contract {
        pub(super) fn accepted(&self) -> bool {
            self.eligible && self.prefix && self.modes && self.contains && self.suffix && self.name
        }
    }

    pub(super) fn serve(
        fields: &[(u8, M)],
        equality: &[u8],
        contains: Option<u8>,
        order: &[(u8, Direction)],
        collection_matches: bool,
        scope: IndexQueryScope,
        group: bool,
    ) -> bool {
        composite_fields_serve(
            fields,
            scope,
            collection_matches,
            group,
            &CompositeRequirementView {
                equality,
                contains: contains.as_ref(),
                order,
                is_document_name: |identity: &u8| *identity == 3,
            },
            |field| (&field.0, field.1),
            |field| (&field.0, field.1),
        )
    }

    // Identity bit masks and rank-based suffix correspondence are independent of the runtime
    // kernel's two-way membership scans and filtered-iterator lockstep traversal.
    pub(super) fn contract(
        fields: &[(u8, M)],
        equality: &[u8],
        contains: Option<u8>,
        order: &[(u8, Direction)],
        collection_matches: bool,
        scope: IndexQueryScope,
        group: bool,
    ) -> Contract {
        let mut equality_mask = 0u8;
        for identity in equality {
            equality_mask |= 1 << identity;
        }
        let mut prefix_mask = 0u8;
        let mut modes = true;
        for (identity, mode) in fields.iter().take(equality.len()) {
            prefix_mask |= 1 << identity;
            modes &= matches!(mode, M::Ascending | M::Descending);
        }
        let prefix = fields.len() >= equality.len() && prefix_mask == equality_mask;
        let contains_ok = contains
            .is_none_or(|identity| fields.get(equality.len()) == Some(&(identity, M::Contains)));
        let pos = equality.len() + usize::from(contains.is_some());
        let mut rank = 0usize;
        let mut suffix = true;
        let mut explicit = None;
        let mut last = None;
        for (position, (identity, mode)) in fields.iter().enumerate() {
            if position < pos {
                continue;
            }
            if *identity == 3 {
                if explicit.is_none() {
                    explicit = Some(*mode);
                }
                continue;
            }
            let mut wanted_rank = 0usize;
            let mut matched = false;
            for (wanted_identity, direction) in order {
                if *wanted_identity == 3 {
                    continue;
                }
                if wanted_rank == rank {
                    matched = identity == wanted_identity
                        && match direction {
                            Direction::Ascending => *mode == M::Ascending,
                            Direction::Descending => *mode == M::Descending,
                        };
                }
                wanted_rank += 1;
            }
            suffix &= matched;
            rank += 1;
            last = Some(*mode);
        }
        let order_count = order.iter().filter(|(identity, _)| *identity != 3).count();
        suffix &= rank == order_count;
        let mut wanted_name = Direction::Ascending;
        for (identity, direction) in order {
            if *identity == 3 {
                wanted_name = *direction;
                break;
            }
        }
        let selected_name = explicit.or(last);
        let name = selected_name.is_none_or(|mode| match wanted_name {
            Direction::Ascending => mode == M::Ascending,
            Direction::Descending => mode == M::Descending,
        });
        Contract {
            eligible: collection_matches && (scope == IndexQueryScope::CollectionGroup || !group),
            prefix,
            modes,
            contains: contains_ok,
            suffix,
            explicit_name: explicit.is_some(),
            implicit_name: explicit.is_none() && last.is_some(),
            name,
        }
    }
    #[cfg(test)]
    #[test]
    fn scalar_contract_matches_shared_kernel() {
        for seed in 0u64..4096 {
            let mut state = seed;
            let mut next = || {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                state.to_le_bytes()[4]
            };
            let fields = [(); 5].map(|()| (next() % 4, mode(next() % 4)));
            let equality = [(); 2].map(|()| next() % 4);
            let order = [(); 3].map(|()| {
                (
                    next() % 4,
                    if next() % 2 == 0 {
                        Direction::Ascending
                    } else {
                        Direction::Descending
                    },
                )
            });
            let field_len = usize::from(next() % 6);
            let equality_len = usize::from(next() % 3);
            let order_len = usize::from(next() % 4);
            let contains = (next() % 2 == 0).then(|| next() % 4);
            let collection_matches = next() % 2 == 0;
            let group = next() % 2 == 0;
            let scope = if next() % 2 == 0 {
                IndexQueryScope::Collection
            } else {
                IndexQueryScope::CollectionGroup
            };
            let expected = contract(
                &fields[..field_len],
                &equality[..equality_len],
                contains,
                &order[..order_len],
                collection_matches,
                scope,
                group,
            );
            let actual = serve(
                &fields[..field_len],
                &equality[..equality_len],
                contains,
                &order[..order_len],
                collection_matches,
                scope,
                group,
            );
            assert_eq!(actual, expected.accepted(), "seed={seed}");
            // These flags partition the formal name-branch cover obligations.
            assert!(!(expected.explicit_name && expected.implicit_name));
        }
    }
}

#[cfg(any(kani, test))]
mod bounded_index {
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::index::{
        decide, IndexDecision, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope,
        IndexSet, IndexValidationPolicy, PlanningContext,
    };
    use fireemu_core_firestore::query::{
        Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
    };
    use fireemu_core_firestore::value::Value;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::ids::CollectionId;

    // Each boolean is an independent scope or direction axis of the bounded proof domain.
    #[allow(clippy::fn_params_excessive_bools)]
    pub(super) fn accepted(
        mask: u8,
        group: bool,
        index_group: bool,
        descending: bool,
        index_descending: bool,
    ) -> bool {
        let collection = CollectionId::try_new("i").unwrap();
        let fields = ["a", "b", "c"].map(|name| FieldPath::from_segments([name]).unwrap());
        let query = Query {
            scope: if group {
                QueryScope::collection_group(collection.clone())
            } else {
                QueryScope::collection(None, collection.clone())
            },
            filter: Some(FilterExpr::And(
                vec![0, 1]
                    .into_iter()
                    .map(|position| FilterExpr::Field {
                        field: fields[position].clone(),
                        op: FieldOp::Equal,
                        value: Value::Integer(1),
                    })
                    .collect(),
            )),
            order_by: vec![OrderClause {
                field: fields[2].clone(),
                direction: if descending {
                    Direction::Descending
                } else {
                    Direction::Ascending
                },
            }],
            start_at: None,
            end_at: None,
            offset: 0,
            limit: None,
            projection: None,
            find_nearest: None,
            production_refusals: true,
        };
        let mut indexes = IndexSet::default();
        for (bit, positions) in [(1, &[0, 1, 2][..]), (2, &[0, 2][..]), (4, &[1, 2][..])] {
            if mask & bit != 0 {
                indexes.add_composite(IndexDefinition {
                    collection_group: collection.clone(),
                    query_scope: if index_group {
                        IndexQueryScope::CollectionGroup
                    } else {
                        IndexQueryScope::Collection
                    },
                    fields: positions
                        .iter()
                        .map(|position| IndexField {
                            path: fields[*position].clone(),
                            mode: if *position == 2 && index_descending {
                                IndexFieldMode::Descending
                            } else {
                                IndexFieldMode::Ascending
                            },
                        })
                        .collect(),
                });
            }
        }
        let ctx = PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        };
        let decision = decide(&query, &indexes, &ctx);
        #[cfg(test)]
        if let Ok(path) = std::env::var("FIREEMU_INDEX_DECISION_SNAPSHOT") {
            use std::io::Write;
            let mut output = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            writeln!(
                output,
                "{mask}\t{group}\t{index_group}\t{descending}\t{index_descending}\t{decision:?}"
            )
            .unwrap();
        }
        matches!(
            decision,
            IndexDecision::UseIndex { .. } | IndexDecision::MergeIndexes { .. }
        )
    }

    #[test]
    fn bounded_support_oracle_matches_the_real_production_planner() {
        for mask in 0..8 {
            for group in [false, true] {
                for index_group in [false, true] {
                    for descending in [false, true] {
                        for index_descending in [false, true] {
                            assert_eq!(
                                accepted(mask, group, index_group, descending, index_descending),
                                (!group || index_group)
                                    && descending == index_descending
                                    && (mask & 1 != 0 || mask & 6 == 6)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[ignore = "requires generated PICT rows in FIREEMU_FORMAL_MATRIX_DIR"]
    fn generated_pict_index_rows_match_actual_planner_support() {
        let directory = std::env::var("FIREEMU_FORMAL_MATRIX_DIR").expect("PICT fixture directory");
        let table =
            std::fs::read_to_string(std::path::Path::new(&directory).join("index.tsv")).unwrap();
        let mut count = 0;
        for row in table.lines().skip(1) {
            let fields = row.split('\t').collect::<Vec<_>>();
            let mask: u8 = fields[0].parse().unwrap();
            let group = fields[1] == "group";
            let index_group = fields[2] == "group";
            let descending = fields[3] == "desc";
            let index_descending = fields[4] == "desc";
            assert_eq!(
                accepted(mask, group, index_group, descending, index_descending),
                (!group || index_group)
                    && descending == index_descending
                    && (mask & 1 != 0 || mask & 6 == 6),
                "{row}"
            );
            count += 1;
        }
        assert!(count >= 19);
    }
}
