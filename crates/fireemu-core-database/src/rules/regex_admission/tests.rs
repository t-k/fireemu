use super::*;

#[test]
fn postincrement_guard_boundary() {
    assert_eq!(guard_count(1, 0), Ok(1));
    assert_eq!(guard_count(2, 0), Err(Failure::Resource));
    assert_eq!(guard_count(5001, 5000), Ok(5001));
    assert_eq!(guard_count(5002, 5000), Err(Failure::Resource));
}

#[test]
fn forced_finite_chain_counts_the_empty_successor_subset() {
    assert_eq!(exact_literal_count(1, 2), Ok(Some(4)));
    assert_eq!(exact_literal_count(0, 2), Ok(Some(2)));
    assert_eq!(exact_literal_count(1_000_000, 1), Ok(None));
    assert_eq!(exact_literal_count(1_000_000, 0), Ok(None));
    assert_eq!(exact_literal_count(u64::MAX, 2), Err(Failure::Inconclusive));
}

#[test]
fn counted_repetition_uses_java_signed_integer_domain() {
    assert_eq!(jar_integer("2147483647"), Ok(2147483647));
    assert_eq!(jar_integer("2147483648"), Err(Failure::Integer));
}

// Expected metadata and normalized minimal DFAs come from the pinned offline jar helper.
macro_rules! oracle_case {
    ($test:ident, $name:literal, $expected:literal) => {
        #[test]
        fn $test() {
            assert_eq!(trace_case($name).unwrap(), $expected);
        }
    };
}
oracle_case!(singleton_literal, "literal", "S\ttrue\tskip\tS:0061");
oracle_case!(
    singleton_concatenation,
    "concat-singleton",
    "S\ttrue\tskip\tS:0061,0062"
);
oracle_case!(
    exact_one_keeps_graph_tag,
    "exact-one",
    "G\ttrue\tskip\tG:0-[97-97:1,]1+[]"
);
oracle_case!(
    exact_two_forces_determinization,
    "exact-two",
    "G\tfalse\t4\tG:0-[97-97:1,]1-[97-97:2,]2+[]"
);
oracle_case!(
    empty_exact_two_stays_graph,
    "exact-empty-two",
    "G\tfalse\t2\tG:0+[]"
);
oracle_case!(
    collection_union_keeps_duplicate_copies,
    "union-duplicate",
    "G\tfalse\t3\tG:0-[97-97:1,]1+[]"
);
oracle_case!(
    optional_is_not_singleton,
    "optional",
    "G\tfalse\t3\tG:0+[97-97:1,]1+[]"
);
oracle_case!(star_empty_counts_sink, "star-empty", "G\tfalse\t2\tG:0+[]");
oracle_case!(
    star_a_minimizes_live_states,
    "star-a",
    "G\tfalse\t3\tG:0+[97-97:0,]"
);
oracle_case!(
    bounded_zero_two_preserves_acceptance,
    "bounded-zero-two",
    "G\tfalse\t4\tG:0+[97-97:1,]1+[97-97:2,]2+[]"
);
oracle_case!(
    graph_singleton_concat_stays_graph,
    "concat-graph-singleton",
    "G\tfalse\t4\tG:0-[97-97:1,]1-[98-98:2,]2+[]"
);

fn accepts(value: &Automaton, word: &[u16]) -> bool {
    let graph = value.expanded().unwrap();
    let mut current = BTreeSet::from([graph.initial]);
    for &unit in word {
        current = current
            .into_iter()
            .flat_map(|i| {
                graph.states[i]
                    .edges
                    .iter()
                    .filter(move |e| e.lo <= unit && unit <= e.hi)
                    .map(|e| e.to)
            })
            .collect();
    }
    current.into_iter().any(|i| graph.states[i].accept)
}

#[test]
fn bounded_algebra_minimization_preserves_every_small_word() {
    let seed = [
        Automaton::literal(""),
        Automaton::literal("a"),
        Automaton::literal("b"),
        Automaton::Graph(Graph::empty()),
    ];
    let mut values = seed.to_vec();
    for value in &seed {
        values.push(value.optional().unwrap());
        values.push(value.star().unwrap());
        for min in 0..=3 {
            for max in min..=3 {
                values.push(value.bounded(min, max).unwrap());
            }
        }
    }
    for a in &seed {
        for b in &seed {
            values.push(Automaton::concat(&[a.clone(), b.clone()]).unwrap());
            values.push(Automaton::collection_union(&[a.clone(), b.clone()]).unwrap());
        }
    }
    let mut words = vec![Vec::new()];
    for length in 1..=3 {
        for encoded in 0usize..4usize.pow(length) {
            let mut number = encoded;
            let mut word = Vec::new();
            for _ in 0..length {
                word.push([0, 97, 98, u16::MAX][number % 4]);
                number /= 4;
            }
            words.push(word);
        }
    }
    for original in values {
        let mut minimal = original.clone();
        minimal.minimize(5000).unwrap();
        for word in &words {
            assert_eq!(
                accepts(&original, word),
                accepts(&minimal, word),
                "{original:?}: {word:?}"
            );
        }
        if let Automaton::Graph(graph) = minimal {
            assert!(graph.deterministic);
            assert_eq!(graph.states.len(), graph.reachable().len());
        }
    }
}

#[test]
fn utf16_interval_boundaries_and_surrogates_are_not_unicode_scalars() {
    let graph = Graph {
        initial: 0,
        deterministic: false,
        states: vec![
            State {
                accept: false,
                edges: vec![
                    Edge {
                        lo: 0xd800,
                        hi: 0xdfff,
                        to: 1,
                    },
                    Edge {
                        lo: u16::MAX,
                        hi: u16::MAX,
                        to: 1,
                    },
                ],
            },
            State {
                accept: true,
                edges: Vec::new(),
            },
        ],
    };
    let original = Automaton::Graph(graph);
    let mut value = original.clone();
    assert_eq!(value.minimize(5000), Ok(Some(3)));
    for unit in [0, 0xd7ff, 0xd800, 0xdfff, 0xe000, u16::MAX] {
        assert_eq!(
            accepts(&value, &[unit]),
            unit == u16::MAX || (0xd800..=0xdfff).contains(&unit)
        );
    }
    let literal = Automaton::literal("\u{10000}");
    assert!(accepts(&literal, &[0xd800, 0xdc00]));
    assert!(!accepts(&literal, &[0xd800]));
}

#[test]
fn allocation_limits_are_inconclusive_and_never_resource_policy() {
    let value = Automaton::literal("a");
    assert!(matches!(
        value.bounded(0, 2147483647),
        Err(Failure::Inconclusive)
    ));
    assert_eq!(exact_literal_count(1, 2147483647), Ok(Some(2147483649)));
    assert_eq!(guard_count(2147483649, 5000), Err(Failure::Resource));
}

#[test]
fn counted_integer_leading_zeroes_preserve_value() {
    assert_eq!(
        jar_integer("0000000000000000000000000000000000000000000001"),
        Ok(1)
    );
}

#[test]
fn nullable_concatenation_copies_acceptance_independently_of_minimization() {
    let mut left = Automaton::literal("a").star().unwrap();
    let mut right = Automaton::literal("b").optional().unwrap();
    left.minimize(5000).unwrap();
    right.minimize(5000).unwrap();
    let mut value = Automaton::concat(&[left, right]).unwrap();
    let Automaton::Graph(before) = &value else {
        panic!("the graph tag must survive");
    };
    assert!(!before.deterministic);
    assert!(accepts(&value, &[]));
    assert_eq!(value.minimize(5000), Ok(Some(3)));
    // Direct offline jar reference: concat(minimized a*, minimized b?).
    assert_eq!(value.normal(), "G:0+[97-97:0,98-98:1,]1+[]");
}

#[test]
fn symbolic_bounded_matches_every_small_explicit_partial_dfa() {
    // Every two-state partial deterministic graph over {a,b}, all accepting sets.
    for accept in 0..4 {
        for encoding in 0..81 {
            let mut transitions = encoding;
            let mut graph = Graph {
                states: vec![State::default(); 2],
                initial: 0,
                deterministic: true,
            };
            for i in 0..2 {
                graph.states[i].accept = accept & (1 << i) != 0;
                for unit in [97, 98] {
                    let target = transitions % 3;
                    transitions /= 3;
                    if target != 0 {
                        graph.states[i].edges.push(Edge {
                            lo: unit,
                            hi: unit,
                            to: target - 1,
                        });
                    }
                }
            }
            graph.minimize(5000).unwrap();
            for min in 0..=3 {
                for max in min..=3 {
                    let mut explicit = Automaton::Graph(graph.clone()).bounded(min, max).unwrap();
                    let expected_count = explicit.minimize(5000).unwrap();
                    let (actual, count) = symbolic::bounded(&graph, min, max, 5000).unwrap();
                    assert_eq!(
                        count, expected_count,
                        "accept={accept} graph={encoding} min={min} max={max}"
                    );
                    assert_eq!(
                        actual.normal(),
                        explicit.normal(),
                        "accept={accept} graph={encoding} min={min} max={max}"
                    );
                }
            }
        }
    }
}

fn minimized_graph(mut value: Automaton) -> Graph {
    value.minimize(5000).unwrap();
    value.expanded().unwrap()
}

#[test]
fn symbolic_nullable_huge_counts_preserve_constant_construction_cost() {
    let child = minimized_graph(Automaton::literal("a").star().unwrap());
    for copies in [2, 5000, i32::MAX as u32] {
        for min in [0, 1, copies] {
            let (value, count) = symbolic::bounded(&child, min, copies, 5000).unwrap();
            assert_eq!(count, Some(3));
            assert_eq!(value.normal(), "G:0+[97-97:0,]");
        }
    }
    let empty = minimized_graph(Automaton::literal(""));
    let (value, count) = symbolic::bounded(&empty, i32::MAX as u32, i32::MAX as u32, 5000).unwrap();
    assert_eq!(count, Some(2));
    assert_eq!(value.normal(), "G:0+[]");
}

#[test]
fn symbolic_nonnullable_huge_counts_follow_the_actual_chain_guard() {
    let child = minimized_graph(Automaton::literal("a"));
    assert_eq!(
        symbolic::count_only(&child, 4999, 4999, 5000),
        Ok(Some(5001))
    );
    assert_eq!(
        symbolic::count_only(&child, 5000, 5000, 5000),
        Err(Failure::Resource)
    );
    assert_eq!(
        symbolic::count_only(&child, i32::MAX as u32, i32::MAX as u32, 5000),
        Err(Failure::Resource)
    );
}

#[test]
fn symbolic_nullable_progress_is_not_silently_clamped() {
    let left = minimized_graph(Automaton::literal("a").star().unwrap());
    let right = minimized_graph(Automaton::literal("b").optional().unwrap());
    let child = minimized_graph(
        Automaton::concat(&[Automaton::Graph(left), Automaton::Graph(right)]).unwrap(),
    );
    // Independent fresh-copy/BFS proof: root + M a-suffixes + M b-suffixes + sink.
    // The two progress families give 2M+2, rather than the earlier M+3 expectation.
    for (copies, expected) in [(2, 6), (3, 8), (10, 22), (2499, 5000)] {
        assert_eq!(
            symbolic::count_only(&child, copies, copies, 5000),
            Ok(Some(expected))
        );
    }
    assert_eq!(
        symbolic::count_only(&child, 2500, 2500, 5000),
        Err(Failure::Resource)
    );
    assert_eq!(
        symbolic::count_only(&child, i32::MAX as u32, i32::MAX as u32, 5000),
        Err(Failure::Resource)
    );
}

// Decoder for offline reference observations, not a regex literal admission parser.
fn reference_tree(source: &str) -> ast::Ast {
    struct Reader<'a> {
        text: &'a [u8],
        at: usize,
    }
    impl Reader<'_> {
        fn byte(&mut self, expected: u8) {
            assert_eq!(self.text[self.at], expected);
            self.at += 1;
        }
        fn number(&mut self) -> u32 {
            let start = self.at;
            while self.text.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
            std::str::from_utf8(&self.text[start..self.at])
                .unwrap()
                .parse()
                .unwrap()
        }
        fn tree(&mut self) -> ast::Ast {
            use ast::Ast;
            let kind = self.text[self.at];
            self.at += 1;
            if kind == b'E' {
                return Ast::Empty;
            }
            if kind == b'A' {
                return Ast::Any;
            }
            self.byte(b'(');
            let result = match kind {
                b'L' => Ast::Literal(self.number().try_into().unwrap()),
                b'R' => {
                    let lo = self.number().try_into().unwrap();
                    self.byte(b',');
                    Ast::Range(lo, self.number().try_into().unwrap())
                }
                b'S' => {
                    let mut units = Vec::new();
                    while self.text[self.at] != b')' {
                        units.push(self.number().try_into().unwrap());
                        if self.text[self.at] == b',' {
                            self.at += 1;
                        }
                    }
                    Ast::String(units)
                }
                b'U' | b'C' | b'I' => {
                    let a = Box::new(self.tree());
                    self.byte(b',');
                    let b = Box::new(self.tree());
                    match kind {
                        b'U' => Ast::Union(a, b),
                        b'C' => Ast::Concat(a, b),
                        _ => Ast::Intersection(a, b),
                    }
                }
                b'N' => Ast::Complement(Box::new(self.tree())),
                b'O' => Ast::Optional(Box::new(self.tree())),
                b'T' => Ast::Star(Box::new(self.tree())),
                b'M' => {
                    let n = self.number();
                    self.byte(b',');
                    Ast::Minimum(n, Box::new(self.tree()))
                }
                b'B' => {
                    let n = self.number();
                    self.byte(b',');
                    let m = self.number();
                    self.byte(b',');
                    Ast::Bounded(n, m, Box::new(self.tree()))
                }
                _ => panic!("invalid reference AST"),
            };
            self.byte(b')');
            result
        }
    }
    let mut reader = Reader {
        text: source.as_bytes(),
        at: 0,
    };
    let tree = reader.tree();
    assert_eq!(reader.at, source.len());
    tree
}

const OBSERVED_CANONICAL_TREES: [&str; 8] = [
    "U(C(M(1,C(B(2,3,U(O(T(L(107))),C(B(0,2,L(45)),T(U(L(93),L(97)))))),C(B(0,0,C(O(M(1,L(107))),C(M(1,R(64,91)),B(0,2,R(64,91))))),O(M(1,L(33)))))),C(B(2,3,U(C(B(0,0,L(45)),C(S(),T(R(65,122)))),C(B(0,2,R(32,126)),B(2,3,I(A,N(R(97,122))))))),R(48,57))),C(M(1,R(64,91)),C(O(T(C(M(1,L(45)),M(1,L(98))))),B(2,3,C(O(R(65,90)),O(M(1,R(90,97))))))))",
    "C(T(A),C(B(0,0,U(L(107),L(75))),C(O(M(1,U(B(2,2,I(A,N(U(L(97),L(65))))),C(B(2,3,R(48,57)),T(L(46)))))),C(B(2,3,U(C(U(L(97),L(65)),C(O(U(U(E,R(96,96)),U(R(96,123),R(96,123)))),M(1,U(E,U(R(97,122),R(65,90)))))),C(T(U(U(E,R(48,57)),U(E,U(R(97,102),R(65,70))))),M(1,U(U(E,R(96,96)),U(R(96,123),R(96,123))))))),T(A)))))",
    "C(T(A),C(B(0,0,U(L(107),L(75))),C(O(M(1,U(B(2,2,I(A,N(U(L(97),L(65))))),C(B(2,3,R(48,57)),T(L(46)))))),C(B(2,3,U(C(U(L(97),L(65)),C(O(U(U(E,R(96,96)),U(R(96,123),R(96,123)))),M(1,U(E,U(R(97,122),R(65,90)))))),C(T(U(U(E,R(48,57)),U(E,U(R(97,102),R(65,70))))),M(1,U(U(E,R(96,96)),U(R(96,123),R(96,123))))))),T(A)))))",
    "U(C(M(1,C(B(2,3,U(O(T(L(107))),C(B(0,2,L(45)),T(U(L(93),L(97)))))),C(B(0,0,C(O(M(1,L(107))),C(M(1,R(64,91)),B(0,2,R(64,91))))),O(M(1,L(33)))))),C(B(2,3,U(C(B(0,0,L(45)),C(S(),T(R(65,122)))),C(B(0,2,R(32,126)),B(2,3,I(A,N(R(97,122))))))),R(48,57))),C(M(1,R(64,91)),C(O(T(C(M(1,L(45)),M(1,L(98))))),B(2,3,C(O(R(65,90)),O(M(1,R(90,97))))))))",
    "C(B(2,3,U(C(O(M(1,U(U(E,R(33,64)),U(R(33,122),R(33,90))))),M(1,U(L(45),U(L(97),L(65))))),C(O(T(U(U(E,R(64,64)),U(R(64,91),R(64,91))))),C(M(1,U(C(B(0,0,A),B(2,2,I(A,N(U(E,U(R(97,122),R(65,90))))))),B(2,2,U(L(107),L(75))))),B(0,0,C(U(U(U(R(48,57),R(97,122)),U(R(65,90),L(95))),L(45)),U(U(E,U(R(122,122),R(90,90))),R(90,97)))))))),C(M(1,U(L(93),U(L(97),L(65)))),C(B(2,2,M(1,I(A,N(U(E,U(R(97,122),R(65,90))))))),T(A))))",
    "C(B(2,3,U(C(O(M(1,U(U(E,R(33,64)),U(R(33,122),R(33,90))))),M(1,U(L(45),U(L(97),L(65))))),C(O(T(U(U(E,R(64,64)),U(R(64,91),R(64,91))))),C(M(1,U(C(B(0,0,A),B(2,2,I(A,N(U(E,U(R(97,122),R(65,90))))))),B(2,2,U(L(107),L(75))))),B(0,0,C(U(U(U(R(48,57),R(97,122)),U(R(65,90),L(95))),L(45)),U(U(E,U(R(122,122),R(90,90))),R(90,97)))))))),C(M(1,U(L(93),U(L(97),L(65)))),C(B(2,2,M(1,I(A,N(U(E,U(R(97,122),R(65,90))))))),T(A))))",
    "U(C(T(A),C(B(2,2,B(2,2,U(C(B(2,2,B(2,2,I(A,N(U(U(U(L(97),L(65)),U(L(122),L(90))),U(L(97),L(65))))))),C(T(M(1,L(123))),O(O(U(L(122),L(90)))))),C(A,E)))),C(L(126),N(R(48,57))))),U(C(U(L(105),L(73)),U(L(98),L(66))),C(U(L(97),L(65)),C(L(93),C(U(U(E,U(U(E,R(45,64)),U(R(45,105),R(45,73)))),E),T(A))))))",
    "U(C(T(A),C(B(2,2,B(2,2,U(C(B(2,2,B(2,2,I(A,N(U(U(U(L(97),L(65)),U(L(122),L(90))),U(L(97),L(65))))))),C(T(M(1,L(123))),O(O(U(L(122),L(90)))))),C(A,E)))),C(L(126),N(R(48,57))))),U(C(U(L(105),L(73)),U(L(98),L(66))),C(U(L(97),L(65)),C(L(93),C(U(U(E,U(U(E,R(45,64)),U(R(45,105),R(45,73)))),E),T(A))))))",
];

macro_rules! observed_tree_case {
    ($name:ident,$index:expr) => {
        #[test]
        fn $name() {
            let mut trace = Vec::new();
            let result = reference_tree(OBSERVED_CANONICAL_TREES[$index]).compile(5000, &mut trace);
            assert!(
                matches!(result, Err(Failure::Resource)),
                "result={result:?} trace={trace:?}"
            );
        }
    };
}
observed_tree_case!(canonical_tree_observed_resource_row_1, 0);
observed_tree_case!(canonical_tree_observed_resource_row_2, 1);
observed_tree_case!(canonical_tree_observed_resource_row_3, 2);
observed_tree_case!(canonical_tree_observed_resource_row_4, 3);
observed_tree_case!(canonical_tree_observed_resource_row_5, 4);
observed_tree_case!(canonical_tree_observed_resource_row_6, 5);
observed_tree_case!(canonical_tree_observed_resource_row_7, 6);
observed_tree_case!(canonical_tree_observed_resource_row_8, 7);

#[test]
fn ascii_i_character_and_range_construction_matches_actual_jar_trees() {
    for (lo, hi, expected) in [
        (65, 90, "U(E,U(R(97,122),R(65,90)))"),
        (90, 97, "U(U(E,U(R(122,122),R(90,90))),R(90,97))"),
        (33, 90, "U(U(E,R(33,64)),U(R(33,122),R(33,90)))"),
        (65, 97, "U(U(E,U(R(97,122),R(65,90))),R(65,97))"),
        (97, 97, "U(E,U(R(97,97),R(65,65)))"),
        (122, 97, "E"),
    ] {
        assert_eq!(ast::Ast::ascii_range(lo, hi).unwrap().encode(), expected);
    }
    assert_eq!(ast::Ast::ascii_char(97).unwrap().encode(), "U(L(97),L(65))");
    assert_eq!(ast::Ast::ascii_char(45).unwrap().encode(), "L(45)");
    assert_eq!(
        ast::Ast::ascii_char(0x100).unwrap().encode(),
        "U(L(257),L(256))"
    );
}

#[test]
fn ast_compound_nodes_retain_constructor_observations() {
    for (tree, expected, guard, singleton, deterministic) in [
        ("C(L(97),L(98))", "S:0061,0062", None, true, true),
        ("B(1,1,L(97))", "G:0-[97-97:1,]1+[]", None, false, true),
        (
            "U(L(97),L(97))",
            "G:0-[97-97:1,]1+[]",
            Some(3),
            false,
            false,
        ),
        ("T(S())", "G:0+[]", Some(2), false, false),
        (
            "M(1,L(97))",
            "G:0-[97-97:1,]1+[97-97:1,]",
            Some(4),
            false,
            false,
        ),
    ] {
        let mut trace = Vec::new();
        let value = reference_tree(tree).compile(5000, &mut trace).unwrap();
        assert_eq!(value.normal(), expected);
        let node = trace.last().unwrap();
        assert_eq!(
            (node.guard, node.singleton, node.deterministic),
            (guard, singleton, deterministic)
        );
        assert!(!node.node.is_empty());
    }
}

#[test]
fn every_ascii_i_range_ast_matches_the_offline_jar_reference_digest() {
    let mut digest = 0xcbf29ce484222325u64;
    for lo in 0..128 {
        for hi in 0..128 {
            let encoded = ast::Ast::ascii_range(lo, hi).unwrap().encode() + "\n";
            for byte in encoded.bytes() {
                digest ^= u64::from(byte);
                digest = digest.wrapping_mul(1099511628211);
            }
        }
    }
    assert_eq!(digest, 9261829714427812715);
}

fn denotes(tree: &ast::Ast, word: &[u16]) -> bool {
    use ast::Ast;
    fn repeated(tree: &Ast, word: &[u16], min: u32, max: u32) -> bool {
        let mut ends = vec![false; word.len() + 1];
        ends[0] = true;
        if min == 0 && word.is_empty() {
            return true;
        }
        for count in 1..=max {
            let mut next = vec![false; word.len() + 1];
            for start in 0..=word.len() {
                if ends[start] {
                    for end in start..=word.len() {
                        if denotes(tree, &word[start..end]) {
                            next[end] = true;
                        }
                    }
                }
            }
            ends = next;
            if count >= min && ends[word.len()] {
                return true;
            }
        }
        false
    }
    match tree {
        Ast::Empty => false,
        Ast::Any => word.len() == 1,
        Ast::Literal(c) => word == [*c],
        Ast::String(s) => word == s,
        Ast::Range(lo, hi) => word.len() == 1 && *lo <= word[0] && word[0] <= *hi,
        Ast::Union(a, b) => denotes(a, word) || denotes(b, word),
        Ast::Intersection(a, b) => denotes(a, word) && denotes(b, word),
        Ast::Complement(a) => !denotes(a, word),
        Ast::Concat(a, b) => {
            (0..=word.len()).any(|i| denotes(a, &word[..i]) && denotes(b, &word[i..]))
        }
        Ast::Optional(a) => word.is_empty() || denotes(a, word),
        Ast::Star(a) => {
            let mut ends = vec![false; word.len() + 1];
            ends[0] = true;
            for start in 0..word.len() {
                if ends[start] {
                    for end in start + 1..=word.len() {
                        if denotes(a, &word[start..end]) {
                            ends[end] = true;
                        }
                    }
                }
            }
            ends[word.len()]
        }
        Ast::Minimum(min, a) => (0..=word.len()).any(|i| {
            repeated(a, &word[..i], *min, *min) && denotes(&Ast::Star(a.clone()), &word[i..])
        }),
        Ast::Bounded(min, max, a) => repeated(a, word, *min, *max),
    }
}

#[test]
fn canonical_ast_compiler_preserves_small_language_denotation() {
    use ast::Ast;
    let seeds = [
        Ast::Empty,
        Ast::Any,
        Ast::Literal(97),
        Ast::Literal(98),
        Ast::String(Vec::new()),
        Ast::String(vec![97, 98]),
        Ast::Range(97, 98),
    ];
    let mut trees = seeds.to_vec();
    for a in &seeds {
        for b in &seeds {
            trees.push(Ast::Union(Box::new(a.clone()), Box::new(b.clone())));
            trees.push(Ast::Concat(Box::new(a.clone()), Box::new(b.clone())));
            trees.push(Ast::Intersection(Box::new(a.clone()), Box::new(b.clone())));
        }
    }
    for a in &seeds {
        trees.push(Ast::Complement(Box::new(a.clone())));
        trees.push(Ast::Optional(Box::new(a.clone())));
        trees.push(Ast::Star(Box::new(a.clone())));
        for min in 0..=3 {
            trees.push(Ast::Minimum(min, Box::new(a.clone())));
            for max in min..=3 {
                trees.push(Ast::Bounded(min, max, Box::new(a.clone())));
            }
        }
    }
    let mut words = vec![Vec::new()];
    for length in 1..=3 {
        for encoded in 0usize..4usize.pow(length) {
            let mut word = Vec::new();
            let mut number = encoded;
            for _ in 0..length {
                word.push([0, 97, 98, u16::MAX][number % 4]);
                number /= 4;
            }
            words.push(word);
        }
    }
    for tree in trees {
        let value = tree.compile(5000, &mut Vec::new()).unwrap();
        for word in &words {
            assert_eq!(
                accepts(&value, word),
                denotes(&tree, word),
                "{} on {word:?}",
                tree.encode()
            );
        }
    }
}

#[test]
fn canonical_resource_children_are_compiled_before_zero_or_intersection_operations() {
    use ast::Ast;
    for source in OBSERVED_CANONICAL_TREES {
        let child = reference_tree(source);
        for tree in [
            Ast::Bounded(0, 0, Box::new(child.clone())),
            Ast::Intersection(Box::new(Ast::String(Vec::new())), Box::new(child)),
        ] {
            let result = tree.compile(5000, &mut Vec::new());
            assert!(
                matches!(result, Err(Failure::Resource)),
                "tree={} result={result:?}",
                tree.encode()
            );
        }
    }
}

#[test]
fn canonical_concat_flattens_empty_resource_operand_as_actual_jar() {
    // The independent actual-jar wrapper driver confirms this exact row2 counterexample.
    // It is a regex-internal operation, not a bypass around JS literal validation.
    let tree = ast::Ast::Concat(
        Box::new(ast::Ast::Empty),
        Box::new(reference_tree(OBSERVED_CANONICAL_TREES[1])),
    );
    let mut trace = Vec::new();
    let value = tree.compile(5000, &mut trace).unwrap();
    assert_eq!(value.normal(), "G:0-[]");
    let last = trace.last().unwrap();
    assert_eq!(
        (last.node, last.singleton, last.deterministic, last.guard),
        ("concat", false, true, None)
    );
}

#[test]
fn minimum_operator_observations_match_every_small_offline_jar_case() {
    let mut digest = 0xcbf29ce484222325u64;
    for accept in 0..4 {
        for encoding in 0..81 {
            let mut transitions = encoding;
            let mut graph = Graph {
                states: vec![State::default(); 2],
                initial: 0,
                deterministic: true,
            };
            for i in 0..2 {
                graph.states[i].accept = accept & (1 << i) != 0;
                for unit in [97, 98] {
                    let target = transitions % 3;
                    transitions /= 3;
                    if target != 0 {
                        graph.states[i].edges.push(Edge {
                            lo: unit,
                            hi: unit,
                            to: target - 1,
                        });
                    }
                }
            }
            graph.minimize(5000).unwrap();
            for minimum in 0..=3 {
                let mut value = Automaton::Graph(graph.clone()).minimum(minimum).unwrap();
                let (tag, det) = match &value {
                    Automaton::Singleton(_) => ("S", true),
                    Automaton::Graph(g) => ("G", g.deterministic),
                };
                let count = value
                    .minimize(5000)
                    .unwrap()
                    .map_or("skip".to_owned(), |n| n.to_string());
                let row = format!(
                    "{accept},{encoding},{minimum}\t{tag}\t{det}\t{count}\t{}\n",
                    value.normal()
                );
                for byte in row.bytes() {
                    digest ^= u64::from(byte);
                    digest = digest.wrapping_mul(1099511628211);
                }
            }
        }
    }
    assert_eq!(digest, 10771812847959391979);
}

#[test]
fn minimum_parent_guard_keeps_the_unminimized_star_tail() {
    let child = reference_tree("C(T(L(97)),O(L(98)))");
    let mut trace = Vec::new();
    let value = ast::Ast::Minimum(1, Box::new(child))
        .compile(5000, &mut trace)
        .unwrap();
    assert_eq!(trace.last().unwrap().guard, Some(6));
    assert_eq!(value.normal(), "G:0+[97-98:0,]");
}

const OBSERVED_LITERAL_PATTERNS: [(&str, bool); 8] = [
    (
        r###"^((k*?|-{0,2}[\]a]*){2,3}(k+?[@-[]+[@-[]{0,2}){0}!+?)+(-{0}()[A-z]*|[ -~]{0,2}[^a-z]{2,3}){2,3}\d|[@-[]+(\-+b+)*?([A-Z]?[Z-a]+?){2,3}$"###,
        false,
    ),
    (
        r###"k{0}([^a]{2}|[\d]{2,3}\.*)+?(a[`-{]?[A-Z]+|[0-9a-f]*[`-{]+){2,3}"###,
        true,
    ),
    (
        r###"k{0}([^a]{2}|[\d]{2,3}\.*)+?(a[`-{]?[A-Z]+|[0-9a-f]*[`-{]+){2,3}"###,
        true,
    ),
    (
        r###"^((k*?|-{0,2}[\]a]*){2,3}(k+?[@-[]+[@-[]{0,2}){0}!+?)+(-{0}()[A-z]*|[ -~]{0,2}[^a-z]{2,3}){2,3}\d|[@-[]+(\-+b+)*?([A-Z]?[Z-a]+?){2,3}$"###,
        false,
    ),
    (
        r###"^([!-Z]+?[-a]+|[@-[]*?(.{0}[^a-z]{2}|k{2})+([\w-][Z-a]){0}){2,3}[\]a]+([^a-z]+){2}"###,
        true,
    ),
    (
        r###"^([!-Z]+?[-a]+|[@-[]*?(.{0}[^a-z]{2}|k{2})+([\w-][Z-a]){0}){2,3}[\]a]+([^a-z]+){2}"###,
        true,
    ),
    (
        r###"([^AZ\\a]{2}{2}\{+*Z??|.[i- ]){2}{2}[~]\D|IB|[a][\]][y-s\--I0-\-]"###,
        true,
    ),
    (
        r###"([^AZ\\a]{2}{2}\{+*Z??|.[i- ]){2}{2}[~]\D|IB|[a][\]][y-s\--I0-\-]"###,
        true,
    ),
];

macro_rules! observed_literal_case {
    ($name:ident,$index:expr) => {
        #[test]
        fn $name() {
            let (pattern, mode) = OBSERVED_LITERAL_PATTERNS[$index];
            let tree = reader::literal(pattern, mode).unwrap();
            assert_eq!(tree.encode(), OBSERVED_CANONICAL_TREES[$index]);
            assert!(matches!(
                tree.compile(5000, &mut Vec::new()),
                Err(Failure::Resource)
            ));
        }
    };
}
observed_literal_case!(canonical_literal_observed_row_1, 0);
observed_literal_case!(canonical_literal_observed_row_2, 1);
observed_literal_case!(canonical_literal_observed_row_3, 2);
observed_literal_case!(canonical_literal_observed_row_4, 3);
observed_literal_case!(canonical_literal_observed_row_5, 4);
observed_literal_case!(canonical_literal_observed_row_6, 5);
observed_literal_case!(canonical_literal_observed_row_7, 6);
observed_literal_case!(canonical_literal_observed_row_8, 7);

#[test]
fn canonical_literal_reader_matches_independent_jar_grammar_cases() {
    for (source, mode, expected) in [
        (r###"^a**$"###, false, "T(T(L(97)))"),
        (r###"^a+?$"###, false, "O(M(1,L(97)))"),
        (r###"^(|a)$"###, false, "S(124,97)"),
        (r###"^(a|))$"###, false, "U(L(97),L(41))"),
        (r###"^[a-\d]$"###, false, "R(97,100)"),
        (r###"^[\\a]$"###, false, "L(97)"),
        (
            r###"^\W$"###,
            false,
            "N(U(U(R(48,57),R(97,122)),U(R(65,90),L(95))))",
        ),
        (r###"^\n$"###, false, "L(110)"),
        (r###"^"$"###, false, "L(34)"),
        (
            r###"^a{2147483647}$"###,
            false,
            "B(2147483647,2147483647,L(97))",
        ),
        (
            r###"^a{0000000000000000000000000000000000000000000001}$"###,
            false,
            "B(1,1,L(97))",
        ),
        (r###"^a{2,1}$"###, false, "B(2,1,L(97))"),
        (r###"^😀$"###, false, "S(55357,56832)"),
        (r###"^[￾-￿]$"###, false, "R(65534,65535)"),
        (r###"^$"###, false, "S()"),
        (r###""###, false, "C(T(A),T(A))"),
        (r###"^abc$"###, false, "S(97,98,99)"),
        (r###"a|b"###, false, "U(C(T(A),L(97)),C(L(98),T(A)))"),
        (r###"^[A-Z]$"###, true, "U(E,U(R(97,122),R(65,90)))"),
        (
            r###"^[Z-a]$"###,
            true,
            "U(U(E,U(R(122,122),R(90,90))),R(90,97))",
        ),
        (r###"^a$"###, true, "U(L(97),L(65))"),
    ] {
        assert_eq!(
            reader::literal(source, mode).unwrap().encode(),
            expected,
            "{source}"
        );
    }
    assert!(matches!(
        reader::literal("^a{2147483648}$", false),
        Err(Failure::Integer)
    ));
    assert_eq!(
        reader::literal("^İ$", true).unwrap().encode(),
        "U(L(105),L(304))"
    );
}

#[test]
fn symbolic_minimum_matches_explicit_algebra_and_all_small_jar_observations() {
    let mut digest = 0xcbf29ce484222325u64;
    for accept in 0..4 {
        for encoding in 0..81 {
            let mut transitions = encoding;
            let mut child = Graph {
                states: vec![State::default(); 2],
                initial: 0,
                deterministic: true,
            };
            for i in 0..2 {
                child.states[i].accept = accept & (1 << i) != 0;
                for unit in [97, 98] {
                    let target = transitions % 3;
                    transitions /= 3;
                    if target != 0 {
                        child.states[i].edges.push(Edge {
                            lo: unit,
                            hi: unit,
                            to: target - 1,
                        });
                    }
                }
            }
            child.minimize(5000).unwrap();
            for minimum in 0..=3 {
                let mut explicit = Automaton::Graph(child.clone()).minimum(minimum).unwrap();
                let expected_count = explicit.minimize(5000).unwrap();
                let (actual, count) = minimum::compile(&child, minimum, 5000).unwrap();
                assert_eq!(
                    count, expected_count,
                    "accept={accept} graph={encoding} min={minimum}"
                );
                assert_eq!(
                    actual.normal(),
                    explicit.normal(),
                    "accept={accept} graph={encoding} min={minimum}"
                );
                let row = format!(
                    "{accept},{encoding},{minimum}\tG\t{}\t{}\t{}\n",
                    count.is_none(),
                    count.map_or("skip".to_owned(), |n| n.to_string()),
                    actual.normal()
                );
                for byte in row.bytes() {
                    digest ^= u64::from(byte);
                    digest = digest.wrapping_mul(1099511628211);
                }
            }
        }
    }
    assert_eq!(digest, 10771812847959391979);
}

#[test]
fn symbolic_minimum_preserves_actual_unminimized_tail_counterexample() {
    let child = minimized_graph(
        reference_tree("C(T(L(97)),O(L(98)))")
            .compile(5000, &mut Vec::new())
            .unwrap(),
    );
    let (value, count) = minimum::compile(&child, 1, 5000).unwrap();
    assert_eq!(count, Some(6));
    assert_eq!(value.normal(), "G:0+[97-98:0,]");
}

#[test]
fn symbolic_minimum_huge_literal_follows_the_true_guard() {
    let child = minimized_graph(Automaton::literal("a"));
    assert_eq!(minimum::count_only(&child, 0, 5000), Ok(Some(3)));
    assert_eq!(minimum::count_only(&child, 4998, 5000), Ok(Some(5001)));
    assert_eq!(
        minimum::count_only(&child, 4999, 5000),
        Err(Failure::Resource)
    );
    assert_eq!(
        minimum::count_only(&child, i32::MAX as u32, 5000),
        Err(Failure::Resource)
    );
}

#[test]
fn symbolic_minimum_huge_nullable_and_empty_shortcuts_are_not_copy_caps() {
    let star = minimized_graph(Automaton::literal("a").star().unwrap());
    let (value, count) = minimum::compile(&star, i32::MAX as u32, 5000).unwrap();
    assert_eq!(count, Some(3));
    assert_eq!(value.normal(), "G:0+[97-97:0,]");
    let epsilon = minimized_graph(Automaton::literal(""));
    assert_eq!(
        minimum::count_only(&epsilon, i32::MAX as u32, 5000),
        Ok(Some(2))
    );
    let empty = Graph::empty();
    let (value, count) = minimum::compile(&empty, i32::MAX as u32, 5000).unwrap();
    assert_eq!(count, None);
    assert_eq!(value.normal(), "G:0-[]");
    assert_eq!(minimum::count_only(&empty, 0, 5000), Ok(Some(2)));
}

#[test]
fn canonical_huge_minimum_literal_uses_symbolic_construction() {
    let tree = reader::literal("^a{2147483647,}$", false).unwrap();
    assert!(matches!(
        tree.compile(5000, &mut Vec::new()),
        Err(Failure::Resource)
    ));
}

#[test]
fn canonical_huge_nullable_minimum_is_not_an_implicit_copy_limit() {
    for (source, expected, count) in [
        ("^(a*){2147483647,}$", "G:0+[97-97:0,]", 3),
        ("^(){2147483647,}$", "G:0+[]", 2),
    ] {
        let mut trace = Vec::new();
        let value = reader::literal(source, false)
            .unwrap()
            .compile(5000, &mut trace)
            .unwrap();
        assert_eq!(value.normal(), expected);
        assert_eq!(trace.last().unwrap().guard, Some(count));
    }
}

#[test]
fn java21_all_bmp_case_constructor_records() {
    // Full 65,536-record Java21 primitive oracle, pinned in the private receipt.
    let mut digest = 14695981039346656037_u64;
    for unit in 0..=u16::MAX {
        for byte in (ast::Ast::ascii_char(unit).unwrap().encode() + "\n").bytes() {
            digest = (digest ^ u64::from(byte)).wrapping_mul(1099511628211);
        }
    }
    assert_eq!(digest, 13610395294619413009);
}

#[test]
fn only_case_range_constructor_with_maximum_endpoint_is_nonterminating() {
    assert_eq!(
        format!("{:?}", ast::Ast::ascii_range(65534, 65535)),
        "Err(NonTerminatingCanonicalConstruction)"
    );
    assert_eq!(ast::Ast::ascii_char(65535).unwrap().encode(), "L(65535)");
    assert_eq!(
        reader::literal("^[\u{fffe}-\u{ffff}]$", false)
            .unwrap()
            .encode(),
        "R(65534,65535)"
    );
    assert!(reader::literal("^.$", true).is_ok());
    assert!(reader::literal("^\\D$", true).is_ok());
}

#[test]
fn unicode_range_trees_match_pinned_actual_jar() {
    for (lo, hi, expected) in [
        (127, 304, 4244167995726107161),
        (304, 305, 16992878993420153695),
        (383, 384, 9989053418628567423),
        (8490, 8491, 10980001434733955442),
        (55295, 55297, 17496290649030190801),
        (65533, 65534, 5313257699847433550),
        (0, 65534, 14200542552053570895),
        (1000, 100, 12638217986881231904),
        (65, 65534, 17308574090342897842),
    ] {
        let mut digest = 14695981039346656037_u64;
        for byte in ast::Ast::ascii_range(lo, hi).unwrap().encode().bytes() {
            digest = (digest ^ u64::from(byte)).wrapping_mul(1099511628211);
        }
        assert_eq!(digest, expected, "range {lo}..{hi}");
    }
}

#[test]
fn reader_has_no_prototype_group_or_source_length_refusal() {
    let deep = "^(".to_owned() + &"(".repeat(9999) + "a" + &")".repeat(10000) + "$";
    assert_eq!(
        reader::literal(&deep, false).unwrap(),
        ast::Ast::Literal(97)
    );
    let long = "^".to_owned() + &"a".repeat(30000) + "$";
    assert_eq!(
        reader::literal(&long, false).unwrap(),
        ast::Ast::String(vec![97; 30000])
    );
}

#[test]
fn reader_has_no_prototype_branch_class_or_repeat_part_refusal() {
    let branches = "^".to_owned() + &vec!["a"; 300].join("|") + "$";
    assert!(reader::literal(&branches, false).is_ok());
    let class = "^[".to_owned() + &"a".repeat(300) + "]$";
    assert!(reader::literal(&class, false).is_ok());
    let repeats = "^a".to_owned() + &"?".repeat(300) + "$";
    assert!(reader::literal(&repeats, false).is_ok());
}

#[test]
fn iterative_reader_matches_9331_actual_jar_short_grammar_trees() {
    fn visit(source: &mut String, remaining: usize, digest: &mut u64) {
        if remaining != 0 {
            for c in ['a', '|', '(', ')', '*', '?'] {
                source.push(c);
                visit(source, remaining - 1, digest);
                source.pop();
            }
            return;
        }
        let anchored = "^".to_owned() + source + "$";
        let record = match reader::literal(&anchored, false) {
            Ok(tree) => "OK\t".to_owned() + &tree.encode() + "\n",
            Err(Failure::Syntax) => "SYNTAX\n".to_owned(),
            other => panic!("unexpected {source:?}: {other:?}"),
        };
        for byte in record.bytes() {
            *digest = (*digest ^ u64::from(byte)).wrapping_mul(1099511628211);
        }
    }
    for (length, expected) in [
        3055408861054588246,
        7204934046240591565,
        5236810536733279,
        7751056885520992922,
        5032910289307481147,
        4491928091250344226,
    ]
    .into_iter()
    .enumerate()
    {
        let mut digest = 14695981039346656037_u64;
        visit(&mut String::new(), length, &mut digest);
        assert_eq!(digest, expected, "grammar length {length}");
    }
}

#[test]
fn deeply_nested_ast_compilation_and_disposal_use_bounded_native_stack() {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let source = "^a".to_owned() + &"?".repeat(10000) + "$";
            let tree = reader::literal(&source, false).unwrap();
            let mut trace = Vec::new();
            assert!(tree.compile(5000, &mut trace).is_ok());
            assert_eq!(trace.len(), 10001);
            drop(tree);
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn parse_error_disposes_deep_partial_trees_on_bounded_native_stack() {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| {
            let source = "^a".to_owned() + &"?".repeat(10000) + "($";
            assert!(matches!(
                reader::literal(&source, false),
                Err(Failure::Syntax)
            ));
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn locally_swept_unique_word_reaches_true_admitted_guard_boundary() {
    let mut graph = Automaton::Singleton((0..4999).collect())
        .expanded()
        .unwrap();
    graph.deterministic = false;
    assert_eq!(graph.minimize(5000), Ok(Some(5001)));
    assert_eq!(graph.states.len(), 5000);
    assert!(graph.states.iter().all(|state| state.edges.len() <= 1));
}

#[test]
fn exact_minimization_has_no_prototype_refinement_work_refusal() {
    let mut graph = Automaton::Singleton(vec![97; 3000]).expanded().unwrap();
    assert_eq!(graph.minimize(5000), Ok(None));
    assert_eq!(graph.states.len(), 3001);
}

#[test]
fn ordinary_determinization_refuses_at_discovery_before_frontier_storage() {
    let mut states = vec![State::default(); 20002];
    for unit in 0..20001_u16 {
        states[0].edges.push(Edge {
            lo: unit,
            hi: unit,
            to: usize::from(unit) + 1,
        });
        states[usize::from(unit) + 1].accept = true;
    }
    let mut graph = Graph {
        states,
        initial: 0,
        deterministic: false,
    };
    assert_eq!(graph.determinize(1), Err(Failure::Resource));
}

#[test]
fn local_sweep_preserves_overlapping_destination_reference_counts() {
    let mut graph = Graph {
        initial: 0,
        deterministic: false,
        states: vec![
            State {
                accept: false,
                edges: vec![
                    Edge {
                        lo: 97,
                        hi: 99,
                        to: 1,
                    },
                    Edge {
                        lo: 98,
                        hi: 100,
                        to: 1,
                    },
                ],
            },
            State {
                accept: true,
                edges: Vec::new(),
            },
        ],
    };
    assert_eq!(graph.minimize(5000), Ok(Some(3)));
    assert_eq!(graph.states.len(), 2);
    assert_eq!(
        graph.states[graph.initial].edges,
        vec![Edge {
            lo: 97,
            hi: 100,
            to: 1 - graph.initial
        }]
    );
    let value = Automaton::Graph(graph);
    for unit in 0..=u16::MAX {
        assert_eq!(accepts(&value, &[unit]), (97..=100).contains(&unit));
    }
}

#[test]
fn sparse_minimizer_matches_independent_pair_distinguishability_for_32768_dfas() {
    for code in 0..4096_usize {
        let mut targets = [[3; 2]; 4];
        let mut digits = code;
        for row in targets.iter_mut().take(3) {
            for to in row {
                let digit = digits % 4;
                digits /= 4;
                *to = if digit == 0 { 3 } else { digit - 1 };
            }
        }
        for mask in 0..8 {
            let accepting = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, false];
            let mut different = [[false; 4]; 4];
            for a in 0..4 {
                for b in 0..4 {
                    different[a][b] = accepting[a] != accepting[b];
                }
            }
            loop {
                let old = different;
                for a in 0..4 {
                    for b in 0..4 {
                        different[a][b] |= (0..2).any(|c| old[targets[a][c]][targets[b][c]]);
                    }
                }
                if old == different {
                    break;
                }
            }
            let mut reachable = vec![0];
            let mut cursor = 0;
            while cursor < reachable.len() {
                for to in targets[reachable[cursor]] {
                    if !reachable.contains(&to) {
                        reachable.push(to);
                    }
                }
                cursor += 1;
            }
            let mut representatives = Vec::new();
            for &q in &reachable {
                if different[q][3] && representatives.iter().all(|&r| different[q][r]) {
                    representatives.push(q);
                }
            }
            let expected = representatives.len().max(1);
            let mut graph = Graph {
                initial: 0,
                deterministic: true,
                states: (0..3)
                    .map(|q| State {
                        accept: accepting[q],
                        edges: (0..2)
                            .filter_map(|c| {
                                (targets[q][c] != 3).then_some(Edge {
                                    lo: 97 + c as u16,
                                    hi: 97 + c as u16,
                                    to: targets[q][c],
                                })
                            })
                            .collect(),
                    })
                    .collect(),
            };
            assert_eq!(graph.minimize(5000), Ok(None));
            assert_eq!(graph.states.len(), expected, "code={code} mask={mask}");
            assert!(
                graph
                    .states
                    .iter()
                    .flat_map(|s| &s.edges)
                    .all(|e| e.lo >= 97 && e.hi <= 98)
            );
            let dead = graph.states.len();
            let mut pairs = vec![(0, graph.initial)];
            let mut cursor = 0;
            while cursor < pairs.len() {
                let (a, b) = pairs[cursor];
                assert_eq!(
                    accepting[a],
                    b != dead && graph.states[b].accept,
                    "code={code} mask={mask}"
                );
                for c in 0..2 {
                    let next = if b == dead {
                        dead
                    } else {
                        graph.states[b]
                            .edges
                            .iter()
                            .find(|e| e.lo <= 97 + c as u16 && 97 + c as u16 <= e.hi)
                            .map_or(dead, |e| e.to)
                    };
                    let pair = (targets[a][c], next);
                    if !pairs.contains(&pair) {
                        pairs.push(pair);
                    }
                }
                cursor += 1;
            }
        }
    }
}

#[test]
fn symbolic_repeats_do_not_materialize_irrelevant_global_endpoint_edges() {
    let child = Automaton::Singleton((0..2499).collect())
        .expanded()
        .unwrap();
    let mut explicit = Automaton::Graph(child.clone()).bounded(2, 2).unwrap();
    assert_eq!(explicit.minimize(5000), Ok(Some(5000)));
    let (actual, count) = symbolic::bounded(&child, 2, 2, 5000).unwrap();
    assert_eq!(count, Some(5000));
    assert_eq!(actual.normal(), explicit.normal());
}

#[test]
fn symbolic_minimum_does_not_materialize_irrelevant_global_endpoint_edges() {
    let child = Automaton::Singleton((0..2499).collect())
        .expanded()
        .unwrap();
    let mut explicit = Automaton::Graph(child.clone()).minimum(1).unwrap();
    assert_eq!(explicit.minimize(5000), Ok(Some(5000)));
    let (actual, count) = minimum::compile(&child, 1, 5000).unwrap();
    assert_eq!(count, Some(5000));
    assert_eq!(actual.normal(), explicit.normal());
}

#[test]
fn sparse_nullable_bounded_keys_follow_active_suffixes_only() {
    let mut child = Automaton::Singleton((0..2499).collect())
        .expanded()
        .unwrap();
    child.states[child.initial].accept = true;
    let mut explicit = Automaton::Graph(child.clone()).bounded(2, 2).unwrap();
    assert_eq!(explicit.minimize(5000), Ok(Some(5000)));
    let (actual, count) = symbolic::bounded(&child, 2, 2, 5000).unwrap();
    assert_eq!(count, Some(5000));
    assert_eq!(actual.normal(), explicit.normal());
}

#[test]
fn sparse_nullable_minimum_keys_follow_active_suffixes_only() {
    let mut child = Automaton::Singleton((0..2499).collect())
        .expanded()
        .unwrap();
    child.states[child.initial].accept = true;
    let mut explicit = Automaton::Graph(child.clone()).minimum(1).unwrap();
    assert_eq!(explicit.minimize(5000), Ok(Some(5000)));
    let (actual, count) = minimum::compile(&child, 1, 5000).unwrap();
    assert_eq!(count, Some(5000));
    assert_eq!(actual.normal(), explicit.normal());
}
