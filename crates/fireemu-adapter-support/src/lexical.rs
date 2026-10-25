//! Deterministic language-neutral lexical-v1 Unicode analysis. No morphology or production-equivalence claims.
use unicode_casefold::UnicodeCaseFold;
use unicode_normalization::{
    char::{decompose_canonical, is_combining_mark},
    UnicodeNormalization,
};
use unicode_segmentation::UnicodeSegmentation;

/// Legacy symmetric lexical-v1 compatibility analysis: NFKC, full case fold, NFKC, and unchanged word/CJK segmentation. Runtime search uses the purpose-specific entrypoints.
#[must_use]
pub fn tokenize(input: &str) -> Vec<String> {
    let normalized: String = input.nfkc().case_fold().nfkc().collect();
    segment(&normalized)
}

fn segment(normalized: &str) -> Vec<String> {
    let mut result = Vec::new();
    for word in normalized.unicode_words() {
        let mut buffer = String::new();
        for c in word.chars() {
            if matches!(c as u32,0x3400..=0x4dbf|0x4e00..=0x9fff|0xf900..=0xfaff|0x20000..=0x323af)
            {
                if !buffer.is_empty() {
                    result.push(std::mem::take(&mut buffer));
                }
                result.push(c.to_string());
            } else {
                buffer.push(c);
            }
        }
        if !buffer.is_empty() {
            result.push(buffer);
        }
    }
    result
}

/// Analyze indexed text using the bounded development profile: NFKC, precomposed Latin folded
/// to its base, full case fold, NFKC.
#[must_use]
pub fn tokenize_index(input: &str) -> Vec<String> {
    analyze(input, Purpose::Index)
}

/// Analyze query text: NFKC, full case fold, then precomposed Latin folded to its base, NFKC.
/// The fold runs after case folding, so a mark that case folding splits off (`İ` becomes `i`
/// and U+0307) stays in the query term. Production answers no document for a query holding `İ`,
/// not even a document holding the same word (`İstanbul`, `İzmir`, `İnci` and `İzunex` in the
/// recorded `textlex20261024` and `textdisc20261024` corpora), while `istanbul` matches the
/// document `İstanbul`.
#[must_use]
pub fn tokenize_query(input: &str) -> Vec<String> {
    analyze(input, Purpose::Query)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Index,
    Query,
}

fn analyze(input: &str, purpose: Purpose) -> Vec<String> {
    let folded: String = match purpose {
        Purpose::Index => input
            .nfkc()
            .map(fold_precomposed_latin)
            .case_fold()
            .collect(),
        Purpose::Query => input
            .nfkc()
            .case_fold()
            .map(fold_precomposed_latin)
            .collect(),
    };
    // UAX #29 keeps a colon between letters inside one word (MidLetter); production separates
    // the words there (`title:fox` matched `fox`). NFKC already mapped the full-width and small
    // colons to U+003A.
    let normalized: String = folded
        .nfkc()
        .map(|c| if c == ':' { ' ' } else { c })
        .collect();
    segment(&normalized)
}

// Fold only a scalar's Latin-base decomposition, never marks supplied as separate scalars.
fn fold_precomposed_latin(c: char) -> char {
    if c.is_ascii() {
        return c;
    }
    let mut first = true;
    let mut base = None;
    let mut valid = true;
    decompose_canonical(c, |part| {
        if first {
            first = false;
            if part.is_ascii_alphabetic() {
                base = Some(part);
            } else {
                valid = false;
            }
        } else {
            valid &= is_combining_mark(part);
        }
    });
    if valid {
        base.unwrap_or(c)
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin_purposes_fold_composed_decomposed_width_and_other_latin_bases() {
        for input in ["CAFÉ", "cafe\u{301}", "ｃａｆｅ"] {
            assert_eq!(tokenize_index(input), ["cafe"]);
            assert_eq!(tokenize_query(input), ["cafe"]);
        }
        for (input, expected) in [
            ("naïve", "naive"),
            ("résumé", "resume"),
            ("crème", "creme"),
            ("ÑANDÚ", "nandu"),
        ] {
            assert_eq!(tokenize_index(input), [expected]);
            assert_eq!(tokenize_query(input), [expected]);
        }
    }

    /// Recorded production: the query `İstanbul` matched no document, not even `İstanbul`,
    /// while `istanbul` matched it; `i\u{307}zmir` and `ızunex` matched nothing either.
    #[test]
    fn dotted_capital_latin_base_folds_for_index_but_keeps_its_mark_in_queries() {
        assert_eq!(tokenize_index("İris İSTANBUL"), ["iris", "istanbul"]);
        assert_eq!(
            tokenize_query("İris İSTANBUL"),
            ["i\u{307}ris", "i\u{307}stanbul"]
        );
        assert_eq!(tokenize_query("iris istanbul"), ["iris", "istanbul"]);
        assert_eq!(tokenize_query("i\u{307}zmir"), ["i\u{307}zmir"]);
        assert_eq!(tokenize_query("ızunex"), ["ızunex"]);
        // Case folding that expands into a Latin base and a mark (U+1E96, U+01F0) keeps the
        // mark in a query the same way; NFKC composes the pair again.
        assert_eq!(tokenize_index("ẖ ǰ"), ["h", "j"]);
        assert_eq!(tokenize_query("ẖ ǰ"), ["ẖ", "ǰ"]);
    }

    /// A colon separates words: production returned the document `title:fox` for `fox` and
    /// for `title fox` (recorded calibration corpus `textcal20261024`).
    #[test]
    fn a_colon_separates_words_in_both_purposes() {
        for input in ["title:fox", "title：fox", "title : fox"] {
            assert_eq!(tokenize_index(input), ["title", "fox"], "{input}");
            assert_eq!(tokenize_query(input), ["title", "fox"], "{input}");
        }
    }

    #[test]
    fn greek_other_scripts_and_noncomposing_marks_keep_their_distinctions() {
        for input in [
            "ά α",
            "が ガ",
            "क़",
            "שָׁלוֹם",
            "q\u{301} q\u{308}",
            "i\u{307}ris",
            "東京都の猫",
            "Σ σ ς",
            "Straße",
        ] {
            assert_eq!(tokenize_index(input), tokenize(input), "index {input}");
            assert_eq!(tokenize_query(input), tokenize(input), "query {input}");
        }
        assert_eq!(tokenize_index("ά α"), ["ά", "α"]);
        assert_eq!(tokenize_query("ά α"), ["ά", "α"]);
    }

    #[test]
    fn legacy_entrypoint_keeps_original_symmetric_lexical_v1_analysis() {
        assert_eq!(
            tokenize("CAFÉ cafe\u{301} Straße 東京"),
            ["café", "café", "strasse", "東", "京"]
        );
        assert_eq!(tokenize("İris"), ["i\u{307}ris"]);
    }

    proptest::proptest! {
        #[test]
        fn ascii_purposes_retain_legacy_tokens_apart_from_colons(input in "[ -~]{0,80}") {
            let separated = input.replace(':', " ");
            proptest::prop_assert_eq!(tokenize_index(&input), tokenize(&separated));
            proptest::prop_assert_eq!(tokenize_query(&input), tokenize(&separated));
        }
        /// The purposes differ only where case folding splits a mark off a Latin base: text
        /// without such a scalar analyses the same way for both.
        #[test]
        fn query_analysis_equals_index_analysis_without_expanding_case_folds(input in ".{0,100}") {
            proptest::prop_assume!(!input.nfkc().any(|c| {
                let folded: String = std::iter::once(c).case_fold().collect();
                folded.chars().count() > 1 && folded.chars().any(is_combining_mark)
            }));
            proptest::prop_assert_eq!(tokenize_query(&input), tokenize_index(&input));
        }
        /// Every query term is either an index term or keeps a combining mark the index side
        /// folded away; the query side never drops a mark the index side keeps.
        #[test]
        fn query_terms_differ_from_index_terms_only_by_kept_marks(
            input in "[a-zA-Z İıẖẗẘẙǰÉéßẞŉΐΰ\u{0300}-\u{0310}]{0,40}"
        ) {
            let index = tokenize_index(&input);
            let query = tokenize_query(&input);
            proptest::prop_assert_eq!(index.len(), query.len());
            for (i, q) in index.iter().zip(&query) {
                let stripped: String = q.nfd().filter(|c| !is_combining_mark(*c)).collect();
                let index_stripped: String = i.nfd().filter(|c| !is_combining_mark(*c)).collect();
                proptest::prop_assert_eq!(stripped, index_stripped);
            }
        }
        #[test]
        fn arbitrary_unicode_has_no_empty_tokens_or_panics(input in ".{0,100}") {
            for tokens in [tokenize(&input), tokenize_index(&input), tokenize_query(&input)] {
                proptest::prop_assert!(tokens.iter().all(|token| !token.is_empty()));
            }
        }
        #[test]
        fn generic_precomposed_latin_variants_share_ascii_terms(
            prefix in "[a-z]{0,8}", suffix in "[a-z]{0,8}",
            pair in proptest::sample::select(vec![("é", "e"), ("å", "a"), ("ç", "c"), ("ñ", "n"), ("ü", "u")])
        ) {
            let accented = format!("{prefix}{}{suffix}", pair.0);
            let plain = format!("{prefix}{}{suffix}", pair.1);
            proptest::prop_assert_eq!(tokenize_index(&accented), tokenize_query(&plain));
            proptest::prop_assert_eq!(tokenize_query(&accented), tokenize_index(&plain));
        }
    }
}
