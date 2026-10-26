//! The recorded text-search membership differences no general analysis rule explains, shared
//! by `text_membership_replay.rs` and `text_closure_comparison.rs`. Each names the closure
//! known difference (spec/compatibility/closure/FS-TEXT-SEARCH.json) it belongs to.

/// Recorded cases no general analysis rule explains: 20 CJK/kana cases plus 2 `İpek` cases, all
/// known differences by owner decision 1788 (which widens the six cases of 1785; text search is
/// verified for Latin-script text). They stay pinned so a change in either direction surfaces.
///
/// - Han and kana runs: production segments them with a dictionary. `京都`, `都`, `東京都`,
///   `京` and `京都東京駅` depend on the words around the character (`京都東京駅東京都京都東京駅`
///   contains `東京都` yet matches neither `都` nor `東京都`; `京` alone matches `京` and `京 都`
///   only); `生物研究所` and `"生 物"` separate `生物` from `生 物`; `吉` does not match `吉野家`.
/// - `𠮷`: alone it matches only `𠮷`, but `𠮷ミナ` and `𠮷野家` also match `吉ミナ` and `吉野家`.
/// - Katakana with width and `・` variants: unquoted `ネムラ ﾈﾑﾗ` (and the `・`/`･` forms) match only
///   `ネムラネムラ`, and `カタカナ・ｶﾀｶﾅ` matches nothing, not even the document holding it.
/// - `İpek`: the query keeps the mark case folding splits off `İ` (so `İzmir`, `İnci`, `İzunex`
///   and `İstanbul` match nothing, as production answered), yet production matched `İpek` and
///   `ipek` for the query `İpek`.
///
/// Entries are (membership fixture corpus, query, closure known difference).
pub const UNEXPLAINED: [(&str, &str, &str); 22] = [
    ("textcal20261024#4", "京", "cjkDictionarySegmentation"),
    ("textlex20261024#0", "京都", "cjkDictionarySegmentation"),
    ("textlex20261024#0", "京", "cjkDictionarySegmentation"),
    ("textlex20261024#0", "都", "cjkDictionarySegmentation"),
    ("textlex20261024#0", "東京都", "cjkDictionarySegmentation"),
    (
        "textlex20261024#0",
        "京都東京駅",
        "cjkDictionarySegmentation",
    ),
    (
        "textlex20261024#0",
        "東京駅京都",
        "cjkDictionarySegmentation",
    ),
    (
        "textlex20261024#0",
        "\"京 都\"",
        "cjkDictionarySegmentation",
    ),
    (
        "textproof20261024#0",
        "生物研究所",
        "cjkDictionarySegmentation",
    ),
    (
        "textproof20261024#0",
        "\"生物 研究所\"",
        "cjkDictionarySegmentation",
    ),
    (
        "textproof20261024#0",
        "\"生 物\"",
        "cjkDictionarySegmentation",
    ),
    (
        "textproof20261024#0",
        "カタカナ・ｶﾀｶﾅ",
        "cjkDictionarySegmentation",
    ),
    ("textproof20261024#0", "𠮷野家", "cjkDictionarySegmentation"),
    ("textproof20261024#0", "İpek", "dottedCapitalIpek"),
    (
        "textdisc20261024#0",
        "ネムラ・ﾈﾑﾗ",
        "cjkDictionarySegmentation",
    ),
    (
        "textdisc20261024#0",
        "ネムラ ﾈﾑﾗ",
        "cjkDictionarySegmentation",
    ),
    (
        "textdisc20261024#0",
        "ネムラ･ﾈﾑﾗ",
        "cjkDictionarySegmentation",
    ),
    ("textdisc20261024#0", "吉", "cjkDictionarySegmentation"),
    ("textdisc20261024#0", "𠮷ミナ", "cjkDictionarySegmentation"),
    (
        "textdisc20261024#0",
        "カタカナ・ｶﾀｶﾅ",
        "cjkDictionarySegmentation",
    ),
    ("textdisc20261024#0", "𠮷野家", "cjkDictionarySegmentation"),
    ("textdisc20261024#0", "İpek", "dottedCapitalIpek"),
];

/// The closure known difference of a recorded case, matched on the corpus's collection (the
/// part before `#`, so the order fixture's corpus names match too) and the query.
#[must_use]
pub fn known_difference(corpus: &str, query: &str) -> Option<&'static str> {
    let collection = corpus.split('#').next().unwrap_or(corpus);
    UNEXPLAINED
        .iter()
        .find(|(c, q, _)| c.split('#').next() == Some(collection) && *q == query)
        .map(|(_, _, kind)| *kind)
}
