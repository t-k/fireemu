//! The compatibility-contract gate.
//!
//! `spec/compatibility/contract.json` is the single machine-readable statement of what fireemu
//! claims against a pinned `firebase-tools` release. This crate fails CI when the repository and
//! that statement disagree. The rules it enforces, by ID:
//!
//! | Rule | What it refuses |
//! | --- | --- |
//! | `CC-01` | a malformed contract: a bad schema version, a duplicate surface or claim ID, an unknown scope or state |
//! | `CC-02` | a contract whose pinned version is not the one the differential suite installs, a claim sentence that does not name it, an official emulator of the pinned baseline that no surface enumerates, or a surface that names an emulator the baseline does not ship |
//! | `CC-03` | a manifest capability that is `implemented` or `partial` and is not bound to at least one existing executed test or conformance fixture |
//! | `CC-04` | a manifest entry and the contract that disagree on status, an unknown capability ID, or a manifest entry no claim covers |
//! | `CC-05` | a README that does not carry the version-qualified claim sentence verbatim |
//! | `CC-06` | a deferred or not-planned product that appears as supported in the manifest or the README |
//! | `CC-07` | contradictory public statements: an item one entry calls `unimplemented` that another entry, or the contract's shared vocabulary, calls `implemented` |
//! | `CC-08` | a compatibility profile that sets or declares a configuration key the canonical schema does not define, or a value it does not allow; a declared key without a `hand-written` / `not-implemented` status and a note, or one that is also set; and a profile name the schema's `profile` key does not accept (or accepts and the contract does not declare) |
//! | `CC-09` | a conformance fixture cited as evidence that records unresolved `debt`, unless the claim excludes that step by name with the issue that owns it; a fixture with no `parity` or `documented-divergence` step (so nothing the local oracle answered); a stale exclusion, and a step status the suite does not define |
//!
//! Artifact names resolve the way `tools/traceability-check` resolves them, so the two gates
//! agree on what "an existing test" means: a `tests` name is a function defined in a Rust file
//! under a `tests/` directory anywhere in the workspace, an `integration` name is a
//! repository-relative file that exists, and a `conformance` name is a fixture ID under
//! `conformance/fixtures/`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Where the contract lives, relative to the repository root.
pub const CONTRACT_PATH: &str = "spec/compatibility/contract.json";
/// Where the capability manifest data lives. `crates/fireemu/src/control.rs` embeds this exact
/// file with `include_str!`, so what the checker reads is what the binary publishes.
pub const MANIFEST_PATH: &str = "crates/fireemu/src/capabilities.json";
/// The public claim document.
pub const README_PATH: &str = "README.md";
/// The canonical configuration schema the profile key sets are checked against.
pub const CONFIG_SCHEMA_PATH: &str = "spec/config/fireemu.schema.json";

/// The scopes a surface may declare.
const SCOPES: [&str; 3] = ["active", "deferred", "not-planned"];
/// The states a surface may declare.
const STATES: [&str; 4] = ["claimed", "addition", "gap", "none"];
/// Manifest statuses that oblige a capability to name executed evidence.
const EVIDENCE_BEARING: [&str; 2] = ["implemented", "partial"];

/// What one run found.
#[derive(Debug, Default)]
pub struct Report {
    /// Every rule violation, each prefixed with the rule ID.
    pub problems: Vec<String>,
    /// Informational lines printed on every run.
    pub notes: Vec<String>,
}

impl Report {
    /// True when nothing is wrong.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Runs every compatibility rule against the repository rooted at `root`.
#[must_use]
pub fn check(root: &Path) -> Report {
    let mut report = Report::default();
    let Some(contract) = read_json(root, CONTRACT_PATH, &mut report.problems) else {
        return report;
    };
    let Some(manifest) = read_json(root, MANIFEST_PATH, &mut report.problems) else {
        return report;
    };
    let Some(entries) = manifest.as_object() else {
        report
            .problems
            .push(format!("CC-01: {MANIFEST_PATH} is not a JSON object"));
        return report;
    };

    let statuses: BTreeMap<&str, &str> = entries
        .iter()
        .map(|(id, entry)| (id.as_str(), str_field(entry, "status").unwrap_or("")))
        .collect();

    let surfaces = shape(&contract, &mut report.problems);
    let index = RepoIndex::build(root);

    check_shape(&contract, surfaces, &mut report.problems);
    check_inventory(root, &contract, surfaces, &mut report.problems);
    check_claims(root, surfaces, &statuses, &index, &mut report);
    check_readme_claim(root, &contract, &mut report.problems);
    check_scope_leakage(root, &contract, surfaces, entries, &mut report.problems);
    check_contradictions(root, &contract, entries, &statuses, &mut report.problems);
    check_profiles(root, &contract, &mut report.problems);
    let excluded = excluded_debt_steps(surfaces);
    if excluded > 0 {
        report.notes.push(format!(
            "{excluded} debt step(s) are excluded from claims by name; each names its owning issue"
        ));
    }

    report
}

/// How many fixture steps the claims exclude from their scope (`CC-09`), so every run prints
/// how much recorded debt the public claim is currently carrying around.
fn excluded_debt_steps(surfaces: &[Value]) -> usize {
    surfaces
        .iter()
        .flat_map(|surface| claims_of(surface).iter())
        .filter_map(|claim| claim.get("evidence")?.get("conformance")?.as_array())
        .flatten()
        .filter_map(|item| item.get("excludedSteps")?.as_array())
        .map(Vec::len)
        .sum()
}

/// The `surfaces` array, or an empty slice with the shape problem already reported.
fn shape<'a>(contract: &'a Value, problems: &mut Vec<String>) -> &'a [Value] {
    if let Some(surfaces) = contract.get("surfaces").and_then(Value::as_array) {
        return surfaces.as_slice();
    }
    problems.push(format!("CC-01: {CONTRACT_PATH} has no surfaces array"));
    &[]
}

// ---------------------------------------------------------------------------------------------
// CC-01: the contract itself

fn check_shape(contract: &Value, surfaces: &[Value], problems: &mut Vec<String>) {
    if contract.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        problems.push(format!("CC-01: {CONTRACT_PATH} needs schemaVersion 1"));
    }
    if str_field(contract, "auditDate").unwrap_or("").is_empty() {
        problems.push(format!("CC-01: {CONTRACT_PATH} has no auditDate"));
    }
    let mut surface_ids = BTreeSet::new();
    let mut claim_ids = BTreeSet::new();
    for surface in surfaces {
        let id = str_field(surface, "id").unwrap_or("");
        if id.is_empty() {
            problems.push("CC-01: a surface has no id".to_owned());
            continue;
        }
        if !surface_ids.insert(id) {
            problems.push(format!("CC-01: surface {id} is declared twice"));
        }
        let scope = str_field(surface, "scope").unwrap_or("");
        if !SCOPES.contains(&scope) {
            problems.push(format!(
                "CC-01: surface {id} has scope {scope:?}, not one of {SCOPES:?}"
            ));
        }
        let state = str_field(surface, "state").unwrap_or("");
        if !STATES.contains(&state) {
            problems.push(format!(
                "CC-01: surface {id} has state {state:?}, not one of {STATES:?}"
            ));
        }
        if str_field(surface, "decision").unwrap_or("").is_empty() {
            problems.push(format!("CC-01: surface {id} records no decision"));
        }
        if scope != "active" && !claims_of(surface).is_empty() {
            problems.push(format!(
                "CC-06: surface {id} is {scope} and may not carry parity claims"
            ));
        }
        for claim in claims_of(surface) {
            let cid = str_field(claim, "id").unwrap_or("");
            if cid.is_empty() {
                problems.push(format!("CC-01: a claim of surface {id} has no id"));
            } else if !claim_ids.insert(cid.to_owned()) {
                problems.push(format!("CC-01: claim {cid} is declared twice"));
            }
            if str_field(claim, "statement").unwrap_or("").is_empty() {
                problems.push(format!("CC-01: claim {cid} has an empty statement"));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CC-02: the pinned inventory

fn check_inventory(root: &Path, contract: &Value, surfaces: &[Value], problems: &mut Vec<String>) {
    let baseline = contract.get("baseline");
    check_pin(root, contract, baseline, problems);
    let official: BTreeSet<&str> = baseline
        .and_then(|b| b.get("officialEmulators"))
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if official.is_empty() {
        problems.push(format!(
            "CC-02: {CONTRACT_PATH} baseline.officialEmulators is empty; the pinned inventory is what the taxonomy is checked against"
        ));
        return;
    }
    let mut enumerated = BTreeSet::new();
    for surface in surfaces {
        let id = str_field(surface, "id").unwrap_or("");
        let Some(name) = str_field(surface, "officialEmulator") else {
            if surface.get("official").and_then(Value::as_bool) == Some(true) {
                problems.push(format!(
                    "CC-02: surface {id} is marked official but names no officialEmulator"
                ));
            }
            continue;
        };
        if !official.contains(name) {
            problems.push(format!(
                "CC-02: surface {id} names officialEmulator {name:?}, which firebase-tools {} does not ship",
                str_field(baseline.unwrap_or(&Value::Null), "version").unwrap_or("?")
            ));
        }
        if !enumerated.insert(name) {
            problems.push(format!(
                "CC-02: official emulator {name:?} is enumerated by more than one surface"
            ));
        }
    }
    for name in official.difference(&enumerated) {
        problems.push(format!(
            "CC-02: official emulator {name:?} of the pinned baseline is not enumerated by any surface"
        ));
    }
}

/// The baseline the contract names has to be the one the differential suite actually installs,
/// and the claim sentence has to name that version. This is what makes an upstream upgrade
/// fail closed: bumping the pin in `conformance/package.json` breaks the gate until the
/// contract, the claim and the surface enumeration are reconciled with the new release.
fn check_pin(root: &Path, contract: &Value, baseline: Option<&Value>, problems: &mut Vec<String>) {
    let declared = baseline.and_then(|b| str_field(b, "version")).unwrap_or("");
    if declared.is_empty() {
        problems.push(format!("CC-02: {CONTRACT_PATH} baseline names no version"));
        return;
    }
    let pinned_by = baseline
        .and_then(|b| str_field(b, "pinnedBy"))
        .unwrap_or("conformance/package.json");
    let package = baseline
        .and_then(|b| str_field(b, "package"))
        .unwrap_or("firebase-tools");
    match read_json(root, pinned_by, problems) {
        None => {}
        Some(manifest) => {
            let pinned = manifest
                .get("dependencies")
                .and_then(|d| d.get(package))
                .and_then(Value::as_str)
                .unwrap_or("");
            if pinned != declared {
                problems.push(format!(
                    "CC-02: {CONTRACT_PATH} pins {package} {declared:?} while {pinned_by} installs {pinned:?}; reconcile the delta before the claim can stand"
                ));
            }
        }
    }
    let sentence = contract
        .get("claim")
        .and_then(|c| str_field(c, "sentence"))
        .unwrap_or("");
    if !sentence.contains(declared) {
        problems.push(format!(
            "CC-02: the claim sentence does not name the pinned {package} version {declared:?}, so it is not version-qualified"
        ));
    }
}

// ---------------------------------------------------------------------------------------------
// CC-03 and CC-04: evidence and status agreement

fn check_claims(
    root: &Path,
    surfaces: &[Value],
    statuses: &BTreeMap<&str, &str>,
    index: &RepoIndex,
    report: &mut Report,
) {
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    for surface in surfaces {
        for claim in claims_of(surface) {
            let cid = str_field(claim, "id").unwrap_or("<unnamed>");
            let resolved = resolved_evidence(root, claim, index, &mut report.problems, cid);
            for cap in claim
                .get("capabilities")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let Some(id) = str_field(cap, "id") else {
                    report.problems.push(format!(
                        "CC-04: claim {cid} names a capability without an id"
                    ));
                    continue;
                };
                let declared = str_field(cap, "status").unwrap_or("");
                let Some(&actual) = statuses.get(id) else {
                    report.problems.push(format!(
                        "CC-04: claim {cid} names capability {id}, which the manifest does not declare"
                    ));
                    continue;
                };
                covered.insert(id);
                if declared != actual {
                    report.problems.push(format!(
                        "CC-04: claim {cid} declares capability {id} as {declared:?} while the manifest declares it {actual:?}"
                    ));
                }
                if EVIDENCE_BEARING.contains(&actual) && resolved == 0 {
                    report.problems.push(format!(
                        "CC-03: capability {id} is {actual} but claim {cid} binds it to no existing executed test or conformance fixture"
                    ));
                }
            }
        }
    }
    for (id, status) in statuses {
        if !covered.contains(id) {
            report.problems.push(format!(
                "CC-04: capability {id} ({status}) is in the manifest and in no claim of {CONTRACT_PATH}"
            ));
        }
    }
    report
        .notes
        .push(format!("{} capability entries covered", covered.len()));
}

/// How many evidence items of `claim` resolve. Every item that does not resolve is a problem in
/// its own right, so a claim cannot quietly carry a stale name next to a live one.
fn resolved_evidence(
    root: &Path,
    claim: &Value,
    index: &RepoIndex,
    problems: &mut Vec<String>,
    cid: &str,
) -> usize {
    let Some(evidence) = claim.get("evidence") else {
        return 0;
    };
    let mut resolved = 0;
    for name in strings(evidence, "tests") {
        if index.test_fns.contains(name) {
            resolved += 1;
        } else {
            problems.push(format!(
                "CC-03: claim {cid}: test {name} is not a function defined in any tests/ source file"
            ));
        }
    }
    for name in strings(evidence, "integration") {
        if root.join(name).is_file() {
            resolved += 1;
        } else {
            problems.push(format!(
                "CC-03: claim {cid}: integration file {name} does not exist"
            ));
        }
    }
    for item in evidence
        .get("conformance")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(cited) = CitedFixture::parse(item) else {
            problems.push(format!(
                "CC-03: claim {cid}: a conformance evidence item is neither a fixture name nor an object with a fixture name"
            ));
            continue;
        };
        let name = cited.name;
        let path = root
            .join("conformance/fixtures")
            .join(format!("{name}.json"));
        if !path.is_file() {
            problems.push(format!(
                "CC-03: claim {cid}: conformance fixture {name} has no conformance/fixtures/{name}.json"
            ));
            continue;
        }
        let fixture = fs::read_to_string(&path)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
        let Some(fixture) = fixture else {
            problems.push(format!(
                "CC-09: claim {cid}: conformance fixture {name} is not a JSON document"
            ));
            continue;
        };
        if fixture_is_evidence(&fixture, &cited, problems, cid) {
            resolved += 1;
        }
    }
    resolved
}

/// One `evidence.conformance` item: a fixture name, optionally with the debt steps the claim
/// leaves out of its scope. Written as a bare string or as
/// `{"fixture": name, "excludedSteps": [{"step", "issue", "reason"}]}`.
struct CitedFixture<'a> {
    name: &'a str,
    excluded: Vec<&'a Value>,
}

impl<'a> CitedFixture<'a> {
    fn parse(item: &'a Value) -> Option<Self> {
        if let Some(name) = item.as_str() {
            return Some(Self {
                name,
                excluded: Vec::new(),
            });
        }
        let name = str_field(item, "fixture")?;
        let excluded = item
            .get("excludedSteps")
            .and_then(Value::as_array)
            .map(|steps| steps.iter().collect())
            .unwrap_or_default();
        Some(Self { name, excluded })
    }
}

/// The step statuses `conformance/src/record.mjs` writes.
const STEP_STATUSES: [&str; 4] = ["parity", "documented-divergence", "debt", "pending"];

/// Whether a recorded fixture proves anything for the claim that cites it (`CC-09`).
///
/// A `parity` or `documented-divergence` step is a row the local oracle answered and the replay
/// gates, so it is evidence. A `pending` row is one no local oracle can answer (the production
/// service would have to), so it proves nothing about the official emulator and is neither
/// evidence nor a problem. A `debt` row is a recorded mismatch nobody has ruled on: it
/// invalidates the claim unless the claim excludes that step by name, with the issue that owns
/// it, and an exclusion that names a step which is no longer debt is stale and reported so it
/// gets removed.
fn fixture_is_evidence(
    fixture: &Value,
    cited: &CitedFixture<'_>,
    problems: &mut Vec<String>,
    cid: &str,
) -> bool {
    let name = cited.name;
    let Some(steps) = fixture.get("steps").and_then(Value::as_array) else {
        problems.push(format!(
            "CC-09: claim {cid}: conformance fixture {name} has no steps array"
        ));
        return false;
    };
    let mut status_of: BTreeMap<&str, &str> = BTreeMap::new();
    let mut evidence_steps = 0;
    for step in steps {
        let id = str_field(step, "id").unwrap_or("<unnamed>");
        let status = str_field(step, "status").unwrap_or("");
        status_of.insert(id, status);
        match status {
            "parity" | "documented-divergence" => evidence_steps += 1,
            "pending" | "debt" => {}
            other => problems.push(format!(
                "CC-09: claim {cid}: conformance fixture {name} step {id} has status {other:?}, which is none of {STEP_STATUSES:?}"
            )),
        }
    }
    let mut excluded_ids: BTreeSet<&str> = BTreeSet::new();
    for exclusion in &cited.excluded {
        let Some(step) = str_field(exclusion, "step") else {
            problems.push(format!(
                "CC-09: claim {cid}: an exclusion of {name} names no step"
            ));
            continue;
        };
        excluded_ids.insert(step);
        if str_field(exclusion, "issue").is_none_or(str::is_empty) {
            problems.push(format!(
                "CC-09: claim {cid}: excluded step {step} of {name} names no owning issue"
            ));
        }
        if str_field(exclusion, "reason").is_none_or(str::is_empty) {
            problems.push(format!(
                "CC-09: claim {cid}: excluded step {step} of {name} gives no reason"
            ));
        }
        match status_of.get(step) {
            None => problems.push(format!(
                "CC-09: claim {cid}: excluded step {step} is not a step of {name}; the exclusion is stale"
            )),
            Some(&"debt") => {}
            Some(status) => problems.push(format!(
                "CC-09: claim {cid}: excluded step {step} of {name} is {status}, not debt; the exclusion is stale"
            )),
        }
    }
    for (id, status) in &status_of {
        if *status == "debt" && !excluded_ids.contains(id) {
            problems.push(format!(
                "CC-09: claim {cid}: conformance fixture {name} step {id} is debt (an unresolved mismatch with the official emulator); resolve it, document it as a divergence in conformance/divergences.json, or exclude it from the claim by name with its owning issue"
            ));
        }
    }
    if evidence_steps == 0 {
        problems.push(format!(
            "CC-09: claim {cid}: conformance fixture {name} carries no parity or documented-divergence step, so nothing in it was answered by the local oracle and it is not evidence"
        ));
        return false;
    }
    true
}

// ---------------------------------------------------------------------------------------------
// CC-05: the public claim sentence

fn check_readme_claim(root: &Path, contract: &Value, problems: &mut Vec<String>) {
    let Some(sentence) = contract.get("claim").and_then(|c| str_field(c, "sentence")) else {
        problems.push(format!("CC-05: {CONTRACT_PATH} declares no claim.sentence"));
        return;
    };
    if sentence.is_empty() {
        problems.push(format!(
            "CC-05: {CONTRACT_PATH} declares an empty claim.sentence"
        ));
        return;
    }
    let wanted = squeeze(sentence);
    let documents = contract
        .get("claim")
        .map(|c| strings(c, "documents"))
        .unwrap_or_default();
    let documents = if documents.is_empty() {
        vec![README_PATH]
    } else {
        documents
    };
    for document in documents {
        let Ok(text) = fs::read_to_string(root.join(document)) else {
            problems.push(format!("CC-05: {document} cannot be read"));
            continue;
        };
        if !squeeze(&text).contains(&wanted) {
            problems.push(format!(
                "CC-05: {document} does not carry the version-qualified claim sentence of {CONTRACT_PATH} verbatim"
            ));
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CC-06: a deferred or not-planned product may never read as supported

fn check_scope_leakage(
    root: &Path,
    contract: &Value,
    surfaces: &[Value],
    entries: &serde_json::Map<String, Value>,
    problems: &mut Vec<String>,
) {
    let disclaimers = contract
        .get("vocabulary")
        .map(|v| strings(v, "scopeDisclaimers"))
        .unwrap_or_default();
    let readme = fs::read_to_string(root.join(README_PATH)).unwrap_or_default();

    for surface in surfaces {
        let scope = str_field(surface, "scope").unwrap_or("");
        if scope == "active" {
            continue;
        }
        let sid = str_field(surface, "id").unwrap_or("");
        let terms = strings(surface, "prohibitedClaimTerms");
        if terms.is_empty() {
            problems.push(format!(
                "CC-06: surface {sid} is {scope} and declares no prohibitedClaimTerms, so nothing stops it from reading as supported"
            ));
        }
        for term in terms {
            let needle = term.to_lowercase();
            for (id, entry) in entries {
                for item in strings(entry, "implemented") {
                    if item.to_lowercase().contains(&needle) {
                        problems.push(format!(
                            "CC-06: manifest entry {id} lists {term:?} as implemented, but surface {sid} is {scope}"
                        ));
                    }
                }
            }
            for (n, line) in readme.lines().enumerate() {
                let lower = line.to_lowercase();
                if !lower.contains(&needle) {
                    continue;
                }
                if !disclaimers
                    .iter()
                    .any(|d| lower.contains(&d.to_lowercase()))
                {
                    problems.push(format!(
                        "CC-06: {README_PATH}:{} names {term:?} without saying it is {scope}",
                        n + 1
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// CC-07: contradictory public statements

fn check_contradictions(
    root: &Path,
    contract: &Value,
    entries: &serde_json::Map<String, Value>,
    statuses: &BTreeMap<&str, &str>,
    problems: &mut Vec<String>,
) {
    // (a) An `unimplemented` item that cross-references a capability the manifest calls
    // implemented. `ST-OBJ-1` listing "Storage triggers (FN-EVT-1)" was exactly this: the entry
    // that owns the behaviour says it works. Such a cross-reference belongs in `notes`.
    for (id, entry) in entries {
        for item in strings(entry, "unimplemented") {
            for (&other, &status) in statuses {
                if other == id || status != "implemented" {
                    continue;
                }
                if references(item, other) {
                    problems.push(format!(
                        "CC-07: manifest entry {id} lists {item:?} as unimplemented while it names {other}, which the manifest declares implemented; say so in notes instead"
                    ));
                }
            }
        }
    }

    // (b) The contract's shared vocabulary: one term, one status, wherever it is written.
    let terms = contract
        .get("vocabulary")
        .and_then(|v| v.get("sharedTerms"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let readme = fs::read_to_string(root.join(README_PATH)).unwrap_or_default();
    for shared in terms {
        let Some(term) = str_field(shared, "term") else {
            problems.push("CC-07: a sharedTerms entry has no term".to_owned());
            continue;
        };
        let declared = str_field(shared, "status").unwrap_or("");
        let needle = term.to_lowercase();
        for owner in strings(shared, "owners") {
            match statuses.get(owner) {
                None => problems.push(format!(
                    "CC-07: shared term {term:?} names owner {owner}, which the manifest does not declare"
                )),
                Some(&actual) if actual != declared => problems.push(format!(
                    "CC-07: shared term {term:?} is declared {declared:?} while its owner {owner} is {actual:?}"
                )),
                Some(_) => {}
            }
        }
        for (id, entry) in entries {
            let (forbidden, why) = if declared == "implemented" {
                ("unimplemented", "implemented")
            } else {
                ("implemented", declared)
            };
            for item in strings(entry, forbidden) {
                if item.to_lowercase().contains(&needle) {
                    problems.push(format!(
                        "CC-07: manifest entry {id} lists {item:?} under {forbidden:?} while the contract declares {term:?} {why}"
                    ));
                }
            }
        }
        if declared == "implemented" {
            for (n, line) in readme.lines().enumerate() {
                let lower = line.to_lowercase();
                if lower.contains(&needle)
                    && (lower.contains("not implemented") || lower.contains("is not supported"))
                {
                    problems.push(format!(
                        "CC-07: {README_PATH}:{} says {term:?} is not implemented while the contract declares it implemented",
                        n + 1
                    ));
                }
            }
        }
    }
}

/// True when `item` names capability `id` as a cross-reference rather than as a coincidence: the
/// identifier stands on its own, with no identifier character on either side.
fn references(item: &str, id: &str) -> bool {
    let bytes = item.as_bytes();
    let mut from = 0;
    while let Some(at) = item[from..].find(id) {
        let start = from + at;
        let end = start + id.len();
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_ident(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

// ---------------------------------------------------------------------------------------------
// CC-08: the compatibility profiles

fn check_profiles(root: &Path, contract: &Value, problems: &mut Vec<String>) {
    let Some(profiles) = contract.get("profiles").and_then(Value::as_object) else {
        problems.push(format!("CC-08: {CONTRACT_PATH} declares no profiles"));
        return;
    };
    let Some(schema) = read_json(root, CONFIG_SCHEMA_PATH, problems) else {
        return;
    };
    // A profile the daemon cannot be put into is a document, not a switch: the names the
    // contract declares and the values the `profile` key accepts have to be the same set.
    let accepted: Vec<String> = schema
        .get("properties")
        .and_then(|p| p.get("profile"))
        .and_then(|p| p.get("enum"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if accepted.is_empty() {
        problems.push(format!(
            "CC-08: {CONFIG_SCHEMA_PATH} declares no enum for the profile key, so no profile can be selected at runtime"
        ));
    }
    for name in &accepted {
        if !profiles.contains_key(name) {
            problems.push(format!(
                "CC-08: {CONFIG_SCHEMA_PATH} accepts profile {name}, which {CONTRACT_PATH} does not declare"
            ));
        }
    }
    for (name, profile) in profiles {
        if !accepted.is_empty() && !accepted.contains(name) {
            problems.push(format!(
                "CC-08: profile {name} is declared but {CONFIG_SCHEMA_PATH} does not accept it as a value of the profile key, so no run can select it"
            ));
        }
        if str_field(profile, "intent").unwrap_or("").is_empty() {
            problems.push(format!("CC-08: profile {name} states no intent"));
        }
        let Some(sets) = profile.get("sets").and_then(Value::as_object) else {
            problems.push(format!("CC-08: profile {name} sets no configuration key"));
            continue;
        };
        if sets.is_empty() {
            problems.push(format!("CC-08: profile {name} sets no configuration key"));
        }
        for (key, value) in sets {
            check_profile_value(&schema, name, key, value, problems);
        }
        // `declared` keys are statements of intent the profile does not switch: each says
        // whether the loader reads it by hand or refuses it, and may not also be under `sets`.
        let declared = profile
            .get("declared")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for (key, entry) in &declared {
            if sets.contains_key(key) {
                problems.push(format!(
                    "CC-08: profile {name} both sets and declares {key}; a key is derived from the profile or it is not"
                ));
            }
            let Some(value) = entry.get("value") else {
                problems.push(format!(
                    "CC-08: profile {name} declares {key} without a value"
                ));
                continue;
            };
            check_profile_value(&schema, name, key, value, problems);
            match str_field(entry, "status") {
                Some("hand-written" | "not-implemented") => {}
                other => problems.push(format!(
                    "CC-08: profile {name} declares {key} with status {other:?}; it must be \"hand-written\" (the loader reads the key but does not derive it) or \"not-implemented\" (the loader refuses the value or reads nothing)"
                )),
            }
            if str_field(entry, "note").is_none_or(str::is_empty) {
                problems.push(format!(
                    "CC-08: profile {name} declares {key} without a note saying why it is not derived"
                ));
            }
        }
    }
}

/// One profile value against the canonical schema: the key must exist, an enum must allow the
/// value, and a boolean key takes a boolean.
fn check_profile_value(
    schema: &Value,
    name: &str,
    key: &str,
    value: &Value,
    problems: &mut Vec<String>,
) {
    let Some(node) = schema_node(schema, key) else {
        problems.push(format!(
            "CC-08: profile {name} sets {key}, which {CONFIG_SCHEMA_PATH} does not define"
        ));
        return;
    };
    if let Some(allowed) = node.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            problems.push(format!(
                "CC-08: profile {name} sets {key} = {value}, which is not one of {allowed:?}"
            ));
        }
    }
    if node.get("type").and_then(Value::as_str) == Some("boolean") && !value.is_boolean() {
        problems.push(format!(
            "CC-08: profile {name} sets {key} = {value}, but the schema declares a boolean"
        ));
    }
}

/// Walks a dotted configuration key through the schema's `properties` chain.
fn schema_node<'a>(schema: &'a Value, key: &str) -> Option<&'a Value> {
    let mut node = schema;
    for part in key.split('.') {
        node = node.get("properties")?.get(part)?;
    }
    Some(node)
}

// ---------------------------------------------------------------------------------------------
// Repository index: the same resolution rules as tools/traceability-check

/// Function names defined in Rust files under a `tests/` directory anywhere in the workspace.
struct RepoIndex {
    test_fns: BTreeSet<String>,
}

impl RepoIndex {
    fn build(root: &Path) -> Self {
        let mut rust_files = Vec::new();
        for top in ["crates", "tools", "verification"] {
            collect(&root.join(top), &mut rust_files);
        }
        let mut test_fns = BTreeSet::new();
        for path in &rust_files {
            if !is_under_tests_dir(path) {
                continue;
            }
            if let Ok(text) = fs::read_to_string(path) {
                collect_fn_names(&text, &mut test_fns);
            }
        }
        Self { test_fns }
    }
}

fn is_under_tests_dir(path: &Path) -> bool {
    path.components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case("tests"))
}

fn collect(dir: &Path, rust_files: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if path.is_dir() {
            if matches!(name.as_str(), "target" | ".git" | "node_modules") {
                continue;
            }
            collect(&path, rust_files);
        } else if path.extension().is_some_and(|x| x == "rs") {
            rust_files.push(path);
        }
    }
}

fn collect_fn_names(text: &str, out: &mut BTreeSet<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") {
            continue;
        }
        if let Some(name) = fn_name(line) {
            out.insert(name.to_owned());
        }
    }
}

/// The identifier of a `fn name(` definition on `line`, if any.
fn fn_name(line: &str) -> Option<&str> {
    let mut rest = line;
    loop {
        let at = rest.find("fn ")?;
        let before_ok = at == 0
            || !rest.as_bytes()[at - 1].is_ascii_alphanumeric() && rest.as_bytes()[at - 1] != b'_';
        let tail = &rest[at + 3..];
        let name: &str = tail
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        let after = tail[name.len()..].trim_start();
        if before_ok && !name.is_empty() && (after.starts_with('(') || after.starts_with('<')) {
            return Some(name);
        }
        rest = tail;
    }
}

// ---------------------------------------------------------------------------------------------
// Small helpers

fn read_json(root: &Path, relative: &str, problems: &mut Vec<String>) -> Option<Value> {
    let path = root.join(relative);
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            problems.push(format!("CC-01: {relative} cannot be read: {e}"));
            return None;
        }
    };
    match serde_json::from_str(&text) {
        Ok(v) => Some(v),
        Err(e) => {
            problems.push(format!("CC-01: {relative} is not valid JSON: {e}"));
            None
        }
    }
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn strings<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn claims_of(surface: &Value) -> &[Value] {
    surface
        .get("claims")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

/// Collapses every run of whitespace into one space, so a claim sentence matches whether the
/// document wraps it or not.
fn squeeze(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}
