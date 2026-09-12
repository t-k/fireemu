//! Source-to-requirement inventory validation and conservative public matrix generation.
//!
//! This first schema intentionally cannot accept execution receipts. Existing artifact
//! references are navigation aids, never proof of execution against the current artifact.

mod render;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::Report;

const BASE: &str = "spec/compatibility";
const GOALS: [&str; 8] = [
    "AUTH-CORE",
    "AUTH-IP-MAIN",
    "FS-STD-NATIVE",
    "FS-ENT-NATIVE",
    "FS-MONGODB",
    "FS-ADMIN",
    "FS-SDK",
    "MANAGED-SERVICE-BOUNDARY",
];

struct Inventory {
    meta: Value,
    sources: Value,
    surfaces: Value,
    features: Value,
    gaps: Value,
    requirements: Value,
    capabilities: Value,
    contract: Value,
    packages: Value,
}

const GAP_KINDS: [&str; 6] = [
    "mismatch",
    "unimplemented",
    "unobserved",
    "observed",
    "unmapped",
    "untested",
];
const GAP_IMPLEMENTATION: [&str; 4] = ["unknown", "unimplemented", "implemented", "fixed"];
const GAP_LOCAL: [&str; 3] = ["none", "passing", "failing"];
const GAP_PRODUCTION: [&str; 3] = ["none", "recorded", "approved"];
const GAP_COMPARISON: [&str; 3] = ["none", "mismatch", "matches-in-scope"];

/// Checks input references and byte-for-byte generated output without writing anything.
pub fn check(root: &Path) -> Report {
    let mut report = Report::default();
    match documents(root) {
        Err(problems) => report.problems = problems,
        Ok(documents) => {
            for (path, expected) in documents {
                if fs::read_to_string(root.join(&path)).ok().as_ref() != Some(&expected) {
                    report.problems.push(format!(
                        "CI-07: {path} is missing or stale; run cargo run -p compat-check -- --write-inventory"
                    ));
                }
            }
        }
    }
    report
}

/// Validates inventory references before writing the generated public documents.
///
/// The CLI additionally preflights the legacy compatibility contract before calling this.
pub fn generate(root: &Path) -> Result<(), Vec<String>> {
    let documents = documents(root)?;
    for (path, contents) in documents {
        let path = root.join(path);
        fs::create_dir_all(path.parent().expect("fixed output has a parent"))
            .and_then(|()| fs::write(&path, contents))
            .map_err(|error| vec![format!("CI-07: {}: {error}", path.display())])?;
    }
    Ok(())
}

fn documents(root: &Path) -> Result<BTreeMap<String, String>, Vec<String>> {
    let read = |path: &str| -> Result<Value, Vec<String>> {
        let bytes =
            fs::read(root.join(path)).map_err(|error| vec![format!("CI-01: {path}: {error}")])?;
        serde_json::from_slice(&bytes).map_err(|error| vec![format!("CI-01: {path}: {error}")])
    };
    let inventory = Inventory {
        meta: read(&format!("{BASE}/inventory.json"))?,
        sources: read(&format!("{BASE}/sources/index.json"))?,
        surfaces: read(&format!("{BASE}/surfaces/index.json"))?,
        features: read(&format!("{BASE}/features.json"))?,
        gaps: read(&format!("{BASE}/gaps.json"))?,
        requirements: read("verification/requirements/requirements.json")?,
        capabilities: read(crate::MANIFEST_PATH)?,
        contract: read(crate::CONTRACT_PATH)?,
        packages: read("conformance/package.json")?,
    };
    let mut problems = Vec::new();
    inventory.validate(&mut problems);
    inventory.validate_gaps(root, &mut problems);
    if problems.is_empty() {
        Ok(render::documents(&inventory))
    } else {
        Err(problems)
    }
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn rows<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn strings<'a>(v: &'a Value, key: &str) -> Vec<&'a str> {
    rows(v, key).iter().filter_map(Value::as_str).collect()
}

fn fail(problems: &mut Vec<String>, rule: &str, context: &str, detail: &str) {
    problems.push(format!("{rule}: {context}: {detail}"));
}

fn shape(v: &Value, required: &[&str], optional: &[&str], context: &str, p: &mut Vec<String>) {
    let Some(object) = v.as_object() else {
        fail(p, "CI-01", context, "expected an object");
        return;
    };
    for key in required {
        if !object.contains_key(*key) {
            fail(p, "CI-01", context, &format!("missing {key}"));
        }
    }
    for key in object.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            fail(p, "CI-01", context, &format!("unknown field {key}"));
        }
    }
}

fn nonempty(v: &Value, keys: &[&str], context: &str, p: &mut Vec<String>) {
    for key in keys {
        if text(v, key).trim().is_empty() {
            fail(
                p,
                "CI-01",
                context,
                &format!("{key} must be a nonempty string"),
            );
        }
    }
}

fn choices(v: &Value, key: &str, choices: &[&str], context: &str, p: &mut Vec<String>) {
    if !choices.contains(&text(v, key)) {
        fail(
            p,
            "CI-01",
            context,
            &format!("unknown {key}: {}", text(v, key)),
        );
    }
}

fn string_array(v: &Value, key: &str, context: &str, p: &mut Vec<String>) {
    let Some(array) = v.get(key).and_then(Value::as_array) else {
        fail(p, "CI-01", context, &format!("{key} must be an array"));
        return;
    };
    let mut seen = BTreeSet::new();
    for entry in array {
        if let Some(s) = entry.as_str().filter(|s| !s.trim().is_empty()) {
            if !seen.insert(s) {
                fail(p, "CI-01", context, &format!("duplicate {key}: {s}"));
            }
        } else {
            fail(
                p,
                "CI-01",
                context,
                &format!("{key} needs nonempty strings"),
            );
        }
    }
}

fn index<'a>(v: &'a Value, key: &str, p: &mut Vec<String>) -> BTreeMap<&'a str, &'a Value> {
    let mut result = BTreeMap::new();
    if !v.get(key).is_some_and(Value::is_array) {
        fail(p, "CI-01", key, "expected an array");
    }
    for row in rows(v, key) {
        let id = text(row, "id");
        if id.is_empty()
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/#".contains(&b))
        {
            fail(p, "CI-01", key, "invalid ID");
        }
        if result.insert(id, row).is_some() {
            fail(p, "CI-01", key, &format!("duplicate ID {id}"));
        }
    }
    result
}

fn references(v: &Value, key: &str, known: &BTreeSet<&str>, p: &mut Vec<String>) {
    string_array(v, key, text(v, "id"), p);
    for id in strings(v, key) {
        if !known.contains(id) {
            fail(
                p,
                "CI-02",
                text(v, "id"),
                &format!("unknown {key} reference {id}"),
            );
        }
    }
}

fn classification(v: &Value, requirements: &BTreeSet<&str>, p: &mut Vec<String>) {
    let id = text(v, "id");
    choices(
        v,
        "classification",
        &[
            "requirement",
            "unknown",
            "duplicate",
            "introductory",
            "client-side",
            "external-service",
            "deferred",
        ],
        id,
        p,
    );
    nonempty(v, &["reason"], id, p);
    references(v, "requirements", requirements, p);
    if (text(v, "classification") == "requirement") == strings(v, "requirements").is_empty() {
        fail(
            p,
            "CI-03",
            id,
            "only requirement classifications must carry requirement IDs",
        );
    }
}

impl Inventory {
    fn validate(&self, p: &mut Vec<String>) {
        self.validate_meta(p);
        let requirements = index(&self.requirements, "requirements", p);
        for row in requirements.values() {
            choices(
                row,
                "status",
                &["planned", "partial", "implemented"],
                text(row, "id"),
                p,
            );
            nonempty(row, &["statement"], text(row, "id"), p);
        }
        let req_ids = requirements.keys().copied().collect();
        let sources = index(&self.sources, "sources", p);
        let source_ids = sources.keys().copied().collect();
        self.validate_sources(&req_ids, p);
        self.validate_surfaces(&req_ids, &source_ids, p);
        let surfaces = index(&self.surfaces, "surfaces", p);
        let surface_ids = surfaces.keys().copied().collect();
        self.validate_features(&req_ids, &source_ids, &surface_ids, p);
    }

    fn validate_meta(&self, p: &mut Vec<String>) {
        shape(
            &self.meta,
            &[
                "schemaVersion",
                "target",
                "inventoryStatus",
                "goals",
                "profiles",
                "evidence",
                "debt",
            ],
            &[],
            "inventory",
            p,
        );
        for (v, key) in [
            (&self.sources, "sources"),
            (&self.surfaces, "surfaces"),
            (&self.features, "features"),
        ] {
            shape(v, &["schemaVersion", key], &[], key, p);
        }
        for v in [&self.meta, &self.sources, &self.surfaces, &self.features] {
            if v["schemaVersion"].as_u64() != Some(1) {
                fail(p, "CI-01", "inventory", "schemaVersion must be 1");
            }
        }
        choices(&self.meta, "target", &["source-tree"], "inventory", p);
        choices(
            &self.meta,
            "inventoryStatus",
            &["incomplete"],
            "inventory",
            p,
        );
        for key in ["goals", "profiles", "debt"] {
            string_array(&self.meta, key, "inventory", p);
        }
        if strings(&self.meta, "goals")
            .into_iter()
            .collect::<BTreeSet<_>>()
            != GOALS.into_iter().collect()
        {
            fail(
                p,
                "CI-06",
                "inventory",
                "all eight goal groups must remain visible",
            );
        }
        if strings(&self.meta, "debt").is_empty() {
            fail(
                p,
                "CI-06",
                "inventory",
                "incomplete inventory needs explicit debt",
            );
        }
        if strings(&self.meta, "profiles").is_empty() {
            fail(p, "CI-02", "inventory", "profiles cannot be empty");
        }
        for profile in strings(&self.meta, "profiles") {
            if self
                .contract
                .get("profiles")
                .and_then(|v| v.get(profile))
                .is_none()
            {
                fail(
                    p,
                    "CI-02",
                    "inventory",
                    &format!("unknown profile {profile}"),
                );
            }
        }
        // Fail closed until receipts bind exact cases, artifact, configuration and assertions.
        if self
            .meta
            .get("evidence")
            .and_then(Value::as_array)
            .is_none_or(|v| !v.is_empty())
        {
            fail(
                p,
                "CI-05",
                "inventory",
                "schema 1 cannot accept execution receipts; evidence must be []",
            );
        }
        self.validate_packages(p);
    }

    fn validate_packages(&self, p: &mut Vec<String>) {
        for sdk in ["firebase", "firebase-admin", "firebase-tools"] {
            if self.packages["dependencies"][sdk]
                .as_str()
                .is_none_or(str::is_empty)
            {
                fail(
                    p,
                    "CI-01",
                    "SDK inventory",
                    &format!("missing {sdk} dependency"),
                );
            }
        }
    }

    fn validate_sources(&self, req_ids: &BTreeSet<&str>, p: &mut Vec<String>) {
        let mut urls = BTreeSet::new();
        for source in rows(&self.sources, "sources") {
            let id = text(source, "id");
            shape(
                source,
                &["id", "url", "kind", "language", "review", "sections"],
                &["provenance"],
                id,
                p,
            );
            nonempty(source, &["url", "language"], id, p);
            let url = text(source, "url");
            let official = [
                "https://firebase.google.com/",
                "https://docs.cloud.google.com/",
                "https://cloud.google.com/",
                "https://identitytoolkit.googleapis.com/",
                "https://firestore.googleapis.com/",
                "https://securetoken.googleapis.com/",
                "https://github.com/googleapis/",
                "https://github.com/firebase/",
            ];
            if !official.iter().any(|prefix| url.starts_with(prefix))
                || url
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || "<>[]()\\\"|`".contains(c))
            {
                fail(
                    p,
                    "CI-01",
                    id,
                    "expected a canonical official HTTPS URL without markup",
                );
            }
            if !urls.insert(url) {
                fail(p, "CI-01", id, "duplicate canonical URL");
            }
            choices(
                source,
                "kind",
                &[
                    "guide",
                    "reference",
                    "discovery",
                    "protobuf",
                    "sdk",
                    "limits",
                    "release-notes",
                    "emulator",
                ],
                id,
                p,
            );
            choices(
                source,
                "review",
                &["discovered", "unavailable", "needs-review"],
                id,
                p,
            );
            // Review completion requires a future snapshot/hash/extractor verification contract.
            // A URL and an author's assertion alone cannot count as reviewed.
            if source.get("provenance").is_some() {
                fail(
                    p,
                    "CI-04",
                    id,
                    "snapshot provenance acceptance is not implemented in schema 1",
                );
            }
            let sections = index(source, "sections", p);
            if sections.is_empty() {
                fail(p, "CI-03", id, "record at least an unknown entry section");
            }
            for section in sections.values() {
                shape(
                    section,
                    &["id", "classification", "reason", "requirements"],
                    &[],
                    id,
                    p,
                );
                classification(section, req_ids, p);
            }
        }
    }

    fn validate_surfaces(
        &self,
        req_ids: &BTreeSet<&str>,
        source_ids: &BTreeSet<&str>,
        p: &mut Vec<String>,
    ) {
        for surface in rows(&self.surfaces, "surfaces") {
            let id = text(surface, "id");
            shape(
                surface,
                &[
                    "id",
                    "source",
                    "locator",
                    "kind",
                    "transport",
                    "classification",
                    "reason",
                    "requirements",
                ],
                &[],
                id,
                p,
            );
            nonempty(surface, &["locator"], id, p);
            if !source_ids.contains(text(surface, "source")) {
                fail(p, "CI-02", id, "unknown source");
            }
            choices(
                surface,
                "kind",
                &[
                    "method",
                    "request",
                    "response",
                    "field",
                    "oneof",
                    "enum",
                    "transport",
                ],
                id,
                p,
            );
            choices(
                surface,
                "transport",
                &["REST", "gRPC", "WebChannel", "SDK", "MongoDB"],
                id,
                p,
            );
            classification(surface, req_ids, p);
        }
    }

    fn validate_features(
        &self,
        req_ids: &BTreeSet<&str>,
        source_ids: &BTreeSet<&str>,
        surface_ids: &BTreeSet<&str>,
        p: &mut Vec<String>,
    ) {
        let features = index(&self.features, "features", p);
        let Some(capabilities) = self.capabilities.as_object() else {
            fail(p, "CI-01", "capabilities", "expected an object");
            return;
        };
        let cap_ids = capabilities.keys().map(String::as_str).collect();
        let claims: BTreeMap<_, _> = rows(&self.contract, "surfaces")
            .iter()
            .flat_map(|s| rows(s, "claims"))
            .map(|c| (text(c, "id"), c))
            .collect();
        let claim_ids = claims.keys().copied().collect();
        for feature in features.values() {
            let id = text(feature, "id");
            shape(
                feature,
                &[
                    "id",
                    "title",
                    "goal",
                    "appliesTo",
                    "sources",
                    "surfaces",
                    "requirements",
                    "capabilities",
                    "claims",
                    "limitations",
                ],
                &[],
                id,
                p,
            );
            nonempty(feature, &["title", "appliesTo"], id, p);
            choices(feature, "goal", &GOALS, id, p);
            for (key, known) in [
                ("requirements", req_ids),
                ("sources", source_ids),
                ("surfaces", surface_ids),
                ("capabilities", &cap_ids),
                ("claims", &claim_ids),
            ] {
                references(feature, key, known, p);
            }
            string_array(feature, "limitations", id, p);
            if strings(feature, "sources").is_empty() || strings(feature, "limitations").is_empty()
            {
                fail(
                    p,
                    "CI-03",
                    id,
                    "features need sources and explicit limitations",
                );
            }
            for cap in strings(feature, "capabilities") {
                if let Some(entry) = capabilities.get(cap) {
                    choices(
                        entry,
                        "status",
                        &["implemented", "partial", "unsupported", "planned"],
                        cap,
                        p,
                    );
                }
                if !strings(feature, "claims")
                    .iter()
                    .filter_map(|id| claims.get(id))
                    .any(|claim| {
                        rows(claim, "capabilities")
                            .iter()
                            .any(|c| text(c, "id") == cap)
                    })
                {
                    fail(
                        p,
                        "CI-02",
                        id,
                        &format!("capability {cap} has no linked contract claim"),
                    );
                }
            }
        }
    }
}

impl Inventory {
    /// The gap ledger: every record names a known feature, keeps its four status axes in
    /// the allowed vocabularies, points at evidence that exists, and cannot claim more
    /// than its axes support (a comparison needs a production observation; a fix needs
    /// passing local tests).
    fn validate_gaps(&self, root: &Path, p: &mut Vec<String>) {
        if self.gaps.get("schemaVersion") != Some(&Value::from(1)) {
            fail(p, "CI-01", "gaps.json", "schemaVersion must be 1");
        }
        nonempty(&self.gaps, &["policy"], "gaps.json", p);
        let feature_ids: BTreeSet<&str> = rows(&self.features, "features")
            .iter()
            .map(|f| text(f, "id"))
            .collect();
        let gaps = index(&self.gaps, "gaps", p);
        for gap in gaps.values() {
            let id = text(gap, "id");
            shape(
                gap,
                &[
                    "id",
                    "feature",
                    "kind",
                    "scope",
                    "implementationStatus",
                    "localTestStatus",
                    "productionObservationStatus",
                    "comparisonStatus",
                    "evidenceRefs",
                    "nextAction",
                    "blockedReason",
                    "requiresProductionChange",
                ],
                &[],
                id,
                p,
            );
            nonempty(gap, &["scope", "nextAction"], id, p);
            if !feature_ids.contains(text(gap, "feature")) {
                fail(p, "CI-02", id, "gap feature is not a known feature id");
            }
            choices(gap, "kind", &GAP_KINDS, id, p);
            choices(gap, "implementationStatus", &GAP_IMPLEMENTATION, id, p);
            choices(gap, "localTestStatus", &GAP_LOCAL, id, p);
            choices(gap, "productionObservationStatus", &GAP_PRODUCTION, id, p);
            choices(gap, "comparisonStatus", &GAP_COMPARISON, id, p);
            string_array(gap, "evidenceRefs", id, p);
            if strings(gap, "evidenceRefs").is_empty() {
                fail(p, "CI-03", id, "gaps need at least one evidence reference");
            }
            for reference in strings(gap, "evidenceRefs") {
                if reference.contains("..") || !root.join(reference).exists() {
                    fail(
                        p,
                        "CI-03",
                        id,
                        &format!("evidence reference {reference} does not exist"),
                    );
                }
            }
            if !gap
                .get("requiresProductionChange")
                .is_some_and(Value::is_boolean)
            {
                fail(p, "CI-01", id, "requiresProductionChange must be a boolean");
            }
            if !gap.get("blockedReason").is_some_and(Value::is_string) {
                fail(
                    p,
                    "CI-01",
                    id,
                    "blockedReason must be a string (possibly empty)",
                );
            }
            if text(gap, "comparisonStatus") != "none"
                && text(gap, "productionObservationStatus") == "none"
            {
                fail(
                    p,
                    "CI-03",
                    id,
                    "a comparison needs a production observation",
                );
            }
            if text(gap, "implementationStatus") == "fixed"
                && text(gap, "localTestStatus") != "passing"
            {
                fail(p, "CI-03", id, "a fix needs passing local tests");
            }
            if text(gap, "kind") == "unobserved"
                && text(gap, "productionObservationStatus") != "none"
            {
                fail(
                    p,
                    "CI-03",
                    id,
                    "an unobserved gap cannot carry a production observation; change its kind",
                );
            }
            if text(gap, "kind") == "observed"
                && text(gap, "productionObservationStatus") == "none"
            {
                fail(
                    p,
                    "CI-03",
                    id,
                    "an observed gap must carry a production observation (recorded or approved)",
                );
            }
        }
    }
}
