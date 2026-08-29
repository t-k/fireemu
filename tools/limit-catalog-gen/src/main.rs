//! Generates `crates/ftd-core-limits/src/generated/*.rs` from `spec/limits/*.json`.
//!
//! This is a development tool. It is never linked into the release binary and a normal build
//! never runs it; the generated files are checked in.
//!
//! ```text
//! limit-catalog-gen generate [--spec-dir spec/limits] [--out-dir crates/ftd-core-limits/src/generated]
//! limit-catalog-gen check    [--spec-dir spec/limits] [--out-dir crates/ftd-core-limits/src/generated]
//! ```

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CatalogJson {
    schema_version: u32,
    id: String,
    product: String,
    edition: String,
    official_revision: String,
    official_last_updated_utc: String,
    reviewed_at_utc: String,
    conformance_revision: String,
    limits: Vec<LimitJson>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct LimitJson {
    id: String,
    class: String,
    boundary: String,
    unit: String,
    maximum: MaximumJson,
    precision: String,
    enforcement_stage: String,
    implemented: String,
    official_text: String,
    #[serde(default)]
    notes: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum MaximumJson {
    Fixed(u64),
    PlanDependent {
        #[serde(rename = "billingDisabled")]
        billing_disabled: u64,
        #[serde(rename = "billingEnabled")]
        billing_enabled: u64,
    },
    NotApplicable(Option<()>),
}

const CLASSES: &[(&str, &str)] = &[
    ("identifier-syntax", "IdentifierSyntax"),
    ("hard-resource", "HardResource"),
    ("runtime-budget", "RuntimeBudget"),
    ("time-budget", "TimeBudget"),
    ("plan-capacity", "PlanCapacity"),
    ("rate-quota", "RateQuota"),
    ("billing-quota", "BillingQuota"),
    ("backend-opaque", "BackendOpaque"),
];
const BOUNDARIES: &[(&str, &str)] = &[
    ("inclusive-maximum", "InclusiveMaximum"),
    ("exclusive-maximum", "ExclusiveMaximum"),
    ("exact", "Exact"),
    ("range-inclusive", "RangeInclusive"),
    ("syntax-constraint", "SyntaxConstraint"),
];
const UNITS: &[(&str, &str)] = &[
    ("count", "Count"),
    ("utf8-bytes", "Utf8Bytes"),
    ("logical-bytes", "LogicalBytes"),
    ("bytes", "Bytes"),
    ("kib", "KiB"),
    ("mib", "MiB"),
    ("published-kilobytes", "PublishedKilobytes"),
    ("seconds", "Seconds"),
    ("requests-per-minute", "RequestsPerMinute"),
    ("read-units", "ReadUnits"),
    ("write-units", "WriteUnits"),
    ("realtime-update-units", "RealtimeUpdateUnits"),
];
const PRECISIONS: &[(&str, &str)] = &[
    ("exact", "Exact"),
    ("boundary-conformance", "BoundaryConformance"),
    ("conservative", "Conservative"),
    ("estimated", "Estimated"),
    ("oracle-only", "OracleOnly"),
    ("not-applicable", "NotApplicable"),
    ("unsupported", "Unsupported"),
];
const STAGES: &[(&str, &str)] = &[
    ("config-load", "ConfigLoad"),
    ("request", "Request"),
    ("commit", "Commit"),
    ("query-plan", "QueryPlan"),
    ("rules-compile", "RulesCompile"),
    ("rules-runtime", "RulesRuntime"),
    ("management-api", "ManagementApi"),
    ("observe", "Observe"),
];
const STATUSES: &[(&str, &str)] = &[
    ("implemented", "Implemented"),
    ("unsupported", "Unsupported"),
    ("not-applicable", "NotApplicable"),
];

const MAX_TEXT_BYTES: usize = 2_000;

fn map_enum(table: &[(&str, &str)], value: &str, what: &str, id: &str) -> Result<String, String> {
    table
        .iter()
        .find(|(k, _)| *k == value)
        .map(|(_, v)| (*v).to_owned())
        .ok_or_else(|| format!("{id}: unknown {what} {value:?}"))
}

fn check_text(id: &str, field: &str, s: &str) -> Result<(), String> {
    if s.len() > MAX_TEXT_BYTES {
        return Err(format!("{id}: {field} exceeds {MAX_TEXT_BYTES} bytes"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("{id}: {field} contains control characters"));
    }
    Ok(())
}

fn is_catalog_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

fn is_limit_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[8 - 1] == b'-'
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

#[allow(clippy::too_many_lines)]
fn render(catalog: &CatalogJson, source_file: &str) -> Result<String, String> {
    if catalog.schema_version != 1 {
        return Err(format!(
            "{}: unsupported schemaVersion {}",
            catalog.id, catalog.schema_version
        ));
    }
    if !is_catalog_id(&catalog.id) {
        return Err(format!("invalid catalog id {:?}", catalog.id));
    }
    for (field, value) in [
        ("officialLastUpdatedUtc", &catalog.official_last_updated_utc),
        ("reviewedAtUtc", &catalog.reviewed_at_utc),
    ] {
        if !is_date(value) {
            return Err(format!("{}: {field} must be YYYY-MM-DD", catalog.id));
        }
    }
    if !catalog.id.ends_with(&catalog.official_last_updated_utc) {
        return Err(format!(
            "{}: catalog id must end with officialLastUpdatedUtc {}",
            catalog.id, catalog.official_last_updated_utc
        ));
    }
    for (field, value) in [
        ("product", &catalog.product),
        ("edition", &catalog.edition),
        ("officialRevision", &catalog.official_revision),
        ("conformanceRevision", &catalog.conformance_revision),
    ] {
        check_text(&catalog.id, field, value)?;
    }
    if catalog.limits.is_empty() {
        return Err(format!("{}: catalog has no limits", catalog.id));
    }

    let mut out = String::new();
    writeln!(
        out,
        "// @generated by tools/limit-catalog-gen from {source_file}."
    )
    .unwrap();
    writeln!(
        out,
        "// Do not edit by hand. Catalogs are immutable: add a new catalog ID instead."
    )
    .unwrap();
    writeln!(out, "#![allow(clippy::all, clippy::pedantic)]").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "use crate::model::*;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "/// Catalog `{}`.", catalog.id).unwrap();
    writeln!(out, "pub const CATALOG: LimitCatalog = LimitCatalog {{").unwrap();
    writeln!(out, "    meta: LimitCatalogMeta {{").unwrap();
    writeln!(out, "        id: {:?},", catalog.id).unwrap();
    writeln!(out, "        product: {:?},", catalog.product).unwrap();
    writeln!(out, "        edition: {:?},", catalog.edition).unwrap();
    writeln!(
        out,
        "        official_revision: {:?},",
        catalog.official_revision
    )
    .unwrap();
    writeln!(
        out,
        "        official_last_updated_utc: {:?},",
        catalog.official_last_updated_utc
    )
    .unwrap();
    writeln!(
        out,
        "        reviewed_at_utc: {:?},",
        catalog.reviewed_at_utc
    )
    .unwrap();
    writeln!(
        out,
        "        conformance_revision: {:?},",
        catalog.conformance_revision
    )
    .unwrap();
    writeln!(out, "    }},").unwrap();
    writeln!(out, "    limits: &[").unwrap();

    let mut seen = BTreeSet::new();
    for l in &catalog.limits {
        if !is_limit_id(&l.id) {
            return Err(format!("{}: invalid limit id {:?}", catalog.id, l.id));
        }
        if !seen.insert(l.id.as_str()) {
            return Err(format!("{}: duplicate limit id {}", catalog.id, l.id));
        }
        check_text(&l.id, "officialText", &l.official_text)?;
        check_text(&l.id, "notes", &l.notes)?;
        if l.official_text.trim().is_empty() {
            return Err(format!("{}: officialText is empty", l.id));
        }
        let class = map_enum(CLASSES, &l.class, "class", &l.id)?;
        let boundary = map_enum(BOUNDARIES, &l.boundary, "boundary", &l.id)?;
        let unit = map_enum(UNITS, &l.unit, "unit", &l.id)?;
        let precision = map_enum(PRECISIONS, &l.precision, "precision", &l.id)?;
        let stage = map_enum(STAGES, &l.enforcement_stage, "enforcementStage", &l.id)?;
        let status = map_enum(STATUSES, &l.implemented, "implemented", &l.id)?;
        let maximum = match &l.maximum {
            MaximumJson::Fixed(v) => format!("LimitMaximum::Fixed({v})"),
            MaximumJson::PlanDependent { billing_disabled, billing_enabled } => format!(
                "LimitMaximum::PlanDependent {{ billing_disabled: {billing_disabled}, billing_enabled: {billing_enabled} }}"
            ),
            MaximumJson::NotApplicable(None) => "LimitMaximum::NotApplicable".to_owned(),
            MaximumJson::NotApplicable(Some(())) => {
                return Err(format!("{}: maximum must be a number, a plan object or null", l.id))
            }
        };
        if l.precision == "exact" && matches!(l.maximum, MaximumJson::NotApplicable(_)) {
            return Err(format!("{}: exact precision requires a maximum", l.id));
        }
        if l.implemented == "implemented" && l.precision == "unsupported" {
            return Err(format!(
                "{}: implemented limit cannot have unsupported precision",
                l.id
            ));
        }
        writeln!(out, "        LimitDefinition {{").unwrap();
        writeln!(out, "            id: {:?},", l.id).unwrap();
        writeln!(out, "            class: LimitClass::{class},").unwrap();
        writeln!(out, "            boundary: LimitBoundary::{boundary},").unwrap();
        writeln!(out, "            unit: LimitUnit::{unit},").unwrap();
        writeln!(out, "            maximum: {maximum},").unwrap();
        writeln!(
            out,
            "            precision: EnforcementPrecision::{precision},"
        )
        .unwrap();
        writeln!(
            out,
            "            enforcement_stage: EnforcementStage::{stage},"
        )
        .unwrap();
        writeln!(
            out,
            "            implemented: ImplementationStatus::{status},"
        )
        .unwrap();
        writeln!(out, "            official_text: {:?},", l.official_text).unwrap();
        writeln!(out, "            notes: {:?},", l.notes).unwrap();
        writeln!(out, "        }},").unwrap();
    }
    writeln!(out, "    ],").unwrap();
    writeln!(out, "}};").unwrap();
    Ok(out)
}

fn module_name(catalog_id: &str) -> String {
    catalog_id.replace('-', "_")
}

fn render_mod(catalogs: &[CatalogJson]) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "// @generated by tools/limit-catalog-gen. Do not edit by hand."
    )
    .unwrap();
    writeln!(out, "//! Generated limit catalogs.").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "use crate::model::LimitCatalog;").unwrap();
    writeln!(out).unwrap();
    for c in catalogs {
        let m = module_name(&c.id);
        writeln!(out, "mod {m};").unwrap();
    }
    writeln!(out).unwrap();
    for c in catalogs {
        let m = module_name(&c.id);
        writeln!(out, "/// Catalog `{}`.", c.id).unwrap();
        // Match rustfmt (max_width = 100) so that `cargo fmt --check` and the generator agree.
        let one_line = format!(
            "pub const {}: LimitCatalog = {m}::CATALOG;",
            m.to_uppercase()
        );
        if one_line.len() <= 100 {
            writeln!(out, "{one_line}").unwrap();
        } else {
            writeln!(out, "pub const {}: LimitCatalog =", m.to_uppercase()).unwrap();
            writeln!(out, "    {m}::CATALOG;").unwrap();
        }
    }
    writeln!(out).unwrap();
    writeln!(
        out,
        "/// Every checked-in catalog, oldest first by file order."
    )
    .unwrap();
    writeln!(out, "pub const ALL_CATALOGS: &[&LimitCatalog] = &[").unwrap();
    for c in catalogs {
        writeln!(out, "    &{},", module_name(&c.id).to_uppercase()).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "/// Finds a catalog by its immutable ID.").unwrap();
    writeln!(out, "#[must_use]").unwrap();
    writeln!(
        out,
        "pub fn find_catalog(id: &str) -> Option<&'static LimitCatalog> {{"
    )
    .unwrap();
    writeln!(
        out,
        "    ALL_CATALOGS.iter().copied().find(|c| c.meta.id == id)"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
    out
}

fn load_catalogs(spec_dir: &Path) -> Result<Vec<(String, CatalogJson)>, String> {
    let mut files: Vec<PathBuf> = fs::read_dir(spec_dir)
        .map_err(|e| format!("cannot read {}: {e}", spec_dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    let mut ids = BTreeSet::new();
    let mut limit_ids = BTreeSet::new();
    for f in files {
        let text = fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let catalog: CatalogJson =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", f.display()))?;
        let stem = f
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned();
        if stem != catalog.id {
            return Err(format!(
                "{}: file name must equal catalog id {}",
                f.display(),
                catalog.id
            ));
        }
        if !ids.insert(catalog.id.clone()) {
            return Err(format!("duplicate catalog id {}", catalog.id));
        }
        for l in &catalog.limits {
            if !limit_ids.insert(l.id.clone()) {
                return Err(format!(
                    "limit id {} appears in more than one catalog",
                    l.id
                ));
            }
        }
        out.push((format!("spec/limits/{stem}.json"), catalog));
    }
    Ok(out)
}

fn expected_files(spec_dir: &Path) -> Result<Vec<(String, String)>, String> {
    let catalogs = load_catalogs(spec_dir)?;
    let mut files = Vec::new();
    for (source, c) in &catalogs {
        files.push((format!("{}.rs", module_name(&c.id)), render(c, source)?));
    }
    let only: Vec<CatalogJson> = catalogs.into_iter().map(|(_, c)| c).collect();
    files.push(("mod.rs".to_owned(), render_mod(&only)));
    Ok(files)
}

fn run(args: &[String]) -> Result<(), String> {
    let mode = args.first().map_or("check", String::as_str);
    let mut spec_dir = PathBuf::from("spec/limits");
    let mut out_dir = PathBuf::from("crates/ftd-core-limits/src/generated");
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--spec-dir" => {
                spec_dir = PathBuf::from(args.get(i + 1).ok_or("--spec-dir needs a value")?);
                i += 2;
            }
            "--out-dir" => {
                out_dir = PathBuf::from(args.get(i + 1).ok_or("--out-dir needs a value")?);
                i += 2;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let files = expected_files(&spec_dir)?;
    match mode {
        "generate" => {
            fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
            for (name, content) in &files {
                fs::write(out_dir.join(name), content).map_err(|e| e.to_string())?;
                println!("wrote {}", out_dir.join(name).display());
            }
            Ok(())
        }
        "check" => {
            let mut drift = Vec::new();
            for (name, content) in &files {
                let path = out_dir.join(name);
                match fs::read_to_string(&path) {
                    Ok(existing) if existing == *content => {}
                    Ok(_) => drift.push(format!("{} differs from spec", path.display())),
                    Err(_) => drift.push(format!("{} is missing", path.display())),
                }
            }
            let expected: BTreeSet<String> = files.iter().map(|(n, _)| n.clone()).collect();
            if let Ok(rd) = fs::read_dir(&out_dir) {
                for e in rd.filter_map(Result::ok) {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let is_rust = std::path::Path::new(&name)
                        .extension()
                        .is_some_and(|x| x.eq_ignore_ascii_case("rs"));
                    if is_rust && !expected.contains(&name) {
                        drift.push(format!("{} has no spec source", e.path().display()));
                    }
                }
            }
            if drift.is_empty() {
                println!("limit catalogs are up to date ({} files)", files.len());
                Ok(())
            } else {
                Err(drift.join("\n"))
            }
        }
        other => Err(format!("unknown mode {other}; use generate or check")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
