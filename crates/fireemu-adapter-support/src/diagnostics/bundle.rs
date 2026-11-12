use super::redact;
use serde_json::{json, Value};

/// The supported bundle schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// A versioned component.
#[derive(Clone, Debug, PartialEq)]
pub struct Component {
    /// Component name.
    pub name: String,
    /// Component version.
    pub version: String,
    /// Associated path, if present.
    pub path: Option<String>,
}
/// Versions of fireemu and related components.
#[derive(Clone, Debug, PartialEq)]
pub struct Versions {
    /// Fireemu version.
    pub fireemu: String,
    /// Runtime components.
    pub runtimes: Vec<Component>,
    /// SDK components.
    pub sdks: Vec<Component>,
}
/// A supported effective configuration value.
#[derive(Clone, Debug, PartialEq)]
pub enum ConfigValue {
    /// A boolean value.
    Bool(bool),
    /// A signed integer value.
    Int(i64),
    /// A string value.
    Str(String),
    /// A null value.
    Null,
}
/// Function execution diagnostics.
#[derive(Clone, Debug, PartialEq)]
pub struct FunctionsSection {
    /// Function events.
    pub events: Vec<Value>,
    /// Function attempts.
    pub attempts: Vec<Value>,
    /// Function retries.
    pub retries: Vec<Value>,
    /// Whether function logs have gaps.
    pub log_gaps: bool,
}
/// A condition evaluated during a rule denial.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleCondition {
    /// Source line.
    pub line: u32,
    /// Source column.
    pub column: u32,
    /// Source excerpt, if available.
    pub excerpt: Option<String>,
    /// Condition outcome.
    pub outcome: String,
}
/// A denied rules request.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleDenial {
    /// Service name.
    pub service: String,
    /// Rules location.
    pub location: String,
    /// Request method.
    pub method: String,
    /// Associated path, if present.
    pub path: String,
    /// User identifier, if present.
    pub uid: Option<String>,
    /// Denial reason.
    pub reason: String,
    /// Evaluated conditions.
    pub conditions: Vec<RuleCondition>,
}
/// Rules history and denials.
#[derive(Clone, Debug, PartialEq)]
pub struct RulesSection {
    /// Whether rules history is enabled.
    pub history_enabled: bool,
    /// Rules history retention.
    pub retention: u32,
    /// History start time, if available.
    pub history_started_at: Option<String>,
    /// Recorded denials.
    pub denials: Vec<RuleDenial>,
    /// Number of dropped entries.
    pub dropped: u64,
}
/// Pending tasks and resources.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingSection {
    /// Pending tasks.
    pub tasks: Vec<Value>,
    /// Pending resources.
    pub resources: Vec<Value>,
}
/// A range of omitted log lines.
#[derive(Clone, Debug, PartialEq)]
pub struct DroppedRange {
    /// Start of the dropped range.
    pub from: String,
    /// End of the dropped range.
    pub to: String,
    /// Number of dropped log lines.
    pub count: u64,
}
/// Captured logs and dropped ranges.
#[derive(Clone, Debug, PartialEq)]
pub struct LogSection {
    /// Captured log lines.
    pub lines: Vec<String>,
    /// Ranges of dropped log lines.
    pub dropped_ranges: Vec<DroppedRange>,
}
/// Caller-provided diagnostics data.
#[derive(Clone, Debug, PartialEq)]
pub struct BundleInput {
    /// Caller-supplied UTC timestamp.
    pub generated_at: String,
    /// Component versions.
    pub versions: Versions,
    /// Effective configuration entries.
    pub config: Vec<(String, ConfigValue)>,
    /// Function diagnostics.
    pub functions: FunctionsSection,
    /// Rules diagnostics.
    pub rules: RulesSection,
    /// Missing index details.
    pub indexes: Vec<Value>,
    /// Pending work.
    pub pending: PendingSection,
    /// Log diagnostics.
    pub logs: LogSection,
}
/// The number of entries omitted from a section.
#[derive(Clone, Debug, PartialEq)]
pub struct Truncation {
    /// Name of the truncated section.
    pub section: String,
    /// Number of retained entries.
    pub kept: usize,
    /// Number of dropped entries.
    pub dropped: u64,
}
/// Maximum retained entries for bounded sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum retained denials.
    pub max_denials: usize,
    /// Maximum retained function events.
    pub max_events: usize,
    /// Maximum retained log lines.
    pub max_log_lines: usize,
    /// Maximum bytes retained in each string value.
    pub max_string_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_denials: 1000,
            max_events: 1000,
            max_log_lines: 1000,
            max_string_bytes: 4096,
        }
    }
}
/// A redacted, bounded diagnostics bundle.
#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    /// Bundle schema version.
    pub schema_version: u32,
    /// Caller-supplied UTC timestamp.
    pub generated_at: String,
    /// Component versions.
    pub versions: Versions,
    /// Effective configuration entries.
    pub config: Vec<(String, ConfigValue)>,
    /// Function diagnostics.
    pub functions: FunctionsSection,
    /// Rules diagnostics.
    pub rules: RulesSection,
    /// Missing index details.
    pub indexes: Vec<Value>,
    /// Pending work.
    pub pending: PendingSection,
    /// Log diagnostics.
    pub logs: LogSection,
    /// Records of truncated sections.
    pub truncations: Vec<Truncation>,
    /// Number of redactions.
    pub redactions: u64,
}

impl Bundle {
    /// Builds a bounded bundle and scrubs sensitive text.
    #[allow(clippy::too_many_lines)]
    pub fn from_input(mut input: BundleInput, limits: Limits) -> Self {
        fn limit<T>(items: &mut Vec<T>, max: usize, section: &str, out: &mut Vec<Truncation>) {
            if items.len() > max {
                out.push(Truncation {
                    section: section.into(),
                    kept: max,
                    dropped: (items.len() - max) as u64,
                });
                items.truncate(max);
            }
        }
        fn clean(v: &mut Value, count: &mut u64, max: usize, cuts: &mut Vec<Truncation>) {
            match v {
                Value::String(s) => {
                    let (new, n) = redact::scrub(s);
                    *s = new;
                    *count += n;
                    if s.len() > max {
                        let mut end = max;
                        while !s.is_char_boundary(end) {
                            end -= 1;
                        }
                        // For string truncations, kept is the byte limit and dropped is the number of bytes removed.
                        cuts.push(Truncation {
                            section: "strings".into(),
                            kept: max,
                            dropped: (s.len() - end) as u64,
                        });
                        s.truncate(end);
                    }
                }
                Value::Array(a) => {
                    for x in a {
                        clean(x, count, max, cuts);
                    }
                }
                Value::Object(o) => {
                    let old = std::mem::take(o);
                    for (k, mut v) in old {
                        if k.eq_ignore_ascii_case("refreshToken")
                            || k.eq_ignore_ascii_case("refresh_token")
                        {
                            v = Value::String("[redacted]".into());
                            *count += 1;
                        }
                        let (k, n) = redact::scrub(&k);
                        *count += n;
                        clean(&mut v, count, max, cuts);
                        o.insert(k, v);
                    }
                }
                _ => {}
            }
        }
        let mut truncations = Vec::new();
        limit(
            &mut input.functions.events,
            limits.max_events,
            "functions.events",
            &mut truncations,
        );
        limit(
            &mut input.rules.denials,
            limits.max_denials,
            "rules.denials",
            &mut truncations,
        );
        limit(
            &mut input.logs.lines,
            limits.max_log_lines,
            "logs.lines",
            &mut truncations,
        );
        let mut b = Self {
            schema_version: SCHEMA_VERSION,
            generated_at: input.generated_at,
            versions: input.versions,
            config: input.config,
            functions: input.functions,
            rules: input.rules,
            indexes: input.indexes,
            pending: input.pending,
            logs: input.logs,
            truncations,
            redactions: 0,
        };
        // Scrub a value representation so nested JSON keys and values receive the same treatment.
        let mut v = to_value(&b);
        let mut count = 0;
        // Config keys are array elements in the JSON representation, so scrub them separately without cutting them.
        let mut config = v
            .as_object_mut()
            .expect("bundle object")
            .remove("config")
            .expect("config");
        let existing_truncations = v
            .as_object_mut()
            .expect("bundle object")
            .remove("truncations")
            .expect("truncations");
        let mut cuts = Vec::new();
        clean(&mut v, &mut count, limits.max_string_bytes, &mut cuts);
        for pair in config.as_array_mut().expect("config array") {
            let pair = pair.as_array_mut().expect("config pair");
            let (key, n) = redact::scrub(pair[0].as_str().expect("config key"));
            pair[0] = Value::String(key);
            count += n;
            clean(&mut pair[1], &mut count, limits.max_string_bytes, &mut cuts);
        }
        v.as_object_mut()
            .expect("bundle object")
            .insert("config".into(), config);
        v.as_object_mut()
            .expect("bundle object")
            .insert("truncations".into(), existing_truncations);
        b = from_value(&v).expect("scrubbing preserves bundle shape");
        b.truncations.extend(cuts);
        b.redactions = count;
        b
    }
}

/// Object keys are emitted in lexicographic order by `serde_json`'s default map.
pub fn to_value(b: &Bundle) -> Value {
    fn component(c: &Component) -> Value {
        json!({"name":c.name,"version":c.version,"path":c.path})
    }
    fn condition(c: &RuleCondition) -> Value {
        json!({"line":c.line,"column":c.column,"excerpt":c.excerpt,"outcome":c.outcome})
    }
    fn denial(d: &RuleDenial) -> Value {
        json!({"service":d.service,"location":d.location,"method":d.method,"path":d.path,"uid":d.uid,"reason":d.reason,"conditions":d.conditions.iter().map(condition).collect::<Vec<_>>()})
    }
    let config: Vec<_> = b
        .config
        .iter()
        .map(|(k, v)| {
            json!([
                k,
                match v {
                    ConfigValue::Bool(x) => json!(x),
                    ConfigValue::Int(x) => json!(x),
                    ConfigValue::Str(x) => json!(x),
                    ConfigValue::Null => Value::Null,
                }
            ])
        })
        .collect();
    json!({"schemaVersion":b.schema_version,"generatedAt":b.generated_at,"versions":{"fireemu":b.versions.fireemu,"runtimes":b.versions.runtimes.iter().map(component).collect::<Vec<_>>(),"sdks":b.versions.sdks.iter().map(component).collect::<Vec<_>>()},"config":config,"functions":{"events":b.functions.events,"attempts":b.functions.attempts,"retries":b.functions.retries,"logGaps":b.functions.log_gaps},"rules":{"historyEnabled":b.rules.history_enabled,"retention":b.rules.retention,"historyStartedAt":b.rules.history_started_at,"denials":b.rules.denials.iter().map(denial).collect::<Vec<_>>(),"dropped":b.rules.dropped},"indexes":b.indexes,"pending":{"tasks":b.pending.tasks,"resources":b.pending.resources},"logs":{"lines":b.logs.lines,"droppedRanges":b.logs.dropped_ranges.iter().map(|r| json!({"from":r.from,"to":r.to,"count":r.count})).collect::<Vec<_>>()},"truncations":b.truncations.iter().map(|t| json!({"section":t.section,"kept":t.kept,"dropped":t.dropped})).collect::<Vec<_>>(),"redactions":b.redactions})
}
/// Encodes a bundle as pretty-printed JSON.
pub fn to_json(b: &Bundle) -> String {
    serde_json::to_string_pretty(&to_value(b)).expect("JSON value is serializable")
}
/// Decodes a bundle from JSON.
pub fn from_json(text: &str) -> Result<Bundle, String> {
    let v = serde_json::from_str(text).map_err(|e| format!("{e}"))?;
    from_value(&v)
}
/// Decodes a bundle from a JSON value, checking its schema version.
#[allow(clippy::too_many_lines)]
pub fn from_value(v: &Value) -> Result<Bundle, String> {
    fn field<'a>(v: &'a Value, k: &str) -> Result<&'a Value, String> {
        v.get(k).ok_or_else(|| format!("missing {k}"))
    }
    fn s(v: &Value) -> Result<String, String> {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| "expected string".into())
    }
    fn opt(v: &Value) -> Result<Option<String>, String> {
        if v.is_null() {
            Ok(None)
        } else {
            Ok(Some(s(v)?))
        }
    }
    fn num(v: &Value) -> Result<u64, String> {
        v.as_u64().ok_or_else(|| "expected unsigned integer".into())
    }
    fn u32v(v: &Value) -> Result<u32, String> {
        u32::try_from(num(v)?).map_err(|e| e.to_string())
    }
    fn boolean(v: &Value) -> Result<bool, String> {
        v.as_bool().ok_or_else(|| "expected boolean".into())
    }
    fn arr(v: &Value) -> Result<&Vec<Value>, String> {
        v.as_array().ok_or_else(|| "expected array".into())
    }
    fn list<T>(v: &Value, f: impl Fn(&Value) -> Result<T, String>) -> Result<Vec<T>, String> {
        arr(v)?.iter().map(f).collect()
    }
    fn component(v: &Value) -> Result<Component, String> {
        Ok(Component {
            name: s(field(v, "name")?)?,
            version: s(field(v, "version")?)?,
            path: opt(field(v, "path")?)?,
        })
    }
    fn condition(v: &Value) -> Result<RuleCondition, String> {
        Ok(RuleCondition {
            line: u32v(field(v, "line")?)?,
            column: u32v(field(v, "column")?)?,
            excerpt: opt(field(v, "excerpt")?)?,
            outcome: s(field(v, "outcome")?)?,
        })
    }
    fn denial(v: &Value) -> Result<RuleDenial, String> {
        Ok(RuleDenial {
            service: s(field(v, "service")?)?,
            location: s(field(v, "location")?)?,
            method: s(field(v, "method")?)?,
            path: s(field(v, "path")?)?,
            uid: opt(field(v, "uid")?)?,
            reason: s(field(v, "reason")?)?,
            conditions: list(field(v, "conditions")?, condition)?,
        })
    }
    let version = field(v, "schemaVersion")?;
    if version.as_u64() != Some(u64::from(SCHEMA_VERSION)) {
        return Err(format!("unsupported schemaVersion {version}"));
    }
    let versions = field(v, "versions")?;
    let functions = field(v, "functions")?;
    let rules = field(v, "rules")?;
    let pending = field(v, "pending")?;
    let logs = field(v, "logs")?;
    Ok(Bundle {
        schema_version: SCHEMA_VERSION,
        generated_at: s(field(v, "generatedAt")?)?,
        versions: Versions {
            fireemu: s(field(versions, "fireemu")?)?,
            runtimes: list(field(versions, "runtimes")?, component)?,
            sdks: list(field(versions, "sdks")?, component)?,
        },
        config: list(field(v, "config")?, |x| {
            let a = arr(x)?;
            if a.len() != 2 {
                return Err("expected config pair".into());
            }
            let val = match &a[1] {
                Value::Null => ConfigValue::Null,
                Value::Bool(b) => ConfigValue::Bool(*b),
                Value::String(s) => ConfigValue::Str(s.clone()),
                Value::Number(n) => ConfigValue::Int(n.as_i64().ok_or("expected signed integer")?),
                _ => return Err("invalid config value".into()),
            };
            Ok((s(&a[0])?, val))
        })?,
        functions: FunctionsSection {
            events: arr(field(functions, "events")?)?.clone(),
            attempts: arr(field(functions, "attempts")?)?.clone(),
            retries: arr(field(functions, "retries")?)?.clone(),
            log_gaps: boolean(field(functions, "logGaps")?)?,
        },
        rules: RulesSection {
            history_enabled: boolean(field(rules, "historyEnabled")?)?,
            retention: u32v(field(rules, "retention")?)?,
            history_started_at: opt(field(rules, "historyStartedAt")?)?,
            denials: list(field(rules, "denials")?, denial)?,
            dropped: num(field(rules, "dropped")?)?,
        },
        indexes: arr(field(v, "indexes")?)?.clone(),
        pending: PendingSection {
            tasks: arr(field(pending, "tasks")?)?.clone(),
            resources: arr(field(pending, "resources")?)?.clone(),
        },
        logs: LogSection {
            lines: list(field(logs, "lines")?, s)?,
            dropped_ranges: list(field(logs, "droppedRanges")?, |x| {
                Ok(DroppedRange {
                    from: s(field(x, "from")?)?,
                    to: s(field(x, "to")?)?,
                    count: num(field(x, "count")?)?,
                })
            })?,
        },
        truncations: list(field(v, "truncations")?, |x| {
            Ok(Truncation {
                section: s(field(x, "section")?)?,
                kept: usize::try_from(num(field(x, "kept")?)?).map_err(|e| e.to_string())?,
                dropped: num(field(x, "dropped")?)?,
            })
        })?,
        redactions: num(field(v, "redactions")?)?,
    })
}
