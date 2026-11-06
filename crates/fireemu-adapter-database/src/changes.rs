//! Coupled RTDB mutation preparation and source-event publication.

use std::fmt;

use fireemu_core_database::DatabaseError;
/// Database types required by source-event capture implementations.
pub use fireemu_core_database::{Content, Leaf, Node, Path, Tree};
use fireemu_core_types::admission::EventAdmissionError;
use serde_json::Value;

/// Originating principal, kept separate from Rules impersonation input.
#[derive(Clone, PartialEq)]
pub struct Principal {
    /// Legacy principal classification, independent of a Rules override.
    pub auth_type: String,
    /// Verified principal identifier, if known.
    pub auth_id: Option<String>,
    /// Legacy user auth object; never a bearer credential.
    pub auth: Option<Value>,
}
impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Principal")
            .field("auth_type", &self.auth_type)
            .finish_non_exhaustive()
    }
}
/// The source operation owning one candidate mutation.
#[derive(Debug, Clone)]
pub struct ChangeContext {
    /// Exact namespace whose tree changes.
    pub namespace: String,
    /// Monotonic source-operation sequence.
    pub sequence: u64,
    /// Resolved source clock time.
    pub now_millis: i64,
    /// Originating principal.
    pub principal: Principal,
}
/// Immutable snapshots prepared before source publication.
#[derive(Debug, Clone)]
pub struct CommittedChange {
    /// Source identity and actor.
    pub context: ChangeContext,
    /// Export-form snapshots selected for this operation.
    pub data: ChangeData,
}
/// Complete trees for generic sinks, or only exact matching changed references.
#[derive(Debug, Clone)]
pub enum ChangeData {
    /// Compatibility path for sinks without a capture projection.
    Whole {
        /// Tree before the mutation.
        before: Value,
        /// Tree after the mutation.
        after: Value,
    },
    /// Each concrete reference appears once, including ancestor trigger snapshots.
    References(Vec<ReferenceChange>),
}
/// Immutable export-form snapshots at a concrete trigger reference.
#[derive(Debug, Clone)]
pub struct ReferenceChange {
    /// Concrete database path, not a wildcard pattern.
    pub reference: Path,
    /// Snapshot before the mutation.
    pub before: Value,
    /// Snapshot after the mutation.
    pub after: Value,
}
/// A reserved complete event fanout, refunded on drop unless published.
pub trait Publication: Send {
    /// Activates already reserved events after source data becomes visible.
    fn publish(self: Box<Self>);
}
/// Atomically admits a whole source operation's event fanout.
pub trait ChangeSink: fmt::Debug + Send + Sync {
    /// Avoids snapshot work for namespaces without a configured target.
    fn interested(&self, _namespace: &str) -> bool {
        true
    }

    /// Whether a write confined to `scope` (the node at `scope` and below, and the existence
    /// of its ancestors) can change a trigger reference. A write it does not affect is applied
    /// in place: no candidate tree, no snapshot comparison and no reservation (review S3).
    fn affects(&self, _namespace: &str, _scope: &Path) -> bool {
        true
    }

    /// Selects exact changed trigger references without exporting unrelated data.
    /// A bounded matcher may reject excessive fanout before retaining all paths.
    fn capture_references(
        &self,
        _namespace: &str,
        _before: &Tree,
        _after: &Tree,
    ) -> Result<Option<Vec<Path>>, EventAdmissionError> {
        Ok(None)
    }

    /// [`Self::capture_references`] for a write confined to `scope`: nothing outside `scope`
    /// and its ancestors changed, so a matcher need not compare other branches.
    fn capture_references_within(
        &self,
        namespace: &str,
        before: &Tree,
        after: &Tree,
        _scope: &Path,
    ) -> Result<Option<Vec<Path>>, EventAdmissionError> {
        self.capture_references(namespace, before, after)
    }

    /// Refuses before source publication, or returns the complete reservation.
    fn reserve(
        &self,
        change: &CommittedChange,
    ) -> Result<Box<dyn Publication>, EventAdmissionError>;
}
/// A candidate can fail validation or coupled event admission.
#[derive(Debug)]
pub enum ChangeError {
    /// The database rejected the candidate mutation.
    Database(DatabaseError),
    /// The event runtime could not reserve the complete fanout.
    Admission(EventAdmissionError),
}
/// A tree candidate and its unpublished event reservation.
pub struct PreparedChange {
    tree: Tree,
    publication: Option<Box<dyn Publication>>,
}
impl PreparedChange {
    /// Publishes source data before activating its already admitted events.
    pub fn commit(self, tree: &mut Tree) {
        *tree = self.tree;
        if let Some(publication) = self.publication {
            publication.publish();
        }
    }
}
/// Builds a complete candidate without touching the visible source tree.
pub fn prepare<R>(
    tree: &Tree,
    context: ChangeContext,
    sink: Option<&dyn ChangeSink>,
    operation: impl FnOnce(&mut Tree) -> Result<R, DatabaseError>,
) -> Result<(R, PreparedChange), ChangeError> {
    prepare_within(tree, &Path::root(), context, sink, operation)
}

/// [`prepare`] for an operation that changes only the node at `scope`, its descendants and
/// whether its ancestors exist (a set or an update at `scope`): whether anything changed is
/// read at `scope` alone, never by comparing the whole tree.
pub fn prepare_within<R>(
    tree: &Tree,
    scope: &Path,
    context: ChangeContext,
    sink: Option<&dyn ChangeSink>,
    operation: impl FnOnce(&mut Tree) -> Result<R, DatabaseError>,
) -> Result<(R, PreparedChange), ChangeError> {
    let mut candidate = tree.clone();
    let result = operation(&mut candidate).map_err(ChangeError::Database)?;
    let publication = if tree.get(scope) == candidate.get(scope) {
        None
    } else if let Some(sink) = sink {
        let data = match sink
            .capture_references_within(&context.namespace, tree, &candidate, scope)
            .map_err(ChangeError::Admission)?
        {
            None => ChangeData::Whole {
                before: export_value(tree, &Path::root()),
                after: export_value(&candidate, &Path::root()),
            },
            Some(paths) => {
                let paths: std::collections::BTreeSet<_> = paths.into_iter().collect();
                let references = paths
                    .into_iter()
                    .filter(|path| tree.get(path) != candidate.get(path))
                    .map(|reference| ReferenceChange {
                        before: export_value(tree, &reference),
                        after: export_value(&candidate, &reference),
                        reference,
                    })
                    .collect();
                ChangeData::References(references)
            }
        };
        if matches!(&data, ChangeData::References(references) if references.is_empty()) {
            None
        } else {
            Some(
                sink.reserve(&CommittedChange { context, data })
                    .map_err(ChangeError::Admission)?,
            )
        }
    } else {
        None
    };
    Ok((
        result,
        PreparedChange {
            tree: candidate,
            publication,
        },
    ))
}

/// The export JSON of the value at `path` (`null` when absent), written from the tree into a
/// `Value` without rendering text: the same `Value` that parsing the compact export text
/// gives, so the trigger event body keeps its bytes. No `.priority` path reaches here: no
/// child has that key, so such a reference never differs between the trees.
fn export_value(tree: &Tree, path: &Path) -> Value {
    tree.get(path).map_or(Value::Null, node_value)
}

/// [`Node::to_json`] in the export format, as a `Value`.
fn node_value(node: &Node) -> Value {
    use fireemu_core_database::node::VALUE_KEY;
    use fireemu_core_database::path::PRIORITY_KEY;
    let priority = node.priority.as_deref().map(priority_value);
    match &node.content {
        Content::Leaf(leaf) => {
            let value = match leaf {
                Leaf::Bool(value) => Value::Bool(*value),
                Leaf::Number(number) => number_value(*number),
                Leaf::String(value) => Value::String(value.clone()),
            };
            match priority {
                None => value,
                Some(priority) => Value::Object(serde_json::Map::from_iter([
                    (VALUE_KEY.to_owned(), value),
                    (PRIORITY_KEY.to_owned(), priority),
                ])),
            }
        }
        Content::Children(children) => {
            let mut map: serde_json::Map<String, Value> = children
                .iter()
                .map(|(key, child)| (key.clone(), node_value(child)))
                .collect();
            if let Some(priority) = priority {
                map.insert(PRIORITY_KEY.to_owned(), priority);
            }
            Value::Object(map)
        }
    }
}

fn priority_value(priority: &fireemu_core_database::Priority) -> Value {
    match priority {
        fireemu_core_database::Priority::Number(number) => number_value(*number),
        fireemu_core_database::Priority::String(value) => Value::String(value.clone()),
    }
}

/// A database number as a `Value`.
fn number_value(number: fireemu_core_database::Number) -> Value {
    match number {
        fireemu_core_database::Number::Int(value) => Value::from(value),
        // A double is read back from its rendered text, as the text path read it:
        // `serde_json`'s default float parser can land one ULP away from the stored double,
        // and the event body must not change here.
        fireemu_core_database::Number::Double(value) => {
            serde_json::from_str(&crate::json_text::java_double(value))
                .expect("a finite double renders a JSON number")
        }
    }
}
