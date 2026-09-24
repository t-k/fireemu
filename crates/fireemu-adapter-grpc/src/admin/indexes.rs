//! Composite indexes created through the Admin API (`collectionGroups/{g}/indexes`).
//!
//! Production builds an index for minutes: it is `CREATING` until it is `READY`, a query that
//! needs it is refused as "currently building" meanwhile, and only a `READY` index serves.
//! The local build takes [`DEFAULT_INDEX_BUILD`] of wall-clock time (or any advance of the
//! virtual clock past it), so both states are observable and a caller polling for `READY`
//! gets there (scope decision C10: the states and their order are production's, not how long
//! each lasts). A deleted index stops serving at once; production keeps serving it for a while,
//! which C10 lets fireemu skip.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fireemu_core_firestore::index::{IndexDefinition, IndexFieldMode, IndexQueryScope, IndexSet};
use fireemu_core_types::time::LogicalInstant;

/// How long a local index build takes.
pub const DEFAULT_INDEX_BUILD: Duration = Duration::from_millis(1500);

/// One index created through the Admin API.
#[derive(Debug, Clone)]
pub struct RuntimeIndex {
    /// The server-assigned id (`CICAgOjXh4EK`-like).
    pub id: String,
    /// What the index covers, as the planner reads it (no implied `__name__`).
    pub definition: IndexDefinition,
    /// When the build started (wall clock).
    pub started: Instant,
    /// When the build started (virtual clock).
    pub start_time: LogicalInstant,
    /// The id of the operation that builds it.
    pub operation: String,
}

/// Where an index stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexState {
    /// Being built: listed, never used by the planner.
    Creating,
    /// Built: used by the planner.
    Ready,
}

impl IndexState {
    /// The API spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "CREATING",
            Self::Ready => "READY",
        }
    }
}

#[derive(Debug, Default)]
struct RegistryState {
    live: BTreeMap<(String, String), Vec<RuntimeIndex>>,
    /// Deleted indexes, oldest first: production's link to create a missing index again
    /// names the index that was deleted.
    deleted: BTreeMap<(String, String), Vec<RuntimeIndex>>,
    /// The databases whose index-file indexes were seeded, with those definitions: they are
    /// the database's deployed indexes until it is deleted or they are.
    seeded: BTreeMap<(String, String), Vec<IndexDefinition>>,
    /// What a deleted database's index list still answers (production keeps listing them).
    tombstones: BTreeMap<(String, String), Vec<RuntimeIndex>>,
    seed: u64,
}

/// The runtime indexes of every database of one backend.
#[derive(Debug)]
pub struct IndexRegistry {
    state: Mutex<RegistryState>,
    build: Mutex<Duration>,
}

impl Default for IndexRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(RegistryState {
                seed: 0x1d3e_5a17_0000_0001,
                ..RegistryState::default()
            }),
            build: Mutex::new(DEFAULT_INDEX_BUILD),
        }
    }
}

/// An index id shaped like production's: base64url of a protobuf varint field 1 holding a
/// 56-bit number, twelve characters long.
fn index_id(seed: &mut u64) -> String {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    encode_index_id(*seed)
}

/// The id of an index the index file declares: derived from its definition, so it is the same
/// every run.
#[must_use]
pub fn configured_index_id(definition: &IndexDefinition) -> String {
    let mut digest = fireemu_core_types::hash::Sha256::new();
    digest.update(b"fireemu:configured-index:");
    digest.update(format!("{definition:?}").as_bytes());
    let bytes = digest.finalize();
    let mut word = [0_u8; 8];
    word.copy_from_slice(&bytes[..8]);
    encode_index_id(u64::from_be_bytes(word))
}

fn encode_index_id(seed: u64) -> String {
    let mut z = seed;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    // A value with its 50th bit set encodes to exactly eight varint bytes.
    let mut value = (z & 0x00ff_ffff_ffff_ffff) | (1 << 49);
    value &= (1 << 56) - 1;
    let mut bytes = vec![0x08];
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            bytes.push(byte);
            break;
        }
        bytes.push(byte | 0x80);
    }
    fireemu_core_types::hash::base64_url_safe(&bytes)
        .trim_end_matches('=')
        .to_owned()
}

impl IndexRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sets how long a build takes (tests and embedders).
    pub fn set_build_duration(&self, build: Duration) {
        *self
            .build
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = build;
    }

    fn build(&self) -> Duration {
        *self
            .build
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Where `index` stands at virtual time `now`.
    #[must_use]
    pub fn state(&self, index: &RuntimeIndex, now: LogicalInstant) -> IndexState {
        let build = self.build();
        let virtual_elapsed = now.as_nanos() - index.start_time.as_nanos();
        if index.started.elapsed() >= build
            || virtual_elapsed >= i128::try_from(build.as_nanos()).unwrap_or(i128::MAX)
        {
            IndexState::Ready
        } else {
            IndexState::Creating
        }
    }

    /// Starts building `definition`, or returns the id of the live index that already covers it.
    ///
    /// # Errors
    ///
    /// The id of the existing index when one has the same definition.
    pub fn create(
        &self,
        project: &str,
        database: &str,
        definition: IndexDefinition,
        start_time: LogicalInstant,
        operation: String,
    ) -> Result<RuntimeIndex, String> {
        let mut state = self.lock();
        let key = (project.to_owned(), database.to_owned());
        if let Some(existing) = state
            .live
            .get(&key)
            .and_then(|all| all.iter().find(|i| i.definition == definition))
        {
            return Err(existing.id.clone());
        }
        let id = index_id(&mut state.seed);
        let index = RuntimeIndex {
            id,
            definition,
            started: Instant::now(),
            start_time,
            operation,
        };
        state.live.entry(key).or_default().push(index.clone());
        Ok(index)
    }

    /// The live index `id` of a database.
    #[must_use]
    pub fn get(&self, project: &str, database: &str, id: &str) -> Option<RuntimeIndex> {
        self.lock()
            .live
            .get(&(project.to_owned(), database.to_owned()))?
            .iter()
            .find(|i| i.id == id)
            .cloned()
    }

    /// The live indexes of a database, oldest first.
    #[must_use]
    pub fn list(&self, project: &str, database: &str) -> Vec<RuntimeIndex> {
        self.lock()
            .live
            .get(&(project.to_owned(), database.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    /// Deletes a live index; returns it.
    pub fn delete(&self, project: &str, database: &str, id: &str) -> Option<RuntimeIndex> {
        let mut state = self.lock();
        let all = state
            .live
            .get_mut(&(project.to_owned(), database.to_owned()))?;
        let at = all.iter().position(|i| i.id == id)?;
        let removed = all.remove(at);
        state
            .deleted
            .entry((project.to_owned(), database.to_owned()))
            .or_default()
            .push(removed.clone());
        Some(removed)
    }

    /// The most recently deleted index whose definition `requirement` names (implied
    /// `__name__` aside), if the missing index a query needs is one that was deleted.
    #[must_use]
    pub fn deleted(
        &self,
        project: &str,
        database: &str,
        requirement: &IndexDefinition,
    ) -> Option<RuntimeIndex> {
        let wanted = with_implied_name(requirement);
        self.lock()
            .deleted
            .get(&(project.to_owned(), database.to_owned()))?
            .iter()
            .rev()
            .find(|index| with_implied_name(&index.definition) == wanted)
            .cloned()
    }

    /// Adds every `READY` index of a database to the planner's catalog.
    pub fn overlay(&self, project: &str, database: &str, now: LogicalInstant, set: &mut IndexSet) {
        for index in self.list(project, database) {
            if self.state(&index, now) == IndexState::Ready
                && !set.composites().contains(&index.definition)
            {
                set.add_composite(index.definition.clone());
            }
        }
    }

    /// The live `CREATING` index whose definition `requirement` names (implied `__name__`
    /// aside), if the missing index a query needs is one being built.
    #[must_use]
    pub fn building(
        &self,
        project: &str,
        database: &str,
        requirement: &IndexDefinition,
        now: LogicalInstant,
    ) -> Option<RuntimeIndex> {
        self.list(project, database).into_iter().find(|index| {
            self.state(index, now) == IndexState::Creating
                && with_implied_name(&index.definition) == with_implied_name(requirement)
        })
    }

    /// Forgets the indexes of the projects `owned` selects (a session reset): the index-file
    /// indexes are seeded again on next use.
    pub fn forget(&self, owned: impl Fn(&str, &str) -> bool) {
        let mut state = self.lock();
        state.live.retain(|(p, d), _| !owned(p, d));
        state.deleted.retain(|(p, d), _| !owned(p, d));
        state.seeded.retain(|(p, d), _| !owned(p, d));
        state.tombstones.retain(|(p, d), _| !owned(p, d));
    }

    /// Adds the index-file indexes of a database, once, as built (`READY`) indexes.
    pub fn seed_configured(&self, project: &str, database: &str, composites: &[IndexDefinition]) {
        let mut state = self.lock();
        let key = (project.to_owned(), database.to_owned());
        if state.seeded.contains_key(&key) {
            return;
        }
        state.seeded.insert(key.clone(), composites.to_vec());
        let live = state.live.entry(key).or_default();
        for definition in composites {
            if live.iter().any(|i| &i.definition == definition) {
                continue;
            }
            live.push(RuntimeIndex {
                id: configured_index_id(definition),
                definition: definition.clone(),
                started: Instant::now(),
                start_time: LogicalInstant::UNIX_EPOCH,
                operation: String::new(),
            });
        }
    }

    /// The index-file indexes of a database that are no longer its indexes (deleted through
    /// the Admin API, or gone with the database): the planner must not use them.
    #[must_use]
    pub fn retracted(&self, project: &str, database: &str) -> Vec<IndexDefinition> {
        let state = self.lock();
        let key = (project.to_owned(), database.to_owned());
        let Some(seeded) = state.seeded.get(&key) else {
            return Vec::new();
        };
        let live = state.live.get(&key);
        seeded
            .iter()
            .filter(|d| !live.is_some_and(|all| all.iter().any(|i| &i.definition == *d)))
            .cloned()
            .collect()
    }

    /// Drops a deleted database's indexes: its index list keeps answering what it had, and a
    /// database recreated under the id starts with none (production, 2026-09-24).
    pub fn drop_database(&self, project: &str, database: &str) {
        let mut state = self.lock();
        let key = (project.to_owned(), database.to_owned());
        let had = state.live.remove(&key).unwrap_or_default();
        state.tombstones.insert(key.clone(), had);
        state.deleted.remove(&key);
    }

    /// What a deleted database's index list answers.
    #[must_use]
    pub fn tombstone(&self, project: &str, database: &str) -> Vec<RuntimeIndex> {
        self.lock()
            .tombstones
            .get(&(project.to_owned(), database.to_owned()))
            .cloned()
            .unwrap_or_default()
    }
}

/// The index with the `__name__` field production adds when the definition names none: after
/// the last field, in the direction of the last ordered field (ascending otherwise), or, for a
/// vector index, ascending just before the vector field.
#[must_use]
pub fn with_implied_name(definition: &IndexDefinition) -> IndexDefinition {
    let mut out = definition.clone();
    if out.fields.iter().any(|f| f.path.is_document_name()) {
        return out;
    }
    let name = |mode| fireemu_core_firestore::index::IndexField {
        path: fireemu_core_firestore::field_path::FieldPath::document_name(),
        mode,
    };
    if let Some(vector) = out
        .fields
        .iter()
        .position(|f| matches!(f.mode, IndexFieldMode::Vector { .. }))
    {
        out.fields.insert(vector, name(IndexFieldMode::Ascending));
        return out;
    }
    let direction = out
        .fields
        .iter()
        .rev()
        .find_map(|f| match f.mode {
            IndexFieldMode::Ascending | IndexFieldMode::Descending => Some(f.mode),
            _ => None,
        })
        .unwrap_or(IndexFieldMode::Ascending);
    out.fields.push(name(direction));
    out
}

/// Whether `id` is shaped like an index id production assigns: base64url of a protobuf
/// message whose field 1 is a varint.
#[must_use]
pub fn is_index_id(id: &str) -> bool {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return false;
    }
    let standard: String = id
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let padded = format!("{standard}{}", "=".repeat((4 - standard.len() % 4) % 4));
    let Ok(bytes) = crate::rest::json::base64_decode(&padded) else {
        return false;
    };
    bytes.first() == Some(&0x08) && bytes.len() >= 2 && bytes.last().is_some_and(|b| b & 0x80 == 0)
}

/// The API spelling of a query scope.
#[must_use]
pub const fn scope_name(scope: IndexQueryScope) -> &'static str {
    match scope {
        IndexQueryScope::Collection => "COLLECTION",
        IndexQueryScope::CollectionGroup => "COLLECTION_GROUP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::index::IndexField;
    use fireemu_core_types::ids::CollectionId;

    fn definition() -> IndexDefinition {
        IndexDefinition {
            collection_group: CollectionId::try_new("items").unwrap(),
            query_scope: IndexQueryScope::Collection,
            fields: vec![
                IndexField {
                    path: FieldPath::parse("a").unwrap(),
                    mode: IndexFieldMode::Ascending,
                },
                IndexField {
                    path: FieldPath::parse("b").unwrap(),
                    mode: IndexFieldMode::Descending,
                },
            ],
        }
    }

    #[test]
    fn an_index_builds_then_serves_and_a_duplicate_names_the_existing_id() {
        let registry = IndexRegistry::default();
        registry.set_build_duration(Duration::from_secs(3600));
        let t0 = LogicalInstant::from_nanos(0);
        let index = registry
            .create("p", "d", definition(), t0, "op".into())
            .unwrap();
        assert_eq!(index.id.len(), 12, "{}", index.id);
        assert_eq!(registry.state(&index, t0), IndexState::Creating);
        let mut set = IndexSet::default();
        registry.overlay("p", "d", t0, &mut set);
        assert!(set.composites().is_empty(), "a building index never serves");
        assert!(registry
            .building("p", "d", &with_implied_name(&definition()), t0)
            .is_some());
        assert_eq!(
            registry
                .create("p", "d", definition(), t0, "op2".into())
                .unwrap_err(),
            index.id
        );
        let later = LogicalInstant::from_nanos(3_600 * 1_000_000_000);
        assert_eq!(registry.state(&index, later), IndexState::Ready);
        registry.overlay("p", "d", later, &mut set);
        assert_eq!(set.composites(), &[definition()]);
        assert!(registry.delete("p", "d", &index.id).is_some());
        assert!(registry.delete("p", "d", &index.id).is_none());
    }

    #[test]
    fn a_vector_index_gets_an_ascending_name_before_the_vector_field_and_ids_are_checked() {
        let vector = IndexDefinition {
            collection_group: CollectionId::try_new("items").unwrap(),
            query_scope: IndexQueryScope::Collection,
            fields: vec![IndexField {
                path: FieldPath::parse("v").unwrap(),
                mode: IndexFieldMode::Vector { dimension: 2 },
            }],
        };
        let shown = with_implied_name(&vector);
        assert!(shown.fields[0].path.is_document_name());
        assert_eq!(shown.fields[0].mode, IndexFieldMode::Ascending);
        assert!(matches!(
            shown.fields[1].mode,
            IndexFieldMode::Vector { .. }
        ));
        assert!(is_index_id("CICAgOjXh4EK"));
        let mut seed = 1;
        assert!(is_index_id(&index_id(&mut seed)));
        assert!(!is_index_id("not-an-index"));
        assert!(!is_index_id(""));
    }

    #[test]
    fn the_implied_name_field_follows_the_last_ordered_field() {
        let implied = with_implied_name(&definition());
        let last = implied.fields.last().unwrap();
        assert!(last.path.is_document_name());
        assert_eq!(last.mode, IndexFieldMode::Descending);
    }
}
