use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use fireemu_core_types::ids::{CollectionId, DocumentId};

use crate::path::DocumentPath;

pub(super) type DirectCollectionPaths =
    BTreeMap<(Option<DocumentPath>, CollectionId), BTreeSet<Arc<DocumentPath>>>;
pub(super) type CollectionGroupPaths = BTreeMap<CollectionId, BTreeSet<Arc<DocumentPath>>>;
pub(super) type ListingTrieIter<'a> =
    Box<dyn Iterator<Item = (&'a DocumentId, &'a ListingTrieDocument)> + 'a>;
pub(super) type ListingTrieNodeIter<'a> = Box<dyn Iterator<Item = &'a ListingTrieDocument> + 'a>;

#[derive(Debug, Clone, Default)]
pub(super) struct PathIndexes {
    direct_collection_paths: DirectCollectionPaths,
    live_direct_collection_paths: DirectCollectionPaths,
    collection_group_paths: CollectionGroupPaths,
    live_collection_group_paths: CollectionGroupPaths,
    live_paths: BTreeSet<Arc<DocumentPath>>,
    listing_trie: ListingTrie,
}

impl PathIndexes {
    pub(super) fn direct_collection_paths(&self) -> &DirectCollectionPaths {
        &self.direct_collection_paths
    }

    pub(super) fn live_direct_collection_paths(&self) -> &DirectCollectionPaths {
        &self.live_direct_collection_paths
    }

    pub(super) fn collection_group_paths(&self) -> &CollectionGroupPaths {
        &self.collection_group_paths
    }

    pub(super) fn live_collection_group_paths(&self) -> &CollectionGroupPaths {
        &self.live_collection_group_paths
    }

    pub(super) fn live_paths(&self) -> &BTreeSet<Arc<DocumentPath>> {
        &self.live_paths
    }

    pub(super) fn listing_trie(&self) -> &ListingTrie {
        &self.listing_trie
    }

    /// Adds a path to the retained indexes using one allocation shared by every family.
    pub(super) fn insert_retained(&mut self, path: &DocumentPath) {
        let shared = Arc::new(path.clone());
        self.direct_collection_paths
            .entry((path.parent_document(), path.collection_id().clone()))
            .or_default()
            .insert(Arc::clone(&shared));
        self.listing_trie.insert_retained(&shared);
        self.collection_group_paths
            .entry(path.collection_id().clone())
            .or_default()
            .insert(shared);
    }

    /// The shared allocation for a path already present in retained indexes.
    pub(super) fn retained_path(&self, path: &DocumentPath) -> Arc<DocumentPath> {
        let retained = self
            .collection_group_paths
            .get(path.collection_id())
            .and_then(|paths| paths.get(path));
        debug_assert!(retained.is_some(), "live paths must first be retained");
        retained.map_or_else(|| Arc::new(path.clone()), Arc::clone)
    }

    pub(super) fn insert_live(&mut self, path: &DocumentPath) {
        let shared = self.retained_path(path);
        self.live_direct_collection_paths
            .entry((path.parent_document(), path.collection_id().clone()))
            .or_default()
            .insert(Arc::clone(&shared));
        self.live_collection_group_paths
            .entry(path.collection_id().clone())
            .or_default()
            .insert(Arc::clone(&shared));
        self.live_paths.insert(shared);
        self.listing_trie.adjust_live(path, true);
    }

    pub(super) fn remove_retained(&mut self, path: &DocumentPath) {
        remove_index_path(
            &mut self.direct_collection_paths,
            (path.parent_document(), path.collection_id().clone()),
            path,
        );
        self.listing_trie.remove_retained(path);
        remove_index_path(
            &mut self.collection_group_paths,
            path.collection_id().clone(),
            path,
        );
    }

    pub(super) fn remove_live(&mut self, path: &DocumentPath) {
        remove_index_path(
            &mut self.live_direct_collection_paths,
            (path.parent_document(), path.collection_id().clone()),
            path,
        );
        remove_index_path(
            &mut self.live_collection_group_paths,
            path.collection_id().clone(),
            path,
        );
        self.live_paths.remove(path);
        self.listing_trie.adjust_live(path, false);
    }

    /// Rebuilds every index from retained paths and their already-interpreted live status.
    pub(super) fn rebuild<'a>(paths: impl IntoIterator<Item = (&'a DocumentPath, bool)>) -> Self {
        let mut indexes = Self::default();
        for (path, live) in paths {
            indexes.insert_retained(path);
            if live {
                indexes.insert_live(path);
            }
        }
        indexes
    }

    #[cfg(test)]
    pub(super) fn replace_live_path_for_test(
        &mut self,
        path: Arc<DocumentPath>,
    ) -> Option<Arc<DocumentPath>> {
        self.live_paths.replace(path)
    }
}

fn remove_index_path<K: Ord>(
    index: &mut BTreeMap<K, BTreeSet<Arc<DocumentPath>>>,
    key: K,
    path: &DocumentPath,
) {
    if let std::collections::btree_map::Entry::Occupied(mut entry) = index.entry(key) {
        entry.get_mut().remove(path);
        if entry.get().is_empty() {
            entry.remove();
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct ListingTrie {
    pub(super) collections: BTreeMap<CollectionId, ListingTrieCollection>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ListingTrieCollection {
    pub(super) documents: BTreeMap<DocumentId, ListingTrieDocument>,
    pub(super) live_candidates: BTreeSet<DocumentId>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ListingTrieDocument {
    pub(super) retained_subtree_paths: usize,
    pub(super) live_subtree_paths: usize,
    pub(super) retained_here: Option<Arc<DocumentPath>>,
    pub(super) representative: Option<Arc<DocumentPath>>,
    pub(super) children: ListingTrie,
}

impl ListingTrie {
    /// Indexes `path` under every prefix, holding the caller's allocation rather than a copy.
    fn insert_retained(&mut self, path: &Arc<DocumentPath>) {
        Self::insert_retained_pairs(self, path.pairs(), path);
    }

    fn insert_retained_pairs(
        trie: &mut Self,
        pairs: &[(CollectionId, DocumentId)],
        path: &Arc<DocumentPath>,
    ) {
        let Some(((collection, document), rest)) = pairs.split_first() else {
            return;
        };
        let node = trie
            .collections
            .entry(collection.clone())
            .or_default()
            .documents
            .entry(document.clone())
            .or_default();
        node.retained_subtree_paths += 1;
        node.representative = Some(Arc::clone(path));
        if rest.is_empty() {
            node.retained_here = Some(Arc::clone(path));
        } else {
            Self::insert_retained_pairs(&mut node.children, rest, path);
        }
    }

    fn remove_retained(&mut self, path: &DocumentPath) {
        Self::remove_retained_pairs(self, path.pairs());
    }

    fn remove_retained_pairs(trie: &mut Self, pairs: &[(CollectionId, DocumentId)]) {
        let Some(((collection, document), rest)) = pairs.split_first() else {
            return;
        };
        let mut remove_collection = false;
        if let Some(collection_node) = trie.collections.get_mut(collection) {
            let mut remove_document = false;
            if let Some(node) = collection_node.documents.get_mut(document) {
                node.retained_subtree_paths = node.retained_subtree_paths.saturating_sub(1);
                if rest.is_empty() {
                    node.retained_here = None;
                } else {
                    Self::remove_retained_pairs(&mut node.children, rest);
                }
                remove_document = node.retained_subtree_paths == 0;
            }
            if remove_document {
                collection_node.documents.remove(document);
                collection_node.live_candidates.remove(document);
            }
            remove_collection = collection_node.documents.is_empty();
        }
        if remove_collection {
            trie.collections.remove(collection);
        }
    }

    fn adjust_live(&mut self, path: &DocumentPath, increase: bool) {
        Self::adjust_live_pairs(self, path.pairs(), increase);
    }

    fn adjust_live_pairs(trie: &mut Self, pairs: &[(CollectionId, DocumentId)], increase: bool) {
        let Some(((collection, document), rest)) = pairs.split_first() else {
            return;
        };
        let Some(collection_node) = trie.collections.get_mut(collection) else {
            debug_assert!(!increase, "live paths must first enter the retained trie");
            return;
        };
        let Some(node) = collection_node.documents.get_mut(document) else {
            debug_assert!(!increase, "live paths must first enter the retained trie");
            return;
        };
        let was_live = node.live_subtree_paths > 0;
        if increase {
            node.live_subtree_paths += 1;
        } else {
            node.live_subtree_paths = node.live_subtree_paths.saturating_sub(1);
        }
        if !rest.is_empty() {
            Self::adjust_live_pairs(&mut node.children, rest, increase);
        }
        let is_live = node.live_subtree_paths > 0;
        if was_live != is_live {
            if is_live {
                collection_node.live_candidates.insert(document.clone());
            } else {
                collection_node.live_candidates.remove(document);
            }
        }
    }

    pub(super) fn collection(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &CollectionId,
    ) -> Option<&ListingTrieCollection> {
        self.collections_under(parent)?.get(collection_id)
    }

    pub(super) fn collections_under(
        &self,
        parent: Option<&DocumentPath>,
    ) -> Option<&BTreeMap<CollectionId, ListingTrieCollection>> {
        let mut trie = self;
        if let Some(parent) = parent {
            for (collection, document) in parent.pairs() {
                trie = &trie
                    .collections
                    .get(collection)?
                    .documents
                    .get(document)?
                    .children;
            }
        }
        Some(&trie.collections)
    }
}

#[cfg(test)]
#[path = "path_indexes_tests.rs"]
mod tests;
