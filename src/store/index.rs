// Copyright 2026 Jeremiah Jordan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The in-memory object index (docs/configuration.md#object-cache).
//!
//! Object metadata exists only inside each encrypted record, so finding an
//! object by Name or by Link used to decrypt every object. This index maps
//! those values to identifiers, in memory only: nothing about it is written
//! to the database. The engine supplies the keys of an object
//! (`protocol/object_index.rs`), and every query still applies its full
//! filter to each candidate, so the index only has to be a superset.
//!
//! It stays a superset without following the engine's savepoints: writes only
//! add keys, so a rolled-back write leaves extra candidates, never missing
//! ones. Identifiers written since the last clean point are pruned to their
//! committed keys when no transaction is open (`Store::commit`,
//! `Store::rollback`).
use super::Object;
use std::collections::{HashMap, HashSet};

/// A value an object can be found by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IndexKey {
    /// A Name value.
    Name(String),
    /// The target of any Link.
    Link(String),
}
/// The keys of an object, in every protocol version's rendering.
pub type KeyFn = fn(&Object) -> Vec<IndexKey>;

pub(super) struct ObjectIndex {
    pub(super) keys_fn: KeyFn,
    by_key: HashMap<IndexKey, HashSet<String>>,
    keys_of: HashMap<String, HashSet<IndexKey>>,
    /// Written since the last prune.
    dirty: HashSet<String>,
}

impl ObjectIndex {
    pub(super) fn new(keys_fn: KeyFn) -> Self {
        Self {
            keys_fn,
            by_key: HashMap::new(),
            keys_of: HashMap::new(),
            dirty: HashSet::new(),
        }
    }
    /// Add an object's keys, keeping any it had: a written version may still
    /// be rolled back to the previous one.
    pub(super) fn add(&mut self, obj: &Object) {
        let keys = (self.keys_fn)(obj);
        self.add_keys(&obj.id, keys);
        self.dirty.insert(obj.id.clone());
    }
    fn add_keys(&mut self, id: &str, keys: Vec<IndexKey>) {
        let held = self.keys_of.entry(id.to_owned()).or_default();
        for key in keys {
            if held.insert(key.clone()) {
                self.by_key.entry(key).or_default().insert(id.to_owned());
            }
        }
    }
    /// An identifier that was written or removed and must be pruned.
    pub(super) fn touch(&mut self, id: &str) {
        self.dirty.insert(id.to_owned());
    }
    pub(super) fn take_dirty(&mut self) -> Vec<String> {
        self.dirty.drain().collect()
    }
    /// Replace an identifier's keys with those of its committed object, or
    /// drop it when it no longer exists.
    pub(super) fn set(&mut self, id: &str, obj: Option<&Object>) {
        if let Some(keys) = self.keys_of.remove(id) {
            for key in keys {
                if let Some(ids) = self.by_key.get_mut(&key) {
                    ids.remove(id);
                    if ids.is_empty() {
                        self.by_key.remove(&key);
                    }
                }
            }
        }
        if let Some(obj) = obj {
            let keys = (self.keys_fn)(obj);
            self.add_keys(id, keys);
        }
    }
    /// Identifiers that may hold `key`, sorted.
    pub(super) fn candidates(&self, key: &IndexKey) -> Vec<String> {
        let mut ids: Vec<String> = self
            .by_key
            .get(key)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(obj: &Object) -> Vec<IndexKey> {
        obj.attrs
            .iter()
            .filter_map(|a| a.string().ok().map(|s| IndexKey::Name(s.to_owned())))
            .collect()
    }
    fn object(id: &str, names: &[&str]) -> Object {
        let mut obj: Object = serde_json::from_value(serde_json::json!({
            "id": id, "owner": "alice", "object_type": 2, "format": 1,
            "algorithm": 3, "bits": 256, "usage": 12, "state": 1,
            "material": [], "attrs": [], "created": 0, "updated": 0
        }))
        .unwrap();
        obj.attrs = names
            .iter()
            .map(|n| crate::ttlv::Node::text(crate::tags::NAME, *n))
            .collect();
        obj
    }
    fn name(n: &str) -> IndexKey {
        IndexKey::Name(n.into())
    }

    #[test]
    fn writes_only_add_and_pruning_sets_the_committed_keys() {
        let mut ix = ObjectIndex::new(keys);
        ix.add(&object("a", &["one"]));
        // A second version keeps the first's keys until pruned.
        ix.add(&object("a", &["two"]));
        assert_eq!(ix.candidates(&name("one")), vec!["a"]);
        assert_eq!(ix.candidates(&name("two")), vec!["a"]);
        assert_eq!(ix.take_dirty(), vec!["a"]);
        ix.set("a", Some(&object("a", &["two"])));
        assert!(ix.candidates(&name("one")).is_empty());
        assert_eq!(ix.candidates(&name("two")), vec!["a"]);
        ix.set("a", None);
        assert!(ix.candidates(&name("two")).is_empty());
        assert!(ix.by_key.is_empty() && ix.keys_of.is_empty());
    }
}
