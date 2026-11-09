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

//! The decrypted-object cache (docs/configuration.md#object-cache).
//!
//! Locate and the uniqueness checks read every object of an owner, and each
//! read decrypts and parses a record. The cache keeps parsed objects, key
//! material included, so repeated scans skip that work. An entry is keyed by
//! the object's identifier and owner and is valid only while the record's
//! hash equals the one in the authenticated index: a write, a rollback or a
//! master-key rotation changes the hash, and the stale entry is dropped on its
//! next use. A hit returns the object the index authenticates; a record row
//! changed behind the index is found when it is next read from the database.
//!
//! The cache is bounded by an approximate size (the decrypted records'
//! length plus a fixed overhead per entry), evicting the least recently used
//! entries, and by an idle time: an entry not used for that long is dropped,
//! on the next use of the cache and by the server's periodic cleanup.
//! Dropping an entry zeroizes its key material (`Object`'s `Drop`).
use super::Object;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

/// Bytes counted per entry beyond the decrypted record.
const ENTRY_OVERHEAD: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    /// Approximate size bound; 0 turns the cache off.
    pub max_bytes: usize,
    /// Entries unused for longer are dropped.
    pub idle: Duration,
}
impl CacheLimits {
    pub const OFF: Self = Self {
        max_bytes: 0,
        idle: Duration::ZERO,
    };
}

struct Entry {
    owner: String,
    hash: [u8; 32],
    object: Arc<Object>,
    size: usize,
    used: Instant,
    /// Position in `order`: larger is more recent.
    stamp: u64,
}

pub(super) struct ObjectCache {
    limits: CacheLimits,
    entries: HashMap<String, Entry>,
    /// Entries by last use, oldest first.
    order: BTreeMap<u64, String>,
    bytes: usize,
    next_stamp: u64,
}

impl ObjectCache {
    pub(super) fn new(limits: CacheLimits) -> Self {
        Self {
            limits,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            bytes: 0,
            next_stamp: 0,
        }
    }
    pub(super) fn set_limits(&mut self, limits: CacheLimits) {
        self.limits = limits;
        self.trim(Instant::now());
    }
    fn enabled(&self) -> bool {
        self.limits.max_bytes > 0
    }
    /// The cached object, when it is the record whose hash the index holds.
    pub(super) fn get(&mut self, owner: &str, id: &str, hash: &[u8; 32]) -> Option<Arc<Object>> {
        if !self.enabled() {
            return None;
        }
        let now = Instant::now();
        self.expire(now);
        let entry = self.entries.get_mut(id)?;
        if entry.owner != owner || entry.hash != *hash {
            self.remove(id);
            return None;
        }
        self.order.remove(&entry.stamp);
        entry.stamp = self.next_stamp;
        self.next_stamp += 1;
        entry.used = now;
        self.order.insert(entry.stamp, id.to_owned());
        Some(entry.object.clone())
    }
    /// Keep a decrypted object; `size` is its decrypted record's length.
    pub(super) fn insert(
        &mut self,
        owner: &str,
        id: &str,
        hash: &[u8; 32],
        object: Arc<Object>,
        size: usize,
    ) {
        let size = size.saturating_add(ENTRY_OVERHEAD + id.len() + owner.len());
        if !self.enabled() || size > self.limits.max_bytes {
            return;
        }
        self.remove(id);
        let now = Instant::now();
        let stamp = self.next_stamp;
        self.next_stamp += 1;
        self.order.insert(stamp, id.to_owned());
        self.bytes += size;
        self.entries.insert(
            id.to_owned(),
            Entry {
                owner: owner.to_owned(),
                hash: *hash,
                object,
                size,
                used: now,
                stamp,
            },
        );
        self.trim(now);
    }
    pub(super) fn remove(&mut self, id: &str) {
        if let Some(entry) = self.entries.remove(id) {
            self.order.remove(&entry.stamp);
            self.bytes -= entry.size;
        }
    }
    /// Drop entries unused for longer than the idle time.
    pub(super) fn expire(&mut self, now: Instant) {
        while let Some((_, id)) = self.order.first_key_value() {
            let idle = self
                .entries
                .get(id)
                .is_some_and(|e| now.saturating_duration_since(e.used) > self.limits.idle);
            if !idle {
                break;
            }
            let id = id.clone();
            self.remove(&id);
        }
    }
    /// Expire, then evict the least recently used entries over the size bound.
    fn trim(&mut self, now: Instant) {
        if !self.enabled() {
            self.clear();
            return;
        }
        self.expire(now);
        while self.bytes > self.limits.max_bytes {
            let Some((_, id)) = self.order.first_key_value() else {
                break;
            };
            let id = id.clone();
            self.remove(&id);
        }
    }
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }
    #[cfg(test)]
    pub(super) fn usage(&self) -> (usize, usize) {
        (self.entries.len(), self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(id: &str) -> Arc<Object> {
        let mut obj: Object = serde_json::from_value(serde_json::json!({
            "id": id, "owner": "alice", "object_type": 2, "format": 1,
            "algorithm": 3, "bits": 256, "usage": 12, "state": 1,
            "material": [1, 2, 3], "attrs": [], "created": 0, "updated": 0
        }))
        .unwrap();
        obj.id = id.into();
        Arc::new(obj)
    }
    fn limits(max_bytes: usize, idle_ms: u64) -> CacheLimits {
        CacheLimits {
            max_bytes,
            idle: Duration::from_millis(idle_ms),
        }
    }

    #[test]
    fn a_changed_hash_or_owner_misses_and_drops_the_entry() {
        let mut c = ObjectCache::new(limits(1 << 20, 60_000));
        c.insert("alice", "a", &[1; 32], object("a"), 100);
        assert!(c.get("alice", "a", &[1; 32]).is_some());
        assert!(c.get("bob", "a", &[1; 32]).is_none());
        assert_eq!(c.usage().0, 0);
        c.insert("alice", "a", &[1; 32], object("a"), 100);
        assert!(c.get("alice", "a", &[2; 32]).is_none());
        assert_eq!(c.usage(), (0, 0));
    }

    #[test]
    fn the_size_bound_evicts_the_least_recently_used() {
        let entry = 100 + ENTRY_OVERHEAD + 1 + 5;
        let mut c = ObjectCache::new(limits(entry * 2, 60_000));
        c.insert("alice", "a", &[1; 32], object("a"), 100);
        c.insert("alice", "b", &[1; 32], object("b"), 100);
        assert!(c.get("alice", "a", &[1; 32]).is_some());
        c.insert("alice", "c", &[1; 32], object("c"), 100);
        assert!(c.get("alice", "b", &[1; 32]).is_none());
        assert!(c.get("alice", "a", &[1; 32]).is_some());
        assert!(c.get("alice", "c", &[1; 32]).is_some());
        assert_eq!(c.usage(), (2, entry * 2));
        // Larger than the whole bound: never cached.
        c.insert("alice", "d", &[1; 32], object("d"), entry * 3);
        assert!(c.get("alice", "d", &[1; 32]).is_none());
    }

    #[test]
    fn idle_entries_expire_and_off_keeps_nothing() {
        let mut c = ObjectCache::new(limits(1 << 20, 20));
        c.insert("alice", "a", &[1; 32], object("a"), 100);
        std::thread::sleep(Duration::from_millis(40));
        c.expire(Instant::now());
        assert_eq!(c.usage(), (0, 0));
        c.insert("alice", "a", &[1; 32], object("a"), 100);
        c.set_limits(CacheLimits::OFF);
        assert_eq!(c.usage(), (0, 0));
        c.insert("alice", "a", &[1; 32], object("a"), 100);
        assert!(c.get("alice", "a", &[1; 32]).is_none());
    }
}
