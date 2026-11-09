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

//! Read-only inputs of the operator metrics (docs/metrics.md): an object
//! census by Object Type and State, read in pages so a caller can release the
//! engine between pages, and the database size. Neither changes the store.
use super::*;

/// The two fields a census needs; the rest of the record is ignored.
#[derive(Deserialize)]
struct Kind {
    object_type: u32,
    state: u32,
}

/// One page of the object census.
pub struct CensusPage {
    /// Object Type and State of each record in the page that authenticated.
    pub objects: Vec<(u32, u32)>,
    /// Records that did not authenticate or parse.
    pub unreadable: u64,
    /// The last identifier read; pass it to the next call. None: no more records.
    pub next: Option<String>,
}

/// Database size from SQLite's page counts (main database file, excluding
/// the WAL).
pub struct StoreSize {
    pub bytes: u64,
    pub free_bytes: u64,
}

impl Store {
    /// Up to `limit` object records after identifier `after`, in identifier
    /// order. Each record is authenticated by its AEAD tag, bound to its owner
    /// and identifier; the object state index is not walked, so a census
    /// spread over several pages is not one consistent snapshot.
    pub fn census_page(&self, after: Option<&str>, limit: usize) -> Result<CensusPage> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id, owner, sealed FROM objects WHERE id > ?1 ORDER BY id LIMIT ?2",
        )?;
        let mut rows = stmt.query(params![after.unwrap_or(""), limit.max(1) as i64])?;
        let mut page = CensusPage {
            objects: vec![],
            unreadable: 0,
            next: None,
        };
        let mut read = 0;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let owner: String = row.get(1)?;
            let sealed: Vec<u8> = row.get(2)?;
            read += 1;
            match self
                .unseal(&Self::aad(&owner, &id), &sealed)
                .ok()
                .and_then(|plaintext| serde_json::from_slice::<Kind>(&plaintext).ok())
            {
                Some(kind) => page.objects.push((kind.object_type, kind.state)),
                None => page.unreadable += 1,
            }
            page.next = Some(id);
        }
        if read < limit.max(1) {
            page.next = None;
        }
        Ok(page)
    }

    pub fn size(&self) -> Result<StoreSize> {
        let pragma = |name: &str| -> Result<u64> {
            let value: i64 = self
                .conn
                .query_row(&format!("PRAGMA {name}"), [], |r| r.get(0))?;
            Ok(value.max(0) as u64)
        };
        let page = pragma("page_size")?;
        Ok(StoreSize {
            bytes: pragma("page_count")? * page,
            free_bytes: pragma("freelist_count")? * page,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> Store {
        let key = dir.join("master.key");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        std::io::Write::write_all(&mut options.open(&key).unwrap(), &[7; 32]).unwrap();
        Store::open(&dir.join("kmip.sqlite"), &key).unwrap()
    }

    fn object(id: &str, object_type: u32, state: u32) -> Object {
        let value = serde_json::json!({
            "id": id, "owner": "alice", "object_type": object_type, "format": 1,
            "algorithm": 3, "bits": 256, "usage": 12, "state": state,
            "material": [1, 2, 3], "attrs": [], "created": 0, "updated": 0,
        });
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn census_pages_cover_every_object_once_and_flag_unreadable_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        assert!(store.census_page(None, 10).unwrap().objects.is_empty());
        for (i, (t, s)) in [(2, 1), (2, 2), (2, 2), (4, 5), (7, 3)].iter().enumerate() {
            store.insert(&object(&format!("id-{i}"), *t, *s)).unwrap();
        }
        let mut seen = vec![];
        let mut after = None;
        let mut pages = 0;
        loop {
            let page = store.census_page(after.as_deref(), 2).unwrap();
            assert_eq!(page.unreadable, 0);
            seen.extend(page.objects);
            pages += 1;
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        assert_eq!(pages, 3);
        seen.sort();
        assert_eq!(seen, vec![(2, 1), (2, 2), (2, 2), (4, 5), (7, 3)]);
        // A record moved to another owner no longer authenticates (its AAD
        // binds the owner); the census counts it instead of failing.
        store
            .conn
            .execute("UPDATE objects SET owner='mallory' WHERE id='id-0'", [])
            .unwrap();
        let page = store.census_page(None, 100).unwrap();
        assert_eq!((page.objects.len(), page.unreadable), (4, 1));
        assert!(page.next.is_none());
        let size = store.size().unwrap();
        assert!(size.bytes > 0 && size.free_bytes <= size.bytes);
    }
}
