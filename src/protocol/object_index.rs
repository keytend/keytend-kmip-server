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

//! The keys the store's object index holds (store/index.rs): every Name value
//! and every Link target an object shows in any protocol version, so a Name or
//! Link filter of any version finds it among the candidates.
use super::*;
use crate::store::IndexKey;

const VERSIONS: [Version; 8] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];

/// The index key a Name or Link attribute (or filter) carries, if any. A
/// filter matches an attribute only when each filter field equals a field
/// of it (`attribute_matches`), so a matching object holds the same key.
pub(super) fn key(a: &Node) -> Option<IndexKey> {
    let text = |n: &Node| n.identifier_text().ok().map(str::to_owned);
    match a.tag {
        NAME => match &a.value {
            Value::Structure(_) => a.get(NAME_VALUE).and_then(text).map(IndexKey::Name),
            _ => text(a).map(IndexKey::Name),
        },
        LINK => a
            .get(LINKED_OBJECT_IDENTIFIER)
            .and_then(text)
            .map(IndexKey::Link),
        tag if identifiers::LINKS.iter().any(|(t, _)| *t == tag)
            || [GROUP_LINK, CERTIFICATE_REQUEST_LINK].contains(&tag) =>
        {
            text(a).map(IndexKey::Link)
        }
        _ => None,
    }
}
/// An object's keys: its stored attributes and its rendering in every
/// version.
pub(crate) fn keys(obj: &Object) -> Vec<IndexKey> {
    let mut keys: Vec<IndexKey> = obj.attrs.iter().filter_map(key).collect();
    for v in VERSIONS {
        keys.extend(object_attrs(obj, v).iter().filter_map(key));
    }
    keys.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    keys.dedup();
    keys
}
