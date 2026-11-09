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

//! Immediate logical archival in the encrypted store, with explicit recovery.
use super::*;

pub(super) fn archived(obj: &Object) -> bool {
    obj.attrs.iter().any(|a| a.tag == ARCHIVE_DATE)
}
pub(super) fn online(obj: &Object) -> R<()> {
    if archived(obj) {
        Err(fail(13, "Object is archived; Recover is required"))
    } else {
        Ok(())
    }
}
pub(super) fn storage_mask(p: &Node, v: Version, filters: &[Node]) -> R<u32> {
    let mut mask = match p.get(STORAGE_STATUS_MASK) {
        None => 1,
        Some(Node {
            value: Value::Integer(value),
            ..
        }) if *value >= 0 => *value as u32,
        Some(_) => return Err(fail(7, "Storage Status Mask must be a nonnegative Integer")),
    };
    if mask & !(if v.0 >= 2 { 7 } else { 3 }) != 0 {
        return Err(fail(7, "Unsupported Storage Status Mask bits"));
    }
    if v.0 < 2 && legacy_destroyed_selected(filters) {
        mask |= LEGACY_DESTROYED;
    }
    Ok(mask)
}
/// Internal 1.x flag (never a wire value: 1.x masks only define bits 1 and 2).
const LEGACY_DESTROYED: u32 = 0x8000_0000;
/// KMIP 1.x has no Destroyed Storage bit. Destroy "SHALL" destroy the key
/// material and the metadata "MAY be retained" (1.4 section 4.21), and the
/// mandatory 1.3/1.4 Profiles test cases (SKFF-M-5/6/7) expect an on-line
/// Locate after Destroy to return nothing, as 2.0 later states explicitly.
/// Retained metadata stays reachable when the request selects it directly,
/// as in the 1.4 Usage Guide queries `Locate(DestroyDate(t),
/// State(Destroyed-Compromised))`.
fn legacy_destroyed_selected(filters: &[Node]) -> bool {
    filters.iter().any(|f| {
        f.tag == DESTROY_DATE || f.tag == STATE && matches!(f.value, Value::Enumeration(5 | 6))
    })
}
pub(super) fn matches_storage(obj: &Object, v: Version, mask: u32) -> bool {
    let archived = archived(obj);
    if v.0 < 2 {
        // Archived rows, destroyed or not, belong to the Archival tier.
        if archived {
            mask & 2 != 0
        } else if obj.state >= 5 {
            mask & 1 != 0 && mask & LEGACY_DESTROYED != 0
        } else {
            mask & 1 != 0
        }
    } else {
        let destroyed = obj.state >= 5;
        // An archived destroyed object must satisfy both explicit exclusions.
        let required = if archived { 2 } else { 0 } | if destroyed { 4 } else { 0 };
        if required == 0 {
            mask & 1 != 0
        } else {
            mask & required == required
        }
    }
}
impl Engine {
    pub(super) fn archive(
        &self,
        owner: &str,
        op: u32,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[UNIQUE_IDENTIFIER])?;
        let mut obj = self.object_including_archived(owner, p, placeholder)?;
        if op == 21 {
            online(&obj)?;
            attributes::append(&mut obj, Node::date(ARCHIVE_DATE, now()))?;
        } else {
            // Recovery of an already online object is an idempotent success.
            // It never revives destroyed material or changes extraction policy.
            if !archived(&obj) {
                return Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)]);
            }
            obj.attrs.retain(|a| a.tag != ARCHIVE_DATE);
            obj.attribute_indices
                .remove(&format!("s:{ARCHIVE_DATE:06x}"));
        }
        obj.updated = now();
        self.store.put(&obj)?;
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
}
