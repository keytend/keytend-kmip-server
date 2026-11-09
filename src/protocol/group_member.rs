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

//! Locate with Object Group Member (KMIP 1.1-1.4 section 4.9, 2.x section
//! 6.1.27; enumeration 1.1 table 246, 2.0 table 429).
//!
//! "When the Object Group attribute and the Object Group Member flag are
//! specified in the request, and the value specified for Object Group Member is
//! 'Group Member Fresh', matching candidate objects SHALL be fresh objects
//! (see 3.34) from the object group. [...] If the value specified for Object
//! Group Member is 'Group Member Default', the server locates the default
//! object as defined by server policy."
//!
//! Server policy here:
//! - In 1.x, which sets no result order, fresh members are returned oldest
//!   first, so a pool of prepared objects is handed out in creation order.
//!   2.0 and later require "descending order of object creation (most
//!   recently created object first)" (2.1 section 6.1.27), which applies
//!   unchanged. No object is generated on the fly when the group has no fresh
//!   member (the text leaves that to server policy).
//! - The default member rotates through the matching members in creation
//!   order, one per Locate. The rotation position is held in memory per
//!   principal and group set, so a restart starts again at the oldest member.
//! - Both values require an Object Group filter, the only case the text
//!   defines.
use super::*;
use std::collections::HashMap;

const FRESH_MEMBER: u32 = 1;
const DEFAULT_MEMBER: u32 = 2;
const MAX_ROTATIONS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Member {
    Fresh,
    Default,
}

/// Default-member positions per (principal, requested group names).
#[derive(Default)]
pub(super) struct Rotation(HashMap<(String, Vec<String>), usize>);
impl Rotation {
    /// The position to use now; the next call for the same key moves on.
    pub(super) fn next(&mut self, owner: &str, filters: &[Node]) -> usize {
        let mut groups = filters
            .iter()
            .filter(|f| f.tag == OBJECT_GROUP)
            .filter_map(|f| f.string().ok().map(str::to_owned))
            .collect::<Vec<_>>();
        groups.sort();
        if self.0.len() >= MAX_ROTATIONS {
            self.0.clear();
        }
        let position = self.0.entry((owner.to_owned(), groups)).or_default();
        let current = *position;
        *position = position.wrapping_add(1);
        current
    }
}

/// The requested Object Group Member, after the filters were decoded.
pub(super) fn requested(p: &Node, v: Version, filters: &[Node]) -> R<Option<Member>> {
    let mut all = p.all(OBJECT_GROUP_MEMBER);
    let Some(n) = all.next() else {
        return Ok(None);
    };
    if v < Version(1, 1) {
        // Object Group Member was introduced in KMIP 1.1.
        return Err(fail(8, "Unsupported Locate field"));
    }
    if all.next().is_some() {
        return Err(fail(7, "Duplicate Locate field"));
    }
    let member = match n.value {
        Value::Enumeration(FRESH_MEMBER) => Member::Fresh,
        Value::Enumeration(DEFAULT_MEMBER) => Member::Default,
        _ => return Err(fail(7, "Invalid Object Group Member")),
    };
    if !filters.iter().any(|f| f.tag == OBJECT_GROUP) {
        return Err(fail(
            7,
            "Object Group Member requires an Object Group filter",
        ));
    }
    Ok(Some(member))
}
