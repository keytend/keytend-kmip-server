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

//! Names held only by destroyed objects
//! (docs/interpretations.md#names-held-only-by-destroyed-objects).
//!
//! KMIP keeps a destroyed object's attributes: 1.x Destroy says the server
//! "MAY retain" metadata (1.4 section 4.21), 2.x/3.0 Destroy says it SHALL
//! (2.1 section 6.1.15), so a destroyed object still carries its Name. The
//! uniqueness rule is "Names SHALL be unique within a given key management
//! domain" (1.4 section 3.2) or "server" (2.1 section 4.32, draft 3.0 section
//! 4.36), scoped per owner (docs/interpretations.md#name-uniqueness). The
//! specification does not say whether a destroyed object still "holds" its
//! Name; clients that re-register a removed key's name (Percona Server's
//! component_keyring_kmip) assume it does not.
//!
//! With `allow` (the default) only objects that are not Destroyed (State 5)
//! or Destroyed Compromised (State 6) hold a Name exclusively:
//! - a new or modified object may take a Name that only destroyed objects of
//!   the owner carry; a destroyed object's own Names are never checked;
//! - a draft 3.0 Name Reference resolves to, in order: the caller's object
//!   that is not destroyed; a granted object that is not destroyed (two such
//!   are ambiguous, as before); the caller's most recently created destroyed
//!   holder; the most recently created granted destroyed holder. Destroyed
//!   holders never make a reference ambiguous;
//! - Locate is unchanged: an on-line Locate never returns destroyed objects
//!   (2.x/3.0 Storage Status Mask default On-line, 2.1 section 6.1.27; 1.x
//!   only when the request selects Destroyed State or Destroy Date, see
//!   archive.rs), so a reused Name locates its live holder alone. A Locate
//!   that selects destroyed objects keeps "descending order of object
//!   creation" (2.1 section 6.1.27, draft 3.0 likewise).
//!
//! `reserve` keeps the earlier behaviour: every holder, destroyed or not,
//! reserves the Name.
use super::*;

/// Whether a Name held only by destroyed objects may be given to another object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum DestroyedNameReuse {
    /// Destroyed holders do not reserve their Names.
    #[default]
    Allow,
    /// Every holder reserves its Names, destroyed or not.
    Reserve,
}
/// Destroyed or Destroyed Compromised.
pub(super) fn destroyed(obj: &Object) -> bool {
    matches!(obj.state, 5 | 6)
}
impl Engine {
    /// Whether `other` keeps `obj` from carrying one of `other`'s Names.
    pub(super) fn reserves_names(&self, obj: &Object, other: &Object) -> bool {
        self.destroyed_name_reuse == DestroyedNameReuse::Reserve
            || !destroyed(obj) && !destroyed(other)
    }
    /// The object a draft 3.0 Name Reference designates (per-owner names and
    /// the module rule above).
    pub(super) fn resolve_name_reference(
        &self,
        owner: &str,
        v: Version,
        name: &str,
    ) -> R<Vec<String>> {
        let named = |obj: &Object| {
            visible(obj, Some(v))
                && obj.attrs.iter().any(|a| {
                    a.tag == NAME && a.get(NAME_VALUE).and_then(|n| n.string().ok()) == Some(name)
                })
        };
        let access = self.locate_access();
        if self.destroyed_name_reuse == DestroyedNameReuse::Reserve {
            // Names are unique per owner, so the caller's own
            // object is resolved first; granted objects of other owners are
            // considered only when the caller owns none with this Name, and
            // two of them with the same Name remain ambiguous.
            let (mut count, mut ids) = self.store.locate(owner, 0, 1, named)?;
            if count == 0 {
                (count, ids) = self.store.locate_scoped(owner, &access, 0, 1, named)?;
            }
            return match count {
                0 => Err(not_found::object()),
                1 => Ok(ids),
                _ => Err(fail(0x35, "Name reference is ambiguous")),
            };
        }
        let live = |obj: &Object| named(obj) && !destroyed(obj);
        for scope in [&[][..], &access] {
            match self.store.locate_scoped(owner, scope, 0, 1, live)? {
                (0, _) => {}
                (1, ids) => return Ok(ids),
                _ => return Err(fail(0x35, "Name reference is ambiguous")),
            }
        }
        // Newest first: the most recently created destroyed holder.
        let dead = |obj: &Object| named(obj) && destroyed(obj);
        for scope in [&[][..], &access] {
            if let (1.., ids) = self.store.locate_scoped(owner, scope, 0, 1, dead)? {
                return Ok(ids);
            }
        }
        Err(not_found::object())
    }
}
