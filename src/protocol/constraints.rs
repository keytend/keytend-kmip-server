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

//! Set Constraints and Get Constraints: the draft 3.0 (CSD02) per-owner sets
//! (6.1.59, 6.1.28) and the KMIP 2.1 server-wide set (6.1.52, 6.1.22).
//!
//! The draft defines a Constraint (section 7.6, table 466; 2.1 section 7.6,
//! table 357) as "a constraint that is applied to operations that create
//! Managed Objects", with optional Object Types (7.25), Object Groups (7.24)
//! and Attributes, and the result reason Constraint Violation (0x4B, table
//! 595): "one or more constraints were violated". Neither edition says how
//! the three fields combine. This server reads them the way Object Defaults
//! (7.23) are scoped:
//!
//! * A constraint applies to a newly created object when the object's type is
//!   one of its Object Types (absent: every type) and, if Object Groups is
//!   present, one of the object's Group Link values (4.35.7) equals one of
//!   them (same Reference or Name Reference text; names are not resolved).
//! * An applicable constraint is satisfied when every attribute in its
//!   Attributes matches an attribute of the created object, with the Locate
//!   filter rule (`attribute_matches`: equal values; a Cryptographic Usage
//!   Mask matches when all of its bits are set; a structure matches when each
//!   given field matches).
//! * A constraint without Attributes would restrict nothing and is refused
//!   with Invalid Field rather than stored as a no-op.
//!
//! **Scopes.** A 3.0 request sets and reads the set of its managed-object
//! owner (the certificate principal, or its verified user or device under
//! credential identity), which applies only to objects that owner creates in
//! 3.0 requests. A 2.1 request sets and reads the one server-wide set
//! (`Scope::Server`), which applies to every Managed Object that a 2.1 or 3.0
//! request item inserts into a managed-object namespace, whoever the owner.
//! In 3.0 an object must satisfy both. 1.x and 2.0 requests are never
//! constrained.
//!
//! The server set is always validated, stored and read back as 2.1, with the
//! fixed normalization owner `"\0server"`, and created objects are compared
//! with it in their 2.1 form, so a 2.1 Name constraint holds for a 3.0
//! Create. Object Groups, and Object Group or Group Link attributes, are
//! Feature Not Supported in the server set: 2.1 groups are Object Group
//! attributes and 3.0 groups are Group Links, and neither edition could
//! satisfy or escape the other's. A server record that cannot be read fails
//! every constrained item with General Failure rather than skipping the
//! check.
//!
//! Enforcement runs after the item: each Managed Object it inserted (Create,
//! Create Key Pair, Register, Re-key, Re-key Key Pair, Derive Key, Certify,
//! Re-certify, the Split Key operations, Import, ...) is checked in its final
//! state. A violation fails the item with Constraint Violation and rolls the
//! item back, so nothing it created remains. Objects that exist already,
//! attribute changes after creation and System Objects (User, Group and
//! credentials) are not checked; their Object Types are refused with Invalid
//! Object Type. Re-Provision (53) is exempt from both sets: its objects are
//! server-generated credentials and its error table has no Constraint
//! Violation.
//!
//! Set Constraints replaces the whole set; an empty Constraints structure
//! removes it. Each set is a hidden record (records.rs) in the encrypted,
//! authenticated store, so it survives restarts, follows batch Undo, is in
//! backups and is never visible to Locate or Get.
use super::*;

/// Constraint Violation (draft 3.0 table 595).
const CONSTRAINT_VIOLATION: u32 = 0x4b;
/// Invalid Object Type (draft 3.0 table 595).
const INVALID_OBJECT_TYPE: u32 = 0x30;
const MAX_CONSTRAINTS: usize = 32;
const MAX_ATTRIBUTES: usize = 32;
const MAX_GROUPS: usize = 32;
const MAX_ENCODED: usize = 64 * 1024;
/// The managed object types a constraint can name (draft 3.0 table 582,
/// without the System Object types).
const MANAGED_TYPES: [u32; 9] = [1, 2, 3, 4, 5, 7, 8, 9, 10];

/// The normalization owner of the server set: no principal's objects
/// resolve under it.
const SERVER: &str = "\0server";
/// The record identifier of the server set.
const SERVER_RECORD: &str = "constraints\0\0server";

fn namespace(owner: &str) -> String {
    format!("{owner}\0constraints")
}
fn record_id(owner: &str) -> String {
    format!("constraints\0{owner}")
}
/// The General Failure of a server set that cannot be read: creations fail
/// closed.
fn unreadable(_: Failure) -> Failure {
    fail(0x100, "The server constraints cannot be read")
}

/// Which constraint set a request reads or replaces.
enum Scope {
    /// A draft 3.0 managed-object owner's own set.
    Owner(String),
    /// The KMIP 2.1 server-wide set.
    Server,
}
impl Scope {
    /// The set Set Constraints and Get Constraints address in `v`.
    fn of(owner: &str, v: Version) -> Self {
        if v.0 >= 3 {
            Self::Owner(owner.to_owned())
        } else {
            Self::Server
        }
    }
    /// (record owner, record identifier).
    fn record(&self) -> (String, String) {
        match self {
            Self::Owner(owner) => (namespace(owner), record_id(owner)),
            Self::Server => (
                records::SERVER_CONSTRAINTS_OWNER.to_owned(),
                SERVER_RECORD.to_owned(),
            ),
        }
    }
    /// The edition and normalization owner the set is read in.
    fn reading(&self, v: Version) -> (Version, &str) {
        match self {
            Self::Owner(owner) => (v, owner),
            Self::Server => (Version(2, 1), SERVER),
        }
    }
}
fn invalid(message: &'static str) -> Failure {
    fail(7, message)
}

/// One validated constraint, attributes in the draft 3.0 encoding (typed
/// links, Name as a Text String), as `object_attrs` projects them.
struct Constraint {
    types: Option<Vec<u32>>,
    groups: Option<Vec<Node>>,
    attributes: Vec<Node>,
}
impl Constraint {
    fn node(&self) -> Node {
        let mut fields = vec![];
        if let Some(types) = &self.types {
            fields.push(Node::structure(
                OBJECT_TYPES,
                types
                    .iter()
                    .map(|t| Node::enumeration(OBJECT_TYPE, *t))
                    .collect(),
            ));
        }
        if let Some(groups) = &self.groups {
            fields.push(Node::structure(OBJECT_GROUPS, groups.clone()));
        }
        fields.push(Node::structure(ATTRIBUTES, self.attributes.clone()));
        Node::structure(CONSTRAINT, fields)
    }
    fn applies(&self, obj: &Object, attrs: &[Node]) -> bool {
        self.types
            .as_ref()
            .is_none_or(|types| types.contains(&obj.object_type))
            && self.groups.as_ref().is_none_or(|groups| {
                attrs
                    .iter()
                    .filter(|a| a.tag == GROUP_LINK)
                    .any(|a| groups.iter().any(|g| g.value == a.value))
            })
    }
    fn satisfied(&self, attrs: &[Node]) -> bool {
        self.attributes
            .iter()
            .all(|c| attrs.iter().any(|a| attribute_matches(c, a)))
    }
}

/// Whether `obj`, in its `v` form, violates one of `set`.
fn violates(set: &[Constraint], obj: &Object, v: Version) -> bool {
    if set.is_empty() {
        return false;
    }
    let attrs = object_attrs(obj, v)
        .iter()
        .map(|a| identifiers::project_attribute(v, a))
        .collect::<Vec<_>>();
    set.iter()
        .any(|c| c.applies(obj, &attrs) && !c.satisfied(&attrs))
}

/// A structure that holds only `tag` children, at most `max` of them.
fn list(n: &Node, tag: u32, max: usize) -> R<&[Node]> {
    let children = n.children()?;
    if children.iter().any(|c| c.tag != tag) {
        return Err(invalid("Unexpected field in a Constraint list"));
    }
    if children.len() > max {
        return Err(fail(0x3a, "Constraint exceeds the server limit"));
    }
    Ok(children)
}

impl Engine {
    fn read_constraint(&self, scope: &Scope, v: Version, n: &Node) -> R<Constraint> {
        let (v, owner) = scope.reading(v);
        no_fields(n, &[OBJECT_TYPES, OBJECT_GROUPS, ATTRIBUTES])?;
        for tag in [OBJECT_TYPES, OBJECT_GROUPS, ATTRIBUTES] {
            if n.all(tag).count() > 1 {
                return Err(invalid("Duplicate Constraint field"));
            }
        }
        let types = match n.get(OBJECT_TYPES) {
            Some(types) => {
                let mut out = vec![];
                for t in list(types, OBJECT_TYPE, MANAGED_TYPES.len())? {
                    let t = t.number()?;
                    if !MANAGED_TYPES.contains(&t) {
                        return Err(fail(
                            INVALID_OBJECT_TYPE,
                            "Constraints apply to Managed Object types only",
                        ));
                    }
                    if !out.contains(&t) {
                        out.push(t);
                    }
                }
                if out.is_empty() {
                    return Err(invalid("Object Types is empty"));
                }
                Some(out)
            }
            None => None,
        };
        let server = matches!(scope, Scope::Server);
        if server && n.get(OBJECT_GROUPS).is_some() {
            return Err(fail(
                8,
                "Object Groups are not supported in server constraints",
            ));
        }
        let groups = match n.get(OBJECT_GROUPS) {
            Some(groups) => {
                let groups = list(groups, GROUP_LINK, MAX_GROUPS)?;
                for g in groups {
                    system::validate_group_link(g, v)?;
                }
                if groups.is_empty() {
                    return Err(invalid("Object Groups is empty"));
                }
                Some(groups.to_vec())
            }
            None => None,
        };
        let attributes = n
            .get(ATTRIBUTES)
            .ok_or(invalid("A Constraint without Attributes restricts nothing"))?;
        let attributes = attributes.children()?;
        if attributes.is_empty() {
            return Err(invalid("A Constraint without Attributes restricts nothing"));
        }
        if attributes.len() > MAX_ATTRIBUTES {
            return Err(fail(0x3a, "Constraint exceeds the server limit"));
        }
        if server
            && attributes
                .iter()
                .any(|a| matches!(a.tag, OBJECT_GROUP | GROUP_LINK))
        {
            return Err(fail(
                8,
                "Group attributes are not supported in server constraints",
            ));
        }
        // The same normalization and validation as attributes given to Create
        // (typed links and Name to their stored form; references to earlier
        // results in the message are not meaningful here and fail).
        let refs = identifiers::References::default();
        let attributes = attributes
            .iter()
            .map(|a| self.normalize_attribute(owner, v, a.clone(), &refs, &None))
            .collect::<R<Vec<_>>>()?;
        validate_attrs(&attributes, v)?;
        Ok(Constraint {
            types,
            groups,
            attributes: attributes
                .iter()
                .map(|a| identifiers::project_attribute(v, a))
                .collect(),
        })
    }

    fn stored_constraints(&self, scope: &Scope, v: Version) -> R<Vec<Constraint>> {
        let (owner, id) = scope.record();
        let read = || {
            let Some(material) = self.read_record(&owner, &id)? else {
                return Ok(vec![]);
            };
            let set = crate::ttlv::decode(&material)?;
            if set.tag != CONSTRAINTS {
                return Err(fail(0x100, "Unexpected constraints record"));
            }
            set.all(CONSTRAINT)
                .map(|c| self.read_constraint(scope, v, c))
                .collect()
        };
        match scope {
            Scope::Server => read().map_err(unreadable),
            Scope::Owner(_) => read(),
        }
    }

    /// 2.1 section 6.1.52: replace the server set; draft 3.0 section
    /// 6.1.59: replace the requester's set.
    pub(super) fn set_constraints(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        let scope = Scope::of(owner, v);
        no_fields(p, &[CONSTRAINTS])?;
        if p.all(CONSTRAINTS).count() != 1 {
            return Err(invalid("Set Constraints requires one Constraints field"));
        }
        let set = p.required(CONSTRAINTS)?;
        let constraints = list(set, CONSTRAINT, MAX_CONSTRAINTS)?
            .iter()
            .map(|c| self.read_constraint(&scope, v, c))
            .collect::<R<Vec<_>>>()?;
        let (space, id) = scope.record();
        if matches!(scope, Scope::Server) {
            tracing::info!(principal = %owner, constraints = constraints.len(), "server constraints replaced");
        }
        if constraints.is_empty() {
            self.remove_record(&space, &id)?;
            return Ok(vec![]);
        }
        // Stored in the form of the edition it is read in (2.1 for the
        // server set, draft 3.0 for an owner's); reading it back repeats the
        // validation above.
        let encoded = Node::structure(
            CONSTRAINTS,
            constraints.iter().map(Constraint::node).collect(),
        )
        .encode();
        if encoded.len() > MAX_ENCODED {
            return Err(fail(0x3a, "Constraints exceed the server limit"));
        }
        self.write_record(&space, &id, records::CONSTRAINTS_RECORD, encoded)?;
        Ok(vec![])
    }

    /// 2.1 section 6.1.22 and draft 3.0 section 6.1.28: "the constraints
    /// that are being applied": the server set in 2.1, the requester's own
    /// set in 3.0 (the server set also applies there; see the module text).
    pub(super) fn get_constraints(&self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[])?;
        Ok(vec![Node::structure(
            CONSTRAINTS,
            self.stored_constraints(&Scope::of(owner, v), v)?
                .iter()
                .map(Constraint::node)
                .collect(),
        )])
    }

    /// Run one operation item and check every Managed Object it inserted:
    /// against the server set in 2.1 and 3.0 requests, and in 3.0 also
    /// against `owner`'s own set for the objects inserted for `owner`.
    /// Re-Provision (53) is exempt from both.
    pub(super) fn constrained(
        &mut self,
        owner: &str,
        v: Version,
        op: u32,
        run: impl FnOnce(&mut Self) -> R<Node>,
    ) -> R<Node> {
        if op == 53 || v < Version(2, 1) {
            return run(self);
        }
        self.store.track_inserts();
        let result = run(self);
        let inserted = self.store.take_inserts();
        let result = result?;
        let managed = inserted
            .iter()
            .filter(|(o, _)| system::certificate_principal(o).is_some())
            .collect::<Vec<_>>();
        if managed.is_empty() {
            return Ok(result);
        }
        let server = self.stored_constraints(&Scope::Server, v)?;
        let own = if v.0 >= 3 && managed.iter().any(|(o, _)| o == owner) {
            self.stored_constraints(&Scope::Owner(owner.to_owned()), v)?
        } else {
            vec![]
        };
        if server.is_empty() && own.is_empty() {
            return Ok(result);
        }
        for (o, id) in managed {
            let Some(obj) = self.store.get(o, id)? else {
                continue;
            };
            if violates(&server, &obj, Version(2, 1)) || o == owner && violates(&own, &obj, v) {
                return Err(fail(
                    CONSTRAINT_VIOLATION,
                    "The created object violates a constraint",
                ));
            }
        }
        Ok(result)
    }
    /// Whether the server constraints and server defaults records can be
    /// read; an error names the one that cannot. Creations fail closed
    /// while the constraints record is unreadable, so a startup check can
    /// report it early.
    pub fn check_server_records(&self) -> anyhow::Result<()> {
        if let Err(e) = self.stored_constraints(&Scope::Server, Version(2, 1)) {
            anyhow::bail!("server constraints record: {}", e.message);
        }
        if let Err(e) = self.stored_defaults() {
            anyhow::bail!("server defaults record: {}", e.message);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_set_is_the_reserved_record() {
        assert_eq!(
            Scope::Server.record(),
            (
                records::SERVER_CONSTRAINTS_OWNER.to_owned(),
                SERVER_RECORD.to_owned()
            )
        );
        // The same layout as an owner's record, under an owner no policy
        // principal can name.
        assert_eq!(
            Scope::Owner(SERVER.to_owned()).record(),
            Scope::Server.record()
        );
        assert!(system::certificate_principal(records::SERVER_CONSTRAINTS_OWNER).is_none());
        assert!(system::certificate_principal(records::SERVER_DEFAULTS_OWNER).is_none());
    }
}
