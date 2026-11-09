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

//! Names held only by destroyed objects (docs/interpretations.md): reuse in
//! `allow` mode (the default) and the earlier reservation in `reserve` mode,
//! with Locate order and draft 3.0 Name Reference resolution per edition.
use keytend_kmip_server::{
    authorization::ObjectGrant,
    protocol::{DestroyedNameReuse, Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use tempfile::TempDir;

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
const V3: Version = Version(3, 0);

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new(policy: DestroyedNameReuse) -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("keys.sqlite"), &k).unwrap();
        Self {
            _dir: d,
            engine: Engine::new(store, true).with_destroyed_name_reuse(policy),
        }
    }
    fn call(&mut self, v: Version, owner: &str, op: u32, p: Vec<Node>) -> Node {
        self.granted(v, owner, op, p, &[])
    }
    fn granted(
        &mut self,
        v: Version,
        owner: &str,
        op: u32,
        p: Vec<Node>,
        grants: &[ObjectGrant],
    ) -> Node {
        let mut header = vec![v.node()];
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, p));
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, header),
                Node::structure(BATCH_ITEM, item),
            ],
        );
        self.engine
            .process_with_grants(owner, &request, None, grants)
            .unwrap()
            .required(BATCH_ITEM)
            .unwrap()
            .clone()
    }
}
fn payload(item: &Node) -> &Node {
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{:?}",
        item.get(RESULT_MESSAGE).map(|n| n.string())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(item: &Node) -> u32 {
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn identifier(item: &Node) -> String {
    payload(item)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn name(v: Version, value: &str) -> Node {
    if v.0 >= 3 {
        Node::text(NAME, value)
    } else {
        Node::structure(
            NAME,
            vec![
                Node::text(NAME_VALUE, value),
                Node::enumeration(NAME_TYPE, 1),
            ],
        )
    }
}
/// One attribute in the version's form: 1.x Attribute, 2.x+ the attribute.
fn attribute(v: Version, a: Node) -> Node {
    if v.0 >= 2 {
        return a;
    }
    let label = match a.tag {
        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
        NAME => "Name",
        STATE => "State",
        _ => unreachable!(),
    };
    let mut value = a;
    value.tag = ATTRIBUTE_VALUE;
    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, label), value])
}
/// A Pre-Active AES key, named when `label` is given. Pre-Active keys can be
/// destroyed without a Revoke in every edition.
fn create(f: &mut Fixture, v: Version, owner: &str, label: Option<&str>) -> Node {
    let mut attributes = vec![
        Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
        Node::int(CRYPTOGRAPHIC_LENGTH, 128),
        Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
    ];
    attributes.extend(label.map(|l| name(v, l)));
    let attributes = attributes.into_iter().map(|a| attribute(v, a)).collect();
    let container = if v.0 >= 2 {
        ATTRIBUTES
    } else {
        TEMPLATE_ATTRIBUTE
    };
    f.call(
        v,
        owner,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(container, attributes),
        ],
    )
}
fn named(f: &mut Fixture, v: Version, owner: &str, label: &str) -> String {
    identifier(&create(f, v, owner, Some(label)))
}
fn destroy(f: &mut Fixture, v: Version, owner: &str, id: &str) {
    payload(&f.call(v, owner, 20, vec![uid(v, id)]));
}
/// Add Attribute of a Name to an existing object.
fn add_name(f: &mut Fixture, v: Version, owner: &str, id: &str, label: &str) -> Node {
    let a = if v.0 >= 2 {
        Node::structure(NEW_ATTRIBUTE, vec![name(v, label)])
    } else {
        attribute(v, name(v, label))
    };
    f.call(v, owner, 13, vec![uid(v, id), a])
}
/// Locate by Name; returns the identifiers in response order.
fn locate(f: &mut Fixture, v: Version, owner: &str, label: &str, extra: Vec<Node>) -> Vec<String> {
    let mut p = extra;
    if v.0 >= 2 {
        p.push(Node::structure(ATTRIBUTES, vec![name(v, label)]));
    } else {
        p.push(attribute(v, name(v, label)));
    }
    let item = f.call(v, owner, 8, p);
    payload(&item)
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect()
}
/// A Name conflict on Add Attribute (its 1.x reason comes from the 1.x
/// Add Attribute error tables; the message is the same everywhere).
fn refused(item: &Node) {
    assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
    assert_eq!(
        item.required(RESULT_MESSAGE).unwrap().string().unwrap(),
        "Name is not unique among the owner's objects"
    );
}
fn duplicate(v: Version) -> u32 {
    if v.0 >= 2 { 0x35 } else { 7 }
}
fn grant(owner: &str, id: &str) -> ObjectGrant {
    ObjectGrant {
        owner: owner.to_owned(),
        user: None,
        device: None,
        identifier: id.to_owned(),
        operations: vec![10, 11],
    }
}

#[test]
fn allow_is_the_default_policy() {
    assert_eq!(DestroyedNameReuse::default(), DestroyedNameReuse::Allow);
}

/// `allow`: a Name held only by destroyed objects can be given again, live
/// objects keep exclusive Names, and other owners are unaffected.
#[test]
fn allow_reuses_names_held_only_by_destroyed_objects() {
    for v in VERSIONS {
        let mut f = Fixture::new(DestroyedNameReuse::Allow);
        let first = named(&mut f, v, "alice", "k");
        assert_eq!(
            reason(&create(&mut f, v, "alice", Some("k"))),
            duplicate(v),
            "{v:?}: a live holder keeps its Name"
        );
        destroy(&mut f, v, "alice", &first);
        let second = named(&mut f, v, "alice", "k");
        assert_ne!(first, second);
        assert_eq!(
            reason(&create(&mut f, v, "alice", Some("k"))),
            duplicate(v),
            "{v:?}: the new live holder is exclusive"
        );
        let unnamed = identifier(&create(&mut f, v, "alice", None));
        refused(&add_name(&mut f, v, "alice", &unnamed, "k"));
        // Two destroyed holders still leave the Name free.
        destroy(&mut f, v, "alice", &second);
        let third = named(&mut f, v, "alice", "k");
        // Another owner's Names are separate in either mode.
        named(&mut f, v, "bob", "k");
        // An on-line Locate finds the live holder alone; selecting destroyed
        // objects as well lists every holder newest first (2.1 section 6.1.27).
        assert_eq!(locate(&mut f, v, "alice", "k", vec![]), [third.as_str()]);
        if v.0 >= 2 {
            let mask = vec![Node::int(STORAGE_STATUS_MASK, 5)];
            let found = locate(&mut f, v, "alice", "k", mask);
            assert_eq!(found, [third, second, first], "{v:?}");
        } else {
            let state = vec![attribute(v, Node::enumeration(STATE, 5))];
            let found = locate(&mut f, v, "alice", "k", state);
            assert_eq!(found, [second, first], "{v:?}");
        }
    }
}

/// `reserve`: every holder keeps its Name, destroyed or not (the earlier
/// behaviour).
#[test]
fn reserve_keeps_destroyed_names() {
    for v in VERSIONS {
        let mut f = Fixture::new(DestroyedNameReuse::Reserve);
        let first = named(&mut f, v, "alice", "k");
        destroy(&mut f, v, "alice", &first);
        assert_eq!(
            reason(&create(&mut f, v, "alice", Some("k"))),
            duplicate(v),
            "{v:?}"
        );
        let unnamed = identifier(&create(&mut f, v, "alice", None));
        refused(&add_name(&mut f, v, "alice", &unnamed, "k"));
        named(&mut f, v, "bob", "k");
        assert!(locate(&mut f, v, "alice", "k", vec![]).is_empty());
    }
}

/// An older live object takes the Name after the destroyed holder. Locate is
/// the same in both modes: an on-line Locate returns the live holder only,
/// and a 2.x Locate that also selects destroyed objects keeps "descending
/// order of object creation" (2.1 section 6.1.27).
#[test]
fn locate_returns_live_holders_unless_destroyed_objects_are_selected() {
    for v in VERSIONS {
        let mut f = Fixture::new(DestroyedNameReuse::Allow);
        let older = identifier(&create(&mut f, v, "alice", None));
        let dead = named(&mut f, v, "alice", "k");
        destroy(&mut f, v, "alice", &dead);
        payload(&add_name(&mut f, v, "alice", &older, "k"));
        assert_eq!(
            locate(&mut f, v, "alice", "k", vec![]),
            [older.as_str()],
            "{v:?}"
        );
        if v.0 >= 2 {
            let mask = vec![Node::int(STORAGE_STATUS_MASK, 5)];
            assert_eq!(
                locate(&mut f, v, "alice", "k", mask),
                [dead, older],
                "{v:?}"
            );
        }
    }
}

fn by_name(f: &mut Fixture, owner: &str, label: &str, grants: &[ObjectGrant]) -> Node {
    f.granted(
        V3,
        owner,
        11,
        vec![Node::name_reference(UNIQUE_IDENTIFIER, label)],
        grants,
    )
}

/// Draft 3.0 Name Reference with `allow`: live holders before destroyed ones,
/// own before granted, and destroyed holders never make it ambiguous.
#[test]
fn name_references_prefer_live_holders_and_are_never_ambiguous_by_destruction() {
    let mut f = Fixture::new(DestroyedNameReuse::Allow);
    let first = named(&mut f, V3, "alice", "k");
    destroy(&mut f, V3, "alice", &first);
    let second = named(&mut f, V3, "alice", "k");
    assert_eq!(identifier(&by_name(&mut f, "alice", "k", &[])), second);
    // Only destroyed holders: the most recently created one.
    destroy(&mut f, V3, "alice", &second);
    assert_eq!(identifier(&by_name(&mut f, "alice", "k", &[])), second);
    assert_eq!(
        reason(&f.call(
            V3,
            "alice",
            10,
            vec![Node::name_reference(UNIQUE_IDENTIFIER, "k")]
        )),
        0x36,
        "Get of the resolved destroyed holder is Object Destroyed"
    );
    // Bob's own holder is destroyed; Alice's live "j" granted to him wins.
    let bobs = named(&mut f, V3, "bob", "j");
    destroy(&mut f, V3, "bob", &bobs);
    let alices = named(&mut f, V3, "alice", "j");
    let grants = [grant("alice", &alices)];
    assert_eq!(identifier(&by_name(&mut f, "bob", "j", &grants)), alices);
    assert_eq!(identifier(&by_name(&mut f, "bob", "j", &[])), bobs);
    // Bob's live holder wins over the granted one.
    let bobs_live = named(&mut f, V3, "bob", "j");
    assert_eq!(identifier(&by_name(&mut f, "bob", "j", &grants)), bobs_live);
    // Carol: two granted live holders stay ambiguous...
    let both = [grant("alice", &alices), grant("bob", &bobs_live)];
    assert_eq!(reason(&by_name(&mut f, "carol", "j", &both)), 0x35);
    // ...but granted destroyed holders resolve to the newest one.
    let dead = [grant("alice", &first), grant("alice", &second)];
    assert_eq!(identifier(&by_name(&mut f, "carol", "k", &dead)), second);
    assert_eq!(reason(&by_name(&mut f, "carol", "missing", &both)), 0x37);
}

/// `reserve` keeps owner-first resolution: the caller's own holder, even
/// destroyed.
#[test]
fn reserve_name_references_keep_owner_first_resolution() {
    let mut f = Fixture::new(DestroyedNameReuse::Reserve);
    let bobs = named(&mut f, V3, "bob", "j");
    destroy(&mut f, V3, "bob", &bobs);
    let alices = named(&mut f, V3, "alice", "j");
    let grants = [grant("alice", &alices)];
    assert_eq!(identifier(&by_name(&mut f, "bob", "j", &grants)), bobs);
    assert_eq!(identifier(&by_name(&mut f, "carol", "j", &grants)), alices);
}

/// Delete Attribute of a Name (no index: the first and only instance).
fn delete_name(f: &mut Fixture, v: Version, owner: &str, id: &str, label: &str) -> Node {
    let a = if v.0 >= 2 {
        Node::structure(CURRENT_ATTRIBUTE, vec![name(v, label)])
    } else {
        Node::text(ATTRIBUTE_NAME, "Name")
    };
    f.call(v, owner, 15, vec![uid(v, id), a])
}

/// `reserve` (docs/attributes.md): a destroyed object's attributes cannot be
/// changed, so its Name cannot be deleted (2.1 Table 204 and draft 3.0 Table
/// 307: Wrong Key Lifecycle State; 1.x and 2.0: Permission Denied) and stays
/// reserved. The owner frees it by deleting the Name before Destroy, or in
/// draft 3.0 by obliterating the destroyed object.
#[test]
fn reserve_frees_a_name_only_before_destroy() {
    for v in VERSIONS {
        let mut f = Fixture::new(DestroyedNameReuse::Reserve);
        let dead = named(&mut f, v, "alice", "k");
        destroy(&mut f, v, "alice", &dead);
        let item = delete_name(&mut f, v, "alice", &dead, "k");
        let expected = if v >= Version(2, 1) { 0x43 } else { 12 };
        assert_eq!(reason(&item), expected, "{v:?}");
        assert_eq!(reason(&create(&mut f, v, "alice", Some("k"))), duplicate(v));
        if v == V3 {
            // Draft 3.0 Obliterate removes the object with its metadata.
            payload(&f.call(v, "alice", 61, vec![uid(v, &dead)]));
            named(&mut f, v, "alice", "k");
        }

        let old = named(&mut f, v, "alice", "j");
        payload(&delete_name(&mut f, v, "alice", &old, "j"));
        destroy(&mut f, v, "alice", &old);
        named(&mut f, v, "alice", "j");
    }
}
