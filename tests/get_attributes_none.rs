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

//! Get Attributes when none of the requested attributes exist
//! (`--get-attributes-none`, docs/interpretations.md, src/protocol/get_attributes_none.rs).
//!
//! 2.0/2.1 section 6.1.20 and draft 3.0 section 6.1.26: "If none of the
//! requested attributes exist, then the response SHALL consist only of the
//! Unique Identifier"; the response tables (2.0 Table 209, 2.1 Table 224,
//! draft 3.0 Table 330) mark Attributes REQUIRED. `empty-attributes` (default)
//! follows the table, `identifier-only` the prose; 1.x is identifier-only in
//! both settings.
//
// REQ:7ebd66853ffb6476 2.x/3.0 none of the requested attributes exist: only the Unique Identifier, under `--get-attributes-none identifier-only` (named configuration; the default returns an empty Attributes structure)
use keytend_kmip_server::{
    protocol::{Engine, GetAttributesNone, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};
use tempfile::TempDir;

const EDITIONS: [Version; 8] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
    Version(2, 0),
    Version(2, 1),
    Version(3, 0),
];
const FORMS: [GetAttributesNone; 2] = [
    GetAttributesNone::EmptyAttributes,
    GetAttributesNone::IdentifierOnly,
];

struct Fixture {
    _dir: TempDir,
    engine: Engine,
}
impl Fixture {
    fn new(form: Option<GetAttributesNone>) -> Self {
        let d = tempfile::tempdir().unwrap();
        let k = d.path().join("master");
        std::fs::write(&k, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("keys.sqlite"), &k).unwrap();
        let mut engine = Engine::new(store, true);
        if let Some(form) = form {
            engine = engine.with_get_attributes_none(form);
        }
        Self { _dir: d, engine }
    }
    fn call(&mut self, v: Version, op: u32, p: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        let mut item = vec![Node::enumeration(OPERATION, op)];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
            item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![1]));
        }
        item.push(Node::structure(REQUEST_PAYLOAD, p));
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, header),
                Node::structure(BATCH_ITEM, item),
            ],
        );
        let response = self.engine.process("alice", &request).unwrap();
        let item = response.get(BATCH_ITEM).unwrap();
        assert_eq!(
            item.required(RESULT_STATUS).unwrap().number().unwrap(),
            0,
            "{v:?} op {op}: reason {:?}",
            item.get(RESULT_REASON).map(|n| n.number().unwrap())
        );
        item.required(RESPONSE_PAYLOAD).unwrap().clone()
    }
    /// An AES key; the Description attribute is never set on it.
    fn key(&mut self, v: Version) -> String {
        let attributes = vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
            Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
        ];
        let template = if v.0 >= 2 {
            Node::structure(ATTRIBUTES, attributes)
        } else {
            Node::structure(
                TEMPLATE_ATTRIBUTE,
                attributes
                    .into_iter()
                    .map(|mut a| {
                        let name = tag_name(a.tag).unwrap();
                        a.tag = ATTRIBUTE_VALUE;
                        Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), a])
                    })
                    .collect(),
            )
        };
        let p = self.call(v, 1, vec![Node::enumeration(OBJECT_TYPE, 2), template]);
        p.required(UNIQUE_IDENTIFIER)
            .unwrap()
            .identifier_text()
            .unwrap()
            .to_owned()
    }
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn select(v: Version, tag: u32) -> Node {
    if v.0 >= 2 {
        Node::enumeration(ATTRIBUTE_REFERENCE, tag)
    } else {
        Node::text(ATTRIBUTE_NAME, tag_name(tag).unwrap())
    }
}
fn fields(p: &Node) -> Vec<u32> {
    p.children().unwrap().iter().map(|n| n.tag).collect()
}
fn attributes(p: &Node) -> Vec<u32> {
    fields(p.required(ATTRIBUTES).unwrap())
}

#[test]
fn the_default_is_an_empty_attributes_structure() {
    assert_eq!(
        GetAttributesNone::default(),
        GetAttributesNone::EmptyAttributes
    );
    for v in [Version(2, 0), Version(2, 1), Version(3, 0)] {
        let mut f = Fixture::new(None);
        let id = f.key(v);
        let p = f.call(v, 11, vec![uid(v, &id), select(v, DESCRIPTION)]);
        assert_eq!(fields(&p), [UNIQUE_IDENTIFIER, ATTRIBUTES], "{v:?}");
        assert!(attributes(&p).is_empty(), "{v:?}");
    }
}

#[test]
fn none_of_the_requested_attributes_exist() {
    for form in FORMS {
        for v in EDITIONS {
            let mut f = Fixture::new(Some(form));
            let id = f.key(v);
            for request in [
                vec![uid(v, &id), select(v, DESCRIPTION)],
                vec![uid(v, &id), select(v, DESCRIPTION), select(v, COMMENT)],
            ] {
                let p = f.call(v, 11, request);
                let want: &[u32] = if v.0 >= 2 && form == GetAttributesNone::EmptyAttributes {
                    &[UNIQUE_IDENTIFIER, ATTRIBUTES]
                } else {
                    // 1.x always; 2.x/3.0 with identifier-only.
                    &[UNIQUE_IDENTIFIER]
                };
                assert_eq!(fields(&p), want, "{form:?} {v:?}");
                if v.0 >= 2 && form == GetAttributesNone::EmptyAttributes {
                    assert!(attributes(&p).is_empty(), "{form:?} {v:?}");
                }
                let id_back = p.required(UNIQUE_IDENTIFIER).unwrap().identifier_text();
                assert_eq!(id_back.unwrap(), id, "{form:?} {v:?}");
            }
        }
    }
}

/// Negative cases: a found attribute, or no selection at all, keeps the
/// Attributes structure in 2.x/3.0 under both settings.
#[test]
fn found_or_unselected_attributes_are_unaffected() {
    for form in FORMS {
        for v in EDITIONS {
            let mut f = Fixture::new(Some(form));
            let id = f.key(v);
            let some = f.call(
                v,
                11,
                vec![
                    uid(v, &id),
                    select(v, DESCRIPTION),
                    select(v, CRYPTOGRAPHIC_LENGTH),
                ],
            );
            let all = f.call(v, 11, vec![uid(v, &id)]);
            if v.0 >= 2 {
                assert_eq!(fields(&some), [UNIQUE_IDENTIFIER, ATTRIBUTES], "{v:?}");
                assert_eq!(attributes(&some), [CRYPTOGRAPHIC_LENGTH], "{form:?} {v:?}");
                assert_eq!(fields(&all), [UNIQUE_IDENTIFIER, ATTRIBUTES], "{v:?}");
                assert!(attributes(&all).contains(&CRYPTOGRAPHIC_ALGORITHM));
            } else {
                assert_eq!(fields(&some), [UNIQUE_IDENTIFIER, ATTRIBUTE], "{v:?}");
                assert!(fields(&all).iter().filter(|t| **t == ATTRIBUTE).count() > 3);
            }
            // Get Attribute List is a different operation and is unchanged.
            let list = f.call(v, 12, vec![uid(v, &id)]);
            assert!(fields(&list).len() > 3, "{form:?} {v:?}");
        }
    }
}
