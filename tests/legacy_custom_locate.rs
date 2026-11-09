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

//! 1.x Locate by Custom Attribute (`x-` client and `y-` server names).
//!
//! 1.0-1.4 Locate: "All attributes are allowed to be used", "Attribute Index
//! values that are provided SHALL be ignored", and "Returned objects SHALL
//! match all of the attributes in the request" (1.0/1.1 section 4.8,
//! 1.2-1.4 section 4.9).
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::{Store, now},
    tags::*,
    ttlv::Node,
};

const V1: [Version; 5] = [
    Version(1, 0),
    Version(1, 1),
    Version(1, 2),
    Version(1, 3),
    Version(1, 4),
];

struct Fixture {
    _dir: tempfile::TempDir,
    e: Engine,
}
impl Fixture {
    fn new() -> Self {
        let d = tempfile::tempdir().unwrap();
        let master = d.path().join("master");
        std::fs::write(&master, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&d.path().join("store"), &master).unwrap();
        Self {
            _dir: d,
            e: Engine::new(store, true),
        }
    }
    fn call(&mut self, v: Version, op: u32, p: Vec<Node>) -> Node {
        let mut h = vec![v.node()];
        if v.0 < 3 {
            h.push(Node::int(BATCH_COUNT, 1));
        }
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, h),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, p),
                    ],
                ),
            ],
        );
        self.e.process("alice", &request).unwrap()
    }
}
fn status(n: &Node) -> (u32, Option<u32>) {
    let item = n.get(BATCH_ITEM).unwrap();
    (
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        item.get(RESULT_REASON).map(|r| r.number().unwrap()),
    )
}
fn payload(n: &Node) -> &Node {
    assert_eq!(status(n).0, 0, "{}", serde_json::to_string(n).unwrap());
    n.get(BATCH_ITEM)
        .unwrap()
        .required(RESPONSE_PAYLOAD)
        .unwrap()
}
/// A 1.x Attribute structure, with an optional Attribute Index.
fn attribute(name: &str, index: Option<i32>, mut value: Node) -> Node {
    value.tag = ATTRIBUTE_VALUE;
    let mut fields = vec![Node::text(ATTRIBUTE_NAME, name)];
    if let Some(index) = index {
        fields.push(Node::int(ATTRIBUTE_INDEX, index));
    }
    fields.push(value);
    Node::structure(ATTRIBUTE, fields)
}
fn standard(a: Node) -> Node {
    let name = tag_name(a.tag).unwrap();
    attribute(name, None, a)
}
fn create(f: &mut Fixture, v: Version, custom: Vec<Node>) -> String {
    let mut attrs = vec![
        standard(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3)),
        standard(Node::int(CRYPTOGRAPHIC_LENGTH, 256)),
        standard(Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12)),
    ];
    attrs.extend(custom);
    payload(&f.call(
        v,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(TEMPLATE_ATTRIBUTE, attrs),
        ],
    ))
    .required(UNIQUE_IDENTIFIER)
    .unwrap()
    .identifier_text()
    .unwrap()
    .to_owned()
}
fn locate(f: &mut Fixture, v: Version, filters: Vec<Node>) -> Vec<String> {
    let mut ids: Vec<String> = payload(&f.call(v, 8, filters))
        .all(UNIQUE_IDENTIFIER)
        .map(|n| n.identifier_text().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}
fn sorted(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids
}

// REQ:fd6f427dab69705f 1.x Locate: returned objects match all of the attributes in the request, including Custom Attributes
// REQ:7ff3a572895845c2 1.0/1.1 Locate: a provided Attribute Index is ignored
// REQ:ba60de6a6924051c 1.2-1.4 Locate: a provided Attribute Index is ignored
#[test]
fn one_x_locate_matches_custom_attributes_of_every_value_type() {
    for v in V1 {
        let mut f = Fixture::new();
        let when = now() - 120;
        let text = Node::text(ATTRIBUTE_VALUE, format!("team {}.{}", v.0, v.1));
        let integer = Node::int(ATTRIBUTE_VALUE, 42);
        let date = Node::date(ATTRIBUTE_VALUE, when);
        let bytes = Node::bytes(ATTRIBUTE_VALUE, vec![1, 2, 3]);
        let both = create(
            &mut f,
            v,
            vec![
                attribute("x-owner", None, text.clone()),
                attribute("x-rank", None, integer.clone()),
                attribute("x-when", None, date.clone()),
                attribute("x-blob", None, bytes.clone()),
            ],
        );
        let owner_only = create(&mut f, v, vec![attribute("x-owner", None, text.clone())]);
        let other = create(
            &mut f,
            v,
            vec![attribute(
                "x-owner",
                None,
                Node::text(ATTRIBUTE_VALUE, "else"),
            )],
        );
        let plain = create(&mut f, v, vec![]);

        // Each value type is matched by equality.
        assert_eq!(
            locate(&mut f, v, vec![attribute("x-owner", None, text.clone())]),
            sorted(vec![both.clone(), owner_only.clone()])
        );
        for (name, value) in [("x-rank", &integer), ("x-when", &date), ("x-blob", &bytes)] {
            assert_eq!(
                locate(&mut f, v, vec![attribute(name, None, value.clone())]),
                vec![both.clone()],
                "{}.{} {name}",
                v.0,
                v.1
            );
        }
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![attribute(
                    "x-owner",
                    None,
                    Node::text(ATTRIBUTE_VALUE, "else")
                )]
            ),
            vec![other.clone()]
        );
        // A different value or type, or a different name, matches nothing.
        assert!(
            locate(
                &mut f,
                v,
                vec![attribute("x-rank", None, Node::int(ATTRIBUTE_VALUE, 41))]
            )
            .is_empty()
        );
        assert!(
            locate(
                &mut f,
                v,
                vec![attribute("x-rank", None, Node::text(ATTRIBUTE_VALUE, "42"))]
            )
            .is_empty()
        );
        assert!(locate(&mut f, v, vec![attribute("x-absent", None, text.clone())]).is_empty());
        // All filters must match: custom and standard together.
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    attribute("x-owner", None, text.clone()),
                    attribute("x-rank", None, integer.clone()),
                ]
            ),
            vec![both.clone()]
        );
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![
                    attribute("x-owner", None, text.clone()),
                    standard(Node::enumeration(OBJECT_TYPE, 2)),
                ]
            ),
            sorted(vec![both.clone(), owner_only.clone()])
        );
        // A provided Attribute Index is ignored.
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![attribute("x-rank", Some(7), integer.clone())]
            ),
            vec![both.clone()]
        );
        // No client creates y- attributes, and this server sets none, so a
        // y- filter is valid and matches nothing.
        assert!(locate(&mut f, v, vec![attribute("y-owner", None, text.clone())]).is_empty());
        // Without filters, every object matches.
        assert_eq!(
            locate(&mut f, v, vec![]),
            sorted(vec![both, owner_only, other, plain])
        );
        // A custom name with nothing after the prefix is malformed.
        let r = f.call(v, 8, vec![attribute("x-", None, text.clone())]);
        assert_eq!(status(&r), (1, Some(7)));
    }
}

#[test]
fn one_x_locate_finds_vendor_x_attributes_set_through_2x() {
    let mut f = Fixture::new();
    let v2 = Version(2, 1);
    let id = payload(&f.call(
        v2,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 2),
            Node::structure(
                ATTRIBUTES,
                vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                    Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                    Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
                    Node::structure(
                        ATTRIBUTE,
                        vec![
                            Node::text(VENDOR_IDENTIFICATION, "x"),
                            Node::text(ATTRIBUTE_NAME, "site"),
                            Node::text(ATTRIBUTE_VALUE, "north"),
                        ],
                    ),
                ],
            ),
        ],
    ))
    .required(UNIQUE_IDENTIFIER)
    .unwrap()
    .identifier_text()
    .unwrap()
    .to_owned();
    for v in V1 {
        assert_eq!(
            locate(
                &mut f,
                v,
                vec![attribute(
                    "x-site",
                    None,
                    Node::text(ATTRIBUTE_VALUE, "north")
                )]
            ),
            vec![id.clone()]
        );
    }
}
