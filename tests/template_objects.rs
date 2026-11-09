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

//! KMIP 1.x Template managed object (Object Type 6) and template Names in
//! Template-Attribute structures.

use keytend_kmip_server::{
    encoding::Format,
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const V10: Version = Version(1, 0);
const V11: Version = Version(1, 1);
const V14: Version = Version(1, 4);
const V20: Version = Version(2, 0);

struct Fixture {
    dir: tempfile::TempDir,
    engine: Engine,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("master");
        std::fs::write(&key, [42; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
        Self {
            dir,
            engine: Engine::new(store, false),
        }
    }
    fn restart(&mut self) {
        let store = Store::open(
            &self.dir.path().join("keys.sqlite"),
            &self.dir.path().join("master"),
        )
        .unwrap();
        self.engine = Engine::new(store, false);
    }
    fn call(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        self.call_as(v, "alice", op, fields)
    }
    fn call_as(&mut self, v: Version, owner: &str, op: u32, fields: Vec<Node>) -> Node {
        let header = vec![v.node(), Node::int(BATCH_COUNT, 1)];
        let request = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, header),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, fields),
                    ],
                ),
            ],
        );
        let request = Format::Ttlv
            .decode(&Format::Ttlv.encode(&request).unwrap())
            .unwrap();
        self.engine.process(owner, &request).unwrap()
    }
    fn ok(&mut self, v: Version, op: u32, fields: Vec<Node>) -> Node {
        let r = self.call(v, op, fields);
        payload(&r).clone()
    }
    fn register(&mut self, v: Version, name: &str, content: Vec<Node>) -> String {
        let p = self.ok(v, 3, template_request(name, content));
        text(&p, UNIQUE_IDENTIFIER)
    }
    fn attributes(&mut self, v: Version, id: &str) -> Vec<(String, Node)> {
        let p = self.ok(v, 11, vec![Node::text(UNIQUE_IDENTIFIER, id)]);
        p.all(ATTRIBUTE)
            .map(|a| {
                (
                    a.required(ATTRIBUTE_NAME)
                        .unwrap()
                        .string()
                        .unwrap()
                        .to_owned(),
                    a.required(ATTRIBUTE_VALUE).unwrap().clone(),
                )
            })
            .collect()
    }
}

fn attr(name: &str, value: Value) -> Node {
    Node::structure(
        ATTRIBUTE,
        vec![
            Node::text(ATTRIBUTE_NAME, name),
            Node {
                tag: ATTRIBUTE_VALUE,
                value,
            },
        ],
    )
}
fn text_attr(name: &str, value: &str) -> Node {
    attr(name, Value::TextString(value.into()))
}
fn name_value(value: &str) -> Value {
    Value::Structure(vec![
        Node::text(NAME_VALUE, value),
        Node::enumeration(NAME_TYPE, 1),
    ])
}
fn name_attr(value: &str) -> Node {
    attr("Name", name_value(value))
}
/// A template reference inside a Template-Attribute (1.x Table 29).
fn template_name(value: &str) -> Node {
    Node {
        tag: NAME,
        value: name_value(value),
    }
}
fn template_request(name: &str, content: Vec<Node>) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 6),
        Node::structure(TEMPLATE_ATTRIBUTE, vec![name_attr(name)]),
        Node::structure(TEMPLATE, content),
    ]
}
fn aes_create(template_attribute: Vec<Node>) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(TEMPLATE_ATTRIBUTE, template_attribute),
    ]
}
fn item(response: &Node) -> &Node {
    response.required(BATCH_ITEM).unwrap()
}
fn payload(response: &Node) -> &Node {
    let item = item(response);
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "reason {:?}, message {:?}",
        item.get(RESULT_REASON).map(|n| n.number().unwrap()),
        item.get(RESULT_MESSAGE).and_then(|n| n.string().ok())
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(response: &Node) -> u32 {
    let item = item(response);
    assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
    item.required(RESULT_REASON).unwrap().number().unwrap()
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag).unwrap().string().unwrap().to_owned()
}
fn values<'a>(attrs: &'a [(String, Node)], name: &str) -> Vec<&'a Node> {
    attrs
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v)
        .collect()
}
fn texts(attrs: &[(String, Node)], name: &str) -> Vec<String> {
    values(attrs, name)
        .into_iter()
        .map(|v| v.string().unwrap().to_owned())
        .collect()
}

#[test]
fn register_get_and_attributes_of_a_template() {
    let mut f = Fixture::new();
    for v in [V14, V10] {
        let name = format!("template-{}.{}", v.0, v.1);
        let content = vec![
            text_attr("Object Group", "group"),
            attr("Cryptographic Algorithm", Value::Enumeration(3)),
            attr("Cryptographic Length", Value::Integer(128)),
            text_attr("x-purpose", "demonstration"),
        ];
        let id = f.register(v, &name, content.clone());
        let attrs = f.attributes(v, &id);
        let mut names = attrs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>();
        names.sort_unstable();
        // 1.0 2.2.6: Unique Identifier, Object Type, Name, Initial Date,
        // Archive Date and Last Change Date apply to the Template itself.
        assert_eq!(
            names,
            [
                "Initial Date",
                "Last Change Date",
                "Name",
                "Object Type",
                "Unique Identifier"
            ]
        );
        assert_eq!(values(&attrs, "Object Type")[0].number().unwrap(), 6);
        let got = f.ok(v, 10, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
        assert_eq!(got.required(OBJECT_TYPE).unwrap().number().unwrap(), 6);
        assert_eq!(text(&got, UNIQUE_IDENTIFIER), id);
        assert!(got.required(TEMPLATE).unwrap().children().unwrap() == content);
        let located = f.ok(
            v,
            8,
            vec![name_attr(&name), attr("Object Type", Value::Enumeration(6))],
        );
        assert_eq!(located.all(UNIQUE_IDENTIFIER).count(), 1);
        // The content applies to created objects, not the Template itself.
        let by_group = f.ok(v, 8, vec![text_attr("Object Group", "group")]);
        assert_eq!(by_group.all(UNIQUE_IDENTIFIER).count(), 0);
    }
}

#[test]
fn template_attributes_follow_the_precedence_rules() {
    let mut f = Fixture::new();
    f.register(
        V14,
        "first",
        vec![
            attr("Cryptographic Algorithm", Value::Enumeration(3)),
            attr("Cryptographic Length", Value::Integer(128)),
            text_attr("Contact Information", "first"),
            text_attr("Object Group", "g1"),
            text_attr("x-ID", "from-first"),
        ],
    );
    f.register(
        V14,
        "second",
        vec![
            text_attr("Contact Information", "second"),
            text_attr("Object Group", "g2"),
            attr("Cryptographic Usage Mask", Value::Integer(12)),
        ],
    );
    let created = f.ok(
        V14,
        1,
        aes_create(vec![
            template_name("first"),
            template_name("second"),
            attr("Cryptographic Length", Value::Integer(256)),
            text_attr("x-ID", "from-request"),
            name_attr("key"),
        ]),
    );
    let id = text(&created, UNIQUE_IDENTIFIER);
    let attrs = f.attributes(V14, &id);
    // The request overrides a template; the last template overrides earlier
    // ones; multi-instance values form a union (1.4 section 4).
    assert!(values(&attrs, "Cryptographic Length")[0] == &Node::int(ATTRIBUTE_VALUE, 256));
    assert_eq!(texts(&attrs, "Contact Information"), ["second"]);
    assert!(values(&attrs, "Cryptographic Usage Mask")[0] == &Node::int(ATTRIBUTE_VALUE, 12));
    let mut groups = texts(&attrs, "Object Group");
    groups.sort_unstable();
    assert_eq!(groups, ["g1", "g2"]);
    assert_eq!(texts(&attrs, "x-ID"), ["from-first", "from-request"]);
    // The templates' own Names are not inherited.
    assert_eq!(values(&attrs, "Name").len(), 1);

    // The same rules apply to Register.
    let registered = f.ok(
        V14,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 7),
            Node::structure(
                TEMPLATE_ATTRIBUTE,
                vec![
                    template_name("second"),
                    attr("Cryptographic Usage Mask", Value::Integer(0)),
                ],
            ),
            Node::structure(
                SECRET_DATA,
                vec![
                    Node::enumeration(SECRET_DATA_TYPE, 1),
                    Node::structure(
                        KEY_BLOCK,
                        vec![
                            Node::enumeration(KEY_FORMAT_TYPE, 2),
                            Node::structure(
                                KEY_VALUE,
                                vec![Node::bytes(KEY_MATERIAL, vec![42; 16])],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    );
    let attrs = f.attributes(V14, &text(&registered, UNIQUE_IDENTIFIER));
    assert_eq!(texts(&attrs, "Object Group"), ["g2"]);
    assert!(values(&attrs, "Cryptographic Usage Mask")[0] == &Node::int(ATTRIBUTE_VALUE, 0));
}

#[test]
fn key_pair_templates_follow_the_four_step_order() {
    let mut f = Fixture::new();
    f.register(
        V14,
        "rsa",
        vec![
            attr("Cryptographic Algorithm", Value::Enumeration(4)),
            attr("Cryptographic Length", Value::Integer(2048)),
            text_attr("Contact Information", "common-template"),
        ],
    );
    f.register(
        V14,
        "public",
        vec![text_attr("Contact Information", "public-template")],
    );
    let created = f.ok(
        V14,
        2,
        vec![
            Node::structure(
                COMMON_TEMPLATE_ATTRIBUTE,
                vec![template_name("rsa"), text_attr("Object Group", "pair")],
            ),
            Node::structure(
                PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                vec![
                    attr("Cryptographic Usage Mask", Value::Integer(1)),
                    text_attr("Contact Information", "private-explicit"),
                ],
            ),
            Node::structure(
                PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                vec![
                    template_name("public"),
                    attr("Cryptographic Usage Mask", Value::Integer(2)),
                ],
            ),
        ],
    );
    let private = f.attributes(V14, &text(&created, PRIVATE_KEY_UNIQUE_IDENTIFIER));
    let public = f.attributes(V14, &text(&created, PUBLIC_KEY_UNIQUE_IDENTIFIER));
    assert_eq!(texts(&private, "Contact Information"), ["private-explicit"]);
    assert_eq!(texts(&public, "Contact Information"), ["public-template"]);
    for attrs in [&private, &public] {
        assert_eq!(texts(attrs, "Object Group"), ["pair"]);
        assert!(values(attrs, "Cryptographic Length")[0] == &Node::int(ATTRIBUTE_VALUE, 2048));
    }
}

#[test]
fn template_references_must_resolve_to_the_callers_templates() {
    let mut f = Fixture::new();
    // 1.4 Table 328: templates that do not exist yield Item Not Found.
    let r = f.call(V14, 1, aes_create(vec![template_name("missing")]));
    assert_eq!(reason(&r), 1);
    f.register(V14, "alice", vec![text_attr("Object Group", "g")]);
    // Private templates are usable by their owner only (1.4 Table 94).
    let r = f.call_as(V14, "bob", 1, aes_create(vec![template_name("alice")]));
    assert_eq!(reason(&r), 1);
    // A Name of another object type is not a template.
    f.ok(V14, 1, aes_create(vec![name_attr("key")]));
    let r = f.call(V14, 1, aes_create(vec![template_name("key")]));
    assert_eq!(reason(&r), 1);
    // An archived template yields Object Archived.
    let located = f.ok(V14, 8, vec![name_attr("alice")]);
    let id = text(&located, UNIQUE_IDENTIFIER);
    f.ok(V14, 21, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
    let r = f.call(V14, 1, aes_create(vec![template_name("alice")]));
    assert_eq!(reason(&r), 13);
    f.ok(V14, 22, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
    f.ok(V14, 1, aes_create(vec![template_name("alice")]));
}

#[test]
fn template_registration_is_validated() {
    let mut f = Fixture::new();
    // 1.2-1.4 Register errors: a Name inside the Template structure.
    let r = f.call(V14, 3, template_request("t", vec![name_attr("inner")]));
    assert_eq!(reason(&r), 7);
    // Table 50 requires at least one Attribute.
    let r = f.call(V14, 3, template_request("t", vec![]));
    assert_eq!(reason(&r), 7);
    // 2.2.6: a Template is a named Managed Object.
    let r = f.call(
        V14,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 6),
            Node::structure(TEMPLATE, vec![text_attr("Object Group", "g")]),
        ],
    );
    assert_eq!(reason(&r), 7);
    // Attributes of created objects belong in the Template structure.
    let mut request = template_request("t", vec![text_attr("Object Group", "g")]);
    request[1] = Node::structure(
        TEMPLATE_ATTRIBUTE,
        vec![
            name_attr("t"),
            attr("Cryptographic Algorithm", Value::Enumeration(3)),
        ],
    );
    let r = f.call(V14, 3, request);
    assert_eq!(reason(&r), 7);
    // Server-set attributes are not client-settable template content.
    let r = f.call(
        V14,
        3,
        template_request("t", vec![attr("State", Value::Enumeration(1))]),
    );
    assert_ne!(reason(&r), 0);
    // Names stay unique across all objects.
    f.register(V14, "t", vec![text_attr("Object Group", "g")]);
    let r = f.call(
        V14,
        3,
        template_request("t", vec![text_attr("Object Group", "g")]),
    );
    assert_eq!(reason(&r), 7);
    // Create is not used for Templates (1.4 section 4.1).
    let r = f.call(
        V14,
        1,
        vec![
            Node::enumeration(OBJECT_TYPE, 6),
            Node::structure(TEMPLATE_ATTRIBUTE, vec![name_attr("c")]),
        ],
    );
    assert_ne!(reason(&r), 0);
}

#[test]
fn legacy_template_content_rules() {
    let mut f = Fixture::new();
    // 1.0/1.1 2.2.6: a Name in the Template applies to the Template itself.
    let r = f.ok(
        V10,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 6),
            Node::structure(TEMPLATE_ATTRIBUTE, vec![]),
            Node::structure(
                TEMPLATE,
                vec![name_attr("legacy"), text_attr("Object Group", "g")],
            ),
        ],
    );
    let id = text(&r, UNIQUE_IDENTIFIER);
    assert_eq!(
        texts(&f.attributes(V10, &id), "Object Group"),
        Vec::<String>::new()
    );
    let key = f.ok(V10, 1, aes_create(vec![template_name("legacy")]));
    let attrs = f.attributes(V10, &text(&key, UNIQUE_IDENTIFIER));
    assert_eq!(texts(&attrs, "Object Group"), ["g"]);
    assert!(values(&attrs, "Name").is_empty());
    // Only the 1.0 list of attributes may be template content.
    let r = f.call(
        V10,
        3,
        template_request(
            "t",
            vec![attr("Digital Signature Algorithm", Value::Enumeration(5))],
        ),
    );
    assert_eq!(reason(&r), 7);
    // 1.0/1.1: only Name is client-settable on the Template itself.
    let r = f.call(
        V11,
        13,
        vec![Node::text(UNIQUE_IDENTIFIER, &id), text_attr("x-note", "n")],
    );
    assert_eq!(reason(&r), 7);
    f.ok(
        V14,
        13,
        vec![Node::text(UNIQUE_IDENTIFIER, &id), text_attr("x-note", "n")],
    );
    assert_eq!(texts(&f.attributes(V14, &id), "x-note"), ["n"]);
    let r = f.call(
        V14,
        13,
        vec![
            Node::text(UNIQUE_IDENTIFIER, &id),
            attr("Cryptographic Usage Mask", Value::Integer(4)),
        ],
    );
    assert_eq!(reason(&r), 7);
}

#[test]
fn operations_that_do_not_apply_to_templates_are_rejected() {
    let mut f = Fixture::new();
    let id = f.register(V14, "t", vec![text_attr("Object Group", "g")]);
    let uid = || Node::text(UNIQUE_IDENTIFIER, &id);
    // Activate/Revoke SHALL NOT specify a Template: Illegal Operation.
    let r = f.call(V14, 18, vec![uid()]);
    assert_eq!(reason(&r), 11);
    let r = f.call(
        V14,
        19,
        vec![
            uid(),
            Node::structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
            ),
        ],
    );
    assert_eq!(reason(&r), 11);
    for op in [4, 9, 16, 17] {
        let mut fields = vec![uid()];
        if op == 17 {
            fields.push(Node::long(USAGE_LIMITS_COUNT, 1));
        }
        let r = f.call(V14, op, fields);
        assert_eq!(reason(&r), 11, "operation {op}");
    }
    // A Template has no Key Block.
    let r = f.call(V14, 10, vec![uid(), Node::enumeration(KEY_FORMAT_TYPE, 1)]);
    assert_eq!(reason(&r), 0x10);
}

#[test]
fn destroying_a_template_removes_it() {
    let mut f = Fixture::new();
    let id = f.register(V14, "t", vec![text_attr("Object Group", "g")]);
    f.ok(V14, 20, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
    for op in [10, 11, 20] {
        let r = f.call(V14, op, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
        assert_eq!(reason(&r), 1, "operation {op}");
    }
    let located = f.ok(V14, 8, vec![attr("Object Type", Value::Enumeration(6))]);
    assert_eq!(located.all(UNIQUE_IDENTIFIER).count(), 0);
    let r = f.call(V14, 1, aes_create(vec![template_name("t")]));
    assert_eq!(reason(&r), 1);
    // All of its meta-data is gone, including the Name.
    f.register(V14, "t", vec![text_attr("Object Group", "g")]);
}

#[test]
fn templates_exist_only_in_kmip_1() {
    let mut f = Fixture::new();
    for v in [V10, V14] {
        let p = f.ok(v, 24, vec![Node::enumeration(QUERY_FUNCTION, 2)]);
        assert!(p.all(OBJECT_TYPE).any(|n| n.number().unwrap() == 6));
    }
    for v in [V20, Version(2, 1)] {
        let p = f.ok(v, 24, vec![Node::enumeration(QUERY_FUNCTION, 2)]);
        assert!(p.all(OBJECT_TYPE).all(|n| n.number().unwrap() != 6));
    }
    let id = f.register(V14, "t", vec![text_attr("Object Group", "g")]);
    // 2.0 Table 430: value 6 is Reserved.
    let r = f.call(
        V20,
        3,
        vec![
            Node::enumeration(OBJECT_TYPE, 6),
            Node::structure(ATTRIBUTES, vec![]),
        ],
    );
    assert_ne!(reason(&r), 0);
    // Stored 1.x Templates are not objects of later versions: 2.0 Table 210
    // Get Attributes answers Object Not Found.
    let r = f.call(V20, 11, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
    assert_eq!(reason(&r), 0x37);
    let located = f.ok(V20, 8, vec![]);
    assert_eq!(located.all(UNIQUE_IDENTIFIER).count(), 0);
}

#[test]
fn templates_persist_across_restarts() {
    let mut f = Fixture::new();
    let id = f.register(V14, "t", vec![text_attr("Object Group", "g")]);
    f.restart();
    let got = f.ok(V14, 10, vec![Node::text(UNIQUE_IDENTIFIER, &id)]);
    assert!(
        got.required(TEMPLATE).unwrap().children().unwrap() == [text_attr("Object Group", "g")]
    );
    let key = f.ok(V14, 1, aes_create(vec![template_name("t")]));
    let attrs = f.attributes(V14, &text(&key, UNIQUE_IDENTIFIER));
    assert_eq!(texts(&attrs, "Object Group"), ["g"]);
}
