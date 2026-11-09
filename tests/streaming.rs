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

use keytend_kmip_server::{
    crypto,
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
struct Fixture {
    dir: tempfile::TempDir,
    e: Engine,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("master");
        std::fs::write(&master, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&dir.path().join("store.sqlite"), &master).unwrap();
        Self {
            dir,
            e: Engine::new(store, true),
        }
    }
}
fn uid(v: Version, id: &str) -> Node {
    if v.0 >= 3 {
        Node::identifier(UNIQUE_IDENTIFIER, id)
    } else {
        Node::text(UNIQUE_IDENTIFIER, id)
    }
}
fn request(v: Version, items: Vec<(u32, Vec<Node>)>, extra: Vec<Node>) -> Node {
    let mut header = vec![v.node()];
    if v.0 < 3 {
        header.push(Node::int(BATCH_COUNT, items.len() as i32));
    }
    header.extend(extra);
    let mut fields = vec![Node::structure(REQUEST_HEADER, header)];
    fields.extend(items.into_iter().enumerate().map(|(i, (op, p))| {
        let mut fields = vec![Node::enumeration(OPERATION, op)];
        if v.0 < 3 {
            fields.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![i as u8]));
        }
        fields.push(Node::structure(REQUEST_PAYLOAD, p));
        Node::structure(BATCH_ITEM, fields)
    }));
    Node::structure(REQUEST_MESSAGE, fields)
}
fn call(e: &mut Engine, owner: &str, v: Version, op: u32, p: Vec<Node>) -> Node {
    e.process(owner, &request(v, vec![(op, p)], vec![]))
        .unwrap()
}
fn item(n: &Node) -> &Node {
    n.get(BATCH_ITEM).unwrap()
}
fn body(n: &Node) -> &Node {
    assert_eq!(
        item(n).required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(n).unwrap()
    );
    item(n).required(RESPONSE_PAYLOAD).unwrap()
}
fn reason(n: &Node) -> u32 {
    item(n).required(RESULT_REASON).unwrap().number().unwrap()
}
fn blob(n: &Node, tag: u32) -> Vec<u8> {
    n.get(tag)
        .map(|n| n.byte_string().unwrap().to_vec())
        .unwrap_or_default()
}
fn attrs(v: Version, values: Vec<Node>) -> Node {
    if v.0 >= 2 {
        Node::structure(ATTRIBUTES, values)
    } else {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            values
                .into_iter()
                .map(|mut n| {
                    let name = match n.tag {
                        CRYPTOGRAPHIC_USAGE_MASK => "Cryptographic Usage Mask",
                        CRYPTOGRAPHIC_ALGORITHM => "Cryptographic Algorithm",
                        CRYPTOGRAPHIC_LENGTH => "Cryptographic Length",
                        USAGE_LIMITS => "Usage Limits",
                        _ => panic!("attribute"),
                    };
                    n.tag = ATTRIBUTE_VALUE;
                    Node::structure(ATTRIBUTE, vec![Node::text(ATTRIBUTE_NAME, name), n])
                })
                .collect(),
        )
    }
}
fn key(
    e: &mut Engine,
    owner: &str,
    v: Version,
    algorithm: u32,
    usage: u32,
    limits: Option<(i64, u32)>,
) -> String {
    let mut a = vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, usage as i32)];
    if let Some((total, unit)) = limits {
        a.push(Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, total),
                Node::enumeration(USAGE_LIMITS_UNIT, unit),
            ],
        ));
    }
    let object = Node::structure(
        SYMMETRIC_KEY,
        vec![Node::structure(
            KEY_BLOCK,
            vec![
                Node::enumeration(KEY_FORMAT_TYPE, 1),
                Node::structure(KEY_VALUE, vec![Node::bytes(KEY_MATERIAL, vec![7; 32])]),
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
            ],
        )],
    );
    let r = call(
        e,
        owner,
        v,
        3,
        vec![Node::enumeration(OBJECT_TYPE, 2), attrs(v, a), object],
    );
    let id = body(&r)
        .required(UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    body(&call(e, owner, v, 18, vec![uid(v, &id)]));
    id
}
fn cp(mode: u32, pad: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, mode),
            Node::enumeration(PADDING_METHOD, pad),
        ],
    )
}
#[allow(clippy::too_many_arguments)]
fn part(
    v: Version,
    id: Option<&str>,
    parameters: Option<Node>,
    data: Option<&[u8]>,
    initial: bool,
    last: bool,
    token: Option<&[u8]>,
    extra: Vec<Node>,
) -> Vec<Node> {
    let mut p = vec![
        Node::boolean(INIT_INDICATOR, initial),
        Node::boolean(FINAL_INDICATOR, last),
    ];
    if let Some(id) = id {
        p.push(uid(v, id));
    }
    if let Some(cp) = parameters {
        p.push(cp);
    }
    if let Some(data) = data {
        p.push(Node::bytes(DATA, data.to_vec()));
    }
    if let Some(token) = token {
        p.push(Node::bytes(CORRELATION_VALUE, token.to_vec()));
    }
    p.extend(extra);
    p
}
fn left(e: &Engine, owner: &str, id: &str) -> i64 {
    let object = e.store.get(owner, id).unwrap().unwrap();
    let limit = object.attrs.iter().find(|a| a.tag == USAGE_LIMITS).unwrap();
    match limit.required(USAGE_LIMITS_COUNT).unwrap().value {
        Value::LongInteger(n) => n,
        _ => panic!("count"),
    }
}

#[test]
fn versioned_aes_multipart_matches_all_modes_and_keeps_gcm_plaintext_private() {
    for v in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let id = key(&mut f.e, "alice", v, 3, 12, None);
        for mode in [1, 2, 4, 5, 6, 9] {
            if mode == 9 && v < Version(1, 4) {
                continue;
            }
            let pad = if [1, 2].contains(&mode) { 3 } else { 1 };
            let parameters = cp(mode, pad);
            let iv = if mode == 2 {
                vec![]
            } else if mode == 9 {
                vec![3; 12]
            } else {
                vec![3; 16]
            };
            let message = (0..257).map(|i| i as u8).collect::<Vec<_>>();
            let mut cipher = vec![];
            let mut token = vec![];
            let mut auth = vec![];
            for (i, chunk) in message.chunks(13).enumerate() {
                let extra = if i == 0 && mode != 2 {
                    vec![Node::bytes(IV_COUNTER_NONCE, iv.clone())]
                } else {
                    vec![]
                };
                let p = part(
                    v,
                    Some(&id),
                    Some(parameters.clone()),
                    Some(chunk),
                    i == 0,
                    false,
                    if i == 0 { None } else { Some(&token) },
                    extra,
                );
                let response = call(&mut f.e, "alice", v, 31, p);
                let payload = body(&response);
                cipher.extend(blob(payload, DATA));
                let next = blob(payload, CORRELATION_VALUE);
                assert_eq!(next.len(), 32);
                if i > 0 {
                    assert_eq!(next, token);
                }
                token = next;
                assert!(payload.get(AUTHENTICATED_ENCRYPTION_TAG).is_none());
            }
            let response = call(
                &mut f.e,
                "alice",
                v,
                31,
                part(v, Some(&id), None, None, false, true, Some(&token), vec![]),
            );
            cipher.extend(blob(body(&response), DATA));
            auth.extend(blob(body(&response), AUTHENTICATED_ENCRYPTION_TAG));
            assert!(body(&response).get(CORRELATION_VALUE).is_none());
            let (expected, tag) = crypto::aes(
                true,
                &[7; 32],
                crypto::AesParameters {
                    mode,
                    padding: pad,
                    tag_len: 16,
                },
                &iv,
                &message,
                &[],
                None,
            )
            .unwrap();
            assert_eq!(cipher, expected.as_slice());
            assert_eq!(auth, tag);
            let replay = call(
                &mut f.e,
                "alice",
                v,
                31,
                part(v, Some(&id), None, None, false, true, Some(&token), vec![]),
            );
            // 1.3/1.4 Encrypt table (1.4 Table 353): no outstanding operation
            // with the Correlation Value is Item Not Found.
            assert_eq!(reason(&replay), if v.0 >= 2 { 0x2e } else { 1 });
            let mut plain = vec![];
            token.clear();
            for (i, chunk) in cipher.chunks(11).enumerate() {
                let mut extra = vec![];
                if i == 0 && mode != 2 {
                    extra.push(Node::bytes(IV_COUNTER_NONCE, iv.clone()));
                }
                if i == 0 && mode == 9 {
                    extra.push(Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, auth.clone()));
                }
                let response = call(
                    &mut f.e,
                    "alice",
                    v,
                    32,
                    part(
                        v,
                        Some(&id),
                        Some(parameters.clone()),
                        Some(chunk),
                        i == 0,
                        false,
                        if i == 0 { None } else { Some(&token) },
                        extra,
                    ),
                );
                let payload = body(&response);
                let data = blob(payload, DATA);
                if mode == 9 {
                    assert!(data.is_empty());
                }
                plain.extend(data);
                token = blob(payload, CORRELATION_VALUE);
            }
            let response = call(
                &mut f.e,
                "alice",
                v,
                32,
                part(v, Some(&id), None, None, false, true, Some(&token), vec![]),
            );
            plain.extend(blob(body(&response), DATA));
            assert_eq!(plain, message);
        }
        f.e.store.verify_audit().unwrap();
    }
}
#[test]
fn stream_object_budgets_charge_once_and_failed_byte_chunks_do_not_advance() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, Some((1, 2)));
    let start = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"abc"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    let token = blob(body(&start), CORRELATION_VALUE);
    assert_eq!(left(&f.e, "alice", &id), 0);
    let next = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            None,
            Some(b"def"),
            false,
            false,
            Some(&token),
            vec![],
        ),
    );
    body(&next);
    assert_eq!(left(&f.e, "alice", &id), 0);
    body(&call(
        &mut f.e,
        "alice",
        v,
        31,
        part(v, Some(&id), None, None, false, true, Some(&token), vec![]),
    ));
    let exhausted = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"abc"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    assert_eq!(reason(&exhausted), 12);
    let id = key(&mut f.e, "alice", v, 3, 12, Some((9, 1)));
    let start = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"abcd"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    let token = blob(body(&start), CORRELATION_VALUE);
    let mut ciphertext = blob(body(&start), DATA);
    assert_eq!(left(&f.e, "alice", &id), 5);
    let rejected = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            None,
            Some(b"badbad"),
            false,
            false,
            Some(&token),
            vec![],
        ),
    );
    assert_eq!(reason(&rejected), 12);
    assert_eq!(left(&f.e, "alice", &id), 5);
    let final_response = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            None,
            Some(b"efghi"),
            false,
            true,
            Some(&token),
            vec![],
        ),
    );
    ciphertext.extend(blob(body(&final_response), DATA));
    assert_eq!(left(&f.e, "alice", &id), 0);
    assert_eq!(
        ciphertext,
        crypto::aes(
            true,
            &[7; 32],
            crypto::AesParameters {
                mode: 6,
                padding: 1,
                tag_len: 16
            },
            &[0; 16],
            b"abcdefghi",
            &[],
            None
        )
        .unwrap()
        .0
        .as_slice()
    );
}
#[test]
fn contexts_bind_owner_version_operation_key_and_parameters_and_destroy_invalidates() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, None);
    let other = key(&mut f.e, "alice", v, 3, 12, None);
    let start = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(1, 3)),
            Some(b"start"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![1; 16])],
        ),
    );
    let token = blob(body(&start), CORRELATION_VALUE);
    for (owner, version, operation, key_id) in [
        ("bob", v, 31, id.as_str()),
        ("alice", Version(2, 0), 31, id.as_str()),
        ("alice", v, 32, id.as_str()),
        ("alice", v, 31, other.as_str()),
    ] {
        let failed = call(
            &mut f.e,
            owner,
            version,
            operation,
            part(
                version,
                Some(key_id),
                None,
                None,
                false,
                true,
                Some(&token),
                vec![],
            ),
        );
        assert_eq!(reason(&failed), 0x2e);
    }
    let changed = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"x"),
            false,
            false,
            Some(&token),
            vec![],
        ),
    );
    assert_eq!(reason(&changed), 7);
    let missing = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(v, Some(&id), None, None, false, false, Some(&token), vec![]),
    );
    assert_eq!(reason(&missing), if v.0 >= 2 { 7 } else { 6 });
    body(&call(
        &mut f.e,
        "alice",
        v,
        19,
        vec![
            uid(v, &id),
            Node::structure(
                REVOCATION_REASON,
                vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
            ),
        ],
    ));
    assert_eq!(
        reason(&call(
            &mut f.e,
            "alice",
            v,
            31,
            part(v, Some(&id), None, None, false, true, Some(&token), vec![])
        )),
        0x43
    );
    body(&call(&mut f.e, "alice", v, 20, vec![uid(v, &id)]));
    assert_eq!(
        reason(&call(
            &mut f.e,
            "alice",
            v,
            31,
            part(v, Some(&id), None, None, false, true, Some(&token), vec![])
        )),
        0x2e
    );
}
#[test]
fn stream_snapshots_follow_outer_response_rollback_and_hash_undo() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, Some((1, 2)));
    let fields = part(
        v,
        Some(&id),
        Some(cp(6, 1)),
        Some(&[1; 512]),
        true,
        false,
        None,
        vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
    );
    let failed =
        f.e.process(
            "alice",
            &request(
                v,
                vec![(31, fields)],
                vec![Node::int(MAXIMUM_RESPONSE_SIZE, 400)],
            ),
        )
        .unwrap();
    assert_eq!(reason(&failed), 2);
    assert_eq!(left(&f.e, "alice", &id), 1);
    let start = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"x"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    body(&start);
    assert_eq!(left(&f.e, "alice", &id), 0);
    let hash = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
    );
    let start = call(
        &mut f.e,
        "alice",
        v,
        39,
        part(
            v,
            None,
            Some(hash.clone()),
            Some(b"original"),
            true,
            false,
            None,
            vec![],
        ),
    );
    let token = blob(body(&start), CORRELATION_VALUE);
    let batch = request(
        v,
        vec![
            (
                39,
                part(
                    v,
                    None,
                    None,
                    Some(b"rolled back"),
                    false,
                    false,
                    Some(&token),
                    vec![],
                ),
            ),
            (0xffff, vec![]),
        ],
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
    );
    let response = f.e.process("alice", &batch).unwrap();
    assert_eq!(
        item(&response)
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    let final_response = call(
        &mut f.e,
        "alice",
        v,
        39,
        part(
            v,
            None,
            None,
            Some(b" final"),
            false,
            true,
            Some(&token),
            vec![],
        ),
    );
    assert_eq!(
        blob(body(&final_response), DATA),
        crypto::hash_data(6, b"original final").unwrap()
    );
    let batch = request(
        v,
        vec![
            (
                39,
                part(v, None, Some(hash), None, true, false, None, vec![]),
            ),
            (0xffff, vec![]),
        ],
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
    );
    let response = f.e.process("alice", &batch).unwrap();
    let payload = item(&response).required(RESPONSE_PAYLOAD).unwrap();
    let token = blob(payload, CORRELATION_VALUE);
    assert_eq!(
        reason(&call(
            &mut f.e,
            "alice",
            v,
            39,
            part(v, None, None, None, false, true, Some(&token), vec![])
        )),
        0x2e
    );
    f.e.store.verify_audit().unwrap();
    assert!(f.dir.path().join("store.sqlite").is_file());
}
#[test]
fn multipart_mac_verify_is_final_only_and_owner_capacity_is_bounded() {
    let mut f = Fixture::new();
    let v = Version(1, 3);
    let id = key(&mut f.e, "alice", v, 9, 0x180, None);
    for operation in [35, 36] {
        let expected = crypto::mac(6, &[7; 32], b"firstsecond").unwrap();
        let start = call(
            &mut f.e,
            "alice",
            v,
            operation,
            part(
                v,
                Some(&id),
                None,
                Some(b"first"),
                true,
                false,
                None,
                vec![],
            ),
        );
        let token = blob(body(&start), CORRELATION_VALUE);
        assert!(body(&start).get(VALIDITY_INDICATOR).is_none());
        assert!(body(&start).get(MAC_DATA).is_none());
        let result = call(
            &mut f.e,
            "alice",
            v,
            operation,
            part(
                v,
                Some(&id),
                None,
                Some(b"second"),
                false,
                true,
                Some(&token),
                if operation == 36 {
                    vec![Node::bytes(MAC_DATA, expected.clone())]
                } else {
                    vec![]
                },
            ),
        );
        if operation == 35 {
            assert_eq!(blob(body(&result), MAC_DATA), expected);
        } else {
            assert_eq!(
                body(&result)
                    .required(VALIDITY_INDICATOR)
                    .unwrap()
                    .number()
                    .unwrap(),
                1
            );
        }
    }
    let v = Version(2, 1);
    let hash = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
    );
    let mut tokens = vec![];
    for _ in 0..16 {
        let r = call(
            &mut f.e,
            "alice",
            v,
            39,
            part(v, None, Some(hash.clone()), None, true, false, None, vec![]),
        );
        tokens.push(blob(body(&r), CORRELATION_VALUE));
    }
    assert_eq!(
        reason(&call(
            &mut f.e,
            "alice",
            v,
            39,
            part(v, None, Some(hash.clone()), None, true, false, None, vec![])
        )),
        2
    );
    body(&call(
        &mut f.e,
        "bob",
        v,
        39,
        part(v, None, Some(hash.clone()), None, true, false, None, vec![]),
    ));
    body(&call(
        &mut f.e,
        "alice",
        v,
        39,
        part(v, None, None, None, false, true, Some(&tokens[0]), vec![]),
    ));
    body(&call(
        &mut f.e,
        "alice",
        v,
        39,
        part(v, None, Some(hash), None, true, false, None, vec![]),
    ));
}

fn pair(e: &mut Engine, v: Version, algorithm: u32) -> (String, String) {
    pair_roles(e, v, algorithm, 1, 2)
}
fn pair_roles(
    e: &mut Engine,
    v: Version,
    algorithm: u32,
    private_mask: u32,
    public_mask: u32,
) -> (String, String) {
    pair_budget(e, v, algorithm, private_mask, public_mask, (1, 2))
}
fn pair_budget(
    e: &mut Engine,
    v: Version,
    algorithm: u32,
    private_mask: u32,
    public_mask: u32,
    limit: (i64, u32),
) -> (String, String) {
    let mut common = attrs(
        v,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
            Node::int(
                CRYPTOGRAPHIC_LENGTH,
                if algorithm == 4 { 2048 } else { 256 },
            ),
        ],
    );
    common.tag = if v.0 == 1 {
        COMMON_TEMPLATE_ATTRIBUTE
    } else {
        COMMON_ATTRIBUTES
    };
    let mut private = attrs(
        v,
        vec![
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, private_mask as i32),
            Node::structure(
                USAGE_LIMITS,
                vec![
                    Node::long(USAGE_LIMITS_TOTAL, limit.0),
                    Node::enumeration(USAGE_LIMITS_UNIT, limit.1),
                ],
            ),
        ],
    );
    private.tag = if v.0 == 1 {
        PRIVATE_KEY_TEMPLATE_ATTRIBUTE
    } else {
        PRIVATE_KEY_ATTRIBUTES
    };
    let mut public = attrs(
        v,
        vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, public_mask as i32)],
    );
    public.tag = if v.0 == 1 {
        PUBLIC_KEY_TEMPLATE_ATTRIBUTE
    } else {
        PUBLIC_KEY_ATTRIBUTES
    };
    let response = call(e, "alice", v, 2, vec![common, private, public]);
    let p = body(&response);
    let private = p
        .required(PRIVATE_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    let public = p
        .required(PUBLIC_KEY_UNIQUE_IDENTIFIER)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned();
    for id in [&private, &public] {
        body(&call(e, "alice", v, 18, vec![uid(v, id)]));
    }
    (private, public)
}
#[test]
fn rsa_and_ec_stream_signatures_hash_once_and_verify_only_on_final_part() {
    for v in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        for algorithm in [4, 6] {
            let mut f = Fixture::new();
            let (private, public) = pair(&mut f.e, v, algorithm);
            let mut params = vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                Node::enumeration(HASHING_ALGORITHM, 6),
            ];
            if algorithm == 4 {
                params.push(Node::enumeration(PADDING_METHOD, 8));
            }
            let params = Node::structure(CRYPTOGRAPHIC_PARAMETERS, params);
            let message = b"multipart signature with an independently selected final hash";
            let mut token = vec![];
            for (i, chunk) in message.chunks(9).enumerate() {
                let r = call(
                    &mut f.e,
                    "alice",
                    v,
                    33,
                    part(
                        v,
                        Some(&private),
                        if i == 0 { Some(params.clone()) } else { None },
                        Some(chunk),
                        i == 0,
                        false,
                        if i == 0 { None } else { Some(&token) },
                        vec![],
                    ),
                );
                assert!(body(&r).get(SIGNATURE_DATA).is_none());
                token = blob(body(&r), CORRELATION_VALUE);
            }
            let final_response = call(
                &mut f.e,
                "alice",
                v,
                33,
                part(
                    v,
                    Some(&private),
                    None,
                    None,
                    false,
                    true,
                    Some(&token),
                    vec![],
                ),
            );
            let signature = blob(body(&final_response), SIGNATURE_DATA);
            assert!(!signature.is_empty());
            assert_eq!(left(&f.e, "alice", &private), 0);
            let public_bytes =
                f.e.store
                    .get("alice", &public)
                    .unwrap()
                    .unwrap()
                    .material
                    .clone();
            assert!(if algorithm == 4 {
                crypto::rsa::verify(
                    &public_bytes,
                    crypto::rsa::SignatureParameters {
                        hash: 6,
                        pss: false,
                        mgf_hash: 4,
                        salt_len: 64,
                    },
                    message,
                    false,
                    &signature,
                )
                .unwrap()
            } else {
                crypto::ec::verify(&public_bytes, 6, message, false, &signature).unwrap()
            });
            for invalid in [false, true] {
                let mut value = signature.clone();
                if invalid {
                    value[0] ^= 1;
                }
                let first = call(
                    &mut f.e,
                    "alice",
                    v,
                    34,
                    part(
                        v,
                        Some(&public),
                        Some(params.clone()),
                        Some(&message[..7]),
                        true,
                        false,
                        None,
                        vec![Node::bytes(SIGNATURE_DATA, value)],
                    ),
                );
                let token = blob(body(&first), CORRELATION_VALUE);
                assert!(body(&first).get(VALIDITY_INDICATOR).is_none());
                let last = call(
                    &mut f.e,
                    "alice",
                    v,
                    34,
                    part(
                        v,
                        Some(&public),
                        None,
                        Some(&message[7..]),
                        false,
                        true,
                        Some(&token),
                        vec![],
                    ),
                );
                assert_eq!(
                    body(&last)
                        .required(VALIDITY_INDICATOR)
                        .unwrap()
                        .number()
                        .unwrap(),
                    if invalid { 2 } else { 1 }
                );
            }
        }
    }
}
#[test]
fn random_iv_and_gcm_final_response_failure_are_transactional() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, None);
    let parameters = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![
            Node::enumeration(BLOCK_CIPHER_MODE, 1),
            Node::enumeration(PADDING_METHOD, 3),
            Node::boolean(RANDOM_IV, true),
        ],
    );
    let first = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(parameters),
            None,
            true,
            false,
            None,
            vec![],
        ),
    );
    let iv = blob(body(&first), IV_COUNTER_NONCE);
    assert_eq!(iv.len(), 16);
    let token = blob(body(&first), CORRELATION_VALUE);
    let last = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            None,
            Some(b"hello"),
            false,
            true,
            Some(&token),
            vec![],
        ),
    );
    let encrypted = blob(body(&last), DATA);
    assert_eq!(
        crypto::aes(
            false,
            &[7; 32],
            crypto::AesParameters {
                mode: 1,
                padding: 3,
                tag_len: 16
            },
            &iv,
            &encrypted,
            &[],
            None
        )
        .unwrap()
        .0
        .as_slice(),
        b"hello"
    );
    let message = vec![2; 512];
    let (ciphertext, tag) = crypto::aes(
        true,
        &[7; 32],
        crypto::AesParameters {
            mode: 9,
            padding: 1,
            tag_len: 16,
        },
        &[4; 12],
        &message,
        b"aad",
        None,
    )
    .unwrap();
    let initial = part(
        v,
        Some(&id),
        Some(cp(9, 1)),
        Some(&ciphertext[..200]),
        true,
        false,
        None,
        vec![
            Node::bytes(IV_COUNTER_NONCE, vec![4; 12]),
            Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, tag),
            Node::bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, b"aad".to_vec()),
        ],
    );
    let start = call(&mut f.e, "alice", v, 32, initial);
    assert!(body(&start).get(DATA).is_none());
    let token = blob(body(&start), CORRELATION_VALUE);
    let final_fields = part(
        v,
        Some(&id),
        None,
        Some(&ciphertext[200..]),
        false,
        true,
        Some(&token),
        vec![],
    );
    let failed =
        f.e.process(
            "alice",
            &request(
                v,
                vec![(32, final_fields.clone())],
                vec![Node::int(MAXIMUM_RESPONSE_SIZE, 400)],
            ),
        )
        .unwrap();
    assert_eq!(reason(&failed), 2);
    let success = call(&mut f.e, "alice", v, 32, final_fields);
    assert_eq!(blob(body(&success), DATA), message);
}
#[test]
fn indicator_types_duplicates_versions_and_explicit_single_part_forms() {
    let mut f = Fixture::new();
    let hash = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
    );
    for v in [Version(1, 3), Version(2, 1), Version(3, 0)] {
        for (initial, last) in [(false, false), (true, true)] {
            let r = call(
                &mut f.e,
                "alice",
                v,
                39,
                part(
                    v,
                    None,
                    Some(hash.clone()),
                    Some(b"single"),
                    initial,
                    last,
                    None,
                    vec![],
                ),
            );
            assert_eq!(
                blob(body(&r), DATA),
                crypto::hash_data(6, b"single").unwrap()
            );
            assert!(body(&r).get(CORRELATION_VALUE).is_none());
        }
        let r = call(
            &mut f.e,
            "alice",
            v,
            39,
            part(v, None, Some(hash.clone()), None, true, true, None, vec![]),
        );
        assert_eq!(blob(body(&r), DATA), crypto::hash_data(6, b"").unwrap());
        let mut duplicate = part(
            v,
            None,
            Some(hash.clone()),
            Some(b"x"),
            false,
            false,
            None,
            vec![],
        );
        duplicate.push(Node::boolean(INIT_INDICATOR, false));
        assert_eq!(reason(&call(&mut f.e, "alice", v, 39, duplicate)), 7);
        let wrong = vec![
            hash.clone(),
            Node::bytes(DATA, vec![]),
            Node::int(INIT_INDICATOR, 1),
        ];
        assert_eq!(reason(&call(&mut f.e, "alice", v, 39, wrong)), 7);
    }
    let v = Version(1, 2);
    let id = key(&mut f.e, "alice", v, 3, 12, None);
    assert_eq!(
        reason(&call(
            &mut f.e,
            "alice",
            v,
            31,
            part(
                v,
                Some(&id),
                Some(cp(6, 1)),
                Some(b"x"),
                true,
                false,
                None,
                vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])]
            )
        )),
        7
    );
}

#[test]
fn rsa_oaep_by_parts_encrypts_and_decrypts_only_on_finalization() {
    for v in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        let mut f = Fixture::new();
        let (private, public) = pair_roles(&mut f.e, v, 4, 8, 4);
        let params = Node::structure(
            CRYPTOGRAPHIC_PARAMETERS,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4),
                Node::enumeration(PADDING_METHOD, 2),
                Node::enumeration(HASHING_ALGORITHM, 6),
            ],
        );
        let first = call(
            &mut f.e,
            "alice",
            v,
            31,
            part(
                v,
                Some(&public),
                Some(params.clone()),
                Some(b"first "),
                true,
                false,
                None,
                vec![],
            ),
        );
        assert!(body(&first).get(DATA).is_none());
        let token = blob(body(&first), CORRELATION_VALUE);
        let encrypted = call(
            &mut f.e,
            "alice",
            v,
            31,
            part(
                v,
                Some(&public),
                None,
                Some(b"last"),
                false,
                true,
                Some(&token),
                vec![],
            ),
        );
        let ciphertext = blob(body(&encrypted), DATA);
        assert_eq!(ciphertext.len(), 256);
        let private_bytes =
            f.e.store
                .get("alice", &private)
                .unwrap()
                .unwrap()
                .material
                .clone();
        assert_eq!(
            crypto::rsa::oaep_decrypt(
                &private_bytes,
                crypto::rsa::OaepParameters {
                    hash: 6,
                    mgf_hash: 4,
                    label: &[]
                },
                &ciphertext
            )
            .unwrap()
            .as_slice(),
            b"first last"
        );
        let mut token = vec![];
        for (i, chunk) in ciphertext.chunks(31).enumerate() {
            let r = call(
                &mut f.e,
                "alice",
                v,
                32,
                part(
                    v,
                    Some(&private),
                    Some(params.clone()),
                    Some(chunk),
                    i == 0,
                    false,
                    if i == 0 { None } else { Some(&token) },
                    vec![],
                ),
            );
            assert!(body(&r).get(DATA).is_none());
            token = blob(body(&r), CORRELATION_VALUE);
        }
        let decrypted = call(
            &mut f.e,
            "alice",
            v,
            32,
            part(
                v,
                Some(&private),
                None,
                None,
                false,
                true,
                Some(&token),
                vec![],
            ),
        );
        assert_eq!(blob(body(&decrypted), DATA), b"first last");
        assert_eq!(left(&f.e, "alice", &private), 1);
    }
}
#[test]
fn true_streaming_handles_multiple_frames_without_retaining_whole_messages() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, None);
    let message = vec![3; 3 * 1024 * 1024 + 7];
    let mut token = vec![];
    let mut ciphertext = vec![];
    for (i, chunk) in message.chunks(32 * 1024).enumerate() {
        let r = call(
            &mut f.e,
            "alice",
            v,
            31,
            part(
                v,
                Some(&id),
                if i == 0 { Some(cp(6, 1)) } else { None },
                Some(chunk),
                i == 0,
                false,
                if i == 0 { None } else { Some(&token) },
                if i == 0 {
                    vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])]
                } else {
                    vec![]
                },
            ),
        );
        ciphertext.extend(blob(body(&r), DATA));
        token = blob(body(&r), CORRELATION_VALUE);
    }
    let last = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(v, Some(&id), None, None, false, true, Some(&token), vec![]),
    );
    ciphertext.extend(blob(body(&last), DATA));
    assert_eq!(
        ciphertext,
        crypto::aes(
            true,
            &[7; 32],
            crypto::AesParameters {
                mode: 6,
                padding: 1,
                tag_len: 16
            },
            &[0; 16],
            &message,
            &[],
            None
        )
        .unwrap()
        .0
        .as_slice()
    );
    let mut token = vec![];
    for (i, chunk) in message.chunks(32 * 1024).enumerate() {
        let r = call(
            &mut f.e,
            "alice",
            v,
            39,
            part(
                v,
                None,
                if i == 0 {
                    Some(Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
                    ))
                } else {
                    None
                },
                Some(chunk),
                i == 0,
                false,
                if i == 0 { None } else { Some(&token) },
                vec![],
            ),
        );
        assert!(body(&r).get(DATA).is_none());
        token = blob(body(&r), CORRELATION_VALUE);
    }
    let last = call(
        &mut f.e,
        "alice",
        v,
        39,
        part(v, None, None, None, false, true, Some(&token), vec![]),
    );
    assert_eq!(
        blob(body(&last), DATA),
        crypto::hash_data(6, &message).unwrap()
    );
}
#[test]
fn gcm_plaintext_and_global_retained_data_limits_fail_without_plaintext() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let alice = key(&mut f.e, "alice", v, 3, 12, None);
    let bob = key(&mut f.e, "bob", v, 3, 12, None);
    let extras = || {
        vec![
            Node::bytes(IV_COUNTER_NONCE, vec![0; 12]),
            Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, vec![0; 16]),
        ]
    };
    for _ in 0..16 {
        let r = call(
            &mut f.e,
            "alice",
            v,
            32,
            part(
                v,
                Some(&alice),
                Some(cp(9, 1)),
                Some(&vec![0; 500 * 1024]),
                true,
                false,
                None,
                extras(),
            ),
        );
        assert!(body(&r).get(DATA).is_none());
    }
    let failed = call(
        &mut f.e,
        "bob",
        v,
        32,
        part(
            v,
            Some(&bob),
            Some(cp(9, 1)),
            Some(&vec![0; 300 * 1024]),
            true,
            false,
            None,
            extras(),
        ),
    );
    assert_eq!(reason(&failed), 2);
    assert!(item(&failed).get(RESPONSE_PAYLOAD).is_none());
    let failed = call(
        &mut f.e,
        "bob",
        v,
        32,
        part(
            v,
            Some(&bob),
            Some(cp(9, 1)),
            Some(&vec![0; crypto::stream::MAX_AUTHENTICATED_PLAINTEXT + 1]),
            true,
            false,
            None,
            extras(),
        ),
    );
    assert_eq!(reason(&failed), 2);
    let success = call(
        &mut f.e,
        "bob",
        v,
        32,
        part(
            v,
            Some(&bob),
            Some(cp(9, 1)),
            None,
            true,
            false,
            None,
            extras(),
        ),
    );
    body(&success);
}

#[test]
fn multipart_prehashed_signatures_accept_initial_or_final_digest_without_double_charge() {
    for v in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        for algorithm in [4, 6] {
            for early in [false, true] {
                let mut f = Fixture::new();
                let (private, public) = pair_budget(&mut f.e, v, algorithm, 1, 2, (32, 1));
                let message = b"already digested by an application";
                let digest = crypto::hash_data(6, message).unwrap();
                let mut params = vec![
                    Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm),
                    Node::enumeration(HASHING_ALGORITHM, 6),
                ];
                if algorithm == 4 {
                    params.push(Node::enumeration(PADDING_METHOD, 8));
                }
                let params = Node::structure(CRYPTOGRAPHIC_PARAMETERS, params);
                let first = call(
                    &mut f.e,
                    "alice",
                    v,
                    33,
                    part(
                        v,
                        Some(&private),
                        Some(params.clone()),
                        None,
                        true,
                        false,
                        None,
                        if early {
                            vec![Node::bytes(DIGESTED_DATA, digest.clone())]
                        } else {
                            vec![]
                        },
                    ),
                );
                let token = blob(body(&first), CORRELATION_VALUE);
                assert_eq!(left(&f.e, "alice", &private), if early { 0 } else { 32 });
                let mixed = call(
                    &mut f.e,
                    "alice",
                    v,
                    33,
                    part(
                        v,
                        Some(&private),
                        None,
                        Some(b"bad mix"),
                        false,
                        true,
                        Some(&token),
                        vec![Node::bytes(DIGESTED_DATA, digest.clone())],
                    ),
                );
                assert_eq!(reason(&mixed), 7);
                let last = call(
                    &mut f.e,
                    "alice",
                    v,
                    33,
                    part(
                        v,
                        Some(&private),
                        None,
                        None,
                        false,
                        true,
                        Some(&token),
                        vec![Node::bytes(DIGESTED_DATA, digest.clone())],
                    ),
                );
                let signature = blob(body(&last), SIGNATURE_DATA);
                assert_eq!(left(&f.e, "alice", &private), 0);
                let public_bytes =
                    f.e.store
                        .get("alice", &public)
                        .unwrap()
                        .unwrap()
                        .material
                        .clone();
                assert!(if algorithm == 4 {
                    crypto::rsa::verify(
                        &public_bytes,
                        crypto::rsa::SignatureParameters {
                            hash: 6,
                            pss: false,
                            mgf_hash: 4,
                            salt_len: 64,
                        },
                        message,
                        false,
                        &signature,
                    )
                    .unwrap()
                } else {
                    crypto::ec::verify(&public_bytes, 6, message, false, &signature).unwrap()
                });
                let first = call(
                    &mut f.e,
                    "alice",
                    v,
                    34,
                    part(
                        v,
                        Some(&public),
                        Some(params),
                        None,
                        true,
                        false,
                        None,
                        vec![
                            Node::bytes(DIGESTED_DATA, digest),
                            Node::bytes(SIGNATURE_DATA, signature),
                        ],
                    ),
                );
                let token = blob(body(&first), CORRELATION_VALUE);
                assert!(body(&first).get(VALIDITY_INDICATOR).is_none());
                let last = call(
                    &mut f.e,
                    "alice",
                    v,
                    34,
                    part(
                        v,
                        Some(&public),
                        None,
                        None,
                        false,
                        true,
                        Some(&token),
                        vec![],
                    ),
                );
                assert_eq!(
                    body(&last)
                        .required(VALIDITY_INDICATOR)
                        .unwrap()
                        .number()
                        .unwrap(),
                    1
                );
            }
        }
    }
}

#[test]
fn replacement_import_invalidates_even_identical_keys_and_undo_restores_destroyed_contexts() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, None);
    let start = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"x"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    let token = blob(body(&start), CORRELATION_VALUE);
    let exported = call(&mut f.e, "alice", v, 43, vec![uid(v, &id)]);
    let p = body(&exported);
    let fields = vec![
        uid(v, &id),
        Node::enumeration(OBJECT_TYPE, 2),
        p.required(ATTRIBUTES).unwrap().clone(),
        p.required(SYMMETRIC_KEY).unwrap().clone(),
        Node::boolean(REPLACE_EXISTING, true),
    ];
    body(&call(&mut f.e, "alice", v, 42, fields));
    assert_eq!(
        reason(&call(
            &mut f.e,
            "alice",
            v,
            31,
            part(v, Some(&id), None, None, false, true, Some(&token), vec![])
        )),
        0x2e
    );
    let first = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"x"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    let token = blob(body(&first), CORRELATION_VALUE);
    let mut encrypted = blob(body(&first), DATA);
    let batch = request(
        v,
        vec![
            (
                19,
                vec![
                    uid(v, &id),
                    Node::structure(
                        REVOCATION_REASON,
                        vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
                    ),
                ],
            ),
            (20, vec![uid(v, &id)]),
            (0xffff, vec![]),
        ],
        vec![Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, 3)],
    );
    let response = f.e.process("alice", &batch).unwrap();
    assert_eq!(
        item(&response)
            .required(RESULT_STATUS)
            .unwrap()
            .number()
            .unwrap(),
        3
    );
    let final_response = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            None,
            Some(b"y"),
            false,
            true,
            Some(&token),
            vec![],
        ),
    );
    encrypted.extend(blob(body(&final_response), DATA));
    assert_eq!(
        encrypted,
        crypto::aes(
            true,
            &[7; 32],
            crypto::AesParameters {
                mode: 6,
                padding: 1,
                tag_len: 16
            },
            &[0; 16],
            b"xy",
            &[],
            None
        )
        .unwrap()
        .0
        .as_slice()
    );
}
#[test]
fn audit_storage_failure_rolls_back_context_capacity_and_usage_together() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let id = key(&mut f.e, "alice", v, 3, 12, Some((1, 2)));
    let conn = rusqlite::Connection::open(f.dir.path().join("store.sqlite")).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_stream_audit BEFORE INSERT ON audit WHEN NEW.operation=31 BEGIN SELECT RAISE(FAIL,'injected audit fault'); END;").unwrap();
    for _ in 0..20 {
        let failed = call(
            &mut f.e,
            "alice",
            v,
            31,
            part(
                v,
                Some(&id),
                Some(cp(6, 1)),
                Some(b"x"),
                true,
                false,
                None,
                vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
            ),
        );
        assert_eq!(reason(&failed), 0x100);
        assert_eq!(left(&f.e, "alice", &id), 1);
    }
    conn.execute_batch("DROP TRIGGER reject_stream_audit")
        .unwrap();
    let success = call(
        &mut f.e,
        "alice",
        v,
        31,
        part(
            v,
            Some(&id),
            Some(cp(6, 1)),
            Some(b"x"),
            true,
            false,
            None,
            vec![Node::bytes(IV_COUNTER_NONCE, vec![0; 16])],
        ),
    );
    body(&success);
    assert_eq!(left(&f.e, "alice", &id), 0);
    f.e.store.verify_audit().unwrap();
}
#[test]
fn global_context_quota_is_shared_without_losing_other_owners_streams() {
    let mut f = Fixture::new();
    let v = Version(2, 1);
    let parameters = Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(HASHING_ALGORITHM, 6)],
    );
    let mut alice_token = vec![];
    for owner in ["alice", "bob", "carol", "dan"] {
        for _ in 0..16 {
            let r = call(
                &mut f.e,
                owner,
                v,
                39,
                part(
                    v,
                    None,
                    Some(parameters.clone()),
                    None,
                    true,
                    false,
                    None,
                    vec![],
                ),
            );
            let token = blob(body(&r), CORRELATION_VALUE);
            if owner == "alice" {
                alice_token = token;
            }
        }
    }
    assert_eq!(
        reason(&call(
            &mut f.e,
            "eve",
            v,
            39,
            part(
                v,
                None,
                Some(parameters.clone()),
                None,
                true,
                false,
                None,
                vec![]
            )
        )),
        2
    );
    body(&call(
        &mut f.e,
        "alice",
        v,
        39,
        part(v, None, None, None, false, true, Some(&alice_token), vec![]),
    ));
    body(&call(
        &mut f.e,
        "eve",
        v,
        39,
        part(v, None, Some(parameters), None, true, false, None, vec![]),
    ));
}
