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
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::Node,
};

// Published SHA "abc" known answers (FIPS 180-4 and FIPS 202). In particular,
// SHA-512/224 and SHA-512/256 are not truncations of SHA-512's known answer.
const VECTORS: &[(u32, &str)] = &[
    (4, "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (
        5,
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    ),
    (
        6,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    (
        7,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    ),
    (
        8,
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    (
        12,
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    ),
    (
        13,
        "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    ),
    (
        14,
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
    ),
    (
        15,
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    (
        16,
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
    ),
    (
        17,
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    ),
];

struct Fixture {
    engine: Engine,
    _directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("master");
        std::fs::write(&master, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&directory.path().join("store.sqlite"), &master).unwrap();
        Self {
            engine: Engine::new(store, true),
            _directory: directory,
        }
    }
    fn call(&mut self, version: Version, fields: Vec<Node>) -> Node {
        let mut header = vec![version.node()];
        if version.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
        }
        self.engine
            .process(
                "alice",
                &Node::structure(
                    REQUEST_MESSAGE,
                    vec![
                        Node::structure(REQUEST_HEADER, header),
                        Node::structure(
                            BATCH_ITEM,
                            vec![
                                Node::enumeration(OPERATION, 39),
                                Node::structure(REQUEST_PAYLOAD, fields),
                            ],
                        ),
                    ],
                ),
            )
            .unwrap()
    }
}
fn cp(hash: u32) -> Node {
    Node::structure(
        CRYPTOGRAPHIC_PARAMETERS,
        vec![Node::enumeration(HASHING_ALGORITHM, hash)],
    )
}
fn body(response: &Node) -> &Node {
    let item = response.required(BATCH_ITEM).unwrap();
    assert_eq!(
        item.required(RESULT_STATUS).unwrap().number().unwrap(),
        0,
        "{}",
        serde_json::to_string(response).unwrap()
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn denied(response: &Node, expected: u32) {
    let item = response.required(BATCH_ITEM).unwrap();
    assert_eq!(item.required(RESULT_STATUS).unwrap().number().unwrap(), 1);
    assert_eq!(
        item.required(RESULT_REASON).unwrap().number().unwrap(),
        expected,
        "{}",
        serde_json::to_string(response).unwrap()
    );
    assert!(item.get(RESPONSE_PAYLOAD).is_none());
}
fn data(response: &Node) -> &[u8] {
    body(response)
        .required(DATA)
        .unwrap()
        .byte_string()
        .unwrap()
}

#[test]
fn sha_known_answers_and_edition_boundaries() {
    let mut fixture = Fixture::new();
    for version in Version::supported(true) {
        for &(hash, answer) in VECTORS {
            let response =
                fixture.call(version, vec![cp(hash), Node::bytes(DATA, b"abc".to_vec())]);
            if version < Version(1, 2) {
                denied(&response, 5);
            } else if hash >= 14 && version < Version(1, 4) {
                denied(&response, 8);
            } else {
                assert_eq!(hex::encode(data(&response)), answer);
            }
        }
    }
}

#[test]
fn multipart_and_explicit_single_forms_use_identical_sha_selection() {
    let mut fixture = Fixture::new();
    for version in Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 3))
    {
        for &(hash, answer) in VECTORS {
            if hash >= 14 && version < Version(1, 4) {
                continue;
            }
            for (init, last) in [(false, false), (true, true)] {
                let response = fixture.call(
                    version,
                    vec![
                        cp(hash),
                        Node::bytes(DATA, b"abc".to_vec()),
                        Node::boolean(INIT_INDICATOR, init),
                        Node::boolean(FINAL_INDICATOR, last),
                    ],
                );
                assert_eq!(hex::encode(data(&response)), answer);
                assert!(body(&response).get(CORRELATION_VALUE).is_none());
            }
            let start = fixture.call(
                version,
                vec![
                    cp(hash),
                    Node::bytes(DATA, b"a".to_vec()),
                    Node::boolean(INIT_INDICATOR, true),
                ],
            );
            assert!(body(&start).get(DATA).is_none());
            let token = body(&start).required(CORRELATION_VALUE).unwrap().clone();
            let middle = fixture.call(
                version,
                vec![token.clone(), Node::bytes(DATA, b"b".to_vec())],
            );
            assert!(body(&middle).get(DATA).is_none());
            let final_response = fixture.call(
                version,
                vec![
                    token,
                    Node::bytes(DATA, b"c".to_vec()),
                    Node::boolean(FINAL_INDICATOR, true),
                ],
            );
            assert_eq!(hex::encode(data(&final_response)), answer);
            assert!(body(&final_response).get(CORRELATION_VALUE).is_none());
        }
    }
}

#[test]
fn typed_and_versioned_parameters_are_enforced_in_every_single_form() {
    let mut fixture = Fixture::new();
    for version in [
        Version(1, 3),
        Version(1, 4),
        Version(2, 0),
        Version(2, 1),
        Version(3, 0),
    ] {
        for flags in [
            vec![],
            vec![Node::boolean(INIT_INDICATOR, false)],
            vec![
                Node::boolean(INIT_INDICATOR, true),
                Node::boolean(FINAL_INDICATOR, true),
            ],
        ] {
            for parameters in [
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::int(HASHING_ALGORITHM, 6)],
                ),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![
                        Node::enumeration(HASHING_ALGORITHM, 6),
                        Node::enumeration(HASHING_ALGORITHM, 7),
                    ],
                ),
            ] {
                // A Hashing Algorithm given twice is Invalid Message in 1.x
                // (1.4 Table 327).
                let expected = if version.0 == 1 && parameters.all(HASHING_ALGORITHM).count() > 1 {
                    4
                } else {
                    7
                };
                let mut fields = vec![parameters, Node::bytes(DATA, b"abc".to_vec())];
                fields.extend(flags.clone());
                denied(&fixture.call(version, fields), expected);
            }
            for unsupported in [0, 1, 2, 3, 9, 10, 11, 18, 0x80000001] {
                let mut fields = vec![cp(unsupported), Node::bytes(DATA, b"abc".to_vec())];
                fields.extend(flags.clone());
                denied(&fixture.call(version, fields), 8);
            }
            if version < Version(1, 4) {
                for hash in 14..=17 {
                    let mut fields = vec![cp(hash), Node::bytes(DATA, b"abc".to_vec())];
                    fields.extend(flags.clone());
                    denied(&fixture.call(version, fields), 8);
                }
            }
        }
    }
}

#[test]
fn rejected_sha_stream_changes_preserve_the_original_context() {
    let mut fixture = Fixture::new();
    for version in [Version(1, 4), Version(2, 0), Version(2, 1), Version(3, 0)] {
        let start = fixture.call(
            version,
            vec![
                cp(15),
                Node::bytes(DATA, b"a".to_vec()),
                Node::boolean(INIT_INDICATOR, true),
            ],
        );
        let token = body(&start).required(CORRELATION_VALUE).unwrap().clone();
        for (parameters, expected) in [(cp(17), 7), (cp(1), 8)] {
            denied(
                &fixture.call(
                    version,
                    vec![
                        token.clone(),
                        parameters,
                        Node::bytes(DATA, b"bad".to_vec()),
                        Node::boolean(FINAL_INDICATOR, true),
                    ],
                ),
                expected,
            );
        }
        let response = fixture.call(
            version,
            vec![
                token,
                Node::bytes(DATA, b"bc".to_vec()),
                Node::boolean(FINAL_INDICATOR, true),
            ],
        );
        assert_eq!(
            hex::encode(data(&response)),
            VECTORS.iter().find(|v| v.0 == 15).unwrap().1
        );
    }
}
