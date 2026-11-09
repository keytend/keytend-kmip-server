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

// RNG Seed uses the KMIP 1.2-3.0 option to ignore client seeding material and
// report Data Length 0. These tests pin that policy: the operation never
// claims accepted bytes, never affects RNG Retrieve output and is never stored.

use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};

const RNG_RETRIEVE: u32 = 37;
const RNG_SEED: u32 = 38;
// The seed sent by every published CS-RNG-O-*-* trace.
const OASIS_SEED: &str = "333c06587706225099a67438f263f8f932f64b860c3a7dbb21bc2bd56685d8bc";

struct Fixture {
    engine: Engine,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let master = directory.path().join("master");
        std::fs::write(&master, [9; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let store = Store::open(&directory.path().join("store.sqlite"), &master).unwrap();
        Self {
            engine: Engine::new(store, true),
            directory,
        }
    }
    fn batch(
        &mut self,
        version: Version,
        continuation: Option<u32>,
        items: Vec<(u32, Vec<Node>)>,
        allowed: Option<&[u32]>,
    ) -> Node {
        let mut header = vec![version.node()];
        if let Some(option) = continuation {
            header.push(Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, option));
        }
        if version.0 < 3 {
            header.push(Node::int(BATCH_COUNT, items.len() as i32));
        }
        let mut message = vec![Node::structure(REQUEST_HEADER, header)];
        message.extend(items.into_iter().enumerate().map(|(index, (op, fields))| {
            let mut item = vec![Node::enumeration(OPERATION, op)];
            if version.0 < 3 {
                item.push(Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]));
            }
            item.push(Node::structure(REQUEST_PAYLOAD, fields));
            Node::structure(BATCH_ITEM, item)
        }));
        self.engine
            .process_authorized("alice", &Node::structure(REQUEST_MESSAGE, message), allowed)
            .unwrap()
    }
    fn call(&mut self, version: Version, op: u32, fields: Vec<Node>) -> Node {
        self.batch(version, None, vec![(op, fields)], None)
    }
}
fn seed() -> Vec<u8> {
    hex::decode(OASIS_SEED).unwrap()
}
fn items(response: &Node) -> Vec<&Node> {
    response.all(BATCH_ITEM).collect()
}
fn status(item: &Node) -> u32 {
    item.required(RESULT_STATUS).unwrap().number().unwrap()
}
fn body(response: &Node) -> &Node {
    let item = response.required(BATCH_ITEM).unwrap();
    assert_eq!(
        status(item),
        0,
        "{}",
        serde_json::to_string(response).unwrap()
    );
    item.required(RESPONSE_PAYLOAD).unwrap()
}
fn denied(response: &Node, expected: u32) {
    let item = response.required(BATCH_ITEM).unwrap();
    assert_eq!(status(item), 1);
    assert_eq!(
        item.required(RESULT_REASON).unwrap().number().unwrap(),
        expected,
        "{}",
        serde_json::to_string(response).unwrap()
    );
    assert!(item.get(RESPONSE_PAYLOAD).is_none());
}
// The only permitted success payload: one Integer Data Length of zero.
fn ignored(payload: &Node) {
    let fields = payload.children().unwrap();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].tag, DATA_LENGTH);
    assert!(matches!(fields[0].value, Value::Integer(0)));
}
fn seeding_versions() -> Vec<Version> {
    Version::supported(true)
        .into_iter()
        .filter(|v| *v >= Version(1, 2))
        .collect()
}
fn retrieve(f: &mut Fixture, version: Version) -> Vec<u8> {
    let response = f.call(version, RNG_RETRIEVE, vec![Node::int(DATA_LENGTH, 32)]);
    body(&response)
        .required(DATA)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec()
}

#[test]
fn seed_is_ignored_and_reported_as_zero_from_1_2() {
    let mut f = Fixture::new();
    for v in seeding_versions() {
        for data in [seed(), vec![], vec![0; 65536]] {
            ignored(body(&f.call(v, RNG_SEED, vec![Node::bytes(DATA, data)])));
        }
    }
}

#[test]
fn edition_gating_and_query_advertisement() {
    let mut f = Fixture::new();
    for v in Version::supported(true) {
        let response = f.call(v, RNG_SEED, vec![Node::bytes(DATA, seed())]);
        let query = f.call(v, 24, vec![Node::enumeration(QUERY_FUNCTION, 1)]);
        let advertised = body(&query)
            .all(OPERATION)
            .any(|n| n.number().unwrap() == RNG_SEED);
        assert_eq!(advertised, v >= Version(1, 2), "{}.{}", v.0, v.1);
        assert_eq!(
            keytend_kmip_server::protocol::operations(v).contains(&RNG_SEED),
            v >= Version(1, 2)
        );
        if v >= Version(1, 2) {
            ignored(body(&response));
        } else {
            denied(&response, 5);
        }
    }
}

#[test]
fn malformed_requests_use_rng_seed_error_reasons() {
    let mut f = Fixture::new();
    for v in seeding_versions() {
        // Invalid Field: missing, duplicate or wrongly typed Data.
        denied(&f.call(v, RNG_SEED, vec![]), 7);
        denied(
            &f.call(
                v,
                RNG_SEED,
                vec![Node::bytes(DATA, seed()), Node::bytes(DATA, seed())],
            ),
            // A field given twice is Invalid Message in 1.x (1.4 Table 327).
            if v.0 == 1 { 4 } else { 7 },
        );
        denied(&f.call(v, RNG_SEED, vec![Node::text(DATA, OASIS_SEED)]), 7);
        denied(&f.call(v, RNG_SEED, vec![Node::int(DATA, 32)]), 7);
        // Fields outside the request payload table: Feature Not Supported in
        // 2.x, Invalid Field in 1.x (1.4 Table 327, unknown field).
        denied(
            &f.call(
                v,
                RNG_SEED,
                vec![Node::bytes(DATA, seed()), Node::int(DATA_LENGTH, 32)],
            ),
            if v.0 == 1 { 7 } else { 8 },
        );
    }
}

#[test]
fn client_seed_never_makes_retrieval_deterministic() {
    let mut outputs = vec![];
    for _ in 0..2 {
        let mut f = Fixture::new();
        for v in seeding_versions() {
            ignored(body(&f.call(v, RNG_SEED, vec![Node::bytes(DATA, seed())])));
            let output = retrieve(&mut f, v);
            assert_eq!(output.len(), 32);
            assert_ne!(output, seed());
            assert!(!outputs.contains(&output));
            outputs.push(output);
        }
    }
}

#[test]
fn certificate_policy_can_deny_seeding_without_affecting_retrieval() {
    let mut f = Fixture::new();
    for v in seeding_versions() {
        let allowed = [24, RNG_RETRIEVE];
        let response = f.batch(
            v,
            None,
            vec![(RNG_SEED, vec![Node::bytes(DATA, seed())])],
            Some(&allowed),
        );
        denied(&response, 12);
        let response = f.batch(
            v,
            None,
            vec![(RNG_RETRIEVE, vec![Node::int(DATA_LENGTH, 16)])],
            Some(&allowed),
        );
        assert_eq!(
            body(&response)
                .required(DATA)
                .unwrap()
                .byte_string()
                .unwrap()
                .len(),
            16
        );
        let allowed = [RNG_SEED];
        let response = f.batch(
            v,
            None,
            vec![(RNG_SEED, vec![Node::bytes(DATA, seed())])],
            Some(&allowed),
        );
        ignored(body(&response));
    }
}

#[test]
fn batches_report_the_ignored_seed_truthfully() {
    let mut f = Fixture::new();
    for v in [Version(1, 2), Version(1, 4), Version(2, 0), Version(2, 1)] {
        // Undo: nothing was mixed, so the Undone item still reports zero bytes used.
        let response = f.batch(
            v,
            Some(3),
            vec![
                (RNG_SEED, vec![Node::bytes(DATA, seed())]),
                (10, vec![Node::text(UNIQUE_IDENTIFIER, "missing")]),
            ],
            None,
        );
        let results = items(&response);
        assert_eq!(
            results.len(),
            2,
            "{}",
            serde_json::to_string(&response).unwrap()
        );
        assert_eq!(status(results[0]), 3);
        ignored(results[0].required(RESPONSE_PAYLOAD).unwrap());
        assert_eq!(status(results[1]), 1);
        // Continue: a malformed seed item fails alone.
        let response = f.batch(
            v,
            Some(1),
            vec![
                (RNG_SEED, vec![Node::text(DATA, OASIS_SEED)]),
                (RNG_SEED, vec![Node::bytes(DATA, seed())]),
            ],
            None,
        );
        let results = items(&response);
        assert_eq!(status(results[0]), 1);
        assert_eq!(status(results[1]), 0);
        ignored(results[1].required(RESPONSE_PAYLOAD).unwrap());
    }
}

#[test]
fn seed_bytes_are_not_persisted_and_audit_stays_valid() {
    let mut f = Fixture::new();
    for v in seeding_versions() {
        ignored(body(&f.call(v, RNG_SEED, vec![Node::bytes(DATA, seed())])));
    }
    f.engine.store.verify_audit().unwrap();
    let needle = seed();
    for entry in std::fs::read_dir(f.directory.path()).unwrap() {
        let path = entry.unwrap().path();
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
            "seed bytes found in {}",
            path.display()
        );
    }
}

#[test]
fn profile_named_xml_request_and_text_encoded_responses() {
    use keytend_kmip_server::encoding::Format;
    let mut f = Fixture::new();
    for (major, minor) in [(1, 3), (1, 4), (2, 0), (2, 1)] {
        let xml = format!(
            r#"<RequestMessage><RequestHeader><ProtocolVersion><ProtocolVersionMajor type="Integer" value="{major}"/><ProtocolVersionMinor type="Integer" value="{minor}"/></ProtocolVersion><BatchCount type="Integer" value="1"/></RequestHeader><BatchItem><Operation type="Enumeration" value="RNGSeed"/><RequestPayload><Data type="ByteString" value="{OASIS_SEED}"/></RequestPayload></BatchItem></RequestMessage>"#
        );
        let request = Format::Xml.decode(xml.as_bytes()).unwrap();
        let response = f.engine.process("alice", &request).unwrap();
        ignored(body(&response));
        for format in [Format::Xml, Format::Json] {
            let encoded = format.encode(&response).unwrap();
            let decoded = format.decode(&encoded).unwrap();
            let item = decoded.required(BATCH_ITEM).unwrap();
            assert_eq!(
                item.required(OPERATION).unwrap().number().unwrap(),
                RNG_SEED
            );
            ignored(item.required(RESPONSE_PAYLOAD).unwrap());
        }
    }
}
