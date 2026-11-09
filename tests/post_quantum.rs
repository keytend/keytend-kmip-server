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

//! ML-KEM, ML-DSA and SLH-DSA managed objects (draft KMIP 3.0 only;
//! docs/algorithms.md#post-quantum-keys). Signatures and KEM outputs are cross-checked with
//! the `openssl` command-line tool (an independent implementation path
//! through the same provider) when the host's CLI offers the algorithms.
use keytend_kmip_server::{
    protocol::{Engine, Version},
    store::Store,
    tags::*,
    ttlv::{Node, Value},
};
use std::process::Command;

const V3: Version = Version(3, 0);
const V21: Version = Version(2, 1);
const CREATE_KEY_PAIR: u32 = 2;
const REGISTER: u32 = 3;
const REKEY_KEY_PAIR: u32 = 29;
const GET: u32 = 10;
const GET_ATTRIBUTES: u32 = 11;
const ACTIVATE: u32 = 18;
const QUERY: u32 = 24;
const SIGN: u32 = 33;
const VERIFY: u32 = 34;
const ENCAPSULATE: u32 = 65;
const DECAPSULATE: u32 = 66;

const ML_KEM_512: u32 = 0x39;
const ML_KEM_768: u32 = 0x3A;
const ML_KEM_1024: u32 = 0x3B;
const ML_DSA_44: u32 = 0x3C;
const ML_DSA_65: u32 = 0x3D;
const ML_DSA_87: u32 = 0x3E;
const SLH_DSA_SHA2_128F: u32 = 0x40;
const SLH_DSA_SHAKE_128S: u32 = 0x45;
const HASH_ML_DSA_44: u32 = 0x57;
const X25519MLKEM768: u32 = 0x5C;

const RAW: u32 = 1;
const PKCS1: u32 = 3;
const PKCS8: u32 = 4;
const X509: u32 = 5;
const SEED_PRIVATE_KEY: u32 = 24;

const SIGN_MASK: i32 = 1;
const VERIFY_MASK: i32 = 2;
const ENCRYPT_MASK: i32 = 4;
const DECRYPT_MASK: i32 = 8;
const KEY_AGREEMENT_MASK: i32 = 0x800;

struct Server {
    _dir: tempfile::TempDir,
    e: Engine,
}
fn server(fips: bool) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("master");
    std::fs::write(&key, [9; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
    Server {
        e: Engine::new(store, true).with_fips(fips),
        _dir: dir,
    }
}
impl Server {
    fn call(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let mut header = vec![v.node()];
        if v.0 < 3 {
            header.push(Node::int(BATCH_COUNT, 1));
        }
        let message = Node::structure(
            REQUEST_MESSAGE,
            vec![
                Node::structure(REQUEST_HEADER, header),
                Node::structure(
                    BATCH_ITEM,
                    vec![
                        Node::enumeration(OPERATION, op),
                        Node::structure(REQUEST_PAYLOAD, payload),
                    ],
                ),
            ],
        );
        let response = self.e.process("alice", &message).unwrap();
        response.required(BATCH_ITEM).unwrap().clone()
    }
    fn ok(&mut self, v: Version, op: u32, payload: Vec<Node>) -> Node {
        let item = self.call(v, op, payload);
        assert_eq!(status(&item).0, 0, "op {op}: {:?}", status(&item));
        item.required(RESPONSE_PAYLOAD).unwrap().clone()
    }
    fn fails(&mut self, v: Version, op: u32, payload: Vec<Node>, reason: u32, what: &str) {
        let item = self.call(v, op, payload);
        let (s, r, m) = status(&item);
        assert_eq!((s, r), (1, reason), "{what}: {m}");
    }
    /// Create and activate a pair; returns (private, public).
    fn pair(&mut self, alg: u32, private_mask: i32, public_mask: i32) -> (String, String) {
        let r = self.ok(
            V3,
            CREATE_KEY_PAIR,
            pair_request(alg, private_mask, public_mask),
        );
        let ids = (
            text(&r, PRIVATE_KEY_UNIQUE_IDENTIFIER),
            text(&r, PUBLIC_KEY_UNIQUE_IDENTIFIER),
        );
        for id in [&ids.0, &ids.1] {
            self.ok(
                V3,
                ACTIVATE,
                vec![Node::reference(UNIQUE_IDENTIFIER, id.as_str())],
            );
        }
        ids
    }
    fn get(&mut self, id: &str, format: u32) -> Node {
        let r = self.ok(
            V3,
            GET,
            vec![
                Node::reference(UNIQUE_IDENTIFIER, id),
                Node::enumeration(KEY_FORMAT_TYPE, format),
            ],
        );
        let block = r
            .children()
            .unwrap()
            .iter()
            .find_map(|n| n.get(KEY_BLOCK))
            .unwrap()
            .clone();
        assert_eq!(
            block.required(KEY_FORMAT_TYPE).unwrap().number().unwrap(),
            format
        );
        block
            .required(KEY_VALUE)
            .unwrap()
            .required(KEY_MATERIAL)
            .unwrap()
            .clone()
    }
    fn bytes(&mut self, id: &str, format: u32) -> Vec<u8> {
        self.get(id, format).byte_string().unwrap().to_vec()
    }
    fn attribute(&mut self, id: &str, tag: u32) -> Option<Node> {
        let r = self.ok(
            V3,
            GET_ATTRIBUTES,
            vec![Node::reference(UNIQUE_IDENTIFIER, id)],
        );
        r.required(ATTRIBUTES).unwrap().get(tag).cloned()
    }
    fn secret(&mut self, id: &str) -> Vec<u8> {
        let r = self.ok(V3, GET, vec![Node::reference(UNIQUE_IDENTIFIER, id)]);
        assert_eq!(r.required(OBJECT_TYPE).unwrap().number().unwrap(), 7);
        r.required(SECRET_DATA)
            .unwrap()
            .required(KEY_BLOCK)
            .unwrap()
            .required(KEY_VALUE)
            .unwrap()
            .required(KEY_MATERIAL)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec()
    }
    fn sign(&mut self, id: &str, data: &[u8], cp: Vec<Node>) -> Vec<u8> {
        let r = self.ok(V3, SIGN, sign_request(id, data, cp));
        r.required(SIGNATURE_DATA)
            .unwrap()
            .byte_string()
            .unwrap()
            .to_vec()
    }
    fn verify(&mut self, id: &str, data: &[u8], signature: &[u8], cp: Vec<Node>) -> u32 {
        let mut payload = sign_request(id, data, cp);
        payload.push(Node::bytes(SIGNATURE_DATA, signature.to_vec()));
        let r = self.ok(V3, VERIFY, payload);
        r.required(VALIDITY_INDICATOR).unwrap().number().unwrap()
    }
}
fn status(item: &Node) -> (u32, u32, String) {
    let number = |tag| item.get(tag).map_or(0, |n| n.number().unwrap());
    let message = item
        .get(RESULT_MESSAGE)
        .map_or(String::new(), |n| n.string().unwrap().to_owned());
    (number(RESULT_STATUS), number(RESULT_REASON), message)
}
fn text(n: &Node, tag: u32) -> String {
    n.required(tag)
        .unwrap()
        .identifier_text()
        .unwrap()
        .to_owned()
}
fn pair_request(alg: u32, private_mask: i32, public_mask: i32) -> Vec<Node> {
    vec![
        Node::structure(
            COMMON_ATTRIBUTES,
            vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg)],
        ),
        Node::structure(
            PRIVATE_KEY_ATTRIBUTES,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, private_mask)],
        ),
        Node::structure(
            PUBLIC_KEY_ATTRIBUTES,
            vec![Node::int(CRYPTOGRAPHIC_USAGE_MASK, public_mask)],
        ),
    ]
}
fn sign_request(id: &str, data: &[u8], cp: Vec<Node>) -> Vec<Node> {
    let mut payload = vec![Node::reference(UNIQUE_IDENTIFIER, id)];
    if !cp.is_empty() {
        payload.push(Node::structure(CRYPTOGRAPHIC_PARAMETERS, cp));
    }
    payload.push(Node::bytes(DATA, data.to_vec()));
    payload
}
fn register(kind: u32, alg: u32, mask: i32, format: u32, material: Node) -> Vec<Node> {
    vec![
        Node::enumeration(OBJECT_TYPE, kind),
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, mask),
            ],
        ),
        Node::structure(
            if kind == 4 { PRIVATE_KEY } else { PUBLIC_KEY },
            vec![Node::structure(
                KEY_BLOCK,
                vec![
                    Node::enumeration(KEY_FORMAT_TYPE, format),
                    Node::structure(KEY_VALUE, vec![material]),
                ],
            )],
        ),
    ]
}
fn context(bytes: &[u8]) -> Node {
    Node::bytes(CONTEXT_STRING, bytes.to_vec())
}
fn number(n: Option<Node>) -> i64 {
    match n.unwrap().value {
        Value::Integer(i) => i64::from(i),
        Value::Enumeration(e) => i64::from(e),
        _ => panic!("not a number"),
    }
}

/// The host `openssl` CLI, when it offers ML-KEM, ML-DSA and SLH-DSA.
fn cli() -> Option<tempfile::TempDir> {
    let out = Command::new("openssl")
        .args(["list", "-signature-algorithms"])
        .output()
        .ok()?;
    let listed = String::from_utf8_lossy(&out.stdout).to_string();
    if !listed.contains("ML-DSA-65") || !listed.contains("SLH-DSA-SHA2-128f") {
        eprintln!("openssl CLI lacks ML-DSA/SLH-DSA; cross-checks skipped");
        return None;
    }
    Some(tempfile::tempdir().unwrap())
}
fn openssl(dir: &std::path::Path, args: &[&str]) -> bool {
    Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// REQ:pq-create-key-pair Draft 3.0 6.1.11: post-quantum pairs carry per-key
// Cryptographic Length and the NIST Security Category of the parameter set.
#[test]
fn create_key_pair_sets_per_key_lengths_category_and_raw_default() {
    let mut s = server(false);
    // (algorithm, private bytes, public bytes, category): FIPS 203 Table 3,
    // FIPS 204 Table 2, FIPS 205 Table 2.
    for (alg, private, public, category) in [
        (ML_KEM_512, 1632, 800, 1),
        (ML_KEM_768, 2400, 1184, 3),
        (ML_KEM_1024, 3168, 1568, 5),
        (ML_DSA_44, 2560, 1312, 2),
        (ML_DSA_65, 4032, 1952, 3),
        (ML_DSA_87, 4896, 2592, 5),
        (SLH_DSA_SHA2_128F, 64, 32, 1),
        (SLH_DSA_SHAKE_128S, 64, 32, 1),
    ] {
        let (sk, pk) = s.pair(alg, SIGN_MASK, VERIFY_MASK);
        for (id, bytes) in [(&sk, private), (&pk, public)] {
            assert_eq!(
                number(s.attribute(id, CRYPTOGRAPHIC_LENGTH)),
                bytes * 8,
                "{alg:#x}"
            );
            assert_eq!(
                number(s.attribute(id, CRYPTOGRAPHIC_ALGORITHM)),
                i64::from(alg)
            );
            assert_eq!(number(s.attribute(id, NIST_SECURITY_CATEGORY)), category);
            assert_eq!(number(s.attribute(id, KEY_FORMAT_TYPE)), i64::from(RAW));
            assert_eq!(s.bytes(id, RAW).len(), bytes as usize);
        }
    }
    // A Cryptographic Length that is not the key's own size is refused.
    let mut request = pair_request(ML_DSA_44, SIGN_MASK, VERIFY_MASK);
    request[0] = Node::structure(
        COMMON_ATTRIBUTES,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, ML_DSA_44),
            Node::int(CRYPTOGRAPHIC_LENGTH, 2560 * 8),
        ],
    );
    s.fails(V3, CREATE_KEY_PAIR, request, 7, "common length");
    let mut request = pair_request(ML_DSA_44, SIGN_MASK, VERIFY_MASK);
    request[1] = Node::structure(
        PRIVATE_KEY_ATTRIBUTES,
        vec![
            Node::int(CRYPTOGRAPHIC_USAGE_MASK, SIGN_MASK),
            Node::int(CRYPTOGRAPHIC_LENGTH, 2560 * 8),
        ],
    );
    s.ok(V3, CREATE_KEY_PAIR, request);
    // A client NIST Security Category must agree.
    let mut request = pair_request(ML_DSA_44, SIGN_MASK, VERIFY_MASK);
    request[0] = Node::structure(
        COMMON_ATTRIBUTES,
        vec![
            Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, ML_DSA_44),
            Node::int(NIST_SECURITY_CATEGORY, 3),
        ],
    );
    s.fails(V3, CREATE_KEY_PAIR, request, 7, "wrong category");
    // It applies to post-quantum keys only, and the client cannot change it.
    let aes = vec![
        Node::enumeration(OBJECT_TYPE, 2),
        Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, ENCRYPT_MASK),
                Node::int(NIST_SECURITY_CATEGORY, 5),
            ],
        ),
    ];
    s.fails(V3, 1, aes, 7, "AES category");
    let (sk, _) = s.pair(ML_DSA_87, SIGN_MASK, VERIFY_MASK);
    for op in [13, 14] {
        let item = s.call(
            V3,
            op,
            vec![
                Node::reference(UNIQUE_IDENTIFIER, sk.as_str()),
                Node::structure(NEW_ATTRIBUTE, vec![Node::int(NIST_SECURITY_CATEGORY, 5)]),
            ],
        );
        assert_eq!(status(&item).0, 1, "op {op} {:?}", status(&item));
    }
    assert_eq!(number(s.attribute(&sk, NIST_SECURITY_CATEGORY)), 5);
    // Quantum Safe (2.0+ section 4.45): category 5 keys qualify, others do
    // not (General Failure, as QS-M-2 expects for AES-128).
    let quantum_safe = |alg| {
        let mut request = pair_request(alg, SIGN_MASK, VERIFY_MASK);
        request[0] = Node::structure(
            COMMON_ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, alg),
                Node::boolean(QUANTUM_SAFE, true),
            ],
        );
        request
    };
    s.ok(V3, CREATE_KEY_PAIR, quantum_safe(ML_KEM_1024));
    s.ok(V3, CREATE_KEY_PAIR, quantum_safe(ML_DSA_87));
    s.fails(
        V3,
        CREATE_KEY_PAIR,
        quantum_safe(ML_KEM_768),
        0x100,
        "category 3",
    );
}

#[test]
fn undefined_editions_fips_mode_and_unimplemented_values_are_refused() {
    let mut s = server(false);
    // KMIP 2.1 defines no post-quantum algorithm (2.1 Table 336 ends at Ed448).
    s.fails(
        V21,
        CREATE_KEY_PAIR,
        pair_request(ML_DSA_65, 1, 2),
        8,
        "2.1",
    );
    // Defined in 3.0 but not implemented: HashML-DSA and the hybrid KEMs.
    for alg in [HASH_ML_DSA_44, X25519MLKEM768] {
        s.fails(
            V3,
            CREATE_KEY_PAIR,
            pair_request(alg, 1, 2),
            8,
            &format!("{alg:#x}"),
        );
    }
    // A pair made over 3.0 is not usable over 2.1.
    let (sk, _) = s.pair(ML_DSA_44, SIGN_MASK, VERIFY_MASK);
    s.fails(
        V21,
        GET,
        vec![Node::text(UNIQUE_IDENTIFIER, sk.as_str())],
        8,
        "2.1 Get",
    );
    // Query: Encapsulate/Decapsulate in 3.0 only, and not in FIPS mode.
    let ops = |s: &mut Server, v| {
        let r = s.ok(v, QUERY, vec![Node::enumeration(QUERY_FUNCTION, 1)]);
        r.children()
            .unwrap()
            .iter()
            .map(|n| n.number().unwrap())
            .collect::<Vec<_>>()
    };
    let listed = ops(&mut s, V3);
    assert!(listed.contains(&ENCAPSULATE) && listed.contains(&DECAPSULATE));
    let listed = ops(&mut s, V21);
    assert!(!listed.contains(&ENCAPSULATE) && !listed.contains(&DECAPSULATE));
    let mut f = server(true);
    let listed = ops(&mut f, V3);
    assert!(!listed.contains(&ENCAPSULATE) && !listed.contains(&DECAPSULATE));
    // FIPS mode refuses generation, registration, use and the operations.
    f.fails(
        V3,
        CREATE_KEY_PAIR,
        pair_request(ML_KEM_768, 8, 4),
        8,
        "FIPS generation",
    );
    f.fails(
        V3,
        ENCAPSULATE,
        vec![Node::reference(UNIQUE_IDENTIFIER, "x")],
        5,
        "FIPS Encapsulate is not offered",
    );
    let (_, public) = s.pair(ML_DSA_44, 1, 2);
    let pk = s.bytes(&public, RAW);
    f.fails(
        V3,
        REGISTER,
        register(
            3,
            ML_DSA_44,
            VERIFY_MASK,
            RAW,
            Node::bytes(KEY_MATERIAL, pk),
        ),
        8,
        "FIPS Register",
    );
}

#[test]
fn ml_dsa_and_slh_dsa_sign_verify_with_options_and_reject_tampering() {
    let mut s = server(false);
    for alg in [ML_DSA_44, ML_DSA_87, SLH_DSA_SHA2_128F, SLH_DSA_SHAKE_128S] {
        let (sk, pk) = s.pair(alg, SIGN_MASK, VERIFY_MASK);
        let message = b"post-quantum message".to_vec();
        let signature = s.sign(&sk, &message, vec![]);
        assert_eq!(s.verify(&pk, &message, &signature, vec![]), 1, "{alg:#x}");
        let mut tampered = signature.clone();
        tampered[10] ^= 1;
        assert_eq!(s.verify(&pk, &message, &tampered, vec![]), 2);
        assert_eq!(s.verify(&pk, b"other", &signature, vec![]), 2);
        assert_eq!(
            s.verify(&pk, &message, &signature[..signature.len() - 1], vec![]),
            2
        );
        // Context strings (FIPS 204 / 205 ctx) bind the signature.
        let with_context = s.sign(&sk, &message, vec![context(b"kmip")]);
        assert_eq!(
            s.verify(&pk, &message, &with_context, vec![context(b"kmip")]),
            1
        );
        assert_eq!(s.verify(&pk, &message, &with_context, vec![]), 2);
        assert_eq!(
            s.verify(&pk, &message, &with_context, vec![context(b"pmik")]),
            2
        );
        // Deterministic signing repeats; hedged (the default) does not.
        let det = vec![Node::boolean(DETERMINISTIC, true)];
        assert_eq!(
            s.sign(&sk, &message, det.clone()),
            s.sign(&sk, &message, det)
        );
        if alg != SLH_DSA_SHAKE_128S {
            assert_ne!(s.sign(&sk, &message, vec![]), s.sign(&sk, &message, vec![]));
        }
        // Negative parameters.
        let long = vec![context(&[0; 256])];
        s.fails(
            V3,
            SIGN,
            sign_request(&sk, &message, long),
            0x24,
            "long context",
        );
        let internal = vec![Node::boolean(INTERNAL, true)];
        s.fails(
            V3,
            SIGN,
            sign_request(&sk, &message, internal),
            0x3e,
            "internal",
        );
        let random = vec![Node::bytes(RANDOM, vec![0; 32])];
        s.fails(
            V3,
            SIGN,
            sign_request(&sk, &message, random),
            0x3e,
            "random",
        );
        let other = vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, ML_DSA_65)];
        if alg != ML_DSA_65 {
            s.fails(
                V3,
                SIGN,
                sign_request(&sk, &message, other),
                0x24,
                "other algorithm",
            );
        }
        let hash = vec![Node::enumeration(HASHING_ALGORITHM, 6)];
        s.fails(V3, SIGN, sign_request(&sk, &message, hash), 8, "hash");
        let prehashed = vec![
            Node::reference(UNIQUE_IDENTIFIER, sk.as_str()),
            Node::bytes(DIGESTED_DATA, vec![0; 64]),
        ];
        s.fails(V3, SIGN, prehashed, 8, "Digested Data");
        // The public key does not sign; the private key does not verify.
        s.fails(
            V3,
            SIGN,
            sign_request(&pk, &message, vec![]),
            0x29,
            "public sign",
        );
    }
    // External mu: ML-DSA only, 64 bytes.
    let (sk, pk) = s.pair(ML_DSA_65, SIGN_MASK, VERIFY_MASK);
    let mu = vec![Node::boolean(EXTERNAL_MU, true)];
    let signature = s.sign(&sk, &[5; 64], mu.clone());
    assert_eq!(s.verify(&pk, &[5; 64], &signature, mu.clone()), 1);
    s.fails(
        V3,
        SIGN,
        sign_request(&sk, &[5; 63], mu.clone()),
        7,
        "short mu",
    );
    let (slh, _) = s.pair(SLH_DSA_SHA2_128F, SIGN_MASK, VERIFY_MASK);
    s.fails(V3, SIGN, sign_request(&slh, &[5; 64], mu), 0x24, "SLH mu");
    // Usage masks are enforced; ML-KEM keys do not sign.
    let (no_sign, _) = s.pair(ML_DSA_44, DECRYPT_MASK, VERIFY_MASK);
    s.fails(V3, SIGN, sign_request(&no_sign, b"m", vec![]), 0x29, "mask");
    let (kem, _) = s.pair(ML_KEM_512, SIGN_MASK, VERIFY_MASK);
    s.fails(V3, SIGN, sign_request(&kem, b"m", vec![]), 8, "KEM key");
}

#[test]
fn key_formats_convert_and_register_round_trip() {
    let mut s = server(false);
    let (sk, pk) = s.pair(ML_DSA_65, SIGN_MASK, VERIFY_MASK);
    let raw_private = s.bytes(&sk, RAW);
    let pkcs8 = s.bytes(&sk, PKCS8);
    let raw_public = s.bytes(&pk, RAW);
    let spki = s.bytes(&pk, X509);
    let seeded = s.get(&sk, SEED_PRIVATE_KEY);
    let seed = seeded
        .required(SEED)
        .unwrap()
        .byte_string()
        .unwrap()
        .to_vec();
    assert_eq!(seed.len(), 32);
    assert_eq!(
        seeded.required(KEY).unwrap().byte_string().unwrap(),
        raw_private
    );
    for (id, format) in [
        (&sk, PKCS1),
        (&sk, X509),
        (&pk, PKCS8),
        (&pk, SEED_PRIVATE_KEY),
    ] {
        s.fails(
            V3,
            GET,
            vec![
                Node::reference(UNIQUE_IDENTIFIER, id.as_str()),
                Node::enumeration(KEY_FORMAT_TYPE, format),
            ],
            0x10,
            "format",
        );
    }
    // Every private form registers back to the same key; every public form
    // to the same public key.
    let seed_only = Node::structure(KEY_MATERIAL, vec![Node::bytes(SEED, seed.clone())]);
    let key_only = Node::structure(KEY_MATERIAL, vec![Node::bytes(KEY, raw_private.clone())]);
    for (format, material) in [
        (RAW, Node::bytes(KEY_MATERIAL, raw_private.clone())),
        (PKCS8, Node::bytes(KEY_MATERIAL, pkcs8.clone())),
        (SEED_PRIVATE_KEY, seeded.clone()),
        (SEED_PRIVATE_KEY, seed_only),
        (SEED_PRIVATE_KEY, key_only),
    ] {
        let r = s.ok(
            V3,
            REGISTER,
            register(4, ML_DSA_65, SIGN_MASK, format, material),
        );
        let id = text(&r, UNIQUE_IDENTIFIER);
        assert_eq!(s.bytes(&id, RAW), raw_private, "format {format}");
        assert_eq!(number(s.attribute(&id, KEY_FORMAT_TYPE)), i64::from(format));
        assert_eq!(number(s.attribute(&id, CRYPTOGRAPHIC_LENGTH)), 4032 * 8);
    }
    for (format, material) in [(RAW, raw_public.clone()), (X509, spki.clone())] {
        let r = s.ok(
            V3,
            REGISTER,
            register(
                3,
                ML_DSA_65,
                VERIFY_MASK,
                format,
                Node::bytes(KEY_MATERIAL, material),
            ),
        );
        let id = text(&r, UNIQUE_IDENTIFIER);
        assert_eq!(s.bytes(&id, X509), spki);
    }
    // Negative: a seed that does not derive the key, wrong lengths, the wrong
    // parameter set, a PKCS#8 key of another algorithm.
    let mut other = raw_private.clone();
    other[100] ^= 1;
    let mismatched = Node::structure(
        KEY_MATERIAL,
        vec![Node::bytes(SEED, seed), Node::bytes(KEY, other)],
    );
    s.fails(
        V3,
        REGISTER,
        register(4, ML_DSA_65, 1, SEED_PRIVATE_KEY, mismatched),
        7,
        "seed",
    );
    let short = Node::bytes(KEY_MATERIAL, raw_public[1..].to_vec());
    s.fails(
        V3,
        REGISTER,
        register(3, ML_DSA_65, 2, RAW, short),
        7,
        "short",
    );
    let wrong_set = Node::bytes(KEY_MATERIAL, raw_public.clone());
    s.fails(
        V3,
        REGISTER,
        register(3, ML_DSA_44, 2, RAW, wrong_set),
        7,
        "set",
    );
    let as_spki = Node::bytes(KEY_MATERIAL, spki);
    s.fails(
        V3,
        REGISTER,
        register(3, ML_DSA_87, 2, X509, as_spki),
        7,
        "SPKI set",
    );
    let pkcs1 = Node::bytes(KEY_MATERIAL, pkcs8);
    s.fails(
        V3,
        REGISTER,
        register(4, ML_DSA_65, 1, PKCS1, pkcs1),
        0x10,
        "PKCS#1",
    );
    let (slh, _) = s.pair(SLH_DSA_SHA2_128F, SIGN_MASK, VERIFY_MASK);
    let slh_seed = Node::structure(KEY_MATERIAL, vec![Node::bytes(SEED, vec![0; 48])]);
    s.fails(
        V3,
        REGISTER,
        register(4, SLH_DSA_SHA2_128F, 1, SEED_PRIVATE_KEY, slh_seed),
        8,
        "SLH seed",
    );
    // An SLH-DSA private key has no seed field.
    let slh_seeded = s.get(&slh, SEED_PRIVATE_KEY);
    assert!(slh_seeded.get(SEED).is_none());
    assert_eq!(
        slh_seeded
            .required(KEY)
            .unwrap()
            .byte_string()
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn create_key_pair_seed_is_deterministic_and_checked() {
    let mut s = server(false);
    let with_seed = |alg: u32, seed: Vec<u8>| {
        let mut request = pair_request(alg, SIGN_MASK, VERIFY_MASK);
        request.push(Node::bytes(SEED, seed));
        request
    };
    let a = s.ok(V3, CREATE_KEY_PAIR, with_seed(ML_DSA_44, vec![1; 32]));
    let b = s.ok(V3, CREATE_KEY_PAIR, with_seed(ML_DSA_44, vec![1; 32]));
    let public = |s: &mut Server, r: &Node| s.bytes(&text(r, PUBLIC_KEY_UNIQUE_IDENTIFIER), RAW);
    assert_eq!(public(&mut s, &a), public(&mut s, &b));
    let k = s.ok(V3, CREATE_KEY_PAIR, with_seed(ML_KEM_768, vec![2; 64]));
    let seeded = s.get(&text(&k, PRIVATE_KEY_UNIQUE_IDENTIFIER), SEED_PRIVATE_KEY);
    assert_eq!(
        seeded.required(SEED).unwrap().byte_string().unwrap(),
        [2; 64]
    );
    s.fails(
        V3,
        CREATE_KEY_PAIR,
        with_seed(ML_DSA_44, vec![1; 31]),
        7,
        "length",
    );
    s.fails(
        V3,
        CREATE_KEY_PAIR,
        with_seed(SLH_DSA_SHA2_128F, vec![1; 48]),
        8,
        "SLH",
    );
    s.fails(V3, CREATE_KEY_PAIR, with_seed(4, vec![1; 32]), 8, "RSA");
    s.fails(
        V21,
        CREATE_KEY_PAIR,
        with_seed(ML_DSA_44, vec![1; 32]),
        8,
        "2.1",
    );
}

#[test]
fn ml_kem_encapsulate_decapsulate_create_shared_secrets() {
    let mut s = server(false);
    for (alg, ciphertext) in [(ML_KEM_512, 768), (ML_KEM_768, 1088), (ML_KEM_1024, 1568)] {
        let (dk, ek) = s.pair(alg, DECRYPT_MASK, ENCRYPT_MASK);
        let r = s.ok(
            V3,
            ENCAPSULATE,
            vec![
                Node::reference(UNIQUE_IDENTIFIER, ek.as_str()),
                Node::structure(ATTRIBUTES, vec![Node::text(OBJECT_GROUP, "kem")]),
            ],
        );
        let ct = r.required(DATA).unwrap().byte_string().unwrap().to_vec();
        assert_eq!(ct.len(), ciphertext);
        let encapsulated = text(&r, UNIQUE_IDENTIFIER);
        assert!(s.attribute(&encapsulated, OBJECT_GROUP).is_some());
        let secret = s.secret(&encapsulated);
        assert_eq!(secret.len(), 32);
        let r = s.ok(
            V3,
            DECAPSULATE,
            vec![
                Node::reference(UNIQUE_IDENTIFIER, dk.as_str()),
                Node::structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    vec![Node::enumeration(KEM_ALGORITHM, 3)],
                ),
                Node::bytes(DATA, ct.clone()),
            ],
        );
        let decapsulated = text(&r, UNIQUE_IDENTIFIER);
        assert_ne!(decapsulated, encapsulated);
        assert_eq!(s.secret(&decapsulated), secret);
        // A modified ciphertext of the right length gives the FIPS 203
        // implicit-rejection secret, not the shared one.
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        let r = s.ok(
            V3,
            DECAPSULATE,
            vec![
                Node::reference(UNIQUE_IDENTIFIER, dk.as_str()),
                Node::bytes(DATA, tampered),
            ],
        );
        assert_ne!(s.secret(&text(&r, UNIQUE_IDENTIFIER)), secret);
        // Negative cases.
        let decap = |id: &str, data: Vec<u8>| {
            vec![
                Node::reference(UNIQUE_IDENTIFIER, id),
                Node::bytes(DATA, data),
            ]
        };
        s.fails(V3, DECAPSULATE, decap(&dk, ct[1..].to_vec()), 7, "length");
        s.fails(
            V3,
            DECAPSULATE,
            decap(&ek, ct.clone()),
            0x30,
            "public decap",
        );
        s.fails(
            V3,
            ENCAPSULATE,
            vec![Node::reference(UNIQUE_IDENTIFIER, dk.as_str())],
            0x30,
            "private encap",
        );
        for (kem, reason) in [(1, 0x3e), (2, 0x3e), (9, 0x24)] {
            s.fails(
                V3,
                ENCAPSULATE,
                vec![
                    Node::reference(UNIQUE_IDENTIFIER, ek.as_str()),
                    Node::structure(
                        CRYPTOGRAPHIC_PARAMETERS,
                        vec![Node::enumeration(KEM_ALGORITHM, kem)],
                    ),
                ],
                reason,
                "KEM Algorithm",
            );
        }
    }
    // Key Agreement also qualifies; Sign alone does not.
    let (_, ek) = s.pair(ML_KEM_768, KEY_AGREEMENT_MASK, KEY_AGREEMENT_MASK);
    s.ok(
        V3,
        ENCAPSULATE,
        vec![Node::reference(UNIQUE_IDENTIFIER, ek.as_str())],
    );
    let (_, ek) = s.pair(ML_KEM_768, DECRYPT_MASK, SIGN_MASK);
    s.fails(
        V3,
        ENCAPSULATE,
        vec![Node::reference(UNIQUE_IDENTIFIER, ek.as_str())],
        0x29,
        "mask",
    );
    // Only ML-KEM keys encapsulate.
    let (_, dsa) = s.pair(ML_DSA_44, SIGN_MASK, ENCRYPT_MASK);
    s.fails(
        V3,
        ENCAPSULATE,
        vec![Node::reference(UNIQUE_IDENTIFIER, dsa.as_str())],
        0x3e,
        "ML-DSA",
    );
    // Encapsulate is not a 2.1 operation.
    s.fails(
        V21,
        ENCAPSULATE,
        vec![Node::text(UNIQUE_IDENTIFIER, ek.as_str())],
        5,
        "2.1",
    );
}

#[test]
fn rekey_key_pair_replaces_a_post_quantum_pair() {
    let mut s = server(false);
    let (sk, pk) = s.pair(ML_DSA_44, SIGN_MASK, VERIFY_MASK);
    let old = s.bytes(&pk, RAW);
    let r = s.ok(
        V3,
        REKEY_KEY_PAIR,
        vec![Node::reference(UNIQUE_IDENTIFIER, sk.as_str())],
    );
    let (nsk, npk) = (
        text(&r, PRIVATE_KEY_UNIQUE_IDENTIFIER),
        text(&r, PUBLIC_KEY_UNIQUE_IDENTIFIER),
    );
    assert_ne!(s.bytes(&npk, RAW), old);
    assert_eq!(number(s.attribute(&nsk, CRYPTOGRAPHIC_LENGTH)), 2560 * 8);
    assert_eq!(number(s.attribute(&npk, CRYPTOGRAPHIC_LENGTH)), 1312 * 8);
    // The replacements take over the Active state (Re-key Key Pair dates).
    let signature = s.sign(&nsk, b"rekeyed", vec![]);
    assert_eq!(s.verify(&npk, b"rekeyed", &signature, vec![]), 1);
    assert_eq!(s.verify(&pk, b"rekeyed", &signature, vec![]), 2);
}

#[test]
fn openssl_cli_cross_checks_signatures_and_kem() {
    let Some(dir) = cli() else { return };
    let d = dir.path();
    let mut s = server(false);
    // Server signs; the CLI verifies with the exported SubjectPublicKeyInfo.
    for (alg, name) in [
        (ML_DSA_65, "ML-DSA-65"),
        (SLH_DSA_SHA2_128F, "SLH-DSA-SHA2-128f"),
    ] {
        let (sk, pk) = s.pair(alg, SIGN_MASK, VERIFY_MASK);
        std::fs::write(d.join("pub.der"), s.bytes(&pk, X509)).unwrap();
        std::fs::write(d.join("msg"), b"cross-check").unwrap();
        std::fs::write(
            d.join("sig"),
            s.sign(&sk, b"cross-check", vec![context(b"abc")]),
        )
        .unwrap();
        let verify = |ctx: &str| {
            let mut args = vec![
                "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", "pub.der",
                "-in", "msg", "-sigfile", "sig",
            ];
            if !ctx.is_empty() {
                args.extend(["-pkeyopt", ctx]);
            }
            openssl(d, &args)
        };
        assert!(verify("context-string:abc"), "{name} CLI verify");
        assert!(!verify(""), "{name} without context");
        // CLI-generated key and signature, registered and verified here.
        assert!(openssl(
            d,
            &[
                "genpkey",
                "-algorithm",
                name,
                "-outform",
                "DER",
                "-out",
                "k.der"
            ]
        ));
        assert!(openssl(
            d,
            &[
                "pkey", "-inform", "DER", "-in", "k.der", "-pubout", "-outform", "DER", "-out",
                "kp.der"
            ]
        ));
        assert!(openssl(
            d,
            &[
                "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", "k.der", "-in", "msg",
                "-out", "csig"
            ]
        ));
        let r = s.ok(
            V3,
            REGISTER,
            register(
                3,
                alg,
                VERIFY_MASK,
                X509,
                Node::bytes(KEY_MATERIAL, std::fs::read(d.join("kp.der")).unwrap()),
            ),
        );
        let id = text(&r, UNIQUE_IDENTIFIER);
        s.ok(
            V3,
            ACTIVATE,
            vec![Node::reference(UNIQUE_IDENTIFIER, id.as_str())],
        );
        let csig = std::fs::read(d.join("csig")).unwrap();
        assert_eq!(
            s.verify(&id, b"cross-check", &csig, vec![]),
            1,
            "{name} CLI signature"
        );
        // The CLI's PKCS#8 private key signs here; the CLI verifies.
        let r = s.ok(
            V3,
            REGISTER,
            register(
                4,
                alg,
                SIGN_MASK,
                PKCS8,
                Node::bytes(KEY_MATERIAL, std::fs::read(d.join("k.der")).unwrap()),
            ),
        );
        let id = text(&r, UNIQUE_IDENTIFIER);
        s.ok(
            V3,
            ACTIVATE,
            vec![Node::reference(UNIQUE_IDENTIFIER, id.as_str())],
        );
        std::fs::write(d.join("sig"), s.sign(&id, b"cross-check", vec![])).unwrap();
        assert!(openssl(
            d,
            &[
                "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", "kp.der",
                "-in", "msg", "-sigfile", "sig"
            ]
        ));
    }
    // ML-KEM: the CLI encapsulates to the server's key; the server
    // decapsulates. The server encapsulates; the CLI decapsulates with the
    // exported PKCS#8 key.
    let (dk, ek) = s.pair(ML_KEM_768, DECRYPT_MASK, ENCRYPT_MASK);
    std::fs::write(d.join("ek.der"), s.bytes(&ek, X509)).unwrap();
    std::fs::write(d.join("dk.der"), s.bytes(&dk, PKCS8)).unwrap();
    assert!(openssl(
        d,
        &[
            "pkeyutl", "-encap", "-pubin", "-keyform", "DER", "-inkey", "ek.der", "-out", "ct",
            "-secret", "ss"
        ]
    ));
    let r = s.ok(
        V3,
        DECAPSULATE,
        vec![
            Node::reference(UNIQUE_IDENTIFIER, dk.as_str()),
            Node::bytes(DATA, std::fs::read(d.join("ct")).unwrap()),
        ],
    );
    assert_eq!(
        s.secret(&text(&r, UNIQUE_IDENTIFIER)),
        std::fs::read(d.join("ss")).unwrap()
    );
    let r = s.ok(
        V3,
        ENCAPSULATE,
        vec![Node::reference(UNIQUE_IDENTIFIER, ek.as_str())],
    );
    std::fs::write(
        d.join("ct2"),
        r.required(DATA).unwrap().byte_string().unwrap(),
    )
    .unwrap();
    let secret = s.secret(&text(&r, UNIQUE_IDENTIFIER));
    assert!(openssl(
        d,
        &[
            "pkeyutl", "-decap", "-keyform", "DER", "-inkey", "dk.der", "-in", "ct2", "-secret",
            "ss2"
        ]
    ));
    assert_eq!(std::fs::read(d.join("ss2")).unwrap(), secret);
}

/// Known answer through the KMIP path: FIPS 204 ML-DSA-65 key generation
/// from the KAT seed xi (Create Key Pair Seed, draft 3.0 Table 283) and a
/// deterministic pure signature with a context string (Table 93) reproduce
/// the published signature byte for byte (tests/pq-kat.json).
#[test]
fn ml_dsa_65_deterministic_known_answer() {
    let kat: serde_json::Value = serde_json::from_str(include_str!("pq-kat.json")).unwrap();
    let field = |name: &str| hex::decode(kat[name].as_str().unwrap()).unwrap();
    let mut s = server(false);
    let mut request = pair_request(ML_DSA_65, SIGN_MASK, VERIFY_MASK);
    request.push(Node::bytes(SEED, field("xi")));
    let r = s.ok(V3, CREATE_KEY_PAIR, request);
    let (sk, pk) = (
        text(&r, PRIVATE_KEY_UNIQUE_IDENTIFIER),
        text(&r, PUBLIC_KEY_UNIQUE_IDENTIFIER),
    );
    for id in [&sk, &pk] {
        s.ok(
            V3,
            ACTIVATE,
            vec![Node::reference(UNIQUE_IDENTIFIER, id.as_str())],
        );
    }
    let options = vec![
        Node::boolean(DETERMINISTIC, true),
        context(&field("context")),
    ];
    let signature = s.sign(&sk, &field("message"), options.clone());
    assert_eq!(hex::encode(&signature), kat["signature"].as_str().unwrap());
    assert_eq!(s.verify(&pk, &field("message"), &signature, options), 1);
}
