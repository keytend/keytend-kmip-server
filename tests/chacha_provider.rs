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

use keytend_kmip_server::crypto::chacha::{Context, Parameters, crypt};
// Published key, nonce, AAD, plaintext, ciphertext and authentication tag.
type PublishedVector = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}
const RAW: Parameters = Parameters {
    authenticated: false,
    initial_counter: 0,
};
const AEAD: Parameters = Parameters {
    authenticated: true,
    initial_counter: 0,
};
// Numeric vectors: RFC 8439 sections 2.3.2 and 2.8.2; latter is also
// OASIS KMIP 2.1 CS-BC-M-CHACHA20POLY1305-1-21. No provider-generated oracle.
// RFC 8439 copyright (c) 2018 IETF Trust and its identified authors.
fn fixture() -> PublishedVector {
    (
        bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
        bytes("070000004041424344454647"),
        bytes("50515253c0c1c2c3c4c5c6c7"),
        bytes(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        ),
        bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        ),
        bytes("1ae10b594f09e26a7e902ecbd0600691"),
    )
}
#[test]
fn published_raw_original_and_ietf_blocks() {
    let original = bytes(
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
    );
    for nonce in [vec![0; 8], vec![0; 12]] {
        let (out, tag) = crypt(true, &[0; 32], RAW, &nonce, &[0; 64], &[], None).unwrap();
        assert_eq!(&*out, &original);
        assert!(tag.is_empty());
        assert_eq!(
            &*crypt(false, &[0; 32], RAW, &nonce, &out, &[], None)
                .unwrap()
                .0,
            &[0; 64]
        );
    }
    let key: Vec<u8> = (0..32).collect();
    let nonce = bytes("000000090000004a00000000");
    let expected = bytes(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e",
    );
    assert_eq!(
        &*crypt(
            true,
            &key,
            Parameters {
                initial_counter: 1,
                ..RAW
            },
            &nonce,
            &[0; 64],
            &[],
            None
        )
        .unwrap()
        .0,
        &expected
    );
}
#[test]
fn published_aead_and_independent_tampering_fail_closed() {
    let (key, nonce, aad, plain, cipher, tag) = fixture();
    let (out, actual_tag) = crypt(true, &key, AEAD, &nonce, &plain, &aad, None).unwrap();
    assert_eq!(&*out, &cipher);
    assert_eq!(actual_tag, tag);
    assert_eq!(
        &*crypt(false, &key, AEAD, &nonce, &cipher, &aad, Some(&tag))
            .unwrap()
            .0,
        &plain
    );
    for which in 0..5 {
        let (mut k, mut n, mut a, _, mut c, mut t) = fixture();
        match which {
            0 => k[0] ^= 1,
            1 => n[0] ^= 1,
            2 => a[0] ^= 1,
            3 => c[0] ^= 1,
            _ => t[0] ^= 1,
        }
        assert!(crypt(false, &k, AEAD, &n, &c, &a, Some(&t)).is_err());
    }
}
#[test]
fn cloned_multipart_snapshots_and_authentication_release() {
    let (key, nonce, aad, plain, cipher, tag) = fixture();
    let mut context = Context::new(true, &key, AEAD, &nonce, &aad, None).unwrap();
    let prefix = context.update(&plain[..17], false).unwrap().0;
    let mut snapshot = context.try_clone().unwrap();
    let (tail, mac) = context.update(&plain[17..], true).unwrap();
    assert_eq!([prefix.to_vec(), tail.to_vec()].concat(), cipher);
    assert_eq!(mac, tag);
    let (mid, _) = snapshot.update(&plain[17..64], false).unwrap();
    let (end, mac) = snapshot.update(&plain[64..], true).unwrap();
    assert_eq!(
        [prefix.to_vec(), mid.to_vec(), end.to_vec()].concat(),
        cipher
    );
    assert_eq!(mac, tag);
    assert!(snapshot.update(&[], true).is_err());
    let mut dec = Context::new(false, &key, AEAD, &nonce, &aad, Some(&tag)).unwrap();
    assert!(dec.update(&cipher[..61], false).unwrap().0.is_empty());
    assert_eq!(dec.retained(), 61);
    let mut copy = dec.try_clone().unwrap();
    assert_eq!(&*dec.update(&cipher[61..], true).unwrap().0, &plain);
    assert_eq!(&*copy.update(&cipher[61..], true).unwrap().0, &plain);
    let mut bad = tag.clone();
    bad[0] ^= 1;
    let mut dec = Context::new(false, &key, AEAD, &nonce, &aad, Some(&bad)).unwrap();
    assert!(dec.update(&cipher[..61], false).unwrap().0.is_empty());
    assert!(dec.update(&cipher[61..], true).is_err());
    assert!(dec.update(&[], true).is_err());
}
#[test]
fn counter_bounds_and_invalid_parameters_are_checked_before_provider_use() {
    for (nonce, counter) in [(vec![0; 12], u32::MAX as u64), (vec![0; 8], u64::MAX)] {
        let p = Parameters {
            initial_counter: counter,
            ..RAW
        };
        assert!(crypt(true, &[0; 32], p, &nonce, &[0; 65], &[], None).is_err());
        assert_eq!(
            crypt(true, &[0; 32], p, &nonce, &[0; 64], &[], None)
                .unwrap()
                .0
                .len(),
            64
        );
        let mut ctx = Context::new(true, &[0; 32], p, &nonce, &[], None).unwrap();
        assert_eq!(ctx.update(&[0; 63], false).unwrap().0.len(), 63);
        assert!(ctx.update(&[0; 2], false).is_err());
        assert_eq!(ctx.update(&[0; 1], true).unwrap().0.len(), 1);
    }
    assert!(
        crypt(
            true,
            &[0; 32],
            Parameters {
                initial_counter: u32::MAX as u64,
                ..RAW
            },
            &[0; 8],
            &[0; 128],
            &[],
            None
        )
        .is_ok()
    );
    assert!(
        Context::new(
            true,
            &[0; 32],
            Parameters {
                initial_counter: u32::MAX as u64 + 1,
                ..RAW
            },
            &[0; 12],
            &[],
            None
        )
        .is_err()
    );
    for nonce in [vec![], vec![0; 7], vec![0; 9], vec![0; 16]] {
        assert!(Context::new(true, &[0; 32], RAW, &nonce, &[], None).is_err());
    }
    assert!(Context::new(true, &[0; 31], RAW, &[0; 8], &[], None).is_err());
    assert!(Context::new(true, &[0; 32], RAW, &[0; 8], &[1], None).is_err());
    assert!(Context::new(true, &[0; 32], RAW, &[0; 8], &[], Some(&[0; 16])).is_err());
    for len in [0, 1, 12, 15, 17, 32] {
        assert!(Context::new(false, &[0; 32], AEAD, &[0; 12], &[], Some(&vec![0; len])).is_err());
    }
    assert!(
        Context::new(
            true,
            &[0; 32],
            Parameters {
                initial_counter: 1,
                ..AEAD
            },
            &[0; 12],
            &[],
            None
        )
        .is_err()
    );
    assert!(Context::new(true, &[0; 32], AEAD, &[0; 8], &[], None).is_err());
}
#[test]
fn authenticated_stream_prefix_bound_does_not_limit_complete_requests() {
    let size = keytend_kmip_server::crypto::stream::MAX_AUTHENTICATED_PLAINTEXT;
    let plain = vec![42; size + 1];
    let key = [1; 32];
    let nonce = [2; 12];
    let (cipher, tag) = crypt(true, &key, AEAD, &nonce, &plain, &[], None).unwrap();
    assert_eq!(
        &*crypt(false, &key, AEAD, &nonce, &cipher, &[], Some(&tag))
            .unwrap()
            .0,
        &plain
    );
    let mut dec = Context::new(false, &key, AEAD, &nonce, &[], Some(&tag)).unwrap();
    assert!(dec.update(&cipher[..size], false).unwrap().0.is_empty());
    assert_eq!(dec.retained(), size);
    assert!(dec.update(&cipher[size..], true).is_err());
}
