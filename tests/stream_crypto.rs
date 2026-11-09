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

use keytend_kmip_server::crypto::{self, stream};

#[test]
fn all_supported_aes_streams_match_one_shot_over_uneven_chunks_and_copied_contexts() {
    for length in [16, 24, 32] {
        for mode in [1, 2, 4, 5, 6, 9] {
            for padding in if [1, 2].contains(&mode) {
                vec![1, 3]
            } else {
                vec![1]
            } {
                let key = vec![7; length];
                let iv = if mode == 2 {
                    vec![]
                } else if mode == 9 {
                    vec![3; 19]
                } else {
                    vec![3; 16]
                };
                let aad = if mode == 9 {
                    b"authenticated stream".as_slice()
                } else {
                    &[]
                };
                let parameters = crypto::AesParameters {
                    mode,
                    padding,
                    tag_len: 12,
                };
                let message = (0..256).map(|i| i as u8).collect::<Vec<_>>();
                let (expected, tag) =
                    crypto::aes(true, &key, parameters, &iv, &message, aad, None).unwrap();
                let mut encrypt = stream::Aes::new(true, &key, parameters, &iv, aad, None).unwrap();
                let mut ciphertext = vec![];
                let mut actual_tag = vec![];
                for chunk in message.chunks(7) {
                    let mut next = encrypt.try_clone().unwrap();
                    let (out, auth) = next.update(chunk, false).unwrap();
                    assert!(auth.is_empty());
                    ciphertext.extend_from_slice(&out);
                    encrypt = next;
                }
                let (out, auth) = encrypt.update(&[], true).unwrap();
                ciphertext.extend_from_slice(&out);
                actual_tag.extend_from_slice(&auth);
                assert_eq!(ciphertext, expected.as_slice());
                assert_eq!(actual_tag, tag);
                let mut decrypt = stream::Aes::new(
                    false,
                    &key,
                    parameters,
                    &iv,
                    aad,
                    if mode == 9 { Some(&tag) } else { None },
                )
                .unwrap();
                let mut plaintext = vec![];
                for chunk in ciphertext.chunks(11) {
                    let mut next = decrypt.try_clone().unwrap();
                    let (out, auth) = next.update(chunk, false).unwrap();
                    assert!(auth.is_empty());
                    if mode == 9 {
                        assert!(out.is_empty());
                    }
                    plaintext.extend_from_slice(&out);
                    decrypt = next;
                }
                let (out, _) = decrypt.update(&[], true).unwrap();
                plaintext.extend_from_slice(&out);
                assert_eq!(plaintext, message);
            }
        }
    }
}
#[test]
fn unauthenticated_gcm_never_releases_plaintext_and_snapshots_are_independent() {
    let parameters = crypto::AesParameters {
        mode: 9,
        padding: 1,
        tag_len: 16,
    };
    let key = [3; 32];
    let iv = [7; 12];
    let message = vec![9; 123];
    let (ciphertext, mut tag) =
        crypto::aes(true, &key, parameters, &iv, &message, b"aad", None).unwrap();
    tag[0] ^= 1;
    let mut stream = stream::Aes::new(false, &key, parameters, &iv, b"aad", Some(&tag)).unwrap();
    assert!(
        stream
            .update(&ciphertext[..64], false)
            .unwrap()
            .0
            .is_empty()
    );
    let mut trial = stream.try_clone().unwrap();
    assert!(trial.update(&ciphertext[64..], true).is_err());
    assert_eq!(stream.retained(), 64);
    let mut bounded = stream::Aes::new(false, &key, parameters, &iv, b"aad", Some(&tag)).unwrap();
    assert!(
        bounded
            .update(&vec![0; stream::MAX_AUTHENTICATED_PLAINTEXT + 1], false)
            .is_err()
    );
}
#[test]
fn incremental_hmac_matches_rfc4231_and_independent_provider_hmac() {
    // RFC 4231 test case 1, HMAC-SHA-256, SHA-384 and SHA-512.
    let vectors = [
        (
            6,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        (
            7,
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        ),
        (
            8,
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        ),
    ];
    for (hash, expected) in vectors {
        let mut mac = stream::Hmac::new(hash, &[0x0b; 20]).unwrap();
        mac.update(b"Hi ").unwrap();
        let mut copy = mac.clone();
        copy.update(b"There").unwrap();
        assert_eq!(
            hex::encode(copy.finish().unwrap()),
            expected.replace(' ', "")
        );
    }
    for hash in [6, 7, 8] {
        for keylen in [1, 64, 128, 131, 300] {
            let key = vec![0xaa; keylen];
            let message = vec![0xdd; 5 * 1024];
            let mut mac = stream::Hmac::new(hash, &key).unwrap();
            for chunk in message.chunks(13) {
                mac.update(chunk).unwrap();
            }
            assert_eq!(
                mac.finish().unwrap(),
                crypto::mac(hash, &key, &message).unwrap()
            );
        }
    }
}
