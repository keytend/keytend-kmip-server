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

use keytend_kmip_server::crypto::wrapping::aes;

#[test]
fn published_rfc3394_and_rfc5649_vectors() {
    let vectors = [
        (
            "000102030405060708090A0B0C0D0E0F",
            "00112233445566778899AABBCCDDEEFF",
            "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
            false,
        ),
        (
            "000102030405060708090A0B0C0D0E0F1011121314151617",
            "00112233445566778899AABBCCDDEEFF",
            "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
            false,
        ),
        (
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "00112233445566778899AABBCCDDEEFF",
            "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
            false,
        ),
        (
            "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
            "c37b7e6492584340bed12207808941155068f738",
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            true,
        ),
        (
            "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
            "466f7250617369",
            "afbeb0f07dfbf5419200f2ccb50bb24f",
            true,
        ),
    ];
    for (key, plain, cipher, padded) in vectors {
        let key = hex::decode(key).unwrap();
        let plain = hex::decode(plain).unwrap();
        let cipher = hex::decode(cipher).unwrap();
        assert_eq!(aes(&key, &plain, padded, true).unwrap().as_slice(), cipher);
        assert_eq!(aes(&key, &cipher, padded, false).unwrap().as_slice(), plain);
    }
}
#[test]
fn aes_wrapping_rejects_corruption_invalid_lengths_and_wrong_keys() {
    for padded in [false, true] {
        let key = [3; 32];
        let ciphertext = aes(&key, &[7; 32], padded, true).unwrap();
        for i in 0..ciphertext.len() {
            let mut damaged = ciphertext.to_vec();
            damaged[i] ^= 1;
            assert!(aes(&key, &damaged, padded, false).is_err());
        }
        assert!(aes(&[4; 32], &ciphertext, padded, false).is_err());
        for n in 0..16 {
            assert!(aes(&key, &vec![0; n], padded, false).is_err());
        }
        assert!(aes(&[1; 15], &ciphertext, padded, false).is_err());
    }
    assert!(aes(&[1; 16], &[2; 8], false, true).is_err());
    assert!(aes(&[1; 16], &[2; 17], false, true).is_err());
    assert!(aes(&[1; 16], &[], true, true).is_err());
    assert!(
        aes(
            &[1; 16],
            &vec![0; keytend_kmip_server::ttlv::MAX_FRAME + 1],
            true,
            true
        )
        .is_err()
    );
}
