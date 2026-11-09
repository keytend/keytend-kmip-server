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

//! NIST SP 800-38A appendix F, AES examples. Fixed expected bytes, not round trips alone.
//! https://doi.org/10.6028/NIST.SP.800-38A
use keytend_kmip_server::{
    codes::{block_mode::*, padding},
    crypto::{AesParameters, aes},
};

fn bytes(s: &str) -> Vec<u8> {
    hex::decode(s.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn nist_sp800_38a_block_and_stream_modes() {
    let plaintext = bytes(
        "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51
        30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710",
    );
    let iv = bytes("000102030405060708090a0b0c0d0e0f");
    let counter = bytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let key = bytes("2b7e151628aed2a6abf7158809cf4f3c");
    let examples = [
        (
            ECB,
            "3ad77bb40d7a3660a89ecaf32466ef97 f5d3d58503b9699de785895a96fdbaaf
            43b1cd7f598ece23881b00e3ed030688 7b0c785e27e8ad3f8223207104725dd4",
        ),
        (
            CBC,
            "7649abac8119b246cee98e9b12e9197d 5086cb9b507219ee95db113a917678b2
            73bed6b8e3c1743b7116e69e22229516 3ff1caa1681fac09120eca307586e1a7",
        ),
        (
            CFB,
            "3b3fd92eb72dad20333449f8e83cfb4a c8a64537a0b3a93fcde3cdad9f1ce58b
            26751f67a3cbb140b1808cf187a4f4df c04b05357c5d1c0eeac4c66f9ff7f2e6",
        ),
        (
            OFB,
            "3b3fd92eb72dad20333449f8e83cfb4a 7789508d16918f03f53c52dac54ed825
            9740051e9c5fecf64344f7a82260edcc 304c6528f659c77866a510d9c1d6ae5e",
        ),
        (
            CTR,
            "874d6191b620e3261bef6864990db6ce 9806f66b7970fdff8617187bb9fffdff
            5ae4df3edbd5d35e5b4f09020db03eab 1e031dda2fbe03d1792170a0f3009cee",
        ),
    ];
    for (mode, expected) in examples {
        let iv = if mode == ECB {
            &[][..]
        } else if mode == CTR {
            &counter
        } else {
            &iv
        };
        let params = AesParameters {
            mode,
            padding: padding::NONE,
            tag_len: 16,
        };
        let ciphertext = bytes(expected);
        assert_eq!(
            &*aes(true, &key, params, iv, &plaintext, &[], None)
                .unwrap()
                .0,
            &ciphertext,
            "mode {mode}"
        );
        assert_eq!(
            &*aes(false, &key, params, iv, &ciphertext, &[], None)
                .unwrap()
                .0,
            &plaintext,
            "mode {mode}"
        );
        if matches!(mode, CFB | OFB | CTR) {
            assert_eq!(
                &*aes(true, &key, params, iv, &plaintext[..37], &[], None)
                    .unwrap()
                    .0,
                &ciphertext[..37]
            );
            assert_eq!(
                &*aes(false, &key, params, iv, &ciphertext[..37], &[], None)
                    .unwrap()
                    .0,
                &plaintext[..37]
            );
        }
    }
    for (key, ciphertext) in [
        (
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "4f021db243bc633d7178183a9fa071e8 b4d9ada9ad7dedf4e5e738763f69145a
            571b242012fb7ae07fa9baac3df102e0 08b0e27988598881d920a9e64f5615cd",
        ),
        (
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d
            39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b",
        ),
    ] {
        let params = AesParameters {
            mode: CBC,
            padding: padding::NONE,
            tag_len: 16,
        };
        let expected = bytes(ciphertext);
        let key = bytes(key);
        assert_eq!(
            &*aes(true, &key, params, &iv, &plaintext, &[], None)
                .unwrap()
                .0,
            &expected
        );
        assert_eq!(
            &*aes(false, &key, params, &iv, &expected, &[], None)
                .unwrap()
                .0,
            &plaintext
        );
    }
}

#[test]
fn nist_gcm_tag_lengths_are_bytes_and_tampering_returns_no_plaintext() {
    // SP 800-38D zero-key example, also in the OASIS CS-BC-M-GCM traces.
    let key = [0; 16];
    let iv = [0; 12];
    let plaintext = [0; 16];
    let expected = bytes("0388dace60b6a392f328c2b971b2fe78");
    let full_tag = bytes("ab6e47d42cec13bdf53a67b21257bddf");
    for tag_len in [4, 8, 12, 13, 14, 15, 16] {
        let params = AesParameters {
            mode: GCM,
            padding: padding::NONE,
            tag_len,
        };
        let (ciphertext, tag) = aes(true, &key, params, &iv, &plaintext, &[], None).unwrap();
        assert_eq!(&*ciphertext, &expected);
        assert_eq!(tag, &full_tag[..tag_len]);
        assert_eq!(
            &*aes(false, &key, params, &iv, &ciphertext, &[], Some(&tag))
                .unwrap()
                .0,
            &plaintext
        );
        let mut bad = tag.clone();
        bad[0] ^= 1;
        let mut wrong_iv = iv;
        wrong_iv[0] ^= 1;
        assert!(aes(false, &key, params, &wrong_iv, &ciphertext, &[], Some(&tag)).is_err());
        let mut wrong_ciphertext = ciphertext.to_vec();
        wrong_ciphertext[0] ^= 1;
        assert!(aes(false, &key, params, &iv, &wrong_ciphertext, &[], Some(&tag)).is_err());
        assert!(aes(false, &key, params, &iv, &ciphertext, &[], Some(&bad)).is_err());
        assert!(
            aes(
                false,
                &key,
                params,
                &iv,
                &ciphertext,
                b"wrong aad",
                Some(&tag)
            )
            .is_err()
        );
        assert!(
            aes(
                false,
                &key,
                params,
                &iv,
                &ciphertext,
                &[],
                Some(&tag[..tag_len - 1])
            )
            .is_err()
        );
    }
    for tag_len in [0, 1, 11, 17, 128] {
        assert!(
            aes(
                true,
                &key,
                AesParameters {
                    mode: GCM,
                    padding: padding::NONE,
                    tag_len
                },
                &iv,
                &plaintext,
                &[],
                None
            )
            .is_err()
        );
    }
    for mode in [ECB, CBC, CFB, OFB, CTR] {
        let iv = if mode == ECB { vec![] } else { vec![0; 16] };
        assert!(
            aes(
                true,
                &key,
                AesParameters {
                    mode,
                    padding: padding::NONE,
                    tag_len: 16
                },
                &iv,
                &plaintext,
                b"aad",
                None
            )
            .is_err()
        );
    }
}
