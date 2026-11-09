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

use keytend_kmip_server::crypto::derivation::{self, CounterLocation, KbkdfParameters, Mode, Prf};
use serde_json::Value;
#[test]
fn nist_cavp_kbkdf_vectors_all_three_modes_hmac_hashes_aes_sizes_and_counter_widths() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/nist-sp800-108.json")).unwrap();
    for v in fixture["vectors"].as_array().unwrap() {
        let mode = match v["mode"].as_str().unwrap() {
            "counter" => Mode::Counter,
            "feedback" => Mode::Feedback,
            _ => Mode::DoublePipeline,
        };
        let prf = match v["prf"].as_str().unwrap() {
            "HMAC_SHA1" => Prf::Hmac(4),
            "HMAC_SHA224" => Prf::Hmac(5),
            "HMAC_SHA256" => Prf::Hmac(6),
            "HMAC_SHA384" => Prf::Hmac(7),
            "HMAC_SHA512" => Prf::Hmac(8),
            _ => Prf::Cmac,
        };
        let decode = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
        let key = decode("input_key");
        let fixed = decode("fixed_input");
        let iv = decode("iv");
        let expected = decode("output");
        let actual = derivation::sp800108(
            &key,
            KbkdfParameters {
                mode,
                prf,
                fixed: &fixed,
                iv: &iv,
                counter_bytes: v["counter_bytes"].as_u64().unwrap() as usize,
                counter_location: CounterLocation::AfterIteration,
            },
            expected.len(),
        )
        .unwrap();
        assert_eq!(actual.as_slice(), expected, "CAVP vector {v}");
    }
}
#[test]
fn rfc5869_extract_and_expand_vectors_and_output_limit() {
    let vectors = [
        (
            vec![0x0b; 22],
            hex::decode("000102030405060708090a0b0c").unwrap(),
            hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap(),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        ),
        (
            vec![0x0b; 22],
            vec![],
            vec![],
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        ),
        (
            (0x00..=0x4f).collect(),
            (0x60..=0xaf).collect(),
            (0xb0..=0xff).collect(),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        ),
    ];
    for (key, salt, info, expected) in vectors {
        let expected = hex::decode(expected).unwrap();
        assert_eq!(
            derivation::hkdf(6, &key, &salt, &info, expected.len())
                .unwrap()
                .as_slice(),
            expected
        );
    }
    assert!(derivation::hkdf(6, b"key", b"", b"", 8160).is_ok());
    assert!(derivation::hkdf(6, b"key", b"", b"", 8161).is_err());
}
#[test]
fn rfc6070_and_rfc7914_pbkdf2_vectors_and_work_limits() {
    for (iterations, expected) in [
        (1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        (2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        (4096, "4b007901b765489abead49d926f721d065a429c1"),
    ] {
        assert_eq!(
            hex::encode(derivation::pbkdf2(4, b"password", b"salt", iterations, 20).unwrap()),
            expected
        );
    }
    assert_eq!(
        hex::encode(derivation::pbkdf2(4, b"pass\0word", b"sa\0lt", 4096, 16).unwrap()),
        "56fa6aa75548099dcc37d7f03425e0c3"
    );
    assert_eq!(
        hex::encode(derivation::pbkdf2(6, b"passwd", b"salt", 1, 64).unwrap()),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    );
    assert!(derivation::pbkdf2(6, b"", b"", 0, 32).is_err());
    assert!(derivation::pbkdf2(6, b"", b"", usize::MAX, 32).is_err());
    assert!(derivation::pbkdf2(6, b"", b"", 1_000_001, 64).is_err());
}
#[test]
fn kbkdf_counter_bounds_iv_constraints_and_truncation() {
    let key = [3; 16];
    let fixed = b"label\0context";
    let derive = |mode, prf, iv: &[u8], counter_bytes, len| {
        derivation::sp800108(
            &key,
            KbkdfParameters {
                mode,
                prf,
                fixed,
                iv,
                counter_bytes,
                counter_location: CounterLocation::AfterIteration,
            },
            len,
        )
    };
    assert!(derive(Mode::Counter, Prf::Cmac, b"", 1, 255 * 16).is_ok());
    assert!(derive(Mode::Counter, Prf::Cmac, b"", 1, 255 * 16 + 1).is_err());
    assert!(derive(Mode::Counter, Prf::Cmac, b"iv", 4, 32).is_err());
    assert!(derive(Mode::Feedback, Prf::Cmac, b"iv", 4, 32).is_err());
    assert!(derive(Mode::Counter, Prf::Cmac, b"", 0, 32).is_err());
    let full = derive(Mode::DoublePipeline, Prf::Hmac(6), b"", 4, 64).unwrap();
    let short = derive(Mode::DoublePipeline, Prf::Hmac(6), b"", 4, 37).unwrap();
    assert_eq!(&full[..37], short.as_slice());
}
