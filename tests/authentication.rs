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

use keytend_kmip_server::crypto::{
    authentication::{self, Mechanism},
    stream,
};
#[test]
fn hmac_all_algorithms_long_keys_empty_messages_and_copy_isolation_match_python() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hmac-independent.json")).unwrap();
    for v in data["vectors"].as_array().unwrap() {
        let mechanism = Mechanism::Hmac(
            authentication::hmac_hash(v["algorithm"].as_u64().unwrap() as u32).unwrap(),
        );
        let key = hex::decode(v["key"].as_str().unwrap()).unwrap();
        let message = hex::decode(v["data"].as_str().unwrap()).unwrap();
        let expected = hex::decode(v["mac"].as_str().unwrap()).unwrap();
        assert_eq!(
            authentication::compute(mechanism, &key, &message).unwrap(),
            expected
        );
        for chunk_size in [1, 7, 16, 64, 143, 512] {
            let mut mac = stream::Mac::new(mechanism, &key).unwrap();
            for chunk in message.chunks(chunk_size) {
                mac.update(&[]).unwrap();
                mac.update(chunk).unwrap();
            }
            let mut snapshot = mac.try_clone().unwrap();
            mac.update(b"discarded trial suffix").unwrap();
            assert_eq!(
                snapshot.finish().unwrap(),
                expected,
                "algorithm {} chunk {}",
                v["hash"],
                chunk_size
            );
        }
    }
}
#[test]
fn cmac_matches_rfc4493_and_independent_provider_for_all_key_sizes_and_chunk_boundaries() {
    // RFC 4493 section 4: all four full AES-CMAC tags, including empty input.
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let message = hex::decode(concat!(
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "f69f2445df4f9b17ad2b417be66c3710"
    ))
    .unwrap();
    for (length, expected) in [
        (0, "bb1d6929e95937287fa37d129b756746"),
        (16, "070a16b46b4d4144f79bdd9dd04a287c"),
        (40, "dfa66747de9ae63030ca32611497c827"),
        (64, "51f0bebf7e3b9d92fc49741779363cfe"),
    ] {
        for chunk in 1..=65 {
            let mut mac = stream::Mac::new(Mechanism::Cmac, &key).unwrap();
            for data in message[..length].chunks(chunk) {
                mac.update(data).unwrap();
                mac.update(&[]).unwrap();
            }
            assert_eq!(hex::encode(mac.finish().unwrap()), expected);
        }
    }
    for length in [16, 24, 32] {
        let key = vec![0xa7; length];
        for n in [0, 1, 15, 16, 17, 31, 32, 33, 64, 127, 128, 129, 1024, 4097] {
            let data = (0..n).map(|i| i as u8).collect::<Vec<_>>();
            let expected = authentication::compute(Mechanism::Cmac, &key, &data).unwrap();
            for chunk in [1, 7, 16, 17, 64, 128, 300] {
                let mut mac = stream::Mac::new(Mechanism::Cmac, &key).unwrap();
                for bytes in data.chunks(chunk) {
                    mac.update(bytes).unwrap();
                }
                let mut snapshot = mac.try_clone().unwrap();
                mac.update(b"rejected suffix").unwrap();
                assert_eq!(snapshot.finish().unwrap(), expected);
            }
        }
    }
    for length in [0, 1, 15, 17, 23, 25, 31, 33] {
        assert!(stream::Mac::new(Mechanism::Cmac, &vec![0; length]).is_err());
    }
}
