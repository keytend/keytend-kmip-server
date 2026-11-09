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

use keytend_kmip_server::crypto::rsa::{self, SignatureParameters};
use openssl::{
    hash::{MessageDigest, hash},
    pkey::PKey,
    rsa::Rsa,
    sign::Verifier,
};

#[test]
fn prehashed_pkcs1_matches_message_signing_without_hashing_twice() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let private = key.private_key_to_pkcs8().unwrap();
    let public = key.public_key_to_der().unwrap();
    let parameters = SignatureParameters {
        hash: 6,
        pss: false,
        mgf_hash: 4,
        salt_len: 0,
    };
    let message = b"independent message verification";
    let digest = hash(MessageDigest::sha256(), message).unwrap();
    let a = rsa::sign(&private, parameters, message, false).unwrap();
    let b = rsa::sign(&private, parameters, &digest, true).unwrap();
    assert_eq!(a, b);
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key).unwrap();
    verifier.update(message).unwrap();
    assert!(verifier.verify(&a).unwrap());
    assert!(rsa::verify(&public, parameters, message, false, &a).unwrap());
    assert!(!rsa::verify(&public, parameters, b"changed", false, &a).unwrap());
}
