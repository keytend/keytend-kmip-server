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
    ec::{self, EcCurves},
    rsa,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ecdsa::EcdsaSig,
    hash::hash,
};

/// The 13 implemented KMIP Recommended Curves
/// (docs/interpretations.md#supported-elliptic-curves); every other KMIP curve
/// is refused.
const SUPPORTED: [u32; 13] = [4, 7, 10, 13, 25, 61, 62, 63, 64, 65, 66, 67, 68];
/// The `--ec-curves nist` set (the default).
const NIST: [u32; 4] = [4, 7, 10, 13];

#[test]
fn rfc6979_published_signatures_verify_on_supported_curves_and_removed_curves_are_refused() {
    let data: serde_json::Value = serde_json::from_str(include_str!("ec-rfc6979.json")).unwrap();
    let cases = data["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 150);
    let mut verified = 0;
    for case in cases {
        let curve = case["curve"].as_u64().unwrap() as u32;
        let hash_id = case["hash"].as_u64().unwrap() as u32;
        let scalar = BigNum::from_hex_str(case["private_scalar"].as_str().unwrap())
            .unwrap()
            .to_vec();
        let public_point = hex::decode(case["public_point"].as_str().unwrap()).unwrap();
        if !SUPPORTED.contains(&curve) {
            // P-192 and the binary curves of RFC 6979 A.2 are no longer
            // supported, whatever the linked OpenSSL offers.
            for result in [
                ec::import_scalar(curve, &scalar),
                ec::import_point(curve, &public_point),
            ] {
                assert!(
                    result.unwrap_err().is::<ec::UnsupportedCurve>(),
                    "curve {curve}"
                );
            }
            continue;
        }
        verified += 1;
        let private = ec::import_scalar(curve, &scalar).unwrap();
        let public = ec::import_point(curve, &public_point).unwrap();
        let signature = EcdsaSig::from_private_components(
            BigNum::from_hex_str(case["r"].as_str().unwrap()).unwrap(),
            BigNum::from_hex_str(case["s"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
        .to_der()
        .unwrap();
        let message = case["message"].as_str().unwrap().as_bytes();
        assert!(ec::verify(&public, hash_id, message, false, &signature).unwrap());
        let digest = hash(rsa::digest(hash_id).unwrap(), message).unwrap();
        assert!(ec::verify(&public, hash_id, &digest, true, &signature).unwrap());
        let native = openssl::pkey::PKey::private_key_from_pkcs8(&private).unwrap();
        assert_eq!(
            ec::point(&native.public_key_to_der().unwrap(), 1).unwrap(),
            public_point
        );
        assert!(!ec::verify(&public, hash_id, b"incorrect message", false, &signature).unwrap());
        let generated = ec::sign(&private, hash_id, message, false).unwrap();
        assert!(ec::verify(&public, hash_id, message, false, &generated).unwrap());
    }
    // P-224, P-256, P-384 and P-521, ten cases each.
    assert_eq!(verified, 40);
}

// REQ:d16f892c3f39563a Cryptographic Domain Parameters fields are optional (1.0 3.7)
// REQ:834eb0033c68e759 Cryptographic Domain Parameters fields are optional (1.1 3.7)
// REQ:246f7fdd3d9ee9bf Cryptographic Domain Parameters fields are optional (1.2 3.7)
// REQ:22fcfd3cc62ffcfd Cryptographic Domain Parameters fields are optional (1.3 3.7)
// REQ:b3216d0ef9416191 Cryptographic Domain Parameters fields are optional (1.4 3.7)
// REQ:9bf2db8e95c4a8ae Cryptographic Domain Parameters fields are optional (2.0/2.1 4.14, 3.0 4.16)
#[test]
fn supported_curves_generate_validate_and_preserve_der_formats_and_the_rest_are_refused() {
    for setting in [EcCurves::Nist, EcCurves::Extended] {
        let _curves = ec::enter(setting);
        let offered: &[u32] = match setting {
            EcCurves::Nist => &NIST,
            EcCurves::Extended => &SUPPORTED,
        };
        let mut supported = 0;
        for curve in 1..=68 {
            assert_eq!(ec::implemented(curve), SUPPORTED.contains(&curve));
            if !offered.contains(&curve) {
                assert!(!ec::supported(curve), "curve {curve}");
                assert!(ec::group(curve).unwrap_err().is::<ec::UnsupportedCurve>());
                assert!(
                    ec::generate(curve)
                        .unwrap_err()
                        .is::<ec::UnsupportedCurve>()
                );
                continue;
            }
            supported += 1;
            assert!(ec::supported(curve));
            let key = ec::generate(curve).unwrap_or_else(|e| panic!("curve {curve}: {e}"));
            let private = key.private_key_to_pkcs8().unwrap();
            let public = key.public_key_to_der().unwrap();
            assert_eq!(
                ec::info(&private, true).unwrap(),
                (curve, ec::group(curve).unwrap().degree())
            );
            assert_eq!(ec::key_curve(&private), Some(curve));
            assert_eq!(ec::key_curve(&public), Some(curve));
            let sec1 = ec::export_der(&private, true, 6).unwrap();
            assert_eq!(ec::key_curve(&sec1), Some(curve));
            let restored = ec::import_der(&sec1, true, 6).unwrap();
            assert_eq!(ec::info(&restored, true).unwrap().0, curve);
            // Every supported curve is over a prime field.
            assert!(ec::point(&public, 3).is_err());
            for compression in [1, 2, 4] {
                let point = ec::point(&public, compression).unwrap();
                let decoded = ec::import_point(curve, &point).unwrap();
                assert_eq!(
                    ec::point(&decoded, 1).unwrap(),
                    ec::point(&public, 1).unwrap()
                );
            }
            let sig = ec::sign(&restored, 8, b"all curve verification", false).unwrap();
            assert!(ec::verify(&public, 8, b"all curve verification", false, &sig).unwrap());
        }
        assert_eq!(supported, offered.len());
    }
}

/// Keys made with `--ec-curves extended` are still recognised from their DER
/// under `nist`, but every operation that needs the curve refuses them:
/// import, export, conversion, signing and verification.
#[test]
fn extended_curve_keys_are_unusable_under_nist() {
    for curve in [25, 61, 62, 63, 64, 65, 66, 67, 68] {
        let (key, sig) = ec::scope(EcCurves::Extended, || {
            let key = ec::generate(curve).unwrap();
            let sig = ec::sign(&key.private_key_to_pkcs8().unwrap(), 8, b"m", false).unwrap();
            (key, sig)
        });
        let private = key.private_key_to_pkcs8().unwrap();
        let public = key.public_key_to_der().unwrap();
        let sec1 = key.ec_key().unwrap().private_key_to_der().unwrap();
        assert_eq!(ec::active(), EcCurves::Nist, "the default outside a scope");
        assert!(!ec::supported(curve));
        assert_eq!(ec::key_curve(&private), Some(curve));
        assert_eq!(ec::key_curve(&public), Some(curve));
        let unsupported = |r: anyhow::Result<()>| {
            assert!(r.unwrap_err().is::<ec::UnsupportedCurve>(), "curve {curve}")
        };
        unsupported(ec::generate(curve).map(drop));
        unsupported(ec::info(&private, true).map(drop));
        unsupported(ec::info(&public, false).map(drop));
        unsupported(ec::import_der(&private, true, 4).map(drop));
        unsupported(ec::import_der(&sec1, true, 6).map(drop));
        unsupported(ec::import_der(&public, false, 5).map(drop));
        unsupported(ec::export_der(&private, true, 6).map(drop));
        unsupported(ec::export_der(&public, false, 5).map(drop));
        unsupported(ec::scalar(&private).map(drop));
        unsupported(ec::point(&public, 1).map(drop));
        unsupported(ec::import_point(curve, &[4; 65]).map(drop));
        unsupported(ec::import_scalar(curve, &[1; 32]).map(drop));
        unsupported(ec::sign(&private, 8, b"m", false).map(drop));
        unsupported(ec::verify(&public, 8, b"m", false, &sig).map(drop));
        // The stored components, read from the DER without OpenSSL, are
        // what the OpenSSL path returns under `extended`.
        let (d_curve, d) = ec::stored_components(&private, true).unwrap();
        let (q_curve, q) = ec::stored_components(&public, false).unwrap();
        assert_eq!((d_curve, q_curve), (curve, curve));
        // Back under `extended` the same key works again.
        ec::scope(EcCurves::Extended, || {
            assert!(ec::verify(&public, 8, b"m", false, &sig).unwrap());
            assert_eq!(d, ec::scalar(&private).unwrap().to_vec());
            assert_eq!(q, ec::point(&public, 1).unwrap());
        });
    }
}

/// `stored_components` reads PKCS#8 and SubjectPublicKeyInfo only, and
/// agrees with OpenSSL on the NIST curves too, including scalars with
/// leading zero bytes.
#[test]
fn stored_components_match_openssl_and_refuse_other_encodings() {
    for curve in NIST {
        for _ in 0..64 {
            let key = ec::generate(curve).unwrap();
            let private = key.private_key_to_pkcs8().unwrap();
            let public = key.public_key_to_der().unwrap();
            assert_eq!(
                ec::stored_components(&private, true).unwrap(),
                (curve, ec::scalar(&private).unwrap().to_vec())
            );
            assert_eq!(
                ec::stored_components(&public, false).unwrap(),
                (curve, ec::point(&public, 1).unwrap())
            );
            let sec1 = key.ec_key().unwrap().private_key_to_der().unwrap();
            assert_eq!(ec::stored_components(&sec1, true), None);
            assert_eq!(ec::stored_components(&public, true), None);
            assert_eq!(ec::stored_components(&private, false), None);
        }
    }
    let rsa = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    assert_eq!(
        ec::stored_components(&rsa.private_key_to_pkcs8().unwrap(), true),
        None
    );
    assert_eq!(
        ec::stored_components(&rsa.public_key_to_der().unwrap(), false),
        None
    );
    for junk in [&[][..], &[0x30, 0x00], &[0x30, 0x03, 0x02, 0x01, 0x00]] {
        assert_eq!(ec::stored_components(junk, true), None);
        assert_eq!(ec::stored_components(junk, false), None);
    }
}

/// Keys, certificates and requests on removed curves are recognised from
/// their DER encoding, before OpenSSL decodes them, so a build whose OpenSSL
/// still has these curves refuses them like one that lacks them.
#[test]
fn removed_curves_are_recognised_in_der_keys_certificates_and_requests() {
    let data: serde_json::Value =
        serde_json::from_str(include_str!("ec-removed-curves.json")).unwrap();
    let curves = data["curves"].as_object().unwrap();
    assert_eq!(curves.len(), 4);
    for (name, fixture) in curves {
        let curve = fixture["curve"].as_u64().unwrap() as u32;
        let bytes = |field: &str| hex::decode(fixture[field].as_str().unwrap()).unwrap();
        assert!(!ec::supported(curve), "{name}");
        assert!(!ec::implemented(curve), "{name}");
        assert!(ec::scope(EcCurves::Extended, || !ec::supported(curve)));
        for field in ["pkcs8", "spki", "sec1"] {
            assert_eq!(ec::key_curve(&bytes(field)), Some(curve), "{name} {field}");
        }
        assert_eq!(
            ec::certificate_curve(&bytes("certificate")),
            Some(curve),
            "{name}"
        );
        assert_eq!(ec::request_curve(&bytes("request")), Some(curve), "{name}");
        assert!(ec::import_der(&bytes("pkcs8"), true, 4).is_err());
        assert!(ec::import_der(&bytes("spki"), false, 5).is_err());
        assert!(matches!(
            keytend_kmip_server::crypto::issuance::parse_request(2, &bytes("request")),
            Err(keytend_kmip_server::crypto::issuance::RequestError::UnsupportedCurve)
        ));
    }
    // Not EC, malformed or empty: left to OpenSSL.
    let rsa = openssl::pkey::PKey::from_rsa(openssl::rsa::Rsa::generate(2048).unwrap()).unwrap();
    assert_eq!(ec::key_curve(&rsa.public_key_to_der().unwrap()), None);
    assert_eq!(ec::key_curve(&rsa.private_key_to_pkcs8().unwrap()), None);
    for junk in [
        &[][..],
        &[0x30][..],
        &[0x30, 0x81][..],
        &[0x30, 0x05, 0x02][..],
    ] {
        assert_eq!(ec::key_curve(junk), None);
        assert_eq!(ec::certificate_curve(junk), None);
        assert_eq!(ec::request_curve(junk), None);
    }
}

#[test]
fn invalid_ec_scalars_points_signatures_and_prehashes_never_verify() {
    assert!(ec::import_scalar(7, &[0; 32]).is_err());
    let group = ec::group(7).unwrap();
    let mut order = BigNum::new().unwrap();
    group
        .order(&mut order, &mut BigNumContext::new().unwrap())
        .unwrap();
    assert!(ec::import_scalar(7, &order.to_vec()).is_err());
    for point in [vec![0], vec![4; 65], vec![2; 5]] {
        assert!(ec::import_point(7, &point).is_err());
    }
    let key = ec::generate(7).unwrap();
    let private = key.private_key_to_pkcs8().unwrap();
    let public = key.public_key_to_der().unwrap();
    let signature = ec::sign(&private, 6, b"message", false).unwrap();
    let mut trailing = signature.clone();
    trailing.push(0);
    assert!(!ec::verify(&public, 6, b"message", false, &trailing).unwrap());
    assert!(!ec::verify(&public, 6, b"message", false, &[0; 64]).unwrap());
    assert!(ec::sign(&private, 6, &[0; 31], true).is_err());
    assert!(ec::verify(&public, 6, &[0; 33], true, &signature).is_err());
    assert!(ec::point(&public, 3).is_err());
    assert!(ec::import_der(&private, false, 5).is_err());
    assert!(ec::group(69).is_err());
}
