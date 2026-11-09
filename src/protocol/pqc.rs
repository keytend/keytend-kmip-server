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

//! ML-KEM, ML-DSA and SLH-DSA key pairs as managed objects
//! (docs/algorithms.md#post-quantum-keys).
//!
//! Only draft KMIP 3.0 defines them: Cryptographic Algorithm ML-KEM-512
//! through SLH-DSA-SHAKE-256f (Table 552, 0x39-0x4A), KEM Algorithm MLKEM
//! (Table 572), Key Format Type Seed Private Key (Table 575, section 3.4),
//! the Cryptographic Parameters fields KEM Algorithm, Deterministic, Context
//! String, Internal, External Mu and Random (Table 93), the Seed field of
//! Create Key Pair (Table 283), NIST Security Category (section 4.39) and
//! the Encapsulate and Decapsulate operations (sections 6.1.22, 6.1.15).
//! KMIP 1.x-2.1 define none of these, so every entry point refuses an
//! earlier protocol version with Feature Not Supported, as for any
//! algorithm a version does not define. FIPS mode refuses them too: the
//! RHEL 9 FIPS provider 3.0.7 implements none (docs/fips.md).
//!
//! Choices the draft leaves open, each documented in docs/algorithms.md#post-quantum-keys:
//! - Default Key Format Type (Table 117 lists no post-quantum key): Raw,
//!   the FIPS 203/204/205 byte encoding, for both keys.
//! - Encapsulate / Decapsulate usage: the draft defines no usage-mask bit
//!   (Table 616), so a key qualifies with any key-establishment bit:
//!   Encrypt, Wrap Key or Key Agreement to encapsulate, and Decrypt,
//!   Unwrap Key or Key Agreement to decapsulate.
//! - The shared secret becomes a Secret Data object of type Seed (the only
//!   non-password Secret Data Type, Table 597), created with the request's
//!   Attributes.
use super::*;
use crate::crypto::pqc::{self as material, Algorithm, Family, SignatureOptions};

pub(super) const ENCAPSULATE: u32 = 65;
pub(super) const DECAPSULATE: u32 = 66;
/// Key Format Type Seed Private Key (draft 3.0 Table 575).
pub(super) const SEED_PRIVATE_KEY: u32 = 24;
const RAW: u32 = 1;
const PKCS8: u32 = 4;
const X509: u32 = 5;
/// KEM Algorithm enumeration (draft 3.0 Table 572).
const KEM_RSASVE: u32 = 1;
const KEM_DHKEM: u32 = 2;
const KEM_MLKEM: u32 = 3;
/// Cryptographic Usage Mask bits (draft 3.0 Table 616).
const ENCAPSULATE_USAGE: u32 = 0x4 | 0x10 | 0x800;
const DECAPSULATE_USAGE: u32 = 0x8 | 0x20 | 0x800;
/// Secret Data Type Seed (draft 3.0 Table 597).
const SEED_SECRET: u32 = 2;

/// The Cryptographic Parameters fields draft 3.0 adds (Table 93).
pub(super) const PARAMETERS: [u32; 7] = [
    KEM_ALGORITHM,
    DETERMINISTIC,
    CONTEXT_STRING,
    INPUT_KEY_MATERIAL,
    INTERNAL,
    EXTERNAL_MU,
    RANDOM,
];

/// A post-quantum Cryptographic Algorithm value this server implements.
pub(super) fn algorithm(alg: u32) -> bool {
    material::parameter_set(alg).is_some()
}
/// A stored public or private key of such an algorithm.
pub(super) fn key(obj: &Object) -> bool {
    matches!(obj.object_type, 3 | 4) && algorithm(obj.algorithm)
}

/// The parameter set of `alg`, available in this version and mode.
pub(super) fn parameter_set(alg: u32, v: Version) -> R<Algorithm> {
    let set = material::parameter_set(alg).ok_or(fail(8, "Unsupported key algorithm"))?;
    if v.0 < 3 {
        return Err(fail(
            8,
            "ML-KEM, ML-DSA and SLH-DSA are defined from KMIP 3.0",
        ));
    }
    if crate::fips::active() {
        return Err(fail(
            8,
            "ML-KEM, ML-DSA and SLH-DSA are not available in FIPS mode",
        ));
    }
    Ok(set)
}

/// Cryptographic Parameters fields of Table 93 (draft 3.0 only).
pub(super) fn validate_parameter(n: &Node, v: Version) -> R<()> {
    if v.0 < 3 {
        return Err(fail(
            7,
            "Cryptographic parameter is unavailable in this version",
        ));
    }
    let ok = match n.tag {
        KEM_ALGORITHM => matches!(n.value, Value::Enumeration(_)),
        DETERMINISTIC | INTERNAL | EXTERNAL_MU => matches!(n.value, Value::Boolean(_)),
        _ => matches!(n.value, Value::ByteString(_)),
    };
    if !ok {
        return Err(fail(7, "Cryptographic parameter has the wrong type"));
    }
    Ok(())
}

/// NIST Security Category (draft 3.0 section 4.39, Integer). The server
/// sets it on every post-quantum key from the parameter set (FIPS 203
/// Table 2, FIPS 204 Table 1, FIPS 205 Table 2); a client value must agree.
pub(super) fn validate_category(a: &Node) -> R<()> {
    if !matches!(a.value, Value::Integer(1..=5)) {
        return Err(fail(7, "NIST Security Category must be an Integer 1-5"));
    }
    Ok(())
}
/// The NIST Security Category of a stored post-quantum key.
pub(super) fn security_category(obj: &Object) -> Option<i32> {
    category(obj)
}
fn category(obj: &Object) -> Option<i32> {
    key(obj).then(|| {
        material::parameter_set(obj.algorithm)
            .map(|a| i32::from(a.security_category()))
            .unwrap_or_default()
    })
}
/// Before an object is stored (through `quantum::check`, which every
/// creation path runs): a client-supplied NIST Security Category must match
/// the key. Get Attributes returns the server's value (`project`).
pub(super) fn check_category(obj: &Object) -> R<()> {
    let expected = category(obj);
    for a in obj.attrs.iter().filter(|a| a.tag == NIST_SECURITY_CATEGORY) {
        if Some(a.number()? as i32) != expected {
            return Err(fail(
                7,
                "NIST Security Category does not match the key's parameter set",
            ));
        }
    }
    Ok(())
}
pub(super) fn project(obj: &Object, v: Version, attrs: &mut Vec<Node>) {
    attrs.retain(|a| a.tag != NIST_SECURITY_CATEGORY);
    if v.0 >= 3
        && let Some(c) = category(obj)
    {
        attrs.push(Node::int(NIST_SECURITY_CATEGORY, c));
    }
}

/// Key Format Types for each half of a pair: Raw (the FIPS encoding),
/// PKCS#8 and Seed Private Key for private keys; Raw and X.509
/// (SubjectPublicKeyInfo) for public keys.
pub(super) fn format_allowed(kind: u32, format: u32) -> bool {
    match kind {
        4 => matches!(format, RAW | PKCS8 | SEED_PRIVATE_KEY),
        3 => matches!(format, RAW | X509),
        _ => false,
    }
}
pub(super) fn default_format() -> u32 {
    RAW
}

/// The post-quantum algorithm a Create Key Pair names, if any.
pub(super) fn pair_algorithm(private: &[Node], public: &[Node]) -> R<Option<u32>> {
    let alg = attr_num(
        private,
        CRYPTOGRAPHIC_ALGORITHM,
        attr_num(public, CRYPTOGRAPHIC_ALGORITHM, 0)?,
    )?;
    Ok(algorithm(alg).then_some(alg))
}
/// Cryptographic Length "SHALL reflect the size of that specific key in
/// bits" and may differ between the two keys (draft 3.0 section 6.1.11 and
/// Table 285), so it is taken out of the shared-attribute reconciliation and
/// checked against each generated key.
pub(super) fn take_lengths(attrs: &mut Vec<Node>) -> R<Option<u32>> {
    let mut length = None;
    for a in attrs.iter().filter(|a| a.tag == CRYPTOGRAPHIC_LENGTH) {
        let n = a.number()?;
        if length.is_some_and(|l| l != n) {
            return Err(fail(7, "Conflicting Cryptographic Length"));
        }
        length = Some(n);
    }
    attrs.retain(|a| a.tag != CRYPTOGRAPHIC_LENGTH);
    Ok(length)
}
/// The Seed field of Create Key Pair (draft 3.0 Table 283).
pub(super) fn request_seed(p: &Node, v: Version, alg: Option<u32>) -> R<Option<Vec<u8>>> {
    let Some(seed) = p.get(SEED) else {
        return Ok(None);
    };
    if v.0 < 3 {
        return Err(fail(8, "Request contains an unsupported field"));
    }
    let seed = seed.byte_string()?;
    match alg.and_then(material::parameter_set).map(|a| a.seed_len()) {
        Some(Some(len)) if len == seed.len() => Ok(Some(seed.to_vec())),
        Some(Some(_)) => Err(fail(7, "Seed length does not match the parameter set")),
        _ => Err(fail(
            8,
            "A key-generation Seed is supported only for ML-KEM and ML-DSA",
        )),
    }
}
pub(super) fn generate(
    alg: u32,
    seed: Option<&[u8]>,
    v: Version,
) -> R<openssl::pkey::PKey<openssl::pkey::Private>> {
    let set = parameter_set(alg, v)?;
    material::generate(set, seed).map_err(|_| fail(10, "Post-quantum key generation failed"))
}
/// The stored DER of one half of a generated pair.
pub(super) fn pair_material(
    kind: u32,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> R<Vec<u8>> {
    if kind == 4 {
        material::private_der(key)
    } else {
        material::public_der(key)
    }
    .map_err(|_| fail(10, "Post-quantum key encoding failed"))
}
/// The Cryptographic Length of one stored key; a requested length must match.
pub(super) fn length(alg: u32, kind: u32, der: &[u8], requested: Option<u32>) -> R<u32> {
    let set = material::parameter_set(alg).ok_or(fail(8, "Unsupported key algorithm"))?;
    let bits =
        material::bits(set, der, kind == 4).map_err(|_| fail(7, "Invalid post-quantum key"))?;
    if requested.is_some_and(|r| r != bits) {
        return Err(fail(
            7,
            "Cryptographic Length does not match the key's encoded size",
        ));
    }
    Ok(bits)
}

/// Register: the stored DER and Cryptographic Length of a key block.
pub(super) fn import_material(
    kind: u32,
    alg: u32,
    format: u32,
    kb: &Node,
    km: &Node,
    v: Version,
) -> R<(Vec<u8>, u32)> {
    let set = parameter_set(alg, v)?;
    if kb.get(KEY_COMPRESSION_TYPE).is_some() {
        return Err(fail(8, "Compression requires an EC public key"));
    }
    if !format_allowed(kind, format) {
        return Err(fail(0x10, "Unsupported post-quantum key format"));
    }
    let private = kind == 4;
    let der = match format {
        RAW => material::import_raw(set, km.byte_string()?, private),
        PKCS8 | X509 => material::import_der(set, km.byte_string()?, private),
        _ => {
            no_fields(km, &[SEED, KEY])?;
            let seed = km.get(SEED).map(Node::byte_string).transpose()?;
            let key = km.get(KEY).map(Node::byte_string).transpose()?;
            if seed.is_some() && set.seed_len().is_none() {
                return Err(fail(8, "SLH-DSA keys have no Seed Private Key seed"));
            }
            material::import_seed(set, seed, key)
        }
    }
    .map_err(|_| fail(7, "Invalid post-quantum key material"))?;
    let bits = length(alg, kind, &der, None)?;
    Ok((der, bits))
}

/// Key Material of a stored key in `format` (Get, Export, Digest).
pub(super) fn key_material(obj: &Object, format: u32) -> R<Node> {
    let set = material::parameter_set(obj.algorithm).ok_or(fail(8, "Unsupported key algorithm"))?;
    if !format_allowed(obj.object_type, format) {
        return Err(fail(0x10, "Unsupported post-quantum key format"));
    }
    let private = obj.object_type == 4;
    let invalid = |_| fail(7, "Invalid stored post-quantum key");
    Ok(match format {
        RAW => Node::bytes(
            KEY_MATERIAL,
            material::raw(set, &obj.material, private)
                .map_err(invalid)?
                .to_vec(),
        ),
        PKCS8 | X509 => Node::bytes(
            KEY_MATERIAL,
            material::import_der(set, &obj.material, private).map_err(invalid)?,
        ),
        _ => {
            let (seed, key) = material::seed_and_key(set, &obj.material).map_err(invalid)?;
            let mut fields = vec![];
            if let Some(seed) = seed {
                fields.push(Node::bytes(SEED, seed.to_vec()));
            }
            fields.push(Node::bytes(KEY, key.to_vec()));
            Node::structure(KEY_MATERIAL, fields)
        }
    })
}

/// Re-key Key Pair: the stored keys must be one pair of one parameter set.
pub(super) fn check_pair(private: &Object, public: &Object, v: Version) -> R<Algorithm> {
    let set = parameter_set(private.algorithm, v)?;
    if public.algorithm != private.algorithm
        || !material::same_pair(set, &private.material, &public.material).unwrap_or(false)
    {
        return Err(fail(12, "Stored keys are not the same mathematical pair"));
    }
    Ok(set)
}

fn bad_parameters(message: &'static str) -> Failure {
    fail(0x24, message)
}
fn unsupported_parameters(message: &'static str) -> Failure {
    fail(0x3e, message)
}

/// Sign and Signature Verify with an ML-DSA or SLH-DSA key: the pure
/// (external) interface of FIPS 204 Algorithms 2-3 and FIPS 205 Algorithms
/// 22-24, with the draft 3.0 Table 93 options.
pub(super) fn signature(obj: &Object, v: Version, op: u32, p: &Node, cp: &Node) -> R<Node> {
    let set = parameter_set(obj.algorithm, v)?;
    if set.family() == Family::MlKem {
        return Err(fail(8, "Unsupported signature key algorithm"));
    }
    if p.get(DIGESTED_DATA).is_some() {
        // Hash-ML-DSA / Hash-SLH-DSA (Table 552, 0x4B-0x59) are separate
        // algorithms, which OpenSSL 3.5 does not implement.
        return Err(fail(
            8,
            "Pre-hashed post-quantum signatures are not implemented",
        ));
    }
    no_fields(
        cp,
        &[
            CRYPTOGRAPHIC_ALGORITHM,
            DETERMINISTIC,
            CONTEXT_STRING,
            INTERNAL,
            EXTERNAL_MU,
            RANDOM,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)? != obj.algorithm {
        return Err(bad_parameters(
            "Cryptographic Algorithm does not match the key",
        ));
    }
    if flag(cp, INTERNAL, false)? {
        // FIPS 204 section 6 / FIPS 205 section 9: the internal functions
        // are for testing, not for applications.
        return Err(unsupported_parameters(
            "The internal signature interface is not offered",
        ));
    }
    if cp.get(RANDOM).is_some() {
        return Err(unsupported_parameters(
            "Externally provided signing randomness is not accepted",
        ));
    }
    let context = cp
        .get(CONTEXT_STRING)
        .map(Node::byte_string)
        .transpose()?
        .unwrap_or_default();
    if context.len() > 255 {
        return Err(bad_parameters("Context String exceeds 255 bytes"));
    }
    let external_mu = flag(cp, EXTERNAL_MU, false)?;
    let data = p.required(DATA)?.byte_string()?;
    if external_mu {
        if set.family() != Family::MlDsa {
            return Err(bad_parameters("External Mu applies only to ML-DSA"));
        }
        if !context.is_empty() {
            return Err(bad_parameters("External Mu already binds the context"));
        }
        if data.len() != 64 {
            return Err(fail(7, "External Mu data must be 64 bytes"));
        }
    }
    let options = SignatureOptions {
        context,
        deterministic: flag(cp, DETERMINISTIC, false)?,
        external_mu,
    };
    if op == 33 {
        let signature = material::sign(set, &obj.material, data, options)
            .map_err(|_| fail(10, "Post-quantum signing failed"))?;
        Ok(Node::bytes(SIGNATURE_DATA, signature))
    } else {
        let valid = material::verify(
            set,
            &obj.material,
            data,
            p.required(SIGNATURE_DATA)?.byte_string()?,
            options,
        )
        .map_err(|_| fail(10, "Post-quantum verification failed"))?;
        Ok(Node::enumeration(
            VALIDITY_INDICATOR,
            if valid { 1 } else { 2 },
        ))
    }
}

impl Engine {
    /// Re-key Key Pair of a post-quantum pair (draft 3.0 section 6.1.54):
    /// the replacement pair has the same parameter set; each key keeps its
    /// Key Format Type unless the request names another.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn rekey_pq_pair(
        &self,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
        mut private: Object,
        mut public: Object,
        (private_mask, public_mask): (u32, u32),
    ) -> R<Vec<Node>> {
        let common = read_attrs_at(p, v, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES)?;
        let mut private_attrs = attributes::pair_union(
            common.clone(),
            read_attrs_at(p, v, PRIVATE_KEY_TEMPLATE_ATTRIBUTE, PRIVATE_KEY_ATTRIBUTES)?,
        )?;
        let mut public_attrs = attributes::pair_union(
            common,
            read_attrs_at(p, v, PUBLIC_KEY_TEMPLATE_ATTRIBUTE, PUBLIC_KEY_ATTRIBUTES)?,
        )?;
        let private_format = ec::take_format(&mut private_attrs, v)?;
        let public_format = ec::take_format(&mut public_attrs, v)?;
        let private_length = take_lengths(&mut private_attrs)?;
        let public_length = take_lengths(&mut public_attrs)?;
        for attrs in [&private_attrs, &public_attrs] {
            if attr_num(attrs, CRYPTOGRAPHIC_ALGORITHM, private.algorithm)? != private.algorithm {
                return Err(fail(7, "Re-key Key Pair cannot change the algorithm"));
            }
        }
        let time = now();
        let offset = rekey::offset(p)?;
        let mut next_private = rekey::replacement(
            &private,
            private_attrs,
            v,
            time,
            offset,
            &[ACTIVATION_DATE, DEACTIVATION_DATE],
            self.maximum_lease,
        )?;
        let mut next_public = rekey::replacement(
            &public,
            public_attrs,
            v,
            time,
            offset,
            &[ACTIVATION_DATE, DEACTIVATION_DATE],
            self.maximum_lease,
        )?;
        next_private.protection_mask = private_mask;
        next_public.protection_mask = public_mask;
        next_private.format = private_format.unwrap_or(private.format);
        next_public.format = public_format.unwrap_or(public.format);
        let key = generate(private.algorithm, None, v)?;
        for (obj, requested) in [
            (&mut next_private, private_length),
            (&mut next_public, public_length),
        ] {
            if !format_allowed(obj.object_type, obj.format) {
                return Err(fail(0x10, "Unsupported post-quantum key format"));
            }
            obj.material = pair_material(obj.object_type, &key)?;
            obj.bits = length(obj.algorithm, obj.object_type, &obj.material, requested)?;
            quantum::check(obj)?;
        }
        attributes::append(&mut next_private, object_link(0x102, &next_public.id))?;
        attributes::append(&mut next_public, object_link(0x103, &next_private.id))?;
        rekey::finish(&mut private, &mut next_private)?;
        rekey::finish(&mut public, &mut next_public)?;
        self.store.put(&private)?;
        self.store.put(&public)?;
        for object in [&next_private, &next_public] {
            self.unique_names(object, v)?;
            self.store.insert(object)?;
        }
        *placeholder = Some(next_private.id.clone());
        Ok(vec![
            Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, &next_private.id),
            Node::text(PUBLIC_KEY_UNIQUE_IDENTIFIER, &next_public.id),
        ])
    }
    /// Encapsulate (draft 3.0 section 6.1.22, Tables 317-319) with an ML-KEM
    /// public key, or Decapsulate (section 6.1.15, Tables 296-298) with the
    /// private key. Each creates a Secret Data object holding the shared
    /// secret and returns its Unique Identifier; Encapsulate also returns the
    /// ciphertext as Data.
    pub(super) fn kem(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let encapsulate = op == ENCAPSULATE;
        no_fields(
            p,
            if encapsulate {
                &[UNIQUE_IDENTIFIER, CRYPTOGRAPHIC_PARAMETERS, ATTRIBUTES][..]
            } else {
                &[
                    UNIQUE_IDENTIFIER,
                    CRYPTOGRAPHIC_PARAMETERS,
                    DATA,
                    ATTRIBUTES,
                ][..]
            },
        )?;
        let mut obj = self.object(owner, p, placeholder)?;
        self.materialize(owner, &mut obj)?;
        if obj.object_type != if encapsulate { 3 } else { 4 } {
            return Err(fail(
                0x30,
                "Encapsulate uses a public key and Decapsulate a private key",
            ));
        }
        check_use(
            &obj,
            v,
            if encapsulate {
                ENCAPSULATE_USAGE
            } else {
                DECAPSULATE_USAGE
            },
            encapsulate,
        )?;
        let cp = cryptographic_parameters(&obj, p, v, false)?;
        no_fields(&cp, &[KEM_ALGORITHM, CRYPTOGRAPHIC_ALGORITHM])?;
        match number(&cp, KEM_ALGORITHM, KEM_MLKEM)? {
            KEM_MLKEM => {}
            KEM_RSASVE | KEM_DHKEM => {
                return Err(unsupported_parameters("Only ML-KEM is implemented"));
            }
            _ => return Err(bad_parameters("Unknown KEM Algorithm")),
        }
        if number(&cp, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)? != obj.algorithm {
            return Err(bad_parameters(
                "Cryptographic Algorithm does not match the key",
            ));
        }
        let set = match material::parameter_set(obj.algorithm) {
            Some(set) if set.family() == Family::MlKem => parameter_set(obj.algorithm, v)?,
            _ => return Err(unsupported_parameters("Only ML-KEM keys encapsulate")),
        };
        let ciphertext = if encapsulate {
            None
        } else {
            let data = p.required(DATA)?.byte_string()?;
            if Some(data.len()) != material::ciphertext_len(set) {
                return Err(fail(
                    7,
                    "Ciphertext length does not match the parameter set",
                ));
            }
            Some(data.to_vec())
        };
        self.consume_protection(&mut obj, 32, v, 0x1a)?;
        let (output, secret) = match &ciphertext {
            None => {
                let (c, s) = material::encapsulate(set, &obj.material)
                    .map_err(|_| fail(10, "Encapsulation failed"))?;
                (Some(c), s)
            }
            Some(c) => (
                None,
                material::decapsulate(set, &obj.material, c)
                    .map_err(|_| fail(10, "Decapsulation failed"))?,
            ),
        };
        let mut fields = vec![Node::enumeration(OBJECT_TYPE, 7)];
        if let Some(attributes) = p.get(ATTRIBUTES) {
            fields.push(attributes.clone());
        }
        fields.push(Node::structure(
            SECRET_DATA,
            vec![
                Node::enumeration(SECRET_DATA_TYPE, SEED_SECRET),
                Node::structure(
                    KEY_BLOCK,
                    vec![
                        Node::enumeration(KEY_FORMAT_TYPE, RAW),
                        Node::structure(
                            KEY_VALUE,
                            vec![Node::bytes(KEY_MATERIAL, secret.to_vec())],
                        ),
                    ],
                ),
            ],
        ));
        let mut shared =
            self.build_object(owner, v, &Node::structure(REQUEST_PAYLOAD, fields), true)?;
        // The secret is server-generated, not client-registered.
        metadata::initialize(&mut shared, v, true)?;
        self.unique_names(&shared, v)?;
        quantum::check(&shared)?;
        self.store.insert(&shared)?;
        *placeholder = Some(shared.id.clone());
        let mut result = vec![Node::text(UNIQUE_IDENTIFIER, &shared.id)];
        if let Some(c) = output {
            result.push(Node::bytes(DATA, c));
        }
        Ok(result)
    }
}
