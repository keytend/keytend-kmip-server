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

//! Durable Split Key representation, field identity and versioned attributes.
use super::*;
use crate::{
    crypto::split::{Method, Parameters, Polynomial},
    store::SplitKeyMetadata,
};

const ATTRIBUTES_SET: &[u32] = &[
    SPLIT_KEY_METHOD,
    SPLIT_KEY_PARTS,
    SPLIT_KEY_THRESHOLD,
    SPLIT_KEY_POLYNOMIAL,
];
pub(super) fn validate_attribute(a: &Node) -> R<()> {
    match (a.tag, &a.value) {
        (SPLIT_KEY_METHOD, Value::Enumeration(1..=4))
        | (SPLIT_KEY_POLYNOMIAL, Value::Enumeration(1..=2)) => Ok(()),
        (SPLIT_KEY_PARTS | SPLIT_KEY_THRESHOLD, Value::Integer(1..=128)) => Ok(()),
        _ => Err(fail(7, "Invalid Split Key attribute")),
    }
}
pub(super) fn ordinary_attributes(attrs: &[Node]) -> R<()> {
    if attrs.iter().any(|a| {
        matches!(
            a.tag,
            SPLIT_KEY_METHOD | SPLIT_KEY_PARTS | SPLIT_KEY_THRESHOLD
        )
    }) {
        return Err(fail(7, "Split Key attributes require a Split Key object"));
    }
    Ok(())
}
pub(super) fn strip_attributes(attrs: &mut Vec<Node>) {
    attrs.retain(|a| !ATTRIBUTES_SET.contains(&a.tag));
}
fn integer(n: &Node, tag: u32) -> R<u32> {
    match n.required(tag)?.value {
        Value::Integer(i) if i > 0 => Ok(i as u32),
        _ => Err(fail(
            7,
            "Split Key counts and identifiers must be positive Integers",
        )),
    }
}
fn prime(n: &Node, v: Version) -> R<Vec<u8>> {
    let Value::BigInteger(bytes) = &n.value else {
        return Err(fail(7, "Prime Field Size must be a Big Integer"));
    };
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) || bytes[0] & 0x80 != 0 {
        return Err(fail(
            7,
            "Prime Field Size must be a positive signed Big Integer",
        ));
    }
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .ok_or(fail(7, "Prime Field Size cannot be zero"))?;
    if bytes.len() - first > crypto::split::MAX_PRIME_BITS / 8 {
        return Err(factory_limit(
            v,
            "Prime Field Size exceeds the server limit",
        ));
    }
    Ok(bytes[first..].to_vec())
}
pub(super) fn read(object: &Node, v: Version, attrs: &[Node]) -> R<SplitKeyMetadata> {
    read_inner(object, v, attrs, false)
}
fn read_inner(
    object: &Node,
    v: Version,
    attrs: &[Node],
    optional_prime: bool,
) -> R<SplitKeyMetadata> {
    let block = object.required(KEY_BLOCK)?;
    if !matches!(
        block.required(KEY_FORMAT_TYPE)?.value,
        Value::Enumeration(1 | 2)
    ) {
        return Err(fail(0x10, "Split Key format must be Raw or Opaque"));
    }
    let algorithm = number(
        block,
        CRYPTOGRAPHIC_ALGORITHM,
        attr_num(attrs, CRYPTOGRAPHIC_ALGORITHM, 0)?,
    )?;
    if matches!(algorithm, 28 | 30) {
        // Validate public metadata before accepting deferred wrapped material,
        // too. A share's field width does not change its source key's size.
        let bits = number(
            block,
            CRYPTOGRAPHIC_LENGTH,
            attr_num(attrs, CRYPTOGRAPHIC_LENGTH, 0)?,
        )?;
        validate_symmetric_parameters(algorithm, bits, v)?;
    }
    no_fields(
        object,
        &[
            SPLIT_KEY_PARTS,
            KEY_PART_IDENTIFIER,
            SPLIT_KEY_THRESHOLD,
            SPLIT_KEY_METHOD,
            PRIME_FIELD_SIZE,
            KEY_BLOCK,
        ],
    )?;
    let parts = integer(object, SPLIT_KEY_PARTS)?;
    let part = integer(object, KEY_PART_IDENTIFIER)?;
    let threshold = integer(object, SPLIT_KEY_THRESHOLD)?;
    let method = match object.required(SPLIT_KEY_METHOD)?.value {
        Value::Enumeration(m @ 1..=4) => m,
        _ => return Err(fail(7, "Invalid Split Key Method")),
    };
    if parts > crypto::split::MAX_PARTS as u32 {
        return Err(factory_limit(v, "Split Key Parts exceeds the server limit"));
    }
    if part > parts || threshold > parts || method == 1 && threshold != parts {
        return Err(fail(7, "Inconsistent Split Key parameters"));
    }
    if method == 4 && v < Version(1, 2) {
        return Err(fail(8, "GF(2^8) requires KMIP 1.2"));
    }
    let prime = object
        .get(PRIME_FIELD_SIZE)
        .map(|n| prime(n, v))
        .transpose()?;
    if method != 3 && prime.is_some() || method == 3 && prime.is_none() && !optional_prime {
        return Err(fail(
            7,
            "Prime Field Size is required only for prime sharing",
        ));
    }
    for tag in ATTRIBUTES_SET {
        let values = attrs.iter().filter(|a| a.tag == *tag).collect::<Vec<_>>();
        if values.len() > 1 {
            return Err(fail(7, "Duplicate Split Key attribute"));
        }
        for a in values {
            if v.0 < 3 {
                return Err(fail(7, "Split Key attributes require draft 3.0"));
            }
            validate_attribute(a)?;
            let expected = match a.tag {
                SPLIT_KEY_PARTS => parts,
                SPLIT_KEY_THRESHOLD => threshold,
                SPLIT_KEY_METHOD => method,
                _ => continue,
            };
            if a.number()? != expected {
                return Err(fail(7, "Split Key object and attributes conflict"));
            }
        }
    }
    let binary = matches!(method, 2 | 4);
    let polynomial = if v.0 >= 3 {
        attrs
            .iter()
            .find(|a| a.tag == SPLIT_KEY_POLYNOMIAL)
            .map(Node::number)
            .transpose()?
    } else {
        binary.then_some(2)
    };
    if v.0 >= 3 && binary && polynomial.is_none() {
        return Err(fail(6, "Draft GF sharing requires Split Key Polynomial"));
    }
    let metadata = SplitKeyMetadata {
        parts,
        part,
        threshold,
        method,
        prime,
        polynomial,
        source: None,
        family: None,
        commitment: None,
    };
    // Public configuration is checked even for deferred-unwrapping or destroyed
    // imports. Plaintext length/residue is checked separately when available.
    let len = metadata
        .prime
        .as_ref()
        .map(|p| (p.len() * 8 - p[0].leading_zeros() as usize - 1) / 8)
        .unwrap_or(1);
    if method != 3 || metadata.prime.is_some() {
        parameters(&metadata, len, v)?;
    }
    Ok(metadata)
}
pub(super) fn parameters(meta: &SplitKeyMetadata, len: usize, v: Version) -> R<Parameters> {
    Parameters::new(
        Method::try_from(meta.method).map_err(|_| fail(7, "Invalid sharing method"))?,
        meta.parts as usize,
        meta.threshold as usize,
        len,
        if matches!(meta.method, 2 | 4) {
            Some(
                Polynomial::try_from(meta.polynomial.ok_or(fail(6, "Field polynomial missing"))?)
                    .map_err(|_| fail(7, "Invalid field polynomial"))?,
            )
        } else {
            None
        },
        meta.prime.as_deref(),
    )
    .map_err(|error| {
        if error.is::<crypto::split::ResourceLimit>() {
            factory_limit(v, "Split Key parameters exceed server limits")
        } else {
            fail(7, "Invalid Split Key parameters")
        }
    })
}
pub(super) fn validate_material(
    meta: &SplitKeyMetadata,
    bytes: &[u8],
    algorithm: u32,
    bits: u32,
    v: Version,
) -> R<()> {
    let len = if (matches!(algorithm, 3 | 28 | 30)
        || crypto::authentication::hmac_hash(algorithm).is_some())
        && bits > 0
    {
        if !bits.is_multiple_of(8) {
            return Err(fail(7, "Split Key length must be byte aligned"));
        }
        bits as usize / 8
    } else if let Some(p) = &meta.prime {
        (p.len() * 8 - p[0].leading_zeros() as usize - 1) / 8
    } else {
        bytes.len()
    };
    let params = parameters(meta, len, v)?;
    params
        .validate_share(meta.part as u16, bytes)
        .map_err(|_| fail(7, "Invalid Split Key share material"))
}
pub(super) fn check_version(obj: &Object, v: Version) -> R<()> {
    if obj.object_type != 5 {
        return Ok(());
    }
    let meta = obj
        .split
        .as_ref()
        .ok_or(fail(7, "Split Key metadata missing"))?;
    if meta.method == 4 && v < Version(1, 2)
        || v.0 < 3 && matches!(meta.method, 2 | 4) && meta.polynomial != Some(2)
    {
        return Err(fail(
            8,
            "Split Key field representation is unavailable in this version",
        ));
    }
    Ok(())
}
pub(super) fn fields(obj: &Object) -> R<Vec<Node>> {
    if obj.object_type != 5 {
        return Ok(vec![]);
    }
    let meta = obj
        .split
        .as_ref()
        .ok_or(fail(7, "Split Key metadata missing"))?;
    Ok(fields_for_metadata(meta))
}
fn fields_for_metadata(meta: &SplitKeyMetadata) -> Vec<Node> {
    let mut fields = vec![
        Node::int(SPLIT_KEY_PARTS, meta.parts as i32),
        Node::int(KEY_PART_IDENTIFIER, meta.part as i32),
        Node::int(SPLIT_KEY_THRESHOLD, meta.threshold as i32),
        Node::enumeration(SPLIT_KEY_METHOD, meta.method),
    ];
    if let Some(p) = &meta.prime {
        let width = (p.len() + usize::from(p[0] & 0x80 != 0)).next_multiple_of(8);
        let mut bytes = vec![0; width];
        bytes[width - p.len()..].copy_from_slice(p);
        fields.push(Node {
            tag: PRIME_FIELD_SIZE,
            value: Value::BigInteger(bytes),
        });
    }
    fields
}
pub(super) fn project(obj: &Object, v: Version, attrs: &mut Vec<Node>) {
    if v.0 < 3 {
        strip_attributes(attrs);
        return;
    }
    let Some(meta) = &obj.split else {
        return;
    };
    strip_attributes(attrs);
    attrs.extend([
        Node::int(SPLIT_KEY_PARTS, meta.parts as i32),
        Node::int(SPLIT_KEY_THRESHOLD, meta.threshold as i32),
        Node::enumeration(SPLIT_KEY_METHOD, meta.method),
    ]);
    if let Some(p) = meta.polynomial {
        attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, p));
    }
}

fn factory_limit(v: Version, message: &'static str) -> Failure {
    fail(if v.0 >= 2 { 0x3a } else { 2 }, message)
}
fn attribute_container(v: Version, attrs: Vec<Node>) -> R<Node> {
    Ok(if v.0 == 1 {
        Node::structure(
            TEMPLATE_ATTRIBUTE,
            attrs.iter().map(encode_attribute).collect::<R<Vec<_>>>()?,
        )
    } else {
        Node::structure(ATTRIBUTES, attrs)
    })
}
fn factory_attributes(old: &Object, v: Version) -> R<Vec<Node>> {
    // Object identity, lifecycle, history and digest belong to the new object.
    // In particular, copying one Name to every part would violate uniqueness.
    let mut attrs = old
        .attrs
        .iter()
        .filter(|a| {
            ![
                UNIQUE_IDENTIFIER,
                SHORT_UNIQUE_IDENTIFIER,
                OBJECT_TYPE,
                OBJECT_CLASS,
                NAME,
                LINK,
                STATE,
                INITIAL_DATE,
                LAST_CHANGE_DATE,
                DESTROY_DATE,
                ACTIVATION_DATE,
                DEACTIVATION_DATE,
                COMPROMISE_DATE,
                COMPROMISE_OCCURRENCE_DATE,
                REVOCATION_REASON,
                LEASE_TIME,
                DIGEST,
                FRESH,
                ALWAYS_SENSITIVE,
                NEVER_EXTRACTABLE,
                ORIGINAL_CREATION_DATE,
                RANDOM_NUMBER_GENERATOR,
                DIGITAL_SIGNATURE_ALGORITHM,
                CERTIFICATE_TYPE,
                CERTIFICATE_LENGTH,
                KEY_FORMAT_TYPE,
                SPLIT_KEY_PARTS,
                SPLIT_KEY_THRESHOLD,
                SPLIT_KEY_METHOD,
                SPLIT_KEY_POLYNOMIAL,
            ]
            .contains(&a.tag)
                && !certificate::identity_attribute(a.tag)
                && (v >= Version(1, 4)
                    || ![SENSITIVE, EXTRACTABLE, COMMENT, DESCRIPTION].contains(&a.tag))
        })
        .cloned()
        .collect::<Vec<_>>();
    attrs.retain(|a| {
        ![
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            CRYPTOGRAPHIC_USAGE_MASK,
        ]
        .contains(&a.tag)
    });
    if old.algorithm != 0 {
        attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, old.algorithm));
    }
    if old.bits != 0 {
        attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, old.bits as i32));
    }
    if old.object_type != 8 {
        attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, old.usage as i32));
    }
    Ok(attrs)
}
fn constrain_flags(
    attrs: &mut Vec<Node>,
    sensitive: bool,
    extractable: bool,
    v: Version,
) -> R<(bool, bool)> {
    if sensitive
        && attrs
            .iter()
            .any(|a| a.tag == SENSITIVE && a.flag().ok() == Some(false))
        || !extractable
            && attrs
                .iter()
                .any(|a| a.tag == EXTRACTABLE && a.flag().ok() == Some(true))
    {
        return Err(fail(
            12,
            "Split Key factory cannot weaken source extraction policy",
        ));
    }
    let sensitive = sensitive || attr_flag(attrs, SENSITIVE, false)?;
    let extractable = extractable && attr_flag(attrs, EXTRACTABLE, true)?;
    attrs.retain(|a| ![SENSITIVE, EXTRACTABLE].contains(&a.tag));
    if v >= Version(1, 4) {
        attrs.push(Node::boolean(SENSITIVE, sensitive));
        attrs.push(Node::boolean(EXTRACTABLE, extractable));
    }
    Ok((sensitive, extractable))
}
fn source_depth(meta: Option<&SplitKeyMetadata>) -> usize {
    meta.and_then(|m| m.source.as_deref())
        .map(|s| 1 + source_depth(s.split.as_deref()))
        .unwrap_or(0)
}
fn generated_prime(len: usize, v: Version) -> R<Vec<u8>> {
    // Public, proven Mersenne fields. Select by public serialization length;
    // no secret enters a variable-precision calculation. Explicit fields retain
    // the backend's larger 32768-bit bound. See https://www.mersenne.org/primes/.
    let exponent = [127usize, 521, 1279, 2203, 4253, 9689, 19937, 23209]
        .into_iter()
        .find(|bits| *bits > len * 8)
        .ok_or(factory_limit(
            v,
            "Automatic prime field selection exceeds the server limit",
        ))?;
    let mut prime = vec![0xff; exponent.div_ceil(8)];
    prime[0] = (1u8 << (exponent % 8)) - 1;
    Ok(prime)
}
impl Engine {
    pub(super) fn prepare_split(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        item: &Node,
        refs: &identifiers::References,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        let payload = item.required(REQUEST_PAYLOAD)?;
        for tag in [ATTRIBUTES, TEMPLATE_ATTRIBUTE] {
            if payload.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate factory attribute container"));
            }
        }
        // 1.2-1.4 Create and Join Split Key take Template references like the
        // other factories (1.4 Tables 362, 363: a missing template is Item Not
        // Found, an archived one Object Archived); expand them before the
        // attributes are read.
        let expanded = self.expand_templates(owner, v, op, payload)?;
        let payload = expanded.as_ref().unwrap_or(payload);
        let mut ids = Vec::new();
        if op == 40 && payload.all(UNIQUE_IDENTIFIER).count() > 1 {
            return Err(fail(7, "Create Split Key requires at most one source"));
        }
        for identifier in payload.all(UNIQUE_IDENTIFIER) {
            ids.extend(self.resolve_identifier(owner, v, identifier, refs, placeholder)?);
            if ids.len() > crypto::split::MAX_PARTS {
                return Err(factory_limit(v, "Too many Split Key source identifiers"));
            }
        }
        if op == 40 && ids.len() > 1 {
            return Err(fail(0x1e, "Create Split Key requires one source"));
        }
        if op == 41 && ids.is_empty() {
            return Err(fail(6, "Join Split Key requires explicit parts"));
        }
        let attrs = read_attrs(payload, v)?
            .into_iter()
            .map(|a| self.normalize_attribute(owner, v, a, refs, placeholder))
            .collect::<R<Vec<_>>>()?;
        let mut normalized = payload.clone();
        if let Value::Structure(fields) = &mut normalized.value {
            let had_attrs = fields
                .iter()
                .any(|n| [ATTRIBUTES, TEMPLATE_ATTRIBUTE].contains(&n.tag));
            fields
                .retain(|n| ![UNIQUE_IDENTIFIER, ATTRIBUTES, TEMPLATE_ATTRIBUTE].contains(&n.tag));
            fields.extend(ids.into_iter().map(|id| Node::text(UNIQUE_IDENTIFIER, id)));
            if had_attrs {
                fields.push(attribute_container(v, attrs)?);
            }
        }
        let mut request = item.clone();
        if let Value::Structure(fields) = &mut request.value {
            *fields
                .iter_mut()
                .find(|n| n.tag == REQUEST_PAYLOAD)
                .expect("required payload") = normalized;
        }
        Ok(vec![request])
    }
    fn split_source(&self, owner: &str, v: Version, payload: &Node) -> R<Object> {
        let mut object = self.object_owned(owner, payload)?;
        check_version(&object, v)?;
        pgp::available(object.object_type, v)?;
        if object.object_type == certificate_request::KIND {
            return Err(fail(8, "Certificate Request objects cannot be split"));
        }
        if object.state >= 5 {
            return Err(fail(12, "Destroyed objects cannot be split or joined"));
        }
        self.materialize(owner, &mut object)?;
        if object.material.is_empty() {
            return Err(fail(0x13, "Split Key source material is absent"));
        }
        Ok(object)
    }
    fn split_result(
        &self,
        owner: &str,
        v: Version,
        kind: u32,
        object: Node,
        mut attrs: Vec<Node>,
        policy: (bool, bool),
    ) -> R<Object> {
        metadata::prepare(&mut attrs, v, true)?;
        let payload = Node::structure(
            REQUEST_PAYLOAD,
            vec![
                Node::enumeration(OBJECT_TYPE, kind),
                attribute_container(v, attrs)?,
                object,
            ],
        );
        let mut result = self.build_object(owner, v, &payload, true)?;
        // Older protocol editions cannot set these flags, but cannot bypass a
        // policy inherited from an object originally created in a newer edition.
        result
            .attrs
            .retain(|a| ![SENSITIVE, EXTRACTABLE].contains(&a.tag));
        result.attrs.extend([
            Node::boolean(SENSITIVE, policy.0),
            Node::boolean(EXTRACTABLE, policy.1),
        ]);
        metadata::initialize(&mut result, v, true)?;
        usage::initialize(&mut result, self.maximum_lease)?;
        self.unique_names(&result, v)?;
        Ok(result)
    }
    pub(super) fn create_split(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                OBJECT_TYPE,
                UNIQUE_IDENTIFIER,
                SPLIT_KEY_PARTS,
                SPLIT_KEY_THRESHOLD,
                SPLIT_KEY_METHOD,
                PRIME_FIELD_SIZE,
                TEMPLATE_ATTRIBUTE,
                ATTRIBUTES,
                PROTECTION_STORAGE_MASKS,
            ],
        )?;
        if v < Version(1, 2) {
            return Err(fail(5, "Create Split Key requires KMIP 1.2"));
        }
        if p.required(OBJECT_TYPE)?.number()? != 5 {
            return Err(fail(
                if v.0 >= 2 { 0x28 } else { 7 },
                "Create Split Key requires Object Type Split Key",
            ));
        }
        let protection_mask = protection::select(p, v)?;
        p.required(if v.0 == 1 {
            TEMPLATE_ATTRIBUTE
        } else {
            ATTRIBUTES
        })?;
        let mut attrs = read_attrs(p, v)?;
        let format = ec::take_format(&mut attrs, v)?.unwrap_or(1);
        if ![1, 2].contains(&format) {
            return Err(fail(0x10, "Split Key output format must be Raw or Opaque"));
        }
        metadata::prepare(&mut attrs, v, true)?;
        validate_attrs(&attrs, v)?;
        let mut fields = vec![
            p.required(SPLIT_KEY_PARTS)?.clone(),
            Node::int(KEY_PART_IDENTIFIER, 1),
            p.required(SPLIT_KEY_THRESHOLD)?.clone(),
            p.required(SPLIT_KEY_METHOD)?.clone(),
            Node::structure(KEY_BLOCK, vec![Node::enumeration(KEY_FORMAT_TYPE, format)]),
        ];
        if let Some(prime) = p.get(PRIME_FIELD_SIZE) {
            fields.push(prime.clone());
        }
        let mut meta = read_inner(&Node::structure(SPLIT_KEY, fields), v, &attrs, true)?;
        let (material, source, source_attrs, algorithm, bits, source_policy) =
            if p.get(UNIQUE_IDENTIFIER).is_some() {
                let source = self.split_source(owner, v, p)?;
                if source_depth(source.split.as_ref()) >= 4 {
                    return Err(factory_limit(
                        v,
                        "Nested Split Key provenance exceeds the server limit",
                    ));
                }
                // Share a portable DER representation for asymmetric keys. The
                // private source description separately retains the requested
                // original format for local reconstruction. External registrations
                // can therefore reconstruct without opaque server provenance.
                let (material, material_format) =
                    if [3, 4].contains(&source.object_type) && ec::algorithm(source.algorithm) {
                        let format = if source.object_type == 4 { 4 } else { 5 };
                        let material = ec::key_material(&source, format, 1)?;
                        (
                            zeroize::Zeroizing::new(material.byte_string()?.to_vec()),
                            format,
                        )
                    } else if [3, 4].contains(&source.object_type) && source.algorithm == 4 {
                        let format = if source.object_type == 4 { 4 } else { 5 };
                        (
                            crypto::rsa::export(&source.material, source.object_type == 4, format)?,
                            format,
                        )
                    } else {
                        (
                            zeroize::Zeroizing::new(source.material.clone()),
                            if source.object_type == 2 {
                                1
                            } else {
                                source.format
                            },
                        )
                    };
                let policy = (
                    attr_flag(&source.attrs, SENSITIVE, false)?,
                    attr_flag(&source.attrs, EXTRACTABLE, true)?,
                );
                let description = crate::store::SplitSource {
                    object_type: source.object_type,
                    secret_type: source.secret_type,
                    opaque_type: source.opaque_type,
                    pgp_version: source.pgp_version,
                    certificate_type: source.certificate_type,
                    pgp_signatures: pgp::signatures(&source.attrs),
                    format: source.format,
                    material_format,
                    length: material.len(),
                    structured: false,
                    sensitive: policy.0,
                    extractable: policy.1,
                    split: source.split.clone().map(Box::new),
                };
                (
                    material,
                    description,
                    factory_attributes(&source, v)?,
                    source.algorithm,
                    source.bits,
                    policy,
                )
            } else {
                let algorithm = attr_num(&attrs, CRYPTOGRAPHIC_ALGORITHM, 3)?;
                let bits = attr_num(&attrs, CRYPTOGRAPHIC_LENGTH, 256)?;
                let (material, kind, source_format, bits) =
                    if algorithm == 4 || ec::algorithm(algorithm) {
                        let (key, bits, _) = rekey::generate_pair(&attrs, &[], v)?;
                        (
                            key.private_key_to_pkcs8()
                                .map_err(|_| fail(10, "Split source key generation failed"))?,
                            4,
                            4,
                            bits,
                        )
                    } else {
                        validate_symmetric_parameters(algorithm, bits, v)?;
                        if bits == 0
                            || !bits.is_multiple_of(8)
                            || bits as usize / 8 > crypto::split::MAX_SECRET_BYTES
                        {
                            return Err(fail(7, "Invalid Split Key source length"));
                        }
                        (crypto::random(bits as usize / 8)?.to_vec(), 2, 1, bits)
                    };
                let description = crate::store::SplitSource {
                    object_type: kind,
                    secret_type: 2,
                    opaque_type: opaque::LEGACY_TYPE,
                    pgp_version: pgp::DEFAULT_VERSION,
                    certificate_type: 1,
                    pgp_signatures: vec![],
                    format: source_format,
                    material_format: source_format,
                    length: material.len(),
                    structured: false,
                    sensitive: false,
                    extractable: true,
                    split: None,
                };
                (
                    zeroize::Zeroizing::new(material),
                    description,
                    vec![],
                    algorithm,
                    bits,
                    (false, true),
                )
            };
        let requested = attrs.clone();
        attrs = attributes::merge(attrs, source_attrs)?;
        // Request flags are checked before source precedence can replace them.
        let mut requested_flags = requested;
        constrain_flags(&mut requested_flags, source_policy.0, source_policy.1, v)?;
        let policy = constrain_flags(&mut attrs, source_policy.0, source_policy.1, v)?;
        strip_attributes(&mut attrs);
        attrs.retain(|a| ![CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_LENGTH].contains(&a.tag));
        if algorithm != 0 {
            attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
        }
        if bits != 0 {
            attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32));
        }
        if meta.method == 3 && meta.prime.is_none() {
            meta.prime = Some(generated_prime(material.len(), v)?);
        }
        let shares = parameters(&meta, material.len(), v)?
            .split(&material)
            .map_err(|_| fail(10, "Split Key generation failed"))?;
        let family = crypto::uuid();
        let commitment = crypto::sha256(&material).to_vec();
        let mut ids = Vec::with_capacity(shares.len());
        for share in shares {
            let mut part = meta.clone();
            part.part = u32::from(share.index);
            part.source = Some(Box::new(source.clone()));
            part.family = Some(family.clone());
            part.commitment = Some(commitment.clone());
            let mut object_fields = fields_for_metadata(&part);
            let mut block = vec![
                Node::enumeration(KEY_FORMAT_TYPE, format),
                Node::structure(
                    KEY_VALUE,
                    vec![Node::bytes(KEY_MATERIAL, share.value.to_vec())],
                ),
            ];
            if algorithm != 0 {
                block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
            }
            if bits != 0 {
                block.push(Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32));
            }
            object_fields.push(Node::structure(KEY_BLOCK, block));
            let mut part_attrs = attrs.clone();
            if v.0 >= 3
                && let Some(poly) = part.polynomial
            {
                part_attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, poly));
            }
            let mut object = self.split_result(
                owner,
                v,
                5,
                Node::structure(SPLIT_KEY, object_fields),
                part_attrs,
                policy,
            )?;
            object.protection_mask = protection_mask;
            object.split = Some(part);
            super::quantum::check(&object)?;
            self.store.insert(&object)?;
            ids.push(object.id.clone());
        }
        *placeholder = ids.first().cloned();
        let mut result = ids
            .into_iter()
            .map(|id| Node::text(UNIQUE_IDENTIFIER, id))
            .collect::<Vec<_>>();
        if v == Version(1, 2) {
            result.insert(0, Node::enumeration(OBJECT_TYPE, 5));
        }
        Ok(result)
    }
}

struct DataTypes {
    secret: u32,
    opaque: u32,
    pgp: u32,
    certificate: u32,
}
fn managed_object(
    kind: u32,
    format: u32,
    mut material: Node,
    algorithm: u32,
    bits: u32,
    data_types: DataTypes,
    nested: Option<&SplitKeyMetadata>,
) -> R<Node> {
    if kind == 1 {
        return Ok(Node::structure(
            CERTIFICATE,
            vec![
                Node::enumeration(CERTIFICATE_TYPE, data_types.certificate),
                Node::bytes(CERTIFICATE_VALUE, material.byte_string()?.to_vec()),
            ],
        ));
    }
    if kind == 8 {
        return Ok(Node::structure(
            OPAQUE_OBJECT,
            vec![
                Node::enumeration(OPAQUE_DATA_TYPE, data_types.opaque),
                Node::bytes(OPAQUE_DATA_VALUE, material.byte_string()?.to_vec()),
            ],
        ));
    }
    if kind == 2 && format == 7 && matches!(material.value, Value::ByteString(_)) {
        material = Node::structure(
            KEY_MATERIAL,
            vec![Node::bytes(KEY, material.byte_string()?.to_vec())],
        );
    }
    let mut block = vec![
        Node::enumeration(KEY_FORMAT_TYPE, format),
        Node::structure(KEY_VALUE, vec![material]),
    ];
    if algorithm != 0 {
        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
    }
    if bits != 0 {
        block.push(Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32));
    }
    let mut fields = if kind == 5 {
        fields_for_metadata(nested.ok_or(fail(
            6,
            "Reconstructing a nested Split Key requires its original metadata",
        ))?)
    } else {
        vec![]
    };
    if kind == 9 {
        fields.push(Node::int(PGP_KEY_VERSION, data_types.pgp as i32));
    }
    if kind == 7 {
        fields.push(Node::enumeration(SECRET_DATA_TYPE, data_types.secret));
    }
    fields.push(Node::structure(KEY_BLOCK, block));
    Ok(Node::structure(object_tag(kind)?, fields))
}
impl Engine {
    pub(super) fn join_split(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        if v < Version(1, 2) {
            return Err(fail(5, "Join Split Key requires KMIP 1.2"));
        }
        let allowed = [
            OBJECT_TYPE,
            UNIQUE_IDENTIFIER,
            SECRET_DATA_TYPE,
            TEMPLATE_ATTRIBUTE,
            ATTRIBUTES,
            PROTECTION_STORAGE_MASKS,
        ];
        if p.children()?.iter().any(|n| !allowed.contains(&n.tag)) {
            return Err(fail(8, "Unsupported Join Split Key field"));
        }
        for tag in allowed.into_iter().filter(|tag| *tag != UNIQUE_IDENTIFIER) {
            if p.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate Join Split Key field"));
            }
        }
        let protection_mask = protection::select(p, v)?;
        let kind = p.required(OBJECT_TYPE)?.number()?;
        object_tag(kind)?;
        if kind == certificate_request::KIND {
            return Err(fail(8, "Certificate Request objects cannot be joined"));
        }
        if kind != 7 && p.get(SECRET_DATA_TYPE).is_some() {
            return Err(fail(7, "Secret Data Type requires a Secret Data result"));
        }
        let mut requested = read_attrs(p, v)?;
        let desired_format = ec::take_format(&mut requested, v)?;
        metadata::prepare(&mut requested, v, true)?;
        validate_attrs(&requested, v)?;
        let mut objects = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for identifier in p.all(UNIQUE_IDENTIFIER) {
            let id = identifier.string()?;
            if !seen.insert(id.to_owned()) {
                return Err(fail(7, "Duplicate Split Key identifier"));
            }
            if objects.len() >= crypto::split::MAX_PARTS {
                return Err(factory_limit(v, "Too many Split Key parts"));
            }
            let object = self.split_source(
                owner,
                v,
                &Node::structure(REQUEST_PAYLOAD, vec![Node::text(UNIQUE_IDENTIFIER, id)]),
            )?;
            if object.object_type != 5 {
                return Err(fail(
                    if v.0 >= 2 { 0x28 } else { 7 },
                    "Join Split Key requires Split Key objects",
                ));
            }
            objects.push(object);
        }
        let first = objects
            .first()
            .ok_or(fail(6, "Join Split Key requires parts"))?;
        let meta = first
            .split
            .as_ref()
            .ok_or(fail(7, "Split Key metadata missing"))?;
        if objects.len() < meta.threshold as usize {
            // 1.2 table 225, 1.3 and 1.4 Join Split Key Errors: "Number of
            // Unique Identifiers given in request is less than Split Key
            // Threshold" -> Cryptographic Failure. 2.x lists no row for it.
            return Err(fail(
                if v.0 == 1 { 10 } else { 7 },
                "Insufficient Split Key parts",
            ));
        }
        let mut source = None;
        let mut family = None;
        let mut commitment: Option<&[u8]> = None;
        let mut sensitive = false;
        let mut extractable = true;
        for object in &objects {
            let part = object
                .split
                .as_ref()
                .ok_or(fail(7, "Split Key metadata missing"))?;
            if part.parts != meta.parts
                || part.threshold != meta.threshold
                || part.method != meta.method
                || part.prime != meta.prime
                || part.polynomial != meta.polynomial
            {
                return Err(fail(7, "Split Key parameters do not agree"));
            }
            if let Some(value) = part.family.as_deref() {
                if family.is_some_and(|known| known != value) {
                    return Err(fail(7, "Split Key families do not agree"));
                }
                family = Some(value);
            }
            if let Some(value) = part.commitment.as_deref() {
                if value.len() != 32 {
                    return Err(fail(7, "Invalid Split Key source commitment"));
                }
                if commitment.is_some_and(|known| !openssl::memcmp::eq(known, value)) {
                    return Err(fail(7, "Split Key source commitments do not agree"));
                }
                commitment = Some(value);
            }
            if let Some(description) = part.source.as_deref() {
                if source.is_some_and(|known: &crate::store::SplitSource| {
                    known.length != description.length
                        || known.object_type != description.object_type
                        || known.format != description.format
                        || known.material_format != description.material_format
                        || known.structured != description.structured
                        || known.opaque_type != description.opaque_type
                        || known.certificate_type != description.certificate_type
                        || known.pgp_version != description.pgp_version
                        || known.pgp_signatures != description.pgp_signatures
                }) {
                    return Err(fail(7, "Split Key source descriptions do not agree"));
                }
                source = Some(description);
                sensitive |= description.sensitive;
                extractable &= description.extractable;
            }
            sensitive |= attr_flag(&object.attrs, SENSITIVE, false)?;
            extractable &= attr_flag(&object.attrs, EXTRACTABLE, true)?;
        }
        // Only an explicit requested weakening is denied. An inherited flag
        // from the first share must not override stricter flags on other parts.
        let policy = constrain_flags(&mut requested, sensitive, extractable, v)?;
        let mut inherited = factory_attributes(first, v)?;
        inherited.retain(|a| ![SENSITIVE, EXTRACTABLE].contains(&a.tag));
        let mut attrs = attributes::merge(inherited, requested)?;
        strip_attributes(&mut attrs);
        let algorithm = attr_num(
            &attrs,
            CRYPTOGRAPHIC_ALGORITHM,
            if matches!(kind, 3 | 4) {
                4
            } else if kind == 2 {
                3
            } else {
                0
            },
        )?;
        let declared_bits = attr_num(&attrs, CRYPTOGRAPHIC_LENGTH, 0)?;
        let binary_object = matches!(kind, 2 | 7);
        let needs_length = binary_object || kind == 8;
        let length = if let Some(source) = source {
            source.length
        } else if binary_object && declared_bits != 0 {
            if !declared_bits.is_multiple_of(8) {
                return Err(fail(7, "Join result length must be byte aligned"));
            }
            declared_bits as usize / 8
        } else if let Some(prime) = &meta.prime {
            if needs_length {
                return Err(fail(
                    6,
                    "External prime shares require the original binary length",
                ));
            }
            (prime.len() * 8 - prime[0].leading_zeros() as usize - 1) / 8
        } else {
            if meta.method == 2 && needs_length {
                return Err(fail(
                    6,
                    "External GF(2^16) shares require the original binary length",
                ));
            }
            first.material.len()
        };
        let shares = objects
            .iter()
            .map(|object| crypto::split::Share {
                index: object.split.as_ref().expect("validated metadata").part as u16,
                value: zeroize::Zeroizing::new(object.material.clone()),
            })
            .collect::<Vec<_>>();
        let mut material = parameters(meta, length, v)?
            .join(&shares)
            .map_err(|_| fail(10, "Split Key reconstruction failed"))?;
        if commitment.is_some_and(|known| !openssl::memcmp::eq(known, &crypto::sha256(&material))) {
            return Err(fail(
                10,
                "Split Key reconstruction does not match its source",
            ));
        }
        // DER and valid armored/binary PGP packets cannot start with zero.
        // Without local provenance, discard only field/GF(2^16) prefix padding.
        if source.is_none() && matches!(kind, 1 | 3 | 4 | 9) && [2, 3].contains(&meta.method) {
            let zeros = material.iter().take_while(|byte| **byte == 0).count();
            material.drain(..zeros);
        }
        let description = source.filter(|source| source.object_type == kind);
        let certificate_type = if kind == 1 {
            description
                .map(|source| source.certificate_type)
                .map(Ok)
                .unwrap_or_else(|| certificate::infer(&material))?
        } else {
            1
        };
        if (kind == 9 || kind == 1 && certificate_type == 2)
            && let Some(description) =
                description.filter(|description| !description.pgp_signatures.is_empty())
        {
            let mut declared = pgp::signatures(&attrs);
            let mut expected = description.pgp_signatures.clone();
            declared.sort_unstable();
            expected.sort_unstable();
            if !declared.is_empty() && declared != expected {
                return Err(fail(
                    7,
                    "Reconstructed PGP signature metadata conflicts with its source",
                ));
            }
            attrs.retain(|attribute| attribute.tag != DIGITAL_SIGNATURE_ALGORITHM);
            attrs.extend(
                description
                    .pgp_signatures
                    .iter()
                    .map(|value| Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, *value)),
            );
        }
        let original_format =
            description
                .map(|source| source.material_format)
                .unwrap_or(match kind {
                    3 => 5,
                    4 => 4,
                    _ => 1,
                });
        let format = desired_format.unwrap_or_else(|| {
            description
                .map(|source| source.format)
                .unwrap_or(original_format)
        });
        let secret_type = number(
            p,
            SECRET_DATA_TYPE,
            description.map(|source| source.secret_type).unwrap_or(2),
        )?;
        pgp::available(kind, v)?;
        let pgp_version = if let Some(description) = description {
            description.pgp_version
        } else if kind == 9 {
            crypto::pgp::version(&material)
                .map_err(|_| fail(7, "Cannot determine reconstructed PGP version"))?
        } else {
            pgp::DEFAULT_VERSION
        };
        let opaque_type = description
            .map(|source| source.opaque_type)
            .unwrap_or(opaque::LEGACY_TYPE);
        let bits = if binary_object {
            (material.len() * 8) as u32
        } else {
            declared_bits
        };
        let nested = description.and_then(|source| source.split.as_deref());
        if kind == 5
            && v.0 >= 3
            && let Some(poly) = nested.and_then(|meta| meta.polynomial)
        {
            attrs.push(Node::enumeration(SPLIT_KEY_POLYNOMIAL, poly));
        }
        let key_material = if description.is_some_and(|source| source.structured) {
            let node = crate::ttlv::decode(&material)?;
            if node.tag != KEY_MATERIAL {
                return Err(fail(7, "Invalid reconstructed Key Material"));
            }
            node
        } else {
            Node::bytes(KEY_MATERIAL, material.to_vec())
        };
        let mut object = managed_object(
            kind,
            original_format,
            key_material,
            algorithm,
            bits,
            DataTypes {
                secret: secret_type,
                opaque: opaque_type,
                pgp: pgp_version,
                certificate: certificate_type,
            },
            nested,
        )?;
        if format != original_format && !matches!(kind, 1 | 8) {
            let temporary = self.build_object(
                owner,
                v,
                &Node::structure(
                    REQUEST_PAYLOAD,
                    vec![
                        Node::enumeration(OBJECT_TYPE, kind),
                        attribute_container(v, attrs.clone())?,
                        object,
                    ],
                ),
                true,
            )?;
            let key_material = if matches!(kind, 3 | 4) && ec::algorithm(algorithm) {
                if !ec::format_allowed(kind, algorithm, format, v) {
                    return Err(fail(0x10, "Unsupported reconstructed EC format"));
                }
                ec::key_material(&temporary, format, 1)?
            } else if matches!(kind, 3 | 4) && algorithm == 4 {
                Node::bytes(
                    KEY_MATERIAL,
                    crypto::rsa::export(&temporary.material, kind == 4, format)?.to_vec(),
                )
            } else {
                Node::bytes(KEY_MATERIAL, temporary.material.clone())
            };
            object = managed_object(
                kind,
                format,
                key_material,
                algorithm,
                bits,
                DataTypes {
                    secret: secret_type,
                    opaque: opaque_type,
                    pgp: pgp_version,
                    certificate: certificate_type,
                },
                nested,
            )?;
        }
        let mut result = self.split_result(owner, v, kind, object, attrs, policy)?;
        result.protection_mask = protection_mask;
        if kind == 5 {
            result.split = nested.cloned();
            check_version(&result, v)?;
        }
        super::quantum::check(&result)?;
        self.store.insert(&result)?;
        *placeholder = Some(result.id.clone());
        let mut response = vec![Node::text(UNIQUE_IDENTIFIER, &result.id)];
        if v == Version(1, 2) {
            response.insert(0, Node::enumeration(OBJECT_TYPE, kind));
        }
        Ok(response)
    }
}
