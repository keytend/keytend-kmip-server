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

//! Derived X.509 metadata, independent from certificate trust validation.
use super::*;
/// Register Attribute Requirements (1.1 Table 129, 2.1 Table 293, 3.0 Table
/// 402) list Cryptographic Algorithm, Cryptographic Length, Certificate Length
/// and Cryptographic Usage Mask, but the attribute rules make the first three
/// "Initially set by Server" and Certificate Length "SHALL be set by the server
/// when the object is created or registered" and not modifiable by the client;
/// the Usage Mask is "Initially set by Server or Client". The mandatory
/// Baseline test BL-M-10 (Profiles 2.0-3.0) registers with only Certificate
/// Type. The server therefore derives these from the certificate (`prepare`
/// rejects supplied values that conflict) and an omitted Usage Mask grants no
/// use. Supplied values must still have the defined types.
pub(super) fn require_register(payload: &Node, v: Version) -> R<()> {
    if v < Version(1, 1) {
        return Ok(());
    }
    let attrs = read_attrs(payload, v)?;
    for tag in [
        CRYPTOGRAPHIC_ALGORITHM,
        CRYPTOGRAPHIC_LENGTH,
        CERTIFICATE_LENGTH,
        CRYPTOGRAPHIC_USAGE_MASK,
    ] {
        let Some(a) = attrs.iter().find(|a| a.tag == tag) else {
            continue;
        };
        let valid = match tag {
            CRYPTOGRAPHIC_ALGORITHM => matches!(a.value, Value::Enumeration(_)),
            CRYPTOGRAPHIC_USAGE_MASK => matches!(a.value,Value::Integer(n) if n>=0),
            _ => matches!(a.value,Value::Integer(n) if n>0),
        };
        if !valid {
            return Err(fail(7, "Invalid Certificate registration attribute type"));
        }
    }
    Ok(())
}
pub(super) fn read_type(object: &Node) -> R<u32> {
    no_fields(object, &[CERTIFICATE_TYPE, CERTIFICATE_VALUE])?;
    match object.required(CERTIFICATE_TYPE)?.value {
        Value::Enumeration(value @ (1 | 2)) => Ok(value),
        Value::Enumeration(_) => Err(fail(8, "Unsupported Certificate Type")),
        _ => Err(fail(7, "Certificate Type must be an Enumeration")),
    }
}
pub(super) fn identity_attribute(tag: u32) -> bool {
    matches!(
        tag,
        X_509_CERTIFICATE_IDENTIFIER
            | X_509_CERTIFICATE_ISSUER
            | X_509_CERTIFICATE_SUBJECT
            | CERTIFICATE_IDENTIFIER
            | CERTIFICATE_ISSUER
            | CERTIFICATE_SUBJECT
            | CERTIFICATE_SUBJECT_CN
            ..=CERTIFICATE_ISSUER_DN_QUALIFIER | CERTIFICATE_SUBJECT_DN | CERTIFICATE_ISSUER_DN
    )
}
pub(super) fn owned_attribute(tag: u32) -> bool {
    identity_attribute(tag)
        || matches!(
            tag,
            CERTIFICATE_TYPE | CERTIFICATE_LENGTH | DIGITAL_SIGNATURE_ALGORITHM
        )
}
fn available(tag: u32, v: Version) -> bool {
    match tag {
        CERTIFICATE_IDENTIFIER | CERTIFICATE_ISSUER | CERTIFICATE_SUBJECT => v.0 == 1,
        X_509_CERTIFICATE_IDENTIFIER | X_509_CERTIFICATE_ISSUER | X_509_CERTIFICATE_SUBJECT => {
            v >= Version(1, 1)
        }
        CERTIFICATE_SUBJECT_CN..=CERTIFICATE_ISSUER_DN_QUALIFIER => v.0 >= 2,
        CERTIFICATE_SUBJECT_DN | CERTIFICATE_ISSUER_DN => v.0 >= 3,
        _ => true,
    }
}
fn identity_nodes(material: &[u8]) -> R<Vec<Node>> {
    let m = crypto::certificate_attributes::inspect(material)
        .map_err(|_| fail(7, "Invalid or unsupported X.509 identity"))?;
    let mut subject = vec![Node::bytes(SUBJECT_DISTINGUISHED_NAME, m.subject)];
    subject.extend(
        m.subject_alternatives
            .into_iter()
            .map(|b| Node::bytes(SUBJECT_ALTERNATIVE_NAME, b)),
    );
    let mut issuer = vec![Node::bytes(ISSUER_DISTINGUISHED_NAME, m.issuer.clone())];
    issuer.extend(
        m.issuer_alternatives
            .into_iter()
            .map(|b| Node::bytes(ISSUER_ALTERNATIVE_NAME, b)),
    );
    let mut nodes = vec![
        Node::structure(
            X_509_CERTIFICATE_IDENTIFIER,
            vec![
                Node::bytes(ISSUER_DISTINGUISHED_NAME, m.issuer),
                Node::bytes(CERTIFICATE_SERIAL_NUMBER, m.serial),
            ],
        ),
        Node::structure(X_509_CERTIFICATE_SUBJECT, subject),
        Node::structure(X_509_CERTIFICATE_ISSUER, issuer),
        Node::structure(
            CERTIFICATE_IDENTIFIER,
            vec![
                Node::text(ISSUER, &m.issuer_text),
                Node::text(SERIAL_NUMBER, &m.serial_text),
            ],
        ),
        Node::structure(
            CERTIFICATE_SUBJECT,
            vec![Node::text(
                CERTIFICATE_SUBJECT_DISTINGUISHED_NAME,
                &m.subject_text,
            )],
        ),
        Node::structure(
            CERTIFICATE_ISSUER,
            vec![Node::text(
                CERTIFICATE_ISSUER_DISTINGUISHED_NAME,
                &m.issuer_text,
            )],
        ),
        Node::text(CERTIFICATE_SUBJECT_DN, m.subject_text),
        Node::text(CERTIFICATE_ISSUER_DN, m.issuer_text),
    ];
    nodes.extend(m.fields.into_iter().map(|(t, s)| Node::text(t, s)));
    Ok(nodes)
}
fn prepare_identity(material: &[u8], attrs: &mut Vec<Node>) -> R<()> {
    let expected = identity_nodes(material)?;
    // Client declarations may omit server-owned fields. Supplied instances must
    // equal the complete derived collection for that attribute, including repeats.
    for tag in attrs
        .iter()
        .filter(|a| identity_attribute(a.tag))
        .map(|a| a.tag)
        .collect::<std::collections::HashSet<_>>()
    {
        let actual = attrs.iter().filter(|a| a.tag == tag).collect::<Vec<_>>();
        let mut derived = expected.iter().filter(|a| a.tag == tag).collect::<Vec<_>>();
        if actual.len() != derived.len() {
            return Err(fail(7, "Certificate identity conflicts with material"));
        }
        for value in actual {
            let position = derived
                .iter()
                .position(|candidate| *candidate == value)
                .ok_or(fail(7, "Certificate identity conflicts with material"))?;
            derived.remove(position);
        }
    }
    attrs.retain(|a| !identity_attribute(a.tag));
    attrs.extend(expected);
    attributes::limits(attrs)
}
pub(super) fn attribute_context(kind: u32, attrs: &[Node]) -> R<()> {
    if kind != 1
        && attrs.iter().any(|a| {
            identity_attribute(a.tag) || matches!(a.tag, CERTIFICATE_TYPE | CERTIFICATE_LENGTH)
        })
    {
        return Err(fail(
            8,
            "Certificate attributes require a Certificate object",
        ));
    }
    Ok(())
}
pub(super) fn validate_attribute(a: &Node, v: Version) -> R<()> {
    if identity_attribute(a.tag) {
        if !available(a.tag, v) {
            return Err(fail(
                7,
                "Certificate attribute is unavailable in this version",
            ));
        }
        if matches!(
            a.tag,
            CERTIFICATE_SUBJECT_CN
                ..=CERTIFICATE_ISSUER_DN_QUALIFIER | CERTIFICATE_SUBJECT_DN | CERTIFICATE_ISSUER_DN
        ) {
            a.string()?;
            return Ok(());
        }
        let (required, optional, bytes) = match a.tag {
            X_509_CERTIFICATE_IDENTIFIER => (
                vec![ISSUER_DISTINGUISHED_NAME, CERTIFICATE_SERIAL_NUMBER],
                vec![],
                true,
            ),
            X_509_CERTIFICATE_SUBJECT => (
                vec![SUBJECT_DISTINGUISHED_NAME],
                vec![SUBJECT_ALTERNATIVE_NAME],
                true,
            ),
            X_509_CERTIFICATE_ISSUER => (
                vec![ISSUER_DISTINGUISHED_NAME],
                vec![ISSUER_ALTERNATIVE_NAME],
                true,
            ),
            CERTIFICATE_IDENTIFIER => (vec![ISSUER, SERIAL_NUMBER], vec![], false),
            CERTIFICATE_SUBJECT => (
                vec![CERTIFICATE_SUBJECT_DISTINGUISHED_NAME],
                vec![CERTIFICATE_SUBJECT_ALTERNATIVE_NAME],
                false,
            ),
            _ => (
                vec![CERTIFICATE_ISSUER_DISTINGUISHED_NAME],
                vec![CERTIFICATE_ISSUER_ALTERNATIVE_NAME],
                false,
            ),
        };
        for tag in &required {
            if a.all(*tag).count() != 1 {
                return Err(fail(7, "Missing or duplicate certificate identity field"));
            }
        }
        for n in a.children()? {
            if !required.contains(&n.tag) && !optional.contains(&n.tag) {
                return Err(fail(7, "Unexpected certificate identity field"));
            }
            if bytes {
                n.byte_string()?;
            } else {
                n.string()?;
            }
        }
        let invalid = |_| fail(7, "Invalid restored X.509 identity encoding");
        if [X_509_CERTIFICATE_IDENTIFIER, X_509_CERTIFICATE_ISSUER].contains(&a.tag) {
            crypto::certificate_attributes::validate_name_der(
                a.required(ISSUER_DISTINGUISHED_NAME)?.byte_string()?,
                false,
            )
            .map_err(invalid)?;
        }
        if a.tag == X_509_CERTIFICATE_IDENTIFIER {
            crypto::certificate_attributes::validate_serial_der(
                a.required(CERTIFICATE_SERIAL_NUMBER)?.byte_string()?,
            )
            .map_err(invalid)?;
        }
        if a.tag == X_509_CERTIFICATE_SUBJECT {
            let empty = crypto::certificate_attributes::validate_name_der(
                a.required(SUBJECT_DISTINGUISHED_NAME)?.byte_string()?,
                true,
            )
            .map_err(invalid)?;
            if empty && a.all(SUBJECT_ALTERNATIVE_NAME).next().is_none() {
                return Err(fail(7, "Empty subject requires alternative names"));
            }
        }
        for n in a
            .children()?
            .iter()
            .filter(|n| [SUBJECT_ALTERNATIVE_NAME, ISSUER_ALTERNATIVE_NAME].contains(&n.tag))
        {
            crypto::certificate_attributes::validate_general_name_der(n.byte_string()?)
                .map_err(invalid)?;
        }
        return Ok(());
    }
    let valid = match a.tag {
        CERTIFICATE_TYPE => matches!(a.value, Value::Enumeration(1 | 2)),
        CERTIFICATE_LENGTH => v >= Version(1, 1) && matches!(a.value, Value::Integer(n) if n > 0),
        _ => false,
    };
    if !valid {
        return Err(fail(7, "Invalid certificate attribute"));
    }
    Ok(())
}
fn set(attrs: &mut Vec<Node>, expected: Node) -> R<()> {
    if attrs
        .iter()
        .any(|a| a.tag == expected.tag && a != &expected)
    {
        return Err(fail(7, "Certificate metadata conflicts with material"));
    }
    attrs.retain(|a| a.tag != expected.tag);
    attrs.push(expected);
    Ok(())
}
pub(super) fn prepare(
    certificate_type: u32,
    der: &[u8],
    attrs: &mut Vec<Node>,
    v: Version,
) -> R<(u32, u32)> {
    if certificate_type == 2 {
        return prepare_pgp(der, attrs, v);
    }
    ec::certificate_curve(der)?;
    let metadata = crypto::certificate::inspect(der)
        .map_err(|_| fail(7, "Invalid or unsupported X.509 certificate"))?;
    let declared = attrs.iter().find(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM);
    let algorithm = if metadata.algorithm == 26 {
        match declared.map(|a| &a.value) {
            Some(Value::Enumeration(value @ (6 | 14 | 15 | 26))) => *value,
            None if v >= Version(1, 2) => 26,
            None => {
                return Err(fail(
                    6,
                    "Legacy EC certificates require an explicit public-key algorithm",
                ));
            }
            _ => return Err(fail(7, "Certificate public-key algorithm conflicts")),
        }
    } else {
        metadata.algorithm
    };
    if !crate::encoding::known_enumeration(
        CRYPTOGRAPHIC_ALGORITHM,
        algorithm,
        &format!("{}.{}", v.0, v.1),
    ) {
        return Err(fail(
            8,
            "Certificate public-key algorithm is unavailable in this version",
        ));
    }
    if attrs
        .iter()
        .filter(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM)
        .count()
        > 1
    {
        return Err(fail(
            if v.0 >= 2 { 0x23 } else { 7 },
            "X.509 signature attribute is single valued",
        ));
    }
    set(attrs, Node::enumeration(CERTIFICATE_TYPE, 1))?;
    set(attrs, Node::int(CERTIFICATE_LENGTH, metadata.length as i32))?;
    set(attrs, Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm))?;
    set(attrs, Node::int(CRYPTOGRAPHIC_LENGTH, metadata.bits as i32))?;
    let signature = metadata.signature.ok_or(fail(
        8,
        "Certificate signature algorithm has no supported KMIP mapping",
    ))?;
    if v >= Version(1, 1) {
        pgp::signature(
            &Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, signature),
            v,
        )?;
    }
    set(
        attrs,
        Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, signature),
    )?;
    prepare_identity(der, attrs)?;
    if v.0 == 1 {
        key_usage_mask(der, attrs)?;
    }
    Ok((algorithm, metadata.bits))
}
/// Usage Mask bits that the 1.x X.509 Key Usage mapping speaks about.
const KEY_USAGE_GOVERNED: u32 = 0x3c3f;
/// 1.0 section 3.14, 1.1-1.4 section 3.19 (1.4 Table 96): "X.509 Key Usage
/// values SHALL be mapped to Cryptographic Usage Mask values in the following
/// manner". The mask permitted by a Key Usage extension (bit n is the RFC
/// 5280 named bit n); an "X or Y" row permits both values.
pub(super) fn key_usage_to_mask(key_usage: u16) -> u32 {
    [
        (0, 0x1 | 0x2),   // digitalSignature: Sign or Verify
        (1, 0x400),       // contentCommitment: Content Commitment
        (2, 0x10 | 0x20), // keyEncipherment: Wrap Key or Unwrap Key
        (3, 0x4 | 0x8),   // dataEncipherment: Encrypt or Decrypt
        (4, 0x800),       // keyAgreement: Key Agreement
        (5, 0x1000),      // keyCertSign: Certificate Sign
        (6, 0x2000),      // cRLSign: CRL Sign
        (7, 0x4),         // encipherOnly: Encrypt
        (8, 0x8),         // decipherOnly: Decrypt
    ]
    .iter()
    .filter(|(bit, _)| key_usage & (1 << bit) != 0)
    .fold(0, |mask, (_, usage)| mask | usage)
}
/// 1.0-1.4 Register of an X.509 certificate with a Key Usage extension: an
/// omitted Usage Mask is derived through the mapping, and a supplied one may
/// not claim a mapped usage that the extension does not grant. Usages the
/// mapping does not cover (Export, MAC, Derive Key, cryptogram and translate
/// usages; the text notes Extended Key Usage is "not considered") are left to
/// the client. Without the extension nothing is derived, and an omitted mask
/// stays 0 (no use), as in 2.x.
fn key_usage_mask(der: &[u8], attrs: &mut Vec<Node>) -> R<()> {
    let identity = crypto::certificate_attributes::inspect(der)
        .map_err(|_| fail(7, "Invalid certificate identity or Key Usage"))?;
    let Some(key_usage) = identity.key_usage else {
        return Ok(());
    };
    let mapped = key_usage_to_mask(key_usage);
    match attrs.iter().find(|a| a.tag == CRYPTOGRAPHIC_USAGE_MASK) {
        None => attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, mapped as i32)),
        Some(a) => {
            let mask = a.number()?;
            if mask & KEY_USAGE_GOVERNED & !mapped != 0 {
                return Err(fail(
                    7,
                    "Cryptographic Usage Mask conflicts with the certificate Key Usage",
                ));
            }
        }
    }
    Ok(())
}
pub(super) fn project(v: Version, attrs: &mut Vec<Node>) {
    attrs.retain(|a| !identity_attribute(a.tag) || available(a.tag, v));
    if v < Version(1, 1) {
        attrs.retain(|a| !matches!(a.tag, CERTIFICATE_LENGTH | DIGITAL_SIGNATURE_ALGORITHM));
    }
}

/// Existing DER records can be enriched from their actual bytes. Never invent
/// unavailable metadata for destroyed records or unsupported historic formats.
pub(super) fn hydrate(obj: &mut Object) {
    if obj.object_type != 1
        || obj.certificate_type != 1
        || obj.material.is_empty()
        || [
            X_509_CERTIFICATE_IDENTIFIER,
            X_509_CERTIFICATE_SUBJECT,
            X_509_CERTIFICATE_ISSUER,
            CERTIFICATE_TYPE,
            CERTIFICATE_LENGTH,
            DIGITAL_SIGNATURE_ALGORITHM,
        ]
        .iter()
        .all(|tag| obj.attrs.iter().any(|a| a.tag == *tag))
    {
        return;
    }
    let mut attrs = obj.attrs.clone();
    if obj.algorithm != 0 && !attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM) {
        attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm));
    }
    if obj.bits != 0 && !attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH) {
        attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, obj.bits as i32));
    }
    // Derive a version-neutral stored representation. Requested wire versions
    // separately reject values that they cannot represent.
    if let Ok((algorithm, bits)) = prepare(1, &obj.material, &mut attrs, Version(3, 0)) {
        obj.attrs = attrs;
        obj.algorithm = algorithm;
        obj.bits = bits;
    }
}

pub(super) fn imported(attrs: &[Node], v: Version, certificate_type: u32) -> R<()> {
    let mut required = vec![
        CRYPTOGRAPHIC_ALGORITHM,
        CRYPTOGRAPHIC_LENGTH,
        CRYPTOGRAPHIC_USAGE_MASK,
        CERTIFICATE_TYPE,
    ];
    if v >= Version(1, 1) {
        required.extend([CERTIFICATE_LENGTH, DIGITAL_SIGNATURE_ALGORITHM]);
    }
    if certificate_type == 1 {
        required.extend([
            X_509_CERTIFICATE_IDENTIFIER,
            X_509_CERTIFICATE_SUBJECT,
            X_509_CERTIFICATE_ISSUER,
        ]);
        if v.0 == 1 {
            required.extend([
                CERTIFICATE_IDENTIFIER,
                CERTIFICATE_SUBJECT,
                CERTIFICATE_ISSUER,
            ]);
        }
    }
    for tag in required {
        let a = attrs
            .iter()
            .find(|a| a.tag == tag)
            .ok_or(fail(6, "Mandatory imported Certificate metadata missing"))?;
        let valid = match tag {
            tag if identity_attribute(tag) => {
                validate_attribute(a, v)?;
                true
            }
            CRYPTOGRAPHIC_ALGORITHM => {
                matches!(a.value,Value::Enumeration(value) if crate::encoding::known_enumeration(tag,value,&format!("{}.{}",v.0,v.1)))
            }
            CERTIFICATE_TYPE => {
                matches!(a.value, Value::Enumeration(value) if value==certificate_type)
            }
            CRYPTOGRAPHIC_USAGE_MASK => matches!(a.value,Value::Integer(n) if n>=0),
            DIGITAL_SIGNATURE_ALGORITHM => {
                pgp::signature(a, v)?;
                true
            }
            _ => matches!(a.value,Value::Integer(n) if n>0),
        };
        if !valid {
            return Err(fail(7, "Invalid imported Certificate metadata"));
        }
    }
    if certificate_type == 1
        && attrs
            .iter()
            .filter(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM)
            .count()
            > 1
    {
        return Err(fail(
            if v.0 >= 2 { 0x23 } else { 7 },
            "X.509 signature attribute is single valued",
        ));
    }
    Ok(())
}

fn prepare_pgp(material: &[u8], attrs: &mut Vec<Node>, v: Version) -> R<(u32, u32)> {
    if attrs.iter().any(|a| identity_attribute(a.tag)) {
        return Err(fail(
            7,
            "X.509 identity attributes require an X.509 certificate",
        ));
    }
    let metadata = crypto::pgp_certificate::inspect(material)
        .map_err(|_| fail(7, "Invalid transferable PGP public key"))?;
    let declared_algorithm = attrs.iter().find(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM);
    let algorithm = match (metadata.algorithm, declared_algorithm.map(|a| &a.value)) {
        (Some(expected), Some(Value::Enumeration(value)))
            if *value == expected || matches!(expected, 6 | 14) && *value == 26 =>
        {
            *value
        }
        (Some(expected), None) => expected,
        (None, Some(Value::Enumeration(value @ 0x80000000..=0x8fffffff))) => *value,
        (None, None) => {
            return Err(fail(
                6,
                "PGP certificate requires declared algorithm metadata",
            ));
        }
        _ => return Err(fail(7, "PGP certificate algorithm conflicts with material")),
    };
    if !crate::encoding::known_enumeration(
        CRYPTOGRAPHIC_ALGORITHM,
        algorithm,
        &format!("{}.{}", v.0, v.1),
    ) {
        return Err(fail(7, "Unavailable PGP certificate algorithm"));
    }
    let bits = metadata
        .bits
        .or_else(|| {
            attrs
                .iter()
                .find(|a| a.tag == CRYPTOGRAPHIC_LENGTH)
                .and_then(|a| {
                    if let Value::Integer(n) = a.value {
                        (n > 0).then_some(n as u32)
                    } else {
                        None
                    }
                })
        })
        .ok_or(fail(6, "PGP certificate length metadata required"))?;
    set(attrs, Node::enumeration(CERTIFICATE_TYPE, 2))?;
    set(attrs, Node::int(CERTIFICATE_LENGTH, material.len() as i32))?;
    set(attrs, Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm))?;
    set(attrs, Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32))?;
    let mut declared = pgp::signatures(attrs);
    for a in attrs
        .iter()
        .filter(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM)
    {
        pgp::signature(a, v)?;
    }
    if metadata.unknown_signatures
        && !declared
            .iter()
            .any(|value| matches!(value, 0x80000000..=0x8fffffff))
    {
        return Err(fail(
            8,
            "Unmapped PGP signature requires explicit vendor metadata",
        ));
    }
    if declared.is_empty() {
        if metadata.signatures.is_empty() {
            return Err(fail(6, "PGP certificate signature metadata required"));
        }
        for value in &metadata.signatures {
            let a = Node::enumeration(DIGITAL_SIGNATURE_ALGORITHM, *value);
            if v >= Version(1, 1) {
                pgp::signature(&a, v)?;
            }
            attrs.push(a);
        }
    } else if !metadata.signatures.is_empty() {
        declared.sort_unstable();
        declared.dedup();
        let mut expected = metadata.signatures.clone();
        expected.sort_unstable();
        if !expected.iter().all(|value| declared.contains(value))
            || !metadata.unknown_signatures && declared != expected
        {
            return Err(fail(7, "PGP certificate signature metadata conflicts"));
        }
    }
    Ok((algorithm, bits))
}
pub(super) fn infer(material: &[u8]) -> R<u32> {
    if crypto::certificate::inspect(material).is_ok() {
        Ok(1)
    } else if crypto::pgp_certificate::inspect(material).is_ok() {
        Ok(2)
    } else {
        Err(fail(7, "Cannot identify reconstructed Certificate Type"))
    }
}

/// Transient provider view only: never persist a certificate as a Public Key.
/// The caller retains authorization/state checks and multipart binding on the
/// original managed certificate. This verifies application signatures, not trust.
pub(super) fn verification_key(obj: &Object, v: Version) -> R<Object> {
    if obj.object_type != 1 {
        return Ok(obj.clone());
    }
    if obj.certificate_type != 1 {
        return Err(fail(
            8,
            "PGP certificate signature verification is not implemented",
        ));
    }
    ec::certificate_curve(&obj.material)?;
    let metadata = crypto::certificate::inspect(&obj.material)
        .map_err(|_| fail(7, "Invalid certificate public key"))?;
    let identity = crypto::certificate_attributes::inspect(&obj.material)
        .map_err(|_| fail(7, "Invalid certificate identity or Key Usage"))?;
    // RFC 5280 allows application-signature verification for digitalSignature
    // and/or nonRepudiation. An absent extension adds no purpose restriction.
    if identity.key_usage.is_some_and(|bits| bits & 3 == 0) {
        return Err(fail(
            if v.0 >= 2 { 0x29 } else { 12 },
            "Certificate Key Usage forbids application signature verification",
        ));
    }
    let algorithm = match (metadata.algorithm, obj.algorithm) {
        (4, 0 | 4) => 4,
        (5, 0 | 5) => 5,
        (26, 0) => 26,
        (26, value @ (6 | 26)) => value,
        _ => {
            return Err(fail(
                8,
                "Certificate subject-key algorithm does not support this verification role",
            ));
        }
    };
    if obj.bits != 0 && obj.bits != metadata.bits {
        return Err(fail(
            7,
            "Certificate public-key length conflicts with stored metadata",
        ));
    }
    let key = openssl::x509::X509::from_der(&obj.material)
        .and_then(|c| c.public_key())
        .and_then(|p| p.public_key_to_der())
        .map_err(|_| fail(10, "Unable to extract certificate subject public key"))?;
    let mut view = obj.clone();
    view.object_type = 3;
    view.format = 5;
    view.algorithm = algorithm;
    view.bits = metadata.bits;
    view.material = key;
    Ok(view)
}

pub(super) fn dsa_hash(cp: &Node, v: Version) -> R<u32> {
    fips_policy::dsa()?;
    no_fields(
        cp,
        &[
            CRYPTOGRAPHIC_ALGORITHM,
            HASHING_ALGORITHM,
            DIGITAL_SIGNATURE_ALGORITHM,
        ],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, 5)? != 5 {
        return Err(fail(7, "DSA algorithm mismatch"));
    }
    let combined = cp
        .get(DIGITAL_SIGNATURE_ALGORITHM)
        .map(Node::number)
        .transpose()?;
    let implied = match combined {
        Some(value @ 9..=11) => Some(value - 5),
        None => None,
        _ => {
            return Err(fail(
                if v.0 >= 2 { 0x3e } else { 8 },
                "Unsupported DSA signature algorithm",
            ));
        }
    };
    let hash = match cp.get(HASHING_ALGORITHM) {
        Some(n) => n.number()?,
        None => implied.ok_or(fail(6, "DSA hashing algorithm required"))?,
    };
    if implied.is_some_and(|value| value != hash) {
        return Err(fail(7, "Conflicting DSA hash parameters"));
    }
    crypto::rsa::digest(hash).map_err(|_| fail(8, "Unsupported DSA hash"))?;
    Ok(hash)
}
