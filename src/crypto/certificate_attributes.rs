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

//! Certificate identity extraction. Byte values preserve complete ASN.1 DER fields.
//! Names are rendered per RFC 2253; this inspection does not establish trust.
use crate::tags::*;
use anyhow::{Result, ensure};
use openssl::x509::{X509, X509NameRef};

#[derive(Debug)]
pub struct Identity {
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub serial: Vec<u8>,
    pub issuer_alternatives: Vec<Vec<u8>>,
    pub subject_alternatives: Vec<Vec<u8>>,
    pub issuer_text: String,
    pub subject_text: String,
    pub serial_text: String,
    pub fields: Vec<(u32, String)>,
    /// RFC 5280 named bits 0 through 8, absent when the extension is absent.
    pub key_usage: Option<u16>,
}
#[derive(Clone, Copy)]
struct Der<'a> {
    tag: u8,
    encoded: &'a [u8],
    value: &'a [u8],
}
fn next<'a>(input: &mut &'a [u8]) -> Result<Der<'a>> {
    ensure!(input.len() >= 2, "Truncated DER field");
    let tag = input[0];
    ensure!(
        tag & 31 != 31,
        "High-tag DER is unsupported in certificate identity"
    );
    let first = input[1];
    let (header, len) = if first < 128 {
        (2, first as usize)
    } else {
        let width = (first & 127) as usize;
        ensure!(
            (1..=4).contains(&width) && input.len() >= 2 + width && input[2] != 0,
            "Invalid DER length"
        );
        let len = input[2..2 + width]
            .iter()
            .fold(0usize, |n, b| (n << 8) | *b as usize);
        ensure!(len >= 128, "Noncanonical DER length");
        (2 + width, len)
    };
    let end = header
        .checked_add(len)
        .filter(|n| *n <= input.len())
        .ok_or_else(|| anyhow::anyhow!("Truncated DER value"))?;
    let result = Der {
        tag,
        encoded: &input[..end],
        value: &input[header..end],
    };
    *input = &input[end..];
    Ok(result)
}
fn sequence(input: &[u8], tag: u8) -> Result<&[u8]> {
    let mut remaining = input;
    let value = next(&mut remaining)?;
    ensure!(
        value.tag == tag && remaining.is_empty(),
        "Unexpected DER container"
    );
    Ok(value.value)
}
/// Validate the byte-preserving form used for restored identity metadata.
pub fn validate_serial_der(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 65536, "Serial size limit");
    let value = sequence(bytes, 2)?;
    ensure!(!value.is_empty(), "Empty INTEGER");
    if value.len() > 1 {
        ensure!(
            !(value[0] == 0 && value[1] & 128 == 0 || value[0] == 255 && value[1] & 128 != 0),
            "Noncanonical INTEGER"
        );
    }
    Ok(())
}
pub fn validate_name_der(bytes: &[u8], allow_empty: bool) -> Result<bool> {
    ensure!(bytes.len() <= 65536, "Name size limit");
    if bytes.is_empty() {
        ensure!(allow_empty, "Empty issuer name");
        return Ok(true);
    }
    let parsed = openssl::x509::X509Name::from_der(bytes)?;
    ensure!(parsed.to_der()? == bytes, "Trailing or reencoded name");
    name(&parsed, false, &mut Vec::new())?;
    let empty = parsed.entries().next().is_none();
    ensure!(allow_empty || !empty, "Empty issuer name");
    Ok(empty)
}
pub fn validate_general_name_der(bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() <= 65536, "Alternative name size limit");
    let mut remaining = bytes;
    let name = next(&mut remaining)?;
    ensure!(
        remaining.is_empty() && !name.value.is_empty(),
        "Invalid GeneralName size"
    );
    match name.tag {
        0x81 | 0x82 | 0x86 => ensure!(name.value.is_ascii(), "Alternative name is not IA5"),
        0x87 => ensure!(
            [4, 16].contains(&name.value.len()),
            "Invalid IP address length"
        ),
        0x88 => {
            oid(name.value)?;
        }
        0xa4 => {
            validate_name_der(name.value, false)?;
        }
        0xa0 => {
            let mut fields = name.value;
            let id = next(&mut fields)?;
            ensure!(id.tag == 6, "OtherName requires an OID");
            oid(id.value)?;
            let value = next(&mut fields)?;
            ensure!(
                fields.is_empty() && value.tag == 0xa0,
                "Invalid OtherName value"
            );
            let mut inner = value.value;
            next(&mut inner)?;
            ensure!(inner.is_empty(), "Invalid OtherName content");
        }
        0xa3 | 0xa5 => {
            // Preserve these forms as ASN.1; complete ORAddress/EDI semantic
            // validation is a separate certificate-profile requirement.
            let mut inner = name.value;
            while !inner.is_empty() {
                next(&mut inner)?;
            }
        }
        _ => anyhow::bail!("Invalid GeneralName tag"),
    }
    Ok(())
}

fn key_usage(bytes: &[u8]) -> Result<u16> {
    let value = sequence(bytes, 3)?;
    ensure!(
        (2..=3).contains(&value.len()),
        "Invalid Key Usage bit string size"
    );
    let unused = value[0] as usize;
    let data = &value[1..];
    ensure!(
        unused < 8 && data[data.len() - 1] & ((1u16 << unused) - 1) as u8 == 0,
        "Invalid Key Usage padding"
    );
    let bits = data.len() * 8 - unused;
    ensure!((1..=9).contains(&bits), "Unknown Key Usage bits");
    ensure!(
        data[data.len() - 1] & (1 << unused) != 0,
        "Noncanonical Key Usage named bits"
    );
    let mut result = 0u16;
    for bit in 0..bits {
        if data[bit / 8] & (128 >> (bit % 8)) != 0 {
            result |= 1 << bit;
        }
    }
    ensure!(result != 0, "Key Usage must contain a set bit");
    Ok(result)
}

fn oid(bytes: &[u8]) -> Result<String> {
    let mut components = Vec::new();
    let mut value = 0u128;
    let mut pending = false;
    for b in bytes {
        ensure!(!(value == 0 && *b == 0x80), "Noncanonical OID");
        value = value
            .checked_mul(128)
            .and_then(|n| n.checked_add((b & 127) as u128))
            .ok_or_else(|| anyhow::anyhow!("OID component exceeds identity renderer limit"))?;
        pending = b & 128 != 0;
        if !pending {
            components.push(value);
            value = 0;
        }
    }
    ensure!(!pending && !components.is_empty(), "Truncated OID");
    let first = components.remove(0);
    let arc = if first < 40 {
        0
    } else if first < 80 {
        1
    } else {
        2
    };
    let mut result = format!("{arc}.{}", first - arc * 40);
    for component in components {
        result.push('.');
        result.push_str(&component.to_string());
    }
    Ok(result)
}
fn mapping(oid: &str) -> (Option<u32>, Option<&'static str>) {
    match oid {
        "2.5.4.3" => (Some(CERTIFICATE_SUBJECT_CN), Some("CN")),
        "2.5.4.10" => (Some(CERTIFICATE_SUBJECT_O), Some("O")),
        "2.5.4.11" => (Some(CERTIFICATE_SUBJECT_OU), Some("OU")),
        "1.2.840.113549.1.9.1" => (Some(CERTIFICATE_SUBJECT_EMAIL), None),
        "2.5.4.6" => (Some(CERTIFICATE_SUBJECT_C), Some("C")),
        "2.5.4.8" => (Some(CERTIFICATE_SUBJECT_ST), Some("ST")),
        "2.5.4.7" => (Some(CERTIFICATE_SUBJECT_L), Some("L")),
        "0.9.2342.19200300.100.1.1" => (Some(CERTIFICATE_SUBJECT_UID), Some("UID")),
        "2.5.4.5" => (Some(CERTIFICATE_SUBJECT_SERIAL_NUMBER), None),
        "2.5.4.12" => (Some(CERTIFICATE_SUBJECT_TITLE), None),
        "0.9.2342.19200300.100.1.25" => (Some(CERTIFICATE_SUBJECT_DC), Some("DC")),
        "2.5.4.46" => (Some(CERTIFICATE_SUBJECT_DN_QUALIFIER), None),
        "2.5.4.9" => (None, Some("STREET")),
        _ => (None, None),
    }
}
fn escape(text: &str) -> String {
    let mut result = String::new();
    for (at, c) in text.char_indices() {
        if c.is_control() {
            for b in c.to_string().as_bytes() {
                result.push_str(&format!("\\{b:02X}"));
            }
        } else {
            if [',', '+', '"', '\\', '<', '>', ';', '='].contains(&c)
                || at == 0 && c == '#'
                || c == ' ' && (at == 0 || at + 1 == text.len())
            {
                result.push('\\');
            }
            result.push(c);
        }
    }
    result
}
fn name(name: &X509NameRef, issuer: bool, fields: &mut Vec<(u32, String)>) -> Result<String> {
    let encoded = name.to_der()?;
    let mut rdns = sequence(&encoded, 0x30)?;
    let mut entries = name.entries();
    let mut rendered = Vec::new();
    while !rdns.is_empty() {
        let rdn = next(&mut rdns)?;
        ensure!(rdn.tag == 0x31 && !rdn.value.is_empty(), "Invalid RDN");
        let mut values = rdn.value;
        let mut pair = Vec::new();
        let mut previous: Option<&[u8]> = None;
        while !values.is_empty() {
            let attribute = next(&mut values)?;
            ensure!(
                previous.is_none_or(|p| p <= attribute.encoded),
                "Noncanonical RDN ordering"
            );
            previous = Some(attribute.encoded);
            ensure!(attribute.tag == 0x30, "Invalid name attribute");
            let mut data = attribute.value;
            let id = next(&mut data)?;
            ensure!(id.tag == 6, "Missing name OID");
            let value = next(&mut data)?;
            ensure!(data.is_empty(), "Trailing name attribute");
            let oid = oid(id.value)?;
            let (field, short) = mapping(&oid);
            let entry = entries
                .next()
                .ok_or_else(|| anyhow::anyhow!("Name entry mismatch"))?;
            let text = if field.is_some() || short.is_some() {
                Some(entry.data().to_string()?)
            } else {
                None
            };
            if let Some(field) = field {
                fields.push((field + if issuer { 12 } else { 0 }, text.clone().unwrap()));
            }
            pair.push(if let Some(short) = short {
                format!("{short}={}", escape(text.as_deref().unwrap()))
            } else {
                format!("{oid}=#{}", hex::encode(value.encoded))
            });
        }
        rendered.push(pair.join("+"));
    }
    ensure!(entries.next().is_none(), "Trailing name entries");
    rendered.reverse();
    Ok(rendered.join(","))
}

pub fn inspect(der: &[u8]) -> Result<Identity> {
    ensure!(
        !der.is_empty() && der.len() <= 65536,
        "Certificate size limit"
    );
    let cert = X509::from_der(der)?;
    ensure!(
        cert.to_der()? == der,
        "Trailing or reencoded certificate data"
    );
    let mut certificate = sequence(der, 0x30)?;
    let tbs = next(&mut certificate)?;
    ensure!(tbs.tag == 0x30, "Invalid TBSCertificate");
    let mut tbs = tbs.value;
    let mut serial = next(&mut tbs)?;
    if serial.tag == 0xa0 {
        serial = next(&mut tbs)?;
    }
    ensure!(serial.tag == 2, "Missing certificate serial number");
    validate_serial_der(serial.encoded)?;
    let signature = next(&mut tbs)?;
    ensure!(signature.tag == 0x30, "Invalid signature identifier");
    let issuer = next(&mut tbs)?;
    ensure!(issuer.tag == 0x30, "Invalid issuer");
    validate_name_der(issuer.encoded, false)?;
    let validity = next(&mut tbs)?;
    ensure!(validity.tag == 0x30, "Invalid validity");
    let subject = next(&mut tbs)?;
    ensure!(subject.tag == 0x30, "Invalid subject");
    let spki = next(&mut tbs)?;
    ensure!(spki.tag == 0x30, "Invalid public key");
    let mut subject_alternatives = Vec::new();
    let mut issuer_alternatives = Vec::new();
    let mut found = std::collections::HashSet::new();
    let mut usage = None;
    while !tbs.is_empty() {
        let optional = next(&mut tbs)?;
        if optional.tag != 0xa3 {
            ensure!(
                [0x81, 0x82].contains(&optional.tag),
                "Invalid certificate field"
            );
            continue;
        }
        let mut extensions = sequence(optional.value, 0x30)?;
        while !extensions.is_empty() {
            let extension = next(&mut extensions)?;
            ensure!(extension.tag == 0x30, "Invalid extension");
            let mut items = extension.value;
            let id = next(&mut items)?;
            ensure!(
                id.tag == 6 && found.insert(id.value.to_vec()),
                "Duplicate or invalid certificate extension"
            );
            let mut value = next(&mut items)?;
            if value.tag == 1 {
                ensure!(value.value == [0xff], "Invalid extension critical flag");
                value = next(&mut items)?;
            }
            ensure!(
                value.tag == 4 && items.is_empty(),
                "Invalid extension value"
            );
            if id.value == [0x55, 0x1d, 0x0f] {
                usage = Some(key_usage(value.value)?);
            }
            if id.value == [0x55, 0x1d, 0x11] || id.value == [0x55, 0x1d, 0x12] {
                let mut names = sequence(value.value, 0x30)?;
                ensure!(!names.is_empty(), "Empty alternative names");
                let target = if id.value[2] == 0x11 {
                    &mut subject_alternatives
                } else {
                    &mut issuer_alternatives
                };
                while !names.is_empty() {
                    let general = next(&mut names)?;
                    ensure!(
                        matches!(
                            general.tag,
                            0xa0 | 0x81 | 0x82 | 0xa3 | 0xa4 | 0xa5 | 0x86 | 0x87 | 0x88
                        ),
                        "Invalid GeneralName"
                    );
                    validate_general_name_der(general.encoded)?;
                    target.push(general.encoded.to_vec());
                }
            }
        }
    }
    ensure!(
        !subject.value.is_empty() || !subject_alternatives.is_empty(),
        "An empty subject requires alternative names"
    );
    let mut fields = Vec::new();
    let issuer_text = name(cert.issuer_name(), true, &mut fields)?;
    let subject_text = name(cert.subject_name(), false, &mut fields)?;
    Ok(Identity {
        issuer: issuer.encoded.to_vec(),
        subject: if subject.value.is_empty() {
            vec![]
        } else {
            subject.encoded.to_vec()
        },
        serial: serial.encoded.to_vec(),
        issuer_alternatives,
        subject_alternatives,
        issuer_text,
        subject_text,
        serial_text: cert.serial_number().to_bn()?.to_dec_str()?.to_string(),
        fields,
        key_usage: usage,
    })
}

/// CA capability of a certificate for issuance policy (RFC 5280 4.2.1.9 and 4.2.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaConstraints {
    /// basicConstraints is present with cA TRUE.
    pub ca: bool,
    /// keyCertSign when keyUsage is present; None when keyUsage is absent.
    pub key_cert_sign: Option<bool>,
}
pub fn ca_constraints(der: &[u8]) -> Result<CaConstraints> {
    let identity = inspect(der)?;
    let mut certificate = sequence(der, 0x30)?;
    let tbs = next(&mut certificate)?;
    let mut tbs = tbs.value;
    let mut ca = false;
    while !tbs.is_empty() {
        let field = next(&mut tbs)?;
        if field.tag != 0xa3 {
            continue;
        }
        let mut extensions = sequence(field.value, 0x30)?;
        while !extensions.is_empty() {
            let mut items = next(&mut extensions)?.value;
            let id = next(&mut items)?;
            let mut value = next(&mut items)?;
            if value.tag == 1 {
                value = next(&mut items)?;
            }
            if id.value == [0x55, 0x1d, 0x13] {
                let mut constraints = sequence(value.value, 0x30)?;
                if !constraints.is_empty() {
                    let first = next(&mut constraints)?;
                    if first.tag == 1 {
                        ensure!(first.value.len() == 1, "Invalid cA flag");
                        ca = first.value[0] == 0xff;
                    }
                }
            }
        }
    }
    Ok(CaConstraints {
        ca,
        key_cert_sign: identity.key_usage.map(|bits| bits & (1 << 5) != 0),
    })
}
