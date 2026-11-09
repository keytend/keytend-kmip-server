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

//! Versioned PGP containers. Cryptographic processing remains the client's task.
use super::*;
pub(super) const DEFAULT_VERSION: u32 = 4;
pub(super) fn signature(attribute: &Node, v: Version) -> R<u32> {
    match attribute.value {
        Value::Enumeration(value)
            if crate::encoding::known_enumeration(
                DIGITAL_SIGNATURE_ALGORITHM,
                value,
                &format!("{}.{}", v.0, v.1),
            ) =>
        {
            Ok(value)
        }
        _ => Err(fail(
            7,
            "Invalid or unavailable Digital Signature Algorithm",
        )),
    }
}
pub(super) fn signatures(attrs: &[Node]) -> Vec<u32> {
    attrs
        .iter()
        .filter(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM)
        .filter_map(|a| a.number().ok())
        .collect()
}
pub(super) fn projectable(attribute: &Node, v: Version) -> R<()> {
    if !matches!(attribute.value,Value::Enumeration(value) if crate::encoding::known_enumeration(attribute.tag,value,&format!("{}.{}",v.0,v.1)))
    {
        return Err(fail(
            8,
            "Object metadata cannot be represented in this protocol version",
        ));
    }
    Ok(())
}
pub(super) fn attribute_context(kind: u32, attrs: &[Node]) -> R<()> {
    if ![1, 9].contains(&kind) && attrs.iter().any(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM) {
        return Err(fail(
            8,
            "Digital Signature Algorithm attributes require a Certificate or PGP object",
        ));
    }
    Ok(())
}
pub(super) fn metadata(kind: u32, algorithm: u32, bits: u32, attrs: &[Node], v: Version) -> R<()> {
    attribute_context(kind, attrs)?;
    if kind != 9 {
        return Ok(());
    }
    available(kind, v)?;
    for attribute in attrs {
        let valid = match attribute.tag {
            CRYPTOGRAPHIC_ALGORITHM => matches!(attribute.value, Value::Enumeration(_)),
            CRYPTOGRAPHIC_LENGTH => matches!(attribute.value, Value::Integer(value) if value>0),
            CRYPTOGRAPHIC_USAGE_MASK => {
                matches!(attribute.value, Value::Integer(value) if value>=0)
            }
            _ => true,
        };
        if !valid {
            return Err(fail(7, "Invalid PGP mandatory attribute type"));
        }
    }
    let has_algorithm = attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM);
    let has_length = attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH);
    if has_algorithm != has_length {
        return Err(fail(
            6,
            "PGP algorithm and length attributes must be supplied together",
        ));
    }
    if algorithm == 0
        || bits == 0
        || !attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_USAGE_MASK)
        || signatures(attrs).is_empty()
    {
        return Err(fail(
            6,
            "PGP algorithm, length, usage mask and signature metadata are required",
        ));
    }
    if !crate::encoding::known_enumeration(
        CRYPTOGRAPHIC_ALGORITHM,
        algorithm,
        &format!("{}.{}", v.0, v.1),
    ) {
        return Err(fail(
            7,
            "Invalid or unavailable PGP cryptographic algorithm",
        ));
    }
    for attribute in attrs
        .iter()
        .filter(|a| a.tag == DIGITAL_SIGNATURE_ALGORITHM)
    {
        signature(attribute, v)?;
    }
    Ok(())
}
pub(super) fn available(kind: u32, v: Version) -> R<()> {
    if kind == 9 && v < Version(1, 2) {
        return Err(fail(8, "PGP Key requires KMIP 1.2"));
    }
    Ok(())
}
pub(super) fn read(object: &Node, v: Version) -> R<u32> {
    available(9, v)?;
    no_fields(object, &[PGP_KEY_VERSION, KEY_BLOCK])?;
    let block = object.required(KEY_BLOCK)?;
    no_fields(
        block,
        &[
            KEY_FORMAT_TYPE,
            KEY_VALUE,
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            KEY_WRAPPING_DATA,
        ],
    )?;
    match block.required(KEY_FORMAT_TYPE)?.value {
        Value::Enumeration(1 | 2) => {}
        Value::Enumeration(_) => return Err(fail(0x10, "Unsupported PGP key format")),
        _ => return Err(fail(7, "PGP Key Format Type must be an Enumeration")),
    }
    if block
        .get(CRYPTOGRAPHIC_ALGORITHM)
        .is_some_and(|n| !matches!(n.value, Value::Enumeration(_)))
    {
        return Err(fail(7, "PGP algorithm must be an Enumeration"));
    }
    if block
        .get(CRYPTOGRAPHIC_LENGTH)
        .is_some_and(|n| !matches!(n.value,Value::Integer(bits) if bits>0))
    {
        return Err(fail(
            7,
            "PGP cryptographic length must be a positive Integer",
        ));
    }
    match object.required(PGP_KEY_VERSION)?.value {
        Value::Integer(version @ (3 | 4)) => Ok(version as u32),
        Value::Integer(_) => Err(fail(8, "PGP Key Version must be 3 or 4")),
        _ => Err(fail(7, "PGP Key Version must be an Integer")),
    }
}
