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

//! Metadata-only objects: Register without a Key Value (KMIP 1.2-1.4
//! sections 3.41/3.42, 2.0/2.1 sections 4.27/4.28).
//!
//! From 1.2 the Key Block's Key Value is optional (1.2 Table 7: "Key Value
//! [...] No"). "Key Value Present SHALL be created by the server if the Key
//! Value is absent from the Key Block in a Register request", and the client
//! "MAY" give a Key Value Location "when the Key Value is omitted". Such an
//! object is stored with Key Value Present false and no key material.
//!
//! Server policy and limits:
//! - Applies to Symmetric Keys, Private Keys and Secret Data from 1.2, and
//!   also Public Keys from 2.0 (1.2-1.4: "does not apply to [...] Public
//!   Keys"; 2.x: "All Objects"). Split Keys and PGP Keys need their material
//!   for validation here and are refused with Feature Not Supported.
//! - The Key Block must name the Key Format Type, and for keys the
//!   Cryptographic Algorithm and Length, because nothing can be derived
//!   ("MAY be omitted only if this information is available from the Key
//!   Value").
//! - Key Value Location is accepted only on such objects (it indicates "the
//!   location of the Key Value absent from the object"), from 1.2, with the
//!   Uninterpreted Text String or URI type.
//! - Get returns the Key Block without a Key Value, as registered. A Get that
//!   asks for another Key Format Type, a Key Compression Type or wrapping,
//!   and every operation that needs the key value (cryptographic operations,
//!   Re-key, Derive Key, Export, use as a wrapping or derivation key, ...)
//!   fails with Key Value Not Present (1.2 Table 271 value 00000013: "A meta
//!   data only object. The key value is not present on the server").
//!   Metadata operations (Locate, Check, attributes, lease and usage
//!   allocation, lifecycle, archival) work as for any object.
//! - The server never sets Key Value Present to true; ordinary objects carry
//!   no Key Value Present attribute ("SHALL always have a value: No"), so a
//!   Locate filter of true matches nothing.
use super::*;

/// Operations that read only metadata, so a metadata-only object can be
/// their target: Locate, Check, Get (see `get`), Get Attributes, Get
/// Attribute List, Add/Modify/Delete Attribute, Obtain Lease, Get Usage
/// Allocation, Activate, Revoke, Destroy, Archive, Recover, Adjust and Set
/// Attribute, and the draft Deactivate.
const METADATA_OPERATIONS: [u32; 18] = [
    8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 48, 49, 64,
];

pub(super) fn defined(v: Version) -> bool {
    v >= Version(1, 2)
}
/// The object was registered without a Key Value.
pub(super) fn absent(obj: &Object) -> bool {
    obj.attrs
        .iter()
        .any(|a| a.tag == KEY_VALUE_PRESENT && a.value == Value::Boolean(false))
}
pub(super) fn not_present() -> Failure {
    fail(0x13, "Key Value is not present on the server")
}
/// Refuse a metadata-only object as the target of an operation that needs
/// its key value.
pub(super) fn require_for(obj: &Object, operation: u32) -> R<()> {
    if absent(obj) && !METADATA_OPERATIONS.contains(&operation) {
        return Err(not_present());
    }
    Ok(())
}
/// Refuse a metadata-only object wherever its material is used.
pub(super) fn require(obj: &Object) -> R<()> {
    if absent(obj) {
        return Err(not_present());
    }
    Ok(())
}
/// The Register object's Key Block has no Key Value (1.2 and later; before
/// 1.2 the ordinary path refuses it).
pub(super) fn omitted(object: &Node, v: Version) -> bool {
    defined(v)
        && object
            .get(KEY_BLOCK)
            .is_some_and(|kb| kb.get(KEY_VALUE).is_none())
}
/// Register of a Key Block without a Key Value: the Key Format Type,
/// algorithm and length come from the Key Block and the attributes. Returns
/// (format, algorithm, bits); the caller stores empty material.
pub(super) fn register(
    kind: u32,
    object: &Node,
    attrs: &mut Vec<Node>,
    v: Version,
) -> R<(u32, u32, u32)> {
    match kind {
        2 | 4 | 7 => {}
        3 if v.0 >= 2 => {}
        3 => {
            return Err(fail(
                7,
                "A Public Key cannot omit its Key Value before KMIP 2.0",
            ));
        }
        _ => {
            return Err(fail(
                8,
                "Metadata-only objects of this type are not supported",
            ));
        }
    }
    no_fields(object, &[KEY_BLOCK, SECRET_DATA_TYPE])?;
    if kind == 7 && ![1, 2].contains(&number(object, SECRET_DATA_TYPE, 2)?) {
        return Err(fail(8, "Only Password or Seed Secret Data is supported"));
    }
    let kb = object.required(KEY_BLOCK)?;
    no_fields(
        kb,
        &[
            KEY_FORMAT_TYPE,
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
        ],
    )?;
    let format = kb.required(KEY_FORMAT_TYPE)?.number()?;
    if format >= 0x8000_0000
        || !crate::encoding::known_enumeration(KEY_FORMAT_TYPE, format, &format!("{}.{}", v.0, v.1))
    {
        return Err(fail(0x10, "Unknown Key Format Type"));
    }
    let declared = |tag: u32| -> R<Option<u32>> {
        let block = kb.get(tag).map(Node::number).transpose()?;
        let attribute = attrs
            .iter()
            .find(|a| a.tag == tag)
            .map(Node::number)
            .transpose()?;
        match (block, attribute) {
            (Some(b), Some(a)) if a != b => Err(fail(7, "Key Block metadata conflicts")),
            (b, a) => Ok(b.or(a)),
        }
    };
    let (algorithm, bits) = if kind == 7 {
        // The Key Block algorithm and length do not apply to Secret Data.
        if kb.get(CRYPTOGRAPHIC_ALGORITHM).is_some() || kb.get(CRYPTOGRAPHIC_LENGTH).is_some() {
            return Err(fail(7, "Secret Data has no Key Block algorithm"));
        }
        (
            declared(CRYPTOGRAPHIC_ALGORITHM)?.unwrap_or(0),
            declared(CRYPTOGRAPHIC_LENGTH)?.unwrap_or(0),
        )
    } else {
        let algorithm = declared(CRYPTOGRAPHIC_ALGORITHM)?;
        let bits = declared(CRYPTOGRAPHIC_LENGTH)?;
        match (algorithm, bits) {
            (Some(a), Some(b)) if a != 0 && b > 0 => (a, b),
            _ => {
                return Err(fail(
                    6,
                    "Cryptographic Algorithm and Length are required without a Key Value",
                ));
            }
        }
    };
    if algorithm != 0
        && (algorithm >= 0x8000_0000
            || !crate::encoding::known_enumeration(
                CRYPTOGRAPHIC_ALGORITHM,
                algorithm,
                &format!("{}.{}", v.0, v.1),
            ))
    {
        return Err(fail(7, "Unknown Cryptographic Algorithm"));
    }
    attrs.push(Node::boolean(KEY_VALUE_PRESENT, false));
    Ok((format, algorithm, bits))
}
/// Key Value Location value checks (1.2 Table 132, enumeration 9.1.3.2.35).
pub(super) fn validate_location(a: &Node) -> R<()> {
    no_fields(a, &[KEY_VALUE_LOCATION_VALUE, KEY_VALUE_LOCATION_TYPE])?;
    a.required(KEY_VALUE_LOCATION_VALUE)?.string()?;
    match a.required(KEY_VALUE_LOCATION_TYPE)?.value {
        Value::Enumeration(1 | 2) => Ok(()),
        _ => Err(fail(7, "Unsupported Key Value Location Type")),
    }
}
/// Key Value Location only describes an absent Key Value.
pub(super) fn location_allowed(attrs: &[Node]) -> R<()> {
    if attrs.iter().any(|a| a.tag == KEY_VALUE_LOCATION)
        && !attrs
            .iter()
            .any(|a| a.tag == KEY_VALUE_PRESENT && a.value == Value::Boolean(false))
    {
        return Err(fail(
            7,
            "Key Value Location applies only to an object without a Key Value",
        ));
    }
    Ok(())
}
/// Get of a metadata-only object: the Key Block as registered. Format
/// conversion, compression and wrapping need the absent value.
pub(super) fn get(obj: &Object, p: &Node) -> R<Vec<Node>> {
    if p.get(KEY_COMPRESSION_TYPE).is_some()
        || p.get(KEY_WRAPPING_SPECIFICATION).is_some()
        || number(p, KEY_FORMAT_TYPE, obj.format)? != obj.format
    {
        return Err(not_present());
    }
    let mut block = vec![Node::enumeration(KEY_FORMAT_TYPE, obj.format)];
    if obj.object_type != 7 {
        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm));
        block.push(Node::int(CRYPTOGRAPHIC_LENGTH, obj.bits as i32));
    }
    let mut children = vec![];
    if obj.object_type == 7 {
        children.push(Node::enumeration(SECRET_DATA_TYPE, obj.secret_type));
    }
    children.push(Node::structure(KEY_BLOCK, block));
    Ok(vec![
        Node::enumeration(OBJECT_TYPE, obj.object_type),
        Node::text(UNIQUE_IDENTIFIER, &obj.id),
        Node::structure(object_tag(obj.object_type)?, children),
    ])
}
/// Neither attribute exists before 1.2.
pub(super) fn project(v: Version, attrs: &mut Vec<Node>) {
    if !defined(v) {
        attrs.retain(|a| ![KEY_VALUE_PRESENT, KEY_VALUE_LOCATION].contains(&a.tag));
    }
}
