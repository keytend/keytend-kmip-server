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

//! Locate filters on descriptive attributes: Contact Information,
//! Description, Comment, Digest, Key Format Type, Revocation Reason and Key
//! Value Location.
//!
//! Locate (1.0 4.8, 1.1-1.4 4.9, 2.0 6.1.27, 2.1 6.1.28) allows every
//! attribute and returns objects that match all of them. A structure filter
//! may omit fields, and a multi-instance attribute (Digest, Key Value
//! Location) matches when any instance does: `attribute_matches` in
//! protocol.rs implements both. This module only decides which of these
//! attributes the edition defines and checks the filter's shape, so that a
//! malformed filter fails instead of matching nothing.
use super::*;

/// The attributes handled here that `v` defines.
pub(super) fn supported(tag: u32, v: Version) -> bool {
    match tag {
        CONTACT_INFORMATION | DIGEST | REVOCATION_REASON => true,
        // 1.4 sections 3.46/3.47; 2.0 sections 4.9/4.19.
        DESCRIPTION | COMMENT => v >= Version(1, 4),
        // An attribute only from 2.0 (2.0 section 4.25); in 1.x Key Format Type
        // is a Key Block and Digest field.
        KEY_FORMAT_TYPE => v.0 >= 2,
        // 1.2 section 3.42, 2.0 section 4.26.
        KEY_VALUE_LOCATION => key_value::defined(v),
        _ => false,
    }
}

/// Description, Comment, Key Format Type and Key Value Location in an
/// edition that lacks them: the 1.x Attribute Name decodes, but the edition
/// has no such attribute.
pub(super) fn undefined(tag: u32, v: Version) -> bool {
    matches!(
        tag,
        DESCRIPTION | COMMENT | KEY_FORMAT_TYPE | KEY_VALUE_LOCATION
    ) && !supported(tag, v)
}

/// Checks the type of a filter on one of these attributes.
pub(super) fn validate(f: &Node, v: Version) -> R<()> {
    match f.tag {
        CONTACT_INFORMATION | DESCRIPTION | COMMENT => {
            f.string()?;
        }
        KEY_FORMAT_TYPE => enumeration(f)?,
        DIGEST => {
            // 1.0 section 3.17: Hashing Algorithm and Digest Value; Key Format
            // Type is a Digest field from 1.1 (section 3.17).
            let mut allowed = vec![HASHING_ALGORITHM, DIGEST_VALUE];
            if v >= Version(1, 1) {
                allowed.push(KEY_FORMAT_TYPE);
            }
            no_fields(f, &allowed)?;
            optional(f, HASHING_ALGORITHM, enumeration)?;
            optional(f, KEY_FORMAT_TYPE, enumeration)?;
            optional(f, DIGEST_VALUE, |n| Ok(n.byte_string().map(|_| ())?))?;
        }
        REVOCATION_REASON => {
            no_fields(f, &[REVOCATION_REASON_CODE, REVOCATION_MESSAGE])?;
            optional(f, REVOCATION_REASON_CODE, enumeration)?;
            optional(f, REVOCATION_MESSAGE, |n| Ok(n.string().map(|_| ())?))?;
        }
        KEY_VALUE_LOCATION => {
            no_fields(f, &[KEY_VALUE_LOCATION_VALUE, KEY_VALUE_LOCATION_TYPE])?;
            optional(f, KEY_VALUE_LOCATION_VALUE, |n| {
                Ok(n.string().map(|_| ())?)
            })?;
            optional(f, KEY_VALUE_LOCATION_TYPE, enumeration)?;
        }
        _ => {}
    }
    Ok(())
}

fn enumeration(n: &Node) -> R<()> {
    match n.value {
        Value::Enumeration(_) => Ok(()),
        _ => Err(fail(7, "Locate filter field must be an Enumeration")),
    }
}

/// A structure filter may omit any field (`no_fields` refuses duplicates);
/// a field that is present has its defined type.
fn optional(f: &Node, tag: u32, check: impl Fn(&Node) -> R<()>) -> R<()> {
    f.get(tag).map_or(Ok(()), check)
}
