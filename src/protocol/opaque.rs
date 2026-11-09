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

//! Lossless Opaque Object extension types and immutable versioned metadata.
use super::*;
pub(super) const LEGACY_TYPE: u32 = 0x80000000;
pub(super) fn value(node: &Node) -> R<u32> {
    match node.value {
        Value::Enumeration(value @ 0x80000000..=0x8fffffff) => Ok(value),
        Value::Enumeration(_) => Err(fail(8, "Opaque Data Type is outside the extension range")),
        _ => Err(fail(7, "Opaque Data Type must be an Enumeration")),
    }
}
pub(super) fn read(object: &Node) -> R<u32> {
    no_fields(object, &[OPAQUE_DATA_TYPE, OPAQUE_DATA_VALUE])?;
    value(object.required(OPAQUE_DATA_TYPE)?)
}
pub(super) fn reject_attribute(attrs: &[Node], v: Version) -> R<()> {
    if attrs.iter().any(|a| a.tag == OPAQUE_DATA_TYPE) {
        if v.0 < 2 {
            return Err(fail(7, "Opaque Data Type attribute requires KMIP 2.0"));
        }
        return Err(usage::read_only(v));
    }
    Ok(())
}
pub(super) fn project(obj: &Object, v: Version, attrs: &mut Vec<Node>) {
    attrs.retain(|a| a.tag != OPAQUE_DATA_TYPE);
    if obj.object_type == 8 && v.0 >= 2 {
        attrs.push(Node::enumeration(OPAQUE_DATA_TYPE, obj.opaque_type));
    }
}
