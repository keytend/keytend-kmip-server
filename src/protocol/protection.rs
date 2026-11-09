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

//! Backend protection-storage selection and server-owned attribute projection.
use super::*;

// Only properties guaranteed in native, Docker and Kubernetes execution.
// Physical location, operator, hardware and validation claims are not inferred.
pub(super) const SOFTWARE: u32 = 1;

pub(super) fn mask(node: &Node, v: Version) -> R<u32> {
    if v.0 < 2 {
        return Err(fail(7, "Protection Storage Mask requires KMIP 2.0"));
    }
    match node.value {
        Value::Integer(value) => Ok(value as u32),
        _ => Err(fail(7, "Protection Storage Mask must be an Integer")),
    }
}
fn supported(value: u32, reason: u32) -> R<u32> {
    if value & !SOFTWARE == 0 {
        Ok(value)
    } else {
        Err(fail(reason, "Requested protection storage is unavailable"))
    }
}
fn alternatives(payload: &Node, tag: u32, v: Version) -> R<Option<Vec<u32>>> {
    if payload.all(tag).count() > 1 {
        return Err(fail(7, "Duplicate Protection Storage Masks container"));
    }
    let Some(container) = payload.get(tag) else {
        return Ok(None);
    };
    if v.0 < 2 {
        return Err(fail(7, "Protection Storage Masks require KMIP 2.0"));
    }
    let fields = container.children()?;
    // Validate the complete request before selecting an alternative. A later
    // malformed field must not be hidden by an earlier satisfiable selection.
    let choices = fields
        .iter()
        .map(|field| {
            if field.tag != PROTECTION_STORAGE_MASK {
                return Err(fail(7, "Unexpected Protection Storage Masks field"));
            }
            mask(field, v)
        })
        .collect::<R<Vec<_>>>()?;
    Ok(Some(choices))
}
fn choose(choices: Option<Vec<u32>>, reason: u32) -> R<Option<u32>> {
    let Some(choices) = choices else {
        return Ok(None);
    };
    choices
        .into_iter()
        .find(|value| value & !SOFTWARE == 0)
        .map(Some)
        .ok_or(fail(
            reason,
            "No permissible protection storage selection is available",
        ))
}
fn selection(payload: &Node, tag: u32, v: Version, reason: u32) -> R<Option<u32>> {
    choose(alternatives(payload, tag, v)?, reason)
}

fn combine(a: Option<u32>, b: Option<u32>) -> u32 {
    match (a, b) {
        (None, None) => SOFTWARE,
        _ => a.unwrap_or(0) | b.unwrap_or(0),
    }
}
pub(super) fn select(payload: &Node, v: Version) -> R<u32> {
    Ok(selection(payload, PROTECTION_STORAGE_MASKS, v, 0x44)?.unwrap_or(SOFTWARE))
}
// Derive Key's operation-specific error tables omit Protection Storage
// Unavailable. Feature Not Supported is the applicable listed reason in all
// three applicable editions (2.0, 2.1 and the pinned draft).
pub(super) fn derive(payload: &Node, v: Version) -> R<u32> {
    Ok(selection(payload, PROTECTION_STORAGE_MASKS, v, 8)?.unwrap_or(SOFTWARE))
}
pub(super) fn pair(payload: &Node, v: Version) -> R<(u32, u32)> {
    let common = selection(payload, COMMON_PROTECTION_STORAGE_MASKS, v, 0x48)?;
    let private = selection(payload, PRIVATE_PROTECTION_STORAGE_MASKS, v, 0x48)?;
    let public = selection(payload, PUBLIC_PROTECTION_STORAGE_MASKS, v, 0x49)?;
    // The common constraint applies to both objects. A role constraint also
    // applies to that role; never silently discard either supplied constraint.
    Ok((combine(common, private), combine(common, public)))
}
pub(super) fn imported(payload: &Node, attrs: &[Node], v: Version) -> R<u32> {
    let choices = alternatives(payload, PROTECTION_STORAGE_MASKS, v)?;
    let mut recorded = None;
    for node in attrs.iter().filter(|a| a.tag == PROTECTION_STORAGE_MASK) {
        if recorded.is_some() {
            return Err(fail(7, "Duplicate imported Protection Storage Mask"));
        }
        recorded = Some(supported(mask(node, v)?, 0x44)?);
    }
    if let Some(recorded) = recorded {
        // Preserve supplied readonly restore metadata and choose a compatible
        // complete alternative, even if it is not the first satisfiable one.
        // Rewriting this value could also invalidate authenticated attributes
        // in an As Registered wrapped envelope.
        if choices
            .as_ref()
            .is_some_and(|choices| !choices.contains(&recorded))
        {
            return Err(fail(
                0x44,
                "Imported protection storage conflicts with the permissible selections",
            ));
        }
        Ok(recorded)
    } else {
        Ok(choose(choices, 0x44)?.unwrap_or(SOFTWARE))
    }
}
pub(super) fn reject_client_attribute(attrs: &[Node], v: Version) -> R<()> {
    if let Some(node) = attrs.iter().find(|a| a.tag == PROTECTION_STORAGE_MASK) {
        mask(node, v)?;
        return Err(usage::read_only(v));
    }
    Ok(())
}
pub(super) fn project(object: &Object, v: Version, attrs: &mut Vec<Node>) {
    attrs.retain(|a| a.tag != PROTECTION_STORAGE_MASK);
    if v.0 >= 2 {
        attrs.push(Node::int(
            PROTECTION_STORAGE_MASK,
            object.protection_mask as i32,
        ));
    }
}
