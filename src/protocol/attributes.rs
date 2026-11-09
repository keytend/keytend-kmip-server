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

//! Attribute identity and stable KMIP 1.x indices; value selection in 2.x+.
use super::*;
use std::collections::{HashMap, HashSet};

pub(super) fn multiple(tag: u32) -> bool {
    if matches!(
        tag,
        CERTIFICATE_SUBJECT_CN
            ..=CERTIFICATE_ISSUER_DN_QUALIFIER | CERTIFICATE_SUBJECT_DN | CERTIFICATE_ISSUER_DN
    ) {
        return true;
    }
    [
        NAME,
        ALTERNATIVE_NAME,
        APPLICATION_SPECIFIC_INFORMATION,
        LINK,
        GROUP_LINK,
        CERTIFICATE_REQUEST_LINK,
        OBJECT_GROUP,
        DIGEST,
        CRYPTOGRAPHIC_PARAMETERS,
        DIGITAL_SIGNATURE_ALGORITHM,
        KEY_VALUE_LOCATION,
        ATTRIBUTE,
    ]
    .contains(&tag)
}
/// KMIP 1.2+ Alternative Name: no interpretation, normalization or uniqueness policy.
/// The value/type pair is stored exactly, including repeated identical instances.
pub(super) fn validate_alternative_name(a: &Node, v: Version) -> R<()> {
    if v < Version(1, 2) {
        return Err(fail(8, "Alternative Name requires KMIP 1.2"));
    }
    no_fields(a, &[ALTERNATIVE_NAME_VALUE, ALTERNATIVE_NAME_TYPE])?;
    let value = a.required(ALTERNATIVE_NAME_VALUE)?.string()?;
    let kind = a.required(ALTERNATIVE_NAME_TYPE)?;
    if !matches!(kind.value, Value::Enumeration(_)) {
        return Err(fail(7, "Alternative Name Type must be an Enumeration"));
    }
    if !crate::encoding::known_enumeration(
        ALTERNATIVE_NAME_TYPE,
        kind.number()?,
        &format!("{}.{}", v.0, v.1),
    ) || !matches!(kind.value, Value::Enumeration(1..=7))
    {
        return Err(fail(8, "Alternative Name Type is not supported"));
    }
    if a.children()?.iter().map(|n| n.tag).collect::<Vec<_>>()
        != [ALTERNATIVE_NAME_VALUE, ALTERNATIVE_NAME_TYPE]
    {
        return Err(fail(7, "Alternative Name fields are out of order"));
    }
    // Local resource policy; byte length is intentional for UTF-8 text.
    if value.len() > 4096 {
        return Err(fail(2, "Alternative Name Value exceeds 4096 bytes"));
    }
    Ok(())
}
/// Locate permits partial structures; omitted fields impose no matching condition.
/// Draft 3.0 omits the explicit older Locate rule; preserving it is local policy.
pub(super) fn validate_alternative_name_filter(a: &Node, v: Version) -> R<()> {
    if v < Version(1, 2) {
        return Err(fail(8, "Alternative Name requires KMIP 1.2"));
    }
    match a.children()? {
        [] => Ok(()),
        [value] if value.tag == ALTERNATIVE_NAME_VALUE => validate_alternative_name(
            &Node::structure(
                ALTERNATIVE_NAME,
                vec![value.clone(), Node::enumeration(ALTERNATIVE_NAME_TYPE, 1)],
            ),
            v,
        ),
        [kind] if kind.tag == ALTERNATIVE_NAME_TYPE => validate_alternative_name(
            &Node::structure(
                ALTERNATIVE_NAME,
                vec![Node::text(ALTERNATIVE_NAME_VALUE, ""), kind.clone()],
            ),
            v,
        ),
        _ => validate_alternative_name(a, v),
    }
}
fn vendor_key(vendor: &str, name: &str) -> String {
    format!(
        "v:{}",
        serde_json::to_string(&(vendor, name)).expect("serialize string identity")
    )
}
pub(super) fn identity(a: &Node) -> R<String> {
    if a.tag == ATTRIBUTE {
        let (vendor, name) = vendor_identity(a)?;
        Ok(vendor_key(vendor, name))
    } else {
        Ok(format!("s:{:06x}", a.tag))
    }
}
fn reference_key(reference: &AttributeSelector) -> String {
    match reference {
        AttributeSelector::Standard(tag) => format!("s:{tag:06x}"),
        AttributeSelector::Vendor(vendor, name) => vendor_key(vendor, name),
    }
}
fn name_key(name: &str) -> Option<String> {
    if let Some(name) = name.strip_prefix("x-") {
        Some(vendor_key("x", name))
    } else if let Some(name) = name.strip_prefix("y-") {
        Some(vendor_key("y", name))
    } else {
        tag_for_attr(name).map(|tag| format!("s:{tag:06x}"))
    }
}
fn legacy_name(a: &Node) -> R<String> {
    if a.tag != ATTRIBUTE {
        return Ok(attr_name(a.tag)?.to_owned());
    }
    let (vendor, name) = vendor_identity(a)?;
    if !["x", "y"].contains(&vendor) {
        return Err(fail(
            8,
            "Vendor attribute has no KMIP 1.x custom attribute representation",
        ));
    }
    Ok(format!("{vendor}-{name}"))
}
fn index(n: Option<&Node>) -> R<i32> {
    match n.map(|n| &n.value) {
        None => Ok(0),
        Some(Value::Integer(i)) if *i >= 0 => Ok(*i),
        _ => Err(fail(7, "Attribute Index must be a nonnegative Integer")),
    }
}
/// A client change to a date attribute that is modifiable "only while in
/// Pre-Active state" (or Pre-Active or Active) attempted in another state.
/// 1.x reports a refused read-only change as Permission Denied (1.4 Table 342);
/// the 2.0 Modify Attribute errors (Table 249) have no state reason, leaving
/// Permission Denied; 2.1 Table 267 and 3.0 Table 373 add Wrong Key Lifecycle State.
fn lifecycle_refusal(v: Version) -> Failure {
    if v >= Version(2, 1) {
        fail(
            0x43,
            "Attribute cannot be changed in the current lifecycle state",
        )
    } else {
        fail(
            12,
            "Attribute cannot be changed in the current lifecycle state",
        )
    }
}
pub(super) fn decode_attribute(n: &Node) -> R<Node> {
    no_fields(n, &[ATTRIBUTE_NAME, ATTRIBUTE_INDEX, ATTRIBUTE_VALUE])?;
    index(n.get(ATTRIBUTE_INDEX))?;
    let name = n.required(ATTRIBUTE_NAME)?.string()?;
    if let Some((vendor, name)) = name
        .strip_prefix("x-")
        .map(|n| ("x", n))
        .or_else(|| name.strip_prefix("y-").map(|n| ("y", n)))
    {
        if name.is_empty() {
            return Err(fail(7, "Custom attribute name is empty"));
        }
        let value = n.required(ATTRIBUTE_VALUE)?.clone();
        if let Value::Structure(fields) = &value.value
            && fields
                .iter()
                .any(|f| matches!(f.value, Value::Structure(_)))
        {
            return Err(fail(
                7,
                "Legacy custom values cannot contain nested structures",
            ));
        }
        return Ok(Node::structure(
            ATTRIBUTE,
            vec![
                Node::text(VENDOR_IDENTIFICATION, vendor),
                Node::text(ATTRIBUTE_NAME, name),
                value,
            ],
        ));
    }
    let tag = tag_for_attr(name)
        .filter(|tag| *tag != ATTRIBUTE)
        .ok_or(fail(8, "Unsupported attribute"))?;
    let mut value = n.required(ATTRIBUTE_VALUE)?.clone();
    value.tag = tag;
    Ok(value)
}
pub(super) fn encode_attribute(a: &Node) -> R<Node> {
    encode_attribute_at(a, 0, true)
}
pub(super) fn encode_attribute_at(a: &Node, index: i32, multi_signature: bool) -> R<Node> {
    let mut value = if a.tag == ATTRIBUTE {
        a.required(ATTRIBUTE_VALUE)?.clone()
    } else {
        a.clone()
    };
    value.tag = ATTRIBUTE_VALUE;
    let mut fields = vec![Node::text(ATTRIBUTE_NAME, legacy_name(a)?)];
    if multiple(a.tag) && (a.tag != DIGITAL_SIGNATURE_ALGORITHM || multi_signature) {
        fields.push(Node::int(ATTRIBUTE_INDEX, index));
    }
    fields.push(value);
    Ok(Node::structure(ATTRIBUTE, fields))
}
fn absent(v: Version, instance: bool) -> Failure {
    fail(
        if v.0 >= 2 {
            if instance { 0x20 } else { 0x21 }
        } else {
            1
        },
        "Attribute instance not found",
    )
}
fn ambiguous(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x1e } else { 7 },
        "Attribute instance is ambiguous",
    )
}
fn one(n: &Node) -> R<Node> {
    let fields = n.children()?;
    if fields.len() != 1 {
        return Err(fail(
            7,
            "Attribute container must contain exactly one value",
        ));
    }
    Ok(fields[0].clone())
}
pub(super) fn indices(obj: &Object, key: &str, count: usize) -> R<Vec<i32>> {
    let values = obj
        .attribute_indices
        .get(key)
        .cloned()
        .unwrap_or_else(|| (0..count as i32).collect());
    if values.len() != count
        || values.iter().any(|i| *i < 0)
        || values.iter().collect::<HashSet<_>>().len() != count
    {
        return Err(fail(0x100, "Stored attribute indices are inconsistent"));
    }
    Ok(values)
}
pub(super) fn limits(attrs: &[Node]) -> R<()> {
    if attrs.len() > 1024 || attrs.iter().map(Node::encoded_len).sum::<usize>() > 262_144 {
        return Err(fail(2, "Object attribute storage limit exceeded"));
    }
    Ok(())
}
/// Add server-generated metadata without renumbering existing legacy instances.
pub(super) fn append(obj: &mut Object, attribute: Node) -> R<()> {
    let key = identity(&attribute)?;
    let count = obj
        .attrs
        .iter()
        .filter(|a| identity(a).ok().as_ref() == Some(&key))
        .count();
    let mut numbers = indices(obj, &key, count)?;
    let mut number = 0;
    while numbers.contains(&number) {
        number += 1;
    }
    numbers.push(number);
    obj.attribute_indices.insert(key, numbers);
    obj.attrs.push(attribute);
    limits(&obj.attrs)
}
pub(super) fn merge(mut base: Vec<Node>, overrides: Vec<Node>) -> R<Vec<Node>> {
    let replaced = overrides.iter().map(identity).collect::<R<HashSet<_>>>()?;
    base.retain(|a| identity(a).is_ok_and(|key| !replaced.contains(&key)));
    base.extend(overrides);
    Ok(base)
}

/// Pair inputs union multi-instance values; specific single values override common.
pub(super) fn pair_union(mut common: Vec<Node>, specific: Vec<Node>) -> R<Vec<Node>> {
    let replaced = specific
        .iter()
        .filter(|a| !multiple(a.tag))
        .map(identity)
        .collect::<R<HashSet<_>>>()?;
    common.retain(|a| identity(a).is_ok_and(|key| !replaced.contains(&key)));
    for a in specific {
        if !multiple(a.tag) || !common.contains(&a) {
            common.push(a);
        }
    }
    limits(&common)?;
    Ok(common)
}

pub(super) fn first_instance(obj: &Object, tag: u32) -> R<Option<Node>> {
    let values = obj
        .attrs
        .iter()
        .filter(|a| a.tag == tag)
        .collect::<Vec<_>>();
    let key = format!("s:{tag:06x}");
    let numbers = indices(obj, &key, values.len())?;
    Ok(numbers
        .iter()
        .enumerate()
        .min_by_key(|(_, index)| *index)
        .map(|(position, _)| values[position].clone()))
}
/// Select the attributes explicitly requested for the encrypted Key Value.
pub(super) fn wrapping_attributes(obj: &Object, v: Version, specification: &Node) -> R<Vec<Node>> {
    let selector_tag = if v.0 >= 3 {
        ATTRIBUTE_REFERENCE
    } else {
        ATTRIBUTE_NAME
    };
    let mut selected = HashSet::new();
    for n in specification.all(selector_tag) {
        let key = if v.0 >= 3 {
            reference_key(&AttributeSelector::read(n)?)
        } else {
            name_key(n.string()?).ok_or(fail(8, "Unsupported wrapped attribute"))?
        };
        if !selected.insert(key) {
            return Err(fail(7, "Duplicate wrapped attribute selector"));
        }
    }
    if selected.is_empty() {
        return Ok(vec![]);
    }
    let attrs = object_attrs(obj, v);
    let mut totals = HashMap::<String, usize>::new();
    for a in &attrs {
        *totals.entry(identity(a)?).or_default() += 1;
    }
    let mut positions = HashMap::<String, usize>::new();
    let mut found = HashSet::new();
    let mut result = vec![];
    for a in attrs {
        let key = identity(&a)?;
        let position = positions.entry(key.clone()).or_default();
        let index = indices(obj, &key, totals[&key])?[*position];
        *position += 1;
        if selected.contains(&key) {
            if [1, 9].contains(&obj.object_type)
                && matches!(a.tag, DIGITAL_SIGNATURE_ALGORITHM | CRYPTOGRAPHIC_ALGORITHM)
            {
                pgp::projectable(&a, v)?;
            }
            found.insert(key);
            result.push(if v.0 == 1 {
                encode_attribute_at(&a, index, obj.object_type != 1 || obj.certificate_type == 2)?
            } else {
                a
            });
        }
    }
    if found.len() != selected.len() {
        return Err(fail(1, "Requested wrapped attribute not found"));
    }
    if v.0 >= 2 {
        Ok(vec![Node::structure(ATTRIBUTES, result)])
    } else {
        Ok(result)
    }
}

impl Engine {
    pub(super) fn get_attrs(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &Option<String>,
        list: bool,
    ) -> R<Vec<Node>> {
        let allowed = if v.0 == 1 {
            &[UNIQUE_IDENTIFIER, ATTRIBUTE_NAME][..]
        } else {
            &[UNIQUE_IDENTIFIER, ATTRIBUTE_REFERENCE][..]
        };
        if p.children()?.iter().any(|n| !allowed.contains(&n.tag))
            || p.all(UNIQUE_IDENTIFIER).count() > 1
            || list && v.0 == 1 && p.get(ATTRIBUTE_NAME).is_some()
        {
            return Err(fail(7, "Invalid attribute request fields"));
        }
        let mut selected = HashSet::new();
        for n in p.all(if v.0 == 1 {
            ATTRIBUTE_NAME
        } else {
            ATTRIBUTE_REFERENCE
        }) {
            let key = if v.0 == 1 {
                let name = n.string()?;
                name_key(name).unwrap_or_else(|| format!("unknown:{name}"))
            } else {
                reference_key(&AttributeSelector::read(n)?)
            };
            // 1.1-1.4 Get Attributes error tables (1.1 table 261, 1.2 table
            // 302, 1.3 table 317, 1.4 table 339): "The same Attribute Name is
            // present more than once" is Invalid Message. 1.0 has no such rule;
            // 2.x forbids repeats without a dedicated reason (Invalid Field).
            if !selected.insert(key) && v >= Version(1, 1) {
                return Err(fail(
                    if v.0 == 1 { 4 } else { 7 },
                    "Duplicate attribute selector",
                ));
            }
        }
        let obj = self.object(owner, p, placeholder)?;
        pgp::available(obj.object_type, v)?;
        let attrs = object_attrs(&obj, v);
        let mut totals = HashMap::<String, usize>::new();
        for a in &attrs {
            *totals.entry(identity(a)?).or_default() += 1;
        }
        let mut positions = HashMap::<String, usize>::new();
        let mut seen = HashSet::new();
        let mut out = vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)];
        let mut direct = vec![];
        for a in attrs {
            let key = identity(&a)?;
            let position = positions.entry(key.clone()).or_default();
            let index = indices(&obj, &key, totals[&key])?[*position];
            *position += 1;
            if !selected.is_empty() && !selected.contains(&key) {
                continue;
            }
            if !list
                && [1, 9].contains(&obj.object_type)
                && matches!(a.tag, DIGITAL_SIGNATURE_ALGORITHM | CRYPTOGRAPHIC_ALGORITHM)
            {
                pgp::projectable(&a, v)?;
            }
            if list {
                if !seen.insert(key) {
                    continue;
                }
                if v.0 == 1 {
                    out.push(Node::text(ATTRIBUTE_NAME, legacy_name(&a)?));
                } else if a.tag == ATTRIBUTE {
                    let (vendor, name) = vendor_identity(&a)?;
                    out.push(Node::structure(
                        ATTRIBUTE_REFERENCE,
                        vec![
                            Node::text(VENDOR_IDENTIFICATION, vendor),
                            Node::text(ATTRIBUTE_NAME, name),
                        ],
                    ));
                } else {
                    out.push(Node::enumeration(ATTRIBUTE_REFERENCE, a.tag));
                }
            } else if v.0 == 1 {
                out.push(encode_attribute_at(
                    &a,
                    index,
                    obj.object_type != 1 || obj.certificate_type == 2,
                )?);
            } else {
                direct.push(a);
            }
        }
        // docs/interpretations.md, Get Attributes: when none of the requested
        // attributes exist, 2.1 section 6.1.20 says the response holds only
        // the Unique Identifier, while Table 224 marks Attributes REQUIRED and
        // some Java clients reject a reply without it. `--get-attributes-none`
        // picks the form (get_attributes_none.rs); the default returns an
        // empty Attributes structure.
        if !list
            && v.0 >= 2
            && self
                .get_attributes_none
                .attributes_present(!selected.is_empty(), direct.len())
        {
            out.push(Node::structure(ATTRIBUTES, direct));
        }
        Ok(out)
    }

    pub(super) fn modify_attr(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        let allowed = match (v.0 == 1, op) {
            (true, 15) => &[UNIQUE_IDENTIFIER, ATTRIBUTE_NAME, ATTRIBUTE_INDEX][..],
            (true, _) => &[UNIQUE_IDENTIFIER, ATTRIBUTE][..],
            (false, 15) => &[UNIQUE_IDENTIFIER, CURRENT_ATTRIBUTE, ATTRIBUTE_REFERENCE][..],
            (false, 14) => &[UNIQUE_IDENTIFIER, CURRENT_ATTRIBUTE, NEW_ATTRIBUTE][..],
            _ => &[UNIQUE_IDENTIFIER, NEW_ATTRIBUTE][..],
        };
        no_fields(p, allowed)?;
        let mut obj = self.object(owner, p, placeholder)?;
        // 2.0 Tables 154, 249, 189 and 298 (Add, Modify, Delete and Set
        // Attribute) have no state reason, leaving Permission Denied; 2.1
        // added Wrong Key Lifecycle State (Tables 169, 267, 204, 324).
        if obj.state >= 5 {
            return Err(fail(
                if v >= Version(2, 1) { 0x43 } else { 12 },
                "Cannot modify destroyed object attributes",
            ));
        }
        let new = if op == 15 {
            None
        } else if v.0 == 1 {
            let a = p.required(ATTRIBUTE)?;
            if op == 13 && a.get(ATTRIBUTE_INDEX).is_some() {
                return Err(fail(7, "Add Attribute cannot specify an index"));
            }
            Some(decode_attribute(a)?)
        } else {
            Some(one(p.required(NEW_ATTRIBUTE)?)?)
        };
        if let Some(a) = &new {
            template::own_attribute(&obj, a, v)?;
        }
        let current = p.get(CURRENT_ATTRIBUTE).map(one).transpose()?;
        let reference_link = if v.0 >= 3 {
            p.get(ATTRIBUTE_REFERENCE)
                .and_then(|n| n.number().ok())
                .and_then(identifiers::link_type)
        } else {
            None
        };
        let link_kind = reference_link.or_else(|| {
            if v.0 >= 3 {
                new.as_ref()
                    .or(current.as_ref())
                    .filter(|n| n.tag == LINK)
                    .and_then(|n| n.get(LINK_TYPE))
                    .and_then(|n| n.number().ok())
            } else {
                None
            }
        });
        let key = if reference_link.is_some() {
            format!("s:{LINK:06x}")
        } else if let Some(a) = new.as_ref().or(current.as_ref()) {
            identity(a)?
        } else if v.0 == 1 {
            name_key(p.required(ATTRIBUTE_NAME)?.string()?).ok_or_else(|| absent(v, false))?
        } else {
            reference_key(&AttributeSelector::read(p.required(ATTRIBUTE_REFERENCE)?)?)
        };
        if let Some(current) = &current
            && identity(current)? != key
        {
            return Err(fail(7, "Attribute identities do not match"));
        }
        if let Some(reference) = p.get(ATTRIBUTE_REFERENCE)
            && reference_link.is_none()
            && reference_key(&AttributeSelector::read(reference)?) != key
        {
            return Err(fail(
                7,
                "Attribute Reference does not match Current Attribute",
            ));
        }
        let mut matches = obj
            .attrs
            .iter()
            .enumerate()
            .filter_map(|(position, a)| {
                identity(a)
                    .is_ok_and(|id| id == key)
                    .then_some((position, a.clone()))
            })
            .collect::<Vec<_>>();
        let tag = new
            .as_ref()
            .or(current.as_ref())
            .or_else(|| matches.first().map(|(_, a)| a))
            .map(|a| a.tag)
            .or_else(|| {
                key.strip_prefix("s:")
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
            })
            .unwrap_or(ATTRIBUTE);
        if tag == ALTERNATIVE_NAME {
            if v < Version(1, 2) {
                return Err(fail(8, "Alternative Name requires KMIP 1.2"));
            }
            for a in new.iter().chain(current.iter()) {
                validate_alternative_name(a, v)?;
            }
        }
        metadata::before_mutation(&mut obj, v, op, tag, new.as_ref())?;
        matches = obj
            .attrs
            .iter()
            .enumerate()
            .filter_map(|(position, a)| {
                identity(a)
                    .is_ok_and(|id| id == key)
                    .then_some((position, a.clone()))
            })
            .collect();
        if tag == LEASE_TIME {
            return Err(usage::read_only(v));
        }
        if tag == USAGE_LIMITS && obj.usage_consumed {
            return Err(usage::read_only(v));
        }
        if tag == ATTRIBUTE {
            // Deleting by reference must enforce server ownership too.
            let vendor = key
                .strip_prefix("v:")
                .and_then(|s| serde_json::from_str::<(String, String)>(s).ok())
                .map(|id| id.0);
            if vendor.as_deref() == Some("y") {
                return Err(usage::read_only(v));
            }
        }
        if ![
            NAME,
            ALTERNATIVE_NAME,
            OBJECT_GROUP,
            APPLICATION_SPECIFIC_INFORMATION,
            CONTACT_INFORMATION,
            COMMENT,
            DESCRIPTION,
            CRYPTOGRAPHIC_PARAMETERS,
            ATTRIBUTE,
            USAGE_LIMITS,
            LINK,
            SENSITIVE,
            EXTRACTABLE,
            ORIGINAL_CREATION_DATE,
            RANDOM_NUMBER_GENERATOR,
            ACTIVATION_DATE,
            DEACTIVATION_DATE,
            PROCESS_START_DATE,
            PROTECT_STOP_DATE,
        ]
        .contains(&tag)
            && !(v.0 >= 2 && super::quantum::attribute(tag))
            && !(v.0 >= 3 && [GROUP_LINK, CERTIFICATE_REQUEST_LINK].contains(&tag))
            && !(super::key_value::defined(v) && tag == KEY_VALUE_LOCATION)
        {
            return Err(usage::read_only(v));
        }
        if tag == KEY_VALUE_LOCATION && op != 15 && !super::key_value::absent(&obj) {
            return Err(fail(
                7,
                "Key Value Location applies only to an object without a Key Value",
            ));
        }
        if [
            ACTIVATION_DATE,
            DEACTIVATION_DATE,
            PROCESS_START_DATE,
            PROTECT_STOP_DATE,
        ]
        .contains(&tag)
        {
            if op == 15 {
                return Err(usage::read_only(v));
            }
            let state_allowed = if tag == ACTIVATION_DATE {
                obj.state == 1
            } else {
                [1, 2].contains(&obj.state)
            };
            if !state_allowed {
                return Err(lifecycle_refusal(v));
            }
            if [PROCESS_START_DATE, PROTECT_STOP_DATE].contains(&tag)
                && attr_time(&obj.attrs, tag).is_some_and(|date| date <= now())
            {
                return Err(usage::read_only(v));
            }
        }
        let numbers = indices(&obj, &key, matches.len())?;
        let eligible = matches
            .iter()
            .enumerate()
            .filter(|(_, (_, a))| {
                link_kind
                    .is_none_or(|kind| a.get(LINK_TYPE).and_then(|n| n.number().ok()) == Some(kind))
            })
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        // 1.0 is self-contradictory here: Table 241 lists Invalid Field for a
        // Delete without an Attribute Index of a multi-instance attribute,
        // while its attribute text says index 0 "is assumed if the Attribute
        // Index is not specified". Clients rely on the default (OVH kmip-go
        // deletes the first instance this way), so 1.0 assumes index 0 like 1.1+.
        let legacy_index = if v.0 == 1 {
            index(if op == 15 {
                p.get(ATTRIBUTE_INDEX)
            } else {
                p.get(ATTRIBUTE).and_then(|n| n.get(ATTRIBUTE_INDEX))
            })?
        } else {
            0
        };
        if !multiple(tag) && legacy_index != 0 {
            return Err(absent(v, true));
        }
        let target = if op == 13 {
            if (!multiple(tag) || link_kind.is_some_and(identifiers::single_link))
                && !eligible.is_empty()
            {
                // 1.x Add Attribute table (1.4 Table 341): "The specified
                // attribute already exists": Illegal Operation.
                return Err(fail(
                    if v.0 >= 2 { 0x23 } else { 0x0B },
                    "Attribute is single valued",
                ));
            }
            None
        } else if op == 49 && eligible.is_empty() {
            None
        } else if v.0 == 1 {
            // 1.x Modify Attribute table (1.4 Table 342): "A specified
            // attribute does not exist (i.e., it needs to first be added)":
            // Invalid Field; a missing instance of a present attribute stays
            // Item Not Found.
            if op == 14 && matches.is_empty() {
                return Err(fail(7, "Attribute must be added before it is modified"));
            }
            Some(
                numbers
                    .iter()
                    .position(|i| *i == legacy_index)
                    .ok_or_else(|| absent(v, !matches.is_empty()))?,
            )
        } else if let Some(current) = &current {
            let positions = matches
                .iter()
                .enumerate()
                .filter(|(_, (_, a))| a == current)
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            if positions.len() > 1 {
                return Err(ambiguous(v));
            }
            Some(
                *positions
                    .first()
                    .ok_or_else(|| absent(v, !matches.is_empty()))?,
            )
        } else if op == 15 {
            if eligible.is_empty() {
                return Err(absent(v, false));
            }
            None
        } else {
            if eligible.len() > 1 {
                return Err(ambiguous(v));
            }
            Some(if eligible.is_empty() {
                return Err(absent(v, false));
            } else {
                eligible[0]
            })
        };
        if tag == USAGE_LIMITS {
            return self.modify_usage(obj, v, op, new);
        }
        if let Some(a) = &new {
            validate_attrs(std::slice::from_ref(a), v)?;
        }
        let mut values = matches
            .iter()
            .zip(&numbers)
            .map(|((_, a), i)| (*i, a.clone()))
            .collect::<Vec<_>>();
        let response = if op == 15 {
            if let Some(target) = target {
                Some(values.remove(target))
            } else {
                if let Some(kind) = link_kind {
                    values.retain(|(_, a)| {
                        a.get(LINK_TYPE).and_then(|n| n.number().ok()) != Some(kind)
                    });
                } else {
                    values.clear();
                }
                None
            }
        } else {
            let value = new.ok_or(fail(6, "New Attribute required"))?;
            let number = if let Some(target) = target {
                let number = values[target].0;
                values[target] = (number, value.clone());
                number
            } else {
                let mut number = 0;
                while numbers.contains(&number) {
                    number += 1;
                }
                values.push((number, value.clone()));
                number
            };
            Some((number, value))
        };
        let insertion = matches
            .first()
            .map_or(obj.attrs.len(), |(position, _)| *position);
        for (position, _) in matches.iter().rev() {
            obj.attrs.remove(*position);
        }
        values.sort_by_key(|(number, _)| *number);
        obj.attribute_indices
            .insert(key, values.iter().map(|(i, _)| *i).collect());
        obj.attrs
            .splice(insertion..insertion, values.into_iter().map(|(_, a)| a));
        limits(&obj.attrs)?;
        identifiers::validate_link_cardinality(&obj.attrs, v)?;
        let dates = obj
            .attrs
            .iter()
            .filter(|a| {
                [
                    ACTIVATION_DATE,
                    DEACTIVATION_DATE,
                    PROCESS_START_DATE,
                    PROTECT_STOP_DATE,
                ]
                .contains(&a.tag)
            })
            .cloned()
            .collect::<Vec<_>>();
        validate_attrs(&dates, v)?;
        apply_dates(&mut obj);
        self.unique_names(&obj, v)?;
        metadata::update_history(&mut obj, tag)?;
        super::quantum::check(&obj)?;
        obj.updated = now();
        self.store.put(&obj)?;
        let mut out = vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)];
        if v.0 == 1
            && let Some((index, a)) = response
        {
            out.push(encode_attribute_at(
                &a,
                index,
                obj.object_type != 1 || obj.certificate_type == 2,
            )?);
        }
        Ok(out)
    }

    pub(super) fn unique_names(&self, obj: &Object, v: Version) -> R<()> {
        let names = obj
            .attrs
            .iter()
            .filter(|a| a.tag == NAME)
            .map(|a| {
                Ok((
                    a.required(NAME_VALUE)?.string()?.to_owned(),
                    number(a, NAME_TYPE, 1)?,
                ))
            })
            .collect::<R<Vec<_>>>()?;
        if names.is_empty() {
            return Ok(());
        }
        if names
            .iter()
            .enumerate()
            .any(|(i, n)| names[..i].contains(n))
        {
            return Err(fail(if v.0 >= 2 { 0x35 } else { 7 }, "Name is not unique"));
        }
        // docs/interpretations.md, name uniqueness: Names are
        // unique per owner. 2.1/3.0 say "unique within a given key management
        // server" (1.x: "key management domain"), but a server-wide check
        // tells one tenant which names another holds; PyKMIP and Cosmian KMS
        // enforce no cross-object uniqueness at all. Only the owner's own
        // records are read (docs/authorization.md, "Tenant isolation and Names").
        // Names held only by destroyed objects follow the configured reuse
        // policy (destroyed_names.rs).
        // Only objects the index lists under one of the names can collide.
        let candidates = names
            .iter()
            .map(|(name, _)| {
                self.store
                    .index_candidates(&crate::store::IndexKey::Name(name.clone()))
            })
            .collect::<Option<Vec<_>>>()
            .map(|lists| {
                let mut ids = lists.concat();
                ids.sort();
                ids.dedup();
                ids
            });
        let (count, _) = self.store.locate_among(
            &obj.owner,
            &[],
            candidates.as_deref(),
            0,
            0,
            false,
            |other| {
                other.id != obj.id
                    && self.reserves_names(obj, other)
                    && other.attrs.iter().any(|a| {
                        a.tag == NAME
                            && a.get(NAME_VALUE).and_then(|n| n.string().ok()).is_some_and(
                                |value| {
                                    names.iter().any(|(name, kind)| {
                                        name == value && number(a, NAME_TYPE, 1).ok() == Some(*kind)
                                    })
                                },
                            )
                    })
            },
        )?;
        if count > 0 {
            return Err(fail(
                if v.0 >= 2 { 0x35 } else { 7 },
                "Name is not unique among the owner's objects",
            ));
        }
        Ok(())
    }
}
