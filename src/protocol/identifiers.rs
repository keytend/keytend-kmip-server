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

//! Versioned identifier types, message-local references and attribute projection.
use super::*;
use std::collections::HashMap;

pub(super) const LINKS: &[(u32, u32)] = &[
    (CERTIFICATE_LINK, 0x101),
    (PUBLIC_KEY_LINK, 0x102),
    (PRIVATE_KEY_LINK, 0x103),
    (DERIVATION_OBJECT_LINK, 0x104),
    (DERIVED_OBJECT_LINK, 0x105),
    (REPLACEMENT_OBJECT_LINK, 0x106),
    (REPLACED_OBJECT_LINK, 0x107),
    (PARENT_LINK, 0x108),
    (CHILD_LINK, 0x109),
    (PREVIOUS_LINK, 0x10a),
    (NEXT_LINK, 0x10b),
    (PKCS_12_CERTIFICATE_LINK, 0x10c),
    (PKCS_12_PASSWORD_LINK, 0x10d),
    (WRAPPING_KEY_LINK, 0x10e),
];
/// The failure for an omitted Unique Identifier when the ID Placeholder is
/// unset, or was emptied by a Locate that matched nothing or several objects.
///
/// KMIP 1.x section 4.9 only says such later batched operations "fail".
/// Missing Data appears in no 1.x operation error table; the one row every
/// 1.x table gives for an operation that identifies no object is Item Not
/// Found (for example 1.1 table 260 and 1.2 table 301, Get: "No object with
/// the specified Unique Identifier exists"). The 1.2 Test Cases note expects
/// Item Not Found in both of its revisions (TC-152-11 in 1.1, TC-152-12 in
/// 1.2). 2.x keeps Missing Data, which `missing_data::versioned` rewrites to
/// the Invalid Field its error tables list.
pub(super) fn no_placeholder(v: Option<Version>) -> Failure {
    fail(
        if v.is_some_and(|v| v.0 == 1) { 1 } else { 6 },
        "Unique Identifier or ID Placeholder required",
    )
}
pub(super) fn link_type(tag: u32) -> Option<u32> {
    LINKS.iter().find(|(t, _)| *t == tag).map(|(_, kind)| *kind)
}
pub(super) fn single_link(kind: u32) -> bool {
    ![0x101, 0x104, 0x105].contains(&kind)
}
pub(super) fn validate_link_cardinality(attrs: &[Node], v: Version) -> R<()> {
    let mut seen = std::collections::HashSet::new();
    for a in attrs.iter().filter(|a| a.tag == LINK) {
        let kind = a.required(LINK_TYPE)?.number()?;
        if (kind == 0x106 || v.0 >= 3 && single_link(kind)) && !seen.insert(kind) {
            return Err(fail(
                if v.0 >= 2 { 0x23 } else { 7 },
                "Link attribute is single valued",
            ));
        }
    }
    Ok(())
}
pub(super) fn request_identifier_tag(v: Version, op: u32) -> u32 {
    if op == 29 && v.0 < 3 {
        PRIVATE_KEY_UNIQUE_IDENTIFIER
    } else {
        UNIQUE_IDENTIFIER
    }
}
pub(super) fn draft_types(n: &Node) -> bool {
    match &n.value {
        Value::Identifier(_) | Value::Reference(_) | Value::NameReference(_) => true,
        Value::Structure(fields) => fields.iter().any(draft_types),
        _ => false,
    }
}
fn nonempty(value: &str) -> R<String> {
    if value.is_empty() {
        Err(fail(7, "Identifier text must not be empty"))
    } else {
        Ok(value.to_owned())
    }
}
#[derive(Default)]
pub(super) struct References {
    returned: Vec<String>,
    operations: HashMap<u32, Vec<String>>,
}
impl References {
    pub(super) fn start(&mut self, op: u32) {
        self.operations.remove(&op);
    }
    pub(super) fn observe(&mut self, op: u32, payload: &Node) {
        let ids = payload
            .children()
            .unwrap_or(&[])
            .iter()
            .filter(|n| {
                [
                    UNIQUE_IDENTIFIER,
                    PRIVATE_KEY_UNIQUE_IDENTIFIER,
                    PUBLIC_KEY_UNIQUE_IDENTIFIER,
                ]
                .contains(&n.tag)
            })
            .filter_map(|n| n.identifier_text().ok().map(str::to_owned))
            .collect::<Vec<_>>();
        self.returned.extend(ids.clone());
        self.operations.entry(op).or_default().extend(ids);
    }
    fn resolve(&self, v: Version, n: &Node, placeholder: &Option<String>) -> R<Vec<String>> {
        match &n.value {
            Value::TextString(value) if v.0 < 3 => Ok(vec![nonempty(value)?]),
            Value::Identifier(value) | Value::Reference(value) if v.0 >= 3 => {
                Ok(vec![nonempty(value)?])
            }
            Value::Enumeration(1) if v.0 >= 2 => Ok(vec![
                placeholder
                    .clone()
                    .ok_or(fail(6, "ID Placeholder is empty"))?,
            ]),
            Value::Enumeration(value) if v.0 >= 2 => {
                let op = match value {
                    2 => 6,
                    3 => 1,
                    4..=6 => 2,
                    7 => 40,
                    8 => 5,
                    9 => 42,
                    10 => 41,
                    11 => 8,
                    12 => 3,
                    13 => 4,
                    14 => 7,
                    15..=17 => 29,
                    18 if v >= Version(2, 1) => 53,
                    19 if v.0 >= 3 => 62,
                    20 if v.0 >= 3 => 60,
                    21 if v.0 >= 3 => 63,
                    _ => return Err(fail(7, "Invalid Unique Identifier Enumeration")),
                };
                let ids = self
                    .operations
                    .get(&op)
                    .filter(|ids| !ids.is_empty())
                    .ok_or(fail(
                        6,
                        "No successful preceding result for identifier enumeration",
                    ))?;
                if [5, 16].contains(value) {
                    Ok(vec![ids[0].clone()])
                } else if [6, 17].contains(value) {
                    Ok(vec![
                        ids.get(1)
                            .ok_or(fail(6, "Public key result is absent"))?
                            .clone(),
                    ])
                } else {
                    Ok(ids.clone())
                }
            }
            Value::Integer(value) if v.0 >= 2 => {
                let index = if *value < 0 {
                    self.returned.len() as i64 + i64::from(*value)
                } else {
                    i64::from(*value)
                };
                let id = usize::try_from(index)
                    .ok()
                    .and_then(|i| self.returned.get(i))
                    .ok_or(fail(7, "Identifier response index is out of range"))?;
                Ok(vec![id.clone()])
            }
            _ => Err(fail(
                7,
                "Identifier encoding is invalid for this protocol version",
            )),
        }
    }
}
impl Engine {
    pub(super) fn resolve_identifier(
        &self,
        owner: &str,
        v: Version,
        n: &Node,
        refs: &References,
        placeholder: &Option<String>,
    ) -> R<Vec<String>> {
        if let Value::NameReference(name) = &n.value
            && v.0 >= 3
        {
            nonempty(name)?;
            return self.resolve_name_reference(owner, v, name);
        }
        refs.resolve(v, n, placeholder)
    }
    pub(super) fn normalize_attribute(
        &self,
        owner: &str,
        v: Version,
        mut a: Node,
        refs: &References,
        placeholder: &Option<String>,
    ) -> R<Node> {
        if v.0 >= 3 && a.tag == LINK {
            return Err(fail(7, "Draft 3.0 uses typed link attributes"));
        }
        if v.0 >= 3 && a.tag == NAME {
            return Ok(Node::structure(
                NAME,
                vec![
                    Node::text(NAME_VALUE, a.string()?),
                    Node::enumeration(NAME_TYPE, 1),
                ],
            ));
        }
        if v.0 >= 3
            && let Some(kind) = link_type(a.tag)
        {
            a = Node::structure(
                LINK,
                vec![
                    Node::enumeration(LINK_TYPE, kind),
                    Node {
                        tag: LINKED_OBJECT_IDENTIFIER,
                        value: a.value.clone(),
                    },
                ],
            );
        }
        // Draft 3.0 sections 4.35.4, 4.35.7 and 4.35.11: a Unique Identifier
        // Enumeration or Integer names an earlier result in this message.
        if v.0 >= 3
            && [
                CREDENTIAL_LINK,
                GROUP_LINK,
                CERTIFICATE_REQUEST_LINK,
                PASSWORD_LINK,
            ]
            .contains(&a.tag)
            && matches!(a.value, Value::Enumeration(_) | Value::Integer(_))
        {
            let ids = self.resolve_identifier(owner, v, &a, refs, placeholder)?;
            if ids.len() != 1 {
                return Err(fail(0x1e, "A link requires one target"));
            }
            return Ok(Node::reference(a.tag, &ids[0]));
        }
        if a.tag == UNIQUE_IDENTIFIER && v.0 >= 3 {
            let Value::Identifier(value) = &a.value else {
                return Err(fail(
                    7,
                    "Object identifier attributes require Identifier encoding",
                ));
            };
            return Ok(Node::text(UNIQUE_IDENTIFIER, nonempty(value)?));
        }
        if a.tag == LINK {
            no_fields(&a, &[LINK_TYPE, LINKED_OBJECT_IDENTIFIER])?;
            let n = a.required(LINKED_OBJECT_IDENTIFIER)?;
            let target = if v.0 >= 3 && matches!(n.value, Value::NameReference(_)) {
                nonempty(n.identifier_text()?)?;
                n.clone()
            } else {
                let ids = self.resolve_identifier(owner, v, n, refs, placeholder)?;
                if ids.len() != 1 {
                    return Err(fail(0x1e, "A link requires one target"));
                }
                Node::text(LINKED_OBJECT_IDENTIFIER, &ids[0])
            };
            return Ok(Node::structure(
                LINK,
                vec![a.required(LINK_TYPE)?.clone(), target],
            ));
        }
        Ok(a)
    }
    fn normalize_wrapping_references(
        &self,
        owner: &str,
        v: Version,
        n: &mut Node,
        refs: &References,
        placeholder: &Option<String>,
    ) -> R<()> {
        if [ENCRYPTION_KEY_INFORMATION, MAC_SIGNATURE_KEY_INFORMATION].contains(&n.tag) {
            if let Value::Structure(fields) = &mut n.value {
                for id in fields.iter_mut().filter(|n| n.tag == UNIQUE_IDENTIFIER) {
                    // Draft 3.0 as this server reads it (docs/interpretations.md):
                    // a wrapping key is named by Identifier or
                    // Reference (or a message-local Enumeration or Integer),
                    // never by Name Reference.
                    if matches!(id.value, Value::NameReference(_)) {
                        return Err(fail(7, "A wrapping key cannot be named by Name Reference"));
                    }
                    let ids = self.resolve_identifier(owner, v, id, refs, placeholder)?;
                    if ids.len() != 1 {
                        return Err(fail(0x1e, "Wrapping requires a single key reference"));
                    }
                    *id = Node::text(UNIQUE_IDENTIFIER, &ids[0]);
                }
            }
        } else if [
            REQUEST_PAYLOAD,
            KEY_WRAPPING_SPECIFICATION,
            KEY_WRAPPING_DATA,
            KEY_BLOCK,
            SYMMETRIC_KEY,
            PRIVATE_KEY,
            PUBLIC_KEY,
            SECRET_DATA,
            SPLIT_KEY,
            PGP_KEY,
        ]
        .contains(&n.tag)
            && let Value::Structure(fields) = &mut n.value
        {
            for field in fields {
                self.normalize_wrapping_references(owner, v, field, refs, placeholder)?;
            }
        }
        Ok(())
    }
    pub(super) fn prepare_identifiers(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        item: &Node,
        refs: &References,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        if v.0 < 3 && draft_types(item) {
            return Err(fail(7, "Draft identifier types require protocol 3.0"));
        }
        // An operation the edition does not define is refused before its
        // payload is examined (1.4 section 11.1: Operation Not Supported).
        if !self.offered_operations(v).contains(&op) {
            return Err(fail(5, "Operation is not supported for this version"));
        }
        let payload = item.required(REQUEST_PAYLOAD)?;
        if op == 26 {
            return self.prepare_poll(owner, v, item);
        }
        if op == 23 {
            return self.prepare_validation(owner, v, item, refs, placeholder);
        }
        if op == 5 {
            return self.prepare_derivation(owner, v, item, refs, placeholder);
        }
        if [40, 41].contains(&op) {
            return self.prepare_split(owner, v, op, item, refs, placeholder);
        }
        let identifier_tag = request_identifier_tag(v, op);
        let ids = if let Some(n) = payload.get(identifier_tag) {
            self.resolve_identifier(owner, v, n, refs, placeholder)?
        } else if v.0 >= 3
            && [
                4, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 29, 31, 32, 33, 34, 35,
                36, 42, 43, 48, 49, 61, 64, 65, 66,
            ]
            .contains(&op)
        {
            return Err(fail(6, "Unique Identifier is required in draft 3.0"));
        } else {
            vec![String::new()]
        };
        let mut normalized = payload.clone();
        self.normalize_wrapping_references(owner, v, &mut normalized, refs, placeholder)?;
        if let Value::Structure(fields) = &mut normalized.value {
            for field in fields.iter_mut() {
                if [
                    ATTRIBUTES,
                    COMMON_ATTRIBUTES,
                    PRIVATE_KEY_ATTRIBUTES,
                    PUBLIC_KEY_ATTRIBUTES,
                    NEW_ATTRIBUTE,
                    CURRENT_ATTRIBUTE,
                ]
                .contains(&field.tag)
                    && let Value::Structure(attrs) = &mut field.value
                {
                    for a in attrs {
                        *a = self.normalize_attribute(owner, v, a.clone(), refs, placeholder)?;
                        if op == 8 {
                            *a = project_attribute(v, a);
                        }
                    }
                }
            }
        }
        if ids.len() > 128
            || normalized.encoded_len().saturating_mul(ids.len()) > crate::ttlv::MAX_FRAME
        {
            return Err(server_limit(
                v,
                "Expanded request exceeds the server resource limit",
            ));
        }
        Ok(ids
            .into_iter()
            .map(|id| {
                let mut request = item.clone();
                let mut payload = normalized.clone();
                if let Value::Structure(fields) = &mut payload.value
                    && !id.is_empty()
                {
                    if let Some(n) = fields.iter_mut().find(|n| n.tag == identifier_tag) {
                        *n = Node::text(identifier_tag, &id);
                    } else {
                        fields.insert(0, Node::text(identifier_tag, &id));
                    }
                }
                if let Value::Structure(fields) = &mut request.value
                    && let Some(n) = fields.iter_mut().find(|n| n.tag == REQUEST_PAYLOAD)
                {
                    *n = payload;
                }
                request
            })
            .collect())
    }
}
pub(super) fn project_attribute(v: Version, a: &Node) -> Node {
    if v.0 < 3 {
        return a.clone();
    }
    if a.tag == UNIQUE_IDENTIFIER
        && let Value::TextString(value) = &a.value
    {
        return Node::identifier(a.tag, value);
    }
    if a.tag == NAME
        && let Some(value) = a.get(NAME_VALUE).and_then(|n| n.string().ok())
    {
        return Node::text(NAME, value);
    }
    if a.tag == LINK
        && let (Some(kind), Some(target)) = (
            a.get(LINK_TYPE).and_then(|n| n.number().ok()),
            a.get(LINKED_OBJECT_IDENTIFIER),
        )
        && let Some((tag, _)) = LINKS.iter().find(|(_, k)| *k == kind)
    {
        return match &target.value {
            Value::TextString(value) => Node::reference(*tag, value),
            _ => Node {
                tag: *tag,
                value: target.value.clone(),
            },
        };
    }
    a.clone()
}
pub(super) fn project_payload(v: Version, payload: &mut Node) -> R<()> {
    if let Value::Structure(fields) = &mut payload.value
        && v.0 >= 3
    {
        for field in fields {
            if [
                UNIQUE_IDENTIFIER,
                PRIVATE_KEY_UNIQUE_IDENTIFIER,
                PUBLIC_KEY_UNIQUE_IDENTIFIER,
                REPLACED_UNIQUE_IDENTIFIER,
            ]
            .contains(&field.tag)
                && let Value::TextString(value) = &field.value
            {
                *field = Node::identifier(field.tag, value);
            }
        }
    }
    if v.0 < 3 && draft_types(payload) {
        return Err(fail(
            8,
            "Attribute value cannot be represented in this protocol version",
        ));
    }
    Ok(())
}
