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

//! KMIP 1.x Template managed object (Object Type 6; deprecated in 1.3,
//! listed as Reserved in 2.0 Table 430).
//!
//! A Template is "a named Managed Object containing the client-settable
//! attributes of a Managed Cryptographic Object" (1.0-1.4 section 2.2.6).
//! Its content (the Template structure) is held in `Object::material` as
//! encoded TTLV, so the persisted record keeps the existing schema. The
//! template's own attributes (Name, dates, ...) are ordinary `attrs`.
use super::*;

pub(super) const KIND: u32 = 6;

/// Template-Attribute structures that may carry template Names (1.x 2.1.8).
const CONTAINERS: [u32; 4] = [
    TEMPLATE_ATTRIBUTE,
    COMMON_TEMPLATE_ATTRIBUTE,
    PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
    PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
];
/// Operations whose 1.x request payloads specify attributes "using
/// templates and/or individual attributes": Create, Create Key Pair,
/// Register, Re-key, Derive Key, Certify, Re-certify, Re-key Key Pair,
/// Create Split Key and Join Split Key (1.4 sections 4.1-4.8, 4.38-4.39).
const OPERATIONS: [u32; 10] = [1, 2, 3, 4, 5, 6, 7, 29, 40, 41];
/// 1.0/1.1 section 2.2.6: "The Template MAY be the subject of the Register,
/// Locate, Get, Get Attributes, Get Attribute List, Add Attribute, Modify
/// Attribute, Delete Attribute, and Destroy operations." Archive Date is
/// listed as applicable to the Template itself, and the 1.x Create/Register
/// error tables name an archived Template, so Archive and Recover apply too.
const SUBJECT_OF: [u32; 11] = [3, 8, 10, 11, 12, 13, 14, 15, 20, 21, 22];

/// Templates exist only in KMIP 1.x; 2.0 Table 430 marks value 6 Reserved.
pub(super) fn defined(v: Version) -> bool {
    v.0 == 1
}
/// 1.4 section 4.21: "If the Unique Identifier specifies a Template object,
/// then the object itself, including all meta-data, SHALL be destroyed."
/// The store keeps a metadata-free tombstone that no lookup returns.
fn destroyed(obj: &Object) -> bool {
    obj.object_type == KIND && obj.state >= 5
}
/// Whether a stored object exists for a request of version `v` (None for
/// server-internal lookups). Templates are invisible to 2.x and later.
pub(super) fn visible(obj: &Object, v: Option<Version>) -> bool {
    obj.object_type != KIND || !destroyed(obj) && v.is_none_or(defined)
}
/// Reject operations that do not apply to Templates with Illegal Operation
/// (1.4 Table 346: "Unique Identifier specifies a template or other object
/// that is not able to be activated"; likewise Revoke, Table 347). Only
/// reachable for 1.x requests, since Templates are invisible otherwise.
pub(super) fn permits(obj: &Object, op: u32) -> R<()> {
    if obj.object_type == KIND && !SUBJECT_OF.contains(&op) {
        return Err(fail(11, "Operation does not apply to a Template"));
    }
    Ok(())
}
/// Objects referenced as keys (wrapping keys, split sources) must be keys:
/// 1.4 Table 337 "Object with Encryption Key Information exists, but it is
/// not a key" yields Illegal Operation.
pub(super) fn not_key(obj: &Object) -> R<()> {
    if obj.object_type == KIND {
        return Err(fail(11, "A Template is not a key"));
    }
    Ok(())
}

/// Attributes applicable to the Template object itself.
///
/// 1.0/1.1 section 2.2.6: "Attributes applicable to the Template itself are:
/// Unique Identifier, Object Type, Name, Initial Date, Archive Date, and Last
/// Change Date"; only Name is client-settable. 1.2 dropped that list, so the
/// client-settable "All Objects" attributes of section 3 also apply. The
/// "Templates" entries of section 3 (Cryptographic Algorithm, dates, ...)
/// keep the 1.0/1.1 meaning: they apply to objects created using the
/// Template and belong in its Template structure.
fn own_attribute_applies(tag: u32, v: Version) -> bool {
    tag == NAME
        || v >= Version(1, 2)
            && [
                OBJECT_GROUP,
                APPLICATION_SPECIFIC_INFORMATION,
                CONTACT_INFORMATION,
                ATTRIBUTE,
                ALTERNATIVE_NAME,
                COMMENT,
            ]
            .contains(&tag)
}
/// Attribute-modification hook: Add/Modify Attribute on a Template accepts
/// only attributes applicable to the Template itself.
pub(super) fn own_attribute(obj: &Object, a: &Node, v: Version) -> R<()> {
    if obj.object_type == KIND && !own_attribute_applies(a.tag, v) {
        return Err(fail(7, "Attribute does not apply to a Template object"));
    }
    Ok(())
}
/// Attributes a Template structure may carry for objects created using it.
///
/// 1.0 section 2.2.6 lists Cryptographic Algorithm, Cryptographic Length,
/// Cryptographic Domain Parameters, Cryptographic Parameters, Operation Policy
/// Name, Cryptographic Usage Mask, Usage Limits, Activation Date, Process
/// Start Date, Protect Stop Date, Deactivation Date, Object Group, Application
/// Specific Information, Contact Information and Custom Attribute; 1.1 adds
/// Certificate Length and Digital Signature Algorithm. 1.2-1.4 only say
/// "client-settable attributes of a Managed Cryptographic Object", so the
/// ordinary attribute validation (and the operation applying the Template)
/// decides there.
fn content_attribute_applies(tag: u32, v: Version) -> bool {
    v >= Version(1, 2)
        || [
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
            CRYPTOGRAPHIC_PARAMETERS,
            OPERATION_POLICY_NAME,
            CRYPTOGRAPHIC_USAGE_MASK,
            USAGE_LIMITS,
            ACTIVATION_DATE,
            PROCESS_START_DATE,
            PROTECT_STOP_DATE,
            DEACTIVATION_DATE,
            OBJECT_GROUP,
            APPLICATION_SPECIFIC_INFORMATION,
            CONTACT_INFORMATION,
            ATTRIBUTE,
        ]
        .contains(&tag)
        || v == Version(1, 1) && [CERTIFICATE_LENGTH, DIGITAL_SIGNATURE_ALGORITHM].contains(&tag)
}

/// Stored Template content, in internal attribute form.
fn content(obj: &Object) -> R<Vec<Node>> {
    let node = crate::ttlv::decode(&obj.material)
        .ok()
        .filter(|n| n.tag == TEMPLATE)
        .ok_or(fail(0x100, "Stored Template content is invalid"))?;
    Ok(node.children()?.to_vec())
}
/// An Attribute structure without Attribute Index, as in Table 50 and the
/// Template-Attribute structures of Table 29.
fn plain_attribute(a: &Node) -> R<Node> {
    let mut n = encode_attribute(a)?;
    if let Value::Structure(fields) = &mut n.value {
        fields.retain(|f| f.tag != ATTRIBUTE_INDEX);
    }
    Ok(n)
}

/// Template object attributes, replacing the managed-cryptographic-object
/// projection: no State, Digest, Fresh, Lease Time or Cryptographic Usage
/// Mask, which 1.x section 3 applies to cryptographic objects only.
pub(super) fn attributes(obj: &Object, v: Version) -> Vec<Node> {
    let mut attrs = obj.attrs.clone();
    attrs.retain(|a| {
        !(v < Version(1, 2) && a.tag == ALTERNATIVE_NAME || v < Version(1, 4) && a.tag == COMMENT)
    });
    attrs.extend([
        Node::text(UNIQUE_IDENTIFIER, &obj.id),
        Node::enumeration(OBJECT_TYPE, KIND),
        Node::date(INITIAL_DATE, obj.created),
        Node::date(LAST_CHANGE_DATE, obj.updated),
    ]);
    attrs
        .into_iter()
        .map(|a| identifiers::project_attribute(v, &a))
        .collect()
}

/// Get of a Template returns its Template structure (1.4 Table 194). A
/// Template has no Key Block, so key format, compression and wrapping
/// requests do not apply.
pub(super) fn get(obj: &Object, p: &Node) -> R<Vec<Node>> {
    if p.get(KEY_FORMAT_TYPE).is_some() {
        return Err(fail(0x10, "A Template has no key format"));
    }
    if p.get(KEY_COMPRESSION_TYPE).is_some() {
        return Err(fail(0x11, "A Template has no key compression"));
    }
    if p.get(KEY_WRAP_TYPE).is_some() || p.get(KEY_WRAPPING_SPECIFICATION).is_some() {
        return Err(fail(8, "A Template has no Key Block to wrap"));
    }
    Ok(vec![
        Node::enumeration(OBJECT_TYPE, KIND),
        Node::text(UNIQUE_IDENTIFIER, &obj.id),
        Node::structure(
            TEMPLATE,
            content(obj)?
                .iter()
                .map(plain_attribute)
                .collect::<R<Vec<_>>>()?,
        ),
    ])
}

/// Destroy a Template entirely (1.4 section 4.21), leaving a tombstone
/// without attributes or content that every lookup treats as absent.
pub(super) fn destroy(obj: &mut Object) {
    obj.state = 5;
    obj.material.zeroize();
    obj.material.clear();
    obj.attrs.clear();
    obj.attribute_indices.clear();
    obj.updated = now();
}

impl Engine {
    /// Resolve template Names in 1.x Template-Attribute structures into
    /// individual attributes, returning the rewritten payload (None when the
    /// request names no template).
    ///
    /// 1.4 section 4: "If more than one template name is specified, and there
    /// is a conflict between the single-instance attributes in the templates,
    /// then the value in the last of the conflicting templates takes
    /// precedence. If there is a conflict between the single-instance
    /// attributes in the request and the single-instance attributes in a
    /// specified template, then the attribute values in the request take
    /// precedence. For multi-instance attributes, the union of attribute
    /// values is used when the attributes are specified more than once."
    ///
    /// Each container is expanded on its own, so Create Key Pair keeps the
    /// order of 1.4 section 4.2: explicit Private/Public, then their
    /// templates, then explicit Common, then Common templates; the existing
    /// Common/specific union applies the last two steps.
    pub(super) fn expand_templates(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
    ) -> R<Option<Node>> {
        if !defined(v) || !OPERATIONS.contains(&op) {
            return Ok(None);
        }
        let Value::Structure(fields) = &p.value else {
            return Ok(None);
        };
        let names = |f: &Node| match &f.value {
            Value::Structure(children) => children.iter().any(|n| n.tag == NAME),
            _ => false,
        };
        if !fields
            .iter()
            .any(|f| CONTAINERS.contains(&f.tag) && names(f))
        {
            return Ok(None);
        }
        let mut expanded = p.clone();
        if let Value::Structure(fields) = &mut expanded.value {
            for f in fields
                .iter_mut()
                .filter(|f| CONTAINERS.contains(&f.tag) && names(f))
            {
                *f = self.expand_container(owner, f)?;
            }
        }
        Ok(Some(expanded))
    }
    fn expand_container(&self, owner: &str, container: &Node) -> R<Node> {
        let mut inherited = vec![];
        let mut explicit = vec![];
        for n in container.children()? {
            match n.tag {
                NAME => {
                    let template = self.template_by_name(owner, n)?;
                    inherited = attributes::pair_union(inherited, content(&template)?)?;
                }
                ATTRIBUTE => explicit.push(decode_attribute(n)?),
                _ => return Err(fail(7, "Invalid Template-Attribute field")),
            }
        }
        let merged = attributes::pair_union(inherited, explicit)?;
        Ok(Node::structure(
            container.tag,
            merged.iter().map(plain_attribute).collect::<R<Vec<_>>>()?,
        ))
    }
    /// The caller's Template with this Name. Default policy for private
    /// templates (1.4 Table 94): "Any operation referencing the Template
    /// using a Template-Attribute: Allowed to owner only".
    fn template_by_name(&self, owner: &str, name: &Node) -> R<Object> {
        no_fields(name, &[NAME_VALUE, NAME_TYPE])?;
        let value = name.required(NAME_VALUE)?.string()?;
        let kind = number(name, NAME_TYPE, 1)?;
        let (count, ids) = self.store.locate(owner, 0, 1, |o| {
            o.object_type == KIND
                && !destroyed(o)
                && o.attrs.iter().any(|a| {
                    a.tag == NAME
                        && a.get(NAME_VALUE).and_then(|n| n.string().ok()) == Some(value)
                        && number(a, NAME_TYPE, 1).ok() == Some(kind)
                })
        })?;
        // 1.4 Tables 328-330: "Templates that do not exist are given in
        // request" yields Item Not Found.
        let id = match (count, ids.first()) {
            (1, Some(id)) => id,
            (0, _) => return Err(fail(1, "Template not found")),
            _ => return Err(fail(7, "Template name is ambiguous")),
        };
        let obj = self
            .store
            .get(owner, id)?
            .ok_or(fail(1, "Template not found"))?;
        // "Template object is archived" yields Object Archived.
        archive::online(&obj)?;
        Ok(obj)
    }
    /// Register of a Template (1.4 section 4.3, Table 169).
    pub(super) fn register_template(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[OBJECT_TYPE, TEMPLATE_ATTRIBUTE, TEMPLATE])?;
        let mut attrs = read_attrs(p, v)?;
        let mut content = vec![];
        for n in p.required(TEMPLATE)?.children()? {
            if n.tag != ATTRIBUTE {
                return Err(fail(7, "Template fields must be Attributes"));
            }
            let a = decode_attribute(n)?;
            if a.tag == NAME {
                // 1.0/1.1 2.2.6: none of the attributes in a Template "except
                // the Name attribute apply to the template object itself".
                // 1.2-1.4 Register errors: "Trying to register a new Template
                // object containing a Name attribute with the Template
                // structure" yields Invalid Field.
                if v >= Version(1, 2) {
                    return Err(fail(7, "A Template structure cannot contain a Name"));
                }
                attrs.push(a);
            } else if !content_attribute_applies(a.tag, v) {
                return Err(fail(7, "Attribute cannot be specified in a Template"));
            } else {
                content.push(a);
            }
        }
        // Table 50: at least one Attribute is REQUIRED.
        if content.is_empty() {
            return Err(fail(7, "A Template structure requires an Attribute"));
        }
        if attrs.iter().any(|a| !own_attribute_applies(a.tag, v)) {
            return Err(fail(7, "Attribute does not apply to a Template object"));
        }
        // 2.2.6: "A Template is a named Managed Object"; templates are only
        // ever referenced by Name.
        if !attrs.iter().any(|a| a.tag == NAME) {
            return Err(fail(7, "A Template requires a Name"));
        }
        metadata::prepare(&mut attrs, v, false)?;
        validate_attrs(&attrs, v)?;
        metadata::prepare(&mut content, v, false)?;
        validate_attrs(&content, v)?;
        let material = Node::structure(TEMPLATE, content).encode();
        if material.len() > 262_144 {
            return Err(fail(2, "Template content exceeds the storage limit"));
        }
        let time = now();
        let mut obj = Object {
            id: crypto::uuid(),
            owner: owner.into(),
            object_type: KIND,
            secret_type: 2,
            opaque_type: opaque::LEGACY_TYPE,
            pgp_version: pgp::DEFAULT_VERSION,
            certificate_type: 1,
            format: 0,
            algorithm: 0,
            bits: 0,
            usage: 0,
            protection_mask: protection::SOFTWARE,
            usage_consumed: false,
            replacement_id: None,
            wrapped: None,
            imported: false,
            metadata: Default::default(),
            split: None,
            // Internal only: State does not apply to Templates and is never
            // projected (1.4 section 3.22 applies it to cryptographic objects).
            state: 1,
            material,
            attrs,
            attribute_indices: Default::default(),
            created: time,
            updated: time,
        };
        metadata::initialize(&mut obj, v, false)?;
        attributes::limits(&obj.attrs)?;
        self.unique_names(&obj, v)?;
        self.store.insert(&obj)?;
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
}
