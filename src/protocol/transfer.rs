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

//! Restore supplied metadata without Register's initial-attribute defaults.
use super::*;
use crate::store::WrappedValue;
use std::collections::{BTreeMap, HashSet};

pub(super) fn wrap_type(p: &Node, default: u32, v: Version) -> R<u32> {
    if p.get(KEY_WRAP_TYPE).is_some() && v < Version(1, 4) {
        return Err(fail(7, "Key Wrap Type requires KMIP 1.4"));
    }
    match p.get(KEY_WRAP_TYPE).map(|n| &n.value) {
        None => Ok(default),
        Some(Value::Enumeration(n @ (1 | 2))) => Ok(*n),
        _ => Err(fail(7, "Invalid Key Wrap Type")),
    }
}
fn singleton(attrs: &[Node], tag: u32) -> R<Option<&Node>> {
    let mut found = attrs.iter().filter(|a| a.tag == tag);
    let result = found.next();
    if found.next().is_some() {
        return Err(fail(7, "Duplicate imported attribute"));
    }
    Ok(result)
}
fn required(attrs: &[Node], tag: u32) -> R<&Node> {
    singleton(attrs, tag)?.ok_or(fail(6, "Required imported attribute missing"))
}
fn key_attributes(obj: &Object) -> Vec<Node> {
    let mut attrs = vec![];
    if obj.algorithm != 0 {
        attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm));
    }
    if obj.bits != 0 {
        attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, obj.bits as i32));
    }
    if obj.object_type != 8 {
        attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, obj.usage as i32));
    }
    if [1, 9].contains(&obj.object_type) {
        attrs.extend(
            obj.attrs
                .iter()
                .filter(|a| certificate::owned_attribute(a.tag))
                .cloned(),
        );
    }
    attrs
}
fn registration(v: Version, obj: &Object, value: Node) -> R<Node> {
    let mut attrs = key_attributes(obj);
    if obj.object_type == 1 {
        certificate::project(v, &mut attrs);
    }
    split::project(obj, v, &mut attrs);
    Ok(Node::structure(
        REQUEST_PAYLOAD,
        vec![
            Node::enumeration(OBJECT_TYPE, obj.object_type),
            if v.0 == 1 {
                Node::structure(
                    TEMPLATE_ATTRIBUTE,
                    attrs.iter().map(encode_attribute).collect::<R<_>>()?,
                )
            } else {
                Node::structure(ATTRIBUTES, attrs)
            },
            value,
        ],
    ))
}
fn clear_object(object: &Node, mut value: Node, v: Version) -> R<(Node, Vec<Node>)> {
    let attr_tag = if v.0 == 1 { ATTRIBUTE } else { ATTRIBUTES };
    if value
        .children()?
        .iter()
        .any(|n| ![KEY_MATERIAL, attr_tag].contains(&n.tag))
        || value.all(KEY_MATERIAL).count() != 1
        || v.0 >= 2 && value.all(ATTRIBUTES).count() > 1
    {
        return Err(fail(7, "Invalid wrapped Key Value"));
    }
    let embedded = if v.0 == 1 {
        value
            .all(ATTRIBUTE)
            .map(decode_attribute)
            .collect::<R<Vec<_>>>()?
    } else {
        value
            .get(ATTRIBUTES)
            .map(Node::children)
            .transpose()?
            .unwrap_or(&[])
            .to_vec()
    };
    if let Value::Structure(fields) = &mut value.value {
        fields.retain(|n| n.tag == KEY_MATERIAL);
    }
    let mut object = object.clone();
    let Value::Structure(fields) = &mut object.value else {
        return Err(fail(7, "Object must be a Structure"));
    };
    let block = fields
        .iter_mut()
        .find(|n| n.tag == KEY_BLOCK)
        .ok_or(fail(6, "Key Block missing"))?;
    let Value::Structure(fields) = &mut block.value else {
        return Err(fail(7, "Key Block must be a Structure"));
    };
    fields.retain(|n| ![KEY_VALUE, KEY_WRAPPING_DATA].contains(&n.tag));
    fields.push(value);
    Ok((object, embedded))
}
impl Engine {
    pub(super) fn materialize(&self, owner: &str, obj: &mut Object) -> R<()> {
        key_value::require(obj)?;
        if !obj.material.is_empty() || obj.state >= 5 {
            return Ok(());
        }
        let Some(wrapped) = &obj.wrapped else {
            return Ok(());
        };
        let v = Version(wrapped.version[0], wrapped.version[1]);
        let block = wrapped.object.required(KEY_BLOCK)?;
        let (value, _) = self.unwrap_value(owner, v, block)?;
        let (clear, _) = clear_object(&wrapped.object, value, v)?;
        let mut validated = self.build_object(owner, v, &registration(v, obj, clear)?, true)?;
        obj.material = std::mem::take(&mut validated.material);
        metadata::verify_digests(obj).map_err(|_| fail(10, "Key unwrapping failed"))?;
        if !obj.attrs.iter().any(|a| a.tag == DIGEST) {
            add_digest(obj)?;
            attributes::limits(&obj.attrs)?;
            obj.updated = now();
            self.store.put(obj)?;
        }
        Ok(())
    }
    pub(super) fn registered_value(&self, v: Version, obj: &Object) -> R<Node> {
        let wrapped = obj
            .wrapped
            .as_ref()
            .ok_or(fail(0x13, "No registered envelope"))?;
        let data = wrapped
            .object
            .required(KEY_BLOCK)?
            .required(KEY_WRAPPING_DATA)?;
        if wrapped.version[0] != v.0 && number(data, ENCODING_OPTION, 2)? != 1 {
            return Err(fail(
                8,
                "As Registered TTLV transfer across major versions is not implemented",
            ));
        }
        let mut value = wrapped.object.clone();
        fn project(n: &mut Node, v: Version) {
            if n.tag == UNIQUE_IDENTIFIER {
                if let Ok(id) = n.identifier_text() {
                    // Key Wrapping Data identifiers use Identifier in
                    // draft 3.0 (as in wrapping.rs).
                    *n = if v.0 >= 3 {
                        Node::identifier(n.tag, id)
                    } else {
                        Node::text(n.tag, id)
                    };
                }
            } else if let Value::Structure(fields) = &mut n.value {
                if v == Version(1, 0) {
                    fields.retain(|n| n.tag != ENCODING_OPTION);
                }
                for field in fields {
                    project(field, v);
                }
            }
        }
        project(&mut value, v);
        Ok(value)
    }
    pub(super) fn import_object(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        // 1.4 uses repeated Attribute fields, rather than Template Attribute.
        let mut allowed = vec![
            UNIQUE_IDENTIFIER,
            OBJECT_TYPE,
            REPLACE_EXISTING,
            KEY_WRAP_TYPE,
            PROTECTION_STORAGE_MASKS,
            SYMMETRIC_KEY,
            PUBLIC_KEY,
            PRIVATE_KEY,
            SPLIT_KEY,
            CERTIFICATE,
            SECRET_DATA,
            OPAQUE_OBJECT,
            PGP_KEY,
        ];
        allowed.push(if v.0 == 1 { ATTRIBUTE } else { ATTRIBUTES });
        if p.children()?.iter().any(|n| !allowed.contains(&n.tag)) {
            return Err(fail(8, "Unsupported Import field"));
        }
        for tag in allowed.into_iter().filter(|t| *t != ATTRIBUTE) {
            if p.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate Import field"));
            }
        }
        let id = p.required(UNIQUE_IDENTIFIER)?.string()?.to_owned();
        // NUL is reserved for the server's hidden record identifiers
        // (records.rs); server-generated identifiers never contain it.
        if id.is_empty() || id.len() > 1024 || id.contains('\0') {
            return Err(fail(7, "Invalid imported identifier"));
        }
        let replace = flag(p, REPLACE_EXISTING, false)?;
        let existing = self.store.owner_of(&id)?;
        if let Some(existing_owner) = &existing {
            if existing_owner != owner {
                return Err(fail(12, "Import target is not owned by principal"));
            }
            if !replace {
                return Err(fail(24, "Import target already exists"));
            }
        }
        let attrs = if v.0 == 1 {
            p.all(ATTRIBUTE)
                .map(decode_attribute)
                .collect::<R<Vec<_>>>()?
        } else {
            p.required(ATTRIBUTES)?.children()?.to_vec()
        };
        let protection_mask = protection::imported(p, &attrs, v)?;
        let kind = if v.0 >= 2 {
            p.required(OBJECT_TYPE)?.number()?
        } else if let Some(n) = p.get(OBJECT_TYPE) {
            n.number()?
        } else {
            required(&attrs, OBJECT_TYPE)?.number()?
        };
        pgp::available(kind, v)?;
        if kind == certificate_request::KIND {
            return Err(fail(
                8,
                "Import of Certificate Request objects is not implemented",
            ));
        }
        certificate::attribute_context(kind, &attrs)?;
        let object = p.required(object_tag(kind)?)?;
        if kind == 9 {
            pgp::read(object, v)?;
        }
        if kind != 5 {
            split::ordinary_attributes(&attrs)?;
        }
        if p.children()?
            .iter()
            .filter(|n| {
                [
                    SYMMETRIC_KEY,
                    PUBLIC_KEY,
                    PRIVATE_KEY,
                    SPLIT_KEY,
                    CERTIFICATE,
                    SECRET_DATA,
                    OPAQUE_OBJECT,
                    PGP_KEY,
                ]
                .contains(&n.tag)
            })
            .count()
            != 1
        {
            return Err(fail(7, "Import requires exactly one object"));
        }
        if kind == 1 {
            certificate::read_type(object)?;
        } else if kind == 8 {
            opaque::read(object)?;
        }
        if ![1, 8].contains(&kind) {
            object.required(KEY_BLOCK)?.required(KEY_FORMAT_TYPE)?;
        }
        let block = object.get(KEY_BLOCK);
        let wrapped = block.and_then(|b| b.get(KEY_WRAPPING_DATA)).is_some();
        if v.0 >= 2 && wrapped != p.get(KEY_WRAP_TYPE).is_some() {
            return Err(fail(
                7,
                "Key Wrap Type is required exactly when the imported object is wrapped",
            ));
        }
        let wrap = wrap_type(p, 2, v)?;
        let mut clear = None;
        if wrapped && wrap == 1 {
            let (value, _) = self.unwrap_value(owner, v, block.expect("wrapped block"))?;
            let (object, embedded) = clear_object(object, value, v)?;
            // The outer list supplies all attributes. Conflicting authenticated
            // metadata is rejected, rather than silently replacing either value.
            for mut a in embedded {
                a = self.normalize_attribute(
                    owner,
                    v,
                    a,
                    &identifiers::References::default(),
                    &None,
                )?;
                if !attrs.contains(&a) {
                    if attrs
                        .iter()
                        .any(|b| attributes::identity(b).ok() == attributes::identity(&a).ok())
                    {
                        return Err(fail(7, "Wrapped and imported attributes conflict"));
                    }
                    return Err(fail(
                        7,
                        "Import must include the wrapped attributes in its outer attribute list",
                    ));
                }
            }
            clear = Some(object);
        }
        let state = required(&attrs, STATE)?.number()?;
        if !(1..=6).contains(&state)
            || !matches!(required(&attrs, STATE)?.value, Value::Enumeration(_))
        {
            return Err(fail(7, "Invalid imported State"));
        }
        let created = date_value(required(&attrs, INITIAL_DATE)?)?;
        let updated = date_value(required(&attrs, LAST_CHANGE_DATE)?)?;
        let mut obj = Object {
            id,
            owner: owner.into(),
            object_type: kind,
            certificate_type: if kind == 1 {
                certificate::read_type(object)?
            } else {
                1
            },
            pgp_version: if kind == 9 {
                pgp::read(object, v)?
            } else {
                pgp::DEFAULT_VERSION
            },
            opaque_type: if kind == 8 {
                opaque::read(object)?
            } else {
                opaque::LEGACY_TYPE
            },
            secret_type: if kind == 7 {
                number(object, SECRET_DATA_TYPE, 2)?
            } else {
                2
            },
            format: block
                .map(|b| number(b, KEY_FORMAT_TYPE, 1))
                .transpose()?
                .unwrap_or(0),
            algorithm: attr_num(&attrs, CRYPTOGRAPHIC_ALGORITHM, 0)?,
            bits: attr_num(&attrs, CRYPTOGRAPHIC_LENGTH, 0)?,
            usage: attr_num(&attrs, CRYPTOGRAPHIC_USAGE_MASK, 0)?,
            protection_mask,
            usage_consumed: false,
            replacement_id: None,
            wrapped: None,
            imported: true,
            metadata: crate::store::ObjectMetadata {
                origin: crate::store::MetadataOrigin::Imported,
                version: [v.0, v.1],
                ..Default::default()
            },
            split: if kind == 5 {
                Some(split::read(object, v, &attrs)?)
            } else {
                None
            },
            state,
            material: vec![],
            attrs: vec![],
            attribute_indices: BTreeMap::new(),
            created,
            updated,
        };
        if let Some(block) = block {
            if kind == 9 {
                pgp::read(object, v)?;
            } else if kind != 5 {
                no_fields(object, &[KEY_BLOCK, SECRET_DATA_TYPE])?;
            }
            no_fields(
                block,
                &[
                    KEY_FORMAT_TYPE,
                    KEY_COMPRESSION_TYPE,
                    KEY_VALUE,
                    CRYPTOGRAPHIC_ALGORITHM,
                    CRYPTOGRAPHIC_LENGTH,
                    KEY_WRAPPING_DATA,
                ],
            )?;
            if obj.algorithm == 0 {
                obj.algorithm = number(block, CRYPTOGRAPHIC_ALGORITHM, 0)?;
            }
            if obj.bits == 0 {
                obj.bits = number(block, CRYPTOGRAPHIC_LENGTH, 0)?;
            }
            if number(block, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)? != obj.algorithm
                || number(block, CRYPTOGRAPHIC_LENGTH, obj.bits)? != obj.bits
            {
                return Err(fail(7, "Imported key metadata conflicts"));
            }
            if kind == 7 && ![1, 2].contains(&number(object, SECRET_DATA_TYPE, 2)?) {
                return Err(fail(8, "Only Password or Seed Secret Data is supported"));
            }
            if kind == 2 && obj.algorithm == tdea::ALGORITHM {
                tdea::validate_length(obj.bits)?;
            } else if kind == 2 {
                validate_symmetric_parameters(obj.algorithm, obj.bits, v)?;
            }
            if !match kind {
                2 => [1, 7].contains(&obj.format),
                3 => {
                    transparent::format_allowed(3, obj.algorithm, obj.format)
                        || ec::format_allowed(3, obj.algorithm, obj.format, v)
                }
                4 => {
                    transparent::format_allowed(4, obj.algorithm, obj.format)
                        || ec::format_allowed(4, obj.algorithm, obj.format, v)
                }
                7 => [1, 2].contains(&obj.format),
                5 | 9 => [1, 2].contains(&obj.format),
                _ => false,
            } {
                return Err(fail(0x10, "Unsupported imported key format"));
            }
        }
        metadata::require_import(&obj, v, &attrs, state < 5 && (!wrapped || wrap == 1))?;
        if kind == 1 {
            certificate::imported(&attrs, v, obj.certificate_type)?;
        }
        pgp::metadata(kind, obj.algorithm, obj.bits, &attrs, v)?;
        let mut normal = vec![];
        let mut seen = HashSet::new();
        for a in &attrs {
            let key = attributes::identity(a)?;
            if !seen.insert(key) && !attributes::multiple(a.tag) {
                return Err(fail(7, "Duplicate imported attribute"));
            }
            match a.tag {
                UNIQUE_IDENTIFIER if a.string()? == obj.id => {}
                OBJECT_TYPE if matches!(a.value,Value::Enumeration(value) if value==kind) => {}
                UNIQUE_IDENTIFIER | OBJECT_TYPE => {
                    return Err(fail(7, "Imported identity conflicts"));
                }
                STATE | INITIAL_DATE | LAST_CHANGE_DATE => {}
                PROTECTION_STORAGE_MASK if v.0 >= 2 => {}
                OPAQUE_DATA_TYPE if v.0 >= 2 && kind == 8 => {
                    if opaque::value(a)? != obj.opaque_type {
                        return Err(fail(7, "Imported Opaque Data Type conflicts with object"));
                    }
                }
                FRESH if v >= Version(1, 1) => {
                    obj.metadata.fresh = Some(a.flag()?);
                }
                ALWAYS_SENSITIVE if v >= Version(1, 4) => {
                    obj.metadata.always_sensitive = Some(a.flag()?);
                }
                NEVER_EXTRACTABLE if v >= Version(1, 4) => {
                    obj.metadata.never_extractable = Some(a.flag()?);
                }
                KEY_FORMAT_TYPE
                    if matches!(a.value,Value::Enumeration(value) if value==attribute_format(&obj))
                        && v.0 >= 2 => {}
                KEY_FORMAT_TYPE => return Err(fail(7, "Imported key format conflicts")),
                LEASE_TIME => {
                    usage::interval_value(a)?;
                    obj.attrs.push(a.clone());
                }
                USAGE_LIMITS => {
                    obj.usage_consumed = usage::validate_restored(a)?;
                    obj.attrs.push(a.clone());
                }
                DIGEST => {
                    no_fields(a, &[HASHING_ALGORITHM, DIGEST_VALUE, KEY_FORMAT_TYPE])?;
                    if !matches!(a.required(HASHING_ALGORITHM)?.value, Value::Enumeration(_)) {
                        return Err(fail(7, "Digest hash must be an Enumeration"));
                    }
                    crypto::rsa::digest(a.required(HASHING_ALGORITHM)?.number()?)
                        .map_err(|_| fail(8, "Unsupported digest algorithm"))?;
                    let bytes = a.required(DIGEST_VALUE)?.byte_string()?;
                    if bytes.len()
                        != crypto::rsa::digest(a.required(HASHING_ALGORITHM)?.number()?)
                            .map_err(|_| fail(8, "Unsupported digest algorithm"))?
                            .size()
                    {
                        return Err(fail(7, "Digest length disagrees with its algorithm"));
                    }
                    if let Some(f) = a.get(KEY_FORMAT_TYPE)
                        && !matches!(f.value, Value::Enumeration(_))
                    {
                        return Err(fail(7, "Digest format must be an Enumeration"));
                    }
                    obj.attrs.push(a.clone());
                }
                SHORT_UNIQUE_IDENTIFIER if v.0 >= 2 => {
                    a.byte_string()?;
                    obj.attrs.push(a.clone());
                }
                OBJECT_CLASS if v.0 >= 3 && matches!(a.value, Value::Enumeration(1)) => {
                    obj.attrs.push(a.clone());
                }
                SPLIT_KEY_METHOD | SPLIT_KEY_PARTS | SPLIT_KEY_THRESHOLD | SPLIT_KEY_POLYNOMIAL
                    if kind == 5 && v.0 >= 3 => {}
                REVOCATION_REASON => {
                    revocation::reason(a)?;
                    obj.attrs.push(a.clone());
                }
                DESTROY_DATE | COMPROMISE_DATE | COMPROMISE_OCCURRENCE_DATE | ARCHIVE_DATE => {
                    date_value(a)?;
                    obj.attrs.push(a.clone());
                }
                ATTRIBUTE if vendor_identity(a)?.0 == "y" => {
                    let mut check = a.clone();
                    if let Value::Structure(fields) = &mut check.value {
                        *fields
                            .iter_mut()
                            .find(|n| n.tag == VENDOR_IDENTIFICATION)
                            .ok_or(fail(6, "Vendor ID missing"))? =
                            Node::text(VENDOR_IDENTIFICATION, "x");
                    }
                    validate_attrs(&[check], v)?;
                    obj.attrs.push(a.clone());
                }
                _ => normal.push(a.clone()),
            }
        }
        validate_attrs(&normal, v)?;
        metadata::validate_restored(&obj.metadata, &normal)?;
        obj.attrs.extend(normal);
        identifiers::validate_link_cardinality(&obj.attrs, v)?;
        obj.replacement_id = obj
            .attrs
            .iter()
            .find(|a| link_kind(a) == Some(0x106))
            .and_then(|a| a.get(LINKED_OBJECT_IDENTIFIER))
            .and_then(|a| a.identifier_text().ok())
            .map(str::to_owned);
        attributes::limits(&obj.attrs)?;
        revocation::validate_restored(&obj)?;
        if v.0 == 1 {
            // Preserve explicit stable indices, including gaps, across restore.
            for a in p.all(ATTRIBUTE) {
                let decoded = decode_attribute(a)?;
                if attributes::multiple(decoded.tag) {
                    let index = match a.get(ATTRIBUTE_INDEX).map(|n| &n.value) {
                        None => 0,
                        Some(Value::Integer(i)) if *i >= 0 => *i,
                        _ => return Err(fail(7, "Invalid Attribute Index")),
                    };
                    let values = obj
                        .attribute_indices
                        .entry(attributes::identity(&decoded)?)
                        .or_default();
                    if values.contains(&index) {
                        return Err(fail(7, "Duplicate Attribute Index"));
                    }
                    values.push(index);
                }
            }
        }
        if state >= 5 {
            if wrapped
                || block.is_some_and(|b| b.get(KEY_VALUE).is_some())
                || object.get(CERTIFICATE_VALUE).is_some()
                || object.get(OPAQUE_DATA_VALUE).is_some()
            {
                return Err(fail(7, "Destroyed import cannot contain object material"));
            }
        } else if wrapped && wrap == 2 {
            let block = block.expect("wrapped block");
            let cipher = block.required(KEY_VALUE)?.byte_string()?;
            if cipher.is_empty() || cipher.len() > 65536 {
                return Err(fail(7, "Invalid wrapped object size"));
            }
            // Envelope validity is checked when unwrapping, allowing backup
            // restore before its KEK is available. No plaintext is persisted.
            obj.wrapped = Some(WrappedValue {
                object: object.clone(),
                version: [v.0, v.1],
                opaque: true,
            });
        } else {
            let clear = clear.unwrap_or_else(|| object.clone());
            let mut checked = self.build_object(owner, v, &registration(v, &obj, clear)?, true)?;
            obj.format = checked.format;
            obj.algorithm = checked.algorithm;
            obj.bits = checked.bits;
            obj.material = std::mem::take(&mut checked.material);
            if kind == 1 {
                obj.attrs.retain(|a| !certificate::owned_attribute(a.tag));
                obj.attrs.extend(
                    std::mem::take(&mut checked.attrs)
                        .into_iter()
                        .filter(|a| certificate::owned_attribute(a.tag)),
                );
            }
        }
        metadata::verify_digests(&obj)?;
        self.unique_short_id(&obj, v)?;
        self.unique_names(&obj, v)?;
        super::quantum::check(&obj)?;
        if existing.is_some() {
            self.store.put(&obj)?;
        } else {
            self.store.insert(&obj)?;
        }
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    pub(super) fn export_object(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let obj = self.object(owner, p, placeholder)?;
        split::check_version(&obj, v)?;
        pgp::available(obj.object_type, v)?;
        // Use Get's authorization, format and wrapping checks for live material.
        let mut fields = if obj.state < 5 {
            self.get(owner, v, p, placeholder, v.0 == 1)?
        } else {
            no_fields(
                p,
                &[
                    UNIQUE_IDENTIFIER,
                    KEY_FORMAT_TYPE,
                    KEY_COMPRESSION_TYPE,
                    KEY_WRAP_TYPE,
                    KEY_WRAPPING_SPECIFICATION,
                ],
            )?;
            wrap_type(p, 1, v)?;
            if p.get(KEY_WRAPPING_SPECIFICATION).is_some()
                || p.get(KEY_COMPRESSION_TYPE).is_some()
                || number(p, KEY_FORMAT_TYPE, obj.format)? != obj.format
            {
                // 2.1 section 6.1.18: a destroyed object is exported without
                // its key material. A requested transformation of that
                // material fails as Get does.
                return Err(fail(
                    if v.0 >= 2 {
                        OBJECT_DESTROYED_REASON
                    } else {
                        0x13
                    },
                    "Destroyed object has no key material to transform",
                ));
            }
            let object = match obj.object_type {
                1 => Node::structure(
                    CERTIFICATE,
                    vec![Node::enumeration(CERTIFICATE_TYPE, obj.certificate_type)],
                ),
                8 => Node::structure(
                    OPAQUE_OBJECT,
                    vec![Node::enumeration(OPAQUE_DATA_TYPE, obj.opaque_type)],
                ),
                certificate_request::KIND => Node::structure(
                    CERTIFICATE_REQUEST,
                    vec![Node::enumeration(
                        CERTIFICATE_REQUEST_TYPE,
                        obj.certificate_type,
                    )],
                ),
                kind => {
                    let mut block = vec![Node::enumeration(KEY_FORMAT_TYPE, obj.format)];
                    // Not applicable to Secret Data (Key Block table, 1.x 2.1.3, 2.0+ 3.1).
                    if kind != 7 && obj.algorithm != 0 {
                        block.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm));
                    }
                    if kind != 7 && obj.bits != 0 {
                        block.push(Node::int(CRYPTOGRAPHIC_LENGTH, obj.bits as i32));
                    }
                    let mut fields = vec![];
                    fields.extend(split::fields(&obj)?);
                    if kind == 9 {
                        fields.push(Node::int(PGP_KEY_VERSION, obj.pgp_version as i32));
                    }
                    if kind == 7 {
                        fields.push(Node::enumeration(SECRET_DATA_TYPE, obj.secret_type));
                    }
                    fields.push(Node::structure(KEY_BLOCK, block));
                    Node::structure(object_tag(kind)?, fields)
                }
            };
            vec![
                Node::enumeration(OBJECT_TYPE, obj.object_type),
                Node::text(UNIQUE_IDENTIFIER, &obj.id),
                object,
            ]
        };
        let object = fields.pop().expect("Get object");
        let attrs = self.get_attrs(
            owner,
            v,
            &Node::structure(
                REQUEST_PAYLOAD,
                vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)],
            ),
            &None,
            false,
        )?;
        fields.extend(attrs.into_iter().filter(|n| n.tag != UNIQUE_IDENTIFIER));
        fields.push(object);
        *placeholder = Some(obj.id.clone());
        Ok(fields)
    }
}
