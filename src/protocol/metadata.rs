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

//! Factory provenance, write-once origin data and persistent extraction history.
use super::*;
use crate::store::{MetadataOrigin, ObjectMetadata};

pub(super) fn carries_material(p: &Node) -> bool {
    let Some(kind) = p.get(OBJECT_TYPE).and_then(|n| n.number().ok()) else {
        return false;
    };
    let Ok(tag) = object_tag(kind) else {
        return false;
    };
    p.get(tag).is_some_and(|value| match kind {
        1 => value.get(CERTIFICATE_VALUE).is_some(),
        8 => value.get(OPAQUE_DATA_VALUE).is_some(),
        super::certificate_request::KIND => value.get(CERTIFICATE_REQUEST_VALUE).is_some(),
        _ => value
            .get(KEY_BLOCK)
            .is_some_and(|b| b.get(KEY_VALUE).is_some()),
    })
}

pub(super) fn default_rng() -> Node {
    // The provider's internal RNG construction is not attested by this service.
    Node::structure(
        RANDOM_NUMBER_GENERATOR,
        vec![Node::enumeration(RNG_ALGORITHM, 1)],
    )
}
pub(super) fn validate_rng(n: &Node) -> R<()> {
    no_fields(
        n,
        &[
            RNG_ALGORITHM,
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            HASHING_ALGORITHM,
            DRBG_ALGORITHM,
            RECOMMENDED_CURVE,
            FIPS186_VARIATION,
            PREDICTION_RESISTANCE,
        ],
    )?;
    if !matches!(n.required(RNG_ALGORITHM)?.value, Value::Enumeration(1..=6)) {
        return Err(fail(7, "Invalid RNG Algorithm"));
    }
    for n in n.children()? {
        match n.tag {
            PREDICTION_RESISTANCE => {
                n.flag()?;
            }
            CRYPTOGRAPHIC_LENGTH if matches!(n.value,Value::Integer(i) if i>0) => {}
            CRYPTOGRAPHIC_LENGTH => {
                return Err(fail(7, "RNG cryptographic length must be positive"));
            }
            _ if matches!(n.value, Value::Enumeration(_)) => {}
            _ => return Err(fail(7, "RNG parameter must be an Enumeration")),
        }
    }
    Ok(())
}
pub(super) fn prepare(attrs: &mut Vec<Node>, v: Version, generated: bool) -> R<()> {
    protection::reject_client_attribute(attrs, v)?;
    opaque::reject_attribute(attrs, v)?;
    for a in attrs.iter() {
        if v < Version(1, 1) && a.tag == FRESH
            || v < Version(1, 2) && a.tag == ORIGINAL_CREATION_DATE
            || v < Version(1, 3) && a.tag == RANDOM_NUMBER_GENERATOR
            || v < Version(1, 4) && matches!(a.tag, ALWAYS_SENSITIVE | NEVER_EXTRACTABLE)
        {
            return Err(fail(7, "Attribute is unavailable in this version"));
        }
    }
    if attrs
        .iter()
        .any(|a| matches!(a.tag, ALWAYS_SENSITIVE | NEVER_EXTRACTABLE))
    {
        return Err(usage::read_only(v));
    }
    if generated && attrs.iter().any(|a| a.tag == ORIGINAL_CREATION_DATE) {
        return Err(usage::read_only(v));
    }
    if generated
        && attrs
            .iter()
            .any(|a| a.tag == FRESH && a.flag().ok() == Some(false))
    {
        return Err(fail(7, "New server objects must be Fresh"));
    }
    if generated && attrs.iter().any(|a| a.tag == RANDOM_NUMBER_GENERATOR) {
        if v < Version(1, 3) {
            return Err(fail(7, "RNG attributes require KMIP 1.3"));
        }
        let actual = default_rng();
        let mut matches = false;
        for desired in attrs.iter().filter(|a| a.tag == RANDOM_NUMBER_GENERATOR) {
            validate_rng(desired)?;
            matches |= desired
                .children()?
                .iter()
                .all(|n| actual.get(n.tag) == Some(n));
        }
        if !matches {
            return Err(fail(8, "The requested RNG cannot be provided"));
        }
        attrs.retain(|a| a.tag != RANDOM_NUMBER_GENERATOR);
        attrs.push(actual);
    }
    Ok(())
}
pub(super) fn initialize(obj: &mut Object, v: Version, generated: bool) -> R<()> {
    let fresh = if generated {
        true
    } else {
        attr_flag(&obj.attrs, FRESH, true)?
    };
    obj.attrs
        .retain(|a| !matches!(a.tag, FRESH | ALWAYS_SENSITIVE | NEVER_EXTRACTABLE));
    obj.metadata = ObjectMetadata {
        version: [v.0, v.1],
        origin: if generated {
            MetadataOrigin::Generated
        } else {
            MetadataOrigin::Registered
        },
        fresh: Some(fresh),
        always_sensitive: Some(attr_flag(&obj.attrs, SENSITIVE, false)?),
        never_extractable: Some(!attr_flag(&obj.attrs, EXTRACTABLE, true)?),
    };
    if generated {
        obj.attrs
            .retain(|a| !matches!(a.tag, ORIGINAL_CREATION_DATE | RANDOM_NUMBER_GENERATOR));
        obj.attrs
            .push(Node::date(ORIGINAL_CREATION_DATE, obj.created));
        obj.attrs.push(default_rng());
    }
    Ok(())
}
pub(super) fn hydrate(obj: &mut Object) -> R<()> {
    certificate::hydrate(obj);
    if obj.metadata.origin == MetadataOrigin::Legacy {
        // Extraction flags could not be modified by older writers. For ordinary
        // records their current flags still prove their initial history; imported
        // histories were not recorded, so never assert the stronger true claim.
        obj.metadata
            .always_sensitive
            .get_or_insert(!obj.imported && attr_flag(&obj.attrs, SENSITIVE, false)?);
        obj.metadata
            .never_extractable
            .get_or_insert(!obj.imported && !attr_flag(&obj.attrs, EXTRACTABLE, true)?);
        obj.metadata.fresh.get_or_insert(false);
    }

    Ok(())
}
pub(super) fn project(obj: &Object, v: Version, attrs: &mut Vec<Node>) {
    let legacy = obj.metadata.origin == MetadataOrigin::Legacy;
    let fresh = obj
        .metadata
        .fresh
        .or((legacy || v.0 >= 2 && obj.imported && obj.metadata.version[0] < 2).then_some(false));
    let always_sensitive = obj.metadata.always_sensitive.or_else(|| {
        legacy.then(|| !obj.imported && attr_flag(&obj.attrs, SENSITIVE, false).unwrap_or(false))
    });
    let never_extractable = obj.metadata.never_extractable.or_else(|| {
        legacy.then(|| !obj.imported && !attr_flag(&obj.attrs, EXTRACTABLE, true).unwrap_or(true))
    });
    if v >= Version(1, 1)
        && (v.0 >= 2 || obj.object_type != 8)
        && let Some(value) = fresh
    {
        attrs.push(Node::boolean(FRESH, value));
    }
    if v >= Version(1, 4) {
        if !obj.imported || legacy {
            if !attrs.iter().any(|a| a.tag == SENSITIVE) {
                attrs.push(Node::boolean(SENSITIVE, false));
            }
            if !attrs.iter().any(|a| a.tag == EXTRACTABLE) {
                attrs.push(Node::boolean(EXTRACTABLE, true));
            }
        }
        if let Some(value) = always_sensitive {
            attrs.push(Node::boolean(ALWAYS_SENSITIVE, value));
        }
        if let Some(value) = never_extractable {
            attrs.push(Node::boolean(NEVER_EXTRACTABLE, value));
        }
    }
    // Imports before this was projected in 2.0 did not store a short ID.
    if v.0 >= 2
        && obj.metadata.version < [2, 1]
        && obj.imported
        && !attrs.iter().any(|a| a.tag == SHORT_UNIQUE_IDENTIFIER)
    {
        attrs.push(Node::bytes(
            SHORT_UNIQUE_IDENTIFIER,
            crypto::sha256(obj.id.as_bytes()).to_vec(),
        ));
    }
    if v.0 >= 3
        && obj.imported
        && obj.metadata.version[0] < 3
        && !attrs.iter().any(|a| a.tag == OBJECT_CLASS)
    {
        attrs.push(Node::enumeration(OBJECT_CLASS, 1));
    }
    if v == Version(1, 0) {
        attrs.retain(|a| {
            a.tag != DIGEST
                || a.get(KEY_FORMAT_TYPE)
                    .is_none_or(|f| f.number().ok() == Some(obj.format))
        });
        for a in attrs.iter_mut().filter(|a| a.tag == DIGEST) {
            if let Value::Structure(fields) = &mut a.value {
                fields.retain(|n| n.tag != KEY_FORMAT_TYPE);
            }
        }
    }
    attrs.retain(|a| {
        !(v < Version(1, 1) && a.tag == FRESH
            || v < Version(1, 2) && a.tag == ORIGINAL_CREATION_DATE
            || v < Version(1, 3) && a.tag == RANDOM_NUMBER_GENERATOR
            || v.0 < 2 && a.tag == SHORT_UNIQUE_IDENTIFIER
            || v.0 < 3 && a.tag == OBJECT_CLASS
            || v < Version(1, 4)
                && matches!(
                    a.tag,
                    SENSITIVE | EXTRACTABLE | ALWAYS_SENSITIVE | NEVER_EXTRACTABLE
                ))
    });
}
pub(super) fn validate_restored(metadata: &ObjectMetadata, attrs: &[Node]) -> R<()> {
    if metadata.always_sensitive == Some(true) && !attr_flag(attrs, SENSITIVE, false)?
        || metadata.never_extractable == Some(true) && attr_flag(attrs, EXTRACTABLE, true)?
    {
        return Err(fail(
            7,
            "Imported extraction history contradicts current flags",
        ));
    }
    Ok(())
}
pub(super) fn require_import(
    obj: &Object,
    v: Version,
    attrs: &[Node],
    clear_available: bool,
) -> R<()> {
    let mut required = vec![UNIQUE_IDENTIFIER, OBJECT_TYPE];
    if v >= Version(1, 4) {
        required.extend([SENSITIVE, EXTRACTABLE, ALWAYS_SENSITIVE, NEVER_EXTRACTABLE]);
    }
    if v.0 >= 2 {
        required.push(FRESH);
        if !matches!(obj.object_type, 1 | 8) {
            required.push(KEY_FORMAT_TYPE);
        }
    }
    if v.0 >= 2 {
        required.push(SHORT_UNIQUE_IDENTIFIER);
    }
    if v.0 >= 3 {
        required.push(OBJECT_CLASS);
    }
    if required
        .iter()
        .any(|tag| !attrs.iter().any(|a| a.tag == *tag))
    {
        return Err(fail(6, "Mandatory imported attribute missing"));
    }
    if let Some(short) = attrs.iter().find(|a| a.tag == SHORT_UNIQUE_IDENTIFIER)
        && short.byte_string()?.len() != 32
    {
        return Err(fail(7, "Short Unique Identifier must contain 32 bytes"));
    }
    let digests = attrs.iter().filter(|a| a.tag == DIGEST).collect::<Vec<_>>();
    let default = if v.0 >= 2 {
        default_digest_format(obj)
    } else {
        obj.format
    };
    if (clear_available || !digests.is_empty())
        && !digests.iter().any(|d| {
            d.get(HASHING_ALGORITHM).and_then(|n| n.number().ok()) == Some(SHA256)
                && (matches!(obj.object_type, 1 | 8)
                    || d.get(KEY_FORMAT_TYPE).and_then(|n| n.number().ok()) == Some(default))
        })
    {
        return Err(fail(
            6,
            "Mandatory SHA-256 digest for the required key format missing",
        ));
    }
    Ok(())
}
pub(super) fn verify_digests(obj: &Object) -> R<()> {
    use subtle::ConstantTimeEq;
    if obj.material.is_empty() && !(obj.object_type == 8 && obj.state < 5) {
        return Ok(());
    }
    for digest in obj.attrs.iter().filter(|a| a.tag == DIGEST) {
        let algorithm = digest.required(HASHING_ALGORITHM)?.number()?;
        let actual = openssl::hash::hash(
            crypto::rsa::digest(algorithm).map_err(|_| fail(8, "Unsupported digest algorithm"))?,
            &digest_input(obj, number(digest, KEY_FORMAT_TYPE, obj.format)?)?,
        )
        .map_err(anyhow::Error::from)?;
        if !bool::from(
            actual
                .as_ref()
                .ct_eq(digest.required(DIGEST_VALUE)?.byte_string()?),
        ) {
            return Err(fail(7, "Imported Digest disagrees with object material"));
        }
    }
    Ok(())
}
pub(super) fn before_mutation(
    obj: &mut Object,
    v: Version,
    op: u32,
    tag: u32,
    new: Option<&Node>,
) -> R<()> {
    if matches!(tag, SENSITIVE | EXTRACTABLE) {
        if v < Version(1, 4) || op == 15 {
            return Err(usage::read_only(v));
        }
        let current = attr_flag(&obj.attrs, tag, tag == EXTRACTABLE)?;
        if !obj.attrs.iter().any(|a| a.tag == tag) {
            obj.attrs.push(Node::boolean(tag, current));
        }
        let next = new.ok_or(fail(6, "New extraction flag required"))?.flag()?;
        if v.0 >= 3 && current != next && (tag == SENSITIVE && !next || tag == EXTRACTABLE && next)
        {
            return Err(usage::read_only(v));
        }
    }
    if matches!(tag, ORIGINAL_CREATION_DATE | RANDOM_NUMBER_GENERATOR) {
        if op != 13 && op != 49 || obj.attrs.iter().any(|a| a.tag == tag) {
            return Err(usage::read_only(v));
        }
        let registered = matches!(
            obj.metadata.origin,
            MetadataOrigin::Registered | MetadataOrigin::Imported
        );
        if !registered {
            return Err(usage::read_only(v));
        }
    }
    Ok(())
}
pub(super) fn update_history(obj: &mut Object, tag: u32) -> R<()> {
    if tag == SENSITIVE {
        obj.metadata.always_sensitive = Some(
            obj.metadata.always_sensitive.unwrap_or(false)
                && attr_flag(&obj.attrs, SENSITIVE, false)?,
        );
    }
    if tag == EXTRACTABLE {
        obj.metadata.never_extractable = Some(
            obj.metadata.never_extractable.unwrap_or(false)
                && !attr_flag(&obj.attrs, EXTRACTABLE, true)?,
        );
    }
    Ok(())
}
impl Engine {
    pub(super) fn unique_short_id(&self, obj: &Object, v: Version) -> R<()> {
        if v.0 < 2 {
            return Ok(());
        }
        let Some(short) = obj.attrs.iter().find(|a| a.tag == SHORT_UNIQUE_IDENTIFIER) else {
            return Ok(());
        };
        let short = short.byte_string()?;
        let collision = self.store.any_object(|other| {
            if other.id == obj.id {
                return false;
            }
            let actual = other
                .attrs
                .iter()
                .find(|a| a.tag == SHORT_UNIQUE_IDENTIFIER)
                .and_then(|n| n.byte_string().ok());
            actual
                .map(|value| value == short)
                .unwrap_or_else(|| crypto::sha256(other.id.as_bytes()).as_slice() == short)
        })?;
        if collision {
            return Err(fail(7, "Short Unique Identifier is not unique"));
        }
        Ok(())
    }
    pub(super) fn mark_served(&self, obj: &mut Object) -> R<()> {
        let prior = (
            obj.metadata.always_sensitive,
            obj.metadata.never_extractable,
        );
        if !attr_flag(&obj.attrs, SENSITIVE, false)? {
            obj.metadata.always_sensitive = Some(false);
        }
        if attr_flag(&obj.attrs, EXTRACTABLE, true)? {
            obj.metadata.never_extractable = Some(false);
        }
        if obj.metadata.fresh != Some(false)
            || prior
                != (
                    obj.metadata.always_sensitive,
                    obj.metadata.never_extractable,
                )
        {
            obj.metadata.fresh = Some(false);
            obj.updated = now();
            self.store.put(obj)?;
        }
        Ok(())
    }
}
