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

//! Transactional symmetric and RSA pair replacement, dates and retained history.
use super::*;

pub(super) fn generate_pair(
    private: &[Node],
    public: &[Node],
    v: Version,
) -> R<(openssl::pkey::PKey<openssl::pkey::Private>, u32, u32)> {
    let algorithm = attr_num(
        private,
        CRYPTOGRAPHIC_ALGORITHM,
        attr_num(public, CRYPTOGRAPHIC_ALGORITHM, 4)?,
    )?;
    if attr_num(public, CRYPTOGRAPHIC_ALGORITHM, algorithm)? != algorithm {
        return Err(fail(7, "Private and public key algorithms conflict"));
    }
    if ec::algorithm(algorithm) {
        ec::validate_algorithm(algorithm, v)?;
        let private_curve = ec::requested_curve(private)?;
        let public_curve = ec::requested_curve(public)?;
        if matches!((private_curve,public_curve),(Some(a),Some(b)) if a!=b) {
            return Err(fail(7, "Private and public curves conflict"));
        }
        let specified_bits = attr_num(
            private,
            CRYPTOGRAPHIC_LENGTH,
            attr_num(public, CRYPTOGRAPHIC_LENGTH, 0)?,
        )?;
        // The length selects a curve only when no curve is named; a named
        // curve is checked against the length below (brainpoolP320 and
        // brainpoolP512 have lengths with no default curve).
        let curve = match private_curve.or(public_curve) {
            Some(curve) => curve,
            None => match specified_bits {
                0 | 256 => 7,
                192 => 1,
                224 => 4,
                384 => 10,
                521 => 13,
                _ => return Err(fail(7, "EC curve is required for this length")),
            },
        };
        let bits = ec::curve(curve, v)?.degree();
        for attrs in [private, public] {
            if attr_num(attrs, CRYPTOGRAPHIC_LENGTH, bits)? != bits {
                return Err(fail(7, "EC curve and key length conflict"));
            }
        }
        let key = crypto::ec::generate(curve).map_err(|_| fail(10, "EC generation failed"))?;
        return Ok((key, bits, algorithm));
    }
    if private
        .iter()
        .chain(public)
        .any(|a| a.tag == CRYPTOGRAPHIC_DOMAIN_PARAMETERS)
    {
        return Err(fail(7, "RSA does not accept EC domain parameters"));
    }
    if algorithm != 4 {
        return Err(fail(8, "Only RSA key pair generation is supported"));
    }
    let bits = attr_num(
        private,
        CRYPTOGRAPHIC_LENGTH,
        attr_num(public, CRYPTOGRAPHIC_LENGTH, 2048)?,
    )?;
    if attr_num(public, CRYPTOGRAPHIC_LENGTH, bits)? != bits {
        return Err(fail(7, "Private and public key lengths conflict"));
    }
    if ![2048, 3072, 4096].contains(&bits) {
        return Err(fail(7, "RSA must be 2048, 3072 or 4096 bits"));
    }
    let key = crypto::rsa::generate(bits).map_err(|_| fail(10, "RSA key generation failed"))?;
    Ok((key, bits, algorithm))
}
pub(super) fn offset(p: &Node) -> R<Option<i64>> {
    p.get(OFFSET)
        .map(|n| match n.value {
            Value::Interval(value) => Ok(i64::from(value)),
            _ => Err(fail(7, "Offset must be an Interval")),
        })
        .transpose()
}
pub(super) fn eligible(old: &Object, v: Version) -> R<()> {
    if old.state >= 5 {
        // 1.2-1.4 Re-key and Re-key Key Pair tables (1.4 Tables 331, 332):
        // "The Key Value is not present on the server": Key Value Not
        // Present. A destroyed key has no Key Value.
        return Err(fail(
            if v.0 == 1 && v >= Version(1, 2) {
                0x13
            } else {
                12
            },
            "Destroyed keys cannot be replaced",
        ));
    }
    if old.replacement_id.is_some() || old.attrs.iter().any(|a| link_kind(a) == Some(0x106)) {
        return Err(fail(12, "This key already has a replacement"));
    }
    if old.material.is_empty() {
        return Err(fail(
            if v >= Version(1, 2) { 0x13 } else { 12 },
            "Key value is not present",
        ));
    }
    Ok(())
}
pub(super) fn replacement(
    old: &Object,
    mut overrides: Vec<Node>,
    v: Version,
    time: i64,
    offset: Option<i64>,
    dates: &[u32],
    lease: u32,
) -> R<Object> {
    eligible(old, v)?;
    metadata::prepare(&mut overrides, v, true)?;
    validate_attrs(&overrides, v)?;
    let reserved = if old.object_type == 2 {
        &[0x106, 0x107][..]
    } else {
        &[0x102, 0x103, 0x106, 0x107][..]
    };
    if overrides
        .iter()
        .any(|a| link_kind(a).is_some_and(|kind| reserved.contains(&kind)))
    {
        return Err(fail(7, "Replacement links are assigned by the server"));
    }
    if offset.is_some() && overrides.iter().any(|a| dates.contains(&a.tag)) {
        return Err(fail(
            4,
            "Offset and explicit lifecycle dates cannot be combined",
        ));
    }
    let attrs = old
        .attrs
        .iter()
        .filter(|a| {
            ![
                COMPROMISE_DATE,
                COMPROMISE_OCCURRENCE_DATE,
                DESTROY_DATE,
                REVOCATION_REASON,
                LINK,
                DIGEST,
                LEASE_TIME,
                RANDOM_NUMBER_GENERATOR,
                ORIGINAL_CREATION_DATE,
                SHORT_UNIQUE_IDENTIFIER,
                OBJECT_CLASS,
            ]
            .contains(&a.tag)
        })
        .cloned()
        .collect();
    let mut obj = old.clone();
    obj.id = crypto::uuid();
    obj.created = time;
    obj.updated = time;
    obj.state = 1;
    obj.usage_consumed = false;
    obj.replacement_id = None;
    obj.wrapped = None;
    obj.imported = false;
    obj.attrs = attributes::merge(attrs, overrides)?;
    obj.attribute_indices.clear();
    obj.material.zeroize();
    obj.material.clear();
    if let Some(offset) = offset {
        let activation = time
            .checked_add(offset)
            .ok_or(fail(7, "Activation Date overflow"))?;
        let prior = attr_time(&old.attrs, ACTIVATION_DATE);
        if prior.is_none()
            && dates[1..]
                .iter()
                .any(|tag| attr_time(&old.attrs, *tag).is_some())
        {
            return Err(fail(
                0xb,
                "Offset requires the existing Activation Date to shift other dates",
            ));
        }
        obj.attrs.retain(|a| !dates.contains(&a.tag));
        obj.attrs.push(Node::date(ACTIVATION_DATE, activation));
        if let Some(prior) = prior {
            let delta = activation
                .checked_sub(prior)
                .ok_or(fail(7, "Date offset overflow"))?;
            for tag in &dates[1..] {
                if let Some(value) = attr_time(&old.attrs, *tag) {
                    let value = value
                        .checked_add(delta)
                        .ok_or(fail(7, "Shifted date overflow"))?;
                    obj.attrs.push(Node::date(*tag, value));
                }
            }
        }
    }
    validate_attrs(&obj.attrs, v)?;
    obj.algorithm = attr_num(&obj.attrs, CRYPTOGRAPHIC_ALGORITHM, old.algorithm)?;
    obj.bits = attr_num(&obj.attrs, CRYPTOGRAPHIC_LENGTH, old.bits)?;
    obj.usage = attr_num(&obj.attrs, CRYPTOGRAPHIC_USAGE_MASK, old.usage)?;
    metadata::initialize(&mut obj, v, true)?;
    usage::initialize(&mut obj, lease)?;
    Ok(obj)
}
pub(super) fn finish(old: &mut Object, obj: &mut Object) -> R<()> {
    add_digest(obj)?;
    attributes::append(obj, object_link(0x107, &old.id))?;
    apply_dates(obj);
    old.attrs.retain(|a| a.tag != NAME);
    old.attribute_indices.remove(&format!("s:{NAME:06x}"));
    old.replacement_id = Some(obj.id.clone());
    attributes::append(old, object_link(0x106, &obj.id))?;
    old.updated = obj.created;
    Ok(())
}
impl Engine {
    pub(super) fn rekey(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                OFFSET,
                TEMPLATE_ATTRIBUTE,
                ATTRIBUTES,
                PROTECTION_STORAGE_MASKS,
            ],
        )?;
        let protection_mask = protection::select(p, v)?;
        let mut old = self.object(owner, p, placeholder)?;
        self.materialize(owner, &mut old)?;
        if old.object_type != 2 {
            return Err(fail(12, "Re-key requires a retained symmetric key"));
        }
        let mut obj = replacement(
            &old,
            read_attrs(p, v)?,
            v,
            now(),
            offset(p)?,
            &[
                ACTIVATION_DATE,
                PROCESS_START_DATE,
                PROTECT_STOP_DATE,
                DEACTIVATION_DATE,
            ],
            self.maximum_lease,
        )?;
        obj.protection_mask = protection_mask;
        obj.material = if obj.algorithm == tdea::ALGORITHM {
            tdea::generate(self.triple_des, obj.bits)?
        } else {
            validate_symmetric_parameters(obj.algorithm, obj.bits, v)?;
            fips_policy::generated_symmetric(obj.algorithm, obj.bits)?;
            crypto::random((obj.bits / 8) as usize)?.to_vec()
        };
        finish(&mut old, &mut obj)?;
        self.store.put(&old)?;
        self.unique_names(&obj, v)?;
        self.store.insert(&obj)?;
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    pub(super) fn linked_key(
        &self,
        owner: &str,
        v: Version,
        object: &Object,
        kind: u32,
    ) -> R<Object> {
        let links = object
            .attrs
            .iter()
            .filter(|a| link_kind(a) == Some(kind))
            .collect::<Vec<_>>();
        if links.len() != 1 {
            return Err(fail(12, "A key pair requires one unambiguous peer link"));
        }
        let target = links[0].required(LINKED_OBJECT_IDENTIFIER)?;
        let target = match &target.value {
            Value::TextString(value) if v.0 >= 3 => Node::reference(UNIQUE_IDENTIFIER, value),
            _ => target.clone(),
        };
        let ids = self.resolve_identifier(
            owner,
            v,
            &target,
            &identifiers::References::default(),
            &None,
        )?;
        if ids.len() != 1 {
            return Err(fail(12, "A key pair requires one peer object"));
        }
        self.object(
            owner,
            &Node::structure(
                REQUEST_PAYLOAD,
                vec![Node::text(UNIQUE_IDENTIFIER, &ids[0])],
            ),
            &None,
        )
    }
    pub(super) fn rekey_pair(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let id_tag = identifiers::request_identifier_tag(v, 29);
        no_fields(
            p,
            &[
                id_tag,
                OFFSET,
                COMMON_TEMPLATE_ATTRIBUTE,
                PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                COMMON_ATTRIBUTES,
                PRIVATE_KEY_ATTRIBUTES,
                PUBLIC_KEY_ATTRIBUTES,
                COMMON_PROTECTION_STORAGE_MASKS,
                PRIVATE_PROTECTION_STORAGE_MASKS,
                PUBLIC_PROTECTION_STORAGE_MASKS,
            ],
        )?;
        let (private_mask, public_mask) = protection::pair(p, v)?;
        let id = p.get(id_tag).map(|n| {
            let mut n = n.clone();
            n.tag = UNIQUE_IDENTIFIER;
            n
        });
        let mut private = self.object(
            owner,
            &Node::structure(REQUEST_PAYLOAD, id.into_iter().collect()),
            placeholder,
        )?;
        let specified_public = if v.0 >= 3 && private.object_type == 3 {
            let public_id = private.id.clone();
            private = self.linked_key(owner, v, &private, 0x103)?;
            Some(public_id)
        } else {
            None
        };
        let pq = super::pqc::key(&private);
        if private.object_type != 4
            || !(private.algorithm == 4 || ec::algorithm(private.algorithm) || pq)
        {
            return Err(fail(
                12,
                "Re-key Key Pair requires an RSA, EC or post-quantum private key",
            ));
        }
        let mut public = self.linked_key(owner, v, &private, 0x102)?;
        // Post-quantum keys of one pair have different lengths (draft 3.0
        // Table 285).
        if public.object_type != 3
            || public.algorithm != private.algorithm
            || !pq && public.bits != private.bits
            || specified_public.is_some_and(|id| id != public.id)
            || self.linked_key(owner, v, &public, 0x103)?.id != private.id
        {
            return Err(fail(12, "Key pair links are not reciprocal"));
        }
        self.materialize(owner, &mut private)?;
        self.materialize(owner, &mut public)?;
        eligible(&private, v)?;
        eligible(&public, v)?;
        if private.algorithm == 4
            && (!transparent::format_allowed(4, 4, private.format)
                || !transparent::format_allowed(3, 4, public.format))
        {
            return Err(fail(8, "Unsupported RSA pair formats"));
        }
        // Mutable relationship metadata cannot make unrelated material into a pair.
        if pq {
            super::pqc::check_pair(&private, &public, v)?;
            return self.rekey_pq_pair(
                v,
                p,
                placeholder,
                private,
                public,
                (private_mask, public_mask),
            );
        }
        let old_private = openssl::pkey::PKey::private_key_from_der(&private.material)
            .map_err(|_| fail(7, "Invalid RSA private key"))?;
        let public_der = if ec::algorithm(public.algorithm) {
            zeroize::Zeroizing::new(public.material.clone())
        } else {
            crypto::rsa::export(&public.material, false, 5)
                .map_err(|_| fail(7, "Invalid RSA public key"))?
        };
        let old_public = openssl::pkey::PKey::public_key_from_der(&public_der)
            .map_err(|_| fail(7, "Invalid RSA public key"))?;
        let expected = if ec::algorithm(private.algorithm) {
            openssl::pkey::Id::EC
        } else {
            openssl::pkey::Id::RSA
        };
        if old_private.id() != expected
            || old_public.id() != expected
            || !old_private.public_eq(&old_public)
            || old_private.bits() != private.bits
        {
            return Err(fail(12, "Stored keys are not the same mathematical pair"));
        }
        let common = read_attrs_at(p, v, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES)?;
        let mut private_attrs = attributes::pair_union(
            common.clone(),
            read_attrs_at(p, v, PRIVATE_KEY_TEMPLATE_ATTRIBUTE, PRIVATE_KEY_ATTRIBUTES)?,
        )?;
        let mut public_attrs = attributes::pair_union(
            common,
            read_attrs_at(p, v, PUBLIC_KEY_TEMPLATE_ATTRIBUTE, PUBLIC_KEY_ATTRIBUTES)?,
        )?;
        let private_format = ec::take_format(&mut private_attrs, v)?;
        let public_format = ec::take_format(&mut public_attrs, v)?;
        let prior_curve = if ec::algorithm(private.algorithm) {
            ec::stored_curve(&private, v)?;
            Some(crypto::ec::info(&private.material, true)?.0)
        } else {
            None
        };
        let time = now();
        let offset = offset(p)?;
        let mut next_private = replacement(
            &private,
            private_attrs,
            v,
            time,
            offset,
            &[ACTIVATION_DATE, DEACTIVATION_DATE],
            self.maximum_lease,
        )?;
        let mut next_public = replacement(
            &public,
            public_attrs,
            v,
            time,
            offset,
            &[ACTIVATION_DATE, DEACTIVATION_DATE],
            self.maximum_lease,
        )?;
        next_private.protection_mask = private_mask;
        next_public.protection_mask = public_mask;
        next_private.format = private_format.unwrap_or(private.format);
        next_public.format = public_format.unwrap_or(public.format);
        let parameters = |object: &Object| {
            let mut parameters = vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, object.algorithm),
                Node::int(CRYPTOGRAPHIC_LENGTH, object.bits as i32),
            ];
            if let Some(domain) = object
                .attrs
                .iter()
                .find(|a| a.tag == CRYPTOGRAPHIC_DOMAIN_PARAMETERS)
            {
                parameters.push(domain.clone());
            } else if ec::algorithm(object.algorithm)
                && let Some(curve) = prior_curve
            {
                parameters.push(Node::structure(
                    CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                    vec![Node::enumeration(RECOMMENDED_CURVE, curve)],
                ));
            }
            parameters
        };
        let (key, bits, algorithm) =
            generate_pair(&parameters(&next_private), &parameters(&next_public), v)?;
        for obj in [&mut next_private, &mut next_public] {
            obj.bits = bits;
            obj.algorithm = algorithm;
            if ec::algorithm(algorithm) {
                if !ec::format_allowed(obj.object_type, algorithm, obj.format, v) {
                    return Err(fail(0x10, "Unsupported replacement EC format"));
                }
                obj.material = if obj.object_type == 4 {
                    if obj.format == 6 {
                        key.ec_key()?.private_key_to_der()?
                    } else {
                        key.private_key_to_pkcs8()?
                    }
                } else {
                    key.public_key_to_der()?
                };
            } else {
                obj.material = if obj.object_type == 4 {
                    match obj.format {
                        3 | transparent::RSA_PRIVATE => key.rsa()?.private_key_to_der()?,
                        4 => key.private_key_to_pkcs8()?,
                        _ => return Err(fail(0x10, "Unsupported RSA private format")),
                    }
                } else {
                    match obj.format {
                        3 | transparent::RSA_PUBLIC => key.rsa()?.public_key_to_der_pkcs1()?,
                        5 => key.public_key_to_der()?,
                        _ => return Err(fail(0x10, "Unsupported RSA public format")),
                    }
                };
            }
        }
        attributes::append(&mut next_private, object_link(0x102, &next_public.id))?;
        attributes::append(&mut next_public, object_link(0x103, &next_private.id))?;
        finish(&mut private, &mut next_private)?;
        finish(&mut public, &mut next_public)?;
        // Release both old names before checking either replacement; all four
        // records and audit share the caller's savepoint and response-size gate.
        self.store.put(&private)?;
        self.store.put(&public)?;
        for object in [&next_private, &next_public] {
            self.unique_names(object, v)?;
            self.store.insert(object)?;
        }
        *placeholder = Some(next_private.id.clone());
        Ok(vec![
            Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, &next_private.id),
            Node::text(PUBLIC_KEY_UNIQUE_IDENTIFIER, &next_public.id),
        ])
    }
}
