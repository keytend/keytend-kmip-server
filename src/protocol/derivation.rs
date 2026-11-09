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

//! Versioned derivation, explicit source binding and atomic reciprocal links.
use super::*;
use crypto::derivation::{self as kdf, CounterLocation, KbkdfParameters, Mode, Prf};
use zeroize::Zeroizing;

fn unsupported(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x3e } else { 8 },
        "Unsupported derivation parameters",
    )
}
fn hash(cp: &Node, default: Option<u32>, v: Version) -> R<u32> {
    no_fields(cp, &[HASHING_ALGORITHM, CRYPTOGRAPHIC_ALGORITHM])?;
    let implied = cp
        .get(CRYPTOGRAPHIC_ALGORITHM)
        .map(|n| match n.number()? {
            algorithm if crypto::authentication::hmac_hash(algorithm).is_some() => {
                mac::validate_key_algorithm(algorithm, v)?;
                Ok(crypto::authentication::hmac_hash(algorithm).unwrap())
            }
            _ => Err(unsupported(v)),
        })
        .transpose()?;
    let hash = cp
        .get(HASHING_ALGORITHM)
        .map(Node::number)
        .transpose()?
        .or(implied)
        .or(default)
        .ok_or(fail(6, "Derivation hash required"))?;
    if implied.is_some_and(|value| value != hash) {
        return Err(fail(7, "Conflicting derivation PRF and hash"));
    }
    if (14..=17).contains(&hash) && v < Version(1, 4) {
        return Err(unsupported(v));
    }
    kdf::digest(hash).map_err(|_| unsupported(v))?;
    Ok(hash)
}
fn prf(key: &Object, cp: &Node, v: Version) -> R<Prf> {
    if key.object_type != 2 {
        return Err(fail(
            if v.0 >= 2 { 0x28 } else { 7 },
            "Symmetric derivation key required",
        ));
    }
    match key.algorithm {
        algorithm if crypto::authentication::hmac_hash(algorithm).is_some() => {
            mac::validate_key_algorithm(algorithm, v)?;
            Ok(Prf::Hmac(
                crypto::authentication::hmac_hash(algorithm).unwrap(),
            ))
        }
        3 => {
            no_fields(cp, &[BLOCK_CIPHER_MODE, CRYPTOGRAPHIC_ALGORITHM])?;
            if number(cp, BLOCK_CIPHER_MODE, 0)? != 7
                || number(cp, CRYPTOGRAPHIC_ALGORITHM, 3)? != 3
            {
                return Err(unsupported(v));
            }
            Ok(Prf::Cmac)
        }
        _ => Err(unsupported(v)),
    }
}
fn data<'a>(objects: &'a [Object], params: &'a Node, required: bool) -> R<&'a [u8]> {
    let secret = objects.iter().find(|o| o.object_type == 7);
    let explicit = params
        .get(DERIVATION_DATA)
        .map(Node::byte_string)
        .transpose()?;
    match (secret, explicit) {
        (Some(_), Some(_)) => Err(fail(7, "Derivation Data conflicts with Secret Data input")),
        (Some(secret), None) => Ok(&secret.material),
        (None, Some(bytes)) => Ok(bytes),
        (None, None) if !required => Ok(&[]),
        _ => Err(fail(6, "Derivation Data required")),
    }
}
impl Engine {
    pub(super) fn prepare_derivation(
        &self,
        owner: &str,
        v: Version,
        item: &Node,
        refs: &identifiers::References,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        let payload = item.required(REQUEST_PAYLOAD)?;
        let mut ids = vec![];
        for n in payload.all(UNIQUE_IDENTIFIER) {
            if matches!(&n.value,Value::TextString(s)|Value::Reference(s)|Value::Identifier(s)|Value::NameReference(s) if s.is_empty())
                || matches!(n.value, Value::Enumeration(1))
            {
                return Err(fail(7, "Derive Key cannot use the ID Placeholder"));
            }
            ids.extend(self.resolve_identifier(owner, v, n, refs, placeholder)?);
            if ids.len() > 2 {
                return Err(fail(
                    2,
                    "At most two sources are supported for these derivation methods",
                ));
            }
        }
        if ids.is_empty() {
            return Err(fail(6, "Derive Key requires explicit source identifiers"));
        }
        if ids.len() == 2 && ids[0] == ids[1] {
            return Err(fail(7, "Duplicate derivation source"));
        }
        let mut normalized = payload.clone();
        if let Value::Structure(fields) = &mut normalized.value {
            fields.retain(|n| n.tag != UNIQUE_IDENTIFIER);
            fields.extend(ids.into_iter().map(|id| Node::text(UNIQUE_IDENTIFIER, id)));
            for field in fields.iter_mut().filter(|n| n.tag == ATTRIBUTES) {
                for a in match &mut field.value {
                    Value::Structure(a) => a,
                    _ => return Err(fail(7, "Attributes must be a Structure")),
                } {
                    *a = self.normalize_attribute(owner, v, a.clone(), refs, placeholder)?;
                }
            }
        }
        let mut request = item.clone();
        if let Value::Structure(fields) = &mut request.value {
            *fields
                .iter_mut()
                .find(|n| n.tag == REQUEST_PAYLOAD)
                .expect("required payload") = normalized;
        }
        Ok(vec![request])
    }
    pub(super) fn derive_key(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let allowed = [
            OBJECT_TYPE,
            UNIQUE_IDENTIFIER,
            DERIVATION_METHOD,
            DERIVATION_PARAMETERS,
            TEMPLATE_ATTRIBUTE,
            ATTRIBUTES,
            PROTECTION_STORAGE_MASKS,
        ];
        if p.children()?.iter().any(|n| !allowed.contains(&n.tag)) {
            return Err(fail(8, "Unsupported Derive Key field"));
        }
        for tag in allowed.into_iter().filter(|t| *t != UNIQUE_IDENTIFIER) {
            if p.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate Derive Key field"));
            }
        }
        let protection_mask = protection::derive(p, v)?;
        let kind = p.required(OBJECT_TYPE)?.number()?;
        if ![2, 7].contains(&kind) {
            return Err(fail(
                if v.0 >= 2 { 0x28 } else { 7 },
                "Only Symmetric Key and Secret Data may be derived",
            ));
        }
        let method = match p.required(DERIVATION_METHOD)?.value {
            Value::Enumeration(m) => m,
            _ => return Err(fail(7, "Derivation Method must be an Enumeration")),
        };
        if method == 8 {
            return Err(fail(8, "Asymmetric key agreement is not implemented"));
        }
        if !(1..=10).contains(&method) || method >= 9 && v < Version(2, 0) {
            return Err(unsupported(v));
        }
        fips_policy::derivation_method(method, v)?;
        let params = p.required(DERIVATION_PARAMETERS)?;
        let fields = [
            CRYPTOGRAPHIC_PARAMETERS,
            INITIALIZATION_VECTOR,
            DERIVATION_DATA,
            SALT,
            ITERATION_COUNT,
        ];
        if params.children()?.iter().any(|n| !fields.contains(&n.tag)) {
            return Err(unsupported(v));
        }
        for tag in fields {
            if params.all(tag).count() > 1
                && !(tag == DERIVATION_DATA && method == 9 && v >= Version(2, 0))
            {
                return Err(fail(7, "Duplicate derivation parameter"));
            }
        }
        let iv = params
            .get(INITIALIZATION_VECTOR)
            .map(Node::byte_string)
            .transpose()?
            .unwrap_or(&[]);
        if ![4, 6].contains(&method) && params.get(INITIALIZATION_VECTOR).is_some() {
            return Err(fail(7, "This derivation method does not use an IV"));
        }
        if method != 1 && params.get(ITERATION_COUNT).is_some()
            || ![1, 10].contains(&method) && params.get(SALT).is_some()
        {
            return Err(fail(7, "Unexpected salt or iteration count"));
        }
        p.required(if v.0 == 1 {
            TEMPLATE_ATTRIBUTE
        } else {
            ATTRIBUTES
        })?;
        let mut attrs = read_attrs(p, v)?;
        let formats = attrs
            .iter()
            .filter(|a| a.tag == KEY_FORMAT_TYPE)
            .collect::<Vec<_>>();
        if formats.len() > 1 || !formats.is_empty() && v.0 < 2 {
            return Err(fail(7, "Invalid derivation key format attribute"));
        }
        let format = formats
            .first()
            .map(|n| n.number())
            .transpose()?
            .unwrap_or(1);
        attrs.retain(|a| a.tag != KEY_FORMAT_TYPE);
        metadata::prepare(&mut attrs, v, true)?;
        validate_attrs(&attrs, v)?;
        if !attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH)
            || kind == 2 && !attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM)
        {
            return Err(fail(
                6,
                "Explicit derived length and symmetric algorithm required",
            ));
        }
        if attrs
            .iter()
            .any(|a| matches!(link_kind(a), Some(0x104 | 0x105)))
        {
            return Err(fail(7, "Derivation links are assigned by the server"));
        }
        let bits = attr_num(&attrs, CRYPTOGRAPHIC_LENGTH, 0)?;
        if bits == 0 || !bits.is_multiple_of(8) || bits as usize / 8 > kdf::MAX_OUTPUT {
            return Err(fail(7, "Unsupported derived length"));
        }
        let length = (bits / 8) as usize;
        let algorithm = attr_num(&attrs, CRYPTOGRAPHIC_ALGORITHM, 0)?;
        if kind == 2 {
            validate_symmetric_parameters(algorithm, bits, v)?;
        }
        if !(kind == 2 && [1, 7].contains(&format) || kind == 7 && [1, 2].contains(&format)) {
            return Err(fail(0x10, "Unsupported derived format"));
        }
        let mut objects = vec![];
        for n in p.all(UNIQUE_IDENTIFIER) {
            let mut obj = self.object(
                owner,
                &Node::structure(REQUEST_PAYLOAD, vec![n.clone()]),
                &None,
            )?;
            if ![2, 7].contains(&obj.object_type) {
                return Err(fail(
                    if v.0 >= 2 { 0x28 } else { 7 },
                    "Unsupported derivation input object",
                ));
            }
            self.materialize(owner, &mut obj)?;
            // 1.x Derive Key table (1.4 Table 333): "One or more of the
            // specified objects are not able to be used to derive a new
            // key": Invalid Field.
            check_use(&obj, v, 512, true).map_err(|e| {
                if v.0 == 1 && e.reason == 12 {
                    fail(7, "Source object cannot be used to derive a key")
                } else {
                    e
                }
            })?;
            objects.push(obj);
        }
        if objects.is_empty()
            || objects.len() > 2
            || objects.len() == 2 && objects[0].object_type == objects[1].object_type
        {
            return Err(fail(7, "Invalid derivation source combination"));
        }
        let empty_cp = Node::structure(CRYPTOGRAPHIC_PARAMETERS, vec![]);
        let key = objects.iter().find(|o| o.object_type == 2);
        let stored =
            if let Some(key) = key.filter(|_| v.0 == 1 && [2, 4, 5, 6, 7].contains(&method)) {
                attributes::first_instance(key, CRYPTOGRAPHIC_PARAMETERS)?
            } else {
                None
            };
        let cp = params
            .get(CRYPTOGRAPHIC_PARAMETERS)
            .or(stored.as_ref())
            .unwrap_or(&empty_cp);
        cp.children()?;
        // HMAC keys name their PRF; Cryptographic Parameters are ignored.
        if !(method == 3
            || [5, 6, 7].contains(&method)
                && key.is_some_and(|k| crypto::authentication::hmac_hash(k.algorithm).is_some()))
        {
            validate_cryptographic_parameters(cp, v)?;
        }
        for n in params.children()? {
            if matches!(n.tag, DERIVATION_DATA | SALT) && n.byte_string()?.len() > kdf::MAX_OUTPUT {
                return Err(fail(2, "Derivation input exceeds storage limit"));
            }
        }
        if v.0 == 1
            && [4, 5, 6, 7].contains(&method)
            && params.get(CRYPTOGRAPHIC_PARAMETERS).is_some()
            && let Some(mode) = cp.get(BLOCK_CIPHER_MODE)
        {
            let key = key.ok_or(fail(6, "Derivation key required"))?;
            if !key
                .attrs
                .iter()
                .filter(|a| a.tag == CRYPTOGRAPHIC_PARAMETERS)
                .any(|a| a.get(BLOCK_CIPHER_MODE) == Some(mode))
            {
                return Err(fail(7, "Derivation mode does not match stored parameters"));
            }
        }
        let failure = || fail(10, "Key derivation failed");
        let material: Zeroizing<Vec<u8>> = match method {
            1 => {
                if objects.len() != 1 || params.get(DERIVATION_DATA).is_some() {
                    return Err(fail(
                        7,
                        "PBKDF2 requires one managed password source without redundant Derivation Data",
                    ));
                }
                let hash = hash(cp, Some(4), v)?;
                let salt = params.required(SALT)?.byte_string()?;
                let count = match params.required(ITERATION_COUNT)?.value {
                    Value::Integer(i) if i > 0 => i as usize,
                    _ => return Err(fail(7, "Iteration Count must be positive")),
                };
                fips_policy::pbkdf2(objects[0].material.len(), salt.len(), count, length, v)?;
                if count
                    > kdf::MAX_WORK
                        / length.div_ceil(kdf::digest(hash).map_err(|_| unsupported(v))?.size())
                {
                    return Err(fail(2, "PBKDF2 work limit exceeded"));
                }
                kdf::pbkdf2(hash, &objects[0].material, salt, count, length)
                    .map_err(|_| failure())?
            }
            2 => {
                let bytes = if let Some(key) = key {
                    if objects.len() != 1 || params.get(DERIVATION_DATA).is_some() {
                        return Err(fail(
                            7,
                            "HASH requires either key material or derivation data",
                        ));
                    }
                    &key.material[..]
                } else {
                    data(&objects, params, true)?
                };
                let hash = hash(cp, None, v)?;
                if length > kdf::digest(hash).map_err(|_| unsupported(v))?.size() {
                    return Err(fail(7, "Requested key exceeds hash output"));
                }
                kdf::hash(hash, bytes, length).map_err(|_| failure())?
            }
            3 => {
                let key = key.ok_or(fail(6, "HMAC derivation key missing"))?;
                let hash = crypto::authentication::hmac_hash(key.algorithm)
                    .ok_or_else(|| unsupported(v))?;
                mac::validate_key_algorithm(key.algorithm, v)?;
                let prf = Prf::Hmac(hash);
                let mut output = prf
                    .compute(&key.material, data(&objects, params, true)?)
                    .map_err(|_| failure())?;
                if length > output.len() {
                    return Err(fail(7, "Requested key exceeds HMAC output"));
                }
                output.truncate(length);
                output
            }
            4 => {
                let key = key.ok_or(fail(6, "Encryption derivation key missing"))?;
                if key.algorithm != 3 {
                    return Err(unsupported(v));
                }
                no_fields(
                    cp,
                    &[BLOCK_CIPHER_MODE, PADDING_METHOD, CRYPTOGRAPHIC_ALGORITHM],
                )?;
                if number(cp, CRYPTOGRAPHIC_ALGORITHM, 3)? != 3 {
                    return Err(unsupported(v));
                }
                let mode = number(cp, BLOCK_CIPHER_MODE, 0)?;
                if ![1, 2, 4, 5, 6].contains(&mode) {
                    return Err(unsupported(v));
                }
                let padding = number(cp, PADDING_METHOD, 1)?;
                let (mut output, _) = crypto::aes(
                    true,
                    &key.material,
                    crypto::AesParameters {
                        mode,
                        padding,
                        tag_len: 16,
                    },
                    iv,
                    data(&objects, params, true)?,
                    &[],
                    None,
                )
                .map_err(|_| failure())?;
                if length > output.len() {
                    return Err(fail(7, "Requested key exceeds encrypted data"));
                }
                output.truncate(length);
                output
            }
            5..=7 => {
                let key = key.ok_or(fail(6, "KDF derivation key missing"))?;
                let prf = prf(key, cp, v)?;
                let mut fixed = Zeroizing::new(data(&objects, params, true)?.to_vec());
                fixed.extend_from_slice(&bits.to_be_bytes());
                let blocks = length.div_ceil(prf.output_len().map_err(|_| unsupported(v))?);
                if blocks
                    .saturating_mul(fixed.len().div_ceil(64) + 4)
                    .saturating_mul(2)
                    > kdf::MAX_WORK
                {
                    return Err(fail(2, "KDF work limit exceeded"));
                }
                let mode = match method {
                    5 => Mode::Counter,
                    6 => Mode::Feedback,
                    _ => Mode::DoublePipeline,
                };
                if !iv.is_empty() && iv.len() != prf.output_len().map_err(|_| unsupported(v))? {
                    return Err(fail(7, "Invalid KDF feedback IV"));
                }
                kdf::sp800108(
                    &key.material,
                    KbkdfParameters {
                        mode,
                        prf,
                        fixed: &fixed,
                        iv,
                        counter_bytes: 4,
                        counter_location: CounterLocation::AfterIteration,
                    },
                    length,
                )
                .map_err(|_| failure())?
            }
            9 => {
                if objects.len() != 1 {
                    return Err(fail(7, "AWS derivation requires one source"));
                }
                let values = params
                    .all(DERIVATION_DATA)
                    .map(Node::byte_string)
                    .collect::<Result<Vec<_>, _>>()?;
                if values.len() != 3 || values.iter().any(|v| v.is_empty()) {
                    return Err(fail(
                        7,
                        "AWS derivation needs Date, Region and Service in order",
                    ));
                }
                if values[0].len() != 8
                    || !values[0].iter().all(u8::is_ascii_digit)
                    || values[1..]
                        .iter()
                        .any(|v| v.len() > 128 || std::str::from_utf8(v).is_err())
                {
                    return Err(fail(7, "Invalid AWS Date, Region or Service"));
                }
                if !cp.children()?.is_empty() && hash(cp, Some(6), v)? != 6 {
                    return Err(unsupported(v));
                }
                if length > 32 {
                    return Err(fail(7, "AWS signing key has only 256 bits"));
                }
                kdf::aws_v4(
                    &objects[0].material,
                    values[0],
                    values[1],
                    values[2],
                    length,
                )
                .map_err(|_| failure())?
            }
            10 => {
                if objects.len() != 1 {
                    return Err(fail(7, "HKDF requires one input key material object"));
                }
                let hash = hash(cp, Some(6), v)?;
                if length > 255 * kdf::digest(hash).map_err(|_| unsupported(v))?.size() {
                    return Err(fail(7, "HKDF output exceeds 255 hash blocks"));
                }
                fips_policy::hkdf(objects[0].material.len(), v)?;
                kdf::hkdf(
                    hash,
                    &objects[0].material,
                    params
                        .get(SALT)
                        .map(Node::byte_string)
                        .transpose()?
                        .unwrap_or(&[]),
                    params
                        .get(DERIVATION_DATA)
                        .map(Node::byte_string)
                        .transpose()?
                        .unwrap_or(&[]),
                    length,
                )
                .map_err(|_| failure())?
            }
            _ => return Err(unsupported(v)),
        };
        let km = if format == 7 {
            Node::structure(KEY_MATERIAL, vec![Node::bytes(KEY, material.to_vec())])
        } else {
            Node::bytes(KEY_MATERIAL, material.to_vec())
        };
        let mut kb = vec![
            Node::enumeration(KEY_FORMAT_TYPE, format),
            Node::structure(KEY_VALUE, vec![km]),
            Node::int(CRYPTOGRAPHIC_LENGTH, bits as i32),
        ];
        if algorithm != 0 {
            kb.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
        }
        let mut value = vec![];
        if kind == 7 {
            value.push(Node::enumeration(SECRET_DATA_TYPE, 2));
        }
        value.push(Node::structure(KEY_BLOCK, kb));
        let attrs = if v.0 == 1 {
            Node::structure(
                TEMPLATE_ATTRIBUTE,
                attrs.iter().map(encode_attribute).collect::<R<_>>()?,
            )
        } else {
            Node::structure(ATTRIBUTES, attrs)
        };
        let request = Node::structure(
            REQUEST_PAYLOAD,
            vec![
                Node::enumeration(OBJECT_TYPE, kind),
                attrs,
                Node::structure(object_tag(kind)?, value),
            ],
        );
        let mut obj = self.build_object(owner, v, &request, true)?;
        obj.protection_mask = protection_mask;
        metadata::initialize(&mut obj, v, true)?;
        attributes::limits(&obj.attrs)?;
        for source in &mut objects {
            // Charge each input's lifetime derivation authority by output bytes
            // or one new object; repeated PRF rounds do not count as new objects.
            self.consume_protection(source, length, v, if v.0 >= 2 { 0x1a } else { 12 })?;
            attributes::append(source, object_link(0x105, &obj.id))?;
            attributes::append(&mut obj, object_link(0x104, &source.id))?;
            self.store.put(source)?;
        }
        self.unique_names(&obj, v)?;
        super::quantum::check(&obj)?;
        self.store.insert(&obj)?;
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
}
