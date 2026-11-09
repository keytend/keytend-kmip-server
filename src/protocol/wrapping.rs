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

//! Protected key transfer with explicit algorithms, ownership and transaction accounting.
use super::*;
use zeroize::Zeroizing;

fn encoding(n: &Node, v: Version) -> R<u32> {
    if v == Version(1, 0) && n.get(ENCODING_OPTION).is_some() {
        return Err(fail(7, "Encoding Option requires KMIP 1.1"));
    }
    match n.get(ENCODING_OPTION).map(|n| &n.value) {
        None => Ok(2),
        Some(Value::Enumeration(value @ (1 | 2))) => Ok(*value),
        _ => Err(fail(7, "Invalid Encoding Option")),
    }
}
fn encrypt_only(n: &Node) -> R<()> {
    if !matches!(n.required(WRAPPING_METHOD)?.value, Value::Enumeration(1)) {
        return Err(fail(8, "Only Encrypt wrapping is implemented"));
    }
    if n.get(MAC_SIGNATURE_KEY_INFORMATION).is_some() || n.get(MAC_SIGNATURE).is_some() {
        return Err(fail(
            7,
            "Encrypt wrapping does not accept MAC/signature fields",
        ));
    }
    Ok(())
}
fn same_parameters(a: &Node, b: &Node) -> bool {
    match (a.children(), b.children()) {
        (Ok(a), Ok(b)) => a.len() == b.len() && a.iter().all(|n| b.contains(n)),
        _ => false,
    }
}
fn aes_parameters(cp: &Node) -> R<bool> {
    no_fields(
        cp,
        &[CRYPTOGRAPHIC_ALGORITHM, BLOCK_CIPHER_MODE, PADDING_METHOD],
    )?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, 3)? != 3 || number(cp, PADDING_METHOD, 1)? != 1 {
        return Err(fail(8, "Unsupported AES wrapping parameters"));
    }
    match cp.required(BLOCK_CIPHER_MODE)?.number()? {
        12 => Ok(true),
        13 => Ok(false),
        _ => Err(fail(8, "Unsupported AES wrapping mode")),
    }
}
fn oaep_parameters(cp: &Node, v: Version) -> R<crypto::rsa::OaepParameters<'_>> {
    no_fields(
        cp,
        &[
            CRYPTOGRAPHIC_ALGORITHM,
            PADDING_METHOD,
            HASHING_ALGORITHM,
            MASK_GENERATOR,
            MASK_GENERATOR_HASHING_ALGORITHM,
            P_SOURCE,
        ],
    )?;
    validate_cryptographic_parameters(cp, v)?;
    if number(cp, CRYPTOGRAPHIC_ALGORITHM, 4)? != 4
        || number(cp, PADDING_METHOD, 0)? != 2
        || number(cp, MASK_GENERATOR, 1)? != 1
    {
        return Err(fail(8, "Unsupported RSA wrapping parameters"));
    }
    let hash = number(cp, HASHING_ALGORITHM, 4)?;
    let mgf_hash = number(cp, MASK_GENERATOR_HASHING_ALGORITHM, 4)?;
    crypto::rsa::digest(hash).map_err(|_| fail(8, "Unsupported OAEP hash"))?;
    crypto::rsa::digest(mgf_hash).map_err(|_| fail(8, "Unsupported OAEP MGF hash"))?;
    Ok(crypto::rsa::OaepParameters {
        hash,
        mgf_hash,
        label: cp
            .get(P_SOURCE)
            .map(Node::byte_string)
            .transpose()?
            .unwrap_or(&[]),
    })
}
impl Engine {
    fn wrapping_key(
        &self,
        owner: &str,
        v: Version,
        information: &Node,
        strict: bool,
    ) -> R<(Object, Node)> {
        no_fields(information, &[UNIQUE_IDENTIFIER, CRYPTOGRAPHIC_PARAMETERS])?;
        information.required(UNIQUE_IDENTIFIER)?;
        // 2.x Get and Export error tables (2.1 Tables 219, 222) name the
        // wrapping object's own reasons; 1.x keeps Item Not Found. Another
        // principal's key fails exactly like a missing one.
        let key = self.object_owned(owner, information).map_err(|e| {
            if v.0 >= 2 && e.reason == 13 {
                fail(0x40, "Wrapping object is archived")
            } else if v.0 >= 2 && not_found::is_object(&e) {
                fail(0x42, "Wrapping object not found")
            } else {
                e
            }
        })?;
        // 1.x Get and Export tables (1.4 Tables 338, 364): "Object with
        // Encryption Key Information exists, but it is not a key": Illegal
        // Operation.
        if v.0 == 1 && ![2, 3, 4].contains(&key.object_type) {
            return Err(fail(0x0B, "Wrapping object is not a key"));
        }
        if key.state >= 5 || key.material.is_empty() {
            return Err(fail(0x13, "Wrapping key value is not present"));
        }
        let cp = if let Some(cp) = information.get(CRYPTOGRAPHIC_PARAMETERS) {
            validate_cryptographic_parameters(cp, v)?;
            if strict
                && !key
                    .attrs
                    .iter()
                    .filter(|a| a.tag == CRYPTOGRAPHIC_PARAMETERS)
                    .any(|a| same_parameters(cp, a))
            {
                return Err(fail(
                    if v.0 == 1 { 1 } else { 7 },
                    "Wrapping parameters do not match a stored instance",
                ));
            }
            cp.clone()
        } else {
            attributes::first_instance(&key, CRYPTOGRAPHIC_PARAMETERS)?.ok_or(fail(
                if strict && v.0 == 1 { 1 } else { 6 },
                "Wrapping key has no Cryptographic Parameters",
            ))?
        };
        validate_cryptographic_parameters(&cp, v)?;
        Ok((key, cp))
    }
    /// 1.x Get and Export tables (1.4 Tables 338, 364): the object named by
    /// MAC/Signature Key Information must exist (Item Not Found), be a key
    /// (Illegal Operation) and be able to MAC or sign (Permission Denied).
    /// MAC/sign wrapping itself is not implemented, so a usable key still
    /// ends in Feature Not Supported.
    fn legacy_signature_key(&self, owner: &str, spec: &Node) -> R<()> {
        let Some(information) = spec.get(MAC_SIGNATURE_KEY_INFORMATION) else {
            return Ok(());
        };
        no_fields(information, &[UNIQUE_IDENTIFIER, CRYPTOGRAPHIC_PARAMETERS])?;
        let key = self.object_owned(owner, information)?;
        if ![2, 3, 4].contains(&key.object_type) {
            return Err(fail(0x0B, "MAC/Signature key object is not a key"));
        }
        // Sign (0x01) or MAC Generate (0x80), on an Active key.
        if key.state != 2 || key.usage & (0x01 | 0x80) == 0 || key.material.is_empty() {
            return Err(fail(12, "Key cannot be used to MAC or sign"));
        }
        Ok(())
    }
    pub(super) fn wrap_value(
        &self,
        owner: &str,
        v: Version,
        target: &Object,
        mut value: Node,
        spec: &Node,
    ) -> R<(Node, Node)> {
        let selector = if v.0 >= 3 {
            ATTRIBUTE_REFERENCE
        } else {
            ATTRIBUTE_NAME
        };
        let allowed = [
            WRAPPING_METHOD,
            ENCRYPTION_KEY_INFORMATION,
            MAC_SIGNATURE_KEY_INFORMATION,
            selector,
            ENCODING_OPTION,
        ];
        if spec.children()?.iter().any(|n| !allowed.contains(&n.tag)) {
            return Err(fail(8, "Unsupported wrapping specification field"));
        }
        for tag in allowed {
            if tag != selector && spec.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate wrapping specification field"));
            }
        }
        if v.0 == 1 {
            self.legacy_signature_key(owner, spec)?;
        }
        encrypt_only(spec)?;
        let option = encoding(spec, v)?;
        let attrs = attributes::wrapping_attributes(target, v, spec)?;
        // 1.1-1.4 Get and Export tables (1.4 Tables 338, 364): "Encoding
        // Option not permitted when Key Wrapping Specification contains
        // attribute names" and "cannot be provided in the desired Encoding
        // Option": Encoding Option Error, which the 2.x tables also list.
        if option == 1 && !attrs.is_empty() {
            return Err(fail(0x12, "No Encoding cannot include wrapped attributes"));
        }
        if let Value::Structure(fields) = &mut value.value {
            fields.extend(attrs);
        }
        let plaintext = if option == 1 {
            if !matches!(value.required(KEY_MATERIAL)?.value, Value::ByteString(_)) {
                return Err(fail(
                    0x12,
                    "No Encoding of transparent material is unsupported",
                ));
            }
            Zeroizing::new(value.required(KEY_MATERIAL)?.byte_string()?.to_vec())
        } else {
            Zeroizing::new(value.encode())
        };
        let information = spec.required(ENCRYPTION_KEY_INFORMATION)?;
        let (mut key, cp) = self.wrapping_key(owner, v, information, true)?;
        check_use(&key, v, 16, true)?;
        let encrypted = if key.object_type == 2 && key.algorithm == 3 {
            let padded = aes_parameters(&cp)?;
            if !padded && (plaintext.len() < 16 || !plaintext.len().is_multiple_of(8)) {
                return Err(fail(
                    7,
                    "NIST Key Wrap requires at least two complete 64-bit blocks",
                ));
            }
            self.consume_protection(
                &mut key,
                plaintext.len(),
                v,
                if v.0 >= 2 { 0x1a } else { 12 },
            )?;
            crypto::wrapping::aes(&key.material, &plaintext, padded, true)
                .map_err(|_| fail(10, "Key wrapping failed"))?
                .to_vec()
        } else if key.object_type == 3 && key.algorithm == 4 {
            let parameters = oaep_parameters(&cp, v)?;
            if !fips_policy::rsa_transport(key.bits) {
                return Err(fail(8, "RSA keys below 2048 bits cannot wrap in FIPS mode"));
            }
            let maximum = (key.bits as usize).div_ceil(8).saturating_sub(
                2 * crypto::rsa::digest(parameters.hash)
                    .map_err(|_| fail(8, "Unsupported OAEP hash"))?
                    .size()
                    + 2,
            );
            if plaintext.len() > maximum {
                return Err(fail(7, "Wrapped value is too long for RSA OAEP"));
            }
            self.consume_protection(
                &mut key,
                plaintext.len(),
                v,
                if v.0 >= 2 { 0x1a } else { 12 },
            )?;
            crypto::rsa::oaep_encrypt(&key.material, parameters, &plaintext)
                .map_err(|_| fail(10, "Key wrapping failed"))?
        } else {
            return Err(fail(
                8,
                "An AES key or RSA public key is required for wrapping",
            ));
        };
        let mut fields = vec![
            Node::enumeration(WRAPPING_METHOD, 1),
            Node::structure(
                ENCRYPTION_KEY_INFORMATION,
                vec![
                    // docs/interpretations.md, identifier type inside Key Wrapping Data:
                    // draft 3.0 writes this field with type Identifier, as
                    // the OASIS trace AX-M-2-30 does (draft Table 36 also
                    // allows Reference, which is accepted on input).
                    if v.0 >= 3 {
                        Node::identifier(UNIQUE_IDENTIFIER, &key.id)
                    } else {
                        Node::text(UNIQUE_IDENTIFIER, &key.id)
                    },
                    cp,
                ],
            ),
        ];
        // Key Wrapping Data Encoding Option is optional: "If not present, the
        // wrapped Key Value structure SHALL be TTLV encoded" (1.4 Table 9; 2.1
        // Table 15). Echo the client's choice and leave the default implicit.
        if spec.get(ENCODING_OPTION).is_some() {
            fields.push(Node::enumeration(ENCODING_OPTION, option));
        }
        Ok((
            Node::bytes(KEY_VALUE, encrypted),
            Node::structure(KEY_WRAPPING_DATA, fields),
        ))
    }
    pub(super) fn unwrap_value(&self, owner: &str, v: Version, block: &Node) -> R<(Node, String)> {
        let data = block.required(KEY_WRAPPING_DATA)?;
        no_fields(
            data,
            &[
                WRAPPING_METHOD,
                ENCRYPTION_KEY_INFORMATION,
                MAC_SIGNATURE_KEY_INFORMATION,
                MAC_SIGNATURE,
                IV_COUNTER_NONCE,
                ENCODING_OPTION,
            ],
        )?;
        encrypt_only(data)?;
        if data.get(IV_COUNTER_NONCE).is_some() {
            return Err(fail(8, "Explicit wrapping IVs are not implemented"));
        }
        let option = encoding(data, v)?;
        let (key, cp) =
            self.wrapping_key(owner, v, data.required(ENCRYPTION_KEY_INFORMATION)?, false)?;
        let wrapping_id = key.id.clone();
        let ciphertext = block.required(KEY_VALUE)?.byte_string()?;
        let plaintext = if key.object_type == 2 && key.algorithm == 3 {
            check_use(&key, v, 32, false)?;
            crypto::wrapping::aes(&key.material, ciphertext, aes_parameters(&cp)?, false)
                .map_err(|_| fail(10, "Key unwrapping failed"))?
        } else if [3, 4].contains(&key.object_type) && key.algorithm == 4 {
            let private = if key.object_type == 3 {
                self.linked_key(owner, v, &key, 0x103)?
            } else {
                key
            };
            if private.object_type != 4 || private.algorithm != 4 {
                return Err(fail(8, "An RSA private key is required for unwrapping"));
            }
            check_use(&private, v, 32, false)?;
            let parameters = oaep_parameters(&cp, v)?;
            if !fips_policy::rsa_transport(private.bits) {
                return Err(fail(
                    8,
                    "RSA keys below 2048 bits cannot unwrap in FIPS mode",
                ));
            }
            if ciphertext.len() != (private.bits as usize).div_ceil(8) {
                return Err(fail(10, "Key unwrapping failed"));
            }
            crypto::rsa::oaep_decrypt(&private.material, parameters, ciphertext)
                .map_err(|_| fail(10, "Key unwrapping failed"))?
        } else {
            return Err(fail(
                8,
                "An AES key or RSA key pair is required for unwrapping",
            ));
        };
        let value = if option == 1 {
            if matches!(number(block, KEY_FORMAT_TYPE, 1)?, 7 | 14..=21) {
                return Err(fail(7, "No Encoding requires Byte String key material"));
            }
            Node::structure(
                KEY_VALUE,
                vec![Node::bytes(KEY_MATERIAL, plaintext.to_vec())],
            )
        } else {
            let value = crate::ttlv::decode(&plaintext)?;
            if value.tag != KEY_VALUE {
                return Err(fail(7, "Wrapped plaintext must be a Key Value"));
            }
            value
        };
        Ok((value, wrapping_id))
    }
    pub(super) fn register(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        protection::select(p, v)?;
        let kind = number(p, OBJECT_TYPE, 0)?;
        pgp::available(kind, v)?;
        if kind == template::KIND && template::defined(v) {
            return self.register_template(owner, v, p, placeholder);
        }
        let object = p.get(object_tag(kind)?);
        let block = object.and_then(|n| n.get(KEY_BLOCK));
        if block.and_then(|n| n.get(KEY_WRAPPING_DATA)).is_none() {
            return self.create(owner, v, p, true, placeholder);
        }
        let block = block.expect("checked wrapped block");
        let (mut value, wrapping_id) = self.unwrap_value(owner, v, block)?;
        let attribute_tag = if v.0 == 1 { ATTRIBUTE } else { ATTRIBUTES };
        if value
            .children()?
            .iter()
            .any(|n| ![KEY_MATERIAL, attribute_tag].contains(&n.tag))
            || value.all(KEY_MATERIAL).count() != 1
            || v.0 >= 2 && value.all(ATTRIBUTES).count() > 1
        {
            return Err(fail(7, "Invalid wrapped Key Value fields"));
        }
        let mut embedded = if v.0 == 1 {
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
        for a in &mut embedded {
            *a = self.normalize_attribute(
                owner,
                v,
                a.clone(),
                &identifiers::References::default(),
                &None,
            )?;
        }
        let mut attrs = attributes::merge(embedded, read_attrs(p, v)?)?;
        if v.0 >= 2 {
            if attrs.iter().any(|a| link_kind(a) == Some(0x10e)) {
                return Err(fail(7, "Wrapping Key Link is assigned by the server"));
            }
            attrs.push(object_link(0x10e, &wrapping_id));
        }
        if let Value::Structure(fields) = &mut value.value {
            fields.retain(|n| n.tag == KEY_MATERIAL);
        }
        let mut normalized = p.clone();
        if let Value::Structure(fields) = &mut normalized.value {
            fields.retain(|n| ![ATTRIBUTES, TEMPLATE_ATTRIBUTE].contains(&n.tag));
            fields.push(if v.0 == 1 {
                Node::structure(
                    TEMPLATE_ATTRIBUTE,
                    attrs.iter().map(encode_attribute).collect::<R<Vec<_>>>()?,
                )
            } else {
                Node::structure(ATTRIBUTES, attrs)
            });
            for object in fields
                .iter_mut()
                .filter(|n| n.tag == object_tag(kind).unwrap_or(0))
            {
                if let Value::Structure(fields) = &mut object.value {
                    for block in fields.iter_mut().filter(|n| n.tag == KEY_BLOCK) {
                        if let Value::Structure(fields) = &mut block.value {
                            fields.retain(|n| ![KEY_VALUE, KEY_WRAPPING_DATA].contains(&n.tag));
                            fields.push(value.clone());
                        }
                    }
                }
            }
        }
        let mut obj = self.build_object(owner, v, &normalized, true)?;
        obj.wrapped = Some(crate::store::WrappedValue {
            object: object.expect("wrapped object").clone(),
            version: [v.0, v.1],
            opaque: false,
        });
        self.unique_names(&obj, v)?;
        super::quantum::check(&obj)?;
        self.store.insert(&obj)?;
        *placeholder = Some(obj.id.clone());
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
}
