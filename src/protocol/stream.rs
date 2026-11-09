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

//! Owner-bound multipart state with copy-on-write snapshots for database rollback.
use super::*;
use openssl::hash::Hasher;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const MAX_STREAMS: usize = 64;
const MAX_OWNER_STREAMS: usize = 16;
const MAX_RETAINED: usize = 8 * 1024 * 1024;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(300);
const LIFETIME: Duration = Duration::from_secs(3600);
#[derive(Clone, Default)]
pub(super) struct Streams {
    states: HashMap<Vec<u8>, Arc<State>>,
}
impl Streams {
    pub(super) fn purge(&mut self) {
        let now = Instant::now();
        self.states.retain(|_, s| {
            now.duration_since(s.touched) < IDLE && now.duration_since(s.created) < LIFETIME
        });
    }
    pub(super) fn invalidate_key(&mut self, owner: &str, id: &str) {
        self.states
            .retain(|_, s| s.owner != owner || s.key_id.as_deref() != Some(id));
    }
    fn retained(&self) -> usize {
        self.states.values().map(|s| s.retained()).sum()
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Parameters {
    Cipher(crypto::CipherParameters),
    Oaep {
        hash: u32,
        mgf_hash: u32,
        label: Vec<u8>,
        max_input: usize,
        modulus_len: usize,
    },
    Rsa(crypto::rsa::SignatureParameters),
    Ec(u32),
    Dsa(u32),
    Mac(crypto::authentication::Mechanism),
    Hash(u32),
}
enum Context {
    Cipher(crypto::stream::Symmetric),
    Oaep(Arc<Zeroizing<Vec<u8>>>),
    Digest(Hasher),
    Mac(crypto::stream::Mac),
}
impl Context {
    fn try_clone(&self) -> R<Self> {
        Ok(match self {
            Self::Cipher(c) => Self::Cipher(
                c.try_clone()
                    .map_err(|_| fail(10, "Unable to copy cipher state"))?,
            ),
            Self::Oaep(data) => Self::Oaep(data.clone()),
            Self::Digest(h) => Self::Digest(h.clone()),
            Self::Mac(h) => Self::Mac(
                h.try_clone()
                    .map_err(|_| fail(10, "Unable to copy MAC state"))?,
            ),
        })
    }
    fn retained(&self) -> usize {
        match self {
            Self::Cipher(c) => c.retained(),
            Self::Oaep(data) => data.len(),
            _ => 0,
        }
    }
}
struct State {
    owner: String,
    version: Version,
    operation: u32,
    key_id: Option<String>,
    binding: Option<KeyBinding>,
    cp: Node,
    parameters: Parameters,
    context: Context,
    iv: Vec<u8>,
    expected: Option<Arc<Zeroizing<Vec<u8>>>>,
    prehashed: Option<Arc<Zeroizing<Vec<u8>>>>,
    bytes: u64,
    created: Instant,
    touched: Instant,
}
impl State {
    fn retained(&self) -> usize {
        self.context.retained()
            + self.expected.as_ref().map_or(0, |s| s.len())
            + self.prehashed.as_ref().map_or(0, |s| s.len())
            + self.cp.encoded_len()
            + self.iv.len()
            + self.owner.len()
            + self.key_id.as_ref().map_or(0, |s| s.len())
            + match &self.parameters {
                Parameters::Oaep { label, .. } => label.len(),
                _ => 0,
            }
    }
    fn try_clone(&self) -> R<Self> {
        Ok(Self {
            owner: self.owner.clone(),
            version: self.version,
            operation: self.operation,
            key_id: self.key_id.clone(),
            binding: self.binding.clone(),
            cp: self.cp.clone(),
            parameters: self.parameters.clone(),
            context: self.context.try_clone()?,
            iv: self.iv.clone(),
            expected: self.expected.clone(),
            prehashed: self.prehashed.clone(),
            bytes: self.bytes,
            created: self.created,
            touched: self.touched,
        })
    }
}
pub(super) fn requested(p: &Node) -> bool {
    [INIT_INDICATOR, FINAL_INDICATOR, CORRELATION_VALUE]
        .iter()
        .any(|tag| p.get(*tag).is_some())
}
fn correlation_error(v: Version) -> Failure {
    fail(
        if v.0 >= 2 { 0x2e } else { 7 },
        "Invalid multipart correlation value",
    )
}
#[derive(Clone, PartialEq, Eq)]
struct KeyBinding {
    kind: u32,
    algorithm: u32,
    bits: u32,
    format: u32,
    digest: Vec<u8>,
}
fn binding(obj: &Object) -> R<KeyBinding> {
    Ok(KeyBinding {
        kind: obj.object_type,
        algorithm: obj.algorithm,
        bits: obj.bits,
        format: obj.format,
        digest: crypto::hash_data(SHA256, &obj.material)?,
    })
}
fn validate_expected(state: &mut State, p: &Node) -> R<()> {
    let tag = match state.operation {
        34 => SIGNATURE_DATA,
        36 => MAC_DATA,
        _ => return Ok(()),
    };
    if let Some(n) = p.get(tag) {
        let input = n.byte_string()?;
        if let Some(previous) = &state.expected {
            if previous.as_slice() != input {
                return Err(fail(
                    7,
                    "Verification value changed during multipart operation",
                ));
            }
        } else {
            state.expected = Some(Arc::new(Zeroizing::new(input.to_vec())));
        }
    }
    Ok(())
}
fn signature_parameters(obj: &Object, cp: &Node, v: Version, op: u32) -> R<Parameters> {
    if matches!(op, 33 | 34) {
        if op == 33 && obj.object_type != 4 || op == 34 && obj.object_type != 3 {
            return Err(fail(8, "Signature key role mismatch"));
        }
        if [6, 26].contains(&obj.algorithm) {
            ec::validate_algorithm(obj.algorithm, v)?;
            return Ok(Parameters::Ec(ec::hash_parameters(cp, v, obj, op == 34)?));
        }
        if op == 34 && obj.algorithm == 5 {
            return Ok(Parameters::Dsa(certificate::dsa_hash(cp, v)?));
        }
        if obj.algorithm != 4 {
            return Err(fail(8, "Unsupported signature key algorithm"));
        }
        let parameters = rsa::signature_parameters(cp, v, obj.bits)?;
        fips_policy::rsa_signature(&parameters, obj.bits, op == 33, v)?;
        Ok(Parameters::Rsa(parameters))
    } else {
        let mechanism = mac::parameters(obj, cp, v)?;
        fips_policy::mac(mechanism, &obj.material, op == 35)?;
        Ok(Parameters::Mac(mechanism))
    }
}
impl Engine {
    pub(super) fn multipart(
        &mut self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        if v < Version(1, 3) {
            return Err(fail(7, "Multipart fields require KMIP 1.3"));
        }
        for tag in [INIT_INDICATOR, FINAL_INDICATOR, CORRELATION_VALUE] {
            if p.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate multipart field"));
            }
        }
        let init = flag(p, INIT_INDICATOR, false)?;
        let last = flag(p, FINAL_INDICATOR, false)?;
        let correlation = p
            .get(CORRELATION_VALUE)
            .map(Node::byte_string)
            .transpose()?;
        if correlation.is_some_and(|value| value.len() != 32) {
            return Err(correlation_error(v));
        }
        // Explicit false indicators and init+final select a single-part operation.
        if correlation.is_none() && (!init && !last || init && last) {
            let mut request = p.clone();
            let Value::Structure(fields) = &mut request.value else {
                return Err(fail(7, "Invalid cryptographic request"));
            };
            fields.retain(|n| ![INIT_INDICATOR, FINAL_INDICATOR].contains(&n.tag));
            if init
                && last
                && request.get(DATA).is_none()
                && request.get(DIGESTED_DATA).is_none()
                && let Value::Structure(fields) = &mut request.value
            {
                fields.push(Node::bytes(DATA, vec![]));
            }
            return match op {
                31 | 32 => self.crypt(owner, v, op, &request, placeholder),
                33..=36 => self.sign_mac(owner, v, op, &request, placeholder),
                39 => hashing::single(&request, v),
                _ => Err(fail(8, "Unsupported multipart operation")),
            };
        }
        if init == correlation.is_some() {
            return Err(correlation_error(v));
        }
        let mut allowed = vec![
            CRYPTOGRAPHIC_PARAMETERS,
            DATA,
            INIT_INDICATOR,
            FINAL_INDICATOR,
            CORRELATION_VALUE,
        ];
        if op != 39 {
            allowed.push(UNIQUE_IDENTIFIER);
        }
        if matches!(op, 31 | 32) {
            allowed.extend([
                IV_COUNTER_NONCE,
                AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
                AUTHENTICATED_ENCRYPTION_TAG,
            ]);
        }
        if op == 34 {
            allowed.push(SIGNATURE_DATA);
        }
        if op == 36 {
            allowed.push(MAC_DATA);
        }
        if p.get(DIGESTED_DATA).is_some()
            && (v < Version(1, 4) || !matches!(op, 33 | 34) || p.get(DATA).is_some())
        {
            return Err(fail(7, "Incompatible prehashed multipart input"));
        }
        if matches!(op, 33 | 34) && v >= Version(1, 4) {
            allowed.push(DIGESTED_DATA);
        }
        no_fields(p, &allowed)?;
        let data = match p.get(DATA) {
            Some(n) => n.byte_string()?,
            None if init || last || p.get(DIGESTED_DATA).is_some() => &[],
            None => return Err(fail(6, "Data required for intermediate multipart requests")),
        };
        let token = if init {
            if self.streams.states.len() >= MAX_STREAMS
                || self
                    .streams
                    .states
                    .values()
                    .filter(|s| s.owner == owner)
                    .count()
                    >= MAX_OWNER_STREAMS
            {
                return Err(fail(2, "Multipart context capacity exceeded"));
            }
            let mut candidate = None;
            for _ in 0..8 {
                let value = crypto::random(32)?.to_vec();
                if !self.streams.states.contains_key(&value) {
                    candidate = Some(value);
                    break;
                }
            }
            candidate.ok_or(fail(10, "Unable to allocate correlation value"))?
        } else {
            correlation.ok_or_else(|| correlation_error(v))?.to_vec()
        };
        let previous = if init {
            None
        } else {
            Some(
                self.streams
                    .states
                    .get(&token)
                    .filter(|s| s.owner == owner && s.version == v && s.operation == op)
                    .cloned()
                    .ok_or_else(|| correlation_error(v))?,
            )
        };
        if !init
            && (p.get(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA).is_some()
                || p.get(AUTHENTICATED_ENCRYPTION_TAG).is_some())
        {
            return Err(fail(
                7,
                "Authentication fields belong only to initial multipart request",
            ));
        }
        let mut object = if op == 39 {
            None
        } else {
            let mut obj = self.object(owner, p, placeholder)?;
            self.materialize(owner, &mut obj)?;
            check_use(
                &obj,
                v,
                match op {
                    31 => 4,
                    32 => 8,
                    33 => 1,
                    34 => 2,
                    35 => 0x80,
                    _ => 0x100,
                },
                matches!(op, 31 | 33 | 35),
            )?;
            Some(obj)
        };
        if let (Some(state), Some(obj)) = (&previous, &object)
            && (state.key_id.as_deref() != Some(obj.id.as_str())
                || state.binding.as_ref() != Some(&binding(obj)?))
        {
            return Err(correlation_error(v));
        }
        let certificate_key = if op == 34 && object.as_ref().is_some_and(|o| o.object_type == 1) {
            Some(certificate::verification_key(object.as_ref().unwrap(), v)?)
        } else {
            None
        };
        let cp = if let Some(state) = &previous {
            match p.get(CRYPTOGRAPHIC_PARAMETERS) {
                Some(cp) => {
                    validate_cryptographic_parameters(cp, v)?;
                    cp.clone()
                }
                None => state.cp.clone(),
            }
        } else if let Some(obj) = &object {
            cryptographic_parameters(obj, p, v, matches!(op, 31..=34))?
        } else {
            p.required(CRYPTOGRAPHIC_PARAMETERS)?.clone()
        };
        validate_cryptographic_parameters(&cp, v)?;
        let mut generated_iv = None;
        let parameters = if matches!(op, 31 | 32)
            && object.as_ref().is_some_and(|o| o.algorithm == 4)
        {
            let setup = rsa::encryption_parameters(object.as_ref().unwrap(), &cp, p, v, op == 31)?;
            Parameters::Oaep {
                hash: setup.parameters.hash,
                mgf_hash: setup.parameters.mgf_hash,
                label: setup.parameters.label.to_vec(),
                max_input: setup.max_input,
                modulus_len: setup.modulus_len,
            }
        } else if matches!(op, 31 | 32) {
            let mut setup_request = Node::structure(
                REQUEST_PAYLOAD,
                p.children()?
                    .iter()
                    .filter(|n| {
                        [
                            IV_COUNTER_NONCE,
                            AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
                            AUTHENTICATED_ENCRYPTION_TAG,
                        ]
                        .contains(&n.tag)
                    })
                    .cloned()
                    .collect(),
            );
            if let Some(state) = &previous
                && p.get(IV_COUNTER_NONCE).is_none()
                && !state.iv.is_empty()
                && let Value::Structure(fields) = &mut setup_request.value
            {
                fields.push(Node::bytes(IV_COUNTER_NONCE, state.iv.clone()));
            }
            let setup = cipher::setup(
                object.as_ref().unwrap(),
                &cp,
                &setup_request,
                v,
                op == 31,
                self.triple_des,
            )?;
            if let Some(state) = &previous
                && setup.iv != state.iv
            {
                return Err(fail(7, "Multipart IV changed"));
            }
            if init {
                generated_iv = Some((setup.iv.clone(), setup.generated_iv));
            }
            Parameters::Cipher(setup.parameters)
        } else if op == 39 {
            Parameters::Hash(hashing::parameters(&cp, v)?)
        } else {
            signature_parameters(
                certificate_key.as_ref().or(object.as_ref()).unwrap(),
                &cp,
                v,
                op,
            )?
        };
        let mut state = if let Some(previous) = &previous {
            if parameters != previous.parameters {
                return Err(fail(7, "Multipart parameters changed"));
            }
            previous.try_clone()?
        } else {
            let context = match parameters {
                Parameters::Cipher(aes) => Context::Cipher(
                    crypto::stream::Symmetric::new(
                        op == 31,
                        &object.as_ref().unwrap().material,
                        aes,
                        &generated_iv.as_ref().unwrap().0,
                        p.get(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA)
                            .map(Node::byte_string)
                            .transpose()?
                            .unwrap_or(&[]),
                        p.get(AUTHENTICATED_ENCRYPTION_TAG)
                            .map(Node::byte_string)
                            .transpose()?,
                    )
                    .map_err(|_| fail(10, "Unable to initialize cipher stream"))?,
                ),
                Parameters::Oaep { .. } => Context::Oaep(Arc::new(Zeroizing::new(vec![]))),
                Parameters::Mac(mechanism) => Context::Mac(
                    crypto::stream::Mac::new(mechanism, &object.as_ref().unwrap().material)
                        .map_err(|_| fail(10, "Unable to initialize MAC stream"))?,
                ),
                Parameters::Hash(hash) => Context::Digest(
                    Hasher::new(crypto::hashing::digest(hash)?)
                        .map_err(|_| fail(10, "Unable to initialize hash stream"))?,
                ),
                Parameters::Rsa(p) => Context::Digest(
                    Hasher::new(crypto::rsa::digest(p.hash)?)
                        .map_err(|_| fail(10, "Unable to initialize signature digest"))?,
                ),
                Parameters::Ec(hash) | Parameters::Dsa(hash) => Context::Digest(
                    Hasher::new(crypto::rsa::digest(hash)?)
                        .map_err(|_| fail(10, "Unable to initialize signature digest"))?,
                ),
            };
            let now = Instant::now();
            State {
                owner: owner.into(),
                version: v,
                operation: op,
                key_id: object.as_ref().map(|o| o.id.clone()),
                binding: object.as_ref().map(binding).transpose()?,
                cp: cp.clone(),
                parameters: parameters.clone(),
                context,
                iv: generated_iv
                    .as_ref()
                    .map(|v| v.0.clone())
                    .unwrap_or_default(),
                expected: None,
                prehashed: None,
                bytes: 0,
                created: now,
                touched: now,
            }
        };
        validate_expected(&mut state, p)?;
        let mut charged_bytes = data.len();
        if let Some(digest) = p.get(DIGESTED_DATA) {
            let digest = digest.byte_string()?;
            let hash = match state.parameters {
                Parameters::Rsa(p) => p.hash,
                Parameters::Ec(hash) | Parameters::Dsa(hash) => hash,
                _ => return Err(fail(7, "Prehashed input requires a signature operation")),
            };
            if digest.len() != crypto::rsa::digest(hash)?.size() {
                return Err(fail(
                    7,
                    "Digested Data length does not match signature hash",
                ));
            }
            if let Some(existing) = &state.prehashed {
                if existing.as_slice() != digest {
                    return Err(fail(7, "Digested Data changed"));
                }
            } else {
                if state.bytes != 0 {
                    return Err(fail(7, "Cannot mix streamed message and prehashed input"));
                }
                state.prehashed = Some(Arc::new(Zeroizing::new(digest.to_vec())));
                charged_bytes = digest.len();
            }
        }
        if state.prehashed.is_some() && !data.is_empty() {
            return Err(fail(7, "Cannot mix streamed message and prehashed input"));
        }
        state.bytes = state
            .bytes
            .checked_add(charged_bytes as u64)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or(fail(2, "Multipart input limit exceeded"))?;
        if let Context::Cipher(cipher) = &state.context
            && cipher.holds_plaintext()
            && cipher.retained().saturating_add(data.len())
                > crypto::stream::MAX_AUTHENTICATED_PLAINTEXT
        {
            return Err(fail(2, "Authenticated plaintext buffer limit exceeded"));
        }
        if matches!(op, 31 | 33 | 35) {
            self.consume_stream_protection(
                object.as_mut().unwrap(),
                charged_bytes,
                init,
                v,
                if op == 35 && v.0 >= 2 { 26 } else { 12 },
            )?;
        }
        let mut result = vec![];
        if let Some(id) = &state.key_id {
            result.push(Node::text(UNIQUE_IDENTIFIER, id));
        }
        match &mut state.context {
            Context::Cipher(cipher) => {
                let (out, tag) = cipher
                    .update(data, last)
                    .map_err(|_| fail(10, "Multipart cryptographic operation failed"))?;
                if !out.is_empty() || last {
                    result.push(Node::bytes(DATA, out.to_vec()));
                }
                if !tag.is_empty() {
                    result.push(Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, tag));
                }
                if let Some((iv, true)) = &generated_iv {
                    result.push(Node::bytes(IV_COUNTER_NONCE, iv.clone()));
                }
            }
            Context::Oaep(buffer) => {
                let Parameters::Oaep {
                    hash,
                    mgf_hash,
                    label,
                    max_input,
                    modulus_len,
                } = &state.parameters
                else {
                    return Err(fail(10, "Invalid OAEP stream state"));
                };
                if buffer.len().saturating_add(data.len()) > *max_input {
                    return Err(fail(
                        if op == 31 { 7 } else { 10 },
                        "RSA multipart input length invalid",
                    ));
                }
                Arc::make_mut(buffer).extend_from_slice(data);
                if last {
                    let key = &object.as_ref().unwrap().material;
                    let parameters = crypto::rsa::OaepParameters {
                        hash: *hash,
                        mgf_hash: *mgf_hash,
                        label,
                    };
                    let out = if op == 31 {
                        crypto::rsa::oaep_encrypt(key, parameters, buffer)
                            .map_err(|_| fail(10, "RSA multipart encryption failed"))?
                    } else {
                        if buffer.len() != *modulus_len {
                            return Err(fail(10, "RSA multipart decryption failed"));
                        }
                        crypto::rsa::oaep_decrypt(key, parameters, buffer)
                            .map_err(|_| fail(10, "RSA multipart decryption failed"))?
                            .to_vec()
                    };
                    result.push(Node::bytes(DATA, out));
                }
            }
            Context::Mac(mac) => {
                mac.update(data)
                    .map_err(|_| fail(10, "Multipart MAC update failed"))?;
                if last {
                    let actual = mac.finish().map_err(|_| fail(10, "Multipart MAC failed"))?;
                    if op == 35 {
                        result.push(Node::bytes(MAC_DATA, actual));
                    } else {
                        use subtle::ConstantTimeEq;
                        let expected = state
                            .expected
                            .as_ref()
                            .ok_or(fail(6, "MAC Data required on final request"))?;
                        result.push(Node::enumeration(
                            VALIDITY_INDICATOR,
                            if bool::from(actual.as_slice().ct_eq(expected.as_slice())) {
                                1
                            } else {
                                2
                            },
                        ));
                    }
                }
            }
            Context::Digest(hash) => {
                hash.update(data)
                    .map_err(|_| fail(10, "Multipart digest update failed"))?;
                if last {
                    let digest = Zeroizing::new(if let Some(digest) = &state.prehashed {
                        digest.to_vec()
                    } else {
                        hash.finish()
                            .map_err(|_| fail(10, "Multipart digest failed"))?
                            .to_vec()
                    });
                    match state.parameters {
                        Parameters::Hash(_) => result.push(Node::bytes(DATA, digest.to_vec())),
                        Parameters::Rsa(parameters) => {
                            let object = certificate_key.as_ref().or(object.as_ref()).unwrap();
                            if op == 33 {
                                result.push(Node::bytes(
                                    SIGNATURE_DATA,
                                    crypto::rsa::sign(&object.material, parameters, &digest, true)
                                        .map_err(|_| fail(10, "Multipart RSA signing failed"))?,
                                ));
                            } else {
                                let expected = state
                                    .expected
                                    .as_ref()
                                    .ok_or(fail(6, "Signature Data required on final request"))?;
                                let valid = crypto::rsa::verify(
                                    &object.material,
                                    parameters,
                                    &digest,
                                    true,
                                    expected,
                                )
                                .map_err(|_| fail(10, "Multipart RSA verification failed"))?;
                                result.push(Node::enumeration(
                                    VALIDITY_INDICATOR,
                                    if valid { 1 } else { 2 },
                                ));
                            }
                        }
                        Parameters::Ec(hash) => {
                            let object = certificate_key.as_ref().or(object.as_ref()).unwrap();
                            if op == 33 {
                                result.push(Node::bytes(
                                    SIGNATURE_DATA,
                                    crypto::ec::sign(&object.material, hash, &digest, true)
                                        .map_err(|_| fail(10, "Multipart ECDSA signing failed"))?,
                                ));
                            } else {
                                let expected = state
                                    .expected
                                    .as_ref()
                                    .ok_or(fail(6, "Signature Data required on final request"))?;
                                let valid = crypto::ec::verify(
                                    &object.material,
                                    hash,
                                    &digest,
                                    true,
                                    expected,
                                )
                                .map_err(|_| fail(10, "Multipart ECDSA verification failed"))?;
                                result.push(Node::enumeration(
                                    VALIDITY_INDICATOR,
                                    if valid { 1 } else { 2 },
                                ));
                            }
                        }
                        Parameters::Dsa(hash) => {
                            let object = certificate_key.as_ref().or(object.as_ref()).unwrap();
                            let expected = state
                                .expected
                                .as_ref()
                                .ok_or(fail(6, "Signature Data required on final request"))?;
                            let valid = crypto::dsa::verify(
                                &object.material,
                                hash,
                                &digest,
                                true,
                                expected,
                            )
                            .map_err(|_| fail(10, "Multipart DSA verification failed"))?;
                            result.push(Node::enumeration(
                                VALIDITY_INDICATOR,
                                if valid { 1 } else { 2 },
                            ));
                        }
                        _ => return Err(fail(10, "Invalid multipart digest state")),
                    }
                }
            }
        }
        if last {
            self.streams.states.remove(&token);
        } else {
            let retained = self
                .streams
                .retained()
                .saturating_sub(previous.as_ref().map_or(0, |s| s.retained()))
                .saturating_add(state.retained());
            if retained > MAX_RETAINED {
                return Err(fail(2, "Multipart retained-data budget exceeded"));
            }
            state.touched = Instant::now();
            self.streams.states.insert(token.clone(), Arc::new(state));
            result.push(Node::bytes(CORRELATION_VALUE, token));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> State {
        let now = Instant::now();
        State {
            owner: "alice".into(),
            version: Version(2, 1),
            operation: 39,
            key_id: None,
            binding: None,
            cp: Node::structure(
                CRYPTOGRAPHIC_PARAMETERS,
                vec![Node::enumeration(HASHING_ALGORITHM, SHA256)],
            ),
            parameters: Parameters::Hash(SHA256),
            context: Context::Digest(Hasher::new(crypto::digest(SHA256).unwrap()).unwrap()),
            iv: vec![],
            expected: None,
            prehashed: None,
            bytes: 0,
            created: now,
            touched: now,
        }
    }
    #[test]
    fn idle_and_absolute_lifetimes_are_enforced_independently() {
        let mut streams = Streams::default();
        let mut idle = state();
        idle.touched -= IDLE + Duration::from_secs(1);
        let mut old = state();
        old.created -= LIFETIME + Duration::from_secs(1);
        streams.states.insert(vec![1], Arc::new(idle));
        streams.states.insert(vec![2], Arc::new(old));
        streams.states.insert(vec![3], Arc::new(state()));
        streams.purge();
        assert_eq!(streams.states.len(), 1);
        assert!(streams.states.contains_key(&vec![3]));
    }
    #[test]
    fn maximum_stream_input_is_checked_without_counter_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let master = dir.path().join("master");
        std::fs::write(&master, [7; 32]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut engine = Engine::new(
            Store::open(&dir.path().join("store.sqlite"), &master).unwrap(),
            false,
        );
        let mut full = state();
        full.bytes = MAX_BYTES;
        let token = vec![7; 32];
        engine.streams.states.insert(token.clone(), Arc::new(full));
        let p = Node::structure(
            REQUEST_PAYLOAD,
            vec![
                Node::bytes(CORRELATION_VALUE, token.clone()),
                Node::bytes(DATA, vec![1]),
                Node::boolean(FINAL_INDICATOR, true),
            ],
        );
        assert_eq!(
            engine
                .multipart("alice", Version(2, 1), 39, &p, &None)
                .err()
                .unwrap()
                .reason,
            2
        );
        assert_eq!(engine.streams.states[&token].bytes, MAX_BYTES);
    }
}
