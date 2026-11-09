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

//! The same typed, versioned Hash selection for single and multipart requests.
use super::*;

pub(super) fn parameters(cp: &Node, v: Version) -> R<u32> {
    no_fields(cp, &[HASHING_ALGORITHM])?;
    validate_cryptographic_parameters(cp, v)?;
    let hash = number(cp, HASHING_ALGORITHM, SHA256)?;
    if (14..=17).contains(&hash) && v < Version(1, 4) {
        return Err(fail(8, "SHA-3 Hash requires KMIP 1.4"));
    }
    crypto::hashing::digest(hash).map_err(|_| fail(8, "Unsupported hash algorithm"))?;
    Ok(hash)
}

pub(super) fn single(p: &Node, v: Version) -> R<Vec<Node>> {
    no_fields(p, &[CRYPTOGRAPHIC_PARAMETERS, DATA])?;
    let hash = parameters(p.required(CRYPTOGRAPHIC_PARAMETERS)?, v)?;
    let output = crypto::hashing::compute(hash, p.required(DATA)?.byte_string()?)
        .map_err(|_| fail(10, "Hash provider operation failed"))?;
    Ok(vec![Node::bytes(DATA, output)])
}
