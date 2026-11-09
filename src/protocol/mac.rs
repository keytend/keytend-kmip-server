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

//! MAC selection is an operation parameter, not equality with the key's label.
use super::*;
use crypto::authentication::{Mechanism, hmac_hash};

pub(super) fn validate_key_algorithm(algorithm: u32, v: Version) -> R<()> {
    if (35..=38).contains(&algorithm) && v < Version(1, 4) {
        return Err(fail(7, "HMAC-SHA3 requires KMIP 1.4"));
    }
    Ok(())
}
pub(super) fn parameters(obj: &Object, cp: &Node, v: Version) -> R<Mechanism> {
    if obj.object_type != 2 {
        return Err(fail(
            if v.0 >= 2 { 0x28 } else { 7 },
            "Symmetric MAC key required",
        ));
    }
    no_fields(
        cp,
        &[
            HASHING_ALGORITHM,
            CRYPTOGRAPHIC_ALGORITHM,
            BLOCK_CIPHER_MODE,
        ],
    )?;
    let algorithm = number(cp, CRYPTOGRAPHIC_ALGORITHM, obj.algorithm)?;
    validate_key_algorithm(algorithm, v)?;
    if let Some(hash) = hmac_hash(algorithm) {
        if cp.get(BLOCK_CIPHER_MODE).is_some() || number(cp, HASHING_ALGORITHM, hash)? != hash {
            return Err(fail(
                7,
                "Parameters conflict with the selected HMAC algorithm",
            ));
        }
        Ok(Mechanism::Hmac(hash))
    } else if algorithm == 3 {
        if cp.get(HASHING_ALGORITHM).is_some() {
            return Err(fail(7, "AES-CMAC does not accept a hashing algorithm"));
        }
        if number(cp, BLOCK_CIPHER_MODE, 0)? != 7 {
            return Err(fail(8, "AES MAC requires CMAC block cipher mode"));
        }
        if ![16, 24, 32].contains(&obj.material.len()) {
            return Err(fail(7, "AES-CMAC requires a 128, 192 or 256-bit key"));
        }
        Ok(Mechanism::Cmac)
    } else {
        Err(fail(8, "Unsupported MAC algorithm"))
    }
}
