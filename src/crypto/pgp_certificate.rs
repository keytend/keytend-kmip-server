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

//! Bounded RFC 4880 transferable-public-key framing and metadata inspection.
//! This does not verify certifications, revocations, trust or key strength.
use anyhow::{Result, bail, ensure};
use zeroize::Zeroizing;
const MAX: usize = 65536;
#[derive(Debug)]
pub struct Metadata {
    pub algorithm: Option<u32>,
    pub bits: Option<u32>,
    pub signatures: Vec<u32>,
    pub unknown_signatures: bool,
}
fn armor(material: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        !material.is_empty() && material.len() <= MAX,
        "Certificate size limit"
    );
    if material[0] & 0x80 != 0 {
        return Ok(Zeroizing::new(material.to_vec()));
    }
    let text = std::str::from_utf8(material)?.trim();
    let mut lines = text.lines();
    ensure!(
        lines.next() == Some("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "Public-key armor required"
    );
    let mut body = false;
    let mut ended = false;
    let mut checksum = None;
    let mut encoded = Zeroizing::new(String::new());
    for line in lines {
        let line = line.trim();
        if ended {
            ensure!(line.is_empty(), "Trailing armor data");
            continue;
        }
        if !body {
            if line.is_empty() {
                body = true;
            } else {
                ensure!(
                    line.contains(':') && line.is_ascii(),
                    "Invalid armor header"
                );
            }
        } else if line == "-----END PGP PUBLIC KEY BLOCK-----" {
            ended = true;
        } else if let Some(value) = line.strip_prefix('=') {
            ensure!(
                checksum.is_none() && value.len() == 4,
                "Invalid armor checksum"
            );
            checksum = Some(openssl::base64::decode_block(value)?);
        } else {
            ensure!(
                checksum.is_none()
                    && !line.is_empty()
                    && line
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
                "Invalid armor body"
            );
            encoded.push_str(line);
        }
    }
    ensure!(
        body && ended && !encoded.is_empty(),
        "Incomplete public-key armor"
    );
    let decoded = Zeroizing::new(openssl::base64::decode_block(&encoded)?);
    if let Some(checksum) = checksum {
        let mut crc = 0xb704ceu32;
        for byte in &*decoded {
            crc ^= (*byte as u32) << 16;
            for _ in 0..8 {
                crc <<= 1;
                if crc & 0x1000000 != 0 {
                    crc ^= 0x1864cfb;
                }
            }
        }
        ensure!(
            checksum == crc.to_be_bytes()[1..],
            "Armor checksum mismatch"
        );
    }
    Ok(decoded)
}
fn take<'a>(bytes: &'a [u8], at: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = at
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| anyhow::anyhow!("Truncated packet"))?;
    let result = &bytes[*at..end];
    *at = end;
    Ok(result)
}
fn packet<'a>(bytes: &'a [u8], at: &mut usize) -> Result<(u8, &'a [u8])> {
    let header = take(bytes, at, 1)?[0];
    ensure!(header & 0x80 != 0, "Invalid packet header");
    let (tag, length) = if header & 0x40 != 0 {
        let first = take(bytes, at, 1)?[0];
        let len = match first {
            0..=191 => first as usize,
            192..=223 => ((first as usize - 192) << 8) + take(bytes, at, 1)?[0] as usize + 192,
            255 => u32::from_be_bytes(take(bytes, at, 4)?.try_into()?) as usize,
            _ => bail!("Partial lengths are not allowed for certificate packets"),
        };
        (header & 63, len)
    } else {
        let width = match header & 3 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => 0,
        };
        let len = if width == 0 {
            bytes.len() - *at
        } else {
            take(bytes, at, width)?
                .iter()
                .fold(0usize, |n, b| (n << 8) | *b as usize)
        };
        ((header >> 2) & 15, len)
    };
    ensure!(
        !matches!(tag, 5 | 7),
        "Secret keys cannot be stored as public certificates"
    );
    Ok((tag, take(bytes, at, length)?))
}
fn integer(body: &[u8], at: &mut usize, nonzero: bool) -> Result<u32> {
    let bits = u16::from_be_bytes(take(body, at, 2)?.try_into()?) as u32;
    if bits == 0 {
        ensure!(!nonzero, "Empty public key integer");
        return Ok(0);
    }
    let value = take(body, at, bits.div_ceil(8) as usize)?;
    ensure!(
        value[0] != 0 && (value.len() as u32 - 1) * 8 + 8 - value[0].leading_zeros() == bits,
        "Noncanonical MPI"
    );
    Ok(bits)
}
fn mpi(body: &[u8], at: &mut usize) -> Result<u32> {
    integer(body, at, true)
}
fn public(body: &[u8]) -> Result<(u8, Option<u32>, Option<u32>)> {
    let version = *body
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty public key"))?;
    ensure!(matches!(version, 3 | 4), "Unsupported public-key version");
    let mut at = if version == 3 { 7 } else { 5 };
    let algorithm = take(body, &mut at, 1)?[0];
    if version == 3 {
        ensure!(matches!(algorithm, 1..=3), "V3 public keys require RSA");
    }
    let (mapped, bits) = match algorithm {
        1..=3 => {
            let bits = mpi(body, &mut at)?;
            mpi(body, &mut at)?;
            (Some(4), Some(bits))
        }
        17 => {
            let bits = mpi(body, &mut at)?;
            for _ in 0..3 {
                mpi(body, &mut at)?;
            }
            (Some(5), Some(bits))
        }
        18 | 19 => {
            let len = take(body, &mut at, 1)?[0] as usize;
            ensure!(len > 0 && len < 255, "Invalid curve OID length");
            let oid = take(body, &mut at, len)?;
            let point_start = at + 2;
            mpi(body, &mut at)?;
            let point = &body[point_start..at];
            ensure!(
                point.first() == Some(&4) && point.len() >= 3 && point.len() % 2 == 1,
                "Uncompressed public point required"
            );
            if algorithm == 18 {
                let len = take(body, &mut at, 1)?[0] as usize;
                ensure!(len == 3, "Invalid ECDH KDF parameters");
                let kdf = take(body, &mut at, len)?;
                ensure!(kdf[0] == 1, "Invalid ECDH KDF version");
            }
            let bits = match oid {
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7] => Some(256),
                [0x2b, 0x81, 4, 0, 0x22] => Some(384),
                [0x2b, 0x81, 4, 0, 0x23] => Some(521),
                [0x2b, 0x81, 4, 0, 0x0a] => Some(256),
                _ => None,
            };
            if let Some(bits) = bits {
                ensure!(
                    point.len() == 1 + 2 * (bits as usize).div_ceil(8),
                    "Point length differs from curve"
                );
            }
            (Some(if algorithm == 18 { 14 } else { 6 }), bits)
        }
        _ => {
            ensure!(at < body.len(), "Missing public key material");
            return Ok((version, None, None));
        }
    };
    ensure!(at == body.len(), "Unexpected public-key material");
    Ok((version, mapped, bits))
}
fn signature(body: &[u8]) -> Result<(u8, Option<u32>)> {
    let version = *body
        .first()
        .ok_or_else(|| anyhow::anyhow!("Empty signature"))?;
    let (kind, public, hash, mut at) = match version {
        3 => {
            ensure!(body.len() >= 19 && body[1] == 5, "Invalid V3 signature");
            (body[2], body[15], body[16], 19)
        }
        4 => {
            ensure!(body.len() >= 6, "Invalid V4 signature");
            let mut at = 4;
            let hashed = u16::from_be_bytes(take(body, &mut at, 2)?.try_into()?) as usize;
            take(body, &mut at, hashed)?;
            let unhashed = u16::from_be_bytes(take(body, &mut at, 2)?.try_into()?) as usize;
            take(body, &mut at, unhashed)?;
            take(body, &mut at, 2)?;
            (body[1], body[2], body[3], at)
        }
        _ => bail!("Unsupported signature version"),
    };
    let mapped = match (public, hash) {
        (1 | 3, 1) => Some(2),
        (1 | 3, 2) => Some(3),
        (1 | 3, 11) => Some(4),
        (1 | 3, 8) => Some(5),
        (1 | 3, 9) => Some(6),
        (1 | 3, 10) => Some(7),
        (17, 2) => Some(9),
        (17, 11) => Some(10),
        (17, 8) => Some(11),
        (19, 2) => Some(12),
        (19, 11) => Some(13),
        (19, 8) => Some(14),
        (19, 9) => Some(15),
        (19, 10) => Some(16),
        _ => None,
    };
    match public {
        1 | 3 => {
            integer(body, &mut at, false)?;
        }
        17 | 19 => {
            integer(body, &mut at, false)?;
            integer(body, &mut at, false)?;
        }
        _ => {
            ensure!(at < body.len(), "Missing signature material");
            return Ok((kind, mapped));
        }
    }
    ensure!(at == body.len(), "Trailing signature material");
    Ok((kind, mapped))
}
pub fn inspect(material: &[u8]) -> Result<Metadata> {
    let bytes = armor(material)?;
    let mut at = 0;
    let mut count = 0;
    let mut primary = None;
    let mut identities = 0;
    let mut phase = 0;
    let mut bound = true;
    let mut signatures = Vec::new();
    let mut unknown_signatures = false;
    while at < bytes.len() {
        count += 1;
        ensure!(count <= 4096, "Too many certificate packets");
        let (tag, body) = packet(&bytes, &mut at)?;
        match tag {
            10 => ensure!(body == b"PGP", "Invalid marker packet"),
            6 => {
                ensure!(
                    primary.is_none(),
                    "A Certificate contains one primary public key"
                );
                primary = Some(public(body)?);
                phase = 1;
            }
            13 | 17 => {
                ensure!(
                    matches!(phase, 1 | 2),
                    "Identity outside public-key identity section"
                );
                if tag == 17 {
                    ensure!(!body.is_empty(), "Empty user attribute");
                }
                if tag == 13 {
                    std::str::from_utf8(body)?;
                    identities += 1;
                }
                phase = 2;
            }
            14 => {
                ensure!(
                    phase >= 2 && bound && primary.is_some_and(|p| p.0 == 4),
                    "Unbound or invalid subkey"
                );
                public(body)?;
                phase = 3;
                bound = false;
            }
            2 => {
                let (kind, mapped) = signature(body)?;
                ensure!(
                    match phase {
                        1 => matches!(kind, 0x1f | 0x20),
                        2 => matches!(kind, 0x10..=0x13 | 0x30),
                        3 => matches!(kind, 0x18 | 0x28),
                        _ => false,
                    },
                    "Signature does not match certificate section"
                );
                if phase == 3 && kind == 0x18 {
                    bound = true;
                }
                if let Some(value) = mapped {
                    if !signatures.contains(&value) {
                        signatures.push(value);
                    }
                } else {
                    unknown_signatures = true;
                }
            }
            60..=63 => {}
            _ => bail!("Packet is not part of a transferable public key"),
        }
    }
    let (_, algorithm, bits) = primary.ok_or_else(|| anyhow::anyhow!("No public primary key"))?;
    ensure!(
        identities > 0 && bound,
        "Missing identity or subkey binding"
    );
    Ok(Metadata {
        algorithm,
        bits,
        signatures,
        unknown_signatures,
    })
}
