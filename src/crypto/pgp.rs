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

//! Bounded primary-key version inspection for external PGP share reconstruction.
//! This does not validate PGP signatures, ownership, passphrases or key strength.
use anyhow::{Result, bail, ensure};
use zeroize::Zeroizing;
const MAX: usize = 65536;
fn length(data: &[u8], at: &mut usize) -> Result<(usize, bool)> {
    let first = *data
        .get(*at)
        .ok_or_else(|| anyhow::anyhow!("Missing packet length"))?;
    *at += 1;
    Ok(match first {
        0..=191 => (first as usize, false),
        192..=223 => {
            let next = *data
                .get(*at)
                .ok_or_else(|| anyhow::anyhow!("Truncated packet length"))?;
            *at += 1;
            (((first as usize - 192) << 8) + next as usize + 192, false)
        }
        255 => {
            let bytes = data
                .get(*at..*at + 4)
                .ok_or_else(|| anyhow::anyhow!("Truncated packet length"))?;
            *at += 4;
            (
                u32::from_be_bytes(bytes.try_into().unwrap()) as usize,
                false,
            )
        }
        _ => (1usize << (first & 31), true),
    })
}
fn primary(data: &[u8]) -> Result<u32> {
    let mut at = 0;
    while at < data.len() {
        let header = data[at];
        at += 1;
        ensure!(header & 0x80 != 0, "Invalid PGP packet header");
        let tag;
        let mut count;
        let mut partial = false;
        if header & 0x40 != 0 {
            tag = header & 63;
            (count, partial) = length(data, &mut at)?;
        } else {
            tag = (header >> 2) & 15;
            let width = match header & 3 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 0,
            };
            if width == 0 {
                count = data.len() - at;
            } else {
                let bytes = data
                    .get(at..at + width)
                    .ok_or_else(|| anyhow::anyhow!("Truncated old packet length"))?;
                at += width;
                count = bytes.iter().fold(0usize, |n, b| (n << 8) | *b as usize);
            }
        }
        let first = data.get(at).copied();
        let mut total = 0usize;
        loop {
            at = at
                .checked_add(count)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| anyhow::anyhow!("Packet exceeds PGP data"))?;
            total = total
                .checked_add(count)
                .ok_or_else(|| anyhow::anyhow!("PGP length overflow"))?;
            if !partial {
                break;
            }
            (count, partial) = length(data, &mut at)?;
        }
        if matches!(tag, 5 | 6) {
            ensure!(total > 0, "Empty primary-key packet");
            return match first {
                Some(v @ (3 | 4)) => Ok(v as u32),
                _ => bail!("Unsupported primary-key version"),
            };
        }
    }
    bail!("No PGP primary-key packet")
}
pub fn version(material: &[u8]) -> Result<u32> {
    ensure!(
        !material.is_empty() && material.len() <= MAX,
        "PGP inspection size limit"
    );
    if material[0] & 0x80 != 0 {
        return primary(material);
    }
    let text = std::str::from_utf8(material)?;
    let mut start = false;
    let mut ending = "";
    let mut body = false;
    let mut end = false;
    let mut encoded = Zeroizing::new(String::new());
    for line in text.lines().map(str::trim) {
        if !start {
            if matches!(
                line,
                "-----BEGIN PGP PUBLIC KEY BLOCK-----" | "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            ) {
                start = true;
                ending = if line.contains("PUBLIC") {
                    "-----END PGP PUBLIC KEY BLOCK-----"
                } else {
                    "-----END PGP PRIVATE KEY BLOCK-----"
                };
            }
        } else if !body {
            if line.is_empty() {
                body = true;
            }
        } else if line == ending {
            end = true;
            break;
        } else if !line.starts_with('=') {
            ensure!(
                line.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
                "Invalid armor encoding"
            );
            encoded.push_str(line);
        }
    }
    ensure!(
        start && body && end && !encoded.is_empty(),
        "Incomplete PGP armor"
    );
    let decoded = Zeroizing::new(openssl::base64::decode_block(&encoded)?);
    primary(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspect_real_armored_fixtures_and_old_and_new_packet_headers() {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/openpgp.json")).unwrap();
        for (name, expected) in [("v3_public", 3), ("v4_public", 4), ("v4_private", 4)] {
            assert_eq!(
                version(fixtures[name].as_str().unwrap().as_bytes()).unwrap(),
                expected
            );
        }
        for expected in [3u8, 4] {
            // Only the packet's version is interpreted. These are header vectors,
            // not complete cryptographic keys or signature validation fixtures.
            for bytes in [
                vec![0x98, 1, expected],
                vec![0x99, 0, 1, expected],
                vec![0x9a, 0, 0, 0, 1, expected],
                vec![0x9b, expected],
                vec![0xc6, 1, expected],
                vec![0xc5, 255, 0, 0, 0, 1, expected],
                vec![0xca, 3, b'P', b'G', b'P', 0xc6, 1, expected],
            ] {
                assert_eq!(version(&bytes).unwrap(), expected as u32);
            }
            let mut two_octet = vec![0xc6, 192, 0, expected];
            two_octet.resize(195, 0);
            assert_eq!(version(&two_octet).unwrap(), expected as u32);
            let mut partial = vec![0xc6, 233, expected]; // 512-octet partial chunk.
            partial.resize(514, 0);
            partial.extend([1, 0]);
            assert_eq!(version(&partial).unwrap(), expected as u32);
        }
    }
    #[test]
    fn malformed_headers_armor_and_size_are_rejected_without_panics() {
        for bytes in [
            vec![],
            vec![0],
            vec![0x98],
            vec![0x99, 0],
            vec![0x9a, 0, 0, 0],
            vec![0xc6],
            vec![0xc6, 192],
            vec![0xc6, 255, 0, 0, 0],
            vec![0xc6, 0],
            vec![0xc6, 2, 4],
            vec![0xc6, 1, 5],
            vec![0xc6, 233, 4],
            vec![0xca, 3, b'P', b'G', b'P'],
            vec![0xff; MAX + 1],
        ] {
            assert!(version(&bytes).is_err());
        }
        for text in [
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxgEE\n-----END PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxgEE",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----",
        ] {
            assert!(version(text.as_bytes()).is_err());
        }
        // Deterministic malformed input and every truncation of a valid armor.
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/openpgp.json")).unwrap();
        let armor = fixture["v4_private"].as_str().unwrap().as_bytes();
        for end in 0..armor.len() - 1 {
            let _ = version(&armor[..end]);
        }
        let mut state = 0x4b4d4950u32;
        for len in 0..2048 {
            let bytes = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                    (state >> 24) as u8
                })
                .collect::<Vec<_>>();
            let _ = version(&bytes);
        }
    }
}
