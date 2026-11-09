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

//! Bounded binary TTLV codec. Lengths and padding are validated before allocation.
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_FRAME: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 16_384;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Node {
    pub tag: u32,
    pub value: Value,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Value {
    Structure(Vec<Node>),
    Integer(i32),
    LongInteger(i64),
    BigInteger(Vec<u8>),
    Enumeration(u32),
    Boolean(bool),
    TextString(String),
    ByteString(Vec<u8>),
    DateTime(i64),
    Interval(u32),
    DateTimeExtended(i64),
    Identifier(String),
    Reference(String),
    NameReference(String),
}
impl Drop for Value {
    fn drop(&mut self) {
        match self {
            Self::BigInteger(v) | Self::ByteString(v) => v.zeroize(),
            Self::TextString(v)
            | Self::Identifier(v)
            | Self::Reference(v)
            | Self::NameReference(v) => v.zeroize(),
            _ => {}
        }
    }
}
#[derive(Debug, Error)]
#[error("invalid TTLV: {0}")]
pub struct DecodeError(pub &'static str);
type Result<T> = std::result::Result<T, DecodeError>;
impl Node {
    pub fn structure(tag: u32, children: Vec<Self>) -> Self {
        Self {
            tag,
            value: Value::Structure(children),
        }
    }
    pub fn int(tag: u32, value: i32) -> Self {
        Self {
            tag,
            value: Value::Integer(value),
        }
    }
    pub fn long(tag: u32, value: i64) -> Self {
        Self {
            tag,
            value: Value::LongInteger(value),
        }
    }
    pub fn interval(tag: u32, value: u32) -> Self {
        Self {
            tag,
            value: Value::Interval(value),
        }
    }
    pub fn enumeration(tag: u32, value: u32) -> Self {
        Self {
            tag,
            value: Value::Enumeration(value),
        }
    }
    pub fn text(tag: u32, value: impl Into<String>) -> Self {
        Self {
            tag,
            value: Value::TextString(value.into()),
        }
    }
    pub fn bytes(tag: u32, value: impl Into<Vec<u8>>) -> Self {
        Self {
            tag,
            value: Value::ByteString(value.into()),
        }
    }
    pub fn identifier(tag: u32, value: impl Into<String>) -> Self {
        Self {
            tag,
            value: Value::Identifier(value.into()),
        }
    }
    pub fn reference(tag: u32, value: impl Into<String>) -> Self {
        Self {
            tag,
            value: Value::Reference(value.into()),
        }
    }
    pub fn name_reference(tag: u32, value: impl Into<String>) -> Self {
        Self {
            tag,
            value: Value::NameReference(value.into()),
        }
    }
    pub fn boolean(tag: u32, value: bool) -> Self {
        Self {
            tag,
            value: Value::Boolean(value),
        }
    }
    pub fn date(tag: u32, value: i64) -> Self {
        Self {
            tag,
            value: Value::DateTime(value),
        }
    }
    pub fn children(&self) -> Result<&[Node]> {
        if let Value::Structure(v) = &self.value {
            Ok(v)
        } else {
            Err(DecodeError("expected Structure"))
        }
    }
    pub fn get(&self, tag: u32) -> Option<&Node> {
        self.children().ok()?.iter().find(|n| n.tag == tag)
    }
    pub fn all(&self, tag: u32) -> impl Iterator<Item = &Node> {
        self.children()
            .unwrap_or(&[])
            .iter()
            .filter(move |n| n.tag == tag)
    }
    pub fn required(&self, tag: u32) -> Result<&Node> {
        let mut it = self.all(tag);
        let n = it.next().ok_or(DecodeError("missing field"))?;
        if it.next().is_some() {
            return Err(DecodeError("duplicate field"));
        }
        Ok(n)
    }
    pub fn number(&self) -> Result<u32> {
        match &self.value {
            Value::Integer(v) if *v >= 0 => Ok(*v as u32),
            Value::Enumeration(v) | Value::Interval(v) => Ok(*v),
            _ => Err(DecodeError("expected nonnegative number")),
        }
    }
    pub fn string(&self) -> Result<&str> {
        match &self.value {
            Value::TextString(v) => Ok(v),
            _ => Err(DecodeError("expected Text String")),
        }
    }
    /// Text carried by an identifier-like value; ordinary text fields remain strict.
    pub fn identifier_text(&self) -> Result<&str> {
        match &self.value {
            Value::TextString(v)
            | Value::Identifier(v)
            | Value::Reference(v)
            | Value::NameReference(v) => Ok(v),
            _ => Err(DecodeError("expected identifier text")),
        }
    }
    pub fn byte_string(&self) -> Result<&[u8]> {
        match &self.value {
            Value::ByteString(v) => Ok(v),
            _ => Err(DecodeError("expected Byte String")),
        }
    }
    pub fn flag(&self) -> Result<bool> {
        match &self.value {
            Value::Boolean(v) => Ok(*v),
            _ => Err(DecodeError("expected Boolean")),
        }
    }
    /// Encoded size without copying key material or allocating a wire buffer.
    pub fn encoded_len(&self) -> usize {
        let len = match &self.value {
            Value::Structure(fields) => fields
                .iter()
                .fold(0usize, |size, n| size.saturating_add(n.encoded_len())),
            Value::Integer(_) | Value::Enumeration(_) | Value::Interval(_) => 4,
            Value::LongInteger(_)
            | Value::Boolean(_)
            | Value::DateTime(_)
            | Value::DateTimeExtended(_) => 8,
            Value::BigInteger(v) => v.len().max(1),
            Value::ByteString(v) => v.len(),
            Value::TextString(v)
            | Value::Identifier(v)
            | Value::Reference(v)
            | Value::NameReference(v) => v.len(),
        };
        8usize.saturating_add(len.saturating_add(7) & !7)
    }
    pub fn encode(&self) -> Vec<u8> {
        let (kind, data) = match &self.value {
            Value::Structure(v) => {
                let mut data = Vec::new();
                for child in v {
                    let encoded = Zeroizing::new(child.encode());
                    data.extend_from_slice(&encoded);
                }
                (1, data)
            }
            Value::Integer(v) => (2, v.to_be_bytes().to_vec()),
            Value::LongInteger(v) => (3, v.to_be_bytes().to_vec()),
            // KMIP 1.0-1.4 9.1.1.4 and 2.x 10.1.2: sign-extend with leading
            // bytes to a multiple of eight; the padding is part of the value.
            Value::BigInteger(v) => {
                let fill = if v.first().is_some_and(|b| b & 0x80 != 0) {
                    0xff
                } else {
                    0
                };
                let mut data = vec![fill; v.len().max(1).next_multiple_of(8) - v.len()];
                data.extend_from_slice(v);
                (4, data)
            }
            Value::Enumeration(v) => (5, v.to_be_bytes().to_vec()),
            Value::Boolean(v) => (6, u64::from(*v).to_be_bytes().to_vec()),
            Value::TextString(v) => (7, v.as_bytes().to_vec()),
            Value::ByteString(v) => (8, v.clone()),
            Value::DateTime(v) => (9, v.to_be_bytes().to_vec()),
            Value::Interval(v) => (10, v.to_be_bytes().to_vec()),
            Value::DateTimeExtended(v) => (11, v.to_be_bytes().to_vec()),
            Value::Identifier(v) => (12, v.as_bytes().to_vec()),
            Value::Reference(v) => (13, v.as_bytes().to_vec()),
            Value::NameReference(v) => (14, v.as_bytes().to_vec()),
        };
        let data = Zeroizing::new(data);
        let mut result = Vec::with_capacity(8 + data.len().next_multiple_of(8));
        result.extend_from_slice(&self.tag.to_be_bytes()[1..]);
        result.push(kind);
        result.extend_from_slice(&(data.len() as u32).to_be_bytes());
        result.extend_from_slice(&data);
        result.resize(result.len().next_multiple_of(8), 0);
        result
    }
}
pub fn frame_length(header: &[u8; 8]) -> Result<usize> {
    let len = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if len > MAX_FRAME - 8 {
        return Err(DecodeError("frame exceeds limit"));
    }
    Ok(8 + len.next_multiple_of(8))
}
pub fn decode(data: &[u8]) -> Result<Node> {
    if data.len() > MAX_FRAME {
        return Err(DecodeError("frame exceeds limit"));
    }
    let mut nodes = 0;
    let (n, used) = parse(data, 0, &mut nodes)?;
    if used != data.len() {
        return Err(DecodeError("trailing data"));
    }
    Ok(n)
}
fn parse(data: &[u8], depth: usize, nodes: &mut usize) -> Result<(Node, usize)> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(DecodeError("complexity limit"));
    }
    let h: &[u8; 8] = data
        .get(..8)
        .ok_or(DecodeError("truncated header"))?
        .try_into()
        .unwrap();
    let total = frame_length(h)?;
    let len = u32::from_be_bytes(h[4..8].try_into().unwrap()) as usize;
    if data.len() < total {
        return Err(DecodeError("truncated value"));
    }
    let body = &data[8..8 + len];
    if data[8 + len..total].iter().any(|&b| b != 0) {
        return Err(DecodeError("nonzero padding"));
    }
    let tag = u32::from_be_bytes([0, h[0], h[1], h[2]]);
    if !(0x420001..=0x42ffff).contains(&tag) && !(0x540000..=0x54ffff).contains(&tag) {
        return Err(DecodeError("invalid tag namespace"));
    }
    let value = match h[3] {
        1 => {
            if !len.is_multiple_of(8) {
                return Err(DecodeError("unaligned Structure"));
            }
            let mut v = vec![];
            let mut pos = 0;
            while pos < len {
                let (n, used) = parse(&body[pos..], depth + 1, nodes)?;
                v.push(n);
                pos += used;
            }
            Value::Structure(v)
        }
        2 if len == 4 => Value::Integer(i32::from_be_bytes(body.try_into().unwrap())),
        3 if len == 8 => Value::LongInteger(i64::from_be_bytes(body.try_into().unwrap())),
        4 if len > 0 && len.is_multiple_of(8) => Value::BigInteger(body.to_vec()),
        5 if len == 4 => Value::Enumeration(u32::from_be_bytes(body.try_into().unwrap())),
        6 if len == 8 && body[..7] == [0; 7] && body[7] <= 1 => Value::Boolean(body[7] == 1),
        7 => Value::TextString(
            std::str::from_utf8(body)
                .map_err(|_| DecodeError("invalid UTF-8"))?
                .into(),
        ),
        8 => Value::ByteString(body.to_vec()),
        9 if len == 8 => Value::DateTime(i64::from_be_bytes(body.try_into().unwrap())),
        10 if len == 4 => Value::Interval(u32::from_be_bytes(body.try_into().unwrap())),
        11 if len == 8 => Value::DateTimeExtended(i64::from_be_bytes(body.try_into().unwrap())),
        12..=14 => {
            let value = std::str::from_utf8(body)
                .map_err(|_| DecodeError("invalid UTF-8"))?
                .to_owned();
            match h[3] {
                12 => Value::Identifier(value),
                13 => Value::Reference(value),
                _ => Value::NameReference(value),
            }
        }
        _ => return Err(DecodeError("unknown type or invalid length")),
    };
    Ok((Node { tag, value }, total))
}
