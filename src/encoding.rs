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

//! Profile-defined text encodings, sharing the exact binary TTLV data model.
use crate::{
    tags::*,
    ttlv::{self, Node, Value},
};
use anyhow::{Result, bail, ensure};
pub use options::{
    BooleanForm, DateTimeForm, EnumerationForm, MaskForm, NameForm, NumberForm, Preset,
    TextEncoding, TextEncodingArgs,
};
use serde::{
    Deserialize,
    de::{self, SeqAccess, Visitor},
};
use std::{collections::BTreeMap, fmt, sync::OnceLock};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_TEXT_FRAME: usize = 8 * ttlv::MAX_FRAME;
const MAX_DEPTH: usize = 32;
pub(crate) const MAX_NODES: usize = 16_384;
const SAFE_NUMBER: i64 = 1i64 << 52;
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Ttlv,
    Json,
    Xml,
}
impl Format {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Ttlv => "application/octet-stream",
            Self::Json => "application/json",
            Self::Xml => "text/xml",
        }
    }
    pub fn decode(self, data: &[u8]) -> Result<Node> {
        if self == Self::Ttlv {
            return Ok(ttlv::decode(data)?);
        }
        ensure!(data.len() <= MAX_TEXT_FRAME, "text frame too large");
        let raw = if self == Self::Json {
            serde_json::from_slice::<RawNode>(data)?
        } else {
            xml::parse(data)?
        };
        let version = message_version(&raw);
        let mut count = 0;
        let node = convert(&raw, self, version, None, 0, &mut count)?;
        ensure!(
            node.encoded_len() <= ttlv::MAX_FRAME,
            "decoded frame too large"
        );
        Ok(node)
    }
    /// Encode with the default response forms (`TextEncoding::default()`).
    pub fn encode(self, node: &Node) -> Result<Zeroizing<Vec<u8>>> {
        self.encode_with(node, &TextEncoding::default())
    }
    /// Encode with the configured response forms of the text encodings.
    pub fn encode_with(self, node: &Node, forms: &TextEncoding) -> Result<Zeroizing<Vec<u8>>> {
        checked_node_count(node)?;
        ensure!(
            node.encoded_len() <= ttlv::MAX_FRAME,
            "binary equivalent too large"
        );
        if self == Self::Ttlv {
            return Ok(Zeroizing::new(node.encode()));
        }
        let mut out = Zeroizing::new(Vec::new());
        if self == Self::Json {
            write_json(node, &mut out, node_version(node), None, forms)?
        } else {
            xml::write(node, &mut out, forms)?
        }
        ensure!(out.len() <= MAX_TEXT_FRAME, "text response too large");
        Ok(out)
    }
}
#[derive(Deserialize)]
struct Registry {
    tags: BTreeMap<String, u32>,
    enums: BTreeMap<String, BTreeMap<String, u32>>,
}
fn registries() -> &'static BTreeMap<String, Registry> {
    static REG: OnceLock<BTreeMap<String, Registry>> = OnceLock::new();
    REG.get_or_init(|| {
        serde_json::from_str(include_str!("wire_registry.json")).expect("generated wire registry")
    })
}
/// Whether the pinned specification of `version` defines `tag`.
pub(crate) fn known_tag(tag: u32, version: &str) -> bool {
    registries()
        .get(version)
        .is_some_and(|registry| registry.tags.values().any(|t| *t == tag))
}
/// Numeric validation uses the pinned version's enumeration, independent of the
/// client's choice of binary or symbolic encoding. Vendor values remain opaque.
pub(crate) fn known_enumeration(tag: u32, value: u32, version: &str) -> bool {
    if (0x80000000..=0x8fffffff).contains(&value) {
        return true;
    }
    registries().get(version).is_some_and(|registry| {
        registry.tags.iter().any(|(name, number)| {
            *number == tag
                && registry
                    .enums
                    .get(name)
                    .is_some_and(|values| values.values().any(|v| *v == value))
        })
    })
}
fn tag(text: &str) -> Result<u32> {
    if let Some(hex) = text.strip_prefix("0x") {
        ensure!(hex.len() == 6, "tag width invalid");
        return Ok(u32::from_str_radix(hex, 16)?);
    }
    if text.len() == 7
        && text.starts_with(['x', 'X'])
        && text[1..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Ok(u32::from_str_radix(&text[1..], 16)?);
    }
    registries()
        .values()
        .find_map(|r| r.tags.get(text).copied())
        .ok_or_else(|| anyhow::anyhow!("unknown tag name"))
}
/// Enumeration tables whose normalized title is not the tag name, for example
/// "Recommended Curve Enumeration" for Recommended Curve (1.x section 9.1.3.2,
/// 2.x section 11). Profiles 5.4.1/5.5.1 map every enumeration by name.
const ENUMERATION_TABLES: [(&str, &[&str]); 6] = [
    ("RecommendedCurve", &["RecommendedCurveEnumeration"]),
    ("DestroyAction", &["DestroyActionType"]),
    ("ObjectGroupMember", &["ObjectGroupMemberOption"]),
    ("NISTKeyType", &["NISTKeyTypeEnumeration"]),
    ("ProfileName", &["ProfileNameType", "Profile"]),
    ("UniqueIdentifier", &["UniqueIdentifierEnumerations"]),
];
fn symbolic(tag: u32, name: &str, version: Option<&str>) -> Result<u32> {
    if tag == ATTRIBUTE_REFERENCE {
        return tag_number(name);
    }
    let lookup = |r: &Registry| {
        r.tags
            .iter()
            .filter(|(_, value)| **value == tag)
            .find_map(|(key, _)| {
                let tables = ENUMERATION_TABLES
                    .iter()
                    .find(|(tag_name, _)| tag_name == key)
                    .map_or(&[][..], |(_, tables)| *tables);
                std::iter::once(key.as_str())
                    .chain(tables.iter().copied())
                    .find_map(|table| r.enums.get(table).and_then(|e| e.get(name).copied()))
            })
    };
    version
        .and_then(|v| registries().get(v))
        .and_then(lookup)
        .or_else(|| {
            if version.is_none() {
                registries().values().find_map(lookup)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("unknown enumeration name"))
}
fn tag_number(name: &str) -> Result<u32> {
    tag(name)
}
fn attr_tag(name: &str) -> Option<u32> {
    tag(&normalize(name)).ok()
}
fn normalize(name: &str) -> String {
    // Attribute names used as text remain spaced in KMIP 1.x. Their canonical
    // tag names contain words, digits and underscores; no enum spelling is guessed.
    name.split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}
fn structure_kind() -> String {
    "Structure".to_owned()
}
fn optional_text<'de, D: de::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    tag: String,
    #[serde(default = "structure_kind", rename = "type")]
    kind: String,
    #[serde(default, rename = "name", deserialize_with = "optional_text")]
    _name: Option<String>,
    value: RawValue,
}
enum RawValue {
    Array(Vec<RawNode>),
    String(String),
    Number(serde_json::Number),
    Bool(bool),
    Null,
}
impl Drop for RawValue {
    fn drop(&mut self) {
        if let Self::String(s) = self {
            s.zeroize()
        }
    }
}
impl<'de> Deserialize<'de> for RawValue {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("TTLV scalar or child array")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = vec![];
                while let Some(n) = seq.next_element()? {
                    if values.len() >= MAX_NODES {
                        return Err(de::Error::custom("too many nodes"));
                    }
                    values.push(n)
                }
                Ok(RawValue::Array(values))
            }
            fn visit_str<E: de::Error>(self, s: &str) -> std::result::Result<Self::Value, E> {
                Ok(RawValue::String(s.to_owned()))
            }
            fn visit_string<E: de::Error>(self, s: String) -> std::result::Result<Self::Value, E> {
                Ok(RawValue::String(s))
            }
            fn visit_i64<E: de::Error>(self, n: i64) -> std::result::Result<Self::Value, E> {
                Ok(RawValue::Number(n.into()))
            }
            fn visit_u64<E: de::Error>(self, n: u64) -> std::result::Result<Self::Value, E> {
                Ok(RawValue::Number(n.into()))
            }
            fn visit_f64<E: de::Error>(self, n: f64) -> std::result::Result<Self::Value, E> {
                if n.is_finite() && n.fract() == 0.0 && n.abs() < (SAFE_NUMBER as f64) {
                    Ok(RawValue::Number((n as i64).into()))
                } else {
                    Err(de::Error::custom("integer precision invalid"))
                }
            }
            fn visit_bool<E: de::Error>(self, b: bool) -> std::result::Result<Self::Value, E> {
                Ok(RawValue::Bool(b))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(RawValue::Null)
            }
        }
        d.deserialize_any(V)
    }
}
fn children(raw: &RawNode) -> &[RawNode] {
    match &raw.value {
        RawValue::Array(c) => c,
        _ => &[],
    }
}
fn message_version(raw: &RawNode) -> Option<&'static str> {
    let root = if matches!(tag(&raw.tag).ok(), Some(REQUEST_MESSAGE | RESPONSE_MESSAGE)) {
        children(raw)
            .iter()
            .find(|n| matches!(tag(&n.tag).ok(), Some(REQUEST_HEADER | RESPONSE_HEADER)))?
    } else {
        raw
    };
    let version = children(root)
        .iter()
        .find(|n| tag(&n.tag).ok() == Some(PROTOCOL_VERSION))?;
    let number = |tag_number| {
        children(version)
            .iter()
            .find(|n| tag(&n.tag).ok() == Some(tag_number))
            .and_then(|n| unsigned(&n.value, 4, Format::Xml).ok())
    };
    version_name(
        number(PROTOCOL_VERSION_MAJOR)?,
        number(PROTOCOL_VERSION_MINOR)?,
    )
}
/// The protocol version a message node declares in its header.
fn node_version(n: &Node) -> Option<&'static str> {
    let version = n
        .get(RESPONSE_HEADER)
        .or_else(|| n.get(REQUEST_HEADER))?
        .get(PROTOCOL_VERSION)?;
    version_name(
        version.get(PROTOCOL_VERSION_MAJOR)?.number().ok()?.into(),
        version.get(PROTOCOL_VERSION_MINOR)?.number().ok()?.into(),
    )
}
fn version_name(major: u64, minor: u64) -> Option<&'static str> {
    match (major, minor) {
        (1, 0) => Some("1.0"),
        (1, 1) => Some("1.1"),
        (1, 2) => Some("1.2"),
        (1, 3) => Some("1.3"),
        (1, 4) => Some("1.4"),
        (2, 0) => Some("2.0"),
        (2, 1) => Some("2.1"),
        (3, 0) => Some("3.0"),
        _ => None,
    }
}
fn string(value: &RawValue) -> Result<&str> {
    if let RawValue::String(s) = value {
        Ok(s)
    } else {
        bail!("string value required")
    }
}
fn hex(value: &str, bytes: usize) -> Result<u64> {
    let s = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex prefix required"))?;
    ensure!(
        s.len() == bytes * 2 && s.bytes().all(|b| b.is_ascii_hexdigit()),
        "hex width invalid"
    );
    Ok(u64::from_str_radix(s, 16)?)
}
fn unsigned(value: &RawValue, bytes: usize, format: Format) -> Result<u64> {
    let n = match value {
        RawValue::Number(n) => n
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("unsigned integer required"))?,
        RawValue::String(s) if s.starts_with("0x") => hex(s, bytes)?,
        RawValue::String(s) if format == Format::Xml => s.trim().parse()?,
        _ => bail!("unsigned integer required"),
    };
    ensure!(bytes == 8 || n <= u32::MAX as u64, "integer overflow");
    Ok(n)
}
fn signed(value: &RawValue, bytes: usize, format: Format) -> Result<i64> {
    let n = match value {
        RawValue::Number(n) => {
            let n = n
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("signed integer required"))?;
            if bytes == 8 {
                ensure!(
                    n.unsigned_abs() < (SAFE_NUMBER as u64),
                    "unsafe JSON integer precision"
                )
            }
            n
        }
        RawValue::String(s) if s.starts_with("0x") => {
            let n = hex(s, bytes)?;
            if bytes == 4 {
                n as u32 as i32 as i64
            } else {
                n as i64
            }
        }
        RawValue::String(s) if format == Format::Xml => s.trim().parse()?,
        _ => bail!("signed integer required"),
    };
    ensure!(bytes == 8 || i32::try_from(n).is_ok(), "integer overflow");
    Ok(n)
}
fn enum_value(value: &RawValue, tag: u32, version: Option<&str>, format: Format) -> Result<u32> {
    match value {
        RawValue::String(s) if !s.starts_with("0x") => symbolic(
            tag,
            if format == Format::Xml { s.trim() } else { s },
            version,
        ),
        _ => Ok(unsigned(value, 4, format)? as u32),
    }
}
pub(crate) fn is_mask(tag: u32) -> bool {
    [
        CRYPTOGRAPHIC_USAGE_MASK,
        STORAGE_STATUS_MASK,
        PROTECTION_STORAGE_MASK,
    ]
    .contains(&tag)
}
/// A mask component "as a 32-bit unsigned big-endian hex string" (Profiles
/// 2.1 sections 5.4.1.6.4 and 5.5.1.6.4). The same sections' own example
/// "0x0000008" has seven digits, so up to eight digits are accepted here.
fn mask_hex(part: &str) -> Result<u32> {
    let digits = part
        .strip_prefix("0x")
        .ok_or_else(|| anyhow::anyhow!("hex prefix required"))?;
    ensure!(
        (1..=8).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_hexdigit()),
        "mask hex width invalid"
    );
    Ok(u32::from_str_radix(digits, 16)?)
}
/// The component text of a mask (docs/interpretations.md, symbolic masks in
/// XML): the version's component names separated by
/// `separator` (XML: space, JSON: '|'), in bit order, with any
/// bits the version does not name as one "0x%08X" component, and zero as
/// "0x00000000". Profiles 2.1 sections 5.4.1.6.4 and 5.5.1.6.4 allow names or
/// hex components; every OASIS XML trace and OVH's kmip-go write names, and
/// IBM's XML decoder rejects decimal masks. `TextEncoding` selects the form.
pub(crate) fn mask_text(tag: u32, value: i32, version: Option<&str>, separator: &str) -> String {
    let bits = value as u32;
    // A message without a known version names nothing: all bits are hex.
    let names = version.and_then(|v| registries().get(v)).and_then(|r| {
        r.tags
            .iter()
            .find(|(_, number)| **number == tag)
            .and_then(|(name, _)| r.enums.get(name))
    });
    let mut parts = vec![];
    let mut unnamed = bits;
    for bit in (0..32).map(|i| 1u32 << i).filter(|b| bits & b != 0) {
        if let Some((name, _)) = names.and_then(|n| n.iter().find(|(_, v)| **v == bit)) {
            parts.push(name.clone());
            unnamed &= !bit;
        }
    }
    if unnamed != 0 || parts.is_empty() {
        parts.push(format!("0x{unnamed:08X}"));
    }
    parts.join(separator)
}
fn mask(value: &RawValue, tag: u32, version: Option<&str>, format: Format) -> Result<i32> {
    if let RawValue::String(s) = value {
        // An empty component list denotes no bits. XML's xsd:list permits an
        // empty sequence and collapses only the XML Schema whitespace set.
        if s.is_empty()
            || format == Format::Xml && s.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Ok(0);
        }
        if format == Format::Xml
            && let Ok(n) = s.trim().parse::<i32>()
        {
            return Ok(n);
        }
        let parts = if format == Format::Json {
            s.split('|').collect::<Vec<_>>()
        } else {
            s.split_whitespace().collect()
        };
        ensure!(!parts.is_empty(), "empty mask");
        let mut result = 0;
        for part in parts {
            result |= if part.starts_with("0x") {
                mask_hex(part)?
            } else {
                symbolic(tag, part, version)?
            };
        }
        return Ok(result as i32);
    }
    Ok(signed(value, 4, format)? as i32)
}
fn convert(
    raw: &RawNode,
    format: Format,
    version: Option<&str>,
    attribute: Option<u32>,
    depth: usize,
    count: &mut usize,
) -> Result<Node> {
    ensure!(
        depth <= MAX_DEPTH && *count < MAX_NODES,
        "node resource limit"
    );
    *count += 1;
    let tag = tag(&raw.tag)?;
    let effective = if tag == ATTRIBUTE_VALUE {
        attribute.unwrap_or(tag)
    } else {
        tag
    };
    let value = match raw.kind.as_str() {
        "Structure" => {
            let nodes = match &raw.value {
                RawValue::Array(c) => c.as_slice(),
                RawValue::Null => &[],
                _ => bail!("structure child array required"),
            };
            let attr = if tag == ATTRIBUTE {
                nodes
                    .iter()
                    .find(|n| crate::encoding::tag(&n.tag).ok() == Some(ATTRIBUTE_NAME))
                    .and_then(|n| string(&n.value).ok())
                    .and_then(attr_tag)
            } else {
                None
            };
            Value::Structure(
                nodes
                    .iter()
                    .map(|n| convert(n, format, version, attr, depth + 1, count))
                    .collect::<Result<_>>()?,
            )
        }
        "Integer" => Value::Integer(if is_mask(effective) {
            mask(&raw.value, effective, version, format)?
        } else {
            signed(&raw.value, 4, format)? as i32
        }),
        "LongInteger" => Value::LongInteger(signed(&raw.value, 8, format)?),
        "BigInteger" => {
            let data = match &raw.value {
                RawValue::Number(_) => signed(&raw.value, 8, format)?.to_be_bytes().to_vec(),
                RawValue::String(s) => {
                    let s = if format == Format::Json {
                        s.strip_prefix("0x")
                            .ok_or_else(|| anyhow::anyhow!("big integer hex prefix required"))?
                    } else {
                        s.trim()
                    };
                    ensure!(
                        !s.is_empty() && s.len() % 16 == 0,
                        "big integer width invalid"
                    );
                    hex::decode(s)?
                }
                _ => bail!("big integer required"),
            };
            Value::BigInteger(data)
        }
        "Enumeration" => Value::Enumeration(enum_value(&raw.value, effective, version, format)?),
        "Boolean" => Value::Boolean(match &raw.value {
            RawValue::Bool(b) if format == Format::Json => *b,
            RawValue::String(s) if format == Format::Xml => match s.trim() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => bail!("invalid Boolean"),
            },
            RawValue::String(s) => match hex(s, 8)? {
                0 => false,
                1 => true,
                _ => bail!("invalid Boolean"),
            },
            _ => bail!("Boolean required"),
        }),
        "TextString" => Value::TextString(string(&raw.value)?.to_owned()),
        "ByteString" => {
            let s = string(&raw.value)?;
            Value::ByteString(hex::decode(if format == Format::Xml {
                s.trim()
            } else {
                s
            })?)
        }
        "DateTime" => {
            let s = string(&raw.value)?;
            Value::DateTime(if format == Format::Json && s.starts_with("0x") {
                hex(s, 8)? as i64
            } else {
                date::parse(s.trim())?
            })
        }
        "Interval" => Value::Interval(unsigned(&raw.value, 4, format)? as u32),
        "DateTimeExtended" => Value::DateTimeExtended(signed(&raw.value, 8, format)?),
        "Identifier" => Value::Identifier(string(&raw.value)?.to_owned()),
        "Reference" => Value::Reference(string(&raw.value)?.to_owned()),
        "NameReference" => Value::NameReference(string(&raw.value)?.to_owned()),
        _ => bail!("unknown TTLV type"),
    };
    let n = Node { tag, value };
    ensure!(
        n.encoded_len() <= ttlv::MAX_FRAME,
        "decoded frame too large"
    );
    Ok(n)
}
/// Count the complete tree while applying the encoder's structural checks.
/// Protocol budgeting uses this for binary responses too: the binary decoder
/// has the same node and depth bounds even though `Node::encode` is unchecked.
pub(crate) fn checked_node_count(node: &Node) -> Result<usize> {
    let mut count = 0;
    check(node, 0, &mut count)?;
    Ok(count)
}
fn check(n: &Node, depth: usize, count: &mut usize) -> Result<()> {
    ensure!(
        n.tag <= 0xffffff && depth <= MAX_DEPTH && *count < MAX_NODES,
        "node resource limit"
    );
    *count += 1;
    if let Value::Structure(children) = &n.value {
        for n in children {
            check(n, depth + 1, count)?
        }
    }
    if let Value::BigInteger(b) = &n.value {
        ensure!(!b.is_empty() && b.len() % 8 == 0, "invalid big integer")
    }
    Ok(())
}
fn kind(value: &Value) -> &'static str {
    match value {
        Value::Structure(_) => "Structure",
        Value::Integer(_) => "Integer",
        Value::LongInteger(_) => "LongInteger",
        Value::BigInteger(_) => "BigInteger",
        Value::Enumeration(_) => "Enumeration",
        Value::Boolean(_) => "Boolean",
        Value::TextString(_) => "TextString",
        Value::ByteString(_) => "ByteString",
        Value::DateTime(_) => "DateTime",
        Value::Interval(_) => "Interval",
        Value::DateTimeExtended(_) => "DateTimeExtended",
        Value::Identifier(_) => "Identifier",
        Value::Reference(_) => "Reference",
        Value::NameReference(_) => "NameReference",
    }
}
/// The XML attribute text of a non-structure value without a symbolic form
/// (Profiles 2.1 sections 5.4.1.6.3-5.4.1.6.13 give one form per type).
fn xml_scalar(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Integer(n) => n.to_string(),
        Value::Interval(n) => n.to_string(),
        Value::LongInteger(n) | Value::DateTimeExtended(n) => n.to_string(),
        Value::BigInteger(b) => hex::encode(b),
        Value::Enumeration(n) => format!("0x{n:08x}"),
        Value::Boolean(b) => b.to_string(),
        Value::TextString(s)
        | Value::Identifier(s)
        | Value::Reference(s)
        | Value::NameReference(s) => s.clone(),
        Value::ByteString(b) => hex::encode(b),
        Value::DateTime(n) => date::format(*n),
        Value::Structure(_) => bail!("scalar required"),
    })
}
/// A JSON Number that holds `n` exactly: Profiles 2.1 sections 5.5.1.6.5,
/// 5.5.1.6.6 and 5.5.1.6.13 require hex for magnitudes at or above 2^52.
fn safe_number(n: i64, form: NumberForm) -> Option<serde_json::Value> {
    (form == NumberForm::Number && n.unsigned_abs() < (SAFE_NUMBER as u64)).then(|| n.into())
}
/// The JSON value of a non-structure node in the configured forms. `effective`
/// is the tag that determines its enumeration or mask table.
fn json_scalar(
    n: &Node,
    effective: u32,
    version: Option<&str>,
    forms: &TextEncoding,
) -> Result<serde_json::Value> {
    use serde_json::Value as J;
    Ok(match &n.value {
        Value::Integer(m) if is_mask(effective) => match forms.json_masks {
            MaskForm::Number => J::from(*m),
            MaskForm::Hex => J::from(format!("0x{:08x}", *m as u32)),
            MaskForm::Names => J::from(mask_text(effective, *m, version, "|")),
        },
        Value::Integer(m) => match forms.json_integers {
            NumberForm::Number => J::from(*m),
            NumberForm::Hex => J::from(format!("0x{:08x}", *m as u32)),
        },
        Value::Interval(m) => match forms.json_intervals {
            NumberForm::Number => J::from(*m),
            NumberForm::Hex => J::from(format!("0x{m:08x}")),
        },
        Value::LongInteger(m) => safe_number(*m, forms.json_long_integers)
            .unwrap_or_else(|| J::from(format!("0x{:016x}", *m as u64))),
        Value::DateTimeExtended(m) => safe_number(*m, forms.json_date_time_extended)
            .unwrap_or_else(|| J::from(format!("0x{:016x}", *m as u64))),
        // A Number decodes to exactly eight bytes, so only an eight-byte
        // value keeps its width as a Number.
        Value::BigInteger(b) => b
            .as_slice()
            .try_into()
            .ok()
            .and_then(|bytes| safe_number(i64::from_be_bytes(bytes), forms.json_big_integers))
            .unwrap_or_else(|| J::from(format!("0x{}", hex::encode(b)))),
        Value::Enumeration(value) => match (
            forms.json_enumerations,
            enum_name(effective, *value, version),
        ) {
            (EnumerationForm::Name, Some(name)) => J::from(name),
            (EnumerationForm::Number, Some(_)) => J::from(*value),
            _ => J::from(format!("0x{value:08x}")),
        },
        Value::Boolean(b) => match forms.json_booleans {
            BooleanForm::Boolean => J::from(*b),
            BooleanForm::Hex => J::from(format!("0x{:016x}", u64::from(*b))),
        },
        Value::TextString(s)
        | Value::Identifier(s)
        | Value::Reference(s)
        | Value::NameReference(s) => J::from(s.as_str()),
        Value::ByteString(b) => J::from(hex::encode(b)),
        Value::DateTime(t) => J::from(match forms.json_date_times {
            DateTimeForm::Hex => format!("0x{:016x}", *t as u64),
            DateTimeForm::Text => date::format(*t),
        }),
        Value::Structure(_) => bail!("scalar required"),
    })
}
/// The edition's name of an enumeration value, if `version` names it. A 2.x/3.0
/// Attribute Reference enumerates tags; a 1.x Attribute Value's `effective`
/// tag comes from its Attribute Name.
fn enum_name(effective: u32, value: u32, version: Option<&str>) -> Option<&'static str> {
    names::edition_enum(effective, value, version?)
}
/// The tag an Attribute Value's enumeration or mask follows: the 1.x
/// Attribute Name's tag (`attribute`) when present.
fn effective_tag(n: &Node, attribute: Option<u32>) -> u32 {
    if n.tag == ATTRIBUTE_VALUE {
        attribute.unwrap_or(n.tag)
    } else {
        n.tag
    }
}
/// The tag of the 1.x Attribute Name inside an Attribute structure.
fn attribute_context(n: &Node) -> Option<u32> {
    if n.tag == ATTRIBUTE {
        n.get(ATTRIBUTE_NAME)
            .and_then(|name| name.string().ok())
            .and_then(attr_tag)
    } else {
        None
    }
}
/// JSON in the configured forms (`TextEncoding`). Names come from `version`,
/// the message's protocol version (Profiles 2.1 sections 5.5.1.3 and
/// 5.5.1.6.7; docs/interpretations.md); anything that edition does
/// not name, and every tag of a message without a known version, is written in
/// hex. `attribute` is the tag a 1.x Attribute Name designates, for its
/// Attribute Value.
fn write_json(
    n: &Node,
    out: &mut Vec<u8>,
    version: Option<&str>,
    attribute: Option<u32>,
    forms: &TextEncoding,
) -> Result<()> {
    use std::io::Write;
    match version
        .filter(|_| forms.json_tags == NameForm::Name)
        .and_then(|v| names::edition_tag(n.tag, v))
    {
        Some(name) => write!(out, "{{\"tag\":\"{name}\"")?,
        None => write!(out, "{{\"tag\":\"0x{:06x}\"", n.tag)?,
    }
    write!(out, ",\"type\":\"{}\",\"value\":", kind(&n.value))?;
    if let Value::Structure(children) = &n.value {
        let attr = attribute_context(n);
        out.push(b'[');
        for (i, n) in children.iter().enumerate() {
            if i > 0 {
                out.push(b',')
            }
            write_json(n, out, version, attr, forms)?
        }
        out.push(b']')
    } else {
        let mut value = json_scalar(n, effective_tag(n, attribute), version, forms)?;
        let written = serde_json::to_writer(&mut *out, &value);
        if let serde_json::Value::String(s) = &mut value {
            s.zeroize()
        }
        written?
    }
    out.push(b'}');
    ensure!(out.len() <= MAX_TEXT_FRAME, "text response too large");
    Ok(())
}
mod date;
mod names;
mod options;
mod xml;
