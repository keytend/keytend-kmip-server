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

//! Test oracle: the binary TTLV length of a JSON or XML message, computed from
//! the received text without the server's decoder, `Node` or `encoded_len`.
//! Profiles 1.3-2.1 and draft 3.0 sections 5.4 and 5.5 interpret Maximum
//! Response Size as this length. Each item is an 8-byte tag/type/length header
//! followed by its value padded to a multiple of eight bytes (KMIP 1.4
//! section 9.1.1; 2.1 section 15).
#![allow(dead_code)]

use keytend_kmip_server::encoding::Format;

fn padded(len: usize) -> usize {
    8 + len.div_ceil(8) * 8
}
fn hex_bytes(text: &str) -> usize {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    assert!(hex.len().is_multiple_of(2), "odd hex value {text}");
    hex.len() / 2
}
/// Length of a primitive from its KMIP type name and textual value.
fn leaf(kind: &str, value: Option<&str>) -> usize {
    match kind {
        "Integer" | "Enumeration" | "Interval" | "LongInteger" | "Boolean" | "DateTime"
        | "DateTimeExtended" => 16,
        // A Big Integer is sign-extended to a multiple of eight bytes; a JSON
        // number (no text) fits in one eight-byte block.
        "BigInteger" => value.map_or(16, |v| {
            let len = hex_bytes(v);
            assert!(len.is_multiple_of(8), "unpadded Big Integer {v}");
            8 + len
        }),
        "ByteString" => padded(hex_bytes(value.unwrap_or(""))),
        "TextString" | "Identifier" | "Reference" | "NameReference" => {
            padded(value.unwrap_or("").len())
        }
        other => panic!("unknown KMIP type {other}"),
    }
}
fn json(node: &serde_json::Value) -> usize {
    let kind = node
        .get("type")
        .map_or("Structure", |t| t.as_str().expect("type is text"));
    let value = node.get("value");
    if kind == "Structure" {
        return 8 + value
            .and_then(|v| v.as_array())
            .map_or(0, |items| items.iter().map(json).sum());
    }
    let text = value.and_then(|v| v.as_str()).map(str::to_owned);
    // Numbers, booleans and masks have fixed widths, so their text is unused.
    leaf(kind, text.as_deref())
}
fn xml(data: &[u8]) -> usize {
    use quick_xml::{XmlVersion, events::Event};
    let mut reader = quick_xml::Reader::from_reader(data);
    let mut stack: Vec<usize> = vec![0];
    loop {
        match reader.read_event().expect("well-formed XML") {
            Event::Start(element) => {
                // Only structures have child elements.
                assert!(
                    element.attributes().all(|a| {
                        let a = a.unwrap();
                        a.key.into_inner() != "type" || a.value.as_ref() == "Structure"
                    }),
                    "typed element with content"
                );
                stack.push(0);
            }
            Event::End(_) => {
                let children = stack.pop().unwrap();
                *stack.last_mut().unwrap() += 8 + children;
            }
            Event::Empty(element) => {
                let mut kind = String::from("Structure");
                let mut value = None;
                for attr in element.attributes() {
                    let attr = attr.unwrap();
                    let text = attr
                        .normalized_value(XmlVersion::Implicit1_0)
                        .unwrap()
                        .into_owned();
                    match attr.key.into_inner() {
                        "type" => kind = text,
                        "value" => value = Some(text),
                        _ => {}
                    }
                }
                *stack.last_mut().unwrap() += if kind == "Structure" {
                    8
                } else {
                    leaf(&kind, value.as_deref())
                };
            }
            Event::Eof => break,
            _ => {}
        }
    }
    assert_eq!(stack.len(), 1, "unbalanced XML");
    stack[0]
}
/// Binary TTLV-equivalent length of an encoded message in `format`.
pub fn ttlv_equivalent(format: Format, bytes: &[u8]) -> usize {
    match format {
        Format::Ttlv => bytes.len(),
        Format::Json => json(&serde_json::from_slice(bytes).expect("JSON")),
        Format::Xml => xml(bytes),
    }
}
