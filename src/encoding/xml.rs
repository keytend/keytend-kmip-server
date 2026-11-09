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

//! Attribute-value XML with no DTD, external entity or schema resolution.
use super::*;
use quick_xml::{
    NsReader, XmlVersion,
    events::{BytesStart, Event},
    name::ResolveResult,
};
fn xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{d7ff}').contains(&c)
        || ('\u{e000}'..='\u{fffd}').contains(&c)
        || ('\u{10000}'..='\u{10ffff}').contains(&c)
}
struct Frame {
    tag: String,
    kind: String,
    value: Option<String>,
    children: Vec<RawNode>,
}
fn frame(start: &BytesStart<'_>) -> Result<Frame> {
    let local = start.local_name();
    let local = local.as_ref();
    let mut attrs = BTreeMap::new();
    for attr in start.attributes() {
        let attr = attr?;
        let key = attr.key.as_ref();
        if key == "xmlns" || key.starts_with("xmlns:") {
            continue;
        }
        ensure!(
            ["tag", "name", "type", "value"].contains(&key),
            "unsupported XML attribute"
        );
        let value = attr.normalized_value(XmlVersion::Implicit1_0)?.into_owned();
        ensure!(value.chars().all(xml_char), "invalid XML character");
        ensure!(
            attrs.insert(key.to_owned(), value).is_none(),
            "duplicate XML attribute"
        );
    }
    let tag = if local == "TTLV" {
        attrs
            .remove("tag")
            .ok_or_else(|| anyhow::anyhow!("generic TTLV tag missing"))?
    } else {
        ensure!(
            !attrs.contains_key("tag"),
            "named XML element has tag override"
        );
        local.to_owned()
    };
    let kind = attrs.remove("type").unwrap_or_else(structure_kind);
    let value = attrs.remove("value");
    if kind == "Structure" {
        ensure!(value.is_none(), "structure cannot have a scalar value")
    } else {
        ensure!(value.is_some(), "scalar value missing")
    }
    Ok(Frame {
        tag,
        kind,
        value,
        children: vec![],
    })
}
fn finish(frame: Frame) -> RawNode {
    RawNode {
        tag: frame.tag,
        kind: frame.kind,
        _name: None,
        value: match frame.value {
            Some(s) => RawValue::String(s),
            None => RawValue::Array(frame.children),
        },
    }
}
fn append(node: RawNode, stack: &mut [Frame], root: &mut Option<RawNode>) -> Result<()> {
    if let Some(parent) = stack.last_mut() {
        ensure!(parent.kind == "Structure", "primitive has nested children");
        parent.children.push(node)
    } else {
        ensure!(root.is_none(), "multiple XML roots");
        *root = Some(node)
    }
    Ok(())
}
pub(super) fn parse(data: &[u8]) -> Result<RawNode> {
    let text = std::str::from_utf8(data)?;
    ensure!(text.chars().all(xml_char), "invalid XML document character");
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut reader = NsReader::from_str(text);
    reader.config_mut().enable_all_checks(true);
    let mut stack = Vec::<Frame>::new();
    let mut root = None;
    let mut count = 0;
    let mut declared = false;
    let mut first = true;
    loop {
        let (namespace, event) = reader.read_resolved_event()?;
        if matches!(&event, Event::Start(_) | Event::Empty(_) | Event::End(_)) {
            match namespace {
                ResolveResult::Unbound => (),
                ResolveResult::Bound(ns) => ensure!(
                    ns.as_ref() == "urn:oasis:tc:kmip:xmlns",
                    "unknown XML namespace"
                ),
                ResolveResult::Unknown(_) => bail!("unbound XML namespace"),
            }
        }
        match event {
            Event::Start(s) => {
                ensure!(
                    stack.len() <= MAX_DEPTH && count < MAX_NODES,
                    "XML node resource limit"
                );
                count += 1;
                ensure!(root.is_none(), "multiple XML roots");
                stack.push(frame(&s)?);
            }
            Event::Empty(s) => {
                ensure!(
                    stack.len() <= MAX_DEPTH && count < MAX_NODES,
                    "XML node resource limit"
                );
                count += 1;
                append(finish(frame(&s)?), &mut stack, &mut root)?
            }
            Event::End(_) => {
                let f = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("unmatched XML close"))?;
                append(finish(f), &mut stack, &mut root)?
            }
            Event::Text(t) => ensure!(
                t.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r')),
                "TTLV XML values must use attributes"
            ),
            Event::Decl(d) => {
                ensure!(
                    first
                        && !declared
                        && root.is_none()
                        && stack.is_empty()
                        && d.version()?.as_ref() == "1.0",
                    "invalid XML declaration"
                );
                if let Some(enc) = d.encoding() {
                    ensure!(
                        enc?.eq_ignore_ascii_case("UTF-8"),
                        "unsupported XML encoding"
                    )
                }
                declared = true;
            }
            Event::Comment(_) | Event::PI(_) => (),
            Event::CData(t) => ensure!(
                stack.last().is_some_and(|f| f.kind == "Structure")
                    && t.chars().all(|c| matches!(c, ' ' | '\t' | '\n' | '\r')),
                "TTLV XML values must use attributes"
            ),
            Event::GeneralRef(r) => ensure!(
                stack.last().is_some_and(|f| f.kind == "Structure")
                    && r.resolve_char_ref()?
                        .is_some_and(|c| matches!(c, ' ' | '\t' | '\n' | '\r')),
                "unsupported XML entity content"
            ),
            Event::Eof => break,
            Event::DocType(_) => bail!("DTD is forbidden"),
        }
        first = false;
    }
    ensure!(stack.is_empty(), "unclosed XML structure");
    root.ok_or_else(|| anyhow::anyhow!("XML root missing"))
}
fn escaped(s: &str, out: &mut Vec<u8>) -> Result<()> {
    for c in s.chars() {
        ensure!(xml_char(c), "value cannot be represented in XML 1.0");
        match c {
            '&' => out.extend_from_slice(b"&amp;"),
            '<' => out.extend_from_slice(b"&lt;"),
            '>' => out.extend_from_slice(b"&gt;"),
            '"' => out.extend_from_slice(b"&quot;"),
            '\'' => out.extend_from_slice(b"&apos;"),
            '\t' => out.extend_from_slice(b"&#x9;"),
            '\n' => out.extend_from_slice(b"&#xA;"),
            '\r' => out.extend_from_slice(b"&#xD;"),
            _ => {
                let mut bytes = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut bytes).as_bytes())
            }
        }
        ensure!(out.len() <= MAX_TEXT_FRAME, "XML response too large")
    }
    Ok(())
}
/// The element in the configured tag form: the specific element named by the
/// edition's normalized tag name, or the general `TTLV` element that "allows
/// any TTLV including extensions to be encoded" (Profiles 2.1 section
/// 5.4.1.6). Tags the edition does not name always use the general form.
fn element(n: &Node, version: Option<&str>, forms: &TextEncoding) -> Option<&'static str> {
    version
        .filter(|_| forms.xml_tags == NameForm::Name)
        .and_then(|v| names::edition_tag(n.tag, v))
}
/// `attribute` is the tag a 1.x Attribute Name designates, for its Attribute
/// Value; `version` is the message's protocol version.
fn emit(
    n: &Node,
    out: &mut Vec<u8>,
    version: Option<&str>,
    attribute: Option<u32>,
    forms: &TextEncoding,
) -> Result<()> {
    use std::io::Write;
    let name = element(n, version, forms);
    match (name, &n.value) {
        // "The 'type' property / attribute is optional for a Structure"
        // (5.4.1.6.2); the specific form omits it, as the OASIS XML traces do.
        (Some(name), Value::Structure(_)) => write!(out, "<{name}")?,
        (Some(name), value) => write!(out, "<{name} type=\"{}\"", kind(value))?,
        (None, value) => {
            write!(out, "<TTLV tag=\"0x{:06x}\"", n.tag)?;
            // 5.4.1.6: the general form has an optional 'name' attribute,
            // e.g. <TTLV tag="0x54FFFF" name="SomeExtension" …/>. Written
            // with the name tag form for a tag this edition does not name
            // when another edition publishes a name for it (5.4.1.3).
            if let Some(published) = version
                .filter(|_| forms.xml_tags == NameForm::Name)
                .and_then(|v| names::published_tag(n.tag, v))
            {
                write!(out, " name=\"{published}\"")?;
            }
            write!(out, " type=\"{}\"", kind(value))?
        }
    }
    if let Value::Structure(children) = &n.value {
        out.push(b'>');
        let attr = attribute_context(n);
        for n in children {
            emit(n, out, version, attr, forms)?
        }
        write!(out, "</{}>", name.unwrap_or("TTLV"))?;
    } else {
        out.extend_from_slice(b" value=\"");
        let effective = effective_tag(n, attribute);
        let value = match &n.value {
            Value::Integer(mask) if is_mask(effective) => match forms.xml_masks {
                MaskForm::Names => mask_text(effective, *mask, version, " "),
                MaskForm::Hex => format!("0x{:08x}", *mask as u32),
                MaskForm::Number => mask.to_string(),
            },
            // 5.4.1.6.7: "either a hex string or the CamelCase enum text".
            Value::Enumeration(value) => match enum_name(effective, *value, version) {
                Some(name) if forms.xml_enumerations == NameForm::Name => name.to_owned(),
                _ => format!("0x{value:08x}"),
            },
            value => xml_scalar(value)?,
        };
        let value = Zeroizing::new(value);
        escaped(&value, out)?;
        out.extend_from_slice(b"\"/>")
    }
    ensure!(out.len() <= MAX_TEXT_FRAME, "XML response too large");
    Ok(())
}
pub(super) fn write(n: &Node, out: &mut Vec<u8>, forms: &TextEncoding) -> Result<()> {
    out.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    emit(n, out, node_version(n), None, forms)
}
