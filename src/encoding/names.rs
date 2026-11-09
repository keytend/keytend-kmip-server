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

//! Edition-scoped normalized names for JSON output
//! (docs/interpretations.md). Profiles 2.1 section 5.5.1.3 lets a tag be the
//! "0x" hex value or "the normalised text of a Tag as specified in the KMIP
//! Specification"; section 5.5.1.6.7 lets an Enumeration be a Number, hex, or
//! the CamelCase enumeration text. Each name comes from the edition of the
//! message, so a value renamed or withdrawn by a later edition is written in
//! the vocabulary of the response's own protocol version. Anything that edition
//! does not name (extensions, unknown values, withdrawn slots) stays hex.
use super::*;
use std::collections::HashMap;

/// Registry rows for slots an edition no longer names (for example 2.x Object
/// Type 6, formerly Template). Writing "Reserved" would not identify a value.
const UNNAMED: &str = "Reserved";
/// Values whose table lists two spellings; the first is written, both decode.
/// - Mask Generator: 2.x/3.0 tables print MFG1; the 1.4 table, the mechanism
///   prose and the official traces use MGF1 (docs/interpretations.md).
/// - Split Key Method: the official traces spell GF(2^16) and GF(2^8) with an
///   underscore (scripts/generate_wire_registry.py keeps both spellings).
const PREFERRED: [(&str, u32, &str); 3] = [
    ("MaskGenerator", 1, "MGF1"),
    ("SplitKeyMethod", 2, "PolynomialSharingGF2_16"),
    ("SplitKeyMethod", 4, "PolynomialSharingGF2_8"),
];
struct Names {
    tags: HashMap<u32, &'static str>,
    enums: HashMap<u32, HashMap<u32, &'static str>>,
}
/// The enumeration tables the reader (`symbolic`) consults for a tag name.
fn tables(key: &str) -> impl Iterator<Item = &str> {
    let aliases = ENUMERATION_TABLES
        .iter()
        .find(|(tag_name, _)| *tag_name == key)
        .map_or(&[][..], |(_, tables)| *tables);
    std::iter::once(key).chain(aliases.iter().copied())
}
fn build(r: &'static Registry) -> Names {
    let tags = r
        .tags
        .iter()
        .filter(|(name, _)| name.as_str() != UNNAMED)
        .map(|(name, tag)| (*tag, name.as_str()))
        .collect();
    let mut enums = HashMap::new();
    for (key, tag) in &r.tags {
        // `None` marks a value with two spellings and no recorded preference.
        let mut values: HashMap<u32, Option<&'static str>> = HashMap::new();
        for table in tables(key) {
            let Some(entries) = r.enums.get(table) else {
                continue;
            };
            let mut spellings: HashMap<u32, Vec<&'static str>> = HashMap::new();
            for (name, value) in entries.iter().filter(|(n, _)| n.as_str() != UNNAMED) {
                spellings.entry(*value).or_default().push(name.as_str());
            }
            for (value, names) in spellings {
                values
                    .entry(value)
                    .or_insert_with(|| match names.as_slice() {
                        [only] => Some(*only),
                        _ => PREFERRED
                            .iter()
                            .find(|(t, v, p)| *t == table && *v == value && names.contains(p))
                            .map(|(_, _, p)| *p),
                    });
            }
        }
        let named: HashMap<u32, &'static str> = values
            .into_iter()
            .filter_map(|(value, name)| name.map(|n| (value, n)))
            .collect();
        if !named.is_empty() {
            enums.insert(*tag, named);
        }
    }
    Names { tags, enums }
}
fn names(version: &str) -> Option<&'static Names> {
    static NAMES: OnceLock<BTreeMap<&'static str, Names>> = OnceLock::new();
    NAMES
        .get_or_init(|| {
            registries()
                .iter()
                .map(|(version, r)| (version.as_str(), build(r)))
                .collect()
        })
        .get(version)
}
/// The edition's normalized name of `tag`, if that edition defines one.
pub(super) fn edition_tag(tag: u32, version: &str) -> Option<&'static str> {
    names(version)?.tags.get(&tag).copied()
}
/// A name another pinned edition publishes for a tag that `version` does not
/// name, newest edition first: Profiles 2.1 section 5.4.1.3 lets a producer
/// use "names of new tags added in future KMIP versions", and a slot a later
/// edition reserves keeps the name its earlier editions published. Extension
/// tags (0x54xxxx) have no published name here.
pub(super) fn published_tag(tag: u32, version: &str) -> Option<&'static str> {
    if edition_tag(tag, version).is_some() {
        return None;
    }
    registries()
        .keys()
        .rev()
        .filter(|v| v.as_str() != version)
        .find_map(|v| edition_tag(tag, v))
}
/// The edition's normalized name of enumeration `value` of `tag`. A 2.x/3.0
/// Attribute Reference enumerates tags, so its value is written as a tag name.
pub(super) fn edition_enum(tag: u32, value: u32, version: &str) -> Option<&'static str> {
    let names = names(version)?;
    if tag == ATTRIBUTE_REFERENCE {
        return names.tags.get(&value).copied();
    }
    names.enums.get(&tag)?.get(&value).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_written_name_decodes_to_the_same_number_in_its_edition() {
        let mut checked = (0, 0);
        for (version, r) in registries() {
            for &tag in r.tags.values() {
                if let Some(name) = edition_tag(tag, version) {
                    // Written unescaped by `write_json`.
                    assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
                    assert_eq!(super::super::tag(name).unwrap(), tag, "{version} {name}");
                    checked.0 += 1;
                }
                for value in r.enums.values().flat_map(|t| t.values()).copied() {
                    if let Some(name) = edition_enum(tag, value, version) {
                        assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
                        assert_eq!(symbolic(tag, name, Some(version)).unwrap(), value);
                        checked.1 += 1;
                    }
                }
            }
        }
        assert!(checked.0 > 2000 && checked.1 > 3000, "{checked:?}");
    }

    #[test]
    fn every_enumeration_value_has_one_written_name() {
        // A new registry alias must be given an explicit preference rather than
        // silently falling back to hex. Masks are written numerically in JSON.
        for (version, r) in registries() {
            for (key, tag) in r.tags.iter().filter(|(_, t)| !is_mask(**t)) {
                for table in tables(key) {
                    for (name, value) in r.enums.get(table).into_iter().flatten() {
                        if name != UNNAMED {
                            assert!(
                                edition_enum(*tag, *value, version).is_some(),
                                "{version} {key} {name}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn names_follow_the_edition() {
        use crate::tags::*;
        // Renamed between editions (1.4 vs 2.0+ section 9.1.3.2.x / 11).
        assert_eq!(
            edition_enum(DIGITAL_SIGNATURE_ALGORITHM, 3, "1.4"),
            Some("SHA_1WithRSAEncryptionPKCS_1V1_5")
        );
        assert_eq!(
            edition_enum(DIGITAL_SIGNATURE_ALGORITHM, 3, "2.1"),
            Some("SHA_1WithRSAEncryption")
        );
        assert_eq!(
            edition_enum(HASHING_ALGORITHM, 0xe, "1.4"),
            Some("SHA_3_224")
        );
        assert_eq!(
            edition_enum(HASHING_ALGORITHM, 0xe, "2.0"),
            Some("SHA3_224")
        );
        // Withdrawn: 1.x Template object type is a 2.x reserved slot.
        assert_eq!(edition_enum(OBJECT_TYPE, 6, "1.4"), Some("Template"));
        assert_eq!(edition_enum(OBJECT_TYPE, 6, "2.1"), None);
        // 2.1 tag 0x420171 Rotate Name Type is reserved in draft 3.0; 2.1
        // Result Reason 0x4a Unknown Object Group likewise.
        assert_eq!(edition_tag(0x420171, "2.1"), Some("RotateNameType"));
        assert_eq!(edition_tag(0x420171, "3.0"), None);
        assert_eq!(
            edition_enum(RESULT_REASON, 0x4a, "2.1"),
            Some("UnknownObjectGroup")
        );
        assert_eq!(edition_enum(RESULT_REASON, 0x4a, "3.0"), None);
        // A tag introduced in 2.0 has no 1.x name.
        assert_eq!(edition_tag(ATTRIBUTE_REFERENCE, "1.4"), None);
        assert_eq!(
            edition_tag(ATTRIBUTE_REFERENCE, "2.0"),
            Some("AttributeReference")
        );
        assert_eq!(
            edition_enum(ATTRIBUTE_REFERENCE, STATE, "2.1"),
            Some("State")
        );
        // Preferred spellings; both spellings still decode.
        assert_eq!(edition_enum(ENCODING_OPTION, 1, "2.1"), Some("NoEncoding"));
        assert_eq!(edition_enum(MASK_GENERATOR, 1, "3.0"), Some("MGF1"));
        assert_eq!(symbolic(MASK_GENERATOR, "MFG1", Some("2.1")).unwrap(), 1);
        // Unknown and vendor values, extension tags and unknown editions.
        assert_eq!(edition_enum(OBJECT_TYPE, 0xffff, "2.1"), None);
        assert_eq!(edition_enum(OBJECT_TYPE, 0x8000_0001, "2.1"), None);
        assert_eq!(edition_tag(0x540001, "2.1"), None);
        assert_eq!(edition_tag(OBJECT_TYPE, "1.5"), None);
    }

    #[test]
    fn endpoint_role_has_its_own_names_and_encoding_option_keeps_its_own() {
        use crate::tags::*;
        // 2.0 Table 414, 2.1 Table 452 and 3.0 Table 563 are headed
        // "Encoding Option Name" but define Endpoint Role (section 11.19/11.20).
        for version in ["2.0", "2.1", "3.0"] {
            assert_eq!(edition_enum(ENDPOINT_ROLE, 1, version), Some("Client"));
            assert_eq!(edition_enum(ENDPOINT_ROLE, 2, version), Some("Server"));
            assert_eq!(symbolic(ENDPOINT_ROLE, "Server", Some(version)).unwrap(), 2);
            assert_eq!(
                edition_enum(ENCODING_OPTION, 2, version),
                Some("TTLVEncoding")
            );
            assert!(symbolic(ENCODING_OPTION, "Client", Some(version)).is_err());
            assert!(symbolic(ENDPOINT_ROLE, "NoEncoding", Some(version)).is_err());
        }
        // Endpoint Role is a 2.0 tag: no 1.x name.
        assert_eq!(edition_tag(ENDPOINT_ROLE, "1.4"), None);
        assert_eq!(edition_enum(ENDPOINT_ROLE, 1, "1.4"), None);
    }

    #[test]
    fn published_names_come_from_other_editions_only_for_unnamed_tags() {
        use crate::tags::*;
        // Reserved in draft 3.0, published by 2.1.
        assert_eq!(published_tag(0x420171, "3.0"), Some("RotateNameType"));
        // Added in 2.0, so a 1.4 message can carry its future name.
        assert_eq!(
            published_tag(ATTRIBUTE_REFERENCE, "1.4"),
            Some("AttributeReference")
        );
        // Named by the edition itself: the specific element is used instead.
        assert_eq!(published_tag(OBJECT_TYPE, "2.1"), None);
        // Extension tags have no published name.
        assert_eq!(published_tag(0x540001, "2.1"), None);
    }
}
