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

//! The 2.x/3.0 Get Attributes response when none of the requested attributes
//! exist (`--get-attributes-none`,
//! docs/interpretations.md#get-attributes-when-none-of-the-requested-attributes-exist).
//!
//! The specification text allows two readings. The operation prose says "If
//! none of the requested attributes exist, then the response SHALL consist
//! only of the Unique Identifier" (2.0 and 2.1 section 6.1.20, draft 3.0
//! section 6.1.26; clause `7ebd66853ffb6476`), while the response payload
//! table marks Attributes REQUIRED ("Attributes | Yes | The requested
//! attributes associated with the object": 2.0 Table 209, 2.1 Table 224,
//! draft 3.0 Table 330). Some Java clients reject a reply without Attributes
//! and Cosmian KMS returns an empty structure, so `empty-attributes` (the
//! default) follows the table and
//! `identifier-only` follows the prose. 1.x always returns the identifier
//! alone: its response table has no Attributes structure (1.4 section 4.12).
//! A Get Attributes without Attribute References returns every attribute and
//! is unaffected, as are the internal callers (Get with attributes, Put).

/// Get Attributes response form when no requested attribute exists (2.x/3.0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum GetAttributesNone {
    /// The Unique Identifier and an empty Attributes structure (response
    /// table: Attributes REQUIRED).
    #[default]
    EmptyAttributes,
    /// The Unique Identifier alone (operation prose).
    IdentifierOnly,
}

impl GetAttributesNone {
    /// Whether a 2.x/3.0 response carries the Attributes structure, given
    /// whether the request selected attributes and how many were found.
    pub(super) fn attributes_present(self, selected: bool, found: usize) -> bool {
        !(self == Self::IdentifierOnly && selected && found == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::GetAttributesNone::*;

    #[test]
    fn only_identifier_only_with_a_selection_and_no_match_drops_attributes() {
        assert!(EmptyAttributes.attributes_present(true, 0));
        assert!(EmptyAttributes.attributes_present(false, 0));
        assert!(!IdentifierOnly.attributes_present(true, 0));
        assert!(IdentifierOnly.attributes_present(true, 1));
        assert!(IdentifierOnly.attributes_present(false, 0));
    }
}
