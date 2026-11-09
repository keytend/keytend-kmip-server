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

//! Result Reasons of the KMIP 1.0-1.4 error tables (section 11 of each
//! edition) for conditions the shared code reports with a 2.x-style reason.
//!
//! The 1.x tables name one reason per error condition, and the general table
//! (1.4 Table 327) covers every operation: a field the server does not know
//! in the request's own version is Invalid Field, and a field given twice is
//! Invalid Message. The 2.x tables instead list Feature Not Supported and
//! Invalid Field for these, which the shared validation helpers return. The
//! failure of a 1.x batch item is rewritten once in `Engine::execute`, after
//! `missing_data::versioned` (which only touches 2.x), so each condition reads
//! as its 1.x table row. 2.x and draft 3.0 failures are unchanged.
//!
//! The conditions are recognized by the fixed messages of the helpers that
//! produce them; `tests/error_tables_1x.rs` walks every 1.x table row and fails
//! if a message changes.
use super::*;

const INVALID_MESSAGE: u32 = 0x04;
const INVALID_FIELD: u32 = 0x07;
const FEATURE_NOT_SUPPORTED: u32 = 0x08;
const ITEM_NOT_FOUND: u32 = 0x01;
const CRYPTOGRAPHIC_FAILURE: u32 = 0x0A;
const ILLEGAL_OPERATION: u32 = 0x0B;

/// A field the operation does not define (1.4 Table 327: "Same major & minor
/// version, unknown field": Invalid Field), an Object Type outside the
/// operation's types (Tables 328, 330, 362, 363, 365: "Object Type is not
/// recognized": Invalid Field) and derivation methods or parameters the server
/// does not implement (Table 333: "Invalid Derivation Method", "Invalid
/// Derivation Parameters": Invalid Field).
const UNKNOWN_FIELD: &[&str] = &[
    "Request contains an unsupported field",
    "Unsupported Derive Key field",
    "Unsupported Locate field",
    "Unsupported Join Split Key field",
    "Unsupported Import field",
    "Unsupported wrapping specification field",
    "Unsupported attribute",
    "Unknown attribute",
    "Unsupported object type",
    "Object type is not supported by this operation",
    "Unsupported derivation parameters",
];
/// The same field more than once (1.4 Table 327: Invalid Message), and
/// derivation data given both inline and as a Secret Data object (Table 333:
/// "Ambiguous derivation data": Invalid Message).
const REPEATED_FIELD: &[&str] = &[
    "Duplicate field",
    "Derivation Data conflicts with Secret Data input",
];
/// A requested length beyond the derivation output (1.4 Table 333:
/// Cryptographic Failure).
const DERIVATION_OUTPUT: &[&str] = &[
    "Requested key exceeds hash output",
    "Requested key exceeds HMAC output",
    "Requested key exceeds encrypted data",
];

/// A request of a later 1.x minor version than this server's newest (1.4).
///
/// 1.4 Table 327, "Same major version, different minor versions; unknown
/// fields/fields the server does not understand": ignore the unknown fields
/// and process the rest normally (with 1.4 section 6.1: servers support
/// backward compatibility within a major version). The request is processed
/// and answered as 1.4, without the fields 1.4 does not define. Vendor
/// extension tags (0x54xxxx) are kept; the operations judge them as usual.
pub(super) fn newer_minor(v: Version) -> bool {
    v.0 == 1 && v.1 > 4
}
pub(super) fn without_unknown_fields(n: &Node) -> Node {
    let keep =
        |tag: u32| (0x540000..=0x54ffff).contains(&tag) || crate::encoding::known_tag(tag, "1.4");
    match &n.value {
        Value::Structure(children) => Node::structure(
            n.tag,
            children
                .iter()
                .filter(|c| keep(c.tag))
                .map(without_unknown_fields)
                .collect(),
        ),
        _ => n.clone(),
    }
}

/// Rewrite a 1.x failure to the reason of its error table row.
pub(super) fn versioned(v: Version, op: u32, e: Failure) -> Failure {
    if v.0 != 1 {
        return e;
    }
    let reason = match (e.reason, e.message) {
        (FEATURE_NOT_SUPPORTED, m) if UNKNOWN_FIELD.contains(&m) => INVALID_FIELD,
        (INVALID_FIELD, m) if REPEATED_FIELD.contains(&m) => INVALID_MESSAGE,
        (INVALID_FIELD, m) if DERIVATION_OUTPUT.contains(&m) => CRYPTOGRAPHIC_FAILURE,
        // Add and Modify Attribute (Tables 341, 342): another object's Name,
        // or a second value of a single-valued attribute, is Illegal
        // Operation. Create, Register and the other factories keep Invalid
        // Field for a Name in use.
        (INVALID_FIELD, "Name is not unique among the owner's objects")
            if [13, 14].contains(&op) =>
        {
            ILLEGAL_OPERATION
        }
        // Encrypt to Hash (1.4 Tables 353-361): "No outstanding operation
        // with the specified Correlation Value exists": Item Not Found.
        (INVALID_FIELD, "Invalid multipart correlation value") => ITEM_NOT_FOUND,
        // Join Split Key (1.2-1.4): fewer parts than the threshold is listed
        // as Cryptographic Failure.
        (INVALID_FIELD, "Insufficient Split Key parts") => CRYPTOGRAPHIC_FAILURE,
        // Validate (Table 351): a combination that names no certificate list
        // is Invalid Message.
        (INVALID_FIELD, "Certificate chain is empty") => INVALID_MESSAGE,
        _ => return e,
    };
    Failure { reason, ..e }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_1_x_failures_are_rewritten() {
        let unknown = || fail(8, "Request contains an unsupported field");
        assert_eq!(versioned(Version(1, 4), 10, unknown()).reason, 7);
        assert_eq!(versioned(Version(1, 0), 10, unknown()).reason, 7);
        assert_eq!(versioned(Version(2, 0), 10, unknown()).reason, 8);
        assert_eq!(versioned(Version(3, 0), 10, unknown()).reason, 8);
        assert_eq!(versioned(Version(1, 4), 10, fail(8, "Other")).reason, 8);
        let name = || fail(7, "Name is not unique among the owner's objects");
        assert_eq!(versioned(Version(1, 4), 13, name()).reason, 0x0B);
        assert_eq!(versioned(Version(1, 4), 1, name()).reason, 7);
        assert_eq!(
            versioned(Version(1, 2), 10, fail(7, "Duplicate field")).reason,
            4
        );
    }
}
