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

use keytend_kmip_server::{
    tags::*,
    ttlv::{self, Node, Value},
};
use proptest::prelude::*;
#[test]
fn known_ttlv_integer_vector() {
    // OASIS TTLV Integer: tag Cryptographic Length, type 2, length 4, 256 bits.
    let wire = hex::decode("42002a02000000040000010000000000").unwrap();
    let n = ttlv::decode(&wire).unwrap();
    assert_eq!(n.tag, CRYPTOGRAPHIC_LENGTH);
    assert_eq!(n.number().unwrap(), 256);
    assert!(n.encode() == wire);
}
#[test]
fn reject_malformed_lengths_types_padding_and_boolean() {
    for s in [
        "42002a0200000003ffffff00",
        "42002a02000000040000010000000001",
        "42002a06000000080000000000000002",
        "42002aff000000080000000000000000",
        "42002a01000000010000000000000000",
        "42002a08ffffffff",
        "0000000800000000",
    ] {
        assert!(ttlv::decode(&hex::decode(s).unwrap()).is_err(), "{s}");
    }
}
#[test]
fn depth_limit() {
    let mut n = Node::int(CRYPTOGRAPHIC_LENGTH, 1);
    for _ in 0..34 {
        n = Node::structure(ATTRIBUTES, vec![n]);
    }
    assert!(ttlv::decode(&n.encode()).is_err());
}
proptest! {
    #[test]
    fn decoder_never_panics(data in prop::collection::vec(any::<u8>(),0..4096)){let _=ttlv::decode(&data);}
    #[test]
    fn byte_and_text_roundtrip(data in prop::collection::vec(any::<u8>(),0..8192),text in ".{0,128}") {
        let n=Node::structure(REQUEST_PAYLOAD,vec![Node::bytes(DATA,data),Node::text(NAME_VALUE,text),Node{tag:INITIAL_DATE,value:Value::DateTime(123)}]);
        prop_assert_eq!(n.encoded_len(),n.encode().len());
        prop_assert!(ttlv::decode(&n.encode()).unwrap()==n);
    }
}

#[test]
fn draft_identifier_types_have_distinct_utf8_wire_codes_and_strict_padding() {
    for (kind, node) in [
        (12, Node::identifier(UNIQUE_IDENTIFIER, "key-1")),
        (13, Node::reference(UNIQUE_IDENTIFIER, "key-1")),
        (14, Node::name_reference(UNIQUE_IDENTIFIER, "key-1")),
    ] {
        let mut wire = hex::decode("4200940c000000056b65792d31000000").unwrap();
        wire[3] = kind;
        assert_eq!(node.encoded_len(), wire.len());
        assert!(node.encode() == wire);
        assert!(ttlv::decode(&wire).unwrap() == node);
        assert!(node.string().is_err());
        assert_eq!(node.identifier_text().unwrap(), "key-1");
        let mut bad = wire.clone();
        bad[8] = 0xff;
        assert!(ttlv::decode(&bad).is_err());
        let mut bad = wire.clone();
        bad[15] = 1;
        assert!(ttlv::decode(&bad).is_err());
    }
}
