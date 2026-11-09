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

//! Server defaults: Set Defaults (2.1 section 6.1.53, draft 3.0) and Query
//! Defaults Information (2.0 section 6.1.37, 2.1 section 6.1.40; Defaults
//! Information 2.0 section 7.7 / 2.1 section 7.11, Object Defaults 2.0
//! section 7.18 / 2.1 section 7.22). See docs/defaults-and-constraints.md.
//!
//! **Built-in defaults.** Only defaults that the factory operations really
//! apply whenever the attribute is omitted are listed, whatever else the
//! request contains. A default that depends on another attribute
//! (Cryptographic Length 256 for AES but 168 for 3DES, RSA 2048 or EC P-256,
//! Key Format Type by algorithm) is left out rather than reported for one
//! case only. tests/query_defaults.rs creates each listed object type without
//! the listed attributes and compares the result with this list (see
//! docs/messages.md#query).
//!
//! **Server defaults.** Set Defaults layers one server-wide set of Object
//! Defaults over the built-in table; it is offered from 2.1, and the defaults
//! apply to Create, Create Key Pair, Register and Derive Key in 2.0, 2.1 and
//! 3.0 requests (never 1.x). Each entry names one Object Type and sets only:
//!
//! | Object Type | Settable |
//! | --- | --- |
//! | Symmetric Key | Cryptographic Algorithm (+ Length), Usage Mask, Sensitive, Extractable |
//! | Private Key | the pair's Cryptographic Algorithm (+ Length); Usage Mask, Sensitive, Extractable of the private key |
//! | Public Key | Usage Mask, Extractable of the public key |
//! | Secret Data | Usage Mask, Sensitive, Extractable |
//! | Certificate, Opaque Object | Sensitive, Extractable |
//!
//! A Cryptographic Length belongs to the Cryptographic Algorithm of its entry
//! and is injected only when the effective algorithm is that algorithm. A key
//! pair's algorithm and length are one pair-wide choice, injected into Common
//! Attributes. The default algorithm fills an omitted algorithm only when it
//! accepts the size the client chose (a length, or a curve, which only EC
//! takes); otherwise the built-in algorithm stays, as without server
//! defaults. Derive Key, which has no built-in algorithm, gets the default
//! algorithm whenever it names none. The default length is injected only
//! with its own algorithm and when the client gave no length and no curve.
//! Client values always win, attribute by attribute.
//! Register takes only the Usage Mask, Sensitive and Extractable defaults.
//!
//! Every entry is validated again in the request's edition and the current
//! configuration (`--fips`, `--triple-des`, `--ec-curves`) when it is used.
//! An entry that no longer validates is skipped as a whole, with one warning
//! per entry and edition per process, and the built-in defaults apply; a
//! stale default never fails a client's request. Query uses the same
//! resolver.
use super::*;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Object types with an Object Defaults entry: the types the tests create
/// through Create, Create Key Pair or Register. Split Key, PGP Key and
/// Certificate Request are not listed.
const TYPES: [u32; 6] = [1, 2, 3, 4, 7, 8];
/// The server defaults record (records.rs).
const RECORD_ID: &str = "defaults\0server";
/// At most this many attributes in one Object Defaults.
const MAX_ATTRIBUTES: usize = 8;
const INVALID_OBJECT_TYPE: u32 = 0x30;
/// The attributes a server default may set for one side of a key pair, and
/// the only ones Register takes.
const PER_OBJECT: [u32; 3] = [CRYPTOGRAPHIC_USAGE_MASK, SENSITIVE, EXTRACTABLE];

/// The attributes an Object Defaults entry may set for `kind` (None: the
/// type has no server defaults).
fn settable(kind: u32) -> Option<&'static [u32]> {
    const KEYS: [u32; 5] = [
        CRYPTOGRAPHIC_ALGORITHM,
        CRYPTOGRAPHIC_LENGTH,
        CRYPTOGRAPHIC_USAGE_MASK,
        SENSITIVE,
        EXTRACTABLE,
    ];
    match kind {
        2 | 4 => Some(&KEYS),
        3 => Some(&[CRYPTOGRAPHIC_USAGE_MASK, EXTRACTABLE]),
        7 => Some(&PER_OBJECT),
        1 | 8 => Some(&[SENSITIVE, EXTRACTABLE]),
        _ => None,
    }
}

/// The built-in Defaults Information structure (2.0 and later), before
/// server defaults are merged in.
fn information(maximum_lease: u32) -> Vec<(u32, Vec<Node>)> {
    TYPES
        .iter()
        .map(|&kind| (kind, attributes(kind, maximum_lease)))
        .collect()
}

fn attributes(kind: u32, maximum_lease: u32) -> Vec<Node> {
    let mut out = vec![];
    match kind {
        // Create and Register (`build_object`): AES, generated as Raw.
        2 => {
            out.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3));
            out.push(Node::enumeration(KEY_FORMAT_TYPE, 1));
        }
        // Create Key Pair (`rekey::generate_pair`): RSA.
        3 | 4 => out.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 4)),
        _ => {}
    }
    // No usage is granted unless requested. A Certificate takes its mask
    // from the certificate, and an Opaque Object has none.
    if matches!(kind, 2 | 3 | 4 | 7) {
        out.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, 0));
    }
    // Sensitive and Extractable (2.0 sections 4.48/4.23, 2.1 4.55/4.23), the
    // lease and the protection storage choice of every new object.
    out.extend([
        Node::boolean(SENSITIVE, false),
        Node::boolean(EXTRACTABLE, true),
        Node::interval(LEASE_TIME, maximum_lease),
        Node::int(PROTECTION_STORAGE_MASK, protection::SOFTWARE as i32),
    ]);
    out
}

/// One configured Object Defaults entry, for a single Object Type, with the
/// edition it was set in.
struct Entry {
    kind: u32,
    set_in: Version,
    attributes: Vec<Node>,
}
impl Entry {
    fn node(&self) -> Node {
        Node::structure(
            OBJECT_DEFAULTS,
            vec![
                self.set_in.node(),
                Node::enumeration(OBJECT_TYPE, self.kind),
                Node::structure(ATTRIBUTES, self.attributes.clone()),
            ],
        )
    }
    fn get(&self, tag: u32) -> Option<&Node> {
        self.attributes.iter().find(|a| a.tag == tag)
    }
    /// The entry's attributes among `tags`.
    fn among<'a>(&'a self, tags: &'a [u32]) -> impl Iterator<Item = &'a Node> + 'a {
        self.attributes.iter().filter(|a| tags.contains(&a.tag))
    }
}

/// Entries already reported as stale: one warning per entry and request
/// edition per process.
static WARNED: Mutex<BTreeSet<(Vec<u8>, [u32; 2])>> = Mutex::new(BTreeSet::new());
/// Log that `entry` is skipped in `v`, unless it was already logged; true
/// if this call logged it.
fn warn_stale(entry: &Entry, v: Version, why: &Failure) -> bool {
    let first = WARNED
        .lock()
        .map(|mut warned| warned.insert((entry.node().encode(), [v.0, v.1])))
        .unwrap_or(true);
    if first {
        tracing::warn!(
            object_type = entry.kind,
            set_in = %format!("{}.{}", entry.set_in.0, entry.set_in.1),
            edition = %format!("{}.{}", v.0, v.1),
            reason = why.message,
            "server default skipped: not valid in this edition or configuration"
        );
    }
    first
}

/// The record cannot be read: the request fails rather than running without
/// the configured defaults.
fn unreadable() -> Failure {
    fail(0x100, "The server defaults cannot be read")
}

/// Inject `add` into the `tag` container of a request payload, creating the
/// container if `create` allows it. A malformed payload is left as it is,
/// for the operation to refuse.
fn extend(p: &mut Node, tag: u32, add: Vec<Node>, create: bool) -> bool {
    if add.is_empty() {
        return false;
    }
    let Value::Structure(fields) = &mut p.value else {
        return false;
    };
    match fields.iter_mut().find(|f| f.tag == tag) {
        Some(Node {
            value: Value::Structure(children),
            ..
        }) => {
            children.extend(add);
            true
        }
        Some(_) => false,
        None if create => {
            fields.push(Node::structure(tag, add));
            true
        }
        None => false,
    }
}
/// The attributes of the `tag` container of a request payload (none if
/// absent or malformed).
fn container(p: &Node, tag: u32) -> Vec<Node> {
    p.get(tag)
        .and_then(|c| c.children().ok())
        .map(<[Node]>::to_vec)
        .unwrap_or_default()
}

impl Engine {
    /// Set Defaults (2.1 section 6.1.53, draft 3.0): replace the server-wide
    /// set; without Defaults Information, remove every configured default.
    pub(super) fn set_defaults(&mut self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        if v < Version(2, 1) {
            return Err(fail(5, "Set Defaults is defined from KMIP 2.1"));
        }
        no_fields(p, &[DEFAULTS_INFORMATION])?;
        let entries = match p.get(DEFAULTS_INFORMATION) {
            Some(info) => self.read_information(info, v)?,
            None => vec![],
        };
        tracing::info!(principal = %owner, entries = entries.len(), "server defaults replaced");
        if entries.is_empty() {
            self.remove_record(records::SERVER_DEFAULTS_OWNER, RECORD_ID)?;
        } else {
            let material = Node::structure(
                DEFAULTS_INFORMATION,
                entries.iter().map(Entry::node).collect(),
            )
            .encode();
            self.write_record(
                records::SERVER_DEFAULTS_OWNER,
                RECORD_ID,
                records::DEFAULTS_RECORD,
                material,
            )?;
        }
        Ok(vec![])
    }

    /// The validated entries of a Set Defaults request, one per Object Type.
    fn read_information(&self, info: &Node, v: Version) -> R<Vec<Entry>> {
        let children = info.children()?;
        if children.iter().any(|c| c.tag != OBJECT_DEFAULTS) {
            return Err(fail(7, "Defaults Information holds Object Defaults only"));
        }
        let mut out: Vec<Entry> = vec![];
        for defaults in children {
            no_fields(
                defaults,
                &[OBJECT_TYPE, OBJECT_TYPES, ATTRIBUTES, OBJECT_GROUPS],
            )?;
            if defaults.get(OBJECT_GROUPS).is_some() {
                return Err(fail(
                    8,
                    "Object Groups are not supported in server defaults",
                ));
            }
            let enumeration = |n: &Node| match n.value {
                Value::Enumeration(kind) if n.tag == OBJECT_TYPE => Ok(kind),
                _ => Err(fail(7, "Object Type must be an Enumeration")),
            };
            let kinds = match (defaults.get(OBJECT_TYPE), defaults.get(OBJECT_TYPES)) {
                (Some(kind), None) => vec![enumeration(kind)?],
                (None, Some(kinds)) => {
                    let kinds = kinds
                        .children()?
                        .iter()
                        .map(enumeration)
                        .collect::<R<Vec<_>>>()?;
                    if kinds.is_empty() {
                        return Err(fail(7, "Object Types is empty"));
                    }
                    kinds
                }
                _ => {
                    return Err(fail(
                        7,
                        "Object Defaults needs one Object Type or Object Types",
                    ));
                }
            };
            let attributes = defaults
                .get(ATTRIBUTES)
                .ok_or(fail(7, "Object Defaults requires Attributes"))?
                .children()?;
            for kind in kinds {
                if settable(kind).is_none() {
                    return Err(fail(
                        INVALID_OBJECT_TYPE,
                        "The server keeps no defaults for this Object Type",
                    ));
                }
                if out.iter().any(|e| e.kind == kind) {
                    return Err(fail(7, "One Object Defaults per Object Type"));
                }
                self.check_entry(kind, attributes, v)?;
                out.push(Entry {
                    kind,
                    set_in: v,
                    attributes: attributes.to_vec(),
                });
            }
        }
        Ok(out)
    }

    /// Validate one entry in edition `v` under the current configuration:
    /// at Set Defaults, and again before each use.
    fn check_entry(&self, kind: u32, attrs: &[Node], v: Version) -> R<()> {
        let allowed = settable(kind).ok_or(fail(
            INVALID_OBJECT_TYPE,
            "The server keeps no defaults for this Object Type",
        ))?;
        if attrs.is_empty() {
            return Err(fail(7, "Object Defaults without attributes sets nothing"));
        }
        if attrs.len() > MAX_ATTRIBUTES {
            return Err(fail(7, "Too many attributes in Object Defaults"));
        }
        for a in attrs {
            if !allowed.contains(&a.tag) {
                return Err(fail(
                    8,
                    if kind == 3 && matches!(a.tag, CRYPTOGRAPHIC_ALGORITHM | CRYPTOGRAPHIC_LENGTH)
                    {
                        "A key pair's algorithm and length are set in the Private Key entry"
                    } else {
                        "This attribute cannot be a server default for this Object Type"
                    },
                ));
            }
            if attrs.iter().filter(|b| b.tag == a.tag).count() > 1 {
                return Err(fail(7, "Duplicate attribute in Object Defaults"));
            }
            let typed = match a.tag {
                CRYPTOGRAPHIC_ALGORITHM => matches!(a.value, Value::Enumeration(_)),
                CRYPTOGRAPHIC_LENGTH => matches!(a.value, Value::Integer(n) if n > 0),
                CRYPTOGRAPHIC_USAGE_MASK => matches!(a.value, Value::Integer(_)),
                _ => matches!(a.value, Value::Boolean(_)),
            };
            if !typed {
                return Err(fail(7, "Invalid server default value"));
            }
        }
        validate_attrs(attrs, v)?;
        let number = |tag| attrs.iter().find(|a| a.tag == tag).map(Node::number);
        let bits = number(CRYPTOGRAPHIC_LENGTH).transpose()?;
        let Some(algorithm) = number(CRYPTOGRAPHIC_ALGORITHM).transpose()? else {
            if bits.is_some() {
                return Err(fail(
                    7,
                    "Cryptographic Length is a default only with its Cryptographic Algorithm",
                ));
            }
            return Ok(());
        };
        if kind == 2 {
            // What Create checks before it generates (`build_object`).
            if algorithm == tdea::ALGORITHM {
                self.triple_des.permit(tdea::Use::Generate)?;
                tdea::validate_length(bits.unwrap_or(168))?;
            } else {
                let bits = bits.unwrap_or(256);
                validate_symmetric_parameters(algorithm, bits, v)?;
                fips_policy::generated_symmetric(algorithm, bits)?;
            }
        } else if pqc::algorithm(algorithm) {
            // What Create Key Pair checks (`create_pair`, pqc.rs): each key
            // of a post-quantum pair has its own length.
            pqc::parameter_set(algorithm, v)?;
            if bits.is_some() {
                return Err(fail(
                    7,
                    "A post-quantum pair default takes no Cryptographic Length",
                ));
            }
        } else if ec::algorithm(algorithm) {
            // `rekey::generate_pair`: without a curve the length picks one.
            ec::validate_algorithm(algorithm, v)?;
            let curve = match bits.unwrap_or(256) {
                256 => 7,
                192 => 1,
                224 => 4,
                384 => 10,
                521 => 13,
                _ => return Err(fail(7, "No EC curve has this length")),
            };
            ec::curve(curve, v)?;
        } else if algorithm == 4 {
            if bits.is_some_and(|bits| ![2048, 3072, 4096].contains(&bits)) {
                return Err(fail(7, "RSA must be 2048, 3072 or 4096 bits"));
            }
        } else {
            return Err(fail(
                8,
                "Only RSA, EC and post-quantum key pairs are generated",
            ));
        }
        Ok(())
    }

    /// The number of stored entries, stale or not; an error if the record
    /// cannot be read.
    pub(super) fn stored_defaults(&self) -> R<usize> {
        Ok(self.read_entries()?.len())
    }
    fn read_entries(&self) -> R<Vec<Entry>> {
        let Some(material) = self.read_record(records::SERVER_DEFAULTS_OWNER, RECORD_ID)? else {
            return Ok(vec![]);
        };
        let read = || -> R<Vec<Entry>> {
            let set = crate::ttlv::decode(&material)?;
            if set.tag != DEFAULTS_INFORMATION {
                return Err(unreadable());
            }
            set.children()?
                .iter()
                .map(|e| {
                    Ok(Entry {
                        kind: e.required(OBJECT_TYPE)?.number()?,
                        set_in: Version::read(e.required(PROTOCOL_VERSION)?)?,
                        attributes: e.required(ATTRIBUTES)?.children()?.to_vec(),
                    })
                })
                .collect()
        };
        read().map_err(|_| unreadable())
    }
    /// The server defaults usable in a `v` request now: stale entries are
    /// skipped with a warning.
    fn server_defaults(&self, v: Version) -> R<Vec<Entry>> {
        Ok(self
            .read_entries()?
            .into_iter()
            .filter(|e| match self.check_entry(e.kind, &e.attributes, v) {
                Ok(()) => true,
                Err(why) => {
                    warn_stale(e, v, &why);
                    false
                }
            })
            .collect())
    }

    /// Query Defaults Information (2.0 and later): the built-in table with
    /// the server defaults usable in `v` merged in.
    pub(super) fn defaults_information(&self, v: Version) -> R<Node> {
        let entries = self.server_defaults(v)?;
        let pair = entries.iter().find(|e| e.kind == 4);
        let pair_wide = [CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_LENGTH];
        Ok(Node::structure(
            DEFAULTS_INFORMATION,
            information(self.maximum_lease)
                .into_iter()
                .map(|(kind, mut attrs)| {
                    let mut configured = vec![];
                    if matches!(kind, 3 | 4) {
                        configured.extend(pair.into_iter().flat_map(|e| e.among(&pair_wide)));
                    }
                    if let Some(e) = entries.iter().find(|e| e.kind == kind) {
                        configured.extend(e.among(&PER_OBJECT));
                        if kind == 2 {
                            configured.extend(e.among(&pair_wide));
                        }
                    }
                    for a in configured {
                        match attrs.iter().position(|b| b.tag == a.tag) {
                            Some(at) => attrs[at] = a.clone(),
                            // A length goes after its algorithm.
                            None => {
                                let at = attrs
                                    .iter()
                                    .position(|b| b.tag == CRYPTOGRAPHIC_ALGORITHM)
                                    .map_or(0, |at| at + 1);
                                attrs.insert(at, a.clone());
                            }
                        }
                    }
                    Node::structure(
                        OBJECT_DEFAULTS,
                        vec![
                            Node::enumeration(OBJECT_TYPE, kind),
                            Node::structure(ATTRIBUTES, attrs),
                        ],
                    )
                })
                .collect(),
        ))
    }

    /// The request payload of a factory operation (Create 1, Create Key
    /// Pair 2, Register 3, Derive Key 5) in a 2.0 or later request with
    /// server defaults filled in for omitted attributes, or None to use it
    /// unchanged.
    pub(super) fn apply_defaults(
        &self,
        _owner: &str,
        v: Version,
        op: u32,
        p: &Node,
    ) -> R<Option<Node>> {
        if v.0 < 2 || ![1, 2, 3, 5].contains(&op) || !matches!(p.value, Value::Structure(_)) {
            return Ok(None);
        }
        let entries = self.server_defaults(v)?;
        if entries.is_empty() {
            return Ok(None);
        }
        let find = |kind: u32| entries.iter().find(|e| e.kind == kind);
        let mut out = p.clone();
        let changed = if op == 2 {
            self.pair_defaults(v, &mut out, find(4), find(3))
        } else {
            let Some(entry) = p.get(OBJECT_TYPE).and_then(|n| match n.value {
                Value::Enumeration(kind) => find(kind),
                _ => None,
            }) else {
                return Ok(None);
            };
            let given = container(p, ATTRIBUTES);
            let has = |tag: u32| given.iter().any(|a| a.tag == tag);
            let mut add = entry
                .among(&PER_OBJECT)
                .filter(|a| !has(a.tag))
                .cloned()
                .collect::<Vec<_>>();
            // Register takes no algorithm or length: they describe the
            // registered material.
            if op != 3
                && let Some(algorithm) = entry.get(CRYPTOGRAPHIC_ALGORITHM)
            {
                let chosen = given.iter().find(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM);
                // Derive Key has no built-in algorithm, so the default fills
                // an omitted one whatever the length. Create keeps its
                // built-in algorithm for a length the default does not
                // accept, as without server defaults.
                let length = given.iter().find(|a| a.tag == CRYPTOGRAPHIC_LENGTH);
                if chosen.is_none()
                    && (op == 5 || self.accepts_size(2, algorithm, length, false, v))
                {
                    add.push(algorithm.clone());
                }
                if chosen.is_none_or(|c| c == algorithm)
                    && !has(CRYPTOGRAPHIC_LENGTH)
                    && let Some(length) = entry.get(CRYPTOGRAPHIC_LENGTH)
                {
                    add.push(length.clone());
                }
            }
            // Derive Key requires its Attributes; the others may omit them.
            extend(&mut out, ATTRIBUTES, add, op != 5)
        };
        Ok(changed.then_some(out))
    }

    /// Whether a default `algorithm` of Object Type `kind` takes the size the
    /// client chose: its length (checked as a server default would be), or
    /// a curve, which only EC algorithms take.
    fn accepts_size(
        &self,
        kind: u32,
        algorithm: &Node,
        length: Option<&Node>,
        curve: bool,
        v: Version,
    ) -> bool {
        let Ok(number) = algorithm.number() else {
            return false;
        };
        if curve && !ec::algorithm(number) {
            return false;
        }
        let mut attrs = vec![algorithm.clone()];
        attrs.extend(length.cloned());
        self.check_entry(kind, &attrs, v).is_ok()
    }

    /// Create Key Pair: the pair-wide algorithm and length from the Private
    /// Key entry into Common Attributes, and each side's own defaults into
    /// its container.
    fn pair_defaults(
        &self,
        v: Version,
        p: &mut Node,
        private: Option<&Entry>,
        public: Option<&Entry>,
    ) -> bool {
        let common = container(p, COMMON_ATTRIBUTES);
        let private_given = container(p, PRIVATE_KEY_ATTRIBUTES);
        let public_given = container(p, PUBLIC_KEY_ATTRIBUTES);
        let all = || common.iter().chain(&private_given).chain(&public_given);
        let mut changed = false;
        if let Some(algorithm) = private.and_then(|e| e.get(CRYPTOGRAPHIC_ALGORITHM)) {
            let chosen = all()
                .filter(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM)
                .collect::<Vec<_>>();
            let mut add = vec![];
            let sized = all().any(|a| {
                matches!(
                    a.tag,
                    CRYPTOGRAPHIC_LENGTH | CRYPTOGRAPHIC_DOMAIN_PARAMETERS | RECOMMENDED_CURVE
                )
            });
            // A size the default algorithm does not accept keeps the
            // built-in algorithm, as without server defaults.
            let length = all().find(|a| a.tag == CRYPTOGRAPHIC_LENGTH);
            let curve =
                all().any(|a| matches!(a.tag, CRYPTOGRAPHIC_DOMAIN_PARAMETERS | RECOMMENDED_CURVE));
            if chosen.is_empty() && self.accepts_size(4, algorithm, length, curve, v) {
                add.push(algorithm.clone());
            }
            if chosen.iter().all(|c| *c == algorithm)
                && !sized
                && let Some(length) = private.and_then(|e| e.get(CRYPTOGRAPHIC_LENGTH))
            {
                add.push(length.clone());
            }
            changed |= extend(p, COMMON_ATTRIBUTES, add, true);
        }
        for (entry, tag, given) in [
            (private, PRIVATE_KEY_ATTRIBUTES, &private_given),
            (public, PUBLIC_KEY_ATTRIBUTES, &public_given),
        ] {
            let Some(entry) = entry else {
                continue;
            };
            let add = entry
                .among(&PER_OBJECT)
                .filter(|a| !common.iter().chain(given).any(|b| b.tag == a.tag))
                .cloned()
                .collect();
            changed |= extend(p, tag, add, true);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_entry_is_reported_once_per_edition() {
        let entry = Entry {
            kind: 4,
            set_in: Version(3, 0),
            attributes: vec![Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 0x3d)],
        };
        let why = fail(8, "stale");
        assert!(warn_stale(&entry, Version(2, 0), &why));
        assert!(!warn_stale(&entry, Version(2, 0), &why));
        assert!(warn_stale(&entry, Version(2, 1), &why));
        assert!(!warn_stale(&entry, Version(2, 1), &why));
    }

    #[test]
    fn every_listed_type_has_settable_defaults() {
        for kind in TYPES {
            assert!(settable(kind).is_some(), "type {kind}");
        }
        for kind in [5, 6, 9, 10, 11] {
            assert!(settable(kind).is_none(), "type {kind}");
        }
    }
}
