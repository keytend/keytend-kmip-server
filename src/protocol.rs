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

//! KMIP synchronous request processing. Capability discovery reports implemented operations only.
use crate::codes::hash::SHA256;
use crate::{
    crypto,
    store::{Object, Store, now},
    tags::*,
    ttlv::{DecodeError, Node, Value},
};
use zeroize::Zeroize;
mod activation;
mod adjust;
mod archive;
mod asynchronous;
mod attributes;
mod object_index;
use attributes::{decode_attribute, encode_attribute};
mod certificate;
mod certificate_request;
mod certify;
mod channel;
mod cipher;
mod constraints;
mod credential_proofs;
mod defaults;
mod derivation;
mod destroyed_names;
pub use destroyed_names::DestroyedNameReuse;
mod ec;
mod endpoint_role;
mod fips_policy;
mod get_attributes_none;
pub use endpoint_role::{ROLE_CLIENT, ROLE_SERVER, SET_ENDPOINT_ROLE, reversal_accepted};
pub use get_attributes_none::GetAttributesNone;
mod group_member;
mod hashing;
mod identifiers;
mod interop;
mod key_value;
mod lease;
pub use lease::LeaseStates;
mod legacy_errors;
mod locate_dates;
mod locate_filters;
mod log;
mod mac;
mod metadata;
mod missing_data;
mod not_found;
mod notify;
pub use notify::{NOTIFY, Outbound, PUT, ServerToClient, Sink, Subscription};
mod opaque;
mod pair_agreement;
mod pgp;
mod pkcs11;
mod policy;
mod pqc;
mod protection;
mod provisioning;
mod quantum;
mod records;
mod rekey;
mod revocation;
mod rsa;
mod side;
mod split;
mod stream;
mod system;
mod system_credentials;
mod tdea;
mod template;
mod tickets;
mod transfer;
mod undo;
pub use channel::{Channel, Lookup};
pub use ec::EcCurves;
pub use provisioning::Provisioning;
pub use tdea::TripleDesPolicy;
mod transparent;
mod usage;
mod validate;
mod wrapping;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u32, pub u32);
impl Version {
    pub fn node(self) -> Node {
        Node::structure(
            PROTOCOL_VERSION,
            vec![
                Node::int(PROTOCOL_VERSION_MAJOR, self.0 as i32),
                Node::int(PROTOCOL_VERSION_MINOR, self.1 as i32),
            ],
        )
    }
    fn read(n: &Node) -> R<Self> {
        no_fields(n, &[PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR])?;
        Ok(Self(
            n.required(PROTOCOL_VERSION_MAJOR)?.number()?,
            n.required(PROTOCOL_VERSION_MINOR)?.number()?,
        ))
    }
    pub fn supported(draft: bool) -> Vec<Self> {
        let mut v = vec![
            Self(2, 1),
            Self(2, 0),
            Self(1, 4),
            Self(1, 3),
            Self(1, 2),
            Self(1, 1),
            Self(1, 0),
        ];
        if draft {
            v.insert(0, Self(3, 0));
        }
        v
    }
}
pub struct Failure {
    pub reason: u32,
    pub message: &'static str,
    clear_placeholder: bool,
    payload: Option<Box<Node>>,
    unanswerable: bool,
}
impl std::fmt::Debug for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Failure")
            .field("reason", &self.reason)
            .field("message", &self.message)
            .field("clear_placeholder", &self.clear_placeholder)
            .field("has_payload", &self.payload.is_some())
            .field("unanswerable", &self.unanswerable)
            .finish()
    }
}
impl Failure {
    pub fn new(reason: u32, message: &'static str) -> Self {
        Self {
            reason,
            message,
            clear_placeholder: false,
            payload: None,
            unanswerable: false,
        }
    }
    /// No conforming response fits the requested Maximum Response Size, so
    /// nothing was committed and the transport must not send a KMIP message.
    pub fn unanswerable(&self) -> bool {
        self.unanswerable
    }
    fn check_denied(mut self, rejected: Vec<Node>) -> Self {
        self.clear_placeholder = true;
        self.payload = Some(Box::new(Node::structure(RESPONSE_PAYLOAD, rejected)));
        self
    }
}
type R<T> = Result<T, Failure>;
/// Result Reason Object Destroyed (KMIP 2.0+).
const OBJECT_DESTROYED_REASON: u32 = 0x36;
fn fail(reason: u32, message: &'static str) -> Failure {
    Failure::new(reason, message)
}
fn server_limit(v: Version, message: &'static str) -> Failure {
    fail(if v.0 >= 2 { 0x3a } else { 0x100 }, message)
}
fn response_too_large() -> Failure {
    fail(2, "Response exceeds Maximum Response Size")
}
fn unanswerable() -> Failure {
    Failure {
        unanswerable: true,
        ..fail(2, "Maximum Response Size admits no conforming response")
    }
}
impl From<DecodeError> for Failure {
    fn from(_: DecodeError) -> Self {
        fail(7, "Invalid field or missing required data")
    }
}
impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        if e.downcast_ref::<crate::fips::NotApproved>().is_some() {
            return fail(8, "Mechanism is not available in FIPS mode");
        }
        // Backstop of the curve checks (ec.rs): a curve KMIP operations
        // cannot use is Feature Not Supported wherever it is found.
        if e.downcast_ref::<crate::crypto::ec::UnsupportedCurve>()
            .is_some()
        {
            return fail(8, "Unsupported EC curve");
        }
        tracing::error!(error=%e,"KMIP internal operation failed");
        fail(0x100, "Internal operation failed")
    }
}
impl From<openssl::error::ErrorStack> for Failure {
    fn from(_: openssl::error::ErrorStack) -> Self {
        fail(10, "Cryptographic provider operation failed")
    }
}
fn number(n: &Node, tag: u32, default: u32) -> R<u32> {
    n.get(tag)
        .map(Node::number)
        .transpose()
        .map(|v| v.unwrap_or(default))
        .map_err(Into::into)
}
fn flag(n: &Node, tag: u32, default: bool) -> R<bool> {
    n.get(tag)
        .map(Node::flag)
        .transpose()
        .map(|v| v.unwrap_or(default))
        .map_err(Into::into)
}
fn no_fields(n: &Node, tags: &[u32]) -> R<()> {
    if n.children()?.iter().any(|n| !tags.contains(&n.tag)) {
        return Err(fail(8, "Request contains an unsupported field"));
    }
    for tag in tags {
        if n.all(*tag).count() > 1 {
            return Err(fail(7, "Duplicate field"));
        }
    }
    Ok(())
}
/// KMIP 1.0-1.4 section 6.16, 2.0/2.1 section 9.13 and draft 3.0 section
/// 9.11: a receiver that does not understand a Critical Message Extension
/// SHALL reject the entire message. This server understands one extension,
/// its own on a Re-Provision item (`understood`), so every item is checked
/// before authorization, execution, mutation or audit. Any other extension
/// carrying Criticality Indicator True counts, even if its other fields are
/// malformed or it is repeated.
fn critical_extension(items: &[&Node]) -> Option<usize> {
    let critical = |item: &Node, extension: &Node| {
        !understood(item, extension)
            && extension.children().is_ok_and(|fields| {
                fields
                    .iter()
                    .any(|f| f.tag == CRITICALITY_INDICATOR && f.value == Value::Boolean(true))
            })
    };
    items
        .iter()
        .position(|item| item.all(MESSAGE_EXTENSION).any(|e| critical(item, e)))
}
/// This server's Message Extension on a Re-Provision item, which asks for a
/// validity period (provisioning.rs).
fn understood(item: &Node, extension: &Node) -> bool {
    item.get(OPERATION)
        .is_some_and(|op| op.value == Value::Enumeration(53))
        && provisioning::ours(extension)
}

/// The remaining extensions are not Critical, or are this server's own on a
/// Re-Provision item, which Re-Provision reads. A malformed one fails only its
/// item: the 1.x general errors table assigns Invalid Message to a batch item
/// that cannot be parsed and to a repeated field. A well-formed Non-Critical
/// extension is ignored: "the receiver MAY process the rest of the message as
/// if the extension were not present" (1.0-1.4 section 6.16, 2.0/2.1 section
/// 9.13, draft 3.0 section 9.11). Both 1.x Test Cases notes (TC-71-10/11/12,
/// 1.1 note section 7.1) expect exactly that, so the MAY is taken.
fn noncritical_extensions(v: Version, item: &Node) -> R<()> {
    let extensions: Vec<_> = item.all(MESSAGE_EXTENSION).collect();
    if extensions.is_empty() {
        return Ok(());
    }
    // 1.x tables 188-283 do not let the field repeat; 2.0 table 358, 2.1
    // table 396 and draft table 506 say "MAY be repeated".
    if v.0 == 1 && extensions.len() > 1 {
        return Err(fail(4, "Repeated Message Extension"));
    }
    for extension in extensions {
        let malformed = || fail(4, "Malformed Message Extension");
        let Ok([vendor, critical, body]) = extension.children() else {
            return Err(malformed());
        };
        if [vendor.tag, critical.tag, body.tag]
            != [
                VENDOR_IDENTIFICATION,
                CRITICALITY_INDICATOR,
                VENDOR_EXTENSION,
            ]
            || !matches!(critical.value, Value::Boolean(c) if !c || understood(item, extension))
            || body.children().is_err()
        {
            return Err(malformed());
        }
        let vendor = vendor.string().map_err(|_| malformed())?;
        // 2.0 table 380, 2.1 table 418, 3.0 table 526: [A-Za-z0-9_.].
        if v.0 >= 2
            && !vendor
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        {
            return Err(malformed());
        }
    }
    Ok(())
}
fn version_ops(v: Version) -> Vec<u32> {
    let mut ops = vec![
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    // Cancel and Poll (1.0 sections 4.19/4.20, draft 3.0 6.1.5/6.1.45); see
    // asynchronous.rs.
    ops.extend([25, 26]);
    if v >= Version(1, 1) {
        ops.extend([29, 30]);
    }
    if v >= Version(1, 2) {
        ops.extend(31..=41);
    }
    if v >= Version(1, 4) {
        ops.extend([42, 43]);
    }
    if v >= Version(2, 0) {
        // Log, PKCS#11 and Set Endpoint Role (2.0 sections 6.1.28, 6.1.35
        // and 6.1.48; see endpoint_role.rs).
        ops.extend([44, 48, 49, 50, 51]);
    }
    if v >= Version(2, 0) {
        // Login, Logout and Delegated Login (2.0 sections 6.1.29, 6.1.30
        // and 6.1.12; tickets.rs).
        ops.extend([45, 46, 47]);
    }
    if v >= Version(2, 1) {
        ops.push(59);
    }
    if v >= Version(2, 1) {
        // Set Defaults, Set Constraints and Get Constraints (2.1 sections
        // 6.1.53, 6.1.52 and 6.1.22; defaults.rs, constraints.rs).
        ops.extend([54, 55, 56]);
    }
    if v >= Version(2, 1) {
        // Query Asynchronous Requests and Process (2.1 sections 6.1.41,
        // 6.1.39; draft 3.0 6.1.48, 6.1.46).
        ops.extend([57, 58]);
    }
    if v >= Version(3, 0) {
        // Draft 3.0 System Objects and Obliterate.
        ops.extend([60, 61, 62, 63, 64]);
        // Draft 3.0 Encapsulate and Decapsulate (sections 6.1.22, 6.1.15),
        // ML-KEM only (pqc.rs).
        ops.extend([pqc::ENCAPSULATE, pqc::DECAPSULATE]);
    }
    ops.sort();
    ops
}
pub fn operations(v: Version) -> Vec<u32> {
    version_ops(v)
}

/// The selected response encoding.
struct Wire<'a> {
    /// Rejects a response payload that the encoding cannot represent.
    check: &'a mut dyn FnMut(&Node) -> R<()>,
    /// Encoded length of a complete response message.
    len: &'a dyn Fn(&Node) -> R<usize>,
    /// Largest encoded message the server sends, independent of the client.
    frame: usize,
}
// Count additive resources independently: a large text allowance must not hide
// binary-equivalent or node growth. Depth is checked on each complete one-item
// response; adding sibling items cannot increase its maximum depth.
#[derive(Clone, Copy, Default)]
struct ResponseSize {
    encoded: usize,
    binary: usize,
    nodes: usize,
}
impl ResponseSize {
    const MAX: Self = Self {
        encoded: usize::MAX,
        binary: usize::MAX,
        nodes: usize::MAX,
    };
    fn saturating_add(self, other: Self) -> Self {
        Self {
            encoded: self.encoded.saturating_add(other.encoded),
            binary: self.binary.saturating_add(other.binary),
            nodes: self.nodes.saturating_add(other.nodes),
        }
    }
    fn saturating_sub(self, other: Self) -> Self {
        Self {
            encoded: self.encoded.saturating_sub(other.encoded),
            binary: self.binary.saturating_sub(other.binary),
            nodes: self.nodes.saturating_sub(other.nodes),
        }
    }
    fn saturating_mul(self, count: usize) -> Self {
        Self {
            encoded: self.encoded.saturating_mul(count),
            binary: self.binary.saturating_mul(count),
            nodes: self.nodes.saturating_mul(count),
        }
    }
    fn fits(self, budget: Budget) -> bool {
        self.encoded <= budget.frame
            && self.binary <= budget.client
            && self.nodes <= crate::encoding::MAX_NODES
    }
}
/// Limits for one response. Maximum Response Size is a binary TTLV length in
/// every encoding: Profiles 1.3 through 2.1 and draft 3.0 sections 5.4 (XML)
/// and 5.5 (JSON) interpret it "as if it were a TTLV-encoded response, not the
/// length of the" XML or JSON response. The selected encoder's bytes are bound
/// only by the server frame; for TTLV both lengths are the same bytes.
#[derive(Clone, Copy)]
struct Budget {
    /// Binary TTLV-equivalent bytes: the requested limit, at most 1 MiB.
    client: usize,
    /// Selected-encoding bytes the server can send.
    frame: usize,
}
impl Budget {
    fn new(requested: Option<usize>, frame: usize) -> Self {
        Self {
            client: requested.map_or(crate::ttlv::MAX_FRAME, |n| n.min(crate::ttlv::MAX_FRAME)),
            frame,
        }
    }
}
impl Wire<'_> {
    fn measure(&self, node: &Node) -> R<ResponseSize> {
        let nodes = crate::encoding::checked_node_count(node).map_err(|_| response_too_large())?;
        Ok(ResponseSize {
            encoded: (self.len)(node)?,
            binary: node.encoded_len(),
            nodes,
        })
    }
}
#[derive(Default)]
struct Authorization {
    grants: Vec<crate::authorization::ObjectGrant>,
    operation: u32,
    /// Protocol version of the executing request, for version-scoped objects.
    version: Option<Version>,
    identity: Option<system::Identity>,
    /// When the request message was received (1.0 section 3.17).
    received: i64,
    /// Response header Server Hashed Password, set when a 2.0+ Hashed
    /// Password credential verified (credential_proofs.rs).
    server_hashed_password: Option<Vec<u8>>,
    /// The certificate's operation allowlist for this message (None: every
    /// operation, as for in-process callers).
    allowed: Option<Vec<u32>>,
    /// Operations of the request items after the current one whose primary
    /// identifier is the ID Placeholder (omitted in 2.x, or the ID
    /// Placeholder enumeration), set before each request item runs.
    later_placeholder_ops: Vec<u32>,
    /// What this message's Re-Provision must have delivered by the end of
    /// the message, or the whole message fails (provisioning.rs).
    must_deliver: Vec<provisioning::Delivery>,
    /// Whether this message has already attempted a Re-Provision; at most
    /// one may run per message, even if the first one failed
    /// (provisioning.rs).
    re_provision_attempted: bool,
    /// Objects (owner, identifier) that exist only for this message and are
    /// removed before it commits (provisioning.rs).
    message_scoped: Vec<(String, String)>,
}
/// Default server maximum Lease Time (seconds) for new objects.
pub const DEFAULT_MAXIMUM_LEASE_SECONDS: u32 = 3600;
pub struct Engine {
    pub store: Store,
    pub experimental_v3: bool,
    maximum_lease: u32,
    authorization: Authorization,
    streams: stream::Streams,
    certificate_validation: crate::certificates::CertificateValidation,
    usage_ledger: undo::UsageLedger,
    triple_des: TripleDesPolicy,
    server_to_client: Option<ServerToClient>,
    side: side::Side,
    policy_users: std::collections::HashMap<String, Vec<crate::credentials::PolicyUser>>,
    policy_devices: std::collections::HashMap<String, Vec<crate::credentials::PolicyDevice>>,
    tickets: tickets::Tickets,
    group_rotation: group_member::Rotation,
    /// Set by `process_reversible` for the request in progress.
    reversible_channel: bool,
    /// Certificate principals whose verified credentials select the owner.
    credential_owners: std::collections::HashSet<String>,
    /// Imported keys of the current batch whose validation needs primality
    /// tests or factor recovery (`transparent::costly`).
    costly_imports: std::cell::Cell<u32>,
    /// Offer the test-only Interop operation (interop.rs); off by default.
    interop_test_mode: bool,
    /// FIPS mode (fips_policy.rs): refuse and hide non-approved services.
    fips: bool,
    /// Elliptic curves KMIP operations may use (`--ec-curves`, ec.rs).
    ec_curves: crate::crypto::ec::EcCurves,
    /// Response forms of the JSON and XML encodings (encoding/options.rs).
    text_encoding: crate::encoding::TextEncoding,
    /// Whether a Name held only by destroyed objects may be reused
    /// (destroyed_names.rs).
    destroyed_name_reuse: DestroyedNameReuse,
    /// Lifecycle states Obtain Lease serves (lease.rs).
    lease_states: LeaseStates,
    /// 2.x/3.0 Get Attributes form when none of the requested attributes
    /// exist (get_attributes_none.rs).
    get_attributes_none: GetAttributesNone,
    /// Operator request counters (metrics.rs); never key material,
    /// identifiers, principals, Names or attribute values.
    metrics: std::sync::Arc<crate::metrics::Registry>,
    /// The TLS connection of the request in progress (`with_channel`);
    /// None for in-process callers and queued batches.
    channel: Option<channel::Channel>,
    /// Re-Provision configuration (`--provisioning-ca`); None: not offered.
    provisioning: Option<provisioning::Provisioning>,
}
impl Engine {
    pub fn new(store: Store, experimental_v3: bool) -> Self {
        // Name and Link lookups use the in-memory index; without it they scan.
        if let Err(error) = store.enable_index(object_index::keys) {
            tracing::warn!(error = %error, "object index unavailable; lookups scan");
        }
        Self {
            store,
            experimental_v3,
            maximum_lease: DEFAULT_MAXIMUM_LEASE_SECONDS,
            authorization: Authorization::default(),
            streams: stream::Streams::default(),
            certificate_validation: crate::certificates::CertificateValidation::default(),
            usage_ledger: undo::UsageLedger::default(),
            triple_des: TripleDesPolicy::default(),
            server_to_client: None,
            side: side::Side::default(),
            policy_users: Default::default(),
            policy_devices: Default::default(),
            tickets: Default::default(),
            group_rotation: Default::default(),
            reversible_channel: false,
            credential_owners: Default::default(),
            costly_imports: Default::default(),
            interop_test_mode: false,
            fips: false,
            ec_curves: Default::default(),
            text_encoding: Default::default(),
            destroyed_name_reuse: Default::default(),
            lease_states: Default::default(),
            get_attributes_none: Default::default(),
            metrics: Default::default(),
            channel: None,
            provisioning: None,
        }
    }
    /// Count answered requests in this registry (default: a private one).
    pub fn with_metrics(mut self, metrics: std::sync::Arc<crate::metrics::Registry>) -> Self {
        self.metrics = metrics;
        self
    }
    pub fn metrics(&self) -> std::sync::Arc<crate::metrics::Registry> {
        self.metrics.clone()
    }
    /// Time one client request message and count its response. Deferred
    /// asynchronous runs call `process_wire` directly and are not counted
    /// again; their Pending answer was counted when the client sent them.
    fn observed(
        &mut self,
        encoding: &'static str,
        process: impl FnOnce(&mut Self) -> R<Node>,
    ) -> R<Node> {
        let started = std::time::Instant::now();
        let result = process(self);
        match &result {
            Ok(response) => self.metrics.observe(encoding, response, started.elapsed()),
            Err(_) => self.metrics.unanswered(encoding),
        }
        result
    }
    /// Response forms of the JSON and XML encodings (default: compatible).
    pub fn with_text_encoding(mut self, forms: crate::encoding::TextEncoding) -> Self {
        self.text_encoding = forms;
        self
    }
    pub fn text_encoding(&self) -> crate::encoding::TextEncoding {
        self.text_encoding
    }
    /// Reuse of Names held only by destroyed objects (default: allow).
    pub fn with_destroyed_name_reuse(mut self, policy: DestroyedNameReuse) -> Self {
        self.destroyed_name_reuse = policy;
        self
    }
    /// Selects the controlled 3DES compatibility policy (default: disabled).
    pub fn with_triple_des(mut self, policy: TripleDesPolicy) -> Self {
        self.triple_des = policy;
        self
    }
    pub fn with_certificate_validation(
        mut self,
        policy: crate::certificates::CertificateValidation,
    ) -> Self {
        self.certificate_validation = policy;
        self
    }
    /// Maximum Lease Time stored on objects created or registered afterwards.
    /// Zero means no lease limit (Obtain Lease, 2.1 section 6.1.35).
    pub fn with_maximum_lease(mut self, seconds: u32) -> Self {
        self.maximum_lease = seconds;
        self
    }
    /// Lifecycle states that receive a lease (default: Active and Deactivated).
    pub fn with_lease_states(mut self, states: LeaseStates) -> Self {
        self.lease_states = states;
        self
    }
    /// 2.x/3.0 Get Attributes form when none of the requested attributes
    /// exist (default: an empty Attributes structure).
    pub fn with_get_attributes_none(mut self, form: GetAttributesNone) -> Self {
        self.get_attributes_none = form;
        self
    }
    pub fn expire_multipart(&mut self) {
        self.streams.purge();
    }
    /// Whether an asynchronous request is waiting for `run_asynchronous`.
    pub fn asynchronous_pending(&self) -> bool {
        self.side.queue.pending()
    }
    pub fn process(&mut self, owner: &str, request: &Node) -> R<Node> {
        self.process_authorized(owner, request, None)
    }
    pub fn process_authorized(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
    ) -> R<Node> {
        self.process_with_grants(owner, request, allowed, &[])
    }
    pub fn process_with_grants(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
        grants: &[crate::authorization::ObjectGrant],
    ) -> R<Node> {
        self.process_with_grants_checked(owner, request, allowed, grants, &mut |_| Ok(()))
    }
    /// Process with an extra check of each response payload before its item
    /// commits. The closure receives payloads, never the final message. Responses
    /// are budgeted in binary TTLV bytes and bounded by the shared encoder tree
    /// limits; the closure does not supply selected-format byte accounting.
    pub fn process_with_grants_checked(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
        grants: &[crate::authorization::ObjectGrant],
        check: &mut dyn FnMut(&Node) -> R<()>,
    ) -> R<Node> {
        let len = |n: &Node| Ok(n.encoded_len());
        let mut wire = Wire {
            check,
            len: &len,
            frame: crate::ttlv::MAX_FRAME,
        };
        self.observed("ttlv", |engine| {
            engine.process_wire(owner, request, allowed, grants, &mut wire)
        })
    }
    /// Process for a selected encoding. Payload representability and the
    /// server frame use that encoder; Maximum Response Size bounds the binary
    /// TTLV-equivalent length of every candidate response, including errors.
    pub fn process_with_grants_encoded(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
        grants: &[crate::authorization::ObjectGrant],
        format: crate::encoding::Format,
    ) -> R<Node> {
        let forms = self.text_encoding;
        let mut check = |n: &Node| {
            format
                .encode_with(n, &forms)
                .map(drop)
                .map_err(|_| fail(8, "Response cannot be represented in selected encoding"))
        };
        let len = |n: &Node| {
            format
                .encode_with(n, &forms)
                .map(|bytes| bytes.len())
                .map_err(|_| response_too_large())
        };
        let mut wire = Wire {
            check: &mut check,
            len: &len,
            frame: if format == crate::encoding::Format::Ttlv {
                crate::ttlv::MAX_FRAME
            } else {
                crate::encoding::MAX_TEXT_FRAME
            },
        };
        let encoding = match format {
            crate::encoding::Format::Ttlv => "ttlv",
            crate::encoding::Format::Json => "json",
            crate::encoding::Format::Xml => "xml",
        };
        self.observed(encoding, |engine| {
            engine.process_wire(owner, request, allowed, grants, &mut wire)
        })
    }
    fn process_wire(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
        grants: &[crate::authorization::ObjectGrant],
        wire: &mut Wire,
    ) -> R<Node> {
        let _fips = crate::fips::enter(self.fips);
        let _curves = crate::crypto::ec::enter(self.curve_set());
        self.streams.purge();
        self.authorization = Authorization::default();
        crate::authorization::validate(grants)
            .map_err(|_| fail(7, "Invalid object grant policy"))?;
        self.authorization = Authorization {
            grants: grants.to_vec(),
            operation: 0,
            version: None,
            identity: None,
            received: now(),
            server_hashed_password: None,
            allowed: allowed.map(<[u32]>::to_vec),
            ..Authorization::default()
        };
        let result = self.process_authorized_inner(owner, request, allowed, wire);
        self.authorization = Authorization::default();
        self.run_prioritized();
        result
    }
    fn process_authorized_inner(
        &mut self,
        owner: &str,
        request: &Node,
        allowed: Option<&[u32]>,
        wire: &mut Wire,
    ) -> R<Node> {
        let mut version = Version(1, 4);
        let mut client_correlation = None;
        // Apply a well-formed limit to every response, including header errors.
        let limit = Budget::new(
            request
                .get(REQUEST_HEADER)
                .and_then(|h| h.get(MAXIMUM_RESPONSE_SIZE))
                .and_then(|n| n.number().ok())
                .map(|n| n as usize),
            wire.frame,
        );
        let result = (|| -> R<Node> {
            if request.tag != REQUEST_MESSAGE {
                return Err(fail(4, "Expected Request Message"));
            }
            // 1.4 Table 327 "Message cannot be parsed"; the 2.x tables also
            // list Invalid Message for every operation.
            let unparsable = |_| fail(4, "Request Header cannot be parsed");
            let header = request.required(REQUEST_HEADER).map_err(unparsable)?;
            version = Version::read(header.required(PROTOCOL_VERSION).map_err(unparsable)?)
                .map_err(|e| {
                    if e.reason == 7 {
                        fail(4, "Protocol Version cannot be parsed")
                    } else {
                        e
                    }
                })?;
            let newer;
            let request = if legacy_errors::newer_minor(version) {
                version = Version(1, 4);
                newer = legacy_errors::without_unknown_fields(request);
                &newer
            } else {
                request
            };
            let header = request.required(REQUEST_HEADER).map_err(unparsable)?;
            if version >= Version(1, 4)
                && let Some(c) = header.get(CLIENT_CORRELATION_VALUE)
            {
                if c.string()?.len() > 1024 {
                    return Err(fail(7, "Client Correlation Value exceeds the server limit"));
                }
                client_correlation = Some(c.clone());
            }
            if !Version::supported(self.experimental_v3).contains(&version) {
                return Err(fail(
                    if version.0 >= 2 { 0x3f } else { 4 },
                    "Unsupported protocol version",
                ));
            }
            let mut header_fields = vec![
                PROTOCOL_VERSION,
                MAXIMUM_RESPONSE_SIZE,
                ASYNCHRONOUS_INDICATOR,
                BATCH_ERROR_CONTINUATION_OPTION,
                BATCH_ORDER_OPTION,
                TIME_STAMP,
                BATCH_COUNT,
                CLIENT_CORRELATION_VALUE,
                SERVER_CORRELATION_VALUE,
            ];
            // Authentication is a request header field from KMIP 1.0 (table 174).
            header_fields.push(AUTHENTICATION);
            no_fields(header, &header_fields)?;
            if version.0 >= 3
                && (header.get(BATCH_COUNT).is_some() || header.get(BATCH_ORDER_OPTION).is_some())
            {
                return Err(fail(
                    7,
                    "Batch Count and Batch Order Option were removed in draft 3.0",
                ));
            }
            let asynchronous = asynchronous::indicator(version, header)?;
            flag(header, BATCH_ORDER_OPTION, true)?;
            for tag in [CLIENT_CORRELATION_VALUE, SERVER_CORRELATION_VALUE] {
                if let Some(c) = header.get(tag) {
                    if version < Version(1, 4) {
                        return Err(fail(7, "Correlation fields require KMIP 1.4 or later"));
                    }
                    c.string()?;
                }
            }
            if let Some(t) = header.get(TIME_STAMP) {
                date_value(t)?;
            }
            let continuation = number(header, BATCH_ERROR_CONTINUATION_OPTION, 2)?;
            if ![1, 2, 3].contains(&continuation) {
                return Err(fail(7, "Invalid Batch Error Continuation Option"));
            }
            let items: Vec<_> = request.all(BATCH_ITEM).collect();
            if request
                .children()?
                .iter()
                .any(|n| n.tag != REQUEST_HEADER && n.tag != BATCH_ITEM)
            {
                return Err(fail(8, "Unsupported message field"));
            }
            if items.is_empty()
                || items.len() > 128
                || version.0 < 3 && items.len() != header.required(BATCH_COUNT)?.number()? as usize
            {
                return Err(fail(4, "Invalid batch count"));
            }
            if items.len() == 1 && header.get(BATCH_ERROR_CONTINUATION_OPTION).is_some() {
                return Err(fail(
                    7,
                    "Batch Error Continuation Option requires multiple items",
                ));
            }
            if version.0 >= 3
                && items
                    .iter()
                    .any(|item| item.get(UNIQUE_BATCH_ITEM_ID).is_some())
            {
                return Err(fail(7, "Unique Batch Item ID was removed in draft 3.0"));
            }
            if items.len() > 1 && version.0 < 3 {
                let mut ids = std::collections::HashSet::new();
                for item in &items {
                    let id = item.required(UNIQUE_BATCH_ITEM_ID)?.byte_string()?;
                    if id.is_empty() || !ids.insert(id.to_vec()) {
                        return Err(fail(4, "Batch item IDs must be present and distinct"));
                    }
                }
            }
            number(header, MAXIMUM_RESPONSE_SIZE, 0)?;
            if let Some(index) = critical_extension(&items) {
                return critical_failure(
                    version,
                    items[index],
                    client_correlation.as_ref(),
                    limit,
                    wire,
                );
            }
            // Credentials narrow the certificate principal to one of its
            // users or devices (Profiles section 3.1.3); see system.rs. A
            // queued batch carries the identity proved at submission, which
            // must still be current. A principal without any permitted
            // operation (an unlisted certificate) gets Permission Denied for
            // every item, so its credentials are not evaluated at all.
            self.authorization.identity = match self.side.queue.submitted_identity() {
                Some(identity) => {
                    if let Some(identity) = &identity
                        && !self.identity_current(owner, identity)?
                    {
                        return Err(fail(3, "Authentication not successful"));
                    }
                    identity
                }
                None if allowed.is_some_and(<[u32]>::is_empty) => None,
                None => self.authenticate(owner, version, header)?,
            };
            if let Some(pending) = self.defer(
                owner,
                version,
                request,
                &items,
                asynchronous,
                allowed,
                client_correlation.as_ref(),
                limit,
                wire,
            )? {
                return Ok(pending);
            }
            // Credential identity (system.rs `use_credential_identity`):
            // the verified user or device owns, reads and is authorized as
            // itself. Deferred batches above keep the principal and select
            // the identity again when they run.
            let principal = owner;
            let credential_owner = self.request_owner(principal);
            let owner = credential_owner.as_deref().unwrap_or(principal);
            // Before any mutation, choose a header with which a response for
            // the continuation option still fits when every result is the
            // smallest legal failure. The echoed Client Correlation Value is
            // optional (1.4 table 284; 2.1 table 398) and is dropped first.
            let floor = items
                .iter()
                .map(|item| {
                    failure_item(
                        item.get(OPERATION)
                            .and_then(|n| n.number().ok())
                            .unwrap_or(0),
                        item.get(UNIQUE_BATCH_ITEM_ID),
                        &response_too_large(),
                        false,
                    )
                })
                .collect::<Vec<_>>();
            let echoes = match &client_correlation {
                Some(c) => vec![Some(c), None],
                None => vec![None],
            };
            let proof = self.authorization.server_hashed_password.clone();
            let sized = echoes.into_iter().find_map(|echo| {
                let header = with_server_proof(response_header(version, 128, echo), proof.as_ref());
                let empty = Node::structure(RESPONSE_MESSAGE, vec![header.clone()]);
                let base = wire.measure(&empty).ok()?;
                let minimal = floor
                    .iter()
                    .map(|item| item_len(wire, &header, base, item))
                    .collect::<Vec<_>>();
                let needed = if continuation == 1 {
                    minimal
                        .iter()
                        .fold(ResponseSize::default(), |a, b| a.saturating_add(*b))
                } else {
                    minimal[0]
                };
                base.saturating_add(needed)
                    .fits(limit)
                    .then_some((header, base, minimal))
            });
            let Some((mut header, base, minimal)) = sized else {
                return Err(unanswerable());
            };
            // Resources reserved for every result after an index under Continue.
            let mut later = vec![ResponseSize::default(); minimal.len() + 1];
            for i in (0..minimal.len()).rev() {
                later[i] = later[i + 1].saturating_add(minimal[i]);
            }
            let request_count = items.len();
            let streams_before = self.streams.clone();
            self.record_server_changes();
            let side_before = self.side.mark();
            if let Err(error) = self.store.begin() {
                drop(self.store.take_changes());
                return Err(error.into());
            }
            let mut outbound = vec![];
            // The request item index of each response item (asynchronous.rs).
            let mut origins = vec![];
            let tickets_before = self.tickets.clone();
            let run = (|| -> R<Node> {
                self.store
                    .conn
                    .execute_batch("SAVEPOINT batch_changes")
                    .map_err(anyhow::Error::from)?;
                // Protection debits of returned Undo items survive rollback.
                self.usage_ledger.start(continuation == 3);
                let mut responses = vec![];
                let mut events = vec![];
                let mut exposures = std::collections::BTreeMap::new();
                let mut batch_undone = false;
                let mut placeholder = None;
                let mut references = identifiers::References::default();
                let mut pair_generations = 0;
                let mut derivations = 0;
                self.costly_imports.set(0);
                let mut split_factories = 0;
                let mut split_objects = 0usize;
                let mut used = base;
                let later_placeholder_ops = channel::later_placeholder_ops(version, &items);
                'requests: for (index, item) in items.into_iter().enumerate() {
                    let op = number(item, OPERATION, 0)?;
                    let id = item.get(UNIQUE_BATCH_ITEM_ID);
                    self.authorization.later_placeholder_ops = later_placeholder_ops[index].clone();
                    self.authorization.operation = op;
                    self.authorization.version = Some(version);
                    let prepared = if self.side.queue.canceled(index) {
                        Err(fail(9, "Operation canceled by requester"))
                    } else if allowed.is_some_and(|ops| !ops.contains(&op)) {
                        Err(fail(12, "Operation denied by certificate policy"))
                    } else {
                        // Identifiers resolved before execution (3.0 Name
                        // References, expansion) report the versioned reason too.
                        self.prepare_identifiers(
                            owner,
                            version,
                            op,
                            item,
                            &references,
                            &placeholder,
                        )
                        .map_err(|e| not_found::versioned(version, op, e))
                    };
                    let mut prepared = match prepared {
                        Ok(items) => items.into_iter().map(Ok).collect::<Vec<_>>(),
                        Err(e) => vec![Err(e)],
                    };
                    // Reserve one result for each remaining request so Continue
                    // can report every attempted item within the same hard cap.
                    // Reject this expansion atomically, before any of its parts.
                    if responses.len() + prepared.len() + request_count - index - 1 > 128 {
                        prepared = vec![Err(server_limit(
                            version,
                            "Expanded batch exceeds the server limit",
                        ))];
                    }
                    // Continue must answer every expanded item; otherwise
                    // this request item fails without executing.
                    if continuation == 1
                        && !used
                            .saturating_add(minimal[index].saturating_mul(prepared.len()))
                            .saturating_add(later[index + 1])
                            .fits(limit)
                    {
                        prepared = vec![Err(response_too_large())];
                    }
                    references.start(op);
                    let parts = prepared.len();
                    for (part, mut prepared) in prepared.into_iter().enumerate() {
                        // Room needed after this result: the next minimal
                        // failure for Stop and Undo, all later ones for Continue.
                        let after_success = if continuation == 1 {
                            minimal[index]
                                .saturating_mul(parts - part - 1)
                                .saturating_add(later[index + 1])
                        } else if part + 1 < parts {
                            minimal[index]
                        } else {
                            minimal.get(index + 1).copied().unwrap_or_default()
                        };
                        let after_failure = if continuation == 1 {
                            after_success
                        } else {
                            ResponseSize::default()
                        };
                        if !used
                            .saturating_add(minimal[index])
                            .saturating_add(after_failure)
                            .fits(limit)
                        {
                            return Err(unanswerable());
                        }
                        if prepared.is_ok() && [2, 29].contains(&op) {
                            pair_generations += 1;
                            if pair_generations > 4 {
                                prepared = Err(server_limit(
                                    version,
                                    "Batch exceeds the RSA generation limit",
                                ));
                            }
                        }
                        if prepared.is_ok()
                            && let Some(refusal) = certify::refused_under_undo(op, continuation)
                        {
                            prepared = Err(refusal);
                        }
                        if prepared.is_ok() && op == 5 {
                            derivations += 1;
                            if derivations > 4 {
                                prepared = Err(server_limit(
                                    version,
                                    "Batch exceeds the key derivation limit",
                                ));
                            }
                        }
                        let previous_placeholder = placeholder.clone();
                        if prepared.is_ok() && [40, 41].contains(&op) {
                            split_factories += 1;
                            let count = if op == 40 {
                                prepared
                                    .as_ref()
                                    .ok()
                                    .and_then(|n| n.get(REQUEST_PAYLOAD))
                                    .and_then(|p| p.get(SPLIT_KEY_PARTS))
                                    .and_then(|n| n.number().ok())
                                    .unwrap_or(0) as usize
                            } else {
                                1
                            };
                            split_objects = split_objects.saturating_add(count);
                            if split_factories > 4 || split_objects > 128 {
                                prepared = Err(server_limit(
                                    version,
                                    "Batch exceeds the split factory limit",
                                ));
                            }
                        }
                        self.store
                            .conn
                            .execute_batch("SAVEPOINT batch_item")
                            .map_err(anyhow::Error::from)?;
                        let audit_id = prepared
                            .as_ref()
                            .ok()
                            .and_then(|item| item.get(REQUEST_PAYLOAD))
                            .and_then(|p| p.get(identifiers::request_identifier_tag(version, op)))
                            .and_then(|n| n.string().ok())
                            .map(str::to_owned);
                        let streams_before_item = self.streams.clone();
                        let charges_before_item = self.usage_ledger.mark();
                        let side_before_item = self.side.mark();
                        let tickets_before_item = self.tickets.clone();
                        let mut result = prepared
                            .and_then(|item| {
                                // Ticket liveness, budgets and delegated Rights
                                // (tickets.rs), inside the item snapshot.
                                self.ticket_authorize_item(
                                    owner,
                                    version,
                                    op,
                                    &item,
                                    &placeholder,
                                )?;
                                // After a Re-Provision only retrievals run
                                // (provisioning.rs).
                                self.after_re_provision(op)?;
                                self.execute(owner, version, op, &item, &mut placeholder)
                            })
                            .map_err(|e| {
                                legacy_errors::versioned(
                                    version,
                                    op,
                                    missing_data::versioned(version, e),
                                )
                            });
                        // Poll answers with the stored result of the polled item.
                        let polled = self.side.queue.poll.take();
                        if let (Ok(_), Some(fields)) = (&result, &polled)
                            && let Some(payload) = fields.iter().find(|n| n.tag == RESPONSE_PAYLOAD)
                            && let Err(error) = (wire.check)(payload)
                        {
                            result = Err(error);
                        }
                        if let Ok(payload) = &mut result
                            && let Err(error) = identifiers::project_payload(version, payload)
                        {
                            result = Err(error);
                        }
                        if let Ok(payload) = &result
                            && let Err(error) = (wire.check)(payload)
                        {
                            result = Err(error);
                        }
                        // A success is kept only if its response fits; otherwise
                        // this item alone fails with Response Too Large.
                        let mut response = None;
                        let polled_status = polled
                            .as_ref()
                            .map_or(0, |fields| asynchronous::status(fields));
                        let result = result.and_then(|payload| {
                            let node = match polled {
                                Some(fields) => {
                                    let mut item = vec![Node::enumeration(OPERATION, op)];
                                    item.extend(id.cloned());
                                    item.extend(fields);
                                    Node::structure(BATCH_ITEM, item)
                                }
                                None => batch_response(op, id, Ok(payload)),
                            };
                            let size = item_len(wire, &header, base, &node);
                            if used
                                .saturating_add(size)
                                .saturating_add(after_success)
                                .fits(limit)
                            {
                                response = Some((node, size));
                                Ok(())
                            } else {
                                Err(response_too_large())
                            }
                        });
                        let status = if result.is_ok() { polled_status } else { 1 };
                        let (response, size) = match (result, response) {
                            (Ok(()), Some(response)) => response,
                            (result, _) => {
                                let error = result.err().unwrap_or_else(response_too_large);
                                self.streams = streams_before_item;
                                self.usage_ledger.discard_after(charges_before_item);
                                self.side.restore(side_before_item);
                                self.tickets = tickets_before_item;
                                self.store
                                    .conn
                                    .execute_batch("ROLLBACK TO batch_item")
                                    .map_err(anyhow::Error::from)?;
                                placeholder = if error.clear_placeholder {
                                    None
                                } else {
                                    previous_placeholder
                                };
                                fit_failure(wire, &header, base, op, id, error, |size| {
                                    used.saturating_add(size)
                                        .saturating_add(after_failure)
                                        .fits(limit)
                                })
                                .unwrap_or_else(|| (floor[index].clone(), minimal[index]))
                            }
                        };
                        self.store
                            .conn
                            .execute_batch("RELEASE batch_item")
                            .map_err(anyhow::Error::from)?;
                        let payload = response.get(RESPONSE_PAYLOAD).filter(|_| status == 0);
                        if let Some(payload) = payload {
                            references.observe(op, payload);
                        }
                        let audit_id = audit_id.or_else(|| {
                            payload
                                .and_then(|p| {
                                    p.get(UNIQUE_IDENTIFIER)
                                        .or_else(|| p.get(PRIVATE_KEY_UNIQUE_IDENTIFIER))
                                })
                                .and_then(|n| n.identifier_text().ok())
                                .map(str::to_owned)
                        });
                        if continuation == 3
                            && matches!(op, 10 | 43)
                            && payload.is_some_and(metadata::carries_material)
                            && let Some(id) = audit_id.as_ref()
                            && let Some(mut obj) = self.authorized_object(owner, id)?
                        {
                            metadata::hydrate(&mut obj)?;
                            let clear_fresh = op == 10 || version.0 == 1;
                            exposures
                                .entry((obj.owner.clone(), id.clone()))
                                .and_modify(
                                    |(history, clear): &mut (
                                        crate::store::ObjectMetadata,
                                        bool,
                                    )| {
                                        if obj.metadata.always_sensitive == Some(false) {
                                            history.always_sensitive = Some(false);
                                        }
                                        if obj.metadata.never_extractable == Some(false) {
                                            history.never_extractable = Some(false);
                                        }
                                        *clear |= clear_fresh;
                                    },
                                )
                                .or_insert((obj.metadata.clone(), clear_fresh));
                        }
                        events.push((op, audit_id, status));
                        responses.push(response);
                        origins.push(index);
                        used = used.saturating_add(size);
                        if status == 1 && continuation != 1 {
                            if continuation == 3 {
                                batch_undone = true;
                                self.streams = streams_before.clone();
                                self.side.restore(side_before.clone());
                                self.tickets = tickets_before.clone();
                                // Keep operation payloads (required for Operation Undone),
                                // but roll back every mutation. Audit final outcomes below.
                                self.store
                                    .conn
                                    .execute_batch("ROLLBACK TO batch_changes")
                                    .map_err(anyhow::Error::from)?;
                                for response in responses.iter_mut().rev().skip(1) {
                                    let mut fields = vec![];
                                    for tag in [OPERATION, UNIQUE_BATCH_ITEM_ID] {
                                        if let Some(n) = response.get(tag) {
                                            fields.push(n.clone());
                                        }
                                    }
                                    fields.push(Node::enumeration(RESULT_STATUS, 3));
                                    if let Some(payload) = response.get(RESPONSE_PAYLOAD) {
                                        fields.push(payload.clone());
                                    }
                                    *response = Node::structure(BATCH_ITEM, fields);
                                }
                                for event in events.iter_mut().rev().skip(1) {
                                    event.2 = 3;
                                }
                            }
                            break 'requests;
                        }
                        // KMIP 1.0 section 4.9: a failed Check ends the batch
                        // whatever the continuation option ("the server SHALL
                        // ignore any subsequent operations in the batch").
                        if status == 1 && op == 9 && version == Version(1, 0) {
                            break 'requests;
                        }
                    }
                }
                // Message-scoped objects go before the batch commits and
                // before server-to-client messages are derived; an error
                // fails the whole message (provisioning.rs).
                self.finish_message(&responses)?;
                self.store
                    .conn
                    .execute_batch("RELEASE batch_changes")
                    .map_err(anyhow::Error::from)?;
                // Undone payloads keep their protection output, so their usage
                // debits survive (see undo.rs). Without Undo nothing is recorded.
                let charges = self.usage_ledger.finish();
                // A returned Undone payload may still contain key bytes. Keep
                // that exposure history even when its batch changes roll back.
                if batch_undone {
                    self.retain_undone_usage(charges)?;
                    for ((object_owner, id), (history, clear_fresh)) in exposures {
                        if let Some(mut obj) = self.store.get(&object_owner, &id)? {
                            metadata::hydrate(&mut obj)?;
                            let prior = (
                                obj.metadata.fresh,
                                obj.metadata.always_sensitive,
                                obj.metadata.never_extractable,
                            );
                            if history.always_sensitive == Some(false) {
                                obj.metadata.always_sensitive = Some(false);
                            }
                            if history.never_extractable == Some(false) {
                                obj.metadata.never_extractable = Some(false);
                            }
                            if clear_fresh {
                                self.mark_served(&mut obj)?;
                            }
                            if prior
                                != (
                                    obj.metadata.fresh,
                                    obj.metadata.always_sensitive,
                                    obj.metadata.never_extractable,
                                )
                            {
                                obj.updated = now();
                                self.store.put(&obj)?;
                            }
                        }
                    }
                }
                // Verified header credentials attribute events to the user or device.
                let principal = match &self.authorization.identity {
                    Some(identity) => identity.audit_principal(principal),
                    None => principal.to_owned(),
                };
                for (op, id, status) in events {
                    self.store.audit(&principal, op, id.as_deref(), status)?;
                }
                outbound = self.server_messages();
                set_batch_count(&mut header, responses.len());
                let mut out = vec![header];
                out.extend(responses);
                let response = Node::structure(RESPONSE_MESSAGE, out);
                // Every result was sized before it was kept, so this only
                // guards the accounting: nothing commits unless it can be sent.
                if !wire.measure(&response).is_ok_and(|size| size.fits(limit)) {
                    return Err(unanswerable());
                }
                Ok(response)
            })();
            // An aborted batch rolls back entirely and delivers nothing.
            self.usage_ledger.finish();
            // Recording ends with the batch even when no message was built.
            drop(self.store.take_changes());
            match run {
                Ok(r) => {
                    if let Err(error) = self.store.commit() {
                        self.streams = streams_before;
                        self.side.restore(side_before);
                        self.tickets = tickets_before;
                        let _ = self.store.rollback();
                        return Err(error.into());
                    }
                    self.side.commit();
                    self.side.queue.finished(origins);
                    // Only committed changes leave the server.
                    self.deliver(outbound);
                    Ok(r)
                }
                Err(e) => {
                    self.streams = streams_before;
                    self.side.restore(side_before);
                    self.tickets = tickets_before;
                    self.store.rollback()?;
                    Err(e)
                }
            }
        })();
        match result {
            Ok(r) => Ok(r),
            Err(e) => message_failure(
                version,
                legacy_errors::versioned(version, 0, e),
                client_correlation.as_ref(),
                limit,
                wire,
            ),
        }
    }
    fn execute(
        &mut self,
        owner: &str,
        v: Version,
        op: u32,
        item: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Node> {
        // Draft 3.0 constraints are checked on every object the item created.
        self.constrained(owner, v, op, |engine| {
            engine.execute_operation(owner, v, op, item, placeholder)
        })
        .map_err(|e| not_found::versioned(v, op, e))
    }
    fn execute_operation(
        &mut self,
        owner: &str,
        v: Version,
        op: u32,
        item: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Node> {
        noncritical_extensions(v, item)?;
        // A well-formed Non-Critical extension is processed as if absent.
        let fields = [OPERATION, UNIQUE_BATCH_ITEM_ID, REQUEST_PAYLOAD];
        if item.children()?.iter().any(|n| n.tag == MESSAGE_EXTENSION) {
            let rest = item
                .children()?
                .iter()
                .filter(|n| n.tag != MESSAGE_EXTENSION);
            no_fields(&Node::structure(item.tag, rest.cloned().collect()), &fields)?;
        } else {
            no_fields(item, &fields)?;
        }
        if !self.offered_operations(v).contains(&op) {
            return Err(fail(5, "Operation is not supported for this version"));
        }
        let p = item.required(REQUEST_PAYLOAD)?;
        // 1.4 Table 327: "Error parsing batch item or payload within batch
        // item" is Invalid Message.
        if v.0 == 1 && !matches!(p.value, Value::Structure(_)) {
            return Err(fail(4, "Request Payload cannot be parsed"));
        }
        let expanded = self.expand_templates(owner, v, op, p)?;
        let p = expanded.as_ref().unwrap_or(p);
        // Server defaults for omitted attributes of factory operations
        // (defaults.rs).
        let defaulted = self.apply_defaults(owner, v, op, p)?;
        let p = defaulted.as_ref().unwrap_or(p);
        let activated = activation::received(v, op, p, self.authorization.received);
        let p = activated.as_ref().unwrap_or(p);
        let mut fields = if [31, 32, 33, 34, 35, 36, 39].contains(&op) && stream::requested(p) {
            self.multipart(owner, v, op, p, placeholder)?
        } else {
            match op {
                1 => self.create(owner, v, p, false, placeholder)?,
                5 => self.derive_key(owner, v, p, placeholder)?,
                3 => self.register(owner, v, p, placeholder)?,
                2 => self.create_pair(owner, v, p, placeholder)?,
                4 => self.rekey(owner, v, p, placeholder)?,
                6 => self.certify(owner, v, p, placeholder)?,
                7 => self.recertify(owner, v, p, placeholder)?,
                29 => self.rekey_pair(owner, v, p, placeholder)?,
                40 => self.create_split(owner, v, p, placeholder)?,
                41 => self.join_split(owner, v, p, placeholder)?,
                8 => self.locate(owner, v, p, placeholder)?,
                9 => self.check(owner, v, p, placeholder)?,
                10 => self.get(owner, v, p, placeholder, true)?,
                42 => self.import_object(owner, v, p, placeholder)?,
                43 => self.export_object(owner, v, p, placeholder)?,
                11 => self.get_attrs(owner, v, p, placeholder, false)?,
                12 => self.get_attrs(owner, v, p, placeholder, true)?,
                48 => self.adjust_attr(owner, v, p, placeholder)?,
                13..=15 | 49 => self.modify_attr(owner, v, op, p, placeholder)?,
                16 => self.obtain_lease(owner, p, placeholder)?,
                17 => self.allocate_usage(owner, v, p, placeholder)?,
                21 | 22 => self.archive(owner, op, p, placeholder)?,
                18..=20 | 64 => self.lifecycle(owner, v, op, p, placeholder)?,
                23 => self.validate_certificates(owner, v, p)?,
                24 => self.query(owner, v, p)?,
                25 => self.cancel(owner, v, p)?,
                26 => self.poll(owner, v, p)?,
                44 => self.log_message(owner, p)?,
                50 => self.set_endpoint_role(owner, v, p)?,
                51 => self.pkcs11(owner, v, p)?,
                interop::INTEROP => self.interop(owner, v, p)?,
                57 => self.query_asynchronous(owner, v, p)?,
                58 => self.process_asynchronous(owner, v, p)?,
                30 => {
                    let requested = p
                        .all(PROTOCOL_VERSION)
                        .map(Version::read)
                        .collect::<R<Vec<_>>>()?;
                    if p.children()?.iter().any(|n| n.tag != PROTOCOL_VERSION) {
                        return Err(fail(7, "Unsupported discovery field"));
                    }
                    Version::supported(self.experimental_v3)
                        .into_iter()
                        .filter(|v| requested.is_empty() || requested.contains(v))
                        .map(Version::node)
                        .collect()
                }
                31 | 32 => self.crypt(owner, v, op, p, placeholder)?,
                33..=36 => self.sign_mac(owner, v, op, p, placeholder)?,
                37 => {
                    no_fields(p, &[DATA_LENGTH])?;
                    let len = p.required(DATA_LENGTH)?.number()? as usize;
                    let b = crypto::random(len)
                        .map_err(|_| fail(7, "Random length must not exceed 65536 bytes"))?;
                    vec![Node::bytes(DATA, b.to_vec())]
                }
                // KMIP 1.2-3.0 RNG Seed: the server MAY ignore the seeding
                // material and indicate this with Data Length 0. Client bytes
                // never reach the provider DRBG, which stays OS-seeded; the
                // request tree zeroizes them on drop and they are not logged.
                38 => {
                    no_fields(p, &[DATA])?;
                    p.required(DATA)?.byte_string()?;
                    vec![Node::int(DATA_LENGTH, 0)]
                }
                39 => hashing::single(p, v)?,
                59 => {
                    no_fields(p, &[])?;
                    vec![]
                }
                45 => self.login(owner, v, p)?,
                46 => self.logout(owner, v, p)?,
                47 => self.delegated_login(owner, v, p, placeholder)?,
                53 => self.re_provision(owner, v, item, p, placeholder)?,
                54 => self.set_defaults(owner, v, p)?,
                55 => self.set_constraints(owner, v, p)?,
                56 => self.get_constraints(owner, v, p)?,
                60 => self.create_group(owner, v, p, placeholder)?,
                61 => self.obliterate(owner, p, placeholder)?,
                62 => self.create_user(owner, v, p, placeholder)?,
                63 => self.create_credential(owner, v, p, placeholder)?,
                pqc::ENCAPSULATE | pqc::DECAPSULATE => self.kem(owner, v, op, p, placeholder)?,
                _ => return Err(fail(5, "Operation not implemented")),
            }
        };
        if matches!(op, 20 | 42)
            && let Some(id) = fields
                .iter()
                .find(|n| n.tag == UNIQUE_IDENTIFIER)
                .and_then(|n| n.string().ok())
        {
            self.streams.invalidate_key(owner, id);
        }
        Ok(Node::structure(
            RESPONSE_PAYLOAD,
            std::mem::take(&mut fields),
        ))
    }
    fn authorized_object(&self, caller: &str, id: &str) -> R<Option<Object>> {
        Ok(self
            .stored_object(caller, id)?
            .filter(|o| visible(o, self.authorization.version)))
    }
    fn stored_object(&self, caller: &str, id: &str) -> R<Option<Object>> {
        if let Some(object) = self.store.get(caller, id)? {
            return Ok(Some(object));
        }
        for grant in &self.authorization.grants {
            if grant.identifier == id
                && grant.operations.contains(&self.authorization.operation)
                && let Some(object) = self.store.get(&grant.object_owner(), id)?
            {
                return Ok(Some(object));
            }
        }
        Ok(None)
    }
    fn locate_access(&self) -> Vec<(String, &str)> {
        self.authorization
            .grants
            .iter()
            .filter(|grant| grant.operations.contains(&self.authorization.operation))
            .map(|grant| (grant.object_owner(), grant.identifier.as_str()))
            .collect()
    }
    fn object_owned(&self, owner: &str, p: &Node) -> R<Object> {
        let id = p.required(UNIQUE_IDENTIFIER)?.string()?;
        let mut obj = self
            .store
            .get(owner, id)?
            .filter(|o| visible(o, self.authorization.version))
            .ok_or_else(not_found::object)?;
        template::not_key(&obj)?;
        key_value::require(&obj)?;
        metadata::hydrate(&mut obj)?;
        if apply_dates(&mut obj) {
            self.store.put(&obj)?;
        }
        archive::online(&obj)?;
        Ok(obj)
    }
    fn object(&self, owner: &str, p: &Node, placeholder: &Option<String>) -> R<Object> {
        let obj = self.object_including_archived(owner, p, placeholder)?;
        archive::online(&obj)?;
        Ok(obj)
    }
    fn object_including_archived(
        &self,
        owner: &str,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Object> {
        let id = match p.get(UNIQUE_IDENTIFIER) {
            Some(n) => n.string()?,
            None => placeholder
                .as_deref()
                .ok_or_else(|| identifiers::no_placeholder(self.authorization.version))?,
        };
        let mut obj = self
            .authorized_object(owner, id)?
            .ok_or_else(not_found::object)?;
        template::permits(&obj, self.authorization.operation)?;
        key_value::require_for(&obj, self.authorization.operation)?;
        metadata::hydrate(&mut obj)?;
        if apply_dates(&mut obj) {
            self.store.put(&obj)?;
        }
        Ok(obj)
    }
    fn create(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        register: bool,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        if register
            && p.get(OBJECT_TYPE)
                .is_some_and(|n| n.number().ok() == Some(1))
        {
            certificate::require_register(p, v)?;
        }
        let obj = self.build_object(owner, v, p, register)?;
        self.unique_names(&obj, v)?;
        quantum::check(&obj)?;
        self.store.insert(&obj)?;
        *placeholder = Some(obj.id.clone());
        let mut result = vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)];
        if !register {
            result.insert(0, Node::enumeration(OBJECT_TYPE, obj.object_type));
        }
        Ok(result)
    }
    fn build_object(&self, owner: &str, v: Version, p: &Node, register: bool) -> R<Object> {
        no_fields(
            p,
            &[
                OBJECT_TYPE,
                TEMPLATE_ATTRIBUTE,
                ATTRIBUTES,
                SYMMETRIC_KEY,
                SECRET_DATA,
                CERTIFICATE,
                PUBLIC_KEY,
                PRIVATE_KEY,
                SPLIT_KEY,
                OPAQUE_OBJECT,
                PGP_KEY,
                CERTIFICATE_REQUEST,
                PROTECTION_STORAGE_MASKS,
            ],
        )?;
        let protection_mask = protection::select(p, v)?;
        let kind = p.required(OBJECT_TYPE)?.number()?;
        if ![1, 2, 3, 4, 5, 7, 8, 9, certificate_request::KIND].contains(&kind)
            || !register && kind != 2
        {
            return Err(fail(8, "Object type is not supported by this operation"));
        }
        pgp::available(kind, v)?;
        certificate_request::available(kind, v)?;
        fips_policy::object_type(kind)?;
        let expected_object_tag = object_tag(kind)?;
        if p.children()?.iter().any(|n| {
            [
                SYMMETRIC_KEY,
                SECRET_DATA,
                CERTIFICATE,
                PUBLIC_KEY,
                PRIVATE_KEY,
                SPLIT_KEY,
                OPAQUE_OBJECT,
                PGP_KEY,
                CERTIFICATE_REQUEST,
            ]
            .contains(&n.tag)
                && (!register || n.tag != expected_object_tag)
        }) {
            return Err(fail(7, "Unexpected object in payload"));
        }
        let mut attrs = read_attrs(p, v)?;
        metadata::prepare(&mut attrs, v, !register)?;
        validate_attrs(&attrs, v)?;
        certificate::attribute_context(kind, &attrs)?;
        let split = if kind == 5 {
            let meta = split::read(p.required(SPLIT_KEY)?, v, &attrs)?;
            split::strip_attributes(&mut attrs);
            Some(meta)
        } else {
            split::ordinary_attributes(&attrs)?;
            None
        };
        let mut alg = attr_num(
            &attrs,
            CRYPTOGRAPHIC_ALGORITHM,
            if kind == 2 { 3 } else { 0 },
        )?;
        let mut bits = attr_num(
            &attrs,
            CRYPTOGRAPHIC_LENGTH,
            if kind == 2 && alg == tdea::ALGORITHM {
                168
            } else if kind == 2 {
                256
            } else {
                0
            },
        )?;
        let mut usage = attr_num(&attrs, CRYPTOGRAPHIC_USAGE_MASK, 0)?;
        let mut metadata_only = false;
        let (format, material) = if register {
            let object_tag = object_tag(kind)?;
            let o = p.required(object_tag)?;
            if kind == 1 {
                let certificate_type = certificate::read_type(o)?;
                let b = o.required(CERTIFICATE_VALUE)?.byte_string()?.to_vec();
                (alg, bits) = certificate::prepare(certificate_type, &b, &mut attrs, v)?;
                usage = attr_num(&attrs, CRYPTOGRAPHIC_USAGE_MASK, 0)?;
                (0, b)
            } else if kind == 8 {
                opaque::read(o)?;
                (0, o.required(OPAQUE_DATA_VALUE)?.byte_string()?.to_vec())
            } else if kind == certificate_request::KIND {
                (0, certificate_request::read(o)?.1)
            } else if key_value::omitted(o, v) {
                let format;
                (format, alg, bits) = key_value::register(kind, o, &mut attrs, v)?;
                fips_policy::asymmetric_algorithm(kind, alg)?;
                if kind == 2 && alg == tdea::ALGORITHM {
                    tdea::metadata_only(self.triple_des, bits)?;
                } else if kind == 2 {
                    validate_symmetric_parameters(alg, bits, v)?;
                }
                metadata_only = true;
                (format, vec![])
            } else {
                if kind == 9 {
                    pgp::read(o, v)?;
                } else if kind != 5 {
                    no_fields(o, &[KEY_BLOCK, SECRET_DATA_TYPE])?;
                }
                if kind == 7 && ![1, 2].contains(&number(o, SECRET_DATA_TYPE, 2)?) {
                    return Err(fail(8, "Only Password or Seed Secret Data is supported"));
                }
                let kb = o.required(KEY_BLOCK)?;
                no_fields(
                    kb,
                    &[
                        KEY_FORMAT_TYPE,
                        KEY_COMPRESSION_TYPE,
                        KEY_VALUE,
                        CRYPTOGRAPHIC_ALGORITHM,
                        CRYPTOGRAPHIC_LENGTH,
                    ],
                )?;
                let f = number(kb, KEY_FORMAT_TYPE, 1)?;
                let kv = kb.required(KEY_VALUE)?;
                no_fields(kv, &[KEY_MATERIAL])?;
                let km = kv.required(KEY_MATERIAL)?;
                let reported_alg = number(
                    kb,
                    CRYPTOGRAPHIC_ALGORITHM,
                    match (alg, transparent::implied_algorithm(f)) {
                        (0, Some(implied)) if matches!(kind, 3 | 4) => implied,
                        _ => alg,
                    },
                )?;
                if attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_ALGORITHM) && reported_alg != alg {
                    return Err(fail(7, "Conflicting algorithm"));
                }
                alg = reported_alg;
                fips_policy::asymmetric_algorithm(kind, alg)?;
                let is_ec = matches!(kind, 3 | 4) && ec::algorithm(alg);
                let is_pq = matches!(kind, 3 | 4) && pqc::algorithm(alg);
                let is_transparent = transparent::handles(kind, alg, f);
                if matches!(kind, 3 | 4)
                    && transparent::implied_algorithm(f).is_some_and(|implied| implied != alg)
                {
                    return Err(fail(7, "Key format conflicts with the algorithm"));
                }
                let m = if is_pq {
                    let (material, actual_bits) = pqc::import_material(kind, alg, f, kb, km, v)?;
                    bits = actual_bits;
                    material
                } else if is_transparent {
                    if kb.get(KEY_COMPRESSION_TYPE).is_some() {
                        return Err(fail(8, "Compression requires an EC public key"));
                    }
                    // Like RSA generation, primality tests and factor
                    // recovery are bounded per batch, so one message cannot
                    // hold the engine for long (Server Limit Exceeded).
                    if transparent::costly(kind, alg, f) {
                        let count = self.costly_imports.get() + 1;
                        self.costly_imports.set(count);
                        if count > transparent::MAX_COSTLY_PER_BATCH {
                            return Err(server_limit(
                                v,
                                "Batch exceeds the asymmetric key validation limit",
                            ));
                        }
                    }
                    let (material, actual_bits) = transparent::import_material(kind, alg, f, km)?;
                    bits = actual_bits;
                    material
                } else if is_ec {
                    let (material, actual_bits) = ec::import_material(kind, alg, f, km, &attrs, v)?;
                    bits = actual_bits;
                    if let Some(c) = kb.get(KEY_COMPRESSION_TYPE) {
                        if kind != 3 || !matches!(c.value, Value::Enumeration(1..=4)) {
                            return Err(fail(7, "Invalid EC public key compression"));
                        }
                        if matches!(f, 15 | 17 | 21) {
                            let expected = crypto::ec::point(&material, c.number()?)
                                .map_err(|_| fail(7, "Compression disagrees with curve"))?;
                            if expected != km.required(Q_STRING)?.byte_string()? {
                                return Err(fail(7, "Compression disagrees with point encoding"));
                            }
                        } else if c.number()? != 1 {
                            return Err(fail(8, "Compressed DER import is unsupported"));
                        }
                    }
                    material
                } else {
                    if kb.get(KEY_COMPRESSION_TYPE).is_some() {
                        return Err(fail(8, "Compression requires an EC public key"));
                    }
                    if kind == 2 && ![1, 7].contains(&f)
                        || kind == 7 && ![1, 2].contains(&f)
                        || kind == 3 && ![3, 5].contains(&f)
                        || kind == 4 && ![3, 4].contains(&f)
                        || [5, 9].contains(&kind) && ![1, 2].contains(&f)
                    {
                        return Err(fail(0x10, "Unsupported key format"));
                    }
                    if f == 7 && kind == 2 {
                        no_fields(km, &[KEY])?;
                        km.required(KEY)?.byte_string()?.to_vec()
                    } else {
                        km.byte_string()?.to_vec()
                    }
                };
                if kind == 2 && alg == tdea::ALGORITHM {
                    bits = tdea::import(
                        self.triple_des,
                        &m,
                        kb.get(CRYPTOGRAPHIC_LENGTH)
                            .map(|_| number(kb, CRYPTOGRAPHIC_LENGTH, 0))
                            .transpose()?,
                        attrs
                            .iter()
                            .any(|a| a.tag == CRYPTOGRAPHIC_LENGTH)
                            .then_some(bits),
                    )?;
                } else if kind == 2 || kind == 7 {
                    let actual = (m.len() * 8) as u32;
                    if kb.get(CRYPTOGRAPHIC_LENGTH).is_some()
                        && number(kb, CRYPTOGRAPHIC_LENGTH, actual)? != actual
                        || attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH) && bits != actual
                    {
                        return Err(fail(7, "Key length does not match material"));
                    }
                    bits = actual;
                }
                if kind == 9 {
                    let declared = number(kb, CRYPTOGRAPHIC_LENGTH, bits)?;
                    if attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH) && bits != declared {
                        return Err(fail(7, "PGP key metadata length conflicts"));
                    }
                    bits = declared;
                }
                if kind == 5 {
                    let reported_bits = number(kb, CRYPTOGRAPHIC_LENGTH, bits)?;
                    if attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH) && reported_bits != bits
                    {
                        return Err(fail(7, "Split Key length metadata conflicts"));
                    }
                    bits = reported_bits;
                    split::validate_material(
                        split.as_ref().expect("split metadata"),
                        &m,
                        alg,
                        bits,
                        v,
                    )?;
                }
                if kind == 3 && !is_ec && !is_pq && !is_transparent {
                    let k = if f == 3 {
                        openssl::rsa::Rsa::public_key_from_der_pkcs1(&m)
                            .and_then(openssl::pkey::PKey::from_rsa)
                    } else {
                        openssl::pkey::PKey::public_key_from_der(&m)
                    }
                    .map_err(|_| fail(7, "Invalid public key"))?;
                    if k.id() != openssl::pkey::Id::RSA || alg != 4 {
                        return Err(fail(8, "Only RSA public keys are supported"));
                    }
                    bits = rsa_bounds(&k)?;
                }
                if kind == 4 && !is_ec && !is_pq && !is_transparent {
                    let k = if f == 3 {
                        openssl::rsa::Rsa::private_key_from_der(&m)
                            .and_then(openssl::pkey::PKey::from_rsa)
                    } else {
                        openssl::pkey::PKey::private_key_from_pkcs8(&m)
                    }
                    .map_err(|_| fail(7, "Invalid private key"))?;
                    if k.id() != openssl::pkey::Id::RSA || alg != 4 {
                        return Err(fail(8, "Only RSA private keys are supported"));
                    }
                    bits = rsa_bounds(&k)?;
                }
                if [3, 4].contains(&kind)
                    && (kb.get(CRYPTOGRAPHIC_LENGTH).is_some()
                        && number(kb, CRYPTOGRAPHIC_LENGTH, bits)? != bits
                        || attrs.iter().any(|a| a.tag == CRYPTOGRAPHIC_LENGTH)
                            && attr_num(&attrs, CRYPTOGRAPHIC_LENGTH, bits)? != bits)
                {
                    return Err(fail(7, "Asymmetric key length does not match material"));
                }
                (f, m)
            }
        } else if alg == tdea::ALGORITHM {
            (1, tdea::generate(self.triple_des, bits)?)
        } else {
            validate_symmetric_parameters(alg, bits, v)?;
            fips_policy::generated_symmetric(alg, bits)?;
            (1, crypto::random((bits / 8) as usize)?.to_vec())
        };
        if material.is_empty() && kind != 8 && !metadata_only || material.len() > 65536 {
            return Err(fail(7, "Invalid object size"));
        }
        key_value::location_allowed(&attrs)?;
        if kind == 2 && alg != tdea::ALGORITHM && !metadata_only {
            validate_symmetric_parameters(alg, bits, v)?;
        }
        pgp::metadata(kind, alg, bits, &attrs, v)?;
        let id = crypto::uuid();
        let time = now();
        let mut obj = Object {
            id: id.clone(),
            owner: owner.into(),
            opaque_type: if kind == 8 {
                opaque::read(p.required(OPAQUE_OBJECT)?)?
            } else {
                opaque::LEGACY_TYPE
            },
            object_type: kind,
            certificate_type: if kind == 1 {
                certificate::read_type(p.required(CERTIFICATE)?)?
            } else if kind == certificate_request::KIND {
                certificate_request::read(p.required(CERTIFICATE_REQUEST)?)?.0
            } else {
                1
            },
            pgp_version: if kind == 9 {
                pgp::read(p.required(PGP_KEY)?, v)?
            } else {
                pgp::DEFAULT_VERSION
            },
            secret_type: if kind == 7 {
                number(p.required(SECRET_DATA)?, SECRET_DATA_TYPE, 2)?
            } else {
                2
            },
            format,
            algorithm: alg,
            bits,
            usage,
            protection_mask,
            usage_consumed: false,
            replacement_id: None,
            wrapped: None,
            imported: false,
            metadata: Default::default(),
            split,
            state: 1,
            material,
            attrs,
            attribute_indices: Default::default(),
            created: time,
            updated: time,
        };
        metadata::initialize(&mut obj, v, !register)?;
        usage::initialize(&mut obj, self.maximum_lease)?;
        // The Digest is computed over a Key Value that is absent here.
        if !metadata_only {
            add_digest(&mut obj)?;
        }
        attributes::limits(&obj.attrs)?;
        apply_dates(&mut obj);
        Ok(obj)
    }
    fn create_pair(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                COMMON_TEMPLATE_ATTRIBUTE,
                PRIVATE_KEY_TEMPLATE_ATTRIBUTE,
                PUBLIC_KEY_TEMPLATE_ATTRIBUTE,
                COMMON_ATTRIBUTES,
                PRIVATE_KEY_ATTRIBUTES,
                PUBLIC_KEY_ATTRIBUTES,
                COMMON_PROTECTION_STORAGE_MASKS,
                PRIVATE_PROTECTION_STORAGE_MASKS,
                PUBLIC_PROTECTION_STORAGE_MASKS,
                SEED,
            ],
        )?;
        let (private_mask, public_mask) = protection::pair(p, v)?;
        let common = read_attrs_at(p, v, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES)?;
        let mut private = attributes::pair_union(
            common.clone(),
            read_attrs_at(p, v, PRIVATE_KEY_TEMPLATE_ATTRIBUTE, PRIVATE_KEY_ATTRIBUTES)?,
        )?;
        let mut public = attributes::pair_union(
            common,
            read_attrs_at(p, v, PUBLIC_KEY_TEMPLATE_ATTRIBUTE, PUBLIC_KEY_ATTRIBUTES)?,
        )?;
        // Post-quantum pairs (draft 3.0, pqc.rs): each key has its own
        // Cryptographic Length (section 6.1.11, Table 285).
        let pq = pqc::pair_algorithm(&private, &public)?;
        let seed = pqc::request_seed(p, v, pq)?;
        let pq_lengths = if pq.is_some() {
            Some((
                pqc::take_lengths(&mut private)?,
                pqc::take_lengths(&mut public)?,
            ))
        } else {
            None
        };
        pair_agreement::reconcile(&mut private, &mut public)?;
        // 1.0-1.4 Create Key Pair Attribute Requirements (1.0 table 112, 1.4
        // table 168) make Cryptographic Algorithm and Cryptographic Usage Mask
        // REQUIRED in the request; the error tables answer "REQUIRED field(s)
        // missing" with Invalid Message. 2.x drops the REQUIRED column.
        if v.0 == 1 {
            for tag in [CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_USAGE_MASK] {
                if !private.iter().chain(&public).any(|a| a.tag == tag) {
                    return Err(fail(
                        4,
                        "Create Key Pair requires Cryptographic Algorithm and Usage Mask",
                    ));
                }
            }
        }
        let private_format = ec::take_format(&mut private, v)?;
        let public_format = ec::take_format(&mut public, v)?;
        metadata::prepare(&mut private, v, true)?;
        metadata::prepare(&mut public, v, true)?;
        validate_attrs(&private, v)?;
        validate_attrs(&public, v)?;
        pgp::attribute_context(4, &private)?;
        certificate::attribute_context(4, &private)?;
        certificate::attribute_context(3, &public)?;
        pgp::attribute_context(3, &public)?;
        let (key, bits, alg) = match pq {
            Some(alg) => (pqc::generate(alg, seed.as_deref(), v)?, 0, alg),
            None => rekey::generate_pair(&private, &public, v)?,
        };
        // 2.0+ "Default Key Format Type, by Object" (2.0/2.1 Table 81, 3.0 Table
        // 117): RSA Private Key PKCS#1, RSA Public Key PKCS#1. 1.x defines no
        // default; generated 1.x keys keep PKCS#8 and X.509 SubjectPublicKeyInfo.
        let private_format = private_format.unwrap_or(if pq.is_some() {
            pqc::default_format()
        } else if ec::algorithm(alg) {
            ec::default_format(4, alg, v)
        } else if v.0 >= 2 {
            3
        } else {
            4
        });
        let public_format = public_format.unwrap_or(if pq.is_some() {
            pqc::default_format()
        } else if ec::algorithm(alg) {
            ec::default_format(3, alg, v)
        } else if v.0 >= 2 {
            3
        } else {
            5
        });
        if pq.is_some() {
            if !pqc::format_allowed(4, private_format) || !pqc::format_allowed(3, public_format) {
                return Err(fail(0x10, "Unsupported post-quantum pair format"));
            }
        } else if ec::algorithm(alg) {
            if !ec::format_allowed(4, alg, private_format, v)
                || !ec::format_allowed(3, alg, public_format, v)
            {
                return Err(fail(0x10, "Unsupported EC pair format"));
            }
        } else if !transparent::format_allowed(4, alg, private_format)
            || !transparent::format_allowed(3, alg, public_format)
        {
            return Err(fail(0x10, "Unsupported RSA pair format"));
        }
        let priv_id = crypto::uuid();
        let pub_id = crypto::uuid();
        let time = now();
        for (id, kind, format, material, mut attrs, other, link) in [
            (
                &priv_id,
                4,
                private_format,
                if pq.is_some() {
                    pqc::pair_material(4, &key)?
                } else if matches!(private_format, 3 | transparent::RSA_PRIVATE) {
                    key.rsa()?.private_key_to_der()?
                } else if private_format == 6 {
                    key.ec_key()?.private_key_to_der()?
                } else {
                    key.private_key_to_pkcs8()?
                },
                private,
                &pub_id,
                0x102,
            ),
            (
                &pub_id,
                3,
                public_format,
                if pq.is_some() {
                    pqc::pair_material(3, &key)?
                } else if matches!(public_format, 3 | transparent::RSA_PUBLIC) {
                    key.rsa()?.public_key_to_der_pkcs1()?
                } else {
                    key.public_key_to_der()?
                },
                public,
                &priv_id,
                0x103,
            ),
        ] {
            if attrs.iter().any(|a| {
                a.tag == LINK && a.get(LINK_TYPE).and_then(|n| n.number().ok()) == Some(link)
            }) {
                return Err(fail(
                    7,
                    "A generated key pair's reverse link is assigned by the server",
                ));
            }
            attrs.push(Node::structure(
                LINK,
                vec![
                    Node::enumeration(LINK_TYPE, link),
                    Node::text(LINKED_OBJECT_IDENTIFIER, other),
                ],
            ));
            let usage = attr_num(&attrs, CRYPTOGRAPHIC_USAGE_MASK, 0)?;
            let bits = match pq_lengths {
                Some((private_length, public_length)) => pqc::length(
                    alg,
                    kind,
                    &material,
                    if kind == 4 {
                        private_length
                    } else {
                        public_length
                    },
                )?,
                None => bits,
            };
            let mut obj = Object {
                id: id.clone(),
                owner: owner.into(),
                object_type: kind,
                certificate_type: 1,
                opaque_type: opaque::LEGACY_TYPE,
                pgp_version: pgp::DEFAULT_VERSION,
                secret_type: 2,
                format,
                algorithm: alg,
                bits,
                usage,
                protection_mask: if kind == 4 { private_mask } else { public_mask },
                usage_consumed: false,
                replacement_id: None,
                wrapped: None,
                imported: false,
                metadata: Default::default(),
                split: None,
                state: 1,
                material,
                attrs,
                attribute_indices: Default::default(),
                created: time,
                updated: time,
            };
            metadata::initialize(&mut obj, v, true)?;
            usage::initialize(&mut obj, self.maximum_lease)?;
            add_digest(&mut obj)?;
            attributes::limits(&obj.attrs)?;
            apply_dates(&mut obj);
            self.unique_names(&obj, v)?;
            quantum::check(&obj)?;
            self.store.insert(&obj)?;
        }
        *placeholder = Some(priv_id.clone());
        Ok(vec![
            Node::text(PRIVATE_KEY_UNIQUE_IDENTIFIER, priv_id),
            Node::text(PUBLIC_KEY_UNIQUE_IDENTIFIER, pub_id),
        ])
    }
    fn locate(
        &mut self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &mut Option<String>,
    ) -> R<Vec<Node>> {
        let mut filters = vec![];
        for n in p.children()? {
            match n.tag {
                MAXIMUM_ITEMS | OFFSET_ITEMS | STORAGE_STATUS_MASK => {}
                OBJECT_GROUP_MEMBER if v >= Version(1, 1) => {}
                ATTRIBUTE if v.0 == 1 => filters.push(decode_attribute(n)?),
                ATTRIBUTES if v.0 >= 2 => filters.extend(n.children()?.to_vec()),
                _ => return Err(fail(8, "Unsupported Locate field")),
            }
        }
        for f in &filters {
            if f.tag == PROTECTION_STORAGE_MASK {
                protection::mask(f, v)?;
            }
            if f.tag == OPAQUE_DATA_TYPE {
                if v.0 < 2 {
                    return Err(fail(7, "Opaque Data Type attribute requires KMIP 2.0"));
                }
                opaque::value(f)?;
            }
            if certificate::identity_attribute(f.tag)
                || matches!(f.tag, CERTIFICATE_TYPE | CERTIFICATE_LENGTH)
            {
                certificate::validate_attribute(f, v)?;
            }
            if f.tag == DIGITAL_SIGNATURE_ALGORITHM {
                pgp::signature(f, v)?;
            }
            if locate_filters::undefined(f.tag, v) {
                return Err(fail(7, "Filter is unavailable in this version"));
            }
            if locate_filters::supported(f.tag, v) {
                locate_filters::validate(f, v)?;
            }
            if ![
                UNIQUE_IDENTIFIER,
                OBJECT_TYPE,
                STATE,
                CRYPTOGRAPHIC_ALGORITHM,
                CRYPTOGRAPHIC_LENGTH,
                CRYPTOGRAPHIC_USAGE_MASK,
                PROTECTION_STORAGE_MASK,
                OPAQUE_DATA_TYPE,
                DIGITAL_SIGNATURE_ALGORITHM,
                CERTIFICATE_TYPE,
                CERTIFICATE_LENGTH,
                NAME,
                ALTERNATIVE_NAME,
                OBJECT_GROUP,
                APPLICATION_SPECIFIC_INFORMATION,
                CRYPTOGRAPHIC_PARAMETERS,
                CRYPTOGRAPHIC_DOMAIN_PARAMETERS,
                ATTRIBUTE,
                USAGE_LIMITS,
                LEASE_TIME,
                FRESH,
                SENSITIVE,
                EXTRACTABLE,
                ALWAYS_SENSITIVE,
                NEVER_EXTRACTABLE,
                RANDOM_NUMBER_GENERATOR,
                SHORT_UNIQUE_IDENTIFIER,
                OBJECT_CLASS,
                ARCHIVE_DATE,
                SPLIT_KEY_METHOD,
                SPLIT_KEY_PARTS,
                SPLIT_KEY_THRESHOLD,
                SPLIT_KEY_POLYNOMIAL,
            ]
            .contains(&f.tag)
                && !locate_dates::standard(f.tag)
                && !(v.0 >= 2 && quantum::attribute(f.tag))
                && !certificate::identity_attribute(f.tag)
                && !(v.0 >= 3 && identifiers::link_type(f.tag).is_some())
                && !(v.0 >= 3 && [GROUP_LINK, CERTIFICATE_REQUEST_LINK].contains(&f.tag))
                && !(v.0 < 3 && f.tag == LINK)
                && !(policy::defined(v) && f.tag == OPERATION_POLICY_NAME)
                && !(key_value::defined(v) && f.tag == KEY_VALUE_PRESENT)
                && !locate_filters::supported(f.tag, v)
            {
                return Err(fail(8, "Unsupported Locate filter"));
            }
            if f.tag == KEY_VALUE_PRESENT {
                f.flag()?;
            }
            if f.tag == OPERATION_POLICY_NAME {
                // Another name is well formed but matches no object.
                f.string()?;
            }
            if f.tag == LINK {
                // Both fields, as in an attribute value: 2.x request normalization resolves the target.
                no_fields(f, &[LINK_TYPE, LINKED_OBJECT_IDENTIFIER])?;
                if !matches!(
                    f.required(LINK_TYPE)?.value,
                    Value::Enumeration(0x101..=0x10e)
                ) {
                    return Err(fail(7, "Unsupported Link Type"));
                }
                if !matches!(&f.required(LINKED_OBJECT_IDENTIFIER)?.value, Value::TextString(id) if !id.is_empty())
                {
                    return Err(fail(7, "Invalid link target"));
                }
            }
            if matches!(
                f.tag,
                FRESH | SENSITIVE | EXTRACTABLE | ALWAYS_SENSITIVE | NEVER_EXTRACTABLE
            ) {
                if f.tag == FRESH && v < Version(1, 1) || f.tag != FRESH && v < Version(1, 4) {
                    return Err(fail(7, "Filter is unavailable in this version"));
                }
                f.flag()?;
            }
            if [
                SPLIT_KEY_METHOD,
                SPLIT_KEY_PARTS,
                SPLIT_KEY_THRESHOLD,
                SPLIT_KEY_POLYNOMIAL,
            ]
            .contains(&f.tag)
            {
                if v.0 < 3 {
                    return Err(fail(7, "Split Key attribute filters require draft 3.0"));
                }
                split::validate_attribute(f)?;
            }
            if f.tag == RANDOM_NUMBER_GENERATOR {
                if v < Version(1, 3) {
                    return Err(fail(7, "Filter is unavailable in this version"));
                }
                metadata::validate_rng(f)?;
            }
            if f.tag == SHORT_UNIQUE_IDENTIFIER && (v.0 < 2 || f.byte_string()?.len() != 32) {
                return Err(fail(7, "Invalid Short Unique Identifier filter"));
            }
            if f.tag == OBJECT_CLASS && (v.0 < 3 || !matches!(f.value, Value::Enumeration(_))) {
                return Err(fail(7, "Invalid Object Class filter"));
            }
            if f.tag == ATTRIBUTE {
                vendor_identity(f)?;
                f.required(ATTRIBUTE_VALUE)?;
            }
            if f.tag == GROUP_LINK {
                system::validate_group_link(f, v)?;
            }
            if f.tag == CERTIFICATE_REQUEST_LINK {
                certificate_request::validate_link(f, v)?;
            }
            if f.tag == CRYPTOGRAPHIC_DOMAIN_PARAMETERS {
                ec::domain(f, v)?;
            }
            if f.tag == CRYPTOGRAPHIC_PARAMETERS {
                validate_cryptographic_parameters(f, v)?;
            }
            if f.tag == ALTERNATIVE_NAME {
                attributes::validate_alternative_name_filter(f, v)?;
            }
            if f.tag == USAGE_LIMITS {
                usage::validate_filter(f)?;
            }
            if f.tag == LEASE_TIME {
                usage::interval_value(f)?;
            }
        }
        let storage_mask = archive::storage_mask(p, v, &filters)?;
        let member = group_member::requested(p, v, &filters)?;
        if member == Some(group_member::Member::Fresh) {
            filters.push(Node::boolean(FRESH, true));
        }
        let dates = locate_dates::compile(&mut filters, v)?;
        for tag in [MAXIMUM_ITEMS, OFFSET_ITEMS, ATTRIBUTES, STORAGE_STATUS_MASK] {
            if p.all(tag).count() > 1 {
                return Err(fail(7, "Duplicate Locate field"));
            }
        }
        let max = number(p, MAXIMUM_ITEMS, 1000)?.min(1000) as usize;
        let offset = number(p, OFFSET_ITEMS, 0)? as usize;
        if offset > crate::store::MAX_LOCATE_OFFSET {
            return Err(fail(
                if v.0 >= 2 { 0x1b } else { 7 },
                "Locate offset exceeds resource limit",
            ));
        }
        let matches = |o: &Object| {
            if !visible(o, Some(v)) || !archive::matches_storage(o, v, storage_mask) {
                return false;
            }
            let attrs = object_attrs(o, v);
            dates.iter().all(|date| date.matches(&attrs))
                && filters
                    .iter()
                    .all(|f| attrs.iter().any(|a| attribute_matches(f, a)))
        };
        // A Name or Link filter narrows the objects examined to the index's
        // candidates; `matches` still decides each one.
        let candidates = filters
            .iter()
            .find_map(object_index::key)
            .and_then(|key| self.store.index_candidates(&key));
        let candidates = candidates.as_deref();
        let (total, ids) = match member {
            None => self.store.locate_among(
                owner,
                &self.locate_access(),
                candidates,
                offset,
                max,
                false,
                matches,
            )?,
            // 2.0+ section 6.1.27 returns several identifiers newest first;
            // 1.x sets no order, and fresh members are served oldest first.
            Some(group_member::Member::Fresh) => self.store.locate_among(
                owner,
                &self.locate_access(),
                candidates,
                offset,
                max,
                v.0 == 1,
                matches,
            )?,
            Some(group_member::Member::Default) => {
                // One default object per request; paging does not apply.
                if offset != 0 {
                    return Err(fail(
                        7,
                        "Offset Items does not apply to Group Member Default",
                    ));
                }
                let (members, _) = self.store.locate_among(
                    owner,
                    &self.locate_access(),
                    candidates,
                    0,
                    0,
                    true,
                    matches,
                )?;
                if members == 0 || max == 0 {
                    (0, vec![])
                } else {
                    let position = self.group_rotation.next(owner, &filters)
                        % members.min(crate::store::MAX_LOCATE_OFFSET + 1);
                    let (_, ids) = self.store.locate_among(
                        owner,
                        &self.locate_access(),
                        candidates,
                        position,
                        1,
                        true,
                        matches,
                    )?;
                    (ids.len(), ids)
                }
            }
        };
        *placeholder = if ids.len() == 1 {
            ids.first().cloned()
        } else {
            None
        };
        let mut result = vec![];
        if v >= Version(1, 3) {
            result.push(Node::int(LOCATED_ITEMS, total as i32));
        }
        result.extend(ids.iter().map(|id| Node::text(UNIQUE_IDENTIFIER, id)));
        Ok(result)
    }
    fn get(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &Option<String>,
        served: bool,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                KEY_FORMAT_TYPE,
                KEY_COMPRESSION_TYPE,
                KEY_WRAP_TYPE,
                KEY_WRAPPING_SPECIFICATION,
            ],
        )?;
        let wrap_type = transfer::wrap_type(p, 1, v)?;
        let mut obj = self.object(owner, p, placeholder)?;
        if obj.object_type == template::KIND {
            return template::get(&obj, p);
        }
        split::check_version(&obj, v)?;
        pgp::available(obj.object_type, v)?;
        if obj.object_type == 9 && obj.algorithm != 0 {
            pgp::projectable(
                &Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm),
                v,
            )?;
        }
        if obj.state >= 5 {
            // Every 1.x Get Errors table (1.0 table 236, 1.1 table 260,
            // 1.2 table 301, 1.3 and 1.4 likewise): "Object exists and is
            // not a Template, but the server only has attributes for this
            // object" -> Illegal Operation. Key Value Not Present (0x13,
            // from 1.2) is listed for Re-key, Re-key Key Pair, Derive Key and
            // (1.3+) the cryptographic operations, never for Get.
            // docs/interpretations.md#result-reasons: 2.0 and
            // later report Object Destroyed, as the OASIS traces BL-M-8
            // (2.0-3.0) expect. `object` resolved
            // the identifier through the caller's ownership or grants first,
            // so another principal's destroyed object still fails as not
            // found.
            return Err(fail(
                if v.0 >= 2 {
                    OBJECT_DESTROYED_REASON
                } else {
                    11
                },
                "Key value has been destroyed",
            ));
        }
        if key_value::absent(&obj) {
            let fields = key_value::get(&obj, p)?;
            if served {
                self.mark_served(&mut obj)?;
            }
            return Ok(fields);
        }
        let as_registered = wrap_type == 2 && obj.wrapped.is_some();
        if p.get(KEY_WRAPPING_SPECIFICATION).is_none()
            && !as_registered
            && attr_flag(&obj.attrs, SENSITIVE, false)?
        {
            return Err(fail(0x16, "Object is sensitive"));
        }
        if !attr_flag(&obj.attrs, EXTRACTABLE, true)? {
            return Err(fail(0x17, "Object is not extractable"));
        }
        if obj.object_type == certificate_request::KIND {
            let value = certificate_request::value(&obj, p)?;
            if served {
                self.mark_served(&mut obj)?;
            }
            return Ok(vec![
                Node::enumeration(OBJECT_TYPE, obj.object_type),
                Node::text(UNIQUE_IDENTIFIER, &obj.id),
                value,
            ]);
        }
        let format = number(p, KEY_FORMAT_TYPE, obj.format)?;
        let compression = match p.get(KEY_COMPRESSION_TYPE) {
            None => 1,
            Some(Node {
                value: Value::Enumeration(n),
                ..
            }) => *n,
            Some(_) => return Err(fail(7, "Key Compression Type must be an Enumeration")),
        };
        if p.get(KEY_COMPRESSION_TYPE).is_some()
            && (!ec::algorithm(obj.algorithm) || obj.object_type != 3)
        {
            return Err(fail(8, "Compression requires an EC public key"));
        }
        if as_registered {
            if p.get(KEY_COMPRESSION_TYPE).is_some() {
                return Err(fail(8, "As Registered cannot change compression"));
            }
            if p.get(KEY_WRAPPING_SPECIFICATION).is_some() {
                return Err(fail(
                    8,
                    "Nested wrapping of As Registered values is not implemented",
                ));
            }
            if format != obj.format {
                return Err(fail(
                    0x10,
                    "An As Registered value cannot change key format",
                ));
            }
            let value = self.registered_value(v, &obj)?;
            if served {
                self.mark_served(&mut obj)?;
            }
            return Ok(vec![
                Node::enumeration(OBJECT_TYPE, obj.object_type),
                Node::text(UNIQUE_IDENTIFIER, &obj.id),
                value,
            ]);
        }
        self.materialize(owner, &mut obj)?;
        let ec_conversion = ec::algorithm(obj.algorithm) && matches!(obj.object_type, 3 | 4);
        if ec_conversion {
            ec::validate_algorithm(obj.algorithm, v)?;
            if ec::as_stored(&obj, format, compression) {
                ec::stored_form_curve(&obj, v)?;
            } else {
                ec::stored_curve(&obj, v)?;
                let (curve, _) = crypto::ec::info(&obj.material, obj.object_type == 4)?;
                ec::curve(curve, v)?;
            }
            if !ec::format_allowed(obj.object_type, obj.algorithm, format, v) {
                return Err(fail(0x10, "Unsupported EC key format for this version"));
            }
        }
        let pq_conversion = pqc::key(&obj);
        if pq_conversion {
            pqc::parameter_set(obj.algorithm, v)?;
            if !pqc::format_allowed(obj.object_type, format) {
                return Err(fail(0x10, "Unsupported post-quantum key format"));
            }
        }
        let rsa_conversion = obj.algorithm == 4
            && match obj.object_type {
                3 => [3, 5].contains(&format),
                4 => [3, 4].contains(&format),
                _ => false,
            };
        let transparent_conversion =
            transparent::format_allowed(obj.object_type, obj.algorithm, format);
        if format != obj.format
            && !(ec_conversion
                || pq_conversion
                || rsa_conversion
                || transparent_conversion
                || obj.object_type == 2 && [1, 7].contains(&format)
                || [5, 9].contains(&obj.object_type) && [1, 2].contains(&format))
        {
            return Err(fail(0x10, "Key format conversion is not supported"));
        }
        if served {
            self.mark_served(&mut obj)?;
        }
        let value = match obj.object_type {
            1 if p.get(KEY_WRAPPING_SPECIFICATION).is_some() => {
                return Err(fail(8, "Certificate wrapping is not implemented"));
            }
            8 if p.get(KEY_WRAPPING_SPECIFICATION).is_some() => {
                return Err(fail(8, "Opaque object wrapping is not implemented"));
            }
            1 => Node::structure(
                CERTIFICATE,
                vec![
                    Node::enumeration(CERTIFICATE_TYPE, obj.certificate_type),
                    Node::bytes(CERTIFICATE_VALUE, obj.material.clone()),
                ],
            ),
            8 => Node::structure(
                OPAQUE_OBJECT,
                vec![
                    Node::enumeration(OPAQUE_DATA_TYPE, obj.opaque_type),
                    Node::bytes(OPAQUE_DATA_VALUE, obj.material.clone()),
                ],
            ),
            kind => {
                let km = if pq_conversion {
                    pqc::key_material(&obj, format)?
                } else if ec_conversion {
                    ec::key_material(&obj, format, compression)?
                } else if transparent_conversion && transparent::is_transparent(format) {
                    transparent::key_material(&obj, format)?
                } else if rsa_conversion && format != obj.format {
                    Node::bytes(
                        KEY_MATERIAL,
                        crypto::rsa::export(&obj.material, kind == 4, format)?.to_vec(),
                    )
                } else if format == 7 {
                    Node::structure(KEY_MATERIAL, vec![Node::bytes(KEY, obj.material.clone())])
                } else {
                    Node::bytes(KEY_MATERIAL, obj.material.clone())
                };
                let value = Node::structure(KEY_VALUE, vec![km]);
                let mut kb = vec![Node::enumeration(KEY_FORMAT_TYPE, format)];
                if ec_conversion && kind == 3 && matches!(format, 15 | 17 | 21) {
                    kb.push(Node::enumeration(KEY_COMPRESSION_TYPE, compression));
                }
                let data = if let Some(spec) = p.get(KEY_WRAPPING_SPECIFICATION) {
                    let (value, data) = self.wrap_value(owner, v, &obj, value, spec)?;
                    kb.push(value);
                    Some(data)
                } else {
                    kb.push(value);
                    None
                };

                // Key Block Cryptographic Algorithm and Length "Does not apply to Secret
                // Data" (Key Block table: 1.x section 2.1.3, 2.0-3.0 section 3.1).
                if kind != 7 && obj.algorithm != 0 {
                    kb.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm));
                }
                if kind != 7 && obj.bits != 0 {
                    kb.push(Node::int(CRYPTOGRAPHIC_LENGTH, obj.bits as i32));
                }
                if let Some(data) = data {
                    kb.push(data);
                }
                let mut children = vec![];
                children.extend(split::fields(&obj)?);
                if kind == 9 {
                    children.push(Node::int(PGP_KEY_VERSION, obj.pgp_version as i32));
                }
                if kind == 7 {
                    children.push(Node::enumeration(SECRET_DATA_TYPE, obj.secret_type));
                }
                children.push(Node::structure(KEY_BLOCK, kb));
                Node::structure(object_tag(kind)?, children)
            }
        };
        Ok(vec![
            Node::enumeration(OBJECT_TYPE, obj.object_type),
            Node::text(UNIQUE_IDENTIFIER, &obj.id),
            value,
        ])
    }
    fn lifecycle(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                REVOCATION_REASON,
                COMPROMISE_OCCURRENCE_DATE,
            ],
        )?;
        let mut obj = self.object(owner, p, placeholder)?;
        if op == 20 && obj.object_type == template::KIND {
            template::destroy(&mut obj);
            self.store.put(&obj)?;
            return Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)]);
        }
        let date_tag = match op {
            18 => {
                if obj.state != 1 {
                    // KMIP 1.x prescribes Permission Denied (1.4 Table 346); 2.0 and later list
                    // Wrong Key Lifecycle State, as for every other lifecycle refusal here.
                    return Err(fail(
                        if v.0 >= 2 { 0x43 } else { 12 },
                        "Only Pre-Active objects can be activated",
                    ));
                }
                obj.state = 2;
                ACTIVATION_DATE
            }
            19 => revocation::apply(&mut obj, v, p)?,
            20 => {
                // 1.4 Table 348 uses Permission Denied for both refusals. The
                // 2.0 Destroy error list (Table 195) also allows Permission
                // Denied, which the 2.0 lifecycle traces expect; 2.1 Table 210
                // traces expect Wrong Key Lifecycle State. Object Destroyed
                // exists from 2.0.
                if obj.state == 2 {
                    return Err(fail(
                        if v >= Version(2, 1) { 0x43 } else { 0xc },
                        "Active objects must be revoked before destruction",
                    ));
                }
                if obj.state >= 5 {
                    return Err(fail(
                        if v.0 >= 2 {
                            OBJECT_DESTROYED_REASON
                        } else {
                            0xc
                        },
                        "Object has already been destroyed",
                    ));
                }
                obj.state = if obj.state == 4 { 6 } else { 5 };
                obj.material.zeroize();
                obj.material.clear();
                obj.wrapped = None;
                DESTROY_DATE
            }
            64 if v.0 == 3 => {
                if obj.state != 2 {
                    return Err(fail(0x43, "Deactivate requires an Active object"));
                }
                obj.state = 3;
                DEACTIVATION_DATE
            }
            _ => return Err(fail(5, "Operation not supported")),
        };
        obj.updated = now();
        obj.attrs.retain(|a| a.tag != date_tag);
        obj.attrs.push(Node::date(date_tag, obj.updated));
        attributes::limits(&obj.attrs)?;
        if op == 19 {
            // Export materializes server metadata (lease, short identifier,
            // etc.) that Import restores. Reserve it too, so an accepted
            // Revoke cannot make its own exported attributes exceed the limit.
            attributes::limits(&object_attrs(&obj, v))?;
        }
        self.store.put(&obj)?;
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    fn query(&self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        if p.children()?.iter().any(|n| n.tag != QUERY_FUNCTION) {
            return Err(fail(7, "Invalid Query field"));
        }
        let functions = p
            .all(QUERY_FUNCTION)
            .map(|n| n.number().map_err(Into::into))
            .collect::<R<Vec<_>>>()?;
        let mut out = vec![];
        for f in functions {
            match f {
                1 => out.extend(
                    self.advertised_operations(owner, v)
                        .into_iter()
                        .map(|op| Node::enumeration(OPERATION, op)),
                ),
                2 => out.extend(
                    // Draft 3.0 System Objects 11-16 (table 582): User,
                    // Group and every credential type (system.rs,
                    // system_credentials.rs).
                    [1, 2, 3, 4, 5, template::KIND, 7, 8, 9, 10]
                        .into_iter()
                        .chain(11..=16)
                        .filter(|kind| *kind != 9 || v >= Version(1, 2))
                        .filter(|kind| *kind != template::KIND || template::defined(v))
                        .filter(|kind| certificate_request::available(*kind, v).is_ok())
                        .filter(|kind| *kind < 11 || v.0 >= 3)
                        .filter(|kind| fips_policy::offers_object_type(self.fips, *kind))
                        .map(|t| Node::enumeration(OBJECT_TYPE, t)),
                ),
                3 => {
                    out.push(Node::text(VENDOR_IDENTIFICATION, "keytend-kmip-server"));
                    out.push(Node::structure(SERVER_INFORMATION, vec![]));
                }
                4..=6 => {}
                // Attestation types (1.2+), validations, profiles and client
                // registration methods (1.3+): none is offered, so these
                // functions succeed with no items (1.4 section 4.25; 2.1
                // section 6.1.40: returned "if the server supports any").
                7 if v >= Version(1, 2) => {}
                9 | 10 | 12 if v >= Version(1, 3) => {}
                // Query RNGs (1.3+): the provider's generator is not described
                // further, which 1.4 section 4.25 and 2.1 section 6.1.40
                // answer with RNG Algorithm Unspecified.
                8 if v >= Version(1, 3) => out.push(Node::structure(
                    RNG_PARAMETERS,
                    vec![Node::enumeration(RNG_ALGORITHM, 1)],
                )),
                // Query Defaults Information (2.0 section 6.1.37, 2.1 section 6.1.40).
                13 if v.0 >= 2 => out.push(self.defaults_information(v)?),
                14 if v.0 >= 2 => out.push(Node::structure(
                    PROTECTION_STORAGE_MASKS,
                    vec![Node::int(
                        PROTECTION_STORAGE_MASK,
                        protection::SOFTWARE as i32,
                    )],
                )),
                11 if v >= Version(1, 3) => out.push(Node::structure(
                    CAPABILITY_INFORMATION,
                    vec![
                        Node::boolean(STREAMING_CAPABILITY, true),
                        // Deferred processing with Poll and Cancel (asynchronous.rs).
                        Node::boolean(ASYNCHRONOUS_CAPABILITY, true),
                        Node::boolean(ATTESTATION_CAPABILITY, false),
                        Node::boolean(BATCH_UNDO_CAPABILITY, true),
                        Node::boolean(BATCH_CONTINUE_CAPABILITY, true),
                    ],
                )),
                _ => return Err(fail(8, "Query function not supported")),
            }
        }
        Ok(out)
    }
    fn crypt(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                CRYPTOGRAPHIC_PARAMETERS,
                DATA,
                IV_COUNTER_NONCE,
                AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA,
                AUTHENTICATED_ENCRYPTION_TAG,
            ],
        )?;
        let mut obj = self.object(owner, p, placeholder)?;
        self.materialize(owner, &mut obj)?;
        let encrypt = op == 31;
        check_use(&obj, v, if encrypt { 4 } else { 8 }, encrypt)?;
        let cp = cryptographic_parameters(&obj, p, v, true)?;
        if obj.algorithm == 4 {
            return self.rsa_crypt(&mut obj, &cp, p, v, encrypt);
        }
        let setup = cipher::setup(&obj, &cp, p, v, encrypt, self.triple_des)?;
        let generated_iv = setup.generated_iv;
        let iv = setup.iv;
        let data = p.required(DATA)?.byte_string()?;
        let aad = p
            .get(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA)
            .map(Node::byte_string)
            .transpose()?
            .unwrap_or(&[]);
        let tag = p
            .get(AUTHENTICATED_ENCRYPTION_TAG)
            .map(Node::byte_string)
            .transpose()?;
        if encrypt {
            self.consume_protection(&mut obj, data.len(), v, 12)?;
        }
        let (out, auth) = crypto::symmetric(
            encrypt,
            &obj.material,
            setup.parameters,
            &iv,
            data,
            aad,
            tag,
        )
        .map_err(|_| fail(10, "Cryptographic operation failed"))?;
        let mut fields = vec![
            Node::text(UNIQUE_IDENTIFIER, &obj.id),
            Node::bytes(DATA, out.to_vec()),
        ];
        if generated_iv {
            fields.push(Node::bytes(IV_COUNTER_NONCE, iv));
        }
        if !auth.is_empty() {
            fields.push(Node::bytes(AUTHENTICATED_ENCRYPTION_TAG, auth));
        }
        Ok(fields)
    }
    fn sign_mac(
        &self,
        owner: &str,
        v: Version,
        op: u32,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                CRYPTOGRAPHIC_PARAMETERS,
                DATA,
                SIGNATURE_DATA,
                MAC_DATA,
                DIGESTED_DATA,
            ],
        )?;
        let mut obj = self.object(owner, p, placeholder)?;
        self.materialize(owner, &mut obj)?;
        let generating = op == 33 || op == 35;
        check_use(
            &obj,
            v,
            match op {
                33 => 1,
                34 => 2,
                35 => 0x80,
                _ => 0x100,
            },
            generating,
        )?;
        if op == 34 && obj.object_type == 1 {
            obj = certificate::verification_key(&obj, v)?;
        }
        let pq = pqc::key(&obj);
        let cp = cryptographic_parameters(&obj, p, v, matches!(op, 33 | 34) && !pq)?;
        if matches!(op, 33 | 34) && !pq {
            no_fields(
                &cp,
                &[
                    HASHING_ALGORITHM,
                    CRYPTOGRAPHIC_ALGORITHM,
                    PADDING_METHOD,
                    DIGITAL_SIGNATURE_ALGORITHM,
                    MASK_GENERATOR,
                    MASK_GENERATOR_HASHING_ALGORITHM,
                    SALT_LENGTH,
                    TRAILER_FIELD,
                ],
            )?;
        }
        let prehashed = p.get(DIGESTED_DATA).is_some();
        if prehashed && (v < Version(1, 4) || ![33, 34].contains(&op))
            || p.get(DATA).is_some() && prehashed
            || p.get(SIGNATURE_DATA).is_some() && op != 34
            || p.get(MAC_DATA).is_some() && op != 36
        {
            return Err(fail(7, "Incompatible cryptographic input fields"));
        }
        let data = p
            .required(if prehashed { DIGESTED_DATA } else { DATA })?
            .byte_string()?;
        if generating {
            self.consume_protection(
                &mut obj,
                data.len(),
                v,
                if op == 35 && v.0 >= 2 { 26 } else { 12 },
            )?;
        }
        let mut result = vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)];
        match op {
            33 | 34 => {
                if op == 33 && obj.object_type != 4 || op == 34 && obj.object_type != 3 {
                    return Err(fail(
                        8,
                        "A signing private key or verifying public key is required",
                    ));
                }
                if pq {
                    result.push(pqc::signature(&obj, v, op, p, &cp)?);
                    return Ok(result);
                }
                if [6, 26].contains(&obj.algorithm) {
                    ec::validate_algorithm(obj.algorithm, v)?;
                    let hash = ec::hash_parameters(&cp, v, &obj, op == 34)?;
                    if prehashed && data.len() != crypto::rsa::digest(hash)?.size() {
                        return Err(fail(7, "Digested Data length does not match ECDSA hash"));
                    }
                    if op == 33 {
                        result.push(Node::bytes(
                            SIGNATURE_DATA,
                            crypto::ec::sign(&obj.material, hash, data, prehashed)
                                .map_err(|_| fail(10, "ECDSA signing failed"))?,
                        ));
                    } else {
                        let valid = crypto::ec::verify(
                            &obj.material,
                            hash,
                            data,
                            prehashed,
                            p.required(SIGNATURE_DATA)?.byte_string()?,
                        )
                        .map_err(|_| fail(10, "ECDSA verification failed"))?;
                        result.push(Node::enumeration(
                            VALIDITY_INDICATOR,
                            if valid { 1 } else { 2 },
                        ));
                    }
                    return Ok(result);
                }
                if op == 34 && obj.algorithm == 5 {
                    let hash = certificate::dsa_hash(&cp, v)?;
                    if prehashed && data.len() != crypto::rsa::digest(hash)?.size() {
                        return Err(fail(7, "Digested Data length does not match DSA hash"));
                    }
                    let valid = crypto::dsa::verify(
                        &obj.material,
                        hash,
                        data,
                        prehashed,
                        p.required(SIGNATURE_DATA)?.byte_string()?,
                    )
                    .map_err(|_| fail(10, "DSA verification failed"))?;
                    result.push(Node::enumeration(
                        VALIDITY_INDICATOR,
                        if valid { 1 } else { 2 },
                    ));
                    return Ok(result);
                }
                if obj.algorithm != 4 {
                    return Err(fail(8, "Unsupported signature key algorithm"));
                }
                let parameters = rsa::signature_parameters(&cp, v, obj.bits)?;
                fips_policy::rsa_signature(&parameters, obj.bits, op == 33, v)?;
                if prehashed && data.len() != crypto::rsa::digest(parameters.hash)?.size() {
                    return Err(fail(
                        7,
                        "Digested Data length does not match the signature hash",
                    ));
                }
                if op == 33 {
                    let sig = crypto::rsa::sign(&obj.material, parameters, data, prehashed)
                        .map_err(|_| fail(10, "Signing failed"))?;
                    result.push(Node::bytes(SIGNATURE_DATA, sig));
                } else {
                    let sig = p.required(SIGNATURE_DATA)?.byte_string()?;
                    let valid =
                        crypto::rsa::verify(&obj.material, parameters, data, prehashed, sig)
                            .map_err(|_| fail(10, "Verification failed"))?;
                    result.push(Node::enumeration(
                        VALIDITY_INDICATOR,
                        if valid { 1 } else { 2 },
                    ));
                }
            }
            35 | 36 => {
                let mechanism = mac::parameters(&obj, &cp, v)?;
                fips_policy::mac(mechanism, &obj.material, op == 35)?;
                let mac = crypto::authentication::compute(mechanism, &obj.material, data)
                    .map_err(|_| fail(10, "MAC failed"))?;
                if op == 35 {
                    result.push(Node::bytes(MAC_DATA, mac));
                } else {
                    use subtle::ConstantTimeEq;
                    let valid =
                        bool::from(mac.as_slice().ct_eq(p.required(MAC_DATA)?.byte_string()?));
                    result.push(Node::enumeration(
                        VALIDITY_INDICATOR,
                        if valid { 1 } else { 2 },
                    ));
                }
            }
            _ => unreachable!(),
        }
        Ok(result)
    }
}
/// The modulus and public exponent bounds every RSA import form shares
/// (`crypto::transparent::check_rsa_bounds`); returns the modulus length.
fn rsa_bounds<T: openssl::pkey::HasPublic>(k: &openssl::pkey::PKeyRef<T>) -> R<u32> {
    let rsa = k.rsa().map_err(|_| fail(7, "Invalid RSA key"))?;
    crypto::transparent::check_rsa_bounds(rsa.n(), rsa.e()).map_err(|_| {
        fail(
            7,
            "RSA key size or public exponent is outside the accepted range",
        )
    })
}
fn check_use(o: &Object, v: Version, mask: u32, generation: bool) -> R<()> {
    if o.material.is_empty() {
        return Err(fail(0x13, "Key value is not available"));
    }
    if o.state != 2 && (generation || ![3, 4].contains(&o.state)) {
        return Err(fail(
            if v.0 >= 2 { 0x43 } else { 12 },
            "Key lifecycle state forbids this operation",
        ));
    }
    if generation && attr_time(&o.attrs, PROTECT_STOP_DATE).is_some_and(|t| t <= now())
        || !generation && attr_time(&o.attrs, PROCESS_START_DATE).is_some_and(|t| t > now())
    {
        // docs/interpretations.md#result-reasons: the OASIS 2.0
        // traces expect Permission Denied and the 2.1/3.0 traces (CS-AC-M-8,
        // CS-BC-M-14) Wrong Key Lifecycle State (2.1 Table 478) for an Active
        // key used outside its Process Start / Protect Stop window.
        return Err(fail(
            if v >= Version(2, 1) { 0x43 } else { 12 },
            "Key usage dates forbid this operation",
        ));
    }
    if !usage::permits_any(o.usage, mask, v) {
        return Err(fail(
            if v.0 >= 2 { 0x29 } else { 12 },
            "Key usage does not permit this operation",
        ));
    }
    Ok(())
}
fn batch_response(op: u32, id: Option<&Node>, result: R<Node>) -> Node {
    let mut out = vec![];
    if op != 0 {
        out.push(Node::enumeration(OPERATION, op));
    }
    if let Some(id) = id {
        out.push(id.clone());
    }
    match result {
        Ok(p) => {
            out.push(Node::enumeration(RESULT_STATUS, 0));
            out.push(p);
        }
        Err(e) => return failure_item(op, id, &e, true),
    }
    Node::structure(BATCH_ITEM, out)
}
/// A failed response item. Operation and Unique Batch Item ID echo the
/// request; Result Message and any failure payload are included with `detail`
/// (1.4 table 285; 2.1 table 399: Result Message is optional).
fn failure_item(op: u32, id: Option<&Node>, e: &Failure, detail: bool) -> Node {
    let mut out = vec![];
    if op != 0 {
        out.push(Node::enumeration(OPERATION, op));
    }
    if let Some(id) = id {
        out.push(id.clone());
    }
    out.push(Node::enumeration(RESULT_STATUS, 1));
    out.push(Node::enumeration(RESULT_REASON, e.reason));
    if detail {
        out.push(Node::text(RESULT_MESSAGE, e.message));
        if let Some(payload) = &e.payload {
            out.push(payload.as_ref().clone());
        }
    }
    Node::structure(BATCH_ITEM, out)
}
/// Additive resources that `item` adds to the item-free `base` message.
/// Checking a complete one-item message also bounds the item's depth in the
/// final response, where every other item is a sibling. Invalid trees never fit.
fn item_len(wire: &Wire, header: &Node, base: ResponseSize, item: &Node) -> ResponseSize {
    wire.measure(&Node::structure(
        RESPONSE_MESSAGE,
        vec![header.clone(), item.clone()],
    ))
    .map_or(ResponseSize::MAX, |n| n.saturating_sub(base))
}
/// The most informative fitting response for a failed item: complete, then
/// without the optional Result Message. A failure payload cannot be dropped,
/// so `None` leaves the caller's minimal Response Too Large result.
fn fit_failure(
    wire: &Wire,
    header: &Node,
    base: ResponseSize,
    op: u32,
    id: Option<&Node>,
    error: Failure,
    fits: impl Fn(ResponseSize) -> bool,
) -> Option<(Node, ResponseSize)> {
    let mut candidates = vec![failure_item(op, id, &error, true)];
    if error.payload.is_none() {
        candidates.push(failure_item(op, id, &error, false));
    }
    candidates.into_iter().find_map(|node| {
        let size = item_len(wire, header, base, &node);
        fits(size).then_some((node, size))
    })
}
fn set_batch_count(header: &mut Node, count: usize) {
    if let Value::Structure(fields) = &mut header.value {
        for field in fields.iter_mut().filter(|n| n.tag == BATCH_COUNT) {
            *field = Node::int(BATCH_COUNT, count as i32);
        }
    }
}
/// A parsable Critical extension rejects the whole message before execution.
/// Return only the first offending item's correlated failure. The cardinality
/// is local policy; Operation and the request ID are mandatory response fields.
fn critical_failure(
    v: Version,
    item: &Node,
    correlation: Option<&Node>,
    limit: Budget,
    wire: &Wire,
) -> R<Node> {
    let op = match item.get(OPERATION).map(|node| &node.value) {
        Some(Value::Enumeration(op)) => *op,
        _ => 0,
    };
    let id = if v.0 < 3 {
        item.get(UNIQUE_BATCH_ITEM_ID)
    } else {
        None
    };
    let error = fail(
        if v.0 >= 2 { 0x3c } else { 8 },
        "Critical Message Extension is not understood",
    );
    // Shed optional correlation before detail, never mandatory item fields.
    for (echo, detail) in [(correlation, true), (None, true), (None, false)] {
        let response = Node::structure(
            RESPONSE_MESSAGE,
            vec![
                response_header(v, 1, echo),
                failure_item(op, id, &error, detail),
            ],
        );
        if wire.measure(&response).is_ok_and(|size| size.fits(limit)) {
            return Ok(response);
        }
    }
    Err(unanswerable())
}
/// A message-level failure (a Batch Item without Operation, 1.4 table 327)
/// for message admission and header errors. Optional fields are shed to fit the
/// limit; if none fits, no KMIP response is sent.
fn message_failure(
    v: Version,
    e: Failure,
    correlation: Option<&Node>,
    limit: Budget,
    wire: &Wire,
) -> R<Node> {
    if e.unanswerable {
        return Err(e);
    }
    for (echo, detail) in [
        (correlation, true),
        (correlation, false),
        (None, true),
        (None, false),
    ] {
        let response = Node::structure(
            RESPONSE_MESSAGE,
            vec![
                response_header(v, 1, echo),
                failure_item(0, None, &e, detail),
            ],
        );
        if wire.measure(&response).is_ok_and(|size| size.fits(limit)) {
            return Ok(response);
        }
    }
    Err(unanswerable())
}
pub fn error_response(v: Version, e: Failure) -> Node {
    error_response_with_correlation(v, e, None)
}
/// The answer to a request on a connection whose certificate the store could
/// not check (a Re-Provision may have retired it): General Failure, in the
/// request's protocol version when it is a supported one, with its Client
/// Correlation Value. The request reaches neither the engine nor the store.
pub fn store_failure_response(request: &Node) -> Node {
    let header = request.get(REQUEST_HEADER);
    let v = header
        .and_then(|h| h.get(PROTOCOL_VERSION))
        .and_then(|n| Version::read(n).ok())
        .filter(|v| Version::supported(true).contains(v))
        .unwrap_or(Version(1, 4));
    error_response_with_correlation(
        v,
        fail(0x100, "Internal operation failed"),
        header.and_then(|h| h.get(CLIENT_CORRELATION_VALUE)),
    )
}
fn response_header(v: Version, count: usize, client_correlation: Option<&Node>) -> Node {
    let mut fields = vec![v.node(), Node::date(TIME_STAMP, now())];
    if v >= Version(1, 4) {
        if let Some(c) = client_correlation {
            fields.push(c.clone());
        }
        fields.push(Node::text(SERVER_CORRELATION_VALUE, crypto::uuid()));
    }
    if v.0 < 3 {
        fields.push(Node::int(BATCH_COUNT, count as i32));
    }
    Node::structure(RESPONSE_HEADER, fields)
}
/// 2.0/2.1 table "Response Header Structure": Server Hashed Password is
/// present "if Hashed Password credential was used", after Time Stamp (and
/// Nonce, which this server never sends).
fn with_server_proof(mut header: Node, proof: Option<&Vec<u8>>) -> Node {
    if let (Some(proof), crate::ttlv::Value::Structure(fields)) = (proof, &mut header.value) {
        let at = fields
            .iter()
            .position(|f| f.tag == TIME_STAMP)
            .map_or(fields.len(), |i| i + 1);
        fields.insert(at, Node::bytes(SERVER_HASHED_PASSWORD, proof.clone()));
    }
    header
}
fn error_response_with_correlation(v: Version, e: Failure, correlation: Option<&Node>) -> Node {
    Node::structure(
        RESPONSE_MESSAGE,
        vec![
            response_header(v, 1, correlation),
            batch_response(0, None, Err(e)),
        ],
    )
}
fn object_tag(kind: u32) -> R<u32> {
    match kind {
        1 => Ok(CERTIFICATE),
        2 => Ok(SYMMETRIC_KEY),
        3 => Ok(PUBLIC_KEY),
        4 => Ok(PRIVATE_KEY),
        5 => Ok(SPLIT_KEY),
        7 => Ok(SECRET_DATA),
        8 => Ok(OPAQUE_OBJECT),
        9 => Ok(PGP_KEY),
        certificate_request::KIND => Ok(CERTIFICATE_REQUEST),
        _ => Err(fail(8, "Unsupported object type")),
    }
}
fn attr_num(attrs: &[Node], tag: u32, default: u32) -> R<u32> {
    attrs
        .iter()
        .find(|n| n.tag == tag)
        .map(Node::number)
        .transpose()
        .map(|n| n.unwrap_or(default))
        .map_err(Into::into)
}
fn attr_flag(attrs: &[Node], tag: u32, default: bool) -> R<bool> {
    attrs
        .iter()
        .find(|n| n.tag == tag)
        .map(Node::flag)
        .transpose()
        .map(|n| n.unwrap_or(default))
        .map_err(Into::into)
}
fn attr_name(tag: u32) -> R<&'static str> {
    match tag {
        CRYPTOGRAPHIC_ALGORITHM => Ok("Cryptographic Algorithm"),
        CRYPTOGRAPHIC_LENGTH => Ok("Cryptographic Length"),
        CRYPTOGRAPHIC_USAGE_MASK => Ok("Cryptographic Usage Mask"),
        APPLICATION_SPECIFIC_INFORMATION => Ok("Application Specific Information"),
        _ => tag_name(tag).ok_or(fail(8, "Unknown attribute")),
    }
}
fn tag_for_attr(name: &str) -> Option<u32> {
    (0x420000..=0x420200).find(|&tag| attr_name(tag).ok() == Some(name))
}
fn read_attrs(p: &Node, v: Version) -> R<Vec<Node>> {
    read_attrs_at(p, v, TEMPLATE_ATTRIBUTE, ATTRIBUTES)
}
fn read_attrs_at(p: &Node, v: Version, old_tag: u32, new_tag: u32) -> R<Vec<Node>> {
    if v.0 == 1 && p.get(new_tag).is_some() || v.0 >= 2 && p.get(old_tag).is_some() {
        return Err(fail(
            7,
            "Attribute container does not match protocol version",
        ));
    }
    if let Some(n) = p.get(if v.0 == 1 { old_tag } else { new_tag }) {
        if v.0 == 1 {
            let mut attrs = n
                .children()?
                .iter()
                .map(|a| {
                    if a.tag == ATTRIBUTE {
                        decode_attribute(a)
                    } else {
                        Err(fail(8, "Template names are not supported"))
                    }
                })
                .collect::<R<Vec<_>>>()?;
            policy::strip(&mut attrs)?;
            Ok(attrs)
        } else {
            Ok(n.children()?.to_vec())
        }
    } else {
        Ok(vec![])
    }
}
fn validate_cryptographic_parameters(cp: &Node, v: Version) -> R<()> {
    no_fields(
        cp,
        &[
            BLOCK_CIPHER_MODE,
            PADDING_METHOD,
            HASHING_ALGORITHM,
            KEY_ROLE_TYPE,
            DIGITAL_SIGNATURE_ALGORITHM,
            CRYPTOGRAPHIC_ALGORITHM,
            RANDOM_IV,
            IV_LENGTH,
            TAG_LENGTH,
            FIXED_FIELD_LENGTH,
            INVOCATION_FIELD_LENGTH,
            COUNTER_LENGTH,
            INITIAL_COUNTER_VALUE,
            SALT_LENGTH,
            MASK_GENERATOR,
            MASK_GENERATOR_HASHING_ALGORITHM,
            P_SOURCE,
            TRAILER_FIELD,
            KEM_ALGORITHM,
            DETERMINISTIC,
            CONTEXT_STRING,
            INPUT_KEY_MATERIAL,
            INTERNAL,
            EXTERNAL_MU,
            RANDOM,
        ],
    )?;
    for n in cp.children()? {
        if pqc::PARAMETERS.contains(&n.tag) {
            pqc::validate_parameter(n, v)?;
            continue;
        }
        if v < Version(1, 2)
            && [
                DIGITAL_SIGNATURE_ALGORITHM,
                CRYPTOGRAPHIC_ALGORITHM,
                RANDOM_IV,
                IV_LENGTH,
                TAG_LENGTH,
                FIXED_FIELD_LENGTH,
                INVOCATION_FIELD_LENGTH,
                COUNTER_LENGTH,
                INITIAL_COUNTER_VALUE,
            ]
            .contains(&n.tag)
            || v < Version(1, 4)
                && [
                    SALT_LENGTH,
                    MASK_GENERATOR,
                    MASK_GENERATOR_HASHING_ALGORITHM,
                    P_SOURCE,
                    TRAILER_FIELD,
                ]
                .contains(&n.tag)
        {
            return Err(fail(
                7,
                "Cryptographic parameter is unavailable in this version",
            ));
        }
        match n.tag {
            RANDOM_IV => {
                n.flag()?;
            }
            P_SOURCE => {
                n.byte_string()?;
            }
            IV_LENGTH
            | TAG_LENGTH
            | FIXED_FIELD_LENGTH
            | INVOCATION_FIELD_LENGTH
            | COUNTER_LENGTH
            | INITIAL_COUNTER_VALUE
            | SALT_LENGTH
            | TRAILER_FIELD => {
                if !matches!(n.value, Value::Integer(i) if i >= 0) {
                    return Err(fail(
                        7,
                        "Cryptographic parameter requires a nonnegative Integer",
                    ));
                }
            }
            _ => {
                if !matches!(n.value, Value::Enumeration(_)) {
                    return Err(fail(7, "Cryptographic parameter requires an Enumeration"));
                }
            }
        }
    }
    Ok(())
}
fn attribute_matches(filter: &Node, actual: &Node) -> bool {
    if filter.tag != actual.tag {
        return false;
    }
    if filter.tag == CRYPTOGRAPHIC_USAGE_MASK {
        return matches!((filter.number(), actual.number()), (Ok(want), Ok(mask)) if mask & want == want);
    }
    if filter.tag == USAGE_LIMITS {
        return usage::filter_matches(filter, actual);
    }
    match (&filter.value, &actual.value) {
        (Value::Structure(fields), Value::Structure(candidates)) => fields
            .iter()
            .all(|f| candidates.iter().any(|a| attribute_matches(f, a))),
        _ => filter == actual,
    }
}
fn cryptographic_parameters(obj: &Object, p: &Node, v: Version, required: bool) -> R<Node> {
    // An explicit request replaces the stored instance, rather than merging
    // partial fields with it. Stored instances are ordered by attribute index.
    let cp = p
        .get(CRYPTOGRAPHIC_PARAMETERS)
        .or_else(|| obj.attrs.iter().find(|a| a.tag == CRYPTOGRAPHIC_PARAMETERS));
    match cp {
        Some(cp) => {
            validate_cryptographic_parameters(cp, v)?;
            Ok(cp.clone())
        }
        None if required => Err(fail(
            6,
            "Cryptographic Parameters required in request or key attributes",
        )),
        None => Ok(Node::structure(CRYPTOGRAPHIC_PARAMETERS, vec![])),
    }
}
fn vendor_identity(a: &Node) -> R<(&str, &str)> {
    no_fields(a, &[VENDOR_IDENTIFICATION, ATTRIBUTE_NAME, ATTRIBUTE_VALUE])?;
    let vendor = a.required(VENDOR_IDENTIFICATION)?.string()?;
    let name = a.required(ATTRIBUTE_NAME)?.string()?;
    if vendor.is_empty()
        || name.is_empty()
        || !vendor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return Err(fail(7, "Invalid vendor attribute identity"));
    }
    Ok((vendor, name))
}
enum AttributeSelector {
    Standard(u32),
    Vendor(String, String),
}
impl AttributeSelector {
    fn read(n: &Node) -> R<Self> {
        match n.value {
            Value::Enumeration(tag) => Ok(Self::Standard(tag)),
            Value::Structure(_) => {
                no_fields(n, &[VENDOR_IDENTIFICATION, ATTRIBUTE_NAME])?;
                let (vendor, name) = vendor_identity(n)?;
                Ok(Self::Vendor(vendor.to_owned(), name.to_owned()))
            }
            _ => Err(fail(7, "Invalid Attribute Reference")),
        }
    }
}
fn validate_attrs(attrs: &[Node], v: Version) -> R<()> {
    attributes::limits(attrs)?;
    identifiers::validate_link_cardinality(attrs, v)?;
    let mut seen = std::collections::HashSet::new();
    for a in attrs {
        let identity = if a.tag == ATTRIBUTE {
            vendor_identity(a)?
        } else {
            ("", "")
        };
        if !seen.insert((a.tag, identity)) && !attributes::multiple(a.tag) {
            return Err(fail(
                8,
                "Multiple instances of an attribute are not supported",
            ));
        }
        match a.tag {
            CRYPTOGRAPHIC_ALGORITHM | CRYPTOGRAPHIC_LENGTH | CRYPTOGRAPHIC_USAGE_MASK => {
                a.number()?;
            }
            CRYPTOGRAPHIC_PARAMETERS => validate_cryptographic_parameters(a, v)?,
            DIGITAL_SIGNATURE_ALGORITHM => {
                pgp::signature(a, v)?;
            }
            tag if certificate::identity_attribute(tag)
                || matches!(tag, CERTIFICATE_TYPE | CERTIFICATE_LENGTH) =>
            {
                certificate::validate_attribute(a, v)?
            }
            LINK => {
                no_fields(a, &[LINK_TYPE, LINKED_OBJECT_IDENTIFIER])?;
                if !matches!(
                    a.required(LINK_TYPE)?.value,
                    Value::Enumeration(0x101..=0x10e)
                ) {
                    return Err(fail(7, "Unsupported Link Type"));
                }
                let target = a.required(LINKED_OBJECT_IDENTIFIER)?;
                match &target.value {
                    Value::TextString(value) | Value::NameReference(value) if !value.is_empty() => {
                    }
                    _ => return Err(fail(7, "Invalid link target")),
                }
            }
            CRYPTOGRAPHIC_DOMAIN_PARAMETERS => ec::domain(a, v)?,
            GROUP_LINK => system::validate_group_link(a, v)?,
            CERTIFICATE_REQUEST_LINK => certificate_request::validate_link(a, v)?,
            USAGE_LIMITS => usage::validate_initial(a)?,
            FRESH if v >= Version(1, 1) => {
                a.flag()?;
            }
            ORIGINAL_CREATION_DATE if v >= Version(1, 2) => {
                date_value(a)?;
            }
            RANDOM_NUMBER_GENERATOR if v >= Version(1, 3) => metadata::validate_rng(a)?,
            ALWAYS_SENSITIVE | NEVER_EXTRACTABLE if v >= Version(1, 4) => {
                return Err(usage::read_only(v));
            }
            LEASE_TIME => return Err(usage::read_only(v)),
            OPERATION_POLICY_NAME if policy::defined(v) => policy::validate(a)?,
            // 1.2 section 3.41: "It SHALL NOT be specified by the client".
            KEY_VALUE_PRESENT if key_value::defined(v) => return Err(usage::read_only(v)),
            KEY_VALUE_LOCATION if key_value::defined(v) => key_value::validate_location(a)?,
            ATTRIBUTE => {
                if identity.0 == "y" {
                    return Err(fail(
                        12,
                        "Client cannot create server-owned vendor attributes",
                    ));
                }
                let value = a.required(ATTRIBUTE_VALUE)?;
                if ["x", "y"].contains(&identity.0)
                    && let Value::Structure(fields) = &value.value
                    && fields
                        .iter()
                        .any(|f| matches!(f.value, Value::Structure(_)))
                {
                    return Err(fail(
                        7,
                        "Legacy custom values cannot contain nested structures",
                    ));
                }
            }
            ALTERNATIVE_NAME => attributes::validate_alternative_name(a, v)?,
            NAME => {
                no_fields(a, &[NAME_VALUE, NAME_TYPE])?;
                a.required(NAME_VALUE)?.string()?;
                if number(a, NAME_TYPE, 1)? != 1 {
                    return Err(fail(
                        8,
                        "Only Uninterpreted Text String names are supported",
                    ));
                }
            }
            OBJECT_GROUP | CONTACT_INFORMATION => {
                a.string()?;
            }
            // Description and Comment are client-modifiable Text Strings from 1.4
            // (1.4 sections 3.46-3.47, 2.0 sections 4.9 and 4.19).
            COMMENT | DESCRIPTION if v >= Version(1, 4) => {
                a.string()?;
            }
            APPLICATION_SPECIFIC_INFORMATION => {
                no_fields(a, &[APPLICATION_NAMESPACE, APPLICATION_DATA])?;
                a.required(APPLICATION_NAMESPACE)?.string()?;
                // 1.x error tables (1.4 Tables 328-335, 341, 342, 362, 363,
                // 365): "Application Data cannot be generated if it was
                // omitted": Application Namespace Not Supported. The server
                // generates data for no namespace (Query Application
                // Namespaces lists none).
                if v.0 == 1 && a.get(APPLICATION_DATA).is_none() {
                    return Err(fail(
                        0x0F,
                        "Application Data cannot be generated for this namespace",
                    ));
                }
                a.required(APPLICATION_DATA)?.string()?;
            }
            ACTIVATION_DATE | DEACTIVATION_DATE | PROCESS_START_DATE | PROTECT_STOP_DATE => {
                date_value(a)?;
            }
            SENSITIVE | EXTRACTABLE if v >= Version(1, 4) => {
                a.flag()?;
            }
            tag if v.0 >= 2 && quantum::attribute(tag) => quantum::validate(a)?,
            NIST_SECURITY_CATEGORY if v.0 >= 3 => pqc::validate_category(a)?,
            SPLIT_KEY_METHOD | SPLIT_KEY_PARTS | SPLIT_KEY_THRESHOLD | SPLIT_KEY_POLYNOMIAL
                if v.0 >= 3 =>
            {
                split::validate_attribute(a)?;
            }
            _ => return Err(fail(8, "Attribute is not supported")),
        }
    }
    if matches!((attr_time(attrs, ACTIVATION_DATE),attr_time(attrs, DEACTIVATION_DATE)),(Some(start),Some(end)) if end<start)
    {
        return Err(fail(7, "Deactivation Date precedes Activation Date"));
    }
    if matches!((attr_time(attrs, ACTIVATION_DATE),attr_time(attrs, PROCESS_START_DATE)),(Some(activation),Some(process)) if process<activation)
    {
        return Err(fail(7, "Process Start Date precedes Activation Date"));
    }
    if matches!((attr_time(attrs, PROTECT_STOP_DATE),attr_time(attrs, DEACTIVATION_DATE)),(Some(protect),Some(deactivation)) if protect>deactivation)
    {
        return Err(fail(7, "Protect Stop Date follows Deactivation Date"));
    }
    Ok(())
}
fn object_attrs(obj: &Object, v: Version) -> Vec<Node> {
    if obj.object_type == template::KIND {
        return template::attributes(obj, v);
    }
    let mut hydrated;
    let obj = if obj.object_type == 1
        && obj.certificate_type == 1
        && [
            CERTIFICATE_LENGTH,
            X_509_CERTIFICATE_IDENTIFIER,
            X_509_CERTIFICATE_ISSUER,
            X_509_CERTIFICATE_SUBJECT,
        ]
        .iter()
        .any(|tag| !obj.attrs.iter().any(|a| a.tag == *tag))
    {
        hydrated = obj.clone();
        certificate::hydrate(&mut hydrated);
        &hydrated
    } else {
        obj
    };
    let mut attrs = obj.attrs.clone();
    metadata::project(obj, v, &mut attrs);
    split::project(obj, v, &mut attrs);
    protection::project(obj, v, &mut attrs);
    opaque::project(obj, v, &mut attrs);
    if obj.object_type == 1 {
        certificate::project(v, &mut attrs);
    }
    policy::project(v, &mut attrs);
    key_value::project(v, &mut attrs);
    if !obj.imported && !attrs.iter().any(|a| a.tag == LEASE_TIME) {
        attrs.push(Node::interval(LEASE_TIME, usage::DEFAULT_LEASE_SECONDS));
    }
    attrs.retain(|a| {
        ![
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            CRYPTOGRAPHIC_USAGE_MASK,
        ]
        .contains(&a.tag)
    });
    attrs.extend([
        Node::text(UNIQUE_IDENTIFIER, &obj.id),
        Node::enumeration(OBJECT_TYPE, obj.object_type),
        Node::enumeration(STATE, effective_state(obj)),
        Node::date(INITIAL_DATE, obj.created),
        Node::date(LAST_CHANGE_DATE, obj.updated),
    ]);
    // Short Unique Identifier is defined from 2.0 (2.0 section 4.49, tag 420136).
    if v.0 >= 2 && !obj.imported {
        attrs.push(Node::bytes(
            SHORT_UNIQUE_IDENTIFIER,
            crypto::sha256(obj.id.as_bytes()).to_vec(),
        ));
    }
    if v.0 >= 3 && !obj.imported {
        attrs.push(Node::enumeration(OBJECT_CLASS, 1));
    }
    pqc::project(obj, v, &mut attrs);
    if obj.algorithm != 0 {
        attrs.push(Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, obj.algorithm));
    }
    if obj.bits != 0 {
        attrs.push(Node::int(CRYPTOGRAPHIC_LENGTH, obj.bits as i32));
    }
    if obj.object_type != 8 {
        attrs.push(Node::int(CRYPTOGRAPHIC_USAGE_MASK, obj.usage as i32));
    }
    let format = attribute_format(obj);
    if v >= Version(2, 0) && format != 0 {
        attrs.push(Node::enumeration(KEY_FORMAT_TYPE, format));
    }
    if v < Version(1, 2) {
        attrs.retain(|a| a.tag != ALTERNATIVE_NAME);
    }
    if v.0 < 3 {
        attrs.retain(|a| ![GROUP_LINK, CERTIFICATE_REQUEST_LINK].contains(&a.tag));
    }
    if v < Version(1, 4) {
        attrs.retain(|a| ![SENSITIVE, EXTRACTABLE, COMMENT, DESCRIPTION].contains(&a.tag));
    }
    if v.0 < 2 {
        attrs.retain(|a| !quantum::attribute(a.tag));
    }
    attrs
        .into_iter()
        .map(|a| identifiers::project_attribute(v, &a))
        .collect()
}

/// Objects the protocol version can represent: Templates exist only in 1.x
/// and Certificate Requests only from 2.0.
fn visible(obj: &Object, v: Option<Version>) -> bool {
    template::visible(obj, v) && certificate_request::visible(obj, v)
}
fn link_kind(n: &Node) -> Option<u32> {
    (n.tag == LINK)
        .then(|| n.get(LINK_TYPE).and_then(|n| n.number().ok()))
        .flatten()
}
fn object_link(kind: u32, id: &str) -> Node {
    Node::structure(
        LINK,
        vec![
            Node::enumeration(LINK_TYPE, kind),
            Node::text(LINKED_OBJECT_IDENTIFIER, id),
        ],
    )
}
fn validate_symmetric_parameters(algorithm: u32, bits: u32, v: Version) -> R<()> {
    mac::validate_key_algorithm(algorithm, v)?;
    fips_policy::symmetric_algorithm(algorithm)?;
    if matches!(algorithm, 28 | 30) {
        if v < Version(1, 4) || bits != 256 {
            return Err(fail(7, "ChaCha20 requires KMIP 1.4 and a 256-bit key"));
        }
        return Ok(());
    }
    if algorithm != 3 && crypto::authentication::hmac_hash(algorithm).is_none()
        || algorithm == 3 && ![128, 192, 256].contains(&bits)
        || algorithm != 3 && !(8..=524288).contains(&bits)
        || !bits.is_multiple_of(8)
    {
        return Err(fail(7, "Unsupported symmetric algorithm or key length"));
    }
    Ok(())
}
fn date_value(n: &Node) -> R<i64> {
    match &n.value {
        Value::DateTime(v) => Ok(*v),
        _ => Err(fail(7, "Expected Date-Time")),
    }
}
fn attr_time(attrs: &[Node], tag: u32) -> Option<i64> {
    attrs
        .iter()
        .find(|a| a.tag == tag)
        .and_then(|a| date_value(a).ok())
}
/// The Key Format Type attribute value. 2.x 4.26: it always has a value for
/// every object; X.509 certificates and Opaque Objects default to X.509 and Opaque.
fn attribute_format(obj: &Object) -> u32 {
    match (obj.format, obj.object_type, obj.certificate_type) {
        (0, 1, 1) => 5,
        (0, 8, _) => 2,
        (0, certificate_request::KIND, _) => certificate_request::PKCS10_FORMAT,
        (format, ..) => format,
    }
}
fn apply_dates(obj: &mut Object) -> bool {
    let previous = obj.state;
    obj.state = effective_state(obj);
    if obj.state != previous {
        obj.updated = now();
    }
    obj.state != previous
}
fn effective_state(obj: &Object) -> u32 {
    let mut state = obj.state;
    let time = now();
    if state == 1 && attr_time(&obj.attrs, ACTIVATION_DATE).is_some_and(|t| t <= time) {
        state = 2;
    }
    if state == 2 && attr_time(&obj.attrs, DEACTIVATION_DATE).is_some_and(|t| t <= time) {
        state = 3;
    }
    state
}
fn default_digest_format(obj: &Object) -> u32 {
    match obj.object_type {
        2 | 7 | 9 => 1,
        3 | 4 if obj.algorithm == 4 => 3,
        3 | 4 if obj.algorithm == transparent::DSA => transparent::default_format(obj.object_type),
        4 if ec::algorithm(obj.algorithm) => 20,
        3 if ec::algorithm(obj.algorithm) => 21,
        _ => obj.format,
    }
}
fn digest_input(obj: &Object, format: u32) -> R<zeroize::Zeroizing<Vec<u8>>> {
    if pqc::key(obj) {
        let n = pqc::key_material(obj, format)?;
        return Ok(zeroize::Zeroizing::new(match &n.value {
            Value::ByteString(data) => data.clone(),
            _ => n.encode(),
        }));
    }
    if ec::algorithm(obj.algorithm) && matches!(obj.object_type, 3 | 4) {
        let n = ec::key_material(obj, format, 1)?;
        return Ok(zeroize::Zeroizing::new(match &n.value {
            Value::ByteString(data) => data.clone(),
            _ => n.encode(),
        }));
    }
    if matches!(obj.object_type, 3 | 4)
        && transparent::format_allowed(obj.object_type, obj.algorithm, format)
        && (transparent::is_transparent(format) || obj.algorithm == transparent::DSA)
    {
        // 1.4 section 3.17 (Digest) and later: a structured Key Material is
        // digested in its TTLV encoding.
        let n = transparent::key_material(obj, format)?;
        return Ok(zeroize::Zeroizing::new(match &n.value {
            Value::ByteString(data) => data.clone(),
            _ => n.encode(),
        }));
    }
    if matches!(obj.object_type, 1 | 8) && format != 0
        || obj.object_type == 2 && ![1, 7].contains(&format)
        || [7, 9].contains(&obj.object_type) && ![1, 2].contains(&format)
        || obj.object_type == 3 && ![3, 5].contains(&format)
        || obj.object_type == 4 && ![3, 4].contains(&format)
    {
        return Err(fail(0x10, "Unsupported digest key format"));
    }
    Ok(if format == 7 {
        zeroize::Zeroizing::new(
            Node::structure(KEY_MATERIAL, vec![Node::bytes(KEY, obj.material.clone())]).encode(),
        )
    } else if obj.algorithm == 4 && matches!(obj.object_type, 3 | 4) && format != obj.format {
        crypto::rsa::export(&obj.material, obj.object_type == 4, format)?
    } else {
        zeroize::Zeroizing::new(obj.material.clone())
    })
}
fn add_digest(obj: &mut Object) -> R<()> {
    obj.attrs.retain(|a| a.tag != DIGEST);
    let mut formats = vec![obj.format];
    let default = default_digest_format(obj);
    if default != obj.format {
        formats.push(default);
    }
    for format in formats {
        let data = digest_input(obj, format)?;
        let mut fields = vec![
            Node::enumeration(HASHING_ALGORITHM, SHA256),
            Node::bytes(DIGEST_VALUE, crypto::hash_data(SHA256, &data)?),
        ];
        if format != 0 {
            fields.push(Node::enumeration(KEY_FORMAT_TYPE, format));
        }
        obj.attrs.push(Node::structure(DIGEST, fields));
    }
    Ok(())
}

#[cfg(test)]
mod response_resource_tests {
    use super::*;
    use crate::encoding::Format;

    #[test]
    fn complete_item_depth_is_bounded_and_siblings_do_not_add_depth() {
        let header = response_header(Version(2, 1), 2, None);
        for format in [Format::Ttlv, Format::Json, Format::Xml] {
            let mut check = |_: &Node| Ok(());
            let len = |n: &Node| {
                format
                    .encode(n)
                    .map(|b| b.len())
                    .map_err(|_| response_too_large())
            };
            let wire = Wire {
                check: &mut check,
                len: &len,
                frame: crate::encoding::MAX_TEXT_FRAME,
            };
            let base = wire
                .measure(&Node::structure(RESPONSE_MESSAGE, vec![header.clone()]))
                .unwrap();
            for nesting in [30, 31] {
                let mut payload = Node::int(DATA, 1);
                for _ in 0..nesting {
                    payload = Node::structure(RESPONSE_PAYLOAD, vec![payload]);
                }
                // Standalone payloads fit, but their full message may be too deep.
                assert!(format.encode(&payload).is_ok());
                let item = batch_response(24, None, Ok(payload));
                let size = item_len(&wire, &header, base, &item);
                let aggregate =
                    Node::structure(RESPONSE_MESSAGE, vec![header.clone(), item.clone(), item]);
                if nesting == 30 {
                    assert!(
                        base.saturating_add(size.saturating_mul(2))
                            .fits(Budget::new(None, wire.frame))
                    );
                    let bytes = format.encode(&aggregate).unwrap();
                    assert!(format.decode(&bytes).is_ok()); // deepest node is exactly 32
                } else {
                    assert!(
                        !base
                            .saturating_add(size)
                            .fits(Budget::new(None, wire.frame))
                    );
                    assert!(format.encode(&aggregate).is_err()); // deepest node is 33
                }
            }
        }
    }

    /// The selected encoder's frame bounds JSON and XML bytes independently of
    /// Maximum Response Size, with the usual per-item continuation results.
    #[test]
    fn server_frame_binds_text_independently_of_the_client_limit() {
        let attributes = Node::structure(
            ATTRIBUTES,
            vec![
                Node::enumeration(CRYPTOGRAPHIC_ALGORITHM, 3),
                Node::int(CRYPTOGRAPHIC_LENGTH, 256),
                Node::int(CRYPTOGRAPHIC_USAGE_MASK, 12),
            ],
        );
        let entries = [
            (1, vec![Node::enumeration(OBJECT_TYPE, 2), attributes]),
            (10, vec![]),
            (24, vec![Node::enumeration(QUERY_FUNCTION, 1)]),
        ];
        for format in [Format::Json, Format::Xml] {
            for continuation in [1, 2, 3] {
                let dir = tempfile::tempdir().unwrap();
                let key = dir.path().join("master");
                std::fs::write(&key, [7; 32]).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
                let store = Store::open(&dir.path().join("keys.sqlite"), &key).unwrap();
                let mut engine = Engine::new(store, false);
                let mut message = vec![Node::structure(
                    REQUEST_HEADER,
                    vec![
                        Version(2, 1).node(),
                        Node::int(MAXIMUM_RESPONSE_SIZE, crate::ttlv::MAX_FRAME as i32),
                        Node::enumeration(BATCH_ERROR_CONTINUATION_OPTION, continuation),
                        Node::int(BATCH_COUNT, 3),
                    ],
                )];
                for (index, (op, payload)) in entries.iter().cloned().enumerate() {
                    message.push(Node::structure(
                        BATCH_ITEM,
                        vec![
                            Node::enumeration(OPERATION, op),
                            Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![index as u8]),
                            Node::structure(REQUEST_PAYLOAD, payload),
                        ],
                    ));
                }
                let request = Node::structure(REQUEST_MESSAGE, message);
                let run = |engine: &mut Engine, frame| {
                    let mut check = |_: &Node| Ok(());
                    let len = |n: &Node| {
                        format
                            .encode(n)
                            .map(|b| b.len())
                            .map_err(|_| response_too_large())
                    };
                    let mut wire = Wire {
                        check: &mut check,
                        len: &len,
                        frame,
                    };
                    let response = engine
                        .process_wire("alice", &request, None, &[], &mut wire)
                        .unwrap();
                    let statuses = response
                        .all(BATCH_ITEM)
                        .map(|i| i.required(RESULT_STATUS).unwrap().number().unwrap())
                        .collect::<Vec<_>>();
                    let created = engine.store.list("alice").unwrap().len();
                    (format.encode(&response).unwrap().len(), statuses, created)
                };
                let (full, statuses, _) = run(&mut engine, crate::encoding::MAX_TEXT_FRAME);
                assert_eq!(statuses, [0, 0, 0]);
                // Batch Count is sized as three digits, so two bytes are spare.
                let (bytes, statuses, created) = run(&mut engine, full + 2);
                assert_eq!((bytes, statuses, created), (full, vec![0, 0, 0], 2));
                let (bytes, statuses, created) = run(&mut engine, full - 1);
                assert!(bytes < full);
                let first = if continuation == 3 { 3 } else { 0 };
                assert_eq!(statuses, [first, first, 1]);
                assert_eq!(created, if continuation == 3 { 2 } else { 3 });
                engine.store.verify_audit().unwrap();
            }
        }
    }

    #[test]
    fn failure_payloads_and_optional_detail_consume_reserved_nodes() {
        let header = response_header(Version(2, 1), 2, None);
        for format in [Format::Ttlv, Format::Json, Format::Xml] {
            let mut check = |_: &Node| Ok(());
            let len = |n: &Node| {
                format
                    .encode(n)
                    .map(|b| b.len())
                    .map_err(|_| response_too_large())
            };
            let wire = Wire {
                check: &mut check,
                len: &len,
                frame: crate::encoding::MAX_TEXT_FRAME,
            };
            let base = wire
                .measure(&Node::structure(RESPONSE_MESSAGE, vec![header.clone()]))
                .unwrap();
            let id = Node::bytes(UNIQUE_BATCH_ITEM_ID, vec![42]);
            let mut error = fail(12, "denied Check");
            error.payload = Some(Box::new(Node::structure(
                RESPONSE_PAYLOAD,
                vec![Node::text(UNIQUE_IDENTIFIER, "key")],
            )));
            let detailed = failure_item(21, Some(&id), &error, true);
            let size = item_len(&wire, &header, base, &detailed);
            // Exactly enough nodes for the detailed failure; bytes are immaterial.
            let used = ResponseSize {
                nodes: crate::encoding::MAX_NODES - size.nodes,
                ..base
            };
            assert!(
                fit_failure(&wire, &header, base, 21, Some(&id), error, |s| used
                    .saturating_add(s)
                    .fits(Budget::new(None, wire.frame)))
                .is_some()
            );
            let mut error = fail(12, "denied Check");
            error.payload = Some(Box::new(Node::structure(
                RESPONSE_PAYLOAD,
                vec![Node::text(UNIQUE_IDENTIFIER, "key")],
            )));
            // A required failure payload cannot be silently removed to fit.
            assert!(
                fit_failure(&wire, &header, base, 21, Some(&id), error, |s| used
                    .saturating_add(s)
                    .saturating_add(ResponseSize {
                        nodes: 1,
                        ..ResponseSize::default()
                    })
                    .fits(Budget::new(None, wire.frame)))
                .is_none()
            );
            let error = fail(12, "denied without payload");
            let terse = failure_item(21, Some(&id), &error, false);
            let terse_size = item_len(&wire, &header, base, &terse);
            let used = ResponseSize {
                nodes: crate::encoding::MAX_NODES - terse_size.nodes,
                ..base
            };
            let (item, _) = fit_failure(&wire, &header, base, 21, Some(&id), error, |s| {
                used.saturating_add(s).fits(Budget::new(None, wire.frame))
            })
            .unwrap();
            assert!(item.get(RESULT_MESSAGE).is_none());
            assert_eq!(item.required(RESULT_REASON).unwrap().number().unwrap(), 12);
            assert_eq!(
                item.required(UNIQUE_BATCH_ITEM_ID)
                    .unwrap()
                    .byte_string()
                    .unwrap(),
                [42]
            );
        }
    }
}
