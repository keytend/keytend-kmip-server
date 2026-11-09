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

//! Operator metrics in the Prometheus text exposition format (version 0.0.4),
//! written here without a client library (docs/metrics.md).
//!
//! Every label value is a `&'static str` chosen from a fixed table, so a
//! client cannot create new series: an operation, version or reason the
//! tables do not name is counted as `unknown`. No key material, object
//! identifier, principal, Name or attribute value is ever recorded.
use crate::tags::{
    BATCH_ITEM, OPERATION, PROTOCOL_VERSION, PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR,
    RESPONSE_HEADER, RESPONSE_MESSAGE, RESULT_REASON, RESULT_STATUS,
};
use crate::ttlv::Node;
use std::{collections::BTreeMap, fmt::Write as _, sync::Mutex, time::Duration};

/// Prometheus text format content type.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Upper bounds (seconds) of the request duration histogram.
pub const DURATION_BUCKETS: [f64; 14] = [
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
/// Upper bounds of the batch-items-per-request histogram (128 is the server
/// batch limit, docs/messages.md#batches).
pub const BATCH_BUCKETS: [f64; 8] = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0];

/// Operation enumeration names (KMIP 2.1 Table 470 and draft 3.0; every
/// edition assigns the same value to the same operation).
const OPERATIONS: [&str; 66] = [
    "Create",
    "CreateKeyPair",
    "Register",
    "ReKey",
    "DeriveKey",
    "Certify",
    "ReCertify",
    "Locate",
    "Check",
    "Get",
    "GetAttributes",
    "GetAttributeList",
    "AddAttribute",
    "ModifyAttribute",
    "DeleteAttribute",
    "ObtainLease",
    "GetUsageAllocation",
    "Activate",
    "Revoke",
    "Destroy",
    "Archive",
    "Recover",
    "Validate",
    "Query",
    "Cancel",
    "Poll",
    "Notify",
    "Put",
    "ReKeyKeyPair",
    "DiscoverVersions",
    "Encrypt",
    "Decrypt",
    "Sign",
    "SignatureVerify",
    "MAC",
    "MACVerify",
    "RNGRetrieve",
    "RNGSeed",
    "Hash",
    "CreateSplitKey",
    "JoinSplitKey",
    "Import",
    "Export",
    "Log",
    "Login",
    "Logout",
    "DelegatedLogin",
    "AdjustAttribute",
    "SetAttribute",
    "SetEndpointRole",
    "PKCS_11",
    "Interop",
    "ReProvision",
    "SetDefaults",
    "SetConstraints",
    "GetConstraints",
    "QueryAsynchronousRequests",
    "Process",
    "Ping",
    "CreateGroup",
    "Obliterate",
    "CreateUser",
    "CreateCredential",
    "Deactivate",
    "Encapsulate",
    "Decapsulate",
];

/// Operation label: the enumeration name, `none` when the response item has
/// no Operation field, `unknown` otherwise (vendor or unassigned values).
pub fn operation_name(operation: Option<u32>) -> &'static str {
    match operation {
        None => "none",
        Some(op) => op
            .checked_sub(1)
            .and_then(|i| OPERATIONS.get(i as usize))
            .copied()
            .unwrap_or("unknown"),
    }
}

/// Result Status names (2.1 Table 480; the same values in 1.x).
pub fn status_name(status: Option<u32>) -> &'static str {
    match status {
        Some(0) => "Success",
        Some(1) => "OperationFailed",
        Some(2) => "OperationPending",
        Some(3) => "OperationUndone",
        None => "none",
        Some(_) => "unknown",
    }
}

/// Result Reason names (2.1 Table 479, plus Illegal Operation (11) and Index
/// Out Of Bounds (14) of 1.4 Table 317; 0x100 is General Failure in every
/// edition).
pub fn reason_name(reason: Option<u32>) -> &'static str {
    let Some(reason) = reason else {
        return "none";
    };
    match reason {
        1 => "ItemNotFound",
        2 => "ResponseTooLarge",
        3 => "AuthenticationNotSuccessful",
        4 => "InvalidMessage",
        5 => "OperationNotSupported",
        6 => "MissingData",
        7 => "InvalidField",
        8 => "FeatureNotSupported",
        9 => "OperationCanceledByRequester",
        10 => "CryptographicFailure",
        11 => "IllegalOperation",
        12 => "PermissionDenied",
        13 => "ObjectArchived",
        14 => "IndexOutOfBounds",
        15 => "ApplicationNamespaceNotSupported",
        16 => "KeyFormatTypeNotSupported",
        17 => "KeyCompressionTypeNotSupported",
        18 => "EncodingOptionError",
        19 => "KeyValueNotPresent",
        20 => "AttestationRequired",
        21 => "AttestationFailed",
        22 => "Sensitive",
        23 => "NotExtractable",
        24 => "ObjectAlreadyExists",
        25 => "InvalidTicket",
        26 => "UsageLimitExceeded",
        27 => "NumericRange",
        28 => "InvalidDataType",
        29 => "ReadOnlyAttribute",
        30 => "MultiValuedAttribute",
        31 => "UnsupportedAttribute",
        32 => "AttributeInstanceNotFound",
        33 => "AttributeNotFound",
        34 => "AttributeReadOnly",
        35 => "AttributeSingleValued",
        36 => "BadCryptographicParameters",
        37 => "BadPassword",
        38 => "CodecError",
        40 => "IllegalObjectType",
        41 => "IncompatibleCryptographicUsageMask",
        42 => "InternalServerError",
        43 => "InvalidAsynchronousCorrelationValue",
        44 => "InvalidAttribute",
        45 => "InvalidAttributeValue",
        46 => "InvalidCorrelationValue",
        47 => "InvalidCSR",
        48 => "InvalidObjectType",
        50 => "KeyWrapTypeNotSupported",
        52 => "MissingInitializationVector",
        53 => "NonUniqueNameAttribute",
        54 => "ObjectDestroyed",
        55 => "ObjectNotFound",
        57 => "NotAuthorised",
        58 => "ServerLimitExceeded",
        59 => "UnknownEnumeration",
        60 => "UnknownMessageExtension",
        61 => "UnknownTag",
        62 => "UnsupportedCryptographicParameters",
        63 => "UnsupportedProtocolVersion",
        64 => "WrappingObjectArchived",
        65 => "WrappingObjectDestroyed",
        66 => "WrappingObjectNotFound",
        67 => "WrongKeyLifecycleState",
        68 => "ProtectionStorageUnavailable",
        69 => "PKCS_11CodecError",
        70 => "PKCS_11InvalidFunction",
        71 => "PKCS_11InvalidInterface",
        72 => "PrivateProtectionStorageUnavailable",
        73 => "PublicProtectionStorageUnavailable",
        74 => "UnknownObjectGroup",
        75 => "ConstraintViolation",
        76 => "DuplicateProcessRequest",
        0x100 => "GeneralFailure",
        _ => "unknown",
    }
}

/// Protocol version label; only the editions this server implements.
pub fn version_name(major: u32, minor: u32) -> &'static str {
    match (major, minor) {
        (1, 0) => "1.0",
        (1, 1) => "1.1",
        (1, 2) => "1.2",
        (1, 3) => "1.3",
        (1, 4) => "1.4",
        (2, 0) => "2.0",
        (2, 1) => "2.1",
        (3, 0) => "3.0",
        _ => "unknown",
    }
}

/// Object Type names (2.1 Table 468; value 6 is Template in 1.x and reserved
/// in 2.x, where the server does not create it).
pub fn object_type_name(object_type: u32) -> &'static str {
    match object_type {
        1 => "Certificate",
        2 => "SymmetricKey",
        3 => "PublicKey",
        4 => "PrivateKey",
        5 => "SplitKey",
        6 => "Template",
        7 => "SecretData",
        8 => "OpaqueObject",
        9 => "PGPKey",
        10 => "CertificateRequest",
        11 => "User",
        12 => "Group",
        13 => "PasswordCredential",
        14 => "DeviceCredential",
        15 => "OneTimePasswordCredential",
        16 => "HashedPasswordCredential",
        _ => "unknown",
    }
}

/// State names (2.1 Table 486).
pub fn state_name(state: u32) -> &'static str {
    match state {
        1 => "PreActive",
        2 => "Active",
        3 => "Deactivated",
        4 => "Compromised",
        5 => "Destroyed",
        6 => "DestroyedCompromised",
        _ => "unknown",
    }
}

/// A fixed-bucket histogram (cumulative buckets are formed when written).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Histogram {
    counts: Vec<u64>,
    sum: f64,
    count: u64,
}
impl Histogram {
    pub fn observe(&mut self, bounds: &[f64], value: f64) {
        if self.counts.len() != bounds.len() {
            self.counts = vec![0; bounds.len()];
        }
        if let Some(i) = bounds.iter().position(|b| value <= *b) {
            self.counts[i] += 1;
        }
        self.sum += value;
        self.count += 1;
    }
    pub fn count(&self) -> u64 {
        self.count
    }
}

/// Label tuple of `kmip_operations_total`.
type OperationKey = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

#[derive(Default)]
struct Counters {
    /// (version, encoding) -> request messages answered.
    requests: BTreeMap<(&'static str, &'static str), u64>,
    /// encoding -> request messages without a KMIP answer (the connection or
    /// HTTP exchange failed instead).
    unanswered: BTreeMap<&'static str, u64>,
    /// (version, encoding, operation, status, reason) -> response batch items.
    operations: BTreeMap<OperationKey, u64>,
    /// operation (or `batch`) -> processing time.
    durations: BTreeMap<&'static str, Histogram>,
    batch_items: Histogram,
    leases_granted: u64,
    /// reason -> refused Obtain Lease items.
    leases_refused: BTreeMap<&'static str, u64>,
}

/// Object census result (`Store::census_page`, run periodically by the server).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Census {
    /// (Object Type, State) -> objects.
    pub objects: BTreeMap<(&'static str, &'static str), u64>,
    /// Records that did not authenticate or parse (should stay 0).
    pub unreadable: u64,
    /// Unix time the census finished.
    pub completed_at: f64,
    pub duration_seconds: f64,
}
impl Census {
    pub fn add(&mut self, object_type: u32, state: u32) {
        *self
            .objects
            .entry((object_type_name(object_type), state_name(state)))
            .or_default() += 1;
    }
}

/// Request and lease counters maintained by the engine, plus the latest
/// object census. Shared with the health listener, which renders it without
/// taking the engine lock.
#[derive(Default)]
pub struct Registry {
    counters: Mutex<Counters>,
    census: Mutex<Option<Census>>,
}

fn number(node: Option<&Node>) -> Option<u32> {
    node.and_then(|n| n.number().ok())
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one answered request message from its response: the response
    /// header's version, and each response batch item's Operation, Result
    /// Status and Result Reason. `elapsed` is the engine's processing time.
    pub fn observe(&self, encoding: &'static str, response: &Node, elapsed: Duration) {
        if response.tag != RESPONSE_MESSAGE {
            return;
        }
        let version = response
            .get(RESPONSE_HEADER)
            .and_then(|h| h.get(PROTOCOL_VERSION))
            .map(|v| {
                version_name(
                    number(v.get(PROTOCOL_VERSION_MAJOR)).unwrap_or(0),
                    number(v.get(PROTOCOL_VERSION_MINOR)).unwrap_or(0),
                )
            })
            .unwrap_or("unknown");
        let items: Vec<_> = response.all(BATCH_ITEM).collect();
        let Ok(mut c) = self.counters.lock() else {
            return;
        };
        *c.requests.entry((version, encoding)).or_default() += 1;
        c.batch_items.observe(&BATCH_BUCKETS, items.len() as f64);
        let mut operations = items.iter().map(|i| number(i.get(OPERATION)));
        // A multi-item batch is timed as a whole; its items are not timed
        // separately.
        let timed = match (items.len(), operations.next()) {
            (1, Some(op)) => operation_name(op),
            _ => "batch",
        };
        c.durations
            .entry(timed)
            .or_default()
            .observe(&DURATION_BUCKETS, elapsed.as_secs_f64());
        for item in items {
            let op = number(item.get(OPERATION));
            let status = number(item.get(RESULT_STATUS));
            let reason = reason_name(number(item.get(RESULT_REASON)));
            let key = (
                version,
                encoding,
                operation_name(op),
                status_name(status),
                reason,
            );
            *c.operations.entry(key).or_default() += 1;
            // Obtain Lease (16): a Success grants a lease; a failure refuses it.
            if op == Some(16) {
                match status {
                    Some(0) => c.leases_granted += 1,
                    Some(1) => *c.leases_refused.entry(reason).or_default() += 1,
                    _ => {}
                }
            }
        }
    }

    /// Count a request message the engine could not answer with KMIP.
    pub fn unanswered(&self, encoding: &'static str) {
        if let Ok(mut c) = self.counters.lock() {
            *c.unanswered.entry(encoding).or_default() += 1;
        }
    }

    pub fn set_census(&self, census: Census) {
        if let Ok(mut c) = self.census.lock() {
            *c = Some(census);
        }
    }

    pub fn census(&self) -> Option<Census> {
        self.census.lock().ok().and_then(|c| c.clone())
    }

    /// Successful and refused Obtain Lease items counted so far.
    pub fn leases(&self) -> (u64, u64) {
        self.counters
            .lock()
            .map(|c| (c.leases_granted, c.leases_refused.values().sum()))
            .unwrap_or_default()
    }

    /// Write the request, lease and census families.
    pub fn write(&self, out: &mut Exposition) {
        {
            let Ok(c) = self.counters.lock() else {
                return;
            };
            out.family(
                "kmip_requests_total",
                "KMIP request messages answered, by protocol version of the response and encoding.",
                "counter",
            );
            for ((version, encoding), n) in &c.requests {
                out.sample(
                    "kmip_requests_total",
                    &[("version", version), ("encoding", encoding)],
                    *n as f64,
                );
            }
            out.family(
                "kmip_requests_unanswered_total",
                "KMIP request messages that ended without a KMIP response (no response fitted, or an internal failure closed the exchange).",
                "counter",
            );
            for (encoding, n) in &c.unanswered {
                out.sample(
                    "kmip_requests_unanswered_total",
                    &[("encoding", encoding)],
                    *n as f64,
                );
            }
            out.family(
                "kmip_operations_total",
                "KMIP response batch items, by protocol version, encoding, operation, result status and result reason.",
                "counter",
            );
            for ((version, encoding, operation, status, reason), n) in &c.operations {
                out.sample(
                    "kmip_operations_total",
                    &[
                        ("version", version),
                        ("encoding", encoding),
                        ("operation", operation),
                        ("status", status),
                        ("reason", reason),
                    ],
                    *n as f64,
                );
            }
            out.family(
                "kmip_request_duration_seconds",
                "Engine processing time of a request message, by operation (operation=\"batch\" for messages with several batch items). Excludes TLS, framing, engine lock wait and header-credential derivation.",
                "histogram",
            );
            for (operation, h) in &c.durations {
                out.histogram(
                    "kmip_request_duration_seconds",
                    &[("operation", operation)],
                    &DURATION_BUCKETS,
                    h,
                );
            }
            out.family(
                "kmip_request_batch_items",
                "Batch items per answered request message.",
                "histogram",
            );
            out.histogram(
                "kmip_request_batch_items",
                &[],
                &BATCH_BUCKETS,
                &c.batch_items,
            );
            out.family(
                "kmip_leases_granted_total",
                "Obtain Lease batch items that succeeded.",
                "counter",
            );
            out.sample("kmip_leases_granted_total", &[], c.leases_granted as f64);
            out.family(
                "kmip_leases_refused_total",
                "Obtain Lease batch items that failed, by result reason.",
                "counter",
            );
            for (reason, n) in &c.leases_refused {
                out.sample(
                    "kmip_leases_refused_total",
                    &[("reason", reason)],
                    *n as f64,
                );
            }
        }
        if let Some(census) = self.census() {
            out.family(
                "kmip_objects",
                "Managed objects by Object Type and State at the last object census.",
                "gauge",
            );
            for ((object_type, state), n) in &census.objects {
                out.sample(
                    "kmip_objects",
                    &[("type", object_type), ("state", state)],
                    *n as f64,
                );
            }
            out.family(
                "kmip_objects_unreadable",
                "Object records the last census could not authenticate or parse.",
                "gauge",
            );
            out.sample("kmip_objects_unreadable", &[], census.unreadable as f64);
            out.family(
                "kmip_object_census_timestamp_seconds",
                "Unix time the last object census finished.",
                "gauge",
            );
            out.sample(
                "kmip_object_census_timestamp_seconds",
                &[],
                census.completed_at,
            );
            out.family(
                "kmip_object_census_duration_seconds",
                "Duration of the last object census.",
                "gauge",
            );
            out.sample(
                "kmip_object_census_duration_seconds",
                &[],
                census.duration_seconds,
            );
        }
    }
}

/// A Prometheus text format document under construction.
#[derive(Default)]
pub struct Exposition {
    text: String,
}

/// Label values: backslash, double quote and line feed are escaped.
fn escape_label(value: &str, out: &mut String) {
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
}

/// Sample values: Prometheus spells the special values `+Inf`, `-Inf` and `NaN`.
fn write_value(value: f64, out: &mut String) {
    if value.is_nan() {
        out.push_str("NaN");
    } else if value.is_infinite() {
        out.push_str(if value > 0.0 { "+Inf" } else { "-Inf" });
    } else {
        let _ = write!(out, "{value}");
    }
}

impl Exposition {
    pub fn new() -> Self {
        Self::default()
    }

    /// `# HELP` and `# TYPE` lines; call once per family, before its samples.
    /// Help text escapes backslash and line feed.
    pub fn family(&mut self, name: &str, help: &str, kind: &str) {
        debug_assert!(valid_name(name), "metric name {name}");
        let _ = write!(self.text, "# HELP {name} ");
        for c in help.chars() {
            match c {
                '\\' => self.text.push_str("\\\\"),
                '\n' => self.text.push_str("\\n"),
                c => self.text.push(c),
            }
        }
        let _ = writeln!(self.text, "\n# TYPE {name} {kind}");
    }

    pub fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: f64) {
        self.text.push_str(name);
        if !labels.is_empty() {
            self.text.push('{');
            for (i, (label, value)) in labels.iter().enumerate() {
                debug_assert!(valid_name(label) && !label.starts_with("__"));
                if i > 0 {
                    self.text.push(',');
                }
                self.text.push_str(label);
                self.text.push_str("=\"");
                escape_label(value, &mut self.text);
                self.text.push('"');
            }
            self.text.push('}');
        }
        self.text.push(' ');
        write_value(value, &mut self.text);
        self.text.push('\n');
    }

    /// `_bucket` (cumulative, ending with `le="+Inf"`), `_sum` and `_count`.
    pub fn histogram(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        bounds: &[f64],
        histogram: &Histogram,
    ) {
        let bucket = format!("{name}_bucket");
        let mut cumulative = 0;
        for (i, bound) in bounds.iter().enumerate() {
            cumulative += histogram.counts.get(i).copied().unwrap_or(0);
            let le = bound.to_string();
            let mut with_le = labels.to_vec();
            with_le.push(("le", &le));
            self.sample(&bucket, &with_le, cumulative as f64);
        }
        let mut with_le = labels.to_vec();
        with_le.push(("le", "+Inf"));
        self.sample(&bucket, &with_le, histogram.count as f64);
        self.sample(&format!("{name}_sum"), labels, histogram.sum);
        self.sample(&format!("{name}_count"), labels, histogram.count as f64);
    }

    pub fn finish(self) -> String {
        self.text
    }
}

/// Metric and label names: `[a-zA-Z_:][a-zA-Z0-9_:]*` (labels without `:`).
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == ':')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tags::*;

    fn response(version: (u32, u32), items: &[(Option<u32>, u32, Option<u32>)]) -> Node {
        let header = Node::structure(
            RESPONSE_HEADER,
            vec![Node::structure(
                PROTOCOL_VERSION,
                vec![
                    Node::int(PROTOCOL_VERSION_MAJOR, version.0 as i32),
                    Node::int(PROTOCOL_VERSION_MINOR, version.1 as i32),
                ],
            )],
        );
        let mut children = vec![header];
        for (op, status, reason) in items {
            let mut fields = vec![];
            if let Some(op) = op {
                fields.push(Node::enumeration(OPERATION, *op));
            }
            fields.push(Node::enumeration(RESULT_STATUS, *status));
            if let Some(reason) = reason {
                fields.push(Node::enumeration(RESULT_REASON, *reason));
            }
            children.push(Node::structure(BATCH_ITEM, fields));
        }
        Node::structure(RESPONSE_MESSAGE, children)
    }

    #[test]
    fn exposition_escapes_labels_and_help_and_spells_special_values() {
        let mut out = Exposition::new();
        out.family("m_total", "a \\ b\nc", "counter");
        out.sample("m_total", &[("l", "x\"y\\z\nw")], 3.0);
        out.sample("g", &[], 0.25);
        out.sample("g", &[("a", "1"), ("b", "")], f64::INFINITY);
        out.sample("g", &[], f64::NEG_INFINITY);
        out.sample("g", &[], f64::NAN);
        assert_eq!(
            out.finish(),
            "# HELP m_total a \\\\ b\\nc\n# TYPE m_total counter\n\
             m_total{l=\"x\\\"y\\\\z\\nw\"} 3\n\
             g 0.25\n\
             g{a=\"1\",b=\"\"} +Inf\n\
             g -Inf\n\
             g NaN\n"
        );
    }

    #[test]
    fn histograms_are_cumulative_and_end_with_inf() {
        let mut h = Histogram::default();
        for v in [0.5, 1.0, 3.0, 100.0] {
            h.observe(&[1.0, 2.0, 4.0], v);
        }
        let mut out = Exposition::new();
        out.histogram("d", &[("op", "Get")], &[1.0, 2.0, 4.0], &h);
        assert_eq!(
            out.finish(),
            "d_bucket{op=\"Get\",le=\"1\"} 2\n\
             d_bucket{op=\"Get\",le=\"2\"} 2\n\
             d_bucket{op=\"Get\",le=\"4\"} 3\n\
             d_bucket{op=\"Get\",le=\"+Inf\"} 4\n\
             d_sum{op=\"Get\"} 104.5\n\
             d_count{op=\"Get\"} 4\n"
        );
        // An empty histogram still writes every bucket.
        let mut out = Exposition::new();
        out.histogram("e", &[], &BATCH_BUCKETS, &Histogram::default());
        let text = out.finish();
        assert_eq!(text.lines().count(), BATCH_BUCKETS.len() + 3);
        assert!(text.contains("e_bucket{le=\"128\"} 0\n"));
        assert!(text.contains("e_count 0\n"));
    }

    #[test]
    fn responses_count_by_version_operation_status_and_reason() {
        let r = Registry::new();
        r.observe(
            "ttlv",
            &response((2, 1), &[(Some(10), 0, None)]),
            Duration::from_millis(2),
        );
        r.observe(
            "json",
            &response(
                (1, 4),
                &[
                    (Some(16), 0, None),
                    (Some(16), 1, Some(12)),
                    (None, 1, Some(4)),
                ],
            ),
            Duration::from_millis(30),
        );
        // A vendor operation and a result reason no table names stay bounded.
        r.observe(
            "ttlv",
            &response((9, 9), &[(Some(0x8000_0001), 1, Some(0x1234))]),
            Duration::ZERO,
        );
        r.unanswered("xml");
        let mut out = Exposition::new();
        r.write(&mut out);
        let text = out.finish();
        for line in [
            "kmip_requests_total{version=\"2.1\",encoding=\"ttlv\"} 1",
            "kmip_requests_total{version=\"1.4\",encoding=\"json\"} 1",
            "kmip_requests_total{version=\"unknown\",encoding=\"ttlv\"} 1",
            "kmip_requests_unanswered_total{encoding=\"xml\"} 1",
            "kmip_operations_total{version=\"2.1\",encoding=\"ttlv\",operation=\"Get\",status=\"Success\",reason=\"none\"} 1",
            "kmip_operations_total{version=\"1.4\",encoding=\"json\",operation=\"ObtainLease\",status=\"OperationFailed\",reason=\"PermissionDenied\"} 1",
            "kmip_operations_total{version=\"1.4\",encoding=\"json\",operation=\"none\",status=\"OperationFailed\",reason=\"InvalidMessage\"} 1",
            "kmip_operations_total{version=\"unknown\",encoding=\"ttlv\",operation=\"unknown\",status=\"OperationFailed\",reason=\"unknown\"} 1",
            "kmip_request_duration_seconds_count{operation=\"Get\"} 1",
            "kmip_request_duration_seconds_count{operation=\"batch\"} 1",
            "kmip_request_duration_seconds_bucket{operation=\"Get\",le=\"0.001\"} 0",
            "kmip_request_duration_seconds_bucket{operation=\"Get\",le=\"0.0025\"} 1",
            "kmip_request_batch_items_bucket{le=\"2\"} 2",
            "kmip_request_batch_items_bucket{le=\"4\"} 3",
            "kmip_request_batch_items_count 3",
            "kmip_leases_granted_total 1",
            "kmip_leases_refused_total{reason=\"PermissionDenied\"} 1",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} missing:\n{text}");
        }
        assert_eq!(r.leases(), (1, 1));
        // No census has run: no object families.
        assert!(!text.contains("kmip_objects"));
        // Every sample line belongs to a declared family.
        let families: Vec<_> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .map(|l| l.split(' ').next().unwrap())
            .collect();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(
                families.iter().any(|f| name == *f
                    || ["_bucket", "_sum", "_count"]
                        .iter()
                        .any(|s| name == format!("{f}{s}"))),
                "{name} has no family"
            );
        }
    }

    #[test]
    fn non_response_nodes_are_ignored() {
        let r = Registry::new();
        r.observe(
            "ttlv",
            &Node::structure(REQUEST_MESSAGE, vec![]),
            Duration::ZERO,
        );
        let mut out = Exposition::new();
        r.write(&mut out);
        assert!(!out.finish().contains("kmip_requests_total{"));
    }

    #[test]
    fn census_counts_use_names_and_appear_once_set() {
        let r = Registry::new();
        let mut census = Census::default();
        census.add(2, 2);
        census.add(2, 2);
        census.add(4, 5);
        census.add(99, 99);
        census.completed_at = 1.5;
        r.set_census(census);
        let mut out = Exposition::new();
        r.write(&mut out);
        let text = out.finish();
        assert!(text.contains("kmip_objects{type=\"SymmetricKey\",state=\"Active\"} 2\n"));
        assert!(text.contains("kmip_objects{type=\"PrivateKey\",state=\"Destroyed\"} 1\n"));
        assert!(text.contains("kmip_objects{type=\"unknown\",state=\"unknown\"} 1\n"));
        assert!(text.contains("kmip_object_census_timestamp_seconds 1.5\n"));
    }

    #[test]
    fn label_tables_are_bounded() {
        assert_eq!(operation_name(Some(1)), "Create");
        assert_eq!(operation_name(Some(16)), "ObtainLease");
        assert_eq!(operation_name(Some(66)), "Decapsulate");
        assert_eq!(operation_name(Some(0)), "unknown");
        assert_eq!(operation_name(Some(67)), "unknown");
        assert_eq!(operation_name(Some(u32::MAX)), "unknown");
        assert_eq!(reason_name(Some(0x100)), "GeneralFailure");
        assert_eq!(version_name(1, 5), "unknown");
        assert!(valid_name("kmip_requests_total") && !valid_name("1x") && !valid_name("a-b"));
    }
}
