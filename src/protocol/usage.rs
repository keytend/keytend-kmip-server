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

//! Lifetime usage accounting and server-controlled client-cache leases.
use super::*;

/// Lease Time recorded for objects that predate a stored value (none of the
/// stored objects are rewritten when the configured maximum changes).
pub(super) const DEFAULT_LEASE_SECONDS: u32 = DEFAULT_MAXIMUM_LEASE_SECONDS;
const UNRESTRICTED: u32 = 0x20_0000;
const GENERATION_USAGE: u32 =
    1 | 4 | 16 | 128 | 512 | 2048 | 4096 | 8192 | 16384 | 65536 | 262144 | 2097152 | 4194304;

/// Standard Unrestricted semantics start in 2.0. Earlier editions can carry
/// this numeric extension bit, but it must not acquire a later permission.
fn unrestricted(mask: u32, v: Version) -> bool {
    v >= Version(2, 0) && mask & UNRESTRICTED != 0
}
pub(super) fn permits_any(mask: u32, requested: u32, v: Version) -> bool {
    mask & requested != 0 || unrestricted(mask, v)
}
fn permits_all(mask: u32, requested: u32, v: Version) -> bool {
    mask & requested == requested || unrestricted(mask, v)
}

#[derive(Clone, Copy)]
struct Limits {
    total: i64,
    remaining: i64,
    unit: u32,
}
impl Limits {
    fn read(n: &Node, initial: bool) -> R<Self> {
        no_fields(
            n,
            &[USAGE_LIMITS_TOTAL, USAGE_LIMITS_COUNT, USAGE_LIMITS_UNIT],
        )?;
        let total = match n.get(USAGE_LIMITS_TOTAL) {
            Some(n) => nonnegative_long(n)?,
            None if initial => i64::MAX,
            None => return Err(fail(7, "Usage Limits Total missing")),
        };
        let unit = match n.get(USAGE_LIMITS_UNIT) {
            Some(n) => unit_value(n)?,
            None if initial => 2,
            None => return Err(fail(7, "Usage Limits Unit missing")),
        };
        let remaining = match n.get(USAGE_LIMITS_COUNT) {
            // The type is still checked, but the client's initial count value
            // (including a negative value) is ignored as required by KMIP.
            Some(Node {
                value: Value::LongInteger(_),
                ..
            }) if initial => total,
            Some(n) => nonnegative_long(n)?,
            None if initial => total,
            None => return Err(fail(7, "Usage Limits Count missing")),
        };
        if remaining > total {
            return Err(fail(7, "Usage Limits Count exceeds Total"));
        }
        Ok(Self {
            total,
            remaining,
            unit,
        })
    }
    fn node(self) -> Node {
        Node::structure(
            USAGE_LIMITS,
            vec![
                Node::long(USAGE_LIMITS_TOTAL, self.total),
                Node::long(USAGE_LIMITS_COUNT, self.remaining),
                Node::enumeration(USAGE_LIMITS_UNIT, self.unit),
            ],
        )
    }
}
fn unit_value(n: &Node) -> R<u32> {
    match n.value {
        Value::Enumeration(unit @ (1 | 2)) => Ok(unit),
        Value::Enumeration(_) => Err(fail(8, "Unsupported Usage Limits Unit")),
        _ => Err(fail(7, "Usage Limits Unit must be an Enumeration")),
    }
}
pub(super) fn nonnegative_long(n: &Node) -> R<i64> {
    match n.value {
        Value::LongInteger(v) if v >= 0 => Ok(v),
        _ => Err(fail(7, "Usage count must be a nonnegative Long Integer")),
    }
}
pub(super) fn interval_value(n: &Node) -> R<u32> {
    match n.value {
        Value::Interval(v) => Ok(v),
        _ => Err(fail(7, "Lease Time must be an Interval")),
    }
}
pub(super) fn read_only(v: Version) -> Failure {
    fail(if v.0 >= 2 { 0x22 } else { 12 }, "Attribute is read-only")
}
pub(super) fn validate_restored(n: &Node) -> R<bool> {
    let limits = Limits::read(n, false)?;
    Ok(limits.remaining < limits.total)
}
pub(super) fn validate_initial(n: &Node) -> R<()> {
    Limits::read(n, true).map(|_| ())
}
pub(super) fn validate_filter(n: &Node) -> R<()> {
    no_fields(
        n,
        &[USAGE_LIMITS_TOTAL, USAGE_LIMITS_COUNT, USAGE_LIMITS_UNIT],
    )?;
    for field in n.children()? {
        if field.tag == USAGE_LIMITS_UNIT {
            unit_value(field)?;
        } else {
            nonnegative_long(field)?;
        }
    }
    Ok(())
}
pub(super) fn filter_matches(filter: &Node, actual: &Node) -> bool {
    let Ok(limits) = Limits::read(actual, false) else {
        return false;
    };
    filter.children().is_ok_and(|fields| {
        fields.iter().all(|field| match field.tag {
            USAGE_LIMITS_TOTAL => nonnegative_long(field).is_ok_and(|v| limits.total >= v),
            USAGE_LIMITS_COUNT => nonnegative_long(field).is_ok_and(|v| limits.remaining >= v),
            USAGE_LIMITS_UNIT => unit_value(field).is_ok_and(|v| limits.unit == v),
            _ => false,
        })
    })
}
/// "A server SHALL store in this attribute the maximum Lease Time it is able
/// to serve" (Lease Time: 1.0 3.15, 1.4 3.20, 2.x 4.30, 3.0 4.34); the
/// maximum is server policy, set when the object is created or registered.
pub(super) fn initialize(obj: &mut Object, lease: u32) -> R<()> {
    obj.usage_consumed = false;
    for a in &mut obj.attrs {
        if a.tag == USAGE_LIMITS {
            *a = Limits::read(a, true)?.node();
        }
    }
    obj.attrs.retain(|a| a.tag != LEASE_TIME);
    obj.attrs.push(Node::interval(LEASE_TIME, lease));
    Ok(())
}
fn limits(obj: &Object) -> R<Option<Limits>> {
    obj.attrs
        .iter()
        .find(|a| a.tag == USAGE_LIMITS)
        .map(|n| Limits::read(n, false))
        .transpose()
}
fn maximum_lease(obj: &Object) -> R<u32> {
    obj.attrs
        .iter()
        .find(|a| a.tag == LEASE_TIME)
        .map(interval_value)
        .transpose()
        .map(|v| v.unwrap_or(DEFAULT_LEASE_SECONDS))
}
fn protection_mask(obj: &Object, v: Version) -> u32 {
    let allowed = match obj.object_type {
        1 | 3 => 4 | 16 | 512 | 2048 | 2097152,
        2 => 4 | 16 | 128 | 512 | 16384 | 65536 | 262144 | 2097152 | 4194304,
        4 => 1 | 512 | 2048 | 4096 | 8192 | 2097152,
        7 => 512,
        8 => GENERATION_USAGE,
        _ => 0,
    };
    // Unrestricted does not itself denote a generating mechanism. Restrict
    // allocation eligibility to the object's existing generating roles.
    let allowed = allowed & !UNRESTRICTED;
    if unrestricted(obj.usage, v) {
        allowed
    } else {
        obj.usage & allowed
    }
}

impl Engine {
    fn lease_duration(&self, obj: &Object) -> R<u32> {
        lease::duration(obj, self.lease_states, maximum_lease(obj)?)
    }
    pub(super) fn obtain_lease(
        &self,
        owner: &str,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[UNIQUE_IDENTIFIER])?;
        let obj = self.object(owner, p, placeholder)?;
        Ok(vec![
            Node::text(UNIQUE_IDENTIFIER, &obj.id),
            Node::interval(LEASE_TIME, self.lease_duration(&obj)?),
            Node::date(LAST_CHANGE_DATE, obj.updated),
        ])
    }
    pub(super) fn check(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                USAGE_LIMITS_COUNT,
                CRYPTOGRAPHIC_USAGE_MASK,
                LEASE_TIME,
            ],
        )?;
        let obj = self.object(owner, p, placeholder)?;
        let mut rejected = vec![];
        let mut reason = 12;
        if let Some(n) = p.get(USAGE_LIMITS_COUNT) {
            let amount = nonnegative_long(n)?;
            if limits(&obj)?.is_some_and(|l| amount > l.remaining) {
                reason = if v.0 >= 2 { 0x1a } else { 12 };
                rejected.push(n.clone());
            }
        }
        if let Some(n) = p.get(CRYPTOGRAPHIC_USAGE_MASK) {
            let mask = n.number()?;
            if !permits_all(obj.usage, mask, v) {
                if rejected.is_empty() {
                    reason = if v.0 >= 2 { 0x29 } else { 12 };
                }
                rejected.push(n.clone());
            }
        }
        if let Some(n) = p.get(LEASE_TIME) {
            let requested = interval_value(n)?;
            let allowed = self
                .lease_duration(&obj)
                .is_ok_and(|available| available == 0 || requested != 0 && requested <= available);
            if !allowed {
                rejected.push(n.clone());
            }
        }
        if !rejected.is_empty() {
            return Err(fail(reason, "Check denied requested attributes").check_denied(rejected));
        }
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    pub(super) fn allocate_usage(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(p, &[UNIQUE_IDENTIFIER, USAGE_LIMITS_COUNT])?;
        // 1.x Get Usage Allocation table (1.4 Table 345): "No Usage Limits
        // Count is specified": Invalid Message.
        let count = match p.get(USAGE_LIMITS_COUNT) {
            None if v.0 == 1 => return Err(fail(4, "Usage Limits Count is required")),
            n => n.ok_or(fail(7, "Usage Limits Count is required"))?,
        };
        let amount = nonnegative_long(count)?;
        let mut obj = self.object(owner, p, placeholder)?;
        if limits(&obj)?.is_none() {
            // 1.4 Table 345: "Object has no Usage Limits attribute":
            // Illegal Operation.
            return Err(fail(
                if v.0 >= 2 { 0x21 } else { 0x0B },
                "Object has no Usage Limits",
            ));
        }
        self.materialize(owner, &mut obj)?;
        let mask = protection_mask(&obj, v);
        if mask == 0 || obj.material.is_empty() {
            return Err(fail(
                if v.0 >= 2 { 0x30 } else { 11 },
                "Object cannot apply cryptographic protection",
            ));
        }
        check_use(&obj, v, mask, true)
            .map_err(|_| fail(12, "Object cannot currently apply cryptographic protection"))?;
        self.debit_usage(&mut obj, amount, if v.0 >= 2 { 0x1a } else { 12 })?;
        Ok(vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)])
    }
    fn debit_usage(&self, obj: &mut Object, amount: i64, exhausted: u32) -> R<()> {
        if let Some(mut limits) = limits(obj)? {
            if amount > limits.remaining {
                return Err(fail(exhausted, "Usage Limits exhausted"));
            }
            limits.remaining -= amount;
            obj.attrs.retain(|a| a.tag != USAGE_LIMITS);
            obj.attrs.push(limits.node());
        }
        obj.usage_consumed = true;
        obj.updated = now();
        self.store.put(obj)?;
        Ok(())
    }
    /// A protection debit whose output an Undo batch may still deliver. Usage
    /// allocations are not recorded: an Undone allocation grants nothing.
    fn debit_protection(&self, obj: &mut Object, amount: i64, exhausted: u32) -> R<()> {
        self.debit_usage(obj, amount, exhausted)?;
        self.usage_ledger.record(&obj.owner, &obj.id, amount);
        Ok(())
    }
    /// Charges an Undo-surviving debit to the object's rolled-back state.
    /// The original debit fit the same lifetime count, less any usage the
    /// undone batch took back, so the floor at zero is only defensive.
    pub(super) fn reapply_usage(&self, obj: &mut Object, amount: i64) -> R<()> {
        if let Some(mut limits) = limits(obj)? {
            limits.remaining = limits.remaining.saturating_sub(amount).max(0);
            obj.attrs.retain(|a| a.tag != USAGE_LIMITS);
            obj.attrs.push(limits.node());
        }
        obj.usage_consumed = true;
        obj.updated = now();
        self.store.put(obj)?;
        Ok(())
    }
    pub(super) fn consume_protection(
        &self,
        obj: &mut Object,
        bytes: usize,
        v: Version,
        exhausted: u32,
    ) -> R<()> {
        let limits = limits(obj)?;
        if limits.is_none() && obj.usage_consumed {
            return Ok(());
        }
        let amount = if limits.is_some_and(|l| l.unit == 1) {
            i64::try_from(bytes).map_err(|_| {
                fail(
                    if v.0 >= 2 { 0x1b } else { 7 },
                    "Usage quantity is too large",
                )
            })?
        } else {
            1
        };
        self.debit_protection(obj, amount, exhausted)
    }
    pub(super) fn consume_stream_protection(
        &self,
        obj: &mut Object,
        bytes: usize,
        initial: bool,
        v: Version,
        exhausted: u32,
    ) -> R<()> {
        let limits = limits(obj)?;
        if limits.is_none() && obj.usage_consumed {
            return Ok(());
        }
        let amount = if limits.is_some_and(|l| l.unit == 1) {
            i64::try_from(bytes)
                .map_err(|_| fail(if v.0 >= 2 { 0x1b } else { 7 }, "Usage quantity too large"))?
        } else {
            i64::from(initial)
        };
        self.debit_protection(obj, amount, exhausted)
    }
    pub(super) fn modify_usage(
        &self,
        mut obj: Object,
        v: Version,
        op: u32,
        new: Option<Node>,
    ) -> R<Vec<Node>> {
        let old = obj.attrs.iter().find(|a| a.tag == USAGE_LIMITS).cloned();
        let previous = limits(&obj)?;
        if obj.usage_consumed || previous.is_some_and(|l| l.remaining != l.total) {
            return Err(read_only(v));
        }
        if op == 13 && old.is_some() {
            return Err(fail(7, "Usage Limits already exists"));
        }
        if matches!(op, 14 | 15) && old.is_none() {
            return Err(fail(
                if v.0 >= 2 { 0x21 } else { 1 },
                "Usage Limits not found",
            ));
        }
        let replacement = if let Some(n) = new {
            if n.get(USAGE_LIMITS_COUNT).is_some() {
                return Err(read_only(v));
            }
            no_fields(&n, &[USAGE_LIMITS_TOTAL, USAGE_LIMITS_UNIT])?;
            let total = n
                .get(USAGE_LIMITS_TOTAL)
                .map(nonnegative_long)
                .transpose()?
                .unwrap_or(previous.map_or(i64::MAX, |l| l.total));
            let unit = n
                .get(USAGE_LIMITS_UNIT)
                .map(unit_value)
                .transpose()?
                .unwrap_or(previous.map_or(2, |l| l.unit));
            Some(
                Limits {
                    total,
                    remaining: total,
                    unit,
                }
                .node(),
            )
        } else {
            None
        };
        obj.attrs.retain(|a| a.tag != USAGE_LIMITS);
        if let Some(n) = &replacement {
            obj.attrs.push(n.clone());
        }
        obj.updated = now();
        self.store.put(&obj)?;
        let mut result = vec![Node::text(UNIQUE_IDENTIFIER, &obj.id)];
        if v.0 == 1
            && let Some(n) = replacement.or(old)
        {
            result.push(encode_attribute(&n)?);
        }
        Ok(result)
    }
}
