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

//! Server-owned reason history and the Revoke transitions.
use super::*;

pub(super) fn reason(rr: &Node) -> R<u32> {
    no_fields(rr, &[REVOCATION_REASON_CODE, REVOCATION_MESSAGE])?;
    let code = match rr.required(REVOCATION_REASON_CODE)?.value {
        Value::Enumeration(code @ 1..=7) => code,
        _ => return Err(fail(7, "Invalid revocation reason")),
    };
    if let Some(message) = rr.get(REVOCATION_MESSAGE) {
        message.string()?;
    }
    Ok(code)
}

fn compromises(v: Version, code: u32) -> bool {
    // 1.0--1.2 Revoke prose says Key Compromise only; 1.3+ includes CA
    // Compromise. CSD02 6.1.51 makes every Revoke a compromise.
    v.0 >= 3 || code == 2 || v >= Version(1, 3) && code == 3
}

/// Mutate a detached object; the caller bounds the completed attributes before
/// writing within the request transaction. There is no repeat/update transition.
pub(super) fn apply(obj: &mut Object, v: Version, p: &Node) -> R<u32> {
    let revocation = match p.get(REVOCATION_REASON) {
        None if v.0 >= 3 => Node::structure(
            REVOCATION_REASON,
            vec![Node::enumeration(REVOCATION_REASON_CODE, 1)],
        ),
        _ => p.required(REVOCATION_REASON)?.clone(),
    };
    let code = reason(&revocation)?;
    let compromised = compromises(v, code);
    // State sections 1.1--1.4 3.22 / 2.0 4.50 / 2.1 4.57 / CSD02 4.67:
    // "Only the transitions described above are permitted."
    let next = match (obj.state, compromised) {
        (1..=3, true) => 4,
        (5, true) => 6,
        (2, false) => 3,
        _ => {
            return Err(fail(
                if v.0 >= 2 { 0x43 } else { 12 },
                "Revoke is not permitted in this lifecycle state",
            ));
        }
    };
    let occurrence = match p.get(COMPROMISE_OCCURRENCE_DATE) {
        Some(date) => {
            if !compromised || date_value(date)? > now() {
                return Err(fail(7, "Invalid Compromise Occurrence Date"));
            }
            Some(date.clone())
        }
        None if v < Version(1, 3) && code == 2 => {
            return Err(fail(
                6,
                "Key Compromise requires Compromise Occurrence Date",
            ));
        }
        // Follow the SHOULD default, never replacing an existing compromise:
        // repeats were already refused above.
        None if compromised => Some(Node::date(COMPROMISE_OCCURRENCE_DATE, obj.created)),
        None => None,
    };
    obj.attrs.retain(|a| a.tag != REVOCATION_REASON);
    obj.attrs.push(revocation);
    if let Some(occurrence) = occurrence {
        obj.attrs.retain(|a| a.tag != COMPROMISE_OCCURRENCE_DATE);
        obj.attrs.push(occurrence);
    }
    obj.state = next;
    Ok(if compromised {
        COMPROMISE_DATE
    } else {
        DEACTIVATION_DATE
    })
}

/// Import restores server metadata, rather than initially assigning it through
/// Create/Register/Add Attribute. A supplied reason must describe a possible
/// completed revocation. Its absence remains legal (out-of-band lifecycle work).
pub(super) fn validate_restored(obj: &Object) -> R<()> {
    let Some(rr) = obj.attrs.iter().find(|a| a.tag == REVOCATION_REASON) else {
        return Ok(());
    };
    let code = reason(rr)?;
    // Import's edition does not identify the edition of the historical Revoke.
    // CA Compromise may describe a 1.0--1.2 deactivation; every supported code
    // may describe a CSD02 compromise. Key Compromise never deactivates.
    // This restores possible histories; it does not permit new Revoke edges.
    let compromised = match obj.state {
        4 | 6 => true,
        3 | 5 if code != 2 => false,
        _ => return Err(fail(7, "Imported Revocation Reason conflicts with state")),
    };
    let date = attr_time(
        &obj.attrs,
        if compromised {
            COMPROMISE_DATE
        } else {
            DEACTIVATION_DATE
        },
    );
    if date.is_none_or(|t| t < obj.created || t > obj.updated || t > now()) {
        return Err(fail(
            7,
            "Imported Revocation Reason conflicts with state or date",
        ));
    }
    let compromise_date = attr_time(&obj.attrs, COMPROMISE_DATE);
    let occurrence = attr_time(&obj.attrs, COMPROMISE_OCCURRENCE_DATE);
    if !compromised && (compromise_date.is_some() || occurrence.is_some())
        || compromised && occurrence.is_some_and(|t| Some(t) > compromise_date)
        || obj.state < 5 && attr_time(&obj.attrs, DESTROY_DATE).is_some()
        || obj.state >= 5
            && attr_time(&obj.attrs, DESTROY_DATE)
                .is_none_or(|t| t < obj.created || t > obj.updated || t > now())
    {
        return Err(fail(7, "Imported revocation lifecycle dates conflict"));
    }
    Ok(())
}
