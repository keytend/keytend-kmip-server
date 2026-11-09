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

//! Which objects Obtain Lease serves, and for how long
//! (docs/lifecycle.md#leases).
//!
//! No clause requires an Active object for Obtain Lease (1.4 section 4.17,
//! 2.0 section 6.1.34, 2.1 section 6.1.35, draft 3.0 section 6.1.42): the
//! server refuses only "If the server determines that a new lease is not
//! permitted" (2.x: "SHALL NOT be issued"). A Deactivated object "SHALL
//! NOT be used for applying cryptographic protection" but may still process
//! protected data (State: 1.4 section 3.22, 2.1 section 4.57, draft 3.0
//! section 4.67), so `active-deactivated` (the default) leases it too;
//! `active` leases Active objects only. Pre-Active ("SHALL NOT
//! be used for any cryptographic purpose"), Compromised and Destroyed objects
//! are always refused. A lease does not widen what an object may do: the
//! server still refuses Encrypt, Sign, MAC and wrapping with a Deactivated
//! key (`check_use`), and a client must keep honouring State and the dates.
//!
//! Every refusal is Permission Denied in every edition: 1.4 Table 344 ("The
//! server determines that a new lease is not permitted to be issued for the
//! specified cryptographic object": Permission Denied); 2.0 Table 252, 2.1
//! Table 270 and draft 3.0 Table 379 list Permission Denied and not Wrong Key
//! Lifecycle State. The messages name the cause and are stable.
//!
//! Lease length. A lease never outlasts the point where the object's permitted
//! use narrows, so the client comes back and sees the new state: an Active
//! object's lease ends at its Protect Stop Date (no more protection, 1.4
//! section 3.26) or Deactivation Date (1.4 section 3.27), whichever comes
//! first and is still ahead. KMIP defines no attribute that ends processing
//! (the "Process Stop Date" in the Active bullet of 1.4 section 3.22 and 2.1
//! section 4.57 is the Protect Stop Date of the sentence before it), so a
//! Deactivated object's lease is bounded by the stored Lease Time alone;
//! Destroy and a compromise take effect at the client's next renewal. A
//! Lease Time of zero is no lease limit ("If the returned value of the lease
//! time is zero, then the server is indicating that no lease interval is
//! effective, and the client MAY use the object without any lease time
//! limit", 1.4 section 4.17, 2.x/3.0 Obtain Lease), unless a date above
//! bounds it.
use super::*;

/// Lifecycle states that receive a lease (`--lease-states`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum LeaseStates {
    /// Only Active objects.
    Active,
    /// Active and Deactivated objects.
    #[default]
    ActiveDeactivated,
}

fn refused(message: &'static str) -> Failure {
    fail(12, message)
}

/// The Lease Time Obtain Lease grants for `obj`, or why it grants none.
pub(super) fn duration(obj: &Object, states: LeaseStates, maximum: u32) -> R<u32> {
    let deactivated = states == LeaseStates::ActiveDeactivated;
    match obj.state {
        2 => {}
        3 if deactivated => {}
        1 => return Err(refused("A Pre-Active object cannot receive a lease")),
        3 => {
            return Err(refused(
                "A Deactivated object cannot receive a lease (server lease policy: Active objects only)",
            ));
        }
        4 => return Err(refused("A Compromised object cannot receive a lease")),
        5 | 6 => return Err(refused("A Destroyed object cannot receive a lease")),
        _ => {
            return Err(refused(
                "This object has no lifecycle state that permits a lease",
            ));
        }
    }
    let time = now();
    let passed = |tag| attr_time(&obj.attrs, tag).is_some_and(|t| t <= time);
    if deactivated {
        let protects = obj.state == 2 && !passed(PROTECT_STOP_DATE) && !passed(DEACTIVATION_DATE);
        let processes = attr_time(&obj.attrs, PROCESS_START_DATE).is_none_or(|t| t <= time);
        if !protects && !processes {
            return Err(refused(
                "The object cannot be used before its Process Start Date",
            ));
        }
    } else if passed(DEACTIVATION_DATE) {
        return Err(refused("The object's Deactivation Date has passed"));
    } else if passed(PROTECT_STOP_DATE) {
        return Err(refused("The object's Protect Stop Date has passed"));
    }
    let mut duration = maximum;
    if obj.state == 2 {
        for tag in [PROTECT_STOP_DATE, DEACTIVATION_DATE] {
            if let Some(deadline) = attr_time(&obj.attrs, tag).filter(|&t| t > time) {
                let remaining = u32::try_from(deadline - time).unwrap_or(u32::MAX);
                // A zero lease is no time limit, never an already expired lease.
                if duration == 0 || remaining < duration {
                    duration = remaining;
                }
            }
        }
    }
    Ok(duration)
}
