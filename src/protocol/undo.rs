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

//! Protection usage that an Undo batch cannot take back.
//!
//! KMIP 1.4 section 6.13 says that under Undo "the server SHALL undo all the
//! previous operations", and Table 366 returns the processed items "with
//! Undone result status". Table 285 (2.1 Table 399) still requires a Response
//! Payload when the status is not a failure, so an undone Encrypt, Sign, MAC,
//! Derive Key or wrapped Get/Export has already delivered its protection
//! output. Usage Limits (1.4 section 3.21) "SHALL only reflect their usage for
//! applying that protection" and are "decremented when the object is used".
//! Rolling the debit back with the rest of the batch would let a client obtain
//! unlimited protection output through failing Undo batches. Every debit
//! taken by an item whose response is kept is therefore re-applied after the
//! batch rolls back. The usage happened and was delivered, so it is not one of
//! the undoable state changes. Debits of objects whose creation was undone have
//! no object left to charge. Get Usage Allocation debits remain undoable: the
//! Undone status withdraws the allocation and no server output depends on it.
//! Derive Key debits are kept even if the batch never reads the derived key;
//! over-counting a lifetime bound is the conservative direction.
use super::*;
use std::cell::RefCell;
use std::collections::BTreeMap;

type Charge = (String, String, i64);

/// Debits recorded while an Undo batch runs; inactive otherwise.
#[derive(Default)]
pub(super) struct UsageLedger(RefCell<Option<Vec<Charge>>>);

impl UsageLedger {
    pub(super) fn start(&self, active: bool) {
        *self.0.borrow_mut() = active.then(Vec::new);
    }
    pub(super) fn record(&self, owner: &str, id: &str, amount: i64) {
        if let Some(charges) = self.0.borrow_mut().as_mut() {
            charges.push((owner.to_owned(), id.to_owned(), amount));
        }
    }
    /// Position before an item, so a failed item's debits can be dropped
    /// along with its savepoint: a failure delivers no protection output.
    pub(super) fn mark(&self) -> usize {
        self.0.borrow().as_ref().map_or(0, Vec::len)
    }
    pub(super) fn discard_after(&self, mark: usize) {
        if let Some(charges) = self.0.borrow_mut().as_mut() {
            charges.truncate(mark);
        }
    }
    /// Stops recording and returns the kept debits per owned object.
    pub(super) fn finish(&self) -> BTreeMap<(String, String), i64> {
        let mut total = BTreeMap::new();
        for (owner, id, amount) in self.0.borrow_mut().take().unwrap_or_default() {
            let entry: &mut i64 = total.entry((owner, id)).or_default();
            *entry = entry.saturating_add(amount);
        }
        total
    }
}

impl Engine {
    /// Re-applies kept debits after `ROLLBACK TO batch_changes`, inside the
    /// same transaction as the undone batch and its audit events.
    pub(super) fn retain_undone_usage(&self, charges: BTreeMap<(String, String), i64>) -> R<()> {
        for ((owner, id), amount) in charges {
            if let Some(mut obj) = self.store.get(&owner, &id)? {
                self.reapply_usage(&mut obj, amount)?;
            }
        }
        Ok(())
    }
}
