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

//! In-memory server state outside the object store: Log messages awaiting
//! commit, PKCS#11 library instances, the asynchronous request queue and
//! the test-mode Interop record.
//! A failed item or an undone or rolled-back batch restores it, like the
//! store savepoints, so no effect of an unreported item survives.
use super::*;

#[derive(Default)]
pub(crate) struct Side {
    pub(super) logs: Vec<(String, String)>,
    pub(super) pkcs11: pkcs11::Libraries,
    pub(super) queue: asynchronous::Queue,
    pub(super) interop: interop::Tests,
}
#[derive(Clone)]
pub(super) struct Mark {
    logs: usize,
    actions: usize,
    pkcs11: pkcs11::Libraries,
    interop: interop::Tests,
}
impl Side {
    pub(super) fn mark(&self) -> Mark {
        Mark {
            logs: self.logs.len(),
            actions: self.queue.actions.len(),
            pkcs11: self.pkcs11.clone(),
            interop: self.interop.clone(),
        }
    }
    pub(super) fn restore(&mut self, mark: Mark) {
        self.logs.truncate(mark.logs);
        self.queue.actions.truncate(mark.actions);
        self.pkcs11 = mark.pkcs11;
        self.interop = mark.interop;
        self.queue.poll = None;
    }
    /// After the store commits: write Log messages and apply queue actions.
    pub(super) fn commit(&mut self) {
        log::emit(std::mem::take(&mut self.logs));
        self.queue.apply();
    }
}
