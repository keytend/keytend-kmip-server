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

//! KMIP 2.0 section 6.1.28 / 2.1 section 6.1.29 Log: "log a message to the
//! server log. The response payload returned is empty."
//!
//! The message goes to the server's structured log (target `kmip::client_log`)
//! with the authenticated principal, never to the HMAC audit chain, whose
//! record format is fixed. The audit chain still records that a Log operation
//! ran (operation 0x2C, principal and status). Messages are held until the
//! batch commits: a failed or undone Log item writes nothing.
use super::*;

/// Largest accepted Log Message, in UTF-8 bytes. The specification sets no
/// limit; a bound keeps one batch from writing unbounded log volume.
pub(super) const MAX_MESSAGE: usize = 4096;

impl Engine {
    pub(super) fn log_message(&mut self, owner: &str, p: &Node) -> R<Vec<Node>> {
        no_fields(p, &[LOG_MESSAGE])?;
        let message = p.required(LOG_MESSAGE)?.string()?;
        if message.len() > MAX_MESSAGE {
            return Err(fail(7, "Log Message exceeds the server limit"));
        }
        self.side.logs.push((owner.to_owned(), message.to_owned()));
        Ok(vec![])
    }
}

/// Write committed client messages. Control characters are escaped so a
/// client cannot forge additional log lines.
pub(super) fn emit(logs: Vec<(String, String)>) {
    for (owner, message) in logs {
        tracing::info!(
            target: "kmip::client_log",
            principal = %owner.escape_debug(),
            message = %message.escape_debug(),
            "KMIP Log operation"
        );
    }
}
