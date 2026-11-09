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

//! A process-local audit floor detects replay of an entire valid live store.
//! Only committed snapshots advance it. It is not an external restart witness.
use super::*;
use subtle::ConstantTimeEq;

#[derive(Clone, Copy)]
pub(super) struct HistoryTip {
    store: [u8; 32],
    sequence: i64,
    mac: [u8; 32],
}

impl Store {
    pub(super) fn history_tip(&self) -> Result<HistoryTip> {
        let marker: Vec<u8> =
            self.conn
                .query_row("SELECT value FROM meta WHERE name='key-check'", [], |row| {
                    row.get(0)
                })?;
        let head: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT seq,mac FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if head.as_ref().is_some_and(|(sequence, _)| *sequence <= 0) {
            bail!("invalid live audit sequence");
        }
        let (sequence, mac) = head.unwrap_or((0, vec![0; 32]));
        if mac.len() != 32 {
            bail!("invalid live audit head");
        }
        Ok(HistoryTip {
            store: crate::crypto::sha256(&marker),
            sequence,
            mac: mac
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid live audit MAC"))?,
        })
    }

    /// Caller holds a SQLite snapshot. Authenticate every unseen link, not only
    /// the last event: a copied authentic head cannot bridge a divergent prefix.
    pub(super) fn verify_history_floor(&self, floor: HistoryTip) -> Result<HistoryTip> {
        let tip = self.history_tip()?;
        if !bool::from(tip.store.ct_eq(&floor.store)) || tip.sequence < floor.sequence {
            bail!(
                "live store history is older than the observed floor or belongs to another store"
            );
        }
        let retained: Option<Vec<u8>> = if floor.sequence == 0 {
            Some(vec![0; 32])
        } else {
            self.conn
                .query_row(
                    "SELECT mac FROM audit WHERE seq=?1",
                    [floor.sequence],
                    |row| row.get(0),
                )
                .optional()?
        };
        if !retained.is_some_and(|mac| bool::from(mac.ct_eq(&floor.mac))) {
            bail!("live store history diverges from the observed floor");
        }
        if tip.sequence == floor.sequence {
            return Ok(tip);
        }
        // Older stores, opened read-only, have no state_root column yet.
        let sql = if self.audit_has_state()? {
            "SELECT seq,timestamp,principal,operation,object_id,status,previous,mac,state_root FROM audit WHERE seq>?1 ORDER BY seq"
        } else {
            "SELECT seq,timestamp,principal,operation,object_id,status,previous,mac,NULL FROM audit WHERE seq>?1 ORDER BY seq"
        };
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query([floor.sequence])?;
        let mut sequence = floor.sequence;
        let mut previous = floor.mac.to_vec();
        while let Some(row) = rows.next()? {
            let current: i64 = row.get(0)?;
            let timestamp = row.get(1)?;
            let principal: String = row.get(2)?;
            let operation = row.get(3)?;
            let identifier: Option<String> = row.get(4)?;
            let status = row.get(5)?;
            let prev: Vec<u8> = row.get(6)?;
            let mac: Vec<u8> = row.get(7)?;
            let state: Option<Vec<u8>> = row.get(8)?;
            sequence = sequence
                .checked_add(1)
                .context("live audit sequence overflow")?;
            let expected = self.audit_mac(
                current,
                timestamp,
                &principal,
                operation,
                identifier.as_deref(),
                status,
                &prev,
                state.as_deref(),
            )?;
            if current != sequence
                || !bool::from(prev.ct_eq(&previous))
                || !bool::from(mac.ct_eq(&expected))
            {
                bail!("live store audit extension authentication failed");
            }
            previous = mac;
        }
        if sequence != tip.sequence || !bool::from(previous.ct_eq(&tip.mac)) {
            bail!("live store audit head changed within its snapshot");
        }
        Ok(tip)
    }

    pub(super) fn check_live_history(&self) -> Result<()> {
        if self.history_failed.get() {
            bail!("live store history failure is latched; checked recovery and restart required");
        }
        if let Some(floor) = self.observed_history.get()
            && let Err(error) = self.verify_history_floor(floor)
        {
            self.history_failed.set(true);
            return Err(error).context("live store history integrity failure");
        }
        Ok(())
    }

    pub(super) fn observe_history(&self, tip: HistoryTip) {
        self.observed_history.set(Some(tip));
    }
}
