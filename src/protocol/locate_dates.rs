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

//! Locate exact/inclusive date predicates; an absent date is the maximum timestamp.
use super::*;
use std::collections::HashMap;

pub(super) fn standard(tag: u32) -> bool {
    matches!(
        tag,
        ACTIVATION_DATE
            | ARCHIVE_DATE
            | COMPROMISE_DATE
            | COMPROMISE_OCCURRENCE_DATE
            | DEACTIVATION_DATE
            | DESTROY_DATE
            | INITIAL_DATE
            | LAST_CHANGE_DATE
            | PROCESS_START_DATE
            | PROTECT_STOP_DATE
            | ORIGINAL_CREATION_DATE
    )
}

pub(super) struct DateRange {
    identity: String,
    extended: bool,
    first: i64,
    second: Option<i64>,
}
impl DateRange {
    fn contains(&self, value: i64) -> bool {
        self.second.map_or(value == self.first, |second| {
            (self.first.min(second)..=self.first.max(second)).contains(&value)
        })
    }
    pub(super) fn matches(&self, attrs: &[Node]) -> bool {
        let mut present = false;
        for attribute in attrs {
            if !attributes::identity(attribute).is_ok_and(|key| key == self.identity) {
                continue;
            }
            present = true;
            let value = if attribute.tag == ATTRIBUTE {
                attribute.get(ATTRIBUTE_VALUE).map(|n| &n.value)
            } else {
                Some(&attribute.value)
            };
            let candidate = match value {
                Some(Value::DateTime(value)) if !self.extended => Some(*value),
                Some(Value::DateTimeExtended(value)) if self.extended => Some(*value),
                _ => None,
            };
            if candidate.is_some_and(|value| self.contains(value)) {
                return true;
            }
        }
        !present && self.contains(i64::MAX)
    }
}

pub(super) fn compile(filters: &mut Vec<Node>, v: Version) -> R<Vec<DateRange>> {
    let mut ranges: Vec<DateRange> = vec![];
    let mut positions: HashMap<(String, bool), usize> = HashMap::new();
    let mut other = vec![];
    for filter in std::mem::take(filters) {
        let standard = standard(filter.tag);
        let value = if filter.tag == ATTRIBUTE {
            &filter.required(ATTRIBUTE_VALUE)?.value
        } else {
            &filter.value
        };
        if !standard
            && !(filter.tag == ATTRIBUTE
                && matches!(value, Value::DateTime(_) | Value::DateTimeExtended(_)))
        {
            other.push(filter);
            continue;
        }
        if filter.tag == ORIGINAL_CREATION_DATE && v < Version(1, 2) {
            return Err(fail(7, "Original Creation Date requires KMIP 1.2"));
        }
        let (extended, value) = match value {
            Value::DateTime(value) => (false, *value),
            Value::DateTimeExtended(value) if !standard => (true, *value),
            _ => return Err(fail(7, "Locate date attribute requires Date-Time")),
        };
        let identity = attributes::identity(&filter)?;
        if let Some(position) = positions.get(&(identity.clone(), extended)) {
            let range = &mut ranges[*position];
            if range.second.replace(value).is_some() {
                return Err(fail(7, "Locate date attribute has more than two bounds"));
            }
        } else {
            positions.insert((identity.clone(), extended), ranges.len());
            ranges.push(DateRange {
                identity,
                extended,
                first: value,
                second: None,
            });
        }
    }
    *filters = other;
    Ok(ranges)
}
