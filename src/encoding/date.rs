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

//! Proleptic Gregorian arithmetic over the full signed 64-bit Unix-second range.
use anyhow::{Result, ensure};
fn before_year(y: i128) -> i128 {
    365 * y + (y + 3).div_euclid(4) - (y + 99).div_euclid(100) + (y + 399).div_euclid(400)
}
fn leap(y: i128) -> bool {
    y.rem_euclid(4) == 0 && (y.rem_euclid(100) != 0 || y.rem_euclid(400) == 0)
}
fn months(y: i128) -> [i128; 12] {
    [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ]
}
pub(super) fn format(seconds: i64) -> String {
    let day = i128::from(seconds.div_euclid(86400)) + before_year(1970);
    let mut lo = -400_000_000_000i128;
    let mut hi = 400_000_000_000i128;
    while lo + 1 < hi {
        let mid = (lo + hi).div_euclid(2);
        if before_year(mid) <= day {
            lo = mid
        } else {
            hi = mid
        }
    }
    let mut remaining = day - before_year(lo);
    let mut month = 1;
    for size in months(lo) {
        if remaining < size {
            break;
        }
        remaining -= size;
        month += 1
    }
    let year = if lo <= 0 {
        format!("-{:04}", 1 - lo)
    } else {
        format!("{lo:04}")
    };
    let time = seconds.rem_euclid(86400);
    format!(
        "{year}-{month:02}-{:02}T{:02}:{:02}:{:02}Z",
        remaining + 1,
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}
pub(super) fn parse(s: &str) -> Result<i64> {
    ensure!(s.is_ascii(), "date must be ASCII");
    let (date, time) = s
        .split_once('T')
        .ok_or_else(|| anyhow::anyhow!("date separator missing"))?;
    let (negative, date) = date
        .strip_prefix('-')
        .map(|s| (true, s))
        .unwrap_or((false, date));
    let mut parts = date.split('-');
    let year = parts.next().unwrap_or("");
    let month = parts.next().unwrap_or("");
    let day = parts.next().unwrap_or("");
    ensure!(
        parts.next().is_none()
            && year.len() >= 4
            && year.len() <= 12
            && (year.len() == 4 || !year.starts_with('0'))
            && year.bytes().all(|b| b.is_ascii_digit())
            && month.len() == 2
            && day.len() == 2,
        "date fields invalid"
    );
    let year = year.parse::<i128>()?;
    ensure!(year != 0, "XML Schema dates have no year zero");
    let year = if negative { 1 - year } else { year };
    let month = month.parse::<usize>()?;
    let day = day.parse::<i128>()?;
    ensure!(
        (1..=12).contains(&month) && day >= 1 && day <= months(year)[month - 1],
        "date range invalid"
    );
    let (time, offset) = if let Some(t) = time.strip_suffix('Z') {
        (t, 0)
    } else {
        let at = time
            .rfind(['+', '-'])
            .ok_or_else(|| anyhow::anyhow!("date timezone required"))?;
        let (t, z) = time.split_at(at);
        ensure!(
            z.len() == 6
                && &z[3..4] == ":"
                && z[1..3]
                    .bytes()
                    .chain(z[4..].bytes())
                    .all(|b| b.is_ascii_digit()),
            "timezone invalid"
        );
        let h = z[1..3].parse::<i128>()?;
        let m = z[4..].parse::<i128>()?;
        ensure!(
            h <= 14 && m < 60 && (h != 14 || m == 0),
            "timezone range invalid"
        );
        (
            t,
            (if z.starts_with('-') { -1 } else { 1 }) * (h * 3600 + m * 60),
        )
    };
    let (clock, fraction) = time
        .split_once('.')
        .map(|(t, f)| (t, Some(f)))
        .unwrap_or((time, None));
    ensure!(
        clock.len() == 8
            && &clock[2..3] == ":"
            && &clock[5..6] == ":"
            && clock
                .bytes()
                .enumerate()
                .all(|(i, b)| i == 2 || i == 5 || b.is_ascii_digit()),
        "time fields invalid"
    );
    if let Some(f) = fraction {
        ensure!(
            !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()),
            "fraction invalid"
        )
    }
    let hour = clock[..2].parse::<i128>()?;
    let minute = clock[3..5].parse::<i128>()?;
    let second = clock[6..].parse::<i128>()?;
    ensure!(
        hour <= 24
            && minute < 60
            && second < 60
            && (hour != 24
                || minute == 0
                    && second == 0
                    && fraction.is_none_or(|f| f.bytes().all(|b| b == b'0'))),
        "time range invalid"
    );
    let days = before_year(year) - before_year(1970)
        + months(year)[..month - 1].iter().sum::<i128>()
        + day
        - 1;
    Ok(i64::try_from(
        days * 86400 + hour * 3600 + minute * 60 + second - offset,
    )?)
}
