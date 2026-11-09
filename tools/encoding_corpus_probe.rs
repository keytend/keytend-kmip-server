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

use keytend_kmip_server::encoding::Format;
use std::io::{self, BufRead};
fn main() {
    for line in io::stdin().lock().lines() {
        let s: String = serde_json::from_str(&line.unwrap()).unwrap();
        let result = match Format::Xml.decode(s.as_bytes()) {
            Ok(n) => serde_json::json!({"ttlv":hex::encode(n.encode())}),
            Err(e) => serde_json::json!({"error":e.to_string()}),
        };
        println!("{}", result);
    }
}
