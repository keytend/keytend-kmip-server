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

//! Offline arithmetic test adapter. Never built into the server or its image.
use keytend_kmip_server::crypto::split::{Method, Parameters, Polynomial, Share};
use serde_json::{Value, json};
use std::io::{self, BufRead};
use zeroize::Zeroizing;

fn run(input: &Value) -> anyhow::Result<Value> {
    let num = |name: &str| -> anyhow::Result<usize> {
        Ok(usize::try_from(input[name].as_u64().ok_or_else(|| anyhow::anyhow!("missing {name}"))?)?)
    };
    let prime = input["prime"].as_str().map(hex::decode).transpose()?;
    let poly = input["polynomial"].as_u64().map(u32::try_from).transpose()?.map(Polynomial::try_from).transpose()?;
    let params = Parameters::new(Method::try_from(u32::try_from(num("method")?)?)?,
        num("parts")?, num("threshold")?, num("secret_len")?, poly, prime.as_deref())?;
    match input["operation"].as_str() {
        Some("split") => {
            let bytes = Zeroizing::new(hex::decode(input["secret"].as_str().unwrap_or(""))?);
            let shares = params.split(&bytes)?;
            Ok(json!({"shares": shares.iter().map(|s| json!({"index":s.index,"value":hex::encode(&*s.value)})).collect::<Vec<_>>()}))
        }
        Some("join") => {
            let shares = input["shares"].as_array().ok_or_else(|| anyhow::anyhow!("missing shares"))?.iter().map(|s| {
                Ok(Share { index:u16::try_from(s["index"].as_u64().unwrap_or(0))?,
                    value:Zeroizing::new(hex::decode(s["value"].as_str().unwrap_or(""))?) })
            }).collect::<anyhow::Result<Vec<_>>>()?;
            Ok(json!({"secret":hex::encode(&*params.join(&shares)?)}))
        }
        _ => anyhow::bail!("invalid operation"),
    }
}
fn main() {
    for line in io::stdin().lock().lines() {
        let output = line.map_err(anyhow::Error::from).and_then(|line| {
            let input: Value = serde_json::from_str(&line)?;
            run(&input)
        });
        println!("{}", match output { Ok(value)=>value, Err(error)=>json!({"error":error.to_string()}) });
    }
}
