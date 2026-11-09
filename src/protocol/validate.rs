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

use super::*;
use crate::certificates::{MAX_BYTES, MAX_CERT_BYTES, MAX_CHAIN};
use openssl::x509::X509;
impl Engine {
    pub(super) fn prepare_validation(
        &self,
        owner: &str,
        v: Version,
        item: &Node,
        refs: &identifiers::References,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        let mut fields = vec![];
        let mut ids = 0;
        for n in item.required(REQUEST_PAYLOAD)?.children()? {
            if n.tag == UNIQUE_IDENTIFIER {
                for id in self.resolve_identifier(owner, v, n, refs, placeholder)? {
                    ids += 1;
                    if ids > MAX_CHAIN {
                        return Err(server_limit(v, "Certificate chain resource limit exceeded"));
                    }
                    fields.push(Node::text(UNIQUE_IDENTIFIER, id));
                }
            } else {
                fields.push(n.clone());
            }
        }
        let mut item = item.clone();
        if let Value::Structure(items) = &mut item.value {
            *items.iter_mut().find(|n| n.tag == REQUEST_PAYLOAD).unwrap() =
                Node::structure(REQUEST_PAYLOAD, fields);
        }
        Ok(vec![item])
    }
    pub(super) fn validate_certificates(&self, owner: &str, v: Version, p: &Node) -> R<Vec<Node>> {
        if p.children()?
            .iter()
            .any(|n| ![CERTIFICATE, UNIQUE_IDENTIFIER, VALIDITY_DATE].contains(&n.tag))
        {
            return Err(fail(7, "Unsupported certificate validation field"));
        }
        if p.all(VALIDITY_DATE).count() > 1 {
            return Err(fail(7, "Duplicate Validity Date"));
        }
        let at = match p.get(VALIDITY_DATE).map(|n| &n.value) {
            None => now(),
            Some(Value::DateTime(at)) => *at,
            _ => return Err(fail(7, "Validity Date must be Date-Time")),
        };
        if p.all(CERTIFICATE).count() + p.all(UNIQUE_IDENTIFIER).count() > MAX_CHAIN {
            return Err(server_limit(v, "Certificate chain resource limit exceeded"));
        }
        let mut certificates = vec![];
        let mut seen = std::collections::HashSet::new();
        let mut bytes = 0usize;
        let mut unusable = false;
        for n in p.children()?.iter().filter(|n| n.tag != VALIDITY_DATE) {
            let der = if n.tag == CERTIFICATE {
                no_fields(n, &[CERTIFICATE_TYPE, CERTIFICATE_VALUE])?;
                match n
                    .get(CERTIFICATE_TYPE)
                    .ok_or(fail(7, "Certificate Type is required"))?
                    .value
                {
                    Value::Enumeration(1) => (),
                    Value::Enumeration(_) => {
                        return Err(fail(8, "Only X.509 certificate validation is supported"));
                    }
                    _ => return Err(fail(7, "Certificate Type must be Enumeration")),
                }
                n.get(CERTIFICATE_VALUE)
                    .ok_or(fail(7, "Certificate Value is required"))?
                    .byte_string()?
                    .to_vec()
            } else {
                let obj = self.object(
                    owner,
                    &Node::structure(REQUEST_PAYLOAD, vec![n.clone()]),
                    &None,
                )?;
                if obj.object_type != 1 {
                    return Err(fail(
                        if v.0 >= 2 { 0x30 } else { 7 },
                        "Certificate object required",
                    ));
                }
                if obj.certificate_type != 1 {
                    return Err(fail(
                        8,
                        "PGP certificate trust validation is not implemented",
                    ));
                }
                if obj.state >= 5 {
                    return Err(fail(12, "Certificate material is destroyed"));
                }
                unusable |= matches!(obj.state, 3 | 4);
                obj.material.clone()
            };
            bytes = bytes.saturating_add(der.len());
            if der.len() > MAX_CERT_BYTES || bytes > MAX_BYTES {
                return Err(server_limit(v, "Certificate chain resource limit exceeded"));
            }
            let cert =
                X509::from_der(&der).map_err(|_| fail(7, "Invalid X.509 certificate encoding"))?;
            ec::certificate_curve(&der)?;
            if cert
                .to_der()
                .map_err(|_| fail(10, "Certificate encoding failed"))?
                != der
            {
                return Err(fail(
                    7,
                    "Certificate Value must contain exactly one DER certificate",
                ));
            }
            if seen.insert(der) {
                certificates.push(cert);
            }
        }
        if certificates.is_empty() {
            return Err(fail(7, "Certificate chain is empty"));
        }
        let validity = if unusable {
            2
        } else {
            self.certificate_validation
                .validate(&certificates, at)
                .map_err(|_| fail(10, "Certificate validation failed"))?
        };
        Ok(vec![Node::enumeration(VALIDITY_INDICATOR, validity)])
    }
}
