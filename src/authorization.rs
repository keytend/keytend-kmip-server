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

//! Explicit read grants. Ownership and the authenticated operation ACL remain authoritative.
use anyhow::{Result, bail};
use serde::Deserialize;
use std::collections::HashSet;

/// Additive permission on exactly one owner's object. This never changes ownership.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObjectGrant {
    pub owner: String,
    /// The object belongs to this verified user (or device) of `owner`,
    /// a principal that uses credential identity. At most one of the two.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
    pub identifier: String,
    pub operations: Vec<u32>,
}
impl ObjectGrant {
    /// The store owner of the granted object (see `protocol::system`).
    pub fn object_owner(&self) -> String {
        match (&self.user, &self.device) {
            (Some(user), _) => format!("{}\0user\0{user}", self.owner),
            (None, Some(device)) => format!("{}\0device\0{device}", self.owner),
            (None, None) => self.owner.clone(),
        }
    }
}
/// Bound policy work and reject ambiguous or accidentally broad permissions.
pub fn validate(grants: &[ObjectGrant]) -> Result<()> {
    if grants.len() > 256 {
        bail!("at most 256 object grants are permitted per certificate");
    }
    let mut objects = HashSet::new();
    for grant in grants {
        if grant.owner.is_empty()
            || grant.owner.len() > 128
            || grant.owner.contains('\0')
            || grant.identifier.is_empty()
            || grant.identifier.len() > 1024
            || grant.operations.is_empty()
            || grant.operations.len() > 4
            || grant
                .operations
                .iter()
                .any(|op| ![8, 10, 11, 12].contains(op))
            || grant.operations.iter().collect::<HashSet<_>>().len() != grant.operations.len()
            || (grant.user.is_some() && grant.device.is_some())
            || [&grant.user, &grant.device]
                .into_iter()
                .flatten()
                .any(|name| name.is_empty() || name.len() > 128 || name.contains('\0'))
            || !objects.insert((grant.object_owner(), &grant.identifier))
        {
            bail!("invalid or duplicate object read grant");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grants_require_bounded_exact_objects_and_supported_distinct_permissions() {
        let valid = ObjectGrant {
            owner: "alice".into(),
            user: None,
            device: None,
            identifier: "tenant:雪:key".into(),
            operations: vec![8, 10, 11, 12],
        };
        validate(std::slice::from_ref(&valid)).unwrap();
        for operations in [vec![], vec![1], vec![13], vec![31], vec![10, 10]] {
            let mut invalid = valid.clone();
            invalid.operations = operations;
            assert!(validate(&[invalid]).is_err());
        }
        assert!(validate(&[valid.clone(), valid.clone()]).is_err());
        for (owner, identifier) in [
            ("".into(), "id".into()),
            ("alice".into(), "".into()),
            ("x".repeat(129), "id".into()),
            ("alice".into(), "x".repeat(1025)),
        ] {
            let mut invalid = valid.clone();
            invalid.owner = owner;
            invalid.identifier = identifier;
            assert!(validate(&[invalid]).is_err());
        }
        let mut fred = valid.clone();
        fred.user = Some("Fred".into());
        assert_eq!(fred.object_owner(), "alice\0user\0Fred");
        validate(&[valid.clone(), fred.clone()]).unwrap();
        let mut both = fred.clone();
        both.device = Some("meter".into());
        assert!(validate(&[both]).is_err());
        for name in ["", "a\0b"] {
            let mut invalid = fred.clone();
            invalid.user = Some(name.into());
            assert!(validate(&[invalid]).is_err());
        }
        assert!(validate(&vec![valid; 257]).is_err());
        assert!(
            serde_json::from_str::<ObjectGrant>(
                r#"{"owner":"alice","identifier":"id","operations":[10],"wildcard":true}"#
            )
            .is_err()
        );
    }
}
