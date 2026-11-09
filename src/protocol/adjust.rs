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

//! KMIP 2.0+ scalar Adjust Attribute, with checked arithmetic and normal mutation policy.
use super::*;
use openssl::bn::{BigNum, BigNumRef};

const MAX_BIG_INTEGER_BYTES: usize = 65_536;
fn data_type() -> Failure {
    fail(0x1c, "Invalid adjustment data type")
}
fn range() -> Failure {
    fail(0x1b, "Adjustment exceeds the numeric range")
}
fn read_only() -> Failure {
    fail(0x1d, "Attribute is read-only")
}

fn signed(bytes: &[u8]) -> R<BigNum> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(8) {
        return Err(data_type());
    }
    if bytes.len() > MAX_BIG_INTEGER_BYTES {
        return Err(fail(2, "Adjustment Big Integer exceeds resource limit"));
    }
    let negative = bytes[0] & 0x80 != 0;
    let mut magnitude = bytes.to_vec();
    if negative {
        let mut carry = true;
        for byte in magnitude.iter_mut().rev() {
            *byte = !*byte;
            if carry {
                let (next, overflow) = byte.overflowing_add(1);
                *byte = next;
                carry = overflow;
            }
        }
    }
    let mut number = BigNum::from_slice(&magnitude).map_err(|_| data_type())?;
    let sign = negative && number.num_bits() != 0;
    number.set_negative(sign);
    magnitude.zeroize();
    Ok(number)
}
fn integer(value: &Value) -> R<BigNum> {
    match value {
        Value::Integer(n) => BigNum::from_dec_str(&n.to_string()).map_err(|_| data_type()),
        Value::LongInteger(n) => BigNum::from_dec_str(&n.to_string()).map_err(|_| data_type()),
        Value::Interval(n) => BigNum::from_dec_str(&n.to_string()).map_err(|_| data_type()),
        Value::BigInteger(bytes) => signed(bytes),
        _ => Err(data_type()),
    }
}
fn encoded(number: &BigNumRef) -> R<Vec<u8>> {
    // Reserve the sign bit, then sign-extend to the TTLV 8-byte block size.
    let negative_power_of_two = number.is_negative()
        && number
            .to_vec()
            .iter()
            .map(|byte| byte.count_ones())
            .sum::<u32>()
            == 1;
    let sign_bits = usize::from(!negative_power_of_two);
    let width = ((number.num_bits() as usize + sign_bits).div_ceil(8))
        .max(1)
        .next_multiple_of(8);
    if width > MAX_BIG_INTEGER_BYTES {
        return Err(fail(2, "Adjusted Big Integer exceeds resource limit"));
    }
    let mut bytes = number.to_vec_padded(width as i32).map_err(|_| range())?;
    if number.is_negative() {
        let mut carry = true;
        for byte in bytes.iter_mut().rev() {
            *byte = !*byte;
            if carry {
                let (next, overflow) = byte.overflowing_add(1);
                *byte = next;
                carry = overflow;
            }
        }
    }
    // An exact negative power of two can use one fewer sign-extension block.
    while bytes.len() > 8 && bytes[..8].iter().all(|b| *b == 0xff) && bytes[8] & 0x80 != 0 {
        bytes.drain(..8);
    }
    Ok(bytes)
}
fn scalar(current: &Value, kind: u32, amount: Option<&Value>) -> R<Value> {
    if let Value::Boolean(value) = current {
        return if kind == 3 {
            Ok(Value::Boolean(!value))
        } else {
            Err(data_type())
        };
    }
    if kind == 3
        && matches!(
            current,
            Value::Interval(_) | Value::DateTime(_) | Value::DateTimeExtended(_)
        )
    {
        return Err(data_type());
    }
    let numeric = match current {
        Value::DateTime(n) | Value::DateTimeExtended(n) => {
            BigNum::from_dec_str(&n.to_string()).map_err(|_| data_type())?
        }
        _ => integer(current)?,
    };
    let mut result = BigNum::new().map_err(|_| range())?;
    match kind {
        1 | 2 => {
            let amount = amount
                .map(integer)
                .transpose()?
                .unwrap_or(BigNum::from_u32(1).map_err(|_| range())?);
            if kind == 1 {
                result.checked_add(&numeric, &amount)
            } else {
                result.checked_sub(&numeric, &amount)
            }
            .map_err(|_| range())?;
        }
        3 => {
            result = numeric;
            let sign = !result.is_negative() && result.num_bits() != 0;
            result.set_negative(sign);
        }
        _ => return Err(fail(7, "Unsupported Adjustment Type")),
    }
    if matches!(current, Value::BigInteger(_)) {
        return Ok(Value::BigInteger(encoded(&result)?));
    }
    if result.num_bits() > 64 {
        return Err(range());
    }
    let number = result
        .to_dec_str()
        .map_err(|_| range())?
        .to_string()
        .parse::<i128>()
        .map_err(|_| range())?;
    Ok(match current {
        Value::Integer(_) => Value::Integer(i32::try_from(number).map_err(|_| range())?),
        Value::LongInteger(_) => Value::LongInteger(i64::try_from(number).map_err(|_| range())?),
        Value::Interval(_) => Value::Interval(u32::try_from(number).map_err(|_| range())?),
        Value::DateTime(_) => Value::DateTime(i64::try_from(number).map_err(|_| range())?),
        Value::DateTimeExtended(_) => {
            Value::DateTimeExtended(i64::try_from(number).map_err(|_| range())?)
        }
        _ => return Err(data_type()),
    })
}
fn initial(tag: u32, amount: Option<&Value>) -> R<Value> {
    match tag {
        SENSITIVE | EXTRACTABLE => Ok(Value::Boolean(false)),
        ACTIVATION_DATE
        | DEACTIVATION_DATE
        | PROCESS_START_DATE
        | PROTECT_STOP_DATE
        | ORIGINAL_CREATION_DATE => Err(data_type()),
        ATTRIBUTE => match amount {
            Some(Value::Integer(_)) => Ok(Value::Integer(0)),
            Some(Value::LongInteger(_)) => Ok(Value::LongInteger(0)),
            Some(Value::BigInteger(_)) => Ok(Value::BigInteger(vec![0; 8])),
            Some(Value::Interval(_)) => Ok(Value::Interval(0)),
            Some(Value::Boolean(_)) => Ok(Value::Boolean(false)),
            _ => Err(data_type()),
        },
        _ => Err(data_type()),
    }
}
impl Engine {
    pub(super) fn adjust_attr(
        &self,
        owner: &str,
        v: Version,
        p: &Node,
        placeholder: &Option<String>,
    ) -> R<Vec<Node>> {
        no_fields(
            p,
            &[
                UNIQUE_IDENTIFIER,
                ATTRIBUTE_REFERENCE,
                ADJUSTMENT_TYPE,
                ADJUSTMENT_VALUE,
            ],
        )?;
        let kind = match p.required(ADJUSTMENT_TYPE)?.value {
            Value::Enumeration(n @ 1..=3) => n,
            _ => return Err(fail(7, "Unsupported Adjustment Type")),
        };
        let reference = AttributeSelector::read(p.required(ATTRIBUTE_REFERENCE)?)?;
        let obj = self.object(owner, p, placeholder)?;
        if obj.state >= 5 {
            return Err(fail(0x43, "Cannot adjust destroyed object attributes"));
        }
        let (key, tag) = match &reference {
            AttributeSelector::Standard(tag) => (format!("s:{tag:06x}"), *tag),
            AttributeSelector::Vendor(vendor, name) => {
                if vendor == "y" {
                    return Err(read_only());
                }
                (
                    attributes::identity(&Node::structure(
                        ATTRIBUTE,
                        vec![
                            Node::text(VENDOR_IDENTIFICATION, vendor),
                            Node::text(ATTRIBUTE_NAME, name),
                            Node::int(ATTRIBUTE_VALUE, 0),
                        ],
                    ))?,
                    ATTRIBUTE,
                )
            }
        };
        // Structural and server-owned metadata cannot acquire scalar semantics.
        if tag != ATTRIBUTE {
            if ![
                NAME,
                OBJECT_GROUP,
                APPLICATION_SPECIFIC_INFORMATION,
                CONTACT_INFORMATION,
                COMMENT,
                DESCRIPTION,
                CRYPTOGRAPHIC_PARAMETERS,
                USAGE_LIMITS,
                LINK,
                RANDOM_NUMBER_GENERATOR,
                SENSITIVE,
                EXTRACTABLE,
                ACTIVATION_DATE,
                DEACTIVATION_DATE,
                PROCESS_START_DATE,
                PROTECT_STOP_DATE,
                ORIGINAL_CREATION_DATE,
            ]
            .contains(&tag)
            {
                if object_attrs(&obj, v).iter().any(|a| a.tag == tag) {
                    return Err(read_only());
                }
                return Err(fail(0x1f, "Unsupported adjustment attribute"));
            }
            if tag == ORIGINAL_CREATION_DATE {
                return Err(read_only());
            }
        }
        let visible = object_attrs(&obj, v);
        let values = visible
            .iter()
            .filter(|a| attributes::identity(a).is_ok_and(|id| id == key))
            .collect::<Vec<_>>();
        if values.len() > 1 {
            return Err(fail(0x1e, "Cannot adjust a multi-valued attribute"));
        }
        let amount = p.get(ADJUSTMENT_VALUE).map(|n| &n.value);
        let current = values
            .first()
            .map(|a| {
                if tag == ATTRIBUTE {
                    a.required(ATTRIBUTE_VALUE).map(|n| n.value.clone())
                } else {
                    Ok(a.value.clone())
                }
            })
            .transpose()?;
        let current = current.map(Ok).unwrap_or_else(|| initial(tag, amount))?;
        let adjusted = scalar(&current, kind, amount)?;
        let value = if let AttributeSelector::Vendor(vendor, name) = reference {
            Node::structure(
                ATTRIBUTE,
                vec![
                    Node::text(VENDOR_IDENTIFICATION, vendor),
                    Node::text(ATTRIBUTE_NAME, name),
                    Node {
                        tag: ATTRIBUTE_VALUE,
                        value: adjusted,
                    },
                ],
            )
        } else {
            Node {
                tag,
                value: adjusted,
            }
        };
        let request = Node::structure(
            REQUEST_PAYLOAD,
            vec![
                Node::text(UNIQUE_IDENTIFIER, &obj.id),
                Node::structure(NEW_ATTRIBUTE, vec![value]),
            ],
        );
        self.modify_attr(owner, v, 49, &request, placeholder)
            .map_err(|error| {
                if error.reason == 0x22 {
                    read_only()
                } else {
                    error
                }
            })
    }
}
