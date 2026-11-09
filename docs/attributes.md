<!--
Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Attributes

Part of the [feature reference](README.md#feature-reference).

How the server stores, returns and changes object attributes. Which
attributes a new key carries in each edition is in the
[support matrix](support-matrix.md#attributes-the-server-reports-on-a-new-key).

- [Reading attributes](#reading-attributes)
- [Changing attributes](#changing-attributes), [Adjust Attribute](#adjust-attribute)
- [Custom and vendor attributes](#custom-and-vendor-attributes)
- [Names](#names), [Alternative Name](#alternative-name)
- [Server-maintained metadata](#server-maintained-metadata)
- [Identifiers and batch references](#identifiers-and-batch-references), [Links](#links)
- [Protection Level, Protection Period and Quantum Safe](#protection-level-protection-period-and-quantum-safe)

## Reading attributes

- Get Attributes returns every instance of each requested attribute; Get
  Attribute List names each attribute once.
- An attribute that a newer edition introduced is left out of responses in
  older editions; it is not deleted. Requests in an older edition cannot set
  it.
- If none of the requested attributes exist, 1.x returns the identifier alone;
  2.x and 3.0 follow `--get-attributes-none`
  ([interpretations](interpretations.md#get-attributes-when-none-of-the-requested-attributes-exist)).
- Naming the same attribute twice is Invalid Message in 1.1–1.4 and Invalid
  Field from 2.0; 1.0 answers it.

## Changing attributes

| Operation | Editions | Behaviour |
| --- | --- | --- |
| Add Attribute | all | Adds an instance. In 1.x the server assigns the index (the lowest free one); a client index is refused. |
| Modify Attribute | all | 1.x: selects by index, 0 when omitted. 2.x/3.0: selects by Current Attribute value; omitting it when there are several instances fails. |
| Delete Attribute | all | 1.x: by index. 2.x/3.0: Current Attribute removes one instance, an Attribute Reference removes all instances. |
| Set Attribute | 2.0+ | Adds or replaces the single instance; ambiguous when several exist. |
| Adjust Attribute | 2.0+ | See [below](#adjust-attribute). |

- 1.x indices are stable: deleting one instance never renumbers the others.
- Multi-instance attributes: Name, Object Group, Application Specific
  Information, Cryptographic Parameters, Alternative Name, Digest, links and
  custom attributes. Others are single-valued.
- Attributes of a destroyed object cannot be changed.
- Sensitive and Extractable can be changed in both directions in the final
  editions; in the 3.0 draft only towards stricter (Sensitive to True,
  Extractable to False).
- Limits per object: 1,024 attribute instances and 256 KiB of encoded
  attributes, including server metadata. A change beyond them fails and
  changes nothing.

Only these attributes can be added, modified, deleted or set by a client;
every other one (server-set dates, State, Digest, Unique Identifier, Lease
Time, Fresh and similar) is read-only, and a change is refused with Permission
Denied in 1.x and Attribute Read Only or Read Only Attribute from 2.0:

| Attribute | Limits |
| --- | --- |
| Name, Object Group, Application Specific Information, Contact Information, Cryptographic Parameters, Link | none beyond the operation's rules |
| Custom attributes | not the server's own (`y-`) |
| Alternative Name | 1.2+ |
| Description, Comment | 1.4+ |
| Usage Limits | until the first use is charged |
| Sensitive, Extractable | 1.4+; not deleted; draft 3.0: only towards stricter |
| Original Creation Date, Random Number Generator | added once (Add or Set Attribute), on a registered or imported object |
| Activation, Deactivation, Process Start and Protect Stop Date | not deleted; only in the states and before the dates [listed in lifecycle](lifecycle.md#states-and-dates) |
| Key Value Location | 1.2+; objects registered without a Key Value |
| Protection Level, Protection Period, Quantum Safe | 2.0+ |
| Group Link, Certificate Request Link | draft 3.0 |

### Example: set and read an attribute

With the [quick-start server](quick-start.md) and the
[HTTPS shell functions](clients/https.md) loaded:
[`set-attribute.json`](../examples/https/set-attribute.json) sets Contact
Information with Set Attribute (KMIP 2.0 and later; in 1.x use Add or Modify
Attribute), and [`get-attributes.json`](../examples/https/get-attributes.json)
reads it back with the key's State:

```bash
ID=$(kmip create.json | field UniqueIdentifier)
kmip set-attribute.json ID="$ID" CONTACT="orders team" | field ResultStatus
R=$(kmip get-attributes.json ID="$ID")
field ContactInformation <<<"$R"; field State <<<"$R"
```

```text
Success
orders team
PreActive
```

The Get Attributes payload names each attribute by an Attribute Reference:

```json
{"tag": "RequestPayload", "value": [
  {"tag": "UniqueIdentifier", "type": "TextString", "value": "$ID"},
  {"tag": "AttributeReference", "type": "Enumeration", "value": "ContactInformation"},
  {"tag": "AttributeReference", "type": "Enumeration", "value": "State"}]}
```

## Adjust Attribute

KMIP 2.0 and later. Increment, Decrement or Negate one attribute with checked
arithmetic:

- Increment and Decrement work on Integer, Long Integer, Big Integer,
  Interval, Date-Time and Date-Time Extended values. The default amount is
  one (one second, one microsecond). Negate works on signed numbers and
  Booleans.
- A missing vendor attribute starts at zero (or False) when the amount tells
  the server its type. More than one instance is Multi Valued Attribute.
- Overflow is refused before anything changes. Read-only attributes, usage
  masks and server-owned `y-` values cannot be adjusted. Date rules are those
  of [lifecycle](lifecycle.md#states-and-dates).

## Custom and vendor attributes

- 1.x custom attributes `x-name` map to 2.x vendor attributes with Vendor
  Identification `x` and the same name, so the same object reads the same way
  in either edition. Their values keep their TTLV type; flat structures are
  allowed, nested ones are not.
- `y-` attributes (vendor `y`) are reserved for the server. Clients can read
  them but not create, change or delete them. This server sets none.
- A 2.x vendor attribute with another Vendor Identification has no 1.x name
  and cannot be requested through 1.x.

## Names

Examples of creating a key with a Name and finding it again:
[HTTPS JSON](clients/https.md#locate-by-name),
[Go](clients/go.md#find-a-key-by-name),
[Python](clients/python.md#common-tasks), [Java](clients/java.md#binary-kmip).

- Names are unique per owner, not server-wide
  ([name uniqueness](interpretations.md#name-uniqueness)). Concurrent requests for the
  same Name create one object and refuse the rest.
- Whether a destroyed object still holds its Name is `--destroyed-name-reuse`
  ([interpretations](interpretations.md#names-held-only-by-destroyed-objects)).
- Re-key moves Names to the replacement.
- A duplicate Name fails with Non Unique Name Attribute from 2.0 and with the
  operation's error reason in 1.x ([below](#duplicate-names-in-kmip-1x)).

### Duplicate names in KMIP 1.x

KMIP 1.x has no Non Unique Name reason; it arrives in 2.0 (Non Unique Name
Attribute, from every operation). In 1.x, each operation's error table gives
its own reason for a Name another object of the owner already holds:

| Operation | 1.x reason |
| --- | --- |
| Create, Create Key Pair, Register, Derive Key, Create and Join Split Key, Import, Re-key, Re-key Key Pair, Certify, Re-certify | Invalid Field |
| Add Attribute, Modify Attribute | Illegal Operation |

A client that renames or moves a Name with Add or Modify Attribute in 1.x must
expect Illegal Operation, not Invalid Field.

## Alternative Name

KMIP 1.2 and later, on every object type. A structure of Alternative Name
Value (text, at most 4,096 bytes, stored exactly as sent) followed by
Alternative Name Type (any of the seven standard types). Alternative Names
need not be unique and may repeat. Locate matches the value, the type, both,
or presence ([Locate](locate.md)). They are not used for Name Reference
resolution.

Description (1.4+) and Comment (1.4+) are single-valued client text
attributes; Contact Information is available in every edition.

## Server-maintained metadata

| Attribute | Editions | Behaviour |
| --- | --- | --- |
| Fresh | 1.1+ (every object type from 2.0) | True until the material is first served by Get (plain or wrapped). Get Attributes does not change it; a 2.x Export does not either. |
| Original Creation Date | 1.2+ | Server objects: equal to their Initial Date. Registered objects: may be supplied once, at Register or by a later Add Attribute. |
| Random Number Generator | 1.3+ | RNG Algorithm Unspecified for server-generated material; registered values are kept. |
| Sensitive, Extractable | 1.4+ | Default False and True. Sensitive blocks plaintext Get but allows wrapped Get; non-extractable blocks both. |
| Always Sensitive, Never Extractable | 1.4+ | Server-owned history; once False, never True again for that object. |
| Digest | all | SHA-256 of the stored material, plus the standard default format when different. Absent for objects without material. |
| Key Format Type | 2.0+ | The stored format. |
| Short Unique Identifier | 2.0+ | SHA-256 of the identifier; unique across the server. |
| Protection Storage Mask | 2.0+ | Software ([key transfer](key-transfer.md#protection-storage)). |
| Object Class | 3.0 draft | Set by the server. |

Material returned in an Operation Undone payload still counts as served: Fresh
and the extraction histories stay False after the rollback.

## Identifiers and batch references

- Unique Identifiers are text in 1.x–2.1 and the Identifier type in the 3.0
  draft. Identifiers and material are the same in every version.
- The **ID Placeholder** carries the identifier of the previous item's result
  (Create, Register, a single-result Locate and others) to the next item.
- From 2.0, a Unique Identifier can also be an integer index into earlier
  results of the batch (negative counts back) or an enumeration naming an
  earlier operation's result. A reference that resolves to several
  identifiers (for example a Locate result) runs the operation once per
  target, as separate batch items; at most 128 targets and 1 MiB of payload
  per expansion. References do not survive the request.
- In the 3.0 draft, Reference and Name Reference identify objects by
  identifier or by Name; a Name Reference resolves among the caller's objects
  first, then granted ones. Link targets given as Name Reference need not
  exist yet.

## Links

Link (1.x–2.x) and the 3.0 typed link attributes are mapped onto each other,
so a link set through one edition reads correctly through another.
Single-valued draft link types refuse a second instance. The server sets
replacement, public/private key, certificate, derivation, wrapping-key and
Certificate Request links; clients may set others. Locate matches a whole
Link (type and target); a partial Link filter or an unknown Link Type is
Invalid Field.

## Protection Level, Protection Period and Quantum Safe

KMIP 2.0 and later, single-valued, set and changed by the client and
filterable in Locate.

- Protection Level must be High or Low.
- Quantum Safe True is accepted only on objects judged quantum safe: 256-bit
  AES, ChaCha20 and ChaCha20-Poly1305 keys and, in the 3.0 draft, NIST
  Security Category 5 post-quantum keys (ML-KEM-1024, ML-DSA-87 and the 256-bit
  SLH-DSA sets). RSA, DSA, DH and EC keys never qualify. Any operation that
  would leave a non-qualifying object marked True fails with General Failure
  ([Quantum Safe reason](interpretations.md#result-reasons)).
