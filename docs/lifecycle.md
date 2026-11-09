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

# Object lifecycle

Part of the [feature reference](README.md#feature-reference).

States, dates, usage limits and leases for managed objects.

- [States and dates](#states-and-dates), [refusals by state](#refusals-by-state)
- [Activate](#activate), [Revoke](#revoke), [Destroy](#destroy)
- [Archive and Recover](#archive-and-recover)
- [Usage limits](#usage-limits), [Check](#check), [Leases](#leases)
- [Usage masks](#usage-masks)

## States and dates

Objects follow the KMIP state machine: Pre-Active, Active, Deactivated,
Compromised, Destroyed and Destroyed Compromised. A state change happens when
an operation asks for it or when a date attribute is reached; the server
applies elapsed dates before it authorizes any use of the object.

| Date | Can be changed by the client |
| --- | --- |
| Activation Date | only while Pre-Active |
| Deactivation Date | while Pre-Active or Active |
| Process Start Date, Protect Stop Date | while Pre-Active or Active, and only before the current date is reached |

- A change outside these windows by Add, Modify, Set or Adjust Attribute
  fails: Permission Denied in 1.x and 2.0, Wrong Key Lifecycle State (0x43)
  from 2.1.
- A client can never delete these dates.
- All dates of an object are checked together. For example, a Process Start
  Date may not precede the Activation Date.
- Setting a date can move the object to a new state at once.

The two usage dates limit different operations:

- From the Protect Stop Date on, a key no longer applies protection:
  Encrypt, Sign, MAC, wrapping another key, Certify and Derive Key are
  refused.
- Before the Process Start Date, it does not yet process protected data:
  Decrypt, Signature Verify, MAC Verify and unwrapping are refused.

The refusal is Permission Denied through 2.0 and Wrong Key
Lifecycle State from 2.1 ([date window](interpretations.md#result-reasons)).

In KMIP 1.0 only, an Activation Date in the past at creation is replaced by
the time the request arrived (the 1.0 rule); later versions keep the
client's value.

## Refusals by state

The Result Reason an operation gets when the object's state forbids it:

| Operation | 2.1 and draft 3.0 | 2.0 | 1.x |
| --- | --- | --- | --- |
| Activate of an object not Pre-Active | Wrong Key Lifecycle State | Wrong Key Lifecycle State | Permission Denied |
| Revoke not permitted in the state (for example a repeated non-compromise Revoke) | Wrong Key Lifecycle State | Wrong Key Lifecycle State | Permission Denied |
| Draft 3.0 Deactivate of an object not Active | Wrong Key Lifecycle State | n/a | n/a |
| Destroy of an Active object | Wrong Key Lifecycle State | Permission Denied | Permission Denied |
| Encrypt, Sign, MAC, wrapping or Derive Key with a key not Active; Decrypt or verification with a Pre-Active key | Wrong Key Lifecycle State | Wrong Key Lifecycle State | Permission Denied (Derive Key: Invalid Field) |
| Add, Modify, Delete or Set Attribute on a Destroyed object | Wrong Key Lifecycle State | Permission Denied | Permission Denied |
| Obtain Lease refused by state | Permission Denied | Permission Denied | Permission Denied |

A Destroyed key has no Key Value, so cryptographic use of it fails with Key
Value Not Present before the state is checked. Permission Denied in 1.x (and
for Obtain Lease everywhere) also means "not authorized": read the Result
Message to tell the two apart.

## Activate

Moves a Pre-Active object to Active. Activating an object in any other state
fails with Permission Denied in 1.x and Wrong Key Lifecycle State from 2.0.
Templates cannot be activated.

## Revoke

Final editions (1.x–2.1) require a Revocation Reason. Whether a Revoke
compromises the object depends on the reason and the edition:

| Reason | 1.0–1.2 | 1.3–2.1 | Draft 3.0 |
| --- | --- | --- | --- |
| Key Compromise | compromises | compromises | compromises |
| CA Compromise | deactivates | compromises | compromises |
| any other reason | deactivates | deactivates | compromises |

In draft 3.0 an omitted reason means Unspecified, and Deactivate (64) is a
separate operation: it takes a Unique Identifier (or the ID Placeholder),
moves an Active object to Deactivated, sets its Deactivation Date to the
current time and returns the identifier. Deactivate of an object in any other
state is Wrong Key Lifecycle State.

- A compromising Revoke moves a Pre-Active, Active or
  Deactivated object to Compromised, and a Destroyed one to Destroyed
  Compromised. A deactivating Revoke works only on an Active object. Every
  other case, including a repeated Revoke of a Compromised object and a
  deactivating Revoke of a Pre-Active or Deactivated object, is refused:
  Permission Denied in 1.x, Wrong Key Lifecycle State from 2.0.
- Compromise Occurrence Date is required with Key Compromise in 1.0–1.2
  (Missing Data otherwise); from 1.3 optional, defaulting to the object's
  Initial Date. Supplying one with a deactivating reason, or one in the
  future, is Invalid Field.

## Destroy

Destroy erases key material and keeps the object's metadata and attributes.
An Active object must be deactivated or revoked first (Permission Denied
through 2.0, Wrong Key Lifecycle State from 2.1).

- Get of a destroyed object fails with Illegal Operation in 1.x and Object
  Destroyed (0x36) from 2.0
  ([Get of a destroyed object](interpretations.md#result-reasons)). Export still
  returns its metadata without material.
- On-line Locate skips destroyed objects. In 1.x, a Locate that selects the
  Destroyed or Destroyed Compromised state or a Destroy Date still finds them;
  from 2.0 the Destroyed storage bit selects them ([Locate](locate.md#storage-status)).
- Whether a destroyed object still holds its Name is the
  `--destroyed-name-reuse` setting
  ([names](interpretations.md#names-held-only-by-destroyed-objects)).
- Older copies of the material remain in backups until those are disposed of.
- The 3.0 draft adds Obliterate, which removes the record entirely
  ([KMIP 3.0](kmip-3.0.md#obliterate)).

## Archive and Recover

Archive marks an object as archived by setting its Archive Date; nothing
moves to another storage tier, and material, state and usage are unchanged.

- An archived object cannot be read or used (Get, Export, Get Attributes,
  attribute changes, lifecycle operations, leases, cryptography) until it is
  recovered: Object Archived, or Wrapping Object Archived (0x40) from 2.0 for
  a wrapping key.
- Archiving an archived object fails with Object Archived. Recovering an
  object that is not archived succeeds and changes nothing.
- Recover removes the Archive Date. The Archive Date is read-only except
  through Import.
- Archived Names stay reserved. Locate finds archived objects only with the
  Archival storage bit.

Database clients rarely need Archive or Recover; leave them out of their
policy unless the integration requires them.

## Usage limits

The Usage Limits attribute (Total, Count, Unit Byte or Object) caps how much
protection a key may apply.

- New objects start with Count equal to Total; a client-supplied Count is
  ignored. Defaults are the largest Long Integer and Unit Object.
- Charged: Encrypt, Sign and MAC (by input bytes, or one use per request),
  wrapped Get and Export (the wrapping key, by the plaintext length or once),
  Derive Key (each source, by output bytes or once), Certify and Re-certify
  (the CA private key), Encapsulate and Decapsulate. Decrypt and all
  verification are never charged.
- A request that would exceed the remaining budget fails; a failed request
  is not charged.
- Get Usage Allocation reserves part of the budget for use outside the
  server, for example by a client that holds the unwrapped key.
- Once anything has been charged, even a zero allocation, Usage Limits can no
  longer be changed. Re-key gives the replacement a fresh budget.

The server cannot count uses of key material a client has already exported.
Keys without Usage Limits have no limit.

## Check

Check tests a usage-mask, usage-limit count and lease request together
without charging anything. A policy denial returns the attributes that
caused it ([failed Check](interpretations.md#payload-of-a-failed-check)) and clears
the ID Placeholder, even under Continue.

## Leases

New objects store the server's maximum Lease Time, `--max-lease-seconds`
(default 3600; `0` means no limit). The value is fixed per object at
creation, so changing the setting affects new objects only. Obtain Lease
returns a lease and the object's Last Change Date.

`--lease-states` (`KMIP_LEASE_STATES`) sets which objects get a lease:

| Value | Leased | Refused |
| --- | --- | --- |
| `active-deactivated` (default) | Active, Deactivated | Pre-Active, Compromised, Destroyed, Destroyed Compromised |
| `active` | Active | every other state |

A Deactivated key may still decrypt and verify, so a client that honours
leases can keep reading data under a rotated key. A lease never permits
encryption, signing, MAC or wrapping with a Deactivated key; the client must
still respect State and the usage dates.

The grant is the stored Lease Time, shortened so it never
outlasts the next point where use narrows:

- Active object: its next Protect Stop Date or Deactivation Date, whichever
  comes first. With `active-deactivated` a passed Protect Stop Date does not
  refuse the lease; with `active` it does.
- Deactivated object: the stored Lease Time alone. Destroy and compromise
  take effect at the client's next renewal.
- An object that may not be used yet (Deactivated before its Process Start
  Date) is refused.

Lease Time 0 means no lease limit: the client may use the object without
renewing ([client notes](clients.md#leases-and-lease-time-0)). A pending
Deactivation or Protect Stop Date still bounds an Active object's lease.

A refused lease is Permission Denied in every edition, with a stable message:

| Cause | Result Message |
| --- | --- |
| Pre-Active | `A Pre-Active object cannot receive a lease` |
| Deactivated with `--lease-states active` | `A Deactivated object cannot receive a lease (server lease policy: Active objects only)` |
| Compromised | `A Compromised object cannot receive a lease` |
| Destroyed or Destroyed Compromised | `A Destroyed object cannot receive a lease` |
| Deactivated before its Process Start Date | `The object cannot be used before its Process Start Date` |
| `active` only: Deactivation Date passed | `The object's Deactivation Date has passed` |
| `active` only: Protect Stop Date passed | `The object's Protect Stop Date has passed` |

Check with a Lease Time applies the same rules. Choosing a Lease Time for KMS
outages: [operations](operations.md#lease-time-and-kms-outages).

## Usage masks

Every cryptographic use checks the object's Cryptographic Usage Mask: Encrypt
needs the Encrypt bit, wrapping needs Wrap Key, derivation needs Derive Key,
and so on. Objects created without a mask get 0, which permits nothing.

| Bit (JSON and XML name) | Value | Versions | What needs it here |
| --- | --- | --- | --- |
| `Sign` | `0x00000001` | all | Sign |
| `Verify` | `0x00000002` | all | Signature Verify |
| `Encrypt` | `0x00000004` | all | Encrypt; Encapsulate (or Wrap Key or Key Agreement) |
| `Decrypt` | `0x00000008` | all | Decrypt; Decapsulate (or Unwrap Key or Key Agreement) |
| `WrapKey` | `0x00000010` | all | the wrapping key of a wrapped Get or Export |
| `UnwrapKey` | `0x00000020` | all | the key that unwraps Register or Import input |
| `Export` | `0x00000040` | 1.x only | none |
| `MACGenerate` | `0x00000080` | all | MAC |
| `MACVerify` | `0x00000100` | all | MAC Verify |
| `DeriveKey` | `0x00000200` | all | the base key of Derive Key |
| `ContentCommitmentNonRepudiation` | `0x00000400` | 1.x only | none |
| `KeyAgreement` | `0x00000800` | all | Encapsulate and Decapsulate (3.0 draft) |
| `CertificateSign` | `0x00001000` | all | the issuer's private key in Certify |
| `CRLSign` | `0x00002000` | all | none |
| `GenerateCryptogram` | `0x00004000` | 1.x only | none |
| `ValidateCryptogram` | `0x00008000` | 1.x only | none |
| `TranslateEncrypt` | `0x00010000` | 1.x only | none |
| `TranslateDecrypt` | `0x00020000` | 1.x only | none |
| `TranslateWrap` | `0x00040000` | 1.x only | none |
| `TranslateUnwrap` | `0x00080000` | 1.x only | none |
| `Authenticate` | `0x00100000` | 2.0 and later | none |
| `Unrestricted` | `0x00200000` | 2.0 and later | permits every use (below) |
| `FPEEncrypt` | `0x00400000` | 2.0 and later | none |
| `FPEDecrypt` | `0x00800000` | 2.0 and later | none |

In JSON and XML a mask can be written as names joined by `|` (JSON) or spaces
(XML), as in the [request examples](../examples/https/create.json). Bits that
no operation needs are stored, returned and matched by Locate and Check. In
2.x `0x00080000` is reserved.

From 2.0, the Unrestricted bit (`0x00200000`) permits every use the object's
type and algorithm allow. It does not override ownership, state, dates,
extraction settings, key roles (a public key still cannot decrypt) or a
certificate's Key Usage extension. In 1.x the same bit has no meaning.
