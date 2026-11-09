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

# Messages, batches and Query

Part of the [feature reference](README.md#feature-reference).

How the server handles request messages as a whole: versions, batches,
response size, asynchronous requests and the Query operation.

- [Version negotiation](#version-negotiation)
- [Batches](#batches)
- [Maximum Response Size](#maximum-response-size)
- [Asynchronous requests](#asynchronous-requests)
- [Unknown identifiers](#unknown-identifiers)
- [Query](#query)
- [Ping](#ping), [Log](#log), [PKCS#11](#pkcs11),
  [Interop test mode](#interop-test-mode)

## Version negotiation

The server accepts KMIP 1.0, 1.1, 1.2, 1.3, 1.4, 2.0 and 2.1, and the 3.0
draft only with `--experimental-v3`. Each request is answered in its own
version. Discover Versions (1.1+) returns the supported versions, newest
first, filtered to those the client lists. A client that names no version
gets the full list.

Draft 3.0 messages have no Batch Count, Batch Order Option or Unique Batch
Item ID; the server derives the item count from the message and rejects those
fields in 3.0.

## Batches

- Items run in request order, each in its own savepoint. Batch Order Option
  False lets a server reorder; this server does not.
- **Stop** (default) leaves completed items committed and returns no later
  items. **Continue** returns the failure and processes the rest. **Undo**
  rolls back every earlier item and returns them as Operation Undone with
  their response payloads.
- Every processed item is audited with its final status in the same
  transaction as the changes that remain.
- A message holds at most 128 items. An identifier reference that expands
  into several targets (2.0 and later) counts each target, and the server
  reserves room for later items; an expansion that does not fit fails as one
  item. Per batch, at most four key-pair generations of any algorithm (Create
  Key Pair and Re-key Key Pair together), four derivations and four Split Key factory runs
  producing at most 128 objects are allowed. These capacity refusals are
  General Failure in 1.x and Server Limit Exceeded (0x3A) from 2.0.

### Undo and protection output

Encrypt, Sign, MAC, Derive Key and wrapped Get or Export run normally in Undo
batches. Because an Operation Undone item still returns its payload
(ciphertext, signature, MAC, wrapped key), its usage-limit charge is kept
after the rollback; otherwise a client could repeat a failing Undo batch for
unlimited output. Objects created and then undone in the batch disappear with
their charges. Get Usage Allocation is fully rolled back. An undone Get of a
key created in the same batch still returns that key's value, as the
response rules require. Certify and Re-certify are refused in Undo batches
(Feature Not Supported), because an undone certificate would remain valid.

## Maximum Response Size

The server honours the request's Maximum Response Size in every encoding,
measured as the binary TTLV length of the response, as Profiles sections 5.4
and 5.5 require for JSON and XML. Values above 1 MiB are treated as 1 MiB.
Fixed server limits apply as well: 1 MiB frames for TTLV, 8 MiB HTTPS JSON or
XML bodies, 16,384 nodes and depth 32 per message.

- An item whose success response does not fit, together with the minimal
  results that must follow it, is rolled back and fails with Response Too
  Large. The batch option then applies.
- A failure's Result Message is dropped first if space is short; required
  fields are never dropped.
- If no valid response fits at all, nothing runs: a TTLV connection is closed
  without a reply, and HTTPS answers HTTP 400 with no KMIP body.

A closed connection does not by itself mean the limit was too small: a
restart, an idle close or a network failure after a committed change looks
the same. Raise the limit, and repeat only what is safe to repeat
([retrying after a lost response](client-errors.md#retrying-after-a-lost-response)).

## Asynchronous requests

| Operation | Editions |
| --- | --- |
| Cancel, Poll | 1.0–2.1, draft 3.0 |
| Query Asynchronous Requests, Process | 2.1, draft 3.0 |

- 2.x Mandatory defers every item of the
  batch, each with its own 16-byte Asynchronous Correlation Value. 1.x True
  and 2.x Optional defer only batches that contain Create Key Pair or Re-key
  Key Pair, and only while the queue has room. Prohibited, False or no
  indicator is always synchronous. Mandatory with Poll, Cancel, Process or
  Query Asynchronous Requests is Invalid Field.
- Poll returns Operation Pending until the item has run, then its stored
  result. An item that expanded into several targets returns one Poll item per
  result. An unknown value is Item Not Found (1.x) or Invalid Asynchronous
  Correlation Value (2.x).
- Cancel works only before the batch runs. Afterwards it reports
  Completed or Failed, and Unavailable for an unknown value.
- Process (2.1) runs the batch before replying. Query Asynchronous
  Requests lists requests whose results have not been collected.
- At most 32 batches are queued, 8 per principal; results are kept for 600
  seconds. A full queue makes Mandatory fail with Server Limit Exceeded;
  Optional falls back to synchronous processing. Correlation values belong to
  the submitting identity and protocol version.
- The queue is in memory: a restart drops queued requests
  (Poll then fails as unknown), and each replica has its own queue.

## Unknown identifiers

A request that names an object the caller cannot use (missing, obliterated,
a 1.x Template seen from 2.x, or another owner's without a grant) gets the
same answer in every case, so ownership is never revealed:

| Version | Operation | Result Reason |
| --- | --- | --- |
| 1.0–1.4 | every operation | Item Not Found (1) |
| 2.0, 2.1, 3.0 | Adjust Attribute, Certify, Create Split Key | Item Not Found (1) |
| 2.0, 2.1, 3.0 | every other operation | Object Not Found (0x37) |
| 2.0, 2.1, 3.0 | missing wrapping key in Get, Export, wrapped Register or Import | Wrapping Object Not Found (0x42) |

## Query

| Query Function | Editions | Answer |
| --- | --- | --- |
| Operations (1) | all | The operations with a handler in the request's edition ([support matrix](support-matrix.md)). Notify and Put only for a principal with a configured endpoint; Interop only in test mode; Re-Provision (2.0 and later) only with `--provisioning-ca` ([Re-Provision](re-provision.md)). |
| Objects (2) | all | Object types accepted in that edition. |
| Server Information (3) | all | Vendor Identification `keytend-kmip-server`. |
| Application Namespaces, Extension List, Extension Map (4–6) | all | none |
| Attestation Types (7) | 1.2+ | none |
| Validations, Profiles, Client Registration Methods (9, 10, 12) | 1.3+ | none |
| RNGs (8) | 1.3+ | RNG Algorithm Unspecified |
| Capabilities (11) | 1.3+ | Streaming, Asynchronous, Batch Undo and Batch Continue true; Attestation false |
| Defaults Information (13) | 2.0+ | See below |
| Storage Protection Masks (14) | 2.0+ | Software (1) |

A function asked for in an edition before its own is Feature Not Supported.

Query Defaults Information reports only the defaults the server applies when
a client omits the attribute. Without [server defaults](defaults-and-constraints.md#set-defaults)
the answer is:

| Object type | Defaults |
| --- | --- |
| Symmetric Key | Cryptographic Algorithm AES, Key Format Type Raw, Cryptographic Usage Mask 0 |
| Public Key, Private Key | Cryptographic Algorithm RSA, Cryptographic Usage Mask 0 |
| Secret Data | Cryptographic Usage Mask 0 |
| all of the above, Certificate, Opaque Object | Sensitive False, Extractable True, Lease Time = `--max-lease-seconds`, Protection Storage Mask Software |

Defaults that depend on other attributes are left out: Cryptographic Length
(256 for AES, 2048 for RSA, the curve size for EC), asymmetric key formats and
the EC curve (P-256 when neither curve nor length is given).

Server defaults set with Set Defaults replace the matching entries, in 2.0
requests too. A configured Cryptographic Length is listed with its
algorithm, and a key pair's configured algorithm and length are listed for
both Public Key and Private Key. Entries that the request's edition or the
current configuration does not allow are left out, as they are when an
object is created
([stale entries](defaults-and-constraints.md#stale-entries)).

## Ping

KMIP 2.1 and the 3.0 draft. An empty request payload gets an empty response
payload; a field in the request fails with Feature Not Supported. The
principal's policy must allow operation 59.

## Log

KMIP 2.0 and later. The message (at most 4096 bytes) goes to the server's
structured log under target `kmip::client_log` with the principal, after the
batch commits; control characters are escaped. The audit chain records the
operation but not the text. The principal's policy must allow operation 44.

## PKCS#11

KMIP 2.0 and later. Only C_Initialize, C_GetInfo and C_Finalize are
implemented; every other function returns CKR_FUNCTION_NOT_SUPPORTED. There
are no slots, tokens or sessions, so a client cannot use it as a PKCS#11
bridge. Library
instances live in memory (16 per principal, 15-minute idle expiry).

## Interop test mode

Interop (52) is offered only with `--interop-test-mode`, for running OASIS
test traces; KMIP forbids it on a production server
([Interop](interpretations.md#interop)).
