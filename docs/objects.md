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

# Object types

Part of the [feature reference](README.md#feature-reference).

Which managed object types the server stores and which operations create
them, then the rules common to all objects and the types that have no page
of their own.

| Object type | Editions | Created by | Reference |
| --- | --- | --- | --- |
| Symmetric Key | all | Create, Register, Re-key, Derive Key, Join Split Key | [algorithms](algorithms.md#symmetric-keys) |
| Public Key, Private Key | all | Create Key Pair, Register, Re-key Key Pair | [algorithms](algorithms.md) |
| Certificate | all | Register, Certify, Re-certify | [certificates](certificates.md) |
| Certificate Request | 2.0+ | Register | [certificates](certificates.md#certificate-requests) |
| Secret Data | all | Register, Derive Key, Encapsulate | [below](#secret-data) |
| Opaque Object | all | Register | [below](#opaque-objects) |
| PGP Key | 1.2+ | Register | [below](#pgp-keys) |
| Split Key | all (Create/Join from 1.2) | Register, Create Split Key | [below](#split-keys) |
| Template | 1.0–1.4 | Register | [below](#templates-kmip-1x) |
| User, Group, credentials | 3.0 draft | Create User, Create Group, Create Credential | [KMIP 3.0](kmip-3.0.md#system-objects) |

Which operations each edition offers: [support matrix](support-matrix.md).

## Common rules

- Key material and object values are at most 65,536 bytes.
- Every object belongs to the principal that created it, or, with
  `"client_identity": "credential"`, to the verified user or device that
  created it ([authorization](authorization.md)).
- Omitted attributes take the defaults that Query Defaults Information
  reports ([Query](messages.md#query)): for example AES for Create, RSA for
  Create Key Pair, and a usage mask of 0, which permits no cryptographic use.
  Set the Cryptographic Usage Mask you need.
- Register validates the material against the declared algorithm, length and
  format; declared values that contradict the material are refused.
- In KMIP 1.0–1.4 Create Key Pair needs Cryptographic Algorithm and
  Cryptographic Usage Mask in the request (Invalid Message otherwise).

## Secret Data

Secret Data Type Password (1) or Seed (2). Register keeps the type; Derive Key
and Encapsulate produce Seed. Get returns Raw or Opaque format, and a Secret
Data Key Block carries no Cryptographic Algorithm or Length.

## Opaque objects

Opaque Data Type may be any value from `0x80000000` to `0x8FFFFFFF`; the
value bytes may be empty. The type is kept exactly, is read-only, and from
2.0 is also an attribute that Locate can match. The server never interprets
opaque content.

## PGP keys

KMIP 1.2 and later. The object holds PGP Key Version 3 or 4 and a Key Block
in Raw or Opaque format, kept byte for byte. Register and Import need a usage
mask and at least one Digital Signature Algorithm value; Cryptographic
Algorithm and Length must come from the Key Block or the attributes, and must
agree. The server does not verify PGP signatures, identities or passphrases,
and performs no PGP cryptography; PGP-aware clients do that.

## Templates (KMIP 1.x)

Templates (Object Type 6) exist in KMIP 1.0–1.4; 2.0 removed them.

- Register a Template holding at least one attribute, and give the
  template its own Name. In 1.2–1.4 a Name inside the template content is
  Invalid Field; in 1.0/1.1 it names the template itself.
- To use a template, name it in a Template-Attribute (Create, Create Key
  Pair, Register, Re-key, Re-key Key Pair, Derive Key, Certify, Re-certify,
  Create and Join Split Key). Request values override template values, a later
  template overrides an earlier one, and multi-instance values are merged.
  Only the caller's own templates resolve; a missing one is Item Not Found, an
  archived one Object Archived.
- Get, Get Attributes, attribute changes, Locate, Archive, Recover and
  Destroy apply to templates. Activate, Revoke, Re-key, Check, leases and
  cryptography are Illegal Operation.
- Templates are invisible to 2.x and 3.0 requests.

## Split keys

Create Split Key and Join Split Key (KMIP 1.2 and later) split a key or
secret into parts and rebuild it. Split Key objects themselves can be
registered, retrieved, wrapped, archived and transferred in every edition.

| Item | Support |
| --- | --- |
| Methods | XOR (threshold equals parts), polynomial sharing over GF(2^16), polynomial sharing over a prime field, and GF(2^8) from 1.2 |
| Sources | An existing object (symmetric key, secret data, opaque object, RSA or EC key, certificate) or newly generated key material |
| Parts | Each part is a new Split Key object in Raw or Opaque format with its own usage limits and history |
| Join | Takes at least the threshold of parts and checks every extra part for consistency. Fewer parts are Cryptographic Failure in 1.2–1.4 and Invalid Field from 2.0. |
| Limits | Per request: 128 parts, 65,536 secret bytes, 4 MiB of share data, 32,768-bit primes. Per batch: four factory runs and 128 new objects (below). |

- Beyond a per-request limit the answer is Response Too Large in 1.x; beyond
  a per-batch limit it is General Failure in 1.x
  ([batch limits](messages.md#batches)). Both are Server Limit Exceeded from
  2.0.
- In the final editions GF(2^8) uses polynomial 285; the 3.0 draft names the
  polynomial (283 or 285) explicitly
  ([interpretations](interpretations.md#split-key-gf28-polynomial)).
- A key rebuilt from parts is a new object: it gets its own usage limits and
  Fresh value, and it keeps the strictest Sensitive and Extractable setting of
  its parts.
- Parts made by this server carry private provenance (original length and
  format) that makes reconstruction exact. Parts registered from outside do
  not; joining external GF(2^16) or prime-field opaque shares therefore fails
  with Missing Data, and external Secret Data or symmetric shares need a
  declared length.
- Splitting is not authenticated secret sharing: an exact quorum of external
  parts is accepted without proof of where it came from.

## Objects without key material

From KMIP 1.2, a Key Block may omit its Key Value at Register (Symmetric Keys,
Private Keys and Secret Data; Public Keys too from 2.0). The object is stored
without material, gets Key Value Present False and no Digest, and may carry
Key Value Location attributes (a text or URI pointing elsewhere). The Key
Block must still give the format and, for keys, algorithm and length. Every
operation that needs the material fails with Key Value Not Present (0x13).
Split Keys and PGP Keys without material are not supported.

## Operation Policy Name (KMIP 1.x)

In 1.0–1.4 every object except a Template reports Operation Policy Name
`default`, the only policy. Requests may name `default`; any other name is
Invalid Field, and the attribute cannot be changed. The authorization it
stands for is the server's normal model ([authorization](authorization.md)),
which is stricter than the published table for public objects: certificates
and public keys are visible to their owner only, unless granted.
