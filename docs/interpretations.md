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

# Specification interpretations

Part of the [feature reference](README.md#feature-reference).

Where the KMIP specification is ambiguous, contradicts itself or its own test
traces, or leaves a choice to the server, this page records what this server
does and why. Where the choice affects some clients and not others, it is a
setting, and its section gives the default. If a client fails on one of
these choices, change only the setting named in that section.

Most of these settings only change how the server answers. Two of them,
`--ec-curves` and `--triple-des`, also choose which algorithms are offered.
[FIPS mode](fips.md) restricts those two: it requires
`--triple-des disabled` and refuses every curve but the NIST ones.

## Settings

| Setting (environment) | Values | Default | Section |
| --- | --- | --- | --- |
| `--text-encoding` (`KMIP_TEXT_ENCODING`) and 13 element settings | see [response forms](encodings.md#response-forms) | `compatible` | [text encodings](#tag-and-enumeration-names-in-json-responses) |
| `--get-attributes-none` (`KMIP_GET_ATTRIBUTES_NONE`) | `empty-attributes`, `identifier-only` | `empty-attributes` | [below](#get-attributes-when-none-of-the-requested-attributes-exist) |
| `--destroyed-name-reuse` (`KMIP_DESTROYED_NAME_REUSE`) | `allow`, `reserve` | `allow` | [below](#names-held-only-by-destroyed-objects) |
| `--lease-states` (`KMIP_LEASE_STATES`) | `active-deactivated`, `active` | `active-deactivated` | [leases](lifecycle.md#leases) |
| `--idle-timeout` (`KMIP_IDLE_TIMEOUT`) | seconds, 0–604800 | `300` | [below](#idle-timeout) |
| `--ec-curves` (`KMIP_EC_CURVES`) | `extended`, `nist` | `extended` | [below](#supported-elliptic-curves) |
| `--triple-des` (`KMIP_TRIPLE_DES`) | `disabled`, `legacy-decrypt`, `enabled` | `disabled` | [3DES](algorithms.md#3des) |
| `--interop-test-mode` (`KMIP_INTEROP_TEST_MODE`) | flag | off | [Interop](#interop) |

Every value is checked at startup; an unknown value stops the server. The
`KMIP listener ready` log line records the values in effect
([logging](configuration.md#logging)).

## Get Attributes when none of the requested attributes exist

In 2.0, 2.1 and the 3.0 draft the operation text says the response then holds
only the Unique Identifier, while the response table marks Attributes as
required. Both readings are allowed:

- `empty-attributes` (default): the Unique Identifier and an empty Attributes
  structure, as Cosmian KMS answers.
- `identifier-only`: the Unique Identifier alone.

A request that finds at least one attribute, or names none, is answered the
same way under both values. KMIP 1.x always returns the identifier alone.

## Names held only by destroyed objects

A destroyed object keeps its attributes, including its Name. The
specification does not say whether it still holds the Name exclusively.
Clients that re-register a removed key's name (Percona Server for MySQL, for
example) assume it does not. Names are unique per owner
([name uniqueness](#name-uniqueness)).

| | `allow` (default) | `reserve` |
| --- | --- | --- |
| Give a new or renamed object a Name that only destroyed objects of the owner carry | allowed | refused: Non Unique Name Attribute (2.x/3.0), the operation's error reason in 1.x |
| Name held by a live object of the owner | refused | refused |
| On-line Locate by Name | live holder only | nothing while only destroyed holders exist |
| Draft 3.0 Name Reference | the caller's live holder, a granted live holder, then the newest destroyed holder | the caller's holders, destroyed or not, before granted ones |

In `reserve` mode an owner frees a Name by deleting or changing it before
Destroy (Delete or Modify Attribute, or Re-key, which moves it to the
replacement). After Destroy the attributes cannot change; in the 3.0 draft,
Obliterate removes the object. Switching between the values changes nothing
stored.

## Idle timeout

A connection that has waited `--idle-timeout` seconds for its next request is
closed; `0` keeps idle connections open. Every connection holds one of
`--max-connections` (default 64), so a long or disabled timeout lets idle
clients fill the server: size `--max-connections` for your long-lived
clients. Percona Server for MySQL's `component_keyring_kmip` does not
reconnect after the server closes an idle connection (its next keyring write
fails once), so keep the timeout longer than its quiet periods or set `0`.

Other deadlines are [fixed limits](configuration.md#fixed-limits). A
certificate trusted by the client CA but missing from the policy gets 30 s for
its single request. There is no overall connection lifetime.

## Supported elliptic curves

KMIP defines 68 Recommended Curves and lets a server choose which it offers.
This server implements the 13 that the RHEL 9 OpenSSL in the image offers, so
native and container builds answer the same way, and by default lets KMIP
operations use all 13. `--ec-curves nist` limits them to the four NIST
curves, the ones FIPS mode allows. The curve list, the operations each
setting affects and the TLS consequences are in
[elliptic curves](algorithms.md#elliptic-curves).

## Message extensions

The server understands no vendor message extension:

- A Critical extension in any item rejects the whole message before anything
  runs: Feature Not Supported in 1.x, Unknown Message Extension (0x3C) from
  2.0. The response carries the first Critical item's Operation and batch
  item ID.
- A malformed non-Critical extension, or a repeated one in 1.x, fails only its
  item with Invalid Message.
- A well-formed non-Critical extension is ignored.

## Tag and enumeration names in JSON responses

Profiles 2.1 sections 5.4.1 and 5.5.1 allow several forms for tags,
enumerations, masks, Big Integers and dates in JSON and XML. Each element has
its own setting, with presets `--text-encoding compatible|readable|hex`
([response forms](encodings.md#response-forms)). Names come from the
response's own protocol version; anything that edition does not name
(extension tags, vendor values, Reserved slots, messages without a known
version) is written in hex. Requests may use any allowed form.

The default `compatible` writes JSON tags by name and enumerations in hex,
because the Cosmian KMS 5.28 client rejects hex tags and also rejects
correctly normalized enumeration names such as `ObjectNotFound` and
`SHA_256`.

## KMIP 1.x Asynchronous Indicator True

No 1.x edition requires asynchronous handling when a client sets the
indicator. Such a request is answered synchronously unless it contains Create
Key Pair or Re-key Key Pair, which may be deferred
([asynchronous requests](messages.md#asynchronous-requests)).

## Other readings

| Topic | Reading |
| --- | --- |
| Lease end for a Deactivated object | The State text mentions a "Process Stop Date" that no edition defines; it is read as the Protect Stop Date of the same sentence, so a Deactivated object's lease is bounded only by its Lease Time ([leases](lifecycle.md#leases)). |
| Re-key Usage Limits | The 1.0/1.1 tables reset the replacement's count; later tables refer to the existing key's. The replacement starts with a full budget and the source keeps its consumed count ([re-key](rekey.md)). |
| 1.x certificate usage mask | 1.0 section 3.14 and 1.1–1.4 section 3.19 say X.509 Key Usage "SHALL be mapped" to the Usage Mask, but not what happens to a supplied mask that asks for more. The server refuses such a mask with Invalid Field; some servers accept it ([usage mask](certificates.md#usage-mask)). |
| Issued certificate validity | Certify and Re-certify have no validity field. The requested Activation Date and Deactivation Date set notBefore and notAfter, the dates the Re-certify Offset rule already ties to the certificate. A date past the issuing CA's notAfter is Invalid Field rather than cut short ([validity period](certificates.md#validity-period); Re-Provision: [its validity period](re-provision.md#validity-period)). |
| Derive Key sources | The request table requires a source identifier while the parameter text describes data-only HASH and PBKDF2 forms. The server requires managed source objects. |
| Constraints (draft 3.0) | The draft defines the Constraint structure but not how its fields combine; the server's reading is in [constraints](kmip-3.0.md#constraints). |
| Login, tickets and delegation | See [Login and tickets](tickets.md#interpretations). |
| Server defaults and constraints | See [server defaults and constraints](defaults-and-constraints.md#interpretations). |
| Re-Provision | See [Re-Provision](re-provision.md#interpretations). |

## Decisions on result reasons and trace conflicts

Where an edition's tables, its text and the OASIS test traces disagree, the
server follows the rules below.

### Result reasons

| Situation | Result Reason | Why |
| --- | --- | --- |
| Encrypt or Decrypt (AES, 3DES, ChaCha20) without a required IV or nonce | Invalid Message, every version | The traces and Cosmian KMS expect it, rather than Missing Data. |
| Use before the Process Start Date, or protection after the Protect Stop Date ([dates](lifecycle.md#states-and-dates)) | Permission Denied through 2.0; Wrong Key Lifecycle State from 2.1 | Each edition's traces. |
| An unsupported AEAD Tag Length (GCM, ChaCha20-Poly1305) | General Failure, every version | The traces. GCM accepts 4, 8 and 12–16 bytes (default 16); ChaCha20-Poly1305 only 16. |
| ChaCha20-Poly1305 Decrypt with a truncated tag | Invalid Field | RFC 8439 defines a 16-byte tag, and truncation weakens authentication; two 2.x traces that use a 12-byte tag therefore fail. |
| Get of a destroyed object, by a caller allowed to use it | Object Destroyed (0x36) from 2.0; Illegal Operation in 1.x | The 2.x traces (the 2.1 and 3.0 Get error tables omit it); 1.x tables (below). |
| An unknown Unique Identifier (2.x) | Item Not Found for Adjust Attribute, Certify and Create Split Key; else Object Not Found | Each operation's [error table](messages.md#unknown-identifiers). |
| An operation on an archived object | Object Archived, every edition | 23 operation error tables in 2.0 and 2.1 omit it; KMIP 2.1 section 6.1 says those lists are not exhaustive. |
| Quantum Safe requested but cannot be honoured | General Failure | The traces; no table names a reason. |
| A request for an obliterated object (draft 3.0) | Object Not Found | The draft's Obliterate text; its trace expects Item Not Found. |

Another owner's destroyed object fails as missing, and plain Export of a
destroyed object still returns it, without key material.

### ECDSA default hash in KMIP 1.3

In KMIP 1.3 only, ECDSA defaults to SHA-256. Signature Verify on an EC key
ignores a Padding Method and an RSA Cryptographic Algorithm and verifies with
the given hash. 1.4 and later require a hash (Missing Data) and refuse RSA
parameters.

### RNG Seed data

KMIP lets the server ignore the seed and report Data Length 0, which this
server does; client bytes are never mixed into the generator
([RNG Seed](crypto-operations.md#rng-retrieve-and-rng-seed)).

### Payload of a failed Check

A Check denied by policy returns the attributes that caused the denial, as the
operation text requires, although the 2.x traces return no payload.

### Interop

The Interop operation is offered only with `--interop-test-mode`
(`KMIP_INTEROP_TEST_MODE`), off by default and logged with a warning at
startup, because KMIP 2.1 section 6.1.26 forbids it on a production server.
Query lists it only then, from 2.0. Begin, End and Reset record and clear only
the caller's test identifier; the draft 3.0 identifier `*` is refused. The
supplied Kubernetes resources leave it off.

### PSS defaults in KMIP 1.3

KMIP 1.3 has no Mask Generator or Salt Length fields. In 1.3 only, MGF1 uses
the message hash, Sign uses the maximum salt length and Signature Verify
accepts any salt length, as the 1.3 trace and PyKMIP do. 1.2 keeps the
PKCS#1 defaults (MGF1-SHA-1, 20-byte salt); 1.4 and later use the table
defaults ([PSS defaults](algorithms.md#pss-defaults)).

### A single-DES-equivalent 3DES test key

A three-key 3DES bundle that collapses to single or two-key DES (for example
three equal parts) is refused under every `--triple-des` value.

### Identifier type inside Key Wrapping Data (draft 3.0)

Draft 3.0 responses type the Unique Identifier of Encryption and MAC/Signature
Key Information as Identifier, as the draft's trace expects. Requests may
use Identifier, Reference or a message-local enumeration or integer; a Name
Reference for a wrapping key is refused (Invalid Field).

### Symbolic masks in XML

By default (the `compatible` and `readable` presets), XML responses write
Cryptographic Usage Mask, Storage Status Mask and Protection Storage Mask as
the edition's names separated by spaces, bits without a name as one
`0x%08X` component and zero as `0x00000000`, as every OASIS XML trace does.
JSON writes numbers under `compatible` and names under `readable`; the `hex`
preset writes both as hex, and `--xml-masks` and `--json-masks` override the
preset ([response forms](encodings.md#response-forms)). Decoders accept one
to eight hex digits.

### Name uniqueness

Names are unique per owner, not per server as the 2.x and 3.0 text says ("Names
SHALL be unique within a given key management server"; 1.x: "key management
domain"). A server-wide rule tells one tenant which Names another uses, and
breaks find-or-create clients when another tenant holds the Name; PyKMIP and
Cosmian KMS enforce no cross-object uniqueness. How Names and Name References
behave between tenants is in
[tenant isolation](authorization.md#tenant-isolation-and-names).

## Specification errata

Printing and table errors in the editions, and what the server does about them.

### Batch failure semantics

KMIP 2.1 table 434 (and draft 3.0 table 542) appear to swap the action text of
the Undo, Stop and Continue rows. This server follows the 1.4 table, the 2.1
definition of Operation Undone and the 2.1 batch trace: Stop leaves
completed items committed and returns no later items, Continue processes the
rest, Undo rolls back earlier items and returns them as Operation Undone with
their payloads ([batches](messages.md#batches)).

### Text encoding table references and source spelling

The 2.x tables print `MFG1` for Mask Generator 1 while the parameter
descriptions and XML examples use `MGF1`: both decode, and named output uses
`MGF1`. The Endpoint Role table is captioned as an Encoding Option table in
2.0, 2.1 and 3.0; its values are written as `Client` and `Server`. Split Key
Method is written in the trace spelling `PolynomialSharingGF2_16` and
`PolynomialSharingGF2_8`; the OVH spellings `PolynomialSharingGF216` and
`PolynomialSharingGF28` are also accepted.

### Split Key GF(2^8) polynomial

The final editions cite FIPS 197 but name polynomial 285, not AES's 283. The
OASIS 1.2 test vector reconstructs with 285, so final editions use 285; the
draft names the polynomial explicitly. The printed GF(2^16) multiplication
formula conflicts with the stated quotient field; the server follows the
quotient ([split keys](objects.md#split-keys)).

### PKCS#11 Correlation Value and C_GetInfo

2.0 and 2.1 return the PKCS#11 Correlation Value only in C_Initialize
responses; the 3.0 draft also echoes it in C_GetInfo and C_Finalize. CK_INFO
carries this server's own identity, not the sample values the traces expect.
