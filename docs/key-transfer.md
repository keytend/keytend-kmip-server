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

# Getting and transferring keys

Part of the [feature reference](README.md#feature-reference).

How Get, wrapped Get and Register, Import and Export return or accept key
material, and the protection storage the server reports.

- [Get](#get)
- [Wrapped Get and Register](#wrapped-get-and-register)
- [Import and Export](#import-and-export)
- [Protection storage](#protection-storage)

## Get

- Get returns the object in its stored format unless the request names
  another Key Format Type; supported conversions are listed per key type in
  [algorithms](algorithms.md). An unsupported format is Key Format Type Not
  Supported.
- Sensitive objects are never returned in plaintext, but can be returned
  wrapped. Non-extractable objects are never returned. Both default to
  allowing retrieval.
- The first Get that returns material sets Fresh to False.
- Get of a destroyed object fails (Illegal Operation in 1.x, Object Destroyed
  from 2.0); see [lifecycle](lifecycle.md#destroy).
- An archived object must be recovered first.

## Wrapped Get and Register

A Key Wrapping Specification on Get returns the key encrypted under another
key the caller owns; a wrapped Key Block on Register is unwrapped and stored.

| Item | Support |
| --- | --- |
| Mechanisms | AES Key Wrap (RFC 3394, block cipher mode 13) and with Padding (RFC 5649, mode 12) under 128-, 192- or 256-bit keys; RSA OAEP with independent message and MGF1 hashes and an optional label |
| Wrapping key | Owned by the caller, with the Wrap Key usage bit for Get and Unwrap Key for Register. An RSA public key wraps; its linked (or an explicitly named) private key unwraps. State and dates apply. |
| Encoding | TTLV-encoded Key Value by default. From 1.1, No Encoding for byte-string key material without attributes. Key Wrapping Data echoes Encoding Option only when the request gave one. |
| Parameters | Explicit wrapping parameters must equal one of the wrapping key's stored Cryptographic Parameters; omitted, the first stored instance is used. A mismatch is Item Not Found in 1.x. |
| Attributes | Selected attributes are wrapped with the key and restored by Register, merged with the request's own attributes. |
| Usage limits | A wrapped Get charges the wrapping key once, or by the plaintext length. Unwrapping is not charged. |

Register checks integrity, unwraps, validates the material as for a plaintext
Register and stores it encrypted at rest. From 1.4 it also keeps the original
envelope, which Get returns with Key Wrap Type As Registered.

Not supported: MAC/sign or combined encrypt-and-MAC wrapping, TR-31,
certificate-based or opaque wrapping keys, ML-KEM wrapping keys, and wrapping
keys that are themselves stored wrapped.

### Example: fetch a Sensitive key wrapped

With the [quick-start server](quick-start.md) and the
[HTTPS shell functions](clients/https.md) loaded:
[`create-kek.json`](../examples/https/create-kek.json) creates and activates
an AES-256 wrapping key with the Wrap Key and Unwrap Key bits and a stored
AES Key Wrap parameter;
[`create-sensitive.json`](../examples/https/create-sensitive.json) creates a
Sensitive data key; [`get-wrapped.json`](../examples/https/get-wrapped.json)
fetches it wrapped under the first key, without encoding (`NoEncoding`).

```sh
KEK=$(kmip create-kek.json | field UniqueIdentifier)
ID=$(kmip create-sensitive.json | field UniqueIdentifier)
kmip get.json ID="$ID" | field ResultReason
kmip get-wrapped.json ID="$ID" KEK="$KEK" | field KeyValue
```

```text
Sensitive
d551f9bee8591e277667f3b43af9390f2c5f477fa67f4e08cce9ee2a3f1c358509ba8775d1e68105
```

The plain Get is refused; the wrapped one returns the 32-byte key as 40 bytes
of RFC 3394 output, which any AES Key Wrap implementation unwraps with the
wrapping key (for example `aes_key_unwrap` in Python's `cryptography`).

## Import and Export

KMIP 1.4 and later. Export returns the object, its identifier and all its
attributes; Import restores such a record as it was, including state, dates,
usage counters and server-maintained attributes.

- **Use Import as restore authority only.** An authorized Import can replace
  an object's state, material and remaining budget. Import writes objects as
  the calling principal and never replaces another principal's object, so give
  operation 42 to a separate administrative certificate mapped to the owner's
  principal ([role templates](configuration.md#role-templates)), not to
  database clients.
- Import requires an explicit identifier (at most 1,024 bytes).
  An existing identifier fails with Object Already Exists unless Replace
  Existing is True; another owner's object is never replaced. Name and Short
  Unique Identifier uniqueness apply.
- Mandatory restore attributes include State, Initial Date and Last Change
  Date; from 1.4 the extraction flags and histories, from 2.0 Fresh, Key
  Format Type and the Short Unique Identifier, and in the 3.0 draft Object
  Class. Plaintext material needs a matching SHA-256 Digest.
- For wrapped input, Key Wrap Type Not Wrapped unwraps and validates before
  storing. As Registered stores the ciphertext as it is, without needing the
  wrapping key yet; the key is unwrapped only when it is used, with a wrapping
  key the caller owns, and plaintext is never written to storage. In 2.x and
  3.0 the Key Wrap Type is required exactly when the input is wrapped; in 1.4
  an omitted type keeps the envelope.
- Export follows Get's format, wrapping and extraction rules. A destroyed
  object exports its metadata without material, which Import restores as a
  destroyed record.
- TTLV-encoded envelopes cannot move As Registered between major versions
  (1.x and 2.x); No Encoding envelopes can.

The server cannot enforce usage limits on exported key material.

### Example: export a key and import it again

With the [quick-start server](quick-start.md) and the
[HTTPS shell functions](clients/https.md) loaded:
[`export.json`](../examples/https/export.json) exports a key's record, and
[`import.json`](../examples/https/import.json) imports a symmetric key's
`Attributes` and `SymmetricKey` structures under its identifier, with Replace
Existing True. `field` prints a structure as the JSON list that `import.json`
takes. This exports a new key, retires it with
[`retire.json`](../examples/https/retire.json) (Activate, Revoke, Destroy),
then restores it:

```bash
ID=$(kmip create.json | field UniqueIdentifier)
R=$(kmip export.json ID="$ID")   # the record, key material included: protect it
kmip retire.json ID="$ID" >/dev/null
kmip get.json ID="$ID" | field ResultReason
kmip import.json ID="$ID" ATTRIBUTES="$(field Attributes <<<"$R")" \
  KEY="$(field SymmetricKey <<<"$R")" | field ResultStatus
K=$(field KeyMaterial <<<"$R")
[ -n "$K" ] && [ "$(kmip get.json ID="$ID" | field KeyMaterial)" = "$K" ] && echo restored
```

```text
ObjectDestroyed
Success
restored
```

The restored key is Pre-Active again, as it was when exported. The same
`import.json` can carry the record to another server, under the same
principal name.

## Protection storage

From 2.0, the only storage the server offers is Software (Protection Storage
Mask 1); Query Storage Protection Masks reports that. A request whose
acceptable masks need Hardware or another property fails (Protection Storage
Unavailable, or Private/Public Protection Storage Unavailable for key pairs;
Feature Not Supported for Derive Key) rather than downgrading. Each object
records its own selection, which is read-only.
