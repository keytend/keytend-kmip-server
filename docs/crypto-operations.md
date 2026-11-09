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

# Cryptographic operations

Part of the [feature reference](README.md#feature-reference).

Encrypt, Decrypt, Sign, Signature
Verify, MAC, MAC Verify, Hash, RNG Retrieve and RNG Seed are in KMIP 1.2 and
later; Derive Key is in every edition; AES-GCM and ChaCha20 need 1.4. Operations that use a stored
key check its owner, state, dates and usage mask ([lifecycle](lifecycle.md)),
and all but Decrypt and the verify operations charge its
[usage limits](lifecycle.md#usage-limits). Hash, RNG Retrieve and
RNG Seed use no stored key.

- [Cryptographic parameters](#cryptographic-parameters)
- [Encrypt and Decrypt](#encrypt-and-decrypt)
- [Sign and Signature Verify](#sign-and-signature-verify)
- [MAC and MAC Verify](#mac-and-mac-verify), [Hash](#hash)
- [RNG Retrieve and RNG Seed](#rng-retrieve-and-rng-seed)
- [Derive Key](#derive-key)
- [Multipart operations](#multipart-operations)

## Cryptographic parameters

A key can store one or more Cryptographic Parameters instances (at Create,
Register or later). A request without parameters uses the first stored
instance; a request with parameters uses exactly those, without merging in
stored fields. IV Length is in bits, Tag Length in bytes.

## Encrypt and Decrypt

Examples of AES-GCM on the server:
[HTTPS JSON](clients/https.md#encrypt-and-decrypt-with-aes-gcm),
[Go](clients/go.md), [Java](clients/java.md#binary-kmip),
[Python over HTTPS](clients/python.md#server-side-encrypt-over-https-json).

| Key | Modes and options |
| --- | --- |
| AES | ECB and CBC (no padding or PKCS#5), CFB (128-bit), OFB, CTR (full 128-bit counter block); GCM from 1.4 |
| ChaCha20 (1.4+) | 64-bit nonce with 64-bit counter, or 96-bit IETF nonce with 32-bit counter; initial counter 0 by default |
| ChaCha20-Poly1305 (1.4+) | 96-bit nonce, 16-byte tag only |
| 3DES | ECB and CBC, only when `--triple-des` allows it |
| RSA | OAEP; encrypt with the public key, decrypt with the private key |

- A supplied IV takes precedence over Random IV. A
  server-generated IV is returned in the Encrypt response; Decrypt never
  generates one. A missing required IV is Invalid Message
  ([missing IV](interpretations.md#result-reasons)). IVs are at most
  1,024 bytes.
- GCM: default IV 96 bits and tag 16 bytes; tags of 4, 8 or 12–16 bytes.
  Another tag length is General Failure
  ([AEAD tag length](interpretations.md#result-reasons)).
  Authentication fails before any plaintext is returned.
- ChaCha20-Poly1305 accepts only full 16-byte tags
  ([truncated tags](interpretations.md#result-reasons)).
- RSA-OAEP: oversized plaintext fails; a corrupt ciphertext, wrong label
  or wrong hash fails uniformly without plaintext.
- In FIPS mode client-chosen GCM encryption IVs are refused.

## Sign and Signature Verify

Examples: [RSA over HTTPS JSON](clients/https.md#sign-and-verify-with-rsa),
[ECDSA with Java](clients/java.md#sign-and-verify).

- RSA (PSS and PKCS#1 v1.5), ECDSA and, in the 3.0 draft, ML-DSA and SLH-DSA
  ([algorithms](algorithms.md)). DSA verification only.
- Sign uses a private key; Signature Verify uses a public key or an X.509
  certificate ([certificates](certificates.md#verifying-signatures-with-a-certificate)).
- From 1.4, Digested Data passes an already computed digest instead of Data
  for RSA, ECDSA and DSA; its size must match the hash. The two cannot be
  combined.
- A wrong signature is a successful response with Validity Indicator Invalid,
  not an error.
- RSA and ECDSA signing need a hash: from the request's parameters, a
  combined Digital Signature Algorithm, or a stored parameters instance. KMIP
  1.3 ECDSA defaults to SHA-256 ([ECDSA default hash](interpretations.md#ecdsa-default-hash-in-kmip-13)).
- ML-DSA and SLH-DSA use the pure interface: they take Data and refuse both a
  Hashing Algorithm and Digested Data
  ([post-quantum keys](algorithms.md#post-quantum-keys)).

## MAC and MAC Verify

- HMAC with the ten HMAC algorithms of [HMAC keys](algorithms.md#hmac-keys),
  and AES-CMAC (Cryptographic Algorithm AES with block cipher mode CMAC) with
  AES keys; CMAC tags are 16 bytes.
- The mechanism comes from the request's parameters, otherwise from the
  first stored instance, otherwise from an HMAC key's own algorithm. An AES
  key needs explicit or stored CMAC or HMAC parameters.
- An invalid MAC is a successful response with Validity Indicator Invalid.
  Tags are compared in constant time.

## Hash

Unkeyed hashing (1.2+): SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
SHA-512/224 and SHA-512/256; SHA3-224/256/384/512 from 1.4. The request needs
a Cryptographic Parameters structure; an empty one means SHA-256. An
unsupported algorithm is Feature Not Supported.

## RNG Retrieve and RNG Seed

- RNG Retrieve returns up to 65,536 random bytes from the OpenSSL
  generator.
- RNG Seed validates the request, ignores the client's bytes and returns
  Data Length 0, as KMIP allows. Client data never reaches the generator and is
  not stored or logged. A policy can allow RNG Retrieve and deny RNG Seed
  (operation 38).

## Derive Key

| Method | Editions | Notes |
| --- | --- | --- |
| PBKDF2 | all | Salt and Iteration Count required; PRF HMAC with SHA-1 (default), SHA-224/256/384/512, MD5, or SHA3-224/256/384/512 from 1.4 |
| HASH | all | SHA-1, SHA-224/256/384/512, MD5, or SHA3-224/256/384/512 from 1.4, over one key or Secret Data; the hash is required |
| HMAC | all | One HMAC, truncated to the requested length |
| ENCRYPT | all | AES ECB, CBC, CFB, OFB or CTR |
| NIST SP 800-108 Counter, Feedback, Double Pipeline | all | PRF from the [HMAC key](algorithms.md#hmac-keys)'s algorithm, or AES-CMAC with an AES key; 32-bit counter and length fields |
| HKDF (RFC 5869) | 2.0+ | Default SHA-256 |
| AWS Signature Version 4 | 2.0+ | Exactly three Derivation Data entries (date, region, service); output up to 256 bits |
| Asymmetric key agreement | | not supported |

Derive Key refuses a missing required field, or one the method does not use
(Invalid Field or Missing Data):

| Field | Required | Notes |
| --- | --- | --- |
| Object Type | yes | Symmetric Key or Secret Data. |
| Unique Identifier | yes, once or twice | The sources (below). |
| Derivation Method | yes | The table above. |
| Derivation Parameters | yes | The structure below. |
| Attributes (2.x), Template-Attribute (1.x) | yes | Cryptographic Length, a multiple of 8; for a Symmetric Key also Cryptographic Algorithm. From 2.0, Key Format Type: Raw (default) or Transparent Symmetric Key for a key, Raw or Opaque for Secret Data. |
| Protection Storage Masks | no | 2.0+. |

| Derivation Parameters field | Methods | Notes |
| --- | --- | --- |
| Cryptographic Parameters | all but HMAC | Hashing Algorithm: required for HASH; default SHA-1 for PBKDF2 and SHA-256 for HKDF and AWS (SHA-256 only); SHA-3 from 1.4. ENCRYPT: Block Cipher Mode, and Padding Method (default None). SP 800-108 with an AES key: Block Cipher Mode CMAC; an HMAC key sets its own PRF. In 1.x, HASH, ENCRYPT and SP 800-108 fall back to the key's stored Cryptographic Parameters. |
| Derivation Data | all but PBKDF2 | The input of HMAC, ENCRYPT and SP 800-108, and of HASH without a key source; required unless a Secret Data source supplies it. HKDF: the info, optional. AWS: three values, in order the date (`YYYYMMDD`), region and service. |
| Salt | PBKDF2, HKDF | Required for PBKDF2. |
| Iteration Count | PBKDF2 | Required, above 0. |
| Initialization Vector | ENCRYPT, SP 800-108 Feedback | Feedback: empty or one PRF output long. |

- Sources: explicit identifiers (not the ID Placeholder), at most one key and
  one Secret Data object, each Active, owned and with the Derive Key usage
  bit.
- Output: an AES or HMAC key, or Seed Secret Data, with an explicit
  byte-aligned Cryptographic Length (at most 65,536 bytes). The new object
  links to its sources and the sources to it.
- Limits: four derivations per batch, PBKDF2 at most 2,000,000 PRF blocks in
  total. Work above a limit is refused, never silently reduced.
- Each source's usage limits are charged once per derived object, or by the
  derived length.

### Example: derive a key with HKDF over HTTPS

Against the [quick-start server](quick-start.md), with the
[`kmip.sh`](../examples/https/kmip.sh) functions loaded (`. examples/https/kmip.sh`
from the checkout).
[`create-derivation-key.json`](../examples/https/create-derivation-key.json)
creates and activates a non-extractable AES-256 key whose only usage is
Derive Key. [`derive.json`](../examples/https/derive.json) derives a new
AES-256 Encrypt/Decrypt key from it with HKDF-SHA-256, with `SALT` and `INFO`
as hex:

```json
{"tag": "RequestMessage", "value": [
  {"tag": "RequestHeader", "value": [
    {"tag": "ProtocolVersion", "value": [
      {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
      {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}]},
    {"tag": "BatchCount", "type": "Integer", "value": 1}]},
  {"tag": "BatchItem", "value": [
    {"tag": "Operation", "type": "Enumeration", "value": "DeriveKey"},
    {"tag": "RequestPayload", "value": [
      {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
      {"tag": "UniqueIdentifier", "type": "TextString", "value": "$KEY"},
      {"tag": "DerivationMethod", "type": "Enumeration", "value": "HKDF"},
      {"tag": "DerivationParameters", "value": [
        {"tag": "CryptographicParameters", "value": [
          {"tag": "HashingAlgorithm", "type": "Enumeration", "value": "SHA_256"}]},
        {"tag": "Salt", "type": "ByteString", "value": "$SALT"},
        {"tag": "DerivationData", "type": "ByteString", "value": "$INFO"}]},
      {"tag": "Attributes", "value": [
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
        {"tag": "CryptographicLength", "type": "Integer", "value": 256},
        {"tag": "CryptographicUsageMask", "type": "Integer", "value": "Encrypt|Decrypt"}]}]}]}]}
```

```bash
BASE=$(kmip create-derivation-key.json | field UniqueIdentifier)
R=$(kmip derive.json KEY="$BASE" SALT="$(hex orders-v1)" INFO="$(hex tenant-42)")
pretty <<<"$R" | tail -5
```

The end of the response (an excerpt):

```text
  {"tag": "BatchItem", "type": "Structure", "value": [
    {"tag": "Operation", "type": "Enumeration", "value": "DeriveKey"},
    {"tag": "ResultStatus", "type": "Enumeration", "value": "Success"},
    {"tag": "ResponsePayload", "type": "Structure", "value": [
      {"tag": "UniqueIdentifier", "type": "TextString", "value": "95bd9816-7e10-4185-bbf4-95bfff7c1dc1"}]}]}]}
```

The response carries only the new key's identifier. The derived key is
Pre-Active: activate it before Encrypt. The same source, salt and info
derive the same key material again, as a new object:

```bash
KEY=$(field UniqueIdentifier <<<"$R")
AGAIN=$(kmip derive.json KEY="$BASE" SALT="$(hex orders-v1)" INFO="$(hex tenant-42)" | field UniqueIdentifier)
kmip get.json ID="$KEY" | field KeyMaterial
kmip get.json ID="$AGAIN" | field KeyMaterial
```

```text
5aca389995f3509c46cb553a50733cbbc9e72688f38369b3832e6179c435b0f3
5aca389995f3509c46cb553a50733cbbc9e72688f38369b3832e6179c435b0f3
```

## Multipart operations

From KMIP 1.3, Encrypt, Decrypt, Sign, Signature Verify, MAC, MAC Verify and
Hash can stream data over several requests:

1. The first request sets Init Indicator; the response holds a 32-byte
   Correlation Value.
2. Later requests carry that value; the last sets Final Indicator. Results
   (ciphertext tail, signature, MAC, digest, Validity Indicator) come with the
   final response. GCM and ChaCha20-Poly1305 decryption return plaintext only
   after the tag verifies.
3. Init and Final together form a single-part request.

A stream is bound to the principal, the key, its material and the
parameters; later parameters must match. It may continue over a new
connection by the same principal. A failed final request leaves the stream
retryable. Usage limits are charged for each part's bytes and once per stream
for object counts.

| Limit | Value |
| --- | ---: |
| Open streams per server | 64 |
| Open streams per principal | 16 |
| Retained data, all streams | 8 MiB |
| AEAD decryption buffer per stream | 512 KiB |
| Input per stream | 16 GiB |
| Idle timeout | 300 s |
| Maximum lifetime | 3,600 s |

Streams live in memory: a restart or timeout discards them, and charges
already made are not refunded. Responses are not replay-cached, so a lost
response leaves the client unsure whether its part was processed. Destroying
or replacing the key ends its streams. RSA-OAEP accepts multipart input only
up to one RSA block. Post-quantum signatures are single-part only.
