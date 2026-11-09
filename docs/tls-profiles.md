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

# TLS profiles (`--tls-profile`)

Part of [configuration and operations](README.md#configuration-and-operations).

The TTLV and HTTPS listeners share one TLS configuration (there is no
per-port policy), selected by `--tls-profile` (`KMIP_TLS_PROFILE`). Choose it
like this:

- **Use `modern`** (the default) unless a client cannot connect.
- If a client offers only ChaCha20-Poly1305, X25519 or finite-field DHE, use
  `mozilla-intermediate` (not allowed in FIPS mode).
- Use a `kmip-*` value only when you must offer a specific authentication
  suite of the KMIP Profiles documents. Each enables exactly the versions,
  suites and groups below, and OpenSSL refuses everything else.

## Policies

| Value | TLS | Server key | FIPS mode | Based on |
| --- | --- | --- | --- | --- |
| `modern` (default) | 1.2, 1.3 | any | allowed | Mozilla intermediate v5, restricted to FIPS-approved choices |
| `mozilla-intermediate` | 1.2, 1.3 | any | refused | Mozilla intermediate v5 as OpenSSL ships it |
| `kmip-2-basic` | 1.3 | any | refused | Profiles 2.0, 2.1, 3.0 Basic and HTTPS |
| `kmip-2-basic-tls12` | 1.2, 1.3 | RSA | refused | the same with the optional TLS 1.2 (legacy) |
| `kmip-1-tls12` | 1.2 | RSA | refused | Profiles 1.1–1.4 TLS 1.2 suite; 1.4 Basic and HTTPS (legacy) |
| `kmip-1-basic` | 1.0–1.2 | RSA | refused | Profiles 1.1–1.3 Basic; 1.3 HTTPS (legacy) |
| `kmip-1-suite-b-128` (alias `kmip-1-suite-b`) | 1.2 | ECDSA P-256 | allowed | Profiles 1.3/1.4 Suite B minLOS_128 |
| `kmip-1-suite-b-192` | 1.2 | ECDSA P-384 | allowed | Profiles 1.3/1.4 Suite B minLOS_192 |
| `kmip-3-quantum-safe` | 1.3 | any | refused | Profiles 3.0 draft Quantum Safe |

The server logs a warning at startup under the three legacy policies. Cipher
suites and groups:

- `modern`: TLS 1.2 ECDHE with AES-GCM (no DHE); TLS 1.3
  `TLS_AES_128_GCM_SHA256` and `TLS_AES_256_GCM_SHA384`; groups secp256r1,
  secp384r1, secp521r1.
- `mozilla-intermediate`: ECDHE and DHE AEAD suites including
  ChaCha20-Poly1305, three TLS 1.3 suites; the library's default groups
  (X25519 first, FFDHE included).
- `kmip-2-basic`: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`;
  groups x25519, secp256r1, secp384r1.
- `kmip-2-basic-tls12`: as `kmip-2-basic`, plus TLS 1.2
  `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`, `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`,
  `TLS_RSA_WITH_AES_256_CBC_SHA256` and `TLS_RSA_WITH_AES_128_CBC_SHA256`.
- `kmip-1-tls12`: `TLS_RSA_WITH_AES_256_CBC_SHA256`,
  `TLS_RSA_WITH_AES_128_CBC_SHA256`; no groups.
- `kmip-1-basic`: `TLS_RSA_WITH_AES_128_CBC_SHA`; no groups.
- `kmip-1-suite-b-128`: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`; secp256r1.
- `kmip-1-suite-b-192`: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`; secp384r1.
- `kmip-3-quantum-safe`: `TLS_AES_256_GCM_SHA384`,
  `TLS_CHACHA20_POLY1305_SHA256`; groups X25519MLKEM768, SecP256r1MLKEM768,
  SecP384r1MLKEM1024.

`keytend-kmip-server tls-profiles` prints every list, with the Profiles
sections each policy is derived from, as JSON.

A policy whose mandatory suites need an RSA or ECDSA server certificate
refuses to start with another key type. No single policy satisfies every KMIP
edition: 1.1–1.3 Basic require TLS 1.0, 1.4 Basic forbids it, and 2.x Basic
requires TLS 1.3.

### Finite-field DHE

`modern` offers no DHE suite or FFDHE
group: DHE is FIPS-approved, but it lets an unauthenticated client make the
server run costly DH public-key checks (CVE-2024-41996). A client that offers
only DHE needs `mozilla-intermediate`. The server-to-client connector uses the
same lists as `modern`.

### Suite B

`kmip-1-suite-b-128` and `kmip-1-suite-b-192` use OpenSSL's
RFC 6460 Suite B mode. Both sides must authenticate with ECDSA certificates
with the digitalSignature key usage, on P-256 (minLOS_128) or P-384
(minLOS_192), signed with ECDSA and the matching hash; the server refuses to
start with a server certificate that cannot be sent under the policy. Mixed
suites, such as AES-128 with P-384, are refused.

### Legacy policies

`kmip-2-basic-tls12`, `kmip-1-tls12` and `kmip-1-basic` enable static-RSA key
exchange (no forward secrecy) and CBC suites, and `kmip-1-basic` also TLS 1.0
and 1.1; the server logs a warning at startup. Use them only for clients that cannot
use `kmip-2-basic` or `modern`. `kmip-1-basic` runs at OpenSSL security level 0 (TLS
1.0 needs it), then puts back the 112-bit key minimum, the refusal of SHA-1
and MD5 certificate signatures, and the same strength for TLS 1.2 handshake
signatures. TLS 1.0 and 1.1 handshake signatures are not covered.

### Quantum Safe

`kmip-3-quantum-safe` uses the hybrid ML-KEM groups of OpenSSL 3.5, which the
image and every supported native build have; the server refuses to start
under this policy with a library that lacks them.

## Limits

- The project has no pinned copy of the Profiles 1.0 document
  ([specification data](specs/README.md)), so there is no 1.0 policy.
- 3DES, static DH/ECDH, PSK and DHE-DSS suites from the Profiles' optional
  lists are not offered; OpenSSL 3.5 cannot provide most of them.
- Startup checks each TLS 1.0–1.2 suite name and the groups against the
  linked library. It cannot see suites that a higher default security level
  would refuse during the handshake (static RSA at level 3 or above).
