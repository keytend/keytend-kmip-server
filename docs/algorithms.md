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

# Algorithms and key formats

Part of the [feature reference](README.md#feature-reference).

Which key types the server generates and accepts, in which formats, and with
which mechanisms. The operations that use them are in
[cryptographic operations](crypto-operations.md). [FIPS mode](fips.md)
narrows everything here to FIPS-approved services.

- [Symmetric keys](#symmetric-keys): [AES](#aes), [HMAC](#hmac-keys),
  [ChaCha20](#chacha20), [3DES](#3des)
- [RSA](#rsa), [DSA](#dsa), [Elliptic curves](#elliptic-curves)
- [Post-quantum keys](#post-quantum-keys) (3.0 draft)
- [Not supported](#not-supported)

## Symmetric keys

Formats: Raw and Transparent Symmetric Key; Get converts between them.

### AES

128, 192 or 256 bits; Create defaults to AES-256. Modes and parameters are in
[Encrypt and Decrypt](crypto-operations.md#encrypt-and-decrypt). AES keys are also
used for AES key wrap, AES-CMAC and the AES-based derivation methods.

### HMAC keys

HMAC-SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and HMAC-MD5 in every edition
with MAC (1.2+); HMAC-SHA3-224/256/384/512 from 1.4. Keys of 1 to 65,536
bytes.

### ChaCha20

ChaCha20 and ChaCha20-Poly1305 from KMIP 1.4, 256-bit keys only. Standalone
Poly1305 is not supported.

### 3DES

Three-key 3DES only, with Cryptographic Length 168 (or 192 counting parity
bits). Single DES and two-key 3DES are refused under every setting, and so is
a bundle whose three parts are not distinct, strong DES keys. NIST SP 800-131A
Rev. 2 no longer allows 3DES encryption, so it is off by default:

| `--triple-des` | Create, Re-key, Encrypt | Register, Import, Decrypt |
| --- | --- | --- |
| `disabled` (default) | refused | refused |
| `legacy-decrypt` | refused | allowed |
| `enabled` | allowed | allowed |

Refusals are Feature Not Supported. Stored 3DES objects can still be read,
listed and destroyed under every value. Encrypt and Decrypt support ECB and
CBC with no padding or PKCS#5 padding; MAC, wrapping, derivation and splitting
do not support 3DES. The server does not enforce the SP 800-67 block limit;
set Usage Limits if you need one. The OASIS Symmetric Key Foundry profile
needs `enabled`.

## RSA

| Property | Support |
| --- | --- |
| Generated sizes | 2048, 3072 or 4096 bits, public exponent 65537 |
| Imported keys | Odd modulus of 1024 to 8192 bits (transparent private keys up to 4096); odd public exponent from 3 to below 2^256 |
| Formats | PKCS#1, PKCS#8, X.509, Transparent RSA keys; Get converts between them |
| Default format of generated keys | PKCS#1 from 2.0; PKCS#8 and SubjectPublicKeyInfo in 1.x |
| Encryption | RSA-OAEP, SHA-1 (default) to SHA-512, optional label |
| Signatures | RSASSA-PSS and PKCS#1 v1.5, SHA-1 to SHA-512 |
| Key wrapping | RSA-OAEP ([key transfer](key-transfer.md#wrapped-get-and-register)) |

PKCS#8 holds private keys and X.509 (SubjectPublicKeyInfo) public keys. The
OAEP hashes for the message and for MGF1 are chosen separately. A signature
scheme is chosen by a combined Digital Signature Algorithm, or by algorithm,
hash and padding parameters. "SHA-1 to SHA-512" means SHA-1, SHA-224,
SHA-256, SHA-384 and SHA-512.

A transparent private key may give the private exponent, the primes or the
CRT exponents; missing values are derived and the key is checked before it is
stored. Checking is expensive, so a batch may hold at most four such imports
(transparent RSA private keys and every transparent DSA key share the quota);
the fifth fails with General Failure in 1.x and Server Limit Exceeded from
2.0.

### PSS defaults

When the request does not give them:

| Edition | Mask generator | Salt length |
| --- | --- | --- |
| 1.2 | MGF1 with SHA-1 | 20 bytes |
| 1.3 | MGF1 with the message hash | Sign: maximum; Verify: any ([PSS defaults](interpretations.md#pss-defaults-in-kmip-13)) |
| 1.4 and later | MGF1 with SHA-1 | the hash's block size: 64 bytes for SHA-1/224/256, 128 for SHA-384/512 |

1.4 and later accept explicit Mask Generator, Mask Generator Hashing
Algorithm, Salt Length (bytes, including 0) and Trailer Field. In FIPS mode a
PSS signature needs a Salt Length no larger than the hash length.

## DSA

DSA keys can be registered as PKCS#8, X.509 or Transparent DSA keys (P of
512–3072 bits, Q of 160, 224 or 256 bits) and used to verify signatures. The
server does not generate DSA keys or sign with them. Transparent DSA keys
count toward the four-per-batch validation quota described under [RSA](#rsa).

## Elliptic curves

| Property | Support |
| --- | --- |
| Curves | P-224, P-256, P-384, P-521, secp256k1 and the brainpool r1/t1 curves; NIST only with `--ec-curves nist` (below) |
| Key types | ECDSA, ECDH and generic EC (1.2+) keys; P-256 when neither curve nor length is given |
| Formats | PKCS#8 and SEC1 (private), X.509 SubjectPublicKeyInfo (public), Transparent ECDSA/ECDH keys and Transparent EC keys (1.3+). Get converts between them. |
| Point encoding | Transparent public keys accept uncompressed, compressed and hybrid points |
| Signatures | ECDSA with SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512, DER-encoded |

ECDH keys can be stored and transferred, but the server offers no key
agreement, and ECDH keys cannot sign.

The server implements 13 of KMIP's 68 Recommended Curves: P-224, P-256,
P-384, P-521, secp256k1, and brainpoolP256, P320, P384 and P512 (r1 and t1).
The other 55 (P-192, binary curves, secp112 to secp224 variants,
prime192v2/v3, prime239v1–v3, brainpoolP160–224) are refused. `--ec-curves`
selects which of these 13 curves KMIP operations may use
([why](interpretations.md#supported-elliptic-curves)):

| `--ec-curves` | Curves |
| --- | --- |
| `extended` (default) | P-224, P-256, P-384, P-521, secp256k1 and the eight brainpool curves |
| `nist` | P-224, P-256, P-384, P-521 |

A request that needs a curve the setting does not offer fails with Feature
Not Supported, "Unsupported EC curve": key generation, Register and Import,
certificates and certificate requests, Validate, Certify, Sign, Signature
Verify, Create Split Key and format conversions. KMIP 1.0 and 1.1 also refuse
curves above 15 ("Curve requires KMIP 1.2"). Keys already stored on a curve
the setting does not offer can still be read in their stored format, but not
used, converted, re-keyed or split. FIPS mode works as `nist` whatever the
setting, so it refuses the other curves in all of these operations; it logs
a note at startup when `extended` is set explicitly.

The TLS listeners accept certificates on any of the 13 curves, whatever
`--ec-curves` says. The default `modern` policy completes no handshake with a
server certificate on secp256k1 or a brainpool curve: its TLS 1.2 groups are
P-256, P-384 and P-521, and it lists no TLS 1.3 signature scheme for these
curves.
Under `mozilla-intermediate`, a brainpoolP256r1 server key (the brainpool
curve tested) works over TLS 1.3 only. A secp256k1 server key completes no
handshake under either policy; TLS 1.3 defines no signature scheme for
secp256k1. For the server certificate, use P-256, P-384 or P-521
([TLS profiles](tls-profiles.md)).

## Post-quantum keys

Only in the 3.0 draft (`--experimental-v3`) and only outside FIPS mode. The
algorithms come from the OpenSSL 3.5 default provider.

| Property | Support |
| --- | --- |
| Algorithms | ML-KEM-512/768/1024 (FIPS 203), ML-DSA-44/65/87 (FIPS 204), the twelve SLH-DSA parameter sets (FIPS 205) |
| Create Key Pair | Generated by the provider; ML-KEM and ML-DSA also from a supplied Seed |
| Formats | Private: Raw (default), PKCS#8, Seed Private Key. Public: Raw (default), X.509. Get converts between them. |
| Sign, Signature Verify | ML-DSA and SLH-DSA, pure interface. Context String up to 255 bytes, Deterministic (default hedged), External Mu for ML-DSA. |
| Encapsulate, Decapsulate | ML-KEM (below) |
| Usage masks | Sign and Verify as for other keys; Encapsulate and Decapsulate below |
| Usage limits | Encapsulate and Decapsulate charge one use, or 32 bytes. |

Each generated key gets its own Cryptographic Length (encoded size in bits)
and NIST Security Category; supplied values must match.

Not implemented: XMSS, SPHINCS-256 and McEliece (2.x values with no format
or operation defined), Hash-ML-DSA and Hash-SLH-DSA, the hybrid KEM key
objects, RSASVE and DHKEM, multipart signing with these keys, post-quantum
certificates and ML-KEM wrapping keys. In FIPS mode the RHEL 9 FIPS provider
implements none of these algorithms, so every post-quantum request is refused
and Encapsulate and Decapsulate are not offered; keys created outside FIPS
mode stay stored.

Hybrid ML-KEM key exchange for TLS is a separate feature
([TLS profiles](tls-profiles.md)).

### Encapsulate and Decapsulate

Encapsulate, with an ML-KEM public key, stores the shared secret as a Secret
Data object and returns its identifier and the ciphertext; Decapsulate, with
the private key, recreates it. A tampered ciphertext gives a different secret,
not an error. Encapsulate needs the Encrypt, Wrap Key or Key Agreement usage
(Decapsulate: Decrypt, Unwrap Key or Key Agreement), or Unrestricted.

## Not supported

- RSA PKCS#1 v1.5 encryption, X9.31 signatures and SHA-3 RSA signatures
- ECDH and ECMQV key agreement, Edwards and Montgomery curves (Ed25519,
  X25519 and others) as KMIP keys, DSA and DH key generation
- AES-CBC-MAC, X9.19 MACs and DES-based MACs
- MD2, MD4, RIPEMD-160 and other legacy hashes
- A deployment-level allowlist of mechanisms beyond `--triple-des`,
  `--ec-curves` and FIPS mode
