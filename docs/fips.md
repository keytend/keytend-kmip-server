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

# FIPS mode

Part of [configuration and operations](README.md#configuration-and-operations).

In default mode, where the server chooses a mechanism itself (internal
cryptography, generated values), it makes a FIPS-approved choice. A client
that explicitly asks for a non-approved mechanism, such as ChaCha20 or DSA,
still gets it. Some defaults that KMIP itself defines are not approved, such
as the [PSS defaults](algorithms.md#pss-defaults); default mode keeps them.

FIPS mode refuses the non-approved services and does not advertise them.
Every other default, format, reason code and response shape stays the same.

No FIPS 140-3 validation is claimed for the server or the image, and FIPS
mode was tested only on an emulated FIPS host
([provider and validation status](#provider-and-validation-status)).

## Running in FIPS mode

1. Run on a FIPS-enabled host (kernel `fips=1`), with the image or with a
   native build and a FIPS provider (an upstream provider needs its
   `fipsmodule.cnf`; the RHEL provider in the image needs none). On
   Kubernetes, schedule the pod on FIPS-enabled nodes: containers share the
   host kernel.
2. Use a FIPS-compatible configuration: `--tls-profile` `modern`,
   `kmip-1-suite-b-128` or `kmip-1-suite-b-192`; `--triple-des disabled`; and
   users-file verifiers in PBKDF2 form with passwords of at least 8 bytes
   ([credentials](credentials.md#users-file)). The server refuses to start
   with an incompatible TLS profile or 3DES setting.
3. Start with `--fips` or `KMIP_FIPS=true`. On a FIPS host
   (`/proc/sys/crypto/fips_enabled` is 1) the server enters FIPS mode even
   without the flag, and logs a warning.
4. Check the provider:

   ```sh
   keytend-kmip-server --fips fips-check
   ```

   It prints JSON with the loaded `fips` and `base` providers' name, version,
   build information and status; status 1 means running. With the image:
   `docker run --rm <image> --fips fips-check`.
5. Monitor `kmip_fips_mode` and `kmip_fips_provider_status`
   ([metrics](metrics.md)).

At startup in FIPS mode the server loads only the `fips` and `base` providers,
checks that approved algorithms come from the FIPS provider and that
non-approved ones (MD5, BLAKE2b, ChaCha20-Poly1305) cannot be fetched, runs a
SHA-256 known-answer test and requires provider status 1. Any failure,
including a missing or corrupted module, stops the server. The maintenance
commands (`check-store`, `backup`, `rotate-master-key`, …) load the provider
the same way.

## What FIPS mode refuses

Every refusal's Result Message names FIPS mode. The Result Reason is the one
the operation already uses for an unsupported mechanism, usually Feature Not
Supported (Invalid Field for Create and Register of a non-approved symmetric
algorithm).

| Service | Refused in FIPS mode |
| --- | --- |
| ChaCha20, ChaCha20-Poly1305, HMAC-MD5, DSA | all use, including Register of such keys |
| Triple-DES | the server refuses to start unless `--triple-des disabled` |
| EC curves | everything but P-224, P-256, P-384 and P-521 (secp256k1, brainpool) |
| RSA signing | keys under 2048 bits (also as Certify issuer keys), SHA-1, PSS with an MGF1 SHA-1 hash or a salt longer than the hash (both are the KMIP defaults: set them explicitly, as the [RSA signing example](clients/https.md#sign-and-verify-with-rsa) does) |
| RSA and ECDSA verification | SHA-1 signatures (the RHEL provider refuses them) |
| RSA-OAEP (encrypt, decrypt, wrap) | keys under 2048 bits |
| HMAC | generating keys under 112 bits, and MACs with them |
| AES-GCM | tags under 96 bits; client-chosen encryption IVs (the server generates the IV) |
| Derive Key | HASH, HMAC, ENCRYPT, NIST SP 800-108 and AWS Signature v4 methods; weak PBKDF2 and HKDF parameters (below) |
| Split keys | Create Split Key, Join Split Key and Split Key objects (refused and not advertised) |
| Post-quantum (draft 3.0) | ML-KEM, ML-DSA and SLH-DSA keys; Encapsulate and Decapsulate (refused and not advertised) |
| Credentials | scrypt password verifiers and passwords under 8 bytes (Authentication Not Successful) |
| TLS | policies other than `modern`, `kmip-1-suite-b-128` and `kmip-1-suite-b-192` (refused at startup) |

The refused Derive Key parameters are PBKDF2 with a password under 8 bytes,
a salt under 16 bytes, under 1000 iterations or output under 112 bits, and
HKDF with input under 112 bits.

Re-Provision ([Re-Provision](re-provision.md)) in FIPS mode generates keys
and signs certificates through the provider. The provisioning CA must meet
the issuer rules above (RSA of at least 2048 bits, or EC on P-256, P-384 or
P-521), or the server refuses to start, and the startup self-test issues one
certificate through the provider.

Still allowed as legacy use: signature verification with RSA keys from 1024
bits or with a SHA-1 MGF1 hash, MAC verification with HMAC keys under 112
bits, and Register of RSA keys under 2048 bits (which can then only verify).
Certificates, PGP keys, Secret Data and Opaque Objects are stored without an
algorithm check.

## Provider and validation status

**Not a validated configuration.** The image ships a FIPS provider build that
has been submitted for validation, not the validated one:

| Module | Package | Module version | Status |
| --- | --- | --- | --- |
| Shipped in the image | `openssl-fips-provider` 3.0.7-11.el9_8 | `3.0.7-cda111b5812c30d4` | Submitted for certification ([RHSA-2026:28832](https://access.redhat.com/errata/RHSA-2026:28832), which fixes CVE-2026-31790) |
| Validated | 3.0.7-6.el9 | `3.0.7-395c1a240fbfffd8` | [CMVP #4857](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4857) (below) |

Certificate #4857 is a FIPS 140-3 level 1 interim validation, with a sunset
date of 28 October 2029. The UBI 9 repositories offer only 3.0.7-11, so the
validated build cannot be pinned from UBI. Status as checked on 30 October 2026.

The certificate's operational environments are RHEL 9 on the listed Intel Xeon,
IBM POWER10 and IBM z16 hardware, in the configuration its security policy
specifies; a container on another kernel, and every arm64 host, is outside
them. FIPS mode was exercised with the RHEL provider only on an emulated FIPS
host (`OPENSSL_FORCE_FIPS_MODE=1`), and with an upstream OpenSSL 3.2.0 FIPS
provider natively; never on a real FIPS-enabled kernel
([test results](status.md#what-has-been-tested)).

The image does not use RHEL's system crypto policy
([OpenSSL configuration](container-image.md#openssl-configuration)), so it behaves
like a native build until FIPS mode loads the provider itself.

## Limits

- GCM encryption IVs and storage nonces are generated by the server from the
  provider's DRBG and passed to the cipher, not generated inside the module
  (FIPS 140-3 IG C.H scenario 2 would need the provider's internal IV
  generation, which the binding does not expose).
- SP 800-108 derivation is refused because the server composes it outside the
  provider.
- Key validation (`EC_KEY_check_key`, `RSA_check_key`, transparent RSA factor
  recovery) uses libcrypto routines outside the provider; it produces no
  protected output.
- With a real FIPS provider, parsing a certificate whose key uses a
  non-approved algorithm can fail in OpenSSL before the policy check, so the
  Result Reason can differ from a host without a provider (EC curves are
  checked by the server first and behave the same everywhere).
- A users-file scrypt verifier costs one PBKDF2 evaluation in FIPS mode and
  never authenticates; replace it with one from `password-verifier`.
- The provider status is read at startup, by `fips-check` and at each
  `/metrics` scrape. A provider that later enters its error state makes its
  operations fail; `/readyz` does not report it.
