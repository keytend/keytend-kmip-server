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

# KMIP certificate objects

Part of the [feature reference](README.md#feature-reference).

The server stores X.509 and PGP certificates, verifies application signatures
with a stored certificate's key, validates X.509 chains against a trust
bundle you configure, stores PKCS#10 certificate requests (2.0+), and issues
end-entity certificates with Certify and Re-certify from a CA key you have
registered. It checks no revocation (CRL or OCSP) of stored certificates.

| To | Use |
| --- | --- |
| Store and retrieve a certificate | [Register and Get](#storing-certificates) |
| Verify a signature with a certificate's key | [Signature Verify](#verifying-signatures-with-a-certificate) |
| Check that a chain is trusted | [Validate](#validate) |
| Keep a certificate request | [Certificate requests](#certificate-requests) |
| Issue a certificate | [Certify and Re-certify](#certify-and-re-certify) |

## Storing certificates

### X.509 certificates

Certificate Type 1: DER, at most 64 KiB. Get returns the exact bytes
registered. Registration checks structure and metadata only: it does not
verify the signature, dates, chain or ownership of the certificate.

Register derives these attributes from the certificate; values you supply
must have the right type and agree with it:

- Cryptographic Algorithm and Cryptographic Length of the subject key
  (RSA, DSA, DH, EC). In KMIP 1.0 and 1.1 an EC certificate needs an explicit
  Cryptographic Algorithm (ECDSA, ECDH or ECMQV).
- Certificate Length, in bytes of the certificate.
- Digital Signature Algorithm of the issuer's signature.
- Identity attributes, read-only:

  | Attribute | Editions |
  | --- | --- |
  | Certificate Identifier, Certificate Subject, Certificate Issuer (text DN and serial) | 1.x |
  | X.509 Certificate Identifier, Subject and Issuer (DER names, serial and alternative names) | 1.1 and later |
  | Subject and issuer CN, O, OU, Email, C, ST, L, UID, Serial Number, Title, DC, DN Qualifier | 2.0, 2.1, 3.0 draft |
  | Subject and issuer DN (RFC 2253 text) | 3.0 draft |

  An empty subject needs subject alternative names. XML cannot carry a NUL
  character in a text name.

### Usage mask

In 2.x and 3.0 an omitted Cryptographic Usage Mask is stored
as 0 (no use). In 1.0–1.4 the X.509 Key Usage extension derives an omitted
mask and limits a supplied one:

| Key Usage | Usage mask |
| --- | --- |
| digitalSignature | Sign, Verify |
| contentCommitment (nonRepudiation) | Content Commitment |
| keyEncipherment | Wrap Key, Unwrap Key |
| dataEncipherment | Encrypt, Decrypt |
| keyAgreement | Key Agreement |
| keyCertSign | Certificate Sign |
| cRLSign | CRL Sign |
| encipherOnly | Encrypt |
| decipherOnly | Decrypt |

A supplied mask that asks for a mapped usage the extension does not grant is
Invalid Field. For example, a CA certificate whose Key Usage is keyCertSign
and cRLSign registers with Certificate Sign and CRL Sign, not with Verify.
Without a Key Usage extension nothing is derived.

### PGP certificates

Certificate Type 2: an RFC 4880 transferable public key, binary or ASCII-armored, at most 64 KiB and 4,096 packets, with a User ID
and no secret-key packets. The primary key's algorithm and length and the
certification signature algorithms are derived; signatures, trust and
revocations are not verified. Validate of a PGP certificate is Feature Not
Supported. A PGP certificate is distinct from a [PGP Key](objects.md#pgp-keys)
object.

## Verifying signatures with a certificate

Signature Verify (1.2+) accepts the identifier of a stored X.509 certificate
and uses its subject key: RSA PKCS#1 v1.5 and PSS, ECDSA and DSA, single-part
or multipart. The certificate must be in a usable state and date window, have
the Verify usage bit, and, if it has a Key Usage extension, include
digitalSignature or nonRepudiation.

A valid signature does not mean the certificate is trusted: use
[Validate](#validate) for that. Signing with a certificate, PGP certificates
and post-quantum certificates are not supported.

## Validate

Validate checks one X.509 chain and returns Validity Indicator Valid (1),
Invalid (2) or Unknown (3). The chain can mix inline certificates and
identifiers of stored certificates, in any order; every certificate given must
be part of the one verified path.

Trust comes only from a separate bundle:

```sh
keytend-kmip-server serve ... --validation-ca /etc/kmip/validation-roots.pem
```

(`KMIP_VALIDATION_CA`). The transport `--ca` is not used for this, and no
operating-system roots are loaded. Without the setting, a well-formed chain
returns Unknown. The bundle holds at most 32 PEM certificates (1 MiB), is read
at startup, and stops startup if malformed. On Kubernetes, mount it with
`extraVolumes` and `extraVolumeMounts` and set `KMIP_VALIDATION_CA` to its
path in `server.env`
([extra files](kubernetes.md#settings-and-extra-files)).

- The optional Validity Date (default now) sets the verification time.
- OpenSSL strict path checking, depth at most 31; at most 32 certificates,
  64 KiB each and 1 MiB together. Keys above 8,192 bits are rejected.
- A stored certificate that is Deactivated or Compromised makes the chain
  Invalid; an archived one must be recovered; a destroyed one is refused.
- No hostname check, no CRL or OCSP, no network fetching.

## Certificate requests

KMIP 2.0 and later (Object Type Certificate Request).

- Register accepts PKCS#10 requests in DER (type 2) or PEM (type 3). The request's
  own signature must verify, and DER must be canonical. CRMF (1) is Feature
  Not Supported; a request that does not parse or verify is Invalid Field.
- Get returns the request as registered, in Key Format Type PKCS#10; a PEM
  request asked for as PKCS#10 is returned as DER.
- Attributes include Digest (SHA-256 of the registered bytes); there is no
  Cryptographic Algorithm or Length.
- Locate, Activate, Revoke and Destroy work as for other objects. 1.x clients
  cannot see these objects.
- Not supported: Import, Create Split Key and Join Split Key of requests.

## Certify and Re-certify

The server issues a certificate only with a CA you have registered. Name the
issuer with a **Certificate Link** in the request attributes, pointing to the
CA certificate. The server follows the links to the signing key:

```text
CA certificate --Public Key Link--> CA public key --Private Key Link--> CA private key
```

Certify succeeds only when:

- the caller owns the CA certificate and both CA keys (grants do not count);
- the CA certificate is an Active X.509 certificate with
  `basicConstraints cA=TRUE`, `keyCertSign` if it has Key Usage, and is within
  its validity period;
- the CA private key matches it, is Active and has the Certificate Sign usage
  bit, and its usage limits allow one more signature;
- the Public Key or (2.0+) stored Certificate Request named by the Unique
  Identifier, if any, is the caller's and is Pre-Active or Active.

Otherwise the result is Permission Denied (Item Not Found for an object the
caller does not own).

Certify takes the request in one of three ways:

- The Unique Identifier names a Public Key and the request is inline. The key
  in the request must equal that public key (Invalid Field otherwise).
- (2.0+) The Unique Identifier names a stored Certificate Request, and no
  inline request is given; both together are Invalid Field.
- (2.0+) An inline request without a Unique Identifier certifies the key in
  the request, and no Public Key Link is created.

| Certify field | Required | Notes |
| --- | --- | --- |
| Unique Identifier | 1.x: yes, or the ID Placeholder; 2.0+: unless a request is given | The public key to certify, or (2.0+) a stored Certificate Request. |
| Certificate Request Type, and Certificate Request (1.x) or Certificate Request Value (2.0+) | yes, unless the Unique Identifier names a stored Certificate Request (then omit both) | PKCS#10 DER (2) or PEM (3), both fields together. CRMF (1) is Feature Not Supported; PGP (4) is reserved from 2.0. |
| Attributes (2.x), Template-Attribute (1.x) | yes | A Certificate Link to the CA certificate. Cryptographic Usage Mask defaults to the public key's. Attributes the certificate determines (such as Cryptographic Algorithm and Length) are ignored; key and replacement Links are refused. |
| Protection Storage Masks | no | 2.0+. |

| Re-certify field | Required | Notes |
| --- | --- | --- |
| Unique Identifier | no (the ID Placeholder); yes in the 3.0 draft | The existing X.509 certificate. |
| Certificate Request Type and value | from 1.1, no | For the same key pair. Without it the subject and alternative names are reused. |
| Certificate Request Unique Identifier | no | 2.0+: a stored Certificate Request instead of an inline one. |
| Offset | no | An Interval that shifts the Activation and Deactivation Dates; with either date given explicitly, Invalid Message. |
| Attributes (2.x), Template-Attribute (1.x) | no | Override the copied attributes; a Certificate Link names another CA. |
| Protection Storage Masks | no | 2.0+. |

### Requests

PKCS#10 DER or PEM, inline or (2.0+) as a stored Certificate
Request. The request's signature must verify. A malformed request is Invalid
Field in 1.x and Invalid CSR (0x2F) from 2.0. Certify without any request is
Feature Not Supported from 1.1 (Invalid Field in 1.0).

### The issued certificate

It is an X.509 v3 end-entity certificate:

- a random 159-bit serial number; subject from the request, issuer from the CA;
- critical `basicConstraints CA:FALSE`; `keyUsage` from the requested
  Cryptographic Usage Mask, or the public key's; subject and authority key
  identifiers;
- `subjectAltName` from the request (DNS, email, URI and IP names); every other
  requested extension is ignored. A mask with Certificate Sign or CRL Sign is
  refused, so the server never issues CA certificates;
- SHA-256 for an RSA CA; SHA-256, SHA-384 or SHA-512 for an EC CA on P-256,
  P-384 or P-521. Subject keys must be RSA of at least 2048 bits or EC on
  P-256, P-384 or P-521;
- valid from now for 365 days unless the request gives dates
  ([validity period](#validity-period)).

It is stored like a registered certificate, linked to the public key and back,
and keeps its Certificate Link to the CA. In the 3.0 draft a certificate
issued from a stored request gets a Certificate Request Link.

### Validity period

KMIP has no validity field, so the server reads the requested lifecycle
dates in the Attributes (2.x) or Template-Attribute (1.x): the Activation
Date sets the certificate's notBefore and the Deactivation Date sets its
notAfter.

| The request gives | notBefore | notAfter |
| --- | --- | --- |
| Neither date | now | 365 days later, cut short at the CA's notAfter |
| Activation Date only | the Activation Date | 365 days later (Re-certify: the existing certificate's length), cut short at the CA's notAfter |
| Deactivation Date only | now | the Deactivation Date |
| Both | the Activation Date | the Deactivation Date |

- The stored certificate gets only the dates the request gives, as given.
  Without an Activation Date it stays Pre-Active, even though its notBefore
  is now, so a client can activate it once its key and links are in place.
  Re-certify with explicit dates copies no other date from the existing
  certificate.
- Without dates, Certify stores neither date, and Re-certify copies the
  existing certificate's dates or shifts them by the Offset, while the new
  certificate runs from now for the existing certificate's length.
- These are Invalid Field, and nothing is issued: a notAfter at or before
  the notBefore (a Deactivation Date that has passed, without an Activation
  Date), an Activation Date at or after the CA's notAfter, and a
  Deactivation Date after it. The server never cuts a requested date short.
- In 1.0, an Activation Date earlier than the request becomes the time the
  request arrived ([lifecycle](lifecycle.md)).

### Re-certify

Re-certify renews a certificate for the same key pair. The request is
optional from 1.1; without it the existing subject and alternative names are
reused. The issuer is the request's Certificate Link, otherwise the existing
one. Attributes are copied, the Name moves to the new certificate,
Replacement and Replaced Object Links are set, the public key's Certificate
Link moves to the new certificate, and an Offset shifts the Activation and
Deactivation Dates. Explicit dates set the new certificate's validity
([validity period](#validity-period)). A certificate can be re-certified
only once.

Certify and Re-certify are refused in Undo batches, because an undone
certificate would remain valid.
