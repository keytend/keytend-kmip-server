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

# Re-Provision

Part of the [feature reference](README.md#feature-reference).

Re-Provision (KMIP 2.0 section 6.1.44, 2.1 section 6.1.48, and the 3.0
draft) replaces the TLS client certificate of the connection that sends it.
The server issues or adopts the new certificate, and the old one is refused
on new connections once the request's message commits. The operation is
offered only when the server runs with a provisioning CA; which editions
define it is in the [support matrix](support-matrix.md). The implementation
is partial: there is no independent client or conformance evidence for it.

- [Turning it on](#turning-it-on)
- [Request forms](#request-forms)
- [Retrieving the new credential](#retrieving-the-new-credential)
- [Refusals](#refusals)
- [Retirement](#retirement)
- [Provisioning CA](#provisioning-ca)
- [Startup log](#startup-log)
- [Lockout recovery](#lockout-recovery)
- [Records, backups and limits](#records-backups-and-limits)
- [Interpretations](#interpretations)

## Turning it on

```sh
keytend-kmip-server serve ... \
  --provisioning-ca provisioning-ca.pem --provisioning-ca-key provisioning-ca.key
```

(`KMIP_PROVISIONING_CA` and `KMIP_PROVISIONING_CA_KEY`; the two go
together, see [configuration](configuration.md#listeners-tls-and-identity).)
Query then lists Re-Provision (53) for KMIP 2.0 and later. As for every
operation, a principal can use it only if its policy entry lists 53. It also
needs Get (10), and the no-parameter form also needs Get Attributes (11):

```json
{"name": "db", "operations": [10, 11, 53]}
```

Use a dedicated sub-CA for provisioning, with `pathLen:0`, and put its
certificate in the `--ca` bundle as well. The CA key is on the server's disk,
so anyone who reads it can mint client certificates for the whole `--ca`
trust. Every certificate the provisioning CA issues copies the subject and
subjectAltName of the certificate it replaces, so it never mints a new
identity.

On Kubernetes, `provisioning.existingSecret` names a Secret with `tls.crt`
and `tls.key` ([Kubernetes](kubernetes.md#settings-and-extra-files)).

## Request forms

The certificate being replaced is the client certificate of the connection,
here called `F`. In every form:

- The new certificate has the subject and subjectAltName of `F`.
- Its key is new: its SubjectPublicKeyInfo differs from `F`'s and from every
  key the principal has had through Re-Provision. Renewing a key that may be
  compromised would hand the new credential to whoever holds it.
- The key has `F`'s algorithm, and for EC the same curve.
- It must pass the listener's own client verification (the
  [listener verifier](#provisioning-ca)) before anything is recorded.
- The objects belong to the certificate principal.
- The ID Placeholder becomes the returned identifier.

| Form | Request payload | The server | Returns |
| --- | --- | --- | --- |
| Certificate request | Certificate Request (Certificate Request Type and Value) | issues a certificate for the request's key | the Certificate's identifier |
| Certificate | Certificate (X.509) | adopts it as the new credential | the Certificate's identifier |
| No parameters | empty | generates a key pair and issues a certificate | the Private Key's identifier |

### Certificate request form

PKCS#10 (type 2) or PEM (type 3), self-signed with
RSA PKCS#1 v1.5 or ECDSA and SHA-224 to SHA-512 (no SHA-1 or MD5; RSA-PSS
requests are refused too). The key is RSA of at least 2048 bits or EC
P-256, P-384 or P-521. The subject, subjectAltName and every other requested
extension are ignored: the request supplies only the key and the proof that
the client holds it. CRMF is Feature Not Supported; a bad request is Invalid
Field.

### Certificate form

The certificate must be X.509 (another Certificate Type is
Feature Not Supported), canonical DER, CA false, carry the clientAuth
Extended Key Usage, have `F`'s subject and subjectAltName set, and pass the
listener verifier with the intermediates the client sent in its handshake. It
must not be `F`, the server's own certificate, a certificate in the policy
file, or one the server has recorded before. An adopted certificate from an
intermediate that the client does not send needs that intermediate in
`--ca`. The server cannot check that the client holds the certificate's
private key: adopting a certificate gives whoever holds its key this
principal's access.

### No-parameter form

The server generates a key pair like `F`'s (RSA with
`F`'s modulus size, 2048 to 4096 bits; EC on `F`'s curve, P-256, P-384 or
P-521) and issues the certificate.

- The Certificate is a normal object of the principal.
- The Private Key exists only for the rest of the message, with Sensitive
  False and Extractable True. The server removes it before the message
  commits, so it never keeps a client's private key: a later Get of its
  identifier fails with Object Not Found.
- No Public Key object is kept. The private key carries a PKCS#12
  Certificate Link to the certificate, so a client learns the certificate
  identifier from Get Attributes of the key.
- Messages run one at a time, so no other connection, other certificate of
  the principal or delegate ever sees the key.

### Issued certificates

Certificates issued for the request and no-parameter forms have CA false, Key
Usage digitalSignature (plus keyEncipherment for RSA), Extended Key Usage
clientAuth, and a validity of 365 days, cut short when the provisioning CA
expires earlier. A client can ask for an earlier notAfter.

### Validity period

The 2.1 and 3.0 draft payloads have no field for it, so the client adds
this server's Message Extension to the Re-Provision batch item:

```text
Message Extension
  Vendor Identification   keytend_kmip_server
  Criticality Indicator   False, or True
  Vendor Extension
    Deactivation Date     the notAfter wanted
```

- It applies to the certificate-request and no-parameter forms. The new
  certificate's notAfter, and the stored certificate's Deactivation Date,
  are that date. notBefore is set as for any issued certificate.
- Invalid Field, and nothing is issued: a date that has passed, a date after
  the provisioning CA's notAfter (never cut short), a Vendor Extension that
  holds anything but one Deactivation Date, two such extensions in one item,
  or the certificate form.
- Non-Critical: a server without this support ignores it and issues the
  default, so check the notAfter of the certificate you receive. Critical: such
  a server rejects the whole message.
- On any other operation the extension is not read: Critical rejects the
  message, Non-Critical is ignored.

## Retrieving the new credential

The certificate-request and no-parameter forms must fetch what they create
in the same message. A later request item must be a Get of the ID
Placeholder (the Unique Identifier omitted in 2.x, or the ID Placeholder
enumeration in 2.x and 3.0):

```text
CSR form:           [Re-Provision(Certificate Request), Get]
No-parameter form:  [Re-Provision, Get, Get Attributes (Link, or 3.0 PKCS#12 Certificate Link)]
```

- Without that Get (and, without parameters, the Get Attributes), the
  Re-Provision item fails with Invalid Field before anything is issued.
- The whole message fails unless a Get of the object succeeds in it and,
  in the no-parameter form, a later item succeeds and returns the
  certificate identifier (the Link). This covers a Get or Get Attributes
  that fails (for example with Response Too Large), a Get Attributes that
  does not ask for the Link, and an item that removes the object first.
  Nothing commits, `F` stays valid, and no item reaches the client. The
  message failure is Invalid Field.
- In the no-parameter form the certificate is public. Fetch it with
  `Get(certificate identifier)` in a later message on the same
  connection, which stays open after the replacement.
- One Re-Provision per message: a second one is Permission Denied, even if
  the first failed.
- After a Re-Provision, only Get, Get Attributes and Get Attribute List may
  follow in its message; any other item is Permission Denied, so nothing in
  the message can remove or change the new credential.

The certificate form needs no retrieval: the client already has the
certificate.

## Refusals

| Situation | Result |
| --- | --- |
| No `--provisioning-ca`, or a 1.x request | Operation Not Supported |
| The policy entry lacks 53, Get (10), or for the no-parameter form Get Attributes (11) | Permission Denied |
| The request is authenticated by a ticket, Login or delegated | Permission Denied |
| [Credential identity](credentials.md#client-identity) is in effect: header credentials of a `"client_identity": "credential"` principal verified | Permission Denied |
| No TLS connection (in-process callers; queued asynchronous batches) | Permission Denied |
| `F` no longer passes the listener verifier (expired, revoked by `--crl`) | Permission Denied |
| `F` was already replaced on this open connection | Permission Denied |
| A second Re-Provision in the same message | Permission Denied |
| Any item other than Get, Get Attributes or Get Attribute List after a Re-Provision in its message | Permission Denied |
| Certificate Request and Certificate together | Invalid Field |
| No retrieval in the message (above) | Invalid Field |
| A key used before, another algorithm or curve, a weak request signature | Invalid Field |
| An adopted certificate that fails a check above | Invalid Field |
| A [validity period](#validity-period) that has passed, ends after the provisioning CA, is malformed, or comes with the certificate form | Invalid Field |
| An issued certificate the listener verifier refuses | Cryptographic Failure |
| More than 1,024 records for the principal (below) | Server Limit Exceeded |
| A Batch Error Continuation Option of Undo | Feature Not Supported |
| Asynchronous Indicator Mandatory | Invalid Field (Optional runs synchronously) |

Send Re-Provision without header credentials. A ticket or a header credential
adds no power here: anyone holding `F`'s key can send the request without
them.

## Retirement

When the message that carries the Re-Provision commits:

- `F` is *retired*. New connections presenting `F` are refused KMIP
  access: the TLS handshake completes and the connection takes the unlisted
  path, one answer with Permission Denied for every item, then the
  connection closes. Metrics count them as `unlisted`.
- The new certificate `N` is *active* for the same principal. It uses the
  policy entry that authorized `F`'s connection (its *anchor*) until you add
  `N` to the policy and remove `F`.
- Tickets that `F` obtained are revoked.
- No open connection is cut off. An open connection on `F` keeps
  working until it closes, but cannot re-provision again or obtain tickets.
- When the replaced certificate was itself provisioned, the old and new
  Certificate objects get Replacement Object and Replaced Object Links.

The store decides first for a new connection's certificate, then the policy
file:

1. A retired fingerprint is refused, even if the policy lists it.
2. An active fingerprint uses the policy entry of its anchor if the anchor is
   still in the policy, otherwise its own entry if you added it. The entry
   must have the recorded principal `name`. A direct entry for `N` under
   another name is a conflict and refuses `N`.
3. Any other fingerprint: the policy alone decides.

If the store cannot be read for this check (for example after a live store
history integrity failure, which also turns readiness to 503), the policy
alone does not admit the certificate: the connection's first request gets
General Failure and the connection closes.

Retirement holds with or without `--provisioning-ca`: removing the flags
stops new Re-Provisions, never revives a retired certificate. There is no
un-retire command.

Fold active fingerprints into the policy. After a Re-Provision, add `N`
under the same `name`, `operations` and grants, and only then remove `F`.
Until then `N` depends on `F`'s entry: deleting `F` from the policy refuses
`N` from the next start. A users file keyed by `F`'s fingerprint needs the
same entries under `N`.

Clients, pods or replicas that share one certificate are all affected when
one of them re-provisions. The others keep the retired certificate and are
refused when they reconnect. Give each client its own
certificate, or do not grant 53 to shared ones.

## Provisioning CA

At startup the server refuses a provisioning CA unless:

- the key matches the certificate, and the key file has no permission bit
  for other users (`o+rwx`);
- the certificate is a currently valid CA (basicConstraints CA:TRUE) with
  the keyCertSign key usage, and RSA or EC;
- it meets the TLS strength rules (no SHA-1 signature, at least 112-bit
  keys) and, in FIPS mode, the FIPS issuer rules
  ([FIPS mode](fips.md#what-fips-mode-refuses));
- it is byte-identical to a certificate in the `--ca` bundle;
- the self-test passes: the server issues a client certificate in memory
  (P-384 under a Suite B 192 profile, P-256 under Suite B 128, otherwise
  RSA-2048) and runs it through the listener verifier.

The *listener verifier* is the handshake's client verification, built from
the same inputs: the `--ca` bundle, `--crl` with revocation checks for every
certificate of the chain, at most 4 intermediates, purpose sslclient, the
curve and strength checks of every chain certificate, and the Suite B rules
of the TLS profile. It re-checks `F` (with the intermediates `F`'s client
sent) and every new certificate. The self-test catches a provisioning CA
that a Suite B profile rejects, and a `--crl` file with no CRL from the
provisioning CA, which would refuse every certificate it issues: add the
provisioning CA's CRL to the file.

## Startup log

Every start lists each provisioning record at info level (state, principal,
anchor, replaced and replacing fingerprints, certificate object, expiry),
and warns about the policy:

| Warning | Meaning and action |
| --- | --- |
| `F anchors active N; add N to the policy under the same name ... before removing F` | `F` is retired but still authorizes `N`. Fold `N` in, then remove `F`. |
| `F was retired by a Re-Provision and is refused; remove it from the policy` | A retired entry no longer serves anything. |
| `N (provisioned for P) is refused: its anchor A is not in the policy` | `N` has neither its anchor nor its own entry. Expected after [lockout recovery](#lockout-recovery); otherwise add `N` under `P`. |
| `N is listed in the policy under X but was provisioned for P: refused (conflict)` | List `N` under `P`, or remove it. |

## Lockout recovery

The server refuses a Re-Provision message that does not deliver the new
credential, but the old certificate is retired when the message commits, so
a client can still be locked out:

- a no-parameter client receives its key, but its connection closes before
  it fetches the public certificate;
- the response is lost after the commit (the connection drops or the client
  stops while reading), in either form.

Retired fingerprints cannot be revived, because the store's refusal
overrides the policy file and there is no un-retire command. Recovery
replaces the credential through the policy instead:

1. Find the principal and the identifiers. The [startup log](#startup-log)
   lists every provisioning record: state, principal, old and new
   fingerprints, and the certificate identifier. The audit chain records the
   Re-Provision item with the identifier it returned.
2. If the client still holds the new private key and another certificate
   is mapped to the same principal `name`, that certificate can Get the
   new certificate by its identifier and hand it over. `N` is already
   active, so no restart is needed. For a single-certificate principal, go
   to step 3.
3. Otherwise, issue a fresh client certificate from a CA in the `--ca`
   bundle (`openssl` or cert-manager, as in
   [TLS setup](tls-setup.md#issuing-them-with-openssl)), and compute its
   fingerprint:

   ```sh
   openssl x509 -in client-new.pem -outform DER | sha256sum | cut -d' ' -f1
   ```

4. Edit the policy file:
   - Copy the old entry under the new fingerprint, keeping the same `name`
     and `operations`, and any `object_grants`, `client_identity` and
     `client_endpoint`.
   - Delete the retired fingerprint `F`. **In this runbook, deleting `F` is
     intended.** `F` is the anchor of `N`, so `N` is refused from the next
     start as well, unless `N` was folded into the policy. That revokes the
     abandoned credential, whose private key the client (or an attacker)
     may still hold.
   - Outside a lockout, never delete an anchoring `F` before folding `N` in
     (the startup warning above).
5. If a [users file](credentials.md#users-file) lists `F`, give the new
   fingerprint the same users and devices and delete `F` there too. The
   server refuses to start when the users file names a fingerprint that is
   not in the policy.
6. Restart the server, because the policy and users file are read only at
   startup:
   - Docker or Compose: `docker restart -t 30 keytend-kmip-server`, or
     `docker compose -f /srv/kmip/compose.yaml up -d --force-recreate`.
   - Kubernetes: change `policy.json`/`policy.existingConfigMap` (and the
     users Secret) and run `helm upgrade`. A chart-managed policy restarts
     the pod; for an existing ConfigMap, or a change to the users Secret
     alone, run `kubectl rollout restart` on the chart's StatefulSet.
7. Check: the principal's objects belong to its `name`, so the client
   sees all of them again with the new certificate. The startup log shows
   `N` as refused (anchor missing), as expected.

## Records, backups and limits

- The server keeps one hidden record per replaced or replacing certificate
  in the store, sealed and authenticated like every object. Clients never
  see them; `check-store` verifies them, `backup` copies them and
  `rotate-master-key` re-seals them. The object census counts them as Object
  Type `unknown`.
- A restore brings back the records as of the backup: it can revive a
  certificate retired after the backup and forget a replacement made after
  it ([backup and restore](backup-restore.md#restore)). Fold active
  fingerprints into the policy so that a restore cannot lock their clients
  out.
- At most 1,024 records per principal, counting active records and
  retired ones whose certificate has not expired; a Re-Provision beyond that
  fails with Server Limit Exceeded. Records of expired certificates are
  dropped at each Re-Provision. A retired record lives until the replaced
  certificate expires, up to 365 days for certificates the server issued, so
  CI that re-provisions one principal several times a day reaches the cap
  within a year: use separate principals, or ask for shorter-lived
certificates ([validity period](#validity-period)).

## Interpretations

| Topic | Reading |
| --- | --- |
| Which credential | "The current client credential" is the TLS client certificate of the connection that carries the request. Re-Provision is refused under any ticket and while credential identity is in effect, because the link credential belongs to the certificate entry and a header credential adds no power. |
| Same-message retrieval (deviation) | 6.1.48 says the client "may then subsequently retrieve the private key via a Get operation". The server supports only the same-message form `[Re-Provision, Get(ID Placeholder), ...]`, for every form that creates something the client must fetch, and for HTTPS, where a second request may arrive on a new connection. A later retrieval would leave a window in which the client has lost `F` without holding `N`. |
| The no-parameter form's private key | It is removed at the end of its message; the server never keeps a client private key. |
| "Made invalid" and "future KMIP requests" | The credential is checked at the TLS handshake, so "future requests" are requests on new connections. The old certificate is refused from the commit of the Re-Provision message on; open connections continue. |
| Subject and alternative names | Never taken from the client. An issued certificate copies them from `F`; an adopted one must match them. |
| Expired, revoked, compromised | The listener verifier re-checks `F` (6.1.48 "SHOULD fail if ... expired", "SHALL fail if ... Revoked" or "compromised"). Revocation and compromise are the CRL's (`--crl`); the KMIP state of a stored copy of the certificate is not consulted, since a client can change it. |
| Error table | The 2.1 table for Re-Provision is captioned "RNG Retrieve Errors" (a copy error). A bad certificate request is Invalid Field, because the table has no Invalid CSR. The record cap is Server Limit Exceeded, which the table does not list. |
| Requested validity | No Re-Provision payload has a field for it, so a vendor Message Extension carries it. Being an extension, a client can send it Non-Critical and still work with a server that ignores it. |
| Validity | An issued certificate's notBefore is set five minutes back (but not before the provisioning CA's), so a verifier whose clock trails the server's accepts it at once. |
| 3.0 draft | Re-Provision is offered in the draft too, with the same payload and rules as 2.1. |
| Undo | Refused with Feature Not Supported, as for Certify and Re-certify: the issued certificate is already in the response and cannot be rolled back. |
