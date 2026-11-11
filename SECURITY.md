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

# Security

keytend-kmip-server is an experimental KMIP test server for CI systems and
for validating KMIP clients and implementations. It is not for production
use, and it stays a test server at 1.0 and beyond. It has not had an independent security audit, FIPS 140-3 validation or OASIS conformance certification
([project status](docs/status.md)).

## Reporting a vulnerability

Report it privately on GitHub:
[Report a vulnerability](https://github.com/keytend/keytend-kmip-server/security/advisories/new),
also on the repository's Security tab. The report becomes a draft security
advisory that only you and the maintainer can see. It is discussed and fixed
there, and the advisory is published from it.

Do not open a public issue. Include the affected version or commit, a
synthetic reproducer and the impact; never include real keys, master keys or
database key material. There is no security-response time commitment yet.

### Supported versions

Fixes go into the next release candidate; no older release line is
maintained.

## Threat model

### What the server protects

Managed keys at rest (every object record is encrypted with AES-256-GCM under
the master key, bound to its owner and identifier); each principal's objects
from other principals; and the integrity of the store and its audit history
(an HMAC-chained audit log, an
[authenticated object index](docs/store-integrity.md), and optional external
[audit checkpoints](docs/audit-checkpoints.md) that reject rollback to an
older store).

### Trust boundaries

| Boundary | Who is trusted | Consequence of compromise |
| --- | --- | --- |
| Client CA (`--ca`) | Whoever can issue certificates from it | Can issue certificates that complete the TLS handshake; the policy refuses each new fingerprint until it is listed. |
| Policy file | Whoever can change it (and restart the server) | Can map any trusted certificate to any principal and operations, and so read or change every principal's objects. |
| Users file (`--users`) | Whoever can change it (and restart the server) | Can add or replace the users and devices behind a listed certificate, and so pass the header-credential checks within that certificate's principal. |
| A listed client's private key | That client | Acts as that client's principal with its operations until the fingerprint is removed from the policy (or, with `--crl`, the certificate is revoked). |
| A delegated ticket | Whoever holds its value | Any listed certificate that presents it acts as the delegator, within the ticket's Rights, until it expires (at most 24 hours), is logged out, or the delegator's certificate is re-provisioned ([delegated tickets](docs/tickets.md#delegated-login)). |
| Provisioning CA key (`--provisioning-ca-key`) | Whoever can read the key file | Can issue certificates that chain to `--ca`; this server accepts only fingerprints its policy or Re-Provision records name, but other services that trust the CA may accept them ([Re-Provision](docs/re-provision.md)). |
| Master key | Whoever can read the key file | With the database, it reveals every managed key and allows forging audit records and checkpoints. |
| Database file and backups | Key material and attributes are encrypted; some metadata is not (below) | Without the master key: no key material or attributes. Backups keep destroyed keys. |
| Health port (8080) | Unauthenticated plain HTTP, on all interfaces by default | Exposes readiness, `/metrics` and `/connection-metrics`: aggregate counts only. |
| Kubernetes namespace administrators | Anyone who can read Secrets, use `pods/exec` or mount the PVC in the server's namespace | Can read the master key and the store, and so every managed key. |
| Host and container runtime | Fully trusted | A privileged host can read process memory and the master key. |

Use a dedicated client CA. The health port's counts never include key
material or identifiers. Readable in the database without the master key:
object identifiers, owner principal names, the number of objects, and each
audit record's time, principal, operation number, object identifier and
result.

### Out of scope

A compromised host, hypervisor or container runtime; memory dumps (zeroization
is best-effort, memory is not locked, and the
[object cache](docs/configuration.md#object-cache) keeps recently used keys in
memory unless it is turned off); HSM-backed or external sealing of the
master key (not implemented); keys a client has already retrieved or cached,
which revocation cannot recall; denial of service beyond the
[fixed limits](docs/configuration.md#fixed-limits).

## Controls

- Mutual TLS on every KMIP connection. By default TLS 1.2 and 1.3 with
  FIPS-approved choices only: ECDHE on P-256, P-384 or P-521 with AES-128-GCM
  or AES-256-GCM, and SHA-2 handshake signatures. Under every profile, keys
  below 112-bit strength (RSA under 2048 bits) and certificate signatures with
  SHA-1 or weaker are refused, except a self-signed root's own signature
  (NIST SP 800-131A;
  [keys and signatures](docs/tls-setup.md#client-certificates)). Legacy
  [TLS profiles](docs/tls-profiles.md) must be selected explicitly.
- Certificate fingerprint and operation allowlists;
  [ownership isolation](docs/authorization.md#tenant-isolation-and-names);
  exact-object [read grants](docs/authorization.md#object-grants); optional
  CRL checking ([`--crl`](docs/configuration.md#listeners-tls-and-identity)).
- Bounded parsing, message sizes, batches and connections.
- Encrypted object records and an HMAC-authenticated audit chain, changed
  atomically, with a live check against database replacement; consistent
  backups; snapshot-based master-key rotation.
- No per-request access log: the audit chain records each operation, but no
  command exports it ([logging](docs/configuration.md#logging)).
- Non-root container without shell or package manager; restricted Kubernetes
  resources with a default-deny NetworkPolicy.
- Optional FIPS mode with the RHEL 9 OpenSSL FIPS provider in the image:
  non-approved services are refused (not validated; [FIPS mode](docs/fips.md)).

Setting these up: certificates and the policy in
[TLS certificates and policy](docs/tls-setup.md), the policy format
and role templates in [configuration](docs/configuration.md#policy-file).

## Hardening checklist

### TLS, identity and protocol

- [ ] Use a dedicated client CA (or intermediate) for KMIP clients only, and
      never deploy the test CA, certificates or policy from `scripts/dev-pki.sh`.
- [ ] Give each database or application its own principal and the least
      operations it needs ([role templates](docs/configuration.md#role-templates)):
      grant Revoke (19) and Destroy (20) only to roles that remove keys
      (Percona Server for MySQL does), Import (42) only to restore procedures,
      and Interop (52) to none. Set Defaults (54) and a 2.1 Set Constraints (55)
      change settings for every principal: grant both only to an
      administrative certificate. Constraints are not an access control:
      1.x and 2.0 requests and later attribute changes are not
      constrained. Grant Delegated Login (47) only to principals that hand
      out access, and Re-Provision (53) only to clients that rotate their
      own certificate.
- [ ] Keep `--interop-test-mode` and `--experimental-v3` off and `--triple-des disabled`.
- [ ] With `--provisioning-ca`, use a dedicated sub-CA (pathLen 0) that also
      appears in `--ca` and signs nothing else, and keep its key file
      readable only by the server. Give each replica its own client
      certificate ([retirement](docs/re-provision.md#retirement)).
- [ ] Keep `--tls-profile modern` unless a client needs another profile; the
      legacy profiles (`kmip-2-basic-tls12`, `kmip-1-tls12`, `kmip-1-basic`)
      enable static-RSA suites without forward secrecy
      ([TLS profiles](docs/tls-profiles.md)).
- [ ] Bind `--health-listen` to a management address, or keep port 8080 on a
      management network: it serves `/metrics` and `/connection-metrics`
      without authentication, as well as health. `--metrics off` removes
      `/metrics` but not `/connection-metrics`. The supplied resources do
      this: Compose and `docker run` publish 8080 on `127.0.0.1` only, and
      the Kubernetes NetworkPolicy admits 8080 only from scrapers labelled
      for it (enforced only by a CNI that supports NetworkPolicy).
- [ ] Set `--max-connections` and `--idle-timeout` for your client count, so
      idle connections cannot hold every slot.
- [ ] Monitor the server certificate's and the CRL's expiry from outside the
      server (no metric reports them), and restart after each renewal
      ([renewing certificates](docs/operations.md#renewing-server-certificates-and-crls)).
- [ ] Configure a CRL if client certificates may need revoking before expiry,
      and remove a retired certificate's fingerprint from the policy and the
      users file. Rotate a client certificate under the same principal name
      ([rotating a client certificate](docs/operations.md#rotating-a-client-certificate)).
- [ ] Size `--max-lease-seconds` to the outage you must survive and the
      revocation delay you accept ([leases](docs/operations.md#lease-time-and-kms-outages)).

### Keys, storage and the image

- [ ] Store and back up the master key separately from the database and its
      backups, and keep it recoverable without the keys it protects.
- [ ] Keep the master key (`/srv/kmip/master`, or the master-key Secret) out
      of the backups that hold the database: a job that copies all of
      `/srv/kmip`, or the whole namespace, captures both.
- [ ] Review the owner, group and ACLs of the master key and the database:
      the server refuses only permission bits for other users
      ([storage](docs/configuration.md#storage)).
- [ ] Expire backups on a schedule: a backup keeps every key that existed
      when it was taken, including keys destroyed later.
- [ ] Rehearse a [master-key rotation](docs/master-key-rotation.md) on a
      copy of the store before you need one; it needs a downtime window.
- [ ] Test [restores](docs/backup-restore.md#restore) regularly.
- [ ] Export [audit checkpoints](docs/audit-checkpoints.md) to independent
      storage and start with `--audit-checkpoint`.
- [ ] Pull the image by digest after [verifying the release](docs/release-signing.md#verifying-a-release).
- [ ] Run the [acceptance check](#acceptance-check) after deploying and
      after every policy change.

### Kubernetes

- [ ] Deliver the master key from an external secret manager where you have
      one (for example through a CSI secrets driver); otherwise enable Secret
      encryption at rest.
- [ ] Use a CNI that enforces NetworkPolicy.
- [ ] Restrict Secret access, `pods/exec`, creating pods and Jobs, and PVC
      access in the `keytend-kmip-server` namespace to the operators who hold
      the master key: the backup Job and the volume helper read the whole
      store, and the backup PVC holds copies of it.

### Acceptance check

Against the deployed server, from a host on the clients' network, with the
[HTTPS helpers](docs/clients/https.md) and three test certificates from your
client CA: `app`, listed in the policy with Create and Get; `other-app`,
listed under another principal with Get; and `unlisted`, not in the policy.
Put them and the CA that issued the server certificate (as `ca.pem`) in one
directory:

```bash
. examples/https/kmip.sh
export KMIP_URL=https://kmip.example.com:5697/kmip KMIP_PKI=$HOME/kmip-acceptance
# expect TAG VALUE...: pass when TAG in the response on standard input is one of the VALUEs
expect() {
  local tag=$1 got; shift
  got=$(field "$tag") || return 1
  for want; do [ "$got" = "$want" ] && { echo "ok: $tag $got"; return 0; }; done
  echo "FAIL: $tag is $got, expected $1" >&2; return 1
}
(
  set -e
  R=$(KMIP_CLIENT=app kmip create.json)
  expect ResultStatus Success 0x00000000 <<<"$R"
  ID=$(field UniqueIdentifier <<<"$R")
  # the key exists, so Object Not Found for other-app below is isolation
  KMIP_CLIENT=app kmip get.json ID="$ID" | expect ResultStatus Success 0x00000000
  KMIP_CLIENT=unlisted kmip create.json | expect ResultReason PermissionDenied 0x0000000c
  KMIP_CLIENT=other-app kmip get.json ID="$ID" | expect ResultReason ObjectNotFound 0x00000037
  # the health port must not answer outside the management network
  if curl -sS -m 5 -o /dev/null http://kmip.example.com:8080/readyz; then
    echo "FAIL: the health port answers from this network" >&2; exit 1
  fi
  echo "acceptance check passed; created $ID"
)
```

It stops at the first unexpected result, with a non-zero exit status. Each
result is accepted by name or as the hex value that the default `compatible`
[response form](docs/configuration.md#json-and-xml-response-forms) returns.
The key it creates stays in the store; destroy it if the `app` role may.
Without the HTTPS listener, make the same calls with your client library.

## Release signatures

`scripts/verify_release.sh VERSION` checks the cosign signature of a
release's `SHA256SUMS` and its OpenPGP signature by the Keytend release key,
then every digest
([release verification](docs/release-signing.md#verifying-a-release)). How
releases are built: [release builds](docs/release-builds.md).
