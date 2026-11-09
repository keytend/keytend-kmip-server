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

# Project status

Part of [getting started](README.md#getting-started).

keytend-kmip-server is **a test server, not for production use**. It is meant for CI systems and for validating KMIP clients and implementations.
It stays a test server at 1.0 and beyond. It is not a complete implementation of any
KMIP edition, holds no conformance certification, has had no independent
security audit, and claims no FIPS 140-3 validation.

- [What works](#what-works)
- [Operations per edition](#operations-per-edition)
- [What has been tested](#what-has-been-tested)
- [Known gaps](#known-gaps)
- [Running the checks](#running-the-checks)

## What works

| Area | Supported |
| --- | --- |
| Protocol versions | KMIP 1.0–1.4, 2.0 and 2.1; the 3.0 draft (CSD02, 7 May 2026) only with `--experimental-v3`. Not every operation, object or attribute of a version is implemented. |
| Transports | Binary TTLV over TLS (5696); optional HTTPS with TTLV, JSON or XML bodies (5697: `--https-listen`, on in the supplied Kubernetes resources). Mutual TLS on both; no plaintext mode. |
| Objects | Symmetric keys; RSA and EC key pairs; X.509 and PGP certificates; secret data; opaque objects; split keys; PGP keys; certificate requests (2.0+); 1.x templates; ML-KEM, ML-DSA and SLH-DSA keys (3.0 draft). |
| Cryptography | AES (ECB, CBC, CFB, OFB, CTR, GCM), ChaCha20, ChaCha20-Poly1305, HMAC, AES-CMAC, RSA, ECDSA, SHA-1/2/3, key wrapping and derivation, multipart; 3DES if enabled ([algorithms](algorithms.md)). |
| Access control | Client certificate fingerprint mapped to a principal and an operation allowlist; per-principal ownership; exact-object read grants; optional request-header credentials; Login and delegated tickets (in memory); optional certificate replacement by Re-Provision. |
| Storage | One SQLite database, objects encrypted with AES-256-GCM under a 32-byte master key; HMAC-chained audit log; online backup; master-key rotation; optional audit checkpoints. |
| Deployment | UBI 9 micro image (amd64, arm64) running as UID 10001; a [Helm chart](kubernetes.md) for Kubernetes (one replica, scheduled backups, and restore, master-key rotation and maintenance mode set through Helm values); Prometheus metrics; FIPS mode using the RHEL 9 OpenSSL FIPS provider. |

The [support matrix](support-matrix.md) lists every operation and object type
per edition, each linked to the page that says what is and is not
implemented, and the attributes a new key reports. How attributes are read
and changed is in [attributes](attributes.md).

## Operations per edition

Operations offered by default, per edition, as Query reports them; the count
leaves out the opt-in operations. Every handler is partial: it
implements the operation for the supported objects and parameters, not every
case the specification describes.

| Edition | Offered by default | Opt-in | Not implemented |
| --- | --- | --- | --- |
| 1.0 | 26 of 28 | Notify, Put | |
| 1.1 | 28 of 30 | Notify, Put | |
| 1.2, 1.3 | 39 of 41 | Notify, Put | |
| 1.4 | 41 of 43 | Notify, Put | |
| 2.0 | 49 of 53 | Notify, Put, Interop, Re-Provision | |
| 2.1 | 55 of 59 | Notify, Put, Interop, Re-Provision | |
| 3.0 draft | 62 of 66 | Interop, Re-Provision | Notify, Put |

Opt-in operations are implemented but offered only when configured: the
server sends Notify and Put only to principals with a `client_endpoint`
([Notify and Put](server-to-client.md)), offers Interop only with
`--interop-test-mode`, which KMIP forbids on a production server, and offers
Re-Provision only with `--provisioning-ca` ([Re-Provision](re-provision.md)).

Login tickets ([Login and tickets](tickets.md)), server defaults and
constraints ([server defaults and constraints](defaults-and-constraints.md))
and Re-Provision have engine and process tests only: no independent client
in the tested set has an API for them, and no OASIS test trace exercises
them.

## What has been tested

The project's own tests cover the areas below. They record which operations
and versions each client and suite exercises. They are not a conformance
result. Results are in each release's [test reports](testing.md#test-reports).

| Area | What the tests cover |
| --- | --- |
| Unit and engine tests (`cargo test`) | Every edition, operation handler and store path |
| Six independent client libraries and the keytend-kmip Java client ([versions](clients.md#tested-clients)) | The operations each client exercises against a running server |
| Percona Server for MongoDB 8.0 and MySQL 8.4 | The [tested scope](percona.md#what-was-tested); the MySQL component does not verify the server by default and does not reconnect after an idle close ([notes](percona.md#percona-server-for-mysql)) |
| OASIS Profiles XML test traces, 1.3 to 3.0 | Strict replay, and replay with the variations the Profiles permit ([trace replay](testing.md#oasis-trace-replay)) |
| FIPS mode (RHEL 9 OpenSSL FIPS provider) | The same tests with the FIPS provider, where only the refusals FIPS requires may differ ([FIPS](fips.md)) |
| Container image (amd64, arm64) and Helm chart | Image hardening checks ([findings](container-image.md#reviewed-findings)); the chart's install, test, backup, upgrade, restore, rotation and maintenance workflows on single-node kind; multi-node, NetworkPolicy enforcement, cert-manager and Prometheus Operator resources are not tested |

The clause-level [requirement matrix](specs/requirement-matrix.json) of the
pinned KMIP documents is incomplete; many clauses are open.

## Known gaps

- Incomplete KMIP semantics: remaining attributes, mechanisms, Locate filters,
  asynchronous operations, and the operations above.
- One local SQLite store and one replica: no high availability, replication
  or failover.
- No HSM or external key sealing; the master key is a file.
- No remote audit witness: audit checkpoints must be retained by the operator.
- No per-request access log ([logging](configuration.md#logging)).
- No hot reload of TLS material, CRLs or policy; changes need a restart.
- No per-tenant rate or size quotas beyond the [fixed limits](configuration.md#fixed-limits).
- Best-effort zeroization only; no memory locking or protection from a
  privileged host. The [object cache](configuration.md#object-cache) keeps
  recently used keys in memory (`--object-cache-mib 0` turns it off).
- The container image carries open scanner findings ([container image](container-image.md#reviewed-findings)).
- Throughput and capacity are not measured or qualified; the
  [fixed limits](configuration.md#fixed-limits) are denial-of-service bounds.
- Production storage, CNI and database topologies are not qualified.

## Running the checks

```sh
python3 scripts/support_matrix.py --check   # the support matrix matches the server
python3 scripts/oasis_conformance.py        # strict OASIS trace replay
```

Both build the server first (`--skip-build` uses an existing
`target/debug` build). `oasis_conformance.py --report-only` records every
outcome without failing. How to run the full test suite is in
[testing](testing.md).
