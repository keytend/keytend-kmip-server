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

# Documentation

| To | Start with | Then |
| --- | --- | --- |
| Evaluate | [Project status](status.md) | [Support matrix](support-matrix.md), [security](../SECURITY.md) |
| Run locally | [Quick start](quick-start.md) | [Manual installation](manual-install.md) |
| Connect an application | [Connecting a client](clients.md) | [Client errors and retries](client-errors.md) |
| Deploy and operate | [Deployment](deployment.md) or [Kubernetes](kubernetes.md) | [Configuration](configuration.md), [runbooks](operations.md) |

## Getting started

- [Quick start](quick-start.md): run a server and make a first request
  ([by hand, changing a setting, or from source](manual-install.md)).
- [Connecting a client](clients.md): what a client needs, with examples for
  [Python](clients/python.md), [Go](clients/go.md), [Java](clients/java.md),
  [C](clients/c.md), [Rust](clients/rust.md) and
  [HTTPS with JSON or XML](clients/https.md) (the rules:
  [JSON, XML and HTTPS bindings](encodings.md));
  [errors and retries](client-errors.md).
- [Project status](status.md) and the [support matrix](support-matrix.md):
  what is supported, tested and missing, per KMIP edition.

## Common tasks

> [!TIP]
> Three different keys can be rotated: an application key that KMIP clients
> use ([Re-key](rekey.md)); the server's own master key, which encrypts the
> store ([master-key rotation](master-key-rotation.md)); and a database's
> master key held in this server, such as Percona's `--kmipRotateMasterKey`
> ([Percona](percona.md)).

In an application:

| Task | Also |
| --- | --- |
| [Create and fetch a key](quick-start.md#make-a-request-with-curl) | [register an existing key](clients/python.md#common-tasks) |
| [Find a key by Name](clients/https.md#locate-by-name) | [Go](clients/go.md#find-a-key-by-name) |
| [Encrypt and decrypt on the server](clients/https.md#encrypt-and-decrypt-with-aes-gcm) | [Python](clients/python.md#server-side-encrypt-over-https-json), [Go](clients/go.md#create-encrypt-and-retire-a-key), [Java](clients/java.md#binary-kmip) |
| [Sign and verify with an RSA key pair](clients/https.md#sign-and-verify-with-rsa) | [ECDSA with Java](clients/java.md#sign-and-verify) |
| [Derive a key with HKDF](crypto-operations.md#example-derive-a-key-with-hkdf-over-https) | |
| [Fetch a Sensitive key wrapped under another key](key-transfer.md#example-fetch-a-sensitive-key-wrapped) | |
| [Set and read an attribute](attributes.md#example-set-and-read-an-attribute) | |
| [Revoke and destroy a key](clients/https.md#retire-a-key-in-one-batch) | |
| [Rotate an application key with Re-key](rekey.md) | [Python](clients/python.md#common-tasks) |
| [Export and import keys](key-transfer.md#import-and-export) | |
| [Turn on request-header credentials](credentials.md) | [Python](clients/python.md#request-header-credentials) |

Running the server:

| Task | Also |
| --- | --- |
| [Issue server and client certificates](tls-setup.md#issuing-them-with-openssl) | [cert-manager](tls-setup.md#issuing-them-with-cert-manager), [revoke with a CRL](tls-setup.md#crl) |
| [Run it with Docker Compose](deployment.md#docker-compose) | [upgrade it](operations.md#upgrading-with-compose) |
| [Install on Kubernetes with Helm](kubernetes.md#install) | `helm test`, [check a client certificate](kubernetes.md#client-namespaces) with [`kmip-check.yaml`](../deploy/kubernetes/tools/kmip-check.yaml) |
| [Reach the server from outside Kubernetes](kubernetes.md#clients-outside-the-cluster) | [allow Notify and Put delivery](server-to-client.md#configuration) |
| [Add or move the health check](deployment.md#health-check) | |
| [Add a client or change its operations](operations.md#changing-the-policy) | [role templates](configuration.md#role-templates) |
| [Rotate a client certificate](operations.md#rotating-a-client-certificate) | [the client CA](operations.md#rotating-the-client-ca) |
| [Recover a client locked out by Re-Provision](re-provision.md#lockout-recovery) | [after a Re-Provision, add the new certificate to the policy](operations.md#re-provision-and-lockout-recovery) |
| [Renew the server certificate or CRL](operations.md#renewing-server-certificates-and-crls) | |
| [Back up](backup-restore.md#back-up) | [schedule](backup-restore.md#scheduled-backups-with-docker), [restore](backup-restore.md#restore), [recover onto a new host](backup-restore.md#recover-onto-a-new-host-or-namespace) |
| [Back up and restore on Kubernetes](backup-restore.md#on-kubernetes) | [run a backup now](backup-restore.md#scheduled-backups-on-kubernetes), [restore with `helm upgrade`](backup-restore.md#restore-on-kubernetes) |
| [Rotate the master key](master-key-rotation.md) | [on Kubernetes](master-key-rotation.md#on-kubernetes), [if it fails](master-key-rotation.md#if-the-docker-rotation-fails) |
| [Export an audit checkpoint](audit-checkpoints.md#export-a-checkpoint) | |
| [Monitor the server](metrics.md#alerts) | |
| [See which version and settings are running](configuration.md#logging) | [`kmip_build_info`](metrics.md#build-and-process) |
| [Upgrade](operations.md#upgrading) | [on Kubernetes](operations.md#upgrading-on-kubernetes), [troubleshoot](operations.md#troubleshooting) |
| [Stop the server for node maintenance](kubernetes.md#availability-and-node-maintenance) | |
| [Verify a release](release-signing.md#verifying-a-release) | |

## Configuration and operations

| Page | Covers |
| --- | --- |
| [Configuration reference](configuration.md) | Commands, every `serve` setting, endpoints, the policy file, limits, logging |
| [Authorization](authorization.md) | Ownership, object grants, tenant isolation |
| [Request-header credentials](credentials.md) | Users, devices, Hashed Password, One Time Password |
| [TLS profiles](tls-profiles.md) | The TLS policies and when to choose them |
| [JSON, XML and HTTPS bindings](encodings.md) | Media types, HTTP status codes, response forms |
| [Deployment](deployment.md) | Inputs, master key, Docker, Podman, Compose |
| [Kubernetes](kubernetes.md) | The Helm chart: install, settings, external clients, monitoring, node maintenance |
| [Operations runbooks](operations.md) | Health, policy and certificate changes, upgrades, incidents |
| [Backup and restore](backup-restore.md) | Backups, schedules and restores, with Docker and the Helm chart |
| [Master-key rotation](master-key-rotation.md) | Re-encrypting the store under a new master key |
| [Metrics](metrics.md) | Prometheus metrics, connection counters, scraping, alerts |
| [Container image](container-image.md) | Image contents, licences, scanner findings |
| [FIPS mode](fips.md) | The OpenSSL FIPS provider and what FIPS mode refuses |

## Security

| Page | Covers |
| --- | --- |
| [Security](../SECURITY.md) | Reporting, threat model, hardening checklist |
| [TLS certificates and policy](tls-setup.md) | Issuing certificates, the policy, CRLs |
| [Store integrity](store-integrity.md) | How the store proves records current and detects a swapped database |
| [Audit checkpoints](audit-checkpoints.md) | Protecting the store against rollback across restarts |
| [Release verification](release-signing.md) | Signatures, checksums, copying to a registry, provenance and SBOM |

## Feature reference

What works in which KMIP edition, which setting controls it, and what is not
supported. The [support matrix](support-matrix.md) links each operation to its
page.

| Page | Covers |
| --- | --- |
| [Object types](objects.md) | Secret data, opaque objects, PGP keys, templates, split keys |
| [Algorithms and key formats](algorithms.md) | AES, HMAC, ChaCha20, 3DES, RSA, DSA, curves, post-quantum keys |
| [Cryptographic operations](crypto-operations.md) | Encrypt, Decrypt, Sign, MAC, Hash, RNG, Derive Key, streaming |
| [KMIP certificate objects](certificates.md) | Storing, verifying, validating, requesting and issuing certificates as KMIP objects (TLS certificates: [TLS setup](tls-setup.md)) |
| [Getting and transferring keys](key-transfer.md) | Get, key wrapping, Import and Export |
| [Object lifecycle](lifecycle.md) | States and dates, Revoke, Destroy, usage limits, leases, usage masks |
| [Re-key](rekey.md) | Re-key and Re-key Key Pair |
| [Attributes](attributes.md) | Reading and changing attributes, names, links |
| [Locate](locate.md) | Filters, dates, storage status, group members |
| [Messages, batches and Query](messages.md) | Batches, Undo, response size, asynchronous requests |
| [Notify, Put and Set Endpoint Role](server-to-client.md) | Server-to-client delivery |
| [Login and tickets](tickets.md) | Login, Logout, Delegated Login, Ticket credentials |
| [Server defaults and constraints](defaults-and-constraints.md) | Set Defaults, Set Constraints, Get Constraints |
| [Re-Provision](re-provision.md) | Replacing a client's TLS certificate |
| [KMIP 3.0 draft](kmip-3.0.md) | System objects, Login, Obliterate, constraints |
| [Specification interpretations](interpretations.md) | Compatibility settings; how ambiguous KMIP rules are read |

## Integrations

- [Percona database encryption](percona.md): MongoDB and MySQL configuration.

## Contributing

- [Testing](testing.md): building from source, the test suites and the image.
- [Interoperability adapters](../interop/README.md): the client programs the
  test suites run.
- [Release builds](release-builds.md): what a release set contains and how it
  is built.
