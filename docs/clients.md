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

# Connecting a client

Part of [getting started](README.md#getting-started).

How a KMIP client connects and authenticates to keytend-kmip-server, which
libraries have been tested, and the server behaviour client code must handle.
The examples use the test certificates and server from the
[quick start](quick-start.md). Errors, their fixes and when a request is safe
to repeat are in [client errors and retries](client-errors.md).

- [What a client needs](#what-a-client-needs)
- [Examples by language](#examples-by-language)
- [Notes for client authors](#notes-for-client-authors)
- [Beyond the test setup](#beyond-the-test-setup)
- [Tested clients](#tested-clients)

## What a client needs

| Item | Requirement |
| --- | --- |
| Endpoint | Binary KMIP on port 5696, or `POST https://<host>:5697/kmip` when the HTTPS listener is on ([endpoints](configuration.md#endpoints)). |
| Server trust | The CA that issued the server certificate. Verify the hostname: the server certificate must list the DNS name or IP the client dials. |
| Client certificate | A certificate with the `clientAuth` extended key usage, issued by a CA in the server's `--ca` bundle (through at most 4 intermediate CAs), and its private key. |
| Authorization | The certificate's SHA-256 fingerprint in the server's [policy](configuration.md#policy-file), with the operations the client calls. Objects belong to the policy's principal, not to the certificate. |
| TLS | TLS 1.2 or 1.3, ECDHE with AES-GCM on P-256, P-384 or P-521 (default `modern` policy; [TLS profiles](tls-profiles.md)). |
| Protocol version | KMIP 1.0–1.4, 2.0 or 2.1. Clients that negotiate use Discover Versions (1.1 and later). The 3.0 draft is off unless the server runs with `--experimental-v3`. |
| JSON and XML | Responses use hex enumeration codes by default (`0x00000000` is Success); `--text-encoding readable` writes names. Requests may use either ([forms](encodings.md#response-forms)). |

Optional request-header credentials (username and password, device) are
checked on top of the certificate when the server has a
[users file](credentials.md#users-file); the
[Python page](clients/python.md#request-header-credentials) has a complete
example.

## Examples by language

Pick by the KMIP version and transport you need:

- For binary KMIP 2.x, use Java ([keytend-kmip](clients/java.md)), or C with
  [IBM libkmipclient](#tested-clients). libkmipclient has no page here, but
  [`integration/ibm/client.c`](../integration/ibm/client.c) is the program the
  project's tests run with it.
- For binary KMIP 1.x, use the Python, Go, C or Rust libraries below.
- From any language, use [HTTPS with JSON or XML](clients/https.md), KMIP
  1.0–2.1.

Each page runs complete programs against the quick-start server and shows
their output. The programs, with their dependency manifests, are in
[`examples/clients`](../examples/clients) (one directory per language); the
HTTPS request files are in [`examples/https`](../examples/https).

| Page | Library | KMIP | Covers |
| --- | --- | --- | --- |
| [Python](clients/python.md) | PyKMIP; standard library | 1.1–1.4, binary; 2.1, HTTPS | Create/Get, Locate by Name, Register, Re-key, Revoke/Destroy, header credentials, AES-GCM, errors |
| [Go](clients/go.md) | OVH kmip-go | 1.0–1.4, binary | Create/Get, find or create by Name, AES-GCM, Revoke/Destroy, errors |
| [Java](clients/java.md) | keytend-kmip | 1.1–2.1, binary and HTTPS | AES-GCM, find or create by Name, ECDSA and RSA Sign/Verify, HTTPS, errors |
| [C](clients/c.md) | OpenKMIP libkmip | 1.0–1.4, binary | Create/Get/Destroy, errors |
| [Rust](clients/rust.md) | NLnet Labs kmip-protocol | 1.0–1.2, binary | Create/Get, Revoke/Destroy, errors |
| [HTTPS with JSON or XML](clients/https.md) | any (`curl`) | 1.0–2.1 | The JSON message, Create/Get, XML, Locate by Name, batches, AES-GCM, RSA Sign/Verify, binary TTLV |

Which operations each KMIP version offers is in the
[support matrix](support-matrix.md).

## Notes for client authors

### Connections

- Reuse one TLS connection for many requests; each connection is a full
  mutual-TLS handshake and policy check.
- The server closes a connection that has been idle for `--idle-timeout`
  (default 300 seconds), and on restart. Reconnect on the next request, and
  retry only what is safe to repeat
  ([retrying](client-errors.md#retrying-after-a-lost-response)).
- One connection carries one request at a time: the server reads a request,
  answers it, then reads the next. Callers that share a connection must take
  turns; for parallel requests, open more connections.
- The store processes one request at a time across all connections, so more
  connections add little throughput. All clients share `--max-connections`
  (default 64) across both KMIP listeners; connections above it wait. Keep
  pools small and close idle connections.

### Leases and Lease Time 0

Lease Time 0 means no lease limit, not an expired lease: a server started
with `--max-lease-seconds 0` reports 0 on every new object, and a client that
treats 0 as "expired" refuses every key there. Lease rules and how to choose
the Lease Time: [leases and KMS outages](operations.md#lease-time-and-kms-outages).

### Result reasons that differ by version

The same refusal can carry different Result Reasons in 1.x, 2.0 and 2.1: an
operation refused by the object's state is Permission Denied in 1.x and
mostly Wrong Key Lifecycle State in 2.x ([refusals by state](lifecycle.md#refusals-by-state)),
and a duplicate Name in 1.x is Invalid Field or Illegal Operation depending on
the operation ([names](attributes.md#duplicate-names-in-kmip-1x)). Match on
the reason for the version you negotiate.

## Beyond the test setup

What changes from the quick start's test setup to a real server:

| Setting | Quick start | Real deployment |
| --- | --- | --- |
| Host | `localhost` | A DNS name or IP in the server certificate ([certificates](tls-setup.md)) |
| CA the client trusts | `ca.pem`, which signed every test certificate | The CA that issued the server certificate, which can differ from the client CA in `--ca` |
| Client certificate and key | `client` | One per application, with its fingerprint in the [policy](configuration.md#policy-file) |
| Operations | All operation numbers (1–66) | Only those the client calls ([role templates](configuration.md#role-templates)) |
| JSON and XML enumerations | Names (`Success`), from `--text-encoding readable` | Hex codes (`0x00000000`) unless the server sets `readable` ([response forms](configuration.md#json-and-xml-response-forms)) |

Where each example sets the host, CA and client certificate:
[Python](clients/python.md#connection-settings),
[Go](clients/go.md#create-encrypt-and-retire-a-key) (`DialContext`),
[Java](clients/java.md#connection-settings),
[C](clients/c.md#create-and-get) (the address and the `SSL_set1_host` name
are separate settings), [Rust](clients/rust.md#connection-notes) and
[HTTPS](clients/https.md) (`KMIP_URL`, `KMIP_PKI`, `KMIP_CLIENT`). Run the
server as in [deployment](deployment.md) or [Kubernetes](kubernetes.md).

## Tested clients

The pinned clients the project tests against the server: six independent
libraries, this project's own Java client, and the built-in clients of two
databases. [Project status](status.md#what-has-been-tested) says what the
tests cover; the results are in each release's
[test reports](testing.md#test-reports).

| Client | Version | Protocol and transport |
| --- | --- | --- |
| [OVH kmip-go](https://github.com/ovh/kmip-go) | v0.9.2 and commit `525ef10` | 1.0–1.4, binary; HTTPS TTLV/JSON/XML |
| [PyKMIP](https://github.com/OpenKMIP/PyKMIP) | commit `4815637` | 1.1–1.4, binary |
| [OpenKMIP libkmip](https://github.com/OpenKMIP/libkmip) | commit `6611941` | 1.0–1.4, binary |
| [NLnet Labs kmip-protocol](https://github.com/NLnetLabs/kmip-protocol) | 0.4.3 | 1.0–1.2 (per operation), binary |
| [Thales kmip-go](https://github.com/ThalesGroup/kmip-go) | commit `5b93a22` | 1.4, binary |
| [IBM libkmipclient](https://github.com/ibm-s390-linux/s390-tools/tree/v2.44.1/libkmipclient) | v2.44.1 | 1.0–2.1, binary and HTTPS TTLV/JSON/XML |
| [keytend-kmip](https://github.com/keytend/keytend-kmip-java) | [0.9.1](https://github.com/keytend/keytend-kmip-java/releases/tag/v0.9.1), the signed release ([install](clients/java.md#install)) | 1.1–2.1 (1.4–2.1 by default), binary and HTTPS |
| Percona Server for MongoDB | 8.0.34-15 | built-in KMIP client ([integration](percona.md)) |
| Percona Server for MySQL | 8.4.11-11 | `component_keyring_kmip`, 1.4 ([integration](percona.md)) |
