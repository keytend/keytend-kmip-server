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

# Client errors and retries

Part of [connecting a client](clients.md).

What a refused request or a failed connection means, how to fix it, and which
requests are safe to repeat after a lost response.

## Errors and what they mean

A refused operation comes back as Result Status `OperationFailed` with a
Result Reason and a Result Message; the connection stays open unless the
certificate is not in the policy. Over HTTPS a KMIP failure is still HTTP 200.

| Result Reason | Cause | Fix |
| --- | --- | --- |
| `PermissionDenied`, message `Operation denied by certificate policy`, then the connection closes | The certificate is trusted but not in the policy. | Add its fingerprint to the policy; restart. |
| `PermissionDenied` on one operation | The operation is not in the certificate's `operations`, or the object's state forbids it (1.x, some 2.0 cases, and Obtain Lease in every edition). | Grant it, or see [refusals by state](lifecycle.md#refusals-by-state). |
| `ObjectNotFound` (2.x) or `ItemNotFound` (1.x) for an existing identifier | Another principal owns it, and the answer is as for a missing object. | Use the owner's principal, or an [object grant](authorization.md). |
| `WrongKeyLifecycleState` (2.x) | The object's state forbids the operation, such as Encrypt with a Pre-Active key (Permission Denied in 1.x). | Activate it first, or see [refusals by state](lifecycle.md#refusals-by-state). |
| `ObjectDestroyed` (2.x) or `IllegalOperation` (1.x) on Get | The key was destroyed; its attributes remain. | Expected after Destroy ([Get](key-transfer.md#get)). |
| `NotExtractable` on Get (1.4+) | The object's Extractable attribute is False: it is never returned, plain or wrapped. | Use it through [server-side operations](crypto-operations.md). |
| `Sensitive` on Get (1.4+) | The object is Sensitive and the Get asks for plaintext. | Get it [wrapped](key-transfer.md#wrapped-get-and-register). |
| `NonUniqueNameAttribute` (2.x); `InvalidField` or `IllegalOperation` (1.x) | The owner already has an object with that Name. | Use another Name, or Locate the existing object ([duplicate names](attributes.md#duplicate-names-in-kmip-1x)). |
| `CryptographicFailure` on Decrypt | Wrong key, IV, ciphertext, tag or Additional Data; an AES-GCM tag that does not verify returns no plaintext. | Do not retry: the same input fails again. Check what was stored with the record. |
| `ItemNotFound` (1.x) for an object created through 2.x | Some objects (certificate requests) do not exist in 1.x. | Use a 2.x request. |
| `AuthenticationNotSuccessful` | A request-header credential did not verify. | Check the users file and the credential. |
| `UnsupportedProtocolVersion` (2.x and 3.0) | The server does not accept the request's Protocol Version, for example 3.0 when it runs without `--experimental-v3`. | Request a version that Discover Versions lists, or start the server with `--experimental-v3` for 3.0. |
| `OperationNotSupported` | Not in the request's KMIP version, or not implemented. | See the [support matrix](support-matrix.md). |
| `FeatureNotSupported` | Algorithm, format, curve or option unsupported, off by a setting (`--triple-des`, `--ec-curves`) or refused in FIPS mode. | See the message and [algorithms](algorithms.md). |

A few 2.x operations answer an unknown identifier with `ItemNotFound` or
`WrappingObjectNotFound` instead ([exceptions](messages.md#unknown-identifiers)).
How each client reports these: [Python](clients/python.md#errors),
[Go](clients/go.md#errors-and-deadlines), [Java](clients/java.md#errors),
[C](clients/c.md#errors), [Rust](clients/rust.md#errors) and
[HTTPS](clients/https.md) (a KMIP failure is HTTP 200).

Failures below the KMIP layer:

| What the client sees | Cause | Fix |
| --- | --- | --- |
| TLS handshake fails; `curl` reports `certificate required` | No client certificate, or one not from a CA in `--ca`. | Present a certificate from the client CA. |
| The client rejects the server certificate | The client does not trust the server CA, or dials a name the certificate does not list. | Trust the server CA; dial a listed name. |
| TLS handshake fails with no shared parameters | The client offers only ChaCha20-Poly1305, X25519 or finite-field DHE. | Update the client, or set `--tls-profile mozilla-intermediate` on the server. |
| TLS handshake fails with a protocol version error | The client offers only TLS 1.0 or 1.1. | Update the client. Only `kmip-1-basic` accepts them, without forward secrecy ([policies](tls-profiles.md#policies)). |
| HTTP 400, 411, 415 | Chunked body, no `Content-Length`, or a missing or unsupported `Content-Type`. | See [HTTP status codes](encodings.md#http-status-codes). |
| HTTP 503 | Four HTTPS requests were already in progress ([fixed limits](configuration.md#fixed-limits)); the request did not run. | Retry after a short, growing delay. |
| HTTP 403 on an open HTTPS connection | The client certificate expired while the connection was open. | Renew it and reconnect. |
| I/O error on the first request after a quiet period | The server closed the idle connection (`--idle-timeout`, default 300 s). | Reconnect on failure, or raise the timeout. |

## Retrying after a lost response

When a connection drops before the response arrives (a server restart, an
idle close, a network failure), or the HTTPS listener answers HTTP 500, the
request may or may not have been applied: the server commits a change before
it encodes the response. Any other non-200 HTTP status means the request did
not run. Retry 503 with backoff, and 408 (the body did not arrive within 10
seconds) once the upload can finish in time; the other statuses need their
cause fixed first ([HTTP status codes](encodings.md#http-status-codes)).

Reads are safe to repeat: an unwrapped Get, Get Attributes, Get Attribute
List and an ordinary Locate. Two reads change state:

- A wrapped Get (with a Key Wrapping Specification) counts against the
  wrapping key's usage limits, if it has any, so a retry spends that budget
  again ([wrapped Get](key-transfer.md#wrapped-get-and-register)).
- A Locate with Object Group Member set to Group Member Default moves the
  group's rotation on by one per request, so a retry can return the next
  member ([Object Group Member](locate.md#object-group-member-11)).

Before repeating a Create or Register, check whether the first attempt
succeeded, for example with Locate by the Name you gave the object; otherwise
you can end up with two objects, or a Name collision. Restarts are described
in [shutdown and restarts](operations.md#shutdown-and-restarts).
