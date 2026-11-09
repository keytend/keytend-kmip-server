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

# JSON, XML and HTTPS bindings

Part of [configuration and operations](README.md#configuration-and-operations).

The HTTPS listener and the JSON and XML encodings carry the same operations,
authorization and store as binary KMIP, whose TTLV encoding writes each item
as a tag, a type, a length and a value. The rules come from the
[KMIP 2.1 Profiles](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html),
sections 5.3 (HTTPS), 5.4 (XML) and 5.5 (JSON), the earlier final Profiles
editions and the [3.0 CSD02 Profiles](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.html).
Example requests are in [clients](clients/https.md) and the
[quick start](quick-start.md#make-a-request-with-curl).

## Enable and connect

`--https-listen 0.0.0.0:5697` (`KMIP_HTTPS_LISTEN`) enables HTTP/1.0 and 1.1
over the same mutual TLS configuration as the binary listener; it is off
unless set, and the supplied Kubernetes resources set it. The path is `/kmip`
(`--https-path`, `KMIP_HTTPS_PATH`). A request is one `POST` of one KMIP
request message with a `Content-Length` and one of these media types:

| Format | Request/response Content-Type |
| --- | --- |
| Binary TTLV | `application/octet-stream` |
| JSON | `application/json` |
| XML | `text/xml` (`application/xml` also accepted in requests and `Accept`) |

With no `Accept` header the response uses the request format; `Accept` can
select another, with quality weights, exclusions and wildcards. Text is UTF-8.
Responses carry an exact `Content-Length` and `Cache-Control: no-cache`.
Persistent connections and pipelining work; HTTP/2 does not. HTTPS requests
use the same certificate principal, operation allowlist, object grants, store
and audit as binary requests, so a key written through one encoding reads the
same through every other. There is no unauthenticated or plaintext KMIP
endpoint. The server can also send Notify and Put over HTTPS to a client that
opts in ([Notify and Put](server-to-client.md#configuration)).

### HTTP status codes

A KMIP result, including a KMIP failure or a request body that is not a valid
KMIP message, is HTTP 200 with an encoded KMIP response: read Result Status in
the body. After HTTP 500 the request may have been applied, because a change
is committed before the response is encoded; check before you repeat a Create
([retrying](client-errors.md#retrying-after-a-lost-response)). Any other status
means no operation ran.

| Status | Cause |
| --- | --- |
| 400 | Bad framing: `Transfer-Encoding` or trailers, an invalid `Content-Length`, a body shorter or longer than it, a missing `Host` in HTTP/1.1, or a request no KMIP response could answer |
| 403 | The client certificate expired while the connection was open |
| 404 | Path other than `--https-path`, or a query string |
| 405 | Method other than `POST` |
| 406 | `Accept` names no supported format, or the response encoding cannot represent the request's Client Correlation Value |
| 408 | The body did not arrive within 10 seconds |
| 411 | No `Content-Length`, or more than one |
| 413 | Body larger than the limit below |
| 415 | Missing, repeated or unsupported `Content-Type` |
| 500 | Internal error, possibly after the request was applied |
| 503 | Four requests already in progress ([fixed limits](configuration.md#fixed-limits)); retry |
| 505 | HTTP version other than 1.0 or 1.1 |

## Response forms

Responses default to `compatible`: JSON tag names with hex enumerations, and
hex XML tags. `--text-encoding readable` (`KMIP_TEXT_ENCODING`) writes names
wherever allowed and text Date-Times; `hex` writes hex throughout. Requests
are accepted in every allowed form whatever the setting. Each element setting
below overrides the preset for one element; its environment variable is its
name in upper case with a `KMIP_` prefix (`KMIP_JSON_TAGS` for `--json-tags`).

| Setting | Values | `compatible` (default) | `readable` | `hex` |
| --- | --- | --- | --- | --- |
| `--json-tags` | `name`, `hex` | `name` | `name` | `hex` |
| `--json-enumerations` | `name`, `hex`, `number` | `hex` | `name` | `hex` |
| `--json-masks` | `number`, `hex`, `names` | `number` | `names` | `hex` |
| `--json-integers` | `number`, `hex` | `number` | `number` | `hex` |
| `--json-long-integers` | `number`, `hex` | `number` | `number` | `hex` |
| `--json-big-integers` | `number`, `hex` | `hex` | `number` | `hex` |
| `--json-intervals` | `number`, `hex` | `number` | `number` | `hex` |
| `--json-date-time-extended` | `number`, `hex` | `number` | `number` | `hex` |
| `--json-booleans` | `boolean`, `hex` | `boolean` | `boolean` | `hex` |
| `--json-date-times` | `hex`, `text` | `hex` | `text` | `hex` |
| `--xml-tags` | `name`, `hex` | `hex` | `name` | `hex` |
| `--xml-enumerations` | `name`, `hex` | `hex` | `name` | `hex` |
| `--xml-masks` | `names`, `hex`, `number` | `names` | `names` | `hex` |

- JSON mask `names` are `|`-separated (`"Encrypt|Decrypt"`); XML mask `names`
  are space-separated (`"Encrypt Decrypt"`), and XML `number` is an xsd:int.
- JSON date-time `text` is an XML Schema dateTime in UTC (`2026-11-04T10:00:00Z`).
- XML tag `name` writes the specific element (`<ObjectType …/>`); `hex` the
  general `<TTLV tag="0x…">` element.

`compatible` is the default because some clients (the Cosmian KMS 5.28
client, for example) reject enumeration names.

These are the elements that Profiles 2.1 sections 5.4.1 (XML) and 5.5.1
(JSON), and the same sections of the 1.3–2.0 and draft 3.0 Profiles, allow in
more than one form
([interpretation](interpretations.md#tag-and-enumeration-names-in-json-responses)).
Whatever the setting, a tag or enumeration value that the response's edition
does not name (extension tags, vendor and unknown values, an edition's
Reserved slots, messages without a known version) is written in hex, and a
JSON Number is used only where it is exact (below 2^52 in magnitude; for Big
Integers, eight-byte values only). XML Integer, Boolean, Date-Time and the other xsd types have one form
each, so they have no setting. Under `--xml-tags name`, a tag the response's
edition does not name is written in the general `<TTLV tag="0x…">` form.

## Limits

- The binary equivalent of a message is at most 1 MiB; a JSON or XML
  body at most 8 MiB, depth 32 and 16,384 nodes; HTTP headers at most 16 KiB
  and 64 headers; 10-second header and body deadlines.
- JSON rejects duplicate or unknown properties and inexact
  numbers; values at or above 2^52 need hex. XML rejects DTDs, external
  entities and non-whitespace text; no schema or network resolution happens.
  Dates cover the full signed 64-bit range.

Test results, including the official XML corpus, are summarised in
[project status](status.md#what-has-been-tested).
