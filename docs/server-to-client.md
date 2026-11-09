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

# Notify, Put and Set Endpoint Role

Part of the [feature reference](README.md#feature-reference).

KMIP lets a server send Notify (an object's attributes changed) and Put (a
new or replacement object) to a client. This server does so only for a
principal that opts in with a `client_endpoint` in its
[policy entry](configuration.md#policy-file). Without one, nothing is sent,
and Notify and Put are not listed in Query.

## Configuration

A principal's policy entry with `client_endpoint`:

```json
{
  "principals": {
    "<fingerprint of agent.pem>": {
      "name": "kmip-agent",
      "operations": [8, 10, 11, 12, 24, 30],
      "client_endpoint": {
        "address": "kmip-agent.example:5697",
        "server_name": "kmip-agent.example",
        "ca": "/etc/kmip/agent-ca.pem",
        "certificate": "/etc/kmip/server-as-client.pem",
        "key": "/etc/kmip/server-as-client.key",
        "protocol_version": "1.4",
        "operations": [27, 28]
      }
    }
  }
}
```

The `client_endpoint` fields:

| Field | Meaning |
| --- | --- |
| `address`, `server_name`, `ca`, `certificate`, `key` | Where to connect, the name to verify, the CA to trust (no system roots), and the server's client certificate; all five or none. |
| `protocol_version` | A final edition, 1.0 to 2.1. Without dial-out fields, 2.0 or 2.1. |
| `operations` | 27 (Notify) and/or 28 (Put). Notify needs the principal to be allowed Get Attributes (11), Put needs Get (10). |
| `transport` | `ttlv` (default) or `https`: HTTP/1.1 POST over the same mutual TLS, as Profiles section 5.3 describes. Needs the dial-out fields. |
| `target` | HTTPS request target, default `/kmip`. |

Without the five dial-out fields, the server uses a
[reversed channel](#set-endpoint-role). Unknown fields are refused at
startup, and a principal can have only one endpoint.

### On Kubernetes

The chart's NetworkPolicy permits no egress and the pod
mounts only the TLS, policy and master-key inputs, so dial-out delivery fails
until the values add an egress rule to the endpoint (and DNS if `address` is a
name) and a Secret for `ca`, `certificate` and `key`; a reversed channel needs
neither. For an endpoint on port 5697 in the namespace `orders`, with its
files in the Secret `kmip-endpoint` and the policy naming them under
`/endpoint/`, add to `kmip-values.yaml` ([Kubernetes](kubernetes.md#settings-and-extra-files)):

```yaml
networkPolicy:
  egress:
    - to: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: orders}}}]
      ports: [{protocol: TCP, port: 5697}]
  dns:
    enabled: true
extraVolumes:
  - {name: endpoint, secret: {secretName: kmip-endpoint, defaultMode: 288}}   # 0440
extraVolumeMounts:
  - {name: endpoint, mountPath: /endpoint, readOnly: true}
```

The DNS rule (`networkPolicy.dns`) selects pods labelled `k8s-app: kube-dns`
in `kube-system` (CoreDNS on kind and most distributions); adjust it for
yours.

## What is sent

Messages follow what a request committed, and are queued only after the
commit. With the Stop (default) or Continue
[batch option](messages.md#batches), a failed item does not undo the items
that succeeded, so their changes stay committed and their messages are sent.
A request that rolls back as a whole (an Undo batch with a failed item, or a
request the server cannot answer) sends nothing. Each object of the principal
that the request wrote yields at most one message:

- A new object gets **Put**: Put Function Replace with the Replaced Unique
  Identifier after Re-key, Re-key Key Pair or Re-certify, otherwise New. The
  object is exactly what an unwrapped Get by the owner would return, so
  Sensitive, non-extractable and destroyed objects are never pushed (each skip
  is audited).
- An existing object whose attributes changed gets **Notify** with the changed
  attributes and Last Change Date; a change to Last Change Date alone is not
  sent. Deleted attributes are reported as the edition defines.

## Delivery

- One queue of 256 messages and one worker per endpoint. A full queue drops
  the message and audits the drop.
- TLS 1.2 or 1.3; the server verifies `server_name`. It sends binary TTLV (or
  HTTP POST with `transport: https`) and requires a successful response in the
  same version.
- For 2.0 and 2.1 endpoints the server first sends Discover Versions and Query
  at the start of each session. If the client does not support the endpoint's
  version, or its Query lacks Notify or Put, that message is not sent. A probe
  answered with Operation Not Supported is ignored, so clients that implement
  only Notify and Put still work.
- A transport failure is retried at most twice (after 1 s and 2 s); a failure
  status from the client is final. Over HTTPS, 5xx is retried and any other
  non-200 status is final.
- Every outcome is written to the audit chain.

Delivery is not durable: queued messages are lost on restart. Notify and Put
are not sent to 3.0 endpoints, and Put carries no Lease Time.

## Set Endpoint Role

KMIP 2.0 and later. A client on a binary TTLV connection can ask the server to
take the client role on that same connection, for example when the server
cannot dial out:

- Endpoint Role Server is always accepted and changes nothing.
- Endpoint Role Client needs a `client_endpoint` for the principal (Permission
  Denied otherwise), the endpoint's `protocol_version` in the request, and a
  TTLV connection (not HTTPS, not an asynchronous batch); otherwise Feature
  Not Supported. The policy must allow operation 50.

After the response, the connection carries the server's Discover Versions,
Query and pending Notify and Put messages. After 30 s without a message, or
120 s in total, the server hands the role back with its own Set Endpoint Role
and the connection serves requests again. If a principal opens a second
reversed channel, the newer one is used. Anything other than the expected
response from the peer closes the connection.
