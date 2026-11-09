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

# HTTPS with JSON or XML

Part of [connecting a client](../clients.md).

The examples run against the [quick-start server](../quick-start.md), with
its test certificates.

The HTTPS listener (`--https-listen`, port 5697 in the examples) takes one
KMIP request message per `POST` to `/kmip`, in the encoding named by
`Content-Type`: `application/octet-stream` (TTLV), `application/json` or
`text/xml`. The response uses the same encoding unless `Accept` asks for
another. Any HTTP client works; the client certificate authenticates as on
the binary port. Encoding rules, limits and the per-element settings are in
[JSON, XML and HTTPS bindings](../encodings.md); the [Java client](java.md#https)
speaks HTTPS too.

A KMIP failure is still HTTP 200, so read Result Status in the body
([HTTP status codes](../encodings.md#http-status-codes)). Before repeating a
request after HTTP 500, read
[retrying](../client-errors.md#retrying-after-a-lost-response).

The request files are in [`examples/https`](../../examples/https), and
[`kmip.sh`](../../examples/https/kmip.sh) there defines the shell functions
the commands use (bash or zsh):

- `kmip FILE [NAME=VALUE …]` posts a request file with `curl` and the test
  `client` certificate, replacing `$NAME` in the file by `VALUE`. It sends
  `.xml` files as XML and everything else as JSON, and prints the response.
  It fails with a message instead when the connection fails, takes over 30
  seconds, or the HTTP status is not 200 (`kmip: HTTP 415: Unsupported Media
  Type`).
- `field TAG` prints the first value of a tag in a JSON response.
- `pretty` indents a JSON or XML response, one element per line.
- `hex TEXT` and `unhex` convert between text and the hex form of byte
  strings.

Load them once per shell; from the checkout:

```sh
. examples/https/kmip.sh
```

`kmip.sh` finds the request files and the quick start's certificates
(`.cache/dev-pki` in the checkout) relative to its own location, so the
commands work from any directory. Set `KMIP_PKI`, `KMIP_CLIENT` (a
certificate name in `KMIP_PKI`) or `KMIP_URL` to use other ones.

- [The JSON message](#the-json-message)
- [XML](#xml)
- [Locate by Name](#locate-by-name)
- [Retire a key in one batch](#retire-a-key-in-one-batch)
- [Encrypt and Decrypt with AES-GCM](#encrypt-and-decrypt-with-aes-gcm)
- [Sign and verify with RSA](#sign-and-verify-with-rsa)
- [Binary TTLV over HTTPS](#binary-ttlv-over-https)

## The JSON message

The quick start's request,
[`create.json`](../../examples/https/create.json), is a KMIP 2.1 Create of a
256-bit AES key:

```json
{"tag": "RequestMessage", "value": [
  {"tag": "RequestHeader", "value": [
    {"tag": "ProtocolVersion", "value": [
      {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
      {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}]},
    {"tag": "BatchCount", "type": "Integer", "value": 1}]},
  {"tag": "BatchItem", "value": [
    {"tag": "Operation", "type": "Enumeration", "value": "Create"},
    {"tag": "RequestPayload", "value": [
      {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
      {"tag": "Attributes", "value": [
        {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
        {"tag": "CryptographicLength", "type": "Integer", "value": 256},
        {"tag": "CryptographicUsageMask", "type": "Integer", "value": "Encrypt|Decrypt"}]}]}]}]}
```

```sh
kmip create.json | pretty
```

```json
{"tag": "ResponseMessage", "type": "Structure", "value": [
  {"tag": "ResponseHeader", "type": "Structure", "value": [
    {"tag": "ProtocolVersion", "type": "Structure", "value": [
      {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
      {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}]},
    {"tag": "TimeStamp", "type": "DateTime", "value": "2026-11-05T08:26:03Z"},
    {"tag": "ServerCorrelationValue", "type": "TextString", "value": "c40c232c-33bf-407f-a9dd-59a9f17fba9c"},
    {"tag": "BatchCount", "type": "Integer", "value": 1}]},
  {"tag": "BatchItem", "type": "Structure", "value": [
    {"tag": "Operation", "type": "Enumeration", "value": "Create"},
    {"tag": "ResultStatus", "type": "Enumeration", "value": "Success"},
    {"tag": "ResponsePayload", "type": "Structure", "value": [
      {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
      {"tag": "UniqueIdentifier", "type": "TextString", "value": "77b20d2c-7df3-4746-8433-5c940563acb4"}]}]}]}
```

Every element is an object with a `tag`, a `type` and a `value`. A
Structure's `value` is an array of elements, and its `type` may be left out
in requests. Byte strings are hex, and enumerations and masks may be names
(masks joined by `|`) or numbers; [encodings](../encodings.md#response-forms)
has the full rules.

## XML

The same Create in XML is
[`create.xml`](../../examples/https/create.xml):

```xml
<RequestMessage>
  <RequestHeader>
    <ProtocolVersion>
      <ProtocolVersionMajor type="Integer" value="2"/>
      <ProtocolVersionMinor type="Integer" value="1"/>
    </ProtocolVersion>
    <BatchCount type="Integer" value="1"/>
  </RequestHeader>
  <BatchItem>
    <Operation type="Enumeration" value="Create"/>
    <RequestPayload>
      <ObjectType type="Enumeration" value="SymmetricKey"/>
      <Attributes>
        <CryptographicAlgorithm type="Enumeration" value="AES"/>
        <CryptographicLength type="Integer" value="256"/>
        <CryptographicUsageMask type="Integer" value="Encrypt Decrypt"/>
      </Attributes>
    </RequestPayload>
  </BatchItem>
</RequestMessage>
```

```sh
kmip create.xml | grep -oE '<(ResultStatus|UniqueIdentifier) [^>]*>'
```

```text
<ResultStatus type="Enumeration" value="Success"/>
<UniqueIdentifier type="TextString" value="e35428b0-c1db-415d-802f-916270ee8cbe"/>
```

`kmip create.xml | pretty` shows the whole response, which has the same
structure as the request, with a `ResponseHeader` and a `ResponsePayload`.

The JSON and XML responses come from a server started with `--text-encoding readable`,
as the quick start's is. With the default `compatible` forms, enumerations
come back as hex (`0x00000000` for Success) and XML uses `<TTLV tag="0x…">`
elements; requests may use either form.

## Locate by Name

Create a key with a Name
([`create-named.json`](../../examples/https/create-named.json)), then find it
again ([`locate.json`](../../examples/https/locate.json)). The time stamp
keeps the Name unique, so the commands can run again:

```sh
NAME=orders-kek-$(date +%s)
kmip create-named.json NAME="$NAME" | field UniqueIdentifier
kmip locate.json NAME="$NAME" | field UniqueIdentifier
```

```text
53e16b74-9c86-4e63-87b3-c2c9698f1816
53e16b74-9c86-4e63-87b3-c2c9698f1816
```

## Retire a key in one batch

A message can carry several batch items. They run in order, the batch stops
at the first failure by default, and each item needs a Unique Batch Item ID.
[`retire.json`](../../examples/https/retire.json) takes the key found above
through the steps an Active key needs: it activates it, revokes it and
destroys it (a Pre-Active key could be destroyed directly). Its header says
`BatchCount` 3, and its second item is:

```json
  {"tag": "BatchItem", "value": [
    {"tag": "Operation", "type": "Enumeration", "value": "Revoke"},
    {"tag": "UniqueBatchItemID", "type": "ByteString", "value": "02"},
    {"tag": "RequestPayload", "value": [
      {"tag": "UniqueIdentifier", "type": "TextString", "value": "$ID"},
      {"tag": "RevocationReason", "value": [
        {"tag": "RevocationReasonCode", "type": "Enumeration", "value": "CessationOfOperation"}]}]}]}
```

Run it:

```sh
ID=$(kmip locate.json NAME="$NAME" | field UniqueIdentifier)
kmip retire.json ID="$ID" | grep -oE '"(Operation|ResultStatus)"[^}]*'
kmip locate.json NAME="$NAME" | field UniqueIdentifier
```

```text
"Operation","type":"Enumeration","value":"Activate"
"ResultStatus","type":"Enumeration","value":"Success"
"Operation","type":"Enumeration","value":"Revoke"
"ResultStatus","type":"Enumeration","value":"Success"
"Operation","type":"Enumeration","value":"Destroy"
"ResultStatus","type":"Enumeration","value":"Success"
None
```

The last Locate finds nothing, because the key is destroyed. Every other
operation has the same shape, an Operation and a Request Payload; the
[support matrix](../support-matrix.md) lists which operations each version
offers, and [batches](../messages.md#batches) the batch options.

## Encrypt and Decrypt with AES-GCM

The server can encrypt with a stored key, so the application need not hold it.
[`create-active.json`](../../examples/https/create-active.json) creates an
AES key with Extractable False and activates it in one batch. It is
[`create.json`](../../examples/https/create.json) with a `BatchCount` of 2, a
`UniqueBatchItemID` on each item, one more attribute in the Create:

```json
{"tag": "Attributes", "value": [
  {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
  {"tag": "CryptographicLength", "type": "Integer", "value": 256},
  {"tag": "CryptographicUsageMask", "type": "Integer", "value": "Encrypt|Decrypt"},
  {"tag": "Extractable", "type": "Boolean", "value": false}]}
```

and a second batch item:

```json
{"tag": "BatchItem", "value": [
  {"tag": "Operation", "type": "Enumeration", "value": "Activate"},
  {"tag": "UniqueBatchItemID", "type": "ByteString", "value": "02"},
  {"tag": "RequestPayload", "value": []}]}
```

The Activate payload is empty: with no Unique Identifier, Activate uses the
ID Placeholder, the identifier of the object the Create before it made.

```sh
KEY=$(kmip create-active.json | field UniqueIdentifier); echo "$KEY"
```

The key is created with Extractable False, so Get refuses it, plain or
wrapped (`kmip get.json ID="$KEY" | field ResultReason` prints
`NotExtractable`). Without that attribute, server-side Encrypt does not stop
anyone allowed Get on the key from fetching it
([getting keys](../key-transfer.md)). Up to KMIP 2.1 a caller allowed
attribute changes can set Extractable back to True, so give the application
a certificate whose operations include neither attribute changes nor Get, as
in the server-side
[role templates](../configuration.md#role-templates).

[`encrypt.json`](../../examples/https/encrypt.json) encrypts `DATA` with the
Additional Data `AAD`, which is authenticated but not encrypted; byte strings
are hex in JSON. Its `RandomIV` lets the server choose the 12-byte IV (FIPS
mode requires that), and the response returns the IV with the ciphertext and
the 16-byte tag:

```bash
AAD=$(hex order-42)
R=$(kmip encrypt.json KEY="$KEY" DATA="$(hex hello)" AAD="$AAD")
CT=$(field Data <<<"$R"); IV=$(field IVCounterNonce <<<"$R"); TAG=$(field AuthenticatedEncryptionTag <<<"$R")
echo "$CT $IV $TAG"
```

```text
2743e0919f 95573d6d75719db5b5b6a3bc ea963bb71a1f90ce87a7d28ac6764fdb
```

Store the key identifier, IV, ciphertext and tag with the record. To decrypt,
send all four back with the same Additional Data
([`decrypt.json`](../../examples/https/decrypt.json)):

```sh
kmip decrypt.json KEY="$KEY" DATA="$CT" IV="$IV" TAG="$TAG" AAD="$AAD" | field Data | unhex
```

```text
hello
```

If the Additional Data, ciphertext or tag has changed, Decrypt fails with
`CryptographicFailure` and returns no plaintext. Tag lengths, IV rules and the
other modes are in [Encrypt and Decrypt](../crypto-operations.md#encrypt-and-decrypt).

## Sign and verify with RSA

[`create-key-pair.json`](../../examples/https/create-key-pair.json) creates
an RSA 3072 key pair whose private key may only sign and whose public key may
only verify ([usage masks](../lifecycle.md#usage-masks)). Its Activation Date
lies in the past, so both keys start Active; without it they would be
Pre-Active and need an Activate each.

```bash
R=$(kmip create-key-pair.json)
PRIV=$(field PrivateKeyUniqueIdentifier <<<"$R"); PUB=$(field PublicKeyUniqueIdentifier <<<"$R")
echo "$PRIV $PUB"
```

```text
fbbeac58-4f7a-44bd-bbc0-2598e8a3078b 0107dd0f-66a4-4034-878d-76001e429958
```

If either is `None`, the Create Key Pair failed: `field ResultReason <<<"$R"`
says why.

[`sign.json`](../../examples/https/sign.json) signs `DATA` under the private
key with RSASSA-PSS, SHA-256, MGF1 with SHA-256 and a 32-byte salt (explicit,
because the KMIP defaults are refused in [FIPS mode](../fips.md)), and
[`verify.json`](../../examples/https/verify.json) checks the signature with
the public key:

```sh
SIG=$(kmip sign.json KEY="$PRIV" DATA="$(hex 'order 42: ship')" | field SignatureData)
kmip verify.json KEY="$PUB" DATA="$(hex 'order 42: ship')" SIG="$SIG" | field ValidityIndicator
kmip verify.json KEY="$PUB" DATA="$(hex 'order 43: ship')" SIG="$SIG" | field ValidityIndicator
```

```text
Valid
Invalid
```

A signature that does not match is a successful response with Validity
Indicator `Invalid`, not an error. Other padding, hashes, ECDSA and
pre-hashed data are in
[Sign and Signature Verify](../crypto-operations.md#sign-and-signature-verify).

## Binary TTLV over HTTPS

Binary KMIP messages also travel over HTTPS: post the TTLV bytes as
`application/octet-stream`, for example from a client whose network path only
allows HTTPS. These 104 bytes are a KMIP 1.4 Discover Versions request. The
commands use the `KMIP_PKI` that `kmip.sh` exports, so load it first:

```sh
T=$(mktemp -d)
TTLV=42007801000000604200770100000038420069010000002042006a0200000004000000010000000042006b020000000400000004
TTLV=${TTLV}0000000042000d0200000004000000010000000042000f010000001842005c05000000040000001e000000004200790100000000
python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' "$TTLV" > "$T/request.ttlv"
P=$KMIP_PKI C=${KMIP_CLIENT:-client} URL=${KMIP_URL:-https://localhost:5697/kmip}
curl -sS --cacert "$P/ca.pem" --cert "$P/$C.pem" --key "$P/$C.key" \
  -H 'Content-Type: application/octet-stream' --data-binary @"$T/request.ttlv" \
  -o "$T/response.ttlv" -w '%{http_code} %{content_type}\n' "$URL"
od -An -tx1 -N4 "$T/response.ttlv"
```

```text
200 application/octet-stream
 42 00 7b 01
```

The response starts with the Response Message tag (`42007b`) and the
Structure type (`01`). With `Accept: application/json` the same TTLV request
gets a JSON response; then remove the request file:

```sh
curl -sS --cacert "$P/ca.pem" --cert "$P/$C.pem" --key "$P/$C.key" \
  -H 'Content-Type: application/octet-stream' -H 'Accept: application/json' \
  --data-binary @"$T/request.ttlv" "$URL" | field ResultStatus
rm -r "$T"
```

```text
Success
```

Next: [beyond the test setup](../clients.md#beyond-the-test-setup).
