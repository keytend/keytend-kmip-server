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

# Python (PyKMIP)

Part of [connecting a client](../clients.md).

[PyKMIP](https://github.com/OpenKMIP/PyKMIP), tested at commit `4815637`,
binary KMIP 1.1–1.4, and the standard library for HTTPS JSON. The complete
programs are in [`examples/clients/python`](../../examples/clients/python);
its [`requirements.txt`](../../examples/clients/python/requirements.txt)
pins PyKMIP.

- [Run the examples](#run-the-examples)
- [Connection settings](#connection-settings)
- [Request-header credentials](#request-header-credentials)
- [Common tasks](#common-tasks)
- [Server-side Encrypt over HTTPS JSON](#server-side-encrypt-over-https-json)
- [Errors](#errors)

## Run the examples

They need the [quick-start server](../quick-start.md) and the PyKMIP
environment that the quick start's
[KMIP library example](../quick-start.md#make-a-request-with-a-kmip-library)
installs in `.cache/pykmip`. Run from the checkout:

```sh
CHECKOUT=$PWD; export KMIP_PKI=$CHECKOUT/.cache/dev-pki
PY=$CHECKOUT/.cache/pykmip/bin/python
cd examples/clients/python
```

Every command below runs in that shell and directory. PyKMIP prints a
harmless `Config file … not found` notice on standard error.

## Connection settings

> [!WARNING]
> PyKMIP checks the server certificate against `ca` but not the host name
> (at the tested commit it wraps the socket without `server_hostname`). Any
> certificate from that CA is accepted as the server, so give the server a
> CA that issues only its certificates, or use the standard library's
> [HTTPS client](#server-side-encrypt-over-https-json), which checks the name.

[`connect.py`](../../examples/clients/python/connect.py) has the settings
for the quick-start server; every program repeats them, so that it runs on
its own. `CLIENT` is `KMIP_CLIENT`, default `client`:

```python
client = ProxyKmipClient(
    hostname="localhost", port=5696,
    cert=f"{PKI}/{CLIENT}.pem", key=f"{PKI}/{CLIENT}.key",
    ca=f"{PKI}/ca.pem",                       # the server's CA
    ssl_version="PROTOCOL_TLSv1_2",           # TLS 1.2 exactly (PyKMIP cannot use 1.3)
    kmip_version=enums.KMIPVersion.KMIP_1_4,
)
with client:
    client.locate(maximum_items=1)   # one round trip
    print("connected")
```

```sh
"$PY" connect.py
```

```text
connected
```

### Timeouts

`ProxyKmipClient` takes no timeout: its socket timeout is 30
seconds for the connect, the TLS handshake and each read, and a `timeout` in
a PyKMIP configuration file is ignored. A server that does not answer raises
`TimeoutError` after 30 seconds. At the tested commit, setting the internal
`client.proxy.timeout = 5` before `open()` (or `with`) changes it.

## Request-header credentials

With a [users file](../credentials.md#users-file), the server also checks a
username and password that the client sends in the request header; the
certificate must still be in the policy. Create a user `app` for the
`client` certificate:

```sh
FP=$(openssl x509 -in "$KMIP_PKI/client.pem" -outform DER | sha256sum | cut -d' ' -f1)   # macOS: shasum -a 256
VERIFIER=$(printf '%s\n' 'correct horse battery staple' |
  docker exec -i keytend-kmip-server keytend-kmip-server password-verifier)
# from source: … | "$CHECKOUT/target/debug/keytend-kmip-server" password-verifier
printf '{"users": {"%s": [{"username": "app", "password_verifier": %s}]}}\n' \
  "$FP" "$VERIFIER" > "$KMIP_PKI/app-users.json"
```

Restart the server with the users file. With the container, add the file and
its variable, then [recreate the container](../manual-install.md#change-a-setting):

```sh
S=$CHECKOUT/.cache/container
install -m 0400 "$KMIP_PKI/app-users.json" "$S/policy/"
echo KMIP_USERS=/policy/app-users.json >> "$S/kmip.env"
(cd "$CHECKOUT" && scripts/quick-start.sh --restart)
```

From source, stop the server and add `--users .cache/dev-pki/app-users.json`
to its [`serve` command](../manual-install.md#run-from-source).

[`credentials.py`](../../examples/clients/python/credentials.py) connects
as `app`, once with the right password and once with a wrong one:

```python
def connect(password):
    return ProxyKmipClient(
        hostname="localhost", port=5696,
        cert=f"{PKI}/{CLIENT}.pem", key=f"{PKI}/{CLIENT}.key", ca=f"{PKI}/ca.pem",
        ssl_version="PROTOCOL_TLSv1_2", kmip_version=enums.KMIPVersion.KMIP_1_4,
        username="app", password=password,
    )
```

```sh
"$PY" credentials.py
```

```text
created be6c0522-173e-44e7-82b4-525f31f9cbc6 as app
AUTHENTICATION_NOT_SUCCESSFUL Authentication not successful
```

Requests without credentials still succeed on the certificate alone. Devices,
administrators and the other credential types are in
[credentials](../credentials.md).

## Common tasks

[`common_tasks.py`](../../examples/clients/python/common_tasks.py) creates a
named key and finds it by Name, encrypts locally with the fetched key,
registers outside key material, re-keys, and retires the keys. Each run uses
a new Name, so it can run any number of times. Finding a key by Name:

```python
name = attributes.AttributeFactory().create_attribute(enums.AttributeType.NAME, NAME)
print("located", client.locate(attributes=[name]))
```

```sh
"$PY" common_tasks.py
```

```text
located ['e45b8ce6-47de-4d38-b381-50aa4bfae24a']
decrypted b'hello'
registered e3bc3b22-ace4-446d-8309-400663c7ba48
re-keyed e45b8ce6-47de-4d38-b381-50aa4bfae24a -> 42490740-0605-4006-86e2-671594e3f0ad
destroyed e45b8ce6-47de-4d38-b381-50aa4bfae24a
```

The data is encrypted in the application with the fetched key and
`cryptography` (installed with PyKMIP); store the nonce with the ciphertext.
Re-key gives the Name to a new key and leaves the old one its material
([Re-key](../rekey.md)). To keep key material on the server instead, use
server-side Encrypt and Decrypt. PyKMIP cannot carry the AES-GCM
authentication tag; send those requests over HTTPS JSON
([below](#server-side-encrypt-over-https-json)), or use the [Go](go.md) or
[Java](java.md) client.

## Server-side Encrypt over HTTPS JSON

[`https_encrypt.py`](../../examples/clients/python/https_encrypt.py) needs
only the standard library. It posts the
[request files](../../examples/https) to the HTTPS listener, filling in
their `$NAME` placeholders as [`kmip.sh`](../../examples/https/kmip.sh) does: it creates and
activates an AES key, encrypts with AES-GCM on the server, decrypts, and
shows the refusal when the Additional Data changes. It accepts Success in
either [text encoding](../configuration.md#json-and-xml-response-forms): `Success` with the
quick start's `readable`, `0x00000000` with the default `compatible`, which
also prints the Result Reason as a hex code (`0x0000000a`).

```python
key = one(kmip("create-active.json"), "UniqueIdentifier")
aad = b"order-42".hex()
sealed = kmip("encrypt.json", KEY=key, DATA=b"hello".hex(), AAD=aad)
ct, iv, tag = (one(sealed, t) for t in ("Data", "IVCounterNonce", "AuthenticatedEncryptionTag"))
opened = kmip("decrypt.json", KEY=key, DATA=ct, IV=iv, TAG=tag, AAD=aad)
```

```sh
"$PY" https_encrypt.py
```

```text
encrypted f232f036-a6ad-46e9-808b-c4c96257aa61 1990e05544 58be4a1239c257cf12ec0db5 59f1c6f341c3e5e1827dfa39b1c4847f
decrypted b'hello'
refused: decrypt.json: CryptographicFailure: Cryptographic operation failed
```

Store the key identifier, IV, ciphertext and tag with the record; the
[HTTPS page](https.md#encrypt-and-decrypt-with-aes-gcm) explains the fields.

Its `kmip()` raises `KmipError` when the server answered and refused the
request. `OSError` (refused connection, TLS failure, `TimeoutError` after
the 10-second `timeout`) and `http.client.HTTPException` (a non-200 status
or a broken response) mean the exchange failed. After a timeout, a lost
connection or HTTP 500 a change may still have been applied: repeat only
what is safe to repeat
([retrying after a lost response](../client-errors.md#retrying-after-a-lost-response)).

## Errors

PyKMIP raises `KmipOperationFailure` for a refused operation, with the
Result Status, Result Reason and Result Message.
[`errors.py`](../../examples/clients/python/errors.py) asks for a key that
does not exist:

```python
try:
    client.get("no-such-key")
except KmipOperationFailure as e:
    print(e.status.name, e.reason.name, e.message)
```

```sh
"$PY" errors.py
```

```text
OPERATION_FAILED ITEM_NOT_FOUND Object not found
```

TLS and connection failures raise other exceptions (`ssl.SSLError`,
`OSError`). The causes of each Result Reason are in
[errors and what they mean](../client-errors.md#errors-and-what-they-mean).

Next: [beyond the test setup](../clients.md#beyond-the-test-setup).
