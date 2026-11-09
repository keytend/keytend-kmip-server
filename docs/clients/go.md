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

# Go (OVH kmip-go)

Part of [connecting a client](../clients.md).

[OVH kmip-go](https://github.com/ovh/kmip-go) v0.9.2, binary KMIP 1.0–1.4.
The complete programs are a Go module in
[`examples/clients/go`](../../examples/clients/go), whose `go.mod` and
`go.sum` pin the library. It requires Go 1.25.5 or later. A `go` command
from Go 1.21 on downloads that toolchain by itself when `GOTOOLCHAIN` is
`auto` (the default) and it can reach the Go module proxy; with an older
`go`, or offline, install Go 1.25.5 or later first.

## Create, encrypt and retire a key

With the [quick-start server](../quick-start.md) running, run from the
checkout:

```sh
export KMIP_PKI=$PWD/.cache/dev-pki
cd examples/clients/go
go run .
```

```text
created a5639e1e-36a5-4efc-b77a-000b35956739: 32-byte AES key over KMIP 1.4
decrypted "hello"
Get after Destroy: IllegalOperation: Key value has been destroyed
```

[`main.go`](../../examples/clients/go/main.go) dials with the test
certificates, creates, activates and fetches an AES key, encrypts and
decrypts with AES-GCM on the server, then revokes and destroys the key:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
client, err := kmipclient.DialContext(ctx, "localhost:5696",
	kmipclient.WithRootCAFile(pki+"/ca.pem"),
	kmipclient.WithClientCertFiles(pki+"/"+cert+".pem", pki+"/"+cert+".key"), // cert: KMIP_CLIENT, default client
)
// …
created, err := client.Create().
	AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
	ExecContext(ctx)
```

For AES-GCM the server picks the IV and returns it with the ciphertext and
tag; store all three. `DialContext` negotiates the version with Discover
Versions, and `kmipclient.EnforceVersion(kmip.V1_4)` pins one; AES-GCM needs
KMIP 1.4.

This program fetches the key with Get to show it; encrypting on the server
does not by itself stop anyone allowed Get from doing the same. For a key
that must stay on the server, create it non-extractable; Get then fails with
`NotExtractable`, as in the [HTTPS example](https.md#encrypt-and-decrypt-with-aes-gcm):

```go
created, err := client.Create().
	AES(256, kmip.CryptographicUsageEncrypt|kmip.CryptographicUsageDecrypt).
	WithAttribute(kmip.AttributeNameExtractable, false). // KMIP 1.4 and later
	ExecContext(ctx)
```

The application's certificate should also lack attribute changes, which could
set Extractable back ([role templates](../configuration.md#role-templates)).

## Errors and deadlines

`ExecContext` folds a KMIP failure into a plain error string. `Batch`
returns the result item instead, so the program can check the Result Reason
of its Get after Destroy; its error is only for TLS, connection or encoding
failures:

```go
res, err := client.Batch(ctx, &payloads.GetRequestPayload{UniqueIdentifier: id})
if err != nil {
	log.Fatal(err)
}
if bi := res[0]; bi.ResultStatus != kmip.ResultStatusSuccess {
	fmt.Printf("Get after Destroy: %s: %s\n", ttlv.EnumStr(bi.ResultReason), bi.ResultMessage)
}
```

`Dial` and `Exec` have no timeout of their own. The context deadline bounds
the dial, the TLS handshake and each request; a server that does not answer
in time gives `context deadline exceeded`. In a long-running program, give
each request its own `context.WithTimeout`. With the certificate that the
CA trusts but the policy does not list, `DialContext` already fails:

```sh
KMIP_CLIENT=unlisted go run .
```

```text
Operation "DiscoverVersions" failed (status="OperationFailed", reason="PermissionDenied") Operation denied by certificate policy
exit status 1
```

## Find a key by Name

[`locate/main.go`](../../examples/clients/go/locate/main.go), in the same
module, finds `orders-kek` or creates it on the first run, and activates a key
that an interrupted run left Pre-Active. In the same directory:

```sh
go run ./locate
go run ./locate
```

```text
created orders-kek: 16f81ad4-f1eb-4671-a312-1b51227f4ca6
found orders-kek: 16f81ad4-f1eb-4671-a312-1b51227f4ca6
```

```go
found, err := client.Locate().WithName(name).ExecContext(ctx)
if err != nil || len(found.UniqueIdentifier) == 0 {
	return "", err
}
return found.UniqueIdentifier[0], nil
```

Names are unique per principal: if another process creates the key between
the Locate and the Create, the server refuses the second Create and the
program locates again. Another principal's `orders-kek` is a different
object, invisible here
([tenant isolation](../authorization.md#tenant-isolation-and-names)). Locate
filters on other attributes too ([Locate](../locate.md)).

More operations (Register, CBC and ECB encryption) are in the project's
adapter, [`interop/ovh-release/main.go`](../../interop/ovh-release/main.go).

Next: [beyond the test setup](../clients.md#beyond-the-test-setup).
