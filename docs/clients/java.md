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

# Java (keytend-kmip)

Part of [connecting a client](../clients.md).

[keytend-kmip](https://github.com/keytend/keytend-kmip-java) 0.9.1 is this
project's Java client, for JDK 17, 21 and 25. It negotiates KMIP 1.4–2.1 by
default (2.1 against this server) and can be pinned to 1.1–1.3, over binary
KMIP or HTTPS. The complete programs are in
[`examples/clients/java`](../../examples/clients/java), with
[`run.sh`](../../examples/clients/java/run.sh) to run them against the
client jar.

- [Install](#install)
- [Binary KMIP](#binary-kmip): find or create a named AES key, encrypt and
  decrypt on the server
- [Sign and verify](#sign-and-verify) with an EC or RSA key pair
- [HTTPS](#https)
- [Errors](#errors)
- [Connection settings](#connection-settings)

## Install

You need a JDK (17, 21 or 25) and bash or zsh. `run.sh` expects two jars in
`examples/clients/java/keytend-kmip-0.9.1/lib`, which Git ignores: the SDK,
`keytend-kmip-0.9.1.jar`, and `slf4j-api-*.jar`, the logging API the SDK needs
at run time. keytend-kmip is not on Maven Central yet (planned from 1.0).

You also need `curl`, `unzip` and GnuPG 2.2 or later (`gpg`). Download the
[v0.9.1 release](https://github.com/keytend/keytend-kmip-java/releases/tag/v0.9.1)
zip and its signature, verify the signature against the Keytend release key
committed in this repository, and unzip it only if that succeeds. Run from the
checkout:

```sh
export KMIP_PKI=$PWD/.cache/dev-pki
cd examples/clients/java
BASE=https://github.com/keytend/keytend-kmip-java/releases/download/v0.9.1
curl -fsSLO "$BASE/keytend-kmip-0.9.1.zip" && curl -fsSLO "$BASE/keytend-kmip-0.9.1.zip.asc"
. ../../../signing/pgp_verify.sh
pgp_verify keytend-kmip-0.9.1.zip.asc keytend-kmip-0.9.1.zip && unzip -q keytend-kmip-0.9.1.zip
```

```text
pgp_verify: good signature by the Keytend release key: keytend-kmip-0.9.1.zip
```

[`signing/pgp_verify.sh`](../../signing/pgp_verify.sh) accepts only a good
signature whose primary key is the
[Keytend release key](../release-signing.md#openpgp-signature), and refuses
one by an expired or revoked key, which plain `gpg --verify` accepts. That
page also shows how to check the fingerprint against an independent copy.

The zip's `lib/` holds both jars `run.sh` uses. To use the SDK from Maven,
run `./mvnw install` in the unzipped `keytend-kmip-0.9.1` directory and depend
on `dev.keytend:keytend-kmip:0.9.1`; Maven brings slf4j-api with it.

`run.sh` puts only the SDK and slf4j-api on the class path, with no logging
binding, so the examples other than `HttpsQuickstart` first print three
`SLF4J(W)` warnings to stderr
(`No SLF4J providers were found`). They are harmless here; an application
binds slf4j-api to its own logging.

## Binary KMIP

[`Quickstart.java`](../../examples/clients/java/Quickstart.java) uses the
high-level `Kms` API: it finds or creates a named AES key and encrypts with
AES-GCM on the server. Run from `examples/clients/java`, with the quick-start
server running and `KMIP_PKI` set as above:

```sh
./run.sh Quickstart
```

```text
KMIP 2.1, key 71a21001-c643-4c7e-b5ac-683cc977ca73 round trip: hello
```

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("localhost:5696")
    .clientIdentityPem(pki.resolve(cert + ".pem"), pki.resolve(cert + ".key"))
    .trustPem(pki.resolve("ca.pem"))
    .build();
try (Kms kms = Kms.connect(config)) {
  KeyHandle kek = kms.keys().createAes(256).named("quickstart-kek")
      .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
      .extractable(false)  // the server refuses to return the key's value
      .findOrCreate();
  byte[] aad = "record-42".getBytes(StandardCharsets.UTF_8);
  byte[] plaintext = "hello".getBytes(StandardCharsets.UTF_8);
  byte[] stored = kek.encrypt(CipherSpec.aesGcm(), plaintext, aad).toBytes();
  byte[] back = kek.decrypt(Ciphertext.fromBytes(stored), aad);
```

`cert` is `KMIP_CLIENT`, default `client`. `findOrCreate` returns the Active
key with that Name or creates and activates one, so the example can run
again. `stored` is what the application keeps; `Ciphertext.fromBytes` reads
it back for Decrypt.

With `extractable(false)`, Get of the key fails with `NotExtractable`, as in
the [HTTPS example](https.md#encrypt-and-decrypt-with-aes-gcm). The
application's certificate should also lack attribute changes, which could set
Extractable back ([role templates](../configuration.md#role-templates)).

## Sign and verify

[`Sign.java`](../../examples/clients/java/Sign.java) finds or creates an EC
P-256 key pair whose private key signs on the server and whose public key
verifies:

```sh
./run.sh Sign
```

```text
signed with abf06db3-2a8f-47de-aecd-898dd1e26936
original: VALID
altered:  INVALID
```

```java
KeyPairHandle signer = kms.keys().createKeyPair(KeyPairSpec.ec(Curve.P_256))
    .named("quickstart-signer", "quickstart-signer-public")
    .privateUsages(KeyUsage.SIGN).publicUsages(KeyUsage.VERIFY)
    .findOrCreate();
SignatureSpec ecdsa = SignatureSpec.ecdsa(Hash.SHA_256);
byte[] signature = signer.privateKey().sign(ecdsa, message);
var verifier = signer.publicKey();
System.out.println("original: " + verifier.verify(ecdsa, message, signature));
```

`findOrCreate` names both halves, so the example can run again with the same
pair. `KeyPairSpec.rsa(3072)` with `SignatureSpec.rsaPss(Hash.SHA_256)` (or
`rsaPkcs1`) does the same with RSA. A signature that does not match is
`INVALID`, not an exception.

## HTTPS

The lower-level `KmipClient` takes any transport.
[`HttpsQuickstart.java`](../../examples/clients/java/HttpsQuickstart.java)
uses the HTTPS listener with JSON bodies (`Encoding.TTLV` and `Encoding.XML`
also work); it reads the client identity as PKCS#12, `client.p12` (or the
`KMIP_CLIENT` name):

```sh
openssl pkcs12 -export -in "$KMIP_PKI/client.pem" -inkey "$KMIP_PKI/client.key" \
  -out "$KMIP_PKI/client.p12" -passout pass:changeit
./run.sh HttpsQuickstart
```

```text
created f3919ba2-1f5b-44e2-9447-11172d438e01 over HTTPS JSON, KMIP 2.1
```

```java
var tls = Tls.context(pki.resolve(cert + ".p12"), "changeit".toCharArray(),
    pki.resolve("ca.pem"));
var https = new HttpsTransport(URI.create("https://localhost:5697/kmip"), tls,
    HttpsTransport.Encoding.JSON);
try (var client = new KmipClient(https, ProtocolVersion.of(2, 1))) {
  String id = client.createSymmetricKey(Enums.CryptographicAlgorithm.AES, 256,
      Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT);
```

## Errors

Every `Kms` failure is an unchecked `KmsException`. Branch on `category()`
(`NOT_FOUND`, `FIX_ACCESS`, `STATE`, `RETRY`, `OUTCOME_UNKNOWN` and others);
`serverReason()` is the server's Result Reason as the client's `KmsReason`
enum, empty when no server answered. One constant can cover several KMIP
reasons with the same remedy: Item Not Found and Object Not Found are both
`NOT_FOUND`.
[`Errors.java`](../../examples/clients/java/Errors.java) reads a key that
does not exist and prints the category, the reason and the message:

```java
try (Kms kms = Kms.connect(config)) {
  kms.keys().handle("no-such-key").attributes();
} catch (KmsException e) {
  System.out.println(e.category() + " " + e.serverReason().orElse(null)
      + ": " + e.getMessage());
}
```

```sh
./run.sh Errors
```

```text
NOT_FOUND NOT_FOUND: attributes no-such-key failed: KMIP GetAttributes returned OperationFailed (1), reason ObjectNotFound (0x00000037) (server message: "Object not found")
```

With the certificate that the CA trusts but the policy does not list,
`KMIP_CLIENT=unlisted ./run.sh Errors` fails at connect:

```text
FIX_ACCESS PERMISSION_DENIED: connect failed: KMIP DiscoverVersions returned OperationFailed (1), reason PermissionDenied (0x0000000C) (server message: "Operation denied by certificate policy")
```

With the server stopped the same program prints `RETRY null: connect: KMIP
request not sent: Connection refused …`. Create one `Kms` per process (it is
thread-safe) and close it at shutdown.

## Connection settings

`KmsConfig.builder()` settings that matter against this server:

| Setting | Default | Notes |
| --- | --- | --- |
| Hostname verification | always on | The server certificate must list the host name given to `endpoints`; there is no switch to turn it off. |
| `callTimeout(d)` | 30 s | One deadline per call, across retries and the wait for a pooled connection; `kms.withTimeout(d)` overrides it per call site. |
| `connectTimeout(d)` | 10 s | TCP connect and TLS handshake together. |
| `poolSize(n)`, `idleTimeout(d)` | 4, 30 s | Connections kept per endpoint, and how long an idle one is kept. |
| `minimumVersion`, `maximumVersion`, `versions(…)` | 1.4 to 2.1 | `versions(KmipVersion.V1_4)` pins one version. |

### Reconnecting

- A pooled connection that has been idle is checked before reuse, so the
  server's idle close (`--idle-timeout`) does not fail a call.
- After a transient failure, reads and cryptographic calls are tried up to
  three times within the call's deadline, on the next endpoint when there
  are several. Reads are Get, Locate, Get Attributes and Query; cryptographic
  calls are Encrypt, Decrypt, Sign, Verify and MAC.
- A retried Encrypt or Sign counts against the key's usage limits again.
  `retryPolicy(RetryPolicy.defaults().toBuilder().retryCrypto(false).build())`
  stops those retries.
- Mutations are never re-sent: a lost answer raises `OUTCOME_UNKNOWN`
  ([retrying](../client-errors.md#retrying-after-a-lost-response)).

The client's own documentation (in `keytend-kmip-0.9.1/docs/` in the zip,
starting with `operating-keys.md` and `choosing-an-api.md`) covers failure categories, rotation,
envelopes, connection pooling, credentials and the lower-level API.

Next: [beyond the test setup](../clients.md#beyond-the-test-setup).
