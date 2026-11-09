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

# Rust (NLnet Labs kmip-protocol)

Part of [connecting a client](../clients.md).

[NLnet Labs kmip-protocol](https://github.com/NLnetLabs/kmip-protocol) 0.4.3,
binary KMIP 1.0–1.2 (it picks the version per operation). Upstream describes
it as a partial implementation. The complete program is a Cargo package in
[`examples/clients/rust`](../../examples/clients/rust); its `Cargo.toml` pins
the crate and `Cargo.lock` the tested dependency versions.

## Create, Get and retire a key

You need Rust (tested with 1.99), a C compiler, `pkg-config` and the OpenSSL
development headers: `build-essential pkg-config libssl-dev` on Debian,
`gcc pkgconf-pkg-config openssl-devel` on RHEL. With the
[quick-start server](../quick-start.md) running, run from the checkout:

```sh
CHECKOUT=$PWD; export KMIP_PKI=$CHECKOUT/.cache/dev-pki
cd examples/clients/rust
cargo run --locked
```

```text
created 41454af8-a727-4560-a147-a188362c8c22: 32-byte AES key
Get after Destroy: Server error: Operation Get failed: Key value has been destroyed
```

[`src/main.rs`](../../examples/clients/rust/src/main.rs) connects with the
test certificates, creates, activates and fetches an AES key, then revokes
and destroys it:

```rust
let client = connect(&ConnectionSettings {
    host: "127.0.0.1".into(), // must match the server certificate (IP or DNS name)
    port: 5696,
    ca_cert: Some(fs::read(format!("{pki}/ca.pem"))?),
    client_cert: Some(ClientCertificate::SeparatePem {
        cert_bytes: fs::read(format!("{pki}/{name}.pem"))?,
        key_bytes: Some(fs::read(format!("{pki}/{name}.key"))?),
    }),
    connect_timeout: Some(Duration::from_secs(5)),
    read_timeout: Some(Duration::from_secs(10)),
    write_timeout: Some(Duration::from_secs(10)),
    ..Default::default()
})?;
```

## Errors

Failures come back as `kmip_protocol::client::Error`: `ItemNotFound` or
`ServerError` with the server's message for a KMIP failure, and
`is_connection_error()` for a lost connection. The program's Get after
Destroy tells them apart:

```rust
match client.get_key(&id) {
    Err(e) if e.is_connection_error() => return Err(e.into()),
    Err(e) => println!("Get after Destroy: {e}"), // the KMIP failure
    Ok(_) => return Err("destroyed key was returned".into()),
}
```

`KMIP_CLIENT` picks another certificate in `KMIP_PKI`. With the one the CA
trusts but the policy leaves out, the first request fails and the program
exits with status 1:

```sh
KMIP_CLIENT=unlisted cargo run --locked
```

```text
Error: ServerError("Operation Create failed: Operation denied by certificate policy")
```

## Connection notes

- The crate connects to the first address a name resolves to, so the program
  dials `127.0.0.1` rather than `localhost`, which can resolve to `::1` first
  while the server listens on IPv4 only.
- `connect_timeout` bounds the TCP connect, and `read_timeout` and
  `write_timeout` each socket read and write, the TLS handshake included.
  They default to none, so without them a server that does not answer blocks
  the call.

## More operations

The client also has helpers for key pairs, Sign and RNG Retrieve. The
project's test adapter, [`interop/nlnet`](../../interop/nlnet), uses them and
runs negative checks (other principals, unlisted and missing certificates).
With `KMIP_PKI` set as above, from any directory:

```sh
KMIP_PORT=5696 cargo run --locked --manifest-path "$CHECKOUT/interop/nlnet/Cargo.toml"
```

Next: [beyond the test setup](../clients.md#beyond-the-test-setup).
