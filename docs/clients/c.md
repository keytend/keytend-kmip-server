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

# C (OpenKMIP libkmip)

Part of [connecting a client](../clients.md).

[OpenKMIP libkmip](https://github.com/OpenKMIP/libkmip), tested at commit
`6611941`, binary KMIP 1.0–1.4. The complete program is
[`examples/clients/c/create_get.c`](../../examples/clients/c/create_get.c),
with a [`Makefile`](../../examples/clients/c/Makefile) that builds libkmip at
that commit next to it.

## Create and Get

You need a C compiler, `make`, Git and the OpenSSL development headers
(`build-essential libssl-dev` on Debian, `gcc make openssl-devel` on RHEL).
With the [quick-start server](../quick-start.md) running, run from the
checkout:

```sh
export KMIP_PKI=$PWD/.cache/dev-pki
cd examples/clients/c
make
./create_get
```

```text
created, fetched and destroyed 5f811f5f-9e1b-4521-8b75-bd1e5ae564c8: 32-byte AES key
```

`make` clones libkmip into `libkmip/` (Git ignores it and `create_get`;
`make clean` removes both). The program creates an AES-256 key, fetches it
and destroys it over mutual TLS, using the client certificate that
`KMIP_CLIENT` names (default `client`). The TLS setup, with the chain check (`SSL_VERIFY_PEER`) and the hostname
check (`SSL_set1_host`):

```c
SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
if (ctx == NULL
    || SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1
    || SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1                 /* server CA */
    || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1                /* client certificate */
    || SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1)
    return fail("TLS setup");
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

BIO *bio = BIO_new_ssl_connect(ctx);
SSL *ssl = NULL;
if (bio != NULL) BIO_get_ssl(bio, &ssl);
if (ssl == NULL || SSL_set1_host(ssl, "localhost") != 1)                 /* check the name */
    return fail("TLS setup");
BIO_set_conn_hostname(bio, "localhost:5696");
if (BIO_do_connect(bio) != 1 || BIO_do_handshake(bio) != 1)
    return fail("TLS connection");
```

and the KMIP calls, which return `KMIP_OK`, a negative libkmip error, or the
failed KMIP Result Status:

```c
int result = kmip_bio_create_symmetric_key_with_context(&k, bio, &ta, &id, &id_len);
if (result == KMIP_OK)
    result = kmip_bio_get_symmetric_key_with_context(&k, bio, id, id_len, &key, &key_len);
if (result == KMIP_OK)  /* a new key is Pre-Active, so Destroy needs no Revoke */
    result = kmip_bio_destroy_symmetric_key_with_context(&k, bio, id, id_len);
```

The project's test adapter, [`interop/libkmip.c`](../../interop/libkmip.c),
runs the same exchange in every 1.x version.

## Errors

On failure the program prints the status and, for Create and Get, the
Result Reason and Message that libkmip records (Destroy records none). With
another certificate:

| Command | Prints |
| --- | --- |
| `KMIP_CLIENT=unlisted ./create_get` (trusted by the CA, not in the policy) | `KMIP request failed: status 1, Permission Denied: Operation denied by certificate policy` |
| `KMIP_CLIENT=other ./create_get` (principal `other-tenant`, which may only read) | the same line: its Create is refused, and it cannot see `client`'s keys |

Status 1 is Result Status Operation Failed. A negative status is a libkmip
error, such as a failed connection or a timeout, with no Result Reason.

## Timeouts

libkmip's BIO calls block. After the connection is up, the program sets
10-second socket timeouts, so a server that accepts the connection but never
answers ends it with status -13, `KMIP_IO_FAILURE`, instead of hanging:

```c
struct timeval limit = {.tv_sec = 10};
int fd = -1;
if (BIO_get_fd(bio, &fd) < 0
    || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, sizeof limit) != 0
    || setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, sizeof limit) != 0)
    return fail("socket timeouts");
```

The TCP connect and TLS handshake inside `BIO_do_connect` are not covered:
to bound them too, connect the socket yourself with a timeout, set the same
options, and attach it with `SSL_set_fd`.

Next: [beyond the test setup](../clients.md#beyond-the-test-setup).
