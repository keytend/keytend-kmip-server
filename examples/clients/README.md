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

# Client examples

Complete programs for the [client pages](../../docs/clients.md), one
directory per language, with their dependency manifests. They run against the
[quick-start server](../../docs/quick-start.md) and read its test
certificates from `KMIP_PKI`. Like [`kmip.sh`](../https/kmip.sh), every
program uses the client certificate that `KMIP_CLIENT` names in that
directory: `client` by default, `other` (read-only) or `unlisted` (refused by
the policy). From the checkout:

```sh
export KMIP_PKI=$PWD/.cache/dev-pki
```

| Directory | Library | Then, in the directory | Page |
| --- | --- | --- | --- |
| [`python`](python) | PyKMIP (`requirements.txt`); standard library | `../../../.cache/pykmip/bin/python connect.py` | [Python](../../docs/clients/python.md) |
| [`go`](go) | OVH kmip-go (`go.mod`, `go.sum`) | `go run .` | [Go](../../docs/clients/go.md) |
| [`java`](java) | keytend-kmip 0.9.1, from the signed release zip | `./run.sh Quickstart` | [Java](../../docs/clients/java.md) |
| [`c`](c) | OpenKMIP libkmip (`Makefile`) | `make && ./create_get` | [C](../../docs/clients/c.md) |
| [`rust`](rust) | NLnet Labs kmip-protocol (`Cargo.toml`, `Cargo.lock`) | `cargo run --locked` | [Rust](../../docs/clients/rust.md) |

Each page lists the prerequisites, the other programs and their output.
Downloads and build output stay in the directories, ignored by Git;
`git clean -ffdX examples/clients` removes them.
