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

<img src="assets/icon.svg" width="64" height="64" alt="Keytend logo">

# keytend-kmip-server

A key management server that speaks KMIP (the OASIS Key Management
Interoperability Protocol), written in Rust, shipped as a container image for
Docker and Kubernetes.

> [!WARNING]
> **A test server, not for production use.** keytend-kmip-server is an
> experimental KMIP implementation for CI systems and for validating KMIP
> clients and implementations. It implements a subset of KMIP 1.0–2.1, holds
> no conformance certification and has had no independent security audit.
> It stays a test server at 1.0 and beyond: do not use it to protect real
> keys or data. The current release is 0.10.0-rc.1.

To evaluate it, read [project status](docs/status.md), the
[support matrix](docs/support-matrix.md) and [security](SECURITY.md). To
integrate it, run the [quick start](#quick-start), then
[connect a client](docs/clients.md) and [configure](docs/configuration.md).

- Use it as a KMIP server in CI pipelines and test environments, to validate
  KMIP client libraries and products with KMIP key management (for example
  Percona Server for MongoDB and MySQL).
- Applications either fetch keys and encrypt locally
  ([getting keys](docs/key-transfer.md)), or keep them on the server and call
  Encrypt, Decrypt, Sign and Verify there
  ([server-side cryptography](docs/crypto-operations.md)).
- Keys live in one SQLite store sealed by a local master-key file, with no
  other KMS or HSM behind it. A policy file sets access; there is no admin
  API.
- Not supported yet: high availability (it runs as a single replica with a
  local store), HSMs, and applying policy or TLS changes without a restart.

## Features

| Feature | Details |
| --- | --- |
| Protocol | Partial support for KMIP 1.0–1.4, 2.0 and 2.1; the 3.0 draft (CSD02) behind `--experimental-v3` |
| Transports | Binary TTLV (Tag, Type, Length, Value) over TLS on 5696; optional HTTPS with TTLV, JSON or XML on 5697 |
| Authentication | Mutual TLS; a policy file lists each client certificate and the operations it may call; optional [header credentials](docs/credentials.md) |
| Objects | Symmetric keys, RSA and EC key pairs, certificates, secret data, opaque objects, split keys, PGP keys ([all](docs/support-matrix.md)) |
| Storage | One SQLite database, every object encrypted with AES-256-GCM, tamper-evident ([store integrity](docs/store-integrity.md)) |
| Clients | Binary KMIP 1.x libraries; binary 2.x with keytend-kmip (Java) or IBM libkmipclient (C); any language over HTTPS JSON/XML ([details](docs/clients.md)) |
| Tested with | Percona Server for MongoDB 8.0 and MySQL 8.4; six independent KMIP libraries ([list](docs/clients.md#tested-clients); [what the tests show](docs/status.md#what-has-been-tested)) |
| Runs as | UBI 9 micro image (amd64, arm64), non-root; optional [FIPS mode](docs/fips.md) (not validated) |
| Deployment | Docker or Compose ([deployment](docs/deployment.md)); a [Helm chart](docs/kubernetes.md) for Kubernetes with scheduled backups, and restore, master-key rotation and maintenance mode set through Helm values |
| Distribution | Signed image archives on [GitHub releases](https://github.com/keytend/keytend-kmip-server/releases) ([verify](docs/release-signing.md#verifying-a-release)); no registry image yet |
| License | Apache 2.0 |

## Quick start

Start the server with disposable test certificates, then create a 256-bit
AES key with a KMIP 2.1 request over HTTPS JSON
([`create.json`](examples/https/create.json)). On an amd64 Linux host with
Docker, Git, bash or zsh, curl, Python 3 and OpenSSL
([prerequisites](docs/quick-start.md#prerequisites)):

```sh
git clone https://github.com/keytend/keytend-kmip-server
cd keytend-kmip-server
```

Get the image in one of two ways:

- Build it (a few minutes, about 1.5 GB of disk):

  ```sh
  docker build -t localhost/keytend-kmip-server:dev .
  ```

- Or load the signed 0.10.0-rc.1 release (needs Python 3.12 or later and gpg):

  ```sh
  scripts/verify_release.sh 0.10.0-rc.1 && export IMAGE=localhost/keytend-kmip-server:0.10.0-rc.1
  ```

Then start it and run the command it suggests:

```sh
scripts/quick-start.sh
```

```text
ready
next (bash or zsh): . examples/https/kmip.sh && kmip create.json | field ResultStatus
```

```sh
. examples/https/kmip.sh && kmip create.json | field ResultStatus
```

```text
Success
```

With Podman, build with `podman build --format docker …`; the script uses
`podman` when there is no `docker` (or set `DOCKER=podman`).
`scripts/quick-start.sh --clean` removes the container and the test state.

The [quick start](docs/quick-start.md) goes on to fetch the key, covers arm64
and a request through a KMIP library; [manual installation](docs/manual-install.md)
shows each step by hand, changing a setting, and running from source.

## Documentation

- [Project status](docs/status.md) and the
  [support matrix](docs/support-matrix.md)
- [Connecting a client](docs/clients.md): examples for Python, Go, Java
  ([keytend-kmip](https://github.com/keytend/keytend-kmip-java), the Keytend
  Java client), C, Rust and HTTPS JSON/XML
- [Client errors and retries](docs/client-errors.md)
- [Configuration reference](docs/configuration.md),
  [deployment](docs/deployment.md) (Docker, Compose) and
  [Kubernetes](docs/kubernetes.md) (Helm chart)
- [Operations runbooks](docs/operations.md): backup and restore, master-key rotation,
  upgrades, troubleshooting
- [Percona database encryption](docs/percona.md)
- [Security policy](SECURITY.md): trust boundaries, hardening, reporting
- [All documentation](docs/README.md), including common tasks

## Development

Build and test commands are in [testing](docs/testing.md). Report security
issues privately through
[GitHub](https://github.com/keytend/keytend-kmip-server/security/advisories/new)
([security policy](SECURITY.md)); other
questions and bugs go to the
[issue tracker](https://github.com/keytend/keytend-kmip-server/issues). The
project has a single maintainer; open an issue before starting a pull request.

## License

Apache License 2.0 ([LICENSE](LICENSE)), Copyright 2026 Jeremiah Jordan.
[NOTICE](NOTICE) keeps third-party attributions. The image carries both in
`/usr/share/licenses/keytend-kmip-server/`. The container image also contains
Red Hat UBI packages, redistributable under the UBI End User License Agreement
([licences and notices](docs/container-image.md#licences-and-notices)).
