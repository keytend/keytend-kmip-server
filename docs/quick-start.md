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

# Quick start

Part of [getting started](README.md#getting-started).

Run a local server with disposable test certificates, then create and fetch a
key: first with `curl` over HTTPS JSON, then with PyKMIP over binary KMIP.
Everything here is for evaluation; deployment beyond the local test setup is
in [deployment](deployment.md).

- [Prerequisites](#prerequisites)
- [Run the container](#run-the-container), from a local build or
  [the signed release](#use-the-signed-release-instead)
- [Make a request with curl](#make-a-request-with-curl)
- [Make a request with a KMIP library](#make-a-request-with-a-kmip-library)
- [Clean up](#clean-up)

Afterwards, [manual installation](manual-install.md) shows each step of the
script by hand, how to
[change a setting](manual-install.md#change-a-setting) and
[renew the test certificates](manual-install.md#renew-the-test-certificates),
and running from source.

## Prerequisites

| Need | Version and notes |
| --- | --- |
| Host | Linux, amd64 or arm64 |
| Container engine | Podman, or Docker 23 or later |
| Tools | Git, bash or zsh, `curl` 7.71 or later, Python 3.8 or later (3.12 or later for the signed release), `openssl` from OpenSSL 1.1.1 or later (`openssl version`) |
| To build the image | Network access to `registry.access.redhat.com`, the UBI package repositories and crates.io; about 1.5 GB of disk. The first build takes a few minutes. |
| For the signed release | gpg (GnuPG 2.2 or later); about 240 MB of downloads from GitHub: the 91 MB release and, on Linux, the 146 MB pinned cosign |

- The build needs BuildKit, Docker's default from 23.
- Your user must be allowed to run containers (rootless Podman, or Docker's
  `docker` group); the container itself runs as your user.
- macOS is untested. To try it, put OpenSSL 3 first on the `PATH` (the system
  `openssl` is LibreSSL), and install cosign 3 for the signed release:
  `brew install openssl@3 cosign; export PATH="$(brew --prefix openssl@3)/bin:$PATH"`.

## Run the container

Get the source; run every later command from the checkout:

```sh
git clone https://github.com/keytend/keytend-kmip-server
cd keytend-kmip-server
```

Then [build the image](#build-the-image) from the checkout, or
[load the signed release candidate](#use-the-signed-release-instead)
0.10.0-rc.1, which needs no build.

### Build the image

The `:dev` tag marks a local build. On amd64 (`uname -m` prints `x86_64`):

```sh
docker build -t localhost/keytend-kmip-server:dev .
```

On arm64 (`uname -m` prints `aarch64` or `arm64`), with the arm64 base images:

```sh
docker build --platform linux/arm64 \
  --build-arg UBI_BUILDER="$(sed -n 's/^ARG UBI_BUILDER_ARM64=//p' Dockerfile)" \
  --build-arg UBI_MICRO="$(sed -n 's/^ARG UBI_MICRO_ARM64=//p' Dockerfile)" \
  -t localhost/keytend-kmip-server:dev .
```

With Podman, or a `docker` command that is Podman (`docker --version` says
so), add `--format docker`; it keeps the image's health check, which the OCI
format has no field for:

```sh
podman build --format docker -t localhost/keytend-kmip-server:dev .
```

### Use the signed release instead

[`scripts/verify_release.sh`](../scripts/verify_release.sh) downloads a
release into a new directory outside the checkout, checks the cosign
signature of its `SHA256SUMS` with the checkout's
[`signing/cosign.pub`](../signing/cosign.pub) and its OpenPGP signature,
then every digest, and only then loads the image for this host's
architecture, tagged with its version. [Verifying a release](release-signing.md#verifying-a-release) shows
each step and the other ways to verify.

```sh
scripts/verify_release.sh 0.10.0-rc.1
```

```text
Verified OK
pgp_verify: good signature by the Keytend release key: /tmp/tmp.Xa1b2C3d4E/release/SHA256SUMS
…
verified and loaded localhost/keytend-kmip-server:0.10.0-rc.1
release files: /tmp/tmp.Xa1b2C3d4E/release
next: IMAGE=localhost/keytend-kmip-server:0.10.0-rc.1 scripts/quick-start.sh
```

cosign also warns about the transparency log, which releases do not use. The
`next:` command starts the server ([start it](#start-it)).

### Start it

```sh
scripts/quick-start.sh
# the signed release: IMAGE=localhost/keytend-kmip-server:0.10.0-rc.1 scripts/quick-start.sh
```

```text
ready
next (bash or zsh): . examples/https/kmip.sh && kmip create.json | field ResultStatus
```

The script uses `docker`, or `podman` when there is no `docker`; with both
installed, run `DOCKER=podman scripts/quick-start.sh` to use Podman.

It writes disposable test certificates (valid for 7 days) and a new master
key under `.cache/`, then starts the container `keytend-kmip-server` on
`127.0.0.1` ports 5696 (binary KMIP), 5697 (HTTPS) and 8080 (health)
([what it runs](manual-install.md#start-the-server)). The test policy lets
the `client` certificate call every operation; `unlisted` is trusted by the
CA but not in the policy. Never use this CA or policy outside a test.
`docker logs keytend-kmip-server` shows the server's log.

If another process holds one of those ports, the container does not start
and the error says `address already in use` (Podman) or
`port is already allocated` (Docker). `sudo ss -ltnp 'sport = :8080'` (or
`:5696`, `:5697`) names the process; stop it, since the script has no port
setting.

The script refuses to run again until you [clean up](#clean-up). A stopped
container (after `docker stop` or a reboot) starts again with
`docker start keytend-kmip-server`. After `docker rm`, or to apply a changed
setting, `scripts/quick-start.sh --restart` recreates the container and keeps
the certificates, master key, data and image.

## Make a request with curl

KMIP over HTTPS is a `POST` of one request message to `/kmip`, authenticated by
the client certificate.
[`examples/https/create.json`](../examples/https/create.json) is a KMIP 2.1
Create request for a 256-bit AES key (the format is in
[JSON, XML and HTTPS bindings](encodings.md)). Send it with the test `client`
certificate:

```sh
P=.cache/dev-pki
curl -sS --cacert $P/ca.pem --cert $P/client.pem --key $P/client.key \
  -H 'Content-Type: application/json' --data-binary @examples/https/create.json \
  https://localhost:5697/kmip | grep -oE '"(ResultStatus|UniqueIdentifier)"[^}]*'
```

```text
"ResultStatus","type":"Enumeration","value":"Success"
"UniqueIdentifier","type":"TextString","value":"e7d04ef6-0dca-4540-a188-402a5bce6917"
```

If `curl` fails the TLS handshake, the test certificates have probably expired
([renew them](manual-install.md#renew-the-test-certificates)).

[`examples/https/kmip.sh`](../examples/https/kmip.sh) wraps that command in
shell functions (bash or zsh): `kmip FILE [NAME=VALUE …]` sends a request
file from that directory, filling in its `$NAME` placeholders, and
`field TAG` prints a value from the JSON response. Create another key and
keep its identifier:

```bash
. examples/https/kmip.sh
R=$(kmip create.json)
field ResultStatus <<<"$R"
ID=$(field UniqueIdentifier <<<"$R"); echo "$ID"
```

```text
Success
3f2c9a4e-58b1-4f0e-9d7c-1a6b2e8d4c07
```

If the status is not `Success`, `field ResultReason <<<"$R"` and
`field ResultMessage <<<"$R"` say why. Fetch the key with Get
([`get.json`](../examples/https/get.json), with `$ID` where the identifier
goes); `pretty <<<"$R"` shows the whole response:

```bash
R=$(kmip get.json ID="$ID")
field ResultStatus <<<"$R"
field KeyMaterial <<<"$R"
```

```text
Success
9e96ffb8c1d0a6e2…5395683f7
```

The 32 key bytes are the hex `KeyMaterial` value (shortened here).

Now send the Create with the `unlisted` certificate, which the CA trusts but
the policy does not list: TLS succeeds, and the server refuses the request.

```sh
KMIP_CLIENT=unlisted kmip create.json | field ResultReason
```

```text
PermissionDenied
```

- Without a client certificate the TLS handshake fails.
- The script starts the server with `--text-encoding readable`
  (`KMIP_TEXT_ENCODING`). Without it the server answers in the default
  `compatible` forms, in which JSON enumerations are hex codes (`0x00000000`
  for Success).

XML, Locate, batches and AES-GCM Encrypt with the same functions are in
[HTTPS with JSON or XML](clients/https.md).

## Make a request with a KMIP library

Most applications speak binary KMIP on port 5696 through a library. Install
[PyKMIP](https://github.com/OpenKMIP/PyKMIP) at the commit this project tests,
pinned in
[`examples/clients/python/requirements.txt`](../examples/clients/python/requirements.txt).
This needs Python's `venv` module (the `python3-venv` package on Debian and
Ubuntu), `git` and access to GitHub; offline, use the
[curl requests](#make-a-request-with-curl).

```sh
python3 -m venv .cache/pykmip
.cache/pykmip/bin/pip install -r examples/clients/python/requirements.txt
```

[`examples/clients/python/quickstart.py`](../examples/clients/python/quickstart.py)
creates, fetches and destroys a key:

```python
import os

from kmip.core import enums
from kmip.pie.client import ProxyKmipClient

PKI = os.environ.get("KMIP_PKI", ".cache/dev-pki")  # the quick start's test certificates
CLIENT = os.environ.get("KMIP_CLIENT", "client")    # the client certificate in PKI

with ProxyKmipClient(
    hostname="localhost", port=5696,
    cert=f"{PKI}/{CLIENT}.pem", key=f"{PKI}/{CLIENT}.key", ca=f"{PKI}/ca.pem",
    ssl_version="PROTOCOL_TLSv1_2", kmip_version=enums.KMIPVersion.KMIP_1_4,
) as client:
    uid = client.create(
        enums.CryptographicAlgorithm.AES, 256,
        cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT,
                                  enums.CryptographicUsageMask.DECRYPT],
    )
    client.activate(uid)
    key = client.get(uid)
    print(f"created {uid}: {len(key.value)}-byte AES key")
    client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, uid)
    client.destroy(uid)
    print(f"destroyed {uid}")
```

```sh
.cache/pykmip/bin/python examples/clients/python/quickstart.py
```

```text
created 8813e065-0fbf-4766-8977-0ac32ce6a0a1: 32-byte AES key
destroyed 8813e065-0fbf-4766-8977-0ac32ce6a0a1
```

PyKMIP also prints a `Config file … not found` notice on standard error; it is
harmless. PyKMIP checks the server certificate against `ca` but not the
hostname, so trust only a CA that issues certificates for this server
([Python](clients/python.md#connection-settings)). Go, Java, C, Rust, HTTPS
and more Python tasks are in the [client guide](clients.md).

## Clean up

From the checkout:

```sh
scripts/quick-start.sh --clean
rm -rf .cache/pykmip                 # the KMIP library example
git clean -ffdXq examples/clients    # downloads and builds of the client pages
```

```text
removed container keytend-kmip-server
removed .cache/container, .cache/dev-pki and .cache/dev-data
```

`--clean` removes the container started from this checkout,
`.cache/container`, `.cache/dev-pki` and `.cache/dev-data` (the store of a
server [run from source](manual-install.md#run-from-source); stop that server
first). `git clean -ffdX` removes only files that Git ignores, here the
libkmip clone and the C build, the keytend-kmip clone or zip and its
signature, and the Rust build of the
[client pages](clients.md#examples-by-language). The clones are Git
repositories, hence the second `-f`.

The images and downloads stay. To remove them too:

```sh
docker rmi localhost/keytend-kmip-server:dev   # a local build
docker rmi localhost/keytend-kmip-server:0.10.0-rc.1   # the signed release (arm64: also …:0.10.0-rc.1-arm64)
docker builder prune   # the build cache of every build on this host (about 1.5 GB after this one)
```

`verify_release.sh` keeps its download (about 90 MB): remove the directory
above the `release files:` path it printed, such as
`rm -rf /tmp/tmp.Xa1b2C3d4E`. On Linux it also keeps the pinned cosign in
`.cache/bin` (`rm -rf .cache/bin`).

Next: [connect your client](clients.md), [configure](configuration.md),
[deploy](deployment.md).
