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

# Manual installation

Part of [getting started](README.md#getting-started).

The commands [`scripts/quick-start.sh`](../scripts/quick-start.sh) runs, step
by step, and how to run the server from source instead of the container. Like
the [quick start](quick-start.md), this is for evaluation only.

- [Start the server](#start-the-server) in a container
- [Change a setting](#change-a-setting)
- [Renew the test certificates](#renew-the-test-certificates)
- [Run from source](#run-from-source)

## Start the server

Build the image first, as in the
[quick start](quick-start.md#run-the-container), or load the
[signed release](quick-start.md#use-the-signed-release-instead) and set
`IMAGE` to its tag. Run every command from the checkout, in one shell:

```sh
IMAGE=${IMAGE:-localhost/keytend-kmip-server:dev}
```

Create the test certificates and a state directory for the container. With
rootless Podman, add `--userns=keep-id` to this and the next `docker run`, so
that your user ID inside the container is your own; on SELinux hosts, also
add `:Z` to the volumes:

```sh
scripts/dev-pki.sh .cache/dev-pki
S=.cache/container
install -d -m 0700 $S $S/tls $S/policy $S/master $S/data
install -m 0400 .cache/dev-pki/server.pem .cache/dev-pki/server.key .cache/dev-pki/ca.pem $S/tls/
install -m 0400 .cache/dev-pki/policy.json $S/policy/
printf '%s\n' "$IMAGE" > $S/image   # the image, for quick-start.sh --restart
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/$S/master:/master" \
  "$IMAGE" generate-master-key --output /master/master.key
```

`scripts/dev-pki.sh` writes a test CA, a server certificate for `localhost`,
`127.0.0.1` and `keytend-kmip-server`, three client certificates and a users
file:

- `client` (principal `database`), which `policy.json` lets call every
  operation;
- `other` (principal `other-tenant`), read-only on its own objects;
- `unlisted`, which the CA trusts but the policy does not list;
- `users.json`, a test user for `client` that only the KMIP 3.0 profile
  tests use; the quick start does not install it.

They expire after 7 days ([renewing them](#renew-the-test-certificates);
[all test fixtures](testing.md#test-certificates)).

The master key is the 32-byte key that encrypts the store. Keep it apart from
the database and back it up separately: without it the stored keys are lost.

The server reads its settings from `KMIP_*` environment variables
([configuration](configuration.md#serve-settings)); keep them in an env file.
`KMIP_HTTPS_LISTEN` turns on the optional HTTPS listener, and
`KMIP_TEXT_ENCODING=readable` writes names instead of hex codes in JSON and
XML responses:

```sh
cat > $S/kmip.env <<'END'
KMIP_CERT=/tls/server.pem
KMIP_KEY=/tls/server.key
KMIP_CA=/tls/ca.pem
KMIP_POLICY=/policy/policy.json
KMIP_MASTER_KEY=/master/master.key
KMIP_HTTPS_LISTEN=0.0.0.0:5697
KMIP_TEXT_ENCODING=readable
END
```

Start the server with resource limits, a read-only root filesystem and no
capabilities, and wait up to 30 seconds for it to be ready (on failure
this prints the server's log and fails). The label lets
`scripts/quick-start.sh --clean` remove the container later:

```sh
docker run -d --name keytend-kmip-server --label dev.keytend.quick-start="$PWD" \
  --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=128 --memory=512m --cpus=2 \
  -p 127.0.0.1:5696:5696 -p 127.0.0.1:5697:5697 -p 127.0.0.1:8080:8080 \
  -v "$PWD/$S/tls:/tls:ro" -v "$PWD/$S/policy:/policy:ro" \
  -v "$PWD/$S/master:/master:ro" -v "$PWD/$S/data:/data" \
  --env-file $S/kmip.env "$IMAGE"
curl -sf --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8080/readyz ||
  { docker logs keytend-kmip-server; false; }
```

```text
ready
```

The store is `$S/data/kmip.sqlite`; SQLite needs the `/tmp`
tmpfs under `--read-only`. The long-running layout (UID 10001, `/srv/kmip`) is in
[deployment](deployment.md#docker-or-podman).

## Change a setting

The container reads its settings from `.cache/container/kmip.env`, one
`KMIP_NAME=value` per line ([every setting](configuration.md#serve-settings)).
Edit it, then recreate the container with the same certificates, master key,
data and image. For example, to accept the KMIP 3.0 draft:

```sh
echo KMIP_EXPERIMENTAL_V3=true >> .cache/container/kmip.env
scripts/quick-start.sh --restart
```

```text
ready
next (bash or zsh): . examples/https/kmip.sh && kmip create.json | field ResultStatus
```

The log line whose `fields.message` is `KMIP listener ready`
(`docker logs keytend-kmip-server`) shows the version and the settings in
effect, for example `"experimental_v3":true`;
[logging](configuration.md#logging) shows how to print it. `--restart` refuses to touch a
container that the script (or the [commands above](#start-the-server)) did
not start from this checkout.

## Renew the test certificates

The test certificates expire after 7 days, and then every TLS handshake
fails. Make new ones in the checkout; for the container, copy them into its
state directory again and recreate it:

```sh
scripts/dev-pki.sh .cache/dev-pki
S=.cache/container   # container only, from here on
install -m 0400 .cache/dev-pki/server.pem .cache/dev-pki/server.key .cache/dev-pki/ca.pem $S/tls/
install -m 0400 .cache/dev-pki/policy.json $S/policy/
scripts/quick-start.sh --restart
```

[From source](#run-from-source), stop the server and start it again instead
of the last three lines. The new `client` certificate maps to the same
principal, so the keys you created stay readable. A users file from the
[Python page](clients/python.md#request-header-credentials) names the old
fingerprint, and the server refuses to start with it: create it again first.

## Run from source

Running from source needs Linux with OpenSSL 3.5 or later, such as Debian 13
or RHEL and UBI 9.9. On distributions with OpenSSL 3.0, such as Debian 12
and Ubuntu 24.04, and on macOS, use the
[container](quick-start.md#run-the-container). KMIP operations use
secp256k1 and the brainpool curves by default; on an OpenSSL without the fix
for CVE-2026-54872 (ECDSA on those curves), set `--ec-curves nist`
([curves](algorithms.md#elliptic-curves)).

You need Rust 1.97 or later, a C compiler, `pkg-config`, the OpenSSL
development headers, and `openssl`, `curl`, Git and Python 3 (with `venv`) for
the test certificates and requests:

```sh
# Debian 13 (its Rust 1.85 is too old: install Rust with https://rustup.rs)
sudo apt install build-essential pkg-config libssl-dev openssl curl git python3 python3-venv
# RHEL 9.9 or a UBI 9 container (rust-toolset is new enough)
sudo dnf install gcc pkgconf-pkg-config openssl-devel openssl curl git python3 rust-toolset
```

Get the source and build it (the first build takes several minutes); run
every later command from the checkout:

```sh
git clone https://github.com/keytend/keytend-kmip-server
cd keytend-kmip-server
cargo build --locked
scripts/dev-pki.sh .cache/dev-pki
install -d -m 0700 .cache/dev-data
target/debug/keytend-kmip-server generate-master-key --output .cache/dev-pki/master.key
```

The test certificates are made the same way as for the
[container](#start-the-server). The master key and the store
(`.cache/dev-data`) are separate from the container's, so keys created in the
container are not visible here. Start the server in its own terminal, from
the checkout:

```sh
target/debug/keytend-kmip-server serve \
  --listen 127.0.0.1:5696 --https-listen 127.0.0.1:5697 \
  --health-listen 127.0.0.1:8080 --text-encoding readable \
  --cert .cache/dev-pki/server.pem --key .cache/dev-pki/server.key \
  --ca .cache/dev-pki/ca.pem --policy .cache/dev-pki/policy.json \
  --database .cache/dev-data/kmip.sqlite --master-key .cache/dev-pki/master.key
```

The server logs JSON lines and `KMIP listener ready` once it is ready. Back
in the terminal you built in, check readiness, then make the
[requests of the quick start](quick-start.md#make-a-request-with-curl):

```sh
curl --retry 10 --retry-connrefused --retry-delay 1 -sf http://127.0.0.1:8080/readyz
```

```text
ready
```

To start again from nothing, stop the server and run
`scripts/quick-start.sh --clean`: it removes the test certificates, the master
key and `.cache/dev-data` together.

Next: [connect your client](clients.md), [configure](configuration.md),
[deploy](deployment.md).
