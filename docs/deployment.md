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

# Deployment

Part of [configuration and operations](README.md#configuration-and-operations).

What a deployment needs, and how to run keytend-kmip-server with Docker,
Podman or Compose. Kubernetes has [its own page](kubernetes.md). Backups,
upgrades and other tasks after installation are in [operations](operations.md), [backup and restore](backup-restore.md)
and [master-key rotation](master-key-rotation.md); every setting is in the
[configuration reference](configuration.md). It is a test server
for CI and client validation, not for production use ([status](status.md)).

- [What you deploy](#what-you-deploy)
- [Master key](#master-key)
- [Docker or Podman](#docker-or-podman): [with Compose](#docker-compose) or
  [without](#without-compose), and the [health check](#health-check)

## What you deploy

A deployment is one server process with one SQLite store. Run a single
replica, and plan for the outage during restarts and node failures.

| Input | Mounted at (image and manifests) | Notes |
| --- | --- | --- |
| Server certificate chain and key | `/tls/server.pem`, `/tls/server.key` | PEM ([issuing certificates](tls-setup.md)). |
| Client CA bundle | `/tls/ca.pem` | The CA that issues client certificates. Prefer a dedicated CA or intermediate. |
| Policy | `/policy/policy.json` | Which client certificates may call which operations ([policy file](configuration.md#policy-file)). |
| Master key | `/master/master.key` | 32 raw bytes from `generate-master-key`. Back it up apart from the database. |
| Data directory | `/data` | Writable, persistent, local filesystem; holds `kmip.sqlite` and its WAL. |
| Temporary directory | `/tmp` | Writable; SQLite statement journals. A 64 MiB tmpfs is enough for the tested workloads. |

The image runs as UID and GID 10001 and needs no capabilities. Key files and
the database must not be accessible to other users: mode 0400/0600, or
0440/0640 with a group that holds only the server's account. The server
checks only the bits for other users, not the group or ACLs
([storage](configuration.md#storage)). Keep client private keys and the
client CA's private key out of the server container; the one CA key it may
hold is the dedicated provisioning sub-CA's, and only when
[Re-Provision](re-provision.md) is on.

Ports: 5696 binary KMIP, 5697 HTTPS KMIP (when enabled), 8080 health and
metrics (plain HTTP; keep it on a management network).

The image is Red Hat UBI 9.9 micro (linux/amd64 and linux/arm64) with no shell
or package manager; its entry point is the server binary, so subcommands run
as `docker run … <image> backup …` ([container image](container-image.md)).

Sizing: the supplied resources request 100m CPU and 128 Mi and allow 2 CPUs
and 512 Mi. Throughput and capacity have not been measured for a published
configuration; size from your own load test.

## Master key

```sh
keytend-kmip-server generate-master-key --output master.key
```

With only the image, write it into a directory you own and move it next to
the other files (with rootless Podman, add `--userns=keep-id`):

```sh
IMAGE=localhost/keytend-kmip-server:dev   # or the image you deploy
install -d -m 0700 master
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/master:/master" \
  "$IMAGE" generate-master-key --output /master/master.key
mv master/master.key master.key && rmdir master
```

Either way `master.key` is created mode 0600 and the command refuses to
overwrite an existing file.

## Docker or Podman

The [container quick start](quick-start.md#run-the-container) runs the image
as your own user for evaluation. For a server that stays up, use a dedicated
directory owned by the image's UID 10001, your own certificates and policy
(not `scripts/dev-pki.sh` output), and the image from your registry by digest
([getting it there](release-signing.md#getting-the-image-into-a-registry)).
Prepare `/srv/kmip`:

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>'
sudo install -d -o 10001 -g 10001 -m 0700 /srv/kmip/tls /srv/kmip/policy /srv/kmip/master \
  /srv/kmip/data /srv/kmip-backups
sudo install -d -m 0700 /srv/kmip-old-keys   # old master keys, root only
sudo install -o 10001 -g 10001 -m 0400 server.pem server.key ca.pem /srv/kmip/tls/
sudo install -o 10001 -g 10001 -m 0400 policy.json /srv/kmip/policy/
docker run --rm -v /srv/kmip/master:/master "$IMAGE" generate-master-key --output /master/master.key
sudo tee /srv/kmip/kmip.env >/dev/null <<'END'
KMIP_CERT=/tls/server.pem
KMIP_KEY=/tls/server.key
KMIP_CA=/tls/ca.pem
KMIP_POLICY=/policy/policy.json
KMIP_MASTER_KEY=/master/master.key
KMIP_HTTPS_LISTEN=0.0.0.0:5697
END
```

Before you start it:

- Back up `/srv/kmip/master/master.key` now, apart from the data directory: a
  store cannot be opened without it ([backup and restore](backup-restore.md)).
- The server certificate needs the host name clients dial as a `DNS:`
  subject alternative name, and `IP:` if they dial an address
  ([server certificate](tls-setup.md#server-certificate)).
- Publish 5696 (and 5697 if enabled) where clients reach them; keep 8080 on
  `127.0.0.1` or a management network. If you move the health listener, see
  [health check](#health-check).
- Put `/srv/kmip/data` on durable local storage with working file locks and
  fsync; never share one database between two containers.

Then start it [with Compose](#docker-compose) or
[with `docker run`](#without-compose). Notes:

- `/srv/kmip/kmip.env` holds the settings, one `KMIP_*` variable per line
  ([configuration](configuration.md#serve-settings)). Docker reads it only
  when it creates the container, so a change takes effect when the container
  is recreated.
- The server logs JSON lines to standard output. Docker's default `json-file`
  log driver never rotates them; both forms below keep at most five 10 MB
  files (or set this for every container in the daemon's `daemon.json`).
  With Podman the options apply to its `k8s-file` driver; its `journald`
  driver is rotated by journald.
- The runbooks' readiness checks use `curl --retry-all-errors`, which needs
  curl 7.71 or later.
- If a proxy sits in front, it must pass TLS through: the server authenticates
  the client certificate itself.
- With rootless Podman, prepare the layout as in
  [rootless Podman](#rootless-podman) instead.

### Rootless Podman

Rootless Podman maps the container's UID 10001 to one of your subordinate
UIDs, which only `podman unshare` can set as an owner. Create the top
directories once as root, owned by you, then prepare the rest as your user:

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>'
sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0700 /srv/kmip /srv/kmip-backups /srv/kmip-old-keys
install -d -m 0700 /srv/kmip/tls /srv/kmip/policy /srv/kmip/master /srv/kmip/data
install -m 0400 server.pem server.key ca.pem /srv/kmip/tls/
install -m 0400 policy.json /srv/kmip/policy/
podman unshare chown -R 10001:10001 /srv/kmip/tls /srv/kmip/policy /srv/kmip/master \
  /srv/kmip/data /srv/kmip-backups
podman run --rm -v /srv/kmip/master:/master "$IMAGE" generate-master-key --output /master/master.key
```

Then write `/srv/kmip/kmip.env` as above, without `sudo`. In this page and
the runbooks, with rootless Podman:

- run `podman` for `docker`;
- run each `sudo` command as `podman unshare` (`sudo sh -c '…'` becomes
  `podman unshare sh -c '…'`), so that files get the container's UID;
- run the runbook scripts with `SUDO='podman unshare' DOCKER=podman`;
- on SELinux hosts, add `:Z` to every volume, in `compose.yaml` too.

### Docker Compose

[`deploy/compose/compose.yaml`](../deploy/compose/compose.yaml) runs the
container with a read-only root, a `/tmp` tmpfs, no capabilities, resource
limits, the `/srv/kmip` volumes and env file, log rotation and the health
check in exec form. The runbooks use it. From the checkout:

```sh
sudo install -m 0644 deploy/compose/compose.yaml /srv/kmip/
printf 'IMAGE=%s\n' "$IMAGE" | sudo tee /srv/kmip/.env >/dev/null
docker compose -f /srv/kmip/compose.yaml up -d
curl -sf --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8080/readyz
```

```text
ready
```

Compose reads `IMAGE` from `.env` next to the file; `KMIP_ROOT` there moves
the layout from `/srv/kmip`. To change a setting, edit `/srv/kmip/kmip.env`
and recreate the container; the data, key and certificates stay:

```sh
docker compose -f /srv/kmip/compose.yaml up -d --force-recreate
```

A new image is the same command after changing `IMAGE` in `.env`
([upgrading](operations.md#upgrading-with-compose)). `docker stop` and
`docker start keytend-kmip-server` work as usual: the container name is fixed.

> [!NOTE]
> Use Docker Compose 2.26 or later, which also works against the Podman
> socket. podman-compose 1.3 turns the exec-form health check into a shell
> command, which fails in this image: disable the health check there and
> probe from outside.

### Without Compose

The same container with `docker run`:

```sh
docker run -d --name keytend-kmip-server --restart unless-stopped \
  --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=128 --memory=512m --cpus=2 \
  --log-opt max-size=10m --log-opt max-file=5 \
  -p 5696:5696 -p 5697:5697 -p 127.0.0.1:8080:8080 \
  -v /srv/kmip/tls:/tls:ro -v /srv/kmip/policy:/policy:ro \
  -v /srv/kmip/master:/master:ro -v /srv/kmip/data:/data \
  --env-file /srv/kmip/kmip.env "$IMAGE"
```

This command has a health check only if the image carries one. A release
image loaded from its Docker archive (`docker load`) does; the same image
copied to a registry as OCI, as in
[getting the image into a registry](release-signing.md#getting-the-image-into-a-registry),
does not, because OCI has no health-check field. Compose sets its own check
either way. `docker image inspect --format '{{json .Config.Healthcheck}}' "$IMAGE"`
prints `null` when there is none; then add one as in
[health check](#health-check), or probe readiness from outside.

Where a runbook recreates the container (`docker compose … up -d`), stop and
remove it instead (`docker stop -t 30 keytend-kmip-server && docker rm
keytend-kmip-server`) and run this command again, with the image the runbook
names and every mount your deployment adds, such as
`-v /srv/kmip/checkpoints:/checkpoints:ro` for an
[audit checkpoint](audit-checkpoints.md#start-the-server-with-it).

### Health check

The image's health check runs `keytend-kmip-server healthcheck`, which asks
`/readyz` on `127.0.0.1:8080`. It does not read `KMIP_HEALTH_LISTEN`, so if
that moves the listener, pass `--address` to match (a numeric `IP:port`). The
image has no shell, so a check you add must be in exec form:

- With Compose, `compose.yaml` has its own exec-form test, with
  `"--address", "127.0.0.1:8080"`; change the address there if you move the
  listener.
- With Podman, use a JSON array, which also adds the check to an image without
  one (append `"--address", "127.0.0.1:9090"` for a listener moved to 9090):
  `--health-cmd '["/usr/local/bin/keytend-kmip-server", "healthcheck"]'`.
  A plain string becomes a shell command and reports unhealthy.
- With Docker Engine, `docker run --health-cmd` always runs a shell, so it
  cannot work here. Use Compose, or probe from outside: from the host, a
  monitoring agent or a systemd timer,
  `curl -sf http://127.0.0.1:8080/readyz` prints `ready` and exits 0 only
  when the server is ready. To turn off a check the image carries, add
  `--no-healthcheck`.
