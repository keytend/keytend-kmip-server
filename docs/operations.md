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

# Operations

Part of [configuration and operations](README.md#configuration-and-operations).

Runbooks for a deployed server. Commands use the container paths of
[deployment](deployment.md) (`/data`, `/master`, `/tls`, `/policy`); with the
image, run them as `docker run --rm … <image> <command>` or, on Kubernetes,
`kubectl -n keytend-kmip-server exec keytend-kmip-server-0 -- keytend-kmip-server <command>`.

- [Health and readiness](#health-and-readiness)
- [Changing the policy](#changing-the-policy):
  [rotating a client certificate](#rotating-a-client-certificate),
  [Re-Provision and lockout recovery](#re-provision-and-lockout-recovery),
  [rotating the client CA](#rotating-the-client-ca)
- [Renewing server certificates and CRLs](#renewing-server-certificates-and-crls)
- [Upgrading](#upgrading): [with Compose](#upgrading-with-compose),
  [on Kubernetes](#upgrading-on-kubernetes), [rolling back](#rolling-back)
- [Shutdown and restarts](#shutdown-and-restarts)
- [Lease Time and KMS outages](#lease-time-and-kms-outages)
- [Audit and integrity](#audit-and-integrity)
- [Store integrity incidents](#store-integrity-incidents)
- [Troubleshooting](#troubleshooting)

Backups and master-key rotation have their own runbooks:
[backup and restore](backup-restore.md) (the copy is useless without the
master key that was current when it was taken) and
[master-key rotation](master-key-rotation.md) (stop the server first).

## Health and readiness

| Check | Healthy | Meaning when not |
| --- | --- | --- |
| `GET /livez` | 200 `alive` | The process is not serving. |
| `GET /readyz` | 200 `ready` | 503: the store is unavailable or its [live history](store-integrity.md#live-history-check) check failed ([below](#store-integrity-incidents)). |
| `keytend-kmip-server healthcheck` | exit 0 | `/readyz` is not 200. |
| `/metrics` | | [Metrics and suggested alerts](metrics.md#alerts). |

A live-history failure stays latched until a checked recovery and restart;
liveness stays 200 so you can investigate. Logs are JSON lines on standard output ([logging](configuration.md#logging)).
A wrong master key or a damaged audit chain stops the server at startup.

## Changing the policy

To authorize a new client or change its operations, edit the policy and
restart the server: like every setting and file, the policy is read only at
startup ([configuration](configuration.md)).

With Docker or Compose, replace the file and restart the container:

```sh
sudo install -o 10001 -g 10001 -m 0400 policy.json /srv/kmip/policy/
docker restart -t 30 keytend-kmip-server
```

On Kubernetes, replace the ConfigMap (and the users Secret, if you use one)
and restart the pod (with the policy in the chart's `policy.json` value
instead, `helm upgrade` restarts it):

```sh
kubectl -n keytend-kmip-server create configmap kmip-policy \
  --from-file=policy.json=policy.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n keytend-kmip-server create secret generic kmip-users \
  --from-file=users.json=users.json --dry-run=client -o yaml | kubectl apply -f -   # with a users file
kubectl -n keytend-kmip-server rollout restart statefulset/keytend-kmip-server
kubectl -n keytend-kmip-server rollout status statefulset/keytend-kmip-server
```

The first `kubectl apply` of an object made with `kubectl create` warns about
a missing `last-applied-configuration` annotation; that is harmless.

### Rotating a client certificate

To replace a client certificate without losing access to its objects:

1. Issue the new certificate. Add its fingerprint to the policy with a copy of
   the old entry: the same principal `name` (a new name is a new owner,
   with no access to the old objects), operations, grants and
   `client_identity`. If a [users file](credentials.md#users-file) lists the
   old fingerprint, add the same users and devices under the new one; the
   server refuses fingerprints of one principal that disagree.
2. Restart the server, switch the client to the new certificate and check that
   it can read its keys.
3. Remove the old fingerprint from the policy and from the users file, and
   restart again. A users file that names a fingerprint missing from the
   policy stops the server at startup.

### Re-Provision and lockout recovery

With `--provisioning-ca`, a client can replace its own certificate with
[Re-Provision](re-provision.md); the old certificate (fingerprint `F`) is
refused on new connections from the commit of that request's message, and
the new one has fingerprint `N`. After each one:

1. Find `N` in the server log: the Re-Provision logs a warning with the
   principal and the old and new fingerprints, and every later start lists
   the provisioning records and warns
   `F anchors active N; add N to the policy ...`.
2. Add `N` to the policy with a copy of `F`'s entry, as in
   [rotating a client certificate](#rotating-a-client-certificate) (same
   `name`, operations, grants, users), restart, then remove `F` and restart
   again. Never remove `F` first: until `N` is in the policy it depends on
   `F`'s entry.

A client is locked out if its connection closed before it fetched the
certificate of a no-parameter Re-Provision, or if the response was lost after
the commit, in either form. The recovery gives the principal a fresh
certificate through the policy; the steps are in
[lockout recovery](re-provision.md#lockout-recovery).

### Rotating the client CA

To move clients to a new client CA (`--ca`) without breaking any client,
trust both CAs while the clients move. Give the new CA a subject name
different from the old one's. Steps 1 and 3 restart the server, and a
single replica is down for the restart; plan the restarts like any other
([shutdown and restarts](#shutdown-and-restarts)).

1. Make the client CA bundle the old CA followed by the new one
   (`cat old-ca.pem new-ca.pem > ca.pem`), and for each client add a new
   certificate from the new CA to the policy as in
   [rotating a client certificate](#rotating-a-client-certificate): same
   principal `name`, operations, grants and users. With `--crl`, add the new
   CA's CRL to the CRL file ([CRL](tls-setup.md#crl)). Restart once.
2. Switch each client to its new certificate and check that it reads its
   keys. Both certificates work in the meantime.
3. When every client has moved, remove the old CA from the bundle, its CRL
   and the old fingerprints from the policy and users file, and restart.
   A certificate from the old CA then fails the TLS handshake (`unknown ca`).

The CA that signed the server certificate is the clients' concern: add the
new one to every client's trust store first, then install the server
certificate it signed ([renewing](#renewing-server-certificates-and-crls)),
then remove the old one from the clients.

## Renewing server certificates and CRLs

The server reads its certificate, key, client CA bundle and CRL only at
startup, and no metric or log line reports when they expire. An expired
server certificate fails every handshake, and with `--crl` an expired CRL
fails every client's chain check, so watch both from outside the server.

1. Before the server certificate expires, issue a new one with the same
   subject alternative names
   ([issuing them](tls-setup.md#issuing-them-with-openssl)); with `--crl`,
   publish the next CRL before the current one's Next Update.
2. Replace the files and restart. With Docker, replace them in
   `/srv/kmip/tls` and run `docker restart -t 30 keytend-kmip-server`. On
   Kubernetes, replace the Secret and restart the pod:

   ```sh
   NS=keytend-kmip-server
   kubectl -n $NS create secret generic kmip-tls \
     --from-file=server.pem=server.pem --from-file=server.key=server.key \
     --from-file=ca.pem=ca.pem --dry-run=client -o yaml | kubectl apply -f -
   kubectl -n $NS rollout restart statefulset/keytend-kmip-server
   kubectl -n $NS rollout status statefulset/keytend-kmip-server
   ```

   When cert-manager renews the Secret, nothing restarts the pod and the
   server keeps serving the old certificate: restart it after every renewal,
   for example in a scheduled window or with a controller that restarts
   workloads when their Secrets change.
3. Check what the server now presents, with a client certificate from the
   policy and the CA that signed the server certificate:

   ```sh
   openssl s_client -connect keytend-kmip-server.example.com:5696 \
     -cert orders-db.pem -key orders-db.key -CAfile ca.pem </dev/null 2>/dev/null |
     openssl x509 -noout -subject -enddate
   openssl crl -in crl.pem -noout -nextupdate   # with --crl
   ```

Run the same check on a schedule, or use a TLS probe that presents a client
certificate (such as the Prometheus blackbox exporter's TCP prober with TLS),
and alert a few weeks before `notAfter` and before the CRL's Next Update.

## Upgrading

1. Take a verified backup with its master key, then stop the server.
2. Start the new version on the same database and key. A release with a newer
   storage schema upgrades the store when it opens it; older binaries then
   refuse the store (`database schema is newer than this binary`).
3. Check `/readyz`, then run `check-store` on the live database (safe while
   the server runs), as the blocks below do.

### Upgrading with Compose

After a [verified backup](backup-restore.md#back-up-with-docker), set the new
digest in `/srv/kmip/.env` and recreate the container
([deployment](deployment.md#docker-compose)); the data, key and settings stay
in `/srv/kmip`:

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<new image digest>'
sudo sed -i "s|^IMAGE=.*|IMAGE=$IMAGE|" /srv/kmip/.env
docker compose -f /srv/kmip/compose.yaml up -d
curl -sf --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8080/readyz
docker exec keytend-kmip-server keytend-kmip-server check-store \
  --database /data/kmip.sqlite --master-key /master/master.key
```

Compose stops the old container (waiting up to 30 seconds) and starts the new
image. Without Compose, remove the container and run the
[`docker run -d` command](deployment.md#without-compose) with the new `IMAGE`.

### Upgrading on Kubernetes

Push the new image to your registry
([getting the image into a registry](release-signing.md#getting-the-image-into-a-registry)),
set its digest in `kmip-values.yaml` and upgrade the release
([Kubernetes](kubernetes.md#install) has the variables):

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
helm test keytend-kmip-server -n $NS --logs
kubectl -n $NS logs job/keytend-kmip-server-pre-upgrade-backup   # names the pre-upgrade backup
```

The pre-upgrade hook backs up the store with the new image (backups never
upgrade a store) and fails the release if the backup fails. The StatefulSet
then stops the old pod before it starts the new one, so the two versions
never run together. Copy the pre-upgrade backup off the cluster
([backups on Kubernetes](backup-restore.md#scheduled-backups-on-kubernetes)):
it is the last copy of the store as the old version left it. Do not combine an upgrade with a master-key
rotation or a restore in one `helm upgrade`; the one exception is the
rollback below. On a large store add `--timeout 15m`: the pre-upgrade backup
and the new pod's startup verification both scan the whole store.

### Rolling back

Restore the pre-upgrade backup and run the old image; never edit the schema
marker. With Docker, run `scripts/docker-restore.sh`
([restore with Docker](backup-restore.md#restore-with-docker)) with `IMAGE`
set to the old digest, `B` to the pre-upgrade backup and `CP` as there. Its
first phase checks the backup with the old image while the server keeps
running; the last one recreates the container with the old image. The
upgraded database is kept in the printed `pre-restore-…` directory: delete
it once a client has read a known key.

On Kubernetes, restore the pre-upgrade backup with the old image in one
upgrade, with the old digest in `kmip-values.yaml`. The old image runs the
restore. `--no-hooks` skips the pre-upgrade backup,
which would run the old image against the upgraded store; `helm rollback`
alone would start the old image on the upgraded store:

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --no-hooks \
  --set restore.from=backup-20261105T143012Z.sqlite --set restore.id=rollback-1 --wait
```

Then continue as in [restore on Kubernetes](backup-restore.md#restore-on-kubernetes).

## Shutdown and restarts

On SIGTERM (or Ctrl-C) the server logs `Draining connections`, stops
accepting connections, lets open connections finish their current request for
up to 20 seconds and then closes the rest. The supplied StatefulSet allows 30
seconds (`terminationGracePeriodSeconds`).

During a restart clients see refused or reset connections, and must reconnect
and retry. A request whose response was lost may or may not have been
applied ([retrying after a lost response](client-errors.md#retrying-after-a-lost-response)).

Pending asynchronous requests, multipart streams and Login tickets do not
survive a restart.

## Lease Time and KMS outages

A client that honours KMIP leases keeps using a cached object (a data key, or
a TLS certificate and private key) only until its lease ends; then it must
reach the server for a new lease. `--max-lease-seconds` (default 3600)
therefore sets the longest KMS outage such a client survives, counted from its
last successful renewal:

- When data-key leases end, encryption and decryption stop on every node
  that could not renew.
- Nodes that present a leased TLS certificate stop presenting it at lease
  end. Nodes of one cluster usually renew at about the same time, so
  a long outage becomes a cluster-wide TLS outage at once.
- The same interval bounds how long a client keeps using a key
  the server has since revoked, deactivated or destroyed.

Choose the Lease Time as the longest KMS outage you must ride out (including a
restore from backup) plus the clients' renewal margin, and no longer than you
can accept a destroyed or compromised key staying in use. Lease Time 0 removes
the limit: clients never stop for an outage, and the server cannot bound use
after Destroy. The value is stored on each object when it is created, so a
change applies to new objects only. Deactivation Dates and Protect Stop Dates
shorten Active leases; which states get a lease and how long it lasts are in
[leases](lifecycle.md#leases). Alerting before leases run out:
[lease-outage alerts](metrics.md#lease-outage-alerts).

Clients that do not use leases, such as Percona Server for MongoDB, keep using
cached keys through an outage, which also delays the effect of a revocation
(observed in the [Percona tests](status.md#what-has-been-tested)).

## Audit and integrity

`check-store` verifies the master key, every record and the HMAC-chained audit
history ([store integrity](store-integrity.md)); the chain is an integrity
record, not an access log ([logging](configuration.md#logging)). To detect an
old but authentic copy of the store, export
[audit checkpoints](audit-checkpoints.md) and start with `--audit-checkpoint`.

## Store integrity incidents

If `/readyz` turns 503 because the live-history check failed, the database
under the running server is not the one it has been writing: for example an
older copy was put in place, or records were changed. The process stays up and
refuses storage operations with General Failure, and the failure stays latched
until a restart; restarting without investigating can accept an old copy.
Readiness removes the pod from its Service, but databases keep using keys they
have cached.

1. Fence KMIP traffic and administrative changes. Preserve the logs, the
   audit checkpoint and a consistent copy of the suspect database with its
   WAL.
2. Stop the server. Choose the database and master key you believe are
   current, and the audit checkpoint of that key generation. Never regenerate
   or lower the checkpoint from the suspect database.
3. On a copy, run `check-store --database … --master-key … --audit-checkpoint …`.
   An authentic database older than the checkpoint fails. If no candidate
   passes, keep the service fenced: a new empty store cannot decrypt the data
   that the lost keys protected.
4. Start the server on the verified database and key with
   `--audit-checkpoint`, check readiness, `check-store` and known keys from
   authorized clients, then reopen traffic.
5. Keep the incident copies outside the restored volume, and confirm that
   checkpoint export resumes.

Rehearse this on your storage and database topology; there is no automated
fencing.

## Troubleshooting

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Startup: `record authentication failed (wrong key or corrupted store)` or `invalid master key` | The key file does not match the store | Use the matching key, or [restore](backup-restore.md#restore) a matching pair. |
| Startup: `master key must contain exactly 32 raw bytes` or `… must not be accessible to other users` | Wrong file, or mode too open | Use `generate-master-key` output; `chmod 0600` (or 0440/0640, restricted group). |
| Startup: `database must not be accessible to other users` | Readable by others, such as a `cp` under a loose umask | `chmod 0600` the database (owner UID 10001). |
| The container does not start: `address already in use` or `port is already allocated` | Another process, often an earlier container, holds 5696, 5697 or 8080 on the host | `sudo ss -ltnp 'sport = :5696'` (or `:5697`, `:8080`) names it; stop it, or publish other host ports. |
| Startup: `invalid fingerprint or principal in policy` | Uppercase or truncated fingerprint, empty name, or an operation outside 1–66 | Recompute with `openssl x509 -outform DER \| sha256sum`; fix the entry. |
| A maintenance command: `… <path> already exists` | Left over from an earlier run | Use a new name, or remove the leftover (below). |
| Startup: `database schema is newer than this binary` | An older binary on an upgraded store | Use the newer binary, or restore the pre-upgrade backup. |
| SQLite `SQLITE_IOERR_GETTEMPPATH` (6410) | No writable `/tmp` under a read-only root | Mount a tmpfs or `emptyDir` at `/tmp`. |
| Permission errors on `/data` | Data directory not writable by UID 10001 | `chown 10001:10001` the directory (or set `fsGroup`). |
| `/readyz` 503 while `/livez` is 200 | Live-history check failed, or the store is unavailable | Do not just restart; follow [store integrity incidents](#store-integrity-incidents). |
| Every client fails the TLS handshake, after weeks of working | The server certificate (or, with `--crl`, the CRL) expired; nothing in the server reports it | `sudo openssl x509 -enddate -noout -in /srv/kmip/tls/server.pem`; [renew](#renewing-server-certificates-and-crls). |
| Some clients fail the TLS handshake | Untrusted CA, wrong name, no shared TLS parameters, or a revoked certificate | See `kmip_tls_handshake_failures_total` by `reason` ([client errors](client-errors.md#errors-and-what-they-mean)). |
| Clients get Permission Denied and are disconnected | Certificate trusted but missing from the policy | Add its fingerprint ([policy](configuration.md#policy-file)) and restart. |
| Percona Server for MySQL keyring fails after a quiet period | It does not reconnect after an idle close | Set `--idle-timeout` above its quiet periods, or `0` ([Percona](percona.md)). |
| Connections queue or stall | `--max-connections` reached; idle connections hold slots | Watch `kmip_connections_active`; raise `--max-connections` (`KMIP_MAX_CONNECTIONS`) or lower `--idle-timeout`. |
| HTTPS clients get HTTP 503 | Four HTTPS requests already in progress ([fixed limits](configuration.md#fixed-limits)) | Retry; nothing ran. |
| Disk filling | Store growth plus WAL | Alert on the volume's free space ([metrics](metrics.md#alerts)); grow the volume. |

In an `… already exists` refusal, the leftover can be the output itself, its
`-wal` or `-shm` file, or the `--create-directory` directory. After a failed
Docker rotation, see
[if the Docker rotation fails](master-key-rotation.md#if-the-docker-rotation-fails).
