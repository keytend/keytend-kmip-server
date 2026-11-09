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

# Backup and restore

Part of [configuration and operations](README.md#configuration-and-operations).

`backup` writes a transactionally consistent encrypted copy of the store,
including the audit chain, and can run while the server is serving. A backup
is useless without the master key that was current when it was taken: store
the two separately, each with its own access control and retention. Commands
use the container paths of [deployment](deployment.md) (`/data`, `/master`).

- [Back up](#back-up): [with Docker](#back-up-with-docker),
  [scheduled with Docker](#scheduled-backups-with-docker)
- [Restore](#restore): [with Docker](#restore-with-docker)
  ([if it fails](#if-the-docker-restore-fails))
- [On Kubernetes](#on-kubernetes): [scheduled backups](#scheduled-backups-on-kubernetes),
  [volume helper](#volume-helper), [restore](#restore-on-kubernetes),
  [records next to the database](#records-next-to-the-database)
- [Recover onto a new host or namespace](#recover-onto-a-new-host-or-namespace)

## Back up

```sh
keytend-kmip-server backup --database /data/kmip.sqlite \
  --master-key /master/master.key --output /backup/kmip-2026-11-04.sqlite
keytend-kmip-server check-store --database /backup/kmip-2026-11-04.sqlite \
  --master-key /master/master.key
```

```text
Master key, object records and audit chain verified
```

`backup` refuses to overwrite and does not create directories. The output
needs free space for a full copy of the database; with Docker the backup is
first written into the data volume, so that volume needs it. With
[audit checkpoints](audit-checkpoints.md), export a checkpoint from each
verified backup.

`backup` only reads the store and never upgrades it, so it is safe next to a
running server and with a newer release's image. For a scheduled job without
a shell, `--output-dir` names the file itself, verifies it and prunes older
ones:

```sh
keytend-kmip-server backup --database /data/kmip.sqlite \
  --master-key /master/master.key --output-dir /backups --retain 14
```

```text
Backup /backups/backup-20261105T021500Z.sqlite written and verified: 12 objects, 40 audit entries, 98304 bytes
```

- The directory must exist and must not be the database's own. Backups are
  written with mode 0400, so one cannot be served in place. Next to them the
  directory holds `latest.json` (the newest backup: name, size, time,
  verification result, what was pruned), `backup-index.json` (every backup
  this command wrote, with the database it copies) and `.backup.lock`; keep
  all three. A concurrent run into the same directory fails at once.
- `--retain N` keeps the newest `N` backups of this database and deletes
  only older backups that the index records for it, by its path: use the
  same `--database` path every time. Backups of other databases, files copied
  in by hand and look-alike names are listed as unrecorded and never removed.
  A recorded backup is deleted only while it is unchanged (same size and
  SHA-256), still mode 0400 and has no `-wal`, `-shm`, `-journal` or lock
  file next to it.
- A run that fails while writing or verifying the backup leaves
  `latest.json` as it was and exits 1. One that fails later, while pruning
  older backups or rewriting the index, also exits 1, but `latest.json`
  already names the new, verified backup. A run during a
  [restore or in-place rotation](configuration.md#store-lock-and-cutover-records) fails too: run it
  again afterwards.
- `--if-exists` turns a missing database (a server that has never started)
  into a note and exit 0. `--master-key` may be given more than once: the
  first key that opens the store is used and named in the output, which lets
  one job cover both keys of a [rotation](master-key-rotation.md).
- Every successful backup records its time in `/data/kmip.sqlite.last-backup`
  when the data directory is writable; the server reports it as
  `kmip_last_backup_timestamp_seconds` ([metrics](metrics.md)).

### Back up with Docker

For the `/srv/kmip` layout of [deployment](deployment.md#docker-or-podman):
write the backup into the data directory, move it to `/srv/kmip-backups`
(which the layout creates for UID 10001), and check it there with the image. Run on the Docker
host, from any directory:

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>'   # the image you run
B=backup-$(date -u +%Y%m%dT%H%M%SZ).sqlite
docker exec keytend-kmip-server keytend-kmip-server backup \
  --database /data/kmip.sqlite --master-key /master/master.key --output /data/$B
sudo mv /srv/kmip/data/$B /srv/kmip-backups/
docker run --rm -v /srv/kmip-backups:/backup -v /srv/kmip/master:/master:ro "$IMAGE" \
  check-store --database /backup/$B --master-key /master/master.key
```

```text
Master key, object records and audit chain verified
```

With [audit checkpoints](audit-checkpoints.md), export one from the verified
backup, checked against the checkpoint the server starts with:

```sh
docker run --rm -v /srv/kmip-backups:/backup -v /srv/kmip/master:/master:ro \
  -v /srv/kmip/checkpoints:/checkpoints:ro "$IMAGE" audit-checkpoint \
  --database /backup/$B --master-key /master/master.key \
  --previous /checkpoints/checkpoint.json --output /backup/${B%.sqlite}-checkpoint.json
```

```text
Authenticated audit checkpoint exported; retain it independently of database snapshots
```

Then copy the backup off the host, apart from the master key, and the
checkpoint to its independent store
([advancing it](audit-checkpoints.md#advance-it)). With rootless Podman, see
[rootless Podman](deployment.md#rootless-podman).

### Scheduled backups with Docker

The server has no backup schedule; run this script from cron or a systemd
timer (on Kubernetes the chart's [CronJob](#scheduled-backups-on-kubernetes)
does this). It gives every backup a unique name, verifies the copy, keeps 30
days and refuses to start while another run holds its lock.

For the `/srv/kmip` layout of [deployment](deployment.md#docker-or-podman),
as root on the Docker host. Save it as
`/usr/local/sbin/kmip-backup.sh`, mode 0700. A backup that fails
`check-store` is renamed `failed-backup-…` and the script exits non-zero.
Each run deletes backups and failed copies older than `KEEP_DAYS`:

```sh
#!/bin/sh
# /usr/local/sbin/kmip-backup.sh
set -eu
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>'
DEST=/srv/kmip-backups       # owned by 10001, mode 0700
KEEP_DAYS=30
NAME=backup-$(date -u +%Y%m%dT%H%M%SZ).sqlite

exec 9>"$DEST/.lock"
flock -n 9 || { echo "another backup is running" >&2; exit 1; }
trap 'rm -f "/srv/kmip/data/$NAME"' EXIT    # a backup left in the data directory

docker exec keytend-kmip-server keytend-kmip-server backup \
  --database /data/kmip.sqlite --master-key /master/master.key --output /data/$NAME
mv "/srv/kmip/data/$NAME" "$DEST/"
docker run --rm -v "$DEST:/backup" -v /srv/kmip/master:/master:ro "$IMAGE" \
  check-store --database /backup/$NAME --master-key /master/master.key ||
  { mv "$DEST/$NAME" "$DEST/failed-$NAME"; exit 1; }
find "$DEST" \( -name 'backup-*.sqlite' -o -name 'failed-backup-*.sqlite' \) \
  -mtime +$KEEP_DAYS -delete
```

The systemd service below runs as root, so it only works with rootful Docker
or Podman. With rootless Podman, save the script where the user that runs the
container can read it, replace `docker` with `podman`, and run it from that
user's crontab as `podman unshare <path>/kmip-backup.sh`.

Run it daily with a systemd timer (or from cron:
`15 2 * * * /usr/local/sbin/kmip-backup.sh`). The service,
`/etc/systemd/system/kmip-backup.service`:

```ini
[Unit]
Description=Back up keytend-kmip-server

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/kmip-backup.sh
```

The timer, `/etc/systemd/system/kmip-backup.timer`:

```ini
[Unit]
Description=Daily keytend-kmip-server backup

[Timer]
OnCalendar=*-*-* 02:15:00
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now kmip-backup.timer
```

A failed run shows as a failed `kmip-backup.service` (`systemctl
--failed`). The backups stay on the host: copy `/srv/kmip-backups` off it
with your backup tool, apart from the master key.

About the script:

- The script runs as root, so running it is equivalent to reading every
  stored key. Grant it to the backup identity only.
- A failed step stops the script with a non-zero exit; alert
  on it. A `failed-backup-…` copy holds every key like a good one: once you
  have found the cause, delete it rather than wait for `KEEP_DAYS`.
- `flock` is in util-linux; on hosts without it, let the
  scheduler prevent overlapping runs.
- Keep backups older than the last
  [master-key rotation](master-key-rotation.md) together with the record of
  which old key opens them, and apply the same retention to that key.
- With [audit checkpoints](audit-checkpoints.md), add an
  `audit-checkpoint` export from the verified copy.

## Restore

1. Verify the backup with the master key that was current when it was taken.
   If the server runs with `--audit-checkpoint`, check against that
   checkpoint too: the server refuses a store older than its checkpoint, so a
   backup taken before the latest checkpoint fails here and would fail at
   startup ([restoring with a checkpoint](audit-checkpoints.md#restore)). Do
   this before you stop the server:

   ```sh
   keytend-kmip-server check-store --database backup.sqlite --master-key master.key \
     --audit-checkpoint checkpoint.json   # without checkpoints, leave out this flag
   ```

2. Stop the server and wait until it has exited (it drains for up to 20
   seconds).
3. Move the current database and its `-wal` and `-shm` files aside, and put
   the backup into the data directory as `kmip.sqlite`, owned by UID 10001
   with mode 0600. Never restore over a live database. The complete commands:
   [with Docker](#restore-with-docker), [on Kubernetes](#restore-on-kubernetes).
4. Start the server with the backup's master key and the checkpoint you
   checked against. It verifies the whole store at startup and refuses one
   that does not match. Check `/readyz`, run `check-store` again, and have a
   client read a known key before reopening traffic.

`restore` runs steps 1 and 3 as one command, with no shell needed (the
chart's [restore](#restore-on-kubernetes) runs it before the server starts).
It takes the [store lock](configuration.md#store-lock-and-cutover-records), so the server must be
stopped:

```sh
keytend-kmip-server restore --from /backups/backup-20261104T021500Z.sqlite \
  --id 20261105-1 --database /data/kmip.sqlite --master-key /master/master.key \
  --audit-checkpoint /checkpoints/checkpoint.json   # without checkpoints, leave out this flag
```

- It verifies the backup read-only (with the checkpoint, if given) and
  changes nothing if that fails. Then it copies the backup next to the
  database, verifies the copy, moves the current database to
  `pre-restore-<id>/` and installs the copy (mode 0600). The database need
  not exist, which restores onto a new volume. To undo a restore, `backup`
  the database in `pre-restore-<id>/` and restore that with a new id.
- The same `--id` with the same backup again does nothing and exits 0 (with
  `--audit-checkpoint` it still checks the database against it), so it can
  run at every start of a container, even after the backup was pruned. The
  id is bound to its backup (size and SHA-256, recorded in `.restore-<id>`
  next to the database): the same id with another
  backup is refused (`… was already used for …: use a new id`). Use a new id
  for each restore; an id whose `pre-restore-<id>/` already exists is
  refused too.
- An interrupted run leaves `kmip.sqlite.restore.json` next to the database.
  The server and every other maintenance command refuse to start while it
  exists, naming the id. Run `restore` again with the same `--id` and the
  same key: it completes the restore. Only if the copy was changed from
  outside (it is no longer the recorded file, or no longer verifies) does it
  stop, with the steps to finish by hand: follow them, which is the one case
  in which you delete the record yourself. Never delete it otherwise.
- Start the server with the master key you gave.

Objects created after the backup are lost; databases that registered keys
after it will need those keys from elsewhere. Destroy removes current key
material, but older copies remain in backups and storage snapshots until
those are disposed of.

[Re-Provision](re-provision.md#records-backups-and-limits) records are
restored to the backup's state as well: a client certificate retired after
the backup is accepted again, and a replacement made after it is unknown, so
its client is refused unless the policy lists it. Fold active replacement
fingerprints into the policy (the startup log names them) before you rely on
a backup.

### Restore with Docker

[`scripts/docker-restore.sh`](../scripts/docker-restore.sh) runs the steps
above for the `/srv/kmip` layout and Compose file of
[deployment](deployment.md#docker-compose). Run it on the host from the
checkout, as a user who can run `sudo` and `docker`, and set:

- `IMAGE`: the image that checks the backup and then runs the server. Use
  your current image, or the old one when
  [rolling back](operations.md#rolling-back) an upgrade.
- `B`: the backup, a file name in `/srv/kmip-backups` or a path.
- `KEYDIR`: for a backup older than a
  [master-key rotation](master-key-rotation.md), a directory holding the key
  that opens it as `master.key`. Leave it out for the current key.
- `CP`: with [audit checkpoints](audit-checkpoints.md), the checkpoint file
  the container starts with, in `/srv/kmip/checkpoints`. The backup must pass
  it, or the server will refuse to start; to start against another
  checkpoint, install that one in its place first.

The backup, `KEYDIR` and `CP` must be readable by UID 10001.

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>' \
B=backup-20261104T021500Z.sqlite CP=/srv/kmip/checkpoints/checkpoint.json \
  scripts/docker-restore.sh      # leave out CP without a checkpoint
```

```text
restore 20261105T091000Z
phase 1: check the inputs and verify the backup
Master key, object records and audit chain verified
phase 2: stop the server and move the current database aside
previous database in /srv/kmip/pre-restore-20261105T091000Z
phase 3: install the backup
phase 4: recreate the container with registry.example.com/keytend-kmip-server@sha256:… and verify it
Master key, object records and audit chain verified
restored backup-20261104T021500Z.sqlite (restore 20261105T091000Z). Have a client read a known key; …
```

The phases:

1. Check the inputs and that nothing the run writes exists, then verify the
   backup with `check-store` (and `CP`). The server keeps running.
2. Stop the server and move the current database, and a copy of `.env`, to
   `/srv/kmip/pre-restore-<time>/`.
3. Install the backup as `kmip.sqlite` (UID 10001, mode 0600). If `KEYDIR`
   holds a different key, install it too and keep the current one as
   `/srv/kmip-old-keys/master-pre-restore-<time>.key`.
4. Set `IMAGE` in `/srv/kmip/.env`, recreate the container with Compose, wait
   for `/readyz` and run `check-store`.

Have a client read a known key, then delete the `pre-restore-<time>`
directory once the restore is confirmed. With rootless Podman, add
`SUDO='podman unshare' DOCKER=podman`
([rootless Podman](deployment.md#rootless-podman)). Without Compose, run the
phases by hand and recreate the container as
[deployment](deployment.md#without-compose) describes.

#### If the Docker restore fails

- Phase 1: the server was never stopped and nothing changed. The usual
  causes are the wrong key (`record authentication failed`) and a backup
  older than the checkpoint (`audit checkpoint authentication failed`; see
  [restoring with a checkpoint](audit-checkpoints.md#restore)).
- Phase 2, 3 or 4: read `docker logs keytend-kmip-server`, then put back
  what the restore replaced: the previous database, master key and `.env`
  (and so the image). This removes the restored copy; the backup stays.

  ```sh
  CP=/srv/kmip/checkpoints/checkpoint.json \
    scripts/docker-restore.sh --undo 20261105T091000Z   # the time it printed
  ```

  After a successful restore, the same command undoes it, but loses writes
  accepted since.

## On Kubernetes

The [Helm chart](kubernetes.md) runs backups and restores itself. The
commands below use the variables and `kmip-values.yaml` of
[installing the chart](kubernetes.md#install); the release is
`keytend-kmip-server`.

### Scheduled backups on Kubernetes

The CronJob `keytend-kmip-server-backup` runs
`backup --output-dir /backups --retain 7` daily at 02:15
(`backup.schedule`, `backup.retain`) into the PVC
`keytend-kmip-server-backups` (20 Gi, `backup.pvc.size`), which
`helm uninstall` keeps. Its pod mounts the data volume next to the running
server, so it is scheduled on the server's node. Every `helm upgrade` and
`helm rollback` first runs the same backup as a hook; if that backup fails,
the release fails before anything changes. The hook is left out while the
data or backup volume does not exist yet (before the first start, and on the
upgrade that turns `backup.enabled` on) and wherever the chart cannot read
the cluster ([GitOps](kubernetes.md#without-helm-and-gitops)). The hook prunes nothing; its
backups count toward `--retain` at the next scheduled run, so size the PVC for
`retain` plus the upgrades between two runs.

Run a backup now and check it. Each run needs a Job name not used before:

```sh
JOB=backup-$(date -u +%Y%m%d-%H%M%S)
kubectl -n $NS create job --from=cronjob/keytend-kmip-server-backup $JOB
kubectl -n $NS wait --for=condition=complete job/$JOB --timeout=10m
kubectl -n $NS logs job/$JOB
```

```text
Backup /backups/backup-20261105T143012Z.sqlite written and verified: 12 objects, 40 audit entries, 98304 bytes
```

The server reports the time of the last one as
`kmip_last_backup_timestamp_seconds`; the chart's
[PrometheusRule](kubernetes.md#monitoring) alerts when it is older than 26
hours. The log of the last upgrade's backup stays available until the next
upgrade, or for 7 days: `kubectl -n $NS logs job/keytend-kmip-server-pre-upgrade-backup`.
A scheduled run that overlaps a restore or rotation fails and is retried
once; the next scheduled run tries again.

The backup PVC is in the cluster's failure domain: copy backups off it, apart
from the master key. Start the [volume helper](#volume-helper), then:

```sh
kubectl -n $NS exec $H -- cat /backups/latest.json
kubectl -n $NS cp $H:/backups/backup-20261105T143012Z.sqlite ./backup-20261105T143012Z.sqlite
chmod 0600 backup-20261105T143012Z.sqlite
```

`kubectl cp` does not keep the file mode, and the server refuses a database
that other users can read, hence the `chmod`. Verify the copy with
`check-store` and the matching master key, natively or with the image:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" \
  registry.example.com/keytend-kmip-server@sha256:<image digest> \
  check-store --database /work/backup-20261105T143012Z.sqlite --master-key /work/master.key
```

(With rootless Podman, add `--userns=keep-id`.) `backup` writes each file
mode 0400, and retention removes only files that still have that mode. A
storage driver or a prefilled `restore.existingClaim` that changes file modes
when the volume is mounted (a recursive `fsGroup` change) stops the pruning:
the kept files are listed under `kept` in `latest.json`, and the PVC fills.

### Volume helper

The server image has no shell or `tar`. `volumeHelper.enabled` adds a busybox
pod with the backup volume at `/backups` and the data volume at `/data`, for
`kubectl cp` and for deleting earlier databases. Start it and set `H` to its
pod name:

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --set volumeHelper.enabled=true --wait
H=$(kubectl -n $NS get pod -l app.kubernetes.io/component=volume-helper -o name | cut -d/ -f2)
```

Any later upgrade without `--set volumeHelper.enabled=true`, including a
restore, removes it; start it again before the next command that uses `$H`.
Remove it when you are done:

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
```

Running the backup or the helper is equivalent to reading every stored key:
restrict who can create Jobs and pods, use `pods/exec` and read Secrets in the
namespace.

### Restore on Kubernetes

Pick a backup on the backup PVC (`latest.json` names the newest; the
[volume helper](#volume-helper)'s `ls /backups` lists them) and restore it
with one upgrade. `id` names this restore; use a new one each time:

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml \
  --set restore.from=backup-20261105T021500Z.sqlite --set restore.id=20261105-1 --wait
kubectl -n $NS logs keytend-kmip-server-0 -c restore
```

```text
Verified backup /backups/backup-20261105T021500Z.sqlite: 12 objects, 40 audit entries
Restored it as /data/kmip.sqlite (restore 20261105-1); the previous database is in /data/pre-restore-20261105-1
…
```

A new backup needs a new `restore.id`: an id is bound to the backup it
installed, and the init container refuses it with another one. The upgrade
first backs up the current store (the hook), then replaces the pod: an init
container runs [`restore`](#restore) before the server starts, and does
nothing on later starts while the values stay set. The backup must open with
`masterKey.existingSecret` and, with an
[audit checkpoint](audit-checkpoints.md#restore), pass it. For a backup from
before a [master-key rotation](master-key-rotation.md), see
[below](#a-backup-from-before-a-master-key-rotation). Then:

1. Run `helm test keytend-kmip-server -n $NS --logs` and have a client read a
   known key.
2. Remove the restore values: run the upgrade again without the two `--set`
   options. The pod restarts once more.
3. Once the restore is confirmed, start the [volume helper](#volume-helper)
   and delete `/data/pre-restore-20261105-1/` (the previous database) with
   `kubectl -n $NS exec $H -- rm -rf /data/pre-restore-20261105-1`.

To restore a backup kept elsewhere, start the [volume helper](#volume-helper)
and copy the backup into the backup PVC
(`kubectl -n $NS cp backup.sqlite $H:/backups/recovered.sqlite`,
then `kubectl -n $NS exec $H -- chmod 0600 /backups/recovered.sqlite`) and give
`restore.from=recovered.sqlite`; `restore.existingClaim` names another PVC
instead. Copies placed there by hand are never pruned.

If the restore refuses (a wrong key, a backup older than the checkpoint, a
damaged or missing file), the init container fails, the server does not start
and the upgrade fails when `--wait` times out; nothing has changed.
`kubectl -n $NS logs keytend-kmip-server-0 -c restore` names the reason. Fix
the values and upgrade again, or start the old store with an upgrade without
the restore values; the upgrade replaces the stuck pod. If the pod was killed
during the cutover, the next start reruns the same id and finishes it; keep
the restore values until it has, then go on as above.

To go back to the database the restore replaced, restore it like any other
backup. The restore's upgrades removed the helper, so start the
[volume helper](#volume-helper) again and list the directory with sizes:

```sh
kubectl -n $NS exec $H -- ls -la /data/pre-restore-20261105-1
```

If there is no `kmip.sqlite-wal`, or its size is 0, copy the database to the
backup volume and restore it with a new id:

```sh
kubectl -n $NS exec $H -- cp /data/pre-restore-20261105-1/kmip.sqlite /backups/pre-restore-20261105-1.sqlite
kubectl -n $NS exec $H -- chmod 0600 /backups/pre-restore-20261105-1.sqlite
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml \
  --set restore.from=pre-restore-20261105-1.sqlite --set restore.id=20261105-2 --wait
```

If `kmip.sqlite-wal` is not empty, do not copy the main file alone: it can
lack committed changes and still pass verification, because `restore` looks
for a `-wal` file only next to the copy it is given. Copy both files off the
cluster (`kubectl cp`), make a standalone copy with `keytend-kmip-server backup
--database kmip.sqlite --master-key master.key --output standalone.sqlite` in
that directory, copy `standalone.sqlite` into the backup PVC as for a backup
kept elsewhere (above), and restore it with a new id.

#### A backup from before a master-key rotation

Such a backup opens only with the old key, and the store is under the new
one. The pre-upgrade backup tries only `masterKey.existingSecret`, so an
upgrade that names the old key fails in the hook before anything changes.
Back up the current store first, then restore without the hook:

1. [Run a backup now](#scheduled-backups-on-kubernetes) and check its log.
2. Set `masterKey.existingSecret` in `kmip-values.yaml` to the Secret of the
   key that opens the backup (`kmip-master-v1` for a backup from before the
   rotation to `kmip-master-v2`); it stays the server's key after the
   restore. With an audit checkpoint, also put the checkpoint of that key
   generation (the one from before the rotation) back into the checkpoint
   ConfigMap, because the current checkpoint belongs to the new key.
3. Restore with `--no-hooks`:

   ```sh
   helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --no-hooks \
     --set restore.from=backup-20261101T021500Z.sqlite --set restore.id=20261105-1 --wait
   ```

Then check the restore and remove its values as in steps 1 to 3 above. Later
upgrades run the hook again, with the old key on the restored store.

### Records next to the database

What you may find in `/data` through the volume helper:

| File | Meaning |
| --- | --- |
| `kmip.sqlite.lock` | The store lock that `serve` holds. Never delete it while a pod runs. |
| `kmip.sqlite.restore.json`, `kmip.sqlite.rotation.json`, `kmip.sqlite.revert.json` | An unfinished restore, rotation or revert. The server and every backup refuse the store while one exists; the init container finishes it on the next start with the same values. Never delete these by hand. The one exception: when `restore` says its copy `is not the copy restore <id> recorded` or `no longer verifies`, follow the steps it prints. |
| `.restore-<id>` | A completed restore. Keep it while `restore.id` is set. |
| `pre-restore-<id>/`, `pre-rotation-<time>-<n>/`, `post-rotation-<time>-<n>/` | Earlier databases. Delete them once the change is confirmed (and, for `pre-rotation-*`, the new checkpoint published). |
| `kmip.sqlite.last-backup` | The time of the last successful backup, for the metric. |

## Recover onto a new host or namespace

When the host, its disks or the namespace are gone, rebuild from copies kept
elsewhere. You need:

| Item | Why |
| --- | --- |
| A verified backup | The keys, their attributes and the audit history. |
| The master key that opens it | Without it the backup cannot be read. |
| Its audit checkpoint, if you use them | The server refuses a store older than its checkpoint. |
| The policy file | Objects belong to principal names: keep every name, even if certificates (and their fingerprints) change. |
| The users file, if you use one | It names certificate fingerprints; update it for reissued certificates. |
| The settings (`kmip.env`, `compose.yaml` or `kmip-values.yaml`) | Listeners, TLS profile, leases and other non-default settings. |
| The server certificate and key, the client CA bundle and any CRL | Clients trust the server's CA and dial a name its certificate lists. |

Verify the backup with its key (and checkpoint) as in step 1 of
[restore](#restore), then:

- With Docker, prepare `/srv/kmip` as in
  [deployment](deployment.md#docker-or-podman) with the recovered files, but
  install the recovered master key instead of generating one. Install the
  backup as the database before the first start, then start the server and
  check it as in phase 4 of [restore with Docker](#restore-with-docker). Run
  from the directory that holds the recovered files:

  ```sh
  sudo install -o 10001 -g 10001 -m 0400 master.key /srv/kmip/master/master.key
  sudo install -o 10001 -g 10001 -m 0600 backup.sqlite /srv/kmip/data/kmip.sqlite
  ```

- On Kubernetes, [install the chart](kubernetes.md#install) with the
  recovered files, the recovered master key in its Secret and without
  `auditCheckpoint`; the server starts on an empty store. Copy the backup into
  the backup PVC and restore it as in
  [restore on Kubernetes](#restore-on-kubernetes), enabling the checkpoint
  in the same upgrade.
