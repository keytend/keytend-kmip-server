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

# Master-key rotation

Part of [configuration and operations](README.md#configuration-and-operations).

`rotate-master-key` writes a copy of the store encrypted under a new key; the
source database and key file stay as they are, apart from a
[schema migration](configuration.md#store-lock-and-cutover-records). Stop the server first and keep
it stopped until the cutover: the copy is a snapshot, so plan a downtime
window. The procedures keep the serving paths (`/data/kmip.sqlite`,
`/master/master.key`) the same, so backups, upgrades and the next rotation use
the same commands.

- [Rotate](#rotate)
- [What the command guarantees](#what-the-command-guarantees)
- [Rotate in place](#rotate-in-place)
- [Rotate with Docker](#rotate-with-docker) ([if it fails](#if-the-docker-rotation-fails))
- [On Kubernetes](#on-kubernetes) ([revert](#revert-on-kubernetes), [if it fails](#if-the-kubernetes-rotation-fails))

This is separate from rotating a database's own master key through KMIP (for
example Percona's `--kmipRotateMasterKey`; see [Percona](percona.md)).

## Rotate

1. Stop clients and the server, then take and verify a
   [backup](backup-restore.md) with the current key. The data volume needs
   free space for a second full copy of the database: the rotated copy is
   written next to it.
2. Generate the new key and write the rotated copy. With an
   [audit checkpoint](audit-checkpoints.md), add
   `--audit-checkpoint <current checkpoint>` so the source is checked against
   it:

   ```sh
   keytend-kmip-server generate-master-key --output /protected/next-master.key
   keytend-kmip-server rotate-master-key --database /data/kmip.sqlite \
     --master-key /master/master.key --new-master-key /protected/next-master.key \
     --output /data/rotated/kmip.sqlite --create-directory
   ```

   It prints `Verified rotated snapshot: <n> objects, <m> audit entries. …`.
   If it fails, see [below](#what-the-command-guarantees) before you go on.
3. Cut over: move `/data/kmip.sqlite` (and any `-wal`/`-shm` files) into a
   directory named for the UTC time, such as
   `/data/pre-rotation-20261104T021500Z/`, move
   `/data/rotated/kmip.sqlite` to `/data/kmip.sqlite` and remove the empty
   `/data/rotated`. Keep the old key (stored apart from the databases, and
   labelled with the directory it belongs to), then put the new key in
   place of `/master/master.key`.
4. With an audit checkpoint, export a new one from the rotated store under the
   new key and deploy it in place of the old one; the old checkpoint does not
   verify the rotated store, so leave out `--previous` too.

   ```sh
   keytend-kmip-server audit-checkpoint --database /data/kmip.sqlite \
     --master-key /master/master.key --output checkpoint-2026-11-04-rotated.json
   ```

5. Start the server, verify readiness and a known key, then take and test a
   backup with the new key.
6. Keep the old database, old key and old checkpoint until no recovery or
   older backup needs them. Record which key and checkpoint belong to which
   database, but store the key apart from the databases and backups, under
   its own access control. Once the server has accepted writes, going back to
   the old database loses them.

## What the command guarantees

- It checks SQLite integrity, every object record and the whole audit chain
  of the source, and verifies the new copy before publishing it. Objects,
  identifiers, owners, attributes, usage budgets and audit history carry over;
  the audit chain is re-authenticated under the new key, and one rotation
  event is appended ([store integrity](store-integrity.md#backup-and-rotation)).
- It refuses to run while a server holds the
  [store lock](configuration.md#store-lock-and-cutover-records).
- It refuses an output that already exists (or has `-wal`/`-shm` files), a
  symlink, a new key equal to the old one and unknown storage metadata.
  `--create-directory` refuses an existing directory, which is why the cutover
  removes `/data/rotated`.
- The output directory must be on a filesystem with hard links and fsync.
  The copy is staged in a private directory there and published with a hard
  link that refuses to overwrite.
- **When it fails, the source database and key are unchanged** (apart from
  a schema migration), and the server can start on them again.
- A failed run can still leave files behind: an output published before a
  later error (for example a failed directory sync), or
  `.keytend-kmip-server-rotate-*` staging directories from a killed run. None
  of them is a valid copy. Delete the output directory (and any staging
  directories) before you run the rotation again; never cut over to a copy
  from a failed run.
- Rotation scans the whole store and can take a long time on a large one.
  Online rotation, HSM or KMS sealing of the master key and replicated stores
  are not supported.

## Rotate in place

`rotate-master-key --in-place` runs the rotation and the cutover as one
command on the stopped server's volume, with no shell needed; the
[chart](#on-kubernetes) runs it before the server starts. `--master-key` is
the new key (the one the server will start with) and `--previous-master-key`
the current one:

```sh
keytend-kmip-server rotate-master-key --in-place --database /data/kmip.sqlite \
  --master-key /master/master.key --previous-master-key /master-previous/master.key \
  --audit-checkpoint /checkpoints/checkpoint.json --checkpoint-output /run/kmip/checkpoint.json
```

It takes the [store lock](configuration.md#store-lock-and-cutover-records), so the server must be
stopped, then looks at which key opens the store:

- If the new key opens it, there is nothing to do: it verifies the store and
  exits 0, so it can run at every start of a container.
- If the previous key opens it, it writes and verifies the rotated copy as above,
  moves the database to `pre-rotation-<UTC time>-<n>/` next to it, installs the
  copy and verifies it. The store must have this release's schema: after an
  upgrade, start the server once before rotating.
- If neither does, it refuses and changes nothing.

With an audit checkpoint, give the current one as `--audit-checkpoint` and a
new file as `--checkpoint-output`. The source is checked against the old
checkpoint, and a checkpoint for the new key is written to the output; start
the server with that one, because the old checkpoint does not verify the
rotated store. Copy the new checkpoint to your checkpoint store before you
delete the pre-rotation copy. Until you delete it, a later run with the old
checkpoint still works: it checks the old checkpoint against the newest
pre-rotation copy, checks that the store is that copy's rotation, and writes
the output again. Without
`--checkpoint-output` that run fails, as the server would.

Before anything moves, the command writes `kmip.sqlite.rotation.json` next to
the database and removes it when it finishes. If a run is killed, the server
and the read-only commands refuse the database while that record exists; run
the same command again, which checks `--audit-checkpoint` and the copy before
it finishes the cutover. If a check fails after files were moved, the error
says so and names `--revert`. Never delete the record by hand.

`--revert` (same keys) puts back the newest `pre-rotation-<time>-<n>/` database,
which must open with `--previous-master-key`, satisfy `--audit-checkpoint`
(the old checkpoint) and have the current store as its rotation. It moves the
rotated database to `post-rotation-<time>-<n>/`, and also undoes a rotation that
stopped mid-cutover; it records itself in `kmip.sqlite.revert.json` the same
way. Start the server with the previous key and checkpoint afterwards.
Writes accepted since the rotation are not carried back. Keep the previous
key and the pre-rotation copy as step 6 says.

## Rotate with Docker

[`scripts/docker-rotate-master-key.sh`](../scripts/docker-rotate-master-key.sh)
runs the steps above for the `/srv/kmip` layout of
[deployment](deployment.md#docker-or-podman). Take a verified
[backup](backup-restore.md#back-up-with-docker) first, then run it on the
host from the checkout, as a user who can run `sudo` and `docker`. Set
`IMAGE` to the image you run and, if the container starts with an
[audit checkpoint](audit-checkpoints.md#start-the-server-with-it), `CP` to
that file (it must be in `/srv/kmip/checkpoints`, which Compose mounts at
`/checkpoints`):

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>' \
CP=/srv/kmip/checkpoints/checkpoint.json \
  scripts/docker-rotate-master-key.sh      # leave out CP without a checkpoint
```

```text
rotation 20261104T021500Z
phase 1: stop the server and generate the new key
phase 2: write the rotated copy (the source is not changed)
Verified rotated snapshot: 1 objects, 7 audit entries. …
phase 3: cut over
phase 4: export a checkpoint from the rotated store and install it
Authenticated audit checkpoint exported; retain it independently of database snapshots
phase 5: start the server and verify it
Master key, object records and audit chain verified
rotated (rotation 20261104T021500Z). Keep these until no recovery needs them, …
```

The UTC time names the rotation and its files. The phases:

1. Check that the database, key and checkpoint exist and that nothing the
   run writes does; only then stop the server and generate the new key in
   `/srv/kmip/next`.
2. Write the rotated copy, checking the source against the checkpoint; the
   source is not changed.
3. Cut over: the old database to `/srv/kmip/data/pre-rotation-<time>/`, the
   old key to `/srv/kmip-old-keys/master-pre-rotation-<time>.key` (apart from
   the databases), and the new ones in their place.
4. With a checkpoint: move the old one next to the old database, export a new
   one under the new key, install it as `CP` and keep a copy next to it as
   `checkpoint-<time>-rotated.json`.
5. Start the server, wait for `/readyz` and run `check-store`.

Then take a backup under the new key; with a checkpoint, copy
`checkpoint-<time>-rotated.json` to your independent checkpoint store. Keep
the old database, key and checkpoint as step 6 says. With rootless Podman,
add `SUDO='podman unshare' DOCKER=podman`
([rootless Podman](deployment.md#rootless-podman)); `KMIP_ROOT` and
`OLD_KEYS` move the layout (see the script's header).

### If the Docker rotation fails

The script stops at the first failed command and prints
`phase N failed (rotation <time>)` and what to do next. Run every command
below with the same `IMAGE` and `CP`.

- Refused before phase 1 (for example `… already exists`): nothing was
  stopped or changed. An earlier run left that file; work out what that run
  left from the cases below before you remove anything.
- Phase 1 or 2: nothing has changed. The script removes `next` and
  `data/rotated` and starts the server again on the old key. Fix the cause
  and run it again.
- Phase 3: the cutover is partial and the server is stopped. Remove
  nothing. Compare `/srv/kmip/data`, `pre-rotation-<time>`, `/srv/kmip/master`,
  `/srv/kmip-old-keys` and `/srv/kmip/next` with phase 3 above and finish the
  moves by hand (the database, then the old key, then the new key, then
  `rmdir /srv/kmip/next`). Then go on as for phase 4.
- Phase 4 or 5: the database and key are rotated. Fix the cause (for
  phase 5, `docker logs keytend-kmip-server` names it), then either finish
  the rotation or go back to the old key:

  ```sh
  scripts/docker-rotate-master-key.sh --resume 20261104T021500Z     # phases 4 and 5 again
  scripts/docker-rotate-master-key.sh --rollback 20261104T021500Z   # the old database, key and checkpoint
  ```

  `--resume` skips what the failed run finished in phase 4: the export
  writes its file whole or not at all and refuses to replace it.
  `--rollback` moves the rotated database and new key aside to
  `data/post-rotation-<time>/` and `/srv/kmip-old-keys/master-post-rotation-<time>.key`.
  Once the server has accepted writes on the rotated store, a rollback loses
  them.

## On Kubernetes

The [chart](kubernetes.md) rotates in place in an init container when
`rotation.previousMasterKeySecret` is set. The commands use the variables and
`kmip-values.yaml` of [installing the chart](kubernetes.md#install), where
`masterKey.existingSecret` is `kmip-master-v1`. The data volume needs free
space for a second full copy of the database.

1. Generate the next key and put it in a new Secret (with a native build, run
   `keytend-kmip-server generate-master-key --output master-v2.key`):

   ```sh
   IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>'   # the image you run
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" "$IMAGE" \
     generate-master-key --output /work/master-v2.key
   kubectl -n $NS create secret generic kmip-master-v2 --from-file=master.key=master-v2.key
   ```

2. Rotate. The upgrade first backs up the store (the pre-upgrade hook tries
   both keys, and its log names the one that opened the store,
   `kmip-master-v1`), then restarts the pod; the init container rotates
   before the server starts:

   ```sh
   helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml \
     --set masterKey.existingSecret=kmip-master-v2 \
     --set rotation.previousMasterKeySecret=kmip-master-v1 --wait
   kubectl -n $NS logs keytend-kmip-server-0 -c rotate-master-key
   ```

   ```text
   Verified rotated snapshot: 12 objects, 41 audit entries
   Rotated /data/kmip.sqlite to --master-key (12 objects, 41 audit entries); the database from before the rotation is in /data/pre-rotation-20261105T212502Z-1
   …
   ```

   Run `helm test keytend-kmip-server -n $NS --logs` and have a client read a
   known key.

3. With an [audit checkpoint](audit-checkpoints.md#start-the-server-with-it):
   the init container wrote a checkpoint for the new key, and the server runs
   with it. Publish it to the checkpoint ConfigMap and to your independent
   checkpoint store:

   ```sh
   kubectl -n $NS logs keytend-kmip-server-0 -c checkpoint > checkpoint-v2.json
   kubectl -n $NS create configmap kmip-checkpoint \
     --from-file=checkpoint.json=checkpoint-v2.json --dry-run=client -o yaml | kubectl apply -f -
   ```

   Until you do, every start accepts the old checkpoint through the
   pre-rotation copy, as [above](#rotate-in-place).

4. Finish: set `masterKey.existingSecret: kmip-master-v2` in
   `kmip-values.yaml` and upgrade without the rotation values. Then take a
   backup under the new key
   ([run one now](backup-restore.md#scheduled-backups-on-kubernetes)):

   ```sh
   helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
   ```

Keep `kmip-master-v1` (and a copy of `master.key` apart from the databases)
while `/data/pre-rotation-*/` or any backup from before the rotation
exists; delete the directory through the
[volume helper](backup-restore.md#volume-helper) once no
recovery needs it. Do not combine a rotation with an image upgrade: upgrade
first, let the server start, then rotate.

### Revert on Kubernetes

Before step 4, put back the pre-rotation database by adding
`--set rotation.revert=true` to the command of step 2. The server then runs
on `kmip-master-v1` again. With an audit checkpoint, the ConfigMap must hold
the pre-rotation checkpoint: if you already published the new one, put the old
one back first. Writes accepted since the rotation are lost (they stay in
`/data/post-rotation-*/`). Revert, then finish by upgrading with
`kmip-values.yaml`, which still names `kmip-master-v1`:

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml \
  --set masterKey.existingSecret=kmip-master-v2 \
  --set rotation.previousMasterKeySecret=kmip-master-v1 --set rotation.revert=true --wait
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
```

### If the Kubernetes rotation fails

The init container fails, the server does not start and `helm upgrade
--wait` times out (on a large store, give `--timeout 15m`). The next
`helm upgrade` replaces the failing pod. Read why:

```sh
kubectl -n $NS logs keytend-kmip-server-0 -c rotate-master-key
```

- If nothing changed (neither key opens the store, the checkpoint refuses
  the source, an older schema, no space), start the server on the old key,
  fix the cause and start again from step 2. The pre-upgrade backup finds
  the old key itself:

  ```sh
  helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
  ```

- If the pod was killed or evicted during the cutover,
  `kmip.sqlite.rotation.json` exists and the server refuses to start until
  the rotation finishes. Keep the rotation values: the next start runs the
  same command and completes it. Never delete the record. Backups, including
  the pre-upgrade one, refuse the store until then.
- If files were moved and a check failed, the message says so and names
  `--revert`. [Revert](#revert-on-kubernetes), adding `--no-hooks` to the
  revert command: the rotation record is still there, so the pre-upgrade
  backup would refuse the store. The upgrade replaces the failing pod.
- If the server refuses to start after the rotation with
  `audit checkpoint authentication failed`:
  - If you removed the rotation values before publishing the new checkpoint
    (step 3), the checkpoint the init container wrote went with the old pod.
    Run step 2's command again: while `/data/pre-rotation-*/` exists,
    the init container accepts the old checkpoint again and writes a new one.
    Then publish it (step 3) and finish (step 4).
  - Otherwise the ConfigMap holds a checkpoint of neither key generation: put
    back the one from your checkpoint store.
