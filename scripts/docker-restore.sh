#!/usr/bin/env bash
# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Restore a backup into the Docker or Podman deployment in the /srv/kmip
# layout with Compose (docs/backup-restore.md#restore-with-docker). Run it on
# the host:
#
#   IMAGE=<image> B=<backup> [KEYDIR=<dir>] [CP=<checkpoint>] scripts/docker-restore.sh
#   scripts/docker-restore.sh --undo <time>
#
# A restore is named by the UTC time it started (<time>, such as
# 20261104T021500Z), which every message prints. Its phases print
# "phase N: ..." and, on failure, "phase N failed (restore <time>)":
#   1. check the inputs and that nothing the run writes exists, then verify
#      the backup with check-store (and CP); the server keeps running
#   2. stop the server; move the current database, and a copy of .env, to
#      KMIP_ROOT/pre-restore-<time>/
#   3. install the backup, and KEYDIR's master key if it differs from the
#      current one (keeping the current key as
#      OLD_KEYS/master-pre-restore-<time>.key)
#   4. set IMAGE in KMIP_ROOT/.env, recreate the container with Compose, wait
#      for /readyz, run check-store
# After a failure in phase 1 the server was never stopped.
#
# --undo <time> puts back what restore <time> replaced: it stops the server,
# removes the restored database, moves the previous database, master key and
# .env back, recreates the container and verifies it. Writes accepted since
# the restore are lost.
#
#   IMAGE      the image to run, which also checks the backup (required): the
#              image you run, or the old one when rolling back an upgrade
#   B          the backup: a file name in BACKUPS, or a path (required); it,
#              KEYDIR and CP must be readable by UID 10001
#   KEYDIR     the directory whose master.key opens the backup
#              (default KMIP_ROOT/master, the current key)
#   CP         the checkpoint file the container starts with, if any; it must
#              be in KMIP_ROOT/checkpoints, which is mounted at /checkpoints
#   KMIP_ROOT  the layout (default /srv/kmip)
#   BACKUPS    default directory of B (default /srv/kmip-backups)
#   OLD_KEYS   where replaced master keys are kept (default /srv/kmip-old-keys)
#   SUDO       prefix for commands on the layout's files (default sudo; none
#              when run as root; "podman unshare" with rootless Podman)
#   DOCKER     container CLI (default docker, or podman when there is no docker)
set -euo pipefail

NAME=keytend-kmip-server
R=${KMIP_ROOT:-/srv/kmip}
BACKUPS=${BACKUPS:-/srv/kmip-backups}
OLD_KEYS=${OLD_KEYS:-/srv/kmip-old-keys}
KEYDIR=${KEYDIR:-$R/master}
CP=${CP:-}
if [ -z "${SUDO+set}" ]; then
  if [ "$(id -u)" -eq 0 ]; then SUDO=; else SUDO=sudo; fi
fi
if [ -z "${DOCKER:-}" ]; then
  if command -v docker >/dev/null 2>&1; then DOCKER=docker; else DOCKER=podman; fi
fi
usage() {
  echo "usage: IMAGE=<image> B=<backup> [KEYDIR=<dir>] [CP=<checkpoint>] $0" >&2
  echo "       $0 --undo <time>" >&2
  exit 2
}
case $#:${1:-} in
  0:) MODE=restore D=$(date -u +%Y%m%dT%H%M%SZ); [ -n "${IMAGE:-}" ] && [ -n "${B:-}" ] || usage ;;
  2:--undo) MODE=undo D=$2 ;;
  *) usage ;;
esac
case $D in *[!0-9TZ]*|'') usage ;; esac
OLD=$R/pre-restore-$D
OLD_KEY=$OLD_KEYS/master-pre-restore-$D.key
CP_IN=
if [ -n "$CP" ]; then
  case $CP in
    "$R"/checkpoints/*) CP_IN=/checkpoints/${CP#"$R"/checkpoints/} ;;
    *) echo "CP must be in $R/checkpoints, which the container mounts at /checkpoints" >&2; exit 2 ;;
  esac
fi

as_root() { $SUDO "$@"; }
die() { echo "docker-restore.sh: $*" >&2; exit 1; }
PHASE=1
phase() { PHASE=$1; echo "phase $1: $2"; }
stop() {
  "$DOCKER" stop -t 30 "$NAME" >/dev/null 2>&1 || true   # also when there is no container
  [ "$("$DOCKER" container inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ] ||
    die "$NAME is still running"
}
start_and_verify() {
  "$DOCKER" compose -f "$R/compose.yaml" up -d --force-recreate
  curl -sf --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8080/readyz >/dev/null ||
    { "$DOCKER" logs --tail 20 "$NAME"; false; }
  "$DOCKER" exec "$NAME" keytend-kmip-server check-store \
    --database /data/kmip.sqlite --master-key /master/master.key \
    ${CP_IN:+--audit-checkpoint "$CP_IN"}
}
on_exit() {
  local rc=$?
  [ "$rc" -ne 0 ] || return 0
  case $MODE:$PHASE in
    restore:1) echo "docker-restore.sh: phase 1 failed (restore $D); nothing was stopped or changed" >&2 ;;
    restore:*)
      echo "docker-restore.sh: phase $PHASE failed (restore $D)" >&2
      echo "the server is stopped or not verified; read docker logs $NAME, then" \
        "run it with --undo $D to put back the previous database" \
        "(docs/backup-restore.md#if-the-docker-restore-fails)" >&2 ;;
    undo:*) echo "docker-restore.sh: --undo $D failed;" \
      "see docs/backup-restore.md#if-the-docker-restore-fails" >&2 ;;
  esac
}
trap on_exit EXIT

undo() {
  as_root test -f "$OLD/kmip.sqlite" || die "no $OLD/kmip.sqlite: nothing to undo"
  echo "undo: stop the server and put back what restore $D replaced"
  stop
  as_root sh -c 'set -e; cd "$1"
    rm -f data/kmip.sqlite data/kmip.sqlite-wal data/kmip.sqlite-shm
    mv "$2"/kmip.sqlite* data/
    if [ -f "$3" ]; then mv "$3" master/master.key; fi
    if [ -f "$2/.env" ]; then mv "$2/.env" .env; fi
    rmdir "$2"' _ "$R" "$OLD" "$OLD_KEY"
  echo "undo: recreate the container and verify it"
  start_and_verify
  echo "undid restore $D"
}
if [ "$MODE" = undo ]; then PHASE=undo; undo; exit 0; fi

echo "restore $D"
phase 1 "check the inputs and verify the backup"
case $B in */*) ;; *) B=$BACKUPS/$B ;; esac
as_root test -f "$B" || die "no backup $B"
as_root test -f "$KEYDIR/master.key" || die "no $KEYDIR/master.key"
as_root test -f "$R/compose.yaml" && as_root test -f "$R/.env" ||
  die "no $R/compose.yaml and .env (see docs/deployment.md#docker-compose)"
[ -z "$CP" ] || as_root test -f "$CP" || die "no checkpoint $CP"
NEW_KEY=
as_root cmp -s "$KEYDIR/master.key" "$R/master/master.key" || NEW_KEY=1
for f in "$OLD" "$OLD_KEY"; do
  if as_root test -e "$f"; then die "$f already exists"; fi
done
"$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1 || "$DOCKER" pull "$IMAGE" || die "cannot get $IMAGE"
"$DOCKER" run --rm -v "${B%/*}:/backup" -v "$KEYDIR:/master:ro" \
  ${CP:+-v "$CP:/checkpoint.json:ro"} "$IMAGE" \
  check-store --database "/backup/${B##*/}" --master-key /master/master.key \
  ${CP:+--audit-checkpoint /checkpoint.json}

phase 2 "stop the server and move the current database aside"
stop
as_root sh -c 'set -e; mkdir -m 0700 "$1"; cp -p "$2/.env" "$1/.env"
  mv "$2"/data/kmip.sqlite* "$1"/' _ "$OLD" "$R"
echo "previous database in $OLD"

phase 3 "install the backup${NEW_KEY:+ and its master key}"
as_root install -o 10001 -g 10001 -m 0600 "$B" "$R/data/kmip.sqlite"
if [ -n "$NEW_KEY" ]; then
  as_root install -d -m 0700 "$OLD_KEYS"
  as_root cp -p "$R/master/master.key" "$OLD_KEY"
  echo "previous master key in $OLD_KEY"
  as_root install -o 10001 -g 10001 -m 0400 "$KEYDIR/master.key" "$R/master/master.key"
fi

phase 4 "recreate the container with $IMAGE and verify it"
as_root sed -i "s|^IMAGE=.*|IMAGE=$IMAGE|" "$R/.env"
start_and_verify

echo "restored ${B##*/} (restore $D). Have a client read a known key; once the"
echo "restore is confirmed, delete $OLD${NEW_KEY:+ (keep $OLD_KEY while backups need it)}"
