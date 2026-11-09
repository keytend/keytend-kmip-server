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

# Rotate the master key of the Docker or Podman deployment in the /srv/kmip
# layout (docs/master-key-rotation.md#rotate-with-docker). Take and verify a
# backup first. Run it on the host, with the same IMAGE and CP every time:
#
#   IMAGE=<image> [CP=<checkpoint>] scripts/docker-rotate-master-key.sh
#   IMAGE=<image> [CP=<checkpoint>] scripts/docker-rotate-master-key.sh --resume <time>
#   IMAGE=<image> [CP=<checkpoint>] scripts/docker-rotate-master-key.sh --rollback <time>
#
# A rotation is named by the UTC time it started (<time>, such as
# 20261104T021500Z), which every message prints. Its phases print
# "phase N: ..." and, on failure, "phase N failed (rotation <time>)":
#   1. check the inputs and that nothing the run writes exists, stop the
#      server, generate the new key in KMIP_ROOT/next
#   2. write the rotated copy with rotate-master-key, checked against CP
#   3. cut over: the old database to data/pre-rotation-<time>/, the old key to
#      OLD_KEYS/master-pre-rotation-<time>.key, the new ones in their place
#   4. with CP: move the old checkpoint into data/pre-rotation-<time>/, export
#      one from the rotated store, install it as CP and keep a copy next to it
#      as checkpoint-<time>-rotated.json
#   5. start the server, wait for /readyz, run check-store
# After a failure in phase 1 or 2 nothing has changed: the script removes
# what it created and starts the server again on the old key.
#
# Once the cutover is complete (after a failure in phase 4 or 5, or in phase 3
# when the moves have been finished by hand), with the time of that rotation:
#   --resume    stop the server and run phases 4 and 5 again; phase 4 skips
#               what the failed run finished
#   --rollback  stop the server, move the rotated database and new key aside
#               (data/post-rotation-<time>/, OLD_KEYS/master-post-rotation-<time>.key,
#               with the new checkpoint and its copy), put back the old database, key and checkpoint, start and
#               verify; writes accepted since the cutover are not carried back
#
#   IMAGE      the image the server runs (required)
#   CP         the checkpoint file the container starts with, if any; it must
#              be in KMIP_ROOT/checkpoints, which is mounted at /checkpoints
#   KMIP_ROOT  the layout (default /srv/kmip)
#   OLD_KEYS   where old master keys are kept (default /srv/kmip-old-keys)
#   SUDO       prefix for commands on the layout's files (default sudo; none
#              when run as root; "podman unshare" with rootless Podman)
#   DOCKER     container CLI (default docker, or podman when there is no docker)
set -euo pipefail

NAME=keytend-kmip-server
R=${KMIP_ROOT:-/srv/kmip}
OLD_KEYS=${OLD_KEYS:-/srv/kmip-old-keys}
CP=${CP:-}
if [ -z "${SUDO+set}" ]; then
  if [ "$(id -u)" -eq 0 ]; then SUDO=; else SUDO=sudo; fi
fi
if [ -z "${DOCKER:-}" ]; then
  if command -v docker >/dev/null 2>&1; then DOCKER=docker; else DOCKER=podman; fi
fi
usage() {
  echo "usage: IMAGE=<image> [CP=<checkpoint>] $0 [--resume <time> | --rollback <time>]" >&2
  exit 2
}
[ -n "${IMAGE:-}" ] || usage
case $#:${1:-} in
  0:) MODE=rotate D=$(date -u +%Y%m%dT%H%M%SZ) ;;
  2:--resume|2:--rollback) MODE=${1#--} D=$2 ;;
  *) usage ;;
esac
case $D in *[!0-9TZ]*|'') usage ;; esac
OLD_DB=$R/data/pre-rotation-$D
OLD_KEY=$OLD_KEYS/master-pre-rotation-$D.key
NEW_CP=checkpoint-$D-rotated.json
CP_IN=
if [ -n "$CP" ]; then
  case $CP in
    "$R"/checkpoints/*) CP_IN=/checkpoints/${CP#"$R"/checkpoints/} ;;
    *) echo "CP must be in $R/checkpoints, which the container mounts at /checkpoints" >&2; exit 2 ;;
  esac
fi

as_root() { $SUDO "$@"; }
die() { echo "docker-rotate-master-key.sh: $*" >&2; exit 1; }
PHASE=check MADE_NEXT=''
phase() { PHASE=$1; echo "phase $1: $2"; }
ready() {
  curl -sf --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8080/readyz >/dev/null ||
    { "$DOCKER" logs --tail 20 "$NAME"; false; }
}
verify() {
  "$DOCKER" exec "$NAME" keytend-kmip-server check-store \
    --database /data/kmip.sqlite --master-key /master/master.key \
    ${CP_IN:+--audit-checkpoint "$CP_IN"}
}
on_exit() {
  local rc=$?
  [ "$rc" -ne 0 ] || return 0
  case $MODE:$PHASE in
    *:check) echo "docker-rotate-master-key.sh: refused ($MODE $D); nothing was stopped or changed" >&2 ;;
    rotate:1|rotate:2)
      echo "docker-rotate-master-key.sh: phase $PHASE failed (rotation $D)" >&2
      if [ -n "$MADE_NEXT" ]; then as_root rm -rf "$R/next" "$R/data/rotated" || true; fi
      echo "nothing has changed; starting the server again on the old key" >&2
      if "$DOCKER" start "$NAME" >/dev/null && ready; then
        echo "the server is ready" >&2
      else
        echo "the server did not become ready: read docker logs $NAME" >&2
      fi ;;
    rotate:3)
      echo "docker-rotate-master-key.sh: phase 3 failed (rotation $D)" >&2
      echo "the cutover is partial and the server is stopped: remove nothing; finish the" \
        "moves by hand (docs/master-key-rotation.md#if-the-docker-rotation-fails)," \
        "then run it with --resume $D or --rollback $D" >&2 ;;
    *:rollback)
      echo "docker-rotate-master-key.sh: rollback of rotation $D failed;" \
        "see docs/master-key-rotation.md#if-the-docker-rotation-fails" >&2 ;;
    *)
      echo "docker-rotate-master-key.sh: phase $PHASE failed (rotation $D)" >&2
      echo "the database and key are rotated; read docker logs $NAME, fix the cause," \
        "then run it with --resume $D (or --rollback $D)" >&2 ;;
  esac
}
trap on_exit EXIT

# Checks for --resume and --rollback: the cutover of rotation D is complete.
check_cut_over() {
  local f
  for f in "$R/data/kmip.sqlite" "$R/master/master.key" "$OLD_DB/kmip.sqlite" "$OLD_KEY"; do
    as_root test -e "$f" || die "no $f: the cutover of rotation $D is not complete"
  done
  for f in "$R/next" "$R/data/rotated"; do
    if as_root test -e "$f"; then die "$f exists: the cutover of rotation $D is not complete"; fi
  done
}

# Phases 1 to 3.
rotate_and_cut_over() {
  local f
  as_root test -f "$R/data/kmip.sqlite" || die "no $R/data/kmip.sqlite"
  as_root test -f "$R/master/master.key" || die "no $R/master/master.key"
  [ -z "$CP" ] || as_root test -f "$CP" || die "no checkpoint $CP"
  for f in "$R/next" "$R/data/rotated" "$OLD_DB" "$OLD_KEY" "$R/data/$NEW_CP" ${CP:+"${CP%/*}/$NEW_CP"}; do
    if as_root test -e "$f"; then die "$f already exists"; fi
  done
  "$DOCKER" container inspect "$NAME" >/dev/null || die "no container $NAME"
  "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1 || "$DOCKER" pull "$IMAGE" || die "cannot get $IMAGE"

  phase 1 "stop the server and generate the new key"
  "$DOCKER" stop -t 30 "$NAME" >/dev/null
  as_root install -d -o 10001 -g 10001 -m 0700 "$R/next"
  MADE_NEXT=1
  "$DOCKER" run --rm -v "$R/next:/next" "$IMAGE" generate-master-key --output /next/master.key

  phase 2 "write the rotated copy (the source is not changed)"
  "$DOCKER" run --rm -v "$R/data:/data" -v "$R/master:/master:ro" -v "$R/next:/next:ro" \
    ${CP:+-v "$CP:/checkpoint.json:ro"} "$IMAGE" rotate-master-key \
    --database /data/kmip.sqlite --master-key /master/master.key \
    --new-master-key /next/master.key ${CP:+--audit-checkpoint /checkpoint.json} \
    --output /data/rotated/kmip.sqlite --create-directory

  phase 3 "cut over"
  as_root install -d -m 0700 "$OLD_KEYS"
  as_root sh -c 'set -e; cd "$1"
    mkdir -m 0700 "$2" && mv data/kmip.sqlite* "$2"/
    mv data/rotated/kmip.sqlite data/kmip.sqlite && rmdir data/rotated
    mv master/master.key "$3"
    mv next/master.key master/master.key && rmdir next' _ "$R" "$OLD_DB" "$OLD_KEY"
}

# Phase 4; each step is skipped when an earlier run finished it.
install_checkpoint() {
  if as_root test -e "${CP%/*}/$NEW_CP"; then return; fi
  phase 4 "export a checkpoint from the rotated store and install it"
  as_root test -e "$R/data/$NEW_CP" ||
    "$DOCKER" run --rm -v "$R/data:/data" -v "$R/master:/master:ro" "$IMAGE" \
      audit-checkpoint --database /data/kmip.sqlite --master-key /master/master.key \
      --output "/data/$NEW_CP"
  as_root sh -c 'set -e; cd "$1/data"
    if [ -e "$2" ] && ! cmp -s "$2" "$4"; then
      [ ! -e "$3/${2##*/}" ] || { echo "$3/${2##*/} already exists" >&2; exit 1; }
      mv "$2" "$3"/
    fi
    chmod 0444 "$4"; cp -p "$4" "$2"; mv "$4" "${2%/*}/"' _ "$R" "$CP" "$OLD_DB" "$NEW_CP"
}

rollback() {
  local f
  for f in "$R/data/post-rotation-$D" "$OLD_KEYS/master-post-rotation-$D.key"; do
    if as_root test -e "$f"; then die "$f already exists"; fi
  done
  PHASE=rollback
  echo "rollback: stop the server and put back the database and key from before rotation $D"
  "$DOCKER" stop -t 30 "$NAME" >/dev/null
  as_root sh -c 'set -e; cd "$1"
    mkdir -m 0700 "data/post-rotation-$2" && mv data/kmip.sqlite* "data/post-rotation-$2"/
    mv "data/pre-rotation-$2"/kmip.sqlite* data/
    mv master/master.key "$3/master-post-rotation-$2.key"
    mv "$3/master-pre-rotation-$2.key" master/master.key
    for f in "data/checkpoint-$2-rotated.json" "${4%/*}/checkpoint-$2-rotated.json"; do
      if [ -n "$4" ] && [ -e "$f" ]; then mv "$f" "data/post-rotation-$2"/; fi
    done
    if [ -n "$4" ] && [ -e "data/pre-rotation-$2/${4##*/}" ]; then
      mv "data/pre-rotation-$2/${4##*/}" "$4"
    fi' _ "$R" "$D" "$OLD_KEYS" "$CP"
  echo "rollback: start the server and verify it"
  "$DOCKER" start "$NAME" >/dev/null
  ready
  verify
  echo "rolled back rotation $D. The rotated database and new key are in"
  echo "$R/data/post-rotation-$D and $OLD_KEYS/master-post-rotation-$D.key"
}

case $MODE in rotate) echo "rotation $D" ;; *) echo "$MODE rotation $D" ;; esac
case $MODE in
  rotate) rotate_and_cut_over ;;
  resume) check_cut_over; "$DOCKER" stop -t 30 "$NAME" >/dev/null; PHASE=4 ;;
  rollback) check_cut_over; rollback; exit 0 ;;
esac
if [ -n "$CP" ]; then install_checkpoint; fi

phase 5 "start the server and verify it"
"$DOCKER" start "$NAME" >/dev/null
ready
verify

echo "rotated (rotation $D). Keep these until no recovery needs them, the key apart from the databases:"
echo "  old database: $OLD_DB"
echo "  old key:      $OLD_KEY"
[ -z "$CP" ] || echo "  new checkpoint: ${CP%/*}/$NEW_CP (copy it to your checkpoint store; the old one is in $OLD_DB)"
echo "next: take and verify a backup under the new key"
