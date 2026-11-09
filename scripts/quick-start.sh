#!/bin/sh
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

# Evaluation only: start the quick-start server (docs/quick-start.md) in a
# container with disposable test certificates. Run from the checkout. It runs
# the commands of docs/manual-install.md: test certificates in
# .cache/dev-pki, state in .cache/container, a new master key, the container
# keytend-kmip-server on 127.0.0.1 ports 5696, 5697 and 8080, then waits until
# it is ready. With rootless Podman it adds --userns=keep-id, and :Z on SELinux.
#
#   scripts/quick-start.sh            start
#   scripts/quick-start.sh --restart  recreate the container from the settings
#                                     in .cache/container/kmip.env, keeping the
#                                     certificates, master key, data and image
#   scripts/quick-start.sh --clean    remove the container this script started
#                                     from this checkout, .cache/container,
#                                     .cache/dev-pki and .cache/dev-data (the
#                                     run-from-source store); nothing else
#
#   IMAGE   image to run (default localhost/keytend-kmip-server:dev; with
#           --restart, the image the container was started with)
#   DOCKER  container CLI (default docker, or podman when there is no docker)
set -eu
if [ -z "${DOCKER:-}" ]; then
  if command -v docker >/dev/null 2>&1; then DOCKER=docker; else DOCKER=podman; fi
fi
NAME=keytend-kmip-server
LABEL=dev.keytend.quick-start
S=.cache/container

[ -x scripts/dev-pki.sh ] && [ -f examples/https/kmip.sh ] ||
  { echo "quick-start.sh: run it from the checkout" >&2; exit 2; }

# The container, if it exists, must carry this checkout's label.
owned() {
  owner=$("$DOCKER" container inspect --format "{{index .Config.Labels \"$LABEL\"}}" $NAME 2>/dev/null) || return 1
  [ "$owner" = "$PWD" ] ||
    { echo "quick-start.sh: container $NAME was not started by quick-start.sh in $PWD; not changing anything" >&2; exit 2; }
}

userns=
if "$DOCKER" --version 2>/dev/null | grep -qi podman && [ "$(id -u)" -ne 0 ]; then
  userns=--userns=keep-id
fi
z=
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then z=,Z; fi

start() {
  "$DOCKER" run -d --name $NAME --label "$LABEL=$PWD" $userns --user "$(id -u):$(id -g)" \
    --read-only --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --pids-limit=128 --memory=512m --cpus=2 \
    -p 127.0.0.1:5696:5696 -p 127.0.0.1:5697:5697 -p 127.0.0.1:8080:8080 \
    -v "$PWD/$S/tls:/tls:ro$z" -v "$PWD/$S/policy:/policy:ro$z" \
    -v "$PWD/$S/master:/master:ro$z" -v "$PWD/$S/data:/data:rw$z" \
    --env-file $S/kmip.env "$IMAGE" >/dev/null
  curl -sf --retry 30 --retry-all-errors --retry-delay 1 http://127.0.0.1:8080/readyz ||
    { "$DOCKER" logs $NAME; exit 1; }
  echo "next (bash or zsh): . examples/https/kmip.sh && kmip create.json | field ResultStatus"
}

case ${1:-} in
  '') ;;
  --restart)
    [ -f $S/kmip.env ] ||
      { echo "quick-start.sh: no $S/kmip.env; run scripts/quick-start.sh first" >&2; exit 2; }
    [ -n "${IMAGE:-}" ] || IMAGE=$(cat $S/image 2>/dev/null) || IMAGE=localhost/keytend-kmip-server:dev
    printf '%s\n' "$IMAGE" > $S/image
    if owned; then "$DOCKER" rm -f $NAME >/dev/null; fi
    start
    exit 0 ;;
  --clean)
    [ ! -L .cache ] ||
      { echo "quick-start.sh: .cache is a symbolic link; remove it by hand" >&2; exit 2; }
    if owned; then
      "$DOCKER" rm -f $NAME >/dev/null
      echo "removed container $NAME"
    fi
    rm -rf .cache/container .cache/dev-pki .cache/dev-data
    echo "removed .cache/container, .cache/dev-pki and .cache/dev-data"
    exit 0 ;;
  *) echo "usage: scripts/quick-start.sh [--restart | --clean]" >&2; exit 2 ;;
esac

[ ! -e "$S" ] ||
  { echo "quick-start.sh: $S exists; run scripts/quick-start.sh --clean first" >&2; exit 2; }
IMAGE=${IMAGE:-localhost/keytend-kmip-server:dev}

scripts/dev-pki.sh .cache/dev-pki
install -d -m 0700 $S $S/tls $S/policy $S/master $S/data
install -m 0400 .cache/dev-pki/server.pem .cache/dev-pki/server.key .cache/dev-pki/ca.pem $S/tls/
install -m 0400 .cache/dev-pki/policy.json $S/policy/
printf '%s\n' "$IMAGE" > $S/image
"$DOCKER" run --rm $userns --user "$(id -u):$(id -g)" -v "$PWD/$S/master:/master:rw$z" \
  "$IMAGE" generate-master-key --output /master/master.key
cat > $S/kmip.env <<'END'
KMIP_CERT=/tls/server.pem
KMIP_KEY=/tls/server.key
KMIP_CA=/tls/ca.pem
KMIP_POLICY=/policy/policy.json
KMIP_MASTER_KEY=/master/master.key
KMIP_HTTPS_LISTEN=0.0.0.0:5697
KMIP_TEXT_ENCODING=readable
END
start
