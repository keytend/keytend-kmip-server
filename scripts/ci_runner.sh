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

# Prepare a GitHub-hosted runner for a job of the release workflow, and run the
# job's part of the qualification (.github/workflows/release.yml).
#
#   scripts/ci_runner.sh python             the scripts' virtual environment (scripts/python_env.py), first on PATH
#   scripts/ci_runner.sh podman             podman, checked to run a container with CPU, memory and PID limits
#                                           (the tests set them); if it cannot, the runner's user session gets
#                                           delegated cgroup controllers, and the check runs again; the
#                                           runner's AppArmor profile for /usr/sbin/mysqld is unloaded
#   scripts/ci_runner.sh rust               Rust on the runner itself (interop clients, cargo-audit), first on PATH
#   scripts/ci_runner.sh inotify            raise the inotify limits (kind, the PBM agents)
#   scripts/ci_runner.sh space              remove SDKs the jobs do not use, for container images
#   scripts/ci_runner.sh qualify JOB ARGS   scripts/release_candidate.py --ci --job JOB ARGS into $RUNNER_TEMP/bundle
#   scripts/ci_runner.sh part JOB           pack that bundle as $RUNNER_TEMP/part/part-JOB.tar.gz
#                                           (scripts/release_reports.py --part); a separate step, so a
#                                           qualification that timed out still leaves its part
#   scripts/ci_runner.sh identity ARCH      the image job's archive SHA-256 and image ID, as step outputs
#   scripts/ci_runner.sh check-images DIR   the archives in DIR (artifacts, or a release set) are the image
#                                           jobs' ones: IMAGE_SHA256_<ARCH> and IMAGE_ID_<ARCH> for amd64 and arm64
set -euo pipefail
cd "$(dirname "$0")/.."
: "${RUNNER_TEMP:?run on a GitHub Actions runner}"

case $1 in
  python)
    python3 scripts/python_env.py --venv "$RUNNER_TEMP/venv" 2>/dev/null || {
      sudo -n apt-get update -q && sudo -n apt-get install -y -q python3-venv
      python3 scripts/python_env.py --venv "$RUNNER_TEMP/venv"
    }
    echo "$RUNNER_TEMP/venv/bin" >> "$GITHUB_PATH"
    ;;
  podman)
    command -v podman >/dev/null || { sudo -n apt-get update -q && sudo -n apt-get install -y -q podman; }
    podman version --format '{{.Client.Version}}'
    arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
    micro=$(python3 -I -c 'import sys; sys.path.insert(0, "scripts")
from image_evidence import base_images; print(base_images(sys.argv[1])["UBI_MICRO"])' "$arch")
    # A registry or network failure is not a cgroup problem: pull first, and stop if that fails.
    podman pull -q "$micro" >/dev/null || { echo "::error::cannot pull $micro"; exit 1; }
    limited() { podman run --rm --pull=never --cpus=1 --memory=64m --pids-limit=64 "$micro" true; }
    if ! limited; then
      echo "::warning::rootless podman cannot set resource limits; delegating cgroup controllers to the user session"
      uid=$(id -u)
      # Restarting the user manager would kill this job if it runs inside it.
      if grep -q "user@$uid.service" /proc/self/cgroup; then
        echo "::error::this job runs in user@$uid.service, which cannot be restarted to delegate cgroup controllers"
        exit 1
      fi
      sudo -n mkdir -p /etc/systemd/system/user@.service.d
      printf '[Service]\nDelegate=cpu cpuset io memory pids\n' | sudo -n tee /etc/systemd/system/user@.service.d/delegate.conf >/dev/null
      sudo -n systemctl daemon-reload
      sudo -n loginctl enable-linger "$(id -un)"
      sudo -n systemctl restart "user@$uid.service"
      export XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus
      printf 'XDG_RUNTIME_DIR=%s\nDBUS_SESSION_BUS_ADDRESS=%s\n' "$XDG_RUNTIME_DIR" "$DBUS_SESSION_BUS_ADDRESS" >> "$GITHUB_ENV"
      podman system migrate
      limited || {
        echo "::error::rootless podman still cannot run a container with CPU, memory and PID limits"
        cat "/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers" || true
        podman info --format '{{.Host.CgroupManager}} {{.Host.CgroupsVersion}}' || true
        exit 1
      }
    fi
    echo "rootless podman runs containers with resource limits"
    # The runner's MySQL has an AppArmor profile that attaches by path to every /usr/sbin/mysqld, also
    # the Percona one in a rootless container, and denies it its plugin, manifest and messages.
    if sudo -n grep -q '^/usr/sbin/mysqld ' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
      sudo -n apparmor_parser -R /etc/apparmor.d/usr.sbin.mysqld
      echo "unloaded the runner's AppArmor profile for /usr/sbin/mysqld"
    fi
    ;;
  rust)
    if ! command -v cargo >/dev/null; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal
      echo "$HOME/.cargo/bin" >> "$GITHUB_PATH"
    fi
    ;;
  space)
    sudo -n rm -rf /usr/local/lib/android /usr/share/dotnet /opt/ghc /usr/local/.ghcup /usr/share/swift
    df -h /
    ;;
  inotify)
    sudo -n sysctl -w fs.inotify.max_user_instances=1024 fs.inotify.max_user_watches=1048576
    ;;
  qualify)
    job=$2; shift 2
    exec python3 scripts/release_candidate.py --ci --job "$job" --bundle "$RUNNER_TEMP/bundle" "$@"
    ;;
  part)
    [ -f "$RUNNER_TEMP/bundle/manifest.json" ] || { echo "::error::no bundle to pack: the qualification did not start"; exit 1; }
    python3 scripts/release_reports.py --part --bundle "$RUNNER_TEMP/bundle" --output "$RUNNER_TEMP/part/part-$2.tar.gz"
    ;;
  identity)
    python3 -I - "$2" >> "$GITHUB_OUTPUT" <<'PY'
import hashlib, json, pathlib, sys
arch = sys.argv[1]
directory = pathlib.Path('artifacts') if arch == 'amd64' else pathlib.Path('artifacts', f'linux-{arch}')
image = json.loads((directory/'image.json').read_text())
with (directory/image['archive']).open('rb') as archive:
    assert hashlib.file_digest(archive, 'sha256').hexdigest() == image['sha256'], 'archive differs from image.json'
print(f"sha256_{arch}={image['sha256']}\nimage_id_{arch}={image['image_id']}")
PY
    ;;
  check-images)
    python3 -I - "$2" <<'PY'
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
problems = []
for arch in ('amd64', 'arm64'):
    expected = os.environ.get(f'IMAGE_SHA256_{arch.upper()}'), os.environ.get(f'IMAGE_ID_{arch.upper()}')
    # A release set has linux-<arch>/; the image jobs' artifacts have the amd64 files at the top.
    directory = root/f'linux-{arch}' if (root/f'linux-{arch}').is_dir() or arch != 'amd64' else root
    image = json.loads((directory/'image.json').read_text())
    with (directory/image['archive']).open('rb') as archive:
        actual = hashlib.file_digest(archive, 'sha256').hexdigest(), image['image_id']
    if not all(expected) or actual != expected or image['sha256'] != expected[0]:
        problems.append(f'{arch}: {directory} holds {actual} (image.json {image["sha256"]}), the image job published {expected}')
if problems:
    sys.exit('the image archives are not the image jobs\' ones:\n'+'\n'.join(problems))
print('image archives match the image jobs: amd64 and arm64')
PY
    ;;
  *)
    echo "unknown step: $1" >&2; exit 2
    ;;
esac
