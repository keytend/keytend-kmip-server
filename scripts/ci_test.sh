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

# Clippy and the tests inside the pinned UBI builder image, which has the
# OpenSSL 3.5 the server needs (the release workflow's test job runs it).
#
#   podman run --rm -v "$PWD:/src:Z" -w /src -e RUST_TOOLCHAIN=<version> \
#     -e OPENSSL_CONF=/src/image/openssl.cnf <UBI_BUILDER> bash /src/scripts/ci_test.sh <openssl-devel package>
#
# It installs the compiler and that OpenSSL as root, then runs Clippy and
# cargo test as an ordinary user, as the tests expect (root ignores file modes).
# OPENSSL_CONF is the image's OpenSSL configuration, in place of the system
# crypto policy. The source tree must be readable by others.
set -euo pipefail
dnf install -y -q --nodocs --setopt=install_weak_deps=0 gcc git python3 "$1" >/dev/null
useradd -m ci
runuser -u ci -- env RUST_TOOLCHAIN="$RUST_TOOLCHAIN" OPENSSL_CONF="$OPENSSL_CONF" bash -euo pipefail -c '
  export CARGO_TARGET_DIR=$HOME/target
  curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain "$RUST_TOOLCHAIN" -c clippy
  . "$HOME/.cargo/env"
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked'
