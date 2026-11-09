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

# Download a signed release, verify it and load its image
# (docs/release-signing.md#by-hand does the same by hand).
#
#   scripts/verify_release.sh VERSION [amd64|arm64]
#   scripts/verify_release.sh 0.10.0-rc.1           # for example
#
# Run it from the root of a checkout: it trusts only the checkout's
# signing/cosign.pub and cosign pin. In a new directory outside the checkout
# it downloads SHA256SUMS, SHA256SUMS.sigstore.json, the signed-release
# archive and SHA256SUMS.asc. It unpacks only regular files and directories
# under release/, checks the cosign signature of SHA256SUMS and its OpenPGP
# signature by the Keytend release key (signing/pgp_verify.sh), then the digest of every file
# SHA256SUMS lists, and only then loads the image for the architecture
# (default: this host's) and tags it localhost/keytend-kmip-server:VERSION.
# It then keeps the directory and prints its path, for the registry copy in
# docs/release-signing.md; after a failure it removes it.
#
# Needs bash, curl, Python 3.12 or later, Docker or Podman and gpg (GnuPG 2.2
# or later). On Linux it fetches the pinned cosign
# (scripts/cosign_tool.py, SHA-256 checked); on other systems it uses the
# cosign 3 on the PATH.
#
#   DOCKER        container CLI (default docker, or podman when there is no docker)
#   RELEASE_BASE  where to download from (default the GitHub release of
#                 VERSION); any URL curl reads, such as file:///path/to/dir
set -euo pipefail

die() { echo "verify_release.sh: $*" >&2; exit 1; }

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: scripts/verify_release.sh VERSION [amd64|arm64], for example 0.10.0-rc.1" >&2; exit 2; }
VERSION=$1
case $VERSION in *[!0-9A-Za-z.+-]*|'') die "bad version: $VERSION" ;; esac
ARCH=${2:-$(uname -m)}
case $ARCH in
  amd64|x86_64) ARCH=amd64; ARCHIVE=linux-amd64/keytend-kmip-server-$VERSION.docker.tar ;;
  arm64|aarch64) ARCH=arm64; ARCHIVE=linux-arm64/keytend-kmip-server-$VERSION-linux-arm64.docker.tar ;;
  *) die "unsupported architecture: $ARCH (amd64 or arm64)" ;;
esac

[ -f signing/cosign.pub ] && [ -f signing/pgp_verify.sh ] && [ -f scripts/cosign_tool.py ] ||
  die "run it from the root of a checkout"
CHECKOUT=$PWD
if [ -z "${DOCKER:-}" ]; then
  if command -v docker >/dev/null 2>&1; then DOCKER=docker; else DOCKER=podman; fi
fi
if command -v sha256sum >/dev/null 2>&1; then SHA256SUM=(sha256sum); else SHA256SUM=(shasum -a 256); fi
case $(uname -s) in
  Linux) COSIGN=$(python3 scripts/cosign_tool.py fetch | cut -d' ' -f1) ;;   # pinned cosign, SHA-256 checked
  *) COSIGN=$(command -v cosign) || die "install cosign 3" ;;
esac

# 1. Download into a new directory outside the checkout.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT   # removed on failure; kept once the image is loaded
case $WORK/ in "$CHECKOUT"/*) die "$WORK is inside the checkout; set TMPDIR elsewhere" ;; esac
BASE=${RELEASE_BASE:-https://github.com/keytend/keytend-kmip-server/releases/download/v$VERSION}
command -v gpg >/dev/null 2>&1 || die "install gpg (GnuPG 2.2 or later) to check SHA256SUMS.asc"
for f in SHA256SUMS SHA256SUMS.sigstore.json SHA256SUMS.asc "keytend-kmip-server-$VERSION-signed-release.tar"; do
  curl -fsSL -o "$WORK/$f" "$BASE/$f" || die "cannot download $BASE/$f"
done

# 2. Unpack, accepting only regular files and directories under release/.
python3 -I - "$WORK" "$VERSION" <<'PY'
import sys, tarfile
work, version = sys.argv[1:]
with tarfile.open(f"{work}/keytend-kmip-server-{version}-signed-release.tar") as tar:
    for m in tar.getmembers():
        parts = m.name.split("/")
        if not (m.isfile() or m.isdir()) or parts[0] != "release" or ".." in parts:
            sys.exit(f"refusing archive member {m.name!r}")
    tar.extractall(work, filter="data")
PY
cp "$WORK"/SHA256SUMS* "$WORK/release/"

# 3. The signatures of SHA256SUMS, then every digest, then load.
"$COSIGN" verify-blob --key "$CHECKOUT/signing/cosign.pub" --insecure-ignore-tlog=true \
  --bundle "$WORK/release/SHA256SUMS.sigstore.json" "$WORK/release/SHA256SUMS" ||
  die "the signature of SHA256SUMS does not verify; nothing loaded"
# shellcheck source=signing/pgp_verify.sh
(set +o pipefail; . "$CHECKOUT/signing/pgp_verify.sh" &&
  pgp_verify "$WORK/release/SHA256SUMS.asc" "$WORK/release/SHA256SUMS") ||
  die "the OpenPGP signature of SHA256SUMS does not verify; nothing loaded"
(cd "$WORK/release" && "${SHA256SUM[@]}" --quiet -c SHA256SUMS) ||
  die "a digest does not match SHA256SUMS; nothing loaded"
[ -f "$WORK/release/$ARCHIVE" ] || die "the release has no $ARCH image"
"$DOCKER" load -i "$WORK/release/$ARCHIVE"

# 4. Tag the image with its version: arm64 loads as …:VERSION-arm64.
LOADED=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["image_tag"])' \
  "$WORK/release/linux-$ARCH/image.json")
TAG=localhost/keytend-kmip-server:$VERSION
[ "$LOADED" = "$TAG" ] || "$DOCKER" tag "$LOADED" "$TAG"
trap - EXIT
echo "verified and loaded $TAG"
echo "release files: $WORK/release"
echo "next: IMAGE=$TAG scripts/quick-start.sh"
