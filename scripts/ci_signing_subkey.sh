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

# Add the CI signing subkey to the Keytend release key and hand it to the
# product repository's release workflow (docs/release-signing.md#openpgp-signature).
#
#   scripts/ci_signing_subkey.sh
#
# For the key holder only: it needs the release key's primary secret in the
# default gpg keyring, and gpg asks for its passphrase. It
#
# 1. adds an Ed25519 signing subkey, valid for two years;
# 2. exports that subkey's secret alone (the primary as a stub), without a
#    passphrase, into a temporary directory, and stores it as the secret
#    KEYTEND_SIGNING_KEY of keytend/keytend-kmip-server, with its
#    fingerprint as the variable KEYTEND_SIGNING_SUBKEY;
# 3. writes the updated public key to signing/keytend-release-key.asc.
#
# The exported secret never reaches the disk outside the temporary directory,
# which is removed on exit. Commit the public key, publish it to the
# keyservers (printed at the end) and record the subkey in
# docs/release-signing.md#openpgp-signature.
set -euo pipefail

PRIMARY=3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F
REPOSITORY=keytend/keytend-kmip-server
[ -f signing/keytend-release-key.asc ] || { echo "run it from the root of the checkout" >&2; exit 2; }

# Field 15 of the sec line is "#" when only a stub of the primary is present.
gpg --batch --with-colons --list-secret-keys "$PRIMARY" 2>/dev/null | awk -F: '$1 == "sec" && $15 !~ /#/ {ok = 1} END {exit !ok}' ||
  { echo "the release key's primary secret is not in this keyring" >&2; exit 1; }

subkeys() { gpg --batch --with-colons --list-keys "$PRIMARY" | awk -F: '$1 == "sub" {s = 1; next} s && $1 == "fpr" {print $10; s = 0}'; }
before=$(subkeys)
gpg --quick-add-key "$PRIMARY" ed25519 sign 2y
SUBKEY=$(comm -13 <(printf '%s\n' "$before" | sort) <(subkeys | sort))
[ "$(printf '%s\n' "$SUBKEY" | grep -c .)" = 1 ] || { echo "could not find the new subkey" >&2; exit 1; }
echo "new CI signing subkey: $SUBKEY"

WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
gpg --armor --export-options export-reset-subkey-passwd --export-secret-subkeys "$SUBKEY!" > "$WORK/subkey.asc"
gh secret set KEYTEND_SIGNING_KEY -R "$REPOSITORY" < "$WORK/subkey.asc"
gh variable set KEYTEND_SIGNING_SUBKEY -R "$REPOSITORY" --body "$SUBKEY"

gpg --armor --export "$PRIMARY" > signing/keytend-release-key.asc
gpg --show-keys --with-subkey-fingerprints signing/keytend-release-key.asc

cat <<EOF

Done. Next:
  git add signing/keytend-release-key.asc   # and record $SUBKEY in docs/release-signing.md
  gpg --export $PRIMARY | curl -fsS -T - https://keys.openpgp.org
  gpg --keyserver hkps://keyserver.ubuntu.com --send-keys $PRIMARY
EOF
