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

# Verify an OpenPGP signature against the Keytend release key
# (docs/release-signing.md#openpgp-signature). Source this file from bash or
# zsh, from any directory, then call:
#
#   pgp_verify SIGNATURE FILE
#
# It succeeds only for a good signature whose primary key is RELEASE_KEY,
# checked in a temporary keyring that holds only keytend-release-key.asc from
# this directory. Plain `gpg --verify` is not enough: it uses your keyring and
# exits 0 for a good signature by an expired or revoked key.
#
# Needs gpg (GnuPG 2.2 or later).

RELEASE_KEY=3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F
PGP_VERIFY_DIR=$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")" && pwd)

pgp_verify() {
  local home out rc
  [ $# -eq 2 ] || { echo 'usage: pgp_verify SIGNATURE FILE' >&2; return 2; }
  home=$(mktemp -d) || return 1
  out=$(gpg --homedir "$home" --batch --quiet --import "$PGP_VERIFY_DIR/keytend-release-key.asc" 2>/dev/null &&
    gpg --homedir "$home" --batch --status-fd 1 --verify "$1" "$2" 2>/dev/null)
  rc=$?
  gpgconf --homedir "$home" --kill all 2>/dev/null
  rm -rf -- "$home"
  if [ "$rc" -eq 0 ] &&
    ! printf '%s\n' "$out" | grep -Eq '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY|FAILURE)( |$)' &&
    printf '%s\n' "$out" | grep -q '^\[GNUPG:\] GOODSIG ' &&
    [ "$(printf '%s\n' "$out" | awk '$2 == "VALIDSIG" {print $NF}')" = "$RELEASE_KEY" ]; then
    echo "pgp_verify: good signature by the Keytend release key: $2" >&2
    return 0
  fi
  echo "pgp_verify: REFUSED: $1 is not a good release-key signature of $2" >&2
  return 1
}
