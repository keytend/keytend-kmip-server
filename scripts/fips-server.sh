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

# FIPS-mode server launcher for the replay harnesses (docs/fips.md):
#   python3 scripts/oasis_profile_replay.py --binary scripts/fips-server.sh --output fips.json
# It runs KEYTEND_FIPS_BINARY (default target/debug/keytend-kmip-server) with
# KMIP_FIPS=true. KEYTEND_FIPS_OPENSSL_CONF and KEYTEND_FIPS_OPENSSL_MODULES, when
# set, become OPENSSL_CONF and OPENSSL_MODULES for the server only, so the
# harness's own OpenSSL is unaffected. Without a FIPS provider the server
# refuses to start. The report's runtime_binary_sha256 is this script's.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export KMIP_FIPS=true
if [ -n "${KEYTEND_FIPS_OPENSSL_CONF:-}" ]; then export OPENSSL_CONF="$KEYTEND_FIPS_OPENSSL_CONF"; fi
if [ -n "${KEYTEND_FIPS_OPENSSL_MODULES:-}" ]; then export OPENSSL_MODULES="$KEYTEND_FIPS_OPENSSL_MODULES"; fi
exec "${KEYTEND_FIPS_BINARY:-$root/target/debug/keytend-kmip-server}" "$@"
