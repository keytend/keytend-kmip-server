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

# Run one Java example against the quick-start server, from this directory:
#
#   ./run.sh Quickstart | Sign | HttpsQuickstart | Errors
#
# Needs a JDK (17, 21 or 25), KMIP_PKI set to the test certificates, and the
# SDK jar and slf4j-api (the one library it needs at run time) in
# keytend-kmip-0.10.0-rc.1/lib here, unpacked from the verified release zip
# (docs/clients/java.md#install).
set -eu
cd "$(dirname "$0")"
LIB=keytend-kmip-0.10.0-rc.1/lib
JAR=$LIB/keytend-kmip-0.10.0-rc.1.jar
[ -f "$JAR" ] ||
  { echo "run.sh: no $JAR here; see docs/clients/java.md#install" >&2; exit 2; }
SLF4J=$(ls "$LIB"/slf4j-api-*.jar 2>/dev/null | head -n 1)
[ -n "$SLF4J" ] ||
  { echo "run.sh: no $LIB/slf4j-api-*.jar here; see docs/clients/java.md#install" >&2; exit 2; }
exec java -cp "$JAR:$SLF4J" "${1:?usage: ./run.sh Quickstart|Sign|HttpsQuickstart|Errors}.java"
