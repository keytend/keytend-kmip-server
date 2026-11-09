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

# A physical restore intentionally stops mongod and starts temporary mongods.
# Keep its owned container/agent alive; never automatically restart the database.
set -eu
db_pid=''
stop_node() {
    trap '' TERM INT
    if [ -n "$db_pid" ] && kill -0 "$db_pid" 2>/dev/null; then
        kill -TERM "$db_pid"
        wait "$db_pid" || true
    fi
    exit 0
}
trap stop_node TERM INT
mongod "$@" &
db_pid=$!
wait "$db_pid" || true
db_pid=''
while :; do
    sleep 1 &
    wait "$!" || true
done
