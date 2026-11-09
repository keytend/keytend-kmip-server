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

FROM docker.io/percona/percona-backup-mongodb@sha256:4b2ad0398d7099a009bf49388f57c3e4bd244fcd6d76e36b7355d421dd3a018e AS pbm
FROM docker.io/percona/percona-server-mongodb@sha256:e1004538c31619ec471aa39423ef9ffa39a598750661c2d6c66d785de852d538
COPY --from=pbm /usr/bin/pbm /usr/bin/pbm-agent /usr/bin/
COPY --from=pbm /licenses /usr/share/licenses/pbm-upstream/
COPY node.sh /usr/local/bin/pbm-qualification-node
COPY command.sh /usr/local/bin/pbm-qualification-command
COPY LICENSE NOTICE /usr/share/licenses/keytend-kmip-server-qualification/
ENTRYPOINT ["/usr/local/bin/pbm-qualification-node"]
