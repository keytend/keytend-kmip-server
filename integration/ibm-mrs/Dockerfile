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

# Existing unchanged SDK image is an input, never overwritten. The harness verifies
# every SDK source against the released archive and records its library hash.
ARG SDK_BASE
FROM ${SDK_BASE}
USER 0:0
COPY client.c /mrs-client.c
RUN cc -std=c11 -Wall -Wextra -Werror -I/src/include /mrs-client.c -L/src/libkmipclient -Wl,-rpath,/src/libkmipclient -lkmipclient -lcrypto -o /ibm-mrs-client
USER 10001:10001
ENTRYPOINT ["/ibm-mrs-client"]
