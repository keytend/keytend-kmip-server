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

# Build create_get against libkmip at the commit this project tests.
#   make            clone and build libkmip, then the example
#   make clean      remove the example and the libkmip clone
LIBKMIP_COMMIT = 6611941

create_get: create_get.c libkmip/lib/libkmip.a
	$(CC) -I libkmip/include create_get.c libkmip/lib/libkmip.a -lssl -lcrypto -o $@

libkmip/lib/libkmip.a:
	git clone --quiet https://github.com/OpenKMIP/libkmip
	git -C libkmip checkout --quiet $(LIBKMIP_COMMIT)
	$(MAKE) -C libkmip libs

clean:
	rm -rf create_get libkmip

.PHONY: clean
