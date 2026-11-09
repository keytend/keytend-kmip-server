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


# Test consumer only; this image is separate from the delivered server image.
# UBI 9.8 minimal (linux/amd64 manifest of index sha256:4b79c93106c14ad1c234907f83441ff0e4f8d24e78426a36e159098e9f7e6fa5).
# UBI has json-c but not its headers, so json-c 0.19 is built from the upstream release tarball
# (pinned SHA-256; its contents match the json-c-0.19-20260627 tag). integration/ibm-mrs builds on this
# image, so the compiler stays in it.
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:ee7fd2977589d1f776d703e99a03b2ee1c332868bb2b2e2f921c3c1abc55ce9b
ARG JSON_C=https://s3.amazonaws.com/json-c_releases/releases/json-c-0.19.tar.gz
ARG JSON_C_SHA256=37ad0249902e301bd9052bf712e511fcc6acff4ecaad4b5900aad9ce564e26de
RUN microdnf -y --nodocs --setopt=install_weak_deps=0 install gcc make cmake pkgconf-pkg-config openssl-devel libxml2-devel libcurl-devel tar gzip && microdnf clean all
RUN set -eu; curl -sSfL -o /tmp/json-c.tar.gz $JSON_C; echo "$JSON_C_SHA256  /tmp/json-c.tar.gz" | sha256sum -c -; \
    mkdir /tmp/json-c && tar -xzf /tmp/json-c.tar.gz -C /tmp/json-c --strip-components=1; \
    cmake -S /tmp/json-c -B /tmp/json-c/build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_STATIC_LIBS=OFF -DBUILD_TESTING=OFF; \
    cmake --build /tmp/json-c/build -j2; cmake --install /tmp/json-c/build; \
    echo /usr/local/lib64 > /etc/ld.so.conf.d/json-c.conf; ldconfig; rm -rf /tmp/json-c /tmp/json-c.tar.gz
ENV PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig
COPY sdk /src
RUN make -C /src/libkmipclient -j2
COPY client.c /client.c
RUN cc -std=c11 -Wall -Wextra -Werror -I/src/include /client.c -L/src/libkmipclient -Wl,-rpath,/src/libkmipclient -lkmipclient -lcrypto -o /ibm-client
USER 10001:10001
ENTRYPOINT ["/ibm-client"]
