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
# UBI 9.8 minimal and micro, linux/amd64 manifests (indexes sha256:4b79c93106c14ad1c234907f83441ff0e4f8d24e78426a36e159098e9f7e6fa5
# and sha256:6d9eff186ce3ccf399c1835265e7fd3f83bd112cc3422da2d39fd44e234aab59). UBI's go-toolset is older than
# the go directive, so the official Go release archive is used, pinned by its published SHA-256.
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:ee7fd2977589d1f776d703e99a03b2ee1c332868bb2b2e2f921c3c1abc55ce9b AS build
ARG GO=https://go.dev/dl/go1.27.3.linux-amd64.tar.gz
ARG GO_SHA256=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
RUN microdnf -y --nodocs --setopt=install_weak_deps=0 install tar gzip && microdnf clean all
RUN set -eu; curl -sSfL -o /tmp/go.tar.gz $GO; echo "$GO_SHA256  /tmp/go.tar.gz" | sha256sum -c -; tar -xzf /tmp/go.tar.gz -C /usr/local; rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH GOPATH=/go GOTOOLCHAIN=local
WORKDIR /adapter
COPY go.mod go.sum ./
RUN go mod download && go mod verify && go list -m -json all > /modules.json
COPY main.go ./
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /ovh-mrs .
FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:13df0c7843e3a70b0d149a151eccf8180d2034d041566076cf72d4a2886fa215
COPY --from=build /ovh-mrs /ovh-mrs
COPY --from=build /modules.json /modules.json
COPY --from=build /go/pkg/mod/cache/download/github.com/ovh/kmip-go/@v/v0.9.3-0.20261019141409-525ef10d1246.zip /sdk.zip
COPY main.go go.mod go.sum /adapter/
USER 10001:10001
ENTRYPOINT ["/ovh-mrs"]
