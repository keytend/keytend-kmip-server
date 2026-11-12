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
# UBI 9.9 minimal and micro, linux/amd64 manifests (indexes sha256:ecb40c7bdfa5b0bb71e978c98c7cf56ce38edf1f8fb3561078acbc4b13698c07
# and sha256:b59ac4f291d86027c2681f7a7b1cbf7448972fc55a6cb8e25cab5aa5eef5ce5f). UBI's go-toolset is older than
# the go directive, so the official Go release archive is used, pinned by its published SHA-256.
FROM registry.access.redhat.com/ubi9/ubi-minimal@sha256:f8700bef6b1c99d806c13e43542ce9f2534b137914ade791e4ced7283221147b AS build
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
FROM registry.access.redhat.com/ubi9/ubi-micro@sha256:c55b3d2c48728e4a4ebc3f63a716e5ba135a5f44097667eaea8ccd3f8404fa66
COPY --from=build /ovh-mrs /ovh-mrs
COPY --from=build /modules.json /modules.json
COPY --from=build /go/pkg/mod/cache/download/github.com/ovh/kmip-go/@v/v0.9.3-0.20261019141409-525ef10d1246.zip /sdk.zip
COPY main.go go.mod go.sum /adapter/
USER 10001:10001
ENTRYPOINT ["/ovh-mrs"]
