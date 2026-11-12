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

# Pinned upstream images (per-architecture manifests of registry.access.redhat.com UBI 9.9).
# Refreshed to the latest before each release (scripts/check_image_updates.py, docs/release-builds.md).
# UBI_BUILDER/UBI_MICRO are the linux/amd64 manifests (the default build). scripts/package.py --arch arm64
# passes the *_ARM64 linux/arm64 manifests of the same releases (ubi 9.9-1793830043, ubi-micro
# 9.9-1793867126) as UBI_BUILDER/UBI_MICRO. All four were taken from these multi-architecture indexes:
# index UBI_BUILDER: registry.access.redhat.com/ubi9/ubi@sha256:8b212f75a0e5a156ac28b1c5c030d2e8a07715254e19d522286118279399af81
# index UBI_MICRO: registry.access.redhat.com/ubi9/ubi-micro@sha256:b59ac4f291d86027c2681f7a7b1cbf7448972fc55a6cb8e25cab5aa5eef5ce5f
ARG UBI_BUILDER=registry.access.redhat.com/ubi9/ubi@sha256:961b1473e79d0bfe6dcd11c0c2e7fbf824716319e31f9acda2789b191989c3d5
ARG UBI_MICRO=registry.access.redhat.com/ubi9/ubi-micro@sha256:c55b3d2c48728e4a4ebc3f63a716e5ba135a5f44097667eaea8ccd3f8404fa66
ARG UBI_BUILDER_ARM64=registry.access.redhat.com/ubi9/ubi@sha256:b921e23e046a3c6d77e7d11c66cb026b1a432e4ef10a34b18d888a4e81409574
ARG UBI_MICRO_ARM64=registry.access.redhat.com/ubi9/ubi-micro@sha256:7db0e5dd87ab34c048a07e389e523dde4ad42903563e813bb887d6e7500cd939
# Red Hat's signed rust-toolset (>= rust-version 1.97 in Cargo.toml) and OpenSSL headers.
ARG BUILD_PACKAGES="rust-toolset-1.97.1-4.el9_9 openssl-devel-3.5.9-1.el9_9"
# Exact RPMs (name-version-release) shipped in the runtime root. The kept ubi-micro packages
# plus OpenSSL 3.5 libraries, the separately packaged RHEL 9 OpenSSL FIPS provider 3.0.7
# (fips.so), the system crypto policy OpenSSL reads, and zlib, which libcrypto links.
# Everything else ubi-micro or dnf brings (bash, coreutils-single, glibc-common, tzdata,
# ca-certificates, p11-kit, ...) is erased with its files and RPM database record, so
# scanners and the SBOM see exactly what ships. A retired version fails the build.
ARG RUNTIME_PACKAGES="basesystem-11-13.el9 filesystem-3.16-5.el9 setup-2.13.7-10.el9 redhat-release-9.9-1.0.el9 glibc-2.34-290.el9_9 libgcc-11.5.0-17.el9_9 zlib-1.2.11-40.el9 crypto-policies-20260714-1.git65b74f7.el9 openssl-libs-3.5.9-1.el9_9 openssl-fips-provider-3.0.7-11.el9_8 openssl-fips-provider-so-3.0.7-11.el9_8"

FROM ${UBI_MICRO} AS micro

FROM ${UBI_BUILDER} AS build
ARG BUILD_PACKAGES
RUN dnf install -y --nodocs --setopt=install_weak_deps=0 $BUILD_PACKAGES && dnf clean all && rm -rf /var/cache/dnf
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY crates ./crates
# The registry and target directories are build caches kept by the image builder between
# builds, so a source change recompiles only this workspace's crates. The pinned toolchain and
# Cargo.lock still decide every input; the caches are disposable. The build context arrives
# with zero modification times, which Cargo would read as older than the cached outputs, so
# the workspace sources are touched first: this workspace always recompiles, dependencies stay
# cached.
RUN --mount=type=cache,id=keytend-cargo-registry,target=/root/.cargo/registry \
    --mount=type=cache,id=keytend-cargo-target,target=/build/target \
    find Cargo.toml src crates -type f -exec touch {} + && \
    cargo build --locked --release && cp target/release/keytend-kmip-server /build/keytend-kmip-server

# Assemble the runtime root from ubi-micro's root and signed UBI 9 RPMs. dnf verifies each
# package against the Red Hat release key; rpm erases unneeded packages without running
# their scriptlets (there is no shell left to run them). ubi-micro's root is copied in the same
# step rather than by COPY: on an overlay store (fuse-overlayfs) a file rpm replaces on upgrade
# and then erases can expose the lower layer's original again.
FROM ${UBI_BUILDER} AS runtime-root
ARG RUNTIME_PACKAGES
RUN --mount=type=bind,from=micro,source=/,target=/micro \
    set -eu; root=/rootfs; mkdir $root; cp -a /micro/. $root/; \
    dnf install -y --installroot=$root --config=/etc/dnf/dnf.conf --setopt=reposdir=/etc/yum.repos.d --releasever=9 \
      --setopt=gpgcheck=1 --setopt=install_weak_deps=0 --setopt=tsflags=nodocs $RUNTIME_PACKAGES; \
    keep=$(for spec in $RUNTIME_PACKAGES; do rpm --root $root -q --qf '%{NAME}\n' "$spec"; done); \
    remove=$(rpm --root $root -qa --qf '%{NAME}\n' | grep -vx gpg-pubkey | grep -vxF "$keep" | sort); \
    echo "erasing: $remove"; rpm --root $root -e --nodeps --noscripts --notriggers $remove; \
    test "$(rpm --root $root -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' | grep -v '^gpg-pubkey-' | sort)" = "$(printf '%s\n' $RUNTIME_PACKAGES | sort)"; \
    rpm --root $root -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH} %{RSAHEADER:pgpsig}\n' | sort; \
    # Remove unowned state left by dnf, subscription-manager, erased scriptlets and the base build
    # (repo files without a package manager, the placeholder /dev/null), then unowned empty directories.
    rm -rf $root/var/cache/dnf $root/var/lib/dnf $root/var/log/dnf.log $root/var/log/dnf.librepo.log $root/var/log/dnf.rpm.log $root/var/log/hawkey.log \
      $root/var/lib/rhsm $root/etc/yum.repos.d/ubi.repo $root/etc/yum.repos.d/redhat.repo $root/etc/alternatives $root/var/lib/alternatives $root/dev/null; \
    for pass in 1 2 3; do find $root -depth -type d -empty | while IFS= read -r dir; do rpm --root $root -qf "${dir#$root}" >/dev/null 2>&1 || rmdir "$dir"; done; done; \
    test ! -s $root/var/lib/rpm/rpmdb.sqlite-wal; rm -f $root/var/lib/rpm/rpmdb.sqlite-shm $root/var/lib/rpm/rpmdb.sqlite-wal $root/var/lib/rpm/.rpm.lock; \
    printf 'root:x:0:0:root:/nonexistent:/sbin/nologin\nkmip:x:10001:10001::/nonexistent:/sbin/nologin\n' > $root/etc/passwd; \
    printf 'root:x:0:\nkmip:x:10001:\n' > $root/etc/group; \
    install -d -o 10001 -g 10001 -m 0700 $root/data; install -d -m 0755 $root/usr/local/bin

FROM scratch
ARG UBI_MICRO
LABEL org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Jeremiah Jordan" \
      org.opencontainers.image.title="keytend-kmip-server" \
      org.opencontainers.image.base.name="${UBI_MICRO}" \
      dev.keytend.kmip-server.runtime-root.package-source="${UBI_MICRO}" \
      com.redhat.license_terms="https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI"
COPY --from=runtime-root /rootfs/ /
COPY --from=build /build/keytend-kmip-server /usr/local/bin/keytend-kmip-server
COPY LICENSE NOTICE /usr/share/licenses/keytend-kmip-server/
# The server's own OpenSSL configuration instead of the RHEL system crypto policy, so default
# mode matches the native build; FIPS mode loads the provider itself (see image/openssl.cnf).
COPY image/openssl.cnf /etc/keytend-kmip-server/openssl.cnf
ENV OPENSSL_CONF=/etc/keytend-kmip-server/openssl.cnf
USER 10001:10001
EXPOSE 5696 5697 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/keytend-kmip-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/keytend-kmip-server"]
CMD ["serve"]
