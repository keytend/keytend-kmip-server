<!--
Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Container image

Part of [configuration and operations](README.md#configuration-and-operations).

The server image is built from Red Hat Universal Base Image 9.9 (UBI 9 micro)
for linux/amd64 and linux/arm64. FIPS provider
status is in [FIPS mode](fips.md#provider-and-validation-status); signatures,
SBOMs and provenance are in [release verification](release-signing.md).

## What ships

The `Dockerfile` pins the UBI 9.9 builder (`ubi9/ubi`, label 9.9-1793830043)
and runtime (`ubi9/ubi-micro`, label 9.9-1793867126) images by
per-architecture manifest digest. The server is built with Red Hat's signed
`rust-toolset` 1.97 and `openssl-devel` 3.5.9. The runtime root is the
ubi-micro filesystem plus the pinned RPMs below (signatures verified against
the Red Hat release key); every other package is erased, so scanners and the
SBOM see exactly what ships, and the build fails if a pinned version is
retired. Both platforms ship the same RPM versions:

| RPM | Version | Why it ships |
| --- | --- | --- |
| `glibc` | 2.34-290.el9_9 | C runtime |
| `libgcc` | 11.5.0-17.el9_9 | unwinder loaded by the server |
| `openssl-libs` | 1:3.5.9-1.el9_9 | `libssl.so.3`/`libcrypto.so.3`, `/etc/pki/tls/openssl.cnf` |
| `openssl-fips-provider`, `openssl-fips-provider-so` | 3.0.7-11.el9_8 | the separately packaged RHEL 9 FIPS provider, `/usr/lib64/ossl-modules/fips.so` |
| `crypto-policies` | 20260714-1.git65b74f7.el9 | required by `openssl-libs`; the server does not read the system policy |
| `zlib` | 1.2.11-40.el9 | linked by libcrypto |
| `filesystem`, `setup`, `basesystem`, `redhat-release` | 3.16-5.el9, 2.13.7-10.el9, 11-13.el9, 9.9-1.0.el9 | directory layout, `/etc` skeleton, `/etc/os-release` for scanner OS detection |

The image has no shell, coreutils, OpenSSL CLI or package manager. Besides
the RPM-owned files it holds only the server binary, `LICENSE` and `NOTICE`,
the server's OpenSSL configuration and the RPM database. `/etc/passwd` lists
only `root` and `kmip` (10001). The image runs as UID/GID 10001 with an
exec-form entrypoint, the default command `serve`, a Docker health check and a
0700 `/data` directory. It is about 34 MB.

## Licences and notices

Each shipped RPM's `%license` texts stay under `/usr/share/licenses`. Red Hat
ships the UBI End User License Agreement terms by reference: the
`com.redhat.license_terms` label
(`https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI`) and
ubi-micro's `/root/buildinfo/labels.json`, which the image keeps. `NOTICE`
records the base and those terms. Redistribute the image under the UBI EULA.

## OpenSSL configuration

The image sets `OPENSSL_CONF=/etc/keytend-kmip-server/openssl.cnf`
([`image/openssl.cnf`](../image/openssl.cnf)) and never reads RHEL's
`/etc/pki/tls/openssl.cnf`, which applies the system crypto policy. Default
mode therefore behaves like a native build. In the file:

- RHEL's policy refuses SHA-1 signatures at the EVP level; the
  image sets `rh-allow-sha1-signatures = yes`, so the server decides (FIPS
  mode refuses them, see [FIPS mode](fips.md)).
- The image has no `ssl_conf` section, so libssl's built-in
  defaults apply, as natively. The server sets each listener's versions,
  suites, groups and signature algorithms itself.
- There is no providers section, so the default provider loads on first
  use. FIPS mode (`--fips`, `KMIP_FIPS` or a FIPS kernel flag) loads `fips`
  and `base` itself.
- `config_diagnostics = 1` makes a malformed configuration stop OpenSSL
  initialization.

RHEL's OpenSSL offers 13 named elliptic curves (P-224, P-256, P-384, P-521,
secp256k1 and the brainpool r1 and t1 curves). The server supports exactly
these 13 in native and image builds alike, so both give the same answers. By
default KMIP operations may use all 13; `--ec-curves nist` limits them to the
four NIST curves ([supported curves](algorithms.md#elliptic-curves)).

## Reviewed findings

[`image/trivyignore.yaml`](../image/trivyignore.yaml) lists every scanner
finding that was reviewed and left in the image. Each entry says why the
finding needs no image change, including whether and when the server can
reach it. The release scan fails on a finding without an entry, and on a
reviewed finding that now has a fixed version (the remedy is then a package
update).

Both platforms are built natively from the same sources and RPM versions. The
base-image pins are in the `Dockerfile` and the package inventory in each
release's SBOM.
