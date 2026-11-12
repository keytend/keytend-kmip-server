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

# Release builds

Part of [contributing](README.md#contributing).

What a release set contains and how it is built. How to
verify a release is in [release verification](release-signing.md).

## The release set

A release set is one directory (`scripts/release_artifacts.py assemble`
collects it):

| Path | Content |
| --- | --- |
| `linux-<arch>/keytend-kmip-server-<version>[-linux-<arch>].docker.tar` | Docker archive of the image for that platform, for `docker load` or `kind load image-archive` |
| `linux-<arch>/image.json` | package manifest: image ID, archive SHA-256, base image pins, builder host, source commit |
| `linux-<arch>/sbom.cdx.json` | CycloneDX 1.6 SBOM: the Cargo build graph without dev dependencies, and every RPM in the image |
| `linux-<arch>/provenance.intoto.json` | in-toto Statement v1 with an SLSA v1 provenance predicate (see [how releases are built](#how-releases-are-built)) |
| `index/keytend-kmip-server-<version>.oci.tar` | OCI image layout archive: the multi-architecture image index and every platform's image |
| `index/oci-image-index.json` | the raw OCI image index blob; its SHA-256 is the index digest |
| `index/image-index.json` | index digest, each platform's manifest digest and the bindings to the Docker archives |
| `reports/keytend-kmip-server-<version>-test-reports.tar.gz` | the reports of the qualification run that produced the release ([test reports](testing.md#test-reports)) |
| `SHA256SUMS` | SHA-256 of every file above |
| `SHA256SUMS.sigstore.json` | cosign signature of `SHA256SUMS` (a Sigstore bundle: keyless for a release built by the release workflow) |
| `SHA256SUMS.asc` | detached ASCII-armored OpenPGP signature of `SHA256SUMS` (see [OpenPGP signature](release-signing.md#openpgp-signature)) |

`sign` writes the two signatures; nothing else in the set is signed
separately. `verify` adds
`verification.json`, the verifier's own report, which is not listed or
signed. The archives are build artifacts and stay out of Git.

A GitHub release publishes `SHA256SUMS`, `SHA256SUMS.sigstore.json` and
`SHA256SUMS.asc` as assets, and the release directory as one tar asset named
`keytend-kmip-server-<version>-signed-release.tar` (release assets cannot hold
directories). It also attaches the test reports archive, the same file as in
`reports/`. Other assets, such as a `.sha256` of the tar or a copy of
`cosign.pub`, are not needed for verification.

## How releases are built

Pushing a tag `v<version>` on `main` starts the release workflow
([`.github/workflows/release.yml`](../.github/workflows/release.yml)). The tag
must match the version in `Cargo.toml`. The workflow:

1. builds the amd64 and arm64 images natively, on GitHub's amd64 and arm64
   runners, with `scripts/package.py`, and scans each with
   `scripts/scan_image.py`;
2. qualifies the commit on GitHub-hosted runners, one job per phase of
   `scripts/release_candidate.py --ci`; every test runs the release image
   ([test reports](testing.md#test-reports));
3. merges the jobs' results into the test reports archive and assembles the
   release set with it under `reports/`;
4. if every job passed, signs `SHA256SUMS` with cosign keyless (the
   workflow's GitHub identity, recorded in the Sigstore transparency log) and
   with the OpenPGP CI signing subkey, so the signatures cover the reports;
5. creates a draft GitHub release with the assets below.

A manual run of the workflow does the same on `main` without signing or
releasing; its test reports and unsigned release set are the run's
artifacts.

Publishing the draft starts
[`.github/workflows/publish-image.yml`](../.github/workflows/publish-image.yml).
It verifies the published release with `scripts/verify_release.sh`, pushes
the same images to `ghcr.io/keytend/keytend-kmip-server` as `<version>` (a
multi-architecture index), `<version>-amd64` and `<version>-arm64` (and
`latest` for a final release), and signs the index with cosign keyless
([images on ghcr.io](release-signing.md#images-on-ghcrio)).

- Each platform is built with one `podman build`, with both UBI base images
  pinned by digest, from a build context tar with sorted names, zero
  modification times and root ownership, so the image does not depend on the
  checkout ([build type](#build-type-podman-dockerfile-v1)).
- The server binary has been reproduced byte for byte by
  separate uncached builds; image IDs are not reproducible (each build writes
  a new RPM database, ldconfig cache and directory times).
- `provenance.intoto.json` is an
  [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
  with an [SLSA v1 provenance](https://slsa.dev/spec/v1.0/provenance)
  predicate, covered by the `SHA256SUMS` signatures. Its subjects are the
  Docker archive and the image configuration digest; it records the source
  commit, the build command, the base images, `Cargo.lock`, every shipped
  RPM, the toolchain, the builder host, and digests of `image.json`, the SBOM
  and the build log.
- The SLSA level is at most Build L1. The provenance is written by
  `scripts/package.py` inside the build job, not by the build platform itself
  (L2), and the signing job holds the OpenPGP subkey in the same workflow (L3).

## Build type `podman-dockerfile-v1`

The `buildType` of each release's provenance. The provenance gives it as the
address of a [section in release verification](release-signing.md#build-type-podman-dockerfile-v1),
which links here.

Each platform's image is built from a normalized build context, with both UBI
base images pinned by digest, and saved as a Docker archive:

```sh
podman build --format docker --platform <platform> \
  --build-arg UBI_BUILDER=<pin> --build-arg UBI_MICRO=<pin> -t <tag> .
podman save --format docker-archive …
```

The OCI index keeps each image's runtime configuration but drops the
Docker-only health check, which OCI has no field for; Kubernetes uses the
probes of the [Helm chart](kubernetes.md) (or of the minimal Kustomize base in
[deploy/kubernetes](../deploy/kubernetes)) instead, and
[deployment](deployment.md#without-compose) covers `docker run`.
