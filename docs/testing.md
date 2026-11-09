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

# Testing

Part of [contributing](README.md#contributing).

How to build and test the server from source. The results of each release
are in its [test reports](#test-reports), not in these pages.

## Test reports

Each release publishes the reports of the run that produced it, as
`reports/keytend-kmip-server-<version>-test-reports.tar.gz` in the release set.
`SHA256SUMS` lists it, so the release signatures cover it, and the GitHub
release also offers it on its own. It holds:

- `manifest.json`: every step of the run, with its command, exit code and log;
- `logs/`: those logs;
- the OASIS trace replays, the case inventory and the requirement matrix;
- the TLS probes of the image, and the arm64 image tests;
- `java/`: the keytend-kmip Java client suite;
- `outputs/`: other step reports, such as the Helm chart and image hardening.

Paths, host names and the user name are replaced by placeholders, which
`README.txt` in the archive lists. Test keys, kubeconfigs and database files
are not included. After [verifying a release](release-signing.md), read the
reports with `tar -xzf reports/keytend-kmip-server-<version>-test-reports.tar.gz`
in its `release/` directory.

## Checks before a change

The native build needs Linux with OpenSSL 3.5 or later, Rust 1.92 or later and the
packages listed under [run from source](manual-install.md#run-from-source).
The test scripts need Python 3.11 or later with the `cryptography` and PyYAML
modules (on Debian 13, `sudo apt install python3-cryptography python3-yaml`).

```sh
python3 scripts/check_license.py
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
cargo build --locked
```

## Test certificates

`scripts/dev-pki.sh DIR` writes the disposable fixtures the quick start and
the suites use, valid for 7 days:

- a test CA (`ca.pem`, `ca.key`) and a server certificate for `localhost`,
  `127.0.0.1` and `keytend-kmip-server`;
- client certificates `client`, `other` and `unlisted`;
- `policy.json`: `client` (principal `database`) may call every operation
  (1–66); `other` (principal `other-tenant`) only Locate, Get, Get
  Attributes, Get Attribute List, Query and Discover Versions on its own
  objects; `unlisted` is trusted by the CA but not listed;
- `users.json`: a user `administrator` with password `password` for
  `client`, which the KMIP 3.0 profile traces authenticate as.

Never use them outside a test.

A policy that grants every operation includes Set Defaults (54) and Set
Constraints (55). Their settings persist in the database, and Set Defaults
and a KMIP 2.1 Set Constraints apply to every principal. A suite that calls them on a shared server must reset them
afterwards: Set Defaults without Defaults Information, and Set Constraints
with an empty Constraints structure.

## Process and client suites

These start the built server (`cargo build --locked`) or, with `--image`, the
packaged image. Run them from the repository root.

```sh
# Server process only, no network: TLS, restarts, tenancy, hostile frames,
# streaming and split keys
python3 scripts/test_runtime.py
python3 scripts/test_re_provision.py          # Re-Provision, restarts, lockout recovery
python3 scripts/test_streaming.py
python3 scripts/test_split_arithmetic.py
python3 scripts/test_split_objects.py
python3 scripts/test_oasis_harness.py        # the trace comparator itself

# Independent clients; network access to fetch the pinned clients, plus Go,
# a C compiler and Python 3
python3 scripts/test_interop.py               # OVH and Thales kmip-go, PyKMIP, libkmip, NLnet
python3 scripts/test_https.py --go            # HTTPS transports, with OVH kmip-go
python3 scripts/test_ibm_client.py --build-client   # Podman or Docker; MIT-licensed client sources

# Trial clients, not counted as tested: each takes a native server copy under
# artifacts/ and a new run name, and exits 1 unless the run is clean, also
# for client defects it reproduces
mkdir -p artifacts && cp target/debug/keytend-kmip-server artifacts/keytend-kmip-server-trial
python3 scripts/test_phsym_client.py --binary artifacts/keytend-kmip-server-trial --run-id trial-1
python3 scripts/test_cosmian_client.py --binary artifacts/keytend-kmip-server-trial --run-id trial-1

# The packaged image (after "Building the image" below); Podman or Docker
python3 scripts/test_interop.py --image localhost/keytend-kmip-server:dev
python3 scripts/test_ibm_client.py --image localhost/keytend-kmip-server:dev
python3 scripts/test_streaming.py --image localhost/keytend-kmip-server:dev
python3 scripts/test_stream_expiry.py --image localhost/keytend-kmip-server:dev   # waits five minutes
python3 scripts/test_database.py --engine podman   # Percona containers; large downloads

# Reports generated from the server
python3 scripts/support_matrix.py --check
python3 scripts/coverage.py
python3 scripts/test_catalog_contract.py

# Alert rules; promtool from a Prometheus release
(cd deploy/prometheus && promtool test rules keytend-kmip-server-rules.test.yaml)
```

`scripts/test_interop.py` runs the pinned clients in `interop/` (OVH kmip-go,
including its v0.9.2 release, Thales kmip-go, PyKMIP, libkmip and NLnet Labs
kmip-protocol) and fails if any client fails or is unavailable;
`scripts/test_ibm_client.py` runs IBM libkmipclient. Together they cover the six
independent libraries among the [tested clients](clients.md#tested-clients).

## Support matrix

The tables of the [support matrix](support-matrix.md) are generated:
`scripts/support_matrix.py` starts the current build with
`--experimental-v3`, sends Query Operations and Query Objects in every
edition, and lists the attributes of newly created keys; the rows come from
the pinned specification inventories. Regenerate them after changing
handlers:

```sh
python3 scripts/support_matrix.py          # builds, then rewrites the tables
python3 scripts/support_matrix.py --check  # fails if they are out of date
```

## OASIS trace replay

```sh
python3 scripts/oasis_conformance.py
```

`--report-only` records every outcome without a failing exit code; it never
turns a failure into a pass.

It replays the cases of the Profiles XML test traces, 1.3 to 3.0, recorded in
the [case inventory](specs/oasis-case-inventory.json) (the other
[specification data](specs/README.md) files are listed there). Each case falls
in one category:

- passes the strict replay;
- passes with the variations Profiles section 4.1 permits;
- passes with corrected fixtures;
- a documented deviation;
- passes only with 3DES or Interop test mode on;
- not applicable, excluded, delegated or unverifiable.

The counts per category are in each release's [test reports](#test-reports).

## Building the image

```sh
docker build -t localhost/keytend-kmip-server:dev .
# or: podman build --format docker -t localhost/keytend-kmip-server:dev .
```

The `:dev` tag marks a local build; a build of `main` reports the next
release's version with a `-dev` suffix (`--version`, `kmip_build_info`). The
test scripts expect this tag by default (most take `--image` for another). To build on an arm64 host, pass the arm64
base images as in the [quick start](quick-start.md#run-the-container).

`python3 scripts/package.py --arch arm64 --build-host <arm64 host>` builds the
linux/arm64 image natively on another Podman host over SSH from the same
pinned UBI release.

## Reviewing image scanner findings

`scripts/scan_image.py` scans a packaged archive with the pinned Trivy and
[`image/trivyignore.yaml`](../image/trivyignore.yaml), and fails on any
finding without an entry or with a fixed version
([reviewed findings](container-image.md#reviewed-findings)).
To add an entry, read the finding in the scan summary and the vendor record
(Red Hat's `https://access.redhat.com/security/cve/<id>`), check that RHEL 9
has no fix, and decide from the image and the server source whether the image
needs a change. If it does not, add the identifier with a one-line statement:

```yaml
  - id: CVE-YYYY-NNNNN
    statement: "<package> <component>. <why the image needs no change>."
```

Every entry needs exactly one `id` line and one double-quoted `statement` line;
the scan refuses the file otherwise.

## Kubernetes on kind

Create a disposable kind cluster, load the image archive and run the suite.
With Podman's rootless provider the host needs a delegated systemd scope:

```sh
systemd-run --user --scope -p Delegate=yes \
  env KIND_EXPERIMENTAL_PROVIDER=podman kind create cluster \
  --name keytend-kmip-server-e2e --kubeconfig .cache/kind.kubeconfig

podman save --format docker-archive -o .cache/kmip-new.tar localhost/keytend-kmip-server:dev
KIND_EXPERIMENTAL_PROVIDER=podman kind load image-archive \
  .cache/kmip-new.tar --name keytend-kmip-server-e2e

scripts/dev-pki.sh .cache/kube-pki
target/debug/keytend-kmip-server generate-master-key --output .cache/kube-pki/master.key
python3 scripts/test_kubernetes.py --kubeconfig .cache/kind.kubeconfig \
  --image localhost/keytend-kmip-server:dev \
  --kind-node keytend-kmip-server-e2e-control-plane --engine podman
```

The suite provisions only the `keytend-kmip-server` namespace. It checks
readiness, UID 10001, storage binding, mTLS, key survival after pod replacement
and audit validity, and records the running image's ID (and the archive digest
and source commit when the image was packaged with `scripts/package.py`).
`scripts/test_kubernetes_storage_rotation.py` then exercises a master-key
rotation Job and cutover. kind's default CNI does not enforce NetworkPolicy.

### The Helm chart

`scripts/test_helm_chart.py` runs the chart end to end in its own namespace
(`keytend-helm`, deleted at the end) on the same kind cluster, with the pinned
Helm ([`scripts/helm_tool.py`](../scripts/helm_tool.py) downloads it into
`.cache/bin` and checks its SHA-256) and the native executable for the
operator's local steps:

```sh
python3 scripts/helm_tool.py fetch
cargo build
python3 scripts/test_helm_chart.py --kubeconfig .cache/kind.kubeconfig \
  --image localhost/keytend-kmip-server:dev --pki .cache/kube-pki
```

It lints and renders the chart (every optional resource, with a server-side
dry run), installs it under the `restricted` Pod Security level, runs
`helm test` (which must fail for a refused certificate), runs the backup
CronJob and checks `latest.json` and `kmip_last_backup_timestamp_seconds`,
makes a pre-upgrade backup fail the release, runs upgrade and rollback hooks,
restores a backup (and a copy brought in with `kubectl cp`), enables an audit
checkpoint, rotates the master key with checkpoint publication, reverts,
uses maintenance mode and uninstalls. It writes `artifacts/helm-chart.json`.
The kind node pulls the pinned busybox and curl images from Docker Hub.
`scripts/test_helm_tool.py` holds the unit tests of the chart's template
logic (they skip without the pinned Helm).
