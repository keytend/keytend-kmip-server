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

# Release verification

Part of [security](README.md#security).

Each release set is described by one manifest, `SHA256SUMS`, which lists the
SHA-256 of the files in the set. It is signed twice: with cosign
(`SHA256SUMS.sigstore.json`) and with an OpenPGP signing subkey of the Keytend
release key (`SHA256SUMS.asc`). A release built by the
[release workflow](release-builds.md#how-releases-are-built) is signed with
cosign keyless, as that workflow; an earlier release, built on a workstation,
with the project's cosign key. A valid signature shows that the holder of a
key, or that workflow, signed those bytes.

- [Verifying a release](#verifying-a-release): [by hand](#by-hand) and
  [other ways to verify](#other-ways-to-verify)
- [Images on ghcr.io](#images-on-ghcrio)
- [Getting the image into a registry](#getting-the-image-into-a-registry)
- [OpenPGP signature](#openpgp-signature): the release key fingerprint
- [What the signatures prove](#what-the-signatures-prove)

The contents of a release set, how it is built and its build type are in
[release builds](release-builds.md).

## Verifying a release

From the root of a checkout of this repository:

```sh
scripts/verify_release.sh 0.10.0-rc.1          # or: … 0.10.0-rc.1 arm64
```

```text
Verified OK
pgp_verify: good signature by the Keytend release key: /tmp/tmp.Xa1b2C3d4E/release/SHA256SUMS
…
verified and loaded localhost/keytend-kmip-server:0.10.0-rc.1
release files: /tmp/tmp.Xa1b2C3d4E/release
next: IMAGE=localhost/keytend-kmip-server:0.10.0-rc.1 scripts/quick-start.sh
```

[`scripts/verify_release.sh`](../scripts/verify_release.sh) trusts only the
checkout's keys and cosign pin, and downloads the release into a new
directory outside the checkout, so nothing in the archive can replace the
keys or tools that check it. It stops at the first failure, removing what it
downloaded, and loads nothing unless every check passes:

1. It unpacks only regular files and directories under `release/`.
2. It checks the cosign signature of `SHA256SUMS` and its OpenPGP signature,
   `SHA256SUMS.asc`, with [`pgp_verify`](#openpgp-signature). A keyless
   cosign signature must be by the release workflow for the tag
   `v<version>` and have a transparency-log entry; a key signature must be by
   [`signing/cosign.pub`](../signing/cosign.pub).
3. It checks the digest of every file that `SHA256SUMS` lists.
4. It loads the image for this host's architecture (or the one named). The
   amd64 image loads as `localhost/keytend-kmip-server:<version>`; the arm64
   one loads as `…:<version>-arm64`, which the script also tags
   `…:<version>`.

It keeps the release files for [the registry copy](#getting-the-image-into-a-registry)
and prints their path. It needs bash, curl, Python 3.12 or later, Docker or
Podman, and gpg (GnuPG 2.2 or later). On Linux it fetches the
pinned cosign (SHA-256 checked); on macOS, install cosign 3 yourself. For a
release signed with the key, cosign warns about the transparency log:
`--insecure-ignore-tlog=true` is required because nothing was uploaded to one
([what the signatures prove](#what-the-signatures-prove)).

To run it with the quick start, see
[use the signed release instead](quick-start.md#use-the-signed-release-instead).

### By hand

The same checks, in one bash or zsh shell from the root of the checkout. On
macOS, use `shasum -a 256 -c` instead of `sha256sum -c`.

1. Download the release:

   ```sh
   VERSION=0.10.0-rc.1   # the release to verify
   CHECKOUT=$PWD
   WORK=$(mktemp -d)
   case $(uname -s) in
     Linux) COSIGN=$(python3 scripts/cosign_tool.py fetch | cut -d' ' -f1) ;;   # pinned cosign 3.1.4, SHA-256 checked
     *) COSIGN=cosign ;;   # macOS: the cosign 3 you installed
   esac
   BASE=https://github.com/keytend/keytend-kmip-server/releases/download/v$VERSION
   for f in SHA256SUMS SHA256SUMS.sigstore.json SHA256SUMS.asc keytend-kmip-server-$VERSION-signed-release.tar; do
     curl -fsSL -o "$WORK/$f" "$BASE/$f"
   done
   ```

   (`gh release download v$VERSION -R keytend/keytend-kmip-server -D "$WORK"`
   also works; it fetches every asset.)

2. Unpack the archive, accepting only regular files and directories under
   `release/`:

   ```sh
   python3 -I - "$WORK" "$VERSION" <<'PY'
   import sys, tarfile
   work, version = sys.argv[1:]
   with tarfile.open(f"{work}/keytend-kmip-server-{version}-signed-release.tar") as tar:
       for m in tar.getmembers():
           parts = m.name.split("/")
           if not (m.isfile() or m.isdir()) or parts[0] != "release" or ".." in parts:
               sys.exit(f"refusing archive member {m.name!r}")
       tar.extractall(work, filter="data")
   PY
   cp "$WORK"/SHA256SUMS* "$WORK/release/"
   ARCH=amd64   # or arm64
   ARCHIVE=$(ls "$WORK"/release/linux-$ARCH/*.docker.tar)
   ```

3. Check the signatures, then the digests, and load the image only if every
   check succeeds. A release built by the release workflow (its bundle holds
   a `certificate`) is checked keyless:

   ```sh
   COSIGN_CHECK=(--certificate-oidc-issuer https://token.actions.githubusercontent.com
     --certificate-identity "https://github.com/keytend/keytend-kmip-server/.github/workflows/release.yml@refs/tags/v$VERSION")
   ```

   A release signed with the key is checked with
   `COSIGN_CHECK=(--key "$CHECKOUT/signing/cosign.pub" --insecure-ignore-tlog=true)`
   instead. Then:

   ```sh
   "$COSIGN" verify-blob "${COSIGN_CHECK[@]}" \
     --bundle "$WORK/release/SHA256SUMS.sigstore.json" "$WORK/release/SHA256SUMS" &&
     (. "$CHECKOUT/signing/pgp_verify.sh" &&
      pgp_verify "$WORK/release/SHA256SUMS.asc" "$WORK/release/SHA256SUMS") &&
     (cd "$WORK/release" && sha256sum --quiet -c SHA256SUMS) &&
     docker load -i "$ARCHIVE"
   ```

4. On arm64, tag the image as
   `localhost/keytend-kmip-server:<version>`, the name these docs use:

   ```sh
   LOADED=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["image_tag"])' \
     "$WORK/release/linux-$ARCH/image.json")
   docker tag "$LOADED" localhost/keytend-kmip-server:$VERSION
   ```

To push the verified image to a registry and deploy it by digest, keep
`$WORK/release` and go on to
[getting the image into a registry](#getting-the-image-into-a-registry).

### Other ways to verify

One command checks both signatures and the platforms in place of step 3
(Linux only: it runs the pinned Linux cosign):

```sh
python3 "$CHECKOUT/scripts/release_artifacts.py" verify --dir "$WORK/release" \
  --require-platforms amd64 arm64 && docker load -i "$ARCHIVE"
```

It checks the cosign signature with `signing/cosign.pub` and `SHA256SUMS.asc`
under the same rule as `pgp_verify`; that `SHA256SUMS` lists exactly the files
present and every digest matches; that every required platform is present and
the image index covers exactly the release's platforms; and that cosign
fetched no trusted root, so verification works offline.

## Images on ghcr.io

Releases are also published as
`ghcr.io/keytend/keytend-kmip-server:<version>`, a multi-architecture index
for amd64 and arm64 (`<version>-amd64` and `<version>-arm64` name each
platform). They are the images of the signed release, not a rebuild: the
image IDs match `linux-<arch>/image.json` in the release set. From
v0.10.0-rc.2 on, the index is signed with cosign keyless by
[`publish-image.yml`](../.github/workflows/publish-image.yml):

```sh
cosign verify ghcr.io/keytend/keytend-kmip-server:0.10.0-rc.2 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github\.com/keytend/keytend-kmip-server/\.github/workflows/publish-image\.yml@'
```

Deploy by digest: `docker buildx imagetools inspect` or
`skopeo inspect --raw` shows the index digest.

## Getting the image into a registry

Deploy by digest from a registry you control. After you
[verify a release](#verifying-a-release), set `VERSION` to it and `RELEASE`
to its release files, the `release files:` path that `verify_release.sh`
printed (`$WORK/release` by hand). Copy its multi-architecture OCI index to
the registry with
[skopeo](https://github.com/containers/skopeo). `--preserve-digests` makes
skopeo fail rather than convert a manifest, so the registry serves the index
digest that the signed `image-index.json` records; the last command checks
that it does:

```sh
VERSION=0.10.0-rc.1
RELEASE=/tmp/tmp.Xa1b2C3d4E/release   # the "release files:" path
REGISTRY=registry.example.com
WANT=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["index_digest"])' \
  "$RELEASE/index/image-index.json")
skopeo copy --all --preserve-digests \
  oci-archive:"$RELEASE/index/keytend-kmip-server-$VERSION.oci.tar" \
  docker://$REGISTRY/keytend-kmip-server:$VERSION
GOT=sha256:$(skopeo inspect --raw docker://$REGISTRY/keytend-kmip-server:$VERSION | sha256sum | cut -d' ' -f1)
if [ "$GOT" = "$WANT" ]; then echo "registry index: $GOT"; else echo "MISMATCH: registry $GOT, release $WANT" >&2; false; fi
```

```text
registry index: sha256:accf35a4d335c238e744f5651e91049caad76ab06f17c91f2b797a60a920d6fb
```

Use that digest in the [chart's values](kubernetes.md#install) (`image.digest`) or as
`$REGISTRY/keytend-kmip-server@sha256:…` with
[Docker](deployment.md#docker-or-podman). Without skopeo, push a
single platform after `docker load` with `docker tag` and `docker push`; its
digest is the one `docker push` prints (with Podman,
`podman push --digestfile`), not the index digest.

## OpenPGP signature

Keytend projects sign their releases with subkeys of one published OpenPGP
release key, one signing subkey per project, so one project's subkey can be
revoked or rotated without affecting the others.

The release key (primary): **this is the fingerprint to check.** It certifies
the project subkeys, is held offline by the key holder and is never used by
release tooling.

```text
3A84 912A FBE7 D2B0 4EBA  2A8A 51E6 5DD4 9C6F 987F
keytend-kmip releases <releases@keytend.dev>, Ed25519, expires 2031-10-31
```

The keytend-kmip-server signing subkey, which signs this project's
`SHA256SUMS.asc`:

```text
CE9B FF24 3C9F 66C2 A212  9E3A B02F 69EF AEB7 DBB5
Ed25519 [S], expires 2028-11-03
```

The keytend-kmip (Java client) signing subkey, which signs the Java client's
releases:

```text
AAE2 AF4D D7F2 427F 52B8  00D4 94E0 26FE 1BF6 C09E
Ed25519 [S], expires 2028-11-03
```

The public key is committed as
[`signing/keytend-release-key.asc`](../signing/keytend-release-key.asc)
(with the other [public signing material](../signing/README.md)) and
published on keys.openpgp.org (verified user ID) and keyserver.ubuntu.com.
Check the fingerprint against a copy that did not come from this repository:
keys.openpgp.org serves a key by email address only after the address's
holder has confirmed it, so this lookup must print the fingerprint above:

```sh
curl -fsS https://keys.openpgp.org/vks/v1/by-email/releases%40keytend.dev |
  gpg --show-keys --with-colons | awk -F: '$1 == "fpr" {print $10; exit}'
gpg --show-keys --with-fingerprint --with-subkey-fingerprints signing/keytend-release-key.asc   # the committed file, with both subkeys
```

A signature is accepted when gpg reports a good signature (`GOODSIG`,
`VALIDSIG`) whose primary key, the last field of `VALIDSIG`, is the release key,
whichever subkey made it. A signature by any other key, by an expired or revoked
key (`EXPKEYSIG`, `REVKEYSIG`), an expired signature or one over altered bytes
is refused. [`signing/pgp_verify.sh`](../signing/pgp_verify.sh) (its
`RELEASE_KEY` is the fingerprint above) and `release_artifacts.py verify` both
apply this rule. gpg's "not certified with
a trusted signature" warning only means you have not certified the key
yourself; comparing the primary fingerprint is the check.

The release fingerprint does not change when a signing subkey is extended,
replaced or revoked; such changes are announced here. If a signature fails
with `EXPKEYSIG` or `REVKEYSIG`, update the checkout (or fetch the key from
keys.openpgp.org) to get the current key and verify again.

## What the signatures prove

A release built by the release workflow is signed keyless: the cosign
certificate names the workflow and the tag it ran for, and the signature is
recorded in the public Rekor transparency log, so anyone can see when it was
made. Its OpenPGP signature is made in the same job by a CI signing subkey
held as a repository secret. It shows that the release workflow of this
repository signed those bytes for that tag. The signed set includes the
reports of the tests the same workflow ran on that commit
([test reports](testing.md#test-reports)); they record what was tested, not
an independent audit.

For a release built on a workstation, signing is offline: there is no Rekor transparency-log entry, no trusted
timestamp and no keyless identity. Nobody can check from a public log when a
signature was made or what else a key signed, and a signature made after a key
compromise cannot be told apart from an earlier one. The cosign key is a
development key kept on the maintainer's workstation; the OpenPGP release key
(primary) is held offline and only certifies the per-project signing subkeys.
The signatures show that the files are the ones the maintainer published.
How the files were built is recorded in the provenance, at SLSA Build L1 at
most ([how releases are built](release-builds.md#how-releases-are-built)).

## Build type `podman-dockerfile-v1`

Release provenance gives this section's address as its `buildType`. The
build type is described in [release builds](release-builds.md#build-type-podman-dockerfile-v1).
