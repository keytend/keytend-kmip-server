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

# Signing keys

Public material for verifying releases; no private keys are kept here.

| File | Content |
| --- | --- |
| `cosign.pub` | The project's cosign public key; verifies `SHA256SUMS.sigstore.json` of every release |
| `keytend-release-key.asc` | The Keytend OpenPGP release key ([fingerprints](../docs/release-signing.md#openpgp-signature)); verifies `SHA256SUMS.asc` and the Java client |
| `pgp_verify.sh` | Defines `pgp_verify SIGNATURE FILE` (source it from bash or zsh): accepts only a good signature under the release key, in a keyring that holds only `keytend-release-key.asc` |
| `offline-signing-config.json` | The Sigstore signing configuration used to sign without a transparency log |

The release key file holds the primary key and two signing subkeys, one for
this project and one for the keytend-kmip Java client. How to verify a
release: [verifying a release](../docs/release-signing.md#verifying-a-release).
