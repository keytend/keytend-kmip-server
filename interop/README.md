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

# Interoperability adapters

Small programs that drive the server through other KMIP clients. The test
scripts start a server with test certificates, run each adapter against it,
and fail if a client fails or is missing. The tested clients and their
versions are in [tested clients](../docs/clients.md#tested-clients); what the
runs exercised is in [project status](../docs/status.md#what-has-been-tested).

| Adapter | Client and version | Run by |
| --- | --- | --- |
| [`pykmip.py`](pykmip.py) | PyKMIP, commit `4815637` | `scripts/test_interop.py` |
| [`libkmip.c`](libkmip.c) | OpenKMIP libkmip, commit `6611941` | `scripts/test_interop.py` |
| [`ovh/`](ovh) | OVH kmip-go, commit `525ef10` | `scripts/test_interop.py`, `scripts/test_https.py --go` |
| [`ovh-release/`](ovh-release) | OVH kmip-go v0.9.2 | `scripts/test_interop.py` |
| [`thales/`](thales) | Thales kmip-go, commit `5b93a22` | `scripts/test_interop.py` |
| [`nlnet/`](nlnet) | NLnet Labs kmip-protocol 0.4.3 | `scripts/test_interop.py` |
| [`../integration/ibm/client.c`](../integration/ibm/client.c) | IBM libkmipclient v2.44.1, in a client container | `scripts/test_ibm_client.py` |
| [`phsym/`](phsym) | phsym kmip-rs v0.6.0 (trial, not counted) | `scripts/test_phsym_client.py` |
| [`cosmian/`](cosmian) | Cosmian KMS client 5.28.0 (trial, not counted; BUSL-1.1, test use only) | `scripts/test_cosmian_client.py` |
| [`java/`](java) | the signed keytend-kmip 0.10.0-rc.1 release (commit `0c5c725`) that [`java/keytend-kmip-release.json`](java/keytend-kmip-release.json) pins | `scripts/test_java_*.py` and other feature tests |
| [`pbm/`](pbm) | Percona Backup for MongoDB 2.17.0 test image | `scripts/test_database_pbm*.py` |

phsym kmip-rs and the Cosmian client run in separate trial suites and are not
counted as tested clients: phsym kmip-rs shares its lead maintainer with OVH
kmip-go, and Cosmian's BUSL-1.1 licence allows test use only.

[`clients.lock.json`](clients.lock.json) pins the Git commits that
`scripts/test_interop.py` checks out, and
[`requirements.lock`](requirements.lock) the Python packages. Commands and
prerequisites are in [testing](../docs/testing.md#process-and-client-suites).
