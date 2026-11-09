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

"""Create, fetch and destroy an AES key with PyKMIP (docs/quick-start.md)."""
import os

from kmip.core import enums
from kmip.pie.client import ProxyKmipClient

PKI = os.environ.get("KMIP_PKI", ".cache/dev-pki")  # the quick start's test certificates
CLIENT = os.environ.get("KMIP_CLIENT", "client")    # the client certificate in PKI

with ProxyKmipClient(
    hostname="localhost", port=5696,
    cert=f"{PKI}/{CLIENT}.pem", key=f"{PKI}/{CLIENT}.key", ca=f"{PKI}/ca.pem",
    ssl_version="PROTOCOL_TLSv1_2", kmip_version=enums.KMIPVersion.KMIP_1_4,
) as client:
    uid = client.create(
        enums.CryptographicAlgorithm.AES, 256,
        cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT,
                                  enums.CryptographicUsageMask.DECRYPT],
    )
    client.activate(uid)
    key = client.get(uid)
    print(f"created {uid}: {len(key.value)}-byte AES key")
    client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, uid)
    client.destroy(uid)
    print(f"destroyed {uid}")
