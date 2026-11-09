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

"""Find a key by Name, use it, register outside material, re-key and retire.

Runs any number of times: each run uses a new Name and destroys its keys.
"""
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kmip.core import enums
from kmip.core.factories import attributes
from kmip.pie import objects
from kmip.pie.client import ProxyKmipClient

PKI = os.environ["KMIP_PKI"]
CLIENT = os.environ.get("KMIP_CLIENT", "client")  # the client certificate in PKI
ENCRYPT_DECRYPT = [enums.CryptographicUsageMask.ENCRYPT,
                   enums.CryptographicUsageMask.DECRYPT]
NAME = f"orders-kek-{uuid.uuid4().hex[:8]}"  # Names are unique per principal

with ProxyKmipClient(
    hostname="localhost", port=5696,
    cert=f"{PKI}/{CLIENT}.pem", key=f"{PKI}/{CLIENT}.key", ca=f"{PKI}/ca.pem",
    ssl_version="PROTOCOL_TLSv1_2", kmip_version=enums.KMIPVersion.KMIP_1_4,
) as client:
    # Create a named key, then find it again by its Name.
    uid = client.create(enums.CryptographicAlgorithm.AES, 256, name=NAME,
                        cryptographic_usage_mask=ENCRYPT_DECRYPT)
    client.activate(uid)
    name = attributes.AttributeFactory().create_attribute(enums.AttributeType.NAME, NAME)
    print("located", client.locate(attributes=[name]))

    # Fetch the key and encrypt locally with AES-GCM (nonce, tag and AAD).
    aead = AESGCM(client.get(uid).value)
    nonce = os.urandom(12)
    sealed = aead.encrypt(nonce, b"hello", b"order-42")
    print("decrypted", aead.decrypt(nonce, sealed, b"order-42"))

    # Register key material created elsewhere.
    imported = client.register(objects.SymmetricKey(
        enums.CryptographicAlgorithm.AES, 256, os.urandom(32),
        masks=ENCRYPT_DECRYPT, name=f"{NAME}-imported"))
    print("registered", imported)

    # Re-key: a new key takes over the Name; the old one keeps its material.
    replacement = client.rekey(uid=uid)
    print("re-keyed", uid, "->", replacement)

    # Retire the old key: revoke, then destroy.
    client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, uid)
    client.destroy(uid)
    print("destroyed", uid)

    # Clean up: the replacement is Active, the registered key Pre-Active.
    client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, replacement)
    client.destroy(replacement)
    client.destroy(imported)
