#!/usr/bin/env python3
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

"""Independent PyKMIP wire compatibility and key lifecycle test."""
import os,hashlib
from pathlib import Path
from kmip.pie.client import ProxyKmipClient
from kmip.pie.exceptions import KmipOperationFailure
from kmip.core import enums
p=Path(os.environ['KMIP_PKI'])
for v in [enums.KMIPVersion.KMIP_1_1,enums.KMIPVersion.KMIP_1_2,enums.KMIPVersion.KMIP_1_3,enums.KMIPVersion.KMIP_1_4]:
    with ProxyKmipClient(hostname='localhost',port=int(os.getenv('KMIP_PORT','15696')),cert=str(p/'client.pem'),key=str(p/'client.key'),ca=str(p/'ca.pem'),ssl_version='PROTOCOL_TLSv1_2',kmip_version=v) as c:
        uid=c.create(enums.CryptographicAlgorithm.AES,256,name=f'pykmip-interop-{v.name}',cryptographic_usage_mask=[enums.CryptographicUsageMask.ENCRYPT,enums.CryptographicUsageMask.DECRYPT])
        key=c.get(uid)
        assert len(key.value)==32
        assert c.get(uid).value==key.value
        c.activate(uid)
        got,attrs=c.get_attributes(uid,['State'])
        assert got==uid
        assert attrs[0].attribute_value.value==enums.State.ACTIVE
        c.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION,uid)
        c.destroy(uid)
        try:c.get(uid)
        except KmipOperationFailure as e:
            # 1.x Get error tables: only attributes remain -> Illegal Operation (destroyed-get-reasons.md).
            expected=enums.ResultReason.ILLEGAL_OPERATION
            assert e.reason==expected,str(e)
        else:raise AssertionError('Destroyed key was returned')
        print(f'PASS PyKMIP {v.name}: Create, Get, Activate, GetAttributes, Revoke, Destroy')
        base=c.create(enums.CryptographicAlgorithm.AES,256,cryptographic_usage_mask=[enums.CryptographicUsageMask.DERIVE_KEY])
        original=c.get(base).value;c.activate(base)
        derived=c.derive_key(enums.ObjectType.SYMMETRIC_KEY,[base],enums.DerivationMethod.HASH,
            {'cryptographic_parameters':{'hashing_algorithm':enums.HashingAlgorithm.SHA_256}},
            cryptographic_algorithm=enums.CryptographicAlgorithm.AES,cryptographic_length=256)
        assert c.get(derived).value==hashlib.sha256(original).digest()
        c.destroy(derived);c.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION,base);c.destroy(base)
        print(f'PASS PyKMIP {v.name}: Derive Key HASH matches Python SHA-256')
