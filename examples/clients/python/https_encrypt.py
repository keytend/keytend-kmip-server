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

"""Server-side AES-GCM over HTTPS JSON with the Python standard library.

Posts the request files of examples/https, filling in their $NAME placeholders
as kmip.sh does. Works with either --text-encoding: the server's default
(compatible) writes enumerations as hex codes, the quick start's readable as
names.
"""
import http.client
import json
import os
import ssl
import string

PKI = os.environ["KMIP_PKI"]
CLIENT = os.environ.get("KMIP_CLIENT", "client")  # the client certificate in PKI
EXAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "https")
TLS = ssl.create_default_context(cafile=f"{PKI}/ca.pem")  # also checks the host name
TLS.load_cert_chain(f"{PKI}/{CLIENT}.pem", f"{PKI}/{CLIENT}.key")


def values(node, tag):
    """Every value of TAG in a JSON response, depth first."""
    if node["tag"] == tag:
        yield node["value"]
    if isinstance(node["value"], list):
        for child in node["value"]:
            yield from values(child, tag)


SUCCESS = {"Success", "0x00000000"}  # Result Status Success, readable or compatible


class KmipError(Exception):
    """The server answered, and an item failed."""


def kmip(request, **fields):
    """Post a request file with $NAME replaced; raise KmipError unless every item succeeded."""
    with open(os.path.join(EXAMPLES, request)) as f:
        body = string.Template(f.read()).substitute(fields)
    connection = http.client.HTTPSConnection("localhost", 5697, context=TLS, timeout=10)
    try:
        connection.request("POST", "/kmip", body, {"Content-Type": "application/json"})
        reply = connection.getresponse()
        if reply.status != 200:
            raise http.client.HTTPException(f"HTTP {reply.status}")
        response = json.load(reply)
    finally:
        connection.close()
    if any(status not in SUCCESS for status in values(response, "ResultStatus")):
        raise KmipError(f"{request}: {next(values(response, 'ResultReason'), '')}: "
                        f"{next(values(response, 'ResultMessage'), '')}")
    return response


def one(response, tag):
    return next(values(response, tag))


key = one(kmip("create-active.json"), "UniqueIdentifier")
aad = b"order-42".hex()
sealed = kmip("encrypt.json", KEY=key, DATA=b"hello".hex(), AAD=aad)
ct, iv, tag = (one(sealed, t) for t in ("Data", "IVCounterNonce", "AuthenticatedEncryptionTag"))
print("encrypted", key, ct, iv, tag)
opened = kmip("decrypt.json", KEY=key, DATA=ct, IV=iv, TAG=tag, AAD=aad)
print("decrypted", bytes.fromhex(one(opened, "Data")))
try:
    kmip("decrypt.json", KEY=key, DATA=ct, IV=iv, TAG=tag, AAD=b"order-43".hex())
except KmipError as e:
    print("refused:", e)
