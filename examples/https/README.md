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

# HTTPS request examples

KMIP 2.1 request messages in the JSON form (one in XML) for the HTTPS
listener, and [`kmip.sh`](kmip.sh), which sends them with `curl`. Load it in
bash or zsh from the checkout, then send a file by name, filling in its
`$NAME` placeholders:

```sh
. examples/https/kmip.sh
ID=$(kmip create.json | field UniqueIdentifier)
kmip get.json ID="$ID" | field KeyMaterial
```

`kmip.sh` uses the [quick start](../../docs/quick-start.md)'s test
certificates; `KMIP_PKI`, `KMIP_CLIENT` and `KMIP_URL` select others. Its
functions are described in
[HTTPS with JSON or XML](../../docs/clients/https.md).

| File | Operation | Placeholders | Used in |
| --- | --- | --- | --- |
| [`create.json`](create.json), [`create.xml`](create.xml) | Create an AES-256 key | | [quick start](../../docs/quick-start.md#make-a-request-with-curl), [XML](../../docs/clients/https.md#xml) |
| [`get.json`](get.json) | Get | `ID` | [quick start](../../docs/quick-start.md#make-a-request-with-curl) |
| [`create-named.json`](create-named.json) | Create with a Name | `NAME` | [Locate by Name](../../docs/clients/https.md#locate-by-name) |
| [`locate.json`](locate.json) | Locate by Name | `NAME` | [Locate by Name](../../docs/clients/https.md#locate-by-name) |
| [`retire.json`](retire.json) | Activate, Revoke and Destroy in one batch | `ID` | [retire a key](../../docs/clients/https.md#retire-a-key-in-one-batch) |
| [`create-active.json`](create-active.json) | Create a non-extractable key and Activate it | | [AES-GCM](../../docs/clients/https.md#encrypt-and-decrypt-with-aes-gcm) |
| [`encrypt.json`](encrypt.json), [`decrypt.json`](decrypt.json) | AES-GCM Encrypt, Decrypt | `KEY`, `DATA`, `AAD`; Decrypt also `IV`, `TAG` | [AES-GCM](../../docs/clients/https.md#encrypt-and-decrypt-with-aes-gcm) |
| [`create-key-pair.json`](create-key-pair.json) | Create an RSA 3072 signing key pair | | [Sign and verify](../../docs/clients/https.md#sign-and-verify-with-rsa) |
| [`sign.json`](sign.json), [`verify.json`](verify.json) | RSASSA-PSS Sign, Signature Verify | `KEY`, `DATA`; Verify also `SIG` | [Sign and verify](../../docs/clients/https.md#sign-and-verify-with-rsa) |
| [`create-derivation-key.json`](create-derivation-key.json) | Create and Activate a non-extractable AES key for Derive Key | | [Derive Key](../../docs/crypto-operations.md#example-derive-a-key-with-hkdf-over-https) |
| [`derive.json`](derive.json) | Derive Key with HKDF-SHA-256 | `KEY`, `SALT`, `INFO` | [Derive Key](../../docs/crypto-operations.md#example-derive-a-key-with-hkdf-over-https) |
| [`create-kek.json`](create-kek.json) | Create and Activate an AES key-wrapping key | | [wrapped Get](../../docs/key-transfer.md#example-fetch-a-sensitive-key-wrapped) |
| [`create-sensitive.json`](create-sensitive.json) | Create a Sensitive key | | [wrapped Get](../../docs/key-transfer.md#example-fetch-a-sensitive-key-wrapped) |
| [`get-wrapped.json`](get-wrapped.json) | Get wrapped with AES Key Wrap | `ID`, `KEK` | [wrapped Get](../../docs/key-transfer.md#example-fetch-a-sensitive-key-wrapped) |
| [`set-attribute.json`](set-attribute.json) | Set Attribute (Contact Information) | `ID`, `CONTACT` | [attributes](../../docs/attributes.md#example-set-and-read-an-attribute) |
| [`get-attributes.json`](get-attributes.json) | Get Attributes (Contact Information, State) | `ID` | [attributes](../../docs/attributes.md#example-set-and-read-an-attribute) |
| [`export.json`](export.json) | Export | `ID` | [export and import](../../docs/key-transfer.md#example-export-a-key-and-import-it-again) |
| [`import.json`](import.json) | Import a symmetric key, Replace Existing | `ID`, `ATTRIBUTES`, `KEY` (JSON lists) | [export and import](../../docs/key-transfer.md#example-export-a-key-and-import-it-again) |

Byte strings are hex in JSON (`hex TEXT` converts text). Every file except
`import.json` is valid JSON as it stands; `import.json` takes two JSON lists
in place of its `$ATTRIBUTES` and `$KEY`.
