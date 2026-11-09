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

# Support matrix

Part of [getting started](README.md#getting-started).

What the server implements in each KMIP edition. Every handler is partial:
each operation is implemented for the objects, algorithms and parameters described
on its reference page. Every operation and object type an edition defines has
a row, so what the server lacks shows as "no". The 3.0 column is a draft
([KMIP 3.0](kmip-3.0.md)).

The tables are generated from the server itself, by Query Operations, Query
Objects and newly created keys in every edition
([regenerating them](testing.md#support-matrix)).

<!-- generated:start -->
## Operations

- `yes`: the server has a handler and lists the operation in Query.
- `no`: the edition defines the operation and the server does not implement it.
- `opt-in`: implemented, and listed only when configured.
- Empty: the edition does not define it.
- `No.`: the operation number the [policy file](configuration.md#operation-numbers) uses (the specification writes it in hex).

### KMIP 1.0–1.4

| No. | Operation | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 |
| ---: | --- | :---: | :---: | :---: | :---: | :---: |
| 1 | [Create](objects.md#common-rules) | yes | yes | yes | yes | yes |
| 2 | [Create Key Pair](algorithms.md) | yes | yes | yes | yes | yes |
| 3 | [Register](objects.md#common-rules) | yes | yes | yes | yes | yes |
| 4 | [Re-key](rekey.md) | yes | yes | yes | yes | yes |
| 5 | [Derive Key](crypto-operations.md#derive-key) | yes | yes | yes | yes | yes |
| 6 | [Certify](certificates.md#certify-and-re-certify) | yes | yes | yes | yes | yes |
| 7 | [Re-certify](certificates.md#certify-and-re-certify) | yes | yes | yes | yes | yes |
| 8 | [Locate](locate.md) | yes | yes | yes | yes | yes |
| 9 | [Check](lifecycle.md#check) | yes | yes | yes | yes | yes |
| 10 | [Get](key-transfer.md#get) | yes | yes | yes | yes | yes |
| 11 | [Get Attributes](attributes.md#reading-attributes) | yes | yes | yes | yes | yes |
| 12 | [Get Attribute List](attributes.md#reading-attributes) | yes | yes | yes | yes | yes |
| 13 | [Add Attribute](attributes.md#changing-attributes) | yes | yes | yes | yes | yes |
| 14 | [Modify Attribute](attributes.md#changing-attributes) | yes | yes | yes | yes | yes |
| 15 | [Delete Attribute](attributes.md#changing-attributes) | yes | yes | yes | yes | yes |
| 16 | [Obtain Lease](lifecycle.md#leases) | yes | yes | yes | yes | yes |
| 17 | [Get Usage Allocation](lifecycle.md#usage-limits) | yes | yes | yes | yes | yes |
| 18 | [Activate](lifecycle.md#activate) | yes | yes | yes | yes | yes |
| 19 | [Revoke](lifecycle.md#revoke) | yes | yes | yes | yes | yes |
| 20 | [Destroy](lifecycle.md#destroy) | yes | yes | yes | yes | yes |
| 21 | [Archive](lifecycle.md#archive-and-recover) | yes | yes | yes | yes | yes |
| 22 | [Recover](lifecycle.md#archive-and-recover) | yes | yes | yes | yes | yes |
| 23 | [Validate](certificates.md#validate) | yes | yes | yes | yes | yes |
| 24 | [Query](messages.md#query) | yes | yes | yes | yes | yes |
| 25 | [Cancel](messages.md#asynchronous-requests) | yes | yes | yes | yes | yes |
| 26 | [Poll](messages.md#asynchronous-requests) | yes | yes | yes | yes | yes |
| 27 | [Notify](server-to-client.md) | opt-in | opt-in | opt-in | opt-in | opt-in |
| 28 | [Put](server-to-client.md) | opt-in | opt-in | opt-in | opt-in | opt-in |
| 29 | [Re-key Key Pair](rekey.md) |  | yes | yes | yes | yes |
| 30 | [Discover Versions](messages.md#version-negotiation) |  | yes | yes | yes | yes |
| 31 | [Encrypt](crypto-operations.md#encrypt-and-decrypt) |  |  | yes | yes | yes |
| 32 | [Decrypt](crypto-operations.md#encrypt-and-decrypt) |  |  | yes | yes | yes |
| 33 | [Sign](crypto-operations.md#sign-and-signature-verify) |  |  | yes | yes | yes |
| 34 | [Signature Verify](crypto-operations.md#sign-and-signature-verify) |  |  | yes | yes | yes |
| 35 | [MAC](crypto-operations.md#mac-and-mac-verify) |  |  | yes | yes | yes |
| 36 | [MAC Verify](crypto-operations.md#mac-and-mac-verify) |  |  | yes | yes | yes |
| 37 | [RNG Retrieve](crypto-operations.md#rng-retrieve-and-rng-seed) |  |  | yes | yes | yes |
| 38 | [RNG Seed](crypto-operations.md#rng-retrieve-and-rng-seed) |  |  | yes | yes | yes |
| 39 | [Hash](crypto-operations.md#hash) |  |  | yes | yes | yes |
| 40 | [Create Split Key](objects.md#split-keys) |  |  | yes | yes | yes |
| 41 | [Join Split Key](objects.md#split-keys) |  |  | yes | yes | yes |
| 42 | [Import](key-transfer.md#import-and-export) |  |  |  |  | yes |
| 43 | [Export](key-transfer.md#import-and-export) |  |  |  |  | yes |

### KMIP 2.0, 2.1 and the 3.0 draft

| No. | Operation | 2.0 | 2.1 | 3.0 |
| ---: | --- | :---: | :---: | :---: |
| 1 | [Create](objects.md#common-rules) | yes | yes | yes |
| 2 | [Create Key Pair](algorithms.md) | yes | yes | yes |
| 3 | [Register](objects.md#common-rules) | yes | yes | yes |
| 4 | [Re-key](rekey.md) | yes | yes | yes |
| 5 | [Derive Key](crypto-operations.md#derive-key) | yes | yes | yes |
| 6 | [Certify](certificates.md#certify-and-re-certify) | yes | yes | yes |
| 7 | [Re-certify](certificates.md#certify-and-re-certify) | yes | yes | yes |
| 8 | [Locate](locate.md) | yes | yes | yes |
| 9 | [Check](lifecycle.md#check) | yes | yes | yes |
| 10 | [Get](key-transfer.md#get) | yes | yes | yes |
| 11 | [Get Attributes](attributes.md#reading-attributes) | yes | yes | yes |
| 12 | [Get Attribute List](attributes.md#reading-attributes) | yes | yes | yes |
| 13 | [Add Attribute](attributes.md#changing-attributes) | yes | yes | yes |
| 14 | [Modify Attribute](attributes.md#changing-attributes) | yes | yes | yes |
| 15 | [Delete Attribute](attributes.md#changing-attributes) | yes | yes | yes |
| 16 | [Obtain Lease](lifecycle.md#leases) | yes | yes | yes |
| 17 | [Get Usage Allocation](lifecycle.md#usage-limits) | yes | yes | yes |
| 18 | [Activate](lifecycle.md#activate) | yes | yes | yes |
| 19 | [Revoke](lifecycle.md#revoke) | yes | yes | yes |
| 20 | [Destroy](lifecycle.md#destroy) | yes | yes | yes |
| 21 | [Archive](lifecycle.md#archive-and-recover) | yes | yes | yes |
| 22 | [Recover](lifecycle.md#archive-and-recover) | yes | yes | yes |
| 23 | [Validate](certificates.md#validate) | yes | yes | yes |
| 24 | [Query](messages.md#query) | yes | yes | yes |
| 25 | [Cancel](messages.md#asynchronous-requests) | yes | yes | yes |
| 26 | [Poll](messages.md#asynchronous-requests) | yes | yes | yes |
| 27 | [Notify](server-to-client.md) | opt-in | opt-in | no |
| 28 | [Put](server-to-client.md) | opt-in | opt-in | no |
| 29 | [Re-key Key Pair](rekey.md) | yes | yes | yes |
| 30 | [Discover Versions](messages.md#version-negotiation) | yes | yes | yes |
| 31 | [Encrypt](crypto-operations.md#encrypt-and-decrypt) | yes | yes | yes |
| 32 | [Decrypt](crypto-operations.md#encrypt-and-decrypt) | yes | yes | yes |
| 33 | [Sign](crypto-operations.md#sign-and-signature-verify) | yes | yes | yes |
| 34 | [Signature Verify](crypto-operations.md#sign-and-signature-verify) | yes | yes | yes |
| 35 | [MAC](crypto-operations.md#mac-and-mac-verify) | yes | yes | yes |
| 36 | [MAC Verify](crypto-operations.md#mac-and-mac-verify) | yes | yes | yes |
| 37 | [RNG Retrieve](crypto-operations.md#rng-retrieve-and-rng-seed) | yes | yes | yes |
| 38 | [RNG Seed](crypto-operations.md#rng-retrieve-and-rng-seed) | yes | yes | yes |
| 39 | [Hash](crypto-operations.md#hash) | yes | yes | yes |
| 40 | [Create Split Key](objects.md#split-keys) | yes | yes | yes |
| 41 | [Join Split Key](objects.md#split-keys) | yes | yes | yes |
| 42 | [Import](key-transfer.md#import-and-export) | yes | yes | yes |
| 43 | [Export](key-transfer.md#import-and-export) | yes | yes | yes |
| 44 | [Log](messages.md#log) | yes | yes | yes |
| 45 | [Login](tickets.md#login) | yes | yes | yes |
| 46 | [Logout](tickets.md#logout) | yes | yes | yes |
| 47 | [Delegated Login](tickets.md#delegated-login) | yes | yes | yes |
| 48 | [Adjust Attribute](attributes.md#adjust-attribute) | yes | yes | yes |
| 49 | [Set Attribute](attributes.md#changing-attributes) | yes | yes | yes |
| 50 | [Set Endpoint Role](server-to-client.md#set-endpoint-role) | yes | yes | yes |
| 51 | [PKCS#11](messages.md#pkcs11) | yes | yes | yes |
| 52 | [Interop](messages.md#interop-test-mode) | opt-in | opt-in | opt-in |
| 53 | [Re-Provision](re-provision.md) | opt-in | opt-in | opt-in |
| 54 | [Set Defaults](defaults-and-constraints.md#set-defaults) |  | yes | yes |
| 55 | [Set Constraints](defaults-and-constraints.md#constraints) |  | yes | yes |
| 56 | [Get Constraints](defaults-and-constraints.md#constraints) |  | yes | yes |
| 57 | [Query Asynchronous Requests](messages.md#asynchronous-requests) |  | yes | yes |
| 58 | [Process](messages.md#asynchronous-requests) |  | yes | yes |
| 59 | [Ping](messages.md#ping) |  | yes | yes |
| 60 | [Create Group](kmip-3.0.md#system-objects) |  |  | yes |
| 61 | [Obliterate](kmip-3.0.md#obliterate) |  |  | yes |
| 62 | [Create User](kmip-3.0.md#system-objects) |  |  | yes |
| 63 | [Create Credential](kmip-3.0.md#system-objects) |  |  | yes |
| 64 | [Deactivate](lifecycle.md#revoke) |  |  | yes |
| 65 | [Encapsulate](algorithms.md#post-quantum-keys) |  |  | yes |
| 66 | [Decapsulate](algorithms.md#post-quantum-keys) |  |  | yes |

Opt-in: Notify and Put are sent only to principals with a `client_endpoint`; Interop is offered only with `--interop-test-mode`, which KMIP forbids on a production server; Re-Provision is offered only with `--provisioning-ca`.

## Object types

`yes`: listed by Query Objects in that edition. `no`: the edition defines the type and the server does not accept it. Empty: not defined.

### KMIP 1.0–1.4

| No. | Object type | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 |
| ---: | --- | :---: | :---: | :---: | :---: | :---: |
| 1 | [Certificate](certificates.md) | yes | yes | yes | yes | yes |
| 2 | [Symmetric Key](algorithms.md) | yes | yes | yes | yes | yes |
| 3 | [Public Key](algorithms.md) | yes | yes | yes | yes | yes |
| 4 | [Private Key](algorithms.md) | yes | yes | yes | yes | yes |
| 5 | [Split Key](objects.md#split-keys) | yes | yes | yes | yes | yes |
| 6 | [Template](objects.md#templates-kmip-1x) | yes | yes | yes | yes | yes |
| 7 | [Secret Data](objects.md#secret-data) | yes | yes | yes | yes | yes |
| 8 | [Opaque Object](objects.md#opaque-objects) | yes | yes | yes | yes | yes |
| 9 | [PGP Key](objects.md#pgp-keys) |  |  | yes | yes | yes |

### KMIP 2.0, 2.1 and the 3.0 draft

| No. | Object type | 2.0 | 2.1 | 3.0 |
| ---: | --- | :---: | :---: | :---: |
| 1 | [Certificate](certificates.md) | yes | yes | yes |
| 2 | [Symmetric Key](algorithms.md) | yes | yes | yes |
| 3 | [Public Key](algorithms.md) | yes | yes | yes |
| 4 | [Private Key](algorithms.md) | yes | yes | yes |
| 5 | [Split Key](objects.md#split-keys) | yes | yes | yes |
| 7 | [Secret Data](objects.md#secret-data) | yes | yes | yes |
| 8 | [Opaque Object](objects.md#opaque-objects) | yes | yes | yes |
| 9 | [PGP Key](objects.md#pgp-keys) | yes | yes | yes |
| 10 | [Certificate Request](certificates.md#certificate-requests) | yes | yes | yes |
| 11 | [User](kmip-3.0.md#system-objects) |  |  | yes |
| 12 | [Group](kmip-3.0.md#system-objects) |  |  | yes |
| 13 | [Password Credential](kmip-3.0.md#system-objects) |  |  | yes |
| 14 | [Device Credential](kmip-3.0.md#system-objects) |  |  | yes |
| 15 | [One Time Password Credential](kmip-3.0.md#system-objects) |  |  | yes |
| 16 | [Hashed Password Credential](kmip-3.0.md#system-objects) |  |  | yes |

## Attributes the server reports on a new key

Get Attribute List on a newly created AES-256 key and RSA-2048 private key (`both`: both keys report it; `AES` or `RSA`: only that key does), with only algorithm, length and usage mask supplied. Client-settable attributes (Name, Object Group, Contact Information and others) appear once set; see [attributes](attributes.md).

### KMIP 1.0–1.4

| Attribute | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 |
| --- | :---: | :---: | :---: | :---: | :---: |
| Always Sensitive |  |  |  |  | both |
| Cryptographic Algorithm | both | both | both | both | both |
| Cryptographic Length | both | both | both | both | both |
| Cryptographic Usage Mask | both | both | both | both | both |
| Digest | both | both | both | both | both |
| Extractable |  |  |  |  | both |
| Fresh |  | both | both | both | both |
| Initial Date | both | both | both | both | both |
| Last Change Date | both | both | both | both | both |
| Lease Time | both | both | both | both | both |
| Link | RSA | RSA | RSA | RSA | RSA |
| Never Extractable |  |  |  |  | both |
| Object Type | both | both | both | both | both |
| Operation Policy Name | both | both | both | both | both |
| Original Creation Date |  |  | both | both | both |
| Random Number Generator |  |  |  | both | both |
| Sensitive |  |  |  |  | both |
| State | both | both | both | both | both |
| Unique Identifier | both | both | both | both | both |

### KMIP 2.0, 2.1 and the 3.0 draft

| Attribute | 2.0 | 2.1 | 3.0 |
| --- | :---: | :---: | :---: |
| Always Sensitive | both | both | both |
| Cryptographic Algorithm | both | both | both |
| Cryptographic Length | both | both | both |
| Cryptographic Usage Mask | both | both | both |
| Digest | both | both | both |
| Extractable | both | both | both |
| Fresh | both | both | both |
| Initial Date | both | both | both |
| Key Format Type | both | both | both |
| Last Change Date | both | both | both |
| Lease Time | both | both | both |
| Link | RSA | RSA |  |
| Never Extractable | both | both | both |
| Object Class |  |  | both |
| Object Type | both | both | both |
| Original Creation Date | both | both | both |
| Protection Storage Mask | both | both | both |
| Public Key Link |  |  | RSA |
| Random Number Generator | both | both | both |
| Sensitive | both | both | both |
| Short Unique Identifier | both | both | both |
| State | both | both | both |
| Unique Identifier | both | both | both |
<!-- generated:end -->
