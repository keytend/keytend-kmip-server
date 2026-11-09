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

# Server defaults and constraints

Part of the [feature reference](README.md#feature-reference).

Set Defaults changes the attribute values the server applies when a client
omits them; Set Constraints and Get Constraints restrict the objects clients
may create. Which editions offer each operation is in the
[support matrix](support-matrix.md).

| Operation | 2.0 | 2.1 | 3.0 draft |
| --- | --- | --- | --- |
| Set Defaults (54) | not defined; the server defaults still apply | server-wide | server-wide |
| Set Constraints (55), Get Constraints (56) | not defined; nothing is constrained | server-wide | the requester's own set; the server set applies too |

A certificate allowed Set Constraints can send it as 2.1 (server-wide) or as
3.0 (its own set), so grant both
operations only to an administrative certificate
([role templates](configuration.md#role-templates)). Changes to
the server defaults and to the server-wide constraint set are logged with the
principal ("server defaults replaced", "server constraints replaced")
besides the usual audit entry.

- [Set Defaults](#set-defaults)
- [Constraints](#constraints)
- [Interpretations](#interpretations)

## Set Defaults

Set Defaults (2.1 and the 3.0 draft) replaces the server's whole set of
configured Object Defaults. Without Defaults Information it removes every
configured default, and Query Defaults Information returns to its
documented initial answer ([Query](messages.md#query)). The configured
defaults are layered over the built-in ones: an attribute without a
configured default keeps the built-in behaviour.

Each Object Defaults names an Object Type (or an Object Types list, which
counts as one entry per type) and its Attributes. One entry per Object
Type, at most 8 attributes each. These attributes can be set:

| Object Type | Settable |
| --- | --- |
| Symmetric Key | Cryptographic Algorithm (with an optional Cryptographic Length), Cryptographic Usage Mask, Sensitive, Extractable |
| Private Key | the key pair's Cryptographic Algorithm (with an optional Cryptographic Length); Cryptographic Usage Mask, Sensitive, Extractable of the private key |
| Public Key | Cryptographic Usage Mask, Extractable of the public key |
| Secret Data | Cryptographic Usage Mask, Sensitive, Extractable |
| Certificate, Opaque Object | Sensitive, Extractable |

A Set Defaults request fails, and the previous set stays, when:

| Request | Result Reason |
| --- | --- |
| an Object Type outside the table | Invalid Object Type |
| Object Groups in Object Defaults | Feature Not Supported |
| any other attribute, including Lease Time and Protection Storage Mask | Feature Not Supported |
| an algorithm or length in the Public Key entry | Feature Not Supported |
| an algorithm the factory operation cannot generate in this edition and configuration, for example 3DES without `--triple-des enabled`, or ML-DSA in a 2.1 request | Feature Not Supported or Invalid Field, as Create or Create Key Pair answers it |
| a length without an algorithm, a length the algorithm does not have, a value of the wrong type, a repeated attribute, an empty Attributes, a repeated Object Type, both or neither of Object Type and Object Types | Invalid Field |

Values are checked the way the factory operation checks them, in the
request's edition and under the current `--fips`, `--triple-des` and
`--ec-curves` settings.

### Where defaults apply

Server defaults apply to 2.0, 2.1 and 3.0 requests; 1.x requests never get
them. Each attribute is injected only when the client omits it: a client
value always wins.

- Create takes every default of the Symmetric Key entry. The default
  algorithm is added only when the client named no algorithm and the
  default takes the client's length, if any.
- For Create Key Pair, the Private Key entry's algorithm and length apply to
  the whole pair and go into Common Attributes:
  - The algorithm is added when the client named no Cryptographic Algorithm
    in Common, Private Key or Public Key Attributes and the default takes the
    client's length or curve, if any (only EC takes a curve).
  - The length is added only when the effective algorithm is the default's
    and the client gave no length and no curve anywhere.
  - Each side's Usage Mask, Sensitive and Extractable defaults go into that
    side's attributes unless Common or that side sets them.
- Register takes the Cryptographic Usage Mask, Sensitive and Extractable
  defaults only; the algorithm and length describe the registered material.
- Derive Key takes the entry of the derived Object Type. Derive Key has no
  built-in algorithm, so the default algorithm fills an omitted one even
  when the client gives the length.

Re-key, Re-key Key Pair, Re-certify, Import, the Split Key operations and
Re-Provision get no server defaults.

A request that works without server defaults also works with them. A
Cryptographic Length belongs to its entry's algorithm, and a size the
default algorithm does not take keeps the built-in algorithm. With the
defaults AES and 128, a client asking for 3DES without a length gets 168.
With an ECDSA-256 pair default, a client giving only a 2048-bit length gets
RSA-2048, as without defaults.

### Stale entries

Each entry is checked again, in the request's edition and the current
configuration, every time it would be used. An entry that no longer passes
is skipped as a whole, and the built-in defaults apply; the server logs one
warning per entry and edition. A stale default never fails a client's
request. Examples:

- an ML-DSA pair default, set in a 3.0 request, is skipped in 2.0 and 2.1
  requests;
- a 3DES default is skipped after a restart without `--triple-des enabled`;
- a ChaCha20 default is skipped after a restart with `--fips`.

Query Defaults Information uses the same check, so it lists only the
entries that the request's edition and configuration would apply.

### Storage

The set is a hidden record in the encrypted, authenticated object store
(never a managed object): it survives restarts, follows batch Undo and
savepoints, is copied by `backup` and re-sealed by `rotate-master-key`.
`restore` brings back the set as of the backup. A record that cannot be
read fails every factory request and Query Defaults Information in 2.0
and later with General Failure, rather than ignoring the configured
defaults. Set Defaults without Defaults
Information replaces it.

## Constraints

Set Constraints replaces a constraint set; Get Constraints returns it.

- In KMIP 2.1 they read and replace the one server-wide set. It applies to
  every Managed Object that a 2.1 or 3.0 request creates, whichever
  principal creates it.
- In the 3.0 draft they read and replace the requester's own set, which
  applies to the objects that owner creates in 3.0 requests
  ([KMIP 3.0](kmip-3.0.md#constraints)). A 3.0 object must satisfy the
  server set too. 3.0 Get Constraints returns the owner's set only; read the
  server set with 2.1 Get Constraints.
- 1.x and 2.0 requests are never constrained.

Constraints check what clients create; they are not an access control. A
client that sends 1.x or 2.0 requests, or changes attributes after
creation, is not constrained. Use the policy's operation lists to restrict
clients.

The Constraint structure (Object Types, Object Groups, Attributes) is read
the same way in both editions; [KMIP 3.0](kmip-3.0.md#constraints) has the
rules for how its fields combine and what is checked. A violation fails the
item with Constraint Violation (0x4B) and rolls it back.

The server set differs from a 3.0 owner set in three ways:

- It is always validated, stored and read as 2.1, and a created object is
  compared in its 2.1 form, so a 2.1 Name constraint holds for a 3.0 Create
  whose Name is a Text String.
- Object Groups, and Object Group or Group Link attributes inside
  Attributes, are Feature Not Supported.
- A record that cannot be read fails every constrained item with General
  Failure (fail closed). An empty Set Constraints in 2.1 replaces it.

Re-Provision is exempt from both sets: its objects are server-generated
credentials, and its error table has no Constraint Violation.

Set Constraints replaces the whole set; an empty Constraints structure
removes it. At most 32 constraints, each with at most 32 attributes. The
server set is stored like the server defaults ([storage](#storage)).

## Interpretations

| Topic | Reading |
| --- | --- |
| Scope | The 2.1 text says "the server" sets defaults and constraints, with no owner. Set Defaults (2.1 and 3.0) and the 2.1 constraint operations therefore change one server-wide set. The 3.0 draft keeps the per-owner constraint sets this server already had; a 3.0 Set(Get()) round trip then never copies server constraints into an owner set. |
| Editions | Defaults apply to factory operations in 2.0, 2.1 and 3.0 requests, because 2.0 reports Defaults Information; constraints apply to objects created in 2.1 and 3.0 requests, because 2.0 has neither the operations nor Constraint Violation. 1.x is never affected. |
| "Mandatory attributes" | The 2.1 text applies defaults "if the client does not supply values for mandatory attributes". Most of the settable attributes are optional in 2.x requests; the server applies a default to any settable attribute the client omits. |
| Built-in defaults | Configured entries are layered over the built-in table; removing them restores it. Lease Time and Protection Storage Mask are not settable. |
| Object Groups | Object Groups in Object Defaults or in server constraints is Feature Not Supported. This removes group precedence, overlap between entries and the mapping between 2.1 Object Group and 3.0 Group Link. |
| Cryptographic Length | A Cryptographic Length default is set and applied only with its Cryptographic Algorithm, so a default meant for one algorithm never sizes a key of another. |
| Key pairs | Algorithm, length and curve are one pair dimension, set in the Private Key entry. A default algorithm is used only when the client named no algorithm and the default takes the client's size, so it never conflicts with a client's choice, and no rule is needed for Public and Private Key entries that disagree. |
| Stale entries and unreadable records | Stale entries are skipped and records that cannot be read fail. A default that no longer validates is a configuration change the server can absorb; an unreadable record is a fault, and ignoring it would create objects without the configured protections. |
| Query Defaults Information | Reports the effective set for the request's edition and configuration, with the same resolver as the factory operations. |
| Constraints in 2.1 | They follow the 3.0 reading ([KMIP 3.0](kmip-3.0.md#constraints)), with the three differences listed under [Constraints](#constraints). Re-Provision is exempt. |
