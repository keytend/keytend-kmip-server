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

# KMIP 3.0 draft

Part of the [feature reference](README.md#feature-reference).

KMIP 3.0 is not a final OASIS standard. The server implements part of the
Committee Specification Draft 02 (CSD02) for experimentation, only when
started with `--experimental-v3`, and only for requests with protocol version
3.0. A later draft may change any of this. Which 3.0 operations exist is in
the [support matrix](support-matrix.md).

- [Message differences](#message-differences)
- [System objects](#system-objects)
- [Login and tickets](#login-and-tickets)
- [Obliterate](#obliterate)
- [Constraints](#constraints)
- [Other 3.0 additions](#other-30-additions)

## Message differences

- No Batch Count, Batch Order Option or Unique Batch Item ID.
- Unique Identifiers use the Identifier type; requests may use Reference and
  Name Reference ([attributes](attributes.md#identifiers-and-batch-references)).
  Name is a Text String, and links are typed attributes.
- Revoke always compromises the object; Deactivate is a separate operation.
- Asynchronous processing follows the 2.x rules; a request item that expands
  into several results keeps one correlation value
  ([asynchronous requests](messages.md#asynchronous-requests)).

## System objects

Users, Groups and credentials (Password, Device, One Time Password and Hashed
Password Credential; Object Types 11–16) are created per principal and are
invisible to every other principal and to the generic operations: Get,
Locate, Get Attributes and Destroy never reach them, and no operation returns
a verifier, seed or S1.

Create User, Create Group and Create Credential need the policy grant and a
verified administrator in the request header: a users-file user with
`"administrator": true` ([credentials](credentials.md#users-file)).

Create User needs one Name (unique per principal and against users-file
names) and one to eight Credential Links. A user may link at most one of each
password-type credential.

| Credential | What Create Credential stores, and how it is verified |
| --- | --- |
| Password | Only a PBKDF2-HMAC-SHA-256 verifier (600,000 iterations). Pre-salted password fields are not supported. |
| Device | Device identifiers plus exactly one Password Link to a Password Credential; a 3.0 Device credential authenticates when the identifiers match and the linked password verifies. |
| One Time Password | TOTP only, with a client-supplied seed of at least 128 bits; verified with the user's password as in [credentials](credentials.md#one-time-password). |
| Hashed Password | SHA-256, SHA-384 or SHA-512; verified as in [credentials](credentials.md#hashed-password). |
| Certificate | Stored, but does not authenticate. |

System Objects belong to the principal, even when
[`client_identity: credential`](credentials.md#client-identity) gives its users
and devices their own managed objects; there are no per-user permissions on
them. A System Object's attributes cannot be edited: obliterate and re-create
it.

## Login and tickets

Login, Logout and Delegated Login follow the 2.x rules in
[Login and tickets](tickets.md), with these 3.0 differences:

- Login needs a user who proves a password in the same request; a 2.x Login
  needs no credentials.
- 3.0 tickets authenticate only 3.0 requests, and 2.x tickets only 2.x
  requests.
- Each use re-checks that the user and the System credential that proved it
  still exist; obliterating either revokes the ticket.
- Usage Limits (Unit Object) are supported, and Login is never processed
  asynchronously (Mandatory is Invalid Field).

## Obliterate

Obliterate removes an object record completely, unlike Destroy, which keeps
metadata; the identifier may then be reused. Later references are Object Not
Found. It needs an explicit policy grant of operation 61, and an
administrator for System Objects. Obliterating a credential stops it
authenticating and revokes tickets it proved; obliterating a user retires its
name permanently.

## Constraints

Set Constraints and Get Constraints restrict the objects an owner may
create. In 3.0 requests each managed-object owner has its own set; KMIP 2.1
requests read and replace one server-wide set, which also applies to 3.0
requests ([server defaults and constraints](defaults-and-constraints.md#constraints)).
The draft defines the Constraint structure (Object Types, Object Groups,
Attributes) but not how the fields combine; this server reads them as
follows:

- A constraint applies to a new object whose type is in Object Types (all
  types if absent) and, if Object Groups is present, that has a matching Group
  Link.
- It is satisfied when every attribute in Attributes matches the new object
  as a Locate filter would.
- It is checked after each 3.0 creating operation (Create, Create Key Pair,
  Register, Re-key, Re-key Key Pair, Derive Key, Certify, Re-certify, the
  Split Key operations, Import). A violation fails the item with Constraint
  Violation and rolls it back.
- A new object must satisfy the owner's set and the server set. 3.0 Get
  Constraints returns the owner's set only; 2.1 Get Constraints returns the
  server set.
- Existing objects, later attribute changes, System Objects and
  Re-Provision are not checked.
- Set Constraints replaces the owner's whole set; an empty structure removes
  it. At most 32 constraints with 32 attributes and 32 groups each.

## Other 3.0 additions

- Group Link: multi-instance, the group need not exist; Locate can filter on
  it.
- Post-quantum keys and Encapsulate/Decapsulate:
  [algorithms](algorithms.md#post-quantum-keys).
- Certificate Request Link on issued certificates.
- Set Defaults (server-wide, as in 2.1:
  [server defaults](defaults-and-constraints.md#set-defaults)) and
  Re-Provision (with `--provisioning-ca`, as in 2.1:
  [Re-Provision](re-provision.md)).

Not implemented: HOTP and server-generated seeds, authentication by
certificate credentials, and Notify and Put for 3.0 endpoints.
