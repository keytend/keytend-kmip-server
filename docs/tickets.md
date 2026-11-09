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

# Login and tickets

Part of the [feature reference](README.md#feature-reference).

Login issues a ticket that later requests present as a Ticket credential in
the request header; Logout ends it; Delegated Login issues a ticket that
another client may present with narrower rights. Which editions offer each
operation is in the [support matrix](support-matrix.md): all three from KMIP
2.0, and in the 3.0 draft (`--experimental-v3`). Each is gated by the
certificate's `operations` list like every other operation (Login 45, Logout
46, Delegated Login 47).

The handlers are partial implementations: the readings below are the
server's, and no independent client has exercised them.

- [Login](#login)
- [Logout](#logout)
- [Delegated Login](#delegated-login)
- [Interpretations](#interpretations)

## Login

Mutual TLS has already selected the certificate principal. A Login ticket
stands for that principal plus whatever the Login request's header
credentials proved:

- In 2.0 and 2.1 no credentials are needed. With a users-file user or
  device credential the ticket stands for that user or device; without one,
  for the certificate principal alone.
- In the 3.0 draft the user must prove a password in the same request
  ([KMIP 3.0](kmip-3.0.md#login-and-tickets)).

| Request field | Accepted values |
| --- | --- |
| Lease Time | Interval of 1 to 86,400 seconds, or a Date Time in the future at most 24 hours ahead. Default 1 hour. |
| Request Count | a positive Integer: how many request messages may present the ticket. Default unlimited. |
| Usage Limits | Unit Object only: Total, Count and Unit are required, and 1 ≤ Count ≤ Total. Each batch item executed under the ticket uses one unit. Unit Byte is Feature Not Supported. |

Anything else is Invalid Field. The response is a Ticket: Ticket Type Login
and a 32-byte random Ticket Value.

### Presenting a ticket

A request sends the Ticket credential (Credential
Type 6, 2.0 and later; Invalid Field in 1.x) in its Authentication header.

- It authenticates only for the principal that obtained it, and only in
  requests of the same major edition: a 2.x ticket in 2.0 or 2.1, a 3.0
  ticket in 3.0. Anything else, an unknown or expired ticket, or a spent
  Request Count is Authentication Not Successful.
- The request acts as the identity proved at Login, so under
  [`client_identity: credential`](credentials.md#client-identity) it owns
  objects as that user or device. The user, device or System credential
  must still exist at every use.
- A Login ticket may be combined with a password or device credential. When
  the ticket stands for a user or device, the credential must prove the same
  one; a different user or device, or a second ticket, is Authentication Not
  Successful. A ticket that stands for the principal alone combines with
  any credential that verifies.
- The certificate's own `operations` list still applies to every item.

### Ticket limits

- At most 64 live tickets per principal, delegated tickets included; the
  next Login gets Server Limit Exceeded until one expires or is logged out.
- Tickets live in memory as SHA-256 digests and are lost on restart.
- Request Count is charged once per message, when the ticket is redeemed.
  Usage Limits are charged per batch item, when the item is authorized and
  before it runs. Neither is ever refunded, even when the item fails, the
  batch is undone or the message fails: an undone Get still returns its key
  material, so a refund would let Undo replay it without limit.
- An item that finds the Usage Limits spent fails with Permission Denied.

### When issuance is refused

Login and Delegated Login refuse to issue a ticket (Permission Denied unless
noted) when:

- the request was authenticated by a ticket (no self-renewal), even if it
  also carries a password;
- the connection's certificate was retired by a
  [Re-Provision](re-provision.md), which keeps an open connection working but
  stops it minting new credentials;
- the request asks for asynchronous processing: Asynchronous Indicator
  Mandatory is Invalid Field, Optional runs the message synchronously.

Every ticket records the certificate that obtained it, and a Re-Provision of
that certificate revokes it.

## Logout

Logout ends the named ticket at once.

- The principal that obtained a ticket may log it out, and so may any
  request that presents it.
- An unknown, expired or foreign ticket is Invalid Ticket.
- Later items of the same message that were authenticated by that ticket
  fail with Permission Denied.
- Logout rolls back with its batch: an undone Logout restores the ticket,
  but not budget its items spent.

## Delegated Login

Delegated Login issues a **bearer** ticket: any certificate listed in the
policy may present it, and the request then acts as the delegator, the owner
of the Delegated Login request. Lease Time, Request Count and Usage Limits
work as for Login. Rights is required:

| Right field | Meaning |
| --- | --- |
| Operations | the operations the holder may perform; omitted: every operation the delegator may delegate |
| Objects | the only objects the holder may act on; omitted: every object of the delegator |
| Usage Limits | a budget for this Right, Unit Object only |
| Object Groups | Feature Not Supported (2.1 and 3.0); Invalid Field in 2.0, which does not define it |

Delegated Login refuses with Permission Denied a Right that names:

- an operation outside the delegator's `operations` list;
- an operation that is never delegated: Cancel (25), Poll (26), Login (45),
  Delegated Login (47), Set Endpoint Role (50), Interop (52), Re-Provision (53), Set
  Defaults (54), Set Constraints (55), Query Asynchronous Requests (57),
  Process (58), and Create Group, Obliterate, Create User and Create
  Credential (3.0, 60–63);
- an object the delegator does not own; unknown identifiers get the same
  answer.

Objects lists Unique Identifiers: Text Strings are taken literally, and the
ID Placeholder enumeration is resolved when Delegated Login runs. In 3.0
the identifier types, including Name Reference, resolve as in any other
request. Other enumerations and Integers are Feature Not Supported. Empty
Rights, Operations or Objects are Invalid Field, and so is a Right with
Objects that lists an operation which does not act on one object (for
example Locate or Create). Limits: 16 Rights, 66 Operations and 32 Objects
per Right (Server Limit Exceeded beyond).

### Using a delegated ticket

- It must be the only credential in the request, otherwise Authentication
  Not Successful. It authenticates only in the edition family that issued
  it.
- The request owns, reads and creates objects as the delegator. Object
  grants do not apply, neither the presenter's nor the delegator's.
- Each item needs all of: the presenting certificate's `operations`; the
  delegator's `operations` at issue; ticket budget; and a Right that permits
  the operation and its target and has budget. The first such Right, in
  request order, is charged.
- A Right with Objects permits only operations that act on one object named
  by their Unique Identifier: Check, Get, Get Attributes, Get Attribute
  List, Add, Modify, Delete, Adjust and Set Attribute, Obtain Lease, Get
  Usage Allocation, Activate, Revoke, Destroy, Archive, Recover, Encrypt,
  Decrypt, Sign, Signature Verify, MAC, MAC Verify, Export, and the 3.0
  Deactivate, Encapsulate and Decapsulate. The target is the item's Unique Identifier,
  or in 2.x the ID Placeholder when it is omitted. An item that names any
  other object, for example a wrapping key in a Key Wrapping Specification,
  is refused, and so is a multi-part continuation that carries only a
  Correlation Value. Locate and the factory operations need a Right without
  Objects.
- The holder may log out the ticket it presents without a Right, but no
  other ticket.
- A delegated message is never processed asynchronously: Mandatory is
  Invalid Field, Optional and True run it synchronously.
- The audit chain records the delegator, the word `delegate` and the
  presenting principal, separated by NUL bytes (`alice/user/Fred/delegate/bob`
  in the notation of [credentials](credentials.md)): the delegator part names
  its user or device when one proved the Delegated Login.

The delegator's principal, or any request presenting the ticket, ends it
with Logout. Obliterating the delegator's user or credential, and a
Re-Provision of the certificate that obtained the ticket, revoke it.

## Interpretations

| Topic | Reading |
| --- | --- |
| What a 2.x Login authenticates | KMIP 2.x has no User or Credential objects, and the channel already selected the principal. A 2.x Login needs no credentials, and the ticket stands for the principal plus the user or device the request proved. Draft 3.0 keeps its rule that a password is proved in the same request. |
| Request Count | It counts request messages, charged at authentication. A ticket whose count reaches zero cannot be presented again but stays alive: messages it already authenticated, including queued asynchronous batches, keep running until it expires or is logged out. A queued batch also stops running once its ticket is logged out, expired or revoked. |
| Who may present a delegated ticket | The specification does not say. Any listed certificate may, and acts as the delegator within the intersection of its own allowlist, the delegator's allowlist at issue and the Rights. Unlisted certificates never reach credential evaluation. |
| Logout by the holder of a delegated ticket | 6.1.12 says requests using the ticket "MUST only be permitted to perform the operations specified in the Rights". The holder may nevertheless log out the ticket it presents without a Right, because that only gives up authority. |
| Queue operations and asynchronous processing | Cancel, Poll, Process and Query Asynchronous Requests are never delegated, and a delegated message is never processed asynchronously, because the queue is scoped by owner: a delegate could otherwise see or control the delegator's queued work. |
| Items after a Logout | Items after a Logout of the presenting ticket fail closed with Permission Denied; the delegation context is copied at authentication, so a missing ticket never reads as "no restrictions". |
| Probing identifiers | Identifiers in a delegated request are resolved before the Rights are checked, so a holder can tell whether a delegator identifier outside its Objects exists. Values are never revealed. |
| Draft 3.0 | Draft 3.0 adds Delegated Login with the 2.1 text; Login's Usage Limits are supported there too, and Login and Delegated Login are never processed asynchronously in any edition. |
