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

# Request-header credentials

Part of [configuration and operations](README.md#configuration-and-operations).

Mutual TLS always selects the client's principal. A request may also carry
an Authentication structure in its header; the server then checks every
credential in it against users and devices provisioned for that principal in
the users file (`serve --users`, `KMIP_USERS`), in every protocol version.

> [!IMPORTANT]
> `--users` does not make credentials mandatory. A request without an
> Authentication structure is still served on its certificate alone, as the
> principal. Credentials add a check and can narrow the identity; they never
> replace the certificate policy.

- All credentials must verify. A wrong, unknown or unverifiable credential
  fails the whole message with Authentication Not Successful (Result Reason
  3), the same answer for every cause. A credential is never ignored.
- A principal without provisioned users or devices cannot present
  credentials.
- Users and devices of one principal are invisible to every other principal.
- A verified credential narrows the identity to that user or device: the
  audit chain records `principal/user` or `principal/device`. Objects still
  belong to the principal unless the policy sets
  [`client_identity`](#client-identity) to `credential`.
- 1.0 and 1.1 accept one credential, later editions up to four. Several
  credentials may prove the same user (a password and a One Time Password,
  for example), but together they may name at most one user and one device,
  and hold at most one ticket.

## Credential types

| Type | Editions | Checked against |
| --- | --- | --- |
| Username and Password | all | the user's salted password verifier |
| Device | 1.1+ | a provisioned device: every identifier presented must equal its value, and its password must verify |
| Hashed Password | 2.0+ | the user's `hashed_password` entry ([below](#hashed-password)) |
| One Time Password | 2.0+ | the user's TOTP seed and password ([below](#one-time-password)) |
| Ticket | 2.0+ | a live Login or Delegated Login ticket ([below](#tickets)) |
| Attestation | 1.2+ | not supported (Feature Not Supported): KMIP defines no verification procedure |

A credential type the edition does not define is Invalid Field.

## Tickets

A Ticket credential presents a ticket from
[Login or Delegated Login](tickets.md) (2.0 and later):

- A Login ticket authenticates only for the principal that obtained it, in
  requests of the same major edition (2.0/2.1, or 3.0), and stands for the
  user or device that Login proved, or for the principal alone (a 2.x Login
  needs no credentials). It may be combined with a password or device
  credential: of that same user or device when the ticket stands for one,
  otherwise any that verifies.
- A delegated ticket is a bearer ticket: any listed certificate may present
  it, alone, and acts as the delegator within the ticket's Rights.
- An unknown, expired, logged-out or exhausted ticket, a foreign Login
  ticket or a second ticket is Authentication Not Successful.
- A request authenticated by a ticket cannot obtain another one.

## Users file

```json
{
  "users": {
    "<certificate fingerprint from the policy>": [
      {"username": "app", "administrator": false,
       "password_verifier": {"algorithm": "PBKDF2-HMAC-SHA-256", "iterations": 600000,
                             "salt": "<hex>", "hash": "<hex>"}}
    ]
  },
  "devices": {
    "<certificate fingerprint from the policy>": [
      {"name": "meter-1", "device_serial_number": "serNum123456",
       "device_identifier": "devID2233",
       "password_verifier": {"algorithm": "PBKDF2-HMAC-SHA-256", "iterations": 600000,
                             "salt": "<hex>", "hash": "<hex>"}}
    ]
  }
}
```

Print a verifier with the server (the password is read from standard input):

```sh
printf '%s\n' 'a long random password' | keytend-kmip-server password-verifier
```

Startup refuses the file unless:

- every verifier is PBKDF2-HMAC-SHA-256 with 600,000 iterations, a 16–64 byte
  salt and a 32-byte hash, or the legacy scrypt form (N=2^15, r=8, p=1), which
  never authenticates in [FIPS mode](fips.md);
- each device has a unique name, a password verifier and at least one of
  Device Serial Number, Network, Machine or Media Identifier, unique per
  principal;
- certificates mapped to one principal agree on its users and devices;
- every fingerprint is in the [policy](configuration.md#policy-file), and no
  field is unknown.

`administrator: true` marks a user who may create and obliterate System
Objects in the 3.0 draft. Each verification costs one PBKDF2 evaluation; at
most four run at a time. An unknown username also costs one PBKDF2
evaluation, so response time does not separate unknown users from users with
PBKDF2 verifiers. A legacy scrypt verifier costs one scrypt evaluation
instead, which takes measurably different time: convert scrypt verifiers with
`password-verifier`. There is no per-client rate limit.

## Hashed Password

KMIP 2.0 and later. The client sends Username, a Date Time Extended
Timestamp, an optional Hashing Algorithm (default SHA-256) and
Hashed Password = Hash(S1 ‖ Timestamp) ‖ S2, where S1 = Hash(Username ‖
Password) and S2 = Hash(Password ‖ Username), all over UTF-8 bytes. The server
answers with Server Hashed Password = Hash(Timestamp ‖ S1 ‖ Hash(S2)) in the
response header, so the client can check the server too.

The user needs a `hashed_password` entry. S1 is stored as is (the server
needs it to recompute the proof); S2 is kept only as a salted verifier:

```python
import hashlib, os
u, p = b"app", b"<long random password>"
s1 = hashlib.sha256(u + p).digest()
s2 = hashlib.sha256(p + u).digest()
salt = os.urandom(16)
entry = {"hashing_algorithm": "SHA-256", "s1": s1.hex(),
         "s2_verifier": {"algorithm": "PBKDF2-HMAC-SHA-256", "iterations": 600000,
                         "salt": salt.hex(),
                         "hash": hashlib.pbkdf2_hmac("sha256", s2, salt, 600000).hex()}}
```

- The Timestamp must increase for every accepted request of the user and be
  within 300 s of the server clock. The last accepted value is stored in the
  database and survives restarts.
- `hashing_algorithm` may be SHA-256, SHA-384 or SHA-512.

## One Time Password

KMIP 2.0 and later, TOTP (RFC 6238) only:
`"one_time_password": {"seed": "<hex>", "digest": "SHA-1", "digits": 6, "interval": 30}`
(seed at least 128 bits; digest SHA-1, SHA-256 or SHA-512; 6–8 digits;
interval 15–300 s).

- The Password field is required and must verify: a code alone is not
  accepted.
- A code is accepted for the current time step or one step either side, and
  each step only once; the counter is stored in the database.

## Stored secrets

Neither a `hashed_password` nor a `one_time_password` entry alone lets a
reader of the users file authenticate: a Hashed Password proof also needs S2,
and a One Time Password also needs the password. But S1 lets that reader
guess the password at hash speed, not PBKDF2 speed, and a copied TOTP seed
removes the second factor, leaving only the password. `serve` therefore
refuses a users file with `hashed_password` or `one_time_password` entries
unless `--allow-stored-credential-secrets`
(`KMIP_ALLOW_STORED_CREDENTIAL_SECRETS`) is set. Use long random passwords for
these users. Restoring an older backup rewinds the replay counters.

## Client identity

By default every verified user and device of a principal shares the
principal's objects. With `"client_identity": "credential"` in the policy
entry, a request whose credentials verify acts as that user (or the device,
when no user credential is present):

- that identity owns the objects it creates and sees only its own; other users,
  devices and the bare certificate get the
  [unknown-identifier](messages.md#unknown-identifiers) answer, as for another
  principal (Item Not Found in 1.x, mostly Object Not Found in 2.x). Requests
  without Authentication keep the principal's identity;
- the certificate's operation list still limits every identity;
- an `object_grants` entry can grant a user's or device's object with
  `"user": "app"` or `"device": "meter-1"` next to `owner`;
- objects created before the option was turned on stay with the principal.

Every certificate mapped to one principal must agree on `client_identity`.
