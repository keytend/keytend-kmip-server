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

# Configuration reference

Part of [configuration and operations](README.md#configuration-and-operations).

Every setting of `keytend-kmip-server`, its policy file and its endpoints.
`keytend-kmip-server <command> --help` prints the same flags (with the image:
`docker run --rm <image> serve --help`). Each `serve` flag's environment
variable is `KMIP_` and the flag's name in upper case with `_` for `-`
(`--idle-timeout` is `KMIP_IDLE_TIMEOUT`); the settings tables list both.

**Restart to apply.** Settings, the policy, the users file, certificates and
CRLs are read once, at startup; the server never reloads them. Restart it to
apply a change; the restart closes every connection
([changing the policy](operations.md#changing-the-policy)).

- [Commands](#commands)
- [Endpoints](#endpoints)
- [`serve` settings](#serve-settings)
- [Policy file](#policy-file)
- [Fixed limits](#fixed-limits)
- [Logging](#logging)

## Commands

| Command | Purpose |
| --- | --- |
| `serve` | Run the server. Binary TTLV over mutual TLS; no plaintext mode. |
| `generate-master-key` | Write a new 32-byte raw master key, mode 0600. |
| `check-store` | Verify the master key, SQLite integrity, every object record and the audit chain, read-only, without serving. |
| `backup` | Write a consistent, verified encrypted snapshot (SQLite `VACUUM INTO`) under the same master key: one file (`--output`), or a timestamped file in a directory with retention and a `latest.json` record (`--output-dir`). |
| `restore` | Verify a backup and install it as the database, keeping the previous one ([restore](backup-restore.md#restore)). |
| `rotate-master-key` | Write a verified snapshot re-encrypted under a new master key, or rotate the database in place with `--in-place` ([rotating the master key](master-key-rotation.md)). |
| `audit-checkpoint` | Export an authenticated audit position for independent retention ([audit checkpoints](audit-checkpoints.md)). |
| `password-verifier` | Read one password line from standard input and print a users-file `password_verifier` (PBKDF2-HMAC-SHA-256, 600,000 iterations). |
| `tls-profiles` | Print the TLS policies (versions, suites, groups) as JSON. |
| `fips-check` | Load the OpenSSL FIPS provider as `serve --fips` would and print what was found. Needs `--fips`, `KMIP_FIPS=true` or a FIPS-mode host. |
| `healthcheck` | Exit 0 when `/readyz` answers 200; the image's [health check](deployment.md#health-check). |

`check-store`, `backup` and `audit-checkpoint` can run on the database of a
running server. Stop the server before `rotate-master-key`: writes after its
snapshot are lost.

The maintenance commands take these flags:

| Flag | Commands | Meaning |
| --- | --- | --- |
| `--database DB` | `check-store`, `backup`, `restore`, `rotate-master-key`, `audit-checkpoint` | The SQLite store (or a backup) to read. It must exist, except for `restore`, which may create it. |
| `--master-key KEY` | the same | The master key the store is encrypted under (for `restore`, the key that opens the backup; with `rotate-master-key --in-place`, the new key). Refused if other users can access it. `check-store` and `backup` accept it more than once: the first key that opens the store is used, and the output names it (`Master key <file> opens <database>`). |
| `--output FILE` | `generate-master-key`, `backup`, `rotate-master-key`, `audit-checkpoint` | The file to write. Every command refuses an existing file; the directory must exist, except with `--create-directory`. |
| `--if-exists` | `backup` | If the database does not exist yet (a server that has never started), print `No database at … yet; nothing to back up` and exit 0. |
| `--output-dir DIR` | `backup` | Instead of `--output`: write a verified `backup-<UTC time>.sqlite` into this existing directory, not the database's own, and record it in `DIR/latest.json` and `DIR/backup-index.json` ([back up](backup-restore.md#back-up)). |
| `--retain N` | `backup` | With `--output-dir`: keep the newest `N` (at least 1) backups of this database and delete the older ones that `backup-index.json` records for it ([back up](backup-restore.md#back-up)). |
| `--audit-checkpoint FILE` | `check-store`, `restore`, `rotate-master-key` | Fail if the store is older than, or diverges from, this [audit checkpoint](audit-checkpoints.md). |
| `--previous FILE` | `audit-checkpoint` | Verify the store against the last retained checkpoint before exporting a new one. |
| `--new-master-key KEY` | `rotate-master-key` | The new key, from `generate-master-key`; it must differ from the current one. Not with `--in-place`. |
| `--create-directory` | `rotate-master-key` | Create the output's parent directory, mode 0700, first; it must not exist. For a Kubernetes Job without a shell. |
| `--from FILE` | `restore` | The backup to install. It is verified read-only first; on failure nothing changes. |
| `--id ID` | `restore` | Names the restore: 1–64 of `A-Z a-z 0-9 . _ -`, not starting with `.` or `-`. The replaced database goes to `pre-restore-<ID>/`. The same `ID` with the same backup does nothing, or completes an interrupted restore ([restore](backup-restore.md#restore)). |
| `--in-place` | `rotate-master-key` | Rotate the database itself from `--previous-master-key` to `--master-key`, keeping the old one in `pre-rotation-<UTC time>-<n>/` (a revert uses `post-rotation-<UTC time>-<n>/`; `<n>` makes both names unique) ([in place](master-key-rotation.md#rotate-in-place)). Does nothing once the store opens with `--master-key`. |
| `--previous-master-key KEY` | `rotate-master-key --in-place` | The key the store is encrypted under before the rotation. |
| `--checkpoint-output FILE` | `rotate-master-key --in-place` | Write an audit checkpoint of the store under the key it is left with (or require that an existing file verifies). |
| `--revert` | `rotate-master-key --in-place` | Put back the newest `pre-rotation-<UTC time>-<n>/` database and move the rotated one to `post-rotation-<UTC time>-<n>/`. |
| `--address ADDR` | `healthcheck` | Health listener to probe, a numeric `IP:port` (default `127.0.0.1:8080`). `healthcheck` does not read `KMIP_HEALTH_LISTEN`: pass this when the listener moves. |

Exit status: 0 on success; 1 when the command fails, with the reason on
standard error; 2 for an invalid invocation (an unknown flag, a missing
required setting or a value out of range), with a usage message. For example:

```sh
keytend-kmip-server check-store --database kmip.sqlite --master-key master.key
keytend-kmip-server backup --database kmip.sqlite --master-key master.key --output backup.sqlite
keytend-kmip-server backup --database kmip.sqlite --master-key master.key --output-dir backups --retain 14
keytend-kmip-server audit-checkpoint --database kmip.sqlite --master-key master.key --output cp.json
```

```text
Master key, object records and audit chain verified
Authenticated audit checkpoint exported; retain it independently of database snapshots
```

`backup --output` prints nothing on success; `backup --output-dir` prints the
file it wrote and any it removed. Both record the time of a successful backup
in `<database>.last-backup` when that directory is writable; the server
reports it as `kmip_last_backup_timestamp_seconds` ([metrics](metrics.md)).
With the wrong key, `check-store` fails:

```text
Error: record authentication failed (wrong key or corrupted store)

Caused by:
    OpenSSL error
```

`--fips` (`KMIP_FIPS`) applies to every command except `healthcheck` and
`tls-profiles`, which do not load the FIPS provider; `healthcheck` therefore
checks readiness only, not the provider ([FIPS mode](fips.md)). Apart from
it, only `serve` reads environment variables.

### Store lock and cutover records

`serve` holds the store lock, `<database>.lock` (for example
`/data/kmip.sqlite.lock`), for as long as it runs; `restore` and
`rotate-master-key` (with or without `--in-place`) take it too and exit with
`the store is in use by a running server (lock …)` while it is held. A second
`serve` on the same database fails the same way. The read-only commands,
`check-store`, `backup` and `audit-checkpoint`, take no store lock, except in
a read-only directory (below).

The read-only commands open the store read-only: they never change or upgrade
it, and refuse a store newer than the binary. On a store with an older schema
they verify the master key, every object record and the audit chain, say that
the store has an older schema, and `backup` copies it as it is; the server
builds the store's authenticated object index when it first opens it. They
never write to the database, but may leave empty `-wal` and `-shm` files next
to a stopped one (SQLite needs them to read a WAL database). In a read-only
directory, where SQLite cannot create them, they read only while holding a
shared lock on the store lock, so they need its lock file and refuse while a
server runs. `rotate-master-key` without `--in-place` opens the source as
`serve` does and upgrades an older one; `--in-place` refuses an older store
until the server has opened it once.

`restore` and `rotate-master-key --in-place` (with or without `--revert`)
move database files. Before they move anything they write an
intent record named after the database (`kmip.sqlite.restore.json`,
`kmip.sqlite.rotation.json` or `kmip.sqlite.revert.json`) and remove it
when they finish. While a record exists, `serve`, `check-store`, `backup`
and `audit-checkpoint` refuse the database and name the command that
finishes the cutover: run the same `restore` (same `--id`) or
`rotate-master-key --in-place` again. Only these records count: directories
such as `pre-restore-<time>/` made by hand or by the Docker scripts never
block anything. While a cutover runs it also holds an exclusive `flock` on
the database's directory: the read-only commands hold a shared one, so they
fail at once (`a restore or master-key rotation is changing the database
files`) while a cutover runs, and a cutover waits up to 60 seconds for reads
in progress before it gives up without changing anything.

The database must be a file in a directory, not a mount point of its own
(a single file bind-mounted into the container): a cutover moves its files,
which a file mount does not allow, so `restore` and in-place rotation refuse
it before they write any record. Mount the directory instead. If a cutover
cannot begin for any other reason before anything has moved, it removes its
record and leaves the database as it was.

The locks are `flock(2)` locks: they hold between containers and pods on one
host sharing a volume, but not across hosts, so network filesystems such as
NFS are not supported for the data volume.

## Endpoints

| Port (default) | Setting | Protocol | Paths |
| --- | --- | --- | --- |
| 5696 | `--listen` | Binary TTLV over mutual TLS | |
| 5697 | `--https-listen` (off unless set) | HTTP/1.0 and 1.1 over the same mutual TLS | `POST /kmip` (`--https-path`), TTLV, JSON or XML bodies ([encodings](encodings.md)) |
| 8080 | `--health-listen` | Plain HTTP, unauthenticated | `GET /livez`, `/readyz`, `/metrics` ([metrics](metrics.md)), `/connection-metrics` ([connection counters](metrics.md#connection-counters)) |

Both KMIP listeners share one TLS configuration, certificate policy, store and
connection limit. `/livez` answers 200 while the process serves; `/readyz`
answers 200 when the store is available and its [live history](store-integrity.md#live-history-check)
check passes, and 503 otherwise ([health and readiness](operations.md#health-and-readiness)). Keep the health port on a management network.

Listen addresses are a numeric IP address and port: `127.0.0.1:5696`, or IPv6
in brackets (`[::]:5696`, `[::1]:8080`). Host names are refused
(`--listen localhost:5696` exits with `invalid socket address syntax`). On
Linux `[::]` also accepts IPv4 connections unless the host sets
`net.ipv6.bindv6only=1`; the defaults `0.0.0.0:…` accept IPv4 only
([Kubernetes on IPv6](kubernetes.md#settings-and-extra-files)).

## `serve` settings

Required: `--cert`, `--key`, `--ca`, `--policy`, `--master-key`. A setting
given both as a flag and as its `KMIP_` variable takes the flag's value. With
Docker, keep the variables in an env file
([example](deployment.md#docker-or-podman)).

### Listeners, TLS and identity

| Flag and variable | Default | Meaning |
| --- | --- | --- |
| `--listen` (`KMIP_LISTEN`) | `0.0.0.0:5696` | Binary TTLV listener. |
| `--https-listen` (`KMIP_HTTPS_LISTEN`) | off | HTTPS listener, for example `0.0.0.0:5697`. |
| `--https-path` (`KMIP_HTTPS_PATH`) | `/kmip` | HTTPS request path. |
| `--health-listen` (`KMIP_HEALTH_LISTEN`) | `0.0.0.0:8080` | Health and metrics listener. |
| `--cert` (`KMIP_CERT`) | required | PEM server certificate chain. Include every DNS name and IP clients connect to. |
| `--key` (`KMIP_KEY`) | required | PEM server private key. |
| `--ca` (`KMIP_CA`) | required | PEM CA bundle that client certificates must chain to, through at most 4 intermediate CA certificates. |
| `--crl` (`KMIP_CRL`) | none | PEM CRL; when set, chain revocation checks are required. |
| `--tls-profile` (`KMIP_TLS_PROFILE`) | `modern` | TLS policy of both listeners: `modern`, `mozilla-intermediate` or a `kmip-*` authentication suite ([TLS profiles](tls-profiles.md)). |
| `--policy` (`KMIP_POLICY`) | required | [Policy file](#policy-file). |
| `--users` (`KMIP_USERS`) | none | [Users file](credentials.md#users-file) of request-header credentials, checked on top of mutual TLS ([example](clients/python.md#request-header-credentials)). |
| `--allow-stored-credential-secrets` (`KMIP_ALLOW_STORED_CREDENTIAL_SECRETS`) | off | Accept Hashed Password and One Time Password material in the users file ([credentials](credentials.md#stored-secrets)). |
| `--validation-ca` (`KMIP_VALIDATION_CA`) | none | PEM trust anchors for the KMIP Validate operation, separate from `--ca`. Without it Validate returns Unknown ([certificate validation](certificates.md#validate)). |
| `--max-connections` (`KMIP_MAX_CONNECTIONS`) | `64` | Open connections across both KMIP listeners, 1–1024. Further connections wait until one closes. HTTPS also has a fixed limit of 4 requests in progress ([fixed limits](#fixed-limits)). |
| `--idle-timeout` (`KMIP_IDLE_TIMEOUT`) | `300` | Seconds an idle connection stays open, 0–604800; `0` never closes one. |
| `--provisioning-ca` (`KMIP_PROVISIONING_CA`) | none | PEM certificate of the CA that issues [Re-Provision](re-provision.md) client certificates. With `--provisioning-ca-key`, Re-Provision is offered (2.0 and later). Use a dedicated sub-CA; it must also be in `--ca`. |
| `--provisioning-ca-key` (`KMIP_PROVISIONING_CA_KEY`) | none | PEM private key of `--provisioning-ca`. Needs `--provisioning-ca`, and the file must have no permission bit for other users (`o+rwx`). |

### Storage

| Flag and variable | Default | Meaning |
| --- | --- | --- |
| `--database` (`KMIP_DATABASE`) | `/data/kmip.sqlite` | SQLite store, created mode 0600 if missing. Keep it and its WAL on one local filesystem with working locks and fsync. |
| `--master-key` (`KMIP_MASTER_KEY`) | required | 32-byte raw master key from `generate-master-key`. |
| `--audit-checkpoint` (`KMIP_AUDIT_CHECKPOINT`) | none | Refuse to start unless the store is at or after this [audit checkpoint](audit-checkpoints.md). |
| `--object-cache-mib` (`KMIP_OBJECT_CACHE_MIB`) | `64` | Size of the [object cache](#object-cache) in MiB: `0` turns it off, otherwise 1–65536. |
| `--object-cache-ttl` (`KMIP_OBJECT_CACHE_TTL`) | `600` | Seconds a cached object may go unused before it is dropped: 1–86400. |

SQLite also needs a writable temporary directory (`/tmp`) for statement
journals, even with a read-only root filesystem.

The server refuses to start, and the maintenance commands refuse to run, when
the database or the master key has any permission bit for other users
(`o+rwx`). That is the only check:

- It does not look at the owner, the group's members or ACLs; review those
  yourself (`getfacl`).
- Use mode 0600 or 0400. Use 0640 or 0440 only with a group that holds
  nothing but the server's account.
- The certificate key, policy and users files are not checked at all.

### Object cache

Each object is stored encrypted, with its attributes inside the encryption,
so reading one means decrypting it. Two things keep that work down:

- **The object index:** an in-memory map from every Name value and Link
  target to the objects that hold them, built when the server starts. Locate
  with a Name or Link filter, and the check that a Name is unique, read only
  those objects. Nothing about it is written to the database. It has no
  setting.
- **The object cache:** decrypted objects, kept for the next request. Other
  Locate filters still read every object of the owner, but from memory.

The cache holds key material in plain form in the server's memory, not only
during a request. Its size counts the decrypted records plus a small overhead
each; their parsed form in memory takes more, so leave room above it in a
container's memory limit. When it is full, the least recently used objects leave first.
An object unused for `--object-cache-ttl` seconds leaves within about 30
seconds of that, even when no requests arrive. A leaving object's key
material is overwritten. Set `--object-cache-mib 0` to keep keys in memory
only while a request uses them.

Every request sees every write that finished before it, from any connection
or client:

- A cached object is used only while its stored record is unchanged, which
  the server checks against the database on every read. A write, a
  rolled-back write or a restore never serves an old version.
- Every write adds the object's Names and Link targets to the index before
  its response, and every Locate checks its filter against the current
  record, so a removed Name or Link never matches.
- The index belongs to one server process. `serve` holds the store's writer
  lock for its lifetime, so a second server cannot open the same database
  ([store lock](#store-lock-and-cutover-records)). Network filesystems, where
  that lock does not hold between hosts, are not supported.

### Protocol behaviour

| Flag and variable | Default | Meaning |
| --- | --- | --- |
| `--experimental-v3` (`KMIP_EXPERIMENTAL_V3`) | off | Accept the KMIP 3.0 draft (CSD02). Keep off for database integrations. |
| `--max-lease-seconds` (`KMIP_MAX_LEASE_SECONDS`) | `3600` | Lease Time stored on new objects; `0` means no lease limit. Existing objects keep theirs. See [Lease Time and KMS outages](operations.md#lease-time-and-kms-outages). |
| `--lease-states` (`KMIP_LEASE_STATES`) | `active-deactivated` | Which objects Obtain Lease serves: `active-deactivated` or `active` ([leases](lifecycle.md#leases)). |
| `--destroyed-name-reuse` (`KMIP_DESTROYED_NAME_REUSE`) | `allow` | `allow`: a Name held only by destroyed objects can be reused; `reserve`: destroyed objects keep their Names. |
| `--get-attributes-none` (`KMIP_GET_ATTRIBUTES_NONE`) | `empty-attributes` | 2.x/3.0 Get Attributes when none of the requested attributes exist: an empty Attributes structure, or `identifier-only`. |
| `--triple-des` (`KMIP_TRIPLE_DES`) | `disabled` | Three-key 3DES: `disabled`, `legacy-decrypt` (Register, Import, Decrypt) or `enabled` ([3DES](algorithms.md#3des)). Single DES is never offered. |
| `--ec-curves` (`KMIP_EC_CURVES`) | `extended` | Curves KMIP operations may use: `extended` (P-224, P-256, P-384, P-521, secp256k1 and the brainpool r1/t1 curves) or `nist` (the first four only) ([curves](algorithms.md#elliptic-curves)). |
| `--interop-test-mode` (`KMIP_INTEROP_TEST_MODE`) | off | Offer the KMIP Interop operation (52) for test runs. KMIP forbids it on a production server. |
| `--fips` (`KMIP_FIPS`) | off | [FIPS mode](fips.md); also entered when `/proc/sys/crypto/fips_enabled` is 1. Restricts `--tls-profile` and `--triple-des`. |

The reasons behind these choices are in
[interpretations](interpretations.md).

### JSON and XML response forms

`--text-encoding` (`KMIP_TEXT_ENCODING`) picks a preset:

- `compatible` (default): JSON tags by name with hex enumerations (some
  clients reject normative enumeration names), JSON Numbers, hex Date-Times;
  XML general elements, hex enumerations and mask names.
- `readable`: names and Numbers wherever the Profiles allow them, text
  Date-Times.
- `hex`: hex wherever the Profiles allow it.

Requests are accepted in every allowed form whatever the setting. The quick
start sets `readable`.

Thirteen per-element settings override the preset. Their variables follow
the same rule (`KMIP_JSON_TAGS` for `--json-tags`), and their values are in
[response forms](encodings.md#response-forms):

- JSON: `--json-tags`, `--json-enumerations`, `--json-masks`,
  `--json-integers`, `--json-long-integers`, `--json-big-integers`,
  `--json-intervals`, `--json-date-time-extended`, `--json-booleans`,
  `--json-date-times`;
- XML: `--xml-tags`, `--xml-enumerations`, `--xml-masks`.

### Metrics

| Flag and variable | Default | Meaning |
| --- | --- | --- |
| `--metrics` (`KMIP_METRICS`) | `on` | `on` or `off`: serve `/metrics` on the health listener; with `off` it answers 404 and no object census runs. |
| `--metrics-object-census-interval` (`KMIP_METRICS_OBJECT_CENSUS_INTERVAL`) | `300` | Seconds between object censuses: `0` for none, otherwise 10–86400. |

## Policy file

The policy maps each client certificate to a principal (the owner of the
objects it creates) and to the KMIP operations it may call. A certificate that
chains to `--ca` but is not listed gets one Permission Denied response and the
connection closes.

```json
{
  "principals": {
    "<sha256 of the client certificate, DER, lowercase hex>": {
      "name": "orders-db",
      "operations": [1, 3, 8, 10, 11, 12, 18, 24, 30]
    }
  }
}
```

To write this policy for a client certificate `orders-db.pem`:

```sh
FP=$(openssl x509 -in orders-db.pem -outform DER | sha256sum | cut -d' ' -f1)
printf '{"principals": {"%s": {"name": "orders-db", "operations": [1, 3, 8, 10, 11, 12, 18, 24, 30]}}}\n' \
  "$FP" > policy.json
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Principal: the ownership boundary, 1–128 bytes. Several certificates may share one name (for certificate rotation, or a separate administrative certificate); they then share the same objects. |
| `operations` | yes | Operation numbers this certificate may call (table below). Numbers outside 1–66 are refused at startup. |
| `object_grants` | no | Exact-object read access to another principal's objects ([authorization](authorization.md)). |
| `client_identity` | no | `certificate` (default) or `credential`: with `credential`, a verified header credential acts as that user or device of the principal ([credential identity](credentials.md#client-identity)). |
| `client_endpoint` | no | Opt-in server-to-client Notify and Put delivery: address, TLS files, protocol version and operations ([fields](server-to-client.md#configuration)). |

Unknown fields are refused. Principals see only their own objects (and objects
granted to them); Names are unique per principal, not per server
([tenant isolation](authorization.md#tenant-isolation-and-names)).

The quick start's test policy, `.cache/dev-pki/policy.json` from
`scripts/dev-pki.sh`, is a working file to inspect: real fingerprints, a
full-access principal `database` and a read-only `other-tenant`.

A policy with a database client, a separate administrative certificate for the
same principal, and a reporting principal that may read one of its keys (the
[role templates](#role-templates) below explain each list):

```json
{
  "principals": {
    "<fingerprint of orders-db.pem>": {
      "name": "orders-db",
      "operations": [1, 3, 8, 10, 11, 12, 18, 24, 30]
    },
    "<fingerprint of orders-admin.pem>": {
      "name": "orders-db",
      "operations": [1, 3, 8, 10, 11, 12, 13, 14, 15, 18, 19, 20, 24, 30]
    },
    "<fingerprint of reporting.pem>": {
      "name": "reporting",
      "operations": [8, 10, 11, 12, 24, 30],
      "object_grants": [
        {"owner": "orders-db", "identifier": "<unique identifier>", "operations": [8, 10, 11, 12]}
      ]
    }
  }
}
```

### Operation numbers

| # | Operation | # | Operation | # | Operation |
| --- | --- | --- | --- | --- | --- |
| 1 | Create | 21 | Archive | 41 | Join Split Key (1.2) |
| 2 | Create Key Pair | 22 | Recover | 42 | Import (1.4) |
| 3 | Register | 23 | Validate | 43 | Export (1.4) |
| 4 | Re-key | 24 | Query | 44 | Log (2.0) |
| 5 | Derive Key | 25 | Cancel | 45 | Login (2.0) |
| 6 | Certify | 26 | Poll | 46 | Logout (2.0) |
| 7 | Re-certify | 27 | Notify | 47 | Delegated Login (2.0) |
| 8 | Locate | 28 | Put | 48 | Adjust Attribute (2.0) |
| 9 | Check | 29 | Re-key Key Pair (1.1) | 49 | Set Attribute (2.0) |
| 10 | Get | 30 | Discover Versions (1.1) | 50 | Set Endpoint Role (2.0) |
| 11 | Get Attributes | 31 | Encrypt (1.2) | 51 | PKCS#11 (2.0) |
| 12 | Get Attribute List | 32 | Decrypt (1.2) | 52 | Interop (2.0) |
| 13 | Add Attribute | 33 | Sign (1.2) | 53 | Re-Provision (2.0) |
| 14 | Modify Attribute | 34 | Signature Verify (1.2) | 54 | Set Defaults (2.1) |
| 15 | Delete Attribute | 35 | MAC (1.2) | 55 | Set Constraints (2.1) |
| 16 | Obtain Lease | 36 | MAC Verify (1.2) | 56 | Get Constraints (2.1) |
| 17 | Get Usage Allocation | 37 | RNG Retrieve (1.2) | 57 | Query Asynchronous Requests (2.1) |
| 18 | Activate | 38 | RNG Seed (1.2) | 58 | Process (2.1) |
| 19 | Revoke | 39 | Hash (1.2) | 59 | Ping (2.1) |
| 20 | Destroy | 40 | Create Split Key (1.2) | 60–66 | 3.0 draft, below |

The version in parentheses is the first KMIP edition with the operation. The
3.0 draft adds 60 Create Group, 61 Obliterate, 62 Create User, 63 Create
Credential, 64 Deactivate, 65 Encapsulate and 66 Decapsulate. Which of them
the server implements is in [project status](status.md#operations-per-edition).

### Role templates

The `operations` list for common roles, by [operation number](#operation-numbers):

| Role | Operations |
| --- | --- |
| Percona Server for MongoDB, or an application that creates and reads keys | `[1, 3, 8, 10, 11, 12, 18, 24, 30]` |
| Percona Server for MySQL (`component_keyring_kmip`) | the list above plus `19, 20` |
| Application that encrypts on the server | `[8, 11, 24, 30, 31, 32]` |
| Application that signs on the server | `[8, 11, 24, 30, 33, 34]` |
| Read-only reader of granted objects | `[8, 10, 11, 12, 24, 30]` plus `object_grants` |
| Key administrator (separate certificate, same principal) | the first list plus `13, 14, 15, 19, 20` |

- The first list is Create, Register, Locate, Get, Get Attributes, Get
  Attribute List, Activate, Query and Discover Versions: no Revoke, Destroy or
  Import.
- Percona Server for MySQL revokes and destroys keys for `keyring_key_remove`
  and for its scratch keys during `ALTER INSTANCE ROTATE BINLOG MASTER KEY`;
  without Revoke and Destroy those fail.
- The two server-side roles use keys and never fetch or change them: no Get,
  and no attribute changes, which could set Extractable back to True
  ([attributes](attributes.md#changing-attributes)). Give the application its
  own certificate under the principal name that owns the keys. Create and
  activate the keys with a separate certificate holding the first list, plus
  `2` (Create Key Pair) for signing keys. An object grant cannot allow
  Encrypt or Sign.
- A reader needs its own principal name: sharing the owner's name shares the
  owner's objects.
- The administrator list adds attribute changes, Revoke and Destroy. Add
  `48, 49` (Adjust and Set Attribute) for KMIP 2.x clients that change
  attributes that way, and `21, 22` (Archive, Recover) or `42` (Import) only
  for the procedures that need them.

The database lists cover the operations the Percona runs observed; those runs
granted every operation, so a policy restricted to exactly these lists has not
been tested with Percona. Import (42) can replace an owned object's material,
dates, state and budgets: treat it as restore authority. Interop (52) also needs
`--interop-test-mode`.

Set Defaults (54) and a KMIP 2.1 Set Constraints (55) change
[server-wide settings](defaults-and-constraints.md) for every principal. Grant both only
to an administrative certificate, never to an application role. Get Constraints (56) only reads the set.

The quick start's `scripts/dev-pki.sh` policy grants its `client` certificate
every operation (1–66). It is for tests: do not copy its entries into a real
policy.

## Fixed limits

| Limit | Value |
| --- | --- |
| Binary request frame | 1 MiB |
| JSON/XML request or response | 8 MiB, depth 32, 16,384 nodes |
| HTTP headers | 16 KiB, 64 headers |
| Batch items per request | 128 |
| Key pairs generated per batch (Create Key Pair and Re-key Key Pair, any algorithm) | 4 |
| RNG Retrieve output | 64 KiB |
| TLS handshake; rest of a binary frame after its first 8 bytes; HTTP headers; HTTP body; write | 10 s each |
| Locate results per request (Maximum Items) | 1,000, also the default; page with Offset Items ([Locate](locate.md#results)) |
| Locate Offset Items | 100,000 |
| HTTPS requests in progress | 4 at once, from the request body to the end of the response, across all HTTPS connections; another gets HTTP 503 at once. `--max-connections` does not raise it. |
| Client certificate chain in the TLS handshake | 4 intermediate CA certificates below a `--ca` certificate |
| Validate chains and the `--validation-ca` bundle | 32 certificates, 64 KiB per certificate, 1 MiB per bundle; separate from the handshake limit |
| Object grants per certificate | 256 |
| Header-credential password | 1 KiB |
| Wait for the one request of a certificate the CA trusts but the policy does not list | 30 s, whatever `--idle-timeout` says |

Between requests, a listed client's connection waits under `--idle-timeout`
instead: for the
first 8 bytes of a binary frame, or the first byte of an HTTP request. The
10 s deadline starts once those arrive.

These bound denial of service; throughput and capacity have not been
measured ([known gaps](status.md#known-gaps)). Per-batch and per-operation
limits are on their pages:
[batches and expanded items](messages.md#batches),
[asynchronous requests](messages.md#asynchronous-requests),
[Derive Key](crypto-operations.md#derive-key),
[multipart streams](crypto-operations.md#multipart-operations),
[split keys](objects.md#split-keys) and
[expensive key imports](algorithms.md#rsa).

## Logging

Logs are JSON lines on standard output, one object per event. The level
defaults to `info`; set `RUST_LOG` (for example `RUST_LOG=debug` or
`RUST_LOG=keytend_kmip_server=debug`) to change it. Logs do not intentionally
contain request bodies, key material or cryptographic input or output.

Every event is one line with the same shape: `timestamp`, `level` (`ERROR`,
`WARN`, `INFO`, `DEBUG`), `fields` with `message` and the event's own fields,
and `target`. Filter on `level` and `fields.message`.

`KMIP listener ready` is logged once per start, when the server is ready,
after any FIPS provider messages and configuration warnings. It reports the
version and every `serve` setting except file paths:

- Each field is the flag's name with `_` for `-` (`--idle-timeout` is
  `idle_timeout`), with the value in its command-line spelling;
  `https_listen` is `off` without an HTTPS listener, and `ec_curves` is
  `nist` in FIPS mode.
- The certificate, key, CA bundle, policy, master key and database are not
  logged. For the optional files (`users`, `crl`, `validation_ca`,
  `provisioning` for `--provisioning-ca` and its key, `audit_checkpoint`) it
  logs only whether each is set (`true` or `false`).
- The thirteen element forms are folded into `text_encoding`: the preset, or
  every element form as `option=value` (for example
  `json-tags=hex,json-enumerations=name,…`) when an element option changes it.

To print some fields of the latest start of the
[quick-start container](quick-start.md), here started from the signed
0.10.0-rc.1 release (a local `:dev` build prints the next version with `-dev`):

```sh
docker logs keytend-kmip-server | python3 -c '
import json, sys
events = (json.loads(line) for line in sys.stdin if line.startswith("{"))
ready = [e["fields"] for e in events if e["fields"].get("message") == "KMIP listener ready"]
for name in sys.argv[1:]: print(name, ready[-1][name])
' version listen https_listen tls_profile max_connections
```

```text
version 0.10.0-rc.1
listen 0.0.0.0:5696
https_listen 0.0.0.0:5697
tls_profile modern
max_connections 64
```

Messages worth alerting or searching on (`fields.message`):

| Message | Level | Meaning |
| --- | --- | --- |
| `KMIP listener ready` | info | Startup finished; the fields are the settings in effect ([above](#logging)). |
| `Connection lifecycle counters` | info | [Connection counters](metrics.md#connection-counters); `phase` is `periodic` or `shutdown`. |
| `Draining connections` | info | SIGTERM or Ctrl-C received; see [shutdown](operations.md#shutdown-and-restarts). |
| `FIPS mode: OpenSSL FIPS provider loaded` | info | FIPS mode started, with the provider's name, version and status. |
| `KMIP internal operation failed` | error | A request failed inside the server (General Failure to the client). |
| `object census failed; kmip_objects keeps the previous census` | warn | The metrics census could not read the store. |
| `server-to-client message delivered`, `… not sent`, `… delivery failed` | info, warn | [Notify and Put](server-to-client.md) outcomes. |
| `certificate issued`, `certificate renewed`, `certificate issuance failed` | info, warn | [Certify and Re-certify](certificates.md#certify-and-re-certify). |
| `peer certificate refused by the TLS profile` | warn | A client certificate failed the selected [TLS profile](tls-profiles.md). |

There is **no per-request access log**: successful KMIP operations are not
logged. Each processed batch item, refused ones included, is recorded in the
HMAC-authenticated audit chain (not encrypted: time, principal, operation,
object identifier and result), which `check-store` verifies but which no
command exports. A request rejected before its batch items run (a TLS or HTTP
refusal, an undecodable message, failed header credentials) leaves no audit
record. Use the
[metrics](metrics.md) for request volume and failure reasons. Messages sent
with the KMIP Log operation appear under target `kmip::client_log`.
