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

# Percona database encryption

Part of [integrations](README.md#integrations).

Configuration for using keytend-kmip-server as the key manager of Percona
Server for MongoDB 8.0 (tested with 8.0.34-15) and Percona Server for MySQL
8.4 (tested with 8.4.11-11). Give each database its own client certificate and
principal with its [role](configuration.md#role-templates): operations
`[1, 3, 8, 10, 11, 12, 18, 24, 30]` for MongoDB, and the same plus Revoke (19)
and Destroy (20) for MySQL, whose component removes keys.

## Percona Server for MongoDB

```yaml
security:
  enableEncryption: true
  kmip:
    serverName: keytend-kmip-server.keytend-kmip-server.svc.cluster.local
    port: 5696
    serverCAFile: /etc/kmip/server-ca.pem
    clientCertificateFile: /etc/kmip/client-chain-and-key.pem
    activateKeys: true
    keyStatePollingSeconds: 30
```

- `clientCertificateFile` holds the client certificate chain followed by its
  private key, in one PEM file. With the names of
  [issuing certificates](tls-setup.md#issuing-them-with-openssl), and
  `ca.pem` as `serverCAFile`:

  ```sh
  (umask 077; cat orders-db.pem orders-db.key > client-chain-and-key.pem)   # intermediates go after orders-db.pem
  ```

- The server certificate needs a subject alternative name for `serverName`.
- Without `keyIdentifier`, the database registers a new master key on first
  start and remembers its identifier. `db.serverStatus().encryptionAtRest`
  shows it.
- To rotate the database master key, use Percona's offline procedure: stop
  `mongod`, run it once with `--kmipRotateMasterKey` and the same data
  directory and KMIP settings, let it exit, and start it normally. The old key
  stays on the server; keep it for as long as backups need it.
- With `keyStatePollingSeconds`, `mongod` polls the key state and shuts down
  when its master key is no longer Active (revoked or compromised), so
  revoking the key takes that database offline.
- During a KMIP outage a running `mongod` keeps its cached key, so a
  revocation takes effect only when it can poll again.

## Percona Server for MySQL

Load `component_keyring_kmip` with a global manifest `mysqld.my` next to the
`mysqld` binary:

```json
{"components": "file://component_keyring_kmip"}
```

and configure it in `component_keyring_kmip.cnf` in the plugin directory:

```json
{
  "server_addr": "keytend-kmip-server.keytend-kmip-server.svc.cluster.local",
  "server_port": "5696",
  "client_ca": "/etc/kmip/client.pem",
  "client_key": "/etc/kmip/client.key",
  "server_ca": "/etc/kmip/server-ca.pem",
  "object_group": "mysql-primary",
  "tls_peer_verification": true,
  "tls_hostname_verification": true
}
```

- `client_ca` is the client **certificate** (the component's name for it).
- Set both verification options to `true`: in 8.4.11 they default to `false`,
  and the component then accepts any server.
- The component keeps one connection open and does not reconnect after the
  server closes it for idleness: the next keyring write fails. Set the
  server's `--idle-timeout` above the database's longest quiet period, or to
  `0` ([settings](configuration.md#listeners-tls-and-identity)).
- `keyring_key_remove` revokes and destroys the key, and
  `ALTER INSTANCE ROTATE BINLOG MASTER KEY` destroys and re-registers fixed
  scratch key names: grant Revoke and Destroy, and keep the server's default
  `--destroyed-name-reuse allow`.
- After a restart the component still uses a master key the server reports as
  Compromised; enforce compromise by rotating
  (`ALTER INSTANCE ROTATE INNODB MASTER KEY`) and re-encrypting.

### Check the keyring

In `mysql`, after the first start:

```sql
SELECT STATUS_KEY, STATUS_VALUE FROM performance_schema.keyring_component_status
  WHERE STATUS_KEY IN ('Component_status', 'Tls_peer_verification', 'Tls_hostname_verification');
CREATE DATABASE kmip_check;
CREATE TABLE kmip_check.t (id INT PRIMARY KEY) ENCRYPTION='Y';
SELECT NAME, ENCRYPTION FROM information_schema.INNODB_TABLESPACES WHERE NAME = 'kmip_check/t';
ALTER INSTANCE ROTATE INNODB MASTER KEY;
```

- `Component_status` is `Active`, and both verification values are `true`.
- The first encrypted table makes InnoDB register its master key on the
  server, an Active AES-256 key in the configured `object_group`, and the
  tablespace shows `ENCRYPTION` `Y`.
- The rotation registers the next master key; the previous one stays Active.
- The keys are named `INNODBKey-<server_uuid>-<n>` (`SELECT @@server_uuid`),
  so a Locate by that Name with the database's certificate finds each one.

## What was tested

- MongoDB: encrypted writes; restarts of the KMIP server and the database;
  backup and restore of the KMIP store; database and storage master-key
  rotation; refusal of untrusted, unlisted and unauthorized certificates;
  shutdown after key compromise; three-member replica sets; and Percona Backup
  for MongoDB 2.17.0 physical and point-in-time restores, including a damaged
  oplog chain and an interrupted restore.
- MySQL: encrypted tables, undo, redo and binary logs; restarts; InnoDB
  master-key rotation; refusal of a wrong CA, wrong hostname and unlisted or
  unauthorized certificates.

Production topologies, capacity and cluster-wide point-in-time recovery are
not qualified ([project status](status.md#what-has-been-tested)).
