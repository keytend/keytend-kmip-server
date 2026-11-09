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

# Prometheus metrics

Part of [configuration and operations](README.md#configuration-and-operations).

`GET /metrics` on the health listener (`--health-listen`, default
`0.0.0.0:8080`) returns operator metrics in the Prometheus text exposition
format 0.0.4 (`Content-Type: text/plain; version=0.0.4; charset=utf-8`). The
KMIP listeners (5696 binary TTLV, 5697 HTTPS) never serve it.

- [Settings](#settings)
- [What is exposed](#what-is-exposed): [build and process](#build-and-process),
  [store](#store), [requests and leases](#requests-and-leases),
  [objects](#objects-census), [connections and TLS](#connections-and-tls)
- [Scraping](#scraping), [alerts](#alerts),
  [lease-outage alerts](#lease-outage-alerts)
- [Cost](#cost), [known limits](#known-limits)

## Settings

| Setting (environment) | Values | Default | Notes |
| --- | --- | --- | --- |
| `--metrics` (`KMIP_METRICS`) | `on`, `off` | `on` | `off`: `/metrics` answers 404 and no object census runs. |
| `--metrics-object-census-interval` (`KMIP_METRICS_OBJECT_CENSUS_INTERVAL`) | `0`, or `10`–`86400` | `300` | Seconds between object censuses; `0` runs none (no `kmip_objects` families). |

`/livez`, `/readyz`, `/connection-metrics` and
`keytend-kmip-server healthcheck` work with either value. Metrics are on by
default because they carry no key material, identifiers or names (below).
Set `off` where even aggregate request volume and failure mix must not be
readable on the health port.

## What is exposed

Label values derived from requests come from fixed tables in the server, so
clients cannot create series: an operation, protocol version or result reason
the tables do not name is counted as `unknown`, and a response item without
an Operation field as `none`. The build and provider labels describe the
executable and OpenSSL ([build and process](#build-and-process)).

### Build and process

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kmip_build_info` | gauge (1) | `version`, `commit`, `binary_sha256`, `openssl`, `fips_mode` | Version, commit, executable digest and linked OpenSSL (below). |
| `kmip_fips_mode` | gauge | | 1 in FIPS mode. |
| `kmip_fips_provider_info` | gauge (1) | `provider`, `name`, `version`, `build_info` | FIPS mode only: the loaded `fips` and `base` providers (below). |
| `kmip_fips_provider_status` | gauge | `provider` | FIPS mode only: provider status read at each scrape: 1 running, 0 error state, -1 not reported. |
| `process_start_time_seconds` | gauge | | Start time. |
| `kmip_uptime_seconds` | gauge | | Uptime. |
| `kmip_ready` | gauge | | 1 when `/readyz` would answer 200 (engine available, live-history check passes). |

`kmip_build_info`'s `commit` is `unknown` in the image build, and
`binary_sha256` (the SHA-256 of the running executable) is `pending` just
after start. `kmip_fips_provider_info` labels the providers as they report
themselves, as `keytend-kmip-server --fips fips-check` prints them.

### Store

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kmip_store_verified_timestamp_seconds` | gauge | | When the audit chain and object state index were verified. This happens at start only; a failure stops the server. |
| `kmip_store_audit_checkpoint_verified` | gauge | | 1 when `--audit-checkpoint` was given and verified at start. |
| `kmip_last_backup_timestamp_seconds` | gauge | | When the last successful `backup` of the database was taken, read at each scrape from `<database>.last-backup`, which `backup` writes when it can write to the database's directory ([backup](backup-restore.md#back-up)). 0 when none is recorded. Alert when it is older than your backup interval. |
| `kmip_store_database_bytes` | gauge | | SQLite page count times page size (main file; the WAL is excluded). |
| `kmip_store_free_bytes` | gauge | | SQLite free-list size times page size. |

### Requests and leases

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kmip_requests_total` | counter | `version`, `encoding` | Request messages answered, by response version and encoding (below). |
| `kmip_requests_unanswered_total` | counter | `encoding` | Request messages the engine could not answer with KMIP (no conforming response fitted, or an internal failure closed the exchange). |
| `kmip_operations_total` | counter | `version`, `encoding`, `operation`, `status`, `reason` | One per response batch item, labelled with KMIP names (below). |
| `kmip_request_duration_seconds` | histogram | `operation` | Engine time per request message, 0.5 ms to 10 s (below). |
| `kmip_request_batch_items` | histogram | | Batch items per answered message (buckets 1 to 128). |
| `kmip_lease_max_seconds` | gauge | | `--max-lease-seconds` (0: no lease limit). |
| `kmip_leases_granted_total` | counter | | Obtain Lease items that succeeded. |
| `kmip_leases_refused_total` | counter | `reason` | Obtain Lease items that failed, by Result Reason. |

- `version` is the response header's protocol version; `encoding` is `ttlv`,
  `json` or `xml`, the HTTPS response encoding (the binary listener is always
  `ttlv`).
- `kmip_operations_total` labels use KMIP names, for example
  `reason="ItemNotFound"` (`none` when absent). An asynchronous submission
  counts once, as `OperationPending`.
- `kmip_request_duration_seconds` times the engine only: a multi-item message
  is one sample with `operation="batch"`, and TLS, framing, the engine lock
  wait and header-credential derivation are excluded.

### Objects (census)

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kmip_objects` | gauge | `type`, `state` | Objects by Object Type and State at the last census. The server's own records (server defaults and constraints, 3.0 owner constraints, Re-Provision fingerprint records) count as `type="unknown"`. |
| `kmip_objects_unreadable` | gauge | | Records the last census could not authenticate (AES-256-GCM tag bound to owner and identifier) or parse. Should be 0; otherwise run `check-store`. |
| `kmip_object_census_timestamp_seconds` | gauge | | When the last census finished. |
| `kmip_object_census_duration_seconds` | gauge | | How long it took. |
| `kmip_object_census_interval_seconds` | gauge | | The census interval setting. |

### Connections and TLS

| Family | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `kmip_connections_accepted_total` | counter | `listener` (`ttlv`, `https`) | Connections accepted. |
| `kmip_connections_closed_total` | counter | `listener` | Connections closed. |
| `kmip_connections_errored_total` | counter | `listener` | Connections that ended with an error (handshake, refused certificate, framing, timeout, I/O). |
| `kmip_connections_cancelled_total` | counter | `listener` | Connections cancelled before they finished (shutdown drain). |
| `kmip_connections_active` | gauge | `listener` | Open connections. |
| `kmip_connections_idle_closed_total` | counter | `listener` | Closed after `--idle-timeout`. |
| `kmip_connections_refused_unlisted_total` | counter | `listener` | CA-valid certificate without a policy entry, or one a Re-Provision retired: one Permission Denied answer, then closed. |
| `kmip_tls_handshakes_total` | counter | `listener` | Handshakes started. |
| `kmip_tls_handshakes_succeeded_total` | counter | `listener` | Handshakes completed. |
| `kmip_tls_handshake_failures_total` | counter | `listener`, `reason` | Failed handshakes by [reason](#tls-handshake-failure-reasons). |

Admission to `--max-connections`, the same values as
[`/connection-metrics`](#connection-counters), all without labels:

| Family | Type | Meaning |
| --- | --- | --- |
| `kmip_connections_max` | gauge | The `--max-connections` setting. |
| `kmip_connections_peak_active` | gauge | Most connections open at once since start. |
| `kmip_connections_accept_errors_total` | counter | Failed `accept()` calls on the KMIP listeners. |
| `kmip_connection_admission_waits_total` | counter | Times the accept loop waited for a free connection slot. |
| `kmip_connection_admission_waiting` | gauge | 1 while the accept loop waits for a free slot. |
| `kmip_connection_admission_wait_seconds_total` | counter | Total time the accept loop waited. |

Never exposed: key material, object identifiers, principal or user names,
certificate subjects or fingerprints, Names, attribute values, peer addresses,
request contents and error messages.

### TLS handshake failure reasons

Classified from OpenSSL reason strings; nothing from the peer is copied.

| `reason` | Meaning |
| --- | --- |
| `no_client_certificate` | The client sent no certificate. |
| `certificate_rejected` | The client chain, CRL or expiry check failed. |
| `peer_alert` | The client aborted, for example because it does not trust the server certificate. |
| `protocol_version` | No common TLS version. |
| `no_shared_parameters` | No common suites, groups or signature algorithms. |
| `not_tls` | Plaintext or HTTP on the TLS port. |
| `timeout` | The 10-second handshake deadline passed. |
| `cancelled` | The server was shutting down. |
| `connection_closed`, `other` | Anything else. |

### Connection counters

`GET /connection-metrics` on the health listener returns the listeners'
connection counters as one JSON object, each a total over both listeners:

```json
{
  "accept_error_total": 0,
  "active": 0,
  "admission_wait_ns_total": 0,
  "admission_wait_total": 0,
  "admission_waiting": 0,
  "cancelled_total": 0,
  "clean_total": 16,
  "closed_total": 16,
  "error_total": 0,
  "https_accepted_total": 12,
  "idle_timeout_total": 0,
  "lifetime_timeout_total": 0,
  "max_connections": 64,
  "peak_active": 1,
  "tcp_accepted_total": 16,
  "tls_cancelled_total": 0,
  "tls_failed_total": 0,
  "tls_started_total": 16,
  "tls_succeeded_total": 16,
  "tls_timeout_total": 0,
  "ttlv_accepted_total": 4,
  "ttlv_responses_total": 14
}
```

The metrics above carry the same counts per listener:

| Field | Metric |
| --- | --- |
| `tcp_accepted_total`, `ttlv_accepted_total`, `https_accepted_total` | `kmip_connections_accepted_total` (all, `listener="ttlv"`, `listener="https"`) |
| `active`, `peak_active`, `max_connections` | `kmip_connections_active`, `kmip_connections_peak_active`, `kmip_connections_max` |
| `closed_total` | `kmip_connections_closed_total` |
| `error_total` | `kmip_connections_errored_total` |
| `idle_timeout_total` | `kmip_connections_idle_closed_total` |
| `cancelled_total` | `kmip_connections_cancelled_total` |
| `clean_total` | connections closed without an error (no metric) |
| `accept_error_total` | `kmip_connections_accept_errors_total` |
| `tls_started_total`, `tls_succeeded_total` | `kmip_tls_handshakes_total`, `kmip_tls_handshakes_succeeded_total` |
| `tls_failed_total`, `tls_timeout_total`, `tls_cancelled_total` | `kmip_tls_handshake_failures_total`: every `reason` except `timeout` and `cancelled`; `reason="timeout"`; `reason="cancelled"` |
| `ttlv_responses_total` | binary KMIP responses written (no metric) |
| `admission_wait_total` | `kmip_connection_admission_waits_total` |
| `admission_waiting` | `kmip_connection_admission_waiting` |
| `admission_wait_ns_total` | `kmip_connection_admission_wait_seconds_total` (in seconds) |
| `lifetime_timeout_total` | reserved, always 0: there is no overall connection lifetime |

The server also logs the object as `Connection lifecycle counters` every 30
seconds (`"phase":"periodic"`, the first right after `KMIP listener ready`)
and at shutdown (`"phase":"shutdown"`). In the log line the whole object is
one JSON string in `fields.counters`: parse that string to read a counter.

## Scraping

### Network exposure

The health listener is plain, unauthenticated HTTP on
`--health-listen` (default `0.0.0.0:8080`), the same listener as `/livez`,
`/readyz` and `/connection-metrics`; KMIP ports never serve metrics. Keep it on
a management network: the [container example](quick-start.md#run-the-container) publishes it on
`127.0.0.1:8080` only. Metrics carry no secrets, but they reveal request
volume, the version and operation mix, failure reasons and object counts per
type.

### Kubernetes

The [chart](kubernetes.md#monitoring) annotates the pod with
`prometheus.io/scrape: "true"`, `prometheus.io/port: "8080"` and
`prometheus.io/path: /metrics`, names its port 8080 `health` (the Services
publish the KMIP ports only), and with `metrics.podMonitor.enabled` creates a
Prometheus Operator PodMonitor whose `job` label is `keytend-kmip-server`, as
the alert rules below expect. Your Prometheus resource must select it (its
`podMonitorSelector` and `podMonitorNamespaceSelector`; set
`metrics.podMonitor.labels`). Without the operator, a scrape job:

```yaml
scrape_configs:
  - job_name: keytend-kmip-server
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: [keytend-kmip-server]
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_component, __meta_kubernetes_pod_container_port_name]
        regex: server;health
        action: keep
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
```

Either way, the chart's NetworkPolicy admits port 8080 only from
`networkPolicy.metrics`: by default pods labelled
`access: keytend-kmip-server-metrics` in namespaces labelled
`kmip-metrics: "true"`. Label the Prometheus namespace and pods, or change
the selectors. Kubelet probes reach `/readyz` and `/livez` from the node;
whether the NetworkPolicy applies to node-originated traffic depends on the
CNI, so test both the probes and the scrape after applying the policy.

## Alerts

[`deploy/prometheus/keytend-kmip-server-rules.yaml`](../deploy/prometheus/keytend-kmip-server-rules.yaml)
holds suggested alert rules, ready for a Prometheus `rule_files` entry or a
PrometheusRule resource; the chart's `metrics.prometheusRule.enabled` creates
that resource for the release's namespace and volume, with `KmipBackupStale`
added for its [backups](backup-restore.md#scheduled-backups-on-kubernetes). Adjust `job` to your scrape configuration and the
thresholds to your traffic. For example, the first rule:

```yaml
      - alert: KmipServerDown
        expr: up{job="keytend-kmip-server"} == 0 or kmip_ready == 0 or absent(up{job="keytend-kmip-server"})
        for: 2m
```

`absent()` covers a target that disappears: when Kubernetes discovery drops
the only pod, `up` and `kmip_ready` have no series at all, and the first two
conditions match nothing.

| Rule | Fires when | Tune |
| --- | --- | --- |
| `KmipServerDown`, `KmipLeaseOutageBudget` | Down, not ready or not scraped for 2 or 15 minutes | The second's `for` from the Lease Time ([below](#lease-outage-alerts)) |
| `KmipLeaseTimeChanged` | `--max-lease-seconds` changed | Then update `KmipLeaseOutageBudget` |
| `KmipFipsProviderError` | The FIPS provider is in its error state | |
| `KmipUnansweredRequests`, `KmipServerSideFailures` | Internal failures, in 10 minutes | |
| `KmipLeaseRefusals` | A client renews a lease on an object it can no longer use | |
| `KmipCertificateTrouble` | Rejected, missing or unlisted client certificates, in 15 minutes | |
| `KmipConnectionCapacity`, `KmipConnectionAdmissionWaiting` | Over 80% of `--max-connections` for 10 minutes; connections waiting for 5 | The 0.8 ratio |
| `KmipStoreIntegrity`, `KmipCensusStalled` | A record does not authenticate; the census is stuck | |
| `KmipDiskGrowth` | The database will pass 80% of 10 Gi within 7 days | Your volume size |
| `KmipVolumeFreeSpace` | Under 20% free on the PVC (kubelet metrics) | Only where Prometheus scrapes the kubelet |
| `KmipBackupStale` (chart only) | No successful backup for 26 hours, or none since a start 26 hours ago | `metrics.prometheusRule.backupMaxAgeSeconds` |

`kmip_store_database_bytes` counts the main database file only, not its WAL
or backups written into the volume, so keep the volume free-space rule (or
your platform's equivalent) as well.

### Lease-outage alerts

From [Lease Time and KMS outages](operations.md#lease-time-and-kms-outages): a
lease-honouring client stops using an object when its lease ends, counted
from its last successful renewal. With Lease Time `L`
(`kmip_lease_max_seconds`) and clients that renew at fraction `r` of the lease
(commonly `r = 0.5`), a client has at least `(1 - r) * L` left when an outage
begins. Page early enough to restore within that budget, including a restore
from backup:

- Page when the server has been unavailable for half the guaranteed
  remainder: `for: (1 - r) * L / 2` on the down condition
  (`KmipLeaseOutageBudget`). For the default `L = 3600` s and `r = 0.5`, that
  is `for: 15m`, leaving 15 minutes before the first clients stop. The `for`
  duration is static: update the rule when `--max-lease-seconds` changes
  (`KmipLeaseTimeChanged` reminds you).
- Alert on missing renewals while the server is up:
  `sum(increase(kmip_leases_granted_total[<renewal interval> * 2])) == 0` where
  clients are known to renew, since a network or policy change can stop them
  reaching the server without the server going down.
- `kmip_lease_max_seconds == 0` means no lease limit: outages do not stop
  clients, and no lease alert is needed, but use after Destroy is unbounded.

Objects created before a `--max-lease-seconds` change keep their stored Lease
Time, and a Deactivation Date or Protect Stop Date can end an Active lease
sooner. Size the `for` duration for the shortest effective lease still in use,
so the alert fires before the first clients stop.

## Cost

Counters cost one small lock per message. The object census decrypts every
object record each interval, 256 per engine lock, so requests interleave with
it; watch `kmip_object_census_duration_seconds` and raise the interval (or set
`0`) for very large stores.

## Known limits

- The alert rules have not been run against a live Prometheus scrape of a
  deployment.
- The store's audit chain and object index are verified in full at start
  only, so `kmip_store_verified_timestamp_seconds` is the start time. The
  [live history check](store-integrity.md#live-history-check) runs on every
  request but does not rescan older history; `check-store` remains the full
  check.
- Latency is per message, not per batch item, and excludes lock wait.
- Deferred asynchronous runs and server-to-client deliveries are not counted.
- `commit` is `unknown` unless the build sets `KEYTEND_KMIP_SERVER_COMMIT`; use
  `binary_sha256` to match a running server to a build or to test evidence.
