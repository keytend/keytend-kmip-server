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

# Kubernetes

Part of [configuration and operations](README.md#configuration-and-operations).

How to run keytend-kmip-server on Kubernetes with the Helm chart in
[`deploy/helm/keytend-kmip-server`](../deploy/helm/keytend-kmip-server/README.md).
The chart runs one replica with its SQLite store on a ReadWriteOnce volume,
a daily backup CronJob, a backup before every upgrade and rollback, and
restore, master-key rotation and maintenance mode set through Helm values. The inputs (certificates,
policy, master key) are described in
[deployment](deployment.md#what-you-deploy); backups, upgrades and other
tasks after installation are in
[operations](operations.md), [backup and restore](backup-restore.md#on-kubernetes)
and [master-key rotation](master-key-rotation.md#on-kubernetes).

> [!NOTE]
> The chart is tested on a single-node kind cluster
> ([testing](testing.md#kubernetes-on-kind)); multi-node placement,
> NetworkPolicy enforcement, cert-manager and the Prometheus Operator
> resources are not.

- [Install](#install)
- [Clients outside the cluster](#clients-outside-the-cluster)
- [Settings and extra files](#settings-and-extra-files)
- [cert-manager](#cert-manager)
- [Startup time and the startup probe](#startup-time-and-the-startup-probe)
- [Monitoring](#monitoring)
- [Availability and node maintenance](#availability-and-node-maintenance)
- [Secrets and FIPS](#secrets-and-fips)
- [Removing the server](#removing-the-server)
- [Without Helm, and GitOps](#without-helm-and-gitops)

## Install

You need:

- Kubernetes 1.27 or later;
- Helm 4 (tested with 4.3.1) and `kubectl`, with rights to create the
  chart's resources in a namespace;
- the server image, in a registry the nodes can pull from
  ([copying a release to a registry](release-signing.md#getting-the-image-into-a-registry))
  or loaded into the nodes (kind, below);
- a StorageClass with working file locks and fsync (not NFS) for two
  ReadWriteOnce volumes: the data volume (10 Gi) and the backup volume (20 Gi);
- a CNI that enforces NetworkPolicy, or the chart's policy has no effect;
- your `server.pem`, `server.key`, `ca.pem`, `master.key` and `policy.json`
  ([TLS certificates and policy](tls-setup.md)). The server certificate must
  name `keytend-kmip-server`, `keytend-kmip-server.<namespace>.svc` and
  `keytend-kmip-server.<namespace>.svc.cluster.local`
  ([server certificate](tls-setup.md#server-certificate)); `helm test` dials
  the first.

Run from the directory that holds the `keytend-kmip-server` checkout and
those files. The chart creates no Secrets: create them first, with a version
in the master key's name so that a [rotation](master-key-rotation.md#on-kubernetes)
can add the next one:

```sh
NS=keytend-kmip-server
CHART=keytend-kmip-server/deploy/helm/keytend-kmip-server
kubectl create namespace $NS
kubectl label namespace $NS pod-security.kubernetes.io/enforce=restricted
kubectl -n $NS create secret generic kmip-tls \
  --from-file=server.pem --from-file=server.key --from-file=ca.pem
kubectl -n $NS create secret generic kmip-master-v1 --from-file=master.key
kubectl -n $NS create configmap kmip-policy --from-file=policy.json
```

Write the values that stay the same for every upgrade to `kmip-values.yaml`;
every `helm upgrade` on these pages passes it:

```yaml
image:
  repository: registry.example.com/keytend-kmip-server
  digest: sha256:<image digest>
masterKey:
  existingSecret: kmip-master-v1
tls:
  existingSecret: kmip-tls
policy:
  existingConfigMap: kmip-policy
```

Install, wait for the pod and run the chart's test. The test sends one KMIP
Query over HTTPS with a client certificate from the policy and passes only on
Result Status Success (HTTP 200 also carries KMIP failures); give it a
certificate whose policy entry allows Query (24):

```sh
kubectl -n $NS create secret generic kmip-test-client \
  --from-file=client.pem=orders-db.pem --from-file=client.key=orders-db.key \
  --from-file=ca.pem=ca.pem      # the CA that signed the server certificate
helm install keytend-kmip-server $CHART -n $NS -f kmip-values.yaml \
  --set tests.clientSecret=kmip-test-client --wait
helm test keytend-kmip-server -n $NS --logs
```

```text
…"tag":"ResultStatus","type":"Enumeration","value":"0x00000000"…
KMIP Query succeeded
```

The test expects the default `compatible` [JSON encoding](encodings.md#response-forms). If
`server.env` sets `KMIP_TEXT_ENCODING` to `readable` or `hex`, or changes
`KMIP_JSON_TAGS` or `KMIP_JSON_ENUMERATIONS`, the test fails even when the
Query succeeds.

Put `tests.clientSecret` into `kmip-values.yaml` to keep the test. Without a
registry (for example on kind), load the image into the nodes and use the
local tag:

```sh
kind load docker-image localhost/keytend-kmip-server:dev
# Podman without the docker command (KIND_EXPERIMENTAL_PROVIDER=podman):
podman save --format docker-archive -o kmip-image.tar localhost/keytend-kmip-server:dev &&
  kind load image-archive kmip-image.tar
```

```yaml
image:
  repository: localhost/keytend-kmip-server
  tag: dev
```

If the registry needs credentials, create a pull Secret and name it in
`image.pullSecrets`:

```sh
kubectl -n $NS create secret generic registry-credentials \
  --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson="$HOME/.docker/config.json"
```

With Podman the login is in `${XDG_RUNTIME_DIR}/containers/auth.json`.

### Client namespaces

By default the NetworkPolicy admits ports 5696 and 5697 only from pods
labelled `access: keytend-kmip-server` in namespaces labelled
`kmip-client: "true"` (`networkPolicy.clients` changes the selectors). For a
client namespace `orders`:

```sh
kubectl create namespace orders     # if it does not exist yet
kubectl label namespace orders kmip-client=true
# and in the client's pod template: metadata.labels.access: keytend-kmip-server
```

Clients dial `keytend-kmip-server.keytend-kmip-server.svc:5696` (or `:5697`
for HTTPS) with a client certificate from the policy. To check a client
certificate and the labels from the client's namespace, put the certificate in
a Secret and run the [check pod](../deploy/kubernetes/tools/kmip-check.yaml)
(it reads `client.pem`, `client.key` and `ca.pem` from the Secret
`orders-db-kmip` in `orders`):

```sh
kubectl -n orders create secret generic orders-db-kmip \
  --from-file=client.pem=orders-db.pem --from-file=client.key=orders-db.key \
  --from-file=ca.pem=ca.pem
kubectl apply -f keytend-kmip-server/deploy/kubernetes/tools/kmip-check.yaml
kubectl -n orders wait --for=jsonpath='{.status.phase}'=Succeeded pod/kmip-check --timeout=60s
kubectl -n orders logs kmip-check | grep -oE '"(ResultStatus|VendorIdentification)"[^}]*|curl: .*'
kubectl -n orders delete pod kmip-check
```

`0x00000000` is Success; another Result Status (for example `0x00000001`,
Operation Failed, when the certificate is not in the policy or its entry lacks
Query, 24) means the request reached the server but was refused. A `curl:` TLS error means the
certificate, CA or name does not match; a timeout usually means the
NetworkPolicy labels.

### What the chart runs

The chart creates a StatefulSet `keytend-kmip-server` with one pod as UID
10001, read-only root filesystem, no capabilities, no service-account token
and a 64 MiB memory-backed `/tmp` (counted against the 512 Mi limit); the
Services `keytend-kmip-server` (clients) and `keytend-kmip-server-headless`;
the NetworkPolicy (no egress); the policy, backup PVC, backup CronJob and
pre-upgrade backup Job. Every value is described in
[`values.yaml`](../deploy/helm/keytend-kmip-server/values.yaml).

## Clients outside the cluster

> [!NOTE]
> This renders and passes a server-side dry run, but has not been tested
> against a cloud load balancer.

Expose the server through a `LoadBalancer` Service that forwards TCP, so TLS
passes through to the server, which authenticates the client certificate
itself. Do not terminate TLS in an ingress controller or load balancer. Add
the load balancer's DNS name to the server certificate
([server certificate](tls-setup.md#server-certificate)) and allow the
clients' addresses in the NetworkPolicy. In `kmip-values.yaml`:

```yaml
service:
  type: LoadBalancer
  externalTrafficPolicy: Local          # keeps client source addresses for the NetworkPolicy
  loadBalancerSourceRanges: [203.0.113.0/24]
networkPolicy:
  ipBlocks: [203.0.113.0/24]
```

Whether the source address survives to the NetworkPolicy depends on the load
balancer and the CNI.

## Settings and extra files

Every `serve` setting has an environment variable
([configuration](configuration.md#serve-settings)); set them in
`server.env`. The chart sets the file, database and listener variables itself
and refuses them there. Files have their own values:

```yaml
server:
  env:
    KMIP_IDLE_TIMEOUT: "900"
    KMIP_MAX_CONNECTIONS: "128"
users:
  existingSecret: kmip-users        # users.json (docs/credentials.md#users-file)
crl:
  existingSecret: kmip-crl          # crl.pem; revocation checks become required
provisioning:
  existingSecret: kmip-provisioning # tls.crt and tls.key; turns on Re-Provision
```

```sh
kubectl -n $NS create secret generic kmip-users --from-file=users.json
kubectl -n $NS create secret generic kmip-crl --from-file=crl.pem
kubectl -n $NS create secret generic kmip-provisioning \
  --from-file=tls.crt=provisioning-ca.pem --from-file=tls.key=provisioning-ca.key
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
```

The provisioning Secret holds the CA that issues
[Re-Provision](re-provision.md) client certificates; it is mounted read-only
with mode 0440 and the server refuses to start unless that CA is also in the
client CA bundle. A client that re-provisions has a new certificate the chart
does not know: update the client's own Secret from what it received, and
give each replica its own client certificate
([retirement](re-provision.md#retirement)). The policy still lists the old fingerprint until you
change it, and a policy change restarts the pod
([lockout recovery](re-provision.md#lockout-recovery)).

On an IPv6-only or IPv6-first cluster, set `server.bindAddress: "[::]"`; on
Linux that also accepts IPv4. Other files (a Validate trust anchor, a
server-to-client endpoint's certificates) go in `extraVolumes` and
`extraVolumeMounts`; server-to-client egress is in
[Notify and Put](server-to-client.md#configuration). An
[audit checkpoint](audit-checkpoints.md#start-the-server-with-it) is
`auditCheckpoint.enabled` and `auditCheckpoint.configMap`.

The server reads its files only at startup. A changed value or Secret name
restarts the pod; after changing the content of a Secret or ConfigMap under
the same name, restart it yourself:

```sh
kubectl -n $NS rollout restart statefulset/keytend-kmip-server
```

## cert-manager

With `tls.certManager.enabled`, the chart creates a Certificate from the
issuer you name, into the Secret `keytend-kmip-server-tls`, and points the
server at `tls.crt`, `tls.key` and `ca.crt`:

```yaml
tls:
  certManager:
    enabled: true
    issuerRef: {name: kmip-ca, kind: ClusterIssuer}
  # Only if the clients' CA is not the issuer's CA:
  clientCA:
    existingSecret: kmip-client-ca  # ca.pem
```

The Certificate covers the Service's four names, `keytend-kmip-server`,
`keytend-kmip-server.<namespace>`, `keytend-kmip-server.<namespace>.svc` and
`keytend-kmip-server.<namespace>.svc.cluster.local`, plus
`tls.certManager.dnsNames`.

`ca.crt` is the CA that signed the server certificate; when other CAs
sign the client certificates, give their bundle as `tls.clientCA`, or those
clients are refused. Issuers that leave `ca.crt` out (ACME, some external
issuers) need `tls.clientCA`, or the server finds no client CA file and does
not start. The server reads its certificate at startup only: restart
it after each renewal (`tls.certManager.renewBefore`), for example with a
scheduled `kubectl rollout restart`. See
[issuing with cert-manager](tls-setup.md#issuing-them-with-cert-manager) for
client certificates.

## Startup time and the startup probe

Before it opens any port, health included, the server verifies every object
record and the whole audit chain, so startup time grows with the store. The
startup probe allows `probes.startup.budgetSeconds` (60); a pod that is not
ready by then is restarted, and verification starts over. Raise it when
`check-store` on a recent backup takes more than about 45 seconds. Time it on
storage like the pod's, with the pod's limits (2 CPUs, 512 Mi), from the
directory that holds the backup and its master key:

```sh
IMAGE='registry.example.com/keytend-kmip-server@sha256:<image digest>'   # the image you deploy
time docker run --rm --cpus=2 --memory=512m --user "$(id -u):$(id -g)" -v "$PWD:/work" "$IMAGE" \
  check-store --database /work/backup.sqlite --master-key /work/master.key
```

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml \
  --set probes.startup.budgetSeconds=600 --wait
```

Restore and rotation run in init containers before the probe starts.
`helm upgrade --wait` waits 5 minutes by default. The pre-upgrade backup
(allowed 15 minutes, `backup.preUpgradeHook.activeDeadlineSeconds`), any
restore or rotation, and the startup verification all fall inside that wait,
which is enough only for a small store. Add `--timeout 15m` (or more) when
`check-store` takes more than a minute.

## Monitoring

The pod carries `prometheus.io/*` annotations for `/metrics` on port 8080
([metrics](metrics.md)). With the Prometheus Operator, the chart can create a
PodMonitor and a PrometheusRule with the
[suggested alerts](metrics.md#alerts) for this release's namespace and volume,
plus `KmipBackupStale` (no successful backup for 26 hours):

```yaml
metrics:
  podMonitor: {enabled: true, labels: {release: prometheus}}      # labels your Prometheus selects
  prometheusRule: {enabled: true, labels: {release: prometheus}}
```

The NetworkPolicy admits port 8080 only from `networkPolicy.metrics` (by
default pods labelled `access: keytend-kmip-server-metrics` in namespaces
labelled `kmip-metrics: "true"`).

## Availability and node maintenance

The chart runs one replica; more would be separate stores, not high
availability. It sets no PodDisruptionBudget by default, so `kubectl drain`
evicts the pod, which stops for a moment and starts again wherever its
volumes can attach (with node-local storage, the same node after the
uncordon). To stop the server for a maintenance window instead, and keep its
volumes, Secrets and backups:

```sh
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --set maintenance.enabled=true --wait
# … maintenance …
helm upgrade keytend-kmip-server $CHART -n $NS -f kmip-values.yaml --wait
```

`podDisruptionBudget.enabled` makes drains wait until you stop the server
this way (`maxUnavailable: 0`).

If the server's node fails while its pod is still bound to it, the backup
Jobs, which must run on that node, stay Pending, and so does every upgrade's
pre-upgrade backup until it times out. Once the pod has moved (or the node
object is deleted), they run again; until then upgrade with `--no-hooks`.

Retained PVCs do not count as a backup, because they share the cluster's
failure domain. Copy backups off the cluster
([backup and restore](backup-restore.md#scheduled-backups-on-kubernetes)).

## Secrets and FIPS

The chart mounts the master key from a Kubernetes Secret, which adds no
protection of its own.
Configure Secret encryption at rest and access control, or mount the key from
an external secret manager (for example with the Secrets Store CSI driver,
through `extraVolumes`), and keep it recoverable without anything that
depends on the managed keys.

Schedule FIPS workloads on FIPS-enabled nodes (`nodeSelector`,
`tolerations`): containers share the host kernel, and the server enters FIPS
mode by itself when the kernel reports it ([FIPS mode](fips.md)).

## Removing the server

```sh
helm uninstall keytend-kmip-server -n $NS
```

This keeps the data PVC (`data-keytend-kmip-server-0`), the backup PVC
(`keytend-kmip-server-backups`) and the Secrets, so installing again with the
same values starts on the same store. The last test pod and pre-upgrade backup
Job are Helm hooks, which `helm uninstall` leaves; delete them with
`kubectl -n $NS delete pod,job -l app.kubernetes.io/instance=keytend-kmip-server`.
Deleting the namespace, or those PVCs
with the usual `Delete` reclaim policy, destroys every key unless you hold a
backup and its master key elsewhere.

## Without Helm, and GitOps

`helm template` renders the same resources for `kubectl apply` or a GitOps
tool:

```sh
helm template keytend-kmip-server $CHART -n $NS -f kmip-values.yaml > kmip.yaml
kubectl -n $NS apply -f kmip.yaml
```

Restore, rotation and maintenance work the same way: render with the values
on these pages and apply. Two safeguards need Helm itself, because they read
the cluster with `lookup`, which `helm template` and renderers such as
Argo CD's cannot do:

- The pre-upgrade backup is rendered only when the chart can see the data
  and backup volumes, so these tools leave it out. Run a backup before
  you apply a new image, a restore or a rotation, and check it:
  `kubectl -n $NS create job --from=cronjob/keytend-kmip-server-backup <name>`
  ([backups](backup-restore.md#scheduled-backups-on-kubernetes)).
- With Helm, an upgrade that names another `masterKey.existingSecret`
  without rotation or restore values is refused. Without Helm, such a change starts the server with a key that does not open
  the store, and the pod fails until you put the old Secret name back.

[`deploy/kubernetes`](../deploy/kubernetes/README.md) is a minimal Kustomize
base for one replica, without backups or maintenance values: a namespace, a
StatefulSet, a Service, a NetworkPolicy and a PodDisruptionBudget with
`minAvailable: 1`. Unlike the chart's default, it makes drains wait until you
scale the StatefulSet to 0.
