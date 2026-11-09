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

# Kubernetes resources

The supported way to run keytend-kmip-server on Kubernetes is the Helm chart
in [`../helm/keytend-kmip-server`](../helm/keytend-kmip-server/README.md)
([Kubernetes](../../docs/kubernetes.md)), which also runs the maintenance
tasks listed in its README. Without Helm, render it with `helm template`
([without Helm](../../docs/kubernetes.md#without-helm-and-gitops)).

This directory is a minimal Kustomize base for one replica in the namespace
`keytend-kmip-server`, without those tasks. The test suite
`scripts/test_kubernetes.py` deploys it.

| File | Content |
| --- | --- |
| `namespace.yaml` | The namespace, with the `restricted` Pod Security level |
| `statefulset.yaml` | One replica, a 10 Gi PVC per pod, probes, non-root security context, 64 MiB memory `/tmp` |
| `service.yaml` | Headless Service for 5696 (TTLV) and 5697 (HTTPS) |
| `networkpolicy.yaml` | Default deny; KMIP ports only from labelled client pods, 8080 only from labelled Prometheus pods |
| `pdb.yaml` | PodDisruptionBudget for the single pod (`minAvailable: 1`: drains wait until you scale it to 0) |

The base holds no secrets. Before `kubectl apply -k`, create the TLS Secret
`keytend-kmip-server-tls` (`server.pem`, `server.key`, `ca.pem`), the
master-key Secret `keytend-kmip-server-master` (`master.key`) and the policy
ConfigMap `keytend-kmip-server-policy` (`policy.json`), and set your image in
an overlay (`images:`).

[`tools/kmip-check.yaml`](tools/kmip-check.yaml) sends one HTTPS Query from a
client namespace, to check a client certificate and the NetworkPolicy labels
with either deployment ([client namespaces](../../docs/kubernetes.md#client-namespaces)). Its
curl image is pinned by digest.
