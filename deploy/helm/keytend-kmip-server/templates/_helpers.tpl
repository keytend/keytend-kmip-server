{{- /*
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
*/ -}}
{{/* Names and labels. */}}
{{- define "kmip.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kmip.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "kmip.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kmip.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kmip.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "kmip.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kmip.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "kmip.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* image reference: repository[:tag][@digest] from a values map. */}}
{{- define "kmip.imageRef" -}}
{{- $tag := .image.tag | default .default -}}
{{- if .image.digest -}}
{{- printf "%s:%s@%s" .image.repository $tag .image.digest -}}
{{- else -}}
{{- printf "%s:%s" .image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "kmip.image" -}}
{{- include "kmip.imageRef" (dict "image" .Values.image "default" .Chart.AppVersion) -}}
{{- end -}}

{{- define "kmip.helperImage" -}}
{{- include "kmip.imageRef" (dict "image" .Values.helperImage "default" "latest") -}}
{{- end -}}

{{/* Inputs. */}}
{{- define "kmip.masterKeySecret" -}}
{{- required "masterKey.existingSecret is required: create a Secret with the master key (docs/kubernetes.md)" .Values.masterKey.existingSecret -}}
{{- end -}}

{{- define "kmip.rotating" -}}
{{- if .Values.rotation.previousMasterKeySecret -}}true{{- end -}}
{{- end -}}

{{/* The key the store is under once the init containers have run: the
previous one after a revert, otherwise masterKey. */}}
{{- define "kmip.serverMasterKeySecret" -}}
{{- if and (include "kmip.rotating" .) .Values.rotation.revert -}}
{{- .Values.rotation.previousMasterKeySecret -}}
{{- else -}}
{{- include "kmip.masterKeySecret" . -}}
{{- end -}}
{{- end -}}

{{- define "kmip.tlsSecret" -}}
{{- if .Values.tls.certManager.enabled -}}
{{- default (printf "%s-tls" (include "kmip.fullname" .)) .Values.tls.certManager.secretName -}}
{{- else -}}
{{- required "tls.existingSecret (or tls.certManager.enabled) is required" .Values.tls.existingSecret -}}
{{- end -}}
{{- end -}}

{{- define "kmip.tlsFile" -}}
{{- $files := .root.Values.tls.files -}}
{{- $cm := .root.Values.tls.certManager.enabled -}}
{{- if eq .name "cert" -}}{{- $files.cert | default (ternary "tls.crt" "server.pem" $cm) -}}
{{- else if eq .name "key" -}}{{- $files.key | default (ternary "tls.key" "server.key" $cm) -}}
{{- else -}}{{- $files.ca | default (ternary "ca.crt" "ca.pem" $cm) -}}
{{- end -}}
{{- end -}}

{{- define "kmip.policyConfigMap" -}}
{{- if .Values.policy.existingConfigMap -}}
{{- .Values.policy.existingConfigMap -}}
{{- else if .Values.policy.json -}}
{{- printf "%s-policy" (include "kmip.fullname" .) -}}
{{- else -}}
{{- fail "policy.json or policy.existingConfigMap is required" -}}
{{- end -}}
{{- end -}}

{{- define "kmip.policyDocument" -}}
{{- if kindIs "string" .Values.policy.json -}}
{{- .Values.policy.json -}}
{{- else -}}
{{- toPrettyJson .Values.policy.json -}}
{{- end -}}
{{- end -}}

{{- define "kmip.dataClaim" -}}
{{- printf "data-%s-0" (include "kmip.fullname" .) -}}
{{- end -}}

{{- define "kmip.backupClaim" -}}
{{- default (printf "%s-backups" (include "kmip.fullname" .)) .Values.backup.pvc.existingClaim -}}
{{- end -}}

{{/* The claim mounted at /backups in the server pod: the restore source, or the backup PVC. */}}
{{- define "kmip.backupVolumeClaim" -}}
{{- if .Values.restore.existingClaim -}}
{{- .Values.restore.existingClaim -}}
{{- else if .Values.backup.enabled -}}
{{- include "kmip.backupClaim" . -}}
{{- end -}}
{{- end -}}

{{- define "kmip.checkpointPath" -}}
{{- if include "kmip.rotating" . -}}/run/kmip/checkpoint.json{{- else -}}/checkpoints/{{ .Values.auditCheckpoint.key }}{{- end -}}
{{- end -}}

{{/* Checks that make a wrong combination of values fail at render time. */}}
{{- define "kmip.validate" -}}
{{- $_ := include "kmip.masterKeySecret" . -}}
{{- $_ = include "kmip.tlsSecret" . -}}
{{- $_ = include "kmip.policyConfigMap" . -}}
{{- if and .Values.tls.certManager.enabled (not .Values.tls.certManager.issuerRef.name) -}}
{{- fail "tls.certManager.issuerRef.name is required with tls.certManager.enabled" -}}
{{- end -}}
{{- if and .Values.auditCheckpoint.enabled (not .Values.auditCheckpoint.configMap) -}}
{{- fail "auditCheckpoint.configMap is required with auditCheckpoint.enabled" -}}
{{- end -}}
{{- if or .Values.restore.from .Values.restore.id -}}
{{- if not (and .Values.restore.from .Values.restore.id) -}}
{{- fail "restore.from and restore.id go together" -}}
{{- end -}}
{{- if not (regexMatch "^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$" (toString .Values.restore.id)) -}}
{{- fail "restore.id must be 1-64 letters, digits, '.', '_' or '-', not starting with '.' or '-'" -}}
{{- end -}}
{{- if not (include "kmip.backupVolumeClaim" .) -}}
{{- fail "restore.from needs a backup volume: backup.enabled or restore.existingClaim" -}}
{{- end -}}
{{- if include "kmip.rotating" . -}}
{{- fail "restore and rotation cannot run in the same release: finish one and remove its values first" -}}
{{- end -}}
{{- end -}}
{{- if and .Values.rotation.revert (not (include "kmip.rotating" .)) -}}
{{- fail "rotation.revert needs rotation.previousMasterKeySecret (the key before the rotation)" -}}
{{- end -}}
{{- if and (include "kmip.rotating" .) (eq .Values.rotation.previousMasterKeySecret .Values.masterKey.existingSecret) -}}
{{- fail "rotation.previousMasterKeySecret must differ from masterKey.existingSecret" -}}
{{- end -}}
{{- /* The store stays under the key the running StatefulSet uses (or, during a
rotation, the previous one): another key needs rotation or restore values. */}}
{{- with (lookup "apps/v1" "StatefulSet" $.Release.Namespace (include "kmip.fullname" $)) -}}
{{- $live := list -}}
{{- range .spec.template.spec.volumes -}}
{{- if and .secret (has .name (list "master" "master-previous")) -}}{{- $live = append $live .secret.secretName -}}{{- end -}}
{{- end -}}
{{- $target := include "kmip.serverMasterKeySecret" $ -}}
{{- if and $live (not (has $target $live)) (not (include "kmip.rotating" $)) (not $.Values.restore.from) -}}
{{- fail (printf "masterKey.existingSecret %s is not a key the store is under (%s): to change the master key set rotation.previousMasterKeySecret (docs/master-key-rotation.md); to restore a backup under another key set restore.from" $target (join ", " $live)) -}}
{{- end -}}
{{- end -}}
{{- $reserved := list "KMIP_CERT" "KMIP_KEY" "KMIP_CA" "KMIP_CRL" "KMIP_POLICY" "KMIP_USERS" "KMIP_DATABASE" "KMIP_MASTER_KEY" "KMIP_AUDIT_CHECKPOINT" "KMIP_LISTEN" "KMIP_HTTPS_LISTEN" "KMIP_HEALTH_LISTEN" "KMIP_PROVISIONING_CA" "KMIP_PROVISIONING_CA_KEY" -}}
{{- range $name, $_ := .Values.server.env -}}
{{- if has $name $reserved -}}
{{- fail (printf "server.env.%s is set by the chart; use the matching chart value instead" $name) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.tests.clientSecret (not .Values.server.https.enabled) -}}
{{- fail "tests.clientSecret needs server.https.enabled (the test uses HTTPS)" -}}
{{- end -}}
{{- end -}}

{{/* Security contexts shared by every pod and container (Pod Security "restricted"). */}}
{{- define "kmip.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "kmip.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{/* Pods that mount the ReadWriteOnce data and backup volumes next to the
server. The required term selects the server, backup and helper pods; when
none of them runs, the scheduler lets the first one schedule wherever its
volumes can attach, because the pod matches its own term. */}}
{{- define "kmip.volumeGroupTerm" -}}
labelSelector:
  matchLabels:
    {{- include "kmip.selectorLabels" . | nindent 4 }}
  matchExpressions:
    - key: app.kubernetes.io/component
      operator: In
      values: [server, backup, volume-helper]
topologyKey: kubernetes.io/hostname
{{- end -}}

{{- define "kmip.coScheduled" -}}
affinity:
  podAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - {{ include "kmip.volumeGroupTerm" . | nindent 8 | trim }}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Master-key Secrets a backup tries, comma-separated: the server's key and,
while rotation values are set, both keys of the rotation (the store is under
one of them, whichever step the rotation reached). */}}
{{- define "kmip.candidateKeys" -}}
{{- $keys := list (include "kmip.serverMasterKeySecret" .) -}}
{{- if include "kmip.rotating" . -}}
{{- $keys = append $keys .Values.rotation.previousMasterKeySecret -}}
{{- $keys = append $keys .Values.masterKey.existingSecret -}}
{{- end -}}
{{- $keys | uniq | join "," -}}
{{- end -}}

{{/* The pod spec of a backup run (CronJob and upgrade hook). */}}
{{- define "kmip.backupPod" -}}
{{- $root := .root -}}
restartPolicy: Never
serviceAccountName: {{ include "kmip.serviceAccountName" $root }}
automountServiceAccountToken: false
securityContext:
  {{- include "kmip.podSecurityContext" $root | nindent 2 }}
{{- include "kmip.coScheduled" $root | nindent 0 }}
{{- with $root.Values.image.pullSecrets }}
imagePullSecrets:
  {{- range . }}
  - name: {{ . }}
  {{- end }}
{{- end }}
containers:
  - name: backup
    image: {{ include "kmip.image" $root }}
    imagePullPolicy: {{ $root.Values.image.pullPolicy }}
    args:
      - backup
      - --database
      - /data/kmip.sqlite
      {{- range $i, $_ := .keys }}
      - --master-key
      - /keys/{{ $i }}/{{ $root.Values.masterKey.key }}
      {{- end }}
      - --output-dir
      - /backups
      {{- if .ifExists }}
      - --if-exists
      {{- end }}
      {{- if .retain }}
      - --retain
      - {{ .retain | quote }}
      {{- end }}
    securityContext:
      {{- include "kmip.containerSecurityContext" $root | nindent 6 }}
    resources:
      {{- toYaml $root.Values.backup.resources | nindent 6 }}
    volumeMounts:
      - {name: scratch, mountPath: /tmp}
      - {name: data, mountPath: /data}
      - {name: backups, mountPath: /backups}
      {{- range $i, $_ := .keys }}
      - {name: key-{{ $i }}, mountPath: /keys/{{ $i }}, readOnly: true}
      {{- end }}
volumes:
  - name: scratch
    emptyDir: {medium: Memory, sizeLimit: 64Mi}
  - name: data
    persistentVolumeClaim:
      claimName: {{ include "kmip.dataClaim" $root }}
  - name: backups
    persistentVolumeClaim:
      claimName: {{ include "kmip.backupClaim" $root }}
  {{- range $i, $secret := .keys }}
  - name: key-{{ $i }}
    secret:
      secretName: {{ $secret }}
      defaultMode: 288
  {{- end }}
{{- end -}}

{{/* Byte count of a Kubernetes quantity such as 10Gi (binary and decimal suffixes). */}}
{{- define "kmip.bytes" -}}
{{- $q := toString . -}}
{{- $units := dict "Ki" 1024 "Mi" 1048576 "Gi" 1073741824 "Ti" 1099511627776 "K" 1000 "M" 1000000 "G" 1000000000 "T" 1000000000000 -}}
{{- $number := regexFind "^[0-9]+" $q -}}
{{- $suffix := trimPrefix $number $q -}}
{{- if not $number -}}{{- fail (printf "cannot read the quantity %s" $q) -}}{{- end -}}
{{- if eq $suffix "" -}}{{- $number -}}
{{- else if hasKey $units $suffix -}}{{- mul (atoi $number) (get $units $suffix) -}}
{{- else -}}{{- fail (printf "cannot read the quantity %s (use Ki, Mi, Gi, Ti, K, M, G or T)" $q) -}}
{{- end -}}
{{- end -}}
