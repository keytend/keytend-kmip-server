#!/usr/bin/env python3
# Copyright 2026 Jeremiah Jordan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test the Helm chart (deploy/helm/keytend-kmip-server) end to end on an existing disposable cluster.

Uses only its own namespace (default keytend-helm, deleted at the end). Load the image
into the cluster first; --pki is a scripts/dev-pki.sh directory with master.key. The
native executable (--binary) generates keys and exports audit checkpoints locally, as
an operator would. Steps: lint and render, server-side dry run, install under the
`restricted` Pod Security level, helm test, scheduled backup (latest.json and the
metric), a pre-upgrade hook that fails the release and one that passes, rollback,
restore and its no-op repeat, audit checkpoint, master-key rotation with checkpoint
publication, revert, maintenance mode, uninstall. Writes artifacts/helm-chart.json.
"""
import argparse
import contextlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import helm_tool  # noqa: E402
from test_runtime import ROOT, free_port  # noqa: E402
from wire import connect, create_key, exchange, key_value, reason, request, uid  # noqa: E402

RELEASE = 'keytend-kmip-server'
POD = f'{RELEASE}-0'


class Harness:
    def __init__(self, args):
        self.a = args
        self.kubectl = [args.kubectl, '--kubeconfig', str(pathlib.Path(args.kubeconfig).resolve())]
        self.helm = [str(args.helm or helm_tool.binary()), '--kubeconfig', str(pathlib.Path(args.kubeconfig).resolve())]
        self.ns = args.namespace
        self.pki = pathlib.Path(args.pki).resolve()
        self.work = pathlib.Path(tempfile.mkdtemp(prefix='keytend-helm-'))
        self.results = []
        self.report = {'status': 'running', 'namespace': self.ns, 'helm': helm_tool.VERSION, 'image': args.image, 'passed': self.results}
        self.out = ROOT/'artifacts/helm-chart.json'
        self.out.parent.mkdir(exist_ok=True)
        repository, _, tag = args.image.rpartition(':')
        self.values = {
            'image': {'repository': repository, 'tag': tag, 'pullPolicy': 'Never'},
            'masterKey': {'existingSecret': 'kmip-master-v1'},
            'tls': {'existingSecret': 'kmip-tls'},
            'policy': {'json': (self.pki/'policy.json').read_text()},
            # Never due during the test: backups run on demand from the CronJob.
            'backup': {'schedule': '0 0 1 1 *', 'retain': 3, 'pvc': {'size': '1Gi'}},
            'persistence': {'size': '1Gi'},
            'volumeHelper': {'enabled': True},
            'tests': {'clientSecret': 'kmip-test-client'},
        }

    # ---------------------------------------------------------------- tools

    def k(self, *args, check=True, input=None):
        done = subprocess.run(self.kubectl+['-n', self.ns, *map(str, args)], text=True, capture_output=True, input=input)
        if check and done.returncode:
            raise RuntimeError(f'kubectl {" ".join(map(str, args))} failed: {done.stdout[-2000:]}{done.stderr[-2000:]}')
        return done.stdout

    def h(self, *args, values=None, check=True, timeout=600):
        extra = ['--values', '-'] if values is not None else []
        done = subprocess.run(self.helm+[*map(str, args), *extra], text=True, capture_output=True, timeout=timeout,
                              input=json.dumps(values) if values is not None else None)
        if check and done.returncode:
            raise RuntimeError(f'helm {" ".join(map(str, args))} failed: {done.stdout[-3000:]}{done.stderr[-3000:]}')
        return done

    def upgrade(self, check=True, timeout='8m', **changes):
        values = merge(self.values, changes)
        return self.h('upgrade', RELEASE, helm_tool.CHART, '-n', self.ns, '--wait', '--timeout', timeout, values=values, check=check)

    def passed(self, message):
        self.results.append(message)
        print('PASS', message, flush=True)
        self.save()

    def save(self):
        self.out.write_text(json.dumps(self.report, indent=2)+'\n')

    def secret(self, name, **files):
        args = ['create', 'secret', 'generic', name, *[f'--from-file={key}={path}' for key, path in files.items()], '--dry-run=client', '-o', 'json']
        self.k('apply', '-f', '-', input=self.k(*args))

    def configmap(self, name, **files):
        args = ['create', 'configmap', name, *[f'--from-file={key}={path}' for key, path in files.items()], '--dry-run=client', '-o', 'json']
        self.k('apply', '-f', '-', input=self.k(*args))

    def pod(self, name=POD):
        return json.loads(self.k('get', 'pod', name, '-o', 'json'))

    def wait_job(self, name, timeout=300):
        until = time.monotonic()+timeout
        while time.monotonic() < until:
            status = json.loads(self.k('get', 'job', name, '-o', 'json'))['status']
            conditions = {c['type'] for c in status.get('conditions', []) if c['status'] == 'True'}
            if 'Complete' in conditions:
                return True
            if 'Failed' in conditions:
                return False
            time.sleep(2)
        raise TimeoutError(f'job {name} did not finish')

    def run_backup(self, name):
        self.k('create', 'job', f'--from=cronjob/{RELEASE}-backup', name)
        ok = self.wait_job(name)
        log = self.k('logs', f'job/{name}')
        assert ok, f'backup job {name} failed: {log}'
        return log

    def helper(self):
        return json.loads(self.k('get', 'pod', '-l', 'app.kubernetes.io/component=volume-helper', '-o', 'json'))['items'][0]['metadata']['name']

    def latest(self):
        helper = self.helper()
        latest = json.loads(self.k('exec', helper, '--', 'cat', '/backups/latest.json'))
        listing = self.k('exec', helper, '--', 'ls', '/backups').split()
        return latest, listing

    @contextlib.contextmanager
    def forward(self, port, target=f'pod/{POD}'):
        local = free_port()
        log = tempfile.TemporaryFile()
        process = subprocess.Popen(self.kubectl+['-n', self.ns, 'port-forward', target, f'{local}:{port}', '--address=127.0.0.1'], stdout=log, stderr=log)
        try:
            yield local
        finally:
            process.terminate()
            process.wait(timeout=5)
            log.close()

    def kmip(self, action):
        with self.forward(5696) as port:
            until = time.monotonic()+20
            while True:
                try:
                    with connect(self.pki, port) as c:
                        return action(c)
                except (ConnectionRefusedError, ConnectionResetError, OSError):
                    if time.monotonic() > until:
                        raise
                    time.sleep(.2)

    def metrics(self):
        with self.forward(8080) as port:
            until = time.monotonic()+20
            while True:
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{port}/metrics', timeout=5) as response:
                        return response.read().decode()
                except OSError:
                    if time.monotonic() > until:
                        raise
                    time.sleep(.2)

    def present(self, identifier):
        return self.kmip(lambda c: key_value(c, identifier))

    def absent(self, identifier):
        return self.kmip(lambda c: reason(exchange(c, request(10, [uid(identifier)])))) == 1

    def binary(self, *args):
        return subprocess.run([self.a.binary, *map(str, args)], check=True, capture_output=True, text=True)

    def logs(self, container):
        return self.k('logs', POD, '-c', container)

    # ---------------------------------------------------------------- steps

    def render_checks(self):
        assert helm_tool.rules_in_sync(), 'files/prometheus-rules.yaml differs from deploy/prometheus'
        lint = self.h('lint', helm_tool.CHART, '--strict', values=self.values)
        assert '0 chart(s) failed' in lint.stdout, lint.stdout
        docs, text = helm_tool.render(self.values, namespace=self.ns, helm=self.helm[0])
        assert 'Copyright' not in text, 'license comments leak into rendered manifests'
        kinds = sorted({d['kind'] for d in docs})
        self.report['rendered_kinds'] = kinds
        self.k('create', 'namespace', self.ns, check=False)
        self.k('label', 'namespace', self.ns, '--overwrite', *[f'pod-security.kubernetes.io/{m}=restricted' for m in ('enforce', 'warn', 'audit')])
        # The namespace's default ServiceAccount appears shortly after the namespace; server-side
        # dry runs of pods are refused until it exists.
        for _ in range(60):
            if self.k('get', 'serviceaccount', 'default', '-o', 'name', check=False).strip():
                break
            time.sleep(1)
        # Server-side dry run of every resource whose API the cluster serves (no Prometheus or cert-manager CRDs here).
        everything = merge(self.values, {'metrics': {'podMonitor': {'enabled': True}, 'prometheusRule': {'enabled': True}},
                                         'podDisruptionBudget': {'enabled': True}, 'auditCheckpoint': {'enabled': True, 'configMap': 'cp'},
                                         'masterKey': {'existingSecret': 'kmip-master-v2'}, 'rotation': {'previousMasterKeySecret': 'kmip-master-v1'},
                                         'tls': {'certManager': {'enabled': True, 'issuerRef': {'name': 'ca'}}},
                                         'service': {'type': 'LoadBalancer', 'externalTrafficPolicy': 'Local'}})
        docs, _ = helm_tool.render(everything, namespace=self.ns, helm=self.helm[0])
        # No CRDs for Prometheus Operator or cert-manager here. helm test pods name the chart's
        # ServiceAccount, which a dry run never creates; the test pod runs for real below.
        served = [d for d in docs if d['apiVersion'] not in ('monitoring.coreos.com/v1', 'cert-manager.io/v1')
                  and (d.get('metadata', {}).get('annotations') or {}).get('helm.sh/hook') != 'test']
        self.k('apply', '--dry-run=server', '-f', '-', input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': served}))
        self.report['server_dry_run_kinds'] = sorted({d['kind'] for d in served})
        self.passed(f'helm lint --strict; template renders {len(kinds)} kinds; all features render and pass a server-side dry run '
                    f'({", ".join(self.report["server_dry_run_kinds"])}); chart rules equal deploy/prometheus')

    def install(self):
        self.secret('kmip-tls', **{'server.pem': self.pki/'server.pem', 'server.key': self.pki/'server.key', 'ca.pem': self.pki/'ca.pem'})
        self.secret('kmip-master-v1', **{'master.key': self.pki/'master.key'})
        self.secret('kmip-test-client', **{'client.pem': self.pki/'client.pem', 'client.key': self.pki/'client.key', 'ca.pem': self.pki/'ca.pem'})
        self.h('install', RELEASE, helm_tool.CHART, '-n', self.ns, '--wait', '--timeout', '5m', values=self.values)
        pod = self.pod()
        spec = pod['spec']
        container = spec['containers'][0]
        assert spec['securityContext']['runAsUser'] == 10001 and spec['automountServiceAccountToken'] is False
        assert container['securityContext']['readOnlyRootFilesystem'] and container['securityContext']['capabilities']['drop'] == ['ALL']
        claims = {c['metadata']['name']: c['status']['phase'] for c in json.loads(self.k('get', 'pvc', '-o', 'json'))['items']}
        assert claims == {f'data-{RELEASE}-0': 'Bound', f'{RELEASE}-backups': 'Bound'}, claims
        assert helm_tool.metric_value(self.metrics(), 'kmip_last_backup_timestamp_seconds') == 0
        self.passed('helm install --wait: pod ready under Pod Security "restricted" as UID 10001, read-only root, no capabilities; '
                    'data and backup PVCs bound; kmip_last_backup_timestamp_seconds is 0')
        test = self.h('test', RELEASE, '-n', self.ns, '--logs', timeout=300)
        assert 'KMIP Query succeeded' in test.stdout and '"0x00000000"' in test.stdout, test.stdout
        self.passed('helm test: the test pod gets Result Status Success for an HTTPS KMIP Query with the client certificate')
        # The test fails on a KMIP failure that still answers HTTP 200: the unlisted certificate is refused.
        self.secret('kmip-test-unlisted', **{'client.pem': self.pki/'unlisted.pem', 'client.key': self.pki/'unlisted.key', 'ca.pem': self.pki/'ca.pem'})
        self.upgrade(tests={'clientSecret': 'kmip-test-unlisted'})
        failed = self.h('test', RELEASE, '-n', self.ns, '--logs', check=False, timeout=300)
        assert failed.returncode != 0, failed.stdout
        self.upgrade()
        self.passed('helm test fails for a certificate the server refuses')

    def backups(self):
        self.key_a = self.kmip(create_key)
        self.bytes_a = self.present(self.key_a)
        started = time.time()
        log = self.run_backup('backup-1')
        assert 'written and verified' in log, log
        latest, listing = self.latest()
        problems = helm_tool.latest_problems(latest, listing)
        assert not problems, problems
        assert latest['verification']['objects'] >= 1
        self.backup_a = pathlib.PurePosixPath(latest['file']).name
        recorded = helm_tool.metric_value(self.metrics(), 'kmip_last_backup_timestamp_seconds')
        assert recorded and started-5 <= recorded <= time.time()+5 and abs(recorded-latest['created_unix']) <= 5, (recorded, latest)
        job = json.loads(self.k('get', 'pod', '-l', 'job-name=backup-1', '-o', 'json'))['items'][0]
        assert job['spec']['nodeName'] == self.pod()['spec']['nodeName']
        self.report['backup'] = {'latest': latest, 'metric': recorded}
        self.passed(f'backup CronJob run on the server node: {self.backup_a} verified, latest.json valid, kmip_last_backup_timestamp_seconds = its time')
        self.key_b = self.kmip(create_key)
        # Copy the backup off the cluster as an operator would (kubectl cp through the volume helper).
        local = self.work/self.backup_a
        self.k('cp', f'{self.helper()}:/backups/{self.backup_a}', str(local))
        local.chmod(0o600)  # kubectl cp does not keep the mode; the server refuses a database others can read
        out = self.binary('check-store', '--database', local, '--master-key', self.pki/'master.key')
        assert 'verified' in out.stdout
        self.passed('kubectl cp through the volume helper copies the backup off; check-store verifies it locally')

    def hooks(self):
        uid_before = self.pod()['metadata']['uid']
        revision = self.release_revision()
        # A master-key Secret whose content no longer opens the store: the hook's backup fails.
        wrong = self.work/'wrong.key'
        self.binary('generate-master-key', '--output', wrong)
        self.secret('kmip-master-v1', **{'master.key': wrong})
        try:
            failed = self.upgrade(check=False, podAnnotations={'test/attempt': 'fails'})
        finally:
            self.secret('kmip-master-v1', **{'master.key': self.pki/'master.key'})
        assert failed.returncode != 0 and 'pre-upgrade' in (failed.stdout+failed.stderr), failed.stderr
        status = json.loads(self.h('status', RELEASE, '-n', self.ns, '-o', 'json').stdout)
        assert status['info']['status'] == 'failed', status['info']
        assert self.pod()['metadata']['uid'] == uid_before
        assert 'test/attempt' not in json.loads(self.k('get', 'statefulset', RELEASE, '-o', 'json'))['spec']['template']['metadata'].get('annotations', {})
        self.passed('a failing pre-upgrade backup fails helm upgrade before anything changes: release failed, StatefulSet and pod untouched')
        count = len(self.latest()[1])
        self.upgrade(podAnnotations={'test/attempt': 'passes'})
        latest, listing = self.latest()
        assert len(listing) == count+1 and not helm_tool.latest_problems(latest, listing), (listing, latest)
        assert self.present(self.key_a) == self.bytes_a and self.present(self.key_b)
        hook = self.k('logs', f'job/{RELEASE}-pre-upgrade-backup')
        assert pathlib.PurePosixPath(latest['file']).name in hook and 'written and verified' in hook, hook
        self.passed('helm upgrade runs the pre-upgrade backup (one more verified backup, latest.json updated), then rolls the pod; keys readable')
        self.h('rollback', RELEASE, str(revision), '-n', self.ns, '--wait', '--timeout', '5m')
        latest, after = self.latest()
        assert len(after) == len(listing)+1, after
        self.passed('helm rollback runs the pre-rollback backup')
        self.upgrade()

    def release_revision(self):
        return json.loads(self.h('status', RELEASE, '-n', self.ns, '-o', 'json').stdout)['version']

    def restore(self):
        self.upgrade(restore={'from': self.backup_a, 'id': 'r1'})
        log = self.logs('restore')
        assert 'already completed' not in log, log
        self.report['restore_log'] = log.strip()
        assert self.present(self.key_a) == self.bytes_a, 'key created before the backup must be back'
        assert self.absent(self.key_b), 'key created after the backup must be gone'
        self.key_c = self.kmip(create_key)
        self.k('delete', 'pod', POD, '--wait=true', '--timeout=90s')
        self.k('wait', '--for=condition=Ready', f'pod/{POD}', '--timeout=180s')
        log = self.logs('restore')
        assert 'already completed' in log, log
        assert self.present(self.key_c) and self.present(self.key_a) == self.bytes_a
        self.report['restore'] = {'from': self.backup_a, 'id': 'r1', 'repeat_log': log.strip()}
        self.passed(f'helm upgrade with restore.from={self.backup_a} restore.id=r1: the earlier key is back, the later one gone; '
                    'a restart with the same id does nothing (a key written after the restore survives)')
        # Recovery from a copy brought in from outside (docs/backup-restore.md): kubectl cp, chmod 0600, restore.
        helper = self.helper()
        self.k('cp', str(self.work/self.backup_a), f'{helper}:/backups/recovered.sqlite')
        self.k('exec', helper, '--', 'chmod', '0600', '/backups/recovered.sqlite')
        self.upgrade(restore={'from': 'recovered.sqlite', 'id': 'r2'})
        assert self.present(self.key_a) == self.bytes_a and self.absent(self.key_c)
        self.key_c = self.kmip(create_key)
        self.passed('restore of a backup copied into the backup PVC with kubectl cp (restore.id=r2): the copy is installed')
        self.upgrade()
        # A refused restore stops the pod in its init container; the corrected upgrade replaces that pod
        # by itself (podManagementPolicy Parallel), with no manual pod delete. The refusal: restore id r1
        # is bound to its backup, so r1 with another backup must fail rather than report success.
        other = pathlib.PurePosixPath(self.latest()[0]['file']).name
        assert other != self.backup_a
        failed = self.upgrade(check=False, timeout='90s', restore={'from': other, 'id': 'r1'})
        assert failed.returncode != 0, failed.stdout
        log = self.k('logs', POD, '-c', 'restore', check=False) + self.k('logs', POD, '-c', 'restore', '--previous', check=False)
        assert 'already used' in log, log
        self.report['restore_id_reuse_log'] = log.strip()
        self.upgrade()
        assert self.present(self.key_a) == self.bytes_a and self.present(self.key_c)
        self.passed('restore.id r1 reused with another backup is refused (the init container fails, the release fails); '
                    'the corrected helm upgrade replaces the stuck pod without a manual delete, on the unchanged store')

    def checkpoint(self):
        self.run_backup('backup-2')
        latest, _ = self.latest()
        name = pathlib.PurePosixPath(latest['file']).name
        local = self.work/name
        self.k('cp', f'{self.helper()}:/backups/{name}', str(local))
        local.chmod(0o600)
        self.cp1 = self.work/'checkpoint-1.json'
        self.binary('audit-checkpoint', '--database', local, '--master-key', self.pki/'master.key', '--output', self.cp1)
        self.configmap('kmip-checkpoint', **{'checkpoint.json': self.cp1})
        self.checkpoint_values = {'enabled': True, 'configMap': 'kmip-checkpoint'}
        self.upgrade(auditCheckpoint=self.checkpoint_values)
        assert helm_tool.metric_value(self.metrics(), 'kmip_store_audit_checkpoint_verified') == 1
        self.passed('audit checkpoint exported from a copied backup, put in a ConfigMap and enabled: the server starts with it verified')

    def rotation(self):
        v2 = self.work/'master-v2.key'
        self.binary('generate-master-key', '--output', v2)
        self.secret('kmip-master-v2', **{'master.key': v2})
        rotate = {'masterKey': {'existingSecret': 'kmip-master-v2'}, 'rotation': {'previousMasterKeySecret': 'kmip-master-v1'},
                  'auditCheckpoint': self.checkpoint_values}
        self.upgrade(**rotate)
        log = self.logs('rotate-master-key')
        assert 'nothing to rotate' not in log, log
        self.report['rotation'] = {'rotate_log': log.strip()}
        cp2 = self.logs('checkpoint')
        assert json.loads(cp2) and cp2 != self.cp1.read_text()
        assert self.present(self.key_a) == self.bytes_a and self.present(self.key_c)
        # The pre-upgrade backup tried both rotation keys; v1 (the second) opened the store, which v2 does not yet.
        hook = self.k('logs', f'job/{RELEASE}-pre-upgrade-backup')
        assert '/keys/1/master.key' in hook and 'written and verified' in hook, hook
        self.report['rotation_hook_log'] = hook.strip()
        self.passed('rotation: new versioned Secret plus rotation.previousMasterKeySecret; the pre-upgrade backup tried both keys and named v1; '
                    'the init container rotated in place and wrote the new-key checkpoint; keys readable')
        self.k('delete', 'pod', POD, '--wait=true', '--timeout=90s')
        self.k('wait', '--for=condition=Ready', f'pod/{POD}', '--timeout=180s')
        log = self.logs('rotate-master-key')
        assert 'nothing to rotate' in log, log
        self.report['rotation']['restart_log'] = log.strip()
        assert helm_tool.metric_value(self.metrics(), 'kmip_store_audit_checkpoint_verified') == 1
        self.passed('restart during the rotation window: the init container accepts the old ConfigMap checkpoint through the pre-rotation copy')
        # Revert while the ConfigMap still holds the pre-rotation checkpoint; a key written since is lost.
        key_d = self.kmip(create_key)
        self.upgrade(**merge(rotate, {'rotation': {'revert': True}}))
        assert self.present(self.key_a) == self.bytes_a and self.present(self.key_c) and self.absent(key_d)
        master = next(v for v in self.pod()['spec']['volumes'] if v['name'] == 'master')
        assert master['secret']['secretName'] == 'kmip-master-v1'
        self.report['rotation']['revert_log'] = self.logs('rotate-master-key').strip()
        self.passed('rotation.revert=true puts back the pre-rotation database under the previous key; a key written after the rotation is gone')
        # Forward again, then publish the checkpoint as documented and finish.
        self.upgrade(**rotate)
        published = self.work/'checkpoint-3.json'
        published.write_text(self.logs('checkpoint'))
        self.configmap('kmip-checkpoint', **{'checkpoint.json': published})
        self.values = merge(self.values, {'masterKey': {'existingSecret': 'kmip-master-v2'}, 'auditCheckpoint': self.checkpoint_values})
        self.upgrade()
        assert 'rotate-master-key' not in [c['name'] for c in self.pod()['spec'].get('initContainers', [])]
        assert helm_tool.metric_value(self.metrics(), 'kmip_store_audit_checkpoint_verified') == 1
        assert self.present(self.key_a) == self.bytes_a and self.present(self.key_c)
        refused = self.upgrade(check=False, masterKey={'existingSecret': 'kmip-master-v1'})
        assert refused.returncode != 0 and 'is not a key the store is under' in refused.stderr, refused.stderr
        assert self.present(self.key_a) == self.bytes_a
        self.passed('changing masterKey.existingSecret without rotation values is refused at render time; nothing changes')
        self.passed('rotate again, publish the printed checkpoint to the ConfigMap, remove rotation values: the server starts on v2 with the published checkpoint')

    def maintenance(self):
        self.upgrade(maintenance={'enabled': True}, volumeHelper={'enabled': False})
        assert json.loads(self.k('get', 'statefulset', RELEASE, '-o', 'json'))['spec']['replicas'] == 0
        assert not json.loads(self.k('get', 'pods', '-l', 'app.kubernetes.io/component=server', '-o', 'json'))['items']
        log = self.run_backup('backup-stopped')
        assert 'written and verified' in log
        self.passed('maintenance.enabled: 0 replicas; a backup Job still schedules with no server or helper pod (its own affinity term)')
        self.upgrade()
        assert self.present(self.key_a) == self.bytes_a
        self.passed('maintenance off: the server starts again with its keys')

    def uninstall(self):
        self.h('uninstall', RELEASE, '-n', self.ns, '--wait', '--timeout', '3m')
        claims = {c['metadata']['name'] for c in json.loads(self.k('get', 'pvc', '-o', 'json'))['items']}
        assert {f'data-{RELEASE}-0', f'{RELEASE}-backups'} <= claims, claims
        self.passed('helm uninstall keeps the backup PVC (resource-policy keep) and the data PVC')


def merge(base, changes):
    """Deep copy of base with changes merged in (mappings recursively)."""
    out = json.loads(json.dumps(base))
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge(out[key], value)
        else:
            out[key] = json.loads(json.dumps(value))
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--image', required=True, help='repository:tag of the image loaded into the cluster')
    parser.add_argument('--pki', required=True, help='scripts/dev-pki.sh output with master.key')
    parser.add_argument('--binary', default=str(ROOT/'target/debug/keytend-kmip-server'))
    parser.add_argument('--kubectl', default='kubectl')
    parser.add_argument('--helm', help='helm executable (default: the pinned one, scripts/helm_tool.py)')
    parser.add_argument('--namespace', default='keytend-helm')
    parser.add_argument('--keep', action='store_true', help='keep the namespace for inspection')
    args = parser.parse_args()
    harness = Harness(args)
    harness.save()
    try:
        for step in (harness.render_checks, harness.install, harness.backups, harness.hooks, harness.restore,
                     harness.checkpoint, harness.rotation, harness.maintenance, harness.uninstall):
            step()
        harness.report['status'] = 'passed'
        harness.report['limits'] = ('single-node kind cluster with local-path volumes: pod affinity is exercised but not '
                                    'multi-node placement; kindnet does not enforce NetworkPolicy; PodMonitor, PrometheusRule '
                                    'and Certificate render but are not applied (no CRDs)')
    except BaseException as error:
        harness.report['status'] = 'failed'
        harness.report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        harness.save()
        # Local copies of backups, keys and checkpoints.
        shutil.rmtree(harness.work, ignore_errors=True)
        if not args.keep:
            subprocess.run(harness.kubectl+['delete', 'namespace', args.namespace, '--wait=false'], capture_output=True)


if __name__ == '__main__':
    main()
