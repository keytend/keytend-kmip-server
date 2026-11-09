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

"""Unit tests for scripts/helm_tool.py and the chart's template logic.

The rendering tests need the pinned helm binary (scripts/helm_tool.py fetch) and are
skipped when it is not cached; they never download it.
"""
import io
import pathlib
import subprocess
import sys
import tarfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import helm_tool  # noqa: E402

BASE = {
    'masterKey': {'existingSecret': 'kmip-master-v1'},
    'tls': {'existingSecret': 'kmip-tls'},
    'policy': {'json': '{"principals": {}}'},
}


def archive(members):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as tar:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == 'symlink':
                info.type, info.linkname = tarfile.SYMTYPE, content
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return data.getvalue()


class Pure(unittest.TestCase):
    def test_extract_takes_only_the_helm_member(self):
        data = archive([('linux-amd64/LICENSE', b'license', 'file'), ('linux-amd64/helm', b'\x7fELF binary', 'file')])
        self.assertEqual(helm_tool.extract(data, 'amd64'), b'\x7fELF binary')
        with self.assertRaises(KeyError):
            helm_tool.extract(data, 'arm64')

    def test_extract_refuses_a_link(self):
        data = archive([('linux-amd64/helm', '/bin/sh', 'symlink')])
        with self.assertRaises(ValueError):
            helm_tool.extract(data, 'amd64')

    def test_pins_cover_both_architectures(self):
        for pins in (helm_tool.SHA256, helm_tool.BINARY_SHA256):
            self.assertEqual(set(pins), {'amd64', 'arm64'})
            self.assertTrue(all(len(v) == 64 and int(v, 16) >= 0 for v in pins.values()))

    def test_metric_value_matches_name_and_labels(self):
        text = '\n'.join([
            '# HELP kmip_last_backup_timestamp_seconds When the last backup was taken',
            '# TYPE kmip_last_backup_timestamp_seconds gauge',
            'kmip_last_backup_timestamp_seconds 1793913246',
            'kmip_last_backup_timestamp_seconds_extra 5',
            'kmip_objects{type="SymmetricKey",state="Active"} 3',
            'kmip_objects{type="SecretData",state="Active"} 1',
        ])
        self.assertEqual(helm_tool.metric_value(text, 'kmip_last_backup_timestamp_seconds'), 1793913246)
        self.assertEqual(helm_tool.metric_value(text, 'kmip_objects', {'type': 'SecretData'}), 1)
        self.assertIsNone(helm_tool.metric_value(text, 'kmip_objects', {'type': 'Certificate'}))
        self.assertIsNone(helm_tool.metric_value(text, 'kmip_ready'))

    def test_latest_problems(self):
        good = {'file': '/backups/backup-20261105T211406Z.sqlite', 'bytes': 45056, 'created': '2026-11-05T21:14:06Z',
                'created_unix': 1793913246, 'verified': True, 'pruned': [],
                'verification': {'storage_schema': 18, 'objects': 1, 'audit_entries': 4, 'object_index_verified': True}}
        self.assertEqual(helm_tool.latest_problems(good, ['backup-20261105T211406Z.sqlite', 'latest.json']), [])
        self.assertIn('backup-20261105T211406Z.sqlite is not in the directory', helm_tool.latest_problems(good, ['latest.json']))
        self.assertIn('not verified', helm_tool.latest_problems({**good, 'verified': False}))
        self.assertIn("unexpected file name 'kmip.sqlite'", helm_tool.latest_problems({**good, 'file': 'kmip.sqlite'}))
        self.assertIn('missing pruned', helm_tool.latest_problems({k: v for k, v in good.items() if k != 'pruned'}))

    def test_chart_rules_equal_deploy_prometheus(self):
        self.assertTrue(helm_tool.rules_in_sync(), 'copy deploy/prometheus/keytend-kmip-server-rules.yaml to the chart files/')

    def test_chart_version_matches_the_server(self):
        import tomllib
        # A development build (`-dev`) carries the version of the release it leads to.
        version = tomllib.loads((helm_tool.ROOT/'Cargo.toml').read_text())['package']['version'].removesuffix('-dev')
        chart = (helm_tool.CHART/'Chart.yaml').read_text()
        self.assertIn(f'appVersion: {version}\n', chart)
        self.assertIn(f'version: {version}\n', chart)


def helm_available():
    path = helm_tool.cached()
    return path.exists() and helm_tool.sha256(path) == helm_tool.BINARY_SHA256[helm_tool.host_arch()]


@unittest.skipUnless(helm_available(), 'pinned helm not cached (scripts/helm_tool.py fetch)')
class Templates(unittest.TestCase):
    def render(self, **changes):
        return helm_tool.render(merge(BASE, changes))

    def failure(self, **changes):
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.render(**changes)
        return raised.exception.stderr

    def pod(self, docs):
        return helm_tool.find(docs, 'StatefulSet')['spec']['template']['spec']

    def test_defaults_render_restricted_pods_without_license_comments(self):
        docs, text = self.render(tests={'clientSecret': 'c'}, volumeHelper={'enabled': True})
        self.assertNotIn('Copyright', text)
        pods = [self.pod(docs), helm_tool.find(docs, 'CronJob')['spec']['jobTemplate']['spec']['template']['spec'],
                helm_tool.find(docs, 'Deployment')['spec']['template']['spec'],
                helm_tool.find(docs, 'Pod')['spec']]
        for spec in pods:
            self.assertEqual(spec['securityContext']['runAsUser'], 10001)
            self.assertTrue(spec['securityContext']['runAsNonRoot'])
            self.assertEqual(spec['securityContext']['seccompProfile'], {'type': 'RuntimeDefault'})
            self.assertFalse(spec['automountServiceAccountToken'])
            for container in spec.get('initContainers', []) + spec['containers']:
                self.assertEqual(container['securityContext'], {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                                                'capabilities': {'drop': ['ALL']}})
        self.assertEqual(helm_tool.find(docs, 'StatefulSet')['spec']['replicas'], 1)
        self.assertNotIn('initContainers', self.pod(docs))

    def test_required_inputs_and_wrong_combinations_fail(self):
        self.assertIn('masterKey.existingSecret is required', self.failure(masterKey={'existingSecret': ''}))
        self.assertIn('tls.existingSecret', self.failure(tls={'existingSecret': ''}))
        self.assertIn('policy.json or policy.existingConfigMap', self.failure(policy={'json': None}))
        self.assertIn('restore.from and restore.id go together', self.failure(restore={'from': 'b.sqlite'}))
        self.assertIn('/restore/id', self.failure(restore={'from': 'b.sqlite', 'id': '-x'}))
        self.assertIn('cannot run in the same release', self.failure(restore={'from': 'b.sqlite', 'id': 'r1'},
                                                                     rotation={'previousMasterKeySecret': 'kmip-master-v0'}))
        self.assertIn('rotation.revert needs', self.failure(rotation={'revert': True}))
        self.assertIn('must differ', self.failure(rotation={'previousMasterKeySecret': 'kmip-master-v1'}))
        self.assertIn('set by the chart', self.failure(server={'env': {'KMIP_DATABASE': '/x'}}))
        self.assertIn('auditCheckpoint.configMap', self.failure(auditCheckpoint={'enabled': True}))

    def test_restore_runs_before_the_server(self):
        docs, _ = self.render(restore={'from': 'backup-20261105T021500Z.sqlite', 'id': 'r1'}, auditCheckpoint={'enabled': True, 'configMap': 'cp'})
        init = self.pod(docs)['initContainers']
        self.assertEqual([c['name'] for c in init], ['restore'])
        self.assertEqual(init[0]['args'], ['restore', '--from', '/backups/backup-20261105T021500Z.sqlite', '--id', 'r1',
                                           '--database', '/data/kmip.sqlite', '--master-key', '/master/master.key',
                                           '--audit-checkpoint', '/checkpoints/checkpoint.json'])

    def test_rotation_and_revert_choose_the_keys(self):
        rotation = {'masterKey': {'existingSecret': 'kmip-master-v2'}, 'rotation': {'previousMasterKeySecret': 'kmip-master-v1'},
                    'auditCheckpoint': {'enabled': True, 'configMap': 'cp'}}
        for revert, serving in ((False, 'kmip-master-v2'), (True, 'kmip-master-v1')):
            docs, _ = self.render(**merge(rotation, {'rotation': {'revert': revert}}))
            pod = self.pod(docs)
            self.assertEqual([c['name'] for c in pod['initContainers']], ['rotate-master-key', 'checkpoint'])
            args = pod['initContainers'][0]['args']
            self.assertEqual('--revert' in args, revert)
            self.assertEqual(args[args.index('--checkpoint-output')+1], '/run/kmip/checkpoint.json')
            volumes = {v['name']: v.get('secret', {}).get('secretName') for v in pod['volumes']}
            self.assertEqual((volumes['master'], volumes['master-new'], volumes['master-previous']), (serving, 'kmip-master-v2', 'kmip-master-v1'))
            env = {e['name']: e['value'] for e in pod['containers'][0]['env']}
            self.assertEqual(env['KMIP_AUDIT_CHECKPOINT'], '/run/kmip/checkpoint.json')
            # Backups try the serving key first, then the other key of the rotation.
            cron = helm_tool.find(docs, 'CronJob')['spec']['jobTemplate']['spec']['template']['spec']
            keys = [v['secret']['secretName'] for v in cron['volumes'] if v['name'].startswith('key-')]
            self.assertEqual(keys, [serving, 'kmip-master-v1' if serving == 'kmip-master-v2' else 'kmip-master-v2'])
            args = cron['containers'][0]['args']
            self.assertEqual([args[i+1] for i, a in enumerate(args) if a == '--master-key'], ['/keys/0/master.key', '/keys/1/master.key'])
        docs, _ = self.render(auditCheckpoint={'enabled': True, 'configMap': 'cp'})
        env = {e['name']: e['value'] for e in self.pod(docs)['containers'][0]['env']}
        self.assertEqual(env['KMIP_AUDIT_CHECKPOINT'], '/checkpoints/checkpoint.json')

    def test_backups_are_co_scheduled_and_kept(self):
        docs, _ = self.render(maintenance={'enabled': True})
        self.assertEqual(helm_tool.find(docs, 'StatefulSet')['spec']['replicas'], 0)
        cron = helm_tool.find(docs, 'CronJob')['spec']
        self.assertEqual(cron['concurrencyPolicy'], 'Forbid')
        pod = cron['jobTemplate']['spec']['template']['spec']
        self.assertEqual(pod['containers'][0]['args'], ['backup', '--database', '/data/kmip.sqlite', '--master-key', '/keys/0/master.key',
                                                        '--output-dir', '/backups', '--retain', '7'])
        term = pod['affinity']['podAffinity']['requiredDuringSchedulingIgnoredDuringExecution'][0]
        self.assertEqual(term['topologyKey'], 'kubernetes.io/hostname')
        # The pod matches its own term, so it schedules when no server pod runs.
        labels = cron['jobTemplate']['spec']['template']['metadata']['labels']
        self.assertTrue(all(labels[k] == v for k, v in term['labelSelector']['matchLabels'].items()))
        self.assertIn(labels['app.kubernetes.io/component'], term['labelSelector']['matchExpressions'][0]['values'])
        # Without cluster access lookup finds no volumes, so the hook is left out
        # (helm template, GitOps renderers); the kind harness covers it.
        self.assertFalse([d for d in docs if d['kind'] == 'Job'])
        pvc = helm_tool.find(docs, 'PersistentVolumeClaim')
        self.assertEqual(pvc['metadata']['annotations']['helm.sh/resource-policy'], 'keep')
        docs, _ = self.render(backup={'enabled': False})
        self.assertFalse([d for d in docs if d['kind'] in ('CronJob', 'Job', 'PersistentVolumeClaim')])

    def test_prometheus_rules_are_this_releases(self):
        docs, _ = helm_tool.render(merge(BASE, {'metrics': {'prometheusRule': {'enabled': True}}, 'persistence': {'size': '5Gi'}}),
                                   release='kmip', namespace='team-a')
        rules = {r['alert']: r['expr'] for g in helm_tool.find(docs, 'PrometheusRule')['spec']['groups'] for r in g['rules']}
        self.assertIn('job="keytend-kmip-server", namespace="team-a"', rules['KmipServerDown'])
        self.assertIn(str(5*1024**3), rules['KmipDiskGrowth'])
        self.assertIn('persistentvolumeclaim="data-kmip-keytend-kmip-server-0"', rules['KmipVolumeFreeSpace'])
        self.assertIn('kmip_last_backup_timestamp_seconds', rules['KmipBackupStale'])
        original = helm_tool.documents(helm_tool.RULES.read_text())[0]
        self.assertEqual(set(rules)-{'KmipBackupStale'}, {r['alert'] for g in original['groups'] for r in g['rules']})


def merge(base, changes):
    out = dict(base)
    for key, value in changes.items():
        out[key] = merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else value
    return out


if __name__ == '__main__':
    unittest.main()
