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

"""Template assertions for the chart's Re-Provision values (provisioning.existingSecret).

Renders with the pinned Helm (scripts/helm_tool.py fetch); skipped when it is
not cached, like the other template tests.
"""
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import helm_tool  # noqa: E402
from test_helm_tool import BASE, helm_available, merge  # noqa: E402


@unittest.skipUnless(helm_available(), 'pinned helm not cached (scripts/helm_tool.py fetch)')
class Provisioning(unittest.TestCase):
    def pod(self, **changes):
        docs, _ = helm_tool.render(merge(BASE, changes))
        return helm_tool.find(docs, 'StatefulSet')['spec']['template']['spec']

    def test_off_by_default(self):
        pod = self.pod()
        env = {e['name'] for e in pod['containers'][0]['env']}
        self.assertFalse(env & {'KMIP_PROVISIONING_CA', 'KMIP_PROVISIONING_CA_KEY'})
        self.assertNotIn('provisioning', {v['name'] for v in pod['volumes']})

    def test_the_secret_is_mounted_read_only_with_mode_0440(self):
        pod = self.pod(provisioning={'existingSecret': 'kmip-provisioning-ca'})
        env = {e['name']: e['value'] for e in pod['containers'][0]['env']}
        self.assertEqual(env['KMIP_PROVISIONING_CA'], '/provisioning/tls.crt')
        self.assertEqual(env['KMIP_PROVISIONING_CA_KEY'], '/provisioning/tls.key')
        mounts = {m['name']: m for m in pod['containers'][0]['volumeMounts']}
        self.assertEqual(mounts['provisioning'], {'name': 'provisioning', 'mountPath': '/provisioning', 'readOnly': True})
        volume = {v['name']: v for v in pod['volumes']}['provisioning']
        self.assertEqual(volume['secret'], {'secretName': 'kmip-provisioning-ca', 'defaultMode': 0o440})

    def test_server_env_cannot_set_the_variables(self):
        for name in ('KMIP_PROVISIONING_CA', 'KMIP_PROVISIONING_CA_KEY'):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                helm_tool.render(merge(BASE, {'server': {'env': {name: '/x'}}}))
            self.assertIn('set by the chart', raised.exception.stderr)

    def test_the_schema_refuses_unknown_provisioning_values(self):
        with self.assertRaises(subprocess.CalledProcessError):
            helm_tool.render(merge(BASE, {'provisioning': {'existingSecret': 's', 'key': 'k'}}))


if __name__ == '__main__':
    unittest.main()
