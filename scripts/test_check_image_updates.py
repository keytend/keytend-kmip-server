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

"""Unit tests for scripts/check_image_updates.py and the release gates that run it, with the
registry and the repositories replaced by fakes (no network)."""
import contextlib, io, json, pathlib, sys, tempfile, unittest, urllib.error
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check_image_updates as ciu

DOCKERFILE = (ciu.ROOT/'Dockerfile').read_text()
PINNED = {**ciu.nvrs(ciu.arg(DOCKERFILE, 'RUNTIME_PACKAGES')), **ciu.nvrs(ciu.arg(DOCKERFILE, 'BUILD_PACKAGES'))}
IMAGES = ciu.bases(DOCKERFILE)


class CheckTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = pathlib.Path(directory.name)/'image-updates.json'
        for patch in [mock.patch.object(ciu, 'OUTPUT', self.output), mock.patch.object(ciu.time, 'sleep')]:
            patch.start()
            self.addCleanup(patch.stop)

    def run_check(self, available=None, found=None, registry=None, gone=(), annotate='warning'):
        """Exit status, stdout and stderr of main() against fake repositories and a fake registry."""
        available = {**PINNED, **(available or {})}
        found = PINNED if found is None else found
        registry = {**{(i['repository'], i['platform'].split('/')[1]): i['digest'] for i in IMAGES}, **(registry or {})}

        def fetch(url, attempts=3):
            repository, reference = url.removeprefix(ciu.REGISTRY).split('/manifests/')
            if reference == 'latest':
                return json.dumps({'manifests': [{'digest': digest, 'platform': {'os': 'linux', 'architecture': arch}}
                                                 for (name, arch), digest in registry.items() if name == repository]}).encode()
            return None if reference in gone else b'{}'
        out, err = io.StringIO(), io.StringIO()
        argv = ['check_image_updates.py'] + (['--annotate', annotate] if annotate else [])
        with mock.patch.object(ciu, 'query', return_value=(available, found)), mock.patch.object(ciu, 'fetch', fetch), \
                mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                ciu.main()
                code = 0
            except SystemExit as exit:
                code = exit.code
        return code, out.getvalue(), err.getvalue()

    def test_current_pins_pass(self):
        code, out, _ = self.run_check()
        self.assertEqual(code, 0, out)
        self.assertIn('pins_current', out)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'pins_current')

    def test_a_stale_package_is_behind_with_an_annotation_at_the_requested_level(self):
        code, out, err = self.run_check(available={'glibc': '9.99-1.el9'})
        self.assertEqual(code, 1)
        self.assertIn('::warning title=Stale image pin::runtime package glibc is pinned at', out)
        self.assertIn('9.99-1.el9 is available', out)
        self.assertIn('refresh the pins', err)
        code, out, _ = self.run_check(available={'rust-toolset': '9.99-1.el9'}, annotate='error')
        self.assertEqual(code, 1)
        self.assertIn('::error title=Stale image pin::build package rust-toolset', out)

    def test_a_stale_base_image_still_published_is_behind(self):
        image = IMAGES[3]
        code, out, _ = self.run_check(registry={(image['repository'], 'arm64'): 'sha256:'+'a'*64})
        self.assertEqual(code, 1)
        self.assertIn(f"{image['stage']} (linux/arm64) is pinned at {image['digest']}", out)

    def test_a_pinned_package_no_longer_published_fails_even_as_a_warning_run(self):
        found = {name: version for name, version in PINNED.items() if name != 'openssl-devel'}
        code, out, err = self.run_check(available={'openssl-devel': '9.99-1.el9'}, found=found, annotate='warning')
        self.assertEqual(code, 2)
        self.assertIn('::error title=Pinned image input no longer published::build package openssl-devel-'+PINNED['openssl-devel']
                      +' is no longer in the UBI 9 repositories', out)
        self.assertIn('MISSING', out)
        self.assertIn('no longer published', err)
        self.assertEqual(json.loads(self.output.read_text())['status'], 'pins_missing')

    def test_a_pinned_base_image_no_longer_published_fails(self):
        image = IMAGES[0]
        code, out, _ = self.run_check(registry={(image['repository'], 'amd64'): 'sha256:'+'b'*64}, gone={image['digest']})
        self.assertEqual(code, 2)
        self.assertIn(f"{image['stage']} (linux/amd64) {image['digest']} is no longer in the registry", out)

    def test_a_package_the_repositories_do_not_return_fails_the_check(self):
        available = {name: version for name, version in PINNED.items() if name != 'zlib'}
        with mock.patch.object(ciu, 'query', return_value=(available, PINNED)), mock.patch.object(sys, 'argv', ['x', '--annotate', 'warning']), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as exit:
                ciu.main()
        self.assertEqual(exit.exception.code, 2)
        self.assertIn('returned no version of zlib', err.getvalue())
        self.assertIn('::error title=Image pin check failed::', out.getvalue())

    def test_an_unreachable_registry_fails_with_a_clear_message(self):
        self.output.write_text('{"status": "pins_current"}')
        with mock.patch.object(ciu, 'query', return_value=(PINNED, PINNED)), \
                mock.patch.object(ciu.urllib.request, 'urlopen', side_effect=urllib.error.URLError('Name or service not known')) as urlopen, \
                mock.patch.object(sys, 'argv', ['x']), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as exit:
                ciu.main()
        self.assertEqual(exit.exception.code, 2)
        self.assertEqual(urlopen.call_count, 3, 'transient errors are retried')
        self.assertIn('the image pin check failed, which is not a pass: cannot read https://registry.access.redhat.com/v2/', err.getvalue())
        self.assertIn('Name or service not known', err.getvalue())
        self.assertFalse(self.output.exists(), 'no earlier report is left behind')

    def test_an_unexpected_error_fails_the_check_rather_than_reading_as_stale(self):
        with mock.patch.object(ciu, 'check', side_effect=KeyError('manifests')), mock.patch.object(sys, 'argv', ['x', '--annotate', 'warning']), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            with self.assertRaises(SystemExit) as exit:
                ciu.main()
        self.assertEqual(exit.exception.code, 2)
        self.assertIn("not a pass: KeyError: 'manifests'", err.getvalue())
        self.assertIn('::error title=Image pin check failed::', out.getvalue())

    def test_a_failed_repository_query_fails_the_check(self):
        failed = mock.Mock(returncode=1, stdout='', stderr='Errors during downloading metadata for repository ubi-9-baseos-rpms')
        with mock.patch.object(ciu.subprocess, 'run', return_value=failed):
            with self.assertRaises(ciu.CheckError) as error:
                ciu.query('podman', 'image', PINNED)
        self.assertIn('ubi-9-baseos-rpms', str(error.exception))


class GateTest(unittest.TestCase):
    def test_the_release_workflow_checks_the_pins_before_building(self):
        workflow = yaml.safe_load((ciu.ROOT/'.github/workflows/release.yml').read_text())
        step = next(s for s in workflow['jobs']['check']['steps'] if 'check_image_updates.py' in s.get('run', ''))
        tag, dispatch = step['run'].split('then', 1)[1].split('else')
        self.assertEqual(tag.strip(), 'python3 scripts/check_image_updates.py --engine podman --annotate error', 'a tag on stale pins fails')
        self.assertIn('--annotate warning || [ $? = 1 ]', dispatch, 'a manual run tolerates only stale pins')
        for name, job in workflow['jobs'].items():
            if name != 'check':
                self.assertIn('check', [job['needs']] if isinstance(job['needs'], str) else job['needs'], name)

    def test_the_local_release_preflight_runs_the_check(self):
        source = (ciu.ROOT/'scripts/release_candidate.py').read_text()
        self.assertIn("run.step('preflight','image-pins',['python3','scripts/check_image_updates.py'", source)


if __name__ == '__main__':
    unittest.main()
