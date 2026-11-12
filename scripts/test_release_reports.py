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

"""Unit tests for scripts/release_reports.py: what is packaged, what is edited
and what is refused."""
import io, json, pathlib, sys, tarfile, tempfile, unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import release_reports as rr


class Reports(unittest.TestCase):
    def bundle(self, root):
        b = root/'bundle'
        (b/'logs').mkdir(parents=True)
        (b/'tls-probe-image-default/pki').mkdir(parents=True)
        (b/'tls-probe-image-default/fixtures/x/data').mkdir(parents=True)
        (b/'manifest.json').write_text(json.dumps({'commit': 'abc', 'image_tag': 'localhost/k:1.0', 'phases': {}}))
        home = str(pathlib.Path.home())
        other = '/'.join(['', 'home', 'someone', 'z'])
        (b/'logs/step.log').write_text(f'ran in {b}/x and {home}/y on build-host-7, remote {other}\n')
        (b/'tls-probe-image-default/summary.json').write_text('{}')
        (b/'tls-probe-image-default/pki/ca.key').write_text('-----BEGIN PRIVATE KEY-----\n')
        (b/'tls-probe-image-default/fixtures/x/data/kmip.sqlite').write_bytes(b'db')
        (b/'kind.kubeconfig').write_text('secret')
        return b

    def read(self, archive):
        with tarfile.open(archive) as tar:
            return {m.name: tar.extractfile(m).read().decode() for m in tar.getmembers()}

    def test_reports_are_edited_and_secrets_stay_out(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.bundle(pathlib.Path(d))
            out = pathlib.Path(d)/'r.tar.gz'
            rr.build(b, out, ['build-host-7'])
            files = self.read(out)
            self.assertEqual(sorted(files), ['README.txt', 'logs/step.log', 'manifest.json', 'tls-probe-image-default/summary.json'])
            self.assertEqual(files['logs/step.log'], 'ran in <bundle>/x and ~/y on <host>, remote ~/z\n')
            first = out.read_bytes()
            rr.build(b, out, ['build-host-7'])
            self.assertEqual(out.read_bytes(), first, 'the same reports give the same bytes')

    def test_a_part_is_edited_without_a_readme(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.bundle(pathlib.Path(d))
            out = pathlib.Path(d)/'part.tar.gz'
            rr.build(b, out, ['build-host-7'], part=True)
            files = self.read(out)
            self.assertNotIn('README.txt', files)
            self.assertEqual(files['logs/step.log'], 'ran in <bundle>/x and ~/y on <host>, remote ~/z\n')

    def test_a_private_key_in_a_report_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            b = self.bundle(pathlib.Path(d))
            (b/'logs/leak.log').write_text('-----BEGIN EC PRIVATE KEY-----\n')
            with self.assertRaises(SystemExit):
                rr.build(b, pathlib.Path(d)/'r.tar.gz', [])


if __name__ == '__main__':
    unittest.main()
