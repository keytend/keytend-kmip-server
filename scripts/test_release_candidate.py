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

"""Unit tests for the release workflow's side of scripts/release_candidate.py: the
merge of the jobs' partial bundles, and the records of steps that did not run."""
import json, os, pathlib, re, subprocess, sys, tempfile, unittest
from unittest import mock

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import release_candidate as rc
import release_reports as rr


def part(root, job, phases, files, images=None, groups=None, commit='c0ffee'):
    """A partial bundle as release_reports.py --part packs it."""
    d = root/job
    for name, text in files.items():
        (d/name).parent.mkdir(parents=True, exist_ok=True)
        (d/name).write_text(text)
    manifest = {'commit': commit, 'dirty': False, 'started_at': '20261111T000000Z', 'finished_at': '20261111T010000Z',
                'platforms': ['amd64'], 'images': images or {}, 'phases': phases, 'tools': {'kind': job},
                'ci': {'job': job, 'phases': sorted(phases), 'host': f'runner-{job}', 'runner': 'Linux/X64', 'run': {'run_id': '1'}}}
    if groups:
        manifest['integration_groups'] = groups
    (d/'manifest.json').write_text(json.dumps(manifest))
    archive = root/f'part-{job}.tar.gz'
    rr.build(d, archive, [], part=True)
    return archive


def step(log, exit=0, outputs=None):
    return {'command': ['x'], 'exit': exit, 'seconds': 1, 'log': log, 'log_sha256': '0', 'outputs': outputs or {}}


class Merge(unittest.TestCase):
    def test_parts_are_merged_with_job_names_where_needed(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            a = part(root, 'conformance', {'image': {'load': step('logs/image-load.log')},
                                           'conformance': {'image-strict': step('logs/conformance-image-strict.log', outputs={'conformance-image/strict.json': '1'})}},
                     {'logs/image-load.log': 'a', 'logs/conformance-image-strict.log': 's', 'conformance-image/strict.json': '{}',
                      'integration/summary.json': '{"a": 1}'},
                     images={'amd64': {'tag': 't', 'image_id': 'i'}})
            b = part(root, 'integration-core', {'image': {'load': step('logs/image-load.log', exit=1)},
                                                'integration': {'matrix': step('logs/integration-matrix.log')}},
                     {'logs/image-load.log': 'b', 'logs/integration-matrix.log': 'm', 'integration/summary.json': '{"b": 2}'},
                     groups=['hash'])
            run = rc.Run(root/'bundle')
            manifest = {'commit': 'c0ffee', 'dirty': False, 'started_at': '20261111T020000Z', 'platforms': ['amd64'], 'images': {},
                        'phases': run.phases, 'ci': {'job': 'assemble'}}
            rc.merge(manifest, run, [a, b])
            image = run.phases['image']
            self.assertEqual(sorted(image), ['load (conformance)', 'load (integration-core)'])
            self.assertEqual(image['load (conformance)']['log'], 'logs/conformance/image-load.log')
            self.assertEqual((run.bundle/'logs/integration-core/image-load.log').read_text(), 'b')
            self.assertEqual(run.phases['conformance']['image-strict']['outputs'], {'conformance-image/strict.json': '1'})
            self.assertEqual((run.bundle/'integration/summary.json').read_text(), '{"a": 1}')
            self.assertEqual((run.bundle/'integration/integration-core/summary.json').read_text(), '{"b": 2}')
            self.assertEqual(manifest['images'], {'amd64': {'tag': 't', 'image_id': 'i'}})
            self.assertEqual(manifest['started_at'], '20261111T000000Z')
            self.assertEqual(manifest['ci']['parts']['integration-core']['integration_groups'], ['hash'])
            self.assertEqual(manifest['ci']['parts']['conformance']['host'], 'runner-conformance')
            self.assertEqual(run.failed(), ['image/load (integration-core)'])

    def test_a_part_of_another_commit_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            a = part(root, 'java', {'java': {'suite': step('logs/java-suite.log')}}, {'logs/java-suite.log': 'j'}, commit='bad')
            run = rc.Run(root/'bundle')
            manifest = {'commit': 'c0ffee', 'dirty': False, 'started_at': '20261111T020000Z', 'platforms': ['amd64'], 'images': {},
                        'phases': run.phases, 'ci': {'job': 'assemble'}}
            rc.merge(manifest, run, [a])
            self.assertEqual(run.failed(), ['release/commit-java'])

    def test_steps_not_run_are_recorded_and_not_failures(self):
        with tempfile.TemporaryDirectory() as d:
            run = rc.Run(pathlib.Path(d))
            run.skip('java', 'soak', rc.NOT_RUN['java', 'soak'])
            run.check('integration', 'coverage', ['group not run: pbm'])
            self.assertEqual(run.phases['java']['soak'], {'exit': None, 'not_run': rc.NOT_RUN['java', 'soak']})
            self.assertEqual(run.failed(), ['integration/coverage'])
            self.assertEqual((pathlib.Path(d)/'logs/integration-coverage.log').read_text(), 'group not run: pbm\n')

    def test_an_interrupted_part_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            running = {'command': ['x'], 'exit': 'running', 'log': 'logs/conformance-image-variations.log'}
            a = part(root, 'conformance', {'conformance': {'image-variations': running}}, {'logs/conformance-image-variations.log': ''})
            manifest = json.loads((root/'conformance/manifest.json').read_text())
            del manifest['finished_at']
            (root/'conformance/manifest.json').write_text(json.dumps(manifest))
            a = rr.build(root/'conformance', root/'part-conformance.tar.gz', [], part=True) or root/'part-conformance.tar.gz'
            run = rc.Run(root/'bundle')
            merged = {'commit': 'c0ffee', 'dirty': False, 'started_at': '20261111T020000Z', 'platforms': ['amd64'], 'images': {},
                      'phases': run.phases, 'ci': {'job': 'assemble'}}
            rc.merge(merged, run, [a])
            self.assertEqual(sorted(run.failed()), ['conformance/image-variations', 'release/finished-conformance'])

    def test_a_step_is_saved_as_running_before_it_starts(self):
        with tempfile.TemporaryDirectory() as d:
            saved = []
            run = rc.Run(pathlib.Path(d))
            run.save = lambda: saved.append(json.loads(json.dumps(run.phases)))
            run.step('rust', 'probe', ['true'])
            self.assertEqual([s['rust']['probe']['exit'] for s in saved], ['running', 0])

    def test_the_packed_manifest_has_no_running_step(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = pathlib.Path(d)/'bundle'
            manifest = {'commit': 'abc', 'image_tag': 'localhost/k:1.0', 'phases': {}}
            run = rc.Run(bundle, lambda: rc.write_manifest(bundle, manifest))
            manifest['phases'] = run.phases
            run.step('rust', 'probe', ['true'])
            reports = bundle/'reports/r.tar.gz'
            self.assertTrue(rc.pack_reports(run, reports, []))
            import tarfile
            with tarfile.open(reports) as tar:
                packed = json.loads(tar.extractfile('manifest.json').read())
            exits = [s.get('exit') for steps in packed['phases'].values() for s in steps.values()]
            self.assertEqual(exits, [0])
            self.assertEqual(run.phases['release']['reports']['exit'], 0)
            self.assertFalse((bundle/'.manifest.json.partial').exists())

    def test_a_part_that_tested_another_image_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            a = part(root, 'java', {'java': {'suite': step('logs/java-suite.log')}}, {'logs/java-suite.log': 'j'},
                     images={'amd64': {'image_id': 'other', 'archive_sha256': 'a1'}})
            run = rc.Run(root/'bundle')
            manifest = {'commit': 'c0ffee', 'dirty': False, 'started_at': '20261111T020000Z', 'platforms': ['amd64'],
                        'images': {'amd64': {'image_id': 'built', 'archive_sha256': 'a1'}}, 'phases': run.phases, 'ci': {'job': 'assemble'}}
            rc.merge(manifest, run, [a])
            self.assertEqual(run.failed(), ['release/image-amd64-java'])

    def test_a_ci_phase_without_its_inputs_fails(self):
        # In a copy of the harness, so the run's stand-in for the native executable stays out of this checkout.
        import shutil
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)/'checkout'
            shutil.copytree(rc.ROOT/'scripts', root/'scripts', ignore=shutil.ignore_patterns('__pycache__'))
            for name in ['Cargo.toml', 'Dockerfile', '.gitignore']:
                shutil.copy2(rc.ROOT/name, root/name)
            git = ['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid']
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run([*git, 'add', '-A'], cwd=root, check=True)
            subprocess.run([*git, 'commit', '-q', '-m', 't'], cwd=root, check=True)
            bundle = pathlib.Path(d)/'bundle'
            env = dict(os.environ)
            import python_env
            if not python_env.current():
                # Outside the scripts' venv the run would build one from PyPI: stand in a venv of this
                # Python, marked as built from the lock, where the run restarts.
                env['KEYTEND_CACHE_DIR'] = str(pathlib.Path(d)/'cache')
                with mock.patch.dict('os.environ', env):
                    venv = python_env.default_dir()
                subprocess.run([sys.executable, '-m', 'venv', '--without-pip', '--system-site-packages', str(venv)], check=True)
                (venv/python_env.MARKER).write_text(python_env.lock_sha256()+'\n')
            result = subprocess.run([sys.executable, str(root/'scripts/release_candidate.py'), '--ci', '--phases', 'java',
                                     '--bundle', str(bundle)], capture_output=True, text=True, cwd=root, env=env)
            self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
            manifest = json.loads((bundle/'manifest.json').read_text())
            self.assertEqual(manifest['failed_steps'], ['java/precondition'])
            self.assertEqual(manifest['phases']['runtime']['no-native-server']['exit'], 0)
            self.assertFalse((root/'target/debug/keytend-kmip-server').exists(), 'the stand-in is removed')

    def test_only_the_image_job_uploads_image_artifacts(self):
        workflow = yaml.safe_load((rc.ROOT/'.github/workflows/release.yml').read_text())
        for name, job in workflow['jobs'].items():
            for s in job.get('steps', []):
                if s.get('uses', '').startswith('actions/upload-artifact@'):
                    self.assertEqual(s['with']['name'].startswith('image-'), name == 'image', (name, s['with']['name']))

    def test_no_harness_command_runs_a_native_server(self):
        source = (rc.ROOT/'scripts/release_candidate.py').read_text()
        # Every --binary is the image wrapper, and the replays' {binary} placeholder becomes it.
        self.assertEqual(set(re.findall(r"'--binary',([A-Za-z_'{}]+)", source)), {'server', 'server_fips', "'{binary}'"})
        self.assertIn(".replace('{binary}',str(server))", source)
        for text in ("bundle/'keytend-kmip-server'", "native=", "{native}", "ci_builder.py','pack", 'ci-openssl'):
            self.assertNotIn(text, source)
        # The integration groups either take the image or run it as their server executable.
        import test_integration_parallel as tip
        for name, commands in tip.jobs_for('IMAGE', 'IBM', rc.ROOT, '/w/image-server.sh').items():
            for command in commands:
                self.assertIn('--image', command, name)
                if '--binary' in command:
                    self.assertEqual(command[command.index('--binary')+1], '/w/image-server.sh', name)
        workflow = (rc.ROOT/'.github/workflows/release.yml').read_text()
        for text in ('native-amd64', 'ci_builder.py pack', 'ci_runner.sh native', '/etc/pki/tls'):
            self.assertNotIn(text, workflow)

    def test_the_wrapper_runs_the_image_with_the_harness_paths(self):
        import image_server
        with tempfile.TemporaryDirectory() as d:
            text = image_server.wrapper(pathlib.Path(d), 'abc123', run='r1').read_text()
            self.assertIn('--label dev.keytend.harness-run=r1', text)
            self.assertIn(f'-v {rc.ROOT}:{rc.ROOT}', text)
            self.assertIn('--workdir "$workdir"', text)
            self.assertIn('--no-healthcheck', text)
            self.assertTrue(text.rstrip().endswith('abc123 "$@"'))
            self.assertIn(' KMIP_TRIPLE_DES ', text)
            self.assertNotIn(' KMIP_PKI ', text, 'client settings are not server settings')
            fips = image_server.wrapper(pathlib.Path(d), 'abc123', fips=True).read_text()
            self.assertIn('-e KMIP_FIPS=true -e OPENSSL_FORCE_FIPS_MODE=1', fips)
            self.assertNotIn(' KMIP_FIPS ', fips.split('for name in', 1)[1].split(';', 1)[0], 'a fixed setting is never passed through')

    def test_the_wrapper_passes_only_server_settings_and_falls_back_to_root(self):
        import image_server
        with tempfile.TemporaryDirectory() as d:
            fake = pathlib.Path(d)/'bin'
            fake.mkdir()
            (fake/'podman').write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            (fake/'podman').chmod(0o755)
            wrapper = image_server.wrapper(pathlib.Path(d)/'run', 'IMG') if (pathlib.Path(d)/'run').mkdir() is None else None
            env = {'PATH': f'{fake}:/usr/bin:/bin', 'KMIP_TRIPLE_DES': 'enabled', 'KMIP_PKI': '/x', 'TMPDIR': str(pathlib.Path(d)/'run')}
            argv = subprocess.run([str(wrapper), 'serve'], capture_output=True, text=True, env=env, cwd='/').stdout.split('\n')
            self.assertIn('KMIP_TRIPLE_DES', argv)
            self.assertNotIn('KMIP_PKI', argv)
            self.assertEqual(argv[argv.index('--workdir')+1], '/')

    def test_container_fixtures_never_run_the_native_executable(self):
        import test_database
        from unittest import mock
        calls = []
        def run(args, *rest, **options):
            args = [str(a) for a in args]
            calls.append(args)
            if args[0].endswith('dev-pki.sh'):
                pki = pathlib.Path(args[1])
                pki.mkdir(parents=True)
                for name in ['server.pem', 'server.key', 'ca.pem', 'policy.json']:
                    (pki/name).write_text('x')
            if 'generate-master-key' in args:
                host = args[args.index('-v')+1].split(':')[0]
                (pathlib.Path(host)/'master.key').write_bytes(b'k'*32)
            return subprocess.CompletedProcess(args, 0, '', '')
        with tempfile.TemporaryDirectory() as d, mock.patch('subprocess.run', run):
            server = test_database.ContainerServer(d, 'podman', 'IMG', draft=True)
            self.assertTrue((server.tls/'master.key').exists())
        self.assertIsNone(server.binary)
        self.assertFalse([c for c in calls if any('target/debug' in a for a in c)], calls)
        self.assertTrue([c for c in calls if c[:2] == ['podman', 'run'] and 'IMG' in c and 'generate-master-key' in c])

    @staticmethod
    def cargo_build(target, content):
        """As cargo does: a new artifact in deps/, hard-linked (after unlinking) at target/debug."""
        deps, path = target/'deps/keytend_kmip_server-0123', target/'keytend-kmip-server'
        deps.parent.mkdir(parents=True, exist_ok=True)
        deps.unlink(missing_ok=True)
        deps.write_bytes(content)
        path.unlink(missing_ok=True)
        import os
        os.link(deps, path)
        return deps, path

    def test_the_sentinel_logs_calls_and_puts_the_build_back(self):
        with tempfile.TemporaryDirectory() as d:
            deps, path = self.cargo_build(pathlib.Path(d)/'target/debug', b'\x7fELF built')
            sentinel = rc.NativeSentinel(path, pathlib.Path(d)/'calls.log')
            self.assertEqual(subprocess.run([str(path), 'serve', '--x']).returncode, 99)
            self.assertEqual(len(sentinel.calls()), 1)
            self.assertIn('serve --x', sentinel.calls()[0])
            self.assertEqual(deps.read_bytes(), b'\x7fELF built', 'cargo\'s artifact is untouched')
            sentinel.remove()
            self.assertEqual(path.read_bytes(), b'\x7fELF built')
            self.assertEqual(path.stat().st_ino, deps.stat().st_ino)

    def test_a_killed_run_then_a_cargo_relink_corrupts_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            target, log = pathlib.Path(d)/'target/debug', pathlib.Path(d)/'calls.log'
            self.cargo_build(target, b'\x7fELF old')
            rc.NativeSentinel(target/'keytend-kmip-server', log)  # killed: remove() never runs
            deps, path = self.cargo_build(target, b'\x7fELF new')
            sentinel = rc.NativeSentinel(path, log)
            self.assertEqual(deps.read_bytes(), b'\x7fELF new', 'the stand-in is not written through the hard link')
            self.assertTrue(sentinel.is_stub())
            sentinel.remove()
            self.assertEqual(path.read_bytes(), b'\x7fELF new')
            self.assertFalse(sentinel.aside.exists())

    def test_an_aside_copy_left_behind_goes_back(self):
        with tempfile.TemporaryDirectory() as d:
            target, log = pathlib.Path(d)/'target/debug', pathlib.Path(d)/'calls.log'
            deps, path = self.cargo_build(target, b'\x7fELF built')
            rc.NativeSentinel(path, log)  # killed with the stand-in in place
            sentinel = rc.NativeSentinel(path, log)
            sentinel.remove()
            self.assertEqual(path.read_bytes(), b'\x7fELF built')
            rc.NativeSentinel(path, log)
            path.unlink()  # killed, and the stand-in deleted by hand
            rc.NativeSentinel(path, log).remove()
            self.assertEqual(path.read_bytes(), b'\x7fELF built')
            self.assertEqual(deps.read_bytes(), b'\x7fELF built')

    def test_a_build_during_the_run_is_kept(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d)/'target/debug'
            self.cargo_build(target, b'\x7fELF old')
            sentinel = rc.NativeSentinel(target/'keytend-kmip-server', pathlib.Path(d)/'calls.log')
            deps, path = self.cargo_build(target, b'\x7fELF new')
            sentinel.remove()
            self.assertEqual(path.read_bytes(), b'\x7fELF new')
            self.assertFalse(sentinel.aside.exists())

    def test_a_terminated_run_puts_the_build_back(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d)/'target/debug'
            deps, path = self.cargo_build(target, b'\x7fELF built')
            code = (f"import sys,time;sys.path.insert(0,{str(rc.ROOT/'scripts')!r});import release_candidate as rc\n"
                    f"rc.NativeSentinel({str(path)!r},{str(pathlib.Path(d)/'calls.log')!r}).guard(lambda:open({str(pathlib.Path(d)/'cleaned')!r},'w').close())\n"
                    "print('ready',flush=True);time.sleep(30)\n")
            child = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, text=True)
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            self.assertTrue(path.read_bytes().startswith(rc.NativeSentinel.MARK))
            child.terminate()
            self.assertEqual(child.wait(timeout=10), 128+15)
            self.assertEqual(path.read_bytes(), b'\x7fELF built')
            self.assertTrue((pathlib.Path(d)/'cleaned').exists(), 'the handler also removes the run\'s containers')

    def test_an_ignored_sighup_stays_ignored(self):
        import signal
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d)/'target/debug/keytend-kmip-server'
            previous = signal.signal(signal.SIGHUP, signal.SIG_IGN)
            term = signal.getsignal(signal.SIGTERM)
            try:
                sentinel = rc.NativeSentinel(path, pathlib.Path(d)/'calls.log').guard()
                self.assertIs(signal.getsignal(signal.SIGHUP), signal.SIG_IGN)
                self.assertIsNot(signal.getsignal(signal.SIGTERM), term)
                sentinel.remove()
            finally:
                signal.signal(signal.SIGHUP, previous)
                signal.signal(signal.SIGTERM, term)

    def test_a_replaced_stand_in_is_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d)/'target/debug'
            sentinel = rc.NativeSentinel(target/'keytend-kmip-server', pathlib.Path(d)/'calls.log')
            self.assertFalse(sentinel.replaced)
            self.cargo_build(target, b'\x7fELF new')
            sentinel.remove()
            self.assertTrue(sentinel.replaced)
            clean = rc.NativeSentinel(target/'keytend-kmip-server', pathlib.Path(d)/'calls.log')
            clean.remove()
            self.assertFalse(clean.replaced)

    def test_every_integration_group_is_known(self):
        self.assertIn('pbm-interrupted', rc.integration_groups())
        workflow = (rc.ROOT/'.github/workflows/release.yml').read_text()
        listed = {g for line in workflow.splitlines() if line.strip().startswith('groups:') for g in line.split(':', 1)[1].split()}
        self.assertEqual(listed, rc.integration_groups(), 'the workflow slices cover exactly the integration groups')


class RunnerPaths(unittest.TestCase):
    def test_runner_directories_are_replaced_and_its_account_name_kept(self):
        with tempfile.TemporaryDirectory() as d:
            b = pathlib.Path(d)/'bundle'
            (b/'logs').mkdir(parents=True)
            (b/'manifest.json').write_text(json.dumps({'commit': 'abc', 'image_tag': 'localhost/k:1.0', 'phases': {},
                                                       'ci': {'run': {'run_id': '7', 'workflow_ref': 'w'}}}))
            home = '/'.join(['', 'home', 'runner'])
            env = {'GITHUB_ACTIONS': 'true', 'RUNNER_TEMP': f'{home}/work/_temp', 'RUNNER_WORKSPACE': f'{home}/work/k',
                   'RUNNER_TOOL_CACHE': '/opt/hostedtoolcache'}
            (b/'logs/x.log').write_text(f'{home}/work/_temp/native.tar {home}/work/k/other /opt/hostedtoolcache/Java_Corretto_jdk/17 '
                                        f'{home}/.cargo/bin/cargo; the runner account runner\n')
            out = pathlib.Path(d)/'r.tar.gz'
            from unittest import mock
            with mock.patch.dict(rr.os.environ, env):
                rr.build(b, out, ['fv-az123-45'])
            import tarfile
            with tarfile.open(out) as tar:
                log = tar.extractfile('logs/x.log').read().decode()
                readme = tar.extractfile('README.txt').read().decode()
            self.assertEqual(log, '<runner-temp>/native.tar <runner-work>/other <tool-cache>/Java_Corretto_jdk/17 ~/.cargo/bin/cargo; '
                                  'the runner account runner\n')
            self.assertIn('run 7 of\nw.', readme)
            self.assertNotIn('<user>', readme)


if __name__ == '__main__':
    unittest.main()
