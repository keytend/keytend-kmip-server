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

"""Controlled PBM startup and integration-runner checks; no live fixtures."""
import json
import contextlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from unittest import mock

import test_database_pbm as pbm
import test_integration_parallel as parallel


class RunnerTests(unittest.TestCase):
    def run_groups(self, jobs, workers, slots, child):
        with tempfile.TemporaryDirectory(prefix='runner-test-') as directory:
            out = pathlib.Path(directory)
            with mock.patch.object(parallel.subprocess, 'run', side_effect=child), \
                    mock.patch.object(parallel, 'copy_artifacts'), contextlib.redirect_stdout(io.StringIO()):
                return dict(parallel.run_groups(jobs, out, workers, slots)), out

    def test_db_slots_bound_database_groups_only(self):
        lock = threading.Lock()
        active = {'db': 0, 'peak': 0}
        def child(command, **kwargs):
            if command[0] == 'db':
                with lock:
                    active['db'] += 1
                    active['peak'] = max(active['peak'], active['db'])
                time.sleep(.05)
                with lock:
                    active['db'] -= 1
            return subprocess.CompletedProcess(command, 0)
        jobs = {name: [['db']] for name in ['pbm', 'pbm-destroyed', 'mysql', 'database-baseline']}
        jobs['hash'] = [['other']]
        results, _ = self.run_groups(jobs, 5, 2, child)
        self.assertEqual({r['status'] for r in results.values()}, {'passed'})
        self.assertEqual(active['peak'], 2)

    def test_failure_and_timeout_stop_the_group_and_are_recorded(self):
        calls = []
        def child(command, **kwargs):
            calls.append(command)
            kwargs['stdout'].write('controlled output\n')
            if command == ['slow']:
                raise subprocess.TimeoutExpired(command, 1)
            return subprocess.CompletedProcess(command, 1 if command == ['bad'] else 0)
        results, out = self.run_groups({'hash': [['bad'], ['never']], 'metrics': [['slow']], 'runtime': [['ok']]}, 3, 1, child)
        self.assertNotIn(['never'], calls)
        self.assertEqual(results['hash']['status'], 'failed')
        self.assertEqual(results['metrics']['steps'][0].get('timed_out'), True)
        self.assertEqual(results['runtime']['status'], 'passed')
        self.assertTrue(results['hash']['steps'][0]['log_sha256'])

    def test_failed_run_exits_one_and_each_run_is_a_new_attempt(self):
        with tempfile.TemporaryDirectory(prefix='runner-main-test-') as directory:
            root = pathlib.Path(directory)
            def child(command, **kwargs):
                return subprocess.CompletedProcess(command, 1)
            with mock.patch.object(parallel, 'ROOT', root), mock.patch.object(
                    parallel, 'local_image_id', return_value='controlled-id'), mock.patch.object(
                    parallel, 'packaged_evidence', return_value={'tested_image_config_id': 'controlled-id'}), mock.patch.object(
                    parallel.subprocess, 'check_output', return_value='controlled-commit'), mock.patch.object(
                    parallel.subprocess, 'run', side_effect=child), contextlib.redirect_stdout(io.StringIO()):
                for _ in range(2):
                    with self.assertRaises(SystemExit) as error:
                        parallel.main(['--image', 'controlled-image', '--groups', 'pbm-compromised'])
                    self.assertEqual(error.exception.code, 1)
            attempts = list((root/'artifacts/integration-qualification').glob('attempt-*'))
            self.assertEqual(len(attempts), 2)
            for attempt in attempts:
                summary = json.loads((attempt/'summary.json').read_text())
                self.assertEqual((summary['status'], set(summary['jobs'])), ('failed', {'pbm-compromised'}))
                command = summary['jobs']['pbm-compromised']['steps'][0]['command']
                self.assertEqual(command[1], 'scripts/test_database_pbm_adverse.py')
                self.assertTrue(command[command.index('--output')+1].startswith(str(attempt)))


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pbm-start-test-')
        self.addCleanup(self.temp.cleanup)
        root = pathlib.Path(self.temp.name)
        self.out = root/'output'
        self.out.mkdir()
        patch = mock.patch.object(pbm, 'OUT', self.out)
        patch.start()
        self.addCleanup(patch.stop)
        self.fixture = pbm.PbmSet.__new__(pbm.PbmSet)
        self.fixture.controls = [root/'control']
        self.fixture.controls[0].mkdir()
        self.fixture.password = 'secret/value+with spaces'
        self.fixture.engine = 'controlled-engine'
        self.fixture.names = ['owned-controlled-member']

    def launch(self, command, **kwargs):
        if command[1] == 'inspect':
            return json.dumps({'Running': True, 'Error': '', 'Env': ['must-not-be-collected']})
        directory = self.fixture.controls[0]/pathlib.Path(command[8]).name
        (directory/'pid').write_text('12345')
        return 'detached exec accepted'

    def diagnostics(self):
        paths = [p for p in self.out.glob('agent-start-*.json') if not p.name.endswith('-execution.json')]
        return json.loads(paths[-1].read_text())

    def test_wrapper_retains_real_early_exit_and_redacts_stderr(self):
        # Run the exact wrapper with a controlled child instead of vendor/container.
        original_run = subprocess.run
        def launch(command, **kwargs):
            if command[1] == 'inspect':
                return self.launch(command, **kwargs)
            directory = self.fixture.controls[0]/pathlib.Path(command[8]).name
            child = 'import sys; print(sys.argv[1], file=sys.stderr); sys.exit(126)'
            result = original_run(['sh', '-c', pbm.AGENT_WRAPPER, 'pbm-agent-start',
                str(directory), sys.executable, '-c', child, self.fixture.password],
                capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 126)
            return 'detached exec accepted'
        with mock.patch.object(pbm.subprocess, 'check_output', side_effect=launch):
            started = time.monotonic()
            with self.assertRaisesRegex(AssertionError, 'startup failed without restart'):
                self.fixture.start_agent(0, seconds=.5)
            self.assertLess(time.monotonic()-started, 2)
        data = self.diagnostics()
        self.assertEqual(data['exit'].strip(), '126')
        self.assertIn('[redacted]', data['stderr'])
        self.assertNotIn(self.fixture.password, json.dumps(data))
        execution = next(self.out.glob('*-execution.json')).read_text()
        self.assertEqual(json.loads(execution)['command'][6], pbm.AGENT_WRAPPER)

    def test_detached_wrapper_waits_for_child_and_records_signal_exit(self):
        directory = self.fixture.controls[0]/'lifetime'
        directory.mkdir()
        child = "import time; print('ready', flush=True); time.sleep(30)"
        with subprocess.Popen(['sh', '-c', pbm.AGENT_WRAPPER, 'pbm-agent-start',
                str(directory), sys.executable, '-c', child], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True) as wrapper:
            try:
                until = time.monotonic()+3
                while time.monotonic() < until:
                    if (directory/'stdout').exists() and (directory/'stdout').read_text() == 'ready\n':
                        break
                    time.sleep(.01)
                self.assertEqual((directory/'stdout').read_text(), 'ready\n')
                self.assertIsNone(wrapper.poll())
                self.assertFalse((directory/'exit').exists())
                import signal
                os.kill(int((directory/'pid').read_text()), signal.SIGTERM)
                self.assertEqual(wrapper.wait(timeout=3), 143)
                self.assertEqual((directory/'exit').read_text().strip(), '143')
            finally:
                if wrapper.poll() is None:
                    import signal
                    os.killpg(wrapper.pid, signal.SIGKILL)
                    wrapper.wait(timeout=3)

    def test_failed_host_witness_does_not_waive_or_fail_vendor_survival(self):
        with mock.patch.object(pbm, 'inotify_observation', return_value=dict(ok=False, errno=24)), mock.patch.object(
                pbm.subprocess, 'check_output', side_effect=self.launch), mock.patch.object(
                pbm.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '')):
            self.fixture.start_agent(0, seconds=.5, stable_seconds=.01)
        data = self.diagnostics()
        self.assertFalse(data['launch']['inotify_before_launch']['ok'])
        self.assertFalse(data['inotify_at_collection']['ok'])

    def test_log_ranges_exclude_old_restore_and_later_launch_events(self):
        log = self.fixture.controls[0]/'agent.log'
        log.write_text('old restore Exit: <nil>\n')
        def launch(command, **kwargs):
            if command[1] != 'inspect':
                with log.open('a') as stream:
                    stream.write('new launch error '+self.fixture.password+'\n')
                directory = self.fixture.controls[0]/pathlib.Path(command[8]).name
                (directory/'exit').write_text('1')
            return self.launch(command, **kwargs)
        with mock.patch.object(pbm.subprocess, 'check_output', side_effect=launch):
            for _ in range(2):
                with self.assertRaisesRegex(AssertionError, 'startup failed'):
                    self.fixture.start_agent(0, seconds=.5)
        directories = sorted(self.fixture.controls[0].glob('agent-start-*'))
        for directory in directories:
            self.fixture.agent_diagnostics(0, directory, 'final collection')
            data = json.loads((self.out/(directory.name+'.json')).read_text())
            self.assertTrue(data['agent_log_range_valid'])
            fragment = (self.out/(directory.name+'-agent-launch.log')).read_text()
            self.assertEqual(fragment, 'new launch error [redacted]\n')
            self.assertNotIn('old restore', fragment)

    def test_truncated_or_replaced_log_is_not_claimed_as_launch_output(self):
        log = self.fixture.controls[0]/'agent.log'
        for replace in [False, True]:
            log.write_text('old restore events\n'*10)
            def launch(command, **kwargs):
                if command[1] != 'inspect':
                    if replace:
                        log.rename(log.with_suffix('.old'))
                    log.write_text('new short log\n')
                    directory = self.fixture.controls[0]/pathlib.Path(command[8]).name
                    (directory/'exit').write_text('1')
                return self.launch(command, **kwargs)
            with mock.patch.object(pbm.subprocess, 'check_output', side_effect=launch):
                with self.assertRaisesRegex(AssertionError, 'startup failed'):
                    self.fixture.start_agent(0, seconds=.5)
            directory = self.fixture.agent_starts[0]
            data = json.loads((self.out/(directory.name+'.json')).read_text())
            self.assertFalse(data['agent_log_range_valid'])
            self.assertFalse((self.out/(directory.name+'-agent-launch.log')).exists())

    def test_wrapper_shell_failure_is_captured_separately(self):
        directory = self.fixture.controls[0]/'shell-failure'
        directory.mkdir()
        # Child redirection fails in the shell before executing the vendor.
        (directory/'stdout').mkdir()
        result = subprocess.run(['sh', '-c', pbm.AGENT_WRAPPER,
            'pbm-agent-start', str(directory), 'true'], capture_output=True, text=True, timeout=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, '')
        self.assertTrue((directory/'wrapper-stderr').read_text())
        self.assertNotEqual((directory/'exit').read_text().strip(), '0')

    def test_inotify_witness_closes_descriptor_and_retains_errno(self):
        for fd in [91, -1]:
            library = mock.Mock()
            library.inotify_init1.return_value = fd
            with mock.patch.object(pbm.ctypes, 'CDLL', return_value=library), mock.patch.object(
                    pbm.ctypes, 'get_errno', return_value=24), mock.patch.object(pbm.os, 'close') as close:
                result = pbm.inotify_observation()
            self.assertEqual(result['ok'], fd >= 0)
            if fd >= 0:
                close.assert_called_once_with(fd)
            else:
                close.assert_not_called()
                self.assertEqual(result['errno'], 24)
            self.assertIn('distinct from vendor syscall', result['scope'])

    def test_exec_rejection_retains_stderr_without_credentials_or_environment(self):
        def launch(command, **kwargs):
            if command[1] == 'inspect':
                return self.launch(command, **kwargs)
            raise subprocess.CalledProcessError(126, command, output=
                'failed '+urllib.parse.quote(self.fixture.password, safe=''))
        with mock.patch.object(pbm.subprocess, 'check_output', side_effect=launch):
            with self.assertRaisesRegex(AssertionError, 'startup failed'):
                self.fixture.start_agent(0, seconds=.1)
        data = self.diagnostics()
        self.assertIn('[redacted]', data['observation']['error'])
        self.assertNotIn('Env', data['container_state'])

    def test_no_pid_and_dead_process_are_bounded_failures(self):
        for has_pid in [False, True]:
            def launch(command, **kwargs):
                if command[1] == 'inspect' or has_pid:
                    return self.launch(command, **kwargs)
                return 'detached exec accepted without starting'
            with mock.patch.object(pbm.subprocess, 'check_output', side_effect=launch), mock.patch.object(
                    pbm.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, 'no process')):
                with self.assertRaisesRegex(AssertionError, 'startup failed'):
                    self.fixture.start_agent(0, seconds=.02)
        self.assertEqual(len(list(self.out.glob('*-execution.json'))), 2)

    def test_live_startup_requires_stability_and_later_exit_fails_health_early(self):
        with mock.patch.object(pbm.subprocess, 'check_output', side_effect=self.launch), mock.patch.object(
                pbm.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '')) as probe:
            self.fixture.start_agent(0, seconds=.5, stable_seconds=.01)
            self.assertGreaterEqual(probe.call_count, 2)
            directory = self.fixture.agent_starts[0]
            (directory/'exit').write_text('1')
            with self.assertRaisesRegex(AssertionError, 'agent exited without restart'):
                self.fixture.wait(self.fixture.agent_health, seconds=600)
        data = self.diagnostics()
        self.assertTrue(data['observations'])

    def test_unhealthy_registration_is_retained_on_wait_failure(self):
        self.fixture.primary = lambda: 0
        self.fixture.shell = lambda *args: [{'v': '2.17.0', 'e': self.fixture.password}]
        with mock.patch.object(pbm.time, 'sleep'):
            with self.assertRaises(AssertionError) as error:
                self.fixture.wait(self.fixture.agent_health, seconds=.01)
        self.assertIn('2.17.0', str(error.exception))
        self.assertIn('[redacted]', str(error.exception))
        self.assertNotIn(self.fixture.password, str(error.exception))


if __name__ == '__main__':
    unittest.main()
