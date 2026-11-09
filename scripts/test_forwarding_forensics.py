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

"""Safety boundaries for opt-in process attribution, without attaching to hosts."""
import unittest
import tempfile
import pathlib
from unittest.mock import Mock
from forwarding_forensics import ForwardingCapture, owns_pasta, tcp_rows, SOCKET_SYSCALLS
from analyze_forwarding import trace_failures, correlate


class OwnershipTests(unittest.TestCase):
    def test_exact_namespace_executable_and_both_port_arguments_required(self):
        sandbox = '/run/user/1000/netns/owned'
        ports = ['127.0.0.1/30001-30001:5696-5696', '127.0.0.1/30002-30002:8080-8080']
        args = ['pasta', '--netns', sandbox, '-t', ports[0], '-t', ports[1]]
        self.assertTrue(owns_pasta(dict(exe='/usr/bin/pasta.avx2', argv=args), sandbox, ports))
        for changed in [args[:2] + [sandbox + '-other'] + args[3:], args[:-2],
                        ['pasta', '--debug-message=' + sandbox, '-t', ports[0], '-t', ports[1]]]:
            self.assertFalse(owns_pasta(dict(exe='/usr/bin/pasta', argv=changed), sandbox, ports))
        self.assertFalse(owns_pasta(dict(exe='/tmp/unrelated', argv=args), sandbox, ports))

    def test_no_buffer_syscalls_or_class_expansion(self):
        self.assertEqual(set(SOCKET_SYSCALLS.split(',')),
                         {'socket', 'bind', 'connect', 'accept', 'accept4', 'close',
                          'shutdown', 'getsockname', 'getpeername'})

    def test_namespace_and_host_filters_exclude_unrelated_ports(self):
        table = ('header\n'
                 '0: 0201FEA9:1640 0100007F:ABCD 06 0:0 0:0 0 1000 0 0\n'
                 '1: 0100007F:ABCD 0100007F:1640 01 0:0 0:0 0 1000 0 123\n'
                 '2: 0100007F:0035 0100007F:9999 01 0:0 0:0 0 1000 0 456\n')
        self.assertEqual(len(tcp_rows(table, {5696})), 1)
        self.assertEqual(len(tcp_rows(table, {5696}, either=True)), 2)
        self.assertEqual(tcp_rows(table, {5696})[0]['state'], '06')

    def test_dead_tracer_is_failure_even_with_no_client_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = ForwardingCapture(directory, None, None, pathlib.Path(__file__))
            capture.identity['status'] = 'capturing'
            capture.tracer = Mock()
            capture.tracer.poll.return_value = 1
            capture.tracer.wait.return_value = 1
            with self.assertRaisesRegex(AssertionError, 'metadata collection failed'):
                capture.stop()
            self.assertEqual(capture.identity['status'], 'capture_errors')
            capture.tracer.terminate.assert_not_called()

    def test_correlate_preserves_missing_and_ambiguous_evidence(self):
        lines = [
            '123.000001 accept4(6, {sin_port=htons(40000)}, [16], SOCK_NONBLOCK) = 82 <0.1>',
            '123.000002 connect(84, {sin_port=htons(5696)}, 16) = -1 EADDRNOTAVAIL <0.1>',
            # An extra connect cannot borrow the earlier accept's client port.
            '123.000003 connect(85, {sin_port=htons(5696)}, 16) = -1 EADDRNOTAVAIL <0.1>',
            '123.000004 connect(86, {sin_port=htons(8080)}, 16) = -1 EADDRNOTAVAIL <0.1>']
        failures, outcomes = trace_failures(lines)
        self.assertEqual(outcomes['8080:EADDRNOTAVAIL'], 1)
        self.assertEqual(failures[0]['connect_time_ns'], 123_000_002_000)
        result = correlate(failures, [dict(local=['127.0.0.1', 40000], wall_ns=123_000_010_000),
                                      dict(local=['127.0.0.1', 40001], wall_ns=123_000_010_000)])
        self.assertEqual(result['matched_source_port_and_time'], 1)
        self.assertEqual(result['unmatched_forwarder'], 1)
        self.assertEqual(result['unmatched_client'], 1)
        late = correlate(failures[:1], [dict(local=['127.0.0.1', 40000], wall_ns=130_000_000_000)])
        self.assertEqual(late['matched_source_port_and_time'], 0)


if __name__ == '__main__':
    unittest.main()
