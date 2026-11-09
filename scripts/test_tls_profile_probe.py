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

"""Offline tests for the TLS profile inventory and handshake probe classifier (no servers)."""
import json
import pathlib
import unittest

import tls_profile_probe as probe
import wire

ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY = json.loads(probe.INVENTORY.read_text())

RECEIVED_HANDSHAKE_FAILURE = ('Connecting to 127.0.0.1\n40F7:error:0A000410:SSL routines:ssl3_read_bytes:'
                              'ssl/tls alert handshake failure:../ssl/record/rec_layer_s3.c:916:SSL alert number 40\n')
# TLS 1.3: the client reports a finished handshake, then receives the server's rejection.
TLS13_LATE_REJECT = ('CONNECTION ESTABLISHED\nProtocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384\n'
                     'Verification: OK\n40F7:error:0A00045C:SSL routines:ssl3_read_bytes:tlsv13 alert certificate '
                     'required:../ssl/record/rec_layer_s3.c:916:SSL alert number 116\n')
CLIENT_VERIFY_FAILURE = ('verify error:num=62:hostname mismatch\n40F7:error:0A000086:SSL routines:'
                         'tls_post_process_server_certificate:certificate verify failed:../ssl/statem/statem_clnt.c:2124:\n')
CLIENT_NO_PROTOCOLS = '40F7:error:0A0000BF:SSL routines:tls_setup_handshake:no protocols available:../ssl/statem/statem_lib.c:153:\n'


def row(outcome, *, proto='tls1_2', cipher=None, suite=None, group=None, negotiated=None, identity='client',
        verify_name='localhost', listener='ttlv', **extra):
    version = {'tls1': 'TLSv1', 'tls1_1': 'TLSv1.1', 'tls1_2': 'TLSv1.2', 'tls1_3': 'TLSv1.3'}[proto]
    facts = {'Ciphersuite (IANA)': negotiated or cipher or suite, 'Protocol version': version} if outcome == 'negotiated' else {}
    return {'outcome': outcome, 'proto': proto, 'cipher': cipher, 'suite': suite, 'group': group, 'facts': facts,
            'identity': identity, 'verify_name': verify_name, 'listener': listener, **extra}


def delta(**changed):
    d = dict.fromkeys(probe.DELTA_KEYS, 0)
    d.update(tcp_accepted_total=1, tls_started_total=1, closed_total=1)
    d.update(changed)
    return d


class ClassifyTests(unittest.TestCase):
    def test_received_alert_is_server_rejection(self):
        outcome, _, detail = probe.classify(RECEIVED_HANDSHAKE_FAILURE, None)
        self.assertEqual((outcome, detail), ('server-rejected', 'handshake failure (40)'))

    def test_tls13_reported_handshake_without_kmip_answer_is_not_accepted(self):
        outcome, facts, detail = probe.classify(TLS13_LATE_REJECT, None)
        self.assertEqual(outcome, 'server-rejected')
        self.assertEqual(facts['Protocol version'], 'TLSv1.3')
        self.assertIn('116', detail)

    def test_client_side_verification_failure_is_not_a_server_rejection(self):
        self.assertEqual(probe.classify(CLIENT_VERIFY_FAILURE, None)[0], 'client-rejected-server')

    def test_client_unable_to_build_hello_is_not_a_server_rejection(self):
        self.assertEqual(probe.classify(CLIENT_NO_PROTOCOLS, None)[0], 'client-refused')

    def test_eof_during_handshake_is_not_credited_or_called_an_alert(self):
        err = '80E7:error:0A000126:SSL routines::unexpected eof while reading:../ssl/record/rec_layer_s3.c:698:\n'
        self.assertEqual(probe.classify(err, None)[0], 'closed-during-handshake')

    def test_shutdown_counters_use_the_shutdown_line_only(self):
        startup = json.dumps({'fields': {'message': 'listening', 'counters': 'ignored'}})
        shutdown = json.dumps({'fields': {'phase': 'shutdown', 'counters': json.dumps({'tls_failed_total': 3})}})
        self.assertEqual(probe.shutdown_counters((startup + '\n' + shutdown + '\nnot json\n').encode()), {'tls_failed_total': 3})
        self.assertIsNone(probe.shutdown_counters(startup.encode()))

    def test_handshake_only_is_not_negotiated(self):
        self.assertEqual(probe.classify('Protocol version: TLSv1.2\nCiphersuite: X\n', None)[0],
                         'handshake-without-application-response')

    def test_application_answer_is_required_for_negotiated(self):
        self.assertEqual(probe.classify(TLS13_LATE_REJECT, {'result_status': 0})[0], 'negotiated')


class FramingTests(unittest.TestCase):
    def test_ttlv_frame_needs_declared_length(self):
        frame = wire.encode(wire.structure(0x42007b, wire.integer(0x42000d, 1)))
        self.assertFalse(probe.complete(frame[:-1], False))
        self.assertTrue(probe.complete(frame, False))
        self.assertFalse(probe.complete(frame[:7], False))

    def test_http_needs_full_body(self):
        head = b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n'
        self.assertFalse(probe.complete(head + b'abc', True))
        self.assertTrue(probe.complete(head + b'abcd', True))
        self.assertFalse(probe.complete(b'HTTP/1.1 200 OK\r\n\r\nabcd', True))

    def test_kmip_result_reads_status_and_reason(self):
        item = wire.structure(0x42000f, wire.enumeration(0x42005c, 30), wire.enumeration(0x42007f, 1), wire.enumeration(0x42007e, 12))
        data = wire.encode(wire.structure(0x42007b, wire.structure(0x42007a), item))
        self.assertEqual(probe.kmip_result(data, False), {'result_status': 1, 'result_reason': 12})


class InventoryTests(unittest.TestCase):
    def test_editions_pin_profile_archives(self):
        pins = {p['version']: p for p in json.loads((ROOT / 'docs/specs/profiles.json').read_text())}
        for edition, e in INVENTORY['editions'].items():
            self.assertEqual(e['profiles_sha256'], pins[edition.split('-')[0]]['sha256'], edition)

    def test_tls13_lists_exclude_aes128_gcm_from_2_0(self):
        for edition in ['2.0', '2.1', '3.0-csd02']:
            ciphers = INVENTORY['editions'][edition]['suites']['basic']['ciphers']
            self.assertEqual(sorted(ciphers['tls13_server_shall_all_if_tls13']), ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'])
            self.assertTrue(ciphers['closed_list'])

    def test_no_edition_lists_the_runtime_extra_aead_suites(self):
        extras = {'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                  'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                  'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'}
        for key, s in probe.suite_sets(INVENTORY).items():
            if s['allowed'] is not None:
                self.assertFalse(extras & set(s['allowed']), key)

    def test_only_explicit_lists_are_closed(self):
        sets = probe.suite_sets(INVENTORY)
        self.assertIsNone(sets[('1.1', 'basic')]['allowed'])  # MAY list is an unpinned NIST table
        for edition in ['1.2', '1.3', '1.4']:
            self.assertIsNone(sets[(edition, 'tls12')]['allowed'], edition)
            self.assertIsNotNone(sets[(edition, 'basic')]['allowed'], edition)
        self.assertEqual(sets[('1.4', 'basic')]['protocols_forbidden'], ['SSLv1.0', 'SSLv2.0', 'SSLv3.0', 'TLSv1.0'])
        self.assertIn('TLSv1.0', sets[('1.3', 'basic')]['protocols_required'])


class ArtifactTests(unittest.TestCase):
    def test_archive_identity_reads_nested_layers_without_extraction(self):
        import io, tarfile, tempfile
        def tar(files):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w') as t:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    t.addfile(info, io.BytesIO(data))
            return buf.getvalue()
        layer = tar({'usr/lib/x86_64-linux-gnu/libcrypto.so.3': b'xx OpenSSL 3.0.22 25 Aug 2026 xx',
                     'var/lib/dpkg/status': b'Package: libssl3\nSource: openssl\nVersion: 3.0.22-1~deb12u2\n\n'})
        archive = tar({'manifest.json': json.dumps([{'Config': 'c.json', 'Layers': ['l.tar']}]).encode(), 'l.tar': layer})
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d, 'image.tar')
            path.write_bytes(archive)
            got = probe.archive_tls_identity(path)
        self.assertEqual((got['libssl3_package'], got['openssl_version_string']), ('3.0.22-1~deb12u2', 'OpenSSL 3.0.22 25 Aug 2026'))
        self.assertNotIn('usr/lib/x86_64-linux-gnu/libssl.so.3', got['files_sha256'])  # absent files are not invented

    def test_archive_identity_follows_rhel_library_symlinks_and_records_openssl_env(self):
        import io, tarfile, tempfile
        def tar(files, links={}):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode='w') as t:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    t.addfile(info, io.BytesIO(data))
                for name, target in links.items():
                    info = tarfile.TarInfo(name)
                    info.type, info.linkname = tarfile.SYMTYPE, target
                    t.addfile(info)
            return buf.getvalue()
        layer = tar({'usr/lib64/libcrypto.so.3.5.8': b'xx OpenSSL 3.5.8 25 Aug 2026 xx', 'usr/lib64/libssl.so.3.5.8': b'ssl',
                     'etc/keytend-kmip-server/openssl.cnf': b'conf'},
                    {'usr/lib64/libcrypto.so.3': 'libcrypto.so.3.5.8', 'usr/lib64/libssl.so.3': 'libssl.so.3.5.8', 'lib64': 'usr/lib64'})
        config = json.dumps({'config': {'Env': ['PATH=/usr/bin', 'OPENSSL_CONF=/etc/keytend-kmip-server/openssl.cnf']}}).encode()
        archive = tar({'manifest.json': json.dumps([{'Config': 'c.json', 'Layers': ['l.tar']}]).encode(), 'c.json': config, 'l.tar': layer})
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d, 'image.tar')
            path.write_bytes(archive)
            got = probe.archive_tls_identity(path)
        self.assertEqual(got['openssl_version_string'], 'OpenSSL 3.5.8 25 Aug 2026')
        self.assertEqual(got['openssl_env'], ['OPENSSL_CONF=/etc/keytend-kmip-server/openssl.cnf'])
        self.assertEqual(sorted(got['files_sha256']), ['etc/keytend-kmip-server/openssl.cnf', 'usr/lib64/libcrypto.so.3', 'usr/lib64/libssl.so.3'])
        self.assertEqual(got['files_sha256']['usr/lib64/libssl.so.3'], probe.sha256(b'ssl'))
        self.assertIsNone(got['libssl3_package'])

    def test_compact_keeps_hashes_and_drops_paths_and_extra_facts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            summary = {'started': 's', 'finished': 'f', 'harness_sha256': 'h', 'inventory_sha256': 'i', 'client': {}, 'native_binary': {'sha256': 'n', 'path': '/secret/path'},
                       'pki': {'client': {'certificate_sha256': 'c', 'subject': 'CN=client', 'issuer': 'CN=ca', 'public_key': 'rsa', 'bits': 2048, 'curve': None, 'signature': 'sha256', 'extensions': 'x'}},
                       'fixtures': {'native-rsa': {'kind': 'native', 'server_identity': 'server-rsa', 'started': 's', 'command': [f'{d}/fixtures/native-rsa/data/kmip.sqlite'],
                                                   'closed_after': True, 'server_log_sha256': 'l', 'shutdown_counters': None, 'server_tls_succeeded_equals_client_negotiated': None,
                                                   'results': [{'id': 'p', 'listener': 'ttlv', 'outcome': 'negotiated', 'raw_sha256': 'r', 'kmip': {'result_status': 0},
                                                                'facts': {'Protocol version': 'TLSv1.3', 'Requested Signature Algorithms': 'long'}}], 'evaluation': {'2.0/basic': {'missing_required': [], 'closed_list': True}}}}}
            path = pathlib.Path(d, 'summary.json')
            path.write_text(json.dumps(summary))
            probe.compact(path, pathlib.Path(d, 'out.json'))
            out = json.loads(pathlib.Path(d, 'out.json').read_text())
        f = out['fixtures']['native-rsa']
        self.assertEqual(f['command'], ['$OUTPUT/fixtures/native-rsa/data/kmip.sqlite'])
        self.assertEqual(f['results'][0], {'id': 'p', 'listener': 'ttlv', 'outcome': 'negotiated', 'raw_sha256': 'r', 'kmip': {'result_status': 0}, 'Protocol version': 'TLSv1.3'})
        self.assertEqual(f['evaluation_recorded_at_probe_time'], {'2.0/basic': {'closed_list': True}})
        self.assertIs(f['evaluation_recomputed']['1.3/suite_b_128']['modelled'], False)
        self.assertIsNone(f['evaluation_recomputed']['1.3/suite_b_128']['would_conflict_if_claimed'])
        self.assertNotIn('path', out['native_binary'])
        self.assertNotIn('extensions', out['pki']['client'])


class EvaluateTests(unittest.TestCase):
    def evaluate(self, rows):
        return probe.evaluate(INVENTORY, rows)

    def test_client_cannot_attempt_never_counts_as_missing(self):
        f = self.evaluate([row('negotiated', negotiated='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
                           row('client-cannot-attempt', cipher='TLS_RSA_WITH_AES_128_CBC_SHA256'),
                           row('client-cannot-attempt', cipher='TLS_RSA_WITH_AES_256_CBC_SHA256')])
        self.assertEqual(f['2.1/basic']['missing_required'], [])
        self.assertTrue(any('client-cannot-attempt' in u for u in f['2.1/basic']['untested_required']))

    def test_server_rejection_of_required_suite_is_missing(self):
        f = self.evaluate([row('server-rejected', cipher='TLS_RSA_WITH_AES_128_CBC_SHA256')])
        self.assertIn('TLS_RSA_WITH_AES_128_CBC_SHA256', f['1.4/basic']['missing_required'])

    def test_tls13_aes128_is_outside_2x_but_listed_suites_are_not(self):
        f = self.evaluate([row('negotiated', proto='tls1_3', suite='TLS_AES_128_GCM_SHA256'),
                           row('negotiated', proto='tls1_3', suite='TLS_AES_256_GCM_SHA384'),
                           row('negotiated', proto='tls1_3', suite='TLS_CHACHA20_POLY1305_SHA256')])
        self.assertEqual(f['2.0/basic']['outside_closed_list'], ['TLS_AES_128_GCM_SHA256'])
        self.assertEqual(f['1.1/basic']['outside_closed_list'], [])  # not closed: no credit, no finding

    def test_unlisted_client_hostname_and_https_rows_do_not_count(self):
        rows = [row('negotiated', proto='tls1_3', suite='TLS_AES_128_GCM_SHA256', identity='unlisted'),
                row('negotiated', proto='tls1_3', suite='TLS_AES_128_GCM_SHA256', verify_name='wrong.invalid'),
                row('negotiated', proto='tls1_3', suite='TLS_AES_128_GCM_SHA256', listener='https')]
        self.assertEqual(self.evaluate(rows)['2.0/basic']['outside_closed_list'], [])

    def test_forbidden_protocol_acceptance_is_reported(self):
        f = self.evaluate([row('negotiated', proto='tls1', negotiated='TLS_RSA_WITH_AES_128_CBC_SHA')])
        self.assertEqual(f['1.4/basic']['forbidden_protocols_accepted'], ['TLSv1.0'])
        self.assertEqual(f['1.3/basic']['forbidden_protocols_accepted'], [])

    def test_quantum_safe_rejects_tls12_and_classical_groups(self):
        f = self.evaluate([row('negotiated', proto='tls1_2', negotiated='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
                           row('negotiated', proto='tls1_3', group='x25519', negotiated='TLS_AES_256_GCM_SHA384', negotiated_group='x25519'),
                           row('server-rejected', proto='tls1_3', group='SecP384r1MLKEM1024')])
        qs = f['3.0-csd02/quantum_safe']
        self.assertEqual(qs['forbidden_protocols_accepted'], ['TLSv1.2'])
        self.assertIn('x25519', qs['outside_closed_list'])
        self.assertIn('SecP384r1MLKEM1024', qs['missing_required'])

    def test_credential_mismatch_is_not_missing_or_policy_evidence(self):
        f = self.evaluate([row('negotiated', negotiated='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'),
                           row('server-rejected', cipher='TLS_RSA_WITH_AES_128_CBC_SHA256', credential_compatible=False)])
        self.assertEqual(f['1.4/basic']['missing_required'], [])
        self.assertIn('TLS_RSA_WITH_AES_128_CBC_SHA256: untested-credential-mismatch', f['1.4/basic']['untested_required'])

    def test_2x_tls12_suites_apply_when_fixture_tls12_support_is_observed(self):
        rejected = row('server-rejected', cipher='TLS_RSA_WITH_AES_128_CBC_SHA256')
        without = self.evaluate([row('negotiated', proto='tls1_3', suite='TLS_AES_256_GCM_SHA384'), rejected])['2.0/basic']
        self.assertEqual(without['missing_required'], [])
        self.assertIn('TLSv1.2 suites not applied: server support not observed', without['conditions'])
        with_tls12 = self.evaluate([row('negotiated', negotiated='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'), rejected])['2.0/basic']
        self.assertEqual(with_tls12['missing_required'], ['TLS_RSA_WITH_AES_128_CBC_SHA256'])

    def test_contradicted_server_counters_withdraw_credit_and_findings(self):
        f = self.evaluate([row('negotiated', proto='tls1_3', suite='TLS_AES_128_GCM_SHA256', attribution='contradicted')])
        self.assertEqual(f['2.0/basic']['outside_closed_list'], [])
        self.assertIn('TLS_AES_256_GCM_SHA384: untested', f['3.0-csd02/quantum_safe']['untested_required'])

    def test_server_recorded_failure_without_alert_counts_as_rejection(self):
        f = self.evaluate([row('negotiated', negotiated='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
                           row('closed-during-handshake', cipher='TLS_RSA_WITH_AES_256_CBC_SHA256',
                               attribution='server-recorded-tls-failure-alert-not-observed')])
        self.assertIn('TLS_RSA_WITH_AES_256_CBC_SHA256', f['1.4/tls12']['missing_required'])

    def test_negotiated_groups_come_from_reported_key_exchange(self):
        f = self.evaluate([row('negotiated', proto='tls1_3', suite='TLS_AES_256_GCM_SHA384',
                               negotiated_group=probe.negotiated_group({'Protocol version': 'TLSv1.3', 'Negotiated TLS1.3 group': 'X25519MLKEM768'})),
                           row('negotiated', proto='tls1_3', suite='TLS_CHACHA20_POLY1305_SHA256',
                               negotiated_group=probe.negotiated_group({'Protocol version': 'TLSv1.3', 'Peer Temp Key': 'X25519, 253 bits'}))])
        self.assertEqual(f['3.0-csd02/quantum_safe']['outside_closed_list'], ['x25519'])


class AttributionTests(unittest.TestCase):
    def test_agreeing_counters_confirm_the_client_view(self):
        self.assertEqual(probe.attribute('negotiated', delta(tls_succeeded_total=1, ttlv_responses_total=1)), 'server-confirmed-negotiated')
        self.assertEqual(probe.attribute('server-rejected', delta(tls_failed_total=1)), 'server-confirmed-rejection')
        self.assertEqual(probe.attribute('server-rejected', delta(tls_succeeded_total=1)), 'server-rejected-after-handshake')
        # HTTPS answers and the unlisted-client refusal do not raise ttlv_responses_total.
        self.assertEqual(probe.attribute('negotiated', delta(tls_succeeded_total=1, https_accepted_total=1)), 'server-confirmed-negotiated')

    def test_disagreeing_or_missing_counters_never_confirm(self):
        self.assertEqual(probe.attribute('negotiated', delta(tls_failed_total=1)), 'contradicted')
        self.assertEqual(probe.attribute('negotiated', None), 'unattributed-server-did-not-settle')
        self.assertEqual(probe.attribute('negotiated', delta(tls_started_total=2, tls_succeeded_total=2, ttlv_responses_total=2)),
                         'unattributed-connection-count')

    def test_lost_alert_is_attributed_to_the_server_only_by_its_failure_counter(self):
        self.assertEqual(probe.attribute('closed-during-handshake', delta(tls_failed_total=1)), 'server-recorded-tls-failure-alert-not-observed')
        self.assertEqual(probe.attribute('closed-during-handshake', delta()), 'unattributed')
        self.assertEqual(probe.attribute('client-rejected-server', delta(tls_failed_total=1)), 'client-aborted-server-recorded-failure')

    def test_suite_credentials(self):
        cases = {'TLS_RSA_WITH_AES_128_CBC_SHA256': 'rsa', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 'rsa',
                 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256': 'rsa', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': 'ec',
                 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256': 'ec', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA': 'dsa',
                 'TLS_DH_RSA_WITH_AES_128_CBC_SHA': 'dh', 'TLS_PSK_WITH_AES_128_CBC_SHA': 'psk', 'TLS_AES_128_GCM_SHA256': 'any', '': 'any'}
        self.assertEqual({k: probe.suite_credential(k) for k in cases}, cases)

    def test_group_names_from_openssl_brief_output(self):
        g = probe.negotiated_group
        self.assertEqual(g({'Protocol version': 'TLSv1.2', 'Peer Temp Key': 'ECDH, prime256v1, 256 bits'}), 'secp256r1')
        self.assertEqual(g({'Protocol version': 'TLSv1.3', 'Peer Temp Key': 'ECDH, secp384r1, 384 bits'}), 'secp384r1')
        self.assertEqual(g({'Protocol version': 'TLSv1.3', 'Peer Temp Key': 'DH, 2048 bits'}), 'ffdhe2048')
        self.assertEqual(g({'Protocol version': 'TLSv1.2', 'Peer Temp Key': 'DH, 2048 bits'}), 'dh2048')  # TLS 1.2 DHE params, not a named group
        self.assertIsNone(g({}))

    def test_settled_delta_reads_the_plaintext_metrics_listener(self):
        import socketserver, threading
        states = [{'closed_total': 4, 'active': 1}, {'closed_total': 5, 'active': 0}]
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.rfile.readline()
                body = json.dumps(dict(dict.fromkeys(probe.DELTA_KEYS, 0), **(states.pop(0) if len(states) > 1 else states[0]))).encode()
                self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(body) + body)
        with socketserver.TCPServer(('127.0.0.1', 0), Handler) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            before = dict(dict.fromkeys(probe.DELTA_KEYS, 0), closed_total=4, active=0)
            got = probe.settled_delta(server.server_address[1], before, timeout=2)
            server.shutdown()
        self.assertEqual(got['closed_total'], 1)


class SourceCheckTests(unittest.TestCase):
    def test_verifier_compares_suite_names_and_rejects_unpinned_archives(self):
        import tempfile, zipfile
        import verify_tls_inventory as verify
        page = ('<html><p>3 Authentication Suites</p><p>3.1 Basic Authentication Suite This authentication suite stipulates TLS.</p>'
                '<p>SHALL support TLS_RSA_WITH_AES_128_CBC_SHA256</p><p>Conformant KMIP servers SHALL NOT support any cipher suite not listed above.</p>'
                '<p>4 Conformance Test Cases TLS_FAKE_WITH_NOTHING</p></html>').encode()
        inventory = {'editions': {'9.9': {'suites': {'basic': {'ciphers': {'shall': ['TLS_RSA_WITH_AES_128_CBC_SHA256'], 'closed_list': True}}}}}}
        with tempfile.TemporaryDirectory() as d:
            with zipfile.ZipFile(pathlib.Path(d, 'profiles-9.9.zip'), 'w') as z:
                z.writestr('p.html', page)
            pin = verify.hashlib.sha256(pathlib.Path(d, 'profiles-9.9.zip').read_bytes()).hexdigest()
            self.assertEqual(verify.check(inventory, {'9.9': pin}, d)['9.9']['problems'], [])
            inventory['editions']['9.9']['suites']['basic']['ciphers']['shall'] = ['TLS_RSA_WITH_AES_256_CBC_SHA256']
            problems = verify.check(inventory, {'9.9': pin}, d)['9.9']['problems']
            self.assertEqual(problems[0]['only_in_source'], ['TLS_RSA_WITH_AES_128_CBC_SHA256'])
            with self.assertRaises(ValueError):
                verify.check(inventory, {'9.9': '0' * 64}, d)


class ProfileConflictRegressions(unittest.TestCase):
    def test_tls13_conflicts_with_13_14_tls12_only_suites(self):
        result=probe.evaluate(INVENTORY,[row('negotiated',proto='tls1_3',suite='TLS_AES_256_GCM_SHA384')])
        for edition in ('1.3','1.4'):
            self.assertIn('TLSv1.3',result[edition+'/tls12']['forbidden_protocols_accepted'])
            self.assertTrue(result[edition+'/tls12']['would_conflict_if_claimed'])
        for edition in ('1.1','1.2'):
            self.assertNotIn('TLSv1.3',result[edition+'/tls12']['forbidden_protocols_accepted'])

    def test_suite_b_unknown_is_never_false_or_pruned(self):
        result=probe.evaluate(INVENTORY,[row('negotiated',proto='tls1_2',cipher='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256')])
        for edition in ('1.3','1.4'):
            for suite in ('suite_b_128','suite_b_192'):
                entry=result[edition+'/'+suite]
                self.assertIs(entry['modelled'],False)
                self.assertIsNone(entry['would_conflict_if_claimed'])
                self.assertTrue(entry['unmodelled_requirements'])
                self.assertIn('both peers',INVENTORY['editions'][edition]['suites'][suite]['certificates'].lower())

    def test_tls13_aes128_is_a_closed_list_conflict(self):
        result=probe.evaluate(INVENTORY,[row('negotiated',proto='tls1_3',suite='TLS_AES_128_GCM_SHA256')])
        for edition in ('2.0','2.1','3.0-csd02'):
            self.assertIn('TLS_AES_128_GCM_SHA256',result[edition+'/basic']['outside_closed_list'])
            self.assertTrue(result[edition+'/basic']['would_conflict_if_claimed'])

    def test_source_only_sentence_and_group_closure_cannot_be_removed(self):
        import tempfile,zipfile,hashlib,copy
        import verify_tls_inventory as verify
        html=b'<p>This authentication suite stipulates that a profile conforming to the TLS 1.2 Authentication Suite SHALL use TLS version 1.2 to negotiate a secure channel.</p><p>X25519MLKEM768</p><p>SHALL NOT support any key exchange group not listed above</p><p>4 KMIP Profiles</p>'
        inventory={'editions':{'9.9':{'suites':{'tls12':{'protocols':{'only':['TLSv1.2']},'groups':{'server_shall_all':['X25519MLKEM768'],'closed_list':True}}}}}}
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'profiles-9.9.zip'
            with zipfile.ZipFile(path,'w') as archive:archive.writestr('profile.html',html)
            pins={'9.9':hashlib.sha256(path.read_bytes()).hexdigest()}
            self.assertEqual(verify.check(inventory,pins,tmp)['9.9']['problems'],[])
            for mutation in ('protocol','group'):
                changed=copy.deepcopy(inventory)
                if mutation=='protocol':changed['editions']['9.9']['suites']['tls12']['protocols'].pop('only')
                else:changed['editions']['9.9']['suites']['tls12']['groups']['closed_list']=False
                with self.subTest(mutation=mutation):self.assertTrue(verify.check(changed,pins,tmp)['9.9']['problems'])
            scope=verify.check(inventory,pins,tmp)['9.9']['mechanical_scope']
            self.assertFalse(scope['cipher_strength_and_condition_buckets'])
            self.assertFalse(scope['client_authenticity_and_ports'])



# The kmip-1-basic and kmip-2-basic policies as `keytend-kmip-server tls-profiles` prints them.
BASIC_1 = {'name': 'kmip-1-basic', 'versions': ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'], 'tls12_suites': [{'iana': 'TLS_RSA_WITH_AES_128_CBC_SHA'}],
           'tls13_suites': [], 'groups': [], 'derived_from': [['1.1', 'basic']]}
BASIC_2 = {'name': 'kmip-2-basic', 'versions': ['TLSv1.3'], 'tls12_suites': [],
           'tls13_suites': ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'], 'groups': ['x25519', 'secp256r1', 'secp384r1'],
           'derived_from': [['2.1', 'basic']]}


class PolicyTests(unittest.TestCase):
    def test_listed_suites_must_negotiate_and_everything_else_must_be_refused(self):
        rows = [row('negotiated', proto='tls1', cipher='TLS_RSA_WITH_AES_128_CBC_SHA'),
                row('server-rejected', proto='tls1_2', cipher='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'),
                row('server-rejected', proto='tls1_3'),
                row('server-rejected', proto='tls1_2', offer='every-unlisted', id='tls1_2-unlisted-all')]
        e = probe.evaluate_policy(BASIC_1, rows, 'rsa')
        self.assertEqual((e['verdict'], e['matches'], e['mismatches']), ('matches-policy', 4, []))

    def test_refused_listed_suite_and_accepted_unlisted_suite_are_mismatches(self):
        rows = [row('server-rejected', proto='tls1', cipher='TLS_RSA_WITH_AES_128_CBC_SHA', id='a'),
                row('negotiated', proto='tls1_2', cipher='TLS_RSA_WITH_AES_256_CBC_SHA', id='b')]
        e = probe.evaluate_policy(BASIC_1, rows, 'rsa')
        self.assertEqual(e['verdict'], 'mismatch')
        self.assertEqual(len(e['mismatches']), 2)

    def test_suite_not_defined_for_the_version_must_be_refused(self):
        expected, _ = probe.policy_expectation(dict(BASIC_1, tls12_suites=[{'iana': 'TLS_RSA_WITH_AES_128_CBC_SHA256'}]),
                                               row('server-rejected', proto='tls1', cipher='TLS_RSA_WITH_AES_128_CBC_SHA256'), 'rsa')
        self.assertIs(expected, False)

    def test_untested_rows_never_match(self):
        rows = [row('client-cannot-attempt', proto='tls1_3', suite='TLS_AES_128_CCM_8_SHA256'),
                row('server-rejected', proto='tls1_3', group='x448', attribution='contradicted')]
        e = probe.evaluate_policy(BASIC_2, rows, 'rsa')
        self.assertEqual((e['verdict'], e['rows_checked'], len(e['untested'])), ('untested', 0, 2))

    def test_negotiation_outside_the_policy_is_reported_even_for_an_expected_success(self):
        r = row('negotiated', proto='tls1_3', negotiated='TLS_AES_128_GCM_SHA256', negotiated_group='x448')
        e = probe.evaluate_policy(BASIC_2, [r], 'rsa')
        self.assertEqual(e['verdict'], 'mismatch')
        self.assertEqual(len(e['negotiated_outside_policy']), 2)

    def test_groups_and_authentication_rows(self):
        self.assertIs(probe.policy_expectation(BASIC_2, row('x', proto='tls1_3', group='secp384r1'), 'ec')[0], True)
        self.assertIs(probe.policy_expectation(BASIC_2, row('x', proto='tls1_3', group='ffdhe2048'), 'ec')[0], False)
        self.assertIsNone(probe.policy_expectation(BASIC_2, row('x', proto='tls1_3', identity='foreign'), 'ec')[0])
        self.assertIsNone(probe.policy_expectation(BASIC_1, row('x', proto='tls1_2', group='x25519'), 'rsa')[0])
        # A listed suite the fixture credential cannot serve must still be refused.
        ecdsa = dict(BASIC_1, tls12_suites=[{'iana': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'}])
        self.assertIs(probe.policy_expectation(ecdsa, row('x', cipher='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'), 'rsa')[0], False)

    def test_policy_probes_cover_listed_suites_per_version_and_unlisted_offers(self):
        ids = [p['id'] for p in probe.probes(BASIC_1)]
        self.assertEqual(len(ids), len(set(ids)))
        for i in ['tls1-TLS_RSA_WITH_AES_128_CBC_SHA', 'tls1_1-TLS_RSA_WITH_AES_128_CBC_SHA', 'tls1-unlisted-all',
                  'tls1_1-unlisted-all', 'tls1_2-unlisted-all', 'tls1_3-unlisted-all']:
            self.assertIn(i, ids)
        unlisted = next(p for p in probe.probes(BASIC_1) if p['id'] == 'tls1_2-unlisted-all')
        client = probe.Client.__new__(probe.Client)
        client.binary, client.names = 'openssl', {'TLS_RSA_WITH_AES_128_CBC_SHA': 'AES128-SHA'}
        ok, params, _ = client.capability(unlisted)
        self.assertTrue(ok)
        self.assertEqual(params, ['-cipher', 'ALL:COMPLEMENTOFALL:!AES128-SHA:@SECLEVEL=0'])
        self.assertEqual([p['id'] for p in probe.probes()], [p['id'] for p in probe.probes(None)])
        self.assertNotIn('tls1_2-unlisted-all', [p['id'] for p in probe.probes()])

    def test_checkpoint_rows_are_one_line_each(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            fixture = {'kind': 'native', 'server_identity': 'server-rsa', 'started': 's', 'command': [], 'closed_after': True,
                       'server_log_sha256': 'l', 'shutdown_counters': None, 'server_tls_succeeded_equals_client_negotiated': True,
                       'results': [{'id': 'tls1-default', 'listener': 'ttlv', 'outcome': 'negotiated', 'raw_sha256': 'r',
                                    'facts': {'Protocol version': 'TLSv1', 'Ciphersuite (IANA)': 'TLS_RSA_WITH_AES_128_CBC_SHA'}}],
                       'evaluation': {}, 'policy_evaluation': {'verdict': 'matches-policy'},
                       'policy_claims': {'1.1/basic': {'observed_subset_conflict': False, 'missing_required': []}}}
            summary = {'started': 's', 'finished': 'f', 'harness_sha256': 'h', 'inventory_sha256': 'i', 'client': {},
                       'native_binary': {'sha256': 'n'}, 'pki': {}, 'tls_profile': BASIC_1,
                       'fixtures': {'native-rsa': fixture, 'native-ecdsa': {'kind': 'native', 'server_refused_to_start': 'x'}}}
            path = pathlib.Path(d, 'summary.json')
            path.write_text(json.dumps(summary))
            probe.checkpoint(pathlib.Path(d, 'out.json'), path)
            out = json.loads(pathlib.Path(d, 'out.json').read_text())
        f = out['runs']['kmip-1-basic']['fixtures']['native-rsa']
        self.assertEqual(f['rows'], ['tls1-default|ttlv|negotiated||TLSv1|TLS_RSA_WITH_AES_128_CBC_SHA||r'])
        self.assertEqual(f['policy_claims'], {'1.1/basic': {'observed_subset_conflict': False}})
        self.assertNotIn('evaluation_recomputed', f)
        self.assertEqual(out['verdicts']['kmip-1-basic'], {'native-rsa': 'matches-policy', 'native-ecdsa': 'server refused to start'})

# The Suite B policies as `keytend-kmip-server tls-profiles` prints them.
SUITE_B_128 = {'name': 'kmip-1-suite-b-128', 'versions': ['TLSv1.2'], 'credential': 'ecdsa-p256', 'suite_b': 'min-los128',
               'tls12_suites': [{'iana': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'}], 'tls13_suites': [], 'groups': ['secp256r1'],
               'derived_from': [['1.3', 'suite_b_128']]}
SUITE_B_192 = dict(SUITE_B_128, name='kmip-1-suite-b-192', credential='ecdsa-p384', suite_b='min-los192', groups=['secp384r1'],
                   tls12_suites=[{'iana': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'}], derived_from=[['1.3', 'suite_b_192']])


def suite_b_row(outcome, group, signature, **extra):
    r = row(outcome, **extra)
    if outcome == 'negotiated':
        r['negotiated_group'] = group
        r['facts']['Signature type'] = signature
    return r


class SuiteBPolicyTests(unittest.TestCase):
    def test_suite_b_probes_add_signature_and_client_certificate_rows(self):
        for policy in [SUITE_B_128, SUITE_B_192]:
            selected = probe.probes(policy)
            ids = [p['id'] for p in selected]
            self.assertEqual(len(ids), len(set(ids)))
            for a in probe.SIGALG_PROBES:
                self.assertIn(f'tls1_2-sigalgs-{a}', ids)
            for c in probe.SUITE_B_BAD_CLIENTS:
                p = next(p for p in selected if p['id'] == f'tls1_2-suite-b-{c}')
                self.assertEqual((p['identity'], p['cipher']), (c, policy['tls12_suites'][0]['iana']))
        self.assertFalse([p for p in probe.probes(BASIC_1) if p.get('sigalgs') or p['identity'] in probe.SUITE_B_BAD_CLIENTS])

    def test_sigalgs_rows_pass_the_scheme_to_the_client(self):
        client = probe.Client.__new__(probe.Client)
        client.binary, client.names, client.groups = 'openssl', {}, set()
        p = next(p for p in probe.probes(SUITE_B_192) if p['id'] == 'tls1_2-sigalgs-ecdsa_secp384r1_sha384')
        self.assertEqual(client.capability(p), (True, ['-sigalgs', 'ecdsa_secp384r1_sha384'], None))

    def test_only_the_level_signature_group_and_listed_client_may_negotiate(self):
        expect = lambda policy, r: probe.policy_expectation(policy, r, 'ec')[0]
        self.assertIs(expect(SUITE_B_128, row('x', sigalgs='ecdsa_secp256r1_sha256')), True)
        self.assertIs(expect(SUITE_B_128, row('x', sigalgs='ecdsa_secp384r1_sha384')), False)
        self.assertIs(expect(SUITE_B_192, row('x', sigalgs='ecdsa_secp384r1_sha384')), True)
        self.assertIs(expect(SUITE_B_192, row('x', sigalgs='rsa_pss_rsae_sha256')), False)
        # TLS 1.2 group rows are evaluated under Suite B (no static-RSA fallback), not elsewhere.
        self.assertIs(expect(SUITE_B_192, row('x', group='secp384r1')), True)
        self.assertIs(expect(SUITE_B_192, row('x', group='secp256r1')), False)
        self.assertIsNone(probe.policy_expectation(BASIC_1, row('x', group='secp256r1'), 'rsa')[0])
        for c in probe.SUITE_B_BAD_CLIENTS:
            self.assertIs(expect(SUITE_B_128, row('x', cipher='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', identity=c)), False)
            self.assertIsNone(probe.policy_expectation(BASIC_2, row('x', identity=c), 'ec')[0])

    def test_a_negotiation_with_another_group_or_signature_is_outside_the_policy(self):
        suite = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
        good = suite_b_row('negotiated', 'secp384r1', 'ecdsa_secp384r1_sha384', cipher=suite, id='good')
        e = probe.evaluate_policy(SUITE_B_192, [good], 'ec')
        self.assertEqual((e['verdict'], e['matches']), ('matches-policy', 1))
        for group, signature in [('secp256r1', 'ecdsa_secp384r1_sha384'), ('secp384r1', 'ecdsa_secp256r1_sha256')]:
            r = suite_b_row('negotiated', group, signature, cipher=suite, id='bad')
            e = probe.evaluate_policy(SUITE_B_192, [r], 'ec')
            self.assertEqual((e['verdict'], len(e['negotiated_outside_policy'])), ('mismatch', 1), (group, signature))
        accepted = row('negotiated', cipher=suite, identity='client-wrong-hash', id='wrong-hash')
        self.assertEqual(probe.evaluate_policy(SUITE_B_192, [accepted], 'ec')['verdict'], 'mismatch')


if __name__ == '__main__':
    unittest.main()
