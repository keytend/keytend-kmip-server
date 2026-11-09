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

"""Reduce owned forwarding metadata; preserve all errors and hash the raw inputs."""
import argparse
import collections
import decimal
import hashlib
import json
import pathlib
import re


def trace_failures(lines):
    accept = re.compile(r'^(\d+\.\d+) accept4\((\d+), .*sin_port=htons\((\d+)\).* = (\d+) ')
    connect = re.compile(r'^(\d+\.\d+) connect\((\d+), .*sin_port=htons\((\d+)\).* = -1 (\w+)')
    last = None
    failures = []
    outcomes = collections.Counter()
    ns = lambda value: int(decimal.Decimal(value) * 1_000_000_000)
    for line in lines:
        a = accept.match(line)
        if a:
            last = dict(accept_time_ns=ns(a[1]), listener_fd=int(a[2]),
                        client_port=int(a[3]), accepted_fd=int(a[4]))
        c = connect.match(line)
        if c:
            outcomes[f'{c[3]}:{c[4]}'] += 1
            if int(c[3]) == 5696 and c[4] == 'EADDRNOTAVAIL':
                failures.append(dict(last or {}, connect_time_ns=ns(c[1]), connect_fd=int(c[2])))
                # Never reuse an accept as evidence for a second failed connect.
                last = None
    return failures, outcomes


def correlate(failures, errors, bound_ns=5_000_000_000):
    byport = collections.defaultdict(collections.deque)
    for event in sorted(errors, key=lambda e:e['wall_ns']):
        byport[event['local'][1]].append(event)
    delays = []
    for failure in failures:
        queue = byport[failure.get('client_port')]
        if queue and 0 <= queue[0]['wall_ns'] - failure['connect_time_ns'] < bound_ns:
            delays.append((queue.popleft()['wall_ns'] - failure['connect_time_ns']) / 1_000_000)
    return dict(connect_EADDRNOTAVAIL=len(failures), client_tls_resets=len(errors),
                matched_source_port_and_time=len(delays), unmatched_forwarder=len(failures) - len(delays),
                unmatched_client=sum(len(q) for q in byport.values()), match_bound_seconds=bound_ns / 1e9,
                delay_ms=dict(min=min(delays), max=max(delays)) if delays else None,
                first_failure=failures[0] if failures else None)


def analyze(run):
    run = pathlib.Path(run)
    capture = run / 'forwarding-forensics'
    report = json.loads((run / 'summary.json').read_text())
    identity = json.loads((capture / 'identity.json').read_text())
    assert identity['image_id'] == report['tested_image_config_id']
    with (capture / 'forwarder-sockets.strace').open() as stream:
        failures, outcomes = trace_failures(stream)
    errors = []
    connections = collections.Counter()
    unique_client_ports = set()
    peaks = collections.Counter()
    first_processes = last_processes = None
    first_cgroups = last_cgroups = None
    pool = dict(count=0)

    def table_sample(rows, origin):
        nonlocal pool
        if not isinstance(rows, list):
            return
        # Internal splice socket endpoints are the *peer* side of the KMIP
        # listener. Counting only listener-local rows misses this exhausted pool.
        ports = {int(r['local'].rsplit(':', 1)[1], 16) for r in rows
                 if r['state'] == '06' and int(r['peer'].rsplit(':', 1)[1], 16) == 5696}
        if len(ports) > pool['count']:
            pool = dict(count=len(ports), min=min(ports), max=max(ports), origin=origin,
                        contiguous=len(ports) == max(ports) - min(ports) + 1)

    with (capture / 'metadata.jsonl').open() as stream:
        for line in stream:
            event = json.loads(line)
            if event['kind'] == 'client_connection':
                connections[f"{event['stage']}:{event['error_type']}:{event['errno']}"] += 1
                if event['local']:
                    unique_client_ports.add(event['local'][1])
                if event['stage'] == 'tls_handshake' and event['errno'] == 104:
                    errors.append(event)
            elif event['kind'] == 'snapshot':
                table_sample(event['tables'].get('server'), 'metadata.jsonl')
                for name, proc in event['processes'].items():
                    for field in ('fds', 'threads'):
                        if field in proc:
                            peaks[f'{name}_{field}'] = max(peaks[f'{name}_{field}'], proc[field])
                if first_processes is None:
                    first_processes, first_cgroups = event['processes'], event['cgroups']
                last_processes, last_cgroups = event['processes'], event['cgroups']
    independent = capture / 'independent-both-directions-snapshot.json'
    if independent.exists():
        table_sample(json.loads(independent.read_text())['rows'], independent.name)
    correlation = correlate(failures, errors)
    inputs = [run / 'summary.json', capture / 'identity.json', capture / 'metadata.jsonl',
              capture / 'forwarder-sockets.strace', capture / 'strace-status.log']
    if independent.exists():inputs.append(independent)
    refs = {}
    for path in inputs:
        with path.open('rb') as stream:
            refs[str(path.relative_to(run))] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(status='forensic_measurements_only', benchmark_status=report['status'],
                native_binary_sha256=report['runtime_binary_sha256'],
                image_id=report['tested_image_config_id'], archive_sha256=report['archive_sha256'],
                configured_max_connections=report['configured_max_connections'],
                diagnostic_pasta_no_splice=report.get('diagnostic_pasta_no_splice', False),
                connection_events=dict(connections), distinct_host_client_ports=len(unique_client_ports),
                connect_outcomes=dict(outcomes), correlation=correlation,
                peak_internal_kmip_TIME_WAIT_source_ports=pool, process_peaks=dict(peaks),
                process_before=first_processes, process_after=last_processes,
                cgroup_before=first_cgroups, cgroup_after=last_cgroups,
                cleanup=identity.get('cleanup'), capture_errors=identity['errors'],
                phases=[{k:p[k] for k in ('connection_mode', 'concurrency', 'requested_seconds',
                                          'successful_gets', 'error_count', 'error_details', 'server_counters')}
                        for p in report['phases']], raw_sha256=refs)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=pathlib.Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.run), indent=2))
