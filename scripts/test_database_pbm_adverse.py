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

"""Require actual PBM restore refusal and fallback for an unusable historical key."""
import argparse
import copy
import functools
import hashlib
import json
import pathlib
import time

import test_database_pbm as pbm
from image_evidence import ROOT
from test_database_backup import key_state, manifest, sha
from wire import exchange, key_value, payload, request, structure, enumeration, uid, status, reason


def events(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def snapshot_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(fixture, report, scenario):
    report.update(scenario=scenario, restore_outcome='not_yet_observed',
        limits='Single-host authenticated TLS replica set and shared local backup storage. Tests only deliberate compromise or destruction of the historical backup key with all current member keys retained. No network outage, corrupted/missing oplog, process interruption, storage exhaustion, sharded cluster, independent failure domains, remote retention/encryption, throughput, production RPO/RTO, least-privilege PBM account or external audit-floor rollback qualification. Root database account and development KMIP policy are fixture-only. No full-spec or production approval.')

    def passed(description):
        report['passed'].append(description)
        (pbm.OUT/'image.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS', scenario, description, flush=True)

    backup, target_state, _ = pbm.prepare_recovery(fixture, report, passed)
    historical = report['restored_key_id']
    rotated = report['pre_restore_rotated_key_ids']
    before = {'documents': [{'_id': 999, 'account': 'future-only', 'balance': -1}],
        'indexes': copy.deepcopy(target_state['indexes'])}
    assert before != target_state
    fixture.agree(before)
    stored = manifest(fixture.storage/backup['name'])
    assert stored
    report['backup_files_sha256'] = stored
    report['before_restore_snapshot_sha256'] = snapshot_sha(before)
    with fixture.server.connect() as client:
        current_material = {key: key_value(client, key) for key in rotated}
        revocation = 2 if scenario == 'compromised-key' else 6
        payload(exchange(client, request(19, [uid(historical),
            structure(0x420081, enumeration(0x420082, revocation))])))
        if scenario == 'destroyed-key':
            payload(exchange(client, request(20, [uid(historical)])))
    expected_state = 4 if scenario == 'compromised-key' else 5
    expected_name = 'Compromised' if expected_state == 4 else 'Destroyed'
    assert key_state(fixture.server, historical) == expected_state
    assert all(key_state(fixture.server, key) == 2 for key in rotated)
    with fixture.server.connect() as client:
        assert all(key_value(client, key) == value for key, value in current_material.items())
        if scenario == 'destroyed-key':
            result = exchange(client, request(10, [uid(historical)]))
            report['destroyed_get'] = dict(status=status(result), reason=reason(result))
            # 1.4 Get errors: only attributes remain for a destroyed object -> Illegal Operation.
            assert report['destroyed_get'] == dict(status=1, reason=0x0b), report['destroyed_get']
    assert manifest(fixture.storage/backup['name']) == stored
    report['key_fault'] = dict(identifier=historical, state=expected_state, state_name=expected_name,
        current_member_identifiers=rotated, backup_files_unchanged=True)
    passed('the historical backup key is deliberately '+expected_name.lower()+' through KMIP while all distinct current member keys stay active with exact retained bytes and the physical backup files stay unchanged')

    target = report['restore_target']
    options = ['--base-snapshot='+backup['name'],
        '--time='+str(target['t'])+','+str(target['i']),
        '--fallback-enabled=true', '--allow-partly-done=false', '--yes']
    report['restore_start_options'] = options
    started = time.monotonic()
    restore = fixture.cli_json('restore', *options, label='restore-start')

    def finished():
        result = fixture.cli_json('describe-restore', restore['name'],
            '--config=/control/storage.yaml', label='restore-status')
        assert result['status'] != 'done', 'PBM incorrectly reported successful restore with an unusable backup key'
        if result['status'] != 'error':
            return None
        # A cluster error can precede fallback completion. The terminal agent
        # event occurs only after Snapshot's deferred close/cleanup has returned.
        terminal = []
        for directory in fixture.controls:
            matching = [event for event in events(directory/'agent.log')
                if event.get('e') == 'restore' and event.get('eobj') == restore['name'] and
                event.get('msg', '').startswith('restore: ') and
                event['msg'].endswith('exec cleanup strategy: fallback applyed')]
            if not matching:
                return None
            terminal.append(matching[-1])
        report['terminal_fallback_events'] = terminal
        return result

    result = fixture.wait(finished, seconds=900)
    assert result['type'] == 'physical' and len(result['replsets']) == 1
    assert 'fallback' in result.get('error', '')
    nodes = result['replsets'][0]['nodes']
    assert len(nodes) == 3 and {node['name'] for node in nodes} == {agent['n'] for agent in report['agents']}
    assert all(node['status'] == 'error' for node in nodes)
    key_errors = []
    for member, directory in enumerate(fixture.directories):
        path = directory/'pbm.restore.log'
        failures = [event['attr']['error']['reason'] for event in events(path)
            if event.get('id') == 29120]
        assert failures, 'No structured database encryption refusal for member '+str(member)
        for failure in failures:
            assert failure['what'] == 'key reading failed'
            assert failure['keyManagementFacilityType'] == 'KMIP server'
            assert failure['keyIdentifier']['kmipKeyIdentifier'] == historical
            assert failure['keyState'] == expected_name
            assert failure['reason'] == 'Master encryption key is not in the active state on the key management facility.'
        key_errors.append(dict(member=member, errors=failures))
        (pbm.OUT/('refusal-member-'+str(member)+'.log')).write_text(fixture.redact(path.read_text()))
    report.update(restore=result, key_refusals=key_errors, restore_outcome='refused_with_fallback',
        observed_failure_and_fallback_seconds=round(time.monotonic()-started, 3))
    passed('every temporary database refuses the exact historical KMIP key with its explicit '+expected_name+' state; PBM reports Error and every agent finishes fallback cleanup before any member restart')

    for member in range(3):
        fixture.stop(member)
        fixture.start(member)
    for member in range(3):
        fixture.ready(member)
    fixture.primary()
    fixture.agree(before)
    assert [fixture.key_id(member) for member in range(3)] == rotated
    assert key_state(fixture.server, historical) == expected_state
    assert all(key_state(fixture.server, key) == 2 for key in rotated)
    with fixture.server.connect() as client:
        assert all(key_value(client, key) == value for key, value in current_material.items())
    for member in range(3):
        assert fixture.shell(member, 'db.getSiblingDB("qualification").runCommand({validate:"records",full:true}).valid') is True
    report['fallback_snapshot_sha256'] = snapshot_sha(before)
    report['fallback_member_key_ids'] = [fixture.key_id(member) for member in range(3)]
    passed('all restarted members retain the exact pre-restore future-only document and hidden index definitions with their own current KMIP identities/material; historical target data is not substituted and the key fault is not reset')

    marker = {'_id': 1000, 'account': 'after-fallback', 'balance': 7}
    assert fixture.shell(fixture.primary(), 'db.getSiblingDB("qualification").records.insertOne('+
        json.dumps(marker)+', {writeConcern:{w:"majority",j:true,wtimeout:15000}}).acknowledged') is True
    resumed = copy.deepcopy(before)
    resumed['documents'].append(marker)
    fixture.agree(resumed)
    report['post_fallback_snapshot_sha256'] = snapshot_sha(resumed)
    passed('the recovered replica set accepts a new journaled majority write and every member retains the independently expected documents and indexes')

    for member in range(3):
        fixture.start_agent(member)
    fixture.cli('config', '--force-resync', '--wait', label='resync-after-fallback')
    fixture.wait(fixture.agent_health)
    report['fresh_backup'] = fixture.backup('fresh-base-after-fallback')
    assert report['fresh_backup']['replsets'][0]['security']['kmip']['keyIdentifier'] in rotated
    fixture.cli('config', '--set=pitr.enabled=true', label='resume-pitr-after-fallback')
    report['resumed_agents'] = fixture.wait(fixture.agent_health)
    assert key_state(fixture.server, historical) == expected_state
    passed('healthy restarted PBM agents complete a fresh physical base backup under a current member key and re-enable PITR while the historical backup key remains unusable')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--scenario', required=True, choices=['compromised-key', 'destroyed-key'])
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    output = args.output or ROOT/'artifacts/database-pbm-adverse'/args.scenario
    pbm.execute(args.engine, args.image, output,
        functools.partial(run, scenario=args.scenario))


if __name__ == '__main__':
    main()
