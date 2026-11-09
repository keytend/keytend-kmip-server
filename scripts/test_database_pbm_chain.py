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

"""Exercise actual PBM missing/corrupt oplog refusal without changing KMIP keys."""
import argparse
import copy
import functools
import gzip
import json
import pathlib
import time

import test_database_pbm as pbm
from image_evidence import ROOT
from test_database_backup import key_state, manifest, sha
from test_database_pbm_adverse import events, snapshot_sha
from wire import key_value


def catalog_snapshot(fixture):
    primary=fixture.primary()
    locks=fixture.shell(primary,"db.getSiblingDB('admin').pbmLock.countDocuments({})")
    return dict(chunks=fixture.chunks(),locks=locks)


def wait_catalog_quiet(fixture,report,quiet_seconds=10,timeout=90,clock=time.monotonic,pause=time.sleep):
    """Require a bounded quiet observation window after successful PITR disable.

    This does not prove that PBM can never write another chunk. The exact
    post-injection catalog must still equal the chosen pre-injection catalog.
    Every observation is retained, including changes and a timed-out window.
    """
    if quiet_seconds<=0 or timeout<=quiet_seconds:raise ValueError('invalid catalog observation bounds')
    start=clock();since=None;previous=None
    observations=report.setdefault('catalog_quiescence',dict(quiet_seconds=quiet_seconds,timeout_seconds=timeout,
        scope='Repeated metadata and pbmLock observations after successful PITR disable; not proof of vendor shutdown or cause of an earlier failure',observations=[]))['observations']
    while clock()-start<timeout:
        state=catalog_snapshot(fixture);now=clock()
        observations.append(dict(elapsed_seconds=round(now-start,3),**copy.deepcopy(state)))
        eligible=bool(state['chunks']) and state['locks']==0
        if not eligible or state!=previous:since=now if eligible else None
        previous=copy.deepcopy(state)
        report['catalog_quiescence']['status']='observing'
        (pbm.OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
        if since is not None and now-since>=quiet_seconds:
            report['catalog_quiescence']['status']='quiet_window_observed'
            return state['chunks']
        pause(1)
    report['catalog_quiescence']['status']='timed_out'
    (pbm.OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
    raise TimeoutError('PBM catalog did not remain unchanged and lock-free for the required observation window')


def run(fixture, report, scenario):
    report.update(scenario=scenario, restore_outcome='not_yet_observed',
        limits='One required gzip oplog slice deleted or its header corrupted, with unchanged PBM metadata, base backup and all KMIP keys. Single-host authenticated TLS replica set and shared local storage. No authenticated remote integrity/retention, arbitrary valid-BSON tampering, interrupted restore, storage exhaustion, sharding, independent failure domains, production load/RPO/RTO, least-privilege account or external audit-floor qualification. No full-spec or production approval.')

    def passed(description):
        report['passed'].append(description)
        (pbm.OUT/'image.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS', scenario, description, flush=True)

    backup, target_state, initial_material = pbm.prepare_recovery(fixture, report, passed)
    target = report['restore_target']
    rotated = report['pre_restore_rotated_key_ids']
    before = {'documents': [{'_id': 999, 'account': 'future-only', 'balance': -1}],
        'indexes': copy.deepcopy(target_state['indexes'])}
    assert before != target_state
    fixture.agree(before)
    report['before_restore_snapshot_sha256'] = snapshot_sha(before)
    with fixture.server.connect() as client:
        current_material = {key: key_value(client, key) for key in rotated}
    all_material = initial_material | current_material
    base_files = manifest(fixture.storage/backup['name'])
    assert base_files
    chunks = wait_catalog_quiet(fixture,report)
    report['catalog_before_fault']=copy.deepcopy(chunks)
    (pbm.OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
    required = [chunk for chunk in chunks if pbm.ordered_ts(chunk['start']) < pbm.ordered_ts(target)
        <= pbm.ordered_ts(chunk['end'])]
    assert len(required) == 1, required
    chosen = required[0]
    # Vendor-generated relative names only; never mutate a path outside this
    # disposable fixture, even if storage metadata has an unexpected shape.
    relative = pathlib.PurePosixPath(chosen['name'])
    assert not relative.is_absolute() and '..' not in relative.parts
    path = (fixture.storage/relative).resolve()
    assert path.is_relative_to(fixture.storage.resolve()) and path.is_file()
    original = path.read_bytes()
    assert original[:2] == b'\x1f\x8b' and gzip.decompress(original)
    chunk_files = {chunk['name']: sha(fixture.storage/chunk['name']) for chunk in chunks}
    fault = dict(chunk=chosen, original_sha256=sha(path), original_size=len(original),
        metadata_unchanged=True, base_backup_unchanged=True, all_keys_unchanged=True)
    if scenario == 'missing-oplog':
        path.unlink()
        fault.update(kind='deleted', faulty_sha256=None, faulty_size=None)
    else:
        damaged = bytes([original[0] ^ 0xff])+original[1:]
        path.write_bytes(damaged)
        assert len(damaged) == len(original)
        try:
            gzip.decompress(damaged)
        except gzip.BadGzipFile:
            pass
        else:
            raise AssertionError('Corrupt fixture did not invalidate the gzip header')
        fault.update(kind='invalid_gzip_header', faulty_sha256=sha(path), faulty_size=path.stat().st_size)
    after_fault=catalog_snapshot(fixture)
    fault['metadata_unchanged']=after_fault['chunks']==chunks
    report.update(oplog_fault=fault,catalog_after_fault=after_fault,backup_files_sha256=base_files,oplog_files_sha256=chunk_files)
    (pbm.OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
    assert after_fault['chunks'] == chunks, 'PBM catalog changed during fault injection; before/after snapshots retained'
    assert after_fault['locks'] == 0, 'PBM lock appeared during fault injection; snapshot retained'
    assert manifest(fixture.storage/backup['name']) == base_files
    for name, digest in chunk_files.items():
        if name != chosen['name']:
            assert sha(fixture.storage/name) == digest
    with fixture.server.connect() as client:
        assert all(key_state(fixture.server, key) == 2 and key_value(client, key) == value
            for key, value in all_material.items())
    report.update(oplog_fault=fault, backup_files_sha256=base_files, oplog_files_sha256=chunk_files)
    passed('one real required oplog slice is '+fault['kind']+' while its PBM catalog entry, every other slice, physical backup and all exact Active historical/current KMIP keys remain intact')

    report['catalog_before_restore']=catalog_snapshot(fixture)
    (pbm.OUT/'image.json').write_text(json.dumps(report,indent=2)+'\n')
    assert report['catalog_before_restore']==dict(chunks=chunks,locks=0), 'PBM catalog or lock changed before restore; snapshot retained'

    options = ['--base-snapshot='+backup['name'],
        '--time='+str(target['t'])+','+str(target['i']),
        '--fallback-enabled=true', '--allow-partly-done=false', '--yes']
    report['restore_start_options'] = options
    started = time.monotonic()
    restore = fixture.cli_json('restore', *options, label='restore-start')

    def finished():
        result = fixture.cli_json('describe-restore', restore['name'],
            '--config=/control/storage.yaml', label='restore-status')
        assert result['status'] not in ['done', 'partlyDone'], 'PBM accepted a broken oplog chain'
        if result['status'] != 'error':
            return None
        terminal = []
        for directory in fixture.controls:
            matching = [event for event in events(directory/'agent.log')
                if event.get('e') == 'restore' and event.get('eobj') == restore['name'] and (
                    event.get('msg') == 'recovery successfully finished' if scenario == 'missing-oplog'
                    else event.get('msg', '').startswith('restore: ') and
                        event['msg'].endswith('exec cleanup strategy: fallback applyed'))]
            if not matching:
                return None
            terminal.append(matching[-1])
        report['terminal_agent_events'] = terminal
        return result

    result = fixture.wait(finished, seconds=900)
    nodes = result['replsets'][0]['nodes']
    assert result['type'] == 'physical' and len(result['replsets']) == 1
    assert len(nodes) == 3 and all(node['status'] == 'error' for node in nodes)
    assert {node['name'] for node in nodes} == {agent['n'] for agent in report['agents']}
    node_events = [[event for event in events(directory/'agent.log')
        if event.get('e') == 'restore' and event.get('eobj') == restore['name']]
        for directory in fixture.controls]
    if scenario == 'missing-oplog':
        assert 'failed to ensure chunk' in result['error'] and chosen['name'] in result['error']
        assert all(not any(event.get('msg') == 'stopping mongod and flushing old data'
            for event in observations) for observations in node_events)
        fixture.agree(before)
        outcome = 'refused_before_database_shutdown'
        # The pinned upstream deferred close overwrites the returned preflight
        # error. Its terminal agent text says success despite restore metadata
        # reporting Error. Retain both; that text alone earns no success credit.
        report['vendor_observation'] = 'PBM agent terminal text says recovery successfully finished after preflight refusal; cluster and every node report Error. Terminal text only proves the agent returned, not successful recovery.'
    else:
        assert 'fallback' in result['error']
        assert any('decompress object '+chosen['name'] in event.get('msg', '')
            and 'invalid header' in event['msg'] for observations in node_events for event in observations)
        assert all(any(event.get('msg') == 'stopping mongod and flushing old data'
            for event in observations) for observations in node_events)
        outcome = 'refused_with_fallback'
    report.update(restore=result, restore_outcome=outcome,
        observed_failure_and_cleanup_seconds=round(time.monotonic()-started, 3))
    passed('PBM reports Error on every member for the faulty slice and every agent returns before restart; '+outcome)

    # Never repair the fault before checking recovery. Every retained input must
    # still be faulty, and key loss must not explain the observed refusal.
    assert (not path.exists()) if scenario == 'missing-oplog' else sha(path) == fault['faulty_sha256']
    assert manifest(fixture.storage/backup['name']) == base_files
    for member in range(3):
        fixture.stop(member)
        fixture.start(member)
    for member in range(3):
        fixture.ready(member)
    fixture.primary()
    fixture.agree(before)
    assert [fixture.key_id(member) for member in range(3)] == rotated
    with fixture.server.connect() as client:
        assert all(key_state(fixture.server, key) == 2 and key_value(client, key) == value
            for key, value in all_material.items())
    for member in range(3):
        assert fixture.shell(member, 'db.getSiblingDB("qualification").runCommand({validate:"records",full:true}).valid') is True
    report.update(recovered_snapshot_sha256=snapshot_sha(before), recovered_member_key_ids=rotated,
        faulty_slice_not_repaired_before_recovery=True)
    passed('all cold-restarted members retain the exact newer documents/hidden indexes and their original current KMIP identities/material, with full collection validation and no historical target substituted')

    marker = {'_id': 1000, 'account': 'after-chain-refusal', 'balance': 7}
    assert fixture.shell(fixture.primary(), 'db.getSiblingDB("qualification").records.insertOne('+
        json.dumps(marker)+', {writeConcern:{w:"majority",j:true,wtimeout:15000}}).acknowledged') is True
    resumed = copy.deepcopy(before)
    resumed['documents'].append(marker)
    fixture.agree(resumed)
    report['post_recovery_snapshot_sha256'] = snapshot_sha(resumed)
    passed('the recovered replica set accepts a fresh journaled majority write and every member agrees with the independent document/index oracle')

    for member in range(3):
        fixture.start_agent(member)
    fixture.cli('config', '--force-resync', '--wait', label='resync-after-chain-refusal')
    fixture.wait(fixture.agent_health)
    report['fresh_backup'] = fixture.backup('fresh-base-after-chain-refusal')
    assert report['fresh_backup']['replsets'][0]['security']['kmip']['keyIdentifier'] in rotated
    fixture.cli('config', '--set=pitr.enabled=true', label='resume-pitr-after-chain-refusal')
    report['resumed_agents'] = fixture.wait(fixture.agent_health)
    passed('healthy restarted PBM agents complete a new physical base backup under a retained current key and reenable PITR; the broken old chain receives no recovery credit')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--engine', default='podman', choices=['podman', 'docker'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--scenario', required=True, choices=['missing-oplog', 'corrupt-oplog'])
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    output = args.output or ROOT/'artifacts/database-pbm-chain'/args.scenario
    pbm.execute(args.engine, args.image, output, functools.partial(run, scenario=args.scenario))


if __name__ == '__main__':
    main()
