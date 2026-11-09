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

"""Kill one owned PBM agent during physical copy; distinguish manual fallback.

Linux/Podman-only process injection. No vendor executable or backup is modified.
SIGSTOP closes the observation/signal race; a missed phase never earns credit.
"""
import argparse
import copy
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
import uuid

import test_database
import test_database_pbm as pbm
import test_database_replicaset
from image_evidence import ROOT, local_image_id, packaged_evidence
from test_database_backup import key_state, manifest, sha
from test_database_replicaset import command
from wire import key_value


LIMITS = ('One SIGKILL of one secondary PBM 2.17.0 agent during physical backup '
    'copy on Percona MongoDB 8.0.34-15, one host, local shared storage. Manual '
    'fallback on the killed member is fixture recovery, not PBM automatic '
    'fallback/resumption or a production runbook. No other interruption phases, '
    'host/network/storage/KMIP failures, remote retention/encryption, sharding, '
    'load/RPO/RTO, least-privilege or independent failure-domain qualification. '
    'Root fixture credentials and development KMIP policy. Full specification, '
    'maintained production SDK and production approval gates remain open.')


def events(path):
    result = []
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                # The writer may be in the middle of the last line.
                continue
    return result


def snapshot_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def proc_identity(pid):
    # comm can contain spaces; fields following its final ')' start with state.
    fields = pathlib.Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(pid=pid, state=fields[0], start_ticks=int(fields[19]))


def expected_copy_paths(backup_manifest, replica_set):
    """Fail closed on unfamiliar layouts instead of guessing copy completion."""
    prefix = replica_set+'/'
    paths = set()
    for name in backup_manifest:
        assert name.startswith(prefix), ('unexpected backup replica set', name)
        compressed = name[len(prefix):]
        if compressed == 'filelist.pbm':
            continue  # PBM inventory metadata is not a database restore output.
        suffix = re.search(r'\.s2(?:\.\d+-\d+)?$', compressed)
        assert suffix, ('unqualified backup compression layout', name)
        relative = pathlib.PurePosixPath(compressed[:suffix.start()])
        assert not relative.is_absolute() and '..' not in relative.parts
        paths.add(str(relative))
    assert paths, 'No qualified physical backup output paths'
    return sorted(paths)


class InterruptSet(pbm.PbmSet):
    def __init__(self, *args):
        super().__init__(*args)
        token = uuid.uuid4().hex[:12]
        self.names = ['keytend-pbm-int-e66-'+token+'-'+str(i) for i in range(3)]
        self.server.name = 'keytend-pbm-int-e66-'+token+'-kmip'

    def processes(self, member):
        output = command([self.engine, 'top', self.names[member], 'hpid', 'pid', 'comm'])
        return [dict(host_pid=int(h), container_pid=int(p), command=c)
            for h, p, c in (line.split() for line in output.splitlines()[1:])]

    def owned_agent(self, member):
        agents = [p for p in self.processes(member) if p['command'] == 'pbm-agent']
        assert len(agents) == 1, agents
        agent = agents[0]
        return dict(**agent, **proc_identity(agent['host_pid']),
            container=self.names[member], container_id=self.inspect(member)['Id'])

    def assert_same_agent(self, member, agent):
        assert self.inspect(member)['Id'] == agent['container_id']
        assert any(p['host_pid'] == agent['host_pid'] and
            p['container_pid'] == agent['container_pid'] and p['command'] == 'pbm-agent'
            for p in self.processes(member))
        assert proc_identity(agent['host_pid'])['start_ticks'] == agent['start_ticks']


class RaceLost(AssertionError):
    """The copy phase ended (or had not started) when the agent was stopped: no SIGKILL was sent,
    so the attempt proves nothing either way and may be repeated on a fresh fixture."""


ATTEMPTS = 3


def interrupt(fixture, report, member, name, agent, started):
    """Return only after a verified kill, or fail with explicit race evidence."""
    injection = report['injection']
    path = fixture.controls[member]/'agent.log'
    fallback = fixture.directories[member]/'.fallbacksync'
    until = time.monotonic()+180
    while time.monotonic() < until:
        current = [e for e in events(path) if e.get('e') == 'restore' and e.get('eobj') == name]
        matching = [e for e in current if e.get('msg') == 'copying backup data']
        if matching:
            break
        time.sleep(.005)
    else:
        injection['outcome'] = 'unexecuted_phase_not_observed'
        raise AssertionError('Copy phase not observed; no signal sent')

    # Revalidate ownership before signaling a host PID. start_ticks guards PID reuse.
    fixture.assert_same_agent(member, agent)
    os.kill(agent['host_pid'], signal.SIGSTOP)
    injection.update(outcome='stopped_pending_phase_verification', phase_event=matching[-1],
        stop_utc_ns=time.time_ns(), stop_elapsed_seconds=round(time.monotonic()-started, 6))
    killed = False
    try:
        until = time.monotonic()+5
        while time.monotonic() < until:
            tasks = list(pathlib.Path('/proc', str(agent['host_pid']), 'task').glob('*/stat'))
            if tasks and all(p.read_text().rsplit(')', 1)[1].split()[0] == 'T' for p in tasks):
                break
            time.sleep(.005)
        else:
            raise AssertionError('Agent threads did not all stop')
        current = [e for e in events(path) if e.get('e') == 'restore' and e.get('eobj') == name]
        injection['last_events_while_stopped'] = current[-8:]
        injection['processes_while_stopped'] = fixture.processes(member)
        # A temporary mongod log is created only after copying. This also catches
        # a temporary mongod that raced ahead and exited before process inspection.
        if (fixture.directories[member]/'pbm.restore.log').exists():
            raise RaceLost('Missed pre-temporary-mongod phase')
        if any(p['command'] == 'mongod' for p in injection['processes_while_stopped']):
            raise RaceLost('Temporary mongod already running')
        assert (fallback/'WiredTiger').is_file() and (fallback/'key.db').is_dir()
        assert matching[-1] in current
        injection['copy_events_before_kill'] = [e for e in current if e.get('msg', '').startswith('copy <')]
        if not injection['copy_events_before_kill']:
            raise RaceLost('Copy had not started; no SIGKILL credit')
        if any(e.get('msg') == 'preparing data' for e in current):
            raise RaceLost('Copy phase already ended')
        expected = expected_copy_paths(report['backup_files_sha256'], report['backup']['replsets'][0]['name'])
        missing = [name for name in expected if not (fixture.directories[member]/name).is_file()]
        injection['expected_copy_output_paths'] = expected
        injection['missing_copy_output_paths_while_stopped'] = missing
        if not missing:
            raise RaceLost('Incomplete copying not proved; no SIGKILL credit')
        injection['fallback_files_sha256'] = manifest(fallback)
        assert injection['fallback_files_sha256']
        fixture.assert_same_agent(member, agent)
        os.kill(agent['host_pid'], signal.SIGKILL)
        killed = True
        injection.update(outcome='executed_sigkill_during_copy', kill_utc_ns=time.time_ns(),
            kill_elapsed_seconds=round(time.monotonic()-started, 6))
        fixture.wait(lambda: True if not any(p['host_pid'] == agent['host_pid']
            for p in fixture.processes(member)) else None, seconds=20)
        injection['agent_absent_after_kill'] = True
    except BaseException:
        if not killed:
            injection['outcome'] = 'race_or_verification_failure_no_sigkill'
        raise
    finally:
        if not killed:
            # SIGSTOP alone is never credited as the requested kill injection.
            os.kill(agent['host_pid'], signal.SIGCONT)


def run(fixture, report):
    def passed(description):
        report['passed'].append(description)
        (pbm.OUT/'image.json').write_text(json.dumps(report, indent=2)+'\n')
        print('PASS', description, flush=True)

    backup, target, initial_material = pbm.prepare_recovery(fixture, report, passed)
    assert report['database_build']['version'] == '8.0.34-15'
    before = {'documents': [{'_id': 999, 'account': 'future-only', 'balance': -1}],
        'indexes': copy.deepcopy(target['indexes'])}
    fixture.agree(before)
    rotated = report['pre_restore_rotated_key_ids']
    with fixture.server.connect() as client:
        material = {key: key_value(client, key) for key in rotated}
    report['key_material_sha256'] = {key: hashlib.sha256(value).hexdigest()
        for key, value in {**initial_material, **material}.items()}
    report.update(before_restore_snapshot=before, before_restore_snapshot_sha256=snapshot_sha(before),
        backup_files_sha256=manifest(fixture.storage/backup['name']))
    primary = fixture.primary()
    member = next(i for i in range(3) if i != primary)
    agent = fixture.owned_agent(member)
    report['injection'] = dict(outcome='not_executed', member=member,
        primary_member_before_restore=primary, agent=agent,
        requested_phase='after shutdown/fallback move, during copy, before any temporary mongod',
        signals=['SIGSTOP for phase verification', 'SIGKILL'])
    ts = report['restore_target']
    options = ['--base-snapshot='+backup['name'], '--time='+str(ts['t'])+','+str(ts['i']),
        '--fallback-enabled=true', '--allow-partly-done=false', '--yes']
    report['restore_start_options'] = options
    started = time.monotonic()
    restore = fixture.cli_json('restore', *options, label='restore-start')
    interrupt(fixture, report, member, restore['name'], agent, started)
    passed('one owned secondary PBM agent is SIGKILLed after verified shutdown/fallback move during physical copy; stopped process/phase checks exclude an unexecuted injection or temporary-mongod race')

    def finished():
        result = fixture.cli_json('describe-restore', restore['name'],
            '--config=/control/storage.yaml', label='restore-status')
        report['last_restore_observation'] = result
        assert result['status'] != 'done', 'Restore incorrectly succeeded with killed participant'
        terminal = []
        for i, directory in enumerate(fixture.controls):
            if i == member:
                continue
            matches = [e for e in events(directory/'agent.log') if e.get('e') == 'restore'
                and e.get('eobj') == restore['name'] and e.get('msg', '').startswith('restore: ')
                and e['msg'].endswith('exec cleanup strategy: fallback applyed')]
            if not matches:
                return None
            terminal.append(matches[-1])
        if result['status'] != 'error':
            return None
        report['survivor_terminal_fallback_events'] = terminal
        return result

    result = fixture.wait(finished, seconds=900)
    assert result['type'] == 'physical'
    assert 'stuck' in json.dumps(result) or 'heartbeat' in json.dumps(result)
    report.update(restore=result, observed_failure_and_cleanup_seconds=round(time.monotonic()-started, 3),
        automatic_recovery='surviving agents fallback; killed agent cannot execute deferred cleanup')
    fallback = fixture.directories[member]/'.fallbacksync'
    assert manifest(fallback) == report['injection']['fallback_files_sha256']
    assert not any(e.get('eobj') == restore['name'] and 'fallback applyed' in e.get('msg', '')
        for e in events(fixture.controls[member]/'agent.log'))
    assert not any(p['command'] in ['mongod', 'pbm-agent'] for p in fixture.processes(member))
    passed('PBM reports restore Error after lost-agent heartbeat detection; both surviving agents complete terminal fallback, while the killed member retains untouched fallback files and has no automatic-cleanup credit')

    # No process is allowed to touch the files while the fixture performs manual
    # recovery. Survivors have completed cleanup; stop only these owned containers.
    for i in range(3):
        fixture.stop(i)
    report['manual_fallback'] = dict(member=member, performed=False,
        scope='Fixture-only offline recovery of the killed member from its own intact .fallbacksync; not vendor automatic fallback',
        all_owned_members_stopped=all(not fixture.inspect(i)['State']['Running'] for i in range(3)))
    assert report['manual_fallback']['all_owned_members_stopped']
    expected_files = report['injection']['fallback_files_sha256']
    assert manifest(fallback) == expected_files
    # Quarantine partial restore output; never merge it with the retained database.
    quarantine = fixture.root/'interrupted-copy-quarantine'
    quarantine.mkdir(mode=0o700)
    directory = fixture.directories[member]
    for path in directory.iterdir():
        if path != fallback:
            path.rename(quarantine/path.name)
    for path in list(fallback.iterdir()):
        path.rename(directory/path.name)
    fallback.rmdir()
    assert manifest(directory) == expected_files
    report['manual_fallback'].update(performed=True, restored_files_sha256=expected_files,
        partial_copy_quarantine_sha256=manifest(quarantine), completed_utc_ns=time.time_ns())
    for i in range(3):
        fixture.start(i)
        fixture.ready(i)
        # Cold-check one member at a time with both peers stopped. Initial sync
        # cannot manufacture fallback success from another running member.
        fixture.wait(lambda i=i: True if fixture.snapshot(i) == before else None, seconds=90)
        assert fixture.key_id(i) == rotated[i]
        fixture.stop(i)
    for i in range(3):
        fixture.start(i)
        fixture.ready(i)
    fixture.primary()
    fixture.agree(before)
    assert all(key_state(fixture.server, key) == 2 for key in rotated+report['initial_key_ids'])
    with fixture.server.connect() as client:
        assert all(key_value(client, key) == value for key, value in {**initial_material, **material}.items())
    for i in range(3):
        assert fixture.shell(i, 'db.getSiblingDB("qualification").runCommand({validate:"records",full:true}).valid') is True
    assert manifest(fixture.storage/backup['name']) == report['backup_files_sha256']
    report.update(fallback_snapshot_sha256=snapshot_sha(before),
        fallback_member_key_ids=[fixture.key_id(i) for i in range(3)],
        restore_outcome='error_then_survivor_automatic_and_killed_member_manual_fallback')
    passed('offline manual fallback on the killed member and completed vendor fallback on survivors recover exact newer documents/hidden indexes and original current key identities/bytes; historical target does not replace newer data')

    marker = {'_id': 1000, 'account': 'after-interrupted-restore', 'balance': 7}
    assert fixture.shell(fixture.primary(), 'db.getSiblingDB("qualification").records.insertOne('+
        json.dumps(marker)+', {writeConcern:{w:"majority",j:true,wtimeout:15000}}).acknowledged') is True
    resumed = copy.deepcopy(before)
    resumed['documents'].append(marker)
    fixture.agree(resumed)
    report['post_fallback_snapshot_sha256'] = snapshot_sha(resumed)
    passed('recovered replica set accepts a fresh journaled majority write and all three members match the independent document/index oracle')
    for i in range(3):
        fixture.start_agent(i)
    fixture.cli('config', '--force-resync', '--wait', label='resync-after-interrupt')
    fixture.wait(fixture.agent_health)
    report['fresh_backup'] = fixture.backup('fresh-base-after-interrupt')
    assert report['fresh_backup']['replsets'][0]['security']['kmip']['keyIdentifier'] in rotated
    fixture.cli('config', '--set=pitr.enabled=true', label='resume-pitr-after-interrupt')
    report['resumed_agents'] = fixture.wait(fixture.agent_health)
    passed('healthy PBM agents complete a fresh physical backup under a usable current member key and re-enable PITR after interrupted-restore fallback')


def identity(engine, image):
    config = local_image_id(engine, image)
    package = packaged_evidence(config)
    assert package.get('archive_sha256'), 'A checked archive manifest is required'
    packaged = json.loads((ROOT/'artifacts/image.json').read_text())
    with tarfile.open(ROOT/'artifacts'/packaged['archive']) as archive:
        records = json.load(archive.extractfile('manifest.json'))
        assert len(records) == 1
        assert hashlib.sha256(archive.extractfile(records[0]['Config']).read()).hexdigest() == config
    built = json.loads((ROOT/'artifacts/pbm-fixture-image.json').read_text())
    db_config = local_image_id(engine, pbm.COMBINED)
    assert built['status'] == 'verified_fixture_image' and built['image_config_id'] == db_config
    assert built['percona_image'] == pbm.PERCONA and built['pbm_image'] == pbm.PBM
    for executable, upstream in [('mongod', pbm.PERCONA), ('pbm', pbm.PBM), ('pbm-agent', pbm.PBM)]:
        digests = [command([engine, 'run', '--rm', '--entrypoint', 'sha256sum', source,
            '/usr/bin/'+executable]).split()[0] for source in ['sha256:'+db_config, upstream]]
        assert digests[0] == digests[1] == built['binaries_sha256'][executable]
    return dict(**package, server_image='sha256:'+config,
        combined_database_image_config_id=db_config, database_image=pbm.PERCONA,
        pbm_image=pbm.PBM, vendor_binary_sha256=built['binaries_sha256'],
        fixture_manifest_sha256=sha(ROOT/'artifacts/pbm-fixture-image.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(ROOT/'artifacts'), 'Output must be under this checkout\'s artifacts directory'
    output.mkdir(parents=True, exist_ok=False)  # Never overwrite a failed attempt.
    pbm.OUT = test_database.ART = test_database_replicaset.OUT = output
    report = dict(status='running', scenario='sigkill-agent-during-copy', passed=[], members=3,
        starting_head=command(['git', 'rev-parse', 'HEAD']).strip(),
        limits=LIMITS)
    names = ['scripts/test_database_pbm_interrupt.py', 'scripts/test_database_pbm.py',
        'scripts/test_database_backup.py', 'scripts/test_database_replicaset.py',
        'scripts/test_database.py', 'scripts/test_runtime.py', 'scripts/wire.py',
        'scripts/image_evidence.py', 'scripts/dev-pki.sh', 'interop/pbm/Dockerfile',
        'interop/pbm/node.sh', 'interop/pbm/command.sh', 'scripts/build_pbm_fixture.py']
    for name in names:
        snapshot = output/'harness'/name
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT/name, snapshot)
    binary = ROOT/'target/debug/keytend-kmip-server'
    fixture = None
    try:
        report['runtime_binary_sha256'] = sha(binary)
        report.update(identity('podman', args.image))
        # Freeze both images to config IDs, regardless of later tag movement.
        pbm.COMBINED = 'sha256:'+report['combined_database_image_config_id']
        cache = ROOT/'.cache/pbm-interrupt-e66cd561'
        cache.mkdir(parents=True, exist_ok=True)
        # Stopping the agent mid-copy is a race. A lost race sends no signal and proves nothing, so
        # the whole scenario is repeated on a fresh fixture, at most ATTEMPTS times; every attempt
        # is recorded. Any other failure fails at once.
        report['attempts'] = []
        for attempt in range(1, ATTEMPTS+1):
            pbm.OUT = test_database.ART = test_database_replicaset.OUT = output/f'attempt-{attempt}'
            pbm.OUT.mkdir()
            for key in ('passed', 'injection', 'owned_containers', 'fixture_directory', 'owned_containers_removed'):
                report.pop(key, None)
            report['passed'] = []
            lost = None
            with tempfile.TemporaryDirectory(prefix='fixture-', dir=cache) as directory:
                fixture = InterruptSet(directory, 'podman', report['server_image'])
                report['owned_containers'] = fixture.names+[fixture.server.name]
                report['fixture_directory'] = str(fixture.root)
                try:
                    run(fixture, report)
                except RaceLost as error:
                    lost = str(error)
                finally:
                    fixture.cleanup()
                    report['owned_containers_removed'] = not any(fixture.exists(i) for i in range(3)) and not fixture.server.container_exists()
            removed = not pathlib.Path(report['fixture_directory']).exists()
            assert report['owned_containers_removed'] and removed
            report['attempts'].append(dict(attempt=attempt, outcome='race_lost_no_sigkill' if lost else 'executed',
                detail=lost, injection=report.get('injection')))
            if lost is None:
                break
            print(f'RACE attempt {attempt}: {lost}; repeating on a fresh fixture', flush=True)
        else:
            raise AssertionError(f'race lost in all {ATTEMPTS} attempts; no SIGKILL credit')
        report['fixture_directory_removed'] = True
        report['status'] = 'passed'
    except BaseException as error:
        detail = error.output if isinstance(error, subprocess.CalledProcessError) else str(error)
        report.update(status='failed', error_type=type(error).__name__,
            error=fixture.redact(detail) if fixture else detail)
        raise
    finally:
        report['log_sha256'] = {str(path.relative_to(ROOT)): sha(path) for path in output.glob('*.log')}
        (output/'image.json').write_text(json.dumps(report, indent=2)+'\n')
    print('PASS interrupted-restore lane:', len(report['passed']), 'bounded checks; manual fallback explicitly required')


if __name__ == '__main__':
    main()
