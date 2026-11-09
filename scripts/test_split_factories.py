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

"""Independent OVH generic-payload Create/Join interoperability and real restart."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
from image_evidence import local_image_id, packaged_evidence, source_commit
from https_client import HttpsServer, post
from test_split_objects import SplitContainer
from test_database import ContainerServer
from test_runtime import ROOT
from wire import *


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()



def numeric_exchange(server, transport, message):
    if transport == 'TLS':
        with server.connect() as connection:
            return exchange(connection, message)
    return post(server, message, transport.removeprefix('HTTPS-'))


def attributes(version, values):
    if version[0] >= 2:
        return structure(0x420125, *values)
    names = {0x420042: 'Key Format Type'}
    return structure(0x420091, *[structure(0x420008,
        text(0x42000a, names[n[0]]), node(0x42000b, n[1], n[2])) for n in values])


def numeric_create(server):
    records = []
    material = bytes.fromhex('00000102030405060708090a0b0c0d0e')
    for version in [(1,2), (1,3), (1,4), (2,0), (2,1), (3,0)]:
        for method in [1,2,3,4]:
            for fmt in [1,2]:
                for polynomial in ([1,2] if version[0] >= 3 and method in [2,4] else [2]):
                    for transport in ['TLS','HTTPS-TTLV','HTTPS-JSON','HTTPS-XML']:
                        def call(op, fields):
                            return payload(numeric_exchange(server, transport, request(op, fields, v=version)))
                        source = get(call(3, [enumeration(0x420057,2), attributes(version, []),
                            structure(0x42008f, structure(0x420040, enumeration(0x420042,1),
                            structure(0x420045,binary(0x420043,material)), enumeration(0x420028,3),integer(0x42002a,128)))]),0x420094)[2]
                        attrs = [enumeration(0x420042,fmt)] if version[0] >= 2 else []
                        poly = [enumeration(0x4201b6,polynomial)] if version[0] >= 3 and method in [2,4] else []
                        created = call(40,[enumeration(0x420057,5),uid(source,version),integer(0x42008b,3),
                            integer(0x42008c,3 if method==1 else 2),enumeration(0x42008a,method),attributes(version,attrs+poly)])
                        assert bool(children(created,0x420057)) == (version==(1,2))
                        parts = [n[2] for n in children(created,0x420094)]
                        assert len(parts) == 3 and len(set(parts)) == 3
                        external = []
                        for part in parts:
                            value = get(call(10,[uid(part,version),enumeration(0x420042,fmt)]),0x420089)
                            external.append(get(call(3,[enumeration(0x420057,5),attributes(version,poly),value]),0x420094)[2])
                        def join(ids):
                            selected = ids if method==1 else [ids[2],ids[0]]
                            result = call(41,[enumeration(0x420057,2),*[uid(n,version) for n in selected]])
                            assert bool(children(result,0x420057)) == (version==(1,2))
                            key = get(result,0x420094)[2]
                            value = get(get(get(get(call(10,[uid(key,version)]),0x42008f),0x420040),0x420045),0x420043)[2]
                            assert value == material
                            return key
                        join(external)
                        joined = join(parts)
                        call(20,[uid(source,version)])
                        records.append(dict(version=version,method=method,format=fmt,polynomial=polynomial,
                            transport=transport,joined=joined,parts=parts))
    assert len(records) == 208
    return records


def numeric_verify(server, records):
    material = bytes.fromhex('00000102030405060708090a0b0c0d0e')
    for record in records:
        version = tuple(record['version'])
        def call(op, fields):
            return payload(numeric_exchange(server, record['transport'], request(op, fields, v=version)))
        selected = record['parts'] if record['method']==1 else [record['parts'][2],record['parts'][0]]
        joined = get(call(41,[enumeration(0x420057,2),*[uid(n,version) for n in selected]]),0x420094)[2]
        for key in [record['joined'],joined]:
            value = get(get(get(get(call(10,[uid(key,version)]),0x42008f),0x420040),0x420045),0x420043)[2]
            assert value == material

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image')
    parser.add_argument('--engine', default='podman')
    parser.add_argument('--binary', type=pathlib.Path, default=ROOT/'target/debug/keytend-kmip-server')
    args = parser.parse_args()
    sdk = ROOT/'interop/ovh'
    adapter = ROOT/'integration/split/factories.go'
    executable = ROOT/'.cache/split-factories-go'
    executable.parent.mkdir(exist_ok=True)
    assert subprocess.check_output(['go', 'mod', 'verify'], cwd=sdk, text=True).strip() == 'all modules verified'
    module = json.loads(subprocess.check_output(['go', 'list', '-m', '-json', 'github.com/ovh/kmip-go'], cwd=sdk, text=True))
    pin = json.loads((ROOT/'interop/clients.lock.json').read_text())['ovh']['commit']
    assert module['Version'].endswith(pin[:12])
    subprocess.run(['go', 'build', '-mod=readonly', '-o', str(executable), str(adapter)], cwd=sdk, check=True)
    runtime = packaged_evidence(local_image_id(args.engine, args.image)) if args.image else {'runtime_binary_sha256': sha(args.binary), 'source_commit': source_commit()[0]}
    adapter_hash = sha(executable)
    suffix = 'image' if args.image else 'native'
    out = ROOT/'artifacts'
    out.mkdir(exist_ok=True)
    report_path = out/f'split-factories-{suffix}.json'
    report_path.write_text(json.dumps({'status': 'running'})+'\n')
    with tempfile.TemporaryDirectory(prefix='keytend-factories-') as directory:
        server = SplitContainer(directory, args.engine, args.image) if args.image else HttpsServer(directory, binary=args.binary, draft=True)
        try:
            server.start()
            env = {**os.environ, 'KMIP_PKI': str(server.pki), 'KMIP_PORT': str(server.port), 'KMIP_HTTPS_PORT': str(server.https)}
            records = None
            for phase in ['create', 'verify', 'restore']:
                command = [str(executable), 'create' if phase == 'create' else 'verify']
                if phase != 'create':
                    server.stop()
                    if phase == 'restore':
                        restored = pathlib.Path(directory)/'restored-data'
                        restored.mkdir(mode=0o700)
                        shutil.copyfile(backup, restored/'kmip.sqlite')
                        (restored/'kmip.sqlite').chmod(0o600)
                        server.data = restored
                    server.start()
                    manifest = pathlib.Path(directory)/'records.json'
                    manifest.write_text(json.dumps(records))
                    command.append(str(manifest))
                result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
                (out/f'split-factories-{suffix}-{phase}.log').write_text(result.stderr)
                assert result.returncode == 0, result.stderr
                if phase == 'create':
                    records = json.loads(result.stdout)
                    assert len(records) == 96
                    assert len({(r['Minor'], r['Transport'], r['Method'], r['Format']) for r in records}) == 96
                    numeric_records = numeric_create(server)
                    if args.image:
                        # The CLI container must not publish the live HTTPS port again.
                        subprocess.run(ContainerServer.base(server)+[args.image, 'backup', '--database', '/data/kmip.sqlite',
                            '--master-key', '/tls/master.key', '--output', '/data/backup.sqlite'], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        backup = server.data/'backup.sqlite'
                    else:
                        backup = pathlib.Path(directory)/'backup.sqlite'
                        subprocess.run([str(args.binary), 'backup', '--database', str(server.data/'kmip.sqlite'),
                            '--master-key', str(server.pki/'master.key'), '--output', str(backup)], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    backup_sha256 = sha(backup)
                else:
                    assert json.loads(result.stdout)['status'] == 'passed'
                    numeric_verify(server, numeric_records)
        finally:
            server.stop()
    logs = [out/f'split-factories-{suffix}-{phase}.log' for phase in ['create', 'verify', 'restore']]
    report = dict(status='passed', scope='96 KMIP 1.2/1.3/1.4 OVH SDK lanes: four methods, Raw/Opaque Get/Register share formats (legacy Create has no Key Format Type attribute), TLS and HTTPS TTLV/JSON/XML. Exact source reconstruction from local and Get/Register external shares; joined keys and further reconstruction after actual restart and encrypted CLI backup restoration into a clean data directory, with original source destroyed. Twelve fixed OASIS GF8 vector lanes. Generic SDK payload API; no native Create/Join builders. Separate numeric driver adds 208 all-edition/encoding lanes, both draft polynomials and real restart. Numeric driver is not another independent client. Other object types and full profiles are not established by these network tests.',
        **runtime,
        sdk_repository='https://github.com/ovh/kmip-go', sdk_commit=pin, sdk_module_version=module['Version'],
        sdk_module_sum=module['Sum'], sdk_modules_verified=True, adapter_binary_sha256=adapter_hash,
        go_version=subprocess.check_output(['go', 'version'], text=True).strip(),
        go_factory_lanes=96, local_joins=96, external_registration_joins=96, restart_lanes=96, restore_lanes=96, oasis_fixed_vector_lanes=12,
        numeric_factory_lanes=208, numeric_external_joins=208, numeric_restart_lanes=208, numeric_restore_lanes=208,
        encrypted_backup_sha256=backup_sha256,
        log_sha256={str(p.relative_to(ROOT)): sha(p) for p in logs})
    report_path.write_text(json.dumps(report, indent=2)+'\n')
    print(f'PASS {suffix}: 96 independent OVH Create/Join lanes, 96 SDK restart lanes, 208 numeric lanes, exact restart/backup restore for all 304 lanes, 12 OASIS fixed vector lanes')


if __name__ == '__main__':
    main()
