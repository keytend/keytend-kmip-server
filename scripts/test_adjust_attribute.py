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

"""Independent Python integer oracle for scalar Adjust Attribute over mutual TLS.
Subset evidence; the wire helper is not a production SDK or conformance oracle.
"""
import argparse, hashlib, json, pathlib, random, shutil, tempfile
from image_evidence import ROOT, source_commit, local_image_id, packaged_evidence
from test_runtime import Server
from test_storage_rotation import DraftContainer, cli
from wire import *

ATTRIBUTE, VALUE, ATTRS = 0x420008, 0x42000b, 0x420125
REFERENCE, ADJUSTMENT, AMOUNT = 0x42013b, 0x420158, 0x420162


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def scalar(tag, kind, value):
    if kind == 4:
        # Python signed integers supply the independent two's-complement oracle.
        size = max(8, ((value.bit_length()+1+63)//64)*8)
        value = value.to_bytes(size, 'big', signed=True)
    return node(tag, kind, value)


def vendor(name, kind, value):
    return structure(ATTRIBUTE, text(0x42009d, 'x'), text(0x42000a, name), scalar(VALUE, kind, value))


def reference(name):
    return structure(REFERENCE, text(0x42009d, 'x'), text(0x42000a, name))


def read(client, identifier, version, name):
    result = payload(exchange(client, request(11, [uid(identifier, version), reference(name)], version)))
    values = children(get(result, ATTRS), ATTRIBUTE)
    assert len(values) == 1
    value = get(values[0], VALUE)
    return value[1], int.from_bytes(value[2], 'big', signed=True) if value[1] == 4 else value[2]


def adjust(client, identifier, version, name, operation, amount=None):
    fields = [uid(identifier, version), reference(name), enumeration(ADJUSTMENT, operation)]
    if amount is not None:
        fields.append(scalar(AMOUNT, *amount))
    return exchange(client, request(48, fields, version))


def run(server):
    records, checks, accepted, rejected = [], [], 0, 0
    rng = random.Random(0x4b4d4950)
    server.start()
    try:
        with server.connect() as client:
            for version in [(2, 0), (2, 1), (3, 0)]:
                values = [('int', 2, 2**31-1, -(2**31), 2**31-1),
                          ('long', 3, -(2**63), -(2**63), 2**63-1),
                          ('big', 4, -(2**255), None, None),
                          ('interval', 10, 0, 0, 2**32-1),
                          ('date', 9, 2**63-1, -(2**63), 2**63-1),
                          ('microseconds', 11, -(2**63), -(2**63), 2**63-1),
                          ('flag', 6, False, None, None)]
                attributes = [enumeration(0x420028, 3), integer(0x42002a, 256), integer(0x42002c, 12)]
                attributes += [vendor(name, kind, value) for name, kind, value, _, _ in values]
                identifier = get(payload(exchange(client, request(1, [enumeration(0x420057, 2), structure(ATTRS, *attributes)], version))), 0x420094)[2]
                for name, kind, current, minimum, maximum in values:
                    for index in range(32):
                        operation = 3 if kind == 6 else (index % 3)+1
                        amount = None if index % 4 == 0 else ((4, rng.randint(-(2**180), 2**180)) if name == 'big' else (3, rng.randint(-10000, 10000)))
                        expected_reason = None
                        if operation == 3:
                            if kind in (9, 10, 11):
                                expected_reason = 0x1c
                            candidate = not current if kind == 6 else -current
                        else:
                            delta = amount[1] if amount is not None else 1
                            candidate = current + delta if operation == 1 else current - delta
                        if expected_reason is None and minimum is not None and not minimum <= candidate <= maximum:
                            expected_reason = 0x1b
                        result = adjust(client, identifier, version, name, operation, amount)
                        if expected_reason is not None:
                            assert status(result) == 1 and reason(result) == expected_reason, (version, name, index, result)
                            rejected += 1
                        else:
                            assert get(payload(result), 0x420094)[2] == identifier
                            current = candidate
                            accepted += 1
                        assert read(client, identifier, version, name) == (kind, current), (version, name, index)
                    records.append((identifier, version, name, kind, current))
                # A missing numeric attribute starts at zero, with a supplied type.
                payload(adjust(client, identifier, version, 'absent', 2, (4, 2**200)))
                records.append((identifier, version, 'absent', 4, -(2**200)))
                assert read(client, identifier, version, 'absent') == (4, -(2**200))
                # Read-only usage masks cannot be made writable by an arithmetic API.
                result = exchange(client, request(48, [uid(identifier, version), enumeration(REFERENCE, 0x42002c), enumeration(ADJUSTMENT, 1), integer(AMOUNT, 16)], version))
                assert status(result) == 1 and reason(result) == 0x1d
                checks.append({'version': list(version), 'random_and_boundary_arithmetic': 224, 'absent_numeric': True, 'usage_mask_readonly': True})
        backup = server.root/'backup.sqlite'
        cli(server, 'backup', database=server.data/'kmip.sqlite', master_key=server.pki/'master.key', output=backup).check_returncode()
    finally:
        server.stop()
    for phase in ['restart', 'clean_backup_restore']:
        if phase == 'clean_backup_restore':
            restored = server.root/'restored';restored.mkdir(mode=0o700)
            shutil.copyfile(backup, restored/'kmip.sqlite');(restored/'kmip.sqlite').chmod(0o600)
            server.data = restored
        server.start()
        try:
            with server.connect() as client:
                for identifier, version, name, kind, current in records:
                    assert read(client, identifier, version, name) == (kind, current)
            checks.append({'phase': phase, 'values_verified': len(records)})
        finally:
            server.stop()
    cli(server, 'check-store', database=server.data/'kmip.sqlite', master_key=server.pki/'master.key').check_returncode()
    return dict(lanes=checks, successful_arithmetic=accepted, rejected_arithmetic=rejected, backup_sha256=sha(backup))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--engine', default='podman');args=parser.parse_args()
    binary=sha(ROOT/'target/debug/keytend-kmip-server')
    config=local_image_id(args.engine,args.image) if args.image else None
    evidence=packaged_evidence(config) if config else {'runtime_binary_sha256':binary,'source_commit':source_commit()[0]}
    out=ROOT/'artifacts/adjust-attribute';out.mkdir(parents=True,exist_ok=True)
    path=out/('image.json' if args.image else 'native.json')
    report=dict(status='running',scope='Seeded Python arbitrary-precision arithmetic oracle, TTLV scalar types, absent numeric, readonly mask, restart and clean backup restore; no full conformance or qualified SDK claim',**evidence)
    path.write_text(json.dumps(report,indent=2)+'\n')
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-adjust-') as directory:
            server=DraftContainer(directory,args.engine,args.image) if args.image else Server(directory,draft=True)
            try:report.update(run(server))
            finally:
                server.stop()
                log=pathlib.Path(directory)/'server.log'
                if log.exists():
                    saved=out/(path.stem+'-server.log');shutil.copyfile(log,saved);report['log_sha256']={str(saved.relative_to(ROOT)):sha(saved)}
        report['status']='passed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS Adjust Attribute',path.stem,report['successful_arithmetic'],'accepted,',report['rejected_arithmetic'],'rejected arithmetic cases')

if __name__=='__main__':main()
