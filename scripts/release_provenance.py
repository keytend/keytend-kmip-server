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

"""In-toto Statement v1 with an SLSA v1 build provenance predicate for one image archive.

The statement describes what scripts/package.py did: source commit, build
command, platform, pinned base image digests, package pins, the build context
and Cargo.lock digests, the builder host and the timestamps. The builder is a
developer-operated host, so this is SLSA Build Level 1 provenance at most: it is
signed with the release key afterwards (docs/release-signing.md), but nothing
here is attested by a hardened build platform.
"""
import hashlib
import json
import urllib.parse

STATEMENT_TYPE = 'https://in-toto.io/Statement/v1'
PREDICATE_TYPE = 'https://slsa.dev/provenance/v1'
REPOSITORY = 'https://github.com/keytend/keytend-kmip-server'
BUILD_TYPE = REPOSITORY+'/blob/main/docs/release-signing.md#build-type-podman-dockerfile-v1'


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def oci_reference(reference):
    """`registry/repo@sha256:x` -> (oci://registry/repo, x)."""
    name, digest = reference.split('@sha256:')
    return 'oci://'+name, digest


def rpm_purl(name, fields, distro):
    qualifiers = 'arch='+fields['arch']+(f"&epoch={fields['epoch'][0]}" if fields.get('epoch') else '')+'&distro='+distro
    return 'pkg:rpm/redhat/'+urllib.parse.quote(name, safe='')+'@'+urllib.parse.quote(f"{fields['version']}-{fields['release']}", safe='')+'?'+qualifiers


def statement(*, archive_name, archive_sha256, image_id, platform, commit, dirty, build_command, build_args, base_images,
              base_indexes, build_packages, runtime_packages, distro, context_sha256, source_sha256, cargo_lock_sha256,
              dockerfile_sha256, builder_sha256, builder_host, started, finished, invocation, byproducts):
    """Assemble the statement; every argument is recorded verbatim or as a digest."""
    dependencies = [dict(uri=f'git+{REPOSITORY}@{commit}', digest=dict(gitCommit=commit),
                         annotations=dict(dirty=dirty, note='working tree had uncommitted changes' if dirty else 'clean tree'))]
    for stage, reference in sorted(base_images.items()):
        uri, digest = oci_reference(reference)
        annotations = dict(stage=stage, platform=platform, kind='per-architecture image manifest')
        if stage in base_indexes:
            annotations['multi_architecture_index'] = base_indexes[stage].split('@', 1)[1]
        dependencies.append(dict(uri=uri, digest=dict(sha256=digest), annotations=annotations))
    dependencies += [
        dict(name='build-context.tar', digest=dict(sha256=context_sha256),
             annotations=dict(note='deterministic tar (sorted names, zero mtimes) of the runtime sources the Dockerfile copies')),
        dict(name='Cargo.lock', digest=dict(sha256=cargo_lock_sha256)),
        dict(name='Dockerfile', digest=dict(sha256=dockerfile_sha256)),
        dict(name='runtime-source-fingerprints', digest=dict(sha256=canonical_sha256(source_sha256)),
             annotations=dict(note='SHA-256 of the canonical JSON map {path: sha256} from scripts/image_evidence.py', files=len(source_sha256))),
    ]
    for name, fields in sorted(runtime_packages.items()):
        item = dict(uri=rpm_purl(name, fields, distro), annotations=dict(stage='runtime root', source_rpm=fields.get('sourcerpm', '')))
        if fields.get('sha256header'):
            # RPM SHA-256 header digest from the shipped rpmdb (not a digest of the .rpm file).
            item['annotations']['rpm_sha256header'] = fields['sha256header']
        dependencies.append(item)
    for nvr in build_packages:
        dependencies.append(dict(uri=f'pkg:rpm/redhat/{nvr}', annotations=dict(stage='build toolchain', note='installed by dnf with Red Hat signature verification; not shipped')))
    subjects = [dict(name=archive_name, digest=dict(sha256=archive_sha256)),
                dict(name='image-config', digest=dict(sha256=image_id.removeprefix('sha256:')),
                     annotations=dict(note='image configuration digest (podman image ID)'))]
    return {
        '_type': STATEMENT_TYPE,
        'subject': subjects,
        'predicateType': PREDICATE_TYPE,
        'predicate': {
            'buildDefinition': {
                'buildType': BUILD_TYPE,
                'externalParameters': dict(source=dict(uri=REPOSITORY, commit=commit), platform=platform, dockerfile='Dockerfile',
                                           buildArgs=build_args),
                'internalParameters': dict(command=build_command, builder_host=builder_host),
                'resolvedDependencies': dependencies,
            },
            'runDetails': {
                'builder': dict(id=f'{REPOSITORY}/blob/{commit}/scripts/package.py', version={'scripts/package.py': builder_sha256}),
                'metadata': dict(invocationId=invocation, startedOn=started, finishedOn=finished),
                'byproducts': [dict(name=name, digest=dict(sha256=digest)) for name, digest in sorted(byproducts.items())],
            },
        },
    }


def check(document, archive_name, archive_sha256, image_id):
    """Structural checks shared by the release verifier and the unit tests."""
    assert document['_type'] == STATEMENT_TYPE and document['predicateType'] == PREDICATE_TYPE
    subjects = {item['name']: item['digest']['sha256'] for item in document['subject']}
    assert subjects.get(archive_name) == archive_sha256, 'provenance subject does not name the archive digest'
    assert subjects.get('image-config') == image_id.removeprefix('sha256:'), 'provenance subject does not name the image config'
    build = document['predicate']['buildDefinition']
    assert build['buildType'] == BUILD_TYPE
    commits = [item['digest']['gitCommit'] for item in build['resolvedDependencies'] if 'gitCommit' in item.get('digest', {})]
    assert commits == [build['externalParameters']['source']['commit']], 'source commit is not recorded once'
    images = [item for item in build['resolvedDependencies'] if item.get('uri', '').startswith('oci://')]
    assert {item['annotations']['stage'] for item in images} == {'UBI_BUILDER', 'UBI_MICRO'}
    assert all(len(item['digest']['sha256']) == 64 for item in images)
    return True
