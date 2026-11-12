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

"""Identify the image under test and the source commit it was built from."""
import hashlib,json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATHS=['Cargo.toml','Cargo.lock','Dockerfile','.dockerignore','LICENSE','NOTICE','image/openssl.cnf','src','crates']

def source_fingerprints():
    """SHA-256 of every file in the image build context (recorded in release provenance by scripts/package.py)."""
    files=[ROOT/name for name in SOURCE_PATHS[:7]]+sorted((ROOT/'src').rglob('*.rs'))+sorted((ROOT/'src').rglob('*.json'))+sorted((ROOT/'crates').rglob('*.rs'))+sorted((ROOT/'crates').glob('*/Cargo.toml'))
    return {str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}

def git(*args):return subprocess.run(['git',*args],cwd=ROOT,capture_output=True,text=True)
def source_commit():
    """The current commit, and whether the image sources differ from it."""
    return git('rev-parse','HEAD').stdout.strip(),bool(git('status','--porcelain','--',*SOURCE_PATHS).stdout.strip())

# Image platforms. amd64 keeps the original artifact paths; other platforms use artifacts/linux-<arch>/.
# rpm_arch is the RPM architecture of the shipped binaries, elf_machine the ELF e_machine of the server.
PLATFORMS={'amd64':{'platform':'linux/amd64','rpm_arch':'x86_64','elf_machine':62,'pin_suffix':''},
           'arm64':{'platform':'linux/arm64','rpm_arch':'aarch64','elf_machine':183,'pin_suffix':'_ARM64'}}
def dockerfile_arg(name):
    import re
    return re.search(rf'^ARG {name}="?([^"\n]+)"?$',(ROOT/'Dockerfile').read_text(),re.M).group(1)
def base_images(arch='amd64'):
    """The pinned per-architecture manifest digests of the two UBI stages, as Dockerfile build arguments."""
    suffix=PLATFORMS[arch]['pin_suffix']
    return {stage:dockerfile_arg(stage+suffix) for stage in ['UBI_BUILDER','UBI_MICRO']}
def base_indexes():
    """Multi-architecture index digests the per-architecture pins were taken from (Dockerfile comments)."""
    import re
    return dict(re.findall(r'^# index (UBI_BUILDER|UBI_MICRO): (\S+)$',(ROOT/'Dockerfile').read_text(),re.M))
def artifacts_dir(arch='amd64'):
    return ROOT/'artifacts' if arch=='amd64' else ROOT/'artifacts'/f'linux-{arch}'
def archive_name(version,arch='amd64'):
    return f'keytend-kmip-server-{version}.docker.tar' if arch=='amd64' else f'keytend-kmip-server-{version}-linux-{arch}.docker.tar'
def check_platform(config,arch):
    """The image configuration must be for the requested platform."""
    assert (config.get('os'),config.get('architecture'))==('linux',arch),f"image is {config.get('os')}/{config.get('architecture')}, expected linux/{arch}"

def normalized_id(value):return value.removeprefix('sha256:')
NATIVE=ROOT/'target/debug/keytend-kmip-server'
def runtime_evidence(binary,image=None,engine='podman'):
    """What a report records as the server under test: the image (its ID, archive digest and source
    commit) when `binary` runs it (scripts/image_server.py), else the native executable's SHA-256."""
    if image:return {'runtime':{'kind':'image','image':image,**packaged_evidence(local_image_id(engine,image))}}
    return {'runtime_binary_sha256':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()}
def runtime_identity(report):
    """The server-under-test record of a report written with runtime_evidence (either form)."""
    return report.get('runtime') or {'runtime_binary_sha256':report.get('runtime_binary_sha256')}
def native_sha256(image=None):
    """SHA-256 of the native debug executable for a run against it; None for a run against an image,
    which never needs the native executable (it may not exist)."""
    return None if image else hashlib.sha256(NATIVE.read_bytes()).hexdigest()
def local_image_id(engine,image):
    return normalized_id(json.loads(subprocess.check_output([engine,'image','inspect',image]))[0]['Id'])
def packaged_evidence(config_id,arch='amd64'):
    """The tested image ID, plus the archive digest and source commit when the image was packaged (scripts/package.py).

    Warns, without failing, when the image was built from different sources than the working tree:
    a release run builds its own image from a clean commit, so this only matters for ad hoc runs."""
    result={'tested_image_config_id':normalized_id(config_id)}
    manifest=artifacts_dir(arch)/'image.json'
    if not manifest.exists():return result # An image may be built without exporting an archive.
    m=json.loads(manifest.read_text())
    if normalized_id(m['image_id'])!=normalized_id(config_id):
        raise ValueError(f'tested image does not match {manifest.relative_to(ROOT)}; rebuild/export the intended image')
    result['archive_sha256']=m['sha256']
    if commit:=m.get('source_commit'):
        result['source_commit']=commit
        if m.get('source_dirty') or git('diff','--quiet',commit,'--',*SOURCE_PATHS).returncode:
            print(f'warning: image was built from {commit[:12]}{" with local changes" if m.get("source_dirty") else ""}; '
                  'the working tree sources differ',file=sys.stderr)
    return result
