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

"""The one place that names the external build, test and release tools.

Live scripts import these pins instead of naming a JDK, kind, kubectl or a
cache path themselves. The Java client is the signed keytend-kmip release
pinned in interop/java/keytend-kmip-release.json (scripts/keytend_kmip_release.py).

- JDKs come from SDKMAN: `sdk install java <identifier>`. Paths resolve under
  $SDKMAN_DIR (default ~/.sdkman), never a fixed home directory.
  KEYTEND_JDK_<major> (for example KEYTEND_JDK_17) names a JDK home instead;
  the release workflow sets it to the Corretto JDKs of actions/setup-java.
- kind and kubectl come from the Debian packages and are used from PATH. The
  release workflow downloads the same versions' release binaries, SHA-256
  pinned below (`toolchain.py fetch-kube`).
- helm is the pinned release binary of scripts/helm_tool.py, cached in .cache/bin.
- The shared cache is derived from the repository's git common directory, so
  the main checkout and every linked checkout find the same one.

    toolchain.py fetch-kube     download and check kind and kubectl; print their paths
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]

# SDKMAN Java identifiers, by major version. Every Java lane runs on all three.
JDKS = {17: '17.0.21.0+10-amzn', 21: '21.0.13.0+10-amzn', 25: '25.0.5.0+9-amzn'}
# The default lane JDK, which also compiles the adapters.
BUILD_JDK = 25

# Debian (trixie) package versions the release lane was qualified with. A different
# installed version is reported by the bootstrap check and recorded in the manifest.
KIND_PACKAGE = '0.27.0'
KUBECTL_PACKAGE = '1.32.3'
# Node image for `kind create cluster --image`. kind 0.27.0 defaults to kindest/node v1.32.2;
# the digest pins the multi-architecture image published with that kind release.
KIND_NODE_IMAGE = 'docker.io/kindest/node:v1.32.2@sha256:f226345927d7e348497136874b6d207e0b32cc52154ad8323129352923a3142f'
# Release binaries of the same versions, for hosts without the Debian packages (the release
# workflow's runners). SHA-256 from the published kind-linux-<arch>.sha256sum and
# kubectl.sha256 files of those releases.
KUBE_RELEASES = {
    'kind': {'version': KIND_PACKAGE, 'url': 'https://github.com/kubernetes-sigs/kind/releases/download/v{version}/kind-linux-{arch}',
             'sha256': {'amd64': 'a6875aaea358acf0ac07786b1a6755d08fd640f4c79b7a2e46681cc13f49a04b',
                        'arm64': '5e4507a41c69679562610b1be82ba4f80693a7826f4e9c6e39236169a3e4f9d0'}},
    'kubectl': {'version': KUBECTL_PACKAGE, 'url': 'https://dl.k8s.io/release/v{version}/bin/linux/{arch}/kubectl',
                'sha256': {'amd64': 'ab209d0c5134b61486a0486585604a616a5bb2fc07df46d304b3c95817b2d79f',
                           'arm64': '6c2c91e760efbf3fa111a5f0b99ba8975fb1c58bb3974eca88b6134bcf3717e2'}},
}

# GitHub repository whose published releases are the scan baseline.
RELEASE_REPOSITORY = 'keytend/keytend-kmip-server'


def sdkman_dir(environ=None):
    environ = os.environ if environ is None else environ
    return pathlib.Path(environ.get('SDKMAN_DIR') or pathlib.Path.home()/'.sdkman')


def java_home(major=BUILD_JDK, environ=None):
    """Home of the JDK for a major version (17, 21, 25): KEYTEND_JDK_<major>, else the pinned SDKMAN JDK."""
    environ = os.environ if environ is None else environ
    if environ.get(f'KEYTEND_JDK_{major}'):
        return pathlib.Path(environ[f'KEYTEND_JDK_{major}'])
    return sdkman_dir(environ)/'candidates/java'/JDKS[major]


def java(major=BUILD_JDK, environ=None):
    return java_home(major, environ)/'bin/java'


def javas(environ=None):
    """The pinned java executables, oldest first."""
    return [java(major, environ) for major in sorted(JDKS)]


def git_common_dir(root=ROOT):
    out = subprocess.check_output(['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'], cwd=root, text=True)
    return pathlib.Path(out.strip())


def canonical_cache(root=ROOT, environ=None, common_dir=None):
    """The shared cache: $KEYTEND_CACHE_DIR, else `.cache` next to the git common directory.

    For a normal clone the common directory is <main checkout>/.git, so the cache is the main
    checkout's .cache and every linked checkout resolves the same directory without a symlink
    being made by hand. A bare common directory keeps the cache inside itself."""
    environ = os.environ if environ is None else environ
    if environ.get('KEYTEND_CACHE_DIR'):
        return pathlib.Path(environ['KEYTEND_CACHE_DIR']).expanduser()
    common = pathlib.Path(common_dir) if common_dir else git_common_dir(root)
    return common.parent/'.cache' if common.name == '.git' else common/'.cache'


def ensure_cache_link(root=ROOT, cache=None):
    """Make <root>/.cache resolve to the canonical cache. Returns a short status string.

    A missing .cache becomes a symlink. A real directory or a symlink elsewhere is left
    alone (its contents may not be reproducible) and reported, so a caller can refuse."""
    cache = pathlib.Path(cache) if cache else canonical_cache(root)
    local = pathlib.Path(root)/'.cache'
    if local.resolve() == cache.resolve():
        return 'canonical'
    if local.is_symlink() or local.exists():
        return 'differs'
    cache.mkdir(parents=True, exist_ok=True)
    local.symlink_to(cache)
    return 'linked'


def command_version(command, pattern, args=('version',)):
    """First regex group of `<command> <args>` output, or None when the command is missing."""
    path = shutil.which(str(command))
    if not path:
        return None
    try:
        out = subprocess.run([path, *args], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(pattern, out.stdout + out.stderr)
    return match.group(1) if match else None


def kind_version(kind='kind'):
    return command_version(kind, r'kind v(\S+)')


def kubectl_version(kubectl='kubectl'):
    path = shutil.which(str(kubectl))
    if not path:
        return None
    out = subprocess.run([path, 'version', '--client', '-o', 'json'], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(out.stdout)['clientVersion']['gitVersion'].removeprefix('v')
    except (ValueError, KeyError):
        return None


def tools_record(kind='kind', kubectl='kubectl'):
    """What a release manifest records about the Kubernetes tools actually used."""
    def located(name):
        return shutil.which(str(name))
    return {
        'kind': {'path': located(kind), 'version': kind_version(kind), 'qualified_package': KIND_PACKAGE},
        'kubectl': {'path': located(kubectl), 'version': kubectl_version(kubectl), 'qualified_package': KUBECTL_PACKAGE},
        'kind_node_image': KIND_NODE_IMAGE,
        'helm': helm_record(),
    }


def helm_record():
    import helm_tool
    path = helm_tool.cached()
    return {'path': str(path), 'version': helm_tool.VERSION,
            'pinned': path.exists() and helm_tool.sha256(path) == helm_tool.BINARY_SHA256[helm_tool.host_arch()]}


def host_arch():
    return {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]


def fetch_kube_tool(name, arch=None):
    """Path of the pinned kind or kubectl release binary in .cache/bin, downloaded and checked on first use."""
    arch = arch or host_arch()
    release = KUBE_RELEASES[name]
    path = ROOT/'.cache/bin'/f'{name}-{release["version"]}-linux-{arch}'
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(release['url'].format(version=release['version'], arch=arch), timeout=300) as response:
            data = response.read(256*1024*1024)
        assert hashlib.sha256(data).hexdigest() == release['sha256'][arch], f'{name} download SHA-256 differs from the pin'
        partial = path.with_suffix('.partial')
        partial.write_bytes(data)
        partial.chmod(0o755)
        partial.replace(path)
    with path.open('rb') as file:
        assert hashlib.file_digest(file, 'sha256').hexdigest() == release['sha256'][arch], f'cached {name} differs from the pin: {path}'
    return path


def java_environment(major=BUILD_JDK, environ=None):
    """Environment for a Java child: the pinned JDK first on PATH, no inherited JAVA tool options."""
    environ = dict(os.environ if environ is None else environ)
    for name in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH'):
        environ.pop(name, None)
    home = java_home(major, environ)
    environ['JAVA_HOME'] = str(home)
    environ['PATH'] = str(home/'bin') + os.pathsep + environ.get('PATH', '')
    return environ


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('command', choices=['fetch-kube'])
    parser.parse_args()
    for name in KUBE_RELEASES:
        print(name, fetch_kube_tool(name))


if __name__ == '__main__':
    main()
