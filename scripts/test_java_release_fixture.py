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

"""Verify fresh release extraction and rejection of changed ZIP/JAR bytes."""
import pathlib,shutil,tempfile
import keytend_kmip_release as fixture

def fresh():
    fixture.release.cache_clear()  # release() caches its result per process
    return fixture.release()

def rejected(action):
    try:action()
    except AssertionError:return
    raise AssertionError('modified release was accepted')

def main():
    fixture.release();original=fixture.CACHE
    try:
        with tempfile.TemporaryDirectory(prefix='keytend-release-extract-') as directory:
            fixture.CACHE=pathlib.Path(directory)
            archive=fixture.CACHE/fixture.PIN['asset']
            for name in [archive.name,archive.name+'.sha256',archive.name+'.asc','SHA256SUMS','SHA256SUMS.asc']:shutil.copyfile(original/name,fixture.CACHE/name)
            root,jars,evidence=fresh()
            for name in ['mvnw','integration/generate-certs.sh','integration/catalog/generate-pki.sh']:
                assert (root/name).stat().st_mode&0o111,'ZIP executable modes were lost'
            jar=jars[0];jar.write_bytes(jar.read_bytes()+b'changed')
            rejected(fresh)
            jar.unlink()
            shutil.copyfile(original/fixture.TOP/jar.relative_to(root),jar)
            assert fresh()[2]==evidence
            data=bytearray(archive.read_bytes());data[-1]^=1;archive.write_bytes(data)
            rejected(fresh)
    finally:fixture.CACHE=original;fixture.release.cache_clear()
    print('PASS fresh extraction preserves executable modes; changed JAR and ZIP are rejected')
if __name__=='__main__':main()
