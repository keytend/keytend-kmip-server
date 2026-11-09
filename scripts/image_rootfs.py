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

"""Read the final filesystem of an exported Docker archive without running the image.

Archive contents are treated as data: nothing is extracted to disk or executed.
"""
import hashlib
import json
import posixpath
import tarfile


class Rootfs:
    def __init__(self, archive):
        self.entries = {}
        with tarfile.open(archive) as outer:
            manifest = json.load(outer.extractfile('manifest.json'))
            assert len(manifest) == 1, 'expected one image in the archive'
            self.config_id = manifest[0]['Config'].removesuffix('.json').removeprefix('sha256:')
            self.config = json.load(outer.extractfile(manifest[0]['Config']))
            self.layers = manifest[0]['Layers']
            for layer in self.layers:
                with tarfile.open(fileobj=outer.extractfile(layer)) as tar:
                    for info in tar:
                        name = posixpath.normpath(info.name)
                        if name == '.':
                            continue
                        path = '/'+name.lstrip('/')
                        directory, name = posixpath.split(path)
                        if name == '.wh..wh..opq':
                            self.entries = {p: e for p, e in self.entries.items() if not p.startswith(directory.rstrip('/')+'/')}
                            continue
                        if name.startswith('.wh.'):
                            target = posixpath.join(directory, name[4:])
                            self.entries = {p: e for p, e in self.entries.items() if p != target and not p.startswith(target+'/')}
                            continue
                        if info.islnk():
                            data = self.entries['/'+posixpath.normpath(info.linkname).lstrip('/')][1]
                        else:
                            data = tar.extractfile(info).read() if info.isreg() else None
                        self.entries[path] = (info, data)

    def resolve(self, path, depth=0):
        """Resolve symlinks in every path component inside the image root."""
        assert depth < 40, 'symlink loop: '+path
        parts = [part for part in path.split('/') if part]
        current = '/'
        for index, part in enumerate(parts):
            candidate = posixpath.join(current, part)
            entry = self.entries.get(candidate)
            if entry and entry[0].issym():
                link = entry[0].linkname
                base = '/' if link.startswith('/') else current
                rest = '/'.join(parts[index+1:])
                return self.resolve(posixpath.normpath(posixpath.join(base, link, rest)), depth+1)
            current = candidate
        return current

    def read(self, path):
        info, data = self.entries[self.resolve(path)]
        assert info.isreg() or info.islnk(), path+' is not a regular file'
        return data

    def exists(self, path):
        return self.resolve(path) in self.entries

    def sha256(self, path):
        return hashlib.sha256(self.read(path)).hexdigest()


RPMDB = '/var/lib/rpm/rpmdb.sqlite'
# RPM header tags (rpm/rpmtag.h) read by the image tooling: the SBOM and provenance package
# fields, and each file's path, SHA-256 digest, flags and install state.
RPM_TAGS = {1000: 'name', 1001: 'version', 1002: 'release', 1003: 'epoch', 1014: 'license', 1022: 'arch',
    273: 'sha256header', 1044: 'sourcerpm', 1029: 'filestates', 1035: 'filedigests', 1037: 'fileflags',
    1116: 'dirindexes', 1117: 'basenames', 1118: 'dirnames'}
RPMFILE_LICENSE = 128
RPMFILE_STATE_NORMAL = 0


def elf_info(data):
    """(e_machine, PT_INTERP path or None) of a little-endian ELF64 executable."""
    import struct
    assert data[:4] == b'\x7fELF' and data[4] == 2 and data[5] == 1, 'not a little-endian ELF64 file'
    machine, = struct.unpack_from('<H', data, 18)
    phoff, = struct.unpack_from('<Q', data, 32)
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    for index in range(phnum):
        kind, = struct.unpack_from('<I', data, phoff+index*phentsize)
        if kind == 3:  # PT_INTERP
            offset, = struct.unpack_from('<Q', data, phoff+index*phentsize+8)
            size, = struct.unpack_from('<Q', data, phoff+index*phentsize+32)
            return machine, data[offset:offset+size].rstrip(b'\0').decode()
    return machine, None


def rpm_header(blob):
    """Decode one RPM header blob as stored in the sqlite rpmdb (no lead or magic)."""
    import struct
    count, size = struct.unpack('>II', blob[:8])
    entries, store = blob[8:8+16*count], blob[8+16*count:8+16*count+size]
    assert len(store) == size, 'truncated rpm header'
    fields = {}
    for index in range(count):
        tag, kind, offset, n = struct.unpack('>IIiI', entries[16*index:16*index+16])
        if tag not in RPM_TAGS:
            continue
        if kind in (6, 8, 9):  # STRING, STRING_ARRAY, I18NSTRING
            values = store[offset:].split(b'\0')[:1 if kind == 6 else n]
            value = [v.decode('utf-8', 'replace') for v in values]
            value = value[0] if kind == 6 else value
        elif kind in (1, 2):  # CHAR, INT8
            value = list(struct.unpack(f'>{n}b', store[offset:offset+n]))
        elif kind in (3, 4, 5):  # INT16, INT32, INT64 (unsigned)
            code = {3: 'H', 4: 'I', 5: 'Q'}[kind]
            value = list(struct.unpack(f'>{n}{code}', store[offset:offset+n*struct.calcsize(code)]))
        elif kind == 7:
            value = store[offset:offset+n]
        else:
            raise AssertionError(f'unsupported rpm header type {kind} for tag {tag}')
        fields[RPM_TAGS[tag]] = value
    return fields


def rpm_packages(data):
    """Parse an rpmdb.sqlite image into {name: header fields with a 'files' list}.

    The database comes from our own exported image; it is opened read-only and
    immutable from a private temporary copy.
    """
    import os
    import sqlite3
    import tempfile
    packages = {}
    with tempfile.TemporaryDirectory(prefix='keytend-rpmdb-') as directory:
        path = os.path.join(directory, 'rpmdb.sqlite')
        with open(path, 'wb') as file:
            file.write(data)
        connection = sqlite3.connect(f'file:{path}?mode=ro&immutable=1', uri=True)
        try:
            rows = connection.execute('SELECT blob FROM Packages ORDER BY hnum').fetchall()
        finally:
            connection.close()
    for (blob,) in rows:
        fields = rpm_header(blob)
        if fields['name'] == 'gpg-pubkey':
            continue  # imported signing keys are database pseudo-packages, not shipped software
        assert fields['name'] not in packages, 'duplicate rpm package '+fields['name']
        names = fields.get('basenames', [])
        def column(key, default):
            value = fields.get(key)
            return value if value is not None else [default]*len(names)
        fields['files'] = [dict(path=posixpath.join(fields['dirnames'][d], b), digest=g, flags=f, state=s)
            for d, b, g, f, s in zip(fields.get('dirindexes', []), names, column('filedigests', ''), column('fileflags', 0), column('filestates', 0))]
        fields['evr'] = (f"{fields['epoch'][0]}:" if fields.get('epoch') else '')+f"{fields['version']}-{fields['release']}"
        packages[fields['name']] = fields
    return packages
