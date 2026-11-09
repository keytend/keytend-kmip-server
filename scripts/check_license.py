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

"""Check original project sources for the Apache license appendix notice.

JSON and generated dependency lock files use adjacent .license notices to retain
their native format. External caches and build/test artifacts are not sources.
Third-party files committed unchanged (THIRD_PARTY, listed in NOTICE) keep their own
notices and must not carry this project's copyright.
"""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER = '''Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''
# Third-party files kept with their own license notice: path -> text that must be present
# (None: the generated file has no notice of its own). See NOTICE.
ASF_NOTICE = 'Licensed to the Apache Software Foundation (ASF) under one'
THIRD_PARTY = {}


def source_header(path):
    """Render the appendix notice using the source format's comment syntax."""
    path = pathlib.Path(path)
    if path.suffix in {'.md', '.svg', '.html', '.xml'}:
        return '<!--\n' + HEADER + '-->\n\n'
    if path.suffix == '.c':
        return '/*\n' + HEADER + '*/\n\n'
    if path.parent.name == 'templates' and (path.parent.parent/'Chart.yaml').exists() or \
            path.parent.name == 'tests' and (path.parent.parent.parent/'Chart.yaml').exists():
        # Helm chart templates: a template comment keeps the notice out of rendered manifests and NOTES.
        return '{{- /*\n' + HEADER + '*/ -}}\n'
    prefix = '// ' if path.suffix in {'.rs', '.go', '.mod', '.java'} else '# '
    return '\n'.join(prefix + line if line else prefix.rstrip() for line in HEADER.splitlines()) + '\n\n'


def source_paths():
    listing = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT
    ).decode().split('\0')
    return [ROOT / name for name in sorted(set(listing)) if name and (ROOT / name).is_file()]


def main():
    failures = []
    checked = 0
    for path in source_paths():
        name = path.relative_to(ROOT).as_posix()
        if name in {'LICENSE', 'NOTICE'} or name.endswith('.license'):
            continue
        if name in THIRD_PARTY:
            text = path.read_text()
            if HEADER.splitlines()[0] in text or (THIRD_PARTY[name] and THIRD_PARTY[name] not in text):
                failures.append(name + ' (third-party: keep its own notice, not this project\'s)')
            continue
        checked += 1
        if path.suffix in {'.json', '.sum', '.asc'} or path.name == 'Cargo.lock':
            notice = path.with_name(path.name + '.license')
            valid = notice.exists() and notice.read_text().startswith(HEADER)
        else:
            text = path.read_text()
            if text.startswith(('#!', '<?xml')):
                text = text.split('\n', 1)[1]
            valid = text.startswith(source_header(path))
        if not valid:
            failures.append(name)
    if failures:
        raise SystemExit('Missing or incorrect license notices:\n' + '\n'.join(failures))
    print(f'PASS: Apache-2.0 notices on all {checked} original source/metadata files')


if __name__ == '__main__':
    main()
