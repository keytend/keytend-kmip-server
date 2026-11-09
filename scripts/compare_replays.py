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

"""Compare two Profiles 4.1 variation replay reports case for case.

Used to show that the linux/arm64 image answers every trace as the linux/amd64
image does. Each case is keyed by version and trace; its status, failure detail,
category, exchange counters and recorded variations must match. Decoded
responses are not compared (they carry timestamps and generated identifiers).
Exits 1 when any case differs.
"""
import argparse
import hashlib
import json
import pathlib

FIELDS = ['status', 'detail', 'category', 'completed_exchanges', 'failed_exchange', 'variations', 'transformations']


def cases(report):
    result = {}
    for case in report['cases']:
        key = f"{case['version']} {case['case']}"
        assert key not in result, 'duplicate case '+key
        result[key] = {field: case.get(field) for field in FIELDS}
    return result


def compare(baseline, candidate):
    old, new = cases(baseline), cases(candidate)
    differences = []
    for key in sorted(set(old) | set(new)):
        if key not in old or key not in new:
            differences.append(dict(case=key, baseline=old.get(key), candidate=new.get(key)))
            continue
        fields = [field for field in FIELDS if old[key][field] != new[key][field]]
        if fields:
            differences.append(dict(case=key, fields=fields, baseline={f: old[key][f] for f in fields}, candidate={f: new[key][f] for f in fields}))
    return dict(identical=not differences and baseline['summary'] == candidate['summary'], cases=len(new), compared_fields=FIELDS,
                baseline_summary=baseline['summary'], candidate_summary=candidate['summary'], differences=differences)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('baseline', type=pathlib.Path)
    parser.add_argument('candidate', type=pathlib.Path)
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    result = compare(json.loads(args.baseline.read_text()), json.loads(args.candidate.read_text()))
    result.update(baseline=str(args.baseline), baseline_sha256=hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
                  candidate=str(args.candidate), candidate_sha256=hashlib.sha256(args.candidate.read_bytes()).hexdigest())
    if args.output:
        args.output.write_text(json.dumps(result, indent=1)+'\n')
    print(json.dumps({k: result[k] for k in ['identical', 'cases', 'baseline_summary', 'candidate_summary']}), len(result['differences']), 'differences')
    if not result['identical']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
