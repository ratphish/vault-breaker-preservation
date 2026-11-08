"""Compare corrected static registry-pointer candidates with synthetic runtime keys."""
import argparse
import collections
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('index', type=Path)
parser.add_argument('runtime_map', type=Path)
args = parser.parse_args()
runtime = {}
with args.runtime_map.open(encoding='utf-8-sig') as stream:
    for line in stream:
        row = json.loads(line)
        key = int(row['key'], 16)
        if key in runtime:
            raise ValueError('duplicate runtime key')
        runtime[key] = row
counts, failures, extras = collections.Counter(), [], []
seen = set()
with args.index.open(encoding='utf-8-sig') as stream:
    for line in stream:
        row = json.loads(line)
        tag = int(row['tag'], 16)
        if tag in seen or tag not in runtime:
            raise ValueError('duplicate or missing runtime tag')
        seen.add(tag)
        actual = runtime[tag]['object'].lower()
        matches = [candidate for candidate in row['registry_candidates'] if candidate['pointer'].lower() == actual]
        counts['rows'] += 1
        counts['candidate_pairs'] += len(row['registry_candidates'])
        counts['rows_with_runtime_match'] += bool(matches)
        if not matches and len(failures) < 20:
            failures.append({'tag': row['tag'], 'runtime_object': actual, 'candidates': row['registry_candidates']})
        if len(row['registry_candidates']) != 1 and len(extras) < 20:
            extras.append({'tag': row['tag'], 'candidate_count': len(row['registry_candidates']), 'matching_count': len(matches)})
if len(seen) != len(runtime):
    raise ValueError('runtime and index tag counts differ')
if counts['rows_with_runtime_match'] != len(runtime):
    raise ValueError(f"{len(runtime) - counts['rows_with_runtime_match']} tags have no matching runtime object; examples: {failures}")
print(json.dumps({'counts': dict(counts), 'missing_runtime_match_examples': failures,
                  'multiple_candidate_examples': extras,
                  'scope': 'matching synthetic runtime snapshot and transformed input only'}, indent=2))
