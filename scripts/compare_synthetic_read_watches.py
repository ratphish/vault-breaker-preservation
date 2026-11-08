"""Compare guest read-watch events between two private deterministic replays."""
import argparse
import collections
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('left', type=Path)
parser.add_argument('right', type=Path)
args = parser.parse_args()


def load(path):
    raw = path.read_bytes()
    trace = json.loads(raw.decode('utf-8-sig'))
    events = collections.Counter((x['object'], x['address'], x['size'], x['rip'], x['instruction'])
                                 for x in trace.get('additional_registry_reads', []))
    return hashlib.sha256(raw).hexdigest(), trace['stop'], events


lh, ls, left = load(args.left)
rh, rs, right = load(args.right)
missing, added = left - right, right - left
result = {'left_sha256': lh, 'right_sha256': rh, 'left_stop': ls, 'right_stop': rs,
          'left_events': sum(left.values()), 'right_events': sum(right.values()),
          'missing': sum(missing.values()), 'added': sum(added.values()),
          'equal': ls == rs and not missing and not added,
          'scope': 'event tuple and stop equality only; not complete machine-state equivalence'}
print(json.dumps(result, indent=2))
if not result['equal']:
    raise SystemExit(1)
