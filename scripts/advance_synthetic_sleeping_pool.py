"""Advance a bounded synthetic parent/worker schedule until a non-sleep stop.

Each worker actually runs to its first modeled Sleep before the parent context is
restored. The worker stack/CPU remain in its private checkpoint. This does not
provide real concurrency, independent TLS, thread attach, or timer wakeups.
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('parent', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--steps', type=int, default=8)
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = args.output.resolve()
if not out.is_dir() or out.is_relative_to(root) or not 1 <= args.steps <= 16:
    raise ValueError('output must be an existing private directory; steps must be 1..16')
analysis = Path(r'D:\Marathon-preservation\analysis')
common = [sys.executable, str(root / 'scripts/emulate_tls_callback.py'),
          r'D:\Marathon-preservation\build-26136895-20261031\Marathon.exe',
          '--index', '0', '--count', '10000000', '--timeout-ms', '180000', '--fixed-tsc', '--eager-image',
          '--stub-veh', '--model-veh-exceptions', '--loader-sequence', '--entry-after-loader', '--follow-thread',
          '--resume-parent', '--stub-worker-wait', '--follow-second-thread', '--resume-second-parent',
          '--stub-worker-cache', '--stub-crt-clock', '--model-teb-stack', '--model-crt-initterm-e',
          '--stub-virtualprotect', '--trace-aes', '--accelerate-worker-aes', '--native-aes-every', '4096',
          '--inline-dispatch', '--stub-parent-virtualprotect', '--parent-aes-reference',
          str(analysis / 'synthetic-text-table-complete.json'), '--allow-parent-data', '--allow-parent-vmp',
          '--watch-registry', str(root / 'research/vmp-slot-and-backing-watchpoints.json'),
          '--watch-additional-registry', str(root / 'research/runtime-shared-child-watchpoints.json')]


def run(label, checkpoint, options):
    snapshot, log = out / f'{label}-checkpoint', out / f'{label}.json'
    if snapshot.exists() or log.exists():
        raise ValueError(f'refusing to overwrite {label}')
    with log.open('x', encoding='utf-8') as stream:
        result = subprocess.run(common + ['--resume-checkpoint', str(checkpoint)] + options +
                                ['--save-at-stop', str(snapshot)], cwd=root, stdout=stream, check=False)
    if result.returncode:
        raise RuntimeError(f'{label} exited {result.returncode}')
    trace = json.loads(log.read_text(encoding='utf-8-sig'))
    print(json.dumps({'stage': label, 'stop': trace['stop'], 'checkpoint': trace.get('saved_stop_checkpoint')}), flush=True)
    return trace, snapshot


parent = args.parent.resolve()
for i in range(1, args.steps + 1):
    worker, worker_snapshot = run(f'worker-{i:02}', parent, ['--trace-suspended-worker'])
    if worker['stop'].get('kind') != 'synthetic_worker_sleep' or not worker.get('saved_stop_checkpoint'):
        break
    parent_trace, next_parent = run(f'parent-{i:02}', worker_snapshot, ['--resume-parent-context', str(parent)])
    if not parent_trace.get('saved_stop_checkpoint'):
        break
    parent = next_parent
    if parent_trace['stop'].get('import', '').lower() != 'kernel32.dll!resumethread':
        break
