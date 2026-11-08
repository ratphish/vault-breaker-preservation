"""Private, digest-checked Unicorn snapshots for the synthetic loader model.

Snapshots contain game-derived memory and must stay outside the repository.
They are specific to the same Unicorn build and machine architecture.
"""
import bisect
import ctypes
import hashlib
import json
from pathlib import Path
from unicorn import UC_PROT_ALL

CHUNK = 8 * 1024 * 1024


def save(uc, directory, state, recent, identity):
    root = Path(directory).resolve()
    if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]) or not root.parent.is_dir():
        raise ValueError('checkpoint must be a new private directory')
    root.mkdir()
    regions = []
    for i, (start, end, permissions) in enumerate(uc.mem_regions()):
        size = end - start + 1
        filename = f'region-{i:03d}.bin'
        digest = hashlib.sha256()
        with (root / filename).open('xb') as out:
            for offset in range(0, size, CHUNK):
                data = bytes(uc.mem_read(start + offset, min(CHUNK, size - offset)))
                out.write(data)
                digest.update(data)
        regions.append({'start': start, 'size': size, 'permissions': permissions,
                        'file': filename, 'sha256': digest.hexdigest()})
    context = bytes(uc.context_save())
    (root / 'context.bin').write_bytes(context)
    manifest = {'version': 1, 'identity': identity, 'regions': regions,
                'context_sha256': hashlib.sha256(context).hexdigest(),
                'context_size': len(context), 'state': state, 'recent': list(recent)}
    (root / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return {'path': str(root), 'regions': len(regions), 'bytes': sum(x['size'] for x in regions)}


def restore(uc, directory, identity):
    root = Path(directory).resolve()
    if root.is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError('checkpoint must be private')
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['version'] != 1 or manifest['identity'] != identity:
        raise ValueError('checkpoint identity mismatch')
    current = sorted((lo, hi + 1) for lo, hi, _ in uc.mem_regions())
    starts = [lo for lo, _ in current]
    for item in manifest['regions']:
        start, size = item['start'], item['size']
        if start % 4096 or size <= 0 or size % 4096 or Path(item['file']).name != item['file']:
            raise ValueError('invalid checkpoint region')
        end = start + size
        pos = start
        while pos < end:
            index = bisect.bisect_right(starts, pos) - 1
            if index >= 0 and pos < current[index][1]:
                pos = min(end, current[index][1])
                continue
            next_start = starts[index + 1] if index + 1 < len(starts) else end
            stop = min(end, next_start)
            uc.mem_map(pos, stop - pos, item['permissions'])
            starts.insert(index + 1, pos)
            current.insert(index + 1, (pos, stop))
            pos = stop
        digest = hashlib.sha256()
        with (root / item['file']).open('rb') as src:
            for offset in range(0, size, CHUNK):
                expected = min(CHUNK, size - offset)
                data = src.read(expected)
                if len(data) != expected:
                    raise ValueError('short checkpoint region')
                digest.update(data)
                uc.mem_write(start + offset, data)
            if src.read(1) or digest.hexdigest() != item['sha256']:
                raise ValueError('checkpoint region digest mismatch')
    context = (root / 'context.bin').read_bytes()
    if len(context) != manifest['context_size'] or hashlib.sha256(context).hexdigest() != manifest['context_sha256']:
        raise ValueError('checkpoint context digest mismatch')
    fresh = uc.context_save()
    if fresh.size != len(context):
        raise ValueError('incompatible Unicorn context')
    ctypes.memmove(fresh.context, context, len(context))
    uc.context_restore(fresh)
    return manifest['state'], manifest['recent']
