"""Validate the observed loader-name hash and comparison in a private trace."""
import argparse
import json
from pathlib import Path

SEED = 0xb5f17e87f48f6943
PRIME = 0x100000001b3
MASK = (1 << 64) - 1


def candidate(name):
    value = SEED
    for byte in name.lower().encode('utf-16le'):
        value = ((value * PRIME) ^ byte) & MASK
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('private_trace', type=Path)
    args = parser.parse_args()
    trace = json.loads(args.private_trace.read_text(encoding='utf-8-sig'))
    samples = [row for row in trace['range_events'] if row['pc'] == '0x171412716']
    names = ['Marathon.exe', 'ntdll.dll', 'kernel32.dll', 'kernelbase.dll']
    names += trace['synthetic_loaded_module_images']['names']
    if len(samples) != len(names):
        raise ValueError('unexpected module comparison count')
    results = []
    for name, sample in zip(names, samples):
        calculated = candidate(name)
        observed = int(sample['regs']['rcx'], 16)
        if calculated != observed:
            raise ValueError('candidate hash mismatch for ' + name)
        final = (calculated * PRIME) & MASK  # first byte of the UTF-16 NUL terminator
        target = int(sample['regs']['rax'], 16)
        difference = (final - target) & MASK
        actual = int(sample['regs']['eflags'], 16)
        expected = ((final < target) | ((difference & 255).bit_count() % 2 == 0) << 2
                    | (difference == 0) << 6 | (difference >> 63) << 7
                    | ((((final ^ target) & (final ^ difference)) >> 63) & 1) << 11)
        if actual & 0x8c5 != expected:
            raise ValueError('comparison flags mismatch for ' + name)
        results.append({'module': name, 'hash_before_terminator': f'{calculated:016x}',
                        'compared_hash': f'{final:016x}'})
    values = sorted({row['regs']['rax'] for row in samples})
    print(json.dumps({'seed': f'{SEED:016x}', 'algorithm': 'FNV-1 over lowercase UTF-16LE bytes and first NUL byte',
                      'verified_samples': len(results), 'modules': results,
                      'comparison_targets': values, 'crypt32_candidate_hash': f'{candidate("crypt32.dll") * PRIME & MASK:016x}',
                      'limitation': 'Comparison verified in a synthetic execution; real-runtime reachability unverified.'}, indent=2))


if __name__ == '__main__':
    main()
