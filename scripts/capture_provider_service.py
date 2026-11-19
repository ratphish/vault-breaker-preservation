"""Take one read-only snapshot of the preserved client's provider service."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from observe_settings_startup import ANALYSIS, GAME, PINNED_EXE_SHA256, read_settings_owner
from capture_http_state import Process
from readonly_reference import decode_reference


def capture(pid):
    proc = Process(pid)
    try:
        modules = proc.modules()
        image = modules[0]
        if Path(image['path']) != GAME:
            raise ValueError('Expected the preserved Marathon executable')
        with GAME.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != PINNED_EXE_SHA256:
                raise ValueError('Preserved build hash differs')
        base = int(image['base'], 16)

        def read_int(address, size):
            return int.from_bytes(proc.read(address, size), 'little')

        ref_address = base + 0x3658D650
        ref = proc.read(ref_address, 24)
        provider, _ = decode_reference(proc.read, base, image['size'], ref, 0x3658D650)
        state = read_int(provider + 12, 4)
        service_slot = base + 0x3658AEE0
        service = read_int(service_slot, 8)
        table = read_int(service, 8) if service else 0
        method = read_int(table + 0x18, 8) if table else 0
        def module_owner(address):
            for module in modules:
                start = int(module['base'], 16)
                if start <= address < start + module['size']:
                    return dict(path=module['path'], rva=hex(address - start))
            return None

        def slot38_chain():
            receiver = read_int(base + 0x365c0148, 8)
            vtable = read_int(receiver, 8) if receiver else 0
            target = read_int(vtable + 0x38, 8) if vtable else 0
            return receiver, vtable, target

        def ping_inputs(chain):
            receiver, table, target = chain
            if target != base + 0x32b09dd0:
                return None
            clock = read_int(base + 0x3928e638, 8)
            stamp = read_int(base + 0x3928dc20, 8)
            return dict(status=read_int(base + 0x352f1298, 4),
                        measurement_timestamp=stamp, last_clock_sample=clock,
                        age_at_last_clock_seconds=(clock - stamp) / 1_000_000 if stamp else None,
                        init_byte=read_int(receiver + 0x10, 1),
                        init_method=module_owner(read_int(table + 0x128, 8)))

        owner = module_owner(method)
        selector_known = (method == base + 0x2ff36bb0 and
                          proc.read(base + 0x2ef4d000, 7) == bytes.fromhex('8b050af78e07c3'))
        selector_before = read_int(base + 0x3683c710, 4) if selector_known else None
        def next_check():
            if not selector_known:
                return None
            fields = proc.read(base + 0x3659db08, 8)
            return dict(byte_10498=fields[0], byte_10499=fields[1],
                        signed_1049c=int.from_bytes(fields[4:8], 'little', signed=True),
                        dword_296a0=read_int(base + 0x365b6d10, 4))

        next_before = next_check()
        revision_address = base + 0x3928DA20
        revision_before = read_int(revision_address, 4)
        slot38_before = slot38_chain()
        ping_before = ping_inputs(slot38_before)
        settings = read_settings_owner(proc, base)
        slot38_after = slot38_chain()
        ping_after = ping_inputs(slot38_after)
        revision_after = read_int(revision_address, 4)
        next_after = next_check()
        selector_after = read_int(base + 0x3683c710, 4) if selector_known else None
        stable = (read_int(service_slot, 8) == service
                  and (not service or read_int(service, 8) == table)
                  and (not table or read_int(table + 0x18, 8) == method))
        return dict(pid=pid, utc=datetime.now(timezone.utc).isoformat(),
                    service=hex(service), vtable=hex(table), method=hex(method),
                    method_owner=owner, service_chain_stable=stable,
                    ping_before=ping_before, ping_after=ping_after,
                    slot38=dict(receiver=hex(slot38_before[0]), vtable=hex(slot38_before[1]),
                                method=hex(slot38_before[2]), method_owner=module_owner(slot38_before[2]),
                                stable=slot38_before == slot38_after),
                    selector_before=selector_before, selector_after=selector_after,
                    next_check_before=next_before, next_check_after=next_after,
                    active_sdr_revision_before=revision_before,
                    active_sdr_revision_after=revision_after,
                    provider_before=state, provider_after=read_int(provider + 12, 4),
                    same_provider_reference=proc.read(ref_address, 24) == ref,
                    settings_owner=settings)
    finally:
        proc.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', required=True, type=int)
    args = parser.parse_args()
    result = capture(args.pid)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    path = ANALYSIS / f'provider-service-{args.pid}-{stamp}.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))
    print('Saved to', path)
