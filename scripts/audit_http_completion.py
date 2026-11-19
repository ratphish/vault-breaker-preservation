"""Audit saved read-only observations without accessing a running process.

The offsets below are pinned to the captured Marathon build and its native
WinHTTP callback code. This proves a particular wrapper completed, not that
the higher-level SignOn consumer or bootflow task accepted its response.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from urllib.parse import urlsplit

from marathon_protobuf import ProtobufReader

PINNED_EXE_SHA256 = 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'


def checked_range(row):
    data = bytes.fromhex(row['hex'])
    if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
        raise ValueError('saved range size or SHA-256 mismatch')
    return int(row['address'], 16), data


def load_result(directory, number):
    path = directory / f'result-{number:06d}.json'
    raw = path.read_bytes()
    report = json.loads(raw)
    if report['status'] != 'complete':
        raise ValueError(f'incomplete reader result {number}')
    rows = [checked_range(row) for row in report['ranges']]
    return report['pid'], rows, {'path': str(path.resolve()), 'sha256': hashlib.sha256(raw).hexdigest()}


def audit(directory):
    metadata = json.loads((directory / 'session.json').read_text())
    if metadata['executable_sha256'] != PINNED_EXE_SHA256:
        raise ValueError('unrecognized executable build')
    observations = {}
    sources = []
    for number in [1, 5, 7, 8]:
        pid, rows, source = load_result(directory, number)
        if pid != metadata['pid']:
            raise ValueError('reader result PID differs from session')
        observations[number] = rows
        sources.append(source)

    # Bind the candidate context from the saved WinHTTP record to the native
    # wrapper's independently known request-handle field; do not trust an OS
    # private offset alone as proof of ownership.
    handle, handle_record = observations[5][0]
    context = struct.unpack_from('<Q', handle_record, 0x40)[0]
    first_address, first_identity = observations[7][0]
    fields_address, fields = observations[7][1]
    if first_address != context or fields_address != context + 0x420:
        raise ValueError('wrapper addresses differ from candidate context')
    if struct.unpack_from('<Q', first_identity, 0x10)[0] != handle:
        raise ValueError('native wrapper request handle differs')

    url_address, url_bytes = observations[8][0]
    body_address, body = observations[8][1]
    repeat_address, repeat_identity = observations[8][2]
    state_address, repeat_fields = observations[8][3]
    if (url_address != context + 0x18 or repeat_address != context or
            state_address != context + 0x450):
        raise ValueError('repeated snapshot addresses differ')
    if first_identity[:24] != repeat_identity[:24]:
        raise ValueError('wrapper identity changed between snapshots')
    if fields[0x30:0x54] != repeat_fields:
        raise ValueError('native state/counters changed between snapshots')
    url = url_bytes.split(b'\0', 1)[0].decode('utf-8', 'strict')
    route = urlsplit(url)
    if route.path != '/SignOn' or route.scheme not in ['http', 'https'] or not route.hostname:
        raise ValueError('wrapper route is not SignOn')

    state, adjacent_status = struct.unpack_from('<II', repeat_fields)
    received = struct.unpack_from('<Q', repeat_fields, 0x18)[0]
    last_chunk = struct.unpack_from('<I', repeat_fields, 0x20)[0]
    destination = struct.unpack_from('<Q', fields, 0x18)[0]
    capacity = struct.unpack_from('<Q', fields, 0x20)[0]
    if body_address != destination or not len(body) == received <= capacity:
        raise ValueError('received bytes do not match native destination/counter')

    base = int(metadata['image_base'], 16)
    eof_instruction = bytes.fromhex('c7805004000002000000')
    eof_verified = any(address <= base + 0x06333c1f and
                       data[base + 0x06333c1f - address:base + 0x06333c1f - address + 10] == eof_instruction
                       for address, data in observations[1])
    if not eof_verified:
        raise ValueError('fresh native EOF state-2 store is missing or differs')
    if (state, adjacent_status, last_chunk) != (2, 200, 0):
        raise ValueError('snapshot does not show the completed HTTP-200 wrapper with zero final chunk')

    wire_fields = ProtobufReader(body).parse()
    # Expose field identities/sizes, never session keys/token or body content.
    schema = [{'field': field, 'wire': wire, 'length': len(value)} if wire == 2 else
              {'field': field, 'wire': wire, 'value': value}
              for field, wire, value in wire_fields]
    return dict(pid=metadata['pid'], sources=sources, native_wrapper=hex(context),
                request_handle=hex(handle), route=f'{route.scheme}://{route.hostname}{route.path}',
                post_bytes=struct.unpack_from('<I', fields, 8)[0], native_state=state,
                adjacent_status_value=adjacent_status, last_chunk_field_value=last_chunk,
                received_bytes=received, reply_sha256=hashlib.sha256(body).hexdigest(),
                reply_wire_fields=schema, repeated_identity_and_counters_match=True,
                fresh_eof_store_verified=True, native_http_completion_verified=True,
                engine_result_publication_verified=False, signon_acceptance_verified=False,
                state8_root_cause_verified=False,
                limitations=['Saved sequential observations, not an atomic memory snapshot.',
                             'State 2 and the EOF store are observed separately; the callback event sequence itself was not logged.',
                             'The received protobuf is wire-decodable; semantic acceptance is unproved.',
                             'No consumer above the native wrapper or State 8 dependency is established.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.session_dir)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ['pid', 'native_state', 'received_bytes',
                                                  'native_http_completion_verified', 'state8_root_cause_verified']}))


if __name__ == '__main__':
    main()
