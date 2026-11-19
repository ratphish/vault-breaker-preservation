"""PE parsing controls only; no process handles, network, or game launch."""
import struct

import pytest

from capture_http_state import PEImports


def fixture_pe(path):
    data = bytearray(0x1200)
    data[:2] = b'MZ'; struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x86, 1)
    struct.pack_into('<H', data, 0x94, 0xf0)
    struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<II', data, 0x98 + 120, 0x1000, 40)
    struct.pack_into('<III', data, 0x188 + 12, 0x1000, 0x1000, 0x200)
    struct.pack_into('<IIIII', data, 0x200, 0x1200, 0, 0, 0x1100, 0x1300)
    data[0x300:0x30b] = b'WS2_32.dll\0'
    struct.pack_into('<QQQ', data, 0x400, (1 << 63) | 17, 0x1400, 0)
    data[0x602:0x60a] = b'connect\0'
    path.write_bytes(data)
    return data


def test_ordinal_is_kept_as_ordinal_and_iat_mapping_is_exact(tmp_path):
    path = tmp_path / 'fixture.exe'; fixture_pe(path)
    reader = PEImports(path)
    try:
        assert list(reader.rows()) == [
            {'dll': 'WS2_32.dll', 'symbol': '#17', 'iat_rva': 0x1300},
            {'dll': 'WS2_32.dll', 'symbol': 'connect', 'iat_rva': 0x1308}]
    finally: reader.close()


def test_truncated_import_data_is_rejected(tmp_path):
    path = tmp_path / 'fixture.exe'; data = fixture_pe(path)
    path.write_bytes(data[:0x210])
    reader = PEImports(path)
    try:
        with pytest.raises(ValueError, match='outside file'):
            list(reader.rows())
    finally: reader.close()


def test_no_import_directory_is_empty(tmp_path):
    path = tmp_path / 'fixture.exe'; data = fixture_pe(path)
    struct.pack_into('<II', data, 0x98 + 120, 0, 0); path.write_bytes(data)
    reader = PEImports(path)
    try: assert list(reader.rows()) == []
    finally: reader.close()


def test_malformed_header_rejected(tmp_path):
    path = tmp_path / 'fixture.exe'; path.write_bytes(b'not a PE')
    with pytest.raises(ValueError): PEImports(path)
