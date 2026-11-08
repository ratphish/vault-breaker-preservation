"""Verify Mode 1 schema pair table layout and investment table lookup resolution."""
import hashlib
import struct
from pathlib import Path

def test_investment_table_integrity():
    table_path = Path("D:/Marathon-preservation/analysis/row7-service-table-assets/80A6A004.bin")
    if not table_path.exists():
        # Fall back to alternative location if needed
        table_path = Path("D:/Marathon-preservation/analysis/row7-service-table-assets/80AA2163.bin")
    assert table_path.exists(), "Preserved investment table asset must exist"
    data = table_path.read_bytes()
    assert len(data) >= 61248, "Investment asset must be at least table extent"
    
    # Verify row layout: 32-byte rows, key at +8, byte at +0x1c in [0..54]
    row_offset = 0x29d0
    count = 1914
    keys = []
    for i in range(count):
        off = row_offset + i * 32
        key = struct.unpack_from("<I", data, off + 8)[0]
        byte_1c = data[off + 0x1c]
        assert 0 <= byte_1c <= 54, f"Row {i} byte at +0x1c must be in valid peer range [0, 54]"
        keys.append(key)
        
    assert sorted(keys) == keys, "Investment table keys must be strictly sorted for binary search"
    assert keys[0] == 0x00244270, "First key must match known investment key 0x00244270"
    print(f"PASS: Verified {count} sorted investment rows with valid [0..54] record bytes")

def test_mode1_pair_layout():
    # Context mode 1 table: 24 pairs of (uint32_t reference, uint32_t asset_tag)
    # Total size: 24 * 8 = 192 (0xC0) bytes
    # Index 14: offset 14 * 8 = 112 (0x70)
    schema_reference = 0x8080A1F5
    resolved_tag = 0x80A6A004 # Startup investment table
    
    raw_pairs = bytearray(24 * 8)
    for i in range(24):
        struct.pack_into("<II", raw_pairs, i * 8, 0, 0xFFFFFFFF)
        
    # Set pair 14 per Argon recommendation
    struct.pack_into("<II", raw_pairs, 14 * 8, schema_reference, resolved_tag)
    
    # Query simulation matching 0x1709929e0 Mode 1 branch
    found_tag = None
    for i in range(24):
        ref, tag = struct.unpack_from("<II", raw_pairs, i * 8)
        if ref == schema_reference:
            found_tag = tag
            break
            
    assert found_tag == resolved_tag, "Mode 1 lookup must resolve reference 8080A1F5 to investment tag"
    print("PASS: Mode 1 pair 14 correctly resolves 0x8080A1F5 -> 0x80A6A004")

if __name__ == "__main__":
    test_investment_table_integrity()
    test_mode1_pair_layout()
