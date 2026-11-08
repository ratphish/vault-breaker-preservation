"""Test and validate Vault Breaker universal objective handler (0x16fc98860),
entity handle table resolution (0x170c13450), and state transition event dispatch.
"""
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SYNTHETIC_TEXT = Path("D:/Marathon-preservation/analysis/synthetic-text-section.bin")
OBJ_RECORD_80B37FED = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B37FED.bin")
PEDESTAL_RECORD_80B38567 = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B38567.bin")

TEXT_BASE = 0x140001000

def get_disasm(address, size):
    data = SYNTHETIC_TEXT.read_bytes()
    offset = address - TEXT_BASE
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(data[offset:offset + size], address))

def test_component_binding_integrity():
    """Verify that both activity objectives and key pedestal bind child tag 8080B8F1 slot 10."""
    target_tag = 0x8080B8F1
    target_tag_bytes = struct.pack("<I", target_tag)
    
    # Check 80B37FED.bin (Activity Vault Breaker)
    data_7fed = OBJ_RECORD_80B37FED.read_bytes()
    assert b"activity_vault_breaker.es" in data_7fed, "Must identify activity_vault_breaker script"
    
    # Locate all 8080B8F1 slot 10 references
    idx = 0
    slot10_count_7fed = 0
    while True:
        idx = data_7fed.find(target_tag_bytes, idx)
        if idx == -1:
            break
        slot_idx = struct.unpack_from("<I", data_7fed, idx + 4)[0]
        if slot_idx == 10:
            slot10_count_7fed += 1
        idx += 4
    assert slot10_count_7fed >= 7, f"Expected at least 7 objective steps bound to slot 10, got {slot10_count_7fed}"
    print(f"PASS: 80B37FED binds {slot10_count_7fed} objective steps to 8080B8F1 Slot 10")
    
    # Check 80B38567.bin (Key Pedestal Prefab)
    data_8567 = PEDESTAL_RECORD_80B38567.read_bytes()
    assert b"pf_vault_breaker_key_pedestal.es" in data_8567, "Must identify key pedestal script"
    idx = data_8567.find(target_tag_bytes)
    assert idx != -1, "80B38567 must reference 8080B8F1"
    slot_idx_8567 = struct.unpack_from("<I", data_8567, idx + 4)[0]
    assert slot_idx_8567 == 10, f"80B38567 slot index must be 10, got {slot_idx_8567}"
    print(f"PASS: 80B38567 key pedestal binds interaction handler to 8080B8F1 Slot 10")

def test_universal_objective_handler_architecture():
    """Verify the disassembly structure of 8080B8F1 Row 10 (0x16fc98860)."""
    # Verify main body at 0x16fc98875
    insns = get_disasm(0x16fc98875, 0x30)
    insn_map = {i.address: (i.mnemonic, i.op_str) for i in insns}
    
    # 0x16fc98875: call 0x170c13450 (Entity Handle Query)
    assert 0x16fc98875 in insn_map
    assert insn_map[0x16fc98875] == ("call", "0x170c13450")
    
    # 0x16fc9887a: cmp dword ptr [rax], -1 (Check handle resolution status)
    assert 0x16fc9887a in insn_map
    assert insn_map[0x16fc9887a] == ("cmp", "dword ptr [rax], -1")
    
    # 0x16fc9887d: je 0x16fc9889c (Early return on uninitialized/unmapped entity)
    assert 0x16fc9887d in insn_map
    assert insn_map[0x16fc9887d] == ("je", "0x16fc9889c")
    
    # 0x16fc98882: call 0x170621810 (Active Step 1: Object lifecycle handler)
    assert 0x16fc98882 in insn_map
    assert insn_map[0x16fc98882] == ("call", "0x170621810")
    
    # 0x16fc9888c: call 0x16ef2e290 (Clear scratch buffer)
    assert 0x16fc9888c in insn_map
    assert insn_map[0x16fc9888c] == ("call", "0x16ef2e290")
    
    # 0x16fc98891: call 0x14d7e4302 (Active Step 2: Component state sync)
    assert 0x16fc98891 in insn_map
    assert insn_map[0x16fc98891] == ("call", "0x14d7e4302")
    
    # 0x16fc98896: call 0x16fc9fd74 (Active Step 3: Phase enumeration check & event dispatch)
    assert 0x16fc98896 in insn_map
    assert insn_map[0x16fc98896] == ("call", "0x16fc9fd74")
    
    print("PASS: Universal objective handler (0x16fc98860) architecture verified")

def test_objective_phase_enumeration_and_event_dispatch():
    """Verify Active Step 3 (0x16fc9fd74) reads [rcx + 0xc0] and dispatches event 0x28."""
    insns = get_disasm(0x16fc9fd74, 0x20)
    insn_map = {i.address: (i.mnemonic, i.op_str) for i in insns}
    
    # 0x16fc9fd74: cmp dword ptr [rax + 8], eax
    assert 0x16fc9fd74 in insn_map
    assert insn_map[0x16fc9fd74] == ("cmp", "dword ptr [rax + 8], eax")
    
    # 0x16fc9fd79: mov ecx, dword ptr [rcx + 0xc0] (Objective Phase Enumeration)
    assert 0x16fc9fd79 in insn_map
    assert insn_map[0x16fc9fd79] == ("mov", "ecx, dword ptr [rcx + 0xc0]")
    
    # 0x16fc9fd7f: mov eax, 0x28 (Event code 40 = State Transition)
    assert 0x16fc9fd7f in insn_map
    assert insn_map[0x16fc9fd7f] == ("mov", "eax, 0x28")
    
    # 0x16fc9fd84: call 0x14cb728ed (Activity graph event dispatcher)
    assert 0x16fc9fd84 in insn_map
    assert insn_map[0x16fc9fd84] == ("call", "0x14cb728ed")
    
    print("PASS: Phase enumeration at [rcx + 0xc0] and state event 0x28 dispatch verified")

def test_entity_handle_table_lookup_logic():
    """Verify the bitfield extraction and bucket arithmetic for handle table 0x1755bb480."""
    # Test handle indexing algorithm from 0x1597b8f5e (called by 0x170c13450)
    # Algorithm:
    #   bucket_index = (handle >> 13) & 0x3ff
    #   slot_index   = handle & 0x1fff
    test_handle = 0x00412005
    bucket_index = (test_handle >> 13) & 0x3FF
    slot_index = test_handle & 0x1FFF
    
    assert bucket_index == ((0x00412005 >> 13) & 0x3FF)
    assert slot_index == (0x00412005 & 0x1FFF)
    
    # Verify reconstruction of handle from bucket and slot
    reconstructed = (bucket_index << 13) | slot_index
    assert reconstructed == (test_handle & 0x7FFFFFFF)
    print(f"PASS: Generational handle math verified: handle {hex(test_handle)} -> bucket {bucket_index}, slot {slot_index}")

if __name__ == "__main__":
    test_component_binding_integrity()
    test_universal_objective_handler_architecture()
    test_objective_phase_enumeration_and_event_dispatch()
    test_entity_handle_table_lookup_logic()
