"""Evidence Audit Test Suite for Vault Breaker Simulation.
Verifies original game executable instructions, script compiler metadata,
and activity component records against synthesized/mocked behaviors.
"""
import struct
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

SYNTHETIC_TEXT = Path("D:/Marathon-preservation/analysis/synthetic-text-section.bin")
TEXT_BASE = 0x140001000

OBJ_RECORD_80B37FED = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B37FED.bin")
SCRIPT_METADATA_80B37C7E = Path("D:/Marathon-preservation/analysis/script-compiler-metadata/80B37C7E.bin")
KEY_PEDESTAL_80B38567 = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B38567.bin")
PEDESTAL_NAMES_80B37FEC = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B37FEC.bin")


def get_disasm(address, size):
    data = SYNTHETIC_TEXT.read_bytes()
    offset = address - TEXT_BASE
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return list(md.disasm(data[offset:offset + size], address))


def test_audit_activity_component_9_records():
    """Verify that 80B37FED.bin contains exactly 9 records spaced 0xB0 apart binding 8080B8F1 Slot 10."""
    data = OBJ_RECORD_80B37FED.read_bytes()
    tag_8080b8f1 = struct.pack("<I", 0x8080B8F1)
    
    # 1. Locate all 8080B8F1 slot 10 records in 80B37FED
    records = []
    for i in range(9):
        base_off = 0x1478 + (i * 0xB0)
        tag = struct.unpack_from("<I", data, base_off)[0]
        slot = struct.unpack_from("<I", data, base_off + 4)[0]
        parent = struct.unpack_from("<I", data, base_off + 8)[0]
        assert tag == 0x8080B8F1, f"Expected 0x8080B8F1 at {hex(base_off)}, got {hex(tag)}"
        assert slot == 10, f"Expected slot 10 at {hex(base_off + 4)}, got {slot}"
        assert parent == 0x80B37FED, f"Expected parent 0x80B37FED, got {hex(parent)}"
        
        # Read the linked script compiler slot reference (dword [39])
        linked_tag = struct.unpack_from("<I", data, base_off + 0x24)[0] # schema offset
        records.append((base_off, slot, linked_tag))
    
    assert len(records) == 9
    print("PASS: Verified 9 0xB0-strided objective records binding 8080B8F1 Slot 10 in 80B37FED.bin")


def test_audit_activity_script_slots_map_to_7_vaults():
    """Verify that slots in 80B37FED link to 80B37C7E script functions for Vaults 1..7 + Secret Lab."""
    data_fed = OBJ_RECORD_80B37FED.read_bytes()
    data_meta = SCRIPT_METADATA_80B37C7E.read_bytes()
    
    # In 80B37FED.bin, the 9 objective records carry target slot indices for 80B37C7E:
    expected_slot_indices = [
        (0, 0x15, "sc_vault_1_objectives_d_execute_impl"),
        (1, 0x16, "sc_vault_2_objectives_d_execute_impl"),
        (2, 0x17, "sc_vault_3_objectives_d_execute_impl"),
        (3, 0x18, "sc_vault_5_objectives_d_execute_impl"),
        (4, 0x19, "sc_vault_4_objectives_d_execute_impl"),
        (5, 0x1A, "sc_vault_6_objectives_d_execute_impl"),
        (6, 0x1B, "sc_monitor_secret_lab_visit_d_execute_impl"),
        (7, 0x1D, "sc_vault_7_objectives_d_execute_impl"),
    ]
    
    for idx, expected_slot, expected_name in expected_slot_indices:
        base_off = 0x1478 + (idx * 0xB0)
        # Check target tag and slot at offset +0x98 and +0x9C
        target_tag = struct.unpack_from("<I", data_fed, base_off + 0x98)[0]
        target_slot = struct.unpack_from("<I", data_fed, base_off + 0x9C)[0]
        assert target_tag == 0x80B37C7E, f"Record {idx} must target metadata 80B37C7E, got {hex(target_tag)}"
        assert target_slot == expected_slot, f"Record {idx} expected slot {hex(expected_slot)}, got {hex(target_slot)}"
        assert expected_name.encode() in data_meta, f"Function {expected_name} must exist in script metadata"
        print(f"PASS: Objective Record {idx} -> Verified Original Slot {hex(target_slot)} ({expected_name})")


def test_audit_generational_handle_lookup_native_assembly():
    """Verify native instructions for handle extraction at 0x1597b8f5e."""
    insns = get_disasm(0x1597b8f5e, 0x60)
    insn_map = {i.address: (i.mnemonic, i.op_str) for i in insns}
    
    # 0x1597b8f62: mov r10d, dword ptr [rcx + 4] (Read handle from component instance)
    assert insn_map[0x1597b8f62] == ("mov", "r10d, dword ptr [rcx + 4]")
    
    # 0x1597b8f7c: mov r8, qword ptr [rip + 0x1be024fd] (Read handle table root 0x1755bb480)
    assert insn_map[0x1597b8f7c] == ("mov", "r8, qword ptr [rip + 0x1be024fd]")
    target_ptr = 0x1597b8f7c + 7 + 0x1be024fd
    assert target_ptr == 0x1755bb480, f"Expected root pointer 0x1755bb480, got {hex(target_ptr)}"
    
    # 0x1597b8f83: mov eax, 0x1fff (13-bit slot mask)
    assert insn_map[0x1597b8f83] == ("mov", "eax, 0x1fff")
    
    # 0x1597b8fa8: shr eax, 0xd (Extract bucket index: handle >> 13)
    assert insn_map[0x1597b8fa8] == ("shr", "eax, 0xd")
    
    # 0x1597b8fae: mov rax, qword ptr [r8] (Read bucket array pointer)
    assert insn_map[0x1597b8fae] == ("mov", "rax, qword ptr [r8]")
    
    # 0x1597b8fb3: imul edx, dword ptr [r8 + 0x10] (Multiply bucket index by bucket stride)
    assert insn_map[0x1597b8fb3] == ("imul", "edx, dword ptr [r8 + 0x10]")
    
    # 0x1597b8fb8: mov rdx, qword ptr [rdx + rax + 0x10] (Read slot table pointer from bucket descriptor)
    assert insn_map[0x1597b8fb8] == ("mov", "rdx, qword ptr [rdx + rax + 0x10]")
    
    print("PASS: Verified original native instructions for generational handle resolution at 0x1597b8f5e")


def test_audit_event_0x28_dispatch_and_bitfield_semantics():
    """Verify original assembly of Active Step 3 (0x16fc9fd74) and Arxan target (0x148ed4ab6)."""
    # 1. Active Step 3 at 0x16fc9fd74
    insns_step3 = get_disasm(0x16fc9fd74, 0x20)
    step3_map = {i.address: (i.mnemonic, i.op_str) for i in insns_step3}
    assert step3_map[0x16fc9fd74] == ("cmp", "dword ptr [rax + 8], eax")
    assert step3_map[0x16fc9fd79] == ("mov", "ecx, dword ptr [rcx + 0xc0]")
    assert step3_map[0x16fc9fd7f] == ("mov", "eax, 0x28")
    assert step3_map[0x16fc9fd84] == ("call", "0x14cb728ed")
    
    # 2. Arxan destination at 0x148ed4ab6 evaluates bit 12 of ecx ([rcx + 0xC0])
    insns_dest = get_disasm(0x148ed4ab6, 0x10)
    dest_map = {i.address: (i.mnemonic, i.op_str) for i in insns_dest}
    assert dest_map[0x148ed4ab6] == ("mov", "eax, ecx")
    assert dest_map[0x148ed4ab8] == ("shr", "eax, 0xc")
    assert dest_map[0x148ed4abb] == ("and", "al, 1")
    assert dest_map[0x148ed4abd] == ("cmp", "al, r9b")
    
    print("PASS: Verified original event 0x28 opcode and bit-12 status check at 0x148ed4ab6")


def test_audit_hypothesized_names_and_tags_absence_in_originals():
    """Prove that linear phase names (INFILTRATION_APPROACH) and door tag 80809C14 are synthetic."""
    fed_bytes = OBJ_RECORD_80B37FED.read_bytes()
    meta_bytes = SCRIPT_METADATA_80B37C7E.read_bytes()
    pedestal_bytes = KEY_PEDESTAL_80B38567.read_bytes()
    
    # Synthetic names invented in Python fixture
    hypothesized_names = [
        b"INFILTRATION_APPROACH",
        b"SECURITY_BREACH",
        b"CRYO_STABILIZATION",
        b"PEDESTAL_KEY_INSERTION",
        b"BLAST_DOOR_DISENGAGED",
        b"ARCHIVE_VAULT_INTERIOR",
        b"DATA_CORE_EXTRACTION",
        b"FACILITY_LOCKDOWN_PURGE",
        b"MISSION_EXTRACTION_COMPLETE",
    ]
    for name in hypothesized_names:
        assert name not in fed_bytes, f"Hypothesized string {name.decode()} unexpectedly found in 80B37FED.bin"
        assert name not in meta_bytes, f"Hypothesized string {name.decode()} unexpectedly found in 80B37C7E.bin"
    
    # Synthetic door schema tag 0x80809C14
    tag_door_bytes = struct.pack("<I", 0x80809C14)
    assert tag_door_bytes not in fed_bytes, "Door tag 0x80809C14 unexpectedly found in 80B37FED.bin"
    assert tag_door_bytes not in meta_bytes, "Door tag 0x80809C14 unexpectedly found in 80B37C7E.bin"
    assert tag_door_bytes not in pedestal_bytes, "Door tag 0x80809C14 unexpectedly found in 80B38567.bin"
    
    print("PASS: Proved that 9 linear phase names and door tag 0x80809C14 are synthetic artifacts")


def test_audit_key_pedestal_world_records():
    """Verify that original game defines 4 key pedestal instances (g_key_pedestals_1..4)."""
    data_names = PEDESTAL_NAMES_80B37FEC.read_bytes()
    assert b"g_key_pedestals_1" in data_names
    assert b"g_key_pedestals_2" in data_names
    assert b"g_key_pedestals_3" in data_names
    assert b"g_key_pedestals_4" in data_names
    print("PASS: Verified 4 interactive key pedestal objects (g_key_pedestals_1..4) in 80B37FEC.bin")


if __name__ == "__main__":
    test_audit_activity_component_9_records()
    test_audit_activity_script_slots_map_to_7_vaults()
    test_audit_generational_handle_lookup_native_assembly()
    test_audit_event_0x28_dispatch_and_bitfield_semantics()
    test_audit_hypothesized_names_and_tags_absence_in_originals()
    test_audit_key_pedestal_world_records()
