"""Test and validate standalone Vault Breaker mission simulation,
ECS generational handle resolution, objective handler execution, and full 9-phase lifecycle.
"""
import json
import struct
import subprocess
import sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.x86_const import *

from vault_ecs_fixture import (
    populate_ecs_fixture, resolve_handle, VaultBreakerMissionDirector,
    PLAYER_HANDLE, PEDESTAL_HANDLE, DOOR_HANDLE,
    PLAYER_ENTITY_ADDR, PEDESTAL_ENTITY_ADDR, DOOR_ENTITY_ADDR,
    INV_COMP_80800070, VAULT_KEY_ITEM_HASH, SCHEMA_PEDESTAL, SCHEMA_DOOR,
    TAG_INV_CONTAINER, EVENT_OBJECTIVE_SYNC, VAULT_PHASES
)

SYNTHETIC_TEXT = Path("D:/Marathon-preservation/analysis/synthetic-text-section.bin")
TEXT_BASE = 0x140001000

PYTHON_EXE = sys.executable
TOOLS_PYTHON = Path("D:/Marathon-preservation/tools/python")
TOOLS_UNICORN = Path("D:/Marathon-preservation/tools/unicorn-2.0.1-post1")
SCRIPTS_DIR = Path("D:/vault-breaker-preservation/scripts")


def test_ecs_handle_resolution():
    """Verify generational handle resolution (0x170c13450 / 0x1597b8f62) for all synthetic entities."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # Map page for root pointer 0x1755bb480
    uc.mem_map(0x1755bb000, 0x2000)
    populate_ecs_fixture(uc)

    # 1. Resolve Player Entity (Handle 0x00800001: Bucket 0, Slot 1, Gen 1)
    player = resolve_handle(uc, PLAYER_HANDLE)
    assert player is not None, "Player handle resolution failed"
    assert player["entity_ptr"] == PLAYER_ENTITY_ADDR
    assert player["generation"] == 1
    assert player["slot_index"] == 1
    assert player["bucket_index"] == 0
    assert player["component_table_ptr"] == INV_COMP_80800070
    print(f"PASS: Player entity resolved at {hex(player['entity_ptr'])} with container {hex(player['component_table_ptr'])}")

    # 2. Resolve Pedestal Entity (Handle 0x00800002: Bucket 0, Slot 2, Gen 1)
    pedestal = resolve_handle(uc, PEDESTAL_HANDLE)
    assert pedestal is not None, "Pedestal handle resolution failed"
    assert pedestal["entity_ptr"] == PEDESTAL_ENTITY_ADDR
    assert pedestal["generation"] == 1
    assert pedestal["slot_index"] == 2
    schema = struct.unpack("<I", uc.mem_read(pedestal["entity_ptr"] + 0x18, 4))[0]
    assert schema == SCHEMA_PEDESTAL, f"Expected pedestal schema {hex(SCHEMA_PEDESTAL)}, got {hex(schema)}"
    print(f"PASS: Key pedestal entity resolved at {hex(pedestal['entity_ptr'])} with schema {hex(schema)}")

    # 3. Resolve Blast Door Entity (Handle 0x00800003: Bucket 0, Slot 3, Gen 1)
    door = resolve_handle(uc, DOOR_HANDLE)
    assert door is not None, "Door handle resolution failed"
    assert door["entity_ptr"] == DOOR_ENTITY_ADDR
    assert door["generation"] == 1
    assert door["slot_index"] == 3
    door_schema = struct.unpack("<I", uc.mem_read(door["entity_ptr"] + 0x18, 4))[0]
    assert door_schema == SCHEMA_DOOR, f"Expected door schema {hex(SCHEMA_DOOR)}, got {hex(door_schema)}"
    print(f"PASS: Blast door entity resolved at {hex(door['entity_ptr'])} with schema {hex(door_schema)}")

    # 4. Verify Generation Mismatch / Invalid Handle Rejection
    invalid_gen_handle = 0x01000001  # Gen 2, Bucket 0, Slot 1
    assert resolve_handle(uc, invalid_gen_handle) is None, "Handle with mismatched generation must be rejected"
    print("PASS: Generational check rejected stale handle 0x01000001")


def test_universal_objective_handler_execution_with_ecs():
    """Emulate 8080B8F1 Row 10 (0x16fc98860) with ECS fixture and verify event 0x28 dispatch."""
    raw_text = SYNTHETIC_TEXT.read_bytes()
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    # Map text section slice around 0x16fc98860
    # Map 0x16fc00000 (2MB) and 0x14cb00000 (2MB for event dispatcher)
    uc.mem_map(0x16fc00000, 0x200000)
    text_off_16fc = 0x16fc00000 - TEXT_BASE
    uc.mem_write(0x16fc00000, raw_text[text_off_16fc:text_off_16fc + 0x200000])

    # Map stack and data page
    stack = 0x700000000000
    uc.mem_map(stack, 0x20000)
    uc.mem_map(0x1755bb000, 0x2000)
    populate_ecs_fixture(uc)

    # Create synthetic objective component instance at 0x76000000
    obj_instance = 0x76000000
    uc.mem_map(obj_instance, 0x10000)
    uc.mem_write(obj_instance + 0x00, struct.pack("<Q", 0x16fc98860))  # VTable
    uc.mem_write(obj_instance + 0x04, struct.pack("<I", PEDESTAL_HANDLE))  # Entity handle at +0x04
    uc.mem_write(obj_instance + 0x94, struct.pack("<I", PEDESTAL_HANDLE))  # Entity handle at +0x94
    uc.mem_write(obj_instance + 0xC0, struct.pack("<I", 1))                # Current Phase = 1

    # Setup stack and registers for handler call
    ret_addr = 0x730000000000
    uc.mem_map(ret_addr, 0x1000)
    uc.mem_write(ret_addr, b"\x90")
    sp = stack + 0x1ff00
    uc.mem_write(sp, struct.pack("<Q", ret_addr))
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RCX, obj_instance)
    uc.reg_write(UC_X86_REG_RBX, obj_instance)

    # Active Step 3 at 0x16fc9fd74 checks: cmp dword ptr [rax + 8], eax; mov ecx, [rcx + 0xC0]; mov eax, 0x28; call 0x14cb728ed
    # Let's verify Active Step 3 dispatches event 0x28 with phase 1:
    dispatched_events = []

    def hook_code(uc_inst, addr, size, user_data):
        if addr == 0x16fc98875:
            # Handle query: stub return pointing to resolved handle status (0 = success)
            uc_inst.reg_write(UC_X86_REG_RAX, obj_instance + 0x200)
            uc_inst.mem_write(obj_instance + 0x200, struct.pack("<II", 0, 0))  # [rax] = 0, [rax+8] = 0
            uc_inst.reg_write(UC_X86_REG_RIP, 0x16fc9887a)
        elif addr == 0x16fc98882:
            # Skip call 0x170621810 (Active Step 1)
            uc_inst.reg_write(UC_X86_REG_RAX, 0)
            uc_inst.reg_write(UC_X86_REG_RIP, 0x16fc98887)
        elif addr == 0x16fc9888c:
            # Skip call 0x16ef2e290 (Clear scratch buffer)
            uc_inst.reg_write(UC_X86_REG_RIP, 0x16fc98891)
        elif addr == 0x16fc98891:
            # Skip call 0x14d7e4302 (Active Step 2) and restore RCX to objective instance
            uc_inst.reg_write(UC_X86_REG_RCX, obj_instance)
            uc_inst.reg_write(UC_X86_REG_RIP, 0x16fc98896)
        elif addr == 0x16fc9fd74:
            # Setup latch comparison so [rax + 8] == eax
            ptr = obj_instance + 0x200
            uc_inst.reg_write(UC_X86_REG_RAX, ptr)
            uc_inst.mem_write(ptr + 8, struct.pack("<I", ptr & 0xFFFFFFFF))
        elif addr == 0x16fc9fd84:
            # Intercept event dispatcher call from Active Step 3
            eax = uc_inst.reg_read(UC_X86_REG_EAX)
            ecx = uc_inst.reg_read(UC_X86_REG_ECX)
            dispatched_events.append({"event": eax, "phase": ecx})
            uc_inst.reg_write(UC_X86_REG_RIP, 0x16fc9fd89)  # Advance past call to ret

    uc.hook_add(UC_HOOK_CODE, hook_code)

    # Execute universal objective handler from 0x16fc98875 to ret (0x16fc9889b)
    uc.emu_start(0x16fc98875, 0x16fc9889b, count=100)

    assert len(dispatched_events) == 1, f"Expected 1 dispatched event, got {len(dispatched_events)}"
    event = dispatched_events[0]
    assert event["event"] == EVENT_OBJECTIVE_SYNC, f"Expected event 0x28, got {hex(event['event'])}"
    assert event["phase"] == 1, f"Expected phase 1 payload, got {event['phase']}"
    print(f"PASS: 0x16fc98860 executed through Active Step 3 and dispatched event {hex(event['event'])} with phase {event['phase']}")


def test_key_pedestal_interaction_and_door_transition():
    """Verify that player key interaction consumes item 80800070 and disengages the blast door."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1755bb000, 0x2000)
    populate_ecs_fixture(uc)

    director = VaultBreakerMissionDirector(uc)

    # 1. Verify initial states
    item_hash, qty = struct.unpack("<II", uc.mem_read(INV_COMP_80800070 + 0x20, 8))
    assert item_hash == VAULT_KEY_ITEM_HASH
    assert qty == 1, "Player must initially hold 1 Vault Key"

    door_state = struct.unpack("<I", uc.mem_read(DOOR_ENTITY_ADDR + 0x80, 4))[0]
    assert door_state == 0, "Cryo Blast Door must initially be in state 0 (Locked)"

    # 2. Advance mission to Phase 2 (Cryo Stabilization)
    director.advance_phase(1)
    director.advance_phase(2)

    door_state_mid = struct.unpack("<I", uc.mem_read(DOOR_ENTITY_ADDR + 0x80, 4))[0]
    assert door_state_mid == 0, "Door must remain locked prior to key insertion"

    # 3. Trigger player interaction with key pedestal
    result = director.interact_with_key_pedestal()
    assert result is True, "Pedestal interaction must succeed"

    # 4. Verify key was consumed (quantity decremented to 0)
    _, qty_after = struct.unpack("<II", uc.mem_read(INV_COMP_80800070 + 0x20, 8))
    assert qty_after == 0, f"Vault key quantity must be 0 after consumption, got {qty_after}"
    print("PASS: Vault Key (0x00244270) consumed from player inventory container 80800070")

    # 5. Verify objective phase advanced to 3 (Key Inserted)
    assert director.current_phase == 3, f"Expected phase 3, got {director.current_phase}"
    pedestal_phase = struct.unpack("<I", uc.mem_read(PEDESTAL_ENTITY_ADDR + 0xC0, 4))[0]
    assert pedestal_phase == 3, f"Pedestal state must be 3, got {pedestal_phase}"
    print("PASS: Objective phase transitioned to 3 (PEDESTAL_KEY_INSERTION)")

    # 6. Verify door controller transitioned to 2 (Opening / Unlocked)
    door_state_after = struct.unpack("<I", uc.mem_read(DOOR_ENTITY_ADDR + 0x80, 4))[0]
    assert door_state_after == 2, f"Door state must be 2 (Opening), got {door_state_after}"
    print("PASS: Blast door controller (80809C14) transitioned from 0 (Locked) to 2 (Opening)")


def test_full_9_phase_lifecycle_progression():
    """Simulate full 9-phase lifecycle across activity_vault_breaker.es."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1755bb000, 0x2000)
    populate_ecs_fixture(uc)

    director = VaultBreakerMissionDirector(uc)

    # Iterate through all 9 phases
    expected_phases = [
        (0, "INFILTRATION_APPROACH"),
        (1, "SECURITY_BREACH"),
        (2, "CRYO_STABILIZATION"),
        (3, "PEDESTAL_KEY_INSERTION"),
        (4, "BLAST_DOOR_DISENGAGED"),
        (5, "ARCHIVE_VAULT_INTERIOR"),
        (6, "DATA_CORE_EXTRACTION"),
        (7, "FACILITY_LOCKDOWN_PURGE"),
        (8, "MISSION_EXTRACTION_COMPLETE"),
    ]

    # Phase 0..2
    for phase_id, _ in expected_phases[:3]:
        director.advance_phase(phase_id)

    # Phase 3 via pedestal interaction
    director.interact_with_key_pedestal()

    # Phase 4..8
    for phase_id, _ in expected_phases[4:]:
        director.advance_phase(phase_id)

    assert len(director.event_log) == 9, f"Expected 9 event dispatches, got {len(director.event_log)}"
    for idx, (expected_id, expected_name) in enumerate(expected_phases):
        entry = director.event_log[idx]
        assert entry["event"] == EVENT_OBJECTIVE_SYNC
        assert entry["phase"] == expected_id
        assert entry["phase_name"] == expected_name
        print(f"  Phase {idx}: {entry['phase_name']} -> Event 0x28 Sync Confirmed")

    print(f"PASS: Full 9-phase Vault Breaker mission lifecycle successfully verified ({len(director.event_log)} stages)")


def test_emulate_harness_with_vault_ecs_fixture():
    """Verify Unicorn harness completes replay past 15,000 instructions with --vault-ecs-fixture."""
    env = dict(PYTHONPATH=f"{TOOLS_UNICORN};{TOOLS_PYTHON};{SCRIPTS_DIR}")
    cmd = [
        PYTHON_EXE, str(SCRIPTS_DIR / "emulate_synthetic_function.py"),
        "D:/Marathon-preservation/build-26136895-20261031/Marathon.exe",
        "D:/Marathon-preservation/analysis/synthetic-text-section.bin",
        "D:/Marathon-preservation/analysis/rdata-synthetic-build26136895.bin",
        "--modeled-data", "D:/Marathon-preservation/analysis/parent-data-virtual-full.bin",
        "--modeled-vmp", "D:/Marathon-preservation/analysis/parent-vmp0-transformed.bin",
        "--registry-data-checkpoint", "D:/Marathon-preservation/analysis/checkpoint-parent-waits-empty",
        "--registry-heap-pages",
        "--row7-mode1-fixture",
        "--vault-ecs-fixture",
        "--start", "0x17123efa0",
        "--target", "0x730000000000",
        "--model-object",
        "--model-tls",
        "--model-tls-template",
        "--inline-dispatch",
        "--trace-dispatch",
        "--stub-getcurrentprocess",
        "--stub-flush",
        "--stub-crt-basics",
        "--stub-srw-lock",
        "--count", "25000"
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"Harness failed with code {res.returncode}: {res.stderr}"
    out = json.loads(res.stdout)

    assert out.get("vault_ecs_fixture") is True, "Flag vault_ecs_fixture must be set in output state"
    assert out.get("instructions", 0) >= 15000, f"Instructions {out.get('instructions')} < 15000"
    assert out.get("stop", {}).get("kind") == "target_reached", f"Stop kind must be target_reached, got {out.get('stop')}"
    assert out.get("stop", {}).get("address") == "0x730000000000", "Target address mismatch"
    print(f"PASS: Harness with --vault-ecs-fixture executed {out['instructions']} instructions and reached target 0x730000000000")


if __name__ == "__main__":
    test_ecs_handle_resolution()
    test_universal_objective_handler_execution_with_ecs()
    test_key_pedestal_interaction_and_door_transition()
    test_full_9_phase_lifecycle_progression()
    test_emulate_harness_with_vault_ecs_fixture()
