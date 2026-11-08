"""Synthetic ECS World Fixture and Generational Handle Allocator for Vault Breaker.

Provides verified memory layouts rooted at 0x1755bb480, synthetic entity descriptors
for Player (with item container 80800070), Key Pedestal (80B38567), and Cryo Blast Door (80809C14),
and handle resolution math matching binary logic at 0x1597b8f62..0x170c134bd and 0x16f704b00..0x16f704b70.
"""
import struct

# Memory arena base for ECS fixture (1MB mapped)
ECS_ARENA_BASE       = 0x7FF00000
ECS_ARENA_SIZE       = 0xE0000   # 896KB (below row7_scratch at 0x7FFF0000)

ROOT_STRUCT_ADDR     = ECS_ARENA_BASE + 0x0000
BUCKET_ARRAY_ADDR    = ECS_ARENA_BASE + 0x1000   # 1024 * 0x40 = 0x10000 bytes
BUCKET_0_PTR_ADDR    = ECS_ARENA_BASE + 0x11000
BUCKET_0_HDR_ADDR    = ECS_ARENA_BASE + 0x12000
SLOT_ARRAY_ADDR      = ECS_ARENA_BASE + 0x20000

# Entity Instance Addresses
PLAYER_ENTITY_ADDR   = ECS_ARENA_BASE + 0x30000
INV_COMP_80800070    = ECS_ARENA_BASE + 0x31000
PEDESTAL_ENTITY_ADDR = ECS_ARENA_BASE + 0x40000
DOOR_ENTITY_ADDR     = ECS_ARENA_BASE + 0x50000

# Handles (Generation = 1, Bucket = 0)
PLAYER_HANDLE        = 0x00800001
PEDESTAL_HANDLE      = 0x00800002
DOOR_HANDLE          = 0x00800003

# Item and Schema Constants
VAULT_KEY_ITEM_HASH  = 0x00244270  # Resolves to 0x12 via investment binary search
SCHEMA_PEDESTAL      = 0x80B38567  # pf_vault_breaker_key_pedestal.es
SCHEMA_DOOR          = 0x80809C14  # pf_cryo_blast_door
TAG_INV_CONTAINER    = 0x80800070  # Item reference container
EVENT_OBJECTIVE_SYNC = 0x28        # kEvent_ObjectivePhaseChanged (40)

# 9 Activity Phases for Vault Breaker (activity_vault_breaker.es)
VAULT_PHASES = [
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


def populate_ecs_fixture(uc):
    """Map and populate the synthetic ECS world fixture in Unicorn emulator."""
    uc.mem_map(ECS_ARENA_BASE, ECS_ARENA_SIZE)

    # 1. Bind Root Pointer at 0x1755bb480 (if page already mapped)
    try:
        uc.mem_write(0x1755bb480, struct.pack("<Q", ROOT_STRUCT_ADDR))
    except Exception:
        pass

    # 2. Populate EcsHandleTableRoot (bucket_array_base, reserved, bucket_stride=0x40, count=4096)
    uc.mem_write(ROOT_STRUCT_ADDR, struct.pack("<QQII", BUCKET_ARRAY_ADDR, 0, 0x40, 1024))

    # 3. Populate 4096 Bucket Entries (each 0x40 bytes)
    # Stride = 0x40:
    #   +0x08: slots_base (SLOT_ARRAY_ADDR)
    #   +0x10: slot_table_ptr (BUCKET_0_PTR_ADDR)
    #   +0x30: slot_stride (0x18 = 24 bytes)
    #   +0x34: offset/mask (0)
    entry_bytes = bytearray(0x40)
    struct.pack_into("<QQ", entry_bytes, 8, SLOT_ARRAY_ADDR, BUCKET_0_PTR_ADDR)
    struct.pack_into("<II", entry_bytes, 0x30, 0x18, 0)
    uc.mem_write(BUCKET_ARRAY_ADDR, bytes(entry_bytes) * 4096)

    # 4. Populate Bucket Pointer and Header
    uc.mem_write(BUCKET_0_PTR_ADDR, struct.pack("<Q", BUCKET_0_HDR_ADDR))

    # EcsBucketHeader (+0x00 -> SLOT_ARRAY_ADDR, +0x1C -> capacity = 1024)
    uc.mem_write(BUCKET_0_HDR_ADDR + 0x00, struct.pack("<Q", SLOT_ARRAY_ADDR))
    uc.mem_write(BUCKET_0_HDR_ADDR + 0x1C, struct.pack("<HH", 1024, 1))

    # 5. Populate Slot 1: Player Entity + Inventory Component (80800070)
    uc.mem_write(INV_COMP_80800070 + 0x00, struct.pack("<I", TAG_INV_CONTAINER))
    uc.mem_write(INV_COMP_80800070 + 0x20, struct.pack("<II", VAULT_KEY_ITEM_HASH, 1))

    uc.mem_write(PLAYER_ENTITY_ADDR + 0x00, struct.pack("<Q", 0x16fc98860))  # VTable
    uc.mem_write(PLAYER_ENTITY_ADDR + 0x48, struct.pack("<Q", INV_COMP_80800070))

    # 6. Populate Slot 2: Key Pedestal (pf_vault_breaker_key_pedestal.es / 80B38567)
    uc.mem_write(PEDESTAL_ENTITY_ADDR + 0x00, struct.pack("<Q", 0x16fc98860))
    uc.mem_write(PEDESTAL_ENTITY_ADDR + 0x18, struct.pack("<I", SCHEMA_PEDESTAL))
    uc.mem_write(PEDESTAL_ENTITY_ADDR + 0x94, struct.pack("<I", PLAYER_HANDLE))
    uc.mem_write(PEDESTAL_ENTITY_ADDR + 0xC0, struct.pack("<I", 1))          # Initial Phase = 1

    # 7. Populate Slot 3: Cryo Archive Blast Door (80809C14)
    uc.mem_write(DOOR_ENTITY_ADDR + 0x00, struct.pack("<Q", 0x16fc98860))
    uc.mem_write(DOOR_ENTITY_ADDR + 0x18, struct.pack("<I", SCHEMA_DOOR))
    uc.mem_write(DOOR_ENTITY_ADDR + 0x80, struct.pack("<I", 0))              # 0 = Locked

    # 8. Write Slot Descriptors (Stride = 0x18: [entity_ptr, gen_flags, mask, comp_ptr])
    slots = [
        (1, PLAYER_ENTITY_ADDR,   INV_COMP_80800070),
        (2, PEDESTAL_ENTITY_ADDR, 0),
        (3, DOOR_ENTITY_ADDR,     0),
    ]
    for idx, ent_addr, comp_addr in slots:
        slot_offset = SLOT_ARRAY_ADDR + (idx * 0x18)
        # Generation = 1 (matches bits 23..31 of 0x0080000X)
        uc.mem_write(slot_offset, struct.pack("<QIIQ", ent_addr, 1, 0xFFFFFFFF, comp_addr))


def resolve_handle(uc, handle):
    """Resolve a 32-bit generational entity handle via 0x1755bb480 handle tables."""
    slot_index = handle & 0x1FFF
    bucket_index = (handle >> 13) & 0x3FF
    generation = (handle >> 23) & 0x1FF

    root_ptr = struct.unpack("<Q", uc.mem_read(0x1755bb480, 8))[0]
    bucket_array_base, _, bucket_stride, active_bucket_count = struct.unpack("<QQII", uc.mem_read(root_ptr, 24))
    if bucket_index >= active_bucket_count:
        return None

    bucket_entry_addr = bucket_array_base + (bucket_index * bucket_stride)
    slot_table_ptr = struct.unpack("<Q", uc.mem_read(bucket_entry_addr + 0x10, 8))[0]
    bucket_header_addr = struct.unpack("<Q", uc.mem_read(slot_table_ptr, 8))[0]

    slots_base = struct.unpack("<Q", uc.mem_read(bucket_header_addr + 0x00, 8))[0]
    capacity, flags = struct.unpack("<HH", uc.mem_read(bucket_header_addr + 0x1C, 4))
    if slot_index >= capacity:
        return None

    slot_desc_addr = slots_base + (slot_index * 0x18)
    entity_ptr, gen_flags, mask, comp_ptr = struct.unpack("<QIIQ", uc.mem_read(slot_desc_addr, 24))
    slot_gen = gen_flags & 0x1FF
    if slot_gen != generation:
        return None

    return {
        "handle": handle,
        "slot_index": slot_index,
        "bucket_index": bucket_index,
        "generation": slot_gen,
        "entity_ptr": entity_ptr,
        "component_table_ptr": comp_ptr,
        "slot_descriptor_addr": slot_desc_addr,
    }


class VaultBreakerMissionDirector:
    """Standalone state machine simulating the complete 9-phase Vault Breaker mission."""

    def __init__(self, uc):
        self.uc = uc
        self.current_phase = 0
        self.event_log = []
        self.door_transitions = []

    def dispatch_event_0x28(self, phase):
        """Simulate Activity Graph Event Dispatcher (0x14cb728ed) for event 0x28."""
        self.event_log.append({
            "event": EVENT_OBJECTIVE_SYNC,
            "phase": phase,
            "phase_name": VAULT_PHASES[phase][1] if phase < len(VAULT_PHASES) else f"PHASE_{phase}"
        })

        # Subscriber 1: Door Controller (pf_cryo_blast_door / 80809C14)
        # On phase == 3 (Key Inserted) or phase >= 4 (Blast Door Disengaged):
        # transition door from 0 (Locked) to 2 (Opening)
        if phase >= 3:
            door_state = struct.unpack("<I", self.uc.mem_read(DOOR_ENTITY_ADDR + 0x80, 4))[0]
            if door_state == 0:
                self.uc.mem_write(DOOR_ENTITY_ADDR + 0x80, struct.pack("<I", 2))
                self.door_transitions.append({"from_state": 0, "to_state": 2, "at_phase": phase})

        # Update pedestal entity state
        self.uc.mem_write(PEDESTAL_ENTITY_ADDR + 0xC0, struct.pack("<I", phase))

    def interact_with_key_pedestal(self):
        """Execute Key Pedestal interaction: check key, consume key, advance phase to 3."""
        # 1. Resolve interacting player handle from pedestal (+0x94)
        player_h = struct.unpack("<I", self.uc.mem_read(PEDESTAL_ENTITY_ADDR + 0x94, 4))[0]
        player = resolve_handle(self.uc, player_h)
        assert player is not None, "Failed to resolve player entity handle"

        # 2. Check Player Inventory Container (80800070)
        comp_ptr = player["component_table_ptr"]
        tag = struct.unpack("<I", self.uc.mem_read(comp_ptr, 4))[0]
        assert tag == TAG_INV_CONTAINER, f"Invalid container tag {hex(tag)}"
        item_hash, qty = struct.unpack("<II", self.uc.mem_read(comp_ptr + 0x20, 8))
        assert item_hash == VAULT_KEY_ITEM_HASH, f"Expected vault key hash {hex(VAULT_KEY_ITEM_HASH)}"
        assert qty >= 1, "Player does not have required Vault Key"

        # 3. Consume Vault Key (decrement quantity: 1 -> 0)
        self.uc.mem_write(comp_ptr + 0x24, struct.pack("<I", qty - 1))

        # 4. Advance phase to Phase 3 (Key Inserted)
        self.current_phase = 3
        self.dispatch_event_0x28(3)
        return True

    def advance_phase(self, next_phase):
        """Advance mission to arbitrary phase and dispatch sync notification."""
        self.current_phase = next_phase
        self.dispatch_event_0x28(next_phase)
