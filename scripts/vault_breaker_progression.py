"""Vault Breaker Progression Engine & Selection Graph.
Implements the verified 4-tier vault selection logic, battery socket capacity,
coolant canisters, credentials, DNA cards, and Compiler encounter eligibility.
"""
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class VaultTier(Enum):
    TIER_1 = 1  # Entry Vaults: {1, 2}
    TIER_2 = 2  # Intermediate Vaults: {3, 5}
    TIER_3 = 3  # Advanced Vaults: {4, 6}
    TIER_4 = 4  # Final Vault: {7}
    FINALE = 5  # Compiler Encounter


class GameMode(Enum):
    CRYO_STANDARD = "activity_exp.cryo.standard_synced"
    VAULT_BREAKER_PVE = "activity_exp.cryo.vault_breaker_server"


# Universal physical battery socket capacity across all vault doors in Cryo Archive
TOTAL_BATTERY_SOCKET_CAPACITY = 8

# Verified raw required battery integers from 80B37FED.bin / 80B37C7E.bin
VAULT_BATTERIES_REQUIRED: Dict[int, int] = {
    1: 5,  # Vault 1: 5 required -> 3 pre-installed
    2: 4,  # Vault 2: 4 required -> 4 pre-installed
    3: 5,  # Vault 3: 5 required -> 3 pre-installed
    4: 6,  # Vault 4: 6 required -> 2 pre-installed
    5: 4,  # Vault 5: 4 required -> 4 pre-installed
    6: 8,  # Vault 6: 8 required -> 0 pre-installed (all empty)
    7: 7,  # Vault 7: 7 required -> 1 pre-installed
}

# Verified coolant canister requirement (0 or 1)
VAULT_CANISTER_REQUIRED: Dict[int, bool] = {
    1: False,
    2: True,
    3: False,
    4: False,
    5: True,
    6: True,
    7: False,
}

# Verified credential key requirement
VAULT_CREDENTIALS_REQUIRED: Dict[int, Optional[str]] = {
    1: None,
    2: None,
    3: "quest.run_objectives.cryo.vault_objectives.vault_credentials0",  # Wing Credentials
    4: "quest.run_objectives.cryo.vault_objectives.vault_credentials1",  # Colonist Credentials
    5: "quest.run_objectives.cryo.vault_objectives.vault_credentials2",  # Tranquility Credentials
    6: None,
    7: "quest.run_objectives.cryo.vault_objectives.vault_credentials7",  # Command Credentials
}

# Verified DNA Blueprint requirement (Vault 7 only)
VAULT_DNA_REQUIRED: Dict[int, bool] = {
    1: False, 2: False, 3: False, 4: False, 5: False, 6: False, 7: True
}

# The 6 verified DNA blueprints from 80B37C7E.bin
DNA_BLUEPRINT_CARDS = [
    "quest.run_objectives.cryo.vault_objectives.dna_blueprint_agct",
    "quest.run_objectives.cryo.vault_objectives.dna_blueprint_agtc",
    "quest.run_objectives.cryo.vault_objectives.dna_blueprint_ctag",
    "quest.run_objectives.cryo.vault_objectives.dna_blueprint_gact",
    "quest.run_objectives.cryo.vault_objectives.dna_blueprint_tcag",
    "quest.run_objectives.cryo.vault_objectives.dna_blueprint_tcga",
]

# The 6 infiltration zones from 80B37C7E.bin
INFILTRATION_REGIONS = [
    "infil_region_1", "infil_region_2", "infil_region_3",
    "infil_region_4", "infil_region_5", "infil_region_6"
]

# Eligibility sets by tier
TIER_ELIGIBILITY: Dict[VaultTier, List[int]] = {
    VaultTier.TIER_1: [1, 2],
    VaultTier.TIER_2: [3, 5],
    VaultTier.TIER_3: [4, 6],
    VaultTier.TIER_4: [7],
}


@dataclass
class PlayerInventory:
    batteries: int = 0
    full_canisters: int = 0
    empty_canisters: int = 0
    credentials: Set[str] = field(default_factory=set)
    dna_blueprints: Set[str] = field(default_factory=set)


@dataclass
class VaultRunPlan:
    infil_region: str
    selected_vaults: List[int]  # [stage_1, stage_2, stage_3, 7]
    dna_blueprint: str
    compiler_eligible: bool


class VaultBreakerDirector:
    """Manages the full PvE activity lifecycle, random generation, and validation."""

    def __init__(self, seed: Optional[int] = None, mode: GameMode = GameMode.VAULT_BREAKER_PVE):
        self.mode: GameMode = mode
        self.rng = random.Random(seed)
        self.plan: VaultRunPlan = self._generate_plan()
        
        self.current_tier: VaultTier = VaultTier.TIER_1
        self.current_stage_index: int = 0
        self.completed_vaults: List[int] = []
        
        self.inventory: PlayerInventory = PlayerInventory()
        self.time_remaining_seconds: float = 1200.0  # 20 minutes default match timer
        self.compiler_killed: bool = False
        self.mission_completed: bool = False
        
        self.event_log: List[str] = []

    def _generate_plan(self) -> VaultRunPlan:
        """Deterministically generates a 3-vault route + Vault 7 + Compiler."""
        infil = self.rng.choice(INFILTRATION_REGIONS)
        
        # Pick 1 from each tier
        v1 = self.rng.choice(TIER_ELIGIBILITY[VaultTier.TIER_1])
        v2 = self.rng.choice(TIER_ELIGIBILITY[VaultTier.TIER_2])
        v3 = self.rng.choice(TIER_ELIGIBILITY[VaultTier.TIER_3])
        v4 = 7  # Always Vault 7 in Tier 4
        
        dna = self.rng.choice(DNA_BLUEPRINT_CARDS)
        return VaultRunPlan(
            infil_region=infil,
            selected_vaults=[v1, v2, v3, v4],
            dna_blueprint=dna,
            compiler_eligible=True
        )

    @property
    def current_active_vault(self) -> int:
        if self.current_stage_index < len(self.plan.selected_vaults):
            return self.plan.selected_vaults[self.current_stage_index]
        return 7

    def get_pre_installed_batteries(self, vault_id: int) -> int:
        """Returns the number of batteries already socketed in the 8-socket rack."""
        req = VAULT_BATTERIES_REQUIRED[vault_id]
        return TOTAL_BATTERY_SOCKET_CAPACITY - req

    def supply_loot_for_vault(self, vault_id: int):
        """Simulates finding required resources in the facility for testing."""
        req_batteries = VAULT_BATTERIES_REQUIRED[vault_id]
        self.inventory.batteries += req_batteries
        
        if VAULT_CANISTER_REQUIRED[vault_id]:
            self.inventory.full_canisters += 1
            
        cred_key = VAULT_CREDENTIALS_REQUIRED[vault_id]
        if cred_key:
            self.inventory.credentials.add(cred_key)
            
        if VAULT_DNA_REQUIRED[vault_id]:
            self.inventory.dna_blueprints.add(self.plan.dna_blueprint)

    def attempt_unlock_active_vault(self, elapsed_seconds: float = 0.0) -> bool:
        """Validates all conditions to unlock the active vault."""
        v_id = self.current_active_vault
        
        # 1. Check batteries
        req_batteries = VAULT_BATTERIES_REQUIRED[v_id]
        if self.inventory.batteries < req_batteries:
            return False
            
        # 2. Check canister
        if VAULT_CANISTER_REQUIRED[v_id] and self.inventory.full_canisters < 1:
            return False
            
        # 3. Check credentials
        cred_key = VAULT_CREDENTIALS_REQUIRED[v_id]
        if cred_key and cred_key not in self.inventory.credentials:
            return False
            
        # 4. Check DNA blueprint
        if VAULT_DNA_REQUIRED[v_id] and self.plan.dna_blueprint not in self.inventory.dna_blueprints:
            return False

        # All conditions met: apply elapsed time and consume items
        self.time_remaining_seconds -= elapsed_seconds
        self.inventory.batteries -= req_batteries
        if VAULT_CANISTER_REQUIRED[v_id]:
            self.inventory.full_canisters -= 1

        self.completed_vaults.append(v_id)
        self.event_log.append(f"il_vault_{v_id}_opened")
        self.current_stage_index += 1
        
        # Advance Tier
        if self.current_stage_index == 1:
            self.current_tier = VaultTier.TIER_2
        elif self.current_stage_index == 2:
            self.current_tier = VaultTier.TIER_3
        elif self.current_stage_index == 3:
            self.current_tier = VaultTier.TIER_4
        elif self.current_stage_index == 4:
            self.current_tier = VaultTier.FINALE
            
        return True

    def attempt_compiler_encounter(self) -> bool:
        """Engage The Compiler if Vault 7 is completed and time remains."""
        if self.current_tier != VaultTier.FINALE or 7 not in self.completed_vaults:
            return False
            
        # Compiler condition: sufficient time remaining (minimum 120 seconds for boss fight)
        if self.time_remaining_seconds >= 120.0:
            self.compiler_killed = True
            self.event_log.append("b_compiler_killed")
            self.mission_completed = True
            self.event_log.append("il_pre_exfil")
            return True
        else:
            # Time low -> must exfiltrate without Compiler
            self.mission_completed = True
            self.event_log.append("il_pre_exfil")
            return False
