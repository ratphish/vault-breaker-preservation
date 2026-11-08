"""Authoritative Activity Configuration and Modding Interface for Vault Breaker.

Provides modular, extensible gameplay configuration for standalone emulation.
Allows modders to configure vault tier routing, battery requirements,
hazard field mechanics, and compiler encounter triggers without modifying
the encrypted binary.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
import json

@dataclass
class VaultBreakerModConfig:
    # Tier progression routing
    # Authentic baseline: Tier 1 {1,2} -> Tier 2 {3,5} -> Tier 3 {4,6} -> Tier 4 {7}
    tier_1_vaults: List[int] = field(default_factory=lambda: [1, 2])
    tier_2_vaults: List[int] = field(default_factory=lambda: [3, 5])
    tier_3_vaults: List[int] = field(default_factory=lambda: [4, 6])
    tier_4_vaults: List[int] = field(default_factory=lambda: [7])
    
    # Forced route override (if non-empty, overrides RNG tier selection, e.g. [1, 5, 4, 7])
    forced_route: Optional[List[int]] = None
    
    # Authentic verified battery capacities for Vaults 1..7: [5, 4, 5, 6, 4, 8, 7]
    battery_requirements: Dict[int, int] = field(default_factory=lambda: {
        1: 5,
        2: 4,
        3: 5,
        4: 6,
        5: 4,
        6: 8,
        7: 7
    })
    
    # Pre-installed batteries per vault (default 0 unless modded)
    preinstalled_batteries: Dict[int, int] = field(default_factory=lambda: {
        1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0
    })
    
    # Secret Lab Hazard Antivirus field requirement (authentic: 3 HEC batteries)
    hec_antivirus_batteries_required: int = 3
    
    # DNA Access card requirement for Vault 7
    dna_access_card_required: bool = True
    
    # Mission timer in seconds (default 1800 = 30 minutes, 0 = unlimited)
    mission_time_limit_seconds: int = 1800
    
    # Compiler encounter enabled upon Vault 7 completion
    compiler_encounter_enabled: bool = True

    # Initial pedestal key chances (i_key_chance_1..3 in c_encounter__activity_vault_breaker_instance)
    key_chance_tier1: int = 50
    key_chance_tier2: int = 50
    key_chance_tier3: int = 50

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    @classmethod
    def from_json(cls, data: str) -> "VaultBreakerModConfig":
        parsed = json.loads(data)
        # Convert string dictionary keys back to integers
        if "battery_requirements" in parsed:
            parsed["battery_requirements"] = {int(k): v for k, v in parsed["battery_requirements"].items()}
        if "preinstalled_batteries" in parsed:
            parsed["preinstalled_batteries"] = {int(k): v for k, v in parsed["preinstalled_batteries"].items()}
        return cls(**parsed)
