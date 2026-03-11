"""Difficulty preset module for CTF PCAP generation.

Defines difficulty presets (EASY, MEDIUM, HARD) with validated parameters,
a pool of hard encoding chains, and a resolution function that merges
presets with optional overrides.

Functions:
    resolve_difficulty: Resolve a difficulty name to parameter dict with overrides.

No Flask or integration imports allowed in engine modules.
"""

import random
from typing import Literal

import structlog
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from pydantic_core import PydanticCustomError

from ctf_pcaps.engine.flag import ENCODERS

logger = structlog.get_logger()


class DifficultyPreset(BaseModel):
    """Validated difficulty preset configuration.

    Defines noise ratio, packet count range, encoding chain, noise types,
    and timing jitter for a difficulty level. All fields are validated
    using Pydantic v2 validators.

    Extra fields are forbidden to catch typos.
    """

    model_config = ConfigDict(extra="forbid")

    name: Literal["easy", "medium", "hard"]
    encoding_chain: list[str]
    noise_ratio: float
    packet_count_min: int
    packet_count_max: int
    noise_types: list[str]
    timing_jitter_ms: tuple[float, float]
    split_count_min: int = 1
    split_count_max: int = 1

    @field_validator("noise_ratio")
    @classmethod
    def validate_noise_ratio(cls, v: float) -> float:
        """Ensure noise_ratio is in [0.0, 1.0]."""
        if v < 0.0 or v > 1.0:
            raise PydanticCustomError(
                "invalid_noise_ratio",
                "noise_ratio must be between 0.0 and 1.0, got {value}",
                {"value": v},
            )
        return v

    @field_validator("encoding_chain")
    @classmethod
    def validate_encoding_chain(cls, v: list[str]) -> list[str]:
        """Ensure all encoding chain entries exist in ENCODERS."""
        for enc in v:
            if enc not in ENCODERS:
                raise PydanticCustomError(
                    "invalid_encoding",
                    "Unknown encoding '{encoding}' in chain. Available: {available}",
                    {
                        "encoding": enc,
                        "available": ", ".join(sorted(ENCODERS.keys())),
                    },
                )
        return v

    @model_validator(mode="after")
    def validate_packet_count_range(self):
        """Ensure packet_count_min <= packet_count_max."""
        if self.packet_count_min > self.packet_count_max:
            raise PydanticCustomError(
                "invalid_packet_range",
                "packet_count_min ({min_val}) cannot exceed "
                "packet_count_max ({max_val})",
                {
                    "min_val": self.packet_count_min,
                    "max_val": self.packet_count_max,
                },
            )
        return self

    @model_validator(mode="after")
    def validate_split_count_range(self):
        """Ensure split_count_min >= 1 and split_count_min <= split_count_max."""
        if self.split_count_min < 1:
            raise PydanticCustomError(
                "invalid_split_count",
                "split_count_min must be >= 1, got {value}",
                {"value": self.split_count_min},
            )
        if self.split_count_min > self.split_count_max:
            raise PydanticCustomError(
                "invalid_split_range",
                "split_count_min ({min_val}) cannot exceed split_count_max ({max_val})",
                {
                    "min_val": self.split_count_min,
                    "max_val": self.split_count_max,
                },
            )
        return self


# ---------------------------------------------------------------------------
# Hard Encoding Chains Pool
# ---------------------------------------------------------------------------

HARD_ENCODING_CHAINS: list[list[str]] = [
    ["base64", "hex"],
    ["rot13", "base64"],
    ["hex", "base64"],
    ["hex", "rot13", "base64"],
    ["base64", "rot13"],
    ["rot13", "hex"],
]


# ---------------------------------------------------------------------------
# Preset Constants
# ---------------------------------------------------------------------------

EASY = DifficultyPreset(
    name="easy",
    encoding_chain=["plaintext"],
    noise_ratio=0.2,
    packet_count_min=20,
    packet_count_max=50,
    noise_types=["ARP"],
    timing_jitter_ms=(10.0, 50.0),
    split_count_min=1,
    split_count_max=1,
)

MEDIUM = DifficultyPreset(
    name="medium",
    encoding_chain=["base64"],
    noise_ratio=0.6,
    packet_count_min=200,
    packet_count_max=500,
    noise_types=["ARP", "DNS"],
    timing_jitter_ms=(5.0, 200.0),
    split_count_min=2,
    split_count_max=2,
)

HARD = DifficultyPreset(
    name="hard",
    encoding_chain=["base64", "hex"],
    noise_ratio=0.85,
    packet_count_min=1000,
    packet_count_max=5000,
    noise_types=["ARP", "DNS", "HTTP", "ICMP"],
    timing_jitter_ms=(1.0, 500.0),
    split_count_min=3,
    split_count_max=4,
)

# Lookup table for preset resolution
_PRESETS: dict[str, DifficultyPreset] = {
    "easy": EASY,
    "medium": MEDIUM,
    "hard": HARD,
}


# ---------------------------------------------------------------------------
# Difficulty Resolution
# ---------------------------------------------------------------------------


def resolve_difficulty(
    difficulty: str | None,
    overrides: dict | None = None,
) -> dict | None:
    """Resolve a difficulty name to a parameter dict with optional overrides.

    Args:
        difficulty: Preset name ("easy", "medium", "hard") or None for manual mode.
        overrides: Optional dict of parameter overrides to merge on top.

    Returns:
        Dict with keys: encoding_chain, noise_ratio, packet_count_target,
        noise_types, timing_jitter_ms. Or None if difficulty is None.

    Raises:
        KeyError: If difficulty name is not a valid preset.
    """
    if difficulty is None:
        return None

    key = difficulty.lower()
    if key not in _PRESETS:
        raise KeyError(
            f"Unknown difficulty '{difficulty}'. "
            f"Available: {', '.join(sorted(_PRESETS.keys()))}"
        )

    preset = _PRESETS[key]

    # Randomize packet_count_target within preset range
    packet_count_target = random.randint(
        preset.packet_count_min, preset.packet_count_max
    )

    # Randomize split_count within preset range
    split_count = random.randint(preset.split_count_min, preset.split_count_max)

    # For hard preset without encoding_chain override: random selection from pool
    if key == "hard" and (overrides is None or "encoding_chain" not in overrides):
        encoding_chain = random.choice(HARD_ENCODING_CHAINS)
    else:
        encoding_chain = list(preset.encoding_chain)

    result = {
        "encoding_chain": encoding_chain,
        "noise_ratio": preset.noise_ratio,
        "packet_count_target": packet_count_target,
        "noise_types": list(preset.noise_types),
        "timing_jitter_ms": preset.timing_jitter_ms,
        "split_count": split_count,
    }

    # Merge overrides
    if overrides:
        for k, v in overrides.items():
            if k == "packet_count":
                result["packet_count_target"] = v
            else:
                result[k] = v

    logger.info(
        "difficulty_resolved",
        difficulty=key,
        has_overrides=overrides is not None,
        packet_count_target=result["packet_count_target"],
    )

    return result
