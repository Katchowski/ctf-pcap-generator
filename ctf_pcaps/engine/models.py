"""Pydantic v2 models for YAML scenario template validation.

Defines the contract between YAML templates and the builder system.
All models use Pydantic v2 syntax (ConfigDict, model_validator).

No Flask imports allowed in engine modules.
"""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic_core import PydanticCustomError


class ParameterDef(BaseModel):
    """Definition of a configurable template parameter.

    Validates that min <= max when both are provided.
    Extra fields are forbidden to catch typos in templates.
    """

    model_config = ConfigDict(extra="forbid")

    default: int | float | str | list | bool
    min: int | float | None = None
    max: int | float | None = None
    choices: list[str] | None = None
    description: str = ""

    @model_validator(mode="after")
    def validate_range(self):
        """Ensure min does not exceed max."""
        if self.min is not None and self.max is not None and self.min > self.max:
            raise PydanticCustomError(
                "invalid_range",
                "min ({min_val}) cannot exceed max ({max_val})",
                {"min_val": self.min, "max_val": self.max},
            )
        return self


class Step(BaseModel):
    """A single step in the scenario template.

    Requires an 'action' field but allows arbitrary extra fields
    for step-specific parameters.
    """

    model_config = ConfigDict(extra="allow")

    action: str


class ScenarioCategory(StrEnum):
    """Categories for scenario classification.

    Used for grouping scenarios in the UI and CTFd integration.
    """

    NETWORK_ATTACK = "network_attack"
    WEB_TRAFFIC = "web_traffic"
    COVERT_CHANNEL = "covert_channel"
    MALWARE_C2 = "malware_c2"


class DifficultyHint(StrEnum):
    """Suggested difficulty level for a scenario template.

    This is a hint from the template author, not the same as the
    difficulty engine preset (easy/medium/hard in Phase 04).
    """

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class ScenarioMetadata(BaseModel):
    """Optional metadata section for scenario templates.

    All fields are optional so templates can include as much or
    as little metadata as desired. Extra fields are forbidden.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    category: ScenarioCategory | None = None
    difficulty_hint: DifficultyHint | None = None


class ScenarioTemplate(BaseModel):
    """Top-level YAML scenario template schema.

    Validates the structure of a scenario template loaded from YAML.
    Extra fields are forbidden to catch structural mistakes early.
    """

    model_config = ConfigDict(extra="forbid")

    builder: str
    builder_version: int | None = None
    protocol: str
    parameters: dict[str, ParameterDef] = {}
    steps: list[Step]
    metadata: ScenarioMetadata | None = None


@dataclass
class GenerationResult:
    """Result of a PCAP generation operation.

    Uses stdlib dataclass (not Pydantic) since this is an output
    container, not a validation model.
    """

    file_path: Path
    packet_count: int
    file_size_bytes: int
    generation_duration_ms: float
    builder_used: str
    template_name: str
    flag_text: str | None = None
    flag_encoding: str | None = None
    flag_verified: bool | None = None
    solve_steps: list[str] = field(default_factory=list)
    # Difficulty engine fields (Phase 04)
    difficulty_preset: str | None = None
    noise_ratio: float | None = None
    packet_count_target: int | None = None
    noise_types: list[str] = field(default_factory=list)
    timing_jitter_ms: tuple[float, float] | None = None
    encoding_chain: list[str] = field(default_factory=list)
