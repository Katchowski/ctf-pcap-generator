"""PCAP generation engine.

Public API:
  generate(template_path, output_dir, ...) -> GenerationResult | list[dict]
  dry_run(template_path, ...) -> dict | list[dict]
  load_template(path) -> dict
  validate_template(data) -> ScenarioTemplate | list[dict]
  assemble_flag(inner_text, wrapper) -> str
  DifficultyPreset -- Pydantic model for difficulty presets
  CustomDifficultyParams -- Pydantic model for custom difficulty parameters
  resolve_difficulty(difficulty, overrides) -> dict | None
  resolve_custom_difficulty(params) -> dict | None
  get_available_encodings() -> list[str]
  get_available_noise_types() -> list[str]
  get_custom_defaults() -> dict
"""

from ctf_pcaps.engine.difficulty import (
    CustomDifficultyParams,
    DifficultyPreset,
    get_available_encodings,
    get_available_noise_types,
    get_custom_defaults,
    resolve_custom_difficulty,
    resolve_difficulty,
)
from ctf_pcaps.engine.flag import assemble_flag
from ctf_pcaps.engine.loader import load_template, validate_template
from ctf_pcaps.engine.models import GenerationResult, ScenarioTemplate
from ctf_pcaps.engine.pipeline import dry_run, generate

__all__ = [
    "generate",
    "dry_run",
    "load_template",
    "validate_template",
    "GenerationResult",
    "ScenarioTemplate",
    "assemble_flag",
    "DifficultyPreset",
    "CustomDifficultyParams",
    "resolve_difficulty",
    "resolve_custom_difficulty",
    "get_available_encodings",
    "get_available_noise_types",
    "get_custom_defaults",
]
