"""PCAP generation engine.

Public API:
  generate(template_path, output_dir, ...) -> GenerationResult | list[dict]
  dry_run(template_path, ...) -> dict | list[dict]
  load_template(path) -> dict
  validate_template(data) -> ScenarioTemplate | list[dict]
  assemble_flag(inner_text, wrapper) -> str
  DifficultyPreset -- Pydantic model for difficulty presets
  resolve_difficulty(difficulty, overrides) -> dict | None
"""

from ctf_pcaps.engine.difficulty import DifficultyPreset, resolve_difficulty
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
    "resolve_difficulty",
]
