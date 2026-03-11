"""YAML template loading with !include support and Jinja2 variable resolution.

Loads YAML scenario templates, resolves !include tags relative to the
including file's directory, and resolves {{ param }} template variables
using Jinja2 NativeEnvironment (returns native Python types).

No Flask imports allowed in engine modules.
"""

from pathlib import Path
from typing import Any

import yaml
from jinja2 import StrictUndefined, Undefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import ValidationError

from ctf_pcaps.engine.models import ScenarioTemplate

# Standalone Jinja2 environment -- no Flask dependency
_env = NativeEnvironment(undefined=StrictUndefined)


class IncludeLoader(yaml.SafeLoader):
    """YAML SafeLoader subclass with !include support.

    Never modifies the global SafeLoader -- each instance is bound
    to a base directory for relative path resolution.
    """


def _include_constructor(loader: IncludeLoader, node: yaml.Node) -> Any:
    """Load another YAML file referenced by !include tag.

    Resolves the path relative to the including file's directory.
    Raises FileNotFoundError with a clear message if the file does not exist.
    """
    relative_path = loader.construct_scalar(node)
    full_path = loader._base_dir / relative_path
    if not full_path.exists():
        raise FileNotFoundError(
            f"!include file not found: {relative_path} (resolved to {full_path})"
        )
    with open(full_path) as f:
        return yaml.load(f, Loader=_make_loader(full_path.parent))


def _make_loader(base_dir: Path) -> type:
    """Create an IncludeLoader subclass bound to a specific base directory.

    Each call returns a fresh class so different files can have different
    base directories without interfering with each other.
    """

    class BoundLoader(IncludeLoader):
        _base_dir = base_dir

    BoundLoader.add_constructor("!include", _include_constructor)
    return BoundLoader


def load_template(template_path: Path) -> dict:
    """Load a YAML template file with !include support.

    Args:
        template_path: Path to the YAML template file.

    Returns:
        Parsed YAML content as a dict.

    Raises:
        FileNotFoundError: If template_path or any !include target does not exist.
    """
    template_path = Path(template_path)
    loader_cls = _make_loader(template_path.parent)
    with open(template_path) as f:
        return yaml.load(f, Loader=loader_cls)


def _resolve_value(value: Any, parameters: dict) -> Any:
    """Resolve a single value, handling strings with {{ }} templates."""
    if isinstance(value, str) and "{{" in value:
        try:
            tmpl = _env.from_string(value)
            result = tmpl.render(**parameters)
        except UndefinedError as e:
            raise ValueError(f"Undefined template variable: {e}") from e
        # NativeEnvironment may return an Undefined object for
        # single-variable templates instead of raising. Check explicitly.
        if isinstance(result, Undefined):
            raise ValueError(f"Undefined template variable in '{value}'")
        return result
    elif isinstance(value, dict):
        return resolve_variables(value, parameters)
    elif isinstance(value, list):
        return [_resolve_value(item, parameters) for item in value]
    return value


def resolve_variables(template_data: dict, parameters: dict) -> dict:
    """Resolve {{ param }} variables in template values.

    Uses Jinja2 NativeEnvironment to return native Python types
    (int, list, etc.) rather than strings.

    Args:
        template_data: Dict with potential {{ var }} strings.
        parameters: Dict of variable names to values.

    Returns:
        New dict with all {{ var }} references resolved.

    Raises:
        ValueError: If a referenced variable is not in parameters.
    """
    resolved = {}
    for key, value in template_data.items():
        resolved[key] = _resolve_value(value, parameters)
    return resolved


def validate_template(
    raw_data: dict,
) -> ScenarioTemplate | list[dict]:
    """Validate raw YAML data against the ScenarioTemplate schema.

    Args:
        raw_data: Dict parsed from YAML.

    Returns:
        ScenarioTemplate on success, or a list of structured error dicts
        on failure. Each error dict has: field, error_type, message.
    """
    try:
        return ScenarioTemplate.model_validate(raw_data)
    except ValidationError as e:
        return [
            {
                "field": str(error["loc"]),
                "error_type": error["type"],
                "message": error["msg"],
            }
            for error in e.errors()
        ]


def validate_parameters(template: ScenarioTemplate, overrides: dict) -> list[dict]:
    """Second-pass validation of parameter overrides against constraints.

    Checks that override values fall within the parameter's min/max/choices
    constraints defined in the template.

    Args:
        template: Validated ScenarioTemplate with parameter definitions.
        overrides: Dict of parameter name -> override value.

    Returns:
        List of error dicts (empty if all valid). Each error has:
        field, error_type, message.
    """
    errors = []
    for name, value in overrides.items():
        if name not in template.parameters:
            continue
        param_def = template.parameters[name]
        if param_def.min is not None and value < param_def.min:
            errors.append(
                {
                    "field": name,
                    "error_type": "value_below_minimum",
                    "message": (f"Value {value} is below minimum {param_def.min}"),
                }
            )
        if param_def.max is not None and value > param_def.max:
            errors.append(
                {
                    "field": name,
                    "error_type": "value_above_maximum",
                    "message": (f"Value {value} is above maximum {param_def.max}"),
                }
            )
        if param_def.choices is not None and value not in param_def.choices:
            errors.append(
                {
                    "field": name,
                    "error_type": "invalid_choice",
                    "message": (
                        f"Value '{value}' is not in allowed choices: "
                        f"{param_def.choices}"
                    ),
                }
            )
    return errors
