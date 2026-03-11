"""Builder registry with decorator-based registration.

Provides @register_builder for registering builder classes and get_builder
for looking them up by name and optional version. Supports multiple versions
of the same builder name.

No Flask imports allowed in engine modules.
"""

import copy

import structlog

logger = structlog.get_logger()

_REGISTRY: dict[str, dict[int, type]] = {}


def register_builder(name: str, version: int = 1):
    """Decorator to register a builder class by name and version.

    Args:
        name: Unique builder name (e.g., "simple_tcp").
        version: Version number (default 1). Templates can pin versions.

    Raises:
        ValueError: If name+version combination is already registered.
    """

    def decorator(cls):
        if name not in _REGISTRY:
            _REGISTRY[name] = {}
        if version in _REGISTRY[name]:
            raise ValueError(f"Builder '{name}' version {version} already registered")
        _REGISTRY[name][version] = cls
        logger.debug(
            "builder_registered", builder=name, version=version, cls=cls.__name__
        )
        return cls

    return decorator


def get_builder(name: str, version: int | None = None) -> type:
    """Look up a builder by name and optional version.

    Args:
        name: Builder name to look up.
        version: Specific version number. If None, returns the latest
                 (highest version number).

    Returns:
        The registered builder class.

    Raises:
        KeyError: If the builder name or version is not found.
    """
    if name not in _REGISTRY:
        raise KeyError(f"No builder registered with name '{name}'")
    versions = _REGISTRY[name]
    if version is None:
        version = max(versions.keys())
    if version not in versions:
        raise KeyError(
            f"Builder '{name}' has no version {version}. "
            f"Available: {sorted(versions.keys())}"
        )
    return versions[version]


def get_all_builders() -> dict[str, dict[int, type]]:
    """Return a copy of all registered builders.

    Returns:
        Dict mapping builder names to dicts of version -> class.
    """
    return copy.deepcopy(_REGISTRY)


def clear_registry() -> None:
    """Clear all registered builders. Used for test isolation."""
    _REGISTRY.clear()
