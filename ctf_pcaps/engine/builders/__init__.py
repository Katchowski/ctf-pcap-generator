"""Auto-discovery of builder modules in the builders package.

On import, all modules in this package are automatically imported,
which triggers any @register_builder decorators they contain.
This means adding a new builder file is sufficient for registration --
no manual import list to maintain.
"""

import importlib
import pkgutil

import structlog

logger = structlog.get_logger()


def _discover_builders():
    """Auto-import all modules in the builders package.

    Uses pkgutil.iter_modules to find all submodules and imports them.
    This triggers @register_builder decorators on any builder classes.
    """
    package_path = __path__
    package_name = __name__
    for module_info in pkgutil.iter_modules(package_path, f"{package_name}."):
        try:
            importlib.import_module(module_info.name)
            logger.debug("builder_module_imported", module=module_info.name)
        except Exception:
            logger.exception("builder_module_import_failed", module=module_info.name)


_discover_builders()
