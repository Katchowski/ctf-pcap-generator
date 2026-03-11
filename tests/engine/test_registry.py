"""Tests for the builder registry, BaseBuilder ABC, and auto-discovery.

Verifies decorator-based registration, version lookup, error handling,
and pkgutil-based auto-discovery of builder modules.
"""

from abc import ABC
from collections.abc import Iterator

import pytest

from ctf_pcaps.engine.registry import (
    clear_registry,
    get_all_builders,
    get_builder,
    register_builder,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Clear the builder registry before and after each test."""
    clear_registry()
    yield
    clear_registry()


class TestRegisterBuilder:
    """Tests for the @register_builder decorator."""

    def test_decorator_registers_class(self):
        """@register_builder adds a class to the registry."""

        @register_builder("test_builder", version=1)
        class TestBuilder:
            pass

        result = get_builder("test_builder")
        assert result is TestBuilder

    def test_duplicate_name_version_raises(self):
        """Registering the same name+version twice raises ValueError."""

        @register_builder("dup_builder", version=1)
        class Builder1:
            pass

        with pytest.raises(ValueError, match="already registered"):

            @register_builder("dup_builder", version=1)
            class Builder2:
                pass

    def test_different_versions_allowed(self):
        """Same name with different versions can be registered."""

        @register_builder("versioned", version=1)
        class V1Builder:
            pass

        @register_builder("versioned", version=2)
        class V2Builder:
            pass

        assert get_builder("versioned", version=1) is V1Builder
        assert get_builder("versioned", version=2) is V2Builder


class TestGetBuilder:
    """Tests for get_builder lookup."""

    def test_get_by_name_returns_class(self):
        """get_builder(name) returns the registered class."""

        @register_builder("lookup_test", version=1)
        class LookupBuilder:
            pass

        assert get_builder("lookup_test") is LookupBuilder

    def test_get_by_name_and_version(self):
        """get_builder(name, version) returns the specific version."""

        @register_builder("multi_ver", version=1)
        class V1:
            pass

        @register_builder("multi_ver", version=2)
        class V2:
            pass

        assert get_builder("multi_ver", version=1) is V1
        assert get_builder("multi_ver", version=2) is V2

    def test_no_version_returns_latest(self):
        """get_builder with no version returns the latest (highest version)."""

        @register_builder("latest_test", version=1)
        class V1:
            pass

        @register_builder("latest_test", version=3)
        class V3:
            pass

        @register_builder("latest_test", version=2)
        class V2:
            pass

        # Should return V3 (highest version)
        assert get_builder("latest_test") is V3

    def test_nonexistent_name_raises_keyerror(self):
        """get_builder('nonexistent') raises KeyError with descriptive message."""
        with pytest.raises(KeyError, match="nonexistent"):
            get_builder("nonexistent")

    def test_nonexistent_version_raises_keyerror(self):
        """get_builder with nonexistent version raises KeyError."""

        @register_builder("ver_test", version=1)
        class V1:
            pass

        with pytest.raises(KeyError, match="version 99"):
            get_builder("ver_test", version=99)


class TestGetAllBuilders:
    """Tests for get_all_builders."""

    def test_returns_dict_of_all_registered(self):
        """get_all_builders() returns a dict of all registered builders."""

        @register_builder("builder_a", version=1)
        class A:
            pass

        @register_builder("builder_b", version=1)
        class B:
            pass

        all_builders = get_all_builders()
        assert "builder_a" in all_builders
        assert "builder_b" in all_builders
        assert all_builders["builder_a"][1] is A
        assert all_builders["builder_b"][1] is B

    def test_returns_copy_not_reference(self):
        """get_all_builders returns a copy, not the internal registry."""

        @register_builder("copy_test", version=1)
        class C:
            pass

        all_builders = get_all_builders()
        all_builders.pop("copy_test")
        # Internal registry should still have it
        assert get_builder("copy_test") is C


class TestBaseBuilder:
    """Tests for the BaseBuilder ABC."""

    def test_is_abstract_class(self):
        """BaseBuilder is an ABC."""
        from ctf_pcaps.engine.builders.base import BaseBuilder

        assert issubclass(BaseBuilder, ABC)

    def test_has_abstract_build_method(self):
        """BaseBuilder has abstract method build(self, params, steps, callback)."""
        from ctf_pcaps.engine.builders.base import BaseBuilder

        assert "build" in BaseBuilder.__abstractmethods__

    def test_cannot_instantiate_directly(self):
        """BaseBuilder cannot be instantiated without implementing build()."""
        from ctf_pcaps.engine.builders.base import BaseBuilder

        with pytest.raises(TypeError):
            BaseBuilder()

    def test_concrete_subclass_instantiable(self):
        """A concrete subclass implementing build() can be instantiated."""
        from ctf_pcaps.engine.builders.base import BaseBuilder

        class ConcreteBuilder(BaseBuilder):
            def build(self, params: dict, steps: list[dict], callback=None) -> Iterator:
                yield "packet"

        builder = ConcreteBuilder()
        packets = list(builder.build({}, []))
        assert packets == ["packet"]


class TestAutoDiscovery:
    """Tests for auto-discovery of builder modules."""

    def test_discover_builders_runs_without_error(self):
        """Auto-discovery imports modules from builders/ without error."""
        from ctf_pcaps.engine.builders import _discover_builders

        # Should not raise
        _discover_builders()

    def test_decorated_class_registered_after_decorator(self):
        """A manually decorated class is registered after decorator executes."""

        # This verifies the registration mechanism works with the decorator
        @register_builder("auto_disc_test", version=1)
        class DiscoveryTestBuilder:
            pass

        all_builders = get_all_builders()
        assert "auto_disc_test" in all_builders
        assert all_builders["auto_disc_test"][1] is DiscoveryTestBuilder
