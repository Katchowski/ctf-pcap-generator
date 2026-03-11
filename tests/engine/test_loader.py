"""Tests for YAML template loading with !include and Jinja2 variable resolution."""

import pytest

from ctf_pcaps.engine.loader import (
    load_template,
    resolve_variables,
    validate_parameters,
    validate_template,
)


class TestLoadTemplate:
    """Tests for load_template() YAML loading with !include support."""

    def test_loads_yaml_file_returns_dict(self, tmp_path):
        """load_template() reads a YAML file and returns a parsed dict."""
        yaml_file = tmp_path / "simple.yaml"
        yaml_file.write_text(
            "builder: simple_tcp\n"
            "protocol: tcp\n"
            "steps:\n"
            "  - action: handshake\n"
        )
        result = load_template(yaml_file)
        assert isinstance(result, dict)
        assert result["builder"] == "simple_tcp"
        assert result["protocol"] == "tcp"
        assert result["steps"] == [{"action": "handshake"}]

    def test_resolves_include_tag(self, tmp_path):
        """load_template() resolves !include tags by loading the referenced file."""
        fragment = tmp_path / "fragment.yaml"
        fragment.write_text("action: handshake\nport: 80\n")

        main = tmp_path / "main.yaml"
        main.write_text(
            "builder: simple_tcp\n"
            "protocol: tcp\n"
            "defaults: !include fragment.yaml\n"
        )

        result = load_template(main)
        assert result["defaults"] == {"action": "handshake", "port": 80}

    def test_nested_include(self, tmp_path):
        """load_template() resolves nested !include (A -> B -> C)."""
        file_c = tmp_path / "c.yaml"
        file_c.write_text("timeout: 30\n")

        file_b = tmp_path / "b.yaml"
        file_b.write_text("retry: 3\ninner: !include c.yaml\n")

        file_a = tmp_path / "a.yaml"
        file_a.write_text("builder: test\nouter: !include b.yaml\n")

        result = load_template(file_a)
        assert result["outer"]["retry"] == 3
        assert result["outer"]["inner"]["timeout"] == 30

    def test_missing_include_raises_file_not_found(self, tmp_path):
        """load_template() raises FileNotFoundError for nonexistent !include."""
        main = tmp_path / "main.yaml"
        main.write_text("data: !include nonexistent.yaml\n")

        with pytest.raises(FileNotFoundError, match="nonexistent.yaml"):
            load_template(main)

    def test_include_relative_to_including_file(self, tmp_path):
        """!include resolves relative to the including file's directory."""
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        fragment = subdir / "fragment.yaml"
        fragment.write_text("value: 42\n")

        main = subdir / "main.yaml"
        main.write_text("data: !include fragment.yaml\n")

        result = load_template(main)
        assert result["data"]["value"] == 42


class TestResolveVariables:
    """Tests for resolve_variables() Jinja2 template variable resolution."""

    def test_resolves_string_variable(self):
        """resolve_variables() replaces {{ var }} with the actual value."""
        data = {"host": "{{ target_host }}"}
        params = {"target_host": "10.0.0.1"}
        result = resolve_variables(data, params)
        assert result["host"] == "10.0.0.1"

    def test_returns_native_int(self):
        """resolve_variables() returns native int, not string."""
        data = {"count": "{{ packet_count }}"}
        params = {"packet_count": 42}
        result = resolve_variables(data, params)
        assert result["count"] == 42
        assert isinstance(result["count"], int)

    def test_returns_native_list(self):
        """resolve_variables() returns native list from variable."""
        data = {"ports": "{{ port_list }}"}
        params = {"port_list": [80, 443, 8080]}
        result = resolve_variables(data, params)
        assert result["ports"] == [80, 443, 8080]
        assert isinstance(result["ports"], list)

    def test_handles_nested_dicts(self):
        """resolve_variables() processes nested dicts recursively."""
        data = {
            "outer": {
                "inner": "{{ value }}",
                "static": "unchanged",
            }
        }
        params = {"value": "resolved"}
        result = resolve_variables(data, params)
        assert result["outer"]["inner"] == "resolved"
        assert result["outer"]["static"] == "unchanged"

    def test_handles_lists_with_dicts(self):
        """resolve_variables() processes lists containing dicts."""
        data = {
            "steps": [
                {"action": "connect", "port": "{{ port }}"},
                {"action": "send", "data": "hello"},
            ]
        }
        params = {"port": 8080}
        result = resolve_variables(data, params)
        assert result["steps"][0]["port"] == 8080
        assert result["steps"][1]["data"] == "hello"

    def test_leaves_non_template_values_unchanged(self):
        """resolve_variables() leaves values without {{ }} unchanged."""
        data = {"static": "no templates here", "number": 42, "flag": True}
        params = {}
        result = resolve_variables(data, params)
        assert result["static"] == "no templates here"
        assert result["number"] == 42
        assert result["flag"] is True

    def test_missing_variable_raises_error(self):
        """resolve_variables() raises error for missing variable."""
        data = {"value": "{{ undefined_var }}"}
        params = {"other_var": "exists"}
        with pytest.raises((ValueError, Exception), match="undefined_var"):
            resolve_variables(data, params)

    def test_resolves_list_items_with_templates(self):
        """resolve_variables() resolves string items in lists."""
        data = {"items": ["{{ a }}", "static", "{{ b }}"]}
        params = {"a": "first", "b": "third"}
        result = resolve_variables(data, params)
        assert result["items"] == ["first", "static", "third"]


class TestValidateTemplate:
    """Tests for validate_template() Pydantic schema validation."""

    def test_valid_template_returns_model(self):
        """validate_template() returns ScenarioTemplate on valid input."""
        from ctf_pcaps.engine.models import ScenarioTemplate

        raw = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "handshake"}],
        }
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.builder == "simple_tcp"

    def test_invalid_template_returns_error_list(self):
        """validate_template() returns structured error list on invalid input."""
        raw = {"steps": "not_a_list"}  # missing builder, protocol; steps wrong type
        result = validate_template(raw)
        assert isinstance(result, list)
        assert len(result) > 0
        # Each error has field, error_type, message
        for error in result:
            assert "field" in error
            assert "error_type" in error
            assert "message" in error

    def test_invalid_template_collects_all_errors(self):
        """validate_template() collects all validation errors, not just first."""
        raw = {}  # missing builder, protocol, steps
        result = validate_template(raw)
        assert isinstance(result, list)
        # Should have errors for builder, protocol, and steps at minimum
        fields = [e["field"] for e in result]
        assert any("builder" in f for f in fields)
        assert any("protocol" in f for f in fields)
        assert any("steps" in f for f in fields)


class TestValidateParameters:
    """Tests for validate_parameters() second-pass parameter validation."""

    def test_valid_parameters_return_empty_list(self):
        """validate_parameters() returns empty list for valid overrides."""
        from ctf_pcaps.engine.models import ScenarioTemplate

        template = ScenarioTemplate(
            builder="test",
            protocol="tcp",
            steps=[{"action": "test"}],
            parameters={
                "port": {"default": 80, "min": 1, "max": 65535},
            },
        )
        errors = validate_parameters(template, {"port": 8080})
        assert errors == []

    def test_out_of_range_min(self):
        """validate_parameters() catches values below min."""
        from ctf_pcaps.engine.models import ScenarioTemplate

        template = ScenarioTemplate(
            builder="test",
            protocol="tcp",
            steps=[{"action": "test"}],
            parameters={
                "port": {"default": 80, "min": 1, "max": 65535},
            },
        )
        errors = validate_parameters(template, {"port": 0})
        assert len(errors) == 1
        assert "port" in errors[0]["field"]

    def test_out_of_range_max(self):
        """validate_parameters() catches values above max."""
        from ctf_pcaps.engine.models import ScenarioTemplate

        template = ScenarioTemplate(
            builder="test",
            protocol="tcp",
            steps=[{"action": "test"}],
            parameters={
                "port": {"default": 80, "min": 1, "max": 65535},
            },
        )
        errors = validate_parameters(template, {"port": 70000})
        assert len(errors) == 1
        assert "port" in errors[0]["field"]

    def test_invalid_choice(self):
        """validate_parameters() catches values not in choices."""
        from ctf_pcaps.engine.models import ScenarioTemplate

        template = ScenarioTemplate(
            builder="test",
            protocol="tcp",
            steps=[{"action": "test"}],
            parameters={
                "mode": {"default": "fast", "choices": ["fast", "slow"]},
            },
        )
        errors = validate_parameters(template, {"mode": "turbo"})
        assert len(errors) == 1
        assert "mode" in errors[0]["field"]

    def test_unknown_parameter_ignored(self):
        """validate_parameters() ignores parameters not defined in template."""
        from ctf_pcaps.engine.models import ScenarioTemplate

        template = ScenarioTemplate(
            builder="test",
            protocol="tcp",
            steps=[{"action": "test"}],
            parameters={},
        )
        errors = validate_parameters(template, {"unknown": "value"})
        assert errors == []
