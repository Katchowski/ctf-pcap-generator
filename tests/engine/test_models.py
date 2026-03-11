"""Tests for Pydantic v2 scenario template models and config extensions.

Verifies that ScenarioTemplate, ParameterDef, Step, GenerationResult,
ScenarioMetadata, ScenarioCategory, and DifficultyHint correctly
validate, reject, and hold template data.
"""

from dataclasses import fields as dataclass_fields
from pathlib import Path

import pytest
from pydantic import ValidationError

from ctf_pcaps.engine.models import (
    DifficultyHint,
    GenerationResult,
    ParameterDef,
    ScenarioCategory,
    ScenarioTemplate,
    Step,
)


class TestScenarioTemplate:
    """Tests for the top-level ScenarioTemplate model."""

    def test_valid_template_accepted(self):
        """ScenarioTemplate.model_validate() accepts a valid template dict."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "port": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                }
            },
            "steps": [{"action": "syn_probe", "ports": "{{ port }}"}],
        }
        template = ScenarioTemplate.model_validate(data)
        assert template.builder == "simple_tcp"
        assert template.protocol == "tcp"
        assert len(template.steps) == 1
        assert "port" in template.parameters

    def test_missing_builder_rejected(self):
        """ScenarioTemplate rejects a dict missing required field 'builder'."""
        data = {
            "protocol": "tcp",
            "steps": [{"action": "syn_probe"}],
        }
        with pytest.raises(ValidationError) as exc_info:
            ScenarioTemplate.model_validate(data)
        errors = exc_info.value.errors()
        field_locs = [e["loc"] for e in errors]
        assert ("builder",) in field_locs

    def test_extra_fields_rejected(self):
        """ScenarioTemplate rejects extra fields (extra='forbid')."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "syn_probe"}],
            "unknown_field": "should fail",
        }
        with pytest.raises(ValidationError) as exc_info:
            ScenarioTemplate.model_validate(data)
        errors = exc_info.value.errors()
        assert any("unknown_field" in str(e["loc"]) for e in errors)

    def test_collects_all_validation_errors(self):
        """ScenarioTemplate collects ALL errors when multiple fields invalid."""
        data = {
            "unknown_extra": "bad",
            # Missing 'builder', 'protocol', 'steps' -- all required
        }
        with pytest.raises(ValidationError) as exc_info:
            ScenarioTemplate.model_validate(data)
        errors = exc_info.value.errors()
        # Should have at least 3 errors: missing builder, missing protocol,
        # missing steps, plus extra field
        assert len(errors) >= 3


class TestParameterDef:
    """Tests for ParameterDef model validation."""

    def test_min_greater_than_max_rejected(self):
        """ParameterDef rejects min > max with PydanticCustomError."""
        data = {
            "default": 100,
            "min": 65535,
            "max": 1,
        }
        with pytest.raises(ValidationError) as exc_info:
            ParameterDef.model_validate(data)
        errors = exc_info.value.errors()
        assert len(errors) >= 1
        error = errors[0]
        assert "min" in error["msg"].lower() or "max" in error["msg"].lower()

    def test_valid_range_accepted(self):
        """ParameterDef accepts valid range (min=1, max=65535)."""
        data = {
            "default": 80,
            "min": 1,
            "max": 65535,
        }
        param = ParameterDef.model_validate(data)
        assert param.min == 1
        assert param.max == 65535
        assert param.default == 80


class TestStep:
    """Tests for Step model."""

    def test_accepts_action_plus_extras(self):
        """Step accepts an action field plus arbitrary extra fields."""
        data = {
            "action": "syn_probe",
            "ports": "{{ port_range }}",
            "timeout": 5,
        }
        step = Step.model_validate(data)
        assert step.action == "syn_probe"
        # Extra fields accessible via model_extra
        assert step.model_extra["ports"] == "{{ port_range }}"
        assert step.model_extra["timeout"] == 5


class TestGenerationResult:
    """Tests for GenerationResult dataclass."""

    def test_instantiation(self):
        """GenerationResult holds all required fields."""
        result = GenerationResult(
            file_path=Path("/app/output/abc123.pcap"),
            packet_count=42,
            file_size_bytes=1024,
            generation_duration_ms=150.5,
            builder_used="simple_tcp",
            template_name="syn_scan",
        )
        assert result.file_path == Path("/app/output/abc123.pcap")
        assert result.packet_count == 42
        assert result.file_size_bytes == 1024
        assert result.generation_duration_ms == 150.5
        assert result.builder_used == "simple_tcp"
        assert result.template_name == "syn_scan"

    def test_is_dataclass(self):
        """GenerationResult is a dataclass with the expected fields."""
        field_names = {f.name for f in dataclass_fields(GenerationResult)}
        expected = {
            "file_path",
            "packet_count",
            "file_size_bytes",
            "generation_duration_ms",
            "builder_used",
            "template_name",
            "flag_text",
            "flag_encoding",
            "flag_verified",
            "solve_steps",
            "difficulty_preset",
            "noise_ratio",
            "packet_count_target",
            "noise_types",
            "timing_jitter_ms",
            "encoding_chain",
        }
        assert field_names == expected

    def test_difficulty_fields_default_to_none_or_empty(self):
        """New difficulty fields default to None/empty."""
        result = GenerationResult(
            file_path=Path("/app/output/test.pcap"),
            packet_count=10,
            file_size_bytes=512,
            generation_duration_ms=50.0,
            builder_used="simple_tcp",
            template_name="test",
        )
        assert result.difficulty_preset is None
        assert result.noise_ratio is None
        assert result.packet_count_target is None
        assert result.noise_types == []
        assert result.timing_jitter_ms is None
        assert result.encoding_chain == []

    def test_difficulty_fields_accept_values(self):
        """GenerationResult accepts difficulty fields alongside existing fields."""
        result = GenerationResult(
            file_path=Path("/app/output/test.pcap"),
            packet_count=100,
            file_size_bytes=4096,
            generation_duration_ms=200.0,
            builder_used="simple_tcp",
            template_name="test",
            difficulty_preset="hard",
            noise_ratio=0.85,
            packet_count_target=3000,
            noise_types=["ARP", "DNS", "HTTP", "ICMP"],
            timing_jitter_ms=(1.0, 500.0),
            encoding_chain=["base64", "hex"],
        )
        assert result.difficulty_preset == "hard"
        assert result.noise_ratio == 0.85
        assert result.packet_count_target == 3000
        assert result.noise_types == ["ARP", "DNS", "HTTP", "ICMP"]
        assert result.timing_jitter_ms == (1.0, 500.0)
        assert result.encoding_chain == ["base64", "hex"]


class TestScenarioMetadata:
    """Tests for ScenarioMetadata, ScenarioCategory, and DifficultyHint."""

    def test_metadata_with_all_fields_validates(self):
        """ScenarioTemplate with metadata containing all fields validates."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "send_data"}],
            "metadata": {
                "name": "Test Scenario",
                "description": "A test scenario",
                "category": "network_attack",
                "difficulty_hint": "medium",
            },
        }
        template = ScenarioTemplate.model_validate(data)
        assert template.metadata is not None
        assert template.metadata.name == "Test Scenario"
        assert template.metadata.description == "A test scenario"
        assert template.metadata.category == ScenarioCategory.NETWORK_ATTACK
        assert template.metadata.difficulty_hint == DifficultyHint.MEDIUM

    def test_metadata_with_partial_fields_validates(self):
        """ScenarioTemplate with metadata containing only some fields validates."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "send_data"}],
            "metadata": {
                "name": "Partial Metadata",
            },
        }
        template = ScenarioTemplate.model_validate(data)
        assert template.metadata is not None
        assert template.metadata.name == "Partial Metadata"
        assert template.metadata.description is None
        assert template.metadata.category is None
        assert template.metadata.difficulty_hint is None

    def test_template_without_metadata_validates(self):
        """ScenarioTemplate without metadata section validates (backward compatible)."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "send_data"}],
        }
        template = ScenarioTemplate.model_validate(data)
        assert template.metadata is None

    def test_invalid_category_rejected(self):
        """ScenarioCategory enum rejects invalid category string."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "send_data"}],
            "metadata": {
                "category": "invalid_cat",
            },
        }
        with pytest.raises(ValidationError):
            ScenarioTemplate.model_validate(data)

    def test_invalid_difficulty_rejected(self):
        """DifficultyHint enum rejects invalid difficulty string."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "send_data"}],
            "metadata": {
                "difficulty_hint": "impossible",
            },
        }
        with pytest.raises(ValidationError):
            ScenarioTemplate.model_validate(data)

    def test_metadata_extra_fields_rejected(self):
        """ScenarioMetadata with extra='forbid' rejects unknown fields."""
        data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "steps": [{"action": "send_data"}],
            "metadata": {
                "name": "Test",
                "unknown_field": "should fail",
            },
        }
        with pytest.raises(ValidationError):
            ScenarioTemplate.model_validate(data)

    def test_category_enum_values(self):
        """ScenarioCategory has the expected enum values."""
        assert ScenarioCategory.NETWORK_ATTACK == "network_attack"
        assert ScenarioCategory.WEB_TRAFFIC == "web_traffic"
        assert ScenarioCategory.COVERT_CHANNEL == "covert_channel"
        assert ScenarioCategory.MALWARE_C2 == "malware_c2"

    def test_difficulty_enum_values(self):
        """DifficultyHint has the expected enum values."""
        assert DifficultyHint.EASY == "easy"
        assert DifficultyHint.MEDIUM == "medium"
        assert DifficultyHint.HARD == "hard"

    def test_existing_simple_tcp_yaml_validates_with_metadata(self):
        """Existing simple_tcp.yaml loads and validates with added metadata."""
        from ctf_pcaps.engine.loader import load_template, validate_template

        raw = load_template(Path("scenarios/simple_tcp.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.metadata is not None
        assert result.metadata.name == "Simple TCP Session"

    def test_existing_simple_dns_yaml_validates_with_metadata(self):
        """Existing simple_dns.yaml loads and validates with added metadata."""
        from ctf_pcaps.engine.loader import load_template, validate_template

        raw = load_template(Path("scenarios/simple_dns.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.metadata is not None
        assert result.metadata.name == "Simple DNS Lookup"


class TestConfigExtensions:
    """Tests for engine-related config extensions."""

    def test_config_has_cleanup_ttl(self):
        """Config has CLEANUP_TTL_HOURS with default 24."""
        from ctf_pcaps.config import Config

        assert hasattr(Config, "CLEANUP_TTL_HOURS")
        assert Config.CLEANUP_TTL_HOURS == 24

    def test_config_has_max_pcap_size(self):
        """Config has MAX_PCAP_SIZE_MB with default 100."""
        from ctf_pcaps.config import Config

        assert hasattr(Config, "MAX_PCAP_SIZE_MB")
        assert Config.MAX_PCAP_SIZE_MB == 100

    def test_config_has_max_packet_count(self):
        """Config has MAX_PACKET_COUNT with default 100000."""
        from ctf_pcaps.config import Config

        assert hasattr(Config, "MAX_PACKET_COUNT")
        assert Config.MAX_PACKET_COUNT == 100000
