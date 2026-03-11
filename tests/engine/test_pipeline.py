"""Tests for the pipeline orchestrator.

Verifies generate() and dry_run() functions that wire the full
engine together: load -> validate -> resolve -> build -> write -> cleanup.
Includes flag integration tests for the flag embedding pipeline stage.
"""

from pathlib import Path

import yaml

from ctf_pcaps.engine.models import GenerationResult


class TestGenerate:
    """Tests for the generate() pipeline function."""

    def _write_template(self, tmp_path, template_data):
        """Helper to write a YAML template to tmp_path."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text(yaml.dump(template_data))
        return template_file

    def test_generate_returns_generation_result(self, tmp_path):
        """generate() returns a GenerationResult with all fields populated."""
        from ctf_pcaps.engine.pipeline import generate

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                },
            },
            "steps": [{"action": "send_data", "payload": "Hello"}],
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        result = generate(template_file, output_dir)
        assert isinstance(result, GenerationResult)
        assert result.file_path.exists()
        assert result.packet_count > 0
        assert result.file_size_bytes > 0
        assert result.generation_duration_ms > 0
        assert result.builder_used == "simple_tcp"
        assert result.template_name == "template"

    def test_generate_creates_pcap_file(self, tmp_path):
        """generate() creates a .pcap file in the output directory."""
        from ctf_pcaps.engine.pipeline import generate

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {},
            "steps": [{"action": "send_data", "payload": "test"}],
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        result = generate(template_file, output_dir)
        assert result.file_path.suffix == ".pcap"
        assert result.file_path.parent == output_dir

    def test_generate_with_invalid_template_returns_errors(self, tmp_path):
        """generate() with invalid template YAML returns error list."""
        from ctf_pcaps.engine.pipeline import generate

        template_data = {
            "protocol": "tcp",
            # Missing 'builder' and 'steps'
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        result = generate(template_file, output_dir)
        assert isinstance(result, list)
        assert len(result) > 0
        assert any("builder" in str(e) for e in result)

    def test_generate_with_parameter_overrides(self, tmp_path):
        """generate() with overrides merges them with template defaults."""
        from ctf_pcaps.engine.pipeline import generate

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                },
            },
            "steps": [{"action": "send_data", "payload": "Hello"}],
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        result = generate(template_file, output_dir, overrides={"dport": 443})
        assert isinstance(result, GenerationResult)
        assert result.packet_count > 0

    def test_generate_with_unknown_builder_returns_errors(self, tmp_path):
        """generate() with unknown builder returns structured errors."""
        from ctf_pcaps.engine.pipeline import generate

        template_data = {
            "builder": "nonexistent_builder",
            "protocol": "tcp",
            "parameters": {},
            "steps": [{"action": "send_data", "payload": "test"}],
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        result = generate(template_file, output_dir)
        assert isinstance(result, list)
        assert any("nonexistent_builder" in str(e) for e in result)

    def test_generate_with_invalid_parameter_override(self, tmp_path):
        """generate() with out-of-range override returns errors."""
        from ctf_pcaps.engine.pipeline import generate

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Port",
                },
            },
            "steps": [{"action": "send_data", "payload": "test"}],
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        result = generate(template_file, output_dir, overrides={"dport": 99999})
        assert isinstance(result, list)
        assert len(result) > 0


class TestDryRun:
    """Tests for the dry_run() function."""

    def _write_template(self, tmp_path, template_data):
        """Helper to write a YAML template to tmp_path."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text(yaml.dump(template_data))
        return template_file

    def test_dry_run_returns_expected_structure(self, tmp_path):
        """dry_run() returns dict with builder_name, protocol, etc."""
        from ctf_pcaps.engine.pipeline import dry_run

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
            },
            "steps": [{"action": "send_data", "payload": "test"}],
        }
        template_file = self._write_template(tmp_path, template_data)

        result = dry_run(template_file)
        assert isinstance(result, dict)
        assert result["builder_name"] == "simple_tcp"
        assert result["protocol"] == "tcp"
        assert result["parameter_count"] == 1
        assert result["step_count"] == 1
        assert "parameters" in result
        assert "steps" in result

    def test_dry_run_does_not_create_files(self, tmp_path):
        """dry_run() validates without creating any files."""
        from ctf_pcaps.engine.pipeline import dry_run

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {},
            "steps": [{"action": "send_data", "payload": "test"}],
        }
        template_file = self._write_template(tmp_path, template_data)
        output_dir = tmp_path / "output"

        dry_run(template_file)
        # No output directory or files should be created
        assert not output_dir.exists()

    def test_dry_run_with_invalid_template_returns_errors(self, tmp_path):
        """dry_run() on invalid template returns error list."""
        from ctf_pcaps.engine.pipeline import dry_run

        template_data = {
            "protocol": "tcp",
            # Missing 'builder' and 'steps'
        }
        template_file = self._write_template(tmp_path, template_data)

        result = dry_run(template_file)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_dry_run_resolves_parameters(self, tmp_path):
        """dry_run() returns resolved parameter values."""
        from ctf_pcaps.engine.pipeline import dry_run

        template_data = {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Port",
                },
            },
            "steps": [{"action": "send_data", "payload": "test"}],
        }
        template_file = self._write_template(tmp_path, template_data)

        result = dry_run(template_file, overrides={"dport": 443})
        assert result["parameters"]["dport"] == 443
        assert result["parameters"]["dst_ip"] == "10.0.0.2"


# -----------------------------------------------------------------------
# Flag Integration Tests (Plan 03-02)
# -----------------------------------------------------------------------

_SCENARIOS_DIR = Path(__file__).parent.parent.parent / "scenarios"


class TestGenerationResultFlagFields:
    """Tests that GenerationResult has flag metadata fields."""

    def test_generation_result_default_flag_fields(self):
        """GenerationResult without flag fields has correct defaults."""
        result = GenerationResult(
            file_path=Path("/tmp/test.pcap"),
            packet_count=10,
            file_size_bytes=1024,
            generation_duration_ms=100.0,
            builder_used="simple_tcp",
            template_name="test",
        )
        assert result.flag_text is None
        assert result.flag_encoding is None
        assert result.flag_verified is None
        assert result.solve_steps == []

    def test_generation_result_with_flag_fields(self):
        """GenerationResult accepts flag metadata fields."""
        result = GenerationResult(
            file_path=Path("/tmp/test.pcap"),
            packet_count=10,
            file_size_bytes=1024,
            generation_duration_ms=100.0,
            builder_used="simple_tcp",
            template_name="test",
            flag_text="flag{test}",
            flag_encoding="plaintext",
            flag_verified=True,
            solve_steps=["Step 1"],
        )
        assert result.flag_text == "flag{test}"
        assert result.flag_encoding == "plaintext"
        assert result.flag_verified is True
        assert result.solve_steps == ["Step 1"]


class TestGenerateFlagIntegration:
    """Tests for flag integration in the generate() pipeline."""

    def _write_template(self, tmp_path, template_data):
        """Helper to write a YAML template to tmp_path."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text(yaml.dump(template_data))
        return template_file

    def _tcp_template_data(self):
        """Return a standard TCP template for testing."""
        return {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                },
            },
            "steps": [{"action": "send_data", "payload": "Hello"}],
        }

    def test_generate_no_flag_params_backward_compatible(self, tmp_path):
        """generate() with no flag params is backward-compatible."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir)

        assert isinstance(result, GenerationResult)
        assert result.flag_text is None
        assert result.flag_encoding is None
        assert result.flag_verified is None
        assert result.solve_steps == []

    def test_generate_with_flag_text(self, tmp_path):
        """generate() with flag_text embeds flag and populates result."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir, flag_text="test")

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{test}"
        assert result.flag_encoding == "plaintext"
        assert result.flag_verified is True
        assert len(result.solve_steps) > 0

    def test_generate_with_auto_flag_text(self, tmp_path):
        """generate() with flag_text=None auto-generates flag text."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"

        # Using the sentinel approach: pass flag_text=None explicitly
        # Pipeline should auto-generate text when flag_text is None
        # but flag embedding is triggered (e.g., via _UNSET sentinel)
        result = generate(template_file, output_dir, flag_text=None)

        # When flag_text is None using sentinel, auto-generation happens
        assert isinstance(result, GenerationResult)
        assert result.flag_text is not None
        assert result.flag_text.startswith("flag{")
        assert result.flag_text.endswith("}")
        assert result.flag_verified is True

    def test_generate_with_invalid_encoding_returns_error(self, tmp_path):
        """generate() with invalid flag_encoding returns error list."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", flag_encoding="invalid"
        )

        assert isinstance(result, list)
        assert any(e.get("error_type") == "invalid_encoding" for e in result)

    def test_generate_with_base64_encoding(self, tmp_path):
        """generate() with base64 encoding produces verified result."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="encoded_test", flag_encoding="base64"
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{encoded_test}"
        assert result.flag_encoding == "base64"
        assert result.flag_verified is True

    def test_generate_with_custom_format(self, tmp_path):
        """generate() with custom flag_format wraps correctly."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="mydata", flag_format="CTF"
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "CTF{mydata}"

    def test_generate_flag_exports_assemble_flag(self):
        """__init__.py exports assemble_flag from flag module."""
        from ctf_pcaps.engine import assemble_flag

        assert callable(assemble_flag)
        assert assemble_flag("test") == "flag{test}"


# -----------------------------------------------------------------------
# Difficulty Pipeline Integration Tests (Plan 04-02)
# -----------------------------------------------------------------------


class TestGenerateDifficultyIntegration:
    """Tests for difficulty parameter in generate() pipeline."""

    def _write_template(self, tmp_path, template_data):
        """Helper to write a YAML template to tmp_path."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text(yaml.dump(template_data))
        return template_file

    def _tcp_template_data(self):
        """Return a standard TCP template for testing."""
        return {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                },
            },
            "steps": [{"action": "send_data", "payload": "Hello"}],
        }

    def test_difficulty_none_backward_compatible(self, tmp_path):
        """generate() with difficulty=None + flag is backward-compatible."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir, flag_text="test", difficulty=None)

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{test}"
        assert result.flag_encoding == "plaintext"
        assert result.flag_verified is True
        assert result.difficulty_preset is None
        assert result.noise_ratio is None
        assert result.packet_count_target is None
        assert result.noise_types == []
        assert result.timing_jitter_ms is None
        assert result.encoding_chain == ["plaintext"]

    def test_difficulty_easy_sets_preset_fields(self, tmp_path):
        """generate() with difficulty='easy' populates difficulty fields."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", difficulty="easy"
        )

        assert isinstance(result, GenerationResult)
        assert result.difficulty_preset == "easy"
        assert result.noise_ratio == 0.2
        assert result.noise_types == ["ARP"]
        assert result.flag_encoding == "plaintext"
        assert result.encoding_chain == ["plaintext"]
        assert 20 <= result.packet_count_target <= 50

    def test_difficulty_medium_uses_base64(self, tmp_path):
        """generate() with difficulty='medium' uses base64 encoding."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", difficulty="medium"
        )

        assert isinstance(result, GenerationResult)
        assert result.difficulty_preset == "medium"
        assert result.noise_ratio == 0.6
        assert result.encoding_chain == ["base64"]
        assert result.flag_encoding == "base64"
        assert result.flag_verified is True

    def test_difficulty_hard_uses_chained_encoding(self, tmp_path):
        """generate() with difficulty='hard' uses chained encoding from pool."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", difficulty="hard"
        )

        assert isinstance(result, GenerationResult)
        assert result.difficulty_preset == "hard"
        assert result.noise_ratio == 0.85
        assert len(result.encoding_chain) >= 2
        assert result.flag_verified is True
        assert 1000 <= result.packet_count_target <= 5000

    def test_difficulty_override_noise_ratio(self, tmp_path):
        """generate() with difficulty + noise_ratio override merges correctly."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file,
            output_dir,
            flag_text="test",
            difficulty="medium",
            overrides={"noise_ratio": 0.3},
        )

        assert isinstance(result, GenerationResult)
        assert result.noise_ratio == 0.3

    def test_difficulty_override_encoding_chain(self, tmp_path):
        """generate() with difficulty + encoding_chain override uses that chain."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file,
            output_dir,
            flag_text="test",
            difficulty="hard",
            overrides={"encoding_chain": ["rot13", "base64"]},
        )

        assert isinstance(result, GenerationResult)
        assert result.encoding_chain == ["rot13", "base64"]
        assert result.flag_verified is True

    def test_difficulty_override_packet_count(self, tmp_path):
        """generate() with difficulty + packet_count override sets target."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file,
            output_dir,
            flag_text="test",
            difficulty="easy",
            overrides={"packet_count": 30},
        )

        assert isinstance(result, GenerationResult)
        assert result.packet_count_target == 30

    def test_invalid_difficulty_returns_error(self, tmp_path):
        """generate() with invalid difficulty name returns error list."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", difficulty="extreme"
        )

        assert isinstance(result, list)
        assert any(e.get("error_type") == "invalid_difficulty" for e in result)

    def test_encoding_chain_in_result_reflects_chain_used(self, tmp_path):
        """GenerationResult.encoding_chain reflects actual chain used."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", difficulty="medium"
        )

        assert isinstance(result, GenerationResult)
        assert result.encoding_chain == ["base64"]

    def test_difficulty_easy_timing_jitter(self, tmp_path):
        """generate() with difficulty='easy' has correct timing_jitter_ms."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="test", difficulty="easy"
        )

        assert isinstance(result, GenerationResult)
        assert result.timing_jitter_ms == (10.0, 50.0)

    def test_difficulty_exports_from_engine(self):
        """DifficultyPreset and resolve_difficulty exported from engine."""
        from ctf_pcaps.engine import DifficultyPreset, resolve_difficulty

        assert DifficultyPreset is not None
        assert callable(resolve_difficulty)


# -----------------------------------------------------------------------
# Pipeline Realism Integration Tests (Plan 05-03, Task 2)
# -----------------------------------------------------------------------


class TestPipelineRealismIntegration:
    """Tests for realism features in the generate() pipeline."""

    def _write_template(self, tmp_path, template_data):
        """Helper to write a YAML template to tmp_path."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text(yaml.dump(template_data))
        return template_file

    def _tcp_template_data(self):
        """Return a standard TCP template for testing."""
        return {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                },
            },
            "steps": [{"action": "send_data", "payload": "Hello"}],
        }

    def test_pipeline_ethernet_wrapping(self, tmp_path):
        """Generated PCAP without difficulty has all packets Ether-wrapped."""
        from scapy.layers.l2 import Ether
        from scapy.utils import rdpcap

        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir)

        assert isinstance(result, GenerationResult)
        packets = rdpcap(str(result.file_path))
        assert len(packets) > 0
        for pkt in packets:
            assert pkt.haslayer(Ether), "Packet missing Ether layer"

    def test_pipeline_timestamps_monotonic(self, tmp_path):
        """Generated PCAP has monotonically increasing timestamps."""
        from scapy.utils import rdpcap

        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir)

        packets = rdpcap(str(result.file_path))
        assert len(packets) > 1
        for i in range(len(packets) - 1):
            assert float(packets[i].time) <= float(packets[i + 1].time), (
                f"Timestamp not monotonic at index {i}: "
                f"{float(packets[i].time)} > {float(packets[i + 1].time)}"
            )

    def test_pipeline_timestamps_not_uniform(self, tmp_path):
        """Generated PCAP has non-uniform inter-packet timestamps (jitter)."""
        from scapy.utils import rdpcap

        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir)

        packets = rdpcap(str(result.file_path))
        assert len(packets) > 2

        delays = [
            float(packets[i + 1].time) - float(packets[i].time)
            for i in range(len(packets) - 1)
        ]
        # Not all delays should be identical (jitter exists)
        assert max(delays) - min(delays) > 0, "All inter-packet delays are identical"

    def test_pipeline_with_difficulty_has_noise(self, tmp_path):
        """Generated PCAP with difficulty=medium has noise packets."""
        from scapy.layers.dns import DNS
        from scapy.layers.l2 import ARP
        from scapy.utils import rdpcap

        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir_no_diff = tmp_path / "output_no"
        output_dir_diff = tmp_path / "output_diff"

        result_no = generate(template_file, output_dir_no_diff)
        result_diff = generate(
            template_file, output_dir_diff, flag_text="test", difficulty="medium"
        )

        assert isinstance(result_no, GenerationResult)
        assert isinstance(result_diff, GenerationResult)

        # With difficulty, should have more packets (noise added)
        assert result_diff.packet_count > result_no.packet_count

        # Should have ARP or DNS noise packets
        packets = rdpcap(str(result_diff.file_path))
        has_noise = any(pkt.haslayer(ARP) or pkt.haslayer(DNS) for pkt in packets)
        assert has_noise, "No noise packets (ARP or DNS) found in PCAP"

    def test_pipeline_flag_survives_ethernet_wrapping(self, tmp_path):
        """Flag is still verified after Ethernet wrapping."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="secret", difficulty="easy"
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_verified is True
        assert result.flag_text == "flag{secret}"


# -----------------------------------------------------------------------
# Flag Splitting Pipeline Integration Tests (Plan 10-02)
# -----------------------------------------------------------------------


class TestGenerateSplitFlagIntegration:
    """Tests for split_count in the generate() pipeline."""

    def _write_template(self, tmp_path, template_data):
        """Helper to write a YAML template to tmp_path."""
        template_file = tmp_path / "template.yaml"
        template_file.write_text(yaml.dump(template_data))
        return template_file

    def _tcp_template_data(self):
        """Return a standard TCP template for testing."""
        return {
            "builder": "simple_tcp",
            "protocol": "tcp",
            "parameters": {
                "dst_ip": {"default": "10.0.0.2", "description": "Target IP"},
                "dport": {
                    "default": 80,
                    "min": 1,
                    "max": 65535,
                    "description": "Target port",
                },
            },
            "steps": [{"action": "send_data", "payload": "Hello"}],
        }

    def test_split_count_2_produces_split_result(self, tmp_path):
        """generate() with split_count=2 sets split_active=True and split_count=2."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="split_me", split_count=2
        )

        assert isinstance(result, GenerationResult)
        assert result.split_count == 2
        assert result.split_active is True
        assert result.flag_verified is True
        assert result.flag_text == "flag{split_me}"

    def test_split_count_1_default_no_split(self, tmp_path):
        """generate() with split_count=1 (default) sets split_active=False."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(template_file, output_dir, flag_text="no_split")

        assert isinstance(result, GenerationResult)
        assert result.split_count == 1
        assert result.split_active is False
        assert result.flag_verified is True

    def test_difficulty_medium_uses_split_count_2(self, tmp_path):
        """generate() with difficulty='medium' uses split_count=2 from preset."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="medium_split", difficulty="medium"
        )

        assert isinstance(result, GenerationResult)
        assert result.split_count == 2
        assert result.split_active is True
        assert result.flag_verified is True

    def test_difficulty_easy_no_split(self, tmp_path):
        """generate() with difficulty='easy' uses split_count=1 (no splitting)."""
        from ctf_pcaps.engine.pipeline import generate

        template_file = self._write_template(tmp_path, self._tcp_template_data())
        output_dir = tmp_path / "output"
        result = generate(
            template_file, output_dir, flag_text="easy_flag", difficulty="easy"
        )

        assert isinstance(result, GenerationResult)
        assert result.split_count == 1
        assert result.split_active is False
        assert result.flag_verified is True
