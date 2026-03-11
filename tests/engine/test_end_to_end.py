"""End-to-end tests for the generation engine.

Tests the full pipeline with actual YAML scenario templates from
the scenarios/ directory. Verifies generated PCAPs are readable,
contain expected protocols, and support flag embedding lifecycle.
"""

import importlib
import sys
from pathlib import Path

from scapy.layers.dns import DNS
from scapy.layers.inet import TCP
from scapy.utils import rdpcap

from ctf_pcaps.engine import GenerationResult, generate
from ctf_pcaps.engine.flag import (
    ENCODERS,
    extract_printable_strings,
    verify_flag_in_pcap,
    verify_split_flag_in_pcap,
    verify_stealth,
)

# Locate the scenarios directory at project root
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_SCENARIOS_DIR = _PROJECT_ROOT / "scenarios"


class TestEndToEndTCP:
    """End-to-end tests with simple_tcp.yaml scenario template."""

    def test_simple_tcp_generates_pcap(self, tmp_path):
        """Loading simple_tcp.yaml and generating produces a .pcap file."""
        from ctf_pcaps.engine.pipeline import generate

        template_path = _SCENARIOS_DIR / "simple_tcp.yaml"
        result = generate(template_path, tmp_path)

        from ctf_pcaps.engine.models import GenerationResult

        assert isinstance(result, GenerationResult)
        assert result.file_path.exists()
        assert result.file_path.suffix == ".pcap"

    def test_simple_tcp_pcap_readable_with_rdpcap(self, tmp_path):
        """Generated TCP PCAP is readable with rdpcap()."""
        from ctf_pcaps.engine.pipeline import generate

        result = generate(_SCENARIOS_DIR / "simple_tcp.yaml", tmp_path)
        packets = rdpcap(str(result.file_path))
        assert len(packets) > 0

    def test_simple_tcp_has_handshake_flags(self, tmp_path):
        """Generated TCP PCAP has proper SYN, SYN-ACK, ACK flags."""
        from ctf_pcaps.engine.pipeline import generate

        result = generate(_SCENARIOS_DIR / "simple_tcp.yaml", tmp_path)
        packets = rdpcap(str(result.file_path))

        flags = [str(pkt[TCP].flags) for pkt in packets if pkt.haslayer(TCP)]
        assert "S" in flags, "No SYN packet found"
        assert "SA" in flags, "No SYN-ACK packet found"
        assert "A" in flags, "No ACK packet found"


class TestEndToEndDNS:
    """End-to-end tests with simple_dns.yaml scenario template."""

    def test_simple_dns_generates_pcap(self, tmp_path):
        """Loading simple_dns.yaml and generating produces a .pcap file."""
        from ctf_pcaps.engine.pipeline import generate

        template_path = _SCENARIOS_DIR / "simple_dns.yaml"
        result = generate(template_path, tmp_path)

        from ctf_pcaps.engine.models import GenerationResult

        assert isinstance(result, GenerationResult)
        assert result.file_path.exists()

    def test_simple_dns_pcap_has_dns_packets(self, tmp_path):
        """Generated DNS PCAP contains DNS packets."""
        from ctf_pcaps.engine.pipeline import generate

        result = generate(_SCENARIOS_DIR / "simple_dns.yaml", tmp_path)
        packets = rdpcap(str(result.file_path))
        dns_packets = [pkt for pkt in packets if pkt.haslayer(DNS)]
        assert len(dns_packets) > 0


class TestPublicAPI:
    """Tests for the engine's public API exports."""

    def test_import_generate(self):
        """from ctf_pcaps.engine import generate works."""
        from ctf_pcaps.engine import generate

        assert callable(generate)

    def test_import_dry_run(self):
        """from ctf_pcaps.engine import dry_run works."""
        from ctf_pcaps.engine import dry_run

        assert callable(dry_run)

    def test_import_load_template(self):
        """from ctf_pcaps.engine import load_template works."""
        from ctf_pcaps.engine import load_template

        assert callable(load_template)

    def test_import_validate_template(self):
        """from ctf_pcaps.engine import validate_template works."""
        from ctf_pcaps.engine import validate_template

        assert callable(validate_template)

    def test_import_generation_result(self):
        """from ctf_pcaps.engine import GenerationResult works."""
        from ctf_pcaps.engine import GenerationResult

        assert GenerationResult is not None

    def test_import_scenario_template(self):
        """from ctf_pcaps.engine import ScenarioTemplate works."""
        from ctf_pcaps.engine import ScenarioTemplate

        assert ScenarioTemplate is not None


class TestLayerIsolation:
    """Verify engine has no Flask imports (layer boundary enforcement)."""

    def test_engine_has_no_flask_imports(self):
        """No module under ctf_pcaps.engine imports from flask."""
        engine_modules = [
            name for name in sys.modules if name.startswith("ctf_pcaps.engine")
        ]
        # Force import of the full engine package
        importlib.import_module("ctf_pcaps.engine")
        engine_modules = [
            name for name in sys.modules if name.startswith("ctf_pcaps.engine")
        ]
        for mod_name in engine_modules:
            mod = sys.modules[mod_name]
            if mod is None:
                continue
            mod_attrs = dir(mod)
            # Check the module's globals for flask references
            for attr in mod_attrs:
                obj = getattr(mod, attr, None)
                if obj is not None and hasattr(obj, "__module__"):
                    assert not (obj.__module__ or "").startswith("flask"), (
                        f"Engine module {mod_name} has flask import: "
                        f"{attr} from {obj.__module__}"
                    )


# -----------------------------------------------------------------------
# End-to-End Flag Embedding Tests (Plan 03-02, Task 2)
# -----------------------------------------------------------------------


class TestEndToEndFlagPlaintext:
    """End-to-end plaintext flag embedding with TCP scenario."""

    def test_generate_with_plaintext_flag(self, tmp_path):
        """Plaintext flag is embedded, verified, and extractable."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="secret_data",
            flag_encoding="plaintext",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{secret_data}"
        assert result.flag_encoding == "plaintext"
        assert result.flag_verified is True
        assert len(result.solve_steps) > 0

        # Double-check via independent verification
        _, decode_fn = ENCODERS["plaintext"]
        vr = verify_flag_in_pcap(
            str(result.file_path), "flag{secret_data}", "plaintext", decode_fn
        )
        assert vr["verified"] is True


class TestEndToEndFlagBase64:
    """End-to-end base64 flag embedding with TCP scenario."""

    def test_generate_with_base64_flag(self, tmp_path):
        """Base64 flag is embedded, verified, extractable, and stealth."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="secret_data",
            flag_encoding="base64",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{secret_data}"
        assert result.flag_encoding == "base64"
        assert result.flag_verified is True

        # Stealth: literal flag NOT in raw strings
        assert verify_stealth(str(result.file_path), "flag{secret_data}", "base64")

        # Verify via extract_printable_strings
        with open(result.file_path, "rb") as f:
            raw = f.read()
        strings = extract_printable_strings(raw)
        full_text = " ".join(strings)
        assert "flag{secret_data}" not in full_text


class TestEndToEndFlagHex:
    """End-to-end hex flag embedding with TCP scenario."""

    def test_generate_with_hex_flag(self, tmp_path):
        """Hex flag is embedded, verified, and stealth passes."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="secret_data",
            flag_encoding="hex",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{secret_data}"
        assert result.flag_encoding == "hex"
        assert result.flag_verified is True
        assert verify_stealth(str(result.file_path), "flag{secret_data}", "hex")


class TestEndToEndFlagRot13:
    """End-to-end rot13 flag embedding with TCP scenario."""

    def test_generate_with_rot13_flag(self, tmp_path):
        """ROT13 flag is embedded, verified, and stealth passes."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="secret_data",
            flag_encoding="rot13",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{secret_data}"
        assert result.flag_encoding == "rot13"
        assert result.flag_verified is True
        assert verify_stealth(str(result.file_path), "flag{secret_data}", "rot13")


class TestEndToEndFlagAutoGenerate:
    """End-to-end auto-generated flag text."""

    def test_generate_auto_flag_text(self, tmp_path):
        """Auto-generated flag text produces valid, verified flag."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text=None,
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text is not None
        assert result.flag_text.startswith("flag{")
        assert result.flag_text.endswith("}")
        assert result.flag_verified is True


class TestEndToEndFlagCustomFormat:
    """End-to-end custom flag format wrapper."""

    def test_generate_custom_format(self, tmp_path):
        """Custom flag_format wraps flag correctly."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="mydata",
            flag_format="CTF",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "CTF{mydata}"


class TestEndToEndFlagBackwardCompat:
    """End-to-end backward compatibility without flag params."""

    def test_generate_without_flag_backward_compat(self, tmp_path):
        """generate() with no flag params produces PCAP with no flag."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text is None
        assert result.flag_verified is None
        assert result.solve_steps == []


class TestEndToEndFlagDNS:
    """End-to-end flag embedding with DNS (UDP) scenario."""

    def test_generate_flag_with_dns_template(self, tmp_path):
        """Flag embedding works with UDP-based DNS template."""
        result = generate(
            _SCENARIOS_DIR / "simple_dns.yaml",
            tmp_path,
            flag_text="dns_flag",
            flag_encoding="base64",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{dns_flag}"
        assert result.flag_verified is True


class TestEndToEndSolveSteps:
    """End-to-end solve steps format validation."""

    def test_solve_steps_format(self, tmp_path):
        """Solve steps contain packet number and encoding reference."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="test",
            flag_encoding="base64",
        )

        assert isinstance(result, GenerationResult)
        assert len(result.solve_steps) > 0

        # At least one step mentions a packet number (digit)
        assert any(any(c.isdigit() for c in step) for step in result.solve_steps), (
            "No solve step mentions a packet number"
        )

        # At least one step mentions base64
        combined = " ".join(result.solve_steps)
        assert "base64" in combined.lower() or "Base64" in combined, (
            "No solve step mentions base64 encoding"
        )


# -----------------------------------------------------------------------
# End-to-End Difficulty Preset Tests (Plan 04-02, Task 2)
# -----------------------------------------------------------------------


class TestEndToEndDifficultyEasy:
    """End-to-end Easy preset with actual PCAP generation."""

    def test_easy_preset_generates_pcap_with_plaintext_flag(self, tmp_path):
        """Easy preset: plaintext flag in PCAP, correct difficulty fields."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="easy_flag",
            difficulty="easy",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{easy_flag}"
        assert result.flag_verified is True
        assert result.difficulty_preset == "easy"
        assert result.noise_ratio == 0.2
        assert result.noise_types == ["ARP"]
        assert result.encoding_chain == ["plaintext"]
        assert 20 <= result.packet_count_target <= 50
        assert result.timing_jitter_ms == (10.0, 50.0)

        # Verify flag is extractable from PCAP
        _, decode_fn = ENCODERS["plaintext"]
        vr = verify_flag_in_pcap(
            str(result.file_path), "flag{easy_flag}", "plaintext", decode_fn
        )
        assert vr["verified"] is True


class TestEndToEndDifficultyMedium:
    """End-to-end Medium preset with actual PCAP generation."""

    def test_medium_preset_base64_flag_and_stealth(self, tmp_path):
        """Medium preset: base64 flag, stealth passes, correct fields."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="medium_flag",
            difficulty="medium",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{medium_flag}"
        assert result.flag_verified is True
        assert result.difficulty_preset == "medium"
        assert result.noise_ratio == 0.6
        assert result.encoding_chain == ["base64"]
        assert 200 <= result.packet_count_target <= 500

        # Stealth: literal flag NOT findable in raw strings
        assert verify_stealth(str(result.file_path), "flag{medium_flag}", "base64")

        # Verify flag extractable via split chain decode (medium splits into 2)
        from ctf_pcaps.engine.flag import decode_flag_chain

        def chain_decode(data):
            return decode_flag_chain(data, ["base64"])

        assert result.split_count == 2
        assert result.split_active is True
        vr = verify_split_flag_in_pcap(
            str(result.file_path),
            "flag{medium_flag}",
            ["base64"],
            chain_decode,
            2,
        )
        assert vr["verified"] is True


class TestEndToEndDifficultyHard:
    """End-to-end Hard preset with actual PCAP generation."""

    def test_hard_preset_chained_encoding_and_stealth(self, tmp_path):
        """Hard preset: chained encoding, stealth passes, flag extractable."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="hard_flag",
            difficulty="hard",
        )

        assert isinstance(result, GenerationResult)
        assert result.flag_text == "flag{hard_flag}"
        assert result.flag_verified is True
        assert result.difficulty_preset == "hard"
        assert result.noise_ratio == 0.85
        assert len(result.encoding_chain) >= 2
        assert 1000 <= result.packet_count_target <= 5000
        assert result.noise_types == ["ARP", "DNS", "HTTP", "ICMP"]

        # Stealth: literal flag NOT findable in raw strings
        # Use first encoding in chain for stealth check
        assert verify_stealth(
            str(result.file_path),
            "flag{hard_flag}",
            result.encoding_chain[0],
        )

    def test_hard_preset_with_encoding_chain_override(self, tmp_path):
        """Hard preset with specific encoding_chain override uses that chain."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="override_flag",
            difficulty="hard",
            overrides={"encoding_chain": ["rot13", "base64"]},
        )

        assert isinstance(result, GenerationResult)
        assert result.encoding_chain == ["rot13", "base64"]
        assert result.flag_verified is True

        # Verify we can decode using the exact chain
        # Hard preset splits into 3-4 parts
        from ctf_pcaps.engine.flag import decode_flag_chain

        def chain_decode(data):
            return decode_flag_chain(data, ["rot13", "base64"])

        assert result.split_count >= 3
        assert result.split_active is True
        vr = verify_split_flag_in_pcap(
            str(result.file_path),
            "flag{override_flag}",
            ["rot13", "base64"],
            chain_decode,
            result.split_count,
        )
        assert vr["verified"] is True


class TestEndToEndDifficultyTraceability:
    """Verify all three presets produce full parameter traceability."""

    def test_easy_full_traceability(self, tmp_path):
        """Easy preset: all 6 difficulty fields populated in result."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="trace_easy",
            difficulty="easy",
        )

        assert isinstance(result, GenerationResult)
        assert result.difficulty_preset is not None
        assert result.noise_ratio is not None
        assert result.packet_count_target is not None
        assert len(result.noise_types) > 0
        assert result.timing_jitter_ms is not None
        assert len(result.encoding_chain) > 0

    def test_medium_full_traceability(self, tmp_path):
        """Medium preset: all 6 difficulty fields populated in result."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="trace_medium",
            difficulty="medium",
        )

        assert isinstance(result, GenerationResult)
        assert result.difficulty_preset is not None
        assert result.noise_ratio is not None
        assert result.packet_count_target is not None
        assert len(result.noise_types) > 0
        assert result.timing_jitter_ms is not None
        assert len(result.encoding_chain) > 0

    def test_hard_full_traceability(self, tmp_path):
        """Hard preset: all 6 difficulty fields populated in result."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="trace_hard",
            difficulty="hard",
        )

        assert isinstance(result, GenerationResult)
        assert result.difficulty_preset is not None
        assert result.noise_ratio is not None
        assert result.packet_count_target is not None
        assert len(result.noise_types) > 0
        assert result.timing_jitter_ms is not None
        assert len(result.encoding_chain) > 0


# -----------------------------------------------------------------------
# End-to-End Realism Integration Tests (Plan 05-03, Task 2)
# -----------------------------------------------------------------------


class TestEndToEndMACRandomization:
    """End-to-end MAC address randomization across generations."""

    def test_e2e_mac_address_randomization(self, tmp_path):
        """Same template produces different MAC addresses across two runs."""
        from scapy.layers.l2 import Ether

        out1 = tmp_path / "out1"
        out2 = tmp_path / "out2"

        result1 = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            out1,
            difficulty="easy",
            flag_text="mac_test",
        )
        result2 = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            out2,
            difficulty="easy",
            flag_text="mac_test",
        )

        assert isinstance(result1, GenerationResult)
        assert isinstance(result2, GenerationResult)

        packets1 = rdpcap(str(result1.file_path))
        packets2 = rdpcap(str(result2.file_path))

        macs1 = set()
        macs2 = set()
        for pkt in packets1:
            if pkt.haslayer(Ether):
                macs1.add(pkt[Ether].src)
                macs1.add(pkt[Ether].dst)
        for pkt in packets2:
            if pkt.haslayer(Ether):
                macs2.add(pkt[Ether].src)
                macs2.add(pkt[Ether].dst)

        assert len(macs1) > 0
        assert len(macs2) > 0
        assert macs1 != macs2, "MAC addresses should differ between generations"


class TestEndToEndHardNoiseTypes:
    """End-to-end test for hard difficulty noise types."""

    def test_e2e_hard_difficulty_noise_types(self, tmp_path):
        """Hard difficulty PCAP has ARP, DNS, and ICMP noise packets."""
        from scapy.layers.dns import DNS
        from scapy.layers.inet import ICMP
        from scapy.layers.l2 import ARP

        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="hard_noise",
            difficulty="hard",
        )

        assert isinstance(result, GenerationResult)
        packets = rdpcap(str(result.file_path))

        has_arp = any(pkt.haslayer(ARP) for pkt in packets)
        has_dns = any(pkt.haslayer(DNS) for pkt in packets)
        has_icmp = any(pkt.haslayer(ICMP) for pkt in packets)

        assert has_arp, "Hard difficulty PCAP missing ARP noise"
        assert has_dns, "Hard difficulty PCAP missing DNS noise"
        assert has_icmp, "Hard difficulty PCAP missing ICMP noise"


class TestEndToEndNoiseRatio:
    """End-to-end test for noise ratio approximation."""

    def test_e2e_noise_ratio_approximate(self, tmp_path):
        """Medium difficulty noise ratio approximately matches 0.6."""
        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
            flag_text="ratio_test",
            difficulty="medium",
        )

        assert isinstance(result, GenerationResult)
        packets = rdpcap(str(result.file_path))

        # Count scenario vs noise packets by checking IPs
        # Scenario template uses 10.0.0.x addresses
        # Noise uses different random 10.x.x.x addresses
        total = len(packets)
        assert total > 0

        # With noise_ratio=0.6, noise should be roughly 60% of total
        # We check that noise_ratio is within tolerance
        expected_ratio = 0.6
        # Count packets without TCP to scenario ports as noise indicator
        # A simpler check: just verify total count is significantly more
        # than what the scenario alone would produce
        no_diff_result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path / "no_diff",
        )
        assert isinstance(no_diff_result, GenerationResult)
        scenario_count = no_diff_result.packet_count

        # Noise count = total - scenario_count (approximately)
        # Flag adds 1 packet, so adjust
        noise_count = total - scenario_count - 1  # -1 for flag packet
        if noise_count < 0:
            noise_count = 0

        actual_ratio = noise_count / total if total > 0 else 0
        assert abs(actual_ratio - expected_ratio) < 0.25, (
            f"Noise ratio {actual_ratio:.2f} too far from expected "
            f"{expected_ratio} (tolerance 0.25)"
        )


class TestEndToEndNoDifficultyEther:
    """End-to-end test for Ethernet wrapping without difficulty."""

    def test_e2e_no_difficulty_still_has_ether(self, tmp_path):
        """PCAP without difficulty has all packets Ether-wrapped."""
        from scapy.layers.l2 import Ether

        result = generate(
            _SCENARIOS_DIR / "simple_tcp.yaml",
            tmp_path,
        )

        assert isinstance(result, GenerationResult)
        packets = rdpcap(str(result.file_path))
        assert len(packets) > 0

        for pkt in packets:
            assert pkt.haslayer(Ether), (
                "All packets should have Ether layer even without difficulty"
            )
