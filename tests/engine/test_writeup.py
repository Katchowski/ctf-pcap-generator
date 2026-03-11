"""Tests for writeup generation engine module."""

from pathlib import Path

from ctf_pcaps.engine.models import GenerationResult
from ctf_pcaps.engine.writeup import (
    SCENARIO_FILTERS,
    generate_writeup,
)


def _make_result(**overrides) -> GenerationResult:
    """Create a GenerationResult with sensible defaults for testing."""
    defaults = {
        "file_path": Path("/tmp/dns_tunnel_abc123.pcap"),
        "packet_count": 42,
        "file_size_bytes": 1024,
        "generation_duration_ms": 150.0,
        "builder_used": "dns_tunnel",
        "template_name": "dns_tunnel.yaml",
        "flag_text": "CTF{test_flag_123}",
        "flag_encoding": "base32",
        "flag_verified": True,
        "solve_steps": [
            "Open the PCAP in Wireshark",
            "Filter for DNS queries",
            "Extract subdomain labels",
            "Decode base32 data",
        ],
        "difficulty_preset": "medium",
        "encoding_chain": ["base32"],
    }
    defaults.update(overrides)
    return GenerationResult(**defaults)


class TestAuthorWriteup:
    """Tests for the author (full solution) writeup."""

    def test_author_contains_all_seven_sections(self):
        result = _make_result()
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling exfiltration",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "## Scenario Background" in author
        assert "## Difficulty" in author
        assert "## Recommended Tools" in author
        assert "## Wireshark Filters" in author
        assert "## Step-by-Step Solution" in author
        assert "## Flag" in author
        assert "## What to Learn" in author

    def test_author_contains_flag_text(self):
        result = _make_result(flag_text="CTF{super_secret}")
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "CTF{super_secret}" in author

    def test_author_contains_flag_in_code_block(self):
        result = _make_result(flag_text="CTF{code_block_flag}")
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "`CTF{code_block_flag}`" in author

    def test_author_contains_solve_steps_as_numbered_list(self):
        steps = ["Step one", "Step two", "Step three"]
        result = _make_result(solve_steps=steps)
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "1. Step one" in author
        assert "2. Step two" in author
        assert "3. Step three" in author

    def test_author_contains_scenario_description(self):
        result = _make_result()
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect data exfiltration via DNS",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "Detect data exfiltration via DNS" in author

    def test_author_title_contains_scenario_name(self):
        result = _make_result()
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
        )
        assert "# DNS Tunnel - Solution Writeup" in author


class TestPlayerWriteup:
    """Tests for the player (redacted) writeup."""

    def test_player_contains_five_sections(self):
        result = _make_result()
        _, player = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "## Scenario Background" in player
        assert "## Difficulty" in player
        assert "## Recommended Tools" in player
        assert "## Wireshark Filters" in player
        assert "## What to Learn" in player

    def test_player_omits_flag_section(self):
        result = _make_result(flag_text="CTF{should_not_appear}")
        _, player = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "## Flag" not in player
        assert "CTF{should_not_appear}" not in player

    def test_player_omits_solution_section(self):
        result = _make_result()
        _, player = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Detect DNS tunneling",
            scenario_slug="dns_tunnel",
            difficulty="medium",
        )
        assert "## Step-by-Step Solution" not in player

    def test_player_title_differs_from_author(self):
        result = _make_result()
        author, player = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
        )
        assert "Solution Writeup" in author
        assert "Solution Writeup" not in player
        assert "# DNS Tunnel - Writeup" in player


class TestScenarioFilters:
    """Tests for scenario-specific Wireshark filter registry."""

    def test_dns_tunnel_has_dns_filters(self):
        filters = SCENARIO_FILTERS["dns_tunnel"]
        assert any("dns" in f.lower() for f in filters)

    def test_reverse_shell_has_tcp_filters(self):
        filters = SCENARIO_FILTERS["reverse_shell"]
        assert any("tcp" in f.lower() for f in filters)

    def test_unknown_builder_falls_back_to_default(self):
        result = _make_result(builder_used="totally_unknown_builder")
        author, _ = generate_writeup(
            result,
            scenario_name="Unknown",
            scenario_description="Unknown scenario",
            scenario_slug="unknown",
            difficulty="easy",
        )
        # Should not crash -- uses default filters
        assert "## Wireshark Filters" in author

    def test_filters_render_as_code_blocks(self):
        result = _make_result(builder_used="dns_tunnel")
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
        )
        # Each filter should be in a backtick code block
        for f in SCENARIO_FILTERS["dns_tunnel"]:
            assert f"`{f}`" in author


class TestEdgeCases:
    """Tests for graceful handling of missing/optional fields."""

    def test_no_difficulty_renders_gracefully(self):
        result = _make_result(difficulty_preset=None)
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
            difficulty=None,
        )
        assert "## Difficulty" in author
        # Should not crash or produce empty section

    def test_empty_solve_steps_renders_gracefully(self):
        result = _make_result(solve_steps=[])
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
        )
        assert "## Step-by-Step Solution" in author

    def test_no_flag_text_renders_gracefully(self):
        result = _make_result(flag_text=None)
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
        )
        assert "## Flag" in author

    def test_no_encoding_chain_renders_gracefully(self):
        result = _make_result(encoding_chain=[])
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
            difficulty="hard",
        )
        assert "## Difficulty" in author

    def test_what_to_learn_contains_educational_content(self):
        result = _make_result(builder_used="dns_tunnel")
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="dns_tunnel",
        )
        # What to Learn should have substantive content
        learn_idx = author.index("## What to Learn")
        learn_section = author[learn_idx:]
        # Should have more than just the heading
        assert len(learn_section) > 30

    def test_builder_used_primary_key_for_filters(self):
        """builder_used should be the primary lookup key, not slug."""
        result = _make_result(builder_used="dns_tunnel")
        author, _ = generate_writeup(
            result,
            scenario_name="DNS Tunnel",
            scenario_description="Desc",
            scenario_slug="some_other_slug",
        )
        # Should use dns_tunnel filters from builder_used, not slug
        for f in SCENARIO_FILTERS["dns_tunnel"]:
            assert f"`{f}`" in author
