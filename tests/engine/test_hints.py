"""Tests for hint generation engine module."""

from ctf_pcaps.engine.hints import generate_hints


class TestHintCounts:
    """Tests for hint count based on difficulty."""

    def test_easy_returns_one_hint(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="easy",
            encoding_chain=["base32"],
            challenge_value=100,
        )
        assert len(hints) == 1

    def test_medium_returns_two_hints(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="medium",
            encoding_chain=["base32"],
            challenge_value=250,
        )
        assert len(hints) == 2

    def test_hard_returns_three_hints(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=["base32"],
            challenge_value=500,
        )
        assert len(hints) == 3

    def test_none_difficulty_returns_one_hint(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty=None,
            encoding_chain=[],
            challenge_value=100,
        )
        assert len(hints) == 1


class TestHintCosts:
    """Tests for hint cost percentages."""

    def test_hint_1_cost_is_10_percent(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="easy",
            encoding_chain=[],
            challenge_value=100,
        )
        assert hints[0]["cost"] == 10  # 100 * 0.10

    def test_hint_2_cost_is_20_percent(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="medium",
            encoding_chain=[],
            challenge_value=250,
        )
        assert hints[1]["cost"] == 50  # 250 * 0.20

    def test_hint_3_cost_is_30_percent(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=[],
            challenge_value=500,
        )
        assert hints[2]["cost"] == 150  # 500 * 0.30

    def test_costs_are_integers(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=[],
            challenge_value=333,
        )
        for hint in hints:
            assert isinstance(hint["cost"], int)


class TestHintStructure:
    """Tests for hint dict structure."""

    def test_each_hint_has_content_and_cost_keys(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=["base32"],
            challenge_value=500,
        )
        for hint in hints:
            assert "content" in hint
            assert "cost" in hint

    def test_content_is_string(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="easy",
            encoding_chain=[],
            challenge_value=100,
        )
        assert isinstance(hints[0]["content"], str)


class TestHintContent:
    """Tests for hint content following Category -> Tool -> Technique."""

    def test_hint_1_is_category_level(self):
        """Hint 1 should mention the traffic type (category)."""
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="easy",
            encoding_chain=[],
            challenge_value=100,
        )
        content = hints[0]["content"].lower()
        assert "dns" in content

    def test_hint_2_is_tool_level(self):
        """Hint 2 should mention a specific filter or tool."""
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="medium",
            encoding_chain=[],
            challenge_value=250,
        )
        content = hints[1]["content"].lower()
        assert "filter" in content or "dns.qry" in content

    def test_hint_3_is_technique_level(self):
        """Hint 3 should mention encoding/decoding technique."""
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=["base32"],
            challenge_value=500,
        )
        content = hints[2]["content"].lower()
        assert "base32" in content or "encod" in content or "decod" in content


class TestFallbackBehavior:
    """Tests for unknown builder fallback."""

    def test_unknown_builder_uses_default_templates(self):
        hints = generate_hints(
            builder_name="totally_unknown_builder",
            difficulty="hard",
            encoding_chain=["base64"],
            challenge_value=500,
        )
        assert len(hints) == 3
        for hint in hints:
            assert len(hint["content"]) > 0

    def test_encoding_chain_interpolated_in_technique_hint(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=["base64", "base32"],
            challenge_value=500,
        )
        # Last encoding in chain should appear in hint 3
        content = hints[2]["content"].lower()
        assert "base32" in content

    def test_empty_encoding_chain_uses_plaintext(self):
        hints = generate_hints(
            builder_name="dns_tunnel",
            difficulty="hard",
            encoding_chain=[],
            challenge_value=500,
        )
        content = hints[2]["content"].lower()
        assert "plaintext" in content or len(content) > 0


class TestAllBuilders:
    """Verify all known builders have hint templates."""

    BUILDERS = [
        "dns_tunnel",
        "simple_dns",
        "http_beacon",
        "brute_force",
        "sqli",
        "syn_scan",
        "simple_tcp",
        "reverse_shell",
        "xss_reflected",
        "dir_traversal",
        "arp_spoofing",
        "icmp_exfil",
    ]

    def test_all_builders_produce_hints(self):
        for builder in self.BUILDERS:
            hints = generate_hints(
                builder_name=builder,
                difficulty="hard",
                encoding_chain=["base64"],
                challenge_value=500,
            )
            assert len(hints) == 3, f"Builder {builder} should produce 3 hints"
            for hint in hints:
                assert hint["content"], f"Builder {builder} hint content empty"
                assert hint["cost"] > 0, f"Builder {builder} hint cost <= 0"
