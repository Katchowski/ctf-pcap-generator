"""Tests for the difficulty preset module.

Tests cover: DifficultyPreset Pydantic model validation, preset constants
(EASY, MEDIUM, HARD), HARD_ENCODING_CHAINS pool, and resolve_difficulty
function with override merging.

No Flask imports allowed in engine tests.
"""

import pytest
from pydantic import ValidationError

from ctf_pcaps.engine.difficulty import (
    EASY,
    HARD,
    HARD_ENCODING_CHAINS,
    MEDIUM,
    DifficultyPreset,
    resolve_difficulty,
)


# ---------------------------------------------------------------------------
# DifficultyPreset Model Validation
# ---------------------------------------------------------------------------


class TestDifficultyPresetModel:
    """Tests for DifficultyPreset Pydantic model."""

    def test_valid_preset_accepted(self):
        """DifficultyPreset accepts a fully valid configuration."""
        preset = DifficultyPreset(
            name="easy",
            encoding_chain=["plaintext"],
            noise_ratio=0.2,
            packet_count_min=20,
            packet_count_max=50,
            noise_types=["ARP"],
            timing_jitter_ms=(10.0, 50.0),
        )
        assert preset.name == "easy"
        assert preset.encoding_chain == ["plaintext"]
        assert preset.noise_ratio == 0.2

    def test_noise_ratio_below_zero_rejected(self):
        """DifficultyPreset rejects noise_ratio < 0."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["plaintext"],
                noise_ratio=-0.1,
                packet_count_min=20,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
            )

    def test_noise_ratio_above_one_rejected(self):
        """DifficultyPreset rejects noise_ratio > 1.0."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["plaintext"],
                noise_ratio=1.1,
                packet_count_min=20,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
            )

    def test_unknown_encoding_chain_rejected(self):
        """DifficultyPreset rejects encoding_chain with unknown encodings."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["unknown"],
                noise_ratio=0.2,
                packet_count_min=20,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
            )

    def test_packet_count_min_exceeds_max_rejected(self):
        """DifficultyPreset rejects packet_count_min > packet_count_max."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["plaintext"],
                noise_ratio=0.2,
                packet_count_min=100,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
            )

    def test_extra_fields_rejected(self):
        """DifficultyPreset rejects extra fields (ConfigDict extra='forbid')."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["plaintext"],
                noise_ratio=0.2,
                packet_count_min=20,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
                unknown_field="bad",
            )

    def test_noise_ratio_boundary_zero_accepted(self):
        """DifficultyPreset accepts noise_ratio=0.0 (boundary)."""
        preset = DifficultyPreset(
            name="easy",
            encoding_chain=["plaintext"],
            noise_ratio=0.0,
            packet_count_min=20,
            packet_count_max=50,
            noise_types=["ARP"],
            timing_jitter_ms=(10.0, 50.0),
        )
        assert preset.noise_ratio == 0.0

    def test_noise_ratio_boundary_one_accepted(self):
        """DifficultyPreset accepts noise_ratio=1.0 (boundary)."""
        preset = DifficultyPreset(
            name="easy",
            encoding_chain=["plaintext"],
            noise_ratio=1.0,
            packet_count_min=20,
            packet_count_max=50,
            noise_types=["ARP"],
            timing_jitter_ms=(10.0, 50.0),
        )
        assert preset.noise_ratio == 1.0

    def test_packet_count_min_equals_max_accepted(self):
        """DifficultyPreset accepts packet_count_min == packet_count_max."""
        preset = DifficultyPreset(
            name="easy",
            encoding_chain=["plaintext"],
            noise_ratio=0.2,
            packet_count_min=50,
            packet_count_max=50,
            noise_types=["ARP"],
            timing_jitter_ms=(10.0, 50.0),
        )
        assert preset.packet_count_min == preset.packet_count_max


# ---------------------------------------------------------------------------
# Preset Constants
# ---------------------------------------------------------------------------


class TestPresetConstants:
    """Tests for EASY, MEDIUM, HARD preset constants."""

    def test_easy_preset_values(self):
        """EASY preset has correct parameter values."""
        assert EASY.name == "easy"
        assert EASY.encoding_chain == ["plaintext"]
        assert EASY.noise_ratio == 0.2
        assert EASY.packet_count_min == 20
        assert EASY.packet_count_max == 50
        assert EASY.noise_types == ["ARP"]
        assert EASY.timing_jitter_ms == (10.0, 50.0)

    def test_medium_preset_values(self):
        """MEDIUM preset has correct parameter values."""
        assert MEDIUM.name == "medium"
        assert MEDIUM.encoding_chain == ["base64"]
        assert MEDIUM.noise_ratio == 0.6
        assert MEDIUM.packet_count_min == 200
        assert MEDIUM.packet_count_max == 500
        assert MEDIUM.noise_types == ["ARP", "DNS"]
        assert MEDIUM.timing_jitter_ms == (5.0, 200.0)

    def test_hard_preset_values(self):
        """HARD preset has correct parameter values."""
        assert HARD.name == "hard"
        assert HARD.encoding_chain == ["base64", "hex"]
        assert HARD.noise_ratio == 0.85
        assert HARD.packet_count_min == 1000
        assert HARD.packet_count_max == 5000
        assert HARD.noise_types == ["ARP", "DNS", "HTTP", "ICMP"]
        assert HARD.timing_jitter_ms == (1.0, 500.0)

    def test_presets_are_difficulty_preset_instances(self):
        """All presets are DifficultyPreset instances."""
        assert isinstance(EASY, DifficultyPreset)
        assert isinstance(MEDIUM, DifficultyPreset)
        assert isinstance(HARD, DifficultyPreset)


# ---------------------------------------------------------------------------
# HARD_ENCODING_CHAINS Pool
# ---------------------------------------------------------------------------


class TestHardEncodingChains:
    """Tests for HARD_ENCODING_CHAINS pool."""

    def test_contains_at_least_four_chains(self):
        """Pool contains at least 4 valid chain combinations."""
        assert len(HARD_ENCODING_CHAINS) >= 4

    def test_all_chains_use_valid_encodings(self):
        """All chains in the pool use encodings from ENCODERS."""
        from ctf_pcaps.engine.flag import ENCODERS

        for chain in HARD_ENCODING_CHAINS:
            assert len(chain) >= 2, f"Chain {chain} should have >= 2 encodings"
            for enc in chain:
                assert enc in ENCODERS, f"Unknown encoding '{enc}' in chain {chain}"

    def test_chains_are_lists_of_strings(self):
        """Each chain is a list of strings."""
        for chain in HARD_ENCODING_CHAINS:
            assert isinstance(chain, list)
            for item in chain:
                assert isinstance(item, str)


# ---------------------------------------------------------------------------
# resolve_difficulty Function
# ---------------------------------------------------------------------------


class TestResolveDifficulty:
    """Tests for resolve_difficulty function."""

    def test_none_returns_none(self):
        """resolve_difficulty(None) returns None (fully manual mode)."""
        assert resolve_difficulty(None) is None

    def test_easy_returns_dict_with_correct_keys(self):
        """resolve_difficulty('easy') returns dict with expected keys."""
        result = resolve_difficulty("easy")
        assert isinstance(result, dict)
        expected_keys = {
            "encoding_chain",
            "noise_ratio",
            "packet_count_target",
            "noise_types",
            "timing_jitter_ms",
            "split_count",
        }
        assert set(result.keys()) == expected_keys

    def test_easy_returns_easy_values(self):
        """resolve_difficulty('easy') returns EASY preset values."""
        result = resolve_difficulty("easy")
        assert result["encoding_chain"] == ["plaintext"]
        assert result["noise_ratio"] == 0.2
        assert result["noise_types"] == ["ARP"]
        assert result["timing_jitter_ms"] == (10.0, 50.0)

    def test_easy_packet_count_in_range(self):
        """resolve_difficulty('easy') randomizes packet_count_target in 20-50."""
        for _ in range(20):
            result = resolve_difficulty("easy")
            assert 20 <= result["packet_count_target"] <= 50

    def test_medium_returns_medium_values(self):
        """resolve_difficulty('medium') returns MEDIUM preset values."""
        result = resolve_difficulty("medium")
        assert result["encoding_chain"] == ["base64"]
        assert result["noise_ratio"] == 0.6
        assert result["noise_types"] == ["ARP", "DNS"]
        assert result["timing_jitter_ms"] == (5.0, 200.0)

    def test_medium_packet_count_in_range(self):
        """resolve_difficulty('medium') randomizes packet_count_target in 200-500."""
        for _ in range(20):
            result = resolve_difficulty("medium")
            assert 200 <= result["packet_count_target"] <= 500

    def test_hard_returns_hard_values(self):
        """resolve_difficulty('hard') returns HARD preset base values."""
        result = resolve_difficulty("hard")
        assert result["noise_ratio"] == 0.85
        assert result["noise_types"] == ["ARP", "DNS", "HTTP", "ICMP"]
        assert result["timing_jitter_ms"] == (1.0, 500.0)

    def test_hard_encoding_chain_from_pool(self):
        """resolve_difficulty('hard') randomly selects encoding_chain from pool."""
        chains_seen = set()
        for _ in range(50):
            result = resolve_difficulty("hard")
            chains_seen.add(tuple(result["encoding_chain"]))
        # Should see more than one chain (random selection)
        assert len(chains_seen) > 1
        # All selected chains should be from the pool
        pool_tuples = {tuple(c) for c in HARD_ENCODING_CHAINS}
        assert chains_seen.issubset(pool_tuples)

    def test_hard_packet_count_in_range(self):
        """resolve_difficulty('hard') randomizes packet_count_target in 1000-5000."""
        for _ in range(20):
            result = resolve_difficulty("hard")
            assert 1000 <= result["packet_count_target"] <= 5000

    def test_override_noise_ratio(self):
        """resolve_difficulty with noise_ratio override replaces preset value."""
        result = resolve_difficulty("easy", overrides={"noise_ratio": 0.5})
        assert result["noise_ratio"] == 0.5

    def test_override_encoding_chain_on_hard(self):
        """resolve_difficulty('hard') with encoding_chain override uses specified chain."""
        result = resolve_difficulty(
            "hard", overrides={"encoding_chain": ["rot13", "hex"]}
        )
        assert result["encoding_chain"] == ["rot13", "hex"]

    def test_override_packet_count(self):
        """resolve_difficulty with packet_count override sets packet_count_target."""
        result = resolve_difficulty("medium", overrides={"packet_count": 350})
        assert result["packet_count_target"] == 350

    def test_override_preserves_other_fields(self):
        """Override merging only changes specified fields."""
        result = resolve_difficulty("easy", overrides={"noise_ratio": 0.5})
        assert result["encoding_chain"] == ["plaintext"]
        assert result["noise_types"] == ["ARP"]
        assert result["timing_jitter_ms"] == (10.0, 50.0)

    def test_invalid_difficulty_raises_key_error(self):
        """resolve_difficulty raises KeyError for invalid difficulty name."""
        with pytest.raises(KeyError):
            resolve_difficulty("nightmare")

    def test_case_insensitive_lookup(self):
        """resolve_difficulty handles case-insensitive difficulty names."""
        result = resolve_difficulty("Easy")
        assert result["encoding_chain"] == ["plaintext"]

        result2 = resolve_difficulty("MEDIUM")
        assert result2["encoding_chain"] == ["base64"]


# ---------------------------------------------------------------------------
# Split Count Fields (Phase 10)
# ---------------------------------------------------------------------------


class TestDifficultyPresetSplitCount:
    """Tests for DifficultyPreset split_count_min/split_count_max fields."""

    def test_preset_accepts_split_count_fields(self):
        """DifficultyPreset accepts split_count_min and split_count_max."""
        preset = DifficultyPreset(
            name="easy",
            encoding_chain=["plaintext"],
            noise_ratio=0.2,
            packet_count_min=20,
            packet_count_max=50,
            noise_types=["ARP"],
            timing_jitter_ms=(10.0, 50.0),
            split_count_min=2,
            split_count_max=4,
        )
        assert preset.split_count_min == 2
        assert preset.split_count_max == 4

    def test_split_count_defaults_to_one(self):
        """Default split_count_min and split_count_max are both 1."""
        preset = DifficultyPreset(
            name="easy",
            encoding_chain=["plaintext"],
            noise_ratio=0.2,
            packet_count_min=20,
            packet_count_max=50,
            noise_types=["ARP"],
            timing_jitter_ms=(10.0, 50.0),
        )
        assert preset.split_count_min == 1
        assert preset.split_count_max == 1

    def test_split_count_min_exceeds_max_rejected(self):
        """DifficultyPreset rejects split_count_min > split_count_max."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["plaintext"],
                noise_ratio=0.2,
                packet_count_min=20,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
                split_count_min=5,
                split_count_max=3,
            )

    def test_split_count_min_below_one_rejected(self):
        """DifficultyPreset rejects split_count_min < 1."""
        with pytest.raises(ValidationError):
            DifficultyPreset(
                name="easy",
                encoding_chain=["plaintext"],
                noise_ratio=0.2,
                packet_count_min=20,
                packet_count_max=50,
                noise_types=["ARP"],
                timing_jitter_ms=(10.0, 50.0),
                split_count_min=0,
                split_count_max=1,
            )


class TestPresetSplitCountValues:
    """Tests for preset constants split_count values."""

    def test_easy_split_count(self):
        """EASY preset has split_count 1-1 (no splitting)."""
        assert EASY.split_count_min == 1
        assert EASY.split_count_max == 1

    def test_medium_split_count(self):
        """MEDIUM preset has split_count 2-2."""
        assert MEDIUM.split_count_min == 2
        assert MEDIUM.split_count_max == 2

    def test_hard_split_count(self):
        """HARD preset has split_count 3-4."""
        assert HARD.split_count_min == 3
        assert HARD.split_count_max == 4


class TestResolveDifficultySplitCount:
    """Tests for resolve_difficulty returning split_count."""

    def test_easy_returns_split_count_one(self):
        """resolve_difficulty('easy') returns split_count=1."""
        result = resolve_difficulty("easy")
        assert result["split_count"] == 1

    def test_medium_returns_split_count_two(self):
        """resolve_difficulty('medium') returns split_count=2."""
        result = resolve_difficulty("medium")
        assert result["split_count"] == 2

    def test_hard_returns_split_count_in_range(self):
        """resolve_difficulty('hard') returns split_count in [3, 4]."""
        for _ in range(20):
            result = resolve_difficulty("hard")
            assert 3 <= result["split_count"] <= 4

    def test_none_returns_none_unchanged(self):
        """resolve_difficulty(None) still returns None."""
        assert resolve_difficulty(None) is None
