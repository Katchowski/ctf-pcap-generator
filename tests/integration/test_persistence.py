"""Tests for JSON persistence helpers -- settings and generation history."""

import json

from ctf_pcaps.integration.persistence import (
    load_ctfd_config,
    load_history,
    save_ctfd_config,
    save_history_entry,
    update_history_push_status,
)


class TestLoadCtfdConfig:
    """Tests for load_ctfd_config."""

    def test_returns_defaults_when_file_missing(self, tmp_path):
        result = load_ctfd_config(tmp_path)
        assert result == {"url": "", "token": ""}

    def test_loads_existing_config(self, tmp_path):
        config_file = tmp_path / "ctfd_config.json"
        config_file.write_text(
            json.dumps({"url": "https://ctfd.example.com", "token": "abc123"}),
            encoding="utf-8",
        )
        result = load_ctfd_config(tmp_path)
        assert result["url"] == "https://ctfd.example.com"
        assert result["token"] == "abc123"

    def test_handles_corrupt_json_gracefully(self, tmp_path):
        config_file = tmp_path / "ctfd_config.json"
        config_file.write_text("{invalid json!!!", encoding="utf-8")
        result = load_ctfd_config(tmp_path)
        assert result == {"url": "", "token": ""}


class TestSaveCtfdConfig:
    """Tests for save_ctfd_config."""

    def test_save_and_load_roundtrip(self, tmp_path):
        save_ctfd_config(tmp_path, url="https://ctfd.example.com", token="secret")
        result = load_ctfd_config(tmp_path)
        assert result["url"] == "https://ctfd.example.com"
        assert result["token"] == "secret"

    def test_strips_trailing_slash_from_url(self, tmp_path):
        save_ctfd_config(tmp_path, url="https://ctfd.example.com/", token="token")
        result = load_ctfd_config(tmp_path)
        assert result["url"] == "https://ctfd.example.com"

    def test_strips_multiple_trailing_slashes(self, tmp_path):
        save_ctfd_config(tmp_path, url="https://ctfd.example.com///", token="token")
        result = load_ctfd_config(tmp_path)
        assert result["url"] == "https://ctfd.example.com"


class TestLoadHistory:
    """Tests for load_history."""

    def test_returns_empty_list_when_file_missing(self, tmp_path):
        result = load_history(tmp_path)
        assert result == []

    def test_loads_existing_history(self, tmp_path):
        history_file = tmp_path / "generation_history.json"
        entries = [{"filename": "test.pcap", "pushed": False}]
        history_file.write_text(json.dumps(entries), encoding="utf-8")
        result = load_history(tmp_path)
        assert len(result) == 1
        assert result[0]["filename"] == "test.pcap"

    def test_handles_corrupt_json_gracefully(self, tmp_path):
        history_file = tmp_path / "generation_history.json"
        history_file.write_text("not valid json at all", encoding="utf-8")
        result = load_history(tmp_path)
        assert result == []


class TestSaveHistoryEntry:
    """Tests for save_history_entry."""

    def test_creates_file_when_missing(self, tmp_path):
        entry = {
            "filename": "syn_scan_20260307.pcap",
            "scenario_slug": "syn_scan",
            "scenario_name": "SYN Port Scan",
            "scenario_description": "Simulates a SYN port scan",
            "category": "network_attack",
            "category_label": "Network Attack",
            "flag_text": "flag{test}",
            "difficulty": "medium",
            "timestamp": "2026-03-07T14:30:22",
            "file_size_bytes": 52480,
            "pushed": False,
            "push_challenge_id": None,
            "push_challenge_name": None,
            "push_timestamp": None,
        }
        save_history_entry(tmp_path, entry)

        result = load_history(tmp_path)
        assert len(result) == 1
        assert result[0]["filename"] == "syn_scan_20260307.pcap"
        assert result[0]["pushed"] is False

    def test_appends_to_existing_list(self, tmp_path):
        entry1 = {"filename": "first.pcap", "pushed": False}
        entry2 = {"filename": "second.pcap", "pushed": False}

        save_history_entry(tmp_path, entry1)
        save_history_entry(tmp_path, entry2)

        result = load_history(tmp_path)
        assert len(result) == 2
        assert result[0]["filename"] == "first.pcap"
        assert result[1]["filename"] == "second.pcap"


class TestUpdateHistoryPushStatus:
    """Tests for update_history_push_status."""

    def test_updates_correct_entry(self, tmp_path):
        # Set up two entries
        entry1 = {"filename": "first.pcap", "pushed": False, "push_challenge_id": None}
        entry2 = {
            "filename": "second.pcap",
            "pushed": False,
            "push_challenge_id": None,
        }
        save_history_entry(tmp_path, entry1)
        save_history_entry(tmp_path, entry2)

        # Update the second entry
        update_history_push_status(
            tmp_path,
            filename="second.pcap",
            challenge_id=42,
            challenge_name="My Challenge",
        )

        result = load_history(tmp_path)
        assert result[0]["pushed"] is False
        assert result[1]["pushed"] is True
        assert result[1]["push_challenge_id"] == 42
        assert result[1]["push_challenge_name"] == "My Challenge"
        assert result[1]["push_timestamp"] is not None

    def test_nonexistent_filename_is_noop(self, tmp_path):
        entry = {"filename": "exists.pcap", "pushed": False}
        save_history_entry(tmp_path, entry)

        # Try to update a filename that doesn't exist
        update_history_push_status(
            tmp_path,
            filename="nonexistent.pcap",
            challenge_id=99,
            challenge_name="Ghost",
        )

        result = load_history(tmp_path)
        assert len(result) == 1
        assert result[0]["pushed"] is False
