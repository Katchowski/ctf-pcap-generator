"""Tests for stale PCAP file cleanup sweep."""

import os
import time

import pytest

from ctf_pcaps.engine.cleanup import sweep_stale_files


class TestSweepStaleFiles:
    """Tests for sweep_stale_files() TTL-based cleanup."""

    def _age_file(self, path, hours):
        """Set file mtime to `hours` hours in the past."""
        old_time = time.time() - (hours * 3600)
        os.utime(path, (old_time, old_time))

    def test_deletes_old_pcap_files(self, tmp_path):
        """sweep_stale_files() deletes .pcap files older than ttl_hours."""
        old_file = tmp_path / "old.pcap"
        old_file.write_bytes(b"fake pcap")
        self._age_file(old_file, 48)

        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 1
        assert not old_file.exists()

    def test_keeps_new_pcap_files(self, tmp_path):
        """sweep_stale_files() keeps .pcap files newer than ttl_hours."""
        new_file = tmp_path / "new.pcap"
        new_file.write_bytes(b"fake pcap")
        # File is freshly created, well within TTL

        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 0
        assert new_file.exists()

    def test_deletes_orphaned_tmp_files(self, tmp_path):
        """sweep_stale_files() deletes orphaned .pcap.tmp files older than 1 hour."""
        orphan = tmp_path / "orphan.pcap.tmp"
        orphan.write_bytes(b"incomplete")
        self._age_file(orphan, 2)  # 2 hours old, > 1 hour threshold

        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 1
        assert not orphan.exists()

    def test_keeps_recent_tmp_files(self, tmp_path):
        """sweep_stale_files() keeps .pcap.tmp files newer than 1 hour."""
        recent_tmp = tmp_path / "recent.pcap.tmp"
        recent_tmp.write_bytes(b"in progress")
        # Freshly created, within 1 hour

        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 0
        assert recent_tmp.exists()

    def test_returns_deleted_count(self, tmp_path):
        """sweep_stale_files() returns correct count of deleted files."""
        for i in range(3):
            f = tmp_path / f"old_{i}.pcap"
            f.write_bytes(b"fake")
            self._age_file(f, 48)

        new_file = tmp_path / "keep.pcap"
        new_file.write_bytes(b"keep me")

        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 3

    def test_empty_directory(self, tmp_path):
        """sweep_stale_files() handles empty directory without error."""
        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 0

    def test_missing_directory(self, tmp_path):
        """sweep_stale_files() handles missing directory gracefully."""
        missing = tmp_path / "nonexistent"
        count = sweep_stale_files(missing, ttl_hours=24)
        assert count == 0

    def test_ignores_non_pcap_files(self, tmp_path):
        """sweep_stale_files() ignores files that are not .pcap or .pcap.tmp."""
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("keep me")
        self._age_file(txt_file, 48)

        count = sweep_stale_files(tmp_path, ttl_hours=24)
        assert count == 0
        assert txt_file.exists()
