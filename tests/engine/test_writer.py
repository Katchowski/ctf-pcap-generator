"""Tests for streaming PcapWriter wrapper with atomic rename and limits."""

import re

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

from ctf_pcaps.engine.writer import LimitsExceededError, stream_to_pcap


def _packet_iter(count=5):
    """Generate simple TCP packets for testing."""
    for _ in range(count):
        yield IP(dst="1.2.3.4") / TCP(dport=80)


class TestStreamToPcap:
    """Tests for stream_to_pcap() streaming writer."""

    def test_writes_readable_pcap(self, tmp_path):
        """stream_to_pcap() writes packets that rdpcap() can read back."""
        path, count = stream_to_pcap(_packet_iter(3), tmp_path)
        packets = rdpcap(str(path))
        assert len(packets) == 3

    def test_uuid_filename_pattern(self, tmp_path):
        """stream_to_pcap() creates a UUID-based filename (8 hex chars)."""
        path, _ = stream_to_pcap(_packet_iter(1), tmp_path)
        assert re.match(r"^[0-9a-f]{8}\.pcap$", path.name)

    def test_returns_path_and_count(self, tmp_path):
        """stream_to_pcap() returns (final_path, packet_count) tuple."""
        path, count = stream_to_pcap(_packet_iter(5), tmp_path)
        assert path.exists()
        assert count == 5

    def test_progress_callback(self, tmp_path):
        """stream_to_pcap() calls progress callback every N packets."""
        calls = []
        stream_to_pcap(
            _packet_iter(10),
            tmp_path,
            callback=lambda n: calls.append(n),
            callback_interval=3,
        )
        # At packets 3, 6, 9
        assert calls == [3, 6, 9]

    def test_packet_count_limit(self, tmp_path):
        """stream_to_pcap() raises LimitsExceededError on packet count."""
        with pytest.raises(LimitsExceededError, match="Packet count"):
            stream_to_pcap(_packet_iter(10), tmp_path, max_packets=5)

    def test_file_size_limit(self, tmp_path):
        """stream_to_pcap() raises LimitsExceededError on file size."""
        # Generate many packets to exceed a very small size limit
        def many_packets():
            for _ in range(1000):
                yield IP(dst="1.2.3.4") / TCP(dport=80) / (b"X" * 1000)

        with pytest.raises(LimitsExceededError, match="File size"):
            stream_to_pcap(many_packets(), tmp_path, max_size_mb=0)

    def test_cleanup_temp_file_on_failure(self, tmp_path):
        """stream_to_pcap() removes temp file on failure."""

        def failing_iter():
            yield IP(dst="1.2.3.4") / TCP(dport=80)
            raise RuntimeError("mid-stream failure")

        with pytest.raises(RuntimeError, match="mid-stream"):
            stream_to_pcap(failing_iter(), tmp_path)

        # No .pcap.tmp files should remain
        tmp_files = list(tmp_path.glob("*.pcap.tmp"))
        assert tmp_files == []

    def test_creates_output_directory(self, tmp_path):
        """stream_to_pcap() creates output directory if it does not exist."""
        new_dir = tmp_path / "nested" / "output"
        path, count = stream_to_pcap(_packet_iter(1), new_dir)
        assert new_dir.exists()
        assert path.exists()

    def test_atomic_rename_no_tmp_files(self, tmp_path):
        """No .pcap.tmp files remain after successful write."""
        stream_to_pcap(_packet_iter(3), tmp_path)
        tmp_files = list(tmp_path.glob("*.pcap.tmp"))
        assert tmp_files == []

    def test_final_file_at_returned_path(self, tmp_path):
        """Final .pcap file exists at the returned path."""
        path, _ = stream_to_pcap(_packet_iter(3), tmp_path)
        assert path.exists()
        assert path.suffix == ".pcap"

    def test_cleanup_on_limits_exceeded(self, tmp_path):
        """Temp file cleaned up when LimitsExceededError is raised."""
        with pytest.raises(LimitsExceededError):
            stream_to_pcap(_packet_iter(10), tmp_path, max_packets=3)
        tmp_files = list(tmp_path.glob("*.pcap.tmp"))
        assert tmp_files == []
