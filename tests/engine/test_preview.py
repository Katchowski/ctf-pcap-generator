"""Tests for the PCAP preview analysis module."""

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from ctf_pcaps.engine.preview import analyze_pcap, get_flag_status


@pytest.fixture()
def mixed_pcap(tmp_path):
    """Create a PCAP with mixed TCP, UDP, and ICMP packets."""
    pcap_path = tmp_path / "mixed.pcap"
    packets = [
        # 3 TCP packets between 10.0.0.1 and 10.0.0.2
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET /"),
        IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=12345)
        / Raw(b"HTTP/1.1 200"),
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"ACK"),
        # 2 UDP packets between 10.0.0.1 and 10.0.0.3
        IP(src="10.0.0.1", dst="10.0.0.3") / UDP(sport=5000, dport=53) / Raw(b"dns"),
        IP(src="10.0.0.3", dst="10.0.0.1") / UDP(sport=53, dport=5000) / Raw(b"resp"),
        # 1 ICMP packet
        IP(src="10.0.0.1", dst="10.0.0.4") / ICMP() / Raw(b"ping"),
    ]
    wrpcap(str(pcap_path), packets)
    return pcap_path


@pytest.fixture()
def empty_pcap(tmp_path):
    """Create an empty PCAP file (valid header, no packets)."""
    pcap_path = tmp_path / "empty.pcap"
    wrpcap(str(pcap_path), [])
    return pcap_path


@pytest.fixture()
def many_conversations_pcap(tmp_path):
    """Create a PCAP with more than 5 unique conversations."""
    pcap_path = tmp_path / "many_convos.pcap"
    packets = []
    for i in range(1, 8):
        # Each unique src-dst pair gets i packets
        for _ in range(i):
            packets.append(
                IP(src=f"10.0.0.{i}", dst=f"10.0.1.{i}")
                / TCP(sport=1000 + i, dport=80)
                / Raw(b"data")
            )
    wrpcap(str(pcap_path), packets)
    return pcap_path


class TestAnalyzePcap:
    """Tests for analyze_pcap function."""

    def test_returns_expected_keys(self, mixed_pcap):
        """analyze_pcap returns dict with all required top-level keys."""
        result = analyze_pcap(str(mixed_pcap))
        assert "packet_count" in result
        assert "protocols" in result
        assert "top_conversations" in result
        assert "timeline" in result
        assert "file_size_bytes" in result

    def test_packet_count(self, mixed_pcap):
        """analyze_pcap returns correct total packet count."""
        result = analyze_pcap(str(mixed_pcap))
        assert result["packet_count"] == 6

    def test_protocol_counting(self, mixed_pcap):
        """analyze_pcap counts TCP, UDP, ICMP separately."""
        result = analyze_pcap(str(mixed_pcap))
        protocols = {p["name"]: p["count"] for p in result["protocols"]}
        assert protocols["TCP"] == 3
        assert protocols["UDP"] == 2
        assert protocols["ICMP"] == 1

    def test_protocol_percentages(self, mixed_pcap):
        """Protocol percentages sum to approximately 100."""
        result = analyze_pcap(str(mixed_pcap))
        total_pct = sum(p["pct"] for p in result["protocols"])
        assert abs(total_pct - 100.0) < 1.0

    def test_protocols_sorted_by_count_descending(self, mixed_pcap):
        """Protocols are sorted by count in descending order."""
        result = analyze_pcap(str(mixed_pcap))
        counts = [p["count"] for p in result["protocols"]]
        assert counts == sorted(counts, reverse=True)

    def test_conversation_ranking(self, mixed_pcap):
        """Top conversations sorted by packet count descending."""
        result = analyze_pcap(str(mixed_pcap))
        convos = result["top_conversations"]
        assert len(convos) > 0
        counts = [c["count"] for c in convos]
        assert counts == sorted(counts, reverse=True)

    def test_conversation_has_required_keys(self, mixed_pcap):
        """Each conversation has src, dst, count keys."""
        result = analyze_pcap(str(mixed_pcap))
        for convo in result["top_conversations"]:
            assert "src" in convo
            assert "dst" in convo
            assert "count" in convo

    def test_conversation_max_5(self, many_conversations_pcap):
        """Top conversations limited to max 5 entries."""
        result = analyze_pcap(str(many_conversations_pcap))
        assert len(result["top_conversations"]) <= 5

    def test_timeline_keys(self, mixed_pcap):
        """Timeline contains required timestamp and rate keys."""
        result = analyze_pcap(str(mixed_pcap))
        timeline = result["timeline"]
        assert "duration_seconds" in timeline
        assert "first_packet" in timeline
        assert "last_packet" in timeline
        assert "avg_packet_rate" in timeline

    def test_file_size_bytes_present(self, mixed_pcap):
        """file_size_bytes is a positive integer."""
        result = analyze_pcap(str(mixed_pcap))
        assert result["file_size_bytes"] > 0

    def test_empty_pcap_returns_zeroed(self, empty_pcap):
        """Empty PCAP returns packet_count=0 with empty lists and zeroed timeline."""
        result = analyze_pcap(str(empty_pcap))
        assert result["packet_count"] == 0
        assert result["protocols"] == []
        assert result["top_conversations"] == []
        assert result["timeline"]["duration_seconds"] == 0
        assert result["timeline"]["avg_packet_rate"] == 0


class TestGetFlagStatus:
    """Tests for get_flag_status helper."""

    def test_returns_expected_keys(self):
        """get_flag_status returns dict with all expected keys."""
        entry = {"flag_text": "flag{test}", "difficulty": "medium"}
        result = get_flag_status(entry)
        assert "verified" in result
        assert "encoding_chain" in result
        assert "split_active" in result
        assert "split_count" in result

    def test_with_flag_text(self):
        """When flag_text is present, verified is True."""
        entry = {"flag_text": "flag{test}", "difficulty": "medium"}
        result = get_flag_status(entry)
        assert result["verified"] is True

    def test_without_flag_text(self):
        """When flag_text is empty/None, verified is False."""
        entry = {"flag_text": None, "difficulty": "medium"}
        result = get_flag_status(entry)
        assert result["verified"] is False

    def test_empty_entry(self):
        """Empty dict returns safe defaults."""
        result = get_flag_status({})
        assert result["verified"] is False
        assert result["split_active"] is False
        assert result["split_count"] == 1

    def test_encoding_chain_list_joined(self):
        """List encoding_chain is joined with ' -> ' separator."""
        entry = {"flag_text": "flag{x}", "encoding_chain": ["base64", "hex"]}
        result = get_flag_status(entry)
        assert result["encoding_chain"] == "base64 -> hex"

    def test_encoding_chain_single_item(self):
        """Single-item list encoding_chain returns that item as string."""
        entry = {"flag_text": "flag{x}", "encoding_chain": ["base64"]}
        result = get_flag_status(entry)
        assert result["encoding_chain"] == "base64"

    def test_encoding_chain_empty_list(self):
        """Empty list encoding_chain returns empty string."""
        entry = {"flag_text": "flag{x}", "encoding_chain": []}
        result = get_flag_status(entry)
        assert result["encoding_chain"] == ""

    def test_split_fields_from_entry(self):
        """split_active and split_count are read from entry."""
        entry = {"flag_text": "flag{x}", "split_active": True, "split_count": 3}
        result = get_flag_status(entry)
        assert result["split_active"] is True
        assert result["split_count"] == 3
