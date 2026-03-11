"""Unit tests for the flag embedding module.

Tests cover: flag assembly, encoding/decoding, JSON payload construction,
flag packet building, address extraction, iterator-based embedding,
verification read-back, and stealth checking.

No Flask imports allowed in engine tests.
"""

import base64
import codecs
import json
import os
import tempfile

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import wrpcap

from ctf_pcaps.engine.difficulty import HARD_ENCODING_CHAINS
from ctf_pcaps.engine.flag import (
    ENCODERS,
    _build_solve_steps_chain,
    assemble_flag,
    build_flag_packet,
    build_flag_payload,
    decode_flag,
    decode_flag_chain,
    embed_flag_packet,
    encode_flag,
    encode_flag_chain,
    extract_addresses,
    extract_printable_strings,
    verify_flag_in_pcap,
    verify_stealth,
)

# ---------------------------------------------------------------------------
# Flag Assembly (FLAG-01)
# ---------------------------------------------------------------------------


class TestAssembleFlag:
    """Tests for assemble_flag function."""

    def test_default_wrapper(self):
        result = assemble_flag("secret_data")
        assert result == "flag{secret_data}"

    def test_custom_wrapper(self):
        result = assemble_flag("secret_data", wrapper="CTF")
        assert result == "CTF{secret_data}"

    def test_auto_generated_text(self):
        result = assemble_flag(inner_text=None)
        assert result.startswith("flag{")
        assert result.endswith("}")
        inner = result[5:-1]  # Extract text between flag{ and }
        assert len(inner) == 16  # secrets.token_hex(8) produces 16 chars
        # Verify it's valid hex
        int(inner, 16)

    def test_custom_wrapper_with_custom_text(self):
        result = assemble_flag("mytext", wrapper="MYCTF")
        assert result == "MYCTF{mytext}"

    def test_auto_generated_is_random(self):
        """Two auto-generated flags should differ (with overwhelming probability)."""
        flag1 = assemble_flag()
        flag2 = assemble_flag()
        assert flag1 != flag2


# ---------------------------------------------------------------------------
# Encoding (FLAG-03)
# ---------------------------------------------------------------------------


class TestEncoding:
    """Tests for encode_flag and decode_flag functions."""

    def test_encode_plaintext(self):
        assert encode_flag("flag{test}", "plaintext") == "flag{test}"

    def test_encode_base64(self):
        expected = base64.b64encode(b"flag{test}").decode()
        assert encode_flag("flag{test}", "base64") == expected

    def test_encode_hex(self):
        expected = b"flag{test}".hex()
        assert encode_flag("flag{test}", "hex") == expected

    def test_encode_rot13(self):
        expected = codecs.encode("flag{test}", "rot_13")
        assert encode_flag("flag{test}", "rot13") == expected

    def test_decode_plaintext_roundtrip(self):
        original = "flag{test}"
        encoded = encode_flag(original, "plaintext")
        assert decode_flag(encoded, "plaintext") == original

    def test_decode_base64_roundtrip(self):
        original = "flag{test}"
        encoded = encode_flag(original, "base64")
        assert decode_flag(encoded, "base64") == original

    def test_decode_hex_roundtrip(self):
        original = "flag{test}"
        encoded = encode_flag(original, "hex")
        assert decode_flag(encoded, "hex") == original

    def test_decode_rot13_roundtrip(self):
        original = "flag{test}"
        encoded = encode_flag(original, "rot13")
        assert decode_flag(encoded, "rot13") == original

    def test_invalid_encoding_raises(self):
        with pytest.raises(ValueError, match="Unknown encoding"):
            encode_flag("flag{test}", "invalid_encoding")

    def test_invalid_decoding_raises(self):
        with pytest.raises(ValueError, match="Unknown encoding"):
            decode_flag("flag{test}", "invalid_encoding")

    def test_encoders_registry_has_four_entries(self):
        assert len(ENCODERS) == 4
        assert set(ENCODERS.keys()) == {"plaintext", "base64", "hex", "rot13"}


# ---------------------------------------------------------------------------
# JSON Payload Construction
# ---------------------------------------------------------------------------


class TestBuildFlagPayload:
    """Tests for build_flag_payload function."""

    def test_returns_bytes(self):
        result = build_flag_payload("encoded_data", "10.0.0.1", "10.0.0.2", "abc123")
        assert isinstance(result, bytes)

    def test_valid_json(self):
        result = build_flag_payload("encoded_data", "10.0.0.1", "10.0.0.2", "abc123")
        data = json.loads(result.decode())
        assert "src" in data
        assert "dst" in data
        assert "timestamp" in data
        assert "session_id" in data
        assert "data" in data

    def test_json_data_field_contains_encoded_flag(self):
        result = build_flag_payload("ZmxhZ3t0ZXN0fQ==", "10.0.0.1", "10.0.0.2", "x")
        data = json.loads(result.decode())
        assert data["data"] == "ZmxhZ3t0ZXN0fQ=="

    def test_json_contains_correct_ips(self):
        result = build_flag_payload("data", "192.168.1.1", "10.0.0.5", "sid")
        data = json.loads(result.decode())
        assert data["src"] == "192.168.1.1"
        assert data["dst"] == "10.0.0.5"

    def test_json_contains_session_id(self):
        result = build_flag_payload("data", "1.2.3.4", "5.6.7.8", "sess_99")
        data = json.loads(result.decode())
        assert data["session_id"] == "sess_99"


# ---------------------------------------------------------------------------
# Flag Packet Construction
# ---------------------------------------------------------------------------


class TestBuildFlagPacket:
    """Tests for build_flag_packet function."""

    def test_tcp_packet(self):
        payload = b'{"data": "test"}'
        pkt = build_flag_packet("tcp", "10.0.0.1", "10.0.0.2", 12345, 80, payload)
        assert pkt.haslayer(IP)
        assert pkt.haslayer(TCP)
        assert pkt.haslayer(Raw)
        assert pkt[IP].src == "10.0.0.1"
        assert pkt[IP].dst == "10.0.0.2"
        assert pkt[TCP].sport == 12345
        assert pkt[TCP].dport == 80
        assert pkt[TCP].flags == "PA"  # PSH+ACK
        assert pkt[Raw].load == payload

    def test_udp_packet(self):
        payload = b'{"data": "test"}'
        pkt = build_flag_packet("udp", "10.0.0.1", "10.0.0.2", 12345, 53, payload)
        assert pkt.haslayer(IP)
        assert pkt.haslayer(UDP)
        assert pkt.haslayer(Raw)
        assert pkt[IP].src == "10.0.0.1"
        assert pkt[IP].dst == "10.0.0.2"
        assert pkt[UDP].sport == 12345
        assert pkt[UDP].dport == 53
        assert pkt[Raw].load == payload

    def test_unsupported_protocol_raises(self):
        with pytest.raises(ValueError, match="Unsupported protocol"):
            build_flag_packet("icmp", "10.0.0.1", "10.0.0.2", 1, 1, b"data")


# ---------------------------------------------------------------------------
# Address Extraction (FLAG-02)
# ---------------------------------------------------------------------------


class TestExtractAddresses:
    """Tests for extract_addresses function."""

    def test_extract_from_tcp_packets(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=54321, dport=80)
        result = extract_addresses([pkt])
        assert result == {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "sport": 54321,
            "dport": 80,
        }

    def test_extract_from_udp_packets(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=11111, dport=53)
        result = extract_addresses([pkt])
        assert result == {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "sport": 11111,
            "dport": 53,
        }

    def test_empty_list_raises(self):
        with pytest.raises(ValueError):
            extract_addresses([])

    def test_skips_non_ip_packets(self):
        """If first packet has no IP, keep scanning."""
        non_ip = Raw(load=b"garbage")
        tcp = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=100, dport=200)
        result = extract_addresses([non_ip, tcp])
        assert result["src_ip"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# Flag Embedding Iterator (FLAG-02)
# ---------------------------------------------------------------------------


class TestEmbedFlagPacket:
    """Tests for embed_flag_packet function."""

    def test_increases_packet_count_by_one(self):
        packets = [IP() / TCP() for _ in range(10)]
        flag_pkt = IP() / TCP() / Raw(load=b"FLAG")
        result = list(embed_flag_packet(iter(packets), flag_pkt))
        assert len(result) == 11

    def test_flag_not_in_first_three(self):
        packets = [IP() / TCP() for _ in range(20)]
        flag_pkt = IP() / TCP() / Raw(load=b"FLAG_MARKER")
        result = list(embed_flag_packet(iter(packets), flag_pkt))
        # Flag should not be at positions 0, 1, or 2
        for i in range(3):
            assert not (
                result[i].haslayer(Raw) and result[i][Raw].load == b"FLAG_MARKER"
            )

    def test_flag_not_in_last_four(self):
        packets = [IP() / TCP() for _ in range(20)]
        flag_pkt = IP() / TCP() / Raw(load=b"FLAG_MARKER")
        result = list(embed_flag_packet(iter(packets), flag_pkt))
        # Flag should not be in last 4 positions of the 21-item list
        for i in range(len(result) - 4, len(result)):
            assert not (
                result[i].haslayer(Raw) and result[i][Raw].load == b"FLAG_MARKER"
            )

    def test_short_stream_clamps_to_middle(self):
        """Very short streams (< 8 packets) should clamp insertion to middle."""
        packets = [IP() / TCP() for _ in range(4)]
        flag_pkt = IP() / TCP() / Raw(load=b"FLAG_MARKER")
        result = list(embed_flag_packet(iter(packets), flag_pkt))
        assert len(result) == 5
        # Flag should be at position total//2 = 2
        assert result[2].haslayer(Raw) and result[2][Raw].load == b"FLAG_MARKER"

    def test_randomized_position(self):
        """Different calls should sometimes produce different positions."""
        packets = [IP() / TCP() for _ in range(50)]
        flag_pkt = IP() / TCP() / Raw(load=b"FLAG_MARKER")

        positions = set()
        for _ in range(20):
            result = list(embed_flag_packet(iter(packets), flag_pkt))
            for idx, pkt in enumerate(result):
                if pkt.haslayer(Raw) and pkt[Raw].load == b"FLAG_MARKER":
                    positions.add(idx)
                    break

        # With 20 attempts on a 50-packet stream, we should see > 1 position
        assert len(positions) > 1


# ---------------------------------------------------------------------------
# Verification Read-Back (FLAG-04)
# ---------------------------------------------------------------------------


class TestVerifyFlagInPcap:
    """Tests for verify_flag_in_pcap function."""

    def _write_pcap_with_flag(self, flag_text, encoding="plaintext"):
        """Helper: create a PCAP with a flag packet and return path."""
        encoded = encode_flag(flag_text, encoding)
        _, decode_fn = ENCODERS[encoding]
        payload = build_flag_payload(
            encoded, "10.0.0.1", "10.0.0.2", "test_session"
        )
        flag_pkt = build_flag_packet(
            "tcp", "10.0.0.1", "10.0.0.2", 12345, 80, payload
        )
        # Some filler packets
        filler = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
            for _ in range(5)
        ]
        all_packets = filler[:3] + [flag_pkt] + filler[3:]

        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        wrpcap(path, all_packets)
        return path, decode_fn

    def test_finds_flag_plaintext(self):
        path, decode_fn = self._write_pcap_with_flag("flag{test}", "plaintext")
        try:
            result = verify_flag_in_pcap(path, "flag{test}", "plaintext", decode_fn)
            assert result["verified"] is True
            assert result["packet_index"] is not None
            assert len(result["solve_steps"]) > 0
        finally:
            os.unlink(path)

    def test_finds_flag_base64(self):
        path, decode_fn = self._write_pcap_with_flag("flag{test}", "base64")
        try:
            result = verify_flag_in_pcap(path, "flag{test}", "base64", decode_fn)
            assert result["verified"] is True
        finally:
            os.unlink(path)

    def test_returns_false_when_flag_absent(self):
        """PCAP with no flag packet should return verified=False."""
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
            for _ in range(5)
        ]
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        wrpcap(path, packets)
        try:
            _, decode_fn = ENCODERS["plaintext"]
            result = verify_flag_in_pcap(
                path, "flag{missing}", "plaintext", decode_fn
            )
            assert result["verified"] is False
            assert result["packet_index"] is None
            assert result["solve_steps"] == []
        finally:
            os.unlink(path)

    def test_solve_steps_use_wireshark_indexing(self):
        """Solve steps should use 1-indexed frame numbers (Wireshark style)."""
        path, decode_fn = self._write_pcap_with_flag("flag{test}", "plaintext")
        try:
            result = verify_flag_in_pcap(path, "flag{test}", "plaintext", decode_fn)
            assert result["verified"] is True
            # The flag is at scapy index 3 (0-indexed), so Wireshark frame = 4
            wireshark_frame = result["packet_index"] + 1
            # At least one solve step should mention the frame number
            steps_text = " ".join(result["solve_steps"])
            assert str(wireshark_frame) in steps_text
        finally:
            os.unlink(path)

    def test_solve_steps_include_encoding_instruction(self):
        """Solve steps should include encoding-specific decoding instruction."""
        path, decode_fn = self._write_pcap_with_flag("flag{test}", "base64")
        try:
            result = verify_flag_in_pcap(path, "flag{test}", "base64", decode_fn)
            assert result["verified"] is True
            steps_text = " ".join(result["solve_steps"]).lower()
            assert "base64" in steps_text
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Stealth Verification (FLAG-05)
# ---------------------------------------------------------------------------


class TestExtractPrintableStrings:
    """Tests for extract_printable_strings function."""

    def test_extracts_ascii_runs(self):
        data = b"\x00\x00hello world\x00\x00"
        result = extract_printable_strings(data)
        assert "hello world" in result

    def test_min_length_filter(self):
        data = b"\x00ab\x00abcde\x00"
        result = extract_printable_strings(data, min_length=4)
        assert "abcde" in result
        # "ab" is too short
        assert "ab" not in result

    def test_replicates_gnu_strings(self):
        """Printable ASCII runs >= 4 chars should be extracted."""
        data = b"\x01\x02ABCD\x03\x04EF\x05GHIJKL\x06"
        result = extract_printable_strings(data, min_length=4)
        assert "ABCD" in result
        assert "GHIJKL" in result
        assert "EF" not in result  # Only 2 chars


class TestVerifyStealth:
    """Tests for verify_stealth function."""

    def test_plaintext_always_passes(self):
        """Plaintext encoding always passes stealth."""
        flag_text = "flag{test}"
        payload = build_flag_payload(
            flag_text, "10.0.0.1", "10.0.0.2", "sid"
        )
        pkt = build_flag_packet(
            "tcp", "10.0.0.1", "10.0.0.2", 12345, 80, payload
        )
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        wrpcap(path, [pkt])
        try:
            assert verify_stealth(path, flag_text, "plaintext") is True
        finally:
            os.unlink(path)

    def test_base64_passes_when_flag_not_in_strings(self):
        """Base64 flag should pass stealth when literal is absent."""
        flag_text = "flag{secret_data}"
        encoded = encode_flag(flag_text, "base64")
        payload = build_flag_payload(
            encoded, "10.0.0.1", "10.0.0.2", "sid"
        )
        pkt = build_flag_packet(
            "tcp", "10.0.0.1", "10.0.0.2", 12345, 80, payload
        )
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        wrpcap(path, [pkt])
        try:
            assert verify_stealth(path, flag_text, "base64") is True
        finally:
            os.unlink(path)

    def test_stealth_fails_when_literal_flag_in_raw_bytes(self):
        """Literal flag in raw PCAP for non-plaintext = fail."""
        flag_text = "flag{test}"
        # Literal flag text as raw payload (simulating encoding bug)
        payload = flag_text.encode()
        pkt = build_flag_packet(
            "tcp", "10.0.0.1", "10.0.0.2", 12345, 80, payload
        )
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        wrpcap(path, [pkt])
        try:
            # base64 encoding but literal flag in PCAP = stealth fail
            assert verify_stealth(path, flag_text, "base64") is False
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Chained Encoding (DIFF-01)
# ---------------------------------------------------------------------------


class TestChainedEncoding:
    """Tests for encode_flag_chain and decode_flag_chain functions."""

    def test_single_element_chain_equivalence(self):
        """Single-element chain produces same result as encode_flag."""
        flag_text = "flag{test}"
        assert encode_flag_chain(flag_text, ["base64"]) == encode_flag(
            flag_text, "base64"
        )

    def test_chain_applies_in_order(self):
        """encode_flag_chain applies encodings in order: base64 first, then hex."""
        flag_text = "flag{test}"
        # Manual: base64 first, then hex
        step1 = encode_flag(flag_text, "base64")
        step2 = encode_flag(step1, "hex")
        assert encode_flag_chain(flag_text, ["base64", "hex"]) == step2

    def test_decode_chain_reverses_order(self):
        """decode_flag_chain decodes in reverse order: hex first, then base64."""
        flag_text = "flag{test}"
        encoded = encode_flag_chain(flag_text, ["base64", "hex"])
        decoded = decode_flag_chain(encoded, ["base64", "hex"])
        assert decoded == flag_text

    @pytest.mark.parametrize(
        "chain",
        HARD_ENCODING_CHAINS,
        ids=["-".join(c) for c in HARD_ENCODING_CHAINS],
    )
    def test_roundtrip_all_hard_chains(self, chain):
        """Roundtrip: decode_flag_chain(encode_flag_chain(text, chain), chain) == text."""
        flag_text = "flag{roundtrip_test_value}"
        encoded = encode_flag_chain(flag_text, chain)
        decoded = decode_flag_chain(encoded, chain)
        assert decoded == flag_text

    def test_unknown_encoding_in_chain_raises(self):
        """encode_flag_chain raises ValueError for unknown encoding in chain."""
        with pytest.raises(ValueError, match="Unknown encoding"):
            encode_flag_chain("flag{test}", ["base64", "unknown"])

    def test_decode_unknown_encoding_in_chain_raises(self):
        """decode_flag_chain raises ValueError for unknown encoding in chain."""
        with pytest.raises(ValueError, match="Unknown encoding"):
            decode_flag_chain("encoded_data", ["base64", "unknown"])

    @pytest.mark.parametrize(
        "chain",
        HARD_ENCODING_CHAINS,
        ids=["-".join(c) for c in HARD_ENCODING_CHAINS],
    )
    def test_stealth_passes_for_hard_chains(self, chain):
        """Stealth verification passes for all HARD_ENCODING_CHAINS."""
        flag_text = "flag{stealth_chain_test}"
        encoded = encode_flag_chain(flag_text, chain)
        payload = build_flag_payload(encoded, "10.0.0.1", "10.0.0.2", "sid")
        pkt = build_flag_packet("tcp", "10.0.0.1", "10.0.0.2", 12345, 80, payload)
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        wrpcap(path, [pkt])
        try:
            # Use first encoding in chain as the "encoding" label --
            # stealth check only cares that it's not "plaintext"
            assert verify_stealth(path, flag_text, chain[0]) is True
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Chained Solve Steps (DIFF-01)
# ---------------------------------------------------------------------------


class TestBuildSolveStepsChain:
    """Tests for _build_solve_steps_chain function."""

    def test_produces_reverse_order_decode_steps(self):
        """Solve steps list decoding in reverse order of encoding chain."""
        steps = _build_solve_steps_chain(
            packet_index=5,
            encoding_chain=["base64", "hex"],
            payload_data={"data": "encoded"},
        )
        steps_text = " ".join(steps).lower()
        # hex should be decoded first (reverse order), then base64
        hex_pos = steps_text.find("hex")
        base64_pos = steps_text.find("base64")
        assert hex_pos < base64_pos, "hex decode should come before base64 decode"

    def test_includes_wireshark_frame_number(self):
        """Solve steps include Wireshark 1-indexed frame number."""
        steps = _build_solve_steps_chain(
            packet_index=9,
            encoding_chain=["rot13", "base64"],
            payload_data={"data": "encoded"},
        )
        steps_text = " ".join(steps)
        # Wireshark frame = packet_index + 1 = 10
        assert "#10" in steps_text

    def test_opening_steps_present(self):
        """Solve steps include opening steps (locate packet, examine payload, parse JSON)."""
        steps = _build_solve_steps_chain(
            packet_index=0,
            encoding_chain=["base64"],
            payload_data={"data": "encoded"},
        )
        assert len(steps) >= 3
        # First step should mention locating the packet
        assert "packet" in steps[0].lower() or "pcap" in steps[0].lower()

    def test_final_step_mentions_flag(self):
        """Final solve step mentions the flag."""
        steps = _build_solve_steps_chain(
            packet_index=0,
            encoding_chain=["base64", "hex"],
            payload_data={"data": "encoded"},
        )
        assert "flag" in steps[-1].lower()

    def test_three_element_chain_has_three_decode_steps(self):
        """A 3-element chain should produce 3 decode steps."""
        steps = _build_solve_steps_chain(
            packet_index=0,
            encoding_chain=["hex", "rot13", "base64"],
            payload_data={"data": "encoded"},
        )
        # Opening: locate, examine, parse = 3 steps
        # Decode: 3 steps (one per encoding in reverse)
        # Final: 1 step
        # Total >= 7
        assert len(steps) >= 7
