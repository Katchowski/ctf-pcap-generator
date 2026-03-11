"""Flag embedding module for CTF PCAP generation.

Provides flag assembly, encoding, packet construction, iterator-based
embedding, verification read-back, and stealth checking. This module
is the core flag system that all subsequent pipeline integration depends on.

Functions:
    assemble_flag: Combine wrapper + braces + inner text
    encode_flag: Encode flag text using named encoding
    decode_flag: Decode encoded flag text
    encode_flag_chain: Apply multiple encodings sequentially
    decode_flag_chain: Decode chained encoding in reverse order
    build_flag_payload: Build JSON payload bytes with connection metadata
    build_flag_packet: Construct Scapy packet matching scenario protocol
    extract_addresses: Extract IP/port from builder packets
    embed_flag_packet: Insert flag packet at random position in stream
    verify_flag_in_pcap: Read PCAP and verify decoded flag matches
    extract_printable_strings: Extract ASCII runs from binary data
    verify_stealth: Check literal flag text is not findable via strings

No Flask or integration imports allowed in engine modules.
"""

import base64
import codecs
import json
import random
import re
import secrets
import time
from collections.abc import Iterator
from typing import Any

import structlog
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import rdpcap

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Encoder Registry (FLAG-03)
# ---------------------------------------------------------------------------


def _encode_plaintext(flag: str) -> str:
    return flag


def _decode_plaintext(data: str) -> str:
    return data


def _encode_base64(flag: str) -> str:
    return base64.b64encode(flag.encode()).decode()


def _decode_base64(data: str) -> str:
    return base64.b64decode(data.encode()).decode()


def _encode_hex(flag: str) -> str:
    return flag.encode().hex()


def _decode_hex(data: str) -> str:
    return bytes.fromhex(data).decode()


def _encode_rot13(flag: str) -> str:
    return codecs.encode(flag, "rot_13")


def _decode_rot13(data: str) -> str:
    return codecs.decode(data, "rot_13")


ENCODERS: dict[str, tuple] = {
    "plaintext": (_encode_plaintext, _decode_plaintext),
    "base64": (_encode_base64, _decode_base64),
    "hex": (_encode_hex, _decode_hex),
    "rot13": (_encode_rot13, _decode_rot13),
}


def encode_flag(flag_text: str, encoding: str) -> str:
    """Encode flag text using the named encoding.

    Args:
        flag_text: The assembled flag string (e.g., "flag{secret}").
        encoding: One of "plaintext", "base64", "hex", "rot13".

    Returns:
        Encoded flag string.

    Raises:
        ValueError: If encoding is not recognized.
    """
    if encoding not in ENCODERS:
        raise ValueError(
            f"Unknown encoding '{encoding}'. "
            f"Available: {', '.join(sorted(ENCODERS.keys()))}"
        )
    encode_fn, _ = ENCODERS[encoding]
    result = encode_fn(flag_text)
    logger.info("flag_encoded", encoding=encoding)
    return result


def decode_flag(encoded_text: str, encoding: str) -> str:
    """Decode encoded flag text back to the original.

    Args:
        encoded_text: The encoded flag string.
        encoding: The encoding that was used.

    Returns:
        Decoded flag string.

    Raises:
        ValueError: If encoding is not recognized.
    """
    if encoding not in ENCODERS:
        raise ValueError(
            f"Unknown encoding '{encoding}'. "
            f"Available: {', '.join(sorted(ENCODERS.keys()))}"
        )
    _, decode_fn = ENCODERS[encoding]
    return decode_fn(encoded_text)


# ---------------------------------------------------------------------------
# Chained Encoding (DIFF-01)
# ---------------------------------------------------------------------------


def encode_flag_chain(flag_text: str, encoding_chain: list[str]) -> str:
    """Apply multiple encodings sequentially to flag text.

    Each encoding in the chain is applied in order, with the output
    of one becoming the input of the next.

    Args:
        flag_text: The assembled flag string to encode.
        encoding_chain: List of encoding names to apply in order.

    Returns:
        Encoded flag string after all encodings applied.

    Raises:
        ValueError: If any encoding in the chain is not recognized.
    """
    result = flag_text
    for encoding in encoding_chain:
        result = encode_flag(result, encoding)
    logger.info(
        "flag_chain_encoded",
        chain=encoding_chain,
        chain_length=len(encoding_chain),
    )
    return result


def decode_flag_chain(encoded_text: str, encoding_chain: list[str]) -> str:
    """Decode chained encoding by applying decodings in reverse order.

    Args:
        encoded_text: The encoded flag string.
        encoding_chain: The encoding chain that was used (will be reversed).

    Returns:
        Decoded flag string.

    Raises:
        ValueError: If any encoding in the chain is not recognized.
    """
    result = encoded_text
    for encoding in reversed(encoding_chain):
        result = decode_flag(result, encoding)
    return result


def _build_solve_steps_chain(
    packet_index: int, encoding_chain: list[str], payload_data: dict
) -> list[str]:
    """Build Wireshark-style solve steps for chained encoding.

    Uses 1-indexed frame numbers matching Wireshark display.
    Lists decoding steps in reverse order of the encoding chain.

    Args:
        packet_index: 0-indexed Scapy packet position.
        encoding_chain: The encoding chain used for the flag.
        payload_data: The parsed JSON payload dict.

    Returns:
        List of solve step strings.
    """
    wireshark_frame = packet_index + 1
    steps = [
        f"Open the PCAP in Wireshark and locate packet #{wireshark_frame}",
        "Examine the packet payload (Raw layer data)",
        "Parse the JSON payload to extract the 'data' field",
    ]

    # Decode steps in reverse order
    reversed_chain = list(reversed(encoding_chain))
    for i, encoding in enumerate(reversed_chain, start=1):
        label = encoding.upper() if encoding != "rot13" else "ROT13"
        if encoding == "base64":
            label = "Base64"
        elif encoding == "hex":
            label = "Hex"
        steps.append(f"Step {i}: Apply {label} decoding to the current value")

    steps.append("The final decoded text is the flag")
    return steps


# ---------------------------------------------------------------------------
# Flag Assembly (FLAG-01)
# ---------------------------------------------------------------------------


def assemble_flag(
    inner_text: str | None = None,
    wrapper: str = "flag",
) -> str:
    """Assemble a complete flag string.

    Args:
        inner_text: The flag content. Auto-generated 16-char hex if None.
        wrapper: The prefix before {. Default "flag" produces "flag{...}".

    Returns:
        Assembled flag like "flag{secret_data}" or "CTF{a1b2c3d4e5f6}".
    """
    if inner_text is None:
        inner_text = secrets.token_hex(8)  # 16-char random hex
    result = f"{wrapper}{{{inner_text}}}"
    logger.info(
        "flag_assembled", wrapper=wrapper, has_custom_text=inner_text is not None
    )
    return result


# ---------------------------------------------------------------------------
# JSON Payload Construction
# ---------------------------------------------------------------------------


def build_flag_payload(
    encoded_flag: str,
    src_ip: str,
    dst_ip: str,
    session_id: str,
    part: int | None = None,
    total: int | None = None,
) -> bytes:
    """Build realistic JSON payload containing the encoded flag.

    The JSON envelope includes connection metadata to make the flag
    packet look like structured application data, requiring students
    to parse the payload to find the encoded flag.

    When both part and total are provided, they are included in the
    JSON payload to indicate this is a split flag fragment. When
    omitted, the payload format is unchanged for backward compatibility.

    Args:
        encoded_flag: The encoded flag string to embed.
        src_ip: Source IP address for metadata.
        dst_ip: Destination IP address for metadata.
        session_id: Session identifier for metadata.
        part: Fragment number (1-indexed), or None for unsplit flags.
        total: Total fragment count, or None for unsplit flags.

    Returns:
        JSON bytes ready to use as packet payload.
    """
    payload = {
        "src": src_ip,
        "dst": dst_ip,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "session_id": session_id,
        "data": encoded_flag,
    }
    if part is not None and total is not None:
        payload["part"] = part
        payload["total"] = total
    return json.dumps(payload).encode()


# ---------------------------------------------------------------------------
# Flag Packet Construction
# ---------------------------------------------------------------------------


def build_flag_packet(
    protocol: str,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
) -> Any:
    """Construct a flag-carrying packet matching the scenario protocol.

    TCP packets use PSH+ACK flags. UDP packets are straightforward.
    Checksums are never set manually -- Scapy auto-computes them.

    Args:
        protocol: "tcp" or "udp".
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        sport: Source port.
        dport: Destination port.
        payload: Raw payload bytes (typically JSON from build_flag_payload).

    Returns:
        Scapy packet with IP/transport/Raw layers.

    Raises:
        ValueError: If protocol is not "tcp" or "udp".
    """
    ip_layer = IP(src=src_ip, dst=dst_ip)
    if protocol == "tcp":
        return ip_layer / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=payload)
    elif protocol == "udp":
        return ip_layer / UDP(sport=sport, dport=dport) / Raw(load=payload)
    else:
        raise ValueError(f"Unsupported protocol for flag embedding: {protocol}")


# ---------------------------------------------------------------------------
# Address Extraction (FLAG-02)
# ---------------------------------------------------------------------------


def extract_addresses(packets: list) -> dict:
    """Extract IP/port addresses from the first data packet in the stream.

    Scans packets for the first one with an IP layer plus TCP or UDP
    layer, and returns the addresses for the flag packet to reuse.

    Args:
        packets: List of Scapy packets from the builder.

    Returns:
        Dict with keys: src_ip, dst_ip, sport, dport.

    Raises:
        ValueError: If no suitable IP+transport packet is found.
    """
    for pkt in packets:
        if pkt.haslayer(IP):
            result = {"src_ip": pkt[IP].src, "dst_ip": pkt[IP].dst}
            if pkt.haslayer(TCP):
                result["sport"] = pkt[TCP].sport
                result["dport"] = pkt[TCP].dport
                return result
            elif pkt.haslayer(UDP):
                result["sport"] = pkt[UDP].sport
                result["dport"] = pkt[UDP].dport
                return result
    raise ValueError("No IP packets found in builder output to extract addresses")


# ---------------------------------------------------------------------------
# Flag Embedding Iterator (FLAG-02)
# ---------------------------------------------------------------------------


def embed_flag_packet(
    packets: Iterator[Any],
    flag_packet: Any,
    min_offset: int = 3,
    tail_offset: int = 4,
) -> Iterator[Any]:
    """Insert flag packet at a random valid position in the packet stream.

    Buffers all packets (already bounded by MAX_PACKET_COUNT in writer),
    then inserts flag_packet at a random position avoiding the first
    min_offset and last tail_offset positions. For short streams
    (< min_offset + tail_offset), clamps insertion to the middle.

    Args:
        packets: Iterator of Scapy packets from the builder.
        flag_packet: The flag-carrying packet to insert.
        min_offset: Minimum insertion index (skip first N packets).
        tail_offset: Minimum distance from end (skip last N packets).

    Yields:
        All original packets plus the flag packet at the chosen position.
    """
    packet_list = list(packets)
    total = len(packet_list)

    if total < min_offset + tail_offset:
        # Short stream: clamp to middle
        insert_idx = total // 2
    else:
        lo = min_offset
        hi = total - tail_offset
        insert_idx = random.randint(lo, hi)

    packet_list.insert(insert_idx, flag_packet)
    logger.info("flag_embedded", packet_index=insert_idx, total_packets=total + 1)
    yield from packet_list


# ---------------------------------------------------------------------------
# Solve Steps
# ---------------------------------------------------------------------------


def _build_solve_steps(
    packet_index: int, encoding: str, payload_data: dict
) -> list[str]:
    """Build Wireshark-style solve steps for the flag.

    Uses 1-indexed frame numbers matching Wireshark display.

    Args:
        packet_index: 0-indexed Scapy packet position.
        encoding: The encoding used for the flag.
        payload_data: The parsed JSON payload dict.

    Returns:
        List of solve step strings.
    """
    wireshark_frame = packet_index + 1
    steps = [
        f"Open the PCAP in Wireshark and locate packet #{wireshark_frame}",
        "Examine the packet payload (Raw layer data)",
        "Parse the JSON payload to extract the 'data' field",
    ]

    if encoding == "plaintext":
        steps.append("The 'data' field contains the flag in plaintext")
    elif encoding == "base64":
        steps.append("Base64 decode the 'data' field value to reveal the flag")
    elif encoding == "hex":
        steps.append("Hex decode the 'data' field value to reveal the flag")
    elif encoding == "rot13":
        steps.append(
            "Apply ROT13 decoding to the 'data' field value to reveal the flag"
        )

    return steps


# ---------------------------------------------------------------------------
# Verification Read-Back (FLAG-04)
# ---------------------------------------------------------------------------


def verify_flag_in_pcap(
    pcap_path: str,
    expected_flag: str,
    encoding: str,
    decode_fn: Any,
) -> dict:
    """Read PCAP, find flag packet, verify decoded flag matches.

    Scans all packets with a Raw layer for JSON payloads containing
    a 'data' field. Applies the decode function and compares to the
    expected flag text.

    Args:
        pcap_path: Path to the PCAP file.
        expected_flag: The assembled flag to verify against.
        encoding: The encoding name (for solve steps).
        decode_fn: Function to decode the encoded flag data.

    Returns:
        Dict with keys:
            verified (bool): Whether the flag was found and matches.
            packet_index (int | None): 0-indexed position, or None.
            solve_steps (list[str]): Wireshark-style instructions.
    """
    packets = rdpcap(pcap_path)

    for idx, pkt in enumerate(packets):
        # Try Raw layer first, then fall back to raw bytes of the
        # packet payload. Scapy may auto-dissect UDP port 53 payloads
        # as DNS instead of Raw, hiding our JSON flag payload.
        payload_candidates = []
        if pkt.haslayer(Raw):
            payload_candidates.append(pkt[Raw].load)

        # Fallback: extract raw bytes from the full packet and search
        # for JSON payload boundaries.  This handles cases where Scapy
        # misidentifies the transport payload (e.g., DNS on port 53).
        raw_bytes = bytes(pkt)
        start = raw_bytes.find(b'{"src"')
        if start >= 0:
            payload_candidates.append(raw_bytes[start:])

        for payload_bytes in payload_candidates:
            try:
                payload = payload_bytes.decode("utf-8", errors="ignore")
                data = json.loads(payload)
                if "data" not in data:
                    continue
                decoded = decode_fn(data["data"])
                if decoded == expected_flag:
                    logger.info(
                        "flag_verified",
                        verified=True,
                        packet_index=idx,
                        encoding=encoding,
                    )
                    return {
                        "verified": True,
                        "packet_index": idx,
                        "solve_steps": _build_solve_steps(idx, encoding, data),
                    }
            except (
                json.JSONDecodeError,
                ValueError,
                KeyError,
                UnicodeDecodeError,
            ):
                continue

    logger.info("flag_verified", verified=False, encoding=encoding)
    return {"verified": False, "packet_index": None, "solve_steps": []}


# ---------------------------------------------------------------------------
# Flag Splitting (FLAG-01 / Phase 10)
# ---------------------------------------------------------------------------


def split_encoded_string(encoded: str, split_count: int) -> list[str]:
    """Split encoded string into N roughly equal chunks.

    First chunk gets the remainder if len(encoded) is not evenly
    divisible by split_count.

    Args:
        encoded: The fully encoded flag string.
        split_count: Number of chunks to produce.

    Returns:
        List of string chunks.

    Raises:
        ValueError: If split_count < 1 or > len(encoded).
    """
    if split_count < 1:
        raise ValueError("split_count must be >= 1")
    if split_count > len(encoded):
        raise ValueError(
            f"split_count ({split_count}) exceeds encoded length ({len(encoded)})"
        )

    chunk_size = len(encoded) // split_count
    remainder = len(encoded) % split_count

    chunks = []
    # First chunk gets remainder
    first_end = chunk_size + remainder
    chunks.append(encoded[:first_end])

    offset = first_end
    for _ in range(1, split_count):
        chunks.append(encoded[offset : offset + chunk_size])
        offset += chunk_size

    return chunks


def embed_split_flag_packets(
    packets: Iterator[Any],
    flag_packets: list[Any],
) -> Iterator[Any]:
    """Insert multiple flag fragment packets at random positions.

    Each fragment is embedded independently using embed_flag_packet,
    producing random, non-clustered placement throughout the PCAP.

    Args:
        packets: Iterator of Scapy packets from the builder.
        flag_packets: List of flag fragment packets to insert.

    Yields:
        All original packets plus fragment packets at random positions.
    """
    current_stream = packets
    for flag_pkt in flag_packets:
        current_stream = embed_flag_packet(current_stream, flag_pkt)
    yield from current_stream


# ---------------------------------------------------------------------------
# Split-Aware Verification (FLAG-04 / Phase 10)
# ---------------------------------------------------------------------------


def verify_split_flag_in_pcap(
    pcap_path: str,
    expected_flag: str,
    encoding_chain: list[str],
    decode_fn: Any,
    expected_total: int,
) -> dict:
    """Verify a split flag can be reassembled from PCAP fragments.

    Scans all packets for JSON payloads with "part" and "total" fields.
    Groups fragments by session_id, sorts by part, concatenates data
    fields, applies decode_fn, and compares to expected_flag.

    Args:
        pcap_path: Path to the PCAP file.
        expected_flag: The assembled flag to verify against.
        encoding_chain: The encoding chain used (for solve steps).
        decode_fn: Function to decode the reassembled encoded flag.
        expected_total: Expected number of fragments.

    Returns:
        Dict with keys:
            verified (bool): Whether the flag was found and matches.
            packet_indices (list[int]): 0-indexed positions of fragments.
            session_id (str | None): Session ID of matching fragments.
            solve_steps (list[str]): Wireshark-style instructions.
    """
    packets = rdpcap(pcap_path)

    # Collect all fragment payloads grouped by session_id
    fragments: dict[str, list[dict]] = {}
    fragment_indices: dict[str, list[int]] = {}

    for idx, pkt in enumerate(packets):
        payload_candidates = []
        if pkt.haslayer(Raw):
            payload_candidates.append(pkt[Raw].load)

        # Fallback: extract raw bytes and search for JSON boundaries
        raw_bytes = bytes(pkt)
        start = raw_bytes.find(b'{"src"')
        if start >= 0:
            payload_candidates.append(raw_bytes[start:])

        for payload_bytes in payload_candidates:
            try:
                payload = payload_bytes.decode("utf-8", errors="ignore")
                data = json.loads(payload)
                if "part" not in data or "total" not in data:
                    continue
                sid = data.get("session_id", "")
                fragments.setdefault(sid, []).append(data)
                fragment_indices.setdefault(sid, []).append(idx)
                break  # Don't double-count from both candidates
            except (
                json.JSONDecodeError,
                ValueError,
                KeyError,
                UnicodeDecodeError,
            ):
                continue

    # Try reassembly for each session_id group
    for sid, frags in fragments.items():
        if len(frags) != expected_total:
            continue
        frags_sorted = sorted(frags, key=lambda f: f["part"])
        indices_sorted = [fragment_indices[sid][frags.index(f)] for f in frags_sorted]
        reassembled = "".join(f["data"] for f in frags_sorted)
        try:
            decoded = decode_fn(reassembled)
            if decoded == expected_flag:
                logger.info(
                    "split_flag_verified",
                    verified=True,
                    session_id=sid,
                    fragment_count=len(frags),
                )
                return {
                    "verified": True,
                    "packet_indices": indices_sorted,
                    "session_id": sid,
                    "solve_steps": _build_solve_steps_split(
                        indices_sorted,
                        encoding_chain,
                        sid,
                        expected_total,
                    ),
                }
        except (ValueError, UnicodeDecodeError):
            continue

    logger.info("split_flag_verified", verified=False)
    return {
        "verified": False,
        "packet_indices": [],
        "session_id": None,
        "solve_steps": [],
    }


# ---------------------------------------------------------------------------
# Split Solve Steps (Phase 10)
# ---------------------------------------------------------------------------


def _build_solve_steps_split(
    fragment_indices: list[int],
    encoding_chain: list[str],
    session_id: str,
    split_count: int,
) -> list[str]:
    """Build Wireshark-style solve steps for a split flag.

    Lists steps to find fragments, reassemble, and decode through
    the encoding chain.

    Args:
        fragment_indices: 0-indexed packet positions of fragments.
        encoding_chain: The encoding chain used for the flag.
        session_id: The session ID shared by all fragments.
        split_count: Number of fragments.

    Returns:
        List of solve step strings.
    """
    steps = [
        "Open the PCAP in Wireshark",
        "Filter packets containing JSON payloads with 'part' and 'total' fields",
        f"Identify {split_count} fragments sharing session_id '{session_id}'",
        f"Sort fragments by 'part' number (1 through {split_count})",
        "Concatenate the 'data' fields in order to reassemble the encoded flag",
    ]

    # Add decode steps (same label logic as _build_solve_steps_chain)
    reversed_chain = list(reversed(encoding_chain))
    for i, encoding in enumerate(reversed_chain, start=1):
        label = encoding.upper() if encoding != "rot13" else "ROT13"
        if encoding == "base64":
            label = "Base64"
        elif encoding == "hex":
            label = "Hex"
        steps.append(f"Step {i}: Apply {label} decoding to the reassembled value")

    steps.append("The final decoded text is the flag")
    return steps


# ---------------------------------------------------------------------------
# Stealth Verification (FLAG-05)
# ---------------------------------------------------------------------------


def extract_printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract printable ASCII strings from binary data.

    Replicates GNU `strings` behavior: finds runs of printable
    ASCII characters (0x20-0x7e) of at least min_length.

    Args:
        data: Raw binary data to scan.
        min_length: Minimum string length to extract.

    Returns:
        List of extracted ASCII strings.
    """
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [m.decode("ascii") for m in re.findall(pattern, data)]


def verify_stealth(pcap_path: str, flag_text: str, encoding: str) -> bool:
    """Check that encoded flags are not findable via strings | grep.

    For plaintext encoding, stealth always passes (flag is expected
    to be visible). For other encodings, reads raw PCAP bytes,
    extracts all printable ASCII runs, and checks the literal flag
    text is NOT present.

    Args:
        pcap_path: Path to the PCAP file.
        flag_text: The assembled flag string to search for.
        encoding: The encoding used.

    Returns:
        True if stealth passes (flag NOT findable in raw strings),
        or if encoding is plaintext.
    """
    if encoding == "plaintext":
        logger.info("stealth_checked", encoding=encoding, passed=True)
        return True

    with open(pcap_path, "rb") as f:
        raw_bytes = f.read()

    strings_output = extract_printable_strings(raw_bytes)
    full_text = " ".join(strings_output)
    passed = flag_text not in full_text
    logger.info("stealth_checked", encoding=encoding, passed=passed)
    return passed
