"""ICMP exfiltration builder for covert data extraction via echo payloads.

Generates realistic ICMP exfiltration traffic: a TCP control channel for
initialization, normal ICMP pings for baseline, then ICMP echo-request
packets carrying base64-encoded data chunks in their payloads.

TCP control channel is yielded FIRST so that extract_addresses() in the
flag embedding pipeline can find an IP+TCP packet. ICMP packets (IP layer
but no TCP/UDP) cannot satisfy extract_addresses() alone.

Data can be reassembled by collecting echo-request payloads with seq >= 100,
sorting by seq number, concatenating, and base64-decoding.

No Flask imports allowed in engine modules.
"""

import base64
import random
from collections.abc import Callable, Iterator
from typing import Any

from scapy.layers.inet import ICMP, IP
from scapy.packet import Raw

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.flag import encode_flag_chain
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
        f".{random.randint(1, 254)}"
    )


@register_builder("icmp_exfil", version=1)
class IcmpExfilBuilder(BaseBuilder):
    """Builder that generates ICMP exfiltration traffic.

    Produces a mix of TCP control channel packets and ICMP echo
    request/reply pairs. The TCP control channel is yielded first
    for flag embedding compatibility.

    Exfiltration data is base64-encoded and split into chunks carried
    in ICMP echo-request payloads. Normal pings use seq 0-4 with
    56-byte null payloads; exfil pings use seq 100+ with data chunks.

    Parameters:
        victim_ip: Compromised host IP (default: 10.0.0.50).
        attacker_ip: Attacker/receiver IP (default: 10.0.0.200).
        chunk_size: Bytes per ICMP exfil chunk (default: 32).
        chunk_count: Max exfil chunks (default: 10).
        icmp_id: ICMP identifier, 0 = random (default: 0).
        control_port: TCP control channel port (default: 4444).
        exfil_data: Custom exfil data, empty = auto-generated.
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate ICMP exfiltration packets.

        Yields TCP control channel first, then normal pings, then
        exfiltration pings with data in payloads.
        """
        victim_ip = params.get("victim_ip") or _random_rfc1918_ip()
        attacker_ip = params.get("attacker_ip") or _random_rfc1918_ip()
        chunk_size = params.get("chunk_size", 32)
        chunk_count = params.get("chunk_count", 10)
        icmp_id = params.get("icmp_id", 0)
        control_port = params.get("control_port", 4444)
        exfil_data = params.get("exfil_data", "")

        # Resolve thematic flag
        flag_text = params.get("__flag_text")
        flag_encoding = params.get("__flag_encoding")

        # Generate random ICMP ID if 0
        if icmp_id == 0:
            icmp_id = random.randint(1, 0xFFFF)

        # Build exfiltration data content
        if exfil_data:
            data_content = exfil_data
        else:
            if flag_text:
                embedded_flag = flag_text
                if flag_encoding:
                    embedded_flag = encode_flag_chain(
                        flag_text, flag_encoding
                    )
            else:
                embedded_flag = "flag{PLACEHOLDER_EXFIL_DATA}"
            data_content = (
                f"CONFIDENTIAL: Project files exported. "
                f"Access token: {embedded_flag}. Transfer complete."
            )

        counter = [0]

        # Phase 1: TCP control channel -- yield FIRST for
        # extract_addresses() compatibility
        yield from self._yield_control_channel(
            victim_ip, attacker_ip, control_port, callback, counter
        )

        # Phase 2: Normal pings (baseline connectivity check)
        normal_ping_count = random.randint(3, 5)
        for seq in range(normal_ping_count):
            # Echo request with standard 56-byte null payload
            req = (
                IP(src=victim_ip, dst=attacker_ip, ttl=64)
                / ICMP(type="echo-request", id=icmp_id, seq=seq)
                / Raw(load=b"\x00" * 56)
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield req

            # Echo reply
            reply = (
                IP(src=attacker_ip, dst=victim_ip, ttl=128)
                / ICMP(type="echo-reply", id=icmp_id, seq=seq)
                / Raw(load=b"\x00" * 56)
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield reply

        # Phase 3: Exfiltration pings (data chunks in payloads)
        encoded_data = base64.b64encode(data_content.encode()).decode()
        chunks = [
            encoded_data[i : i + chunk_size]
            for i in range(0, len(encoded_data), chunk_size)
        ]
        # Limit to chunk_count
        chunks = chunks[:chunk_count]

        for i, chunk in enumerate(chunks):
            chunk_bytes = chunk.encode()

            # Exfil echo request with data payload
            req = (
                IP(src=victim_ip, dst=attacker_ip, ttl=64)
                / ICMP(type="echo-request", id=icmp_id, seq=100 + i)
                / Raw(load=chunk_bytes)
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield req

            # Echo reply with null payload of same size
            reply = (
                IP(src=attacker_ip, dst=victim_ip, ttl=128)
                / ICMP(type="echo-reply", id=icmp_id, seq=100 + i)
                / Raw(load=b"\x00" * len(chunk_bytes))
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield reply

    def _yield_control_channel(
        self,
        victim_ip: str,
        attacker_ip: str,
        control_port: int,
        callback: Callable[[int], None] | None,
        counter: list[int],
    ) -> Iterator[Any]:
        """Yield TCP control channel packets."""
        session = TCPSession(
            src_ip=victim_ip, dst_ip=attacker_ip, dport=control_port
        )

        # Handshake
        for pkt in session.handshake():
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield pkt

        # Exfil initialization message
        init_data = b"EXFIL_INIT\n"
        for pkt in session.send_data(init_data, from_client=True):
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield pkt

        # Acknowledgment
        ack_data = b"ACK\n"
        for pkt in session.send_data(ack_data, from_client=False):
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield pkt

        # Teardown
        for pkt in session.teardown():
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield pkt
