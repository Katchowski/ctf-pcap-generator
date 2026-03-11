"""SYN port scan builder for half-open scan traffic generation.

Generates realistic SYN (stealth) port scan traffic: SYN probes to
each target port, SYN-ACK responses for open ports followed by RST
from the scanner, and RST-ACK responses for closed ports.

Does NOT use TCPSession -- SYN scans are half-open by design and
never complete the three-way handshake.

No Flask imports allowed in engine modules.
"""

import random
from collections.abc import Callable, Iterator
from typing import Any

from scapy.layers.inet import IP, TCP

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.registry import register_builder

# Common service ports used as default scan targets
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    143,
    443,
    445,
    993,
    3306,
    3389,
    5432,
    8080,
    8443,
]


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


@register_builder("syn_scan", version=1)
class SynScanBuilder(BaseBuilder):
    """Builder that generates SYN (half-open) port scan traffic.

    For each port in the target list:
    - Sends a SYN probe from the scanner
    - Open ports: target replies SYN-ACK, scanner sends RST (half-open)
    - Closed ports: target replies RST-ACK

    Parameters:
    - src_ip: Scanner IP address (default: random RFC 1918)
    - dst_ip: Target IP address (default: random RFC 1918)
    - ports: List of ports to scan (default: COMMON_PORTS)
    - open_ports: Subset of ports that respond as open (default: [22, 80, 443])
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate SYN scan packets for each target port.

        Yields SYN probes and appropriate responses based on whether
        each port is in the open_ports list.
        """
        src_ip = params.get("src_ip") or _random_rfc1918_ip()
        dst_ip = params.get("dst_ip") or _random_rfc1918_ip()
        ports = params.get("ports", COMMON_PORTS)
        open_ports = set(params.get("open_ports", [22, 80, 443]))

        count = 0

        for port in ports:
            seq = random.randint(1000, 0xFFFFFFFF)
            sport = random.randint(1024, 65535)

            # SYN probe: scanner -> target
            syn = IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(
                sport=sport, dport=port, flags="S", seq=seq
            )
            count += 1
            if callback:
                callback(count)
            yield syn

            if port in open_ports:
                # Open port: SYN-ACK from target
                server_seq = random.randint(1000, 0xFFFFFFFF)
                synack = IP(src=dst_ip, dst=src_ip, ttl=64) / TCP(
                    sport=port,
                    dport=sport,
                    flags="SA",
                    seq=server_seq,
                    ack=seq + 1,
                )
                count += 1
                if callback:
                    callback(count)
                yield synack

                # RST from scanner (half-open close)
                rst = IP(src=src_ip, dst=dst_ip, ttl=64) / TCP(
                    sport=sport,
                    dport=port,
                    flags="R",
                    seq=seq + 1,
                )
                count += 1
                if callback:
                    callback(count)
                yield rst
            else:
                # Closed port: RST-ACK from target
                rst_ack = IP(src=dst_ip, dst=src_ip, ttl=64) / TCP(
                    sport=port,
                    dport=sport,
                    flags="RA",
                    seq=0,
                    ack=seq + 1,
                )
                count += 1
                if callback:
                    callback(count)
                yield rst_ack
