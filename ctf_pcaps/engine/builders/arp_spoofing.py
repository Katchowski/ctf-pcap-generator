"""ARP spoofing / MITM builder for gratuitous ARP + intercepted traffic.

Generates realistic ARP spoofing attack traffic: gratuitous ARP replies
where the attacker claims to be the gateway, combined with intercepted
TCP traffic (HTTP, DNS, or mixed) that the attacker can see due to the
MITM position.

TCP intercepted traffic is yielded FIRST so that extract_addresses()
in the flag embedding pipeline can find an IP+TCP packet. ARP packets
(Layer 2, no IP layer) are yielded after the TCP traffic.

Uses TCPSession composition for intercepted HTTP traffic.
Uses DNSQueryHelper for intercepted DNS traffic.

No Flask imports allowed in engine modules.
"""

import random
from collections.abc import Callable, Iterator
from typing import Any

from scapy.layers.l2 import ARP, Ether

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.flag import encode_flag_chain
from ctf_pcaps.engine.protocols.dns_query import DNSQueryHelper
from ctf_pcaps.engine.protocols.http_session import (
    build_http_request,
    build_http_response,
)
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
        f".{random.randint(1, 254)}"
    )


def _random_mac() -> str:
    """Generate a random MAC address with realistic vendor OUI prefix."""
    ouis = [
        "00:1a:2b",
        "00:50:56",
        "08:00:27",
        "00:0c:29",
        "52:54:00",
    ]
    oui = random.choice(ouis)
    suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
    return f"{oui}:{suffix}"


@register_builder("arp_spoofing", version=1)
class ArpSpoofingBuilder(BaseBuilder):
    """Builder that generates ARP spoofing / MITM attack traffic.

    Produces a mix of ARP packets (Layer 2) and TCP packets (Layer 3/4).
    TCP intercepted traffic is yielded first so the flag embedding
    pipeline's extract_addresses() can find IP+TCP packets.

    Parameters:
        attacker_ip: Attacker IP address (default: 10.0.0.100).
        victim_ip: Victim IP address (default: 10.0.0.50).
        gateway_ip: Gateway IP address (default: 10.0.0.1).
        arp_count: Number of gratuitous ARP replies (default: 5).
        intercepted_type: Type of intercepted traffic (default: http).
        target_host: HTTP host for intercepted traffic.
        dport: Destination port for intercepted HTTP (default: 80).
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate ARP spoofing attack packets.

        Yields TCP intercepted traffic first, then normal ARP exchange,
        then gratuitous ARP replies.
        """
        # attacker_ip is extracted for parameter validation; the attacker
        # is identified by MAC in ARP packets, not by IP.
        params.get("attacker_ip") or _random_rfc1918_ip()
        victim_ip = params.get("victim_ip") or _random_rfc1918_ip()
        gateway_ip = params.get("gateway_ip") or _random_rfc1918_ip()
        arp_count = params.get("arp_count", 5)
        intercepted_type = params.get("intercepted_type", "http")
        target_host = params.get("target_host", "mail.example.com")
        dport = params.get("dport", 80)

        # Resolve thematic flag
        flag_text = params.get("__flag_text")
        flag_encoding = params.get("__flag_encoding")

        # Generate MAC addresses for realism
        attacker_mac = _random_mac()
        victim_mac = _random_mac()
        gateway_mac = _random_mac()

        # Use a mutable list so sub-generators can update the count
        counter = [0]

        # Phase 1: Intercepted traffic (TCP) -- yield FIRST for
        # extract_addresses() compatibility
        if intercepted_type in ("http", "mixed"):
            yield from self._yield_http_intercepted(
                victim_ip,
                target_host,
                dport,
                flag_text,
                flag_encoding,
                callback,
                counter,
            )

        if intercepted_type in ("dns", "mixed"):
            yield from self._yield_dns_intercepted(
                victim_ip, callback, counter
            )

        # Phase 2: Normal ARP exchange (baseline)
        for _ in range(3):
            # ARP who-has from victim to gateway
            who_has = Ether(
                src=victim_mac, dst="ff:ff:ff:ff:ff:ff"
            ) / ARP(
                op="who-has",
                hwsrc=victim_mac,
                psrc=victim_ip,
                hwdst="00:00:00:00:00:00",
                pdst=gateway_ip,
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield who_has

            # ARP is-at reply from gateway
            is_at = Ether(src=gateway_mac, dst=victim_mac) / ARP(
                op="is-at",
                hwsrc=gateway_mac,
                psrc=gateway_ip,
                hwdst=victim_mac,
                pdst=victim_ip,
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield is_at

        # Phase 3: Gratuitous ARP replies (the attack)
        for _ in range(arp_count):
            grat_arp = Ether(
                src=attacker_mac, dst="ff:ff:ff:ff:ff:ff"
            ) / ARP(
                op="is-at",
                hwsrc=attacker_mac,
                psrc=gateway_ip,
                hwdst="ff:ff:ff:ff:ff:ff",
                pdst=victim_ip,
            )
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield grat_arp

    def _yield_http_intercepted(
        self,
        victim_ip: str,
        target_host: str,
        dport: int,
        flag_text: str | None,
        flag_encoding: list[str] | None,
        callback: Callable[[int], None] | None,
        counter: list[int],
    ) -> Iterator[Any]:
        """Yield intercepted HTTP traffic via TCPSession."""
        server_ip = "93.184.216.34"

        session = TCPSession(
            src_ip=victim_ip, dst_ip=server_ip, dport=dport
        )

        # Handshake
        for pkt in session.handshake():
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield pkt

        # HTTP GET request
        request = build_http_request("GET", "/inbox", target_host)
        for pkt in session.send_data(request, from_client=True):
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield pkt

        # Build response body with intercepted data + flag
        if flag_text:
            embedded_flag = flag_text
            if flag_encoding:
                embedded_flag = encode_flag_chain(flag_text, flag_encoding)
            body = (
                "<html><body>"
                "<h1>Inbox</h1>"
                "<p>Intercepted session data: username=admin&amp;"
                f"token={embedded_flag}</p>"
                "</body></html>"
            )
        else:
            body = (
                "<html><body>"
                "<h1>Inbox</h1>"
                "<p>Intercepted session data: username=admin&amp;"
                "token=session_abc123</p>"
                "</body></html>"
            )

        response = build_http_response(200, "OK", body)
        for pkt in session.send_data(response, from_client=False):
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

    def _yield_dns_intercepted(
        self,
        victim_ip: str,
        callback: Callable[[int], None] | None,
        counter: list[int],
    ) -> Iterator[Any]:
        """Yield intercepted DNS traffic."""
        dns_helper = DNSQueryHelper(
            src_ip=victim_ip, dst_ip="8.8.8.8"
        )

        domains = [
            "mail.example.com",
            "login.example.com",
            "internal.corp.local",
        ]

        for domain in domains:
            query = dns_helper.query(domain)
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield query

            answer_ip = (
                f"{random.choice([93, 104, 172])}"
                f".{random.randint(1, 254)}"
                f".{random.randint(1, 254)}"
                f".{random.randint(1, 254)}"
            )
            response = dns_helper.response(query, answer_ip)
            counter[0] += 1
            if callback:
                callback(counter[0])
            yield response
