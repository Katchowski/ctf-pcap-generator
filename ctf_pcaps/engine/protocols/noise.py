"""Noise traffic generators for realistic PCAP background traffic.

Generates ARP, DNS, HTTP, and ICMP background noise to make PCAPs look
like real network captures. Each protocol generates complete sessions
(no orphaned packets). Noise hosts use different IPs from scenario actors.

No Flask imports allowed in engine modules.
"""

import random
from collections.abc import Iterator

import structlog
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from ctf_pcaps.engine.protocols.dns_query import DNSQueryHelper
from ctf_pcaps.engine.protocols.ethernet import MACRegistry, wrap_ethernet
from ctf_pcaps.engine.protocols.tcp_session import TCPSession

logger = structlog.get_logger()

# Plausible real-world domains for DNS noise
DNS_NOISE_DOMAINS = [
    "www.google.com",
    "mail.google.com",
    "dns.google",
    "www.microsoft.com",
    "update.microsoft.com",
    "login.microsoftonline.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "www.amazon.com",
    "s3.amazonaws.com",
    "connectivity.office365.com",
    "outlook.office.com",
    "fonts.googleapis.com",
    "www.cloudflare.com",
    "detectportal.firefox.com",
    "ocsp.digicert.com",
]

# HTTP request paths for noise sessions
HTTP_NOISE_PATHS = [
    "/",
    "/index.html",
    "/favicon.ico",
    "/api/v1/health",
    "/robots.txt",
    "/static/css/main.css",
    "/static/js/app.js",
    "/.well-known/security.txt",
]

# HTTP Host headers for noise sessions
HTTP_NOISE_HOSTS = [
    "www.example.com",
    "cdn.example.net",
    "api.internal.corp",
    "intranet.local",
    "portal.company.com",
]

# External server IPs for HTTP noise destinations
_HTTP_EXTERNAL_IPS = [
    "93.184.216.34",
    "151.101.1.69",
    "104.16.132.229",
    "13.107.42.14",
    "52.85.132.99",
]

# External IPs for ICMP ping targets
_ICMP_TARGETS = [
    "8.8.8.8",
    "1.1.1.1",
    "8.8.4.4",
    "208.67.222.222",
    "9.9.9.9",
]


def calculate_noise_count(scenario_count: int, noise_ratio: float) -> int:
    """Calculate number of noise packets from scenario count and ratio.

    Formula: noise_count = scenario_count * ratio / (1 - ratio)

    Args:
        scenario_count: Number of scenario (attack) packets.
        noise_ratio: Desired fraction of total traffic that is noise (0-1).
            Values <= 0 or >= 1 return 0.

    Returns:
        Number of noise packets to generate.
    """
    if noise_ratio <= 0 or noise_ratio >= 1:
        return 0
    return round(scenario_count * noise_ratio / (1 - noise_ratio))


def _generate_noise_ips(
    count: int,
    exclude_ips: set[str] | None = None,
) -> list[str]:
    """Generate unique RFC 1918 IPs not in the exclude set.

    Args:
        count: Number of unique IPs to generate.
        exclude_ips: Set of IPs to avoid (scenario actor IPs).

    Returns:
        List of unique 10.x.x.x IP addresses.
    """
    exclude = exclude_ips or set()
    ips: list[str] = []
    attempts = 0
    while len(ips) < count and attempts < count * 100:
        ip = (
            f"10.{random.randint(0, 255)}"
            f".{random.randint(0, 255)}"
            f".{random.randint(1, 254)}"
        )
        if ip not in exclude and ip not in ips:
            ips.append(ip)
        attempts += 1
    return ips


def generate_arp_noise(
    host_ips: list[str],
    mac_registry: MACRegistry,
    count: int,
) -> Iterator[Packet]:
    """Generate ARP request/reply pairs.

    Each session yields a broadcast ARP request (who-has) followed by
    a unicast ARP reply (is-at). Uses MACRegistry for consistent MACs.

    Args:
        host_ips: List of noise host IPs to use as ARP participants.
        mac_registry: MACRegistry for IP-to-MAC resolution.
        count: Number of ARP request/reply pairs to generate.

    Yields:
        ARP request and reply packets wrapped in Ethernet frames.
    """
    for _ in range(count):
        src_ip, dst_ip = random.sample(host_ips, 2)
        src_mac = mac_registry.get_mac(src_ip)
        dst_mac = mac_registry.get_mac(dst_ip)

        # ARP request: broadcast
        request = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op="who-has",
            hwsrc=src_mac,
            psrc=src_ip,
            hwdst="00:00:00:00:00:00",
            pdst=dst_ip,
        )
        yield request

        # ARP reply: unicast
        reply = Ether(src=dst_mac, dst=src_mac) / ARP(
            op="is-at",
            hwsrc=dst_mac,
            psrc=dst_ip,
            hwdst=src_mac,
            pdst=src_ip,
        )
        yield reply


def generate_dns_noise(
    host_ips: list[str],
    mac_registry: MACRegistry,
    count: int,
) -> Iterator[Packet]:
    """Generate DNS query/response pairs.

    Each session picks a random host and domain, generates a query and
    matching response. All packets are Ethernet-wrapped.

    Args:
        host_ips: List of noise host IPs to use as DNS clients.
        mac_registry: MACRegistry for Ethernet wrapping.
        count: Number of DNS query/response pairs to generate.

    Yields:
        DNS query and response packets wrapped in Ethernet frames.
    """
    for _ in range(count):
        src_ip = random.choice(host_ips)
        domain = random.choice(DNS_NOISE_DOMAINS)

        helper = DNSQueryHelper(src_ip=src_ip, dst_ip="8.8.8.8")
        query_pkt = helper.query(domain)

        # Generate a plausible answer IP
        answer_ip = (
            f"{random.choice([93, 104, 172, 151, 52])}"
            f".{random.randint(1, 254)}"
            f".{random.randint(1, 254)}"
            f".{random.randint(1, 254)}"
        )
        response_pkt = helper.response(query_pkt, answer_ip)

        yield wrap_ethernet(query_pkt, mac_registry)
        yield wrap_ethernet(response_pkt, mac_registry)


def generate_http_noise(
    host_ips: list[str],
    mac_registry: MACRegistry,
    count: int,
) -> Iterator[Packet]:
    """Generate full HTTP TCP sessions.

    Each session includes TCP handshake, GET request, 200 OK response,
    and TCP teardown. Uses TCPSession for correct seq/ack tracking.
    All packets are Ethernet-wrapped.

    Args:
        host_ips: List of noise host IPs to use as HTTP clients.
        mac_registry: MACRegistry for Ethernet wrapping.
        count: Number of HTTP sessions to generate.

    Yields:
        All TCP packets for each HTTP session, Ethernet-wrapped.
    """
    for _ in range(count):
        client_ip = random.choice(host_ips)
        server_ip = random.choice(_HTTP_EXTERNAL_IPS)

        session = TCPSession(src_ip=client_ip, dst_ip=server_ip, dport=80)

        path = random.choice(HTTP_NOISE_PATHS)
        host = random.choice(HTTP_NOISE_HOSTS)

        request_bytes = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        ).encode()

        response_bytes = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 13\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"Hello, World!"
        )

        # Collect all session packets
        all_packets: list[Packet] = []
        all_packets.extend(session.handshake())
        all_packets.extend(session.send_data(request_bytes, from_client=True))
        all_packets.extend(session.send_data(response_bytes, from_client=False))
        all_packets.extend(session.teardown())

        # Wrap each in Ethernet
        for pkt in all_packets:
            yield wrap_ethernet(pkt, mac_registry)


def generate_icmp_noise(
    host_ips: list[str],
    mac_registry: MACRegistry,
    count: int,
) -> Iterator[Packet]:
    """Generate ICMP echo-request/echo-reply pairs.

    Each exchange picks a random host and external target, generates
    matching request and reply with the same ICMP id and seq.
    All packets are Ethernet-wrapped.

    Args:
        host_ips: List of noise host IPs to use as ping sources.
        mac_registry: MACRegistry for Ethernet wrapping.
        count: Number of ping request/reply pairs to generate.

    Yields:
        ICMP echo-request and echo-reply packets, Ethernet-wrapped.
    """
    for _ in range(count):
        host_ip = random.choice(host_ips)
        target_ip = random.choice(_ICMP_TARGETS)

        icmp_id = random.randint(1, 0xFFFF)
        seq = 1

        # Echo request
        request = (
            IP(src=host_ip, dst=target_ip, ttl=64)
            / ICMP(type="echo-request", id=icmp_id, seq=seq)
            / (b"\x00" * 56)
        )

        # Echo reply
        reply = (
            IP(src=target_ip, dst=host_ip, ttl=128)
            / ICMP(type="echo-reply", id=icmp_id, seq=seq)
            / (b"\x00" * 56)
        )

        yield wrap_ethernet(request, mac_registry)
        yield wrap_ethernet(reply, mac_registry)


# Dispatcher map for protocol types
_NOISE_GENERATORS = {
    "ARP": generate_arp_noise,
    "DNS": generate_dns_noise,
    "HTTP": generate_http_noise,
    "ICMP": generate_icmp_noise,
}


def generate_noise(
    scenario_count: int,
    noise_ratio: float,
    noise_types: list[str],
    mac_registry: MACRegistry,
    exclude_ips: set[str] | None = None,
) -> list[Packet]:
    """Orchestrate noise generation across protocol types.

    Calculates total noise count, generates noise host IPs, distributes
    the count evenly across requested types, and dispatches to the
    per-type generators.

    Args:
        scenario_count: Number of scenario packets (for ratio calculation).
        noise_ratio: Desired noise fraction of total traffic (0-1).
        noise_types: List of noise type strings (e.g., ["ARP", "DNS"]).
        mac_registry: MACRegistry for MAC address assignment.
        exclude_ips: Set of scenario IPs to avoid using as noise hosts.

    Returns:
        List of all noise packets from all requested types.
    """
    total_noise = calculate_noise_count(scenario_count, noise_ratio)
    if total_noise == 0:
        return []

    # Generate noise host IPs (3-5 hosts)
    host_count = random.randint(3, 5)
    host_ips = _generate_noise_ips(host_count, exclude_ips)

    if not host_ips:
        logger.warning("noise_no_hosts_available", exclude_count=len(exclude_ips or []))
        return []

    # Distribute noise count across types evenly
    count_per_type = max(1, total_noise // len(noise_types))

    all_packets: list[Packet] = []
    for noise_type in noise_types:
        generator = _NOISE_GENERATORS.get(noise_type.upper())
        if generator is None:
            logger.warning("noise_unknown_type", noise_type=noise_type)
            continue
        packets = list(generator(host_ips, mac_registry, count_per_type))
        all_packets.extend(packets)

    logger.info(
        "noise_generated",
        total_packets=len(all_packets),
        noise_types=noise_types,
        noise_ratio=noise_ratio,
        host_count=len(host_ips),
    )

    return all_packets
