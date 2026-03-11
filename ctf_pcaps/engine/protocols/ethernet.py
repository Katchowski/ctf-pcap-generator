"""Ethernet layer wrapping with vendor-OUI MAC address registry.

Provides MACRegistry for consistent IP-to-MAC mapping per generation,
and wrap_ethernet for adding Ethernet frames to IP-layer packets.
Uses real vendor OUI prefixes verified against the IEEE database.

No Flask imports allowed in engine modules.
"""

import ipaddress
import random

import structlog
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

logger = structlog.get_logger()

# Verified OUI prefixes (IEEE database via maclookup.app, 2026-03-06)
# Format: (oui_prefix, vendor_name)
OUI_POOL: list[tuple[str, str]] = [
    ("00:1B:21", "Intel"),
    ("00:E0:4C", "Realtek"),
    ("00:26:99", "Cisco"),
    ("3C:22:FB", "Apple"),
    ("F8:DB:88", "Dell"),
    ("00:50:56", "VMware"),
    ("00:0C:29", "VMware"),
    ("00:25:90", "Super Micro"),
    ("00:1A:A0", "Dell"),
    ("AC:DE:48", "Intel"),
]

# Cisco OUIs for gateway/router MACs
GATEWAY_OUI_POOL: list[tuple[str, str]] = [
    ("00:26:99", "Cisco"),
    ("00:1E:BD", "Cisco"),
    ("00:18:0A", "Cisco"),
]


class MACRegistry:
    """Maps IP addresses to consistent MAC addresses per generation.

    Each IP address is assigned a MAC with a real vendor OUI prefix on first
    lookup, and the same MAC is returned for subsequent lookups. Off-subnet
    destinations use a gateway MAC with a Cisco OUI prefix.

    Args:
        subnet: CIDR notation subnet for on-subnet detection.
            Defaults to "10.0.0.0/8".
    """

    def __init__(self, subnet: str = "10.0.0.0/8"):
        self._map: dict[str, str] = {}
        self._subnet = ipaddress.ip_network(subnet, strict=False)
        self._gateway_mac = self._generate_mac(GATEWAY_OUI_POOL)

    def get_mac(self, ip: str) -> str:
        """Return a consistent MAC address for the given IP.

        Generates a new MAC with a vendor OUI prefix on first call for an IP,
        then returns the cached MAC for subsequent calls.

        Args:
            ip: IP address string (e.g., "10.0.0.1").

        Returns:
            MAC address string in XX:XX:XX:xx:xx:xx format.
        """
        if ip not in self._map:
            self._map[ip] = self._generate_mac(OUI_POOL)
        return self._map[ip]

    def get_dst_mac(self, src_ip: str, dst_ip: str) -> str:
        """Return destination MAC based on subnet membership.

        On-subnet destinations get a direct MAC (from get_mac).
        Off-subnet destinations get the gateway MAC (Cisco OUI).

        Args:
            src_ip: Source IP address (unused but kept for API clarity).
            dst_ip: Destination IP address to check subnet membership.

        Returns:
            MAC address string for the Ethernet destination.
        """
        if ipaddress.ip_address(dst_ip) in self._subnet:
            return self.get_mac(dst_ip)
        return self._gateway_mac

    @staticmethod
    def _generate_mac(pool: list[tuple[str, str]]) -> str:
        """Generate a MAC address using a random OUI from the given pool.

        Args:
            pool: List of (oui_prefix, vendor_name) tuples.

        Returns:
            MAC address string in XX:XX:XX:xx:xx:xx format.
        """
        oui, _ = random.choice(pool)
        suffix = ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))
        return f"{oui}:{suffix}"


def wrap_ethernet(pkt: Packet, mac_registry: MACRegistry) -> Packet:
    """Wrap an IP-layer packet in an Ethernet frame.

    Uses the MAC registry to look up source and destination MACs based
    on the packet's IP addresses. Packets that already have an Ethernet
    layer or lack an IP layer are returned unchanged.

    Args:
        pkt: Scapy packet to wrap.
        mac_registry: MACRegistry instance for IP-to-MAC resolution.

    Returns:
        Packet with Ethernet frame, or original packet if already wrapped
        or not an IP packet.
    """
    if pkt.haslayer(Ether):
        return pkt
    if not pkt.haslayer(IP):
        return pkt

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_mac = mac_registry.get_mac(src_ip)
    dst_mac = mac_registry.get_dst_mac(src_ip, dst_ip)

    return Ether(src=src_mac, dst=dst_mac) / pkt
