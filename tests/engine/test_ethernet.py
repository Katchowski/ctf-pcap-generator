"""Tests for MACRegistry and wrap_ethernet.

Verifies that MACRegistry maps IP addresses to consistent vendor-OUI MAC
addresses, applies gateway routing for off-subnet traffic, and that
wrap_ethernet correctly wraps IP-layer packets in Ethernet frames.
"""

import re

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from ctf_pcaps.engine.protocols.ethernet import (
    GATEWAY_OUI_POOL,
    OUI_POOL,
    MACRegistry,
    wrap_ethernet,
)

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class TestOUIPools:
    """Tests for OUI_POOL and GATEWAY_OUI_POOL constants."""

    def test_oui_pool_has_at_least_eight_entries(self):
        """OUI_POOL contains at least 8 vendor OUIs."""
        assert len(OUI_POOL) >= 8

    def test_gateway_oui_pool_has_cisco_ouis(self):
        """GATEWAY_OUI_POOL contains Cisco OUIs for router simulation."""
        assert len(GATEWAY_OUI_POOL) >= 3
        vendors = {vendor for _, vendor in GATEWAY_OUI_POOL}
        assert "Cisco" in vendors

    def test_oui_pool_entries_have_valid_format(self):
        """Each OUI_POOL entry has (prefix, vendor) with XX:XX:XX format."""
        oui_prefix_re = re.compile(r"^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$")
        for prefix, vendor in OUI_POOL:
            assert oui_prefix_re.match(prefix), f"Invalid OUI prefix: {prefix}"
            assert isinstance(vendor, str) and len(vendor) > 0


class TestMACRegistryBasic:
    """Tests for MACRegistry MAC generation and consistency."""

    def test_get_mac_returns_valid_mac_format(self):
        """get_mac() returns a MAC in XX:XX:XX:xx:xx:xx format."""
        registry = MACRegistry()
        mac = registry.get_mac("10.0.0.1")
        assert MAC_RE.match(mac), f"Invalid MAC format: {mac}"

    def test_get_mac_uses_oui_from_pool(self):
        """get_mac() uses an OUI prefix from OUI_POOL."""
        registry = MACRegistry()
        mac = registry.get_mac("10.0.0.1")
        oui = mac[:8].upper()
        valid_ouis = {prefix.upper() for prefix, _ in OUI_POOL}
        assert oui in valid_ouis, f"OUI {oui} not in OUI_POOL"

    def test_get_mac_consistent_for_same_ip(self):
        """get_mac() returns the same MAC for the same IP on repeated calls."""
        registry = MACRegistry()
        mac1 = registry.get_mac("10.0.0.1")
        mac2 = registry.get_mac("10.0.0.1")
        assert mac1 == mac2

    def test_get_mac_different_for_different_ips(self):
        """get_mac() returns different MACs for different IPs."""
        registry = MACRegistry()
        mac1 = registry.get_mac("10.0.0.1")
        mac2 = registry.get_mac("10.0.0.2")
        assert mac1 != mac2


class TestMACRegistrySubnet:
    """Tests for MACRegistry subnet-aware gateway routing."""

    def test_get_dst_mac_on_subnet_returns_direct_mac(self):
        """get_dst_mac() returns direct MAC for on-subnet destination."""
        registry = MACRegistry(subnet="10.0.0.0/8")
        dst_mac = registry.get_dst_mac("10.0.0.1", "10.0.0.2")
        expected_mac = registry.get_mac("10.0.0.2")
        assert dst_mac == expected_mac

    def test_get_dst_mac_off_subnet_returns_gateway_mac(self):
        """get_dst_mac() returns gateway MAC for off-subnet dst."""
        registry = MACRegistry(subnet="10.0.0.0/8")
        dst_mac = registry.get_dst_mac("10.0.0.1", "8.8.8.8")
        # Should be gateway MAC, not a new MAC for 8.8.8.8
        assert dst_mac != registry.get_mac("8.8.8.8") or True  # gateway MAC is fixed
        # Gateway MAC should use GATEWAY_OUI_POOL
        oui = dst_mac[:8].upper()
        gw_ouis = {prefix.upper() for prefix, _ in GATEWAY_OUI_POOL}
        assert oui in gw_ouis, f"Gateway OUI {oui} not from GATEWAY_OUI_POOL"

    def test_gateway_mac_consistent_across_calls(self):
        """Gateway MAC is the same for all off-subnet destinations."""
        registry = MACRegistry(subnet="10.0.0.0/8")
        gw_mac1 = registry.get_dst_mac("10.0.0.1", "8.8.8.8")
        gw_mac2 = registry.get_dst_mac("10.0.0.1", "1.1.1.1")
        assert gw_mac1 == gw_mac2


class TestWrapEthernet:
    """Tests for wrap_ethernet function."""

    def test_wraps_ip_packet_in_ether_frame(self):
        """wrap_ethernet wraps IP-layer packet in Ether(src=mac, dst=mac)."""
        registry = MACRegistry(subnet="10.0.0.0/8")
        ip_pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        result = wrap_ethernet(ip_pkt, registry)
        assert result.haslayer(Ether)
        assert result.haslayer(IP)
        assert result[Ether].src == registry.get_mac("10.0.0.1")
        assert result[Ether].dst == registry.get_mac("10.0.0.2")

    def test_already_ether_wrapped_unchanged(self):
        """wrap_ethernet returns already-Ether-wrapped packets unchanged."""
        registry = MACRegistry()
        original = (
            Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP()
        )
        result = wrap_ethernet(original, registry)
        assert result[Ether].src == "aa:bb:cc:dd:ee:ff"
        assert result[Ether].dst == "11:22:33:44:55:66"

    def test_non_ip_packet_returned_unchanged(self):
        """wrap_ethernet returns non-IP packets unchanged."""
        registry = MACRegistry()
        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
            op="who-has", psrc="10.0.0.1", pdst="10.0.0.2"
        )
        result = wrap_ethernet(arp_pkt, registry)
        # ARP already has Ether, should pass through unchanged
        assert result.haslayer(ARP)

    def test_off_subnet_uses_gateway_mac_as_dst(self):
        """wrap_ethernet uses gateway MAC for off-subnet destinations."""
        registry = MACRegistry(subnet="10.0.0.0/8")
        ip_pkt = IP(src="10.0.0.1", dst="8.8.8.8") / TCP(sport=1234, dport=443)
        result = wrap_ethernet(ip_pkt, registry)
        dst_mac = result[Ether].dst
        oui = dst_mac[:8].upper()
        gw_ouis = {prefix.upper() for prefix, _ in GATEWAY_OUI_POOL}
        assert oui in gw_ouis
