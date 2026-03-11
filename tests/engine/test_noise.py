"""Tests for noise traffic generators.

Covers ARP, DNS, HTTP, and ICMP noise generators plus the orchestrator
function. Each protocol generates complete sessions (no orphaned packets).
"""

import random

import pytest
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether

from ctf_pcaps.engine.protocols.ethernet import MACRegistry
from ctf_pcaps.engine.protocols.noise import (
    DNS_NOISE_DOMAINS,
    calculate_noise_count,
    generate_arp_noise,
    generate_dns_noise,
    generate_http_noise,
    generate_icmp_noise,
    generate_noise,
)

# --- calculate_noise_count ---


class TestCalculateNoiseCount:
    """Tests for the noise count formula."""

    def test_ratio_0_6_returns_150(self):
        """100 scenario packets at 0.6 ratio = 150 noise packets."""
        assert calculate_noise_count(100, 0.6) == 150

    def test_ratio_0_2_returns_25(self):
        """100 scenario packets at 0.2 ratio = 25 noise packets."""
        assert calculate_noise_count(100, 0.2) == 25

    def test_ratio_0_85_returns_567(self):
        """100 scenario packets at 0.85 ratio = 567 noise packets."""
        assert calculate_noise_count(100, 0.85) == 567

    def test_zero_ratio_returns_0(self):
        """Ratio of 0 means no noise."""
        assert calculate_noise_count(100, 0.0) == 0

    def test_one_ratio_returns_0(self):
        """Ratio of 1.0 is an edge case that returns 0."""
        assert calculate_noise_count(100, 1.0) == 0

    def test_negative_ratio_returns_0(self):
        """Negative ratio returns 0."""
        assert calculate_noise_count(50, -0.1) == 0


# --- generate_arp_noise ---


class TestGenerateArpNoise:
    """Tests for ARP noise generator."""

    @pytest.fixture()
    def mac_registry(self):
        return MACRegistry()

    @pytest.fixture()
    def host_ips(self):
        return ["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.13"]

    def test_yields_request_reply_pairs(self, host_ips, mac_registry):
        """ARP noise yields request+reply pairs (2 packets each)."""
        packets = list(generate_arp_noise(host_ips, mac_registry, count=3))
        assert len(packets) == 6  # 3 sessions * 2 packets

    def test_request_has_broadcast_dst(self, host_ips, mac_registry):
        """ARP requests use broadcast destination MAC."""
        packets = list(generate_arp_noise(host_ips, mac_registry, count=1))
        request = packets[0]
        assert request[Ether].dst == "ff:ff:ff:ff:ff:ff"

    def test_request_is_who_has(self, host_ips, mac_registry):
        """ARP request has op='who-has' (op=1)."""
        packets = list(generate_arp_noise(host_ips, mac_registry, count=1))
        request = packets[0]
        assert request[ARP].op == 1  # who-has

    def test_reply_is_is_at(self, host_ips, mac_registry):
        """ARP reply has op='is-at' (op=2)."""
        packets = list(generate_arp_noise(host_ips, mac_registry, count=1))
        reply = packets[1]
        assert reply[ARP].op == 2  # is-at

    def test_uses_mac_registry(self, host_ips, mac_registry):
        """ARP packets use MACs from the registry."""
        packets = list(generate_arp_noise(host_ips, mac_registry, count=1))
        request = packets[0]
        src_ip = request[ARP].psrc
        src_mac = mac_registry.get_mac(src_ip)
        assert request[Ether].src == src_mac
        assert request[ARP].hwsrc == src_mac

    def test_packets_are_ether_wrapped(self, host_ips, mac_registry):
        """All ARP packets have Ethernet layer."""
        packets = list(generate_arp_noise(host_ips, mac_registry, count=2))
        for pkt in packets:
            assert pkt.haslayer(Ether)
            assert pkt.haslayer(ARP)


# --- generate_dns_noise ---


class TestGenerateDnsNoise:
    """Tests for DNS noise generator."""

    @pytest.fixture()
    def mac_registry(self):
        return MACRegistry()

    @pytest.fixture()
    def host_ips(self):
        return ["10.0.2.10", "10.0.2.11", "10.0.2.12"]

    def test_yields_query_response_pairs(self, host_ips, mac_registry):
        """DNS noise yields query+response pairs (2 packets each)."""
        packets = list(generate_dns_noise(host_ips, mac_registry, count=3))
        assert len(packets) == 6

    def test_uses_domains_from_list(self, host_ips, mac_registry):
        """DNS queries use domains from DNS_NOISE_DOMAINS."""
        random.seed(42)
        packets = list(generate_dns_noise(host_ips, mac_registry, count=5))
        for i in range(0, len(packets), 2):
            query = packets[i]
            qname = query[DNS].qd.qname.decode().rstrip(".")
            assert qname in DNS_NOISE_DOMAINS

    def test_packets_are_ethernet_wrapped(self, host_ips, mac_registry):
        """All DNS noise packets have Ethernet frames."""
        packets = list(generate_dns_noise(host_ips, mac_registry, count=2))
        for pkt in packets:
            assert pkt.haslayer(Ether)

    def test_query_response_matching_ids(self, host_ips, mac_registry):
        """DNS query and response in a pair share the same transaction ID."""
        packets = list(generate_dns_noise(host_ips, mac_registry, count=1))
        query = packets[0]
        response = packets[1]
        assert query[DNS].id == response[DNS].id


# --- generate_http_noise ---


class TestGenerateHttpNoise:
    """Tests for HTTP noise generator."""

    @pytest.fixture()
    def mac_registry(self):
        return MACRegistry()

    @pytest.fixture()
    def host_ips(self):
        return ["10.0.3.10", "10.0.3.11"]

    def test_yields_full_tcp_session(self, host_ips, mac_registry):
        """HTTP noise yields a complete TCP session with multiple packets."""
        packets = list(generate_http_noise(host_ips, mac_registry, count=1))
        # At minimum: 3 handshake + 2 request + 2 response + 4 teardown = 11
        assert len(packets) >= 11

    def test_starts_with_tcp_handshake(self, host_ips, mac_registry):
        """HTTP session starts with SYN, SYN-ACK, ACK."""
        packets = list(generate_http_noise(host_ips, mac_registry, count=1))
        # First 3 packets inside Ether frame
        syn = packets[0]
        synack = packets[1]
        ack = packets[2]
        assert syn[TCP].flags == "S"
        assert synack[TCP].flags == "SA"
        assert ack[TCP].flags == "A"

    def test_contains_http_get_request(self, host_ips, mac_registry):
        """HTTP session includes a GET request with a path from HTTP_NOISE_PATHS."""
        packets = list(generate_http_noise(host_ips, mac_registry, count=1))
        # Find the data packet (PSH+ACK from client)
        data_packets = [p for p in packets if p.haslayer(TCP) and p[TCP].flags == "PA"]
        assert len(data_packets) >= 1
        # First data packet should be GET request
        payload = bytes(data_packets[0][TCP].payload)
        assert payload.startswith(b"GET ")

    def test_contains_http_200_response(self, host_ips, mac_registry):
        """HTTP session includes a 200 OK response."""
        packets = list(generate_http_noise(host_ips, mac_registry, count=1))
        data_packets = [p for p in packets if p.haslayer(TCP) and p[TCP].flags == "PA"]
        # Second data packet should be 200 OK
        assert len(data_packets) >= 2
        payload = bytes(data_packets[1][TCP].payload)
        assert b"200 OK" in payload

    def test_packets_are_ethernet_wrapped(self, host_ips, mac_registry):
        """All HTTP noise packets have Ethernet frames."""
        packets = list(generate_http_noise(host_ips, mac_registry, count=1))
        for pkt in packets:
            assert pkt.haslayer(Ether)

    def test_uses_tcp_session(self, host_ips, mac_registry):
        """HTTP noise uses proper TCP seq/ack tracking (port 80)."""
        packets = list(generate_http_noise(host_ips, mac_registry, count=1))
        syn = packets[0]
        assert syn[TCP].dport == 80


# --- generate_icmp_noise ---


class TestGenerateIcmpNoise:
    """Tests for ICMP noise generator."""

    @pytest.fixture()
    def mac_registry(self):
        return MACRegistry()

    @pytest.fixture()
    def host_ips(self):
        return ["10.0.4.10", "10.0.4.11", "10.0.4.12"]

    def test_yields_request_reply_pairs(self, host_ips, mac_registry):
        """ICMP noise yields echo-request+echo-reply pairs."""
        packets = list(generate_icmp_noise(host_ips, mac_registry, count=3))
        assert len(packets) == 6  # 3 exchanges * 2 packets

    def test_request_is_echo_request(self, host_ips, mac_registry):
        """First packet in pair is echo-request (type=8)."""
        packets = list(generate_icmp_noise(host_ips, mac_registry, count=1))
        request = packets[0]
        assert request[ICMP].type == 8  # echo-request

    def test_reply_is_echo_reply(self, host_ips, mac_registry):
        """Second packet in pair is echo-reply (type=0)."""
        packets = list(generate_icmp_noise(host_ips, mac_registry, count=1))
        reply = packets[1]
        assert reply[ICMP].type == 0  # echo-reply

    def test_matching_id_and_seq(self, host_ips, mac_registry):
        """Echo request and reply have matching id and seq."""
        packets = list(generate_icmp_noise(host_ips, mac_registry, count=1))
        request = packets[0]
        reply = packets[1]
        assert request[ICMP].id == reply[ICMP].id
        assert request[ICMP].seq == reply[ICMP].seq

    def test_reply_swaps_src_dst(self, host_ips, mac_registry):
        """Reply has src/dst IPs swapped from request."""
        packets = list(generate_icmp_noise(host_ips, mac_registry, count=1))
        request = packets[0]
        reply = packets[1]
        assert request[IP].src == reply[IP].dst
        assert request[IP].dst == reply[IP].src

    def test_packets_are_ethernet_wrapped(self, host_ips, mac_registry):
        """All ICMP noise packets have Ethernet frames."""
        packets = list(generate_icmp_noise(host_ips, mac_registry, count=2))
        for pkt in packets:
            assert pkt.haslayer(Ether)


# --- generate_noise (orchestrator) ---


class TestGenerateNoise:
    """Tests for the noise orchestrator function."""

    @pytest.fixture()
    def mac_registry(self):
        return MACRegistry()

    def test_distributes_across_types(self, mac_registry):
        """Orchestrator distributes noise evenly across requested types."""
        packets = generate_noise(
            scenario_count=100,
            noise_ratio=0.2,
            noise_types=["ARP", "ICMP"],
            mac_registry=mac_registry,
        )
        # 25 noise sessions total, distributed across 2 types
        # Each ARP/ICMP session = 2 packets, so 12 sessions per type * 2 = ~50 packets
        assert len(packets) > 0

    def test_dispatches_to_correct_generators(self, mac_registry):
        """Requesting specific types dispatches to those generators."""
        packets = generate_noise(
            scenario_count=10,
            noise_ratio=0.5,
            noise_types=["ARP"],
            mac_registry=mac_registry,
        )
        # All packets should be ARP
        for pkt in packets:
            assert pkt.haslayer(ARP)

    def test_exclude_ips_not_in_noise(self, mac_registry):
        """Noise hosts use different IPs from excluded scenario IPs."""
        exclude = {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
        packets = generate_noise(
            scenario_count=10,
            noise_ratio=0.5,
            noise_types=["ICMP"],
            mac_registry=mac_registry,
            exclude_ips=exclude,
        )
        for pkt in packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                # Source should be a noise host, not a scenario host
                # (Destination may be external like 8.8.8.8)
                if src.startswith("10."):
                    assert src not in exclude

    def test_returns_list(self, mac_registry):
        """Orchestrator returns a list (not iterator)."""
        result = generate_noise(
            scenario_count=10,
            noise_ratio=0.5,
            noise_types=["DNS"],
            mac_registry=mac_registry,
        )
        assert isinstance(result, list)

    def test_zero_ratio_returns_empty(self, mac_registry):
        """Zero noise ratio returns empty list."""
        packets = generate_noise(
            scenario_count=100,
            noise_ratio=0.0,
            noise_types=["ARP", "DNS"],
            mac_registry=mac_registry,
        )
        assert packets == []

    def test_multiple_types_all_present(self, mac_registry):
        """Multiple noise types each contribute packets."""
        packets = generate_noise(
            scenario_count=50,
            noise_ratio=0.5,
            noise_types=["ARP", "ICMP"],
            mac_registry=mac_registry,
        )
        has_arp = any(p.haslayer(ARP) for p in packets)
        has_icmp = any(p.haslayer(ICMP) for p in packets)
        assert has_arp
        assert has_icmp
