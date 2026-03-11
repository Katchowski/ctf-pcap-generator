"""Tests for all scenario builders.

Verifies builders are registered in the registry, produce valid
Scapy packets, and integrate correctly with their protocol helpers.

Note: These tests do NOT use clear_registry because the builders must
remain registered throughout. Auto-discovery registers them on first
import of the builders package.
"""

import base64

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

# Import builders package to trigger auto-discovery registration
import ctf_pcaps.engine.builders  # noqa: F401
from ctf_pcaps.engine.registry import get_builder


class TestSimpleTCPBuilder:
    """Tests for SimpleTCPBuilder registration and packet generation."""

    def test_registered_as_simple_tcp(self):
        """SimpleTCPBuilder is registered as 'simple_tcp' version 1."""
        from ctf_pcaps.engine.builders.simple_tcp import SimpleTCPBuilder

        builder_cls = get_builder("simple_tcp")
        assert builder_cls is SimpleTCPBuilder

    def test_build_yields_packets(self):
        """SimpleTCPBuilder.build() yields Scapy Packet objects."""
        builder_cls = get_builder("simple_tcp")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.2", "dport": 80}
        steps = [{"action": "send_data", "payload": "Hello"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt, Packet)

    def test_build_produces_complete_tcp_session(self):
        """SimpleTCPBuilder yields handshake + data + teardown packets."""
        builder_cls = get_builder("simple_tcp")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.2", "dport": 80}
        steps = [{"action": "send_data", "payload": "GET / HTTP/1.1\r\n\r\n"}]
        packets = list(builder.build(params, steps))
        # Should have at least 3 (handshake) + 2 (data+ack) + 4 (teardown) = 9
        assert len(packets) >= 9

        # Check that TCP handshake flags are present
        flags = [str(pkt[TCP].flags) for pkt in packets if pkt.haslayer(TCP)]
        assert "S" in flags  # SYN
        assert "SA" in flags  # SYN-ACK
        # FIN+ACK should be present
        assert any("F" in f for f in flags)

    def test_build_calls_callback(self):
        """SimpleTCPBuilder calls callback with packet count."""
        builder_cls = get_builder("simple_tcp")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.2", "dport": 80}
        steps = [{"action": "send_data", "payload": "Hello"}]
        counts = []
        packets = list(
            builder.build(params, steps, callback=lambda c: counts.append(c))
        )
        assert len(counts) > 0
        assert counts[-1] == len(packets)

    def test_build_no_manual_checksums(self):
        """SimpleTCPBuilder packets have None checksums before serialization."""
        builder_cls = get_builder("simple_tcp")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.2", "dport": 80}
        steps = [{"action": "send_data", "payload": "Hello"}]
        packets = list(builder.build(params, steps))
        for pkt in packets:
            assert pkt[IP].chksum is None


class TestSimpleDNSBuilder:
    """Tests for SimpleDNSBuilder registration and packet generation."""

    def test_registered_as_simple_dns(self):
        """SimpleDNSBuilder is registered as 'simple_dns' version 1."""
        from ctf_pcaps.engine.builders.simple_dns import SimpleDNSBuilder

        builder_cls = get_builder("simple_dns")
        assert builder_cls is SimpleDNSBuilder

    def test_build_yields_dns_packets(self):
        """SimpleDNSBuilder.build() yields DNS packets."""
        builder_cls = get_builder("simple_dns")
        builder = builder_cls()
        params = {"dns_server": "8.8.8.8"}
        steps = [{"action": "dns_lookup", "domain": "example.com"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        # Each dns_lookup produces query + response = 2 packets
        assert len(packets) == 2
        # All packets should have DNS layer
        for pkt in packets:
            assert pkt.haslayer(DNS)

    def test_build_multiple_lookups(self):
        """SimpleDNSBuilder handles multiple dns_lookup steps."""
        builder_cls = get_builder("simple_dns")
        builder = builder_cls()
        params = {"dns_server": "8.8.8.8"}
        steps = [
            {"action": "dns_lookup", "domain": "example.com"},
            {"action": "dns_lookup", "domain": "evil.com"},
            {"action": "dns_lookup", "domain": "test.com"},
        ]
        packets = list(builder.build(params, steps))
        # 3 lookups * 2 packets each = 6
        assert len(packets) == 6

    def test_build_calls_callback(self):
        """SimpleDNSBuilder calls callback with packet count."""
        builder_cls = get_builder("simple_dns")
        builder = builder_cls()
        params = {"dns_server": "8.8.8.8"}
        steps = [{"action": "dns_lookup", "domain": "example.com"}]
        counts = []
        list(builder.build(params, steps, callback=lambda c: counts.append(c)))
        assert len(counts) > 0

    def test_build_no_manual_checksums(self):
        """SimpleDNSBuilder packets have None checksums before serialization."""
        builder_cls = get_builder("simple_dns")
        builder = builder_cls()
        params = {"dns_server": "8.8.8.8"}
        steps = [{"action": "dns_lookup", "domain": "example.com"}]
        packets = list(builder.build(params, steps))
        for pkt in packets:
            assert pkt[IP].chksum is None


class TestSynScanBuilder:
    """Tests for SynScanBuilder registration and packet generation."""

    def test_registered_as_syn_scan(self):
        """SynScanBuilder is registered as 'syn_scan' via get_builder."""
        builder_cls = get_builder("syn_scan")
        assert builder_cls.__name__ == "SynScanBuilder"

    def test_build_yields_packets(self):
        """SynScanBuilder.build() yields Scapy Packet objects."""
        builder_cls = get_builder("syn_scan")
        builder = builder_cls()
        params = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.100",
            "ports": [22, 80],
            "open_ports": [80],
        }
        steps = [{"action": "scan"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt, Packet)

    def test_syn_packets_for_each_port(self):
        """SYN scan produces SYN packets (flags='S') for each target port."""
        builder_cls = get_builder("syn_scan")
        builder = builder_cls()
        ports = [22, 80, 443]
        params = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.100",
            "ports": ports,
            "open_ports": [],
        }
        steps = [{"action": "scan"}]
        packets = list(builder.build(params, steps))
        # With no open ports, each port = SYN + RST-ACK = 2 packets
        syn_packets = [
            p for p in packets if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        ]
        assert len(syn_packets) == len(ports)
        # Verify each port is targeted
        syn_dports = {p[TCP].dport for p in syn_packets}
        assert syn_dports == set(ports)

    def test_open_port_produces_synack_then_rst(self):
        """Open ports produce SYN-ACK response followed by RST from scanner."""
        builder_cls = get_builder("syn_scan")
        builder = builder_cls()
        params = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.100",
            "ports": [80],
            "open_ports": [80],
        }
        steps = [{"action": "scan"}]
        packets = list(builder.build(params, steps))
        # Open port: SYN, SYN-ACK, RST = 3 packets
        assert len(packets) == 3
        flags = [str(p[TCP].flags) for p in packets]
        assert flags[0] == "S"   # SYN from scanner
        assert flags[1] == "SA"  # SYN-ACK from target
        assert flags[2] == "R"   # RST from scanner (half-open)

    def test_closed_port_produces_rst_ack(self):
        """Closed ports produce RST-ACK response from target."""
        builder_cls = get_builder("syn_scan")
        builder = builder_cls()
        params = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.100",
            "ports": [8080],
            "open_ports": [],
        }
        steps = [{"action": "scan"}]
        packets = list(builder.build(params, steps))
        # Closed port: SYN, RST-ACK = 2 packets
        assert len(packets) == 2
        flags = [str(p[TCP].flags) for p in packets]
        assert flags[0] == "S"   # SYN from scanner
        assert flags[1] == "RA"  # RST-ACK from target

    def test_correct_packet_count_mixed(self):
        """Correct total packets: open=3, closed=2 per port."""
        builder_cls = get_builder("syn_scan")
        builder = builder_cls()
        params = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.100",
            "ports": [22, 80, 443, 8080],
            "open_ports": [22, 80],
        }
        steps = [{"action": "scan"}]
        packets = list(builder.build(params, steps))
        # 2 open ports * 3 + 2 closed ports * 2 = 6 + 4 = 10
        assert len(packets) == 10

    def test_syn_scan_yaml_validates(self):
        """syn_scan.yaml loads and validates via ScenarioTemplate."""
        from ctf_pcaps.engine.loader import load_template, validate_template
        from ctf_pcaps.engine.models import ScenarioTemplate

        raw = load_template(Path("scenarios/syn_scan.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.builder == "syn_scan"
        assert result.metadata is not None
        assert result.metadata.name == "SYN Port Scan"
        assert result.metadata.category.value == "network_attack"

    def test_build_calls_callback(self):
        """SynScanBuilder calls callback with packet count."""
        builder_cls = get_builder("syn_scan")
        builder = builder_cls()
        params = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.100",
            "ports": [22, 80],
            "open_ports": [80],
        }
        steps = [{"action": "scan"}]
        counts = []
        packets = list(
            builder.build(params, steps, callback=lambda c: counts.append(c))
        )
        assert len(counts) == len(packets)
        assert counts[-1] == len(packets)


class TestBruteForceBuilder:
    """Tests for BruteForceBuilder registration and packet generation."""

    def test_registered_as_brute_force(self):
        """BruteForceBuilder is registered as 'brute_force'."""
        builder_cls = get_builder("brute_force")
        assert builder_cls.__name__ == "BruteForceBuilder"

    def test_build_yields_packets(self):
        """BruteForceBuilder.build() yields Scapy Packet objects."""
        builder_cls = get_builder("brute_force")
        builder = builder_cls()
        params = {
            "dst_ip": "10.0.0.50",
            "dport": 80,
            "attempt_count": 10,
        }
        steps = [{"action": "brute_force_login"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt, Packet)

    def test_produces_multiple_tcp_sessions(self):
        """Builder produces multiple complete TCP sessions."""
        builder_cls = get_builder("brute_force")
        builder = builder_cls()
        params = {
            "dst_ip": "10.0.0.50",
            "dport": 80,
            "attempt_count": 10,
        }
        steps = [{"action": "brute_force_login"}]
        packets = list(builder.build(params, steps))
        # Each attempt = handshake(3) + request(2) + response(2) + teardown(4)
        # = 11 packets per attempt
        # 10 failed + 1 success = 11 attempts * 11 packets = 121
        syn_packets = [
            p
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        ]
        # Should have 11 SYN packets (10 failed + 1 success)
        assert len(syn_packets) == 11

    def test_each_attempt_uses_different_source_port(self):
        """Each login attempt uses a different source port."""
        builder_cls = get_builder("brute_force")
        builder = builder_cls()
        params = {
            "dst_ip": "10.0.0.50",
            "dport": 80,
            "attempt_count": 10,
        }
        steps = [{"action": "brute_force_login"}]
        packets = list(builder.build(params, steps))
        # Collect source ports from SYN packets (one per session)
        syn_sports = [
            p[TCP].sport
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        ]
        # All source ports must be unique
        assert len(syn_sports) == len(set(syn_sports))

    def test_http_post_login_with_credentials(self):
        """HTTP POST /login requests contain username and password."""
        builder_cls = get_builder("brute_force")
        builder = builder_cls()
        params = {
            "dst_ip": "10.0.0.50",
            "dport": 80,
            "attempt_count": 10,
        }
        steps = [{"action": "brute_force_login"}]
        packets = list(builder.build(params, steps))
        # Find packets with HTTP POST data (PA flags with payload)
        raw_bytes = b"".join(bytes(p) for p in packets)
        assert b"POST /login HTTP/1.1" in raw_bytes
        assert b"username=" in raw_bytes
        assert b"password=" in raw_bytes

    def test_failed_attempts_401_success_200(self):
        """Failed attempts get 401, final success gets 200."""
        builder_cls = get_builder("brute_force")
        builder = builder_cls()
        params = {
            "dst_ip": "10.0.0.50",
            "dport": 80,
            "attempt_count": 10,
        }
        steps = [{"action": "brute_force_login"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Should have 401 responses for failed attempts
        assert b"HTTP/1.1 401 Unauthorized" in raw_bytes
        # Should have exactly one 200 response for success
        assert b"HTTP/1.1 200 OK" in raw_bytes
        assert b"Login successful" in raw_bytes

    def test_default_attempt_count_range(self):
        """Default params produce 10-20 failed attempts plus 1 success."""
        builder_cls = get_builder("brute_force")
        builder = builder_cls()
        # Use defaults (attempt_count=15)
        params = {"dst_ip": "10.0.0.50"}
        steps = [{"action": "brute_force_login"}]
        packets = list(builder.build(params, steps))
        # Count SYN packets = total TCP sessions
        syn_count = sum(
            1
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        )
        # Should be attempt_count(15) + 1 success = 16 sessions
        assert 11 <= syn_count <= 21  # 10-20 failed + 1 success

    def test_brute_force_yaml_validates(self):
        """brute_force.yaml loads and validates via ScenarioTemplate."""
        from ctf_pcaps.engine.loader import load_template, validate_template
        from ctf_pcaps.engine.models import ScenarioTemplate

        raw = load_template(Path("scenarios/brute_force.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.builder == "brute_force"
        assert result.metadata is not None
        assert result.metadata.name == "Brute Force Login"
        assert result.metadata.category.value == "network_attack"


class TestDnsTunnelBuilder:
    """Tests for DnsTunnelBuilder registration and packet generation."""

    def test_registered_as_dns_tunnel(self):
        """DnsTunnelBuilder is registered as 'dns_tunnel'."""
        builder_cls = get_builder("dns_tunnel")
        assert builder_cls.__name__ == "DnsTunnelBuilder"

    def test_build_yields_dns_packets(self):
        """Builder yields Scapy Packet objects with DNS layer."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        params = {
            "dns_server": "8.8.8.8",
            "tunnel_domain": "exfil.attacker.com",
            "secret_message": "test_secret",
        }
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt, Packet)
        # All packets should have DNS layer
        dns_packets = [p for p in packets if p.haslayer(DNS)]
        assert len(dns_packets) == len(packets)

    def test_queries_contain_base32_encoded_chunks(self):
        """DNS queries contain base32-encoded chunks as subdomains."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        secret = "confidential_project_data_2026"
        params = {
            "dns_server": "8.8.8.8",
            "tunnel_domain": "exfil.attacker.com",
            "secret_message": secret,
        }
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        # Filter query packets (qr=0) for the tunnel domain
        tunnel_queries = []
        for pkt in packets:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode().rstrip(".")
                if qname.endswith("exfil.attacker.com"):
                    tunnel_queries.append(qname)
        assert len(tunnel_queries) > 0

    def test_no_subdomain_label_exceeds_63_chars(self):
        """No subdomain label exceeds 63 characters."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        params = {
            "dns_server": "8.8.8.8",
            "tunnel_domain": "exfil.attacker.com",
            "secret_message": "a" * 200,  # Long message
        }
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        for pkt in packets:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode().rstrip(".")
                labels = qname.split(".")
                for label in labels:
                    assert len(label) <= 63

    def test_no_base32_padding_in_subdomain_labels(self):
        """No base32 padding characters appear in subdomain labels."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        params = {
            "dns_server": "8.8.8.8",
            "tunnel_domain": "exfil.attacker.com",
            "secret_message": "confidential_project_data_2026",
        }
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        for pkt in packets:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode().rstrip(".")
                if qname.endswith("exfil.attacker.com"):
                    # Check the chunk part (first label)
                    chunk_label = qname.split(".")[0]
                    assert "=" not in chunk_label

    def test_encoded_data_reassembles_to_original(self):
        """Encoded data can be reassembled to recover original."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        secret = "confidential_project_data_2026"
        tunnel_domain = "exfil.attacker.com"
        params = {
            "dns_server": "8.8.8.8",
            "tunnel_domain": tunnel_domain,
            "secret_message": secret,
        }
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        # Collect chunks from tunnel queries only (qr=0, skip responses)
        indexed_chunks = []
        for pkt in packets:
            if (
                pkt.haslayer(DNS)
                and pkt[DNS].qr == 0
                and pkt.haslayer(DNSQR)
            ):
                qname = pkt[DNSQR].qname.decode().rstrip(".")
                if qname.endswith(tunnel_domain):
                    parts = qname[: -len(tunnel_domain) - 1].split(".")
                    chunk = parts[0]
                    index = int(parts[1])
                    indexed_chunks.append((index, chunk))
        # Sort by index and concatenate
        indexed_chunks.sort(key=lambda x: x[0])
        encoded = "".join(c for _, c in indexed_chunks)
        # Re-pad and decode
        padding = "=" * (-len(encoded) % 8)
        decoded = base64.b32decode(
            encoded.upper() + padding
        ).decode()
        assert decoded == secret

    def test_query_response_pairs(self):
        """Each query has a matching response packet."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        params = {
            "dns_server": "8.8.8.8",
            "tunnel_domain": "exfil.attacker.com",
            "secret_message": "test",
        }
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        # Count queries (qr=0) and responses (qr=1)
        queries = [p for p in packets if p[DNS].qr == 0]
        responses = [p for p in packets if p[DNS].qr == 1]
        assert len(queries) == len(responses)
        assert len(queries) > 0

    def test_default_params_produce_15_to_30_query_pairs(self):
        """Default params produce 15-30 DNS query pairs."""
        builder_cls = get_builder("dns_tunnel")
        builder = builder_cls()
        params = {}  # Use all defaults
        steps = [{"action": "dns_exfiltrate"}]
        packets = list(builder.build(params, steps))
        queries = [p for p in packets if p[DNS].qr == 0]
        assert 15 <= len(queries) <= 30

    def test_dns_tunnel_yaml_validates(self):
        """dns_tunnel.yaml loads and validates via ScenarioTemplate."""
        from ctf_pcaps.engine.loader import load_template, validate_template
        from ctf_pcaps.engine.models import ScenarioTemplate

        raw = load_template(Path("scenarios/dns_tunnel.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.builder == "dns_tunnel"
        assert result.metadata is not None
        assert result.metadata.name == "DNS Tunneling"
        assert result.metadata.category.value == "covert_channel"


class TestSqliBuilder:
    """Tests for SqliBuilder registration and packet generation."""

    def test_registered_as_sqli(self):
        """SqliBuilder is registered as 'sqli' via get_builder."""
        builder_cls = get_builder("sqli")
        assert builder_cls.__name__ == "SqliBuilder"

    def test_build_yields_packets(self):
        """SqliBuilder.build() yields Scapy Packet objects."""
        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt, Packet)

    def test_produces_multiple_tcp_sessions(self):
        """Builder produces multiple complete TCP sessions."""
        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        # Count SYN packets = number of TCP sessions
        syn_packets = [
            p
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        ]
        # 7 payloads = 7 TCP sessions
        assert len(syn_packets) == 7

    def test_http_get_with_sqli_payloads(self):
        """HTTP GET requests contain SQL injection payloads."""
        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Should contain GET requests with query parameters
        assert b"GET /search?" in raw_bytes
        assert b"q=" in raw_bytes

    def test_payload_progression_tautology_to_union(self):
        """Payloads progress from tautology probes to UNION SELECT."""
        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Should contain UNION SELECT in URL-encoded form
        assert b"UNION" in raw_bytes
        assert b"SELECT" in raw_bytes

    def test_failed_injections_error_responses(self):
        """Failed injections get 400 or 500 responses."""
        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Should have error responses (500 for tautology, 400 for bad UNION)
        has_500 = b"HTTP/1.1 500" in raw_bytes
        has_400 = b"HTTP/1.1 400" in raw_bytes
        assert has_500 or has_400
        # Should also have 200 for successful UNION
        assert b"HTTP/1.1 200 OK" in raw_bytes

    def test_successful_union_leaks_data(self):
        """Successful UNION SELECT gets 200 with leaked data."""
        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # The extraction payload should produce leaked credentials
        assert b"s3cr3t_db_pass" in raw_bytes

    def test_url_encoded_payloads(self):
        """URL-encoded payloads use proper percent-encoding."""
        import re

        builder_cls = get_builder("sqli")
        builder = builder_cls()
        params = {"dst_ip": "10.0.0.80", "dport": 80}
        steps = [{"action": "sqli_attack"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Find all GET request lines embedded in packet data
        # Pattern: GET /search?...  HTTP/1.1
        matches = re.findall(
            rb"GET /search\?([^ ]+) HTTP/1\.1", raw_bytes
        )
        assert len(matches) > 0
        for query_part in matches:
            # Raw single quotes must be percent-encoded (%27)
            assert b"'" not in query_part

    def test_sqli_yaml_validates(self):
        """sqli.yaml loads and validates via ScenarioTemplate."""
        from ctf_pcaps.engine.loader import load_template, validate_template
        from ctf_pcaps.engine.models import ScenarioTemplate

        raw = load_template(Path("scenarios/sqli.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.builder == "sqli"
        assert result.metadata is not None
        assert result.metadata.name == "SQL Injection"
        assert result.metadata.category.value == "web_traffic"


class TestHttpBeaconBuilder:
    """Tests for HttpBeaconBuilder registration and packet generation."""

    def test_registered_as_http_beacon(self):
        """HttpBeaconBuilder is registered as 'http_beacon'."""
        builder_cls = get_builder("http_beacon")
        assert builder_cls.__name__ == "HttpBeaconBuilder"

    def test_build_yields_packets(self):
        """HttpBeaconBuilder.build() yields Scapy Packet objects."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {
            "dst_ip": "198.51.100.10",
            "dport": 443,
            "beacon_count": 5,
        }
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        assert len(packets) > 0
        for pkt in packets:
            assert isinstance(pkt, Packet)

    def test_produces_multiple_tcp_sessions(self):
        """Builder produces multiple complete TCP sessions."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {
            "dst_ip": "198.51.100.10",
            "dport": 443,
            "beacon_count": 5,
        }
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        # Count SYN packets (one per TCP session = one per beacon)
        syn_packets = [
            p
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        ]
        assert len(syn_packets) == 5

    def test_innocuous_urls(self):
        """HTTP GET requests use innocuous-looking URLs."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {
            "dst_ip": "198.51.100.10",
            "dport": 443,
            "beacon_count": 5,
        }
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Should contain GET requests with paths like /api/status
        assert b"GET /" in raw_bytes
        # Check at least one known beacon path appears
        known_paths = [
            b"/api/status",
            b"/updates/check",
            b"/static/config.json",
            b"/cdn/health",
            b"/api/v2/sync",
        ]
        found = any(p in raw_bytes for p in known_paths)
        assert found

    def test_realistic_user_agent(self):
        """Requests include a realistic User-Agent header."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {
            "dst_ip": "198.51.100.10",
            "dport": 443,
            "beacon_count": 5,
        }
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        assert b"User-Agent: Mozilla/5.0" in raw_bytes

    def test_response_contains_base64_c2_commands(self):
        """Response bodies contain base64-encoded command data."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {
            "dst_ip": "198.51.100.10",
            "dport": 443,
            "beacon_count": 5,
        }
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        raw_bytes = b"".join(bytes(p) for p in packets)
        # Find base64 data fields in JSON responses
        import json
        import re

        # Extract JSON response bodies
        body_matches = re.findall(
            rb'\{"status":"ok","data":"([^"]+)"\}', raw_bytes
        )
        assert len(body_matches) >= 5
        for encoded_data in body_matches:
            # Should be valid base64
            decoded = base64.b64decode(encoded_data).decode()
            # Should start with a known command prefix
            assert any(
                decoded.startswith(p)
                for p in ["cmd|", "exfil|", "sleep|"]
            )

    def test_default_params_produce_5_to_10_beacon_cycles(self):
        """Default params produce 5-10 beacon cycles."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {}  # Use defaults (beacon_count=8)
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        syn_count = sum(
            1
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        )
        assert 5 <= syn_count <= 10

    def test_each_beacon_uses_unique_source_port(self):
        """Each beacon uses a separate TCP session with unique port."""
        builder_cls = get_builder("http_beacon")
        builder = builder_cls()
        params = {
            "dst_ip": "198.51.100.10",
            "dport": 443,
            "beacon_count": 8,
        }
        steps = [{"action": "beacon_callback"}]
        packets = list(builder.build(params, steps))
        syn_sports = [
            p[TCP].sport
            for p in packets
            if p.haslayer(TCP) and str(p[TCP].flags) == "S"
        ]
        assert len(syn_sports) == 8
        assert len(syn_sports) == len(set(syn_sports))

    def test_http_beacon_yaml_validates(self):
        """http_beacon.yaml loads and validates via ScenarioTemplate."""
        from ctf_pcaps.engine.loader import load_template, validate_template
        from ctf_pcaps.engine.models import ScenarioTemplate

        raw = load_template(Path("scenarios/http_beacon.yaml"))
        result = validate_template(raw)
        assert isinstance(result, ScenarioTemplate)
        assert result.builder == "http_beacon"
        assert result.metadata is not None
        assert result.metadata.name == "HTTP Beaconing / C2"
        assert result.metadata.category.value == "malware_c2"
