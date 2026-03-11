"""Tests for TCP and DNS protocol helpers.

Verifies TCPSession produces correct handshake/data/teardown with proper
seq/ack tracking, and DNSQueryHelper produces matching query/response pairs.
All generated packets must have None checksum fields (Scapy auto-computes).
"""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP

from ctf_pcaps.engine.protocols.dns_query import DNSQueryHelper
from ctf_pcaps.engine.protocols.tcp_session import TCPSession


class TestTCPSessionHandshake:
    """Tests for TCPSession.handshake() -- SYN/SYN-ACK/ACK."""

    def test_handshake_yields_three_packets(self):
        """handshake() yields exactly 3 packets."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        assert len(packets) == 3

    def test_handshake_syn_flags(self):
        """First packet is SYN (flags='S')."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        syn = packets[0]
        assert syn[TCP].flags == "S"
        assert syn[IP].src == "10.0.0.1"
        assert syn[IP].dst == "10.0.0.2"
        assert syn[TCP].sport == 12345
        assert syn[TCP].dport == 80

    def test_handshake_synack_flags(self):
        """Second packet is SYN-ACK (flags='SA')."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        synack = packets[1]
        assert synack[TCP].flags == "SA"
        # SYN-ACK is server->client
        assert synack[IP].src == "10.0.0.2"
        assert synack[IP].dst == "10.0.0.1"

    def test_handshake_ack_flags(self):
        """Third packet is ACK (flags='A')."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        ack = packets[2]
        assert ack[TCP].flags == "A"
        # ACK is client->server
        assert ack[IP].src == "10.0.0.1"
        assert ack[IP].dst == "10.0.0.2"

    def test_handshake_seq_ack_numbers(self):
        """SYN/SYN-ACK/ACK have correct seq/ack math."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        # Record initial seq numbers
        client_seq_init = session.client_seq
        server_seq_init = session.server_seq

        packets = list(session.handshake())
        syn, synack, ack = packets

        # SYN: seq=client_seq, ack=0
        assert syn[TCP].seq == client_seq_init
        assert syn[TCP].ack == 0

        # SYN-ACK: seq=server_seq, ack=client_seq+1
        assert synack[TCP].seq == server_seq_init
        assert synack[TCP].ack == client_seq_init + 1

        # ACK: seq=client_seq+1, ack=server_seq+1
        assert ack[TCP].seq == client_seq_init + 1
        assert ack[TCP].ack == server_seq_init + 1


class TestTCPSessionSendData:
    """Tests for TCPSession.send_data()."""

    def test_send_data_yields_two_packets(self):
        """send_data() yields data packet + ACK."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.send_data(b"Hello"))
        assert len(packets) == 2

    def test_send_data_contains_payload(self):
        """Data packet contains the provided payload."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.send_data(b"Hello"))
        data_pkt = packets[0]
        assert bytes(data_pkt[TCP].payload) == b"Hello"

    def test_send_data_seq_advances_by_payload_length(self):
        """After send_data, client_seq advances by len(payload)."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        seq_before = session.client_seq
        list(session.send_data(b"Hello"))
        assert session.client_seq == seq_before + len(b"Hello")


class TestTCPSessionTeardown:
    """Tests for TCPSession.teardown()."""

    def test_teardown_yields_four_packets(self):
        """teardown() yields FIN+ACK, ACK, FIN+ACK, ACK (4 packets)."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.teardown())
        assert len(packets) == 4

    def test_teardown_has_fin_flags(self):
        """Teardown packets include FIN flags."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.teardown())
        # First packet: client FIN+ACK
        assert "F" in str(packets[0][TCP].flags)
        # Third packet: server FIN+ACK
        assert "F" in str(packets[2][TCP].flags)

    def test_teardown_seq_ack_correct(self):
        """FIN consumes 1 sequence number."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        client_seq_before = session.client_seq
        server_seq_before = session.server_seq
        packets = list(session.teardown())

        # Client FIN+ACK: seq=client_seq, ack=server_seq
        assert packets[0][TCP].seq == client_seq_before
        assert packets[0][TCP].ack == server_seq_before

        # Server ACK: seq=server_seq, ack=client_seq+1 (FIN consumes 1)
        assert packets[1][TCP].seq == server_seq_before
        assert packets[1][TCP].ack == client_seq_before + 1

        # Server FIN+ACK: seq=server_seq, ack=client_seq+1
        assert packets[2][TCP].seq == server_seq_before
        assert packets[2][TCP].ack == client_seq_before + 1

        # Client ACK: seq=client_seq+1, ack=server_seq+1 (FIN consumes 1)
        assert packets[3][TCP].seq == client_seq_before + 1
        assert packets[3][TCP].ack == server_seq_before + 1


class TestTCPSessionFullTracking:
    """Test seq/ack continuity across handshake + data + teardown."""

    def test_no_seq_ack_gaps(self):
        """Full session: handshake -> data -> teardown has no seq/ack gaps."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        client_seq_init = session.client_seq
        server_seq_init = session.server_seq

        # Handshake: client_seq += 1 (SYN), server_seq += 1 (SYN-ACK)
        list(session.handshake())
        assert session.client_seq == client_seq_init + 1
        assert session.server_seq == server_seq_init + 1

        # Data: client_seq += len(payload)
        payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        list(session.send_data(payload))
        assert session.client_seq == client_seq_init + 1 + len(payload)
        assert session.server_seq == server_seq_init + 1

        # Teardown: client_seq += 1 (FIN), server_seq += 1 (FIN)
        list(session.teardown())
        assert session.client_seq == client_seq_init + 1 + len(payload) + 1
        assert session.server_seq == server_seq_init + 1 + 1


class TestTCPSessionRandomization:
    """Test random defaults for src/dst IP and source port."""

    def test_random_src_ip_when_not_provided(self):
        """TCPSession generates a random source IP if not provided."""
        session = TCPSession(dst_ip="10.0.0.2", dport=80)
        assert session.src_ip is not None
        # Should be a valid IP-like string
        parts = session.src_ip.split(".")
        assert len(parts) == 4

    def test_random_dst_ip_when_not_provided(self):
        """TCPSession generates a random destination IP if not provided."""
        session = TCPSession(src_ip="10.0.0.1", dport=80)
        assert session.dst_ip is not None
        parts = session.dst_ip.split(".")
        assert len(parts) == 4

    def test_random_sport_when_not_provided(self):
        """TCPSession picks random ephemeral source port if not provided."""
        session = TCPSession(src_ip="10.0.0.1", dst_ip="10.0.0.2", dport=80)
        assert 1024 <= session.sport <= 65535


class TestDNSQueryHelper:
    """Tests for DNSQueryHelper query/response generation."""

    def test_query_has_correct_qname(self):
        """query() produces a DNS query with correct QNAME."""
        helper = DNSQueryHelper(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        pkt = helper.query("example.com")
        assert pkt.haslayer(DNS)
        assert pkt.haslayer(DNSQR)
        # DNSQR qname includes trailing dot
        qname = pkt[DNSQR].qname
        assert (
            b"example.com" in qname
            if isinstance(qname, bytes)
            else "example.com" in qname
        )

    def test_query_is_udp(self):
        """DNS query uses UDP."""
        helper = DNSQueryHelper(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        pkt = helper.query("example.com")
        assert pkt.haslayer(UDP)
        assert pkt[UDP].dport == 53

    def test_response_matches_query_id(self):
        """response() has matching transaction ID with the query."""
        helper = DNSQueryHelper(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        query_pkt = helper.query("example.com")
        resp_pkt = helper.response(query_pkt, "93.184.216.34")

        assert resp_pkt[DNS].id == query_pkt[DNS].id

    def test_response_has_answer_record(self):
        """response() contains an A record with the answer IP."""
        helper = DNSQueryHelper(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        query_pkt = helper.query("example.com")
        resp_pkt = helper.response(query_pkt, "93.184.216.34")

        assert resp_pkt.haslayer(DNSRR)
        assert resp_pkt[DNSRR].rdata == "93.184.216.34"

    def test_response_swaps_src_dst(self):
        """response() swaps src/dst IPs from the query."""
        helper = DNSQueryHelper(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        query_pkt = helper.query("example.com")
        resp_pkt = helper.response(query_pkt, "93.184.216.34")

        assert resp_pkt[IP].src == "8.8.8.8"
        assert resp_pkt[IP].dst == "10.0.0.1"


class TestTCPSessionOptions:
    """Tests for TCP options on handshake and data packets."""

    def test_syn_has_mss_option(self):
        """SYN packet has MSS option with value 1460."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        syn = packets[0]
        opts = dict(syn[TCP].options)
        assert "MSS" in opts
        assert opts["MSS"] == 1460

    def test_syn_has_sackok_option(self):
        """SYN packet has SAckOK option."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        syn = packets[0]
        opts = dict(syn[TCP].options)
        assert "SAckOK" in opts

    def test_syn_has_wscale_option(self):
        """SYN packet has WScale option with value 7."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        syn = packets[0]
        opts = dict(syn[TCP].options)
        assert "WScale" in opts
        assert opts["WScale"] == 7

    def test_syn_has_timestamp_option(self):
        """SYN packet has Timestamp option with TSecr=0."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        syn = packets[0]
        opts = dict(syn[TCP].options)
        assert "Timestamp" in opts
        tsval, tsecr = opts["Timestamp"]
        assert tsval > 0
        assert tsecr == 0

    def test_synack_echoes_client_tsval(self):
        """SYN-ACK echoes client TSval in TSecr field."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        syn = packets[0]
        synack = packets[1]
        syn_ts = dict(syn[TCP].options)["Timestamp"]
        synack_ts = dict(synack[TCP].options)["Timestamp"]
        # SYN-ACK TSecr should echo client's TSval
        assert synack_ts[1] == syn_ts[0]

    def test_data_packets_have_timestamp(self):
        """Data packets include Timestamp option."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.send_data(b"Hello"))
        data_pkt = packets[0]
        opts = dict(data_pkt[TCP].options)
        assert "Timestamp" in opts

    def test_timestamp_increments_monotonically(self):
        """TSval increments across packets from the same side."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        hs = list(session.handshake())
        data_pkts = list(session.send_data(b"Hello"))

        syn_ts = dict(hs[0][TCP].options)["Timestamp"][0]
        data_ts = dict(data_pkts[0][TCP].options)["Timestamp"][0]
        # Client TSval should increase
        assert data_ts > syn_ts


class TestTCPSessionTTL:
    """Tests for TTL on IP packets."""

    def test_default_ttl_is_64(self):
        """Default TTL is 64 (Linux default)."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        # Client packet (SYN)
        assert packets[0][IP].ttl == 64
        # Server packet (SYN-ACK)
        assert packets[1][IP].ttl == 64

    def test_custom_client_ttl(self):
        """Custom client_ttl is applied to client packets."""
        session = TCPSession(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            sport=12345,
            dport=80,
            client_ttl=128,
        )
        packets = list(session.handshake())
        assert packets[0][IP].ttl == 128  # SYN (client)
        assert packets[2][IP].ttl == 128  # ACK (client)

    def test_custom_server_ttl(self):
        """Custom server_ttl is applied to server packets."""
        session = TCPSession(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            sport=12345,
            dport=80,
            server_ttl=255,
        )
        packets = list(session.handshake())
        assert packets[1][IP].ttl == 255  # SYN-ACK (server)

    def test_mixed_ttl_values(self):
        """Client and server can have different TTLs."""
        session = TCPSession(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            sport=12345,
            dport=80,
            client_ttl=128,
            server_ttl=64,
        )
        packets = list(session.handshake())
        assert packets[0][IP].ttl == 128  # SYN (client)
        assert packets[1][IP].ttl == 64  # SYN-ACK (server)
        assert packets[2][IP].ttl == 128  # ACK (client)


class TestTCPSessionWindowSize:
    """Tests for TCP window size."""

    def test_window_size_default_65535(self):
        """Default window size is 65535."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        for pkt in packets:
            assert pkt[TCP].window == 65535

    def test_window_size_on_data_packets(self):
        """Window size is set on data and ACK packets."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.send_data(b"Hello"))
        for pkt in packets:
            assert pkt[TCP].window == 65535

    def test_window_size_on_teardown(self):
        """Window size is set on teardown packets."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        list(session.handshake())
        packets = list(session.teardown())
        for pkt in packets:
            assert pkt[TCP].window == 65535


class TestNoManualChecksums:
    """Verify no manually set checksum fields on generated packets."""

    def test_tcp_packets_have_none_checksum(self):
        """TCP packets have chksum=None before serialization."""
        session = TCPSession(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", sport=12345, dport=80
        )
        packets = list(session.handshake())
        for pkt in packets:
            assert pkt[IP].chksum is None
            assert pkt[TCP].chksum is None

    def test_dns_packets_have_none_checksum(self):
        """DNS packets have chksum=None before serialization."""
        helper = DNSQueryHelper(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        pkt = helper.query("example.com")
        assert pkt[IP].chksum is None
        assert pkt[UDP].chksum is None
