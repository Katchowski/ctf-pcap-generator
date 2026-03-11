"""TCP session helper with seq/ack tracking, TCP options, and TTL.

Generates realistic TCP sessions with proper three-way handshake,
data transfer with sequence number tracking, and four-way teardown.
Includes standard TCP options (MSS, SAckOK, Timestamp, WScale) on
SYN packets and Timestamp options on data packets. TTL is set per
host role (client/server). Checksums are never set manually -- Scapy
auto-computes them during serialization.

No Flask imports allowed in engine modules.
"""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

# TCP option templates -- Timestamp values are filled per-packet
SYN_OPTIONS = [
    ("MSS", 1460),
    ("SAckOK", b""),
    ("Timestamp", (0, 0)),
    ("NOP", None),
    ("WScale", 7),
]

DATA_OPTIONS = [
    ("NOP", None),
    ("NOP", None),
    ("Timestamp", (0, 0)),
]


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    )


class TCPSession:
    """TCP session helper that tracks sequence and acknowledgment numbers.

    Generates correct SYN/SYN-ACK/ACK handshake, data packets with proper
    seq advancement, and FIN/ACK teardown. Includes standard TCP options
    and configurable TTL per host role. Never sets checksum fields.

    Args:
        src_ip: Source IP address. Random RFC 1918 if None.
        dst_ip: Destination IP address. Random RFC 1918 if None.
        sport: Source port. Random ephemeral (1024-65535) if None.
        dport: Destination port. Defaults to 80.
        client_ttl: TTL for client (src) packets. Defaults to 64.
        server_ttl: TTL for server (dst) packets. Defaults to 64.
        window: TCP window size. Defaults to 65535.
    """

    def __init__(
        self,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        sport: int | None = None,
        dport: int = 80,
        client_ttl: int = 64,
        server_ttl: int = 64,
        window: int = 65535,
    ):
        self.src_ip = src_ip or _random_rfc1918_ip()
        self.dst_ip = dst_ip or _random_rfc1918_ip()
        self.sport = sport if sport is not None else random.randint(1024, 65535)
        self.dport = dport
        self.client_seq = random.randint(1000, 0xFFFFFFFF)
        self.server_seq = random.randint(1000, 0xFFFFFFFF)
        self.client_ttl = client_ttl
        self.server_ttl = server_ttl
        self.window = window
        self._client_tsval = random.randint(1000, 100000)
        self._server_tsval = random.randint(1000, 100000)

    def _make_ts_option(self, is_client: bool) -> list:
        """Build DATA_OPTIONS with filled-in Timestamp values.

        Increments the sender's TSval by a random amount to simulate
        a monotonic clock.

        Args:
            is_client: True for client-side packets, False for server.

        Returns:
            List of TCP options with Timestamp filled in.
        """
        if is_client:
            ts = ("Timestamp", (self._client_tsval, self._server_tsval))
            self._client_tsval += random.randint(10, 100)
        else:
            ts = ("Timestamp", (self._server_tsval, self._client_tsval))
            self._server_tsval += random.randint(10, 100)
        return [("NOP", None), ("NOP", None), ts]

    def _client_to_server(self, **tcp_kwargs) -> Packet:
        """Build a client->server packet with client TTL and window."""
        return IP(src=self.src_ip, dst=self.dst_ip, ttl=self.client_ttl) / TCP(
            sport=self.sport,
            dport=self.dport,
            window=self.window,
            **tcp_kwargs,
        )

    def _server_to_client(self, **tcp_kwargs) -> Packet:
        """Build a server->client packet with server TTL and window."""
        return IP(src=self.dst_ip, dst=self.src_ip, ttl=self.server_ttl) / TCP(
            sport=self.dport,
            dport=self.sport,
            window=self.window,
            **tcp_kwargs,
        )

    def handshake(self) -> Iterator[Packet]:
        """Yield 3 packets: SYN, SYN-ACK, ACK.

        Updates client_seq and server_seq after handshake.
        SYN and SYN-ACK each consume 1 sequence number.
        All packets include standard TCP options.
        """
        # SYN: client -> server (TSval=client, TSecr=0)
        syn_options = [
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (self._client_tsval, 0)),
            ("NOP", None),
            ("WScale", 7),
        ]
        client_tsval_at_syn = self._client_tsval
        self._client_tsval += random.randint(10, 100)

        syn = self._client_to_server(
            flags="S", seq=self.client_seq, ack=0, options=syn_options
        )
        yield syn

        # SYN-ACK: server -> client (TSval=server, TSecr=client's SYN TSval)
        synack_options = [
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (self._server_tsval, client_tsval_at_syn)),
            ("NOP", None),
            ("WScale", 7),
        ]
        self._server_tsval += random.randint(10, 100)

        synack = self._server_to_client(
            flags="SA",
            seq=self.server_seq,
            ack=self.client_seq + 1,
            options=synack_options,
        )
        yield synack

        # ACK: client -> server (Timestamp options)
        ack_options = self._make_ts_option(is_client=True)
        ack = self._client_to_server(
            flags="A",
            seq=self.client_seq + 1,
            ack=self.server_seq + 1,
            options=ack_options,
        )
        yield ack

        # SYN consumes 1 seq number for each side
        self.client_seq += 1
        self.server_seq += 1

    def send_data(self, payload: bytes, from_client: bool = True) -> Iterator[Packet]:
        """Yield data packet + ACK from the other side.

        Args:
            payload: Data bytes to send.
            from_client: If True, client sends and server ACKs.
                         If False, server sends and client ACKs.
        """
        if from_client:
            # Data: client -> server
            data_options = self._make_ts_option(is_client=True)
            data_pkt = (
                self._client_to_server(
                    flags="PA",
                    seq=self.client_seq,
                    ack=self.server_seq,
                    options=data_options,
                )
                / payload
            )
            yield data_pkt

            # ACK: server -> client
            ack_options = self._make_ts_option(is_client=False)
            ack_pkt = self._server_to_client(
                flags="A",
                seq=self.server_seq,
                ack=self.client_seq + len(payload),
                options=ack_options,
            )
            yield ack_pkt

            self.client_seq += len(payload)
        else:
            # Data: server -> client
            data_options = self._make_ts_option(is_client=False)
            data_pkt = (
                self._server_to_client(
                    flags="PA",
                    seq=self.server_seq,
                    ack=self.client_seq,
                    options=data_options,
                )
                / payload
            )
            yield data_pkt

            # ACK: client -> server
            ack_options = self._make_ts_option(is_client=True)
            ack_pkt = self._client_to_server(
                flags="A",
                seq=self.client_seq,
                ack=self.server_seq + len(payload),
                options=ack_options,
            )
            yield ack_pkt

            self.server_seq += len(payload)

    def teardown(self) -> Iterator[Packet]:
        """Yield 4 packets: FIN+ACK, ACK, FIN+ACK, ACK.

        Standard four-way TCP teardown. FIN consumes 1 sequence number.
        All packets include Timestamp options.
        """
        # Client FIN+ACK
        fin1_options = self._make_ts_option(is_client=True)
        fin1 = self._client_to_server(
            flags="FA",
            seq=self.client_seq,
            ack=self.server_seq,
            options=fin1_options,
        )
        yield fin1

        # Server ACK (acknowledges client FIN; FIN consumes 1 seq)
        ack1_options = self._make_ts_option(is_client=False)
        ack1 = self._server_to_client(
            flags="A",
            seq=self.server_seq,
            ack=self.client_seq + 1,
            options=ack1_options,
        )
        yield ack1

        # Server FIN+ACK
        fin2_options = self._make_ts_option(is_client=False)
        fin2 = self._server_to_client(
            flags="FA",
            seq=self.server_seq,
            ack=self.client_seq + 1,
            options=fin2_options,
        )
        yield fin2

        # Client ACK (acknowledges server FIN)
        ack2_options = self._make_ts_option(is_client=True)
        ack2 = self._client_to_server(
            flags="A",
            seq=self.client_seq + 1,
            ack=self.server_seq + 1,
            options=ack2_options,
        )
        yield ack2

        # FIN consumes 1 seq number for each side
        self.client_seq += 1
        self.server_seq += 1
