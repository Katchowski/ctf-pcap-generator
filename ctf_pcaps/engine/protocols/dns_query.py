"""DNS query/response helper for PCAP generation.

Generates realistic DNS query and response pairs with matching
transaction IDs. Checksums are never set manually -- Scapy auto-computes
them during serialization.

No Flask imports allowed in engine modules.
"""

import random

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet


class DNSQueryHelper:
    """DNS query/response pair generator.

    Args:
        src_ip: Source IP address for queries. Random RFC 1918 if None.
        dst_ip: DNS server IP address. Defaults to 8.8.8.8.
        sport: Source port for queries. Random ephemeral if None.
        dport: DNS server port. Defaults to 53.
    """

    def __init__(
        self,
        src_ip: str | None = None,
        dst_ip: str = "8.8.8.8",
        sport: int | None = None,
        dport: int = 53,
    ):
        if src_ip is None:
            octets = (
                f"10.{random.randint(0, 255)}"
                f".{random.randint(0, 255)}"
                f".{random.randint(1, 254)}"
            )
            self.src_ip = octets
        else:
            self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport if sport is not None else random.randint(1024, 65535)
        self.dport = dport

    def query(self, domain: str, qtype: str = "A") -> Packet:
        """Create a DNS query packet.

        Args:
            domain: Domain name to query (e.g., "example.com").
            qtype: Query type (default "A" for IPv4 address).

        Returns:
            Scapy Packet with IP/UDP/DNS layers.
        """
        dns_id = random.randint(1, 0xFFFF)
        pkt = (
            IP(src=self.src_ip, dst=self.dst_ip)
            / UDP(sport=self.sport, dport=self.dport)
            / DNS(
                id=dns_id,
                rd=1,  # Recursion desired
                qd=DNSQR(qname=domain, qtype=qtype),
            )
        )
        return pkt

    def response(self, query_pkt: Packet, answer_ip: str) -> Packet:
        """Create a DNS response packet matching a query.

        Swaps src/dst from the query and includes an A record answer.

        Args:
            query_pkt: The original DNS query packet.
            answer_ip: IP address for the A record answer.

        Returns:
            Scapy Packet with DNS response matching the query's transaction ID.
        """
        pkt = (
            IP(src=query_pkt[IP].dst, dst=query_pkt[IP].src)
            / UDP(sport=query_pkt[UDP].dport, dport=query_pkt[UDP].sport)
            / DNS(
                id=query_pkt[DNS].id,
                qr=1,  # This is a response
                aa=1,  # Authoritative answer
                rd=1,  # Recursion desired (copied from query)
                ra=1,  # Recursion available
                qd=query_pkt[DNS].qd,  # Copy question section
                an=DNSRR(
                    rrname=query_pkt[DNSQR].qname,
                    type="A",
                    rdata=answer_ip,
                    ttl=300,
                ),
            )
        )
        return pkt
