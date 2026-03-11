"""Protocol helpers for PCAP packet crafting.

Provides concrete helpers for generating realistic protocol interactions:
- TCPSession: TCP handshake, data transfer, and teardown with seq/ack tracking
- DNSQueryHelper: DNS query/response pair generation
- MACRegistry: Consistent IP-to-MAC mapping with vendor OUI prefixes
- wrap_ethernet: Ethernet frame wrapping for IP-layer packets
- Noise generators: ARP, DNS, HTTP, ICMP background traffic via generate_noise
"""
