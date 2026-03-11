"""PCAP preview analysis module.

Provides functions to analyze PCAP files and extract protocol statistics,
top conversations, timeline information, and flag verification status.
"""

from collections import Counter
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.utils import rdpcap


def analyze_pcap(pcap_path: str) -> dict:
    """Analyze a PCAP file and return protocol stats, conversations, and timeline.

    Args:
        pcap_path: Path to the PCAP file to analyze.

    Returns:
        Dict with keys: packet_count, protocols, top_conversations,
        timeline, file_size_bytes.
    """
    packets = rdpcap(pcap_path)
    packet_count = len(packets)
    file_size_bytes = Path(pcap_path).stat().st_size

    if packet_count == 0:
        return {
            "packet_count": 0,
            "protocols": [],
            "top_conversations": [],
            "timeline": {
                "duration_seconds": 0,
                "first_packet": None,
                "last_packet": None,
                "avg_packet_rate": 0,
            },
            "file_size_bytes": file_size_bytes,
        }

    # Count protocols using haslayer() checks (elif chain: each packet once)
    protocol_counter: Counter = Counter()
    conversation_counter: Counter = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP):
            protocol_counter["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocol_counter["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocol_counter["ICMP"] += 1
        elif pkt.haslayer(ARP):
            protocol_counter["ARP"] += 1
        else:
            protocol_counter["Other"] += 1

        # Track IP conversations
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            conversation_counter[(src, dst)] += 1

    # Build protocol list sorted by count descending
    protocols = []
    for name, count in protocol_counter.most_common():
        pct = round((count / packet_count) * 100, 1)
        protocols.append({"name": name, "count": count, "pct": pct})

    # Build top 5 conversations sorted by count descending
    top_conversations = []
    for (src, dst), count in conversation_counter.most_common(5):
        top_conversations.append({"src": src, "dst": dst, "count": count})

    # Compute timeline
    first_time = float(packets[0].time)
    last_time = float(packets[-1].time)
    duration = last_time - first_time
    avg_rate = packet_count / duration if duration > 0 else 0

    timeline = {
        "duration_seconds": round(duration, 3),
        "first_packet": first_time,
        "last_packet": last_time,
        "avg_packet_rate": round(avg_rate, 1),
    }

    return {
        "packet_count": packet_count,
        "protocols": protocols,
        "top_conversations": top_conversations,
        "timeline": timeline,
        "file_size_bytes": file_size_bytes,
    }


def get_flag_status(history_entry: dict) -> dict:
    """Extract flag verification info from a history entry.

    Reads stored status fields rather than re-running verification.

    Args:
        history_entry: Dict from generation history with optional keys
            flag_text, difficulty, encoding_chain, split_active, split_count.

    Returns:
        Dict with keys: verified, encoding_chain, split_active, split_count.
    """
    flag_text = history_entry.get("flag_text")
    verified = bool(flag_text)

    encoding_chain = history_entry.get("encoding_chain", "")
    if isinstance(encoding_chain, list):
        encoding_chain = " -> ".join(encoding_chain) if encoding_chain else ""

    split_active = history_entry.get("split_active", False)
    split_count = history_entry.get("split_count", 1)

    return {
        "verified": verified,
        "encoding_chain": encoding_chain,
        "split_active": split_active,
        "split_count": split_count,
    }
