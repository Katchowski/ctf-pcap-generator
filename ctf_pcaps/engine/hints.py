"""Hint generation engine module.

Generates graduated hints for CTF challenges based on scenario type,
difficulty level, and encoding chain. Pure functions with no Flask
imports or side effects.
"""

from __future__ import annotations

# Hint templates per builder following Category -> Tool -> Technique
# progression. Third template uses {encoding} for encoding chain.
HINT_TEMPLATES: dict[str, list[str]] = {
    "dns_tunnel": [
        "This challenge involves DNS traffic analysis.",
        "Filter with dns.qry.name to find unusual subdomains.",
        (
            "The data is {encoding} encoded in subdomain"
            " labels -- collect, sort, decode."
        ),
    ],
    "simple_dns": [
        "This challenge involves DNS queries and responses.",
        "Filter by dns.qry.name and examine query patterns.",
        "Data hidden in DNS records may be {encoding} encoded.",
    ],
    "http_beacon": [
        "Look for periodic HTTP requests resembling C2 beaconing.",
        "Filter http.request.method == GET and check intervals.",
        "Response payloads may be {encoding} encoded.",
    ],
    "brute_force": [
        "This challenge involves HTTP authentication traffic.",
        "Filter POST requests to login and watch response codes.",
        "The flag in the successful response is {encoding} encoded.",
    ],
    "sqli": [
        "This involves web traffic with SQL injection attempts.",
        'Filter HTTP requests containing "UNION" or "SELECT".',
        "Extracted data in the response is {encoding} encoded.",
    ],
    "syn_scan": [
        "This challenge involves TCP port scanning activity.",
        "Filter SYN packets: tcp.flags.syn==1 && tcp.flags.ack==0.",
        "The flag data in open-port responses is {encoding} encoded.",
    ],
    "simple_tcp": [
        "This challenge involves basic TCP communication.",
        "Follow the TCP stream (tcp.stream eq 0) to read it.",
        "Payload data in the stream is {encoding} encoded.",
    ],
    "reverse_shell": [
        "Look for an unusual TCP connection on a non-standard port.",
        "Filter with tcp.port == 4444 and follow the TCP stream.",
        "Commands in the session have {encoding} encoded payload.",
    ],
    "xss_reflected": [
        "This involves web traffic with reflected content.",
        "Filter HTTP responses for unescaped HTML in the body.",
        "The flag is in a script tag -- decode {encoding} encoding.",
    ],
    "dir_traversal": [
        "Look for HTTP requests with path manipulation attempts.",
        "Filter for requests containing '../' in the URI.",
        "Successful (200 OK) responses have {encoding} encoded data.",
    ],
    "arp_spoofing": [
        "This challenge involves Layer 2 ARP traffic analysis.",
        "Filter arp.opcode == 2 for replies with duplicate mappings.",
        "Spoofed associations hide {encoding} encoded data.",
    ],
    "icmp_exfil": [
        "This challenge involves ICMP ping traffic with hidden data.",
        "Filter icmp.seq >= 100 to find exfiltration packets.",
        "ICMP payload bytes from exfil packets are {encoding} encoded.",
    ],
    "_default": [
        "Analyze the network traffic for unusual patterns.",
        "Use Wireshark filters to isolate the relevant protocol.",
        "Packet payloads may contain {encoding} encoded data.",
    ],
}

# Default point values per difficulty (duplicated from routes.py to avoid
# engine -> web import rule violation).
DEFAULT_POINTS: dict[str, int] = {
    "easy": 100,
    "medium": 250,
    "hard": 500,
}

# Hint count per difficulty level.
_HINT_COUNTS: dict[str, int] = {
    "easy": 1,
    "medium": 2,
    "hard": 3,
}

# Cost percentages for each hint position.
_COST_PERCENTAGES: list[float] = [0.10, 0.20, 0.30]


def generate_hints(
    builder_name: str,
    difficulty: str | None,
    encoding_chain: list[str],
    challenge_value: int,
) -> list[dict]:
    """Generate graduated hints for a challenge.

    Args:
        builder_name: The builder used (e.g., "dns_tunnel").
        difficulty: Difficulty level ("easy", "medium", "hard") or None.
        encoding_chain: List of encoding steps applied to the flag.
        challenge_value: Point value of the challenge.

    Returns:
        List of {"content": str, "cost": int} dicts.
    """
    templates = HINT_TEMPLATES.get(builder_name, HINT_TEMPLATES["_default"])
    preset = difficulty or "easy"
    hint_count = _HINT_COUNTS.get(preset, 1)

    # Determine encoding label for template interpolation
    encoding_label = encoding_chain[-1] if encoding_chain else "plaintext"

    hints = []
    for i in range(hint_count):
        content = templates[i].format(encoding=encoding_label)
        cost = int(challenge_value * _COST_PERCENTAGES[i])
        hints.append({"content": content, "cost": cost})
    return hints
