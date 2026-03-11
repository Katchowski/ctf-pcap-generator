"""Writeup generation engine module.

Generates author (full solution) and player (redacted) Markdown writeups
from a GenerationResult and scenario metadata. Pure functions with no
Flask imports or side effects.
"""

from __future__ import annotations

from ctf_pcaps.engine.models import GenerationResult

# Wireshark display filters tailored per scenario type.
# Key is builder_used from GenerationResult.
SCENARIO_FILTERS: dict[str, list[str]] = {
    "dns_tunnel": [
        "dns",
        "dns.qry.name contains exfil",
        'dns.qry.name matches "^[a-z2-7]+\\.[0-9]+\\."',
    ],
    "simple_dns": [
        "dns",
        "dns.qry.name",
        "dns.flags.response == 1",
    ],
    "http_beacon": [
        "http",
        "http.request.method == GET",
        "http.host contains cdn",
    ],
    "brute_force": [
        "http",
        "http.request.method == POST",
        "http.response.code == 401 || http.response.code == 200",
    ],
    "sqli": [
        "http",
        'http.request.uri contains "UNION"',
        'http.request.uri contains "SELECT"',
    ],
    "syn_scan": [
        "tcp",
        "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "tcp.flags.syn == 1 && tcp.flags.ack == 1",
    ],
    "simple_tcp": [
        "tcp",
        "tcp.stream eq 0",
        "tcp.len > 0",
    ],
    "reverse_shell": [
        "tcp.stream eq 0",
        "tcp.port == 4444",
        "tcp.flags.push == 1",
    ],
    "xss_reflected": [
        "http",
        "http.request.uri contains script",
        "http.response.code == 200",
    ],
    "dir_traversal": [
        "http",
        'http.request.uri contains ".."',
        "http.response.code == 200 || http.response.code == 403",
    ],
    "arp_spoofing": [
        "arp",
        "arp.opcode == 2",
        "arp.duplicate-address-detected",
    ],
    "icmp_exfil": [
        "icmp",
        "icmp.type == 8",
        "icmp.seq >= 100",
    ],
    "_default": [
        "tcp",
        "ip.addr",
        "frame.len > 0",
    ],
}

# Recommended tools per scenario type.
SCENARIO_TOOLS: dict[str, str] = {
    "dns_tunnel": "Wireshark, tshark, CyberChef (Base32 decoding)",
    "simple_dns": "Wireshark, tshark",
    "http_beacon": "Wireshark, tshark, strings",
    "brute_force": "Wireshark, tshark, grep",
    "sqli": "Wireshark, tshark, URL decoder",
    "syn_scan": "Wireshark, tshark, nmap (for comparison)",
    "simple_tcp": "Wireshark, tshark",
    "reverse_shell": "Wireshark, tshark, Follow TCP Stream",
    "xss_reflected": "Wireshark, tshark, CyberChef (HTML entity decoding)",
    "dir_traversal": "Wireshark, tshark, HTTP object export",
    "arp_spoofing": "Wireshark, arpwatch",
    "icmp_exfil": "Wireshark, tshark, hex editor",
    "_default": "Wireshark, tshark",
}

# Educational content about real-world attack techniques.
SCENARIO_EDUCATION: dict[str, str] = {
    "dns_tunnel": (
        "DNS tunneling is a technique used by attackers to exfiltrate data or "
        "establish command-and-control channels by encoding data within DNS "
        "queries and responses. Because DNS traffic is rarely blocked by "
        "firewalls, it serves as a covert communication channel. In the wild, "
        "tools like iodine, dnscat2, and DNSExfiltrator use this technique. "
        "Defenders should monitor for unusually long subdomain labels, high "
        "query volumes to a single domain, and non-standard record types."
    ),
    "simple_dns": (
        "DNS is the backbone of internet naming. Attackers often abuse DNS for "
        "reconnaissance (zone transfers, subdomain enumeration) and data "
        "exfiltration. Understanding normal DNS traffic patterns helps "
        "analysts spot anomalies such as unusual query frequencies, rare "
        "record types, or queries to suspicious domains."
    ),
    "http_beacon": (
        "HTTP beaconing is a hallmark of malware command-and-control (C2) "
        "communication. Infected hosts periodically reach out to a C2 server "
        "disguised as normal web traffic. Indicators include regular time "
        "intervals between requests, consistent URL patterns, and small "
        "response payloads. Real-world malware families like Cobalt Strike "
        "and Emotet use HTTP beaconing extensively."
    ),
    "brute_force": (
        "Brute force attacks systematically attempt every possible password "
        "combination against a login endpoint. In the real world, attackers "
        "use tools like Hydra, Burp Suite Intruder, and custom scripts to "
        "automate credential stuffing and password spraying. Network forensics "
        "reveals these attacks through repeated POST requests to login "
        "endpoints with varying credentials and mostly failed response codes."
    ),
    "sqli": (
        "SQL injection remains one of the most critical web application "
        "vulnerabilities. Attackers inject malicious SQL statements through "
        "user input fields to extract, modify, or delete database contents. "
        "UNION-based injection combines results from the original query with "
        "data from other tables. Real-world breaches at major companies have "
        "been caused by SQLi, making it essential to recognize in traffic."
    ),
    "syn_scan": (
        "SYN scanning (half-open scanning) is the most common port scanning "
        "technique used for network reconnaissance. The scanner sends SYN "
        "packets to target ports and analyzes the responses: SYN-ACK "
        "indicates an open port, RST indicates closed. Tools like nmap use "
        "this technique by default. In forensic analysis, SYN scans appear "
        "as rapid connections to sequential ports without completing the "
        "TCP handshake."
    ),
    "simple_tcp": (
        "TCP is the foundation of most internet communication. Understanding "
        "TCP stream analysis -- following the three-way handshake, data "
        "exchange, and teardown -- is essential for network forensics. "
        "Analysts use TCP stream reassembly to reconstruct conversations "
        "and identify data transfers, commands, and anomalies."
    ),
    "reverse_shell": (
        "A reverse shell is a post-exploitation technique where the "
        "compromised host initiates an outbound connection to the attacker, "
        "bypassing inbound firewall rules. The attacker gains interactive "
        "command-line access to the victim. Tools like netcat, Metasploit, "
        "and custom payloads establish reverse shells. In network traffic, "
        "reverse shells appear as persistent TCP connections on unusual ports "
        "with bidirectional command/response data."
    ),
    "xss_reflected": (
        "Reflected Cross-Site Scripting (XSS) occurs when user input is "
        "immediately returned in a web page without sanitization. Attackers "
        "craft malicious URLs containing JavaScript payloads that execute "
        "in victims' browsers, enabling session hijacking, credential theft, "
        "and defacement. In network captures, reflected XSS appears as HTTP "
        "requests with script tags in parameters and responses echoing the "
        "payload back."
    ),
    "dir_traversal": (
        "Directory traversal (path traversal) attacks exploit insufficient "
        "input validation to access files outside the intended directory. "
        "By using sequences like '../' in file path parameters, attackers "
        "can read sensitive system files such as /etc/passwd or "
        "configuration files. This vulnerability has been found in web "
        "servers, file upload handlers, and API endpoints across many "
        "production systems."
    ),
    "arp_spoofing": (
        "ARP spoofing (ARP poisoning) is a Layer 2 attack where an attacker "
        "sends forged ARP replies to associate their MAC address with the IP "
        "of a legitimate host, typically the default gateway. This enables "
        "man-in-the-middle attacks, allowing the attacker to intercept, "
        "modify, or drop traffic. Tools like arpspoof and Ettercap automate "
        "this attack. Detection relies on identifying duplicate IP-to-MAC "
        "mappings and gratuitous ARP replies."
    ),
    "icmp_exfil": (
        "ICMP data exfiltration hides stolen data within the payload of "
        "ICMP echo request and reply packets (pings). Since ICMP is often "
        "allowed through firewalls for diagnostic purposes, it provides a "
        "covert channel for data theft. Tools like icmpsh and custom scripts "
        "encode data in the ICMP payload. Forensic analysts should examine "
        "ICMP packets with unusually large payloads or non-standard data "
        "patterns in the payload bytes."
    ),
    "_default": (
        "Network forensics involves capturing, recording, and analyzing "
        "network traffic to discover the source of security incidents. "
        "Understanding protocol behavior, identifying anomalies, and "
        "reconstructing attacker activities from packet captures are "
        "essential skills for incident response and threat hunting."
    ),
}


def generate_writeup(
    result: GenerationResult,
    scenario_name: str,
    scenario_description: str,
    scenario_slug: str,
    difficulty: str | None = None,
) -> tuple[str, str]:
    """Generate author and player writeup Markdown.

    Args:
        result: The generation result containing solve steps, flag, etc.
        scenario_name: Human-readable scenario name.
        scenario_description: Scenario description text.
        scenario_slug: Scenario slug for fallback lookups.
        difficulty: Difficulty level string (easy/medium/hard) or None.

    Returns:
        Tuple of (author_writeup_md, player_writeup_md).
    """
    # Primary key is builder_used, fallback to scenario_slug, then _default
    lookup_key = result.builder_used
    if lookup_key not in SCENARIO_FILTERS:
        lookup_key = scenario_slug
    if lookup_key not in SCENARIO_FILTERS:
        lookup_key = "_default"

    sections = _build_sections(
        result, scenario_name, scenario_description, lookup_key, difficulty
    )
    author_md = _render_author(sections)
    player_md = _render_player(sections)
    return author_md, player_md


def _build_sections(
    result: GenerationResult,
    scenario_name: str,
    scenario_description: str,
    lookup_key: str,
    difficulty: str | None,
) -> dict:
    """Build a sections dict from result fields and registries."""
    filters = SCENARIO_FILTERS.get(lookup_key, SCENARIO_FILTERS["_default"])
    tools = SCENARIO_TOOLS.get(lookup_key, SCENARIO_TOOLS["_default"])
    education = SCENARIO_EDUCATION.get(lookup_key, SCENARIO_EDUCATION["_default"])

    # Format filters as code blocks
    filters_md = "\n".join(f"- `{f}`" for f in filters)

    # Format solve steps as numbered list
    if result.solve_steps:
        steps_md = "\n".join(
            f"{i}. {step}" for i, step in enumerate(result.solve_steps, 1)
        )
    else:
        steps_md = "No specific solve steps recorded for this challenge."

    # Format difficulty info
    difficulty_str = difficulty or "Not specified"
    difficulty_md = f"**Level:** {difficulty_str}"
    if result.encoding_chain:
        chain_str = " -> ".join(result.encoding_chain)
        difficulty_md += f"\n\n**Encoding chain:** {chain_str}"

    # Format flag
    flag_md = f"`{result.flag_text}`" if result.flag_text else "No flag text available."

    return {
        "name": scenario_name,
        "description": scenario_description,
        "difficulty": difficulty_md,
        "tools": tools,
        "filters": filters_md,
        "solve_steps": steps_md,
        "flag": flag_md,
        "learning": education,
    }


def _render_author(sections: dict) -> str:
    """Render the full author/solution writeup with all 7 sections."""
    parts = [
        f"# {sections['name']} - Solution Writeup\n",
        f"## Scenario Background\n\n{sections['description']}\n",
        f"## Difficulty\n\n{sections['difficulty']}\n",
        f"## Recommended Tools\n\n{sections['tools']}\n",
        f"## Wireshark Filters\n\n{sections['filters']}\n",
        f"## Step-by-Step Solution\n\n{sections['solve_steps']}\n",
        f"## Flag\n\n{sections['flag']}\n",
        f"## What to Learn\n\n{sections['learning']}\n",
    ]
    return "\n".join(parts)


def _render_player(sections: dict) -> str:
    """Render the redacted player writeup (omits Flag and Solution)."""
    parts = [
        f"# {sections['name']} - Writeup\n",
        f"## Scenario Background\n\n{sections['description']}\n",
        f"## Difficulty\n\n{sections['difficulty']}\n",
        f"## Recommended Tools\n\n{sections['tools']}\n",
        f"## Wireshark Filters\n\n{sections['filters']}\n",
        f"## What to Learn\n\n{sections['learning']}\n",
    ]
    return "\n".join(parts)
