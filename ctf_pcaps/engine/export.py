"""Challenge export engine module.

Builds ctfcli-compatible challenge.yml dicts and assembles ZIP bundles
containing challenge.yml + PCAP + writeup. Pure functions with no Flask
imports or side effects beyond ZIP creation.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import yaml


def build_challenge_yml(
    name: str,
    description: str,
    category: str,
    value: int,
    flag_text: str,
    hints: list[dict],
    pcap_filename: str,
) -> dict:
    """Build a ctfcli-compatible challenge.yml dict.

    Args:
        name: Challenge display name.
        description: Challenge description text.
        category: Challenge category (e.g., "network_attack").
        value: Point value for the challenge.
        flag_text: The flag string (e.g., "flag{...}").
        hints: List of {"content": str, "cost": int} dicts.
        pcap_filename: PCAP filename for the files list.

    Returns:
        Dict matching the ctfcli challenge.yml specification.
    """
    return {
        "name": name,
        "description": description,
        "category": category,
        "value": value,
        "type": "standard",
        "state": "hidden",
        "flags": [
            {
                "type": "static",
                "content": flag_text,
                "data": "case_sensitive",
            }
        ],
        "hints": [{"content": h["content"], "cost": h["cost"]} for h in hints],
        "files": [f"dist/{pcap_filename}"],
        "version": "0.1",
    }


def create_export_bundle(
    challenge_yml: dict,
    pcap_path: Path,
    writeup_md: str,
) -> io.BytesIO:
    """Create a ZIP bundle with ctfcli-compatible directory structure.

    Bundle layout:
        challenge.yml   -- challenge metadata
        dist/<pcap>     -- the PCAP file
        writeup.md      -- solution writeup

    Args:
        challenge_yml: Dict to serialize as challenge.yml.
        pcap_path: Path to the PCAP file on disk.
        writeup_md: Writeup Markdown content string.

    Returns:
        BytesIO containing the ZIP file, seeked to position 0.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # challenge.yml at root
        yml_content = yaml.dump(challenge_yml, default_flow_style=False)
        zf.writestr("challenge.yml", yml_content)

        # PCAP in dist/ subdirectory (forward-slash path for cross-platform)
        zf.write(pcap_path, f"dist/{pcap_path.name}")

        # writeup.md at root
        zf.writestr("writeup.md", writeup_md)

    buf.seek(0)
    return buf
