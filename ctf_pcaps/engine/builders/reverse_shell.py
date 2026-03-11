"""Reverse shell builder for interactive command/response session traffic.

Generates realistic reverse shell traffic: a single persistent TCP
session where the victim connects back to the attacker's listener port.
The attacker sends shell commands, the victim returns output with a
shell prompt. OS-specific command sets provide realistic linux or
windows reconnaissance and data exfiltration commands.

Uses TCPSession composition -- one persistent session for the entire
shell interaction.

No Flask imports allowed in engine modules.
"""

import random
from collections.abc import Callable, Iterator
from typing import Any

from ctf_pcaps.engine.builders.base import BaseBuilder
from ctf_pcaps.engine.flag import encode_flag_chain
from ctf_pcaps.engine.protocols.tcp_session import TCPSession
from ctf_pcaps.engine.registry import register_builder

# OS-specific command sets: list of (command, output_template) tuples.
# The last command in each set is the flag-revealing command.
# {flag_placeholder} is replaced with actual flag or placeholder value.
LINUX_COMMANDS = [
    ("whoami", "www-data"),
    ("id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)"),
    (
        "uname -a",
        "Linux webserver 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    ),
    (
        "ifconfig eth0",
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.0.50  netmask 255.255.255.0  broadcast 10.0.0.255",
    ),
    (
        "cat /etc/passwd | head -5",
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync",
    ),
    ("cat /flag.txt", "{flag_placeholder}"),
]

WINDOWS_COMMANDS = [
    ("whoami", "DESKTOP-ABC123\\admin"),
    (
        "ipconfig",
        "Windows IP Configuration\n\n"
        "Ethernet adapter Ethernet0:\n"
        "   IPv4 Address. . . . . . . . . . . : 10.0.0.50\n"
        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
        "   Default Gateway . . . . . . . . . : 10.0.0.1",
    ),
    (
        "systeminfo | findstr OS",
        "OS Name:                   Microsoft Windows 11 Pro\n"
        "OS Version:                10.0.22631 N/A Build 22631",
    ),
    (
        "net user",
        "User accounts for \\\\DESKTOP-ABC123\n\n"
        "-------------------------------------------------------------------------------\n"
        "Administrator            Guest                    admin",
    ),
    ("type C:\\Users\\admin\\Documents\\flag.txt", "{flag_placeholder}"),
]

COMMANDS = {
    "linux": LINUX_COMMANDS,
    "windows": WINDOWS_COMMANDS,
}

DEFAULT_PROMPTS = {
    "linux": "$ ",
    "windows": "C:\\> ",
}

# Placeholder flag used when __flag_text is not provided
_PLACEHOLDER_FLAG = "FLAG{placeholder_reverse_shell_flag}"


def _random_rfc1918_ip() -> str:
    """Generate a random RFC 1918 private IP address (10.x.x.x)."""
    return (
        f"10.{random.randint(0, 255)}.{random.randint(0, 255)}"
        f".{random.randint(1, 254)}"
    )


@register_builder("reverse_shell", version=1)
class ReverseShellBuilder(BaseBuilder):
    """Builder that generates reverse shell session traffic.

    Produces a single persistent TCP session simulating a reverse shell.
    The victim connects back to the attacker's listener port, then the
    attacker sends commands and receives output interactively.

    Parameters:
        victim_ip: Compromised host IP (default: random RFC 1918).
        attacker_ip: Attacker listener IP (default: random RFC 1918).
        listener_port: Attacker listener port (default: 4444).
        os_type: Target OS for command set (default: linux).
        command_count: Number of commands in session (default: 6).
        shell_prompt: Shell prompt string (default: OS-specific).
    """

    def build(
        self,
        params: dict,
        steps: list[dict],
        callback: Callable[[int], None] | None = None,
    ) -> Iterator[Any]:
        """Generate reverse shell session packets.

        Yields packets from a single persistent TCP session with
        alternating command/response data segments.
        """
        victim_ip = params.get("victim_ip") or _random_rfc1918_ip()
        attacker_ip = params.get("attacker_ip") or _random_rfc1918_ip()
        listener_port = params.get("listener_port", 4444)
        os_type = params.get("os_type", "linux")
        command_count = params.get("command_count", 6)
        shell_prompt = params.get(
            "shell_prompt", DEFAULT_PROMPTS.get(os_type, "$ ")
        )

        # Resolve flag text for thematic embedding
        flag_text = params.get("__flag_text")
        flag_encoding = params.get("__flag_encoding")

        if flag_text:
            if flag_encoding:
                embedded_flag = encode_flag_chain(flag_text, flag_encoding)
            else:
                embedded_flag = flag_text
        else:
            embedded_flag = _PLACEHOLDER_FLAG

        # Select OS-specific commands, limited to command_count
        command_set = COMMANDS.get(os_type, LINUX_COMMANDS)[:command_count]

        # Single persistent TCP session (victim connects back to attacker)
        session = TCPSession(
            src_ip=victim_ip, dst_ip=attacker_ip, dport=listener_port
        )

        count = 0

        # Handshake
        for pkt in session.handshake():
            count += 1
            if callback:
                callback(count)
            yield pkt

        # Interactive command/response loop
        for cmd, output_template in command_set:
            # Replace flag placeholder if present
            output = output_template.replace(
                "{flag_placeholder}", embedded_flag
            )

            # Attacker sends command (from_client=False because attacker
            # is the server/listener, victim is the connecting client)
            cmd_data = (cmd + "\n").encode()
            for pkt in session.send_data(cmd_data, from_client=False):
                count += 1
                if callback:
                    callback(count)
                yield pkt

            # Victim responds with output + shell prompt
            output_data = (output + "\n" + shell_prompt).encode()
            for pkt in session.send_data(output_data, from_client=True):
                count += 1
                if callback:
                    callback(count)
                yield pkt

        # Teardown
        for pkt in session.teardown():
            count += 1
            if callback:
                callback(count)
            yield pkt
