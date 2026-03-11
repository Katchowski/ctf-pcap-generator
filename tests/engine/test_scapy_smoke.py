"""Scapy smoke tests -- verify Scapy is importable and functional.

These tests are designed to run inside the Docker container where Scapy
and libpcap are installed. They verify the core dependency is working
correctly before any Phase 2+ generation logic is built.
"""

import inspect


def test_scapy_importable():
    """Scapy core packet types and pcap functions can be imported."""
    from scapy.all import IP, TCP, rdpcap, wrpcap  # noqa: F401


def test_wrpcap_creates_file(tmp_path):
    """wrpcap() writes a valid .pcap file that rdpcap() can read back."""
    from scapy.all import IP, TCP, rdpcap, wrpcap

    # Create a test packet
    pkt = IP(dst="1.2.3.4") / TCP(dport=80)

    # Write to pcap
    pcap_path = str(tmp_path / "test.pcap")
    wrpcap(pcap_path, [pkt])

    # Read back and verify
    packets = rdpcap(pcap_path)
    assert len(packets) == 1
    assert packets[0].haslayer(IP)
    assert packets[0][IP].dst == "1.2.3.4"


def test_layer_isolation():
    """Engine and integration packages do not import from web or flask.

    Verifies the three-layer architecture constraint: engine and integration
    must never pull in web/flask dependencies.
    """
    # Read the source files to check for forbidden imports
    import ctf_pcaps.engine
    import ctf_pcaps.integration

    engine_source = inspect.getsource(ctf_pcaps.engine)
    integration_source = inspect.getsource(ctf_pcaps.integration)

    # Engine must not import from web or flask
    assert "from ctf_pcaps.web" not in engine_source, (
        "engine/__init__.py must not import from ctf_pcaps.web"
    )
    assert "import flask" not in engine_source, (
        "engine/__init__.py must not import flask"
    )

    # Integration must not import from web or flask
    assert "from ctf_pcaps.web" not in integration_source, (
        "integration/__init__.py must not import from ctf_pcaps.web"
    )
    assert "import flask" not in integration_source, (
        "integration/__init__.py must not import flask"
    )
