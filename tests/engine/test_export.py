"""Tests for the ctfcli-compatible export engine module."""

import io
import zipfile

import yaml


def test_build_challenge_yml_returns_dict():
    """build_challenge_yml returns a dict with all required ctfcli keys."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="DNS Tunneling",
        description="Analyze DNS traffic for hidden data.",
        category="covert_channel",
        value=250,
        flag_text="flag{dns_exfil_2026}",
        hints=[
            {"content": "Look at DNS queries.", "cost": 25},
            {"content": "Filter by subdomain length.", "cost": 50},
        ],
        pcap_filename="dns_tunnel_abc123.pcap",
    )

    assert isinstance(result, dict)
    required_keys = {
        "name",
        "description",
        "category",
        "value",
        "type",
        "state",
        "flags",
        "hints",
        "files",
        "version",
    }
    assert required_keys.issubset(result.keys())


def test_build_challenge_yml_name_and_description():
    """build_challenge_yml passes through name and description."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="SYN Port Scan",
        description="Detect port scanning activity.",
        category="network_attack",
        value=100,
        flag_text="flag{syn_scan}",
        hints=[],
        pcap_filename="syn_scan.pcap",
    )

    assert result["name"] == "SYN Port Scan"
    assert result["description"] == "Detect port scanning activity."


def test_build_challenge_yml_category_and_value():
    """build_challenge_yml sets category and value correctly."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="Test",
        description="Test",
        category="web_traffic",
        value=500,
        flag_text="flag{test}",
        hints=[],
        pcap_filename="test.pcap",
    )

    assert result["category"] == "web_traffic"
    assert result["value"] == 500


def test_build_challenge_yml_type_and_state():
    """build_challenge_yml sets type=standard and state=hidden."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="Test",
        description="Test",
        category="misc",
        value=100,
        flag_text="flag{test}",
        hints=[],
        pcap_filename="test.pcap",
    )

    assert result["type"] == "standard"
    assert result["state"] == "hidden"


def test_build_challenge_yml_flags_structure():
    """build_challenge_yml flags list has static flag with case_sensitive data."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="Test",
        description="Test",
        category="misc",
        value=100,
        flag_text="flag{secret_flag}",
        hints=[],
        pcap_filename="test.pcap",
    )

    assert len(result["flags"]) == 1
    flag = result["flags"][0]
    assert flag["type"] == "static"
    assert flag["content"] == "flag{secret_flag}"
    assert flag["data"] == "case_sensitive"


def test_build_challenge_yml_hints_structure():
    """build_challenge_yml hints list matches input content and cost."""
    from ctf_pcaps.engine.export import build_challenge_yml

    hints_input = [
        {"content": "Hint 1", "cost": 10},
        {"content": "Hint 2", "cost": 20},
    ]
    result = build_challenge_yml(
        name="Test",
        description="Test",
        category="misc",
        value=100,
        flag_text="flag{test}",
        hints=hints_input,
        pcap_filename="test.pcap",
    )

    assert len(result["hints"]) == 2
    assert result["hints"][0] == {"content": "Hint 1", "cost": 10}
    assert result["hints"][1] == {"content": "Hint 2", "cost": 20}


def test_build_challenge_yml_files_dist_path():
    """build_challenge_yml files list contains dist/{pcap_filename}."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="Test",
        description="Test",
        category="misc",
        value=100,
        flag_text="flag{test}",
        hints=[],
        pcap_filename="dns_tunnel_abc123.pcap",
    )

    assert result["files"] == ["dist/dns_tunnel_abc123.pcap"]


def test_build_challenge_yml_version():
    """build_challenge_yml version is '0.1'."""
    from ctf_pcaps.engine.export import build_challenge_yml

    result = build_challenge_yml(
        name="Test",
        description="Test",
        category="misc",
        value=100,
        flag_text="flag{test}",
        hints=[],
        pcap_filename="test.pcap",
    )

    assert result["version"] == "0.1"


def test_create_export_bundle_returns_bytesio(tmp_path):
    """create_export_bundle returns a BytesIO object."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    challenge_yml = {"name": "Test", "type": "standard"}
    result = create_export_bundle(challenge_yml, pcap_path, "# Writeup\n")

    assert isinstance(result, io.BytesIO)


def test_create_export_bundle_valid_zip(tmp_path):
    """create_export_bundle produces a valid ZIP file."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    challenge_yml = {"name": "Test", "type": "standard"}
    buf = create_export_bundle(challenge_yml, pcap_path, "# Writeup\n")

    assert zipfile.is_zipfile(buf)


def test_create_export_bundle_contains_expected_files(tmp_path):
    """create_export_bundle ZIP contains challenge.yml, dist/test.pcap, writeup.md."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    challenge_yml = {"name": "Test", "type": "standard"}
    buf = create_export_bundle(challenge_yml, pcap_path, "# Writeup\n")

    with zipfile.ZipFile(buf) as zf:
        names = zf.namelist()

    assert "challenge.yml" in names
    assert "dist/test.pcap" in names
    assert "writeup.md" in names


def test_create_export_bundle_challenge_yml_valid_yaml(tmp_path):
    """challenge.yml inside ZIP is valid YAML matching the input dict."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    challenge_yml = {
        "name": "DNS Tunneling",
        "value": 250,
        "type": "standard",
        "flags": [{"type": "static", "content": "flag{test}"}],
    }
    buf = create_export_bundle(challenge_yml, pcap_path, "# Writeup\n")

    with zipfile.ZipFile(buf) as zf:
        yml_content = zf.read("challenge.yml").decode("utf-8")

    parsed = yaml.safe_load(yml_content)
    assert parsed["name"] == "DNS Tunneling"
    assert parsed["value"] == 250
    assert parsed["flags"][0]["content"] == "flag{test}"


def test_create_export_bundle_pcap_contents(tmp_path):
    """dist/pcap inside ZIP matches the original PCAP file bytes."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 100
    pcap_path = tmp_path / "challenge.pcap"
    pcap_path.write_bytes(pcap_data)

    challenge_yml = {"name": "Test"}
    buf = create_export_bundle(challenge_yml, pcap_path, "# Writeup\n")

    with zipfile.ZipFile(buf) as zf:
        extracted = zf.read("dist/challenge.pcap")

    assert extracted == pcap_data


def test_create_export_bundle_writeup_contents(tmp_path):
    """writeup.md inside ZIP matches the input writeup text."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_path = tmp_path / "test.pcap"
    pcap_path.write_bytes(b"\x00" * 24)

    writeup_text = "# DNS Tunneling\n\nFull solution writeup.\n"
    challenge_yml = {"name": "Test"}
    buf = create_export_bundle(challenge_yml, pcap_path, writeup_text)

    with zipfile.ZipFile(buf) as zf:
        extracted = zf.read("writeup.md").decode("utf-8")

    assert extracted == writeup_text


def test_create_export_bundle_forward_slash_paths(tmp_path):
    """ZIP paths use forward slashes (no Windows backslashes)."""
    from ctf_pcaps.engine.export import create_export_bundle

    pcap_path = tmp_path / "scan_results.pcap"
    pcap_path.write_bytes(b"\x00" * 24)

    challenge_yml = {"name": "Test"}
    buf = create_export_bundle(challenge_yml, pcap_path, "# Writeup\n")

    with zipfile.ZipFile(buf) as zf:
        for name in zf.namelist():
            assert "\\" not in name, f"Backslash found in ZIP path: {name}"
