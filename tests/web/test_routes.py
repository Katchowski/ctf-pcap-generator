"""Tests for Flask web routes."""

from unittest.mock import MagicMock, patch


def test_health_returns_ok(client):
    """GET /health returns 200 with JSON status ok and scapy true."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["scapy"] is True


def test_index_redirects_to_scenarios(client):
    """GET / returns 302 redirect to /scenarios."""
    response = client.get("/")
    assert response.status_code == 302
    assert "/scenarios" in response.headers["Location"]


def test_index_follows_redirect(client):
    """GET / with follow_redirects returns 200 with CTF PCAP Generator."""
    response = client.get("/", follow_redirects=True)
    assert response.status_code == 200
    assert b"CTF PCAP Generator" in response.data


def test_index_contains_bootstrap(client):
    """GET / redirect target contains Bootstrap CSS link."""
    response = client.get("/", follow_redirects=True)
    assert response.status_code == 200
    assert b"bootstrap" in response.data


def test_scenarios_page_returns_200(client):
    """GET /scenarios returns 200 with 'Scenarios' in body."""
    response = client.get("/scenarios")
    assert response.status_code == 200
    assert b"Scenarios" in response.data


def test_scenarios_page_contains_cards(client):
    """GET /scenarios contains 'scenario-card' class."""
    response = client.get("/scenarios")
    assert response.status_code == 200
    assert b"scenario-card" in response.data


def test_scenarios_page_contains_category_tabs(client):
    """GET /scenarios contains 'nav-tabs'."""
    response = client.get("/scenarios")
    assert response.status_code == 200
    assert b"nav-tabs" in response.data


def test_scenarios_cards_partial_returns_200(client):
    """GET /scenarios/cards returns 200."""
    response = client.get("/scenarios/cards")
    assert response.status_code == 200


def test_scenarios_cards_filter_by_category(client):
    """GET /scenarios/cards?category=network_attack returns matching cards."""
    response = client.get("/scenarios/cards?category=network_attack")
    assert response.status_code == 200
    assert b"SYN Port Scan" in response.data
    assert b"DNS Tunnel" not in response.data


def test_scenarios_cards_all_returns_all(client):
    """GET /scenarios/cards returns all scenario names."""
    response = client.get("/scenarios/cards")
    assert response.status_code == 200
    assert b"Simple TCP Session" in response.data
    assert b"Simple DNS Lookup" in response.data
    assert b"SYN Port Scan" in response.data
    assert b"Brute Force Login" in response.data
    assert b"SQL Injection" in response.data
    assert b"DNS Tunneling" in response.data
    assert b"HTTP Beaconing" in response.data


def test_health_still_works(client):
    """GET /health returns 200 with JSON (regression test)."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert "status" in data
    assert isinstance(data["scapy"], bool)


def test_create_app_returns_flask_app():
    """create_app() returns a Flask app instance."""
    from flask import Flask

    from ctf_pcaps.web import create_app

    app = create_app({"TESTING": True})
    assert isinstance(app, Flask)


def test_create_app_accepts_config_override():
    """create_app() accepts config_override dict that updates app.config."""
    from ctf_pcaps.web import create_app

    app = create_app({"TESTING": True, "CUSTOM_KEY": "custom_value"})
    assert app.config["CUSTOM_KEY"] == "custom_value"


def test_health_scapy_check():
    """GET /health returns scapy status based on import availability."""
    from ctf_pcaps.web import create_app

    app = create_app({"TESTING": True})
    client = app.test_client()
    response = client.get("/health")
    data = response.get_json()
    # scapy should be a boolean
    assert isinstance(data["scapy"], bool)


# --- Plan 02: Generation form, difficulty info, download, error pages ---


def test_generate_form_returns_200(client):
    """GET /generate/syn_scan returns 200 with scenario name and key elements."""
    response = client.get("/generate/syn_scan")
    assert response.status_code == 200
    assert b"SYN Port Scan" in response.data
    assert b"Flag" in response.data
    assert b"Difficulty" in response.data
    assert b"Generate PCAP" in response.data


def test_generate_form_unknown_scenario_404(client):
    """GET /generate/nonexistent returns 404."""
    response = client.get("/generate/nonexistent")
    assert response.status_code == 404


def test_difficulty_info_easy(client):
    """GET /api/difficulty/easy returns 200 with preset info."""
    response = client.get("/api/difficulty/easy")
    assert response.status_code == 200
    assert b"Easy" in response.data
    assert b"plaintext" in response.data
    assert b"20%" in response.data


def test_difficulty_info_unknown_204(client):
    """GET /api/difficulty/unknown returns 204 (no content)."""
    response = client.get("/api/difficulty/unknown")
    assert response.status_code == 204


def test_download_non_pcap_404(client):
    """GET /download/notapcap.txt returns 404."""
    response = client.get("/download/notapcap.txt")
    assert response.status_code == 404


def test_download_path_traversal_404(client):
    """GET /download/../../etc/passwd returns 404 (path traversal blocked)."""
    response = client.get("/download/../../etc/passwd")
    assert response.status_code == 404


def test_custom_404_page(client):
    """GET /nonexistent returns 404 with custom page content."""
    response = client.get("/nonexistent")
    assert response.status_code == 404
    assert b"Not Found" in response.data
    assert b"Back to Scenarios" in response.data


def test_generate_form_contains_parameters(client):
    """GET /generate/syn_scan contains scenario-specific parameter fields."""
    response = client.get("/generate/syn_scan")
    assert response.status_code == 200
    assert b"dst_ip" in response.data
    assert b"ports" in response.data


def test_generate_form_has_flag_toggle(client):
    """GET /generate/syn_scan contains embed_flag toggle."""
    response = client.get("/generate/syn_scan")
    assert response.status_code == 200
    assert b"embed_flag" in response.data


def test_generate_stream_returns_sse(client):
    """GET /generate/syn_scan/stream returns text/event-stream content type."""
    response = client.get("/generate/syn_scan/stream")
    assert response.status_code == 200
    assert "text/event-stream" in response.content_type
    # Verify SSE format: data contains 'event:' lines
    assert b"event:" in response.data


def test_coerce_form_params_int():
    """_coerce_form_params converts numeric strings to int."""
    from ctf_pcaps.web.routes import _coerce_form_params

    params = {"count": {"default": 10, "min": 1, "max": 100}}
    result = _coerce_form_params({"param_count": "42"}, params)
    assert result == {"count": 42}


def test_coerce_form_params_empty():
    """_coerce_form_params returns None when no params match."""
    from ctf_pcaps.web.routes import _coerce_form_params

    params = {"count": {"default": 10, "min": 1, "max": 100}}
    result = _coerce_form_params({}, params)
    assert result is None


def test_coerce_form_params_list():
    """_coerce_form_params splits comma-separated values into list."""
    from ctf_pcaps.web.routes import _coerce_form_params

    params = {"ports": {"default": [80, 443], "min": None, "max": None}}
    result = _coerce_form_params({"param_ports": "22, 80, 443"}, params)
    assert result == {"ports": [22, 80, 443]}


def test_coerce_form_params_bool():
    """_coerce_form_params converts boolean string values."""
    from ctf_pcaps.web.routes import _coerce_form_params

    params = {"verbose": {"default": False, "min": None, "max": None}}
    result = _coerce_form_params({"param_verbose": "true"}, params)
    assert result == {"verbose": True}


def test_coerce_form_params_invalid_number():
    """_coerce_form_params skips invalid numeric values."""
    from ctf_pcaps.web.routes import _coerce_form_params

    params = {"count": {"default": 10, "min": 1, "max": 100}}
    result = _coerce_form_params({"param_count": "not_a_number"}, params)
    assert result is None


# --- Plan 08-02: Settings page tests ---


@patch("ctf_pcaps.web.routes.load_ctfd_config")
def test_settings_page_returns_200(mock_load_config, client):
    """GET /settings returns 200 with Settings in body."""
    mock_load_config.return_value = {"url": "", "token": ""}
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"Settings" in response.data


@patch("ctf_pcaps.web.routes.load_ctfd_config")
def test_settings_page_contains_form(mock_load_config, client):
    """GET /settings contains form with ctfd_url input."""
    mock_load_config.return_value = {"url": "", "token": ""}
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"ctfd_url" in response.data
    assert b"ctfd_token" in response.data
    assert b"Save" in response.data


@patch("ctf_pcaps.web.routes.CTFdClient")
@patch("ctf_pcaps.web.routes.save_ctfd_config")
def test_save_settings_saves_config(mock_save, mock_client_cls, client):
    """POST /api/ctfd/settings with url and token saves and tests connection."""
    mock_instance = MagicMock()
    mock_instance.test_connection.return_value = True
    mock_client_cls.return_value = mock_instance

    response = client.post(
        "/api/ctfd/settings",
        data={"ctfd_url": "https://ctfd.test", "ctfd_token": "tok123"},
    )
    assert response.status_code == 200
    assert b"Connected" in response.data or b"success" in response.data
    mock_save.assert_called_once()


@patch("ctf_pcaps.web.routes.CTFdClient")
@patch("ctf_pcaps.web.routes.save_ctfd_config")
def test_save_settings_auth_error(mock_save, mock_client_cls, client):
    """POST /api/ctfd/settings with auth error shows invalid message."""
    from ctf_pcaps.integration.ctfd_client import CTFdAuthError

    mock_instance = MagicMock()
    mock_instance.test_connection.side_effect = CTFdAuthError("bad token")
    mock_client_cls.return_value = mock_instance

    response = client.post(
        "/api/ctfd/settings",
        data={"ctfd_url": "https://ctfd.test", "ctfd_token": "bad"},
    )
    assert response.status_code == 200
    assert b"invalid or expired" in response.data


@patch("ctf_pcaps.web.routes.CTFdClient")
@patch("ctf_pcaps.web.routes.save_ctfd_config")
def test_save_settings_connection_error(mock_save, mock_client_cls, client):
    """POST /api/ctfd/settings with connection error shows unreachable."""
    from ctf_pcaps.integration.ctfd_client import CTFdConnectionError

    mock_instance = MagicMock()
    mock_instance.test_connection.side_effect = CTFdConnectionError("timeout")
    mock_client_cls.return_value = mock_instance

    response = client.post(
        "/api/ctfd/settings",
        data={"ctfd_url": "https://ctfd.test", "ctfd_token": "tok"},
    )
    assert response.status_code == 200
    assert b"Cannot reach" in response.data


# --- Plan 08-02: Push page tests ---


_MOCK_HISTORY_ENTRY = {
    "filename": "test_scan.pcap",
    "scenario_slug": "syn_scan",
    "scenario_name": "SYN Port Scan",
    "scenario_description": "Simulates a SYN port scan attack.",
    "category": "network_attack",
    "category_label": "Network Attack",
    "flag_text": "flag{test123}",
    "difficulty": "medium",
    "timestamp": "2026-03-07T12:00:00",
    "file_size_bytes": 52480,
    "pushed": False,
    "push_challenge_id": None,
    "push_challenge_name": None,
    "push_timestamp": None,
}


@patch("ctf_pcaps.web.routes.load_history")
def test_push_page_returns_200(mock_history, client):
    """GET /push returns 200."""
    mock_history.return_value = []
    response = client.get("/push")
    assert response.status_code == 200


@patch("ctf_pcaps.web.routes.load_history")
def test_push_page_empty_history(mock_history, client):
    """GET /push with no history shows 'No generated PCAPs'."""
    mock_history.return_value = []
    response = client.get("/push")
    assert response.status_code == 200
    assert b"No generated PCAPs" in response.data


@patch("ctf_pcaps.web.routes.load_ctfd_config")
@patch("ctf_pcaps.web.routes.load_history")
def test_push_form_returns_200(mock_history, mock_config, client, tmp_path):
    """GET /push/{filename} with mocked history returns 200 with form."""
    entry = {**_MOCK_HISTORY_ENTRY}
    mock_history.return_value = [entry]
    mock_config.return_value = {"url": "https://ctfd.test", "token": "tok123"}

    # Create the PCAP file so file_exists check passes
    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        (tmp_path / "test_scan.pcap").touch()

        response = client.get("/push/test_scan.pcap")

    assert response.status_code == 200
    assert b"Push Challenge to CTFd" in response.data
    assert b"SYN Port Scan" in response.data


@patch("ctf_pcaps.web.routes.load_ctfd_config")
@patch("ctf_pcaps.web.routes.load_history")
def test_push_form_redirects_without_config(mock_history, mock_config, client):
    """GET /push/{filename} with empty CTFd config redirects to /settings."""
    entry = {**_MOCK_HISTORY_ENTRY}
    mock_history.return_value = [entry]
    mock_config.return_value = {"url": "", "token": ""}

    response = client.get("/push/test_scan.pcap")
    assert response.status_code == 302
    assert "/settings" in response.headers["Location"]


@patch("ctf_pcaps.web.routes.load_ctfd_config")
@patch("ctf_pcaps.web.routes.load_history")
def test_push_form_default_points_easy(mock_history, mock_config, client, tmp_path):
    """Easy difficulty defaults to 100 points."""
    entry = {**_MOCK_HISTORY_ENTRY, "difficulty": "easy"}
    mock_history.return_value = [entry]
    mock_config.return_value = {"url": "https://ctfd.test", "token": "tok"}

    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        (tmp_path / "test_scan.pcap").touch()

        response = client.get("/push/test_scan.pcap")

    assert response.status_code == 200
    assert b'value="100"' in response.data


@patch("ctf_pcaps.web.routes.load_ctfd_config")
@patch("ctf_pcaps.web.routes.load_history")
def test_push_form_default_points_hard(mock_history, mock_config, client, tmp_path):
    """Hard difficulty defaults to 500 points."""
    entry = {**_MOCK_HISTORY_ENTRY, "difficulty": "hard"}
    mock_history.return_value = [entry]
    mock_config.return_value = {"url": "https://ctfd.test", "token": "tok"}

    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        (tmp_path / "test_scan.pcap").touch()

        response = client.get("/push/test_scan.pcap")

    assert response.status_code == 200
    assert b'value="500"' in response.data


@patch("ctf_pcaps.web.routes.update_history_push_status")
@patch("ctf_pcaps.web.routes.CTFdClient")
@patch("ctf_pcaps.web.routes.load_history")
@patch("ctf_pcaps.web.routes.load_ctfd_config")
def test_push_api_success(
    mock_config, mock_history, mock_client_cls, mock_update, client, tmp_path
):
    """POST /api/ctfd/push with success shows confirmation."""
    mock_config.return_value = {"url": "https://ctfd.test", "token": "tok"}
    mock_history.return_value = [_MOCK_HISTORY_ENTRY]

    mock_instance = MagicMock()
    mock_instance.push_challenge.return_value = {
        "challenge_id": 42,
        "admin_url": "https://ctfd.test/admin/challenges/42",
    }
    mock_client_cls.return_value = mock_instance

    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        (tmp_path / "test_scan.pcap").write_bytes(b"fake pcap")

        response = client.post(
            "/api/ctfd/push",
            data={
                "filename": "test_scan.pcap",
                "name": "SYN Port Scan",
                "description": "Test",
                "category": "Network Attack",
                "value": "250",
                "state": "hidden",
            },
        )

    assert response.status_code == 200
    assert b"successfully" in response.data
    mock_update.assert_called_once()


@patch("ctf_pcaps.web.routes.CTFdClient")
@patch("ctf_pcaps.web.routes.load_history")
@patch("ctf_pcaps.web.routes.load_ctfd_config")
def test_push_api_auth_error(
    mock_config, mock_history, mock_client_cls, client, tmp_path
):
    """POST /api/ctfd/push with CTFdAuthError shows auth message."""
    from ctf_pcaps.integration.ctfd_client import CTFdAuthError

    mock_config.return_value = {"url": "https://ctfd.test", "token": "bad"}
    mock_history.return_value = [_MOCK_HISTORY_ENTRY]

    mock_instance = MagicMock()
    mock_instance.push_challenge.side_effect = CTFdAuthError("bad token")
    mock_client_cls.return_value = mock_instance

    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        (tmp_path / "test_scan.pcap").write_bytes(b"fake pcap")

        response = client.post(
            "/api/ctfd/push",
            data={
                "filename": "test_scan.pcap",
                "name": "Test",
                "description": "Test",
                "category": "Network Attack",
                "value": "250",
                "state": "hidden",
            },
        )

    assert response.status_code == 200
    assert b"invalid or expired" in response.data


@patch("ctf_pcaps.web.routes.CTFdClient")
@patch("ctf_pcaps.web.routes.load_history")
@patch("ctf_pcaps.web.routes.load_ctfd_config")
def test_push_api_connection_error(
    mock_config, mock_history, mock_client_cls, client, tmp_path
):
    """POST /api/ctfd/push with CTFdConnectionError shows unreachable."""
    from ctf_pcaps.integration.ctfd_client import CTFdConnectionError

    mock_config.return_value = {"url": "https://ctfd.test", "token": "tok"}
    mock_history.return_value = [_MOCK_HISTORY_ENTRY]

    mock_instance = MagicMock()
    mock_instance.push_challenge.side_effect = CTFdConnectionError("timeout")
    mock_client_cls.return_value = mock_instance

    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        (tmp_path / "test_scan.pcap").write_bytes(b"fake pcap")

        response = client.post(
            "/api/ctfd/push",
            data={
                "filename": "test_scan.pcap",
                "name": "Test",
                "description": "Test",
                "category": "Network Attack",
                "value": "250",
                "state": "hidden",
            },
        )

    assert response.status_code == 200
    assert b"Cannot reach" in response.data


@patch("ctf_pcaps.web.routes.load_ctfd_config")
def test_push_api_file_missing(mock_config, client, tmp_path):
    """POST /api/ctfd/push with nonexistent file shows 'no longer available'."""
    mock_config.return_value = {"url": "https://ctfd.test", "token": "tok"}

    with patch("ctf_pcaps.web.routes.get_config") as mock_get_config:
        mock_cfg = MagicMock()
        mock_cfg.OUTPUT_DIR = str(tmp_path)
        mock_get_config.return_value = mock_cfg
        # Do NOT create the file

        response = client.post(
            "/api/ctfd/push",
            data={
                "filename": "nonexistent.pcap",
                "name": "Test",
                "description": "Test",
                "category": "Test",
                "value": "100",
                "state": "hidden",
            },
        )

    assert response.status_code == 200
    assert b"no longer available" in response.data
