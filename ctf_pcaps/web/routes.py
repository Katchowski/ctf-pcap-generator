"""Blueprint with main routes for the CTF PCAP Generator."""

import queue
import threading
from datetime import UTC, datetime
from pathlib import Path

import structlog
from flask import (
    Blueprint,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    stream_with_context,
    url_for,
)
from flask import (
    Response as FlaskResponse,
)
from werkzeug.utils import secure_filename

from ctf_pcaps.config import get_config
from ctf_pcaps.engine.difficulty import _PRESETS
from ctf_pcaps.engine.loader import load_template, validate_template
from ctf_pcaps.engine.models import GenerationResult, ScenarioTemplate
from ctf_pcaps.engine.pipeline import generate as engine_generate
from ctf_pcaps.integration.ctfd_client import (
    CTFdAuthError,
    CTFdClient,
    CTFdConnectionError,
    CTFdDuplicateError,
    CTFdError,
)
from ctf_pcaps.integration.persistence import (
    load_ctfd_config,
    load_history,
    save_ctfd_config,
    save_history_entry,
    update_history_push_status,
)

logger = structlog.get_logger()

bp = Blueprint("main", __name__)

CATEGORY_LABELS = {
    "network_attack": "Network Attack",
    "web_traffic": "Web Traffic",
    "covert_channel": "Covert Channel",
    "malware_c2": "Malware / C2",
}

_scenario_cache: list[dict] | None = None


def discover_scenarios(scenarios_dir: Path) -> list[dict]:
    """Scan scenario YAML files and return metadata for each valid template.

    Results are cached in a module-level variable after the first call.

    Args:
        scenarios_dir: Path to the directory containing YAML scenario files.

    Returns:
        List of dicts with keys: slug, name, description, category,
        category_label, difficulty_hint, parameters, path.
    """
    global _scenario_cache
    if _scenario_cache is not None:
        return _scenario_cache

    scenarios = []
    for yaml_path in sorted(scenarios_dir.glob("*.yaml")):
        try:
            raw_data = load_template(yaml_path)
            result = validate_template(raw_data)
        except Exception:
            logger.warning(
                "scenario_load_failed",
                path=str(yaml_path),
            )
            continue

        if not isinstance(result, ScenarioTemplate):
            logger.warning(
                "scenario_validation_failed",
                path=str(yaml_path),
                errors=result,
            )
            continue

        metadata = result.metadata
        category = metadata.category.value if metadata and metadata.category else None
        difficulty = (
            metadata.difficulty_hint.value
            if metadata and metadata.difficulty_hint
            else None
        )
        category_label = (
            CATEGORY_LABELS.get(category, "Unknown") if category else "Unknown"
        )

        parameters = {}
        for param_name, param_def in result.parameters.items():
            parameters[param_name] = {
                "default": param_def.default,
                "min": param_def.min,
                "max": param_def.max,
                "choices": param_def.choices,
                "description": param_def.description,
            }

        scenarios.append(
            {
                "slug": yaml_path.stem,
                "name": metadata.name if metadata and metadata.name else yaml_path.stem,
                "description": (
                    metadata.description if metadata and metadata.description else ""
                ),
                "category": category,
                "category_label": category_label,
                "difficulty_hint": difficulty,
                "parameters": parameters,
                "path": str(yaml_path),
            }
        )

    _scenario_cache = scenarios
    logger.info("scenarios_discovered", count=len(scenarios))
    return scenarios


def _get_scenarios_dir() -> Path:
    """Return the path to the scenarios directory."""
    return Path(__file__).parent.parent.parent / "scenarios"


def _coerce_form_params(form_data: dict, scenario_params: dict) -> dict | None:
    """Coerce form string values to types matching scenario parameter defaults.

    Args:
        form_data: Dict of form field names to string values.
        scenario_params: Dict of param name to param definition dict
            (with 'default', 'min', 'max', etc.).

    Returns:
        Dict of coerced overrides, or None if no overrides found.
    """
    overrides: dict = {}
    for name, param_def in scenario_params.items():
        value = form_data.get(f"param_{name}")
        if value is None or value == "":
            continue

        default = param_def["default"]
        try:
            if isinstance(default, bool):
                overrides[name] = value.lower() in ("true", "1", "on", "yes")
            elif isinstance(default, int):
                overrides[name] = int(value)
            elif isinstance(default, float):
                overrides[name] = float(value)
            elif isinstance(default, list):
                items = [item.strip() for item in value.split(",")]
                if all(item.isdigit() for item in items if item):
                    items = [int(item) for item in items if item]
                overrides[name] = items
            else:
                overrides[name] = value
        except (ValueError, TypeError):
            # Skip invalid values; server validation will catch them
            continue

    return overrides if overrides else None


def _format_sse(event_name: str, html: str) -> str:
    """Format an SSE event with multi-line HTML data.

    SSE data lines cannot contain raw newlines. Each line of the
    HTML must be prefixed with 'data: '.

    Args:
        event_name: The SSE event name.
        html: The HTML content to send.

    Returns:
        Formatted SSE event string.
    """
    lines = html.split("\n")
    data_lines = "\n".join(f"data: {line}" for line in lines)
    return f"event: {event_name}\n{data_lines}\n\n"


@bp.route("/")
def index():
    """Redirect to the scenario browser."""
    return redirect(url_for("main.scenarios"))


@bp.route("/scenarios")
def scenarios():
    """Scenario browser page showing all available templates as cards."""
    scenarios_dir = _get_scenarios_dir()
    scenario_list = discover_scenarios(scenarios_dir)
    return render_template(
        "scenarios/browser.html",
        scenarios=scenario_list,
        categories=CATEGORY_LABELS,
    )


@bp.route("/scenarios/cards")
def scenario_cards():
    """HTMX partial: return filtered scenario card grid."""
    category = request.args.get("category")
    scenarios_dir = _get_scenarios_dir()
    scenario_list = discover_scenarios(scenarios_dir)

    if category:
        scenario_list = [s for s in scenario_list if s["category"] == category]

    return render_template("scenarios/_card_grid.html", scenarios=scenario_list)


@bp.route("/health")
def health():
    """Health check endpoint for Docker HEALTHCHECK."""
    scapy_available = _check_scapy()
    return jsonify({"status": "ok", "scapy": scapy_available})


def _check_scapy():
    """Verify Scapy is importable and functional.

    Returns:
        True if Scapy can be imported, False otherwise.
    """
    try:
        from scapy.all import IP, wrpcap  # noqa: F401

        return True
    except ImportError:
        return False


@bp.route("/generate/<scenario>")
def generate_form(scenario):
    """Render the PCAP generation form for a specific scenario.

    Args:
        scenario: The scenario slug from the URL.
    """
    scenarios_dir = _get_scenarios_dir()
    scenario_list = discover_scenarios(scenarios_dir)
    scenario_dict = next((s for s in scenario_list if s["slug"] == scenario), None)
    if scenario_dict is None:
        abort(404)
    return render_template(
        "generate/form.html",
        scenario=scenario_dict,
        presets=list(_PRESETS.keys()),
    )


@bp.route("/api/difficulty/<preset>")
def difficulty_info(preset):
    """Return an HTMX partial with difficulty preset information.

    Args:
        preset: The difficulty preset name (easy, medium, hard).
    """
    if preset not in _PRESETS:
        return "", 204
    preset_obj = _PRESETS[preset]
    return render_template("generate/_difficulty_info.html", preset=preset_obj)


@bp.route("/generate/<scenario>/stream")
def generate_stream(scenario):
    """SSE endpoint that runs PCAP generation and streams progress events.

    Args:
        scenario: The scenario slug from the URL.
    """
    scenarios_dir = _get_scenarios_dir()
    scenario_list = discover_scenarios(scenarios_dir)
    scenario_dict = next((s for s in scenario_list if s["slug"] == scenario), None)
    if scenario_dict is None:
        error_html = render_template(
            "generate/_error.html",
            error_message=f"Scenario '{scenario}' not found.",
            errors=None,
            scenario_slug=scenario,
        )
        return FlaskResponse(
            _format_sse("complete", error_html),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    # Parse flag params
    _SKIP_FLAG = object()
    if "flag_text" in request.args:
        raw_flag = request.args.get("flag_text", "")
        flag_text = None if raw_flag == "" else raw_flag
    else:
        flag_text = _SKIP_FLAG

    flag_format = request.args.get("flag_format", "flag")
    difficulty = request.args.get("difficulty") or None

    # Parse scenario parameter overrides
    overrides = _coerce_form_params(dict(request.args), scenario_dict["parameters"])

    progress_queue: queue.Queue = queue.Queue()

    def progress_callback(current):
        pct = min(int((current / 1000) * 90), 95)
        progress_queue.put(("progress", pct))

    def run_generation():
        try:
            kwargs = {
                "template_path": scenario_dict["path"],
                "overrides": overrides,
                "callback": progress_callback,
                "flag_format": flag_format,
                "difficulty": difficulty,
            }
            if flag_text is not _SKIP_FLAG:
                kwargs["flag_text"] = flag_text

            result = engine_generate(**kwargs)

            if isinstance(result, GenerationResult):
                progress_queue.put(("result", result))
            elif isinstance(result, list):
                progress_queue.put(("field_errors", result))
            else:
                progress_queue.put(("error", "Unexpected result type"))
        except Exception as e:
            logger.exception("generation_error", error=str(e))
            progress_queue.put(("error", str(e)))

    thread = threading.Thread(target=run_generation, daemon=True)
    thread.start()

    def event_stream():
        while True:
            try:
                event_type, data = progress_queue.get(timeout=120)
            except queue.Empty:
                error_html = render_template(
                    "generate/_error.html",
                    error_message="Generation timed out.",
                    errors=None,
                    scenario_slug=scenario,
                )
                yield _format_sse("complete", error_html)
                break

            if event_type == "progress":
                pct = data
                progress_html = render_template("generate/_progress.html", pct=pct)
                yield _format_sse("progress", progress_html)

            elif event_type == "result":
                result = data
                # Build template-friendly result dict
                size_bytes = result.file_size_bytes
                if size_bytes < 1024 * 1024:
                    file_size_display = f"{size_bytes / 1024:.1f} KB"
                else:
                    file_size_display = f"{size_bytes / (1024 * 1024):.1f} MB"
                duration_display = f"{result.generation_duration_ms / 1000:.2f}s"
                result_dict = {
                    "packet_count": result.packet_count,
                    "file_size_bytes": result.file_size_bytes,
                    "file_size_display": file_size_display,
                    "generation_duration_ms": result.generation_duration_ms,
                    "duration_display": duration_display,
                    "difficulty_preset": result.difficulty_preset,
                    "flag_verified": result.flag_verified,
                    "flag_text": result.flag_text,
                    "solve_steps": result.solve_steps,
                    "filename": result.file_path.name,
                }

                # Record generation in history for push page
                try:
                    history_entry = {
                        "filename": result.file_path.name,
                        "scenario_slug": scenario,
                        "scenario_name": scenario_dict["name"],
                        "scenario_description": scenario_dict["description"],
                        "category": scenario_dict["category"],
                        "category_label": scenario_dict["category_label"],
                        "flag_text": result.flag_text,
                        "difficulty": result.difficulty_preset,
                        "timestamp": datetime.now(UTC).isoformat(),
                        "file_size_bytes": result.file_size_bytes,
                        "pushed": False,
                        "push_challenge_id": None,
                        "push_challenge_name": None,
                        "push_timestamp": None,
                    }
                    save_history_entry(
                        Path(get_config().OUTPUT_DIR),
                        history_entry,
                    )
                except Exception:
                    logger.exception("history_save_error")

                result_html = render_template(
                    "generate/_result.html", result=result_dict
                )
                yield _format_sse("complete", result_html)
                break

            elif event_type == "field_errors":
                errors = data
                error_html = render_template(
                    "generate/_error.html",
                    error_message=None,
                    errors=errors,
                    scenario_slug=scenario,
                )
                yield _format_sse("complete", error_html)
                break

            elif event_type == "error":
                error_html = render_template(
                    "generate/_error.html",
                    error_message=str(data),
                    errors=None,
                    scenario_slug=scenario,
                )
                yield _format_sse("complete", error_html)
                break

    return FlaskResponse(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@bp.route("/download/<filename>")
def download_file(filename):
    """Serve a generated PCAP file for download.

    Args:
        filename: The PCAP filename to download.
    """
    from flask import send_from_directory

    safe_name = secure_filename(filename)
    if not safe_name or not safe_name.endswith(".pcap"):
        abort(404)
    config = get_config()
    return send_from_directory(
        config.OUTPUT_DIR,
        safe_name,
        as_attachment=True,
        mimetype="application/vnd.tcpdump.pcap",
    )


DIFFICULTY_POINTS = {
    "easy": 100,
    "medium": 250,
    "hard": 500,
}


@bp.route("/settings")
def settings():
    """Render the CTFd settings page.

    Loads existing CTFd configuration and pre-fills the form.
    Supports a ?next= query parameter for redirect-after-save.
    """
    config = get_config()
    ctfd_config = load_ctfd_config(Path(config.OUTPUT_DIR))
    next_url = request.args.get("next")
    return render_template(
        "settings/settings.html",
        config=ctfd_config,
        next_url=next_url,
    )


@bp.route("/api/ctfd/settings", methods=["POST"])
def save_settings():
    """Save CTFd settings and test connection (HTMX endpoint).

    Reads ctfd_url and ctfd_token from form data. Saves the
    configuration, then tests the connection to CTFd. Returns
    an HTMX partial with the connection status.
    """
    ctfd_url = request.form.get("ctfd_url", "").strip()
    ctfd_token = request.form.get("ctfd_token", "").strip()

    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)
    save_ctfd_config(output_dir, ctfd_url, ctfd_token)

    try:
        client = CTFdClient(ctfd_url, ctfd_token)
        client.test_connection()
        return render_template(
            "settings/_connection_status.html",
            success=True,
            error=None,
        )
    except CTFdAuthError:
        return render_template(
            "settings/_connection_status.html",
            success=False,
            error="API token is invalid or expired. Check your token in Settings.",
        )
    except CTFdConnectionError:
        return render_template(
            "settings/_connection_status.html",
            success=False,
            error=f"Cannot reach CTFd at {ctfd_url}."
            " Check the URL is correct and the server is running.",
        )
    except Exception as exc:
        logger.exception("ctfd_settings_test_error", error=str(exc))
        return render_template(
            "settings/_connection_status.html",
            success=False,
            error=f"Connection test failed: {exc}",
        )


@bp.route("/push")
def push_list():
    """Render the push page with generation history listing.

    Shows all generated PCAPs with their push status. Checks
    if each PCAP file still exists on disk.
    """
    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)
    history = load_history(output_dir)

    # Annotate each entry with file existence
    for entry in history:
        file_path = output_dir / entry.get("filename", "")
        entry["file_exists"] = file_path.exists()

    # Show newest first
    history.reverse()

    return render_template("push/push.html", history=history)


@bp.route("/push/<filename>")
def push_form(filename):
    """Render the push form for a specific PCAP file.

    Pre-populates challenge metadata from generation history.
    Redirects to /settings if CTFd is not configured.

    Args:
        filename: The PCAP filename from generation history.
    """
    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)
    history = load_history(output_dir)

    entry = next((e for e in history if e.get("filename") == filename), None)
    if entry is None:
        abort(404)

    ctfd_config = load_ctfd_config(output_dir)
    if not ctfd_config.get("url") or not ctfd_config.get("token"):
        return redirect(f"/settings?next=/push/{filename}")

    difficulty = entry.get("difficulty") or ""
    default_points = DIFFICULTY_POINTS.get(difficulty.lower(), 100)

    file_path = output_dir / filename
    entry["file_exists"] = file_path.exists()

    return render_template(
        "push/push_form.html",
        entry=entry,
        config=ctfd_config,
        default_points=default_points,
    )


@bp.route("/api/ctfd/push", methods=["POST"])
def push_challenge():
    """Push a challenge to CTFd (HTMX endpoint).

    Reads challenge metadata from form data, loads the PCAP file,
    and pushes to CTFd via the CTFdClient. Returns an HTMX partial
    with the result or error.
    """
    filename = request.form.get("filename", "").strip()
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    category = request.form.get("category", "").strip()
    value = int(request.form.get("value", "100"))
    state = request.form.get("state", "hidden").strip()

    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)

    # Verify PCAP file exists
    file_path = output_dir / filename
    if not file_path.exists():
        return render_template(
            "push/_push_result.html",
            success=False,
            error="PCAP file no longer available. Generate a new one.",
        )

    # Load CTFd config
    ctfd_config = load_ctfd_config(output_dir)
    if not ctfd_config.get("url") or not ctfd_config.get("token"):
        return render_template(
            "push/_push_result.html",
            success=False,
            error="CTFd is not configured. Go to Settings first.",
        )

    # Load history to get flag_text
    history = load_history(output_dir)
    entry = next((e for e in history if e.get("filename") == filename), None)
    flag_text = entry.get("flag_text", "") if entry else ""

    try:
        client = CTFdClient(ctfd_config["url"], ctfd_config["token"])
        result = client.push_challenge(
            name=name,
            description=description,
            category=category,
            value=value,
            state=state,
            file_path=file_path,
            flag_content=flag_text,
        )

        # Update history push status
        update_history_push_status(
            output_dir,
            filename=filename,
            challenge_id=result["challenge_id"],
            challenge_name=name,
        )

        return render_template(
            "push/_push_result.html",
            success=True,
            admin_url=result["admin_url"],
            challenge_name=name,
            error=None,
        )
    except CTFdAuthError:
        return render_template(
            "push/_push_result.html",
            success=False,
            error="API token is invalid or expired."
            " Check your token in <a href='/settings'>Settings</a>.",
        )
    except CTFdConnectionError:
        url = ctfd_config["url"]
        return render_template(
            "push/_push_result.html",
            success=False,
            error=f"Cannot reach CTFd at {url}."
            " Check the URL is correct and the server is running.",
        )
    except CTFdDuplicateError:
        return render_template(
            "push/_push_result.html",
            success=False,
            error=f"A challenge named '{name}' already exists."
            " Change the name or delete the existing one.",
        )
    except CTFdError as exc:
        return render_template(
            "push/_push_result.html",
            success=False,
            error=str(exc),
        )
    except Exception as exc:
        logger.exception("push_unexpected_error", error=str(exc))
        return render_template(
            "push/_push_result.html",
            success=False,
            error=f"Unexpected error: {exc}",
        )


@bp.app_errorhandler(404)
def page_not_found(e):
    """Render custom 404 error page."""
    return render_template("errors/404.html"), 404


@bp.app_errorhandler(500)
def internal_server_error(e):
    """Render custom 500 error page."""
    return render_template("errors/500.html"), 500
