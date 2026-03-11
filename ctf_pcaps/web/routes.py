"""Blueprint with main routes for the CTF PCAP Generator."""

import queue
import secrets
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
from ctf_pcaps.engine.export import build_challenge_yml, create_export_bundle
from ctf_pcaps.engine.hints import DEFAULT_POINTS as HINT_DEFAULT_POINTS
from ctf_pcaps.engine.hints import generate_hints
from ctf_pcaps.engine.loader import load_template, validate_template
from ctf_pcaps.engine.models import GenerationResult, ScenarioTemplate
from ctf_pcaps.engine.pipeline import generate as engine_generate
from ctf_pcaps.engine.preview import analyze_pcap, get_flag_status
from ctf_pcaps.engine.writeup import generate_writeup
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
    load_history_by_batch,
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
    "post_exploitation": "Post-Exploitation",
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

    # Parse split_count (only used when no difficulty preset)
    raw_split = request.args.get("split_count")
    split_count = int(raw_split) if raw_split and raw_split.isdigit() else 1

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
                "split_count": split_count,
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

                # Generate writeup files alongside PCAP
                try:
                    author_md, player_md = generate_writeup(
                        result=result,
                        scenario_name=scenario_dict["name"],
                        scenario_description=scenario_dict["description"],
                        scenario_slug=scenario,
                        difficulty=difficulty,
                    )
                    stem = result.file_path.stem
                    author_path = result.file_path.parent / f"{stem}_writeup.md"
                    player_path = result.file_path.parent / f"{stem}_player.md"
                    author_path.write_text(author_md, encoding="utf-8")
                    player_path.write_text(player_md, encoding="utf-8")
                except Exception:
                    logger.exception("writeup_generation_error")
                    author_path = None
                    player_path = None

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
                    "split_count": result.split_count,
                    "split_active": result.split_active,
                    "writeup_filename": (author_path.name if author_path else None),
                    "player_filename": (player_path.name if player_path else None),
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
                        "writeup_filename": (author_path.name if author_path else None),
                        "player_filename": (player_path.name if player_path else None),
                        "encoding_chain": result.encoding_chain,
                        "split_active": result.split_active,
                        "split_count": result.split_count,
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


@bp.route("/download/writeup/<filename>")
def download_writeup(filename):
    """Serve a generated writeup file for download.

    Args:
        filename: The writeup .md filename to download.
    """
    from flask import send_from_directory

    safe_name = secure_filename(filename)
    if not safe_name or not safe_name.endswith(".md"):
        abort(404)
    config = get_config()
    file_path = Path(config.OUTPUT_DIR) / safe_name
    if not file_path.exists():
        abort(404)
    return send_from_directory(
        config.OUTPUT_DIR,
        safe_name,
        as_attachment=True,
        mimetype="text/markdown",
    )


@bp.route("/download/player/<filename>")
def download_player(filename):
    """Serve a generated player writeup file for download.

    Args:
        filename: The player writeup .md filename to download.
    """
    from flask import send_from_directory

    safe_name = secure_filename(filename)
    if not safe_name or not safe_name.endswith(".md"):
        abort(404)
    config = get_config()
    file_path = Path(config.OUTPUT_DIR) / safe_name
    if not file_path.exists():
        abort(404)
    return send_from_directory(
        config.OUTPUT_DIR,
        safe_name,
        as_attachment=True,
        mimetype="text/markdown",
    )


MAX_PREVIEW_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB


@bp.route("/api/preview/<filename>")
def preview_pcap(filename):
    """Return an HTMX partial with PCAP analysis preview.

    Analyzes the PCAP file using Scapy and returns an HTML fragment
    with protocol breakdown, top conversations, timeline, and flag status.

    Args:
        filename: The PCAP filename to preview.
    """
    safe_name = secure_filename(filename)
    if not safe_name or not safe_name.endswith(".pcap"):
        abort(404)

    config = get_config()
    file_path = Path(config.OUTPUT_DIR) / safe_name
    if not file_path.exists():
        abort(404)

    # Check file size before loading
    if file_path.stat().st_size > MAX_PREVIEW_SIZE_BYTES:
        return "<div class='alert alert-warning'>File too large for preview.</div>"

    analysis = analyze_pcap(str(file_path))

    # Look up history entry for flag status
    output_dir = Path(config.OUTPUT_DIR)
    history = load_history(output_dir)
    entry = next((e for e in history if e.get("filename") == safe_name), None)
    flag_status = get_flag_status(entry) if entry else get_flag_status({})

    return render_template(
        "generate/_preview.html",
        preview=analysis,
        flag_status=flag_status,
        filename=safe_name,
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

    # Generate hints for this challenge
    hints = generate_hints(
        builder_name=entry.get("scenario_slug", "") if entry else "",
        difficulty=entry.get("difficulty") if entry else None,
        encoding_chain=entry.get("encoding_chain", []),
        challenge_value=value,
    )

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
            hints=hints,
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


@bp.route("/export/<filename>")
def export_bundle(filename):
    """Generate and serve a ctfcli-compatible challenge ZIP bundle.

    Assembles challenge.yml + PCAP + writeup into a ZIP download.

    Args:
        filename: The PCAP filename from generation history.
    """
    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)

    # Validate PCAP exists
    safe_name = secure_filename(filename)
    if not safe_name or not safe_name.endswith(".pcap"):
        abort(404)
    pcap_path = output_dir / safe_name
    if not pcap_path.exists():
        abort(404)

    # Load history entry for metadata
    history = load_history(output_dir)
    entry = next((e for e in history if e.get("filename") == safe_name), None)
    if entry is None:
        abort(404)

    # Determine challenge metadata
    scenario_name = entry.get("scenario_name", entry.get("scenario_slug", "Challenge"))
    description = entry.get("scenario_description", "")
    category = entry.get("category", "misc")
    difficulty = entry.get("difficulty")
    value = HINT_DEFAULT_POINTS.get(difficulty, 100) if difficulty else 100
    flag_text = entry.get("flag_text", "")

    # Generate hints
    hints = generate_hints(
        builder_name=entry.get("scenario_slug", ""),
        difficulty=difficulty,
        encoding_chain=entry.get("encoding_chain", []),
        challenge_value=value,
    )

    # Build challenge.yml
    challenge_yml = build_challenge_yml(
        name=scenario_name,
        description=description,
        category=category,
        value=value,
        flag_text=flag_text,
        hints=hints,
        pcap_filename=safe_name,
    )

    # Read writeup if it exists, else generate a placeholder
    stem = pcap_path.stem
    writeup_path = output_dir / f"{stem}_writeup.md"
    if writeup_path.exists():
        writeup_md = writeup_path.read_text(encoding="utf-8")
    else:
        writeup_md = f"# {scenario_name}\n\nWriteup not available.\n"

    # Create ZIP bundle
    zip_buffer = create_export_bundle(challenge_yml, pcap_path, writeup_md)

    # Return ZIP as download
    bundle_name = f"{stem}_bundle.zip"
    return FlaskResponse(
        zip_buffer.getvalue(),
        mimetype="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={bundle_name}",
        },
    )


@bp.route("/batch")
def batch_form():
    """Render the batch generation form with scenario checkboxes."""
    scenarios_dir = _get_scenarios_dir()
    scenario_list = discover_scenarios(scenarios_dir)
    return render_template("batch/form.html", scenarios=scenario_list)


@bp.route("/batch/stream")
def batch_stream():
    """SSE endpoint that generates multiple PCAPs sequentially.

    Accepts repeated ``scenarios`` query params for selected slugs,
    shared ``flag_format`` and ``difficulty``, and per-scenario overrides
    prefixed with ``slug__paramname``.
    """
    selected_slugs = request.args.getlist("scenarios")

    if not selected_slugs:
        empty_html = render_template(
            "batch/_result.html",
            batch_id="",
            results=[],
            errors=[],
            completed=0,
            total=0,
        )
        return FlaskResponse(
            _format_sse("batch-complete", empty_html),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    flag_format = request.args.get("flag_format", "flag")
    difficulty = request.args.get("difficulty") or None
    batch_id = secrets.token_hex(8)

    scenarios_dir = _get_scenarios_dir()
    all_scenarios = discover_scenarios(scenarios_dir)
    scenario_map = {s["slug"]: s for s in all_scenarios}

    # Build list of selected scenarios with per-scenario overrides
    selected = []
    for slug in selected_slugs:
        sc = scenario_map.get(slug)
        if sc is None:
            continue
        # Parse per-scenario overrides: slug__paramname -> paramname
        prefix = f"{slug}__"
        override_data = {}
        for key, val in request.args.items():
            if key.startswith(prefix):
                param_name = key[len(prefix) :]
                override_data[f"param_{param_name}"] = val
        overrides = _coerce_form_params(override_data, sc["parameters"])
        selected.append({"scenario": sc, "overrides": overrides})

    total = len(selected)
    progress_queue: queue.Queue = queue.Queue()

    # Track status for all scenarios
    scenarios_status = []
    for i, item in enumerate(selected):
        scenarios_status.append(
            {
                "index": i,
                "slug": item["scenario"]["slug"],
                "name": item["scenario"]["name"],
                "status": "queued",
                "pct": 0,
                "result": None,
                "error": None,
            }
        )

    def run_batch():
        results_list = []
        errors_list = []
        for i, item in enumerate(selected):
            sc = item["scenario"]
            overrides = item["overrides"]
            progress_queue.put(
                (
                    "scenario-start",
                    {
                        "index": i,
                        "slug": sc["slug"],
                        "name": sc["name"],
                        "total": total,
                    },
                )
            )

            def make_callback(idx):
                def cb(current):
                    pct = min(int((current / 1000) * 90), 95)
                    progress_queue.put(
                        ("scenario-progress", {"index": idx, "pct": pct})
                    )

                return cb

            try:
                result = engine_generate(
                    template_path=sc["path"],
                    overrides=overrides,
                    callback=make_callback(i),
                    flag_format=flag_format,
                    difficulty=difficulty,
                    flag_text=None,  # Auto-generate unique flag per scenario
                )

                if isinstance(result, GenerationResult):
                    # Generate writeups
                    author_path = None
                    player_path = None
                    try:
                        author_md, player_md = generate_writeup(
                            result=result,
                            scenario_name=sc["name"],
                            scenario_description=sc["description"],
                            scenario_slug=sc["slug"],
                            difficulty=difficulty,
                        )
                        stem = result.file_path.stem
                        author_path = result.file_path.parent / f"{stem}_writeup.md"
                        player_path = result.file_path.parent / f"{stem}_player.md"
                        author_path.write_text(author_md, encoding="utf-8")
                        player_path.write_text(player_md, encoding="utf-8")
                    except Exception:
                        logger.exception("batch_writeup_error", slug=sc["slug"])

                    # Build display-friendly size
                    size_bytes = result.file_size_bytes
                    if size_bytes < 1024 * 1024:
                        file_size_display = f"{size_bytes / 1024:.1f} KB"
                    else:
                        file_size_display = f"{size_bytes / (1024 * 1024):.1f} MB"

                    result_dict = {
                        "scenario_name": sc["name"],
                        "scenario_slug": sc["slug"],
                        "filename": result.file_path.name,
                        "flag_text": result.flag_text,
                        "file_size_bytes": result.file_size_bytes,
                        "file_size_display": file_size_display,
                        "flag_verified": result.flag_verified,
                        "writeup_filename": (author_path.name if author_path else None),
                        "player_filename": (player_path.name if player_path else None),
                    }

                    # Save history entry with batch_id
                    try:
                        history_entry = {
                            "filename": result.file_path.name,
                            "scenario_slug": sc["slug"],
                            "scenario_name": sc["name"],
                            "scenario_description": sc["description"],
                            "category": sc["category"],
                            "category_label": sc["category_label"],
                            "flag_text": result.flag_text,
                            "difficulty": result.difficulty_preset,
                            "timestamp": datetime.now(UTC).isoformat(),
                            "file_size_bytes": result.file_size_bytes,
                            "pushed": False,
                            "push_challenge_id": None,
                            "push_challenge_name": None,
                            "push_timestamp": None,
                            "writeup_filename": (
                                author_path.name if author_path else None
                            ),
                            "player_filename": (
                                player_path.name if player_path else None
                            ),
                            "batch_id": batch_id,
                            "encoding_chain": result.encoding_chain,
                            "split_active": result.split_active,
                            "split_count": result.split_count,
                        }
                        save_history_entry(
                            Path(get_config().OUTPUT_DIR),
                            history_entry,
                        )
                    except Exception:
                        logger.exception("batch_history_save_error", slug=sc["slug"])

                    results_list.append(result_dict)
                    progress_queue.put(
                        ("scenario-done", {"index": i, "result": result_dict})
                    )
                elif isinstance(result, list):
                    error_msg = "; ".join(result)
                    errors_list.append(
                        {"index": i, "slug": sc["slug"], "error": error_msg}
                    )
                    progress_queue.put(
                        (
                            "scenario-error",
                            {
                                "index": i,
                                "slug": sc["slug"],
                                "error": error_msg,
                            },
                        )
                    )
                else:
                    errors_list.append(
                        {
                            "index": i,
                            "slug": sc["slug"],
                            "error": "Unexpected result type",
                        }
                    )
                    progress_queue.put(
                        (
                            "scenario-error",
                            {
                                "index": i,
                                "slug": sc["slug"],
                                "error": "Unexpected result type",
                            },
                        )
                    )
            except Exception as e:
                logger.exception(
                    "batch_generation_error", slug=sc["slug"], error=str(e)
                )
                errors_list.append({"index": i, "slug": sc["slug"], "error": str(e)})
                progress_queue.put(
                    (
                        "scenario-error",
                        {"index": i, "slug": sc["slug"], "error": str(e)},
                    )
                )

        progress_queue.put(
            (
                "batch-complete",
                {
                    "batch_id": batch_id,
                    "results": results_list,
                    "errors": errors_list,
                },
            )
        )

    thread = threading.Thread(target=run_batch, daemon=True)
    thread.start()

    def event_stream():
        while True:
            try:
                event_type, data = progress_queue.get(timeout=600)
            except queue.Empty:
                timeout_html = render_template(
                    "batch/_result.html",
                    batch_id=batch_id,
                    results=[],
                    errors=[{"index": 0, "slug": "", "error": "Timed out"}],
                    completed=0,
                    total=total,
                )
                yield _format_sse("batch-complete", timeout_html)
                break

            if event_type == "scenario-start":
                idx = data["index"]
                scenarios_status[idx]["status"] = "generating"
                scenarios_status[idx]["pct"] = 0
                completed = sum(
                    1 for s in scenarios_status if s["status"] in ("done", "error")
                )
                html = render_template(
                    "batch/_progress.html",
                    scenarios_status=scenarios_status,
                    completed=completed,
                    total=total,
                )
                yield _format_sse("batch-progress", html)

            elif event_type == "scenario-progress":
                idx = data["index"]
                scenarios_status[idx]["pct"] = data["pct"]
                completed = sum(
                    1 for s in scenarios_status if s["status"] in ("done", "error")
                )
                html = render_template(
                    "batch/_progress.html",
                    scenarios_status=scenarios_status,
                    completed=completed,
                    total=total,
                )
                yield _format_sse("batch-progress", html)

            elif event_type == "scenario-done":
                idx = data["index"]
                scenarios_status[idx]["status"] = "done"
                scenarios_status[idx]["pct"] = 100
                scenarios_status[idx]["result"] = data["result"]
                completed = sum(
                    1 for s in scenarios_status if s["status"] in ("done", "error")
                )
                html = render_template(
                    "batch/_progress.html",
                    scenarios_status=scenarios_status,
                    completed=completed,
                    total=total,
                )
                yield _format_sse("batch-progress", html)

            elif event_type == "scenario-error":
                idx = data["index"]
                scenarios_status[idx]["status"] = "error"
                scenarios_status[idx]["error"] = data["error"]
                completed = sum(
                    1 for s in scenarios_status if s["status"] in ("done", "error")
                )
                html = render_template(
                    "batch/_progress.html",
                    scenarios_status=scenarios_status,
                    completed=completed,
                    total=total,
                )
                yield _format_sse("batch-progress", html)

            elif event_type == "batch-complete":
                results = data["results"]
                errors = data["errors"]
                html = render_template(
                    "batch/_result.html",
                    batch_id=data["batch_id"],
                    results=results,
                    errors=errors,
                    completed=len(results),
                    total=total,
                )
                yield _format_sse("batch-complete", html)
                break

    return FlaskResponse(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@bp.route("/batch/download/<batch_id>")
def batch_download(batch_id):
    """Download all PCAPs and writeups from a batch as a single ZIP file.

    Collects all history entries for the batch, filters to those with
    existing files, and returns a ZIP archive with flat structure.

    Args:
        batch_id: The batch identifier from batch generation.
    """
    import io
    import zipfile

    from flask import send_file

    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)

    entries = load_history_by_batch(output_dir, batch_id)
    if not entries:
        abort(404)

    # Filter to entries where the PCAP file still exists on disk
    valid_entries = []
    for entry in entries:
        pcap_path = output_dir / entry.get("filename", "")
        if pcap_path.exists():
            valid_entries.append(entry)

    if not valid_entries:
        abort(404)

    # Build ZIP in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in valid_entries:
            filename = entry["filename"]
            pcap_path = output_dir / filename
            zf.write(pcap_path, filename)

            # Add writeup if exists
            stem = Path(filename).stem
            writeup_path = output_dir / f"{stem}_writeup.md"
            if writeup_path.exists():
                zf.write(writeup_path, f"{stem}_writeup.md")

            # Add player writeup if exists
            player_path = output_dir / f"{stem}_player.md"
            if player_path.exists():
                zf.write(player_path, f"{stem}_player.md")

        # Build flags.txt manifest (answer key for organizers)
        flag_lines = []
        for entry in valid_entries:
            flag_text = entry.get("flag_text")
            if flag_text:
                scenario_name = entry.get(
                    "scenario_name", entry.get("scenario_slug", "unknown")
                )
                flag_lines.append(f"{scenario_name}: {flag_text}")

        if flag_lines:
            flags_content = "\n".join(flag_lines) + "\n"
            zf.writestr("flags.txt", flags_content.encode("utf-8"))

    buf.seek(0)

    zip_filename = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_filename,
    )


@bp.route("/batch/push/<batch_id>/stream")
def batch_push_stream(batch_id):
    """SSE endpoint that pushes all batch challenges to CTFd sequentially.

    For each unpushed entry in the batch, pushes to CTFd with per-challenge
    progress updates. Errors on individual challenges are skipped and
    remaining challenges continue.

    Args:
        batch_id: The batch identifier from batch generation.
    """
    config = get_config()
    output_dir = Path(config.OUTPUT_DIR)

    entries = load_history_by_batch(output_dir, batch_id)
    # Filter to entries where file exists AND not already pushed
    pushable = [
        e
        for e in entries
        if (output_dir / e.get("filename", "")).exists() and not e.get("pushed")
    ]

    # Load CTFd config
    ctfd_config = load_ctfd_config(output_dir)
    if not ctfd_config.get("url") or not ctfd_config.get("token"):
        error_html = (
            '<div class="alert alert-danger">'
            "CTFd is not configured. "
            '<a href="/settings">Go to Settings</a> first.'
            "</div>"
        )
        return FlaskResponse(
            _format_sse("push-complete", error_html),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    if not pushable:
        empty_html = (
            '<div class="alert alert-info">'
            "No challenges to push. All may have been pushed already."
            "</div>"
        )
        return FlaskResponse(
            _format_sse("push-complete", empty_html),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    total = len(pushable)
    progress_queue: queue.Queue = queue.Queue()

    # Initialize push status list for template rendering
    push_status = []
    for i, entry in enumerate(pushable):
        push_status.append(
            {
                "index": i,
                "name": entry.get("scenario_name", entry.get("scenario_slug", "")),
                "status": "queued",
                "error": None,
                "challenge_id": None,
            }
        )

    def run_push():
        client = CTFdClient(ctfd_config["url"], ctfd_config["token"])
        pushed_count = 0
        error_count = 0

        for i, entry in enumerate(pushable):
            name = entry.get("scenario_name", entry.get("scenario_slug", ""))
            progress_queue.put(
                ("push-start", {"index": i, "name": name, "total": total})
            )

            try:
                slug = entry.get("scenario_slug", "")
                difficulty = entry.get("difficulty")
                hints = generate_hints(
                    builder_name=slug,
                    difficulty=difficulty,
                    encoding_chain=entry.get("encoding_chain", []),
                    challenge_value=DIFFICULTY_POINTS.get(
                        difficulty.lower() if difficulty else "", 100
                    ),
                )
                points = DIFFICULTY_POINTS.get(
                    difficulty.lower() if difficulty else "", 100
                )

                pcap_path = output_dir / entry["filename"]
                result = client.push_challenge(
                    name=name,
                    description=entry.get("scenario_description", ""),
                    category=entry.get("category_label", "Misc"),
                    value=points,
                    state="hidden",
                    file_path=pcap_path,
                    flag_content=entry.get("flag_text", ""),
                    hints=hints,
                )

                update_history_push_status(
                    output_dir,
                    filename=entry["filename"],
                    challenge_id=result["challenge_id"],
                    challenge_name=name,
                )
                pushed_count += 1
                progress_queue.put(
                    (
                        "push-done",
                        {
                            "index": i,
                            "name": name,
                            "challenge_id": result["challenge_id"],
                        },
                    )
                )
            except Exception as exc:
                logger.exception(
                    "batch_push_error",
                    slug=entry.get("scenario_slug"),
                    error=str(exc),
                )
                error_count += 1
                progress_queue.put(
                    ("push-error", {"index": i, "name": name, "error": str(exc)})
                )

        progress_queue.put(
            (
                "push-complete",
                {
                    "pushed_count": pushed_count,
                    "error_count": error_count,
                    "total": total,
                },
            )
        )

    thread = threading.Thread(target=run_push, daemon=True)
    thread.start()

    def event_stream():
        while True:
            try:
                event_type, data = progress_queue.get(timeout=600)
            except queue.Empty:
                timeout_html = (
                    '<div class="alert alert-warning">Push operation timed out.</div>'
                )
                yield _format_sse("push-complete", timeout_html)
                break

            if event_type == "push-start":
                idx = data["index"]
                push_status[idx]["status"] = "pushing"
                html = render_template(
                    "batch/_push_progress.html",
                    push_status=push_status,
                    pushed=sum(
                        1 for s in push_status if s["status"] in ("done", "error")
                    ),
                    total=total,
                )
                yield _format_sse("push-progress", html)

            elif event_type == "push-done":
                idx = data["index"]
                push_status[idx]["status"] = "done"
                push_status[idx]["challenge_id"] = data["challenge_id"]
                html = render_template(
                    "batch/_push_progress.html",
                    push_status=push_status,
                    pushed=sum(
                        1 for s in push_status if s["status"] in ("done", "error")
                    ),
                    total=total,
                )
                yield _format_sse("push-progress", html)

            elif event_type == "push-error":
                idx = data["index"]
                push_status[idx]["status"] = "error"
                push_status[idx]["error"] = data["error"]
                html = render_template(
                    "batch/_push_progress.html",
                    push_status=push_status,
                    pushed=sum(
                        1 for s in push_status if s["status"] in ("done", "error")
                    ),
                    total=total,
                )
                yield _format_sse("push-progress", html)

            elif event_type == "push-complete":
                summary_html = render_template(
                    "batch/_push_progress.html",
                    push_status=push_status,
                    pushed=data["pushed_count"],
                    total=data["total"],
                    complete=True,
                    pushed_count=data["pushed_count"],
                    error_count=data["error_count"],
                )
                yield _format_sse("push-complete", summary_html)
                break

    return FlaskResponse(
        stream_with_context(event_stream()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@bp.app_errorhandler(404)
def page_not_found(e):
    """Render custom 404 error page."""
    return render_template("errors/404.html"), 404


@bp.app_errorhandler(500)
def internal_server_error(e):
    """Render custom 500 error page."""
    return render_template("errors/500.html"), 500
