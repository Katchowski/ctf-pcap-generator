"""Pipeline orchestrator: load -> validate -> resolve -> build -> write -> cleanup.

Wires together all engine components into a single generate() call
that takes a YAML template path and produces a PCAP file. Supports
optional flag embedding with encoding, verification, and stealth checks.
Applies realism features: Ethernet wrapping, noise injection, and
timestamp jitter on all generated PCAPs.

No Flask imports allowed in engine modules.
"""

import os
import random
import secrets
import time
from collections.abc import Callable
from pathlib import Path

import structlog
from scapy.layers.inet import IP

import ctf_pcaps.engine.builders  # noqa: F401  # triggers auto-discovery
from ctf_pcaps.config import get_config
from ctf_pcaps.engine.cleanup import sweep_stale_files
from ctf_pcaps.engine.difficulty import (
    CustomDifficultyParams,
    resolve_custom_difficulty,
    resolve_difficulty,
)
from ctf_pcaps.engine.flag import (
    ENCODERS,
    _build_solve_steps_chain,
    assemble_flag,
    build_flag_packet,
    build_flag_payload,
    decode_flag_chain,
    embed_flag_packet,
    embed_split_flag_packets,
    encode_flag_chain,
    extract_addresses,
    split_encoded_string,
    verify_flag_in_pcap,
    verify_split_flag_in_pcap,
    verify_stealth,
)
from ctf_pcaps.engine.loader import (
    load_template,
    resolve_variables,
    validate_parameters,
    validate_template,
)
from ctf_pcaps.engine.models import GenerationResult
from ctf_pcaps.engine.protocols.ethernet import MACRegistry, wrap_ethernet
from ctf_pcaps.engine.protocols.noise import generate_noise
from ctf_pcaps.engine.registry import get_builder
from ctf_pcaps.engine.writer import LimitsExceededError, stream_to_pcap

logger = structlog.get_logger()

# Sentinel to distinguish "not provided" from "provided as None (auto-gen)"
_UNSET = object()


def _merge_params(template, overrides):
    """Merge parameter overrides with template defaults.

    Returns a dict of parameter name -> resolved value.
    """
    merged = {}
    for name, param_def in template.parameters.items():
        if overrides and name in overrides:
            merged[name] = overrides[name]
        else:
            merged[name] = param_def.default
    return merged


def _resolve_steps(template, merged_params):
    """Resolve {{ var }} references in step data using merged params."""
    resolved_steps = []
    for step in template.steps:
        step_dict = {"action": step.action, **step.model_extra}
        resolved = resolve_variables(step_dict, merged_params)
        resolved_steps.append(resolved)
    return resolved_steps


def _apply_timestamps(packets: list, jitter_range_ms: tuple[float, float]) -> list:
    """Assign cumulative timestamps with protocol-aware jitter.

    Sets pkt.time on each packet with random inter-packet delays
    drawn from the jitter range. Returns the same list with
    timestamps set.

    Args:
        packets: List of Scapy packets to timestamp.
        jitter_range_ms: (min_ms, max_ms) for inter-packet delay.

    Returns:
        The same list with pkt.time values assigned.
    """
    current_time = time.time()
    for pkt in packets:
        pkt.time = current_time
        current_time += random.uniform(jitter_range_ms[0], jitter_range_ms[1]) / 1000.0
    return packets


def _extract_scenario_ips(packet_list: list) -> set[str]:
    """Extract all unique IP addresses from a list of packets.

    Scans packets for IP layer and collects all unique src/dst IPs.
    Used to tell noise generators which IPs to avoid.

    Args:
        packet_list: List of Scapy packets.

    Returns:
        Set of IP address strings found in the packets.
    """
    ips: set[str] = set()
    for pkt in packet_list:
        if pkt.haslayer(IP):
            ips.add(pkt[IP].src)
            ips.add(pkt[IP].dst)
    return ips


def generate(
    template_path: Path | str,
    output_dir: Path | str | None = None,
    overrides: dict | None = None,
    callback: Callable | None = None,
    callback_interval: int = 100,
    flag_text: str | None = _UNSET,
    flag_format: str = "flag",
    flag_encoding: str = "plaintext",
    difficulty: str | None = None,
    split_count: int = 1,
    custom_difficulty: CustomDifficultyParams | dict | None = None,
) -> GenerationResult | list[dict]:
    """Generate a PCAP file from a YAML scenario template.

    Full pipeline: sweep stale -> load -> validate -> merge params ->
    validate params -> resolve variables -> look up builder -> build
    packets -> embed flag -> stream to PCAP -> verify -> return result.

    Args:
        template_path: Path to the YAML scenario template file.
        output_dir: Directory for output PCAP. Uses Config.OUTPUT_DIR
                    if None.
        overrides: Optional parameter overrides (name -> value).
        callback: Optional progress callback function.
        callback_interval: How often to fire callback (every N packets).
        flag_text: Inner text for the flag. None = auto-generate.
                   Omitted (_UNSET) = no flag embedding.
        flag_format: Flag wrapper prefix (default "flag" -> "flag{...}").
        flag_encoding: Encoding for the flag ("plaintext", "base64",
                       "hex", "rot13").
        difficulty: Difficulty preset ("easy", "medium", "hard") or None.
                    When set, preset encoding chain overrides flag_encoding.
        split_count: Number of flag fragments (1 = no splitting). When
                     difficulty is set, preset split_count overrides this.
        custom_difficulty: Custom difficulty parameters (CustomDifficultyParams
                          or dict). When provided, overrides the difficulty
                          preset. Individual parameters can be set independently.

    Returns:
        GenerationResult on success, or list of error dicts on failure.
    """
    start = time.perf_counter()
    template_path = Path(template_path)
    config = get_config()

    # Determine if flag embedding is active
    flag_active = flag_text is not _UNSET

    # Step 0: Resolve difficulty - custom params take precedence over preset
    resolved_difficulty = None
    difficulty_source = None  # Track source for logging: "preset", "custom", or None

    if custom_difficulty is not None:
        # Custom difficulty parameters provided - use them
        try:
            resolved_difficulty = resolve_custom_difficulty(custom_difficulty)
            difficulty_source = "custom"
        except Exception as e:
            error = {
                "field": "custom_difficulty",
                "error_type": "invalid_custom_difficulty",
                "message": str(e),
            }
            logger.warning("pipeline_invalid_custom_difficulty", error=error)
            return [error]
    elif difficulty is not None:
        # Preset difficulty specified
        try:
            resolved_difficulty = resolve_difficulty(difficulty, overrides)
            difficulty_source = "preset"
        except KeyError as e:
            error = {
                "field": "difficulty",
                "error_type": "invalid_difficulty",
                "message": str(e),
            }
            logger.warning("pipeline_invalid_difficulty", error=error)
            return [error]

    difficulty_active = resolved_difficulty is not None

    # When difficulty is active, encoding_chain and split_count from resolved
    # difficulty take precedence over manual parameters
    if difficulty_active:
        active_encoding_chain = resolved_difficulty["encoding_chain"]
        active_split_count = resolved_difficulty["split_count"]
    else:
        active_encoding_chain = [flag_encoding]  # Wrap single encoding
        active_split_count = split_count  # Use manual parameter

    output_dir = Path(config.OUTPUT_DIR) if output_dir is None else Path(output_dir)

    logger.info(
        "pipeline_start",
        template=str(template_path),
        output_dir=str(output_dir),
        flag_active=flag_active,
        difficulty=difficulty,
        difficulty_source=difficulty_source,
        custom_difficulty=custom_difficulty is not None,
    )

    # Step 8.5 pre-check: Validate encoding(s) early
    if flag_active:
        for enc in active_encoding_chain:
            if enc not in ENCODERS:
                error = {
                    "field": "flag_encoding",
                    "error_type": "invalid_encoding",
                    "message": (
                        f"Unknown encoding '{enc}'. "
                        f"Available: {', '.join(sorted(ENCODERS.keys()))}"
                    ),
                }
                logger.warning("pipeline_invalid_encoding", error=error)
                return [error]

    # Step 1: Sweep stale files
    sweep_stale_files(output_dir, config.CLEANUP_TTL_HOURS)

    # Step 2: Load YAML template
    raw_data = load_template(template_path)
    logger.info("pipeline_template_loaded", template=template_path.name)

    # Step 3: Validate template schema
    validation_result = validate_template(raw_data)
    if isinstance(validation_result, list):
        logger.warning("pipeline_validation_failed", errors=validation_result)
        return validation_result
    template = validation_result

    # Step 4: Merge overrides with template defaults
    merged_params = _merge_params(template, overrides)

    # Step 5: Validate parameter constraints
    if overrides:
        param_errors = validate_parameters(template, overrides)
        if param_errors:
            logger.warning("pipeline_param_validation_failed", errors=param_errors)
            return param_errors

    # Step 6: Resolve variables in steps
    resolved_steps = _resolve_steps(template, merged_params)
    logger.info(
        "pipeline_params_resolved",
        param_count=len(merged_params),
        step_count=len(resolved_steps),
    )

    # Step 7: Look up builder
    try:
        builder_cls = get_builder(template.builder, template.builder_version)
    except KeyError as e:
        error = {
            "field": "builder",
            "error_type": "builder_not_found",
            "message": str(e),
        }
        logger.warning("pipeline_builder_not_found", error=error)
        return [error]

    # Step 8 pre: Assemble flag before build so builders can embed thematically
    assembled_flag = None
    encoded_flag = None
    verification_result = None
    if flag_active:
        # Assemble the flag (auto-generate inner text if None)
        assembled_flag = assemble_flag(flag_text, flag_format)

        # Encode the flag using the active encoding chain
        encoded_flag = encode_flag_chain(assembled_flag, active_encoding_chain)

        # Inject flag text and encoding into params for thematic embedding
        merged_params["__flag_text"] = assembled_flag
        merged_params["__flag_encoding"] = active_encoding_chain

    # Step 8: Build packets
    builder = builder_cls()
    packets = builder.build(merged_params, resolved_steps, callback)
    logger.info("pipeline_building", builder=template.builder)

    # Step 8.5: Flag packet embedding (optional)
    if flag_active:
        # Buffer packets for address extraction and embedding
        packet_list = list(packets)

        # Extract addresses from builder packets
        addrs = extract_addresses(packet_list)

        # Build flag payload(s) and packet(s)
        session_id = secrets.token_hex(3)

        if active_split_count > 1:
            # Split mode: divide encoded flag into fragments
            chunks = split_encoded_string(encoded_flag, active_split_count)
            fragment_packets = []
            for i, chunk in enumerate(chunks, start=1):
                payload = build_flag_payload(
                    chunk,
                    addrs["src_ip"],
                    addrs["dst_ip"],
                    session_id,
                    part=i,
                    total=active_split_count,
                )
                flag_pkt = build_flag_packet(
                    template.protocol,
                    addrs["src_ip"],
                    addrs["dst_ip"],
                    addrs["sport"],
                    addrs["dport"],
                    payload,
                )
                fragment_packets.append(flag_pkt)

            # Scatter fragment packets at random positions
            packets = embed_split_flag_packets(iter(packet_list), fragment_packets)
            logger.info(
                "split_flag_embedded_in_pipeline",
                split_count=active_split_count,
                encoding_chain=active_encoding_chain,
                flag_format=flag_format,
            )
        else:
            # Single flag mode: unchanged behavior
            payload = build_flag_payload(
                encoded_flag, addrs["src_ip"], addrs["dst_ip"], session_id
            )
            flag_pkt = build_flag_packet(
                template.protocol,
                addrs["src_ip"],
                addrs["dst_ip"],
                addrs["sport"],
                addrs["dport"],
                payload,
            )
            packets = embed_flag_packet(iter(packet_list), flag_pkt)
            logger.info(
                "flag_embedded_in_pipeline",
                encoding_chain=active_encoding_chain,
                flag_format=flag_format,
            )

    # Step 8.7: Create MACRegistry (always, not just when difficulty active)
    mac_registry = MACRegistry()

    # Step 8.8: Materialize and wrap all packets in Ethernet
    packet_list = list(packets)
    packet_list = [wrap_ethernet(pkt, mac_registry) for pkt in packet_list]
    logger.info("ethernet_wrapping_complete", packet_count=len(packet_list))

    # Step 8.9: Noise injection (only when difficulty active AND ratio > 0)
    if difficulty_active and resolved_difficulty["noise_ratio"] > 0:
        scenario_ips = _extract_scenario_ips(packet_list)
        noise_packets = generate_noise(
            scenario_count=len(packet_list),
            noise_ratio=resolved_difficulty["noise_ratio"],
            noise_types=resolved_difficulty["noise_types"],
            mac_registry=mac_registry,
            exclude_ips=scenario_ips,
        )
        packet_list.extend(noise_packets)
        logger.info(
            "noise_injected",
            noise_count=len(noise_packets),
            total=len(packet_list),
        )

    # Step 8.10: Timestamp assignment and interleaving
    if difficulty_active:
        jitter_range = resolved_difficulty["timing_jitter_ms"]
    else:
        jitter_range = (5.0, 50.0)

    packet_list = _apply_timestamps(packet_list, jitter_range)
    packet_list.sort(key=lambda p: float(p.time))
    logger.info(
        "timestamps_applied",
        jitter_range_ms=jitter_range,
        packet_count=len(packet_list),
    )

    # Step 9: Write to PCAP
    try:
        file_path, packet_count = stream_to_pcap(
            iter(packet_list),
            output_dir,
            config.MAX_PACKET_COUNT,
            config.MAX_PCAP_SIZE_MB,
            callback,
            callback_interval,
        )
    except LimitsExceededError as e:
        error = {
            "field": "limits",
            "error_type": "limits_exceeded",
            "message": str(e),
        }
        logger.error("pipeline_limits_exceeded", error=error)
        return [error]

    # Step 9.5: Flag verification (if flag was embedded)
    if flag_active and assembled_flag is not None:
        # Build a composite decode function for chained encoding
        def chain_decode_fn(data):
            return decode_flag_chain(data, active_encoding_chain)

        if active_split_count > 1:
            # Split flag verification: find fragments and reassemble
            verification_result = verify_split_flag_in_pcap(
                str(file_path),
                assembled_flag,
                active_encoding_chain,
                chain_decode_fn,
                active_split_count,
            )
        else:
            # Single flag verification (unchanged)
            primary_encoding = active_encoding_chain[0]
            verification_result = verify_flag_in_pcap(
                str(file_path),
                assembled_flag,
                primary_encoding,
                chain_decode_fn,
            )

            # Override solve_steps with chain-aware steps when chain > 1
            if verification_result["verified"] and len(active_encoding_chain) > 1:
                verification_result["solve_steps"] = _build_solve_steps_chain(
                    verification_result["packet_index"],
                    active_encoding_chain,
                    {},  # payload_data not needed for chain steps
                )

        if not verification_result["verified"]:
            os.unlink(file_path)
            error = {
                "field": "flag",
                "error_type": "flag_verification_failed",
                "message": "Flag could not be verified in generated PCAP",
            }
            logger.error("pipeline_flag_verification_failed", error=error)
            return [error]

        # Stealth check: use first encoding in chain for stealth logic
        # If chain contains "plaintext", skip stealth (same as current)
        stealth_encoding = active_encoding_chain[0]
        if not verify_stealth(str(file_path), assembled_flag, stealth_encoding):
            os.unlink(file_path)
            error = {
                "field": "flag",
                "error_type": "flag_stealth_failed",
                "message": (
                    "Flag is findable via strings in encoded PCAP "
                    f"(encoding: {stealth_encoding})"
                ),
            }
            logger.error("pipeline_flag_stealth_failed", error=error)
            return [error]

        logger.info("pipeline_flag_verified", encoding_chain=active_encoding_chain)

    # Step 10: Build result
    elapsed_ms = (time.perf_counter() - start) * 1000

    # Determine difficulty_preset value for result
    # For presets, use the preset name; for custom, use "custom"
    if difficulty_source == "preset":
        result_difficulty_preset = difficulty
    elif difficulty_source == "custom":
        result_difficulty_preset = "custom"
    else:
        result_difficulty_preset = None

    result = GenerationResult(
        file_path=file_path,
        packet_count=packet_count,
        file_size_bytes=file_path.stat().st_size,
        generation_duration_ms=elapsed_ms,
        builder_used=template.builder,
        template_name=template_path.stem,
        flag_text=assembled_flag if flag_active else None,
        flag_encoding=(active_encoding_chain[0] if flag_active else None),
        flag_verified=True if flag_active else None,
        solve_steps=(verification_result["solve_steps"] if verification_result else []),
        difficulty_preset=result_difficulty_preset,
        noise_ratio=(resolved_difficulty["noise_ratio"] if difficulty_active else None),
        packet_count_target=(
            resolved_difficulty["packet_count_target"] if difficulty_active else None
        ),
        noise_types=(resolved_difficulty["noise_types"] if difficulty_active else []),
        timing_jitter_ms=(
            resolved_difficulty["timing_jitter_ms"] if difficulty_active else None
        ),
        encoding_chain=active_encoding_chain if flag_active else [],
        split_count=active_split_count,
        split_active=active_split_count > 1,
    )

    logger.info(
        "pipeline_complete",
        file_path=str(result.file_path),
        packet_count=result.packet_count,
        file_size_bytes=result.file_size_bytes,
        duration_ms=round(result.generation_duration_ms, 2),
        flag_active=flag_active,
    )

    return result


def dry_run(
    template_path: Path | str,
    overrides: dict | None = None,
) -> dict | list[dict]:
    """Validate template and report expected behavior without creating files.

    Runs steps 2-7 of the generate() pipeline (load, validate, merge,
    resolve, look up builder) and returns a summary dict.

    Args:
        template_path: Path to the YAML scenario template file.
        overrides: Optional parameter overrides (name -> value).

    Returns:
        Dict with builder_name, protocol, parameter_count, step_count,
        parameters, and steps on success. List of error dicts on failure.
    """
    template_path = Path(template_path)

    # Step 2: Load
    raw_data = load_template(template_path)

    # Step 3: Validate
    validation_result = validate_template(raw_data)
    if isinstance(validation_result, list):
        return validation_result
    template = validation_result

    # Step 4: Merge
    merged_params = _merge_params(template, overrides)

    # Step 5: Validate parameters
    if overrides:
        param_errors = validate_parameters(template, overrides)
        if param_errors:
            return param_errors

    # Step 6: Resolve
    resolved_steps = _resolve_steps(template, merged_params)

    # Step 7: Look up builder
    try:
        get_builder(template.builder, template.builder_version)
    except KeyError as e:
        return [
            {
                "field": "builder",
                "error_type": "builder_not_found",
                "message": str(e),
            }
        ]

    return {
        "builder_name": template.builder,
        "builder_version": template.builder_version,
        "protocol": template.protocol,
        "parameter_count": len(merged_params),
        "step_count": len(resolved_steps),
        "parameters": merged_params,
        "steps": resolved_steps,
    }
