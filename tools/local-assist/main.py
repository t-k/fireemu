#!/usr/bin/env python3
"""local-assist: a thin, read-only CLI that hands one bounded task to a
loopback llama-server and returns a validated, evidence-carrying result.

    python3 tools/local-assist/main.py --packet /abs/private/task.json --output /abs/private/result.json
    python3 tools/local-assist/main.py --packet ... --output ... --dry-run
    python3 tools/local-assist/main.py parse-log --format nextest --input gate.log --output failures.json --excerpt failures.txt
    python3 tools/local-assist/main.py --reset-lock --state-dir /abs/private/state

The model never gets tools, never sees credentials, and never talks to a
non-loopback host. See docs/compatibility/local-assist.md.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
import time
from pathlib import Path

from local_assist.context_builder import ContextError, read_inputs
from local_assist.inference import (
    RuntimeIdentity,
    budget_check,
    build_messages,
    build_request_body,
    cache_key,
    describe_request,
    load_prompt,
    probe_runtime,
    run_inference,
)
from local_assist.log_parser import parse_log, render_excerpt
from local_assist.packet import PacketError, parse_packet, validate_loopback_url
from local_assist.runtime import (
    DEFAULT_STATE_DIR,
    InferenceLock,
    LockBusy,
    OutputError,
    cache_get,
    cache_put,
    check_new_output_path,
    reset_lock,
    write_new_file,
)
from local_assist.transport import Transport, TransportError, http_json

TOOL_VERSION = "0.1.0"
DEFAULT_ENDPOINT = "http://127.0.0.1:8011/v1/chat/completions"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "fireemu-local-assist" / "config.json"
DEFAULT_CONTEXT_TOKENS = 16384
EXIT_CODES = {
    "ok": 0,
    "dry-run": 0,
    "needs-narrower-input": 2,
    "busy": 3,
    "timeout": 4,
    "schema-invalid": 5,
    "server-error": 6,
    "runtime-mismatch": 7,
    "server-state-unknown": 8,
}
EXIT_USAGE = 1
RESET_HINT = (
    "confirm the server is idle (GET /health, GET /slots shows is_processing "
    "false), then run --reset-lock with the same --state-dir/--config"
)


class ConfigError(ValueError):
    pass


def load_config(path: Path | None) -> dict:
    """Read the optional runtime config. Only known keys are accepted."""
    if path is None:
        if not DEFAULT_CONFIG_PATH.is_file():
            return {}
        path = DEFAULT_CONFIG_PATH
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ConfigError(f"config {path}: {type(error).__name__}")
    if not isinstance(raw, dict):
        raise ConfigError("config must be a JSON object")
    known = {
        "endpoint",
        "alias",
        "contextTokens",
        "responseFormat",
        "stateDir",
        "modelId",
        "quant",
        "apiKeyFile",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise ConfigError(f"config has unknown keys: {', '.join(unknown)}")
    if "endpoint" in raw:
        try:
            validate_loopback_url(raw["endpoint"])
        except PacketError as error:
            raise ConfigError(f"config endpoint: {error}")
    context = raw.get("contextTokens", DEFAULT_CONTEXT_TOKENS)
    if isinstance(context, bool) or not isinstance(context, int) or context < 1024:
        raise ConfigError("config contextTokens must be an integer >= 1024")
    if raw.get("responseFormat", "json_schema") not in ("json_schema", "prompt"):
        raise ConfigError("config responseFormat must be json_schema or prompt")
    for key in ("alias", "stateDir", "modelId", "quant", "apiKeyFile"):
        if key in raw and (not isinstance(raw[key], str) or not raw[key]):
            raise ConfigError(f"config {key} must be a non-empty string")
    return raw


def load_api_key(config: dict) -> str | None:
    """Read the bearer key for the local server from the configured file."""
    path = config.get("apiKeyFile")
    if not path:
        return None
    key_path = Path(path)
    if not key_path.is_absolute():
        raise ConfigError("config apiKeyFile must be an absolute path")
    try:
        if key_path.is_symlink():
            raise ConfigError("config apiKeyFile must not be a symlink")
        mode = key_path.stat().st_mode
        if mode & 0o077:
            raise ConfigError(
                "config apiKeyFile is readable by group or others; chmod 600 it"
            )
        key = key_path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ConfigError(f"config apiKeyFile: {type(error).__name__}")
    if (
        not key
        or len(key) > 512
        or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in key)
    ):
        raise ConfigError("config apiKeyFile must hold one printable token")
    return key


def _stderr(message: str) -> None:
    print(f"local-assist: {message}", file=sys.stderr)


def _result_skeleton(packet, inputs, prompt, base_commit_note: str | None) -> dict:
    return {
        "taskId": packet.taskId,
        "kind": packet.kind,
        "toolVersion": TOOL_VERSION,
        "promptVersion": prompt.version,
        "repoRoot": packet.repoRoot,
        "baseCommit": packet.baseCommit,
        "question": packet.question,
        "inputHashes": [item.identity() for item in inputs],
        "findings": [],
        "unknowns": [],
        "runtime": None,
        "runtimeIdentityVerified": False,
        "usage": {},
        "cache": {"hit": False, "key": None},
        "elapsedSeconds": 0.0,
        "finishStatus": "server-error",
        "reason": "",
        **({"note": base_commit_note} if base_commit_note else {}),
    }


def _emit(result: dict, output: Path, started: float) -> int:
    result["elapsedSeconds"] = round(time.monotonic() - started, 3)
    try:
        write_new_file(
            output,
            json.dumps(result, ensure_ascii=False, indent=2).encode("utf-8") + b"\n",
        )
    except OutputError as error:
        _stderr(f"result not written: {error}")
        return EXIT_USAGE
    status = result["finishStatus"]
    cited = (
        ", ".join(
            f"{f['path']}:{f['startLine']}-{f['endLine']}" for f in result["findings"]
        )
        or "-"
    )
    usage = result.get("usage") or {}
    runtime = result.get("runtime") or {}
    print(
        f"{result['taskId']} {result['kind']} finishStatus={status} "
        f"findings={len(result['findings'])} unknowns={len(result['unknowns'])}"
        + (f" reason={result['reason']}" if result.get("reason") else "")
    )
    print(
        f"usage prompt={usage.get('promptTokens')} completion={usage.get('completionTokens')} "
        f"elapsed={result['elapsedSeconds']}s model={runtime.get('modelId') or '-'} "
        f"cache={'hit' if result['cache']['hit'] else 'miss'}"
    )
    print(f"cited: {cited}")
    print(f"output: {output}")
    return EXIT_CODES[status]


def _config_runtime(endpoint: str, config: dict) -> RuntimeIdentity:
    """The identity pinned by the config alone; nothing was asked of the server."""
    return RuntimeIdentity(
        endpoint=endpoint,
        alias=config.get("alias"),
        modelId=config.get("modelId"),
        quant=config.get("quant"),
    )


def _server_state_unknown(result: dict, record: dict, marker: Path) -> None:
    result["finishStatus"] = "server-state-unknown"
    result["serverStateUnknown"] = True
    result["inflightMarker"] = str(marker)
    result["inflight"] = record
    result["reason"] = (
        f"an earlier run ({record.get('taskId', '?')} started {record.get('startedAt', '?')}) "
        f"was never answered; {RESET_HINT}"
    )


def run_task(args: argparse.Namespace, transport: Transport) -> int:
    started = time.monotonic()
    packet_path = Path(args.packet)
    if not packet_path.is_absolute():
        _stderr("--packet must be an absolute path")
        return EXIT_USAGE
    try:
        packet = parse_packet(json.loads(packet_path.read_text(encoding="utf-8")))
        config = load_config(Path(args.config) if args.config else None)
        api_key = load_api_key(config)
        output = check_new_output_path(args.output)
    except (OSError, ValueError) as error:
        _stderr(f"refused: {error}")
        return EXIT_USAGE
    state_dir = Path(args.state_dir or config.get("stateDir") or DEFAULT_STATE_DIR)
    if api_key and transport is http_json:
        transport = functools.partial(http_json, api_key=api_key)
    endpoint = packet.endpoint or config.get("endpoint") or DEFAULT_ENDPOINT
    try:
        inputs = read_inputs(packet.repoRoot, packet.inputs)
    except ContextError as error:
        _stderr(f"refused: {error}")
        return EXIT_USAGE
    prompt = load_prompt(packet.kind)
    result = _result_skeleton(packet, inputs, prompt, None)
    messages = build_messages(packet, inputs, prompt)
    fits, budget = budget_check(
        messages,
        packet.maxOutputTokens,
        config.get("contextTokens", DEFAULT_CONTEXT_TOKENS),
    )
    result["budget"] = budget
    response_format = config.get("responseFormat", "json_schema")
    if not fits:
        result["finishStatus"] = "needs-narrower-input"
        result["reason"] = (
            f"estimated {budget['estimatedPromptTokens']} prompt tokens exceed the "
            f"{budget['availablePromptTokens']} available; narrow the inputs"
        )
        return _emit(result, output, started)

    if args.dry_run:
        # Everything up to the wire, without the wire: no probe, no lock, no
        # cache lookup, and the prompt text stays out of the result.
        runtime = _config_runtime(endpoint, config)
        body = build_request_body(
            packet, messages, runtime, response_format == "json_schema"
        )
        result["runtime"] = runtime.to_dict()
        result["request"] = {"endpoint": endpoint, **describe_request(body)}
        result["finishStatus"] = "dry-run"
        result["reason"] = "prepared, not sent"
        return _emit(result, output, started)

    lock = InferenceLock(state_dir)
    stale = lock.inflight()
    if stale is not None:
        _server_state_unknown(result, stale, lock.marker)
        _stderr(f"status=server-state-unknown reason={result['reason']}")
        return _emit(result, output, started)

    if config.get("modelId"):
        runtime = _config_runtime(endpoint, config)
    else:
        try:
            runtime = probe_runtime(
                endpoint,
                transport,
                min(10.0, packet.deadlineSeconds),
                config.get("alias"),
            )
        except TransportError as error:
            result["finishStatus"] = (
                error.status if error.status != "busy" else "server-error"
            )
            result["reason"] = f"model probe failed: {error.reason}"
            _stderr(f"status={result['finishStatus']} reason={result['reason']}")
            return _emit(result, output, started)
        if config.get("quant") and not runtime.quant:
            runtime = RuntimeIdentity(
                runtime.endpoint,
                runtime.alias,
                runtime.modelId,
                config["quant"],
                runtime.extra,
            )
    result["runtime"] = runtime.to_dict()
    result["runtimeIdentityVerified"] = runtime.verified

    key = cache_key(packet, inputs, prompt, runtime, response_format)
    result["cache"]["key"] = key
    cached = cache_get(state_dir, key)
    if cached is not None:
        result.update(
            {
                "findings": cached["findings"],
                "unknowns": cached["unknowns"],
                "usage": cached["usage"],
                "finishStatus": "ok",
                "reason": "",
                "cache": {"hit": True, "key": key, "cachedAt": cached.get("cachedAt")},
            }
        )
        return _emit(result, output, started)

    if not lock.acquire():
        result["finishStatus"] = "busy"
        result["reason"] = "another local inference holds the lock"
        return _emit(result, output, started)
    try:
        stale = lock.inflight()
        if stale is not None:
            _server_state_unknown(result, stale, lock.marker)
            _stderr(f"status=server-state-unknown reason={result['reason']}")
            return _emit(result, output, started)
        lock.mark_inflight(
            {
                "taskId": packet.taskId,
                "endpoint": runtime.endpoint,
                "startedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pid": os.getpid(),
                "output": str(output),
            }
        )
        outcome = run_inference(
            packet,
            inputs,
            prompt,
            messages,
            runtime,
            transport,
            use_json_schema=response_format == "json_schema",
        )
        if outcome.serverStateUnknown:
            # The request may still be running on the server: keep the marker
            # so nobody sends another one until an operator has looked.
            result["serverStateUnknown"] = True
            result["inflightMarker"] = str(lock.marker)
            outcome.reason = f"{outcome.reason}; lock kept, {RESET_HINT}"
        else:
            lock.clear_inflight()
    finally:
        lock.release()
    result.update(
        {
            "findings": outcome.findings,
            "unknowns": outcome.unknowns,
            "usage": outcome.usage,
            "finishStatus": outcome.finishStatus,
            "reason": outcome.reason,
            "repairAttempted": outcome.repairAttempted,
        }
    )
    if outcome.modelReported and outcome.modelReported != runtime.modelId:
        result["runtime"]["modelReportedByCompletion"] = outcome.modelReported
    if outcome.finishStatus != "ok":
        _stderr(f"status={outcome.finishStatus} reason={outcome.reason}")
    else:
        cache_put(
            state_dir,
            key,
            {
                "findings": outcome.findings,
                "unknowns": outcome.unknowns,
                "usage": outcome.usage,
                "cachedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "taskId": packet.taskId,
            },
        )
    return _emit(result, output, started)


def run_parse_log(args: argparse.Namespace) -> int:
    source = Path(args.input)
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
        parsed = parse_log(text, args.format)
        output = check_new_output_path(args.output)
        excerpt = check_new_output_path(args.excerpt) if args.excerpt else None
        write_new_file(
            output,
            json.dumps(parsed.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
            + b"\n",
        )
        if excerpt is not None:
            write_new_file(excerpt, render_excerpt(parsed, source.name).encode("utf-8"))
    except (OSError, ValueError) as error:
        _stderr(f"parse-log failed: {error}")
        return EXIT_USAGE
    summary = parsed.summary
    print(
        f"{parsed.format}: run={summary.get('run')} passed={summary.get('passed')} "
        f"failed={summary.get('failed')} skipped={summary.get('skipped')} "
        f"failureBlocks={len(parsed.failures)}"
    )
    print(f"output: {output}")
    if excerpt is not None:
        print(f"excerpt: {excerpt}")
    return 0


def run_reset_lock(args: argparse.Namespace) -> int:
    try:
        config = load_config(Path(args.config) if args.config else None)
    except ConfigError as error:
        _stderr(f"refused: {error}")
        return EXIT_USAGE
    state_dir = Path(args.state_dir or config.get("stateDir") or DEFAULT_STATE_DIR)
    try:
        record = reset_lock(state_dir)
    except LockBusy as error:
        _stderr(f"status=busy reason={error}")
        return EXIT_CODES["busy"]
    except OSError as error:
        _stderr(f"reset failed: {type(error).__name__}")
        return EXIT_USAGE
    if record is None:
        print(f"reset-lock: no in-flight marker under {state_dir}; nothing to do")
    else:
        print(
            f"reset-lock: removed marker for {record.get('taskId', '?')} "
            f"(started {record.get('startedAt', '?')}, pid {record.get('pid', '?')}); "
            "this records the operator's confirmation that the server is idle, "
            "it did not check the server"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local-assist", description=__doc__.split("\n\n")[0]
    )
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser(
        "run", help="run one packet (default when no subcommand is given)"
    )
    run.add_argument(
        "--packet", required=True, help="absolute path of the task packet JSON"
    )
    run.add_argument(
        "--output", required=True, help="absolute path of a NEW result JSON file"
    )
    run.add_argument(
        "--config",
        help="runtime config JSON (default: ~/.config/fireemu-local-assist/config.json)",
    )
    run.add_argument(
        "--state-dir",
        help="lock and cache directory (default: ~/.cache/fireemu-local-assist)",
    )
    run.add_argument(
        "--dry-run",
        action="store_true",
        help="build the context, hashes, budget and request metadata; contact nothing",
    )
    reset = sub.add_parser(
        "reset-lock",
        help="clear the in-flight marker left by a timed-out run (operator confirmed the server idle)",
    )
    reset.add_argument("--config", help="runtime config JSON (for stateDir)")
    reset.add_argument("--state-dir", help="lock directory holding the marker")
    log = sub.add_parser(
        "parse-log",
        help="extract failure blocks from a nextest or pytest log without a model",
    )
    log.add_argument("--input", required=True)
    log.add_argument(
        "--output",
        required=True,
        help="NEW JSON file with the summary and failure blocks",
    )
    log.add_argument(
        "--excerpt", help="NEW text file rendered for a classify-log packet"
    )
    log.add_argument("--format", choices=("auto", "nextest", "pytest"), default="auto")
    return parser


def main(argv: list[str] | None = None, transport: Transport = http_json) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--reset-lock" in argv:
        argv = ["reset-lock"] + [item for item in argv if item != "--reset-lock"]
    if argv and argv[0] not in ("run", "parse-log", "reset-lock", "-h", "--help"):
        argv = ["run"] + argv
    args = build_parser().parse_args(argv)
    if args.command == "parse-log":
        return run_parse_log(args)
    if args.command == "reset-lock":
        return run_reset_lock(args)
    if args.command == "run":
        return run_task(args, transport)
    build_parser().print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
