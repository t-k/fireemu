"""Prompt assembly, one bounded inference, and script-side validation.

The model sees a versioned system prompt plus numbered excerpts. Its reply
must be a JSON object that passes the schema for the packet's kind; findings
that cite anything outside the packet's inputs are dropped by the script and
counted as unknowns. The model's own confidence is never consulted.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from local_assist.context_builder import ReadInput, estimate_tokens, render_numbered
from local_assist.packet import Packet
from local_assist.transport import Transport, TransportError

PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"
PROMPT_FORMAT_VERSION = 1
# Validation changes invalidate prior cached "ok" outcomes even when prompt text
# and model identity are unchanged. This is not the server/model version.
RESPONSE_CONTRACT_VERSION = 2
TERMINAL_FINISH_REASONS = ("stop", "length", "tool_calls", "function_call", "content_filter")
# Rough cost of the JSON scaffolding and chat template around the content.
TEMPLATE_RESERVE_TOKENS = 256
CATEGORIES = (
    "environment",
    "missing-dependency",
    "assertion",
    "timeout",
    "flaky-suspect",
    "regression",
    "unknown",
)
KIND_EXTRA_FIELDS = {
    "find-test-candidates": {},
    "classify-log": {"category": {"type": "string", "enum": list(CATEGORIES)}},
    "propose-tests": {
        "positiveControl": {"type": "string", "minLength": 1},
        "refusalPostState": {"type": "string", "minLength": 1},
    },
}
MAX_STRING_CHARS = 4000
MAX_UNKNOWNS = 50
QUANT_PATTERN = re.compile(
    r"(IQ\d_[A-Z0-9_]+|Q\d_K_[SML]|Q\d_K|Q\d_\d|PQ\d_\d|PTQ\d_\d|BF16|F16|F32)"
)
# llama-server's /props spells the file type "Q4_K - Medium"; the model
# name spells the same quant "Q4_K_M".
FTYPE_SUFFIXES = {" - Small": "_S", " - Medium": "_M", " - Large": "_L"}
PROPS_KEYS = ("model_alias", "total_slots", "build_info", "model_ftype")


@dataclass(frozen=True)
class Prompt:
    kind: str
    system: str
    version: str


@dataclass(frozen=True)
class RuntimeIdentity:
    endpoint: str
    alias: str | None
    modelId: str | None
    quant: str | None
    extra: dict = field(default_factory=dict)
    # True only when the server was probed and /v1/models (and /props, when
    # the server exposes it) reported exactly the alias pinned in the config.
    verified: bool = False

    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "alias": self.alias,
            "modelId": self.modelId,
            "quant": self.quant,
            **({"meta": self.extra} if self.extra else {}),
        }

    @property
    def expected_model(self) -> str | None:
        """The `model` a completion must report, or None when nothing is pinned."""
        return self.alias or self.modelId


@dataclass
class Outcome:
    finishStatus: str
    reason: str = ""
    findings: list[dict] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    usage: dict = field(default_factory=dict)
    modelReported: str | None = None
    repairAttempted: bool = False
    # The request was sent and never fully answered: the server may still be
    # busy with it, so the caller must keep the in-flight marker.
    serverStateUnknown: bool = False


@dataclass(frozen=True)
class Reply:
    content: str
    finish: str | None
    usage: dict
    model: str | None
    truncated: bool
    toolCalls: bool


def load_prompt(kind: str) -> Prompt:
    common = (PROMPTS_DIR / "common.txt").read_bytes()
    specific = (PROMPTS_DIR / f"{kind}.txt").read_bytes()
    digest = hashlib.sha256(common + b"\n" + specific).hexdigest()[:16]
    system = (
        common.decode("utf-8").rstrip() + "\n\n" + specific.decode("utf-8").rstrip()
    )
    return Prompt(
        kind=kind, system=system, version=f"{kind}@{PROMPT_FORMAT_VERSION}-{digest}"
    )


def response_schema(kind: str, max_findings: int) -> dict:
    finding_properties = {
        "claim": {"type": "string", "minLength": 1},
        "path": {"type": "string", "minLength": 1},
        "startLine": {"type": "integer", "minimum": 1},
        "endLine": {"type": "integer", "minimum": 1},
        "evidence": {"type": "string", "minLength": 1},
        **KIND_EXTRA_FIELDS[kind],
    }
    return {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "maxItems": max_findings,
                "items": {
                    "type": "object",
                    "properties": finding_properties,
                    "required": list(finding_properties),
                    "additionalProperties": False,
                },
            },
            "unknowns": {
                "type": "array",
                "maxItems": MAX_UNKNOWNS,
                "items": {"type": "string"},
            },
        },
        "required": ["findings", "unknowns"],
        "additionalProperties": False,
    }


def _clean_string(value: object, name: str, errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{name} must be a string")
        return False
    if not value.strip():
        errors.append(f"{name} must not be empty")
        return False
    if len(value) > MAX_STRING_CHARS:
        errors.append(f"{name} is longer than {MAX_STRING_CHARS} characters")
        return False
    if "\x00" in value or any(ord(ch) < 0x20 and ch not in "\n\t" for ch in value):
        errors.append(f"{name} contains control characters")
        return False
    return True


def validate_response(kind: str, obj: object, max_findings: int) -> list[str]:
    """Return a list of schema violations (empty when the reply is well-formed)."""
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["reply is not a JSON object"]
    extra = sorted(set(obj) - {"findings", "unknowns"})
    if extra:
        errors.append(f"unexpected top-level keys: {', '.join(extra)}")
    findings = obj.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        findings = []
    if len(findings) > max_findings:
        errors.append(f"findings has more than {max_findings} items")
    expected = {
        "claim",
        "path",
        "startLine",
        "endLine",
        "evidence",
        *KIND_EXTRA_FIELDS[kind],
    }
    for index, finding in enumerate(findings):
        name = f"findings[{index}]"
        if not isinstance(finding, dict):
            errors.append(f"{name} must be an object")
            continue
        missing = sorted(expected - set(finding))
        if missing:
            errors.append(f"{name} is missing {', '.join(missing)}")
        unexpected = sorted(set(finding) - expected)
        if unexpected:
            errors.append(f"{name} has unexpected keys {', '.join(unexpected)}")
        for key in ("claim", "path", "evidence"):
            if key in finding:
                _clean_string(finding[key], f"{name}.{key}", errors)
        for key in ("startLine", "endLine"):
            value = finding.get(key)
            if key in finding and (
                isinstance(value, bool) or not isinstance(value, int) or value < 1
            ):
                errors.append(f"{name}.{key} must be a positive integer")
        if (
            isinstance(finding.get("startLine"), int)
            and isinstance(finding.get("endLine"), int)
            and finding["endLine"] < finding["startLine"]
        ):
            errors.append(f"{name} endLine is before startLine")
        if (
            kind == "classify-log"
            and "category" in finding
            and finding["category"] not in CATEGORIES
        ):
            errors.append(f"{name}.category is not one of the allowed categories")
        if kind == "propose-tests":
            for key in ("positiveControl", "refusalPostState"):
                if key in finding:
                    _clean_string(finding[key], f"{name}.{key}", errors)
    unknowns = obj.get("unknowns")
    if not isinstance(unknowns, list):
        errors.append("unknowns must be an array")
    else:
        if len(unknowns) > MAX_UNKNOWNS:
            errors.append(f"unknowns has more than {MAX_UNKNOWNS} items")
        for index, item in enumerate(unknowns):
            _clean_string(item, f"unknowns[{index}]", errors)
    return errors


def build_messages(
    packet: Packet, inputs: list[ReadInput], prompt: Prompt
) -> list[dict]:
    excerpts = "\n".join(render_numbered(item) for item in inputs)
    user = (
        f"Question: {packet.question}\n\n"
        f"Return at most {packet.maxFindings} findings.\n\n"
        f"Excerpts ({len(inputs)}):\n\n{excerpts}"
    )
    return [
        {"role": "system", "content": prompt.system},
        {"role": "user", "content": user},
    ]


def estimate_prompt_tokens(messages: list[dict]) -> int:
    return (
        sum(estimate_tokens(message["content"]) for message in messages)
        + TEMPLATE_RESERVE_TOKENS
    )


def budget_check(
    messages: list[dict], max_output_tokens: int, context_tokens: int
) -> tuple[bool, dict]:
    estimate = estimate_prompt_tokens(messages)
    available = context_tokens - max_output_tokens
    detail = {
        "estimatedPromptTokens": estimate,
        "maxOutputTokens": max_output_tokens,
        "contextTokens": context_tokens,
        "availablePromptTokens": available,
    }
    return estimate <= available, detail


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def accept_findings(
    findings: list[dict], inputs: list[ReadInput]
) -> tuple[list[dict], list[str]]:
    """Keep findings that cite a packet input inside its read range; drop the rest."""
    by_path: dict[str, list[ReadInput]] = {}
    for item in inputs:
        by_path.setdefault(item.path, []).append(item)
    accepted: list[dict] = []
    dropped: list[str] = []
    for finding in findings:
        path = finding["path"]
        start, end = finding["startLine"], finding["endLine"]
        container = next(
            (
                item
                for item in by_path.get(path, [])
                if item.startLine <= start and end <= item.endLine
            ),
            None,
        )
        if container is None:
            dropped.append(
                f"dropped finding citing {path}:{start}-{end}: not inside any packet input"
            )
            continue
        selected = container.text.split("\n")[
            start - container.startLine : end - container.startLine + 1
        ]
        window = _normalize("\n".join(selected))
        evidence = _normalize(finding["evidence"])
        kept = dict(finding)
        kept["evidenceVerified"] = bool(evidence) and evidence in window
        accepted.append(kept)
    return accepted, dropped


def _extract_json(content: str) -> object:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    return json.loads(text)


def _reply_content(reply: dict) -> Reply:
    if not isinstance(reply, dict):
        raise TransportError("server-error", "reply is not an object", inflight=True)
    choices = reply.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise TransportError("server-error", "reply has no choices", inflight=True)
    if len(choices) != 1:
        raise TransportError("server-error", "reply has multiple choices", inflight=True)
    choice = choices[0]
    finish = choice.get("finish_reason")
    # HTTP completion and parseable JSON do not prove generation completion.
    # Do not repair/resend or clear the in-flight marker on an unknown state.
    if not isinstance(finish, str) or finish not in TERMINAL_FINISH_REASONS:
        raise TransportError(
            "server-error", "reply has no recognized terminal finish_reason", inflight=True
        )
    if "truncated" in reply and not isinstance(reply["truncated"], bool):
        raise TransportError("server-error", "reply truncated is not boolean", inflight=True)
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content")
    # Refused/tool-directed completions may have null content. They remain
    # terminal failures below and never reach JSON finding validation.
    if content is None and finish != "stop":
        content = ""
    if not isinstance(content, str):
        raise TransportError("server-error", "reply content is not a string")
    usage = reply.get("usage") if isinstance(reply.get("usage"), dict) else {}
    timings = reply.get("timings") if isinstance(reply.get("timings"), dict) else None
    usage_out = {
        "promptTokens": usage.get("prompt_tokens"),
        "completionTokens": usage.get("completion_tokens"),
    }
    if timings:
        usage_out["timings"] = {
            key: timings[key]
            for key in (
                "prompt_ms",
                "predicted_ms",
                "prompt_per_second",
                "predicted_per_second",
            )
            if key in timings
        }
    model = reply.get("model") if isinstance(reply.get("model"), str) else None
    return Reply(
        content=content,
        finish=finish,
        usage=usage_out,
        model=model,
        truncated=reply.get("truncated") is True,
        toolCalls=bool(message.get("tool_calls") or message.get("function_call")),
    )


def quant_from_ftype(ftype: object) -> str | None:
    if not isinstance(ftype, str):
        return None
    text = ftype.strip()
    for suffix, short in FTYPE_SUFFIXES.items():
        if text.endswith(suffix):
            text = text[: -len(suffix)] + short
            break
    match = QUANT_PATTERN.fullmatch(text)
    return match.group(1) if match else None


def _probe_props(base: str, transport: Transport, timeout: float) -> dict | None:
    """Read /props when the server exposes it; None when it does not."""
    try:
        reply = transport("GET", base + "/props", None, timeout)
    except TransportError:
        return None
    picked = {key: reply[key] for key in PROPS_KEYS if key in reply}
    settings = reply.get("default_generation_settings")
    if isinstance(settings, dict) and "n_ctx" in settings:
        picked["n_ctx"] = settings["n_ctx"]
    return picked


def probe_runtime(
    endpoint: str, transport: Transport, timeout: float, alias: str | None
) -> RuntimeIdentity:
    """Ask the server which model it serves. The identity is part of the cache key.

    With `alias` pinned, /v1/models must list exactly that id and /props (when
    the server exposes it) must report it as `model_alias`; any other answer
    is a runtime mismatch and nothing is sent to the model.
    """
    base = endpoint.split("/v1/", 1)[0]
    reply = transport("GET", base + "/v1/models", None, timeout)
    data = reply.get("data")
    if not isinstance(data, list) or not data or not isinstance(data[0], dict):
        raise TransportError("server-error", "/v1/models did not list a model")
    entry = data[0]
    model_id = entry.get("id") if isinstance(entry.get("id"), str) else None
    if alias is not None and model_id != alias:
        raise TransportError(
            "runtime-mismatch",
            f"/v1/models lists {model_id!r}, config alias is {alias!r}",
        )
    meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
    props = _probe_props(base, transport, timeout)
    if alias is not None and props is not None and props.get("model_alias") != alias:
        raise TransportError(
            "runtime-mismatch",
            f"/props reports model_alias {props.get('model_alias')!r}, "
            f"config alias is {alias!r}",
        )
    quant = None
    for candidate in (
        model_id or "",
        str(meta.get("quant", "")),
        str(meta.get("model_path", "")),
    ):
        match = QUANT_PATTERN.search(candidate)
        if match:
            quant = match.group(1)
            break
    if quant is None and props is not None:
        quant = quant_from_ftype(props.get("model_ftype"))
    picked = {
        key: meta[key] for key in ("n_params", "size", "n_ctx_train") if key in meta
    }
    if props is not None:
        picked["props"] = props
    return RuntimeIdentity(
        endpoint=endpoint,
        alias=alias,
        modelId=model_id,
        quant=quant,
        extra=picked,
        verified=alias is not None,
    )


def cache_key(
    packet: Packet,
    inputs: list[ReadInput],
    prompt: Prompt,
    runtime: RuntimeIdentity,
    response_format: str,
) -> str:
    material = {
        "kind": packet.kind,
        "question": packet.question,
        "maxFindings": packet.maxFindings,
        "maxOutputTokens": packet.maxOutputTokens,
        "inputs": [
            {
                "path": i.path,
                "startLine": i.startLine,
                "endLine": i.endLine,
                "sha256": i.rangeSha256,
            }
            for i in inputs
        ],
        "promptVersion": prompt.version,
        "responseContractVersion": RESPONSE_CONTRACT_VERSION,
        "responseFormat": response_format,
        "runtime": runtime.to_dict(),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True).encode("utf-8")
    ).hexdigest()


def build_request_body(
    packet: Packet,
    messages: list[dict],
    runtime: RuntimeIdentity,
    use_json_schema: bool,
) -> dict:
    """The exact chat-completions body a run sends (before any repair turn)."""
    schema = response_schema(packet.kind, packet.maxFindings)
    body = {
        "model": runtime.expected_model or "default",
        "messages": messages,
        "max_tokens": packet.maxOutputTokens,
        "temperature": 0,
        "stream": False,
        # Both spellings llama-server understands; harmless when the model or
        # the server has reasoning off already.
        "enable_thinking": False,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    if use_json_schema:
        body["response_format"] = {
            "type": "json_schema",
            "json_schema": {
                "name": "local_assist_result",
                "schema": schema,
                "strict": True,
            },
        }
    else:
        body["messages"] = messages[:-1] + [
            {
                "role": "user",
                "content": messages[-1]["content"]
                + "\n\nReply with a single JSON object matching this JSON schema and nothing else:\n"
                + json.dumps(schema),
            }
        ]
    return body


def describe_request(body: dict) -> dict:
    """Request metadata for a dry run: sizes and digests, never the prompt text."""
    encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
    response_format = body.get("response_format")
    return {
        "model": body["model"],
        "maxTokens": body["max_tokens"],
        "temperature": body["temperature"],
        "stream": body["stream"],
        "enableThinking": body["enable_thinking"],
        "responseFormat": response_format["type"] if response_format else "prompt",
        "messages": [
            {
                "role": message["role"],
                "chars": len(message["content"]),
                "sha256": hashlib.sha256(
                    message["content"].encode("utf-8")
                ).hexdigest(),
            }
            for message in body["messages"]
        ],
        "bodyBytes": len(encoded),
        "bodySha256": hashlib.sha256(encoded).hexdigest(),
    }


def run_inference(
    packet: Packet,
    inputs: list[ReadInput],
    prompt: Prompt,
    messages: list[dict],
    runtime: RuntimeIdentity,
    transport: Transport,
    use_json_schema: bool,
) -> Outcome:
    """One chat completion, one optional repair for schema-invalid output."""
    body = build_request_body(packet, messages, runtime, use_json_schema)
    deadline = time.monotonic() + packet.deadlineSeconds
    outcome = Outcome(finishStatus="ok")
    attempt_messages = body["messages"]
    for attempt in range(2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            outcome.finishStatus = "timeout"
            outcome.reason = "deadline exhausted before the request"
            outcome.repairAttempted = attempt == 1
            return outcome
        try:
            raw = transport(
                "POST",
                runtime.endpoint,
                {**body, "messages": attempt_messages},
                remaining,
            )
            reply = _reply_content(raw)
        except TransportError as error:
            # Keep usage/model metadata from an answered first attempt. A failed
            # repair has no measured usage of its own; never invent zero usage.
            outcome.finishStatus = error.status
            outcome.reason = error.reason
            outcome.repairAttempted = attempt == 1
            outcome.serverStateUnknown = error.inflight
            return outcome
        outcome.usage = _merge_usage(outcome.usage, reply.usage)
        outcome.modelReported = reply.model
        outcome.repairAttempted = attempt == 1
        if reply.truncated:
            outcome.finishStatus = "needs-narrower-input"
            outcome.reason = (
                "server reported truncated: true (context overflow); narrow the inputs"
            )
            return outcome
        expected = runtime.expected_model
        if expected is not None and reply.model != expected:
            outcome.finishStatus = "runtime-mismatch"
            outcome.reason = (
                f"completion reports model {reply.model!r}, expected {expected!r}"
            )
            return outcome
        if reply.toolCalls:
            outcome.finishStatus = "schema-invalid"
            outcome.reason = "reply carried tool_calls although no tools were offered"
            return outcome
        if reply.finish == "length":
            outcome.finishStatus = "schema-invalid"
            outcome.reason = "output truncated by max_tokens (finish_reason=length)"
            return outcome
        if reply.finish != "stop":
            outcome.finishStatus = "schema-invalid"
            outcome.reason = "completion did not finish normally (finish_reason is not stop)"
            return outcome
        content = reply.content
        try:
            parsed = _extract_json(content)
            errors = validate_response(packet.kind, parsed, packet.maxFindings)
        except (json.JSONDecodeError, RecursionError):
            parsed = None
            errors = ["reply is not valid JSON"]
        if not errors:
            accepted, dropped = accept_findings(parsed["findings"], inputs)
            outcome.findings = accepted
            outcome.unknowns = [str(item) for item in parsed["unknowns"]] + dropped
            outcome.finishStatus = "ok"
            outcome.reason = ""
            return outcome
        outcome.finishStatus = "schema-invalid"
        outcome.reason = "; ".join(errors)[:500]
        if attempt == 1:
            return outcome
        attempt_messages = body["messages"] + [
            {"role": "assistant", "content": content},
            {
                "role": "user",
                "content": "Your reply did not match the required schema: "
                + "; ".join(errors)[:1000]
                + ". Return the corrected JSON object only.",
            },
        ]
    return outcome


def _merge_usage(previous: dict, current: dict) -> dict:
    if not previous:
        return current
    merged = dict(current)
    for key in ("promptTokens", "completionTokens"):
        a, b = previous.get(key), current.get(key)
        merged[key] = (a or 0) + (b or 0) if (a is not None or b is not None) else None
    if "timings" in previous and "timings" in current:
        merged["timings"] = {"repair": current["timings"], "first": previous["timings"]}
    return merged
