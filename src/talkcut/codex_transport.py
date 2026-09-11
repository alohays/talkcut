"""Verify actual local Codex byte slices, never an authored exchange assertion.

Session registration is outside receipt data and requires operator verification of
this task's session identity. This does not attest a provider cryptographically or
prove blind prior context. Capability calibration still needs independent audit.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

from .composite_registration import session_path as _registered_session
from .project import TalkCutError, sha256

MAX_SLICE_BYTES = 32 * 1024 * 1024
HEADER = re.compile(r"Script completed\nWall time [0-9.]+ seconds\nOutput:\n\Z")


def require(value: Any, message: str) -> None:
    if not value:
        raise TalkCutError("COMPOSITE_TRANSPORT_UNVERIFIED", message)


def raw_ref(ref: Any) -> bytes:
    require(isinstance(ref, dict), "Transport artifact ref missing")
    p = Path(ref.get("path", ""))
    require(
        p.is_absolute() and p.is_file() and sha256(p) == ref.get("sha256"),
        "Transport artifact missing or stale",
    )
    return p.read_bytes()


def packet(kind: str, **kwargs: Any) -> dict[str, Any]:
    return {"schema_version": "composite-input/v1", "kind": kind, **kwargs}


def terminal_tool_code(
    prompt: str, frames: list[dict[str, Any]], outputs: list[dict[str, Any]]
) -> str:
    """Exact tool invocation. No arbitrary code/comments or hidden extra input."""

    def js(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    lines = [
        '// @exec: {"max_output_tokens":64000}',
        "text(" + js(packet("prompt", text=prompt)) + ");",
    ]
    for i, frame in enumerate(frames):
        lines.append(
            "text("
            + js(
                packet(
                    "frame_metadata",
                    sha256=frame["artifact"]["sha256"],
                    timestamp=frame["timestamp"],
                    mime_type=frame["mime_type"],
                )
            )
            + ");"
        )
        lines.append(
            f"const frame{i} = await tools.view_image("
            + js({"path": frame["artifact"]["path"], "detail": "original"})
            + ");"
        )
        lines.append(f"image(frame{i}.image_url);")
    for output in outputs:
        lines.append("text(" + js(packet("tool_result", **output)) + ");")
    return "\n".join(lines) + "\n"


def terminal_initial_task(code: str) -> str:
    """Exact optional fresh-task input, bound to the only permitted tool call."""
    return (
        "Execute exactly this single functions.exec call, then inspect its actual images and raw tool outputs "
        "and return only the requested JSON response. Do not call other tools, read other files, "
        "or infer missing observations. Follow the instructions in the emitted prompt.\n\n"
        + code
    )


def _parse_output(parts: Any) -> list[dict[str, Any]]:
    require(isinstance(parts, list) and parts, "Actual tool output absent")
    parts = list(parts)
    if parts[0].get("type") == "input_text" and HEADER.fullmatch(
        parts[0].get("text", "")
    ):
        parts = parts[1:]
    content: list[dict[str, Any]] = []
    pending: dict[str, Any] | None = None
    for part in parts:
        if part.get("type") == "input_text":
            require(pending is None, "Timestamped frame bytes are missing")
            try:
                value = json.loads(part.get("text", ""))
            except ValueError as e:
                raise TalkCutError(
                    "COMPOSITE_TRANSPORT_UNVERIFIED", "Unexpected terminal tool text"
                ) from e
            require(
                isinstance(value, dict)
                and value.get("schema_version") == "composite-input/v1",
                "Unstructured terminal input or expected-value injection",
            )
            kind = value.get("kind")
            if kind == "prompt":
                require(
                    set(value) == {"schema_version", "kind", "text"},
                    "Prompt packet extra input",
                )
                content.append({"type": "text", "text": value["text"]})
            elif kind == "frame_metadata":
                require(
                    set(value)
                    == {"schema_version", "kind", "sha256", "timestamp", "mime_type"},
                    "Frame packet extra input",
                )
                pending = value
            elif kind == "tool_result":
                require(
                    set(value)
                    == {"schema_version", "kind", "node_id", "artifact_sha256", "text"},
                    "Tool result packet extra input",
                )
                content.append(
                    {
                        "type": "tool_result",
                        **{k: value[k] for k in ("node_id", "artifact_sha256", "text")},
                    }
                )
            else:
                require(False, "Unexpected terminal packet kind")
        else:
            require(
                part.get("type") == "input_image" and pending is not None,
                "Terminal image missing ordered timestamp metadata",
            )
            assert pending is not None
            url = part.get("image_url", "")
            prefix = "data:" + pending["mime_type"] + ";base64,"
            require(
                isinstance(url, str) and url.startswith(prefix),
                "Actual image bytes were not persisted",
            )
            try:
                data = base64.b64decode(url[len(prefix) :], validate=True)
            except ValueError as e:
                raise TalkCutError(
                    "COMPOSITE_TRANSPORT_UNVERIFIED", "Invalid persisted image bytes"
                ) from e
            import hashlib

            require(
                hashlib.sha256(data).hexdigest() == pending["sha256"],
                "Persisted image bytes differ from requested frame",
            )
            content.append(
                {
                    "type": "image",
                    "mime_type": pending["mime_type"],
                    "data_base64": base64.b64encode(data).decode(),
                    "timestamp": pending["timestamp"],
                }
            )
            pending = None
    require(pending is None, "Final frame has no actual persisted image bytes")
    return content


def verify_session_exchange(
    capture_ref: dict[str, Any], *, code: str, model_revision: str, request_id: str
) -> dict[str, Any]:
    capture = json.loads(raw_ref(capture_ref))
    require(
        capture.get("schema_version") == "codex-session-slice/v1",
        "Actual Codex session slice missing",
    )
    session_id = capture.get("session_id")
    source_name = _registered_session(session_id, capture_ref)
    source = Path(source_name)
    require(
        source.is_absolute()
        and source.is_file()
        and not source.is_symlink()
        and source.name.endswith(str(session_id) + ".jsonl"),
        "Registered session log identity differs",
    )
    start, end = capture.get("start_byte"), capture.get("end_byte")
    require(
        type(start) is int
        and type(end) is int
        and 0 <= start < end
        and end - start <= MAX_SLICE_BYTES
        and end <= source.stat().st_size,
        "Terminal execution byte range missing, truncated or too large",
    )
    raw = raw_ref(capture.get("slice"))
    with source.open("rb") as reader:
        if start:
            reader.seek(start - 1)
            require(
                reader.read(1) == b"\n",
                "Session slice does not start at a record boundary",
            )
        reader.seek(start)
        require(
            reader.read(end - start) == raw and raw.endswith(b"\n"),
            "Authored exchange is not the actual append-only session byte range",
        )
    rows = [json.loads(line) for line in raw.splitlines()]
    require(
        rows and rows[0].get("type") == "turn_context",
        "Slice must start with actual turn context",
    )
    context = rows[0].get("payload", {})
    require(
        context.get("turn_id") == capture.get("turn_id")
        and context.get("model") == model_revision,
        "Terminal actual model/turn identity differs",
    )
    require(
        all(
            row.get("type") not in {"compacted", "turn_context", "session_meta"}
            for row in rows[1:]
        ),
        "Terminal context was replaced/compacted during review",
    )
    call_id = capture.get("tool_call_id")
    namespaced_id = (
        f"codex-session:{session_id}/turn:{capture.get('turn_id')}/call:{call_id}"
    )
    require(
        namespaced_id == request_id,
        "Terminal request ID is not the actual namespaced Codex call",
    )
    calls, outputs, finals = [], [], []
    initial_users: list[int] = []
    for index, row in enumerate(rows[1:], 1):
        if row.get("type") == "event_msg":
            require(
                row.get("payload", {}).get("type")
                not in {"task_abort", "task_aborted", "turn_aborted", "error"},
                "Terminal turn was aborted or errored",
            )
        if row.get("type") != "response_item":
            continue
        value = row.get("payload", {})
        kind = value.get("type")
        if kind in {"function_call", "custom_tool_call"}:
            require(
                kind == "custom_tool_call"
                and value.get("name") == "exec"
                and value.get("call_id") == call_id
                and value.get("input") == code,
                "Terminal used an undeclared tool or injected extra instructions",
            )
            calls.append(index)
        elif kind in {"function_call_output", "custom_tool_call_output"}:
            require(
                kind == "custom_tool_call_output" and value.get("call_id") == call_id,
                "Terminal received unrelated tool observations",
            )
            outputs.append((index, value))
        elif kind == "message":
            if value.get("role") == "user":
                require(
                    not calls
                    and not initial_users
                    and value.get("content")
                    == [{"type": "input_text", "text": terminal_initial_task(code)}]
                    and capture.get("initial_task_sha256")
                    == __import__("hashlib")
                    .sha256(terminal_initial_task(code).encode())
                    .hexdigest(),
                    "Additional user input or unbound initial task contaminates execution slice",
                )
                initial_users.append(index)
                continue
            require(
                value.get("role") == "assistant",
                "Additional user input contaminates execution slice",
            )
            if value.get("phase") == "final":
                finals.append((index, value))
            else:
                require(
                    value.get("phase") in {"analysis", "commentary"},
                    "Unexpected visible assistant content during review",
                )
        elif kind == "agent_message":
            require(False, "Additional agent input contaminates execution slice")
        else:
            require(
                kind == "reasoning", "Unknown response item could conceal extra inputs"
            )
        # encrypted reasoning is neither read nor interpreted as output evidence.
    require(
        len(calls) == len(outputs) == len(finals) == 1
        and calls[0] < outputs[0][0] < finals[0][0],
        "Actual terminal call/output/final order incomplete",
    )
    require(
        bool(initial_users) == (capture.get("initial_task_sha256") is not None),
        "Initial-task declaration differs from actual session input",
    )
    final = finals[0][1]
    require(
        final.get("id") == capture.get("response_item_id"),
        "Final assistant response identity differs",
    )
    chunks = final.get("content", [])
    require(
        chunks and all(c.get("type") == "output_text" for c in chunks),
        "Actual final text response missing",
    )
    text = "".join(c["text"] for c in chunks)
    require(text.strip(), "Actual final AI response is empty")
    return {
        "schema_version": "captured-ai-exchange/v1",
        "request": {
            "request_id": request_id,
            "model_revision": model_revision,
            "content": _parse_output(outputs[0][1].get("output")),
        },
        "response": {
            "request_id": request_id,
            "completed": True,
            "completion_basis": "actual_assistant_final",
            "raw_text": text,
        },
        "observed_execution": {
            "session_id": session_id,
            "turn_id": capture["turn_id"],
            "call_id": call_id,
            "started_at": rows[0].get("timestamp"),
            "finished_at": rows[finals[0][0]].get("timestamp"),
            "model_identifier_scope": "requested_model_from_turn_context",
            "provider_model_snapshot": None,
            "provider_finish_reason": None,
            "provider_process_exit_code": None,
        },
    }
