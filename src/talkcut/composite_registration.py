"""Durable, independently audited and request-scoped composite trust.

The local host's preserved evidence is not cryptographic provider attestation.
An independently executed artifact audit is required on every verification;
no caller JSON or process-global dictionary can register itself as trusted.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

_CURRENT: ContextVar[dict[str, Any] | None] = ContextVar(
    "talkcut_composite_registration", default=None
)
_VALIDATING: ContextVar[bool] = ContextVar(
    "talkcut_composite_registering", default=False
)


def _helpers():
    from .composite_review import artifact, require

    return artifact, require


def _refs(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
            return [value]
        return [ref for child in value.values() for ref in _refs(child)]
    if isinstance(value, list):
        return [ref for child in value for ref in _refs(child)]
    return []


def _session(row: dict[str, Any]) -> None:
    artifact, require = _helpers()
    path = Path(row.get("source_log", ""))
    home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).resolve()
    require(
        path.is_absolute()
        and path.is_file()
        and not path.is_symlink()
        and path == path.resolve()
        and path.is_relative_to(home / "sessions")
        and path.name.endswith(str(row.get("session_id")) + ".jsonl"),
        "Registration session is not this host actual canonical Codex log",
    )
    if row.get("origin") == "exec":
        from .codex_cli_transport import LIMIT, loads, raw

        require(path.stat().st_size <= LIMIT, "CLI canonical session exceeds bound")
    with path.open("rb") as stream:
        first = stream.readline(1024 * 1024)
    require(
        first.endswith(b"\n")
        and first == (raw(row.get("metadata")) if row.get("origin") == "exec"
                      else artifact(row.get("metadata"), raw=True)),
        "Actual first session metadata differs from registration",
    )
    meta = json.loads(first)
    payload = meta.get("payload", {})
    if row.get("origin") == "exec":
        require(
            meta.get("type") == "session_meta"
            and payload.get("id") == row.get("session_id")
            and payload.get("source") == "exec"
            and payload.get("thread_source") == "user"
            and "parent_thread_id" not in row
            and "agent_path" not in row,
            "Registered CLI session is not an actual exec origin",
        )
        capture = loads(raw(row.get("capture")))
        require(
            capture.get("schema_version") == "codex-cli-session/v1"
            and capture.get("session_id") == row["session_id"]
            and capture.get("start_byte") == 0,
            "Registered CLI capture identity/range differs",
        )
        session = raw(capture.get("session"))
        require(
            capture.get("end_byte") == len(session)
            and raw({**capture["session"], "path": str(path)}) == session,
            "Registered CLI capture is not the whole current actual session",
        )
        bootstrap = artifact(row.get("bootstrap_context"))
        records = [json.loads(line) for line in session.splitlines()]
        require(
            bootstrap
            == {
                "base_instructions": payload.get("base_instructions"),
                "world_state": [
                    v["payload"] for v in records if v.get("type") == "world_state"
                ],
            },
            "Registered CLI bootstrap context differs from actual session",
        )
        require(
            row.get("profile", {}).get("transport_kind") == "codex_cli_direct_images/v1"
            and row["profile"].get("model_revision") == row.get("model_revision"),
            "Registered CLI profile missing",
        )
        for key in ("terminal_request", "cli_run", "renderer"):
            require(
                isinstance(row.get(key), dict),
                "Registered CLI execution/preflight artifact missing",
            )
            artifact(row[key])
        return
    spawn = (
        payload.get("source", {}).get("subagent", {}).get("thread_spawn", {})
        if isinstance(payload.get("source"), dict)
        else {}
    )
    require(
        meta.get("type") == "session_meta"
        and payload.get("id") == row.get("session_id")
        and spawn.get("parent_thread_id") == row.get("parent_thread_id")
        and spawn.get("agent_path") == row.get("agent_path")
        and isinstance(row.get("parent_thread_id"), str)
        and isinstance(row.get("agent_path"), str),
        "Registered session is not the observed independent child identity",
    )
    capture = artifact(row.get("capture"))
    require(
        capture.get("schema_version") == "codex-session-slice/v1"
        and capture.get("session_id") == row["session_id"],
        "Registered capture belongs to another session",
    )
    artifact(capture.get("slice"), verify_only=True)


def validate_registration(
    ref: dict[str, Any],
    request_ref: dict[str, Any],
    recipe_ref: dict[str, Any],
    dependencies: dict[str, Any],
) -> dict[str, Any]:
    artifact, require = _helpers()
    require(not _VALIDATING.get(), "Composite registration audit bootstrap cycle")
    token = _VALIDATING.set(True)
    try:
        value = artifact(ref)
        require(
            value.get("schema_version") == "composite-registration/v1",
            "Durable independent composite registration missing",
        )
        snapshot = artifact(value.get("snapshot"))
        require(
            snapshot.get("schema_version") == "composite-registration-snapshot/v1"
            and snapshot.get("dependencies") == dependencies
            and snapshot.get("request") == request_ref
            and snapshot.get("recipe") == recipe_ref,
            "Registration belongs to different current request/recipe/dependencies",
        )
        artifact(request_ref)
        artifact(recipe_ref)
        native = snapshot.get("native_builds")
        sessions = snapshot.get("codex_sessions")
        require(
            isinstance(native, list)
            and native
            and isinstance(sessions, list)
            and sessions,
            "Registration must cover native AI and actual terminal transport",
        )
        require(
            len(native) <= 64 and len(sessions) <= 64,
            "Registration exceeds bounded graph size",
        )
        policies = {row.get("profile", {}).get("runtime_sha256"): row for row in native}
        session_map = {row.get("session_id"): row for row in sessions}
        require(
            None not in policies
            and len(policies) == len(native)
            and None not in session_map
            and len(session_map) == len(sessions),
            "Duplicate or missing registration identity",
        )
        for policy in native:
            profile = policy.get("profile", {})
            require(
                set(profile)
                == {
                    "runtime_sha256",
                    "runner_sha256",
                    "model_sha256s",
                    "prompt_sha256",
                    "argv_template",
                    "environment_keys",
                    "native_child_scope",
                }
                and policy.get("leaf_scope") == "audio_semantics_only"
                and policy.get("precision_supported") is False
                and isinstance(policy.get("supervisor_policy"), dict),
                "Native registered profile/scope incomplete",
            )
            for key, expected in (
                ("runtime", profile["runtime_sha256"]),
                ("runner", profile["runner_sha256"]),
                ("prompt", profile["prompt_sha256"]),
                ("build_receipt", policy.get("build_receipt_sha256")),
                ("source_manifest", policy.get("source_manifest_sha256")),
            ):
                require(
                    policy.get(key, {}).get("sha256") == expected
                    and isinstance(expected, str),
                    "Native policy byte identity differs",
                )
            require(
                [row["sha256"] for row in policy.get("models", [])]
                == profile["model_sha256s"],
                "Registered model pair differs",
            )
            for key in ("source_review", "runner_review", "trace_review"):
                require(
                    isinstance(policy.get(key), dict),
                    "Native instrumentation/runner/intake review evidence missing",
                )
        for row in sessions:
            _session(row)
        excluded = snapshot.get("implementation_run_ids", [])
        require(
            isinstance(excluded, list)
            and excluded
            and all(isinstance(v, str) and v for v in excluded),
            "Registration lacks actual implementation/native run separation",
        )
        envelope = artifact(value.get("audit"))
        receipt = artifact(envelope.get("receipt"))
        require(
            receipt.get("schema_version") == "execution-receipt/v1"
            and not receipt.get("_composite_verified")
            and not str(receipt.get("model_revision", "")).startswith("composite/")
            and not any(
                k in receipt
                for k in ("registration", "recipe", "nodes", "_composite_receipt")
            ),
            "Registration audit cannot bootstrap through composite trust",
        )
        require(
            receipt.get("run_id") not in session_map
            and receipt.get("run_id") not in excluded,
            "Registration auditor reuses the reviewed execution",
        )
        input_refs = _refs(
            {k: v for k, v in snapshot.items() if k not in {"implementation_run_ids"}}
        )
        unique = {row["sha256"]: row for row in input_refs}
        require(
            ref["sha256"] not in unique
            and value["snapshot"]["sha256"] not in unique
            and value["audit"]["sha256"] not in unique,
            "Registration artifact graph contains a bootstrap cycle",
        )
        from .review import verify_artifact_audit

        audit = verify_artifact_audit(
            value["audit"],
            scope="composite_registration",
            snapshot_ref=value["snapshot"],
            input_refs=list(unique.values()),
            dependencies=dependencies,
            excluded_run_ids=set(excluded),
        )
        response = audit["response"]
        observations = response.get("registration_observations", {})
        require(
            observations.get("request_sha256") == request_ref["sha256"]
            and observations.get("recipe_sha256") == recipe_ref["sha256"]
            and observations.get("native_profiles")
            == [
                {
                    "profile": row["profile"],
                    "source_manifest_sha256": row["source_manifest_sha256"],
                    "build_receipt_sha256": row["build_receipt_sha256"],
                    "leaf_scope": "audio_semantics_only",
                    "precision_supported": False,
                }
                for row in native
            ]
            and observations.get("terminal_captures")
            == [
                {
                    "session_id": row["session_id"],
                    "capture_sha256": row["capture"]["sha256"],
                    "metadata_sha256": row["metadata"]["sha256"],
                    "model_revision": row["model_revision"],
                    **(
                        {
                            "origin": "exec",
                            "profile": row["profile"],
                            "terminal_request_sha256": row["terminal_request"][
                                "sha256"
                            ],
                            "cli_run_sha256": row["cli_run"]["sha256"],
                            "bootstrap_context_sha256": row["bootstrap_context"][
                                "sha256"
                            ],
                        }
                        if row.get("origin") == "exec"
                        else {}
                    ),
                }
                for row in sessions
            ],
            "Independent auditor did not inspect exact native profiles and actual terminal captures",
        )
        require(
            isinstance(observations.get("reason"), str)
            and len(observations["reason"].strip()) >= 60
            and observations.get("no_expected_answer_input_verified") is True
            and observations.get("native_trace_hooks_verified") is True
            and observations.get("terminal_transport_bytes_verified") is True
            and observations.get("independent_context_verified") is True,
            "Independent registration lacks substantive domain observations",
        )
        return {
            "native": policies,
            "sessions": session_map,
            "registration": ref,
            "request": request_ref,
            "recipe": recipe_ref,
            "audit": audit,
        }
    finally:
        _VALIDATING.reset(token)


@contextmanager
def registration_scope(
    ref: dict[str, Any],
    request_ref: dict[str, Any],
    recipe_ref: dict[str, Any],
    dependencies: dict[str, Any],
) -> Iterator[None]:
    _, require = _helpers()
    require(_CURRENT.get() is None, "Nested composite registration would leak scope")
    value = validate_registration(ref, request_ref, recipe_ref, dependencies)
    token = _CURRENT.set(value)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def native_policy(runtime_sha256: str) -> dict[str, Any]:
    _, require = _helpers()
    current = _CURRENT.get()
    require(
        current is not None and runtime_sha256 in current["native"],
        "Native build lacks scoped independently audited registration",
    )
    assert current is not None
    return current["native"][runtime_sha256]


def session_path(session_id: str, capture_ref: dict[str, Any]) -> str:
    _, require = _helpers()
    current = _CURRENT.get()
    require(
        current is not None and session_id in current["sessions"],
        "Codex session lacks scoped independent registration",
    )
    assert current is not None
    row = current["sessions"][session_id]
    require(
        row["capture"] == capture_ref,
        "Registered terminal capture reused for another range",
    )
    _session(row)
    return str(row["source_log"])


def cli_session_binding(
    session_id: str, capture_ref: dict[str, Any], call: dict[str, Any]
) -> dict[str, Any]:
    _, require = _helpers()
    session_path(session_id, capture_ref)
    current = _CURRENT.get()
    assert current is not None
    row = current["sessions"][session_id]
    require(
        row.get("origin") == "exec"
        and call.get("composite_request") == current["request"]
        and call.get("recipe") == current["recipe"],
        "CLI typed request reused outside its independently registered composite graph",
    )
    return row
