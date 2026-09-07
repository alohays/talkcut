"""Prepare unregistered intake candidates without opening a trust registry.

The caller-supplied policy is an input, never audited registration authority.
This adapter does not run a model, edit its output, or assign semantic success.
Final CLI/registration validation must recheck the original execution graph.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from . import composite_review as cr
from . import native_provenance as native
from .project import artifact_ref, atomic_json


def _normalized(
    verified: dict[str, Any],
    original_ref: dict[str, Any],
    run_ref: dict[str, Any],
    dependencies: dict[str, Any],
    call_ref: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    original, original_call, process = (
        verified["case"],
        verified["request"],
        verified["process"],
    )
    build = cr.artifact(original_call["build_receipt"])
    call = {
        "schema_version": "native-audio-request/v1",
        "dependencies": dependencies,
        "input_modalities": ["audio"],
        "input_artifacts": [original_call["input"], original_call["prompt"]],
        "audio": original_call["input"],
        "prompt": original_call["prompt"],
        "models": original_call["model_refs"],
        "argv": original_call["argv"],
        "trace_nonce": original_call["environment_overrides"]["TALKCUT_INTAKE_NONCE"],
    }
    execution = {
        "schema_version": "native-audio-execution/v1",
        "dependencies": dependencies,
        "completed": original.get("completed") is True,
        "run_id": original["run_id"],
        "native_execution": original_ref,
        "native_run": run_ref,
        "request": call_ref,
        "process": original["supervisor_execution"],
        "runtime": original_call["runtime"],
        "source_manifest": build["source_before"],
        "libraries": original_call["runtime_libraries"],
        **{
            key: process[key]
            for key in ("started_at", "finished_at", "exit_code", "stdout", "stderr")
        },
    }
    return call, execution


def _trace_intake(call: dict[str, Any], execution: dict[str, Any]) -> dict[str, Any]:
    """Use the actual existing intake validator with no policy context override."""
    argv = call["argv"]
    cr.require(
        isinstance(argv, list) and all(isinstance(item, str) for item in argv),
        "Native argv missing",
    )
    cr.require(
        not any(
            flag in argv for flag in ("--video", "--image", "-f", "--file", "--prompt")
        ),
        "Undeclared native input option",
    )
    audio = cr.pcm16(call["audio"])
    stdout = cr.artifact(execution["stdout"], raw=True)
    text = stdout.decode("utf-8")
    cr.require(
        text.strip() and not text.lstrip().startswith(("Traceback", "error:")),
        "Audio AI response empty/failed",
    )
    stderr = cr.artifact(execution["stderr"], raw=True).decode("utf-8")
    events = [
        json.loads(line[len(cr.TRACE_PREFIX) :])
        for line in stderr.splitlines()
        if line.startswith(cr.TRACE_PREFIX)
    ]
    cr._native_trace(events, call, audio, stdout)
    return {
        "sample_count": audio["count"],
        "sample_rate": audio["rate"],
        "float_pcm_sha256": audio["float_sha256"],
        "native_event_count": len(events),
        "stop_reason": "eog",
        "raw_stdout": execution["stdout"],
        "raw_stderr": execution["stderr"],
    }


def prepare_native_intake_candidate(
    input_ref: dict[str, Any], output_dir: Path
) -> dict[str, Any]:
    """Validate raw native bytes/process/intake and serialize an unregistered leaf.

    The explicit policy envelope is hash-bound but not trusted registration.
    Input dependencies are compared unchanged; no output hash is invented or
    added. `completed` in the normalized execution is only a process fact.
    """
    output_dir = Path(output_dir)
    cr.require(
        output_dir.is_absolute()
        and output_dir == output_dir.resolve()
        and not output_dir.exists(),
        "Candidate requires a new canonical output directory",
    )
    envelope = cr.artifact(input_ref)
    cr.require(
        isinstance(envelope, dict)
        and set(envelope)
        == {
            "schema_version",
            "status",
            "accepted_av_seconds",
            "original_case",
            "original_run",
            "dependencies",
            "policy",
        }
        and envelope["schema_version"] == "private-unregistered-native-policy-input/v1"
        and envelope["status"] == "UNREGISTERED_INTAKE_ONLY"
        and type(envelope["accepted_av_seconds"]) is int
        and envelope["accepted_av_seconds"] == 0
        and isinstance(envelope["dependencies"], dict)
        and isinstance(envelope["policy"], dict),
        "Native candidate needs an explicitly unregistered policy input",
    )
    dependencies = copy.deepcopy(envelope["dependencies"])
    original_ref, run_ref, policy = (
        envelope["original_case"],
        envelope["original_run"],
        envelope["policy"],
    )
    source_refs = {}
    for name, module in (("native_provenance", native), ("composite_review", cr)):
        source_file = module.__file__
        cr.require(isinstance(source_file, str), "Native validator source path missing")
        assert isinstance(source_file, str)
        source_refs[name] = artifact_ref(Path(source_file).resolve())
    source_refs["candidate_adapter"] = artifact_ref(Path(__file__).resolve())
    verified = native.verify_native_bundle(original_ref, run_ref, dependencies, policy)
    cr.require(
        verified["request"].get("dependencies") == dependencies,
        "Native request dependency scope differs",
    )
    call, execution = _normalized(verified, original_ref, run_ref, dependencies, {})
    intake = _trace_intake(call, execution)
    # Recheck the original graph after trace/PCM reads. Neither pass opens a
    # registration context or suppresses any actual native validator gate.
    cr.require(
        native.verify_native_bundle(original_ref, run_ref, dependencies, policy)
        == verified,
        "Native original graph changed during candidate validation",
    )
    cr.require(
        cr.artifact(input_ref) == envelope
        and all(artifact_ref(Path(ref["path"])) == ref for ref in source_refs.values()),
        "Candidate input policy or validator source changed",
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    call_path = output_dir / "native-request.json"
    # Match the registered adapter's serialization without changing raw content.
    call_path.write_text(json.dumps(call, ensure_ascii=False, indent=2) + "\n")
    execution["request"] = artifact_ref(call_path)
    execution_path = output_dir / "native-execution.json"
    execution_path.write_text(
        json.dumps(execution, ensure_ascii=False, indent=2) + "\n"
    )
    node = {
        "id": "native-audio",
        "kind": "local_audio_ai",
        "depends_on": [],
        "sample_range": [0, intake["sample_count"]],
        "execution": artifact_ref(execution_path),
    }
    node_path = output_dir / "native-node.json"
    atomic_json(node_path, node)
    candidate = {
        "schema_version": "private-native-intake-candidate/v1",
        "status": "UNREGISTERED_INTAKE_ONLY",
        "accepted_av_seconds": 0,
        "registration_status": "UNVERIFIED",
        "semantic_status": "UNVERIFIED",
        "dependencies": dependencies,
        "original_policy_input": input_ref,
        "original_case": original_ref,
        "original_run": run_ref,
        "original_request": verified["case"]["request"],
        "original_runner": verified["request"]["runner"],
        "validator_sources": source_refs,
        "normalized_request": artifact_ref(call_path),
        "normalized_execution": artifact_ref(execution_path),
        "node": artifact_ref(node_path),
        "intake_observations": intake,
        "scope": "Current original bytes, bounded process completion and complete instrumented intake only; no audited registration, calibration, semantic review or formal acceptance. Final CLI/registration must verify originals again.",
    }
    path = output_dir / "candidate.json"
    atomic_json(path, candidate)
    return artifact_ref(path)
