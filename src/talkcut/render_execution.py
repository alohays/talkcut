"""Capture the actual render worker and bind its output to acceptance inputs.

Completion here describes encoding/cache retrieval. Diagnostic media and missing
audiovisual evidence remain ineligible for final acceptance.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

from .contracts import code_identity
from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    load_project,
    now,
    project_lock,
    read_json,
    verified_json,
)
from .timeline import as_fraction


def run_render(project_dir: Path, profile: str, *, preset: str, crf: int,
               repo_root: Path) -> tuple[dict[str, Any], int]:
    project_dir, repo_root = project_dir.resolve(), repo_root.resolve()
    run_id = "render-execution-" + uuid4().hex
    directory = project_dir / "executions" / run_id
    directory.mkdir(parents=True)
    stdout, stderr = directory / "stdout.json", directory / "stderr.log"
    command = [sys.executable, "-m", "talkcut", "render-worker", str(project_dir),
               "--profile", profile, "--preset", preset, "--crf", str(crf), "--json"]
    before = code_identity(repo_root)
    started, clock = now(), time.monotonic()
    process, failure, exit_code = None, None, None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            process = subprocess.Popen(command, cwd=repo_root, stdout=out, stderr=err,
                                       start_new_session=True)
            exit_code = process.wait(timeout=14460)
        except (OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
            failure = {"type": type(exc).__name__, "message": str(exc)}
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    exit_code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    exit_code = process.wait(timeout=10)
    after = code_identity(repo_root)
    execution = {"schema_version": "render-process/v1", "run_id": run_id,
                 "command": command, "cwd": str(repo_root), "started_at": started,
                 "finished_at": now(), "wall_seconds": time.monotonic() - clock,
                 "exit_code": exit_code, "failure": failure, "before": before, "after": after,
                 "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr)}
    log = directory / "execution.json"
    atomic_json(log, execution)
    error = None
    result: dict[str, Any] = {}
    try:
        if failure is not None or exit_code != 0:
            raise TalkCutError("RENDER_EXECUTION_FAILED", "Render worker failed or was interrupted")
        if before["code_tree_hash"] != after["code_tree_hash"]:
            raise TalkCutError("STALE_RENDER_EXECUTION", "Code changed during render execution")
        result = read_json(stdout)
        with project_lock(project_dir):
            project = load_project(project_dir)
            workflow = verified_json(project["active_render"])
            native = verified_json(workflow["native_render"])
            plan = verified_json(project["active_plan"])
            timeline = verified_json(project["active_timeline"])
            if (result.get("schema_version") != "workflow-render/v1"
                    or result.get("status") != "RENDERED"
                    or result.get("project_revision") != project["revision"]
                    or {k: v for k, v in result.items() if k not in {"cache_hit", "project_revision"}} != workflow
                    or workflow["output"] != native["output"]
                    or workflow["profile"] != profile
                    or native.get("complete") is not True
                    or native.get("exit_code") != 0
                    or native["timeline_hash"] != timeline["timeline_hash"]):
                raise TalkCutError("STALE_RENDER_EXECUTION", "Actual worker output does not match committed project/native render")
            if artifact_ref(native["output"]["path"]) != {k: v for k, v in native["output"].items() if k != "bytes"}:
                raise TalkCutError("SOURCE_CHANGED", "Actual rendered bytes changed")
            dependencies = {"code_tree_hash": before["code_tree_hash"],
                            "contract_hash": plan["contract_hash"], "source_hashes": plan["source_hashes"],
                            "plan_hash": content_hash(plan), "timeline_hash": project["active_timeline"]["sha256"],
                            "output_hash": native["output"]["sha256"]}
            if code_identity(repo_root)["code_tree_hash"] != before["code_tree_hash"]:
                raise TalkCutError("STALE_RENDER_EXECUTION", "Code changed while binding the render receipt")
            receipt = {"schema_version": "execution-receipt/v1", "run_id": run_id,
                       "operation": "render", "executor": sys.executable,
                       "tool_version": f"talkcut {version('talkcut')}", "command": command,
                       "started_at": started, "finished_at": execution["finished_at"],
                       "completed": True, "exit_code": exit_code, "test_only": workflow["test_only"],
                       "log": artifact_ref(log), "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr),
                       "result": artifact_ref(stdout), "dependencies": dependencies,
                       "owner_acceptance": "pending"}
            receipt_path = directory / "receipt.json"
            atomic_json(receipt_path, receipt)
            validation = native["validation"]
            record = {"schema_version": "render-evidence/v1", "render_id": workflow["render_id"],
                      "status": "complete", "complete": True, "profile": profile,
                      "test_only": workflow["test_only"], "output": workflow["output"],
                      "workflow_render": project["active_render"], "native_render": workflow["native_render"],
                      "timeline_hash": project["active_timeline"]["sha256"], "dependencies": dependencies,
                      "receipt": artifact_ref(receipt_path), "actual": {
                          "frame_count": validation["frame_count"], "valid_audio_samples": validation["sample_count"],
                          "video_end_pts": validation["video_end"],
                          "audio_end_pts": str(as_fraction(validation["sample_count"]) / timeline["sample_rate"])},
                      "ai_review": "UNVERIFIED", "owner_acceptance": "pending"}
            record_path = directory / "render.json"
            atomic_json(record_path, record)
            index_path = project_dir / "acceptance.local.json"
            index = read_json(index_path) if index_path.exists() else {
                "schema_version": "acceptance-index/v1", "checks": {}, "reviews": [], "capabilities": [],
                "findings": [], "edit_disposition": "ANALYSIS_UNAVAILABLE", "owner_acceptance": "pending"}
            if index_path.exists():
                atomic_json(directory / "acceptance-before.json", index)
            index.update(render=artifact_ref(record_path), timeline=project["active_timeline"])
            atomic_json(index_path, index)
        return {**result, "execution": artifact_ref(log), "acceptance_render": artifact_ref(record_path)}, 0
    except (TalkCutError, OSError, ValueError, KeyError, TypeError) as exc:
        error = str(exc)
    rejected = {"schema_version": "render-execution-failure/v1", "status": "FAIL", "reason": error,
                "execution": artifact_ref(log), "acceptance": "UNVERIFIED", "owner_acceptance": "pending"}
    try:
        rejected["worker_result"] = read_json(stdout)
    except (OSError, ValueError):
        pass
    atomic_json(directory / "failure.json", rejected)
    code = 130 if failure and failure["type"] == "KeyboardInterrupt" else 2 if exit_code == 2 else 1
    return rejected, code
