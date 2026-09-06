"""Execute typed acceptance measurements with real subprocess provenance.

The measurement command's zero exit means execution completed. Only acceptance
evaluate decides whether its values satisfy the frozen contract. Unknown values
remain null; neither command can manufacture audiovisual or owner approval.
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

from .acceptance import (
    Evaluator,
    EvidenceError,
    measurement_evidence_from_receipt,
    rational,
)
from .contracts import CHECK_REQUIREMENTS, code_identity
from .project import (
    artifact_ref,
    atomic_json,
    load_project,
    now,
    read_json,
    sha256,
    verified_json,
)


def compute(project_dir: Path, check_id: str, raw_path: Path,
            contract: Path, repo: Path) -> dict[str, Any]:
    """Run against actual registered DGIST inputs; final-master status is separate."""
    if check_id not in CHECK_REQUIREMENTS:
        raise ValueError("Unknown contract measurement")
    project = load_project(project_dir)
    project_hash = sha256(project_dir / "project.json")
    raw_ref = artifact_ref(raw_path)
    index_path = project_dir / "acceptance.local.json"
    evaluator = Evaluator(project_dir, "measurement", contract, repo)
    evaluator.index = read_json(index_path)
    evaluator.load_contract()
    evaluator.load_sources()
    evaluator.source_inspections()
    evaluator.bind_plan_timeline()
    workflow = verified_json(project["active_render"])
    native = verified_json(workflow["native_render"])
    evaluator.require(workflow["output"] == native["output"], "Current output identities differ")
    evaluator.artifact(workflow["output"], json_value=False)
    evaluator.deps["output_hash"] = workflow["output"]["sha256"]
    evaluator.output_domain = (rational("0"), rational(evaluator.timeline["duration"]))
    for ref in evaluator.index.get("capabilities", []):
        try:
            evaluator.load_capability(ref)
        except (EvidenceError, ValueError, OSError, KeyError, TypeError) as exc:
            evaluator.invalid_evidence.append({"ref": ref, "reason": str(exc)})
    for ref in evaluator.index.get("reviews", []):
        evaluator.collect_provider_findings(ref)
        try:
            evaluator.load_review(ref)
        except (EvidenceError, ValueError, OSError, KeyError, TypeError) as exc:
            evaluator.invalid_evidence.append({"ref": ref, "reason": str(exc)})
    measured = evaluator.compute_measurement(check_id, raw_ref)
    evaluator.require(sha256(raw_path) == raw_ref["sha256"], "Raw inputs changed during measurement")
    evaluator.require(sha256(project_dir / "project.json") == project_hash, "Project changed during measurement")
    evaluator.require(code_identity(repo)["code_tree_hash"] == evaluator.identity["code_tree_hash"],
                      "Code changed during measurement")
    evaluator.require(sha256(workflow["output"]["path"]) == evaluator.deps["output_hash"],
                      "Output changed during measurement")
    return {"schema_version": "measurement-result/v1", "check_id": check_id,
            "dependencies": evaluator.deps, "raw_inputs": raw_ref,
            "measurements": measured, "evidence_refs": [raw_ref],
            "invalid_review_evidence": evaluator.invalid_evidence,
            "provider_findings": evaluator.provider_findings,
            "subject_profile": workflow["profile"], "subject_test_only": workflow["test_only"],
            "acceptance_status": "UNVERIFIED", "owner_acceptance": "pending"}


def run_measurement(project_dir: Path, check_id: str, raw_path: Path,
                    contract: Path, repo: Path) -> dict[str, Any]:
    """Capture the actual worker stdout, stderr, exit and immutable result refs."""
    project_dir, raw_path, contract, repo = [Path(p).resolve() for p in (project_dir, raw_path, contract, repo)]
    raw_ref = artifact_ref(raw_path)
    run_id = "measurement-" + uuid4().hex
    directory = project_dir / "measurements" / run_id
    directory.mkdir(parents=True)
    command = [sys.executable, "-m", "talkcut", "acceptance", "measure-worker", str(project_dir),
               "--check", check_id, "--input", str(raw_path), "--contract", str(contract), "--json"]
    before = code_identity(repo)
    started, clock = now(), time.monotonic()
    stdout, stderr = directory / "stdout.json", directory / "stderr.log"
    failure = None
    exit_code = None
    interrupted = False
    process = None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            process = subprocess.Popen(command, cwd=repo, stdout=out, stderr=err, start_new_session=True)
            exit_code = process.wait(timeout=14400)
        except (OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
            interrupted = isinstance(exc, KeyboardInterrupt)
            failure = {"type": type(exc).__name__, "message": str(exc)}
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    exit_code = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    exit_code = process.wait(timeout=10)
    after = code_identity(repo)
    activity = {"command": command, "cwd": str(repo), "started_at": started,
                "finished_at": now(), "wall_seconds": time.monotonic() - clock,
                "exit_code": exit_code, "failure": failure, "before": before, "after": after,
                "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr)}
    log_path = directory / "execution.json"
    atomic_json(log_path, activity)
    result = None
    if (exit_code == 0 and failure is None and not interrupted
            and before["code_tree_hash"] == after["code_tree_hash"]):
        try:
            candidate = read_json(stdout)
            if (candidate.get("schema_version") == "measurement-result/v1"
                    and candidate.get("check_id") == check_id
                    and candidate.get("raw_inputs") == raw_ref
                    and sha256(raw_path) == raw_ref["sha256"]
                    and candidate.get("dependencies", {}).get("code_tree_hash") == before["code_tree_hash"]):
                result = candidate
        except (OSError, ValueError, AttributeError):
            pass
    receipt = {"schema_version": "execution-receipt/v1", "run_id": run_id,
               "operation": f"check:{check_id}", "executor": sys.executable,
               "tool_version": f"talkcut {version('talkcut')}", "command": command,
               "started_at": started, "finished_at": activity["finished_at"],
               "completed": result is not None, "exit_code": exit_code,
               "log": artifact_ref(log_path), "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr),
               "result": artifact_ref(stdout), "input_artifacts": [raw_ref],
               "dependencies": result["dependencies"] if result else {},
               "owner_acceptance": "pending"}
    receipt_path = directory / "receipt.json"
    atomic_json(receipt_path, receipt)
    evidence = measurement_evidence_from_receipt(artifact_ref(receipt_path), directory / "evidence.json") if result else None
    response = {"schema_version": "measurement-run/v1", "status": "MEASURED" if result else "FAIL",
                "interrupted": interrupted,
                "run_id": run_id, "receipt": artifact_ref(receipt_path), "evidence": evidence,
                "measurements": result["measurements"] if result else None,
                "acceptance_status": "UNVERIFIED", "owner_acceptance": "pending",
                "reason": "Run acceptance evaluate to verify the complete frozen contract; measurement execution is not readiness"}
    atomic_json(directory / "run.json", response)
    return response
