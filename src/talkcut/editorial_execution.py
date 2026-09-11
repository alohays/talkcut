"""Capture a local editorial verification command and index its immutable result.

This receipt describes local verification only. Original provider executions and
current separate audiovisual reviews remain mandatory on every replay.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

from .contracts import code_identity
from .editorial_binding import require, verify_editorial_inputs
from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    now,
    project_lock,
    read_json,
    sha256,
    verified_json,
)
from .review import register_review_import


def executor_identity(executor: str) -> dict[str, Any]:
    """Measure the interpreter actually used by this local worker route."""
    require(
        isinstance(executor, str) and Path(executor).is_absolute(),
        "Actual editorial executor path is invalid",
    )
    try:
        invoked = Path(executor)
        resolved = invoked.resolve(strict=True)
        current = Path(sys.executable).resolve(strict=True)
        require(
            resolved == current and resolved.is_file() and os.access(invoked, os.X_OK),
            "Actual editorial executor is not this runtime interpreter",
        )
        before = resolved.stat()
        digest = sha256(resolved)
        after = resolved.stat()
        require(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "Actual editorial executor changed while hashing",
        )
    except (OSError, RuntimeError) as exc:
        raise TalkCutError(
            "EDITORIAL_BINDING_UNVERIFIED", "Actual editorial executor is unavailable"
        ) from exc
    return {
        "invoked_path": executor,
        "resolved_path": str(resolved),
        "sha256": digest,
        "bytes": after.st_size,
        "device": after.st_dev,
        "inode": after.st_ino,
        "python_version": sys.version,
        "tool_version": f"talkcut {version('talkcut')}",
    }


def worker_command(
    project_dir: Path,
    snapshot: dict[str, Any],
    reviews: list[dict[str, Any]],
    audit: dict[str, Any] | None,
    executor: str,
) -> list[str]:
    command = [
        executor,
        "-m",
        "talkcut",
        "editorial-worker",
        str(project_dir.resolve()),
        "--snapshot",
        snapshot["path"],
    ]
    for ref in reviews:
        command += ["--review-import", ref["path"]]
    if audit is not None:
        command += ["--no-safe-cuts-audit", audit["path"]]
    return [*command, "--json"]


def verify_editorial_execution(
    binding: dict[str, Any], result: dict[str, Any], project_dir: Path, repo_root: Path
) -> None:
    receipt = verified_json(binding["receipt"])
    execution = verified_json(receipt["log"])
    require(
        receipt.get("schema_version") == "execution-receipt/v1"
        and receipt.get("operation") == "editorial_binding"
        and receipt.get("completed") is True
        and type(receipt.get("exit_code")) is int
        and receipt["exit_code"] == 0
        and receipt.get("owner_acceptance") == "pending"
        and not any(receipt.get(k) for k in ("test_only", "synthetic", "mock")),
        "Actual successful local editorial verification receipt is missing",
    )
    require(
        not any(
            k in receipt
            for k in ("provider_request_id", "model_revision", "composite_graph")
        ),
        "Local editorial verification cannot substitute for a provider execution",
    )
    require(
        receipt.get("dependencies") == result["dependencies"],
        "Editorial receipt dependency mismatch",
    )
    require(
        receipt.get("executor") == sys.executable,
        "Editorial receipt executor was not invoked through this runtime path",
    )
    actual_executor = executor_identity(receipt.get("executor"))
    require(
        receipt.get("executor_identity")
        == execution.get("executor_before")
        == execution.get("executor_after")
        == actual_executor
        and receipt.get("tool_version") == actual_executor["tool_version"],
        "Actual local executor identity or version changed",
    )
    expected = worker_command(
        project_dir,
        result["snapshot"],
        result["review_imports"],
        result["no_safe_cuts_audit"],
        actual_executor["invoked_path"],
    )
    require(
        receipt.get("command") == execution.get("command") == expected,
        "Editorial receipt does not describe the bound worker inputs",
    )
    require(
        execution.get("schema_version") == "editorial-process/v1"
        and execution.get("run_id") == receipt.get("run_id")
        and receipt.get("run_id")
        and execution.get("cwd") == str(repo_root.resolve())
        and type(execution.get("exit_code")) is int
        and execution["exit_code"] == 0
        and execution.get("failure") is None,
        "Editorial process did not successfully execute the recorded command",
    )
    for key in ("started_at", "finished_at", "stdout", "stderr"):
        require(
            receipt.get(key) == execution.get(key),
            "Editorial process receipt differs from capture",
        )
    started, finished = (
        datetime.fromisoformat(receipt[k]) for k in ("started_at", "finished_at")
    )
    require(
        started.tzinfo is not None
        and finished.tzinfo is not None
        and finished >= started,
        "Editorial execution clock is incomplete or reversed",
    )
    current_code = code_identity(repo_root)["code_tree_hash"]
    require(
        execution.get("before", {}).get("code_tree_hash")
        == execution.get("after", {}).get("code_tree_hash")
        == result["dependencies"]["code_tree_hash"]
        == current_code,
        "Code changed during or after editorial verification",
    )
    require(
        binding["verification"] == receipt.get("result") == receipt.get("stdout")
        and verified_json(receipt["stdout"]) == result,
        "Editorial verification is not the captured actual stdout",
    )
    require(
        artifact_ref(receipt["stderr"]["path"]) == receipt["stderr"],
        "Editorial stderr bytes changed",
    )


def run_editorial(
    project_dir: Path,
    snapshot: dict[str, Any],
    reviews: list[dict[str, Any]],
    audit: dict[str, Any] | None,
    repo_root: Path,
) -> tuple[dict[str, Any], int]:
    project_dir, repo_root = project_dir.resolve(), repo_root.resolve()
    run_id = "editorial-execution-" + uuid4().hex
    directory = project_dir / "executions" / run_id
    directory.mkdir(parents=True)
    stdout, stderr = directory / "stdout.json", directory / "stderr.log"
    executor_before = executor_identity(sys.executable)
    command = worker_command(
        project_dir, snapshot, reviews, audit, executor_before["invoked_path"]
    )
    before, project_hash = (
        code_identity(repo_root),
        sha256(project_dir / "project.json"),
    )
    started, clock = now(), time.monotonic()
    failure, exit_code = None, None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            process = subprocess.run(
                command,
                cwd=repo_root,
                stdout=out,
                stderr=err,
                timeout=14460,
                check=False,
            )
            exit_code = process.returncode
        except (OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
            failure = {"type": type(exc).__name__, "message": str(exc)}
    try:
        executor_after = executor_identity(sys.executable)
    except TalkCutError as exc:
        executor_after = None
        failure = failure or {"type": type(exc).__name__, "message": str(exc)}
    execution = {
        "schema_version": "editorial-process/v1",
        "executor_before": executor_before,
        "executor_after": executor_after,
        "run_id": run_id,
        "command": command,
        "cwd": str(repo_root),
        "started_at": started,
        "finished_at": now(),
        "wall_seconds": time.monotonic() - clock,
        "exit_code": exit_code,
        "failure": failure,
        "before": before,
        "after": code_identity(repo_root),
        "stdout": artifact_ref(stdout),
        "stderr": artifact_ref(stderr),
    }
    log = directory / "execution.json"
    atomic_json(log, execution)
    try:
        require(
            failure is None and type(exit_code) is int and exit_code == 0,
            "Editorial verification worker failed or was interrupted",
        )
        result = read_json(stdout)
        require(
            result
            == verify_editorial_inputs(
                project_dir, snapshot, reviews, audit, repo_root
            ),
            "Actual worker result differs from current editorial verification",
        )
        receipt = {
            "schema_version": "execution-receipt/v1",
            "run_id": run_id,
            "operation": "editorial_binding",
            "executor": executor_before["invoked_path"],
            "executor_identity": executor_before,
            "tool_version": executor_before["tool_version"],
            "command": command,
            "started_at": started,
            "finished_at": execution["finished_at"],
            "completed": True,
            "exit_code": exit_code,
            "test_only": False,
            "log": artifact_ref(log),
            "stdout": artifact_ref(stdout),
            "stderr": artifact_ref(stderr),
            "result": artifact_ref(stdout),
            "dependencies": result["dependencies"],
            "owner_acceptance": "pending",
        }
        receipt_path = directory / "receipt.json"
        atomic_json(receipt_path, receipt)
        binding = {
            "schema_version": "editorial-binding/v1",
            "verification": artifact_ref(stdout),
            "receipt": artifact_ref(receipt_path),
            "owner_acceptance": "pending",
        }
        verify_editorial_execution(binding, result, project_dir, repo_root)
        # Reuse final evaluation's actual capability and current review authority.
        for ref in reviews:
            register_review_import(project_dir, ref, repo_root)
        with project_lock(project_dir):
            require(
                sha256(project_dir / "project.json") == project_hash,
                "Project changed while editorial evidence was revalidated",
            )
            require(
                code_identity(repo_root)["code_tree_hash"] == before["code_tree_hash"],
                "Code changed while editorial evidence was indexed",
            )
            index_path = project_dir / "acceptance.local.json"
            index = read_json(index_path)
            require(
                index.get("schema_version") == "acceptance-index/v1"
                and index.get("owner_acceptance", "pending") == "pending",
                "Existing acceptance index is invalid",
            )
            require(
                index.get("timeline") == result["timeline"],
                "Indexed timeline differs from current editorial output",
            )
            indexed_render = verified_json(index.get("render"))
            require(
                indexed_render.get("output") == result["output"]
                and indexed_render.get("dependencies") == result["dependencies"],
                "Indexed render receipt differs from current editorial output",
            )
            atomic_json(directory / "acceptance-before.json", index)
            binding_path = directory / "binding.json"
            atomic_json(binding_path, binding)
            index.update(
                analysis=result["analysis"],
                editorial=artifact_ref(binding_path),
                edit_disposition=result["edit_disposition"],
            )
            atomic_json(index_path, index)
        return {
            "schema_version": "editorial-operation/v1",
            "status": "INDEXED",
            "editorial": artifact_ref(binding_path),
            "execution": artifact_ref(log),
            "edit_disposition": result["edit_disposition"],
            "acceptance_status": "UNVERIFIED",
            "owner_acceptance": "pending",
        }, 0
    except (TalkCutError, OSError, ValueError, KeyError, TypeError) as exc:
        rejected = {
            "schema_version": "editorial-execution-failure/v1",
            "status": "FAIL",
            "reason": str(exc),
            "execution": artifact_ref(log),
            "acceptance_status": "UNVERIFIED",
            "owner_acceptance": "pending",
        }
        atomic_json(directory / "failure.json", rejected)
        return rejected, 1
