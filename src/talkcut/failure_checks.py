"""Execute the fixed, observable filesystem/render failure controls.

``failure-input/v1`` contains ``run`` (a failure-run/v1 artifact reference).
The actual FFmpeg controls include interruption, timeout, invalid encoder argv,
and injected ENOSPC at atomic promotion after successful full output validation.
The ENOSPC control is a syscall fault injection, not a claim to fill a disk.
Provider-specific cases remain unknown without an actual valid provider control.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from uuid import uuid4

from .contracts import CHECK_REQUIREMENTS, code_identity
from .measurement_checks import _file, _json, _require
from .project import TalkCutError, artifact_ref, atomic_json, now

TARGETS = (
    "tests/test_render_recovery.py::test_actual_sigint_preserves_partial_and_success_then_retry",
    "tests/test_render_recovery.py::test_actual_failed_runs_preserve_success_and_retry",
    "tests/test_project.py::test_source_replacement_is_not_valid_cache",
    "tests/test_project.py::test_revision_conflict_preserves_event_chain",
    "tests/test_project.py::test_corrupt_json_and_unknown_major_rejected",
    "tests/test_plan_adversarial.py::test_cache_rejects_valid_hash_from_wrong_render",
)


def _measure(junit: Path) -> dict[str, Any]:
    tree = ET.parse(junit).getroot()
    suites = [tree] if tree.tag == "testsuite" else tree.findall("testsuite")
    nodes = tree.findall(".//testcase")
    _require(nodes and all(int(s.get("errors", "0")) == 0 and int(s.get("failures", "0")) == 0
                           and int(s.get("skipped", "0")) == 0 for s in suites),
             "Failure controls had errors, failures or skipped cases")
    _require(all(not list(n) or all(child.tag not in {"failure", "error", "skipped"} for child in n) for n in nodes),
             "A failure control did not pass")
    identities = [(n.get("classname"), n.get("name")) for n in nodes]
    _require(len(set(identities)) == len(identities) and all(a and b for a, b in identities),
             "Failure control test identities are missing or duplicated")
    names = {n.get("name", "") for n in nodes}
    def required(name: str) -> bool:
        return name in names
    renderer_cases = {
        "sigint": required("test_actual_sigint_preserves_partial_and_success_then_retry"),
        "timeout": required("test_actual_failed_runs_preserve_success_and_retry[timeout]"),
        "subprocess_failure": required("test_actual_failed_runs_preserve_success_and_retry[subprocess_failure]"),
        "disk_full": required("test_actual_failed_runs_preserve_success_and_retry[disk_full_promotion]"),
    }
    expected = {
        "test_actual_sigint_preserves_partial_and_success_then_retry",
        *(f"test_actual_failed_runs_preserve_success_and_retry[{kind}]" for kind in
          ("timeout", "subprocess_failure", "disk_full_promotion")),
        "test_source_replacement_is_not_valid_cache",
        "test_revision_conflict_preserves_event_chain",
        "test_corrupt_json_and_unknown_major_rejected",
        *(f"test_cache_rejects_valid_hash_from_wrong_render[{kind}]" for kind in
          ("foreign_timeline", "foreign_settings", "foreign_profile")),
    }
    _require(names == expected and len(nodes) == len(expected),
             "Failure controls differ from the complete fixed control set")
    values: dict[str, Any] = {key: None for key in CHECK_REQUIREMENTS["failure_injection"]}
    values.update(renderer_cases)
    values.update({
        "source_replacement": required("test_source_replacement_is_not_valid_cache"),
        "concurrent_revision": required("test_revision_conflict_preserves_event_chain"),
        "corrupt_json": required("test_corrupt_json_and_unknown_major_rejected"),
        "stale_cache": any(n.startswith("test_cache_rejects_valid_hash_from_wrong_render[") for n in names),
        **{key: all(renderer_cases.values()) for key in ("partial_not_promoted", "previous_success_preserved", "source_unchanged", "resume_verified")},
    })
    _require(all(v is not False for v in values.values()), "Required fixed filesystem/render control is absent")
    return values


def run_failure_checks(repo_root: Path, output_dir: Path) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    run_id = "failures-" + uuid4().hex
    directory = Path(output_dir).resolve() / run_id
    directory.mkdir(parents=True)
    before = code_identity(root)
    tests = [artifact_ref(root / name) for name in sorted({target.split("::")[0] for target in TARGETS})]
    stdout, stderr, junit = directory / "stdout.log", directory / "stderr.log", directory / "junit.xml"
    command = [sys.executable, "-m", "pytest", *TARGETS, "-q", "--junitxml", str(junit), "--basetemp", str(directory / "fixtures")]
    started, clock = now(), time.monotonic()
    process = None
    execution_failure = None
    returncode = None
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            process = subprocess.Popen(command, cwd=root, stdout=out, stderr=err, start_new_session=True)
            returncode = process.wait(timeout=600)
        except (OSError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
            execution_failure = {"type": type(exc).__name__, "message": str(exc)}
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    returncode = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    returncode = process.wait(timeout=10)
    after = code_identity(root)
    error = None
    values: dict[str, Any] = {key: None for key in CHECK_REQUIREMENTS["failure_injection"]}
    try:
        _require(execution_failure is None and returncode == 0, "Actual fault-control subprocess failed")
        _require(before["code_tree_hash"] == after["code_tree_hash"], "Code changed during failure controls")
        values = _measure(junit)
    except (TalkCutError, ValueError, OSError, ET.ParseError) as exc:
        error = str(exc)
    receipt = {"schema_version": "failure-run/v1", "run_id": run_id, "repo_root": str(root),
               "before": before, "after": after, "test_files": tests, "command": command,
               "started_at": started, "finished_at": now(), "wall_seconds": time.monotonic() - clock,
               "exit_code": returncode, "execution_failure": execution_failure,
               "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr),
               "junit": artifact_ref(junit) if junit.exists() else None, "measurements": values, "error": error,
               "technical_controls_executed": error is None, "status": "UNVERIFIED",
               "provider_control": "UNVERIFIED", "owner_acceptance": "pending"}
    path = directory / "run.json"
    atomic_json(path, receipt)
    return {**receipt, "artifact_ref": artifact_ref(path)}


def verify_failure_checks(raw: dict[str, Any], repo_root: Path, output_dir: Path) -> dict[str, Any]:
    _require(raw.get("schema_version") == "failure-input/v1", "Typed failure inputs missing")
    run = _json(raw.get("run"))
    _require(run.get("schema_version") == "failure-run/v1", "Actual failure control run missing")
    identity = code_identity(repo_root)
    _require(run["before"]["code_tree_hash"] == run["after"]["code_tree_hash"] == identity["code_tree_hash"],
             "Failure controls are stale")
    _require(run.get("technical_controls_executed") is True and run.get("exit_code") == 0, "Fault controls did not execute")
    _require(Path(run["repo_root"]).resolve() == Path(repo_root).resolve(), "Wrong control repository")
    for ref in run["test_files"]:
        _file(ref)
    _file(run["stdout"])
    _file(run["stderr"])
    measured = _measure(_file(run["junit"]))
    _require(run["measurements"] == measured, "Hand-entered failure measurement differs from actual JUnit")
    # Re-run the fixed controls instead of trusting test count or copied PASS.
    repeated = run_failure_checks(repo_root, output_dir)
    _require(repeated["technical_controls_executed"] is True and repeated["measurements"] == measured,
             "Actual failure control replay disagrees with claimed behavior")
    return measured
