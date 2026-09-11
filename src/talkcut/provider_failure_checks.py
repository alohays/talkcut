"""Actual-positive -> fixed counterfactual import -> unchanged-positive recovery.

These optional controls execute no models. A genuine, current review import and
all original source/output subjects are mandatory. Fixed injections are labelled
transport/content tests, never provider-returned bytes or account exhaustion.
The verifier replays imports; it never executes a command supplied by evidence.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any
from uuid import uuid4

from .acceptance import Evaluator, EvidenceError
from .contracts import code_identity
from .measurement_checks import _file, _json, _require
from .project import TalkCutError, artifact_ref, atomic_json, now, read_json
from .review import (
    PROVIDER_CONTROL_FAULTS,
    import_review,
    verify_imported_review,
)

DEPENDENCIES = {"source_hashes", "contract_hash", "code_tree_hash", "timeline_hash", "output_hash"}
STALE_CONTROL_REASON = "Counterfactual/test-only import cannot authorize an actual review"


def _subjects(subjects: dict[str, Any], dependencies: dict[str, Any]) -> None:
    _require(set(subjects) == {"sources", "output", "contract", "timeline"},
             "Exact source/output/contract/timeline control subjects required")
    _require(DEPENDENCIES.issubset(dependencies), "Current control dependencies missing")
    sources = subjects["sources"]
    _require(isinstance(sources, dict) and bool(sources)
             and set(sources) == set(dependencies["source_hashes"]),
             "Complete source control denominator required")
    for role, ref in sources.items():
        _file(ref)
        _require(ref["sha256"] == dependencies["source_hashes"][role], "Control source is stale")
    for name in ("output", "contract", "timeline"):
        _file(subjects[name])
        _require(subjects[name]["sha256"] == dependencies[name + "_hash"],
                 f"Control {name} is stale")


def _closure(*roots: Any) -> list[dict[str, Any]]:
    """Retain every reachable hashed file; cycles do not shrink the inventory.

    JSON references are traversed regardless of parent schema. Binary files,
    including original PNG/PCM/provider JSONL, are hashed in full. Exceeding the
    explicit traversal bounds fails closed, rather than omitting references.
    """
    pending = list(roots)
    seen: dict[str, dict[str, Any]] = {}
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            pending.extend(value.values())
            if "path" not in value or "sha256" not in value:
                continue
            path = _file(value)
            key = str(path.resolve())
            if key in seen:
                _require(seen[key]["sha256"] == value["sha256"], "Conflicting original reference")
                continue
            seen[key] = artifact_ref(path)
            _require(len(seen) <= 20000, "Control reference inventory exceeds bound")
            if path.suffix == ".json":
                _require(path.stat().st_size <= 128 * 1024 * 1024,
                         "Control JSON inventory exceeds bound")
                pending.append(_json(value))
    return [seen[key] for key in sorted(seen)]


def _snapshot(refs: list[dict[str, Any]], repo: Path) -> dict[str, Any]:
    for ref in refs:
        _file(ref)
    return {"code_tree_hash": code_identity(repo)["code_tree_hash"],
            "files": [artifact_ref(ref["path"]) for ref in refs]}


def _positive(positive: dict[str, Any], dependencies: dict[str, Any], directory: Path,
              *, repo_root: Path, contract_ref: dict[str, Any]) -> dict[str, Any]:
    imported = _json(positive)
    _require(imported.get("status") == "PASS" and "control" not in imported
             and imported.get("owner_acceptance") == "pending"
             and not any(imported.get(flag) for flag in ("mock", "synthetic", "test_only")), "Unchanged successful actual positive required")
    for name in ("record", "request", "capability"):
        value = _json(imported.get("artifact_refs", {}).get(name))
        _require(not any(value.get(flag) for flag in ("mock", "synthetic", "test_only")),
                 "Synthetic/mock positive cannot supply provider controls")
    directory.mkdir(parents=True)
    copied = directory / "positive.original.json"
    shutil.copyfile(_file(positive), copied)
    _require(artifact_ref(copied)["sha256"] == positive["sha256"], "Positive copy differs")
    proof = verify_imported_review(artifact_ref(copied))
    for name in ("record", "request", "capability", "receipt"):
        _require(not any(proof[name].get(flag) for flag in ("mock", "synthetic", "test_only")),
                 "Synthetic/mock positive cannot supply provider controls")
    evaluator = Evaluator(directory, "provider-control", _file(contract_ref), repo_root)
    evaluator.deps = dependencies.copy()
    # Reuse the full current capability production gate, including exact
    # receipt code/contract binds, modalities and actual sampling limits.
    evaluator.load_capability(imported["artifact_refs"]["capability"])
    for name in ("record", "request", "receipt"):
        recorded = proof[name].get("dependencies", {})
        _require(all(recorded.get(key) == value for key, value in dependencies.items()),
                 "Positive control dependencies are stale")
    _require(proof["import"]["coverage"] == proof["response"]["observed_intervals"]
             and bool(proof["import"]["coverage"]), "Positive has no verified media coverage")
    return proof


def _stale_refusal(ref: dict[str, Any], directory: Path) -> dict[str, Any]:
    try:
        verify_imported_review(ref)
    except TalkCutError as exc:
        result = {"refused": str(exc) == STALE_CONTROL_REASON, "reason": str(exc), "code": exc.code}
    else:
        result = {"refused": False, "reason": "Injected import was promoted"}
    path = directory / ("stale-refusal-" + uuid4().hex + ".json")
    atomic_json(path, result)
    return {**result, "artifact_ref": artifact_ref(path)}


def _case(kind: str, positive: dict[str, Any], dependencies: dict[str, Any],
          directory: Path, refs: list[dict[str, Any]], repo: Path,
          before: dict[str, Any], contract_ref: dict[str, Any]) -> dict[str, Any]:
    proof = _positive(positive, dependencies, directory / "positive",
                      repo_root=repo, contract_ref=contract_ref)
    original = _json(positive)["artifact_refs"]
    fault = import_review(original["record"]["path"], original["request"]["path"],
                          original["capability"]["path"], directory / "fault", control_fault=kind)
    control = fault.get("control", {})
    _require(fault["status"] == "UNVERIFIED" and fault["coverage"] == []
             and fault["owner_acceptance"] == "pending"
             and control.get("test_only") is True and control.get("counterfactual") is True
             and control.get("actual_provider_outcome") is False
             and control.get("boundary_reached") is True
             and control.get("intended_rejection") is True,
             "Provider fault missed its intended production rejection")
    after_fault = _snapshot(refs, repo)
    _require(before == after_fault, "Original source/output/success/code changed during fault")
    stale_before = _stale_refusal(fault["artifact_ref"], directory)
    _require(stale_before["refused"], "Injected import was usable as stale approval")
    recovery = _positive(positive, dependencies, directory / "recovery",
                         repo_root=repo, contract_ref=contract_ref)
    _require(recovery["response"] == proof["response"]
             and recovery["import"]["coverage"] == proof["import"]["coverage"],
             "Unchanged positive did not recover its original observations/coverage")
    stale_after = _stale_refusal(fault["artifact_ref"], directory)
    _require(stale_after["refused"], "Recovery incorrectly promoted the old failed import")
    after_recovery = _snapshot(refs, repo)
    _require(before == after_recovery, "Original source/output/success/code changed during recovery")
    result = {"kind": kind, "positive": proof["import"]["artifact_ref"],
              "fault": fault["artifact_ref"], "recovery": recovery["import"]["artifact_ref"],
              "stale_before": stale_before["artifact_ref"], "stale_after": stale_after["artifact_ref"],
              "after_fault": after_fault, "after_recovery": after_recovery,
              "resume_from": positive, "intended_rejection": True, "recovery_verified": True,
              "test_only": True, "counterfactual": True, "actual_provider_outcome": False,
              "status": "UNVERIFIED", "coverage": [], "owner_acceptance": "pending"}
    path = directory / "case.json"
    atomic_json(path, result)
    return artifact_ref(path)


def run_provider_failure_controls(positive: dict[str, Any], *, subjects: dict[str, Any],
                                  dependencies: dict[str, Any], repo_root: Path,
                                  output_dir: Path) -> dict[str, Any]:
    """Optional producer. Missing/unverified positives never yield control credit."""
    directory = Path(output_dir).resolve() / ("provider-controls-" + uuid4().hex)
    if isinstance(positive, dict) and isinstance(positive.get("path"), str):
        _require(not directory.is_relative_to(Path(positive["path"]).resolve().parent),
                 "Control artifacts must be outside the original positive directory")
    directory.mkdir(parents=True)
    result: dict[str, Any] = {"schema_version": "provider-failure-run/v1",
        "positive": positive, "subjects": subjects, "dependencies": dependencies,
        "repo_root": str(Path(repo_root).resolve()), "started_at": now(),
        "before": None, "after": None, "cases": {}, "error": None,
        "measurements": dict.fromkeys(PROVIDER_CONTROL_FAULTS),
        "controls_executed": False, "test_only": True, "counterfactual": True,
        "actual_provider_outcome": False, "status": "UNVERIFIED", "owner_acceptance": "pending"}
    try:
        _subjects(subjects, dependencies)
        for name in ("review.py", "provider_failure_checks.py", "failure_checks.py"):
            _require(artifact_ref(Path(__file__).parent / name)["sha256"]
                     == artifact_ref(Path(repo_root) / "src" / "talkcut" / name)["sha256"],
                     "Loaded provider control implementation differs from control repository")
        refs = _closure(positive, subjects)
        before = _snapshot(refs, repo_root)
        result["before"] = before
        _require(before["code_tree_hash"] == dependencies["code_tree_hash"], "Control code is stale")
        # No synthetic JUnit or caller boolean can stand in for this import.
        _positive(positive, dependencies, directory / "initial-positive",
                  repo_root=repo_root, contract_ref=subjects["contract"])
        for kind in PROVIDER_CONTROL_FAULTS:
            result["cases"][kind] = _case(kind, positive, dependencies, directory / kind,
                                          refs, repo_root, before, subjects["contract"])
        result["after"] = _snapshot(refs, repo_root)
        _require(result["after"] == before, "Original control inventory changed")
        result.update(controls_executed=True, measurements=dict.fromkeys(PROVIDER_CONTROL_FAULTS, True))
    except (TalkCutError, EvidenceError, ValueError, TypeError, KeyError, OSError,
            subprocess.SubprocessError, KeyboardInterrupt) as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
    result["finished_at"] = now()
    path = directory / "run.json"
    atomic_json(path, result)
    return {**result, "artifact_ref": artifact_ref(path)}


def _retained_import(ref: dict[str, Any], original: dict[str, Any], *, fault: bool) -> dict[str, Any]:
    value = _json(ref)
    _require(value.get("schema_version") == "review-import/v1"
             and value.get("owner_acceptance") == "pending"
             and set(value.get("artifact_refs", {})) == {"record", "request", "capability"},
             "Retained import envelope differs")
    for name in ("record", "request", "capability"):
        actual = value["artifact_refs"][name]
        _file(actual)
        _require(actual["sha256"] == original[name]["sha256"], "Retained import changed provider inputs")
    if fault:
        control = value.get("control", {})
        _require(value.get("status") == "UNVERIFIED" and value.get("coverage") == []
                 and control.get("test_only") is True and control.get("counterfactual") is True
                 and control.get("actual_provider_outcome") is False
                 and control.get("boundary_reached") is True
                 and control.get("intended_rejection") is True
                 and control.get("gate_content_valid") is False,
                 "Retained failed import was promoted or lost")
        _file(control.get("injected_artifact"))
    else:
        _require(value.get("status") == "PASS" and "control" not in value
                 and bool(value.get("coverage")), "Retained positive/recovery did not succeed")
    return value


def verify_provider_failure_controls(ref: dict[str, Any], *, dependencies: dict[str, Any],
                                     repo_root: Path, output_dir: Path) -> dict[str, Any]:
    """Read every retained control, then regenerate all fixed faults and recovery."""
    run = _json(ref)
    _require(run.get("schema_version") == "provider-failure-run/v1"
             and run.get("test_only") is True and run.get("counterfactual") is True
             and run.get("actual_provider_outcome") is False
             and run.get("status") == "UNVERIFIED" and run.get("owner_acceptance") == "pending",
             "Typed counterfactual provider control run required")
    _require(run.get("controls_executed") is True and run.get("error") is None
             and run.get("dependencies") == dependencies
             and run.get("repo_root") == str(Path(repo_root).resolve()),
             "Provider controls absent, stale or unsuccessful")
    _require(set(run["cases"]) == set(PROVIDER_CONTROL_FAULTS)
             and run["measurements"] == dict.fromkeys(PROVIDER_CONTROL_FAULTS, True),
             "Provider control denominator or measurements differ")
    refs = _closure(run["positive"], run["subjects"])
    _require(_snapshot(refs, repo_root) == run["before"] == run["after"],
             "Provider originals changed or conservation proof differs")
    original = _json(run["positive"])["artifact_refs"]
    retained_faults = {}
    for kind, case_ref in run["cases"].items():
        case = _json(case_ref)
        _closure(case_ref)
        _require(case.get("kind") == kind and case.get("resume_from") == run["positive"]
                 and case.get("intended_rejection") is True and case.get("recovery_verified") is True
                 and case.get("after_fault") == case.get("after_recovery") == run["before"],
                 "Provider case/recovery record differs")
        fault = _retained_import(case["fault"], original, fault=True)
        retained_faults[kind] = fault["control"]
        _require(fault.get("status") == "UNVERIFIED" and fault.get("coverage") == []
                 and fault.get("control", {}).get("kind") == kind
                 and fault["control"].get("intended_rejection") is True,
                 "Retained failed import was promoted or lost")
        for name in ("positive", "recovery"):
            _retained_import(case[name], original, fault=False)
        for name in ("stale_before", "stale_after"):
            _require(_json(case[name]) == {"refused": True, "reason": STALE_CONTROL_REASON,
                                          "code": "REVIEW_UNVERIFIED"}, "Stale control refusal differs")
    repeated = run_provider_failure_controls(run["positive"], subjects=run["subjects"],
                    dependencies=dependencies, repo_root=repo_root, output_dir=output_dir)
    _require(repeated["controls_executed"] is True and repeated["measurements"] == run["measurements"],
             "Actual unchanged-positive/fault/recovery replay did not complete")
    for kind, retained in retained_faults.items():
        repeated_case = _json(repeated["cases"][kind])
        replayed = _json(repeated_case["fault"])["control"]
        keys = {"kind", "boundary", "original_response", "error_code", "gate_content_valid"}
        _require(all(retained.get(key) == replayed.get(key) for key in keys)
                 and retained["injected_artifact"]["sha256"] == replayed["injected_artifact"]["sha256"],
                 "Retained fault differs from deterministic production replay")
        if kind not in {"empty_review", "truncated_review"}:
            _require(retained["reason"] == replayed["reason"], "Retained intended gate reason differs")
    _file(ref)
    return repeated["measurements"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = read_json(args.input)
    _require(set(raw) == {"schema_version", "positive", "subjects", "dependencies"}
             and raw["schema_version"] == "provider-failure-input/v1",
             "Closed provider failure producer input required")
    result = run_provider_failure_controls(raw["positive"], subjects=raw["subjects"],
                    dependencies=raw["dependencies"], repo_root=args.repo, output_dir=args.output)
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if result["controls_executed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
