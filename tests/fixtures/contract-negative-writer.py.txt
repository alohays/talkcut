"""Executed negative controls for the frozen evaluator, never an AV approval.

Every supported case has a successful technical fixture control and a specific
mutation. The verifier replays a fixed, read-only probe over the preserved
inputs; it never executes a command supplied by an evidence author. The three
cases needing an unavailable legitimate editorial/reviewer control stay null.

The timeline controls stop at the render-artifact boundary with a sentinel.
They test the production conservation checks without inventing a successful
master or provider receipt. Cancelled-file checks exercise actual full decode.
These scopes do not establish real DGIST acceptance, AI review or AC12.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from uuid import uuid4

from talkcut.acceptance import Evaluator, EvidenceError, coverage, exit_code, serialized
from talkcut.contracts import (
    CHECK_REQUIREMENTS,
    CRITERIA,
    code_identity,
    expected_contract,
)
from talkcut.media import doctor, frame_inventory, probe
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    load_project,
    sha256,
)
from talkcut.render import RenderError, validate_render

MISSING_CONTROLS = {
    "transcript_only": "No legitimate executed audiovisual reviewer positive control is available.",
    "always_keep": "Authored policy labels cannot supply the missing executed editorial positive control.",
    "fabricated_pass": "No legitimate complete reviewer/actor acceptance ledger positive control is available.",
}
SCOPES = {
    "duplicate_coverage": "production interval-union arithmetic on an explicit 90-second fixture",
    "wrong_hashes": "actual CLI source identity and production output artifact hash checks",
    "hidden_deletion": "production timeline conservation before the render-artifact boundary",
    "sample_export": "production full-source domain check before the render-artifact boundary",
    "threshold_tamper": "production frozen contract validation for numeric, required and blocker limits",
    "error_exit_nonzero": "actual CLI malformed-project error exit plus isolated evaluator exit-status mapping fixtures",
    "renamed_partial": "production full decode of a genuinely interrupted MP4 copy renamed to .mp4",
}
PAIR_NAMES = {
    "duplicate_coverage": ("repeated_window",),
    "wrong_hashes": ("source_bytes", "output_bytes"),
    "hidden_deletion": ("omitted_ledger",),
    "sample_export": ("short_domain",),
    "threshold_tamper": ("numeric_limit", "required_flag", "blocker_limit"),
    "error_exit_nonzero": (
        "malformed_project",
        "failed_status",
        "skipped_criterion",
        "missing_criterion",
    ),
    "renamed_partial": ("interrupted_copy",),
}
REASONS = {
    "duplicate_coverage": "Uncovered fixture interval",
    "wrong_hashes.source_bytes": "SOURCE_CHANGED",
    "wrong_hashes.output_bytes": "Stale or changed artifact",
    "hidden_deletion": "Actual source deletions differ from explicit deletion ledger",
    "sample_export": "Timeline drops or invents part of the measured screen source",
    "threshold_tamper": "Frozen machine contract differs",
    "error_exit_nonzero": "INVALID_ARTIFACT",
    "error_exit_nonzero.failed_status": "Evaluator report is not complete PASS",
    "error_exit_nonzero.skipped_criterion": "Evaluator report is not complete PASS",
    "error_exit_nonzero.missing_criterion": "Evaluator report is not complete PASS",
    "renamed_partial": "Output full decode failed",
}
SOURCE_MUTATION = b"\nTALKCUT_SYNTHETIC_NEGATIVE_SOURCE_MUTATION\n"
MALFORMED_PROJECT = b'{"schema_version":'


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _require(condition: Any, reason: str) -> None:
    if not condition:
        raise TalkCutError("NEGATIVE_EVIDENCE_UNVERIFIED", reason)


def _file(ref: Any) -> Path:
    _require(
        isinstance(ref, dict) and ref.get("path") and ref.get("sha256"),
        "Hashed artifact required",
    )
    path = Path(ref["path"])
    _require(path.is_absolute() and path.is_file(), "Preserved artifact is missing")
    _require(sha256(path) == ref["sha256"], "Preserved artifact bytes changed")
    if "bytes" in ref:
        _require(path.stat().st_size == ref["bytes"], "Preserved artifact size changed")
    return path


def _json(ref: Any) -> Any:
    return json.loads(_file(ref).read_text())


def _save(path: Path, value: Any) -> dict[str, str]:
    _require(
        not path.exists(), "Negative evidence is immutable; choose a fresh directory"
    )
    atomic_json(path, value)
    return artifact_ref(path)


def _execute(
    argv: list[str], directory: Path, name: str, repo: Path, timeout: float = 1200
) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    out, err = directory / f"{name}.stdout.json", directory / f"{name}.stderr.log"
    started, monotonic = _now(), time.monotonic()
    timed_out = False
    env = {**os.environ, "PYTHONPATH": str(repo / "src")}
    with out.open("xb") as stdout, err.open("xb") as stderr:
        process = subprocess.Popen(
            argv, cwd=repo, env=env, stdout=stdout, stderr=stderr
        )
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            code, timed_out = process.wait(timeout=30), True
    value = {
        "schema_version": "negative-process/v1",
        "argv": argv,
        "cwd": str(repo),
        "started_at": started,
        "finished_at": _now(),
        "wall_seconds": time.monotonic() - monotonic,
        "exit_code": code,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "stdout": artifact_ref(out),
        "stderr": artifact_ref(err),
    }
    _save(directory / f"{name}.execution.json", value)
    return value


def _evaluator(repo: Path, project: Path, contract: Path | None = None) -> Evaluator:
    return Evaluator(
        project,
        "negative-technical-fixture",
        contract or repo / "unused-fixture-contract.json",
        repo,
    )


class _ConservationReached(Exception):
    pass


class _TimelineProbe(Evaluator):
    """Stop after real conservation checks; do not manufacture render evidence."""

    def artifact(self, ref: Any, *, json_value: bool = True) -> Any:
        if ref == {"technical_boundary": "render_artifact_not_supplied"}:
            raise _ConservationReached
        return super().artifact(ref, json_value=json_value)


def _timeline_probe(repo: Path, value: dict[str, Any]) -> dict[str, Any]:
    project = load_project(value["project"])
    source = Path(project["sources"]["screen"]["path"])
    metadata = probe(source)
    stream = next(item for item in metadata["streams"] if item["codec_type"] == "video")
    with TemporaryDirectory(prefix="talkcut-negative-pts-") as temp:
        inventory = frame_inventory(source, stream, Path(temp))
    _require(inventory["status"] == "PASS", "Fixture screen PTS inventory failed")
    plan = _json(value["plan"])
    origin = Fraction(plan["timing"]["screen_origin"])
    evaluator = _TimelineProbe(
        Path(value["project"]),
        "negative-technical-fixture",
        repo / "unused-fixture-contract.json",
        repo,
    )
    begin, end = inventory["coverage"]
    evaluator.source_domain = (Fraction(begin) - origin, Fraction(end) - origin)
    evaluator.index = {
        "timeline": value["timeline"],
        "render": {"technical_boundary": "render_artifact_not_supplied"},
    }
    try:
        evaluator.load_timeline_render()
    except _ConservationReached:
        assert evaluator.source_domain is not None
        return {
            "boundary_reached": "render_artifact_not_supplied",
            "source_domain": serialized([evaluator.source_domain]),
            "actual_deletions": serialized(evaluator.deletions),
        }
    raise TalkCutError(
        "NEGATIVE_EVIDENCE_UNVERIFIED", "Conservation boundary did not execute"
    )


def _probe(
    repo: Path, case_id: str, value: dict[str, Any]
) -> tuple[int, dict[str, Any]]:
    """A fixed probe; exceptions and nonzero CLI returns remain actual failures."""
    response: dict[str, Any] = {
        "schema_version": "negative-probe-response/v1",
        "case_id": case_id,
        "scope": SCOPES[case_id],
    }
    try:
        if case_id == "duplicate_coverage":
            facts = coverage(
                [(Fraction(a), Fraction(b)) for a, b in value["domain"]],
                [(Fraction(a), Fraction(b)) for a, b in value["observed"]],
            )
            response["facts"] = facts
            if facts["uncovered_intervals"]:
                response.update(status="FAIL", reason="Uncovered fixture interval")
                return 1, response
        elif case_id in {"hidden_deletion", "sample_export"}:
            facts = _timeline_probe(repo, value)
        elif case_id == "threshold_tamper":
            facts = _evaluator(repo, repo, _file(value["contract"])).load_contract()
        elif (
            case_id == "error_exit_nonzero"
            and value.get("operation") == "exit_mapping_fixture"
        ):
            actual = exit_code(value["report"])
            facts = {
                "computed_exit_code": actual,
                "fixture_scope": "exit_status_mapping_only",
            }
            if actual:
                response.update(
                    status="FAIL",
                    facts=facts,
                    reason="Evaluator report is not complete PASS",
                )
                return actual, response
        elif (
            case_id in {"error_exit_nonzero", "wrong_hashes"}
            and value.get("operation") == "cli_status"
        ):
            # This nested invocation is fixed here, never sourced from a receipt.
            result = subprocess.run(
                [sys.executable, "-m", "talkcut", "status", value["project"], "--json"],
                cwd=repo,
                env={**os.environ, "PYTHONPATH": str(repo / "src")},
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            facts = {
                "cli_exit_code": result.returncode,
                "cli_stdout": json.loads(result.stdout),
                "cli_stderr": result.stderr,
            }
            response["facts"] = facts
            if result.returncode:
                response.update(
                    status="FAIL",
                    reason=facts["cli_stdout"].get("code", "Missing CLI error code"),
                )
                return result.returncode, response
        elif case_id == "wrong_hashes":
            path = _evaluator(repo, repo).artifact(value["output"], json_value=False)
            facts = {"output_hash": sha256(path)}
        elif case_id == "renamed_partial":
            facts = validate_render(
                _file(value["output"]),
                _json(value["timeline"]),
                value["layout"],
                timeout=60,
            )
        else:
            raise TalkCutError(
                "NEGATIVE_EVIDENCE_UNVERIFIED", "Unsupported fixed probe"
            )
        response.update(status="TECHNICAL_CONTROL_PASS", facts=facts)
        return 0, response
    except (
        EvidenceError,
        TalkCutError,
        RenderError,
        ValueError,
        KeyError,
        OSError,
    ) as exc:
        response.update(status="FAIL", error_type=type(exc).__name__, reason=str(exc))
        return 1, response


def _probe_command(case_id: str, input_path: Path, repo: Path) -> list[str]:
    return [
        sys.executable,
        str(Path(__file__).resolve()),
        "probe",
        "--repo",
        str(repo),
        "--case",
        case_id,
        "--input",
        str(input_path),
    ]


def _pair(
    case_id: str,
    name: str,
    control: dict[str, Any],
    mutant: dict[str, Any],
    root: Path,
    repo: Path,
    mutation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    directory = root / "cases" / case_id / name
    directory.mkdir(parents=True)
    a = _save(directory / "control.input.json", control)
    b = _save(directory / "mutation.input.json", mutant)
    return {
        "name": name,
        "control_input": a,
        "mutation_input": b,
        "mutation": mutation or {},
        "control": _execute(
            _probe_command(case_id, _file(a), repo), directory, "control", repo
        ),
        "attack": _execute(
            _probe_command(case_id, _file(b), repo), directory, "attack", repo
        ),
    }


def _project_copy(project: Path, target: Path) -> None:
    shutil.copytree(project, target)
    path = target / "project.json"
    value = json.loads(path.read_text())
    for source in value["sources"].values():
        source["path"] = str(target / Path(source["path"]).relative_to(project))
    atomic_json(path, value)


def run_evaluator_negatives(
    repo_root: str | Path,
    output_dir: str | Path,
    dependencies: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preserve a fresh real run; missing AV controls produce null measurements."""
    repo, root = Path(repo_root).resolve(), Path(output_dir).resolve()
    _require(
        not root.exists() or not any(root.iterdir()),
        "Choose a new or empty negative run directory",
    )
    root.mkdir(parents=True, exist_ok=True)
    started, identity = _now(), code_identity(repo)
    deps = {**(dependencies or {}), "code_tree_hash": identity["code_tree_hash"]}
    harness_ref = artifact_ref(Path(__file__).resolve())
    request_ref = _save(
        root / "request.json",
        {
            "schema_version": "evaluator-negative-request/v1",
            "scope": SCOPES,
            "dependencies": deps,
            "code_identity": identity,
            "harness": harness_ref,
            "fixture_source": artifact_ref(repo / "examples/recovery.py"),
            "actual_dgist_acceptance": False,
            "final_ac12_audit": False,
        },
    )
    toolchain = doctor()
    fixture_dir = root / "fixture"
    fixture_execution = _execute(
        [sys.executable, str(repo / "examples/recovery.py"), str(fixture_dir)],
        root,
        "fixture",
        repo,
    )
    _require(
        fixture_execution["exit_code"] == 0,
        "Actual generated recovery fixture failed; preserved execution cannot be promoted",
    )
    fixture_ref = artifact_ref(fixture_dir / "result.json")
    fixture = _json(fixture_ref)
    baseline, cut = fixture["outputs"]["baseline"], fixture["outputs"]["cut"]
    native = _json(baseline["native_render"])
    cases: dict[str, Any] = {
        key: {
            "status": "UNVERIFIED",
            "scope": "unavailable faithful positive control",
            "reason": reason,
            "pairs": [],
        }
        for key, reason in MISSING_CONTROLS.items()
    }
    for key, scope in SCOPES.items():
        cases[key] = {"status": "UNVERIFIED", "scope": scope, "pairs": []}

    def pair(
        case: str,
        name: str,
        control: dict[str, Any],
        mutant: dict[str, Any],
        mutation: dict[str, Any] | None = None,
    ) -> None:
        cases[case]["pairs"].append(
            _pair(case, name, control, mutant, root, repo, mutation)
        )

    domain = [["0", "90"]]
    windows = [["0", "30"], ["25", "55"], ["50", "80"], ["75", "90"]]
    pair(
        "duplicate_coverage",
        "repeated_window",
        {"domain": domain, "observed": windows},
        {"domain": domain, "observed": [["0", "30"]] * 3},
    )

    project = root / "identity-control"
    init = _execute(
        [
            sys.executable,
            "-m",
            "talkcut",
            "init",
            str(project),
            "--screen",
            str(fixture_dir / "synthetic.mp4"),
            "--speaker",
            str(fixture_dir / "synthetic.mp4"),
            "--json",
        ],
        root,
        "identity-init",
        repo,
    )
    _require(init["exit_code"] == 0, "Synthetic identity control initialization failed")
    wrong_project, malformed_project = (
        root / "identity-mutated",
        root / "malformed-project",
    )
    _project_copy(project, wrong_project)
    _project_copy(project, malformed_project)
    changed = Path(
        json.loads((wrong_project / "project.json").read_text())["sources"]["screen"][
            "path"
        ]
    )
    changed.chmod(0o600)
    with changed.open("ab") as stream:
        stream.write(SOURCE_MUTATION)
    atomic_json(root / "identity-control.snapshot.json", load_project(project))
    (malformed_project / "project.json").write_bytes(MALFORMED_PROJECT)
    cli_control = {"operation": "cli_status", "project": str(project)}
    pair(
        "wrong_hashes",
        "source_bytes",
        cli_control,
        {"operation": "cli_status", "project": str(wrong_project)},
    )
    good_output = baseline["output"]
    bad_output = root / "changed-output.mp4"
    bad_output.write_bytes(_file(good_output).read_bytes() + SOURCE_MUTATION)
    pair(
        "wrong_hashes",
        "output_bytes",
        {"operation": "artifact_hash", "output": good_output},
        {
            "operation": "artifact_hash",
            "output": {**good_output, "path": str(bad_output)},
        },
    )
    pair(
        "error_exit_nonzero",
        "malformed_project",
        cli_control,
        {"operation": "cli_status", "project": str(malformed_project)},
    )
    # This authored function-input fixture is never submitted to acceptance.
    # It isolates exit_code's mapping; no claimed AV judgement becomes evidence.
    mapping: dict[str, Any] = {
        "operation": "exit_mapping_fixture",
        "fixture_scope": "exit_status_mapping_only",
        "not_acceptance_evidence": True,
        "report": {
            "goal_achieved": True,
            "status": "PASS",
            "criteria": [{"id": key, "status": "PASS"} for key in CRITERIA],
        },
    }
    for name in ("failed_status", "skipped_criterion", "missing_criterion"):
        mutant = copy.deepcopy(mapping)
        if name == "failed_status":
            mutant["report"]["status"] = "FAIL"
        elif name == "skipped_criterion":
            mutant["report"]["criteria"][0]["status"] = "SKIP"
        else:
            mutant["report"]["criteria"].pop()
        pair("error_exit_nonzero", name, mapping, mutant)

    for case, render, name in (
        ("hidden_deletion", cut, "omitted_ledger"),
        ("sample_export", baseline, "short_domain"),
    ):
        control = {
            "project": fixture["project"],
            "plan": render["settings"]["plan"],
            "timeline": render["settings"]["timeline"],
        }
        timeline = copy.deepcopy(_json(control["timeline"]))
        if case == "hidden_deletion":
            _require(
                bool(timeline["deletions"]),
                "The legitimate cut control must actually remove an interval",
            )
            timeline["deletions"] = []
        else:
            timeline["domain"]["end"] = "1"
        mutant = {
            **control,
            "timeline": _save(root / f"{case}.timeline.json", timeline),
        }
        pair(case, name, control, mutant)

    contract_ref = _save(root / "contract-control.json", expected_contract())
    for name in PAIR_NAMES["threshold_tamper"]:
        changed_contract = expected_contract()
        if name == "numeric_limit":
            changed_contract["checks"]["sync"]["max_lip_residual_with_uncertainty_ms"][
                "max"
            ] = 800
        elif name == "required_flag":
            changed_contract["criteria"][0]["required"] = False
        else:
            changed_contract["unresolved_P0_P1"] = 1
        ref = _save(root / f"contract-{name}.json", changed_contract)
        pair("threshold_tamper", name, {"contract": contract_ref}, {"contract": ref})

    partial = root / "interrupted-copy.partial"
    interruption = _execute(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-n",
            "-re",
            "-i",
            str(_file(good_output)),
            "-map",
            "0",
            "-c",
            "copy",
            "-flush_packets",
            "1",
            "-f",
            "mp4",
            str(partial),
        ],
        root,
        "interrupted-copy",
        repo,
        timeout=0.5,
    )
    _require(
        interruption["timed_out"] and partial.is_file() and partial.stat().st_size > 0,
        "No genuine interrupted MP4 was produced; keep this case unverified",
    )
    renamed = root / "renamed-interrupted.mp4"
    shutil.copyfile(partial, renamed)
    technical = {
        "timeline": baseline["settings"]["timeline"],
        "layout": native["layout"],
    }
    pair(
        "renamed_partial",
        "interrupted_copy",
        {**technical, "output": good_output},
        {**technical, "output": artifact_ref(renamed)},
        {"interruption": interruption, "partial": artifact_ref(partial)},
    )

    _require(
        code_identity(repo) == identity
        and sha256(harness_ref["path"]) == harness_ref["sha256"],
        "Target code or harness changed during negative execution",
    )
    raw = {
        "schema_version": "evaluator-negative-run/v1",
        "run_id": uuid4().hex,
        "started_at": started,
        "finished_at": _now(),
        "dependencies": deps,
        "request": request_ref,
        "harness": harness_ref,
        "toolchain": toolchain,
        "fixture": fixture_ref,
        "fixture_execution": fixture_execution,
        "identity_initialization": init,
        "cases": cases,
        "test_only": True,
        "actual_dgist_acceptance": False,
        "audiovisual_review": "UNVERIFIED",
        "final_ac12_audit": False,
        "owner_acceptance": "pending",
    }
    # Inventory preserves inputs and every command output, not a self-referential report.
    raw["artifacts"] = [
        artifact_ref(path) for path in sorted(root.rglob("*")) if path.is_file()
    ]
    _save(root / "attempt.json", raw)
    try:
        measurements = verify_evaluator_negatives(
            raw, repo_root=repo, dependencies=deps
        )
    except Exception as exc:
        _save(
            root / "verification-failure.json",
            {
                "status": "FAIL",
                "error_type": type(exc).__name__,
                "reason": str(exc),
                "at": _now(),
            },
        )
        raise
    raw["measurements"] = measurements
    raw["status"] = (
        "PASS"
        if all(value is True for value in measurements.values())
        else "UNVERIFIED"
    )
    raw_ref = _save(root / "result.json", raw)
    receipt = {
        "schema_version": "evaluator-negative-receipt/v1",
        "run_id": raw["run_id"],
        "operation": "check:evaluator_negative",
        "started_at": started,
        "finished_at": _now(),
        "completed": True,
        "status": raw["status"],
        "result": raw_ref,
        "request": request_ref,
        "dependencies": deps,
        "harness": harness_ref,
        "test_only": True,
        "final_ac12_audit": False,
    }
    return {
        "result": raw_ref,
        "receipt": _save(root / "receipt.json", receipt),
        "status": raw["status"],
        "measurements": measurements,
    }


def _same_except(
    left: dict[str, Any], right: dict[str, Any], excluded: set[str]
) -> bool:
    return {k: v for k, v in left.items() if k not in excluded} == {
        k: v for k, v in right.items() if k not in excluded
    }


def _mp4_packet_prefix(path: Path, *, interrupted: bool) -> tuple[bytes, bytes]:
    """Read the fixed stream-copy muxer's container, not arbitrary corrupt bytes."""
    data = path.read_bytes()
    offset, boxes = 0, []
    prefix, packets = b"", b""
    open_mdat = False
    while offset < len(data):
        _require(len(data) - offset >= 8, "Interrupted MP4 has a truncated box header")
        declared = int.from_bytes(data[offset : offset + 4], "big")
        kind = data[offset + 4 : offset + 8]
        header = 8
        if declared == 1:
            _require(len(data) - offset >= 16, "MP4 extended box header is truncated")
            declared = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header = 16
        size = declared or len(data) - offset
        _require(
            size >= header and offset + size <= len(data),
            "MP4 box exceeds preserved bytes",
        )
        boxes.append(kind)
        if kind == b"mdat":
            _require(not packets, "Multiple MP4 packet payloads are unsupported")
            prefix, packets = data[:offset], data[offset + header : offset + size]
            open_mdat = declared == 0
        offset += size
    expected = [b"ftyp", b"free", b"mdat"] + ([] if interrupted else [b"moov"])
    _require(
        boxes == expected and bool(packets) and open_mdat is interrupted,
        "Preserved bytes are not a packet-bearing interrupted MP4 from the fixed muxer",
    )
    return prefix, packets


def _verify_interrupted_packets(output: Path, partial: Path) -> None:
    """Recreate the source's actual packet stream and require a proper prefix.

    Wall-clock cancellation yields different packet counts across hosts. Exact
    prefix equality binds all preserved packets without inventing a stop time.
    """
    actual_prefix, actual_packets = _mp4_packet_prefix(partial, interrupted=True)
    with TemporaryDirectory(prefix="talkcut-negative-copy-replay-") as directory:
        replay = Path(directory) / "complete.mp4"
        command = [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-n",
            "-i",
            str(output),
            "-map",
            "0",
            "-c",
            "copy",
            "-flush_packets",
            "1",
            "-f",
            "mp4",
            str(replay),
        ]
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
        _require(
            process.returncode == 0 and not process.stderr.strip(),
            "Independent source packet copy failed",
        )
        expected_prefix, expected_packets = _mp4_packet_prefix(
            replay, interrupted=False
        )
        _require(
            actual_prefix == expected_prefix
            and len(actual_packets) < len(expected_packets)
            and expected_packets.startswith(actual_packets),
            "Interrupted MP4 packet bytes do not belong to the actual completed fixture output",
        )


def _mutation(case_id: str, pair: dict[str, Any], fixture: dict[str, Any]) -> None:
    """An unrelated failure must never count as the specified adversarial case."""
    a, b, name = (
        _json(pair["control_input"]),
        _json(pair["mutation_input"]),
        pair["name"],
    )
    baseline, cut = fixture["outputs"]["baseline"], fixture["outputs"]["cut"]
    if case_id == "duplicate_coverage":
        _require(
            a
            == {
                "domain": [["0", "90"]],
                "observed": [["0", "30"], ["25", "55"], ["50", "80"], ["75", "90"]],
            }
            and b == {"domain": [["0", "90"]], "observed": [["0", "30"]] * 3},
            "Duplicate-window mutation or its full-coverage control changed",
        )
    elif case_id in {"hidden_deletion", "sample_export"}:
        render = cut if case_id == "hidden_deletion" else baseline
        expected = {
            "project": fixture["project"],
            "plan": render["settings"]["plan"],
            "timeline": render["settings"]["timeline"],
        }
        _require(
            a == expected and _same_except(a, b, {"timeline"}),
            "Timeline control is not the actually rendered fixture",
        )
        original, changed = _json(a["timeline"]), _json(b["timeline"])
        expected_timeline = copy.deepcopy(original)
        if case_id == "hidden_deletion":
            _require(
                bool(original["deletions"]),
                "Hidden-deletion control has no actual deletion",
            )
            expected_timeline["deletions"] = []
        else:
            expected_timeline["domain"]["end"] = "1"
        _require(
            changed == expected_timeline, "Timeline mutation changed unrelated fields"
        )
    elif case_id == "threshold_tamper":
        original, changed = _json(a["contract"]), _json(b["contract"])
        _require(
            original == expected_contract(),
            "Threshold control is not the approved contract",
        )
        expected = copy.deepcopy(original)
        if name == "numeric_limit":
            expected["checks"]["sync"]["max_lip_residual_with_uncertainty_ms"][
                "max"
            ] = 800
        elif name == "required_flag":
            expected["criteria"][0]["required"] = False
        else:
            expected["unresolved_P0_P1"] = 1
        _require(changed == expected, "Contract mutation differs from its fixed case")
    elif case_id == "renamed_partial":
        _require(
            a["output"] == baseline["output"]
            and a["timeline"] == baseline["settings"]["timeline"]
            and a["layout"] == _json(baseline["native_render"])["layout"]
            and _same_except(a, b, {"output"}),
            "Cancelled-file control is not the actual completed render",
        )
        interruption, partial = (
            pair["mutation"]["interruption"],
            _file(pair["mutation"]["partial"]),
        )
        _require(
            interruption["timed_out"] is True
            and type(interruption["exit_code"]) is int
            and interruption["exit_code"] < 0
            and interruption["timeout_seconds"] == 0.5,
            "No preserved real timeout execution",
        )
        expected_argv = [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-n",
            "-re",
            "-i",
            str(_file(a["output"])),
            "-map",
            "0",
            "-c",
            "copy",
            "-flush_packets",
            "1",
            "-f",
            "mp4",
            str(partial),
        ]
        _require(
            interruption["argv"] == expected_argv,
            "Unrelated command was relabelled as interrupted render",
        )
        _file(interruption["stdout"])
        _file(interruption["stderr"])
        output = _file(b["output"])
        _require(
            output.suffix == ".mp4"
            and ".partial" not in output.name
            and sha256(output) == sha256(partial)
            and output.stat().st_size > 0,
            "Mutation is not a renamed preserved partial",
        )
        _verify_interrupted_packets(_file(a["output"]), partial)
    elif case_id == "wrong_hashes" and name == "output_bytes":
        _require(
            a == {"operation": "artifact_hash", "output": baseline["output"]}
            and b["operation"] == a["operation"]
            and _same_except(a["output"], b["output"], {"path"}),
            "Output hash control/reference changed",
        )
        _require(
            Path(b["output"]["path"]).read_bytes()
            == _file(a["output"]).read_bytes() + SOURCE_MUTATION,
            "Output mutation differs from its exact byte change",
        )
    elif case_id == "error_exit_nonzero" and name != "malformed_project":
        expected = {
            "operation": "exit_mapping_fixture",
            "fixture_scope": "exit_status_mapping_only",
            "not_acceptance_evidence": True,
            "report": {
                "goal_achieved": True,
                "status": "PASS",
                "criteria": [{"id": key, "status": "PASS"} for key in CRITERIA],
            },
        }
        _require(
            a == expected,
            "Exit mapping control differs from its explicit structural fixture",
        )
        if name == "failed_status":
            expected["report"]["status"] = "FAIL"
        elif name == "skipped_criterion":
            expected["report"]["criteria"][0]["status"] = "SKIP"
        else:
            expected["report"]["criteria"].pop()
        _require(b == expected, "Exit mapping mutation changed unrelated fields")
    else:
        _require(
            a["operation"] == b["operation"] == "cli_status",
            "Negative command was replaced",
        )
        original = load_project(a["project"])
        _require(
            original["revision"] == 0
            and not original["events"]
            and original["sources"]["screen"]["sha256"]
            == sha256(Path(fixture["project"]).parent / "synthetic.mp4"),
            "CLI positive control is not the generated source fixture",
        )
        target = Path(b["project"]) / "project.json"
        if case_id == "error_exit_nonzero":
            _require(
                target.read_bytes() == MALFORMED_PROJECT,
                "Malformed-project mutation changed",
            )
        else:
            mutant = json.loads(target.read_text())
            normalized = copy.deepcopy(mutant)
            for role, source in normalized["sources"].items():
                source["path"] = original["sources"][role]["path"]
            _require(
                normalized == original,
                "Source-hash attack changed unrelated project fields",
            )
            for role, source in mutant["sources"].items():
                expected_bytes = Path(original["sources"][role]["path"]).read_bytes()
                _require(
                    Path(source["path"]).read_bytes()
                    == expected_bytes + (SOURCE_MUTATION if role == "screen" else b""),
                    "Source mutation does not match the intended role and bytes",
                )


def verify_evaluator_negatives(
    raw: dict[str, Any], *, repo_root: str | Path, dependencies: dict[str, Any]
) -> dict[str, bool | None]:
    """Validate raw bindings and independently replay each supported fixed probe.

    This returns seven narrow technical measurements and three nulls with the
    current registry. No number of passed structural controls fills AV nulls.
    A later AV adapter needs legitimate preserved controls and separate review.
    """
    repo = Path(repo_root).resolve()
    _require(
        raw.get("schema_version") == "evaluator-negative-run/v1",
        "Typed negative raw inputs are missing",
    )
    _require(
        raw.get("dependencies") == dependencies
        and dependencies.get("code_tree_hash") == code_identity(repo)["code_tree_hash"],
        "Stale or different negative execution dependencies",
    )
    _require(
        _file(raw.get("harness")) == Path(__file__).resolve(),
        "Different harness supplied the evidence",
    )
    request = _json(raw.get("request"))
    _require(
        request.get("dependencies") == dependencies
        and request.get("harness") == raw["harness"]
        and request.get("code_identity") == code_identity(repo)
        and request.get("scope") == SCOPES
        and request.get("fixture_source")
        == artifact_ref(repo / "examples/recovery.py"),
        "Request does not bind this exact code, harness and fixture scope",
    )
    _require(
        raw.get("test_only") is True
        and raw.get("actual_dgist_acceptance") is False
        and raw.get("final_ac12_audit") is False
        and raw.get("audiovisual_review") == "UNVERIFIED"
        and raw.get("owner_acceptance") == "pending",
        "Negative fixtures were relabelled as actual media or independent acceptance",
    )
    _require(raw.get("toolchain") == doctor(), "Executed toolchain changed")
    for ref in raw.get("artifacts", []):
        _file(ref)
    _require(
        bool(raw.get("artifacts")),
        "Preserved process/input artifact inventory is missing",
    )
    fixture = _json(raw.get("fixture"))
    _require(
        fixture.get("schema_version") == "recovery-example/v1"
        and fixture.get("test_only") is True
        and fixture.get("audiovisual_review") == "UNVERIFIED",
        "Generated fixture provenance is missing",
    )
    execution = raw.get("fixture_execution", {})
    _require(
        execution.get("argv")
        == [
            sys.executable,
            str(repo / "examples/recovery.py"),
            str(Path(fixture["project"]).parent),
        ]
        and execution.get("exit_code") == 0
        and execution.get("timed_out") is False,
        "Fixture generator did not complete successfully",
    )
    _file(execution["stdout"])
    _file(execution["stderr"])
    from talkcut.measurement_checks import verify_render

    project = load_project(fixture["project"])
    # These actual technical controls are independently decoded and recompiled.
    for name in ("baseline", "cut"):
        verify_render(fixture["outputs"][name], project)
    cases = raw.get("cases", {})
    _require(
        set(cases) == set(CHECK_REQUIREMENTS["evaluator_negative"]),
        "The exact ten required negative cases must remain visible",
    )
    measured: dict[str, bool | None] = {}
    for case_id in CHECK_REQUIREMENTS["evaluator_negative"]:
        case = cases[case_id]
        if case_id in MISSING_CONTROLS:
            _require(
                case
                == {
                    "status": "UNVERIFIED",
                    "scope": "unavailable faithful positive control",
                    "reason": MISSING_CONTROLS[case_id],
                    "pairs": [],
                },
                "A missing legitimate AV/editorial/actor control was converted to PASS",
            )
            measured[case_id] = None
            continue
        _require(
            case.get("scope") == SCOPES[case_id]
            and [item.get("name") for item in case.get("pairs", [])]
            == list(PAIR_NAMES[case_id]),
            "Required paired technical control or mutation is missing",
        )
        for pair in case["pairs"]:
            _mutation(case_id, pair, fixture)
            for key, ref_name in (
                ("control", "control_input"),
                ("attack", "mutation_input"),
            ):
                process, ref = pair[key], pair[ref_name]
                _require(
                    process.get("argv") == _probe_command(case_id, _file(ref), repo)
                    and process.get("cwd") == str(repo)
                    and process.get("timed_out") is False
                    and type(process.get("exit_code")) is int,
                    "Probe receipt command or completion is unrelated",
                )
                _require(
                    bool(process.get("started_at"))
                    and bool(process.get("finished_at"))
                    and datetime.fromisoformat(process["finished_at"])
                    >= datetime.fromisoformat(process["started_at"]),
                    "Probe actual execution times are absent or reversed",
                )
                _require(
                    not _file(process["stderr"]).read_text().strip(),
                    "Probe produced unexpected stderr",
                )
                observed = _json(process["stdout"])
                # Fresh processes import the current pinned runtime instead of
                # accidentally replaying a long-lived interpreter's old imports.
                replay = subprocess.run(
                    _probe_command(case_id, _file(ref), repo),
                    cwd=repo,
                    env={**os.environ, "PYTHONPATH": str(repo / "src")},
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                _require(
                    not replay.stderr.strip(),
                    "Direct probe replay emitted unexpected stderr",
                )
                actual_code, actual_response = (
                    replay.returncode,
                    json.loads(replay.stdout),
                )
                # FFmpeg emits process-local pointer addresses in its diagnostic
                # prefix. Preserve them in stdout, compare the remaining text.
                stable_observed = re.sub(
                    r"(?<=@ )0x[0-9a-fA-F]+",
                    "0xADDRESS",
                    json.dumps(observed, sort_keys=True),
                )
                stable_actual = re.sub(
                    r"(?<=@ )0x[0-9a-fA-F]+",
                    "0xADDRESS",
                    json.dumps(actual_response, sort_keys=True),
                )
                _require(
                    process["exit_code"] == actual_code
                    and stable_observed == stable_actual,
                    "Preserved probe output differs from direct replay",
                )
                if key == "control":
                    _require(
                        actual_code == 0
                        and observed["status"] == "TECHNICAL_CONTROL_PASS",
                        "The alleged positive control never passed its technical scope",
                    )
                else:
                    reason = REASONS.get(
                        f"{case_id}.{pair['name']}", REASONS.get(case_id)
                    )
                    _require(
                        actual_code != 0
                        and reason
                        and reason in observed.get("reason", ""),
                        "The mutation failed for an unrelated reason or incorrectly passed",
                    )
                    if case_id == "duplicate_coverage":
                        _require(
                            observed["facts"]["numerator_seconds"] == "30"
                            and observed["facts"]["uncovered_intervals"]
                            == [["30", "90"]],
                            "Duplicate windows inflated observed coverage",
                        )
            _require(
                pair["control"]["finished_at"] <= pair["attack"]["started_at"],
                "Mutation ran before its positive control",
            )
        measured[case_id] = True
    if "measurements" in raw:
        _require(
            raw["measurements"] == measured,
            "Hand-entered negative measurements differ from direct replay",
        )
    if "status" in raw:
        _require(
            raw["status"]
            == (
                "PASS"
                if all(item is True for item in measured.values())
                else "UNVERIFIED"
            ),
            "Missing controls were hidden by an aggregate PASS",
        )
    return measured


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "probe"))
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case", choices=tuple(SCOPES))
    parser.add_argument("--input", type=Path)
    args = parser.parse_args()
    if args.operation == "probe":
        if args.case is None or args.input is None:
            parser.error("probe requires --case and --input")
        code, response = _probe(
            args.repo.resolve(), args.case, json.loads(args.input.read_text())
        )
        print(json.dumps(response, sort_keys=True))
        return code
    if args.output is None:
        parser.error("run requires --output")
    result = run_evaluator_negatives(args.repo, args.output)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
