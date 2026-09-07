"""Fail-closed evaluation of immutable artifacts, never of supplied AC verdicts.

Execution receipts and hashes establish provenance and byte identity, not the
truth of an AI judgment. The required separate audit examines those receipts and
the original media. No imported ``PASS`` or ``human_approved`` is an acceptance
shortcut. Missing, stale or unsupported evidence cannot make a project ready.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .contracts import (
    CHECK_REQUIREMENTS,
    CRITERIA,
    code_identity,
    file_hash,
    load_schema,
    verify_contract,
)

EVALUATOR_VERSION = "goal-acceptance/v1"
Span = tuple[Fraction, Fraction]

MANIFEST_SCHEMA = load_schema("acceptance-manifest.schema.json")


def rational(value: Any) -> Fraction:
    if isinstance(value, bool) or value is None:
        raise ValueError("A finite media timestamp is required")
    if isinstance(value, dict):
        if (
            set(value) != {"num", "den"}
            or type(value["num"]) is not int
            or type(value["den"]) is not int
        ):
            raise ValueError("A rational requires integer num/den")
        return Fraction(value["num"], value["den"])
    try:
        return Fraction(str(value))
    except (ValueError, ZeroDivisionError) as exc:
        raise ValueError(f"Invalid media timestamp: {value!r}") from exc


def union(intervals: list[Span], domain: Span | None = None) -> list[Span]:
    result: list[Span] = []
    spans = []
    for start, end in intervals:
        if start >= end:
            raise ValueError("Intervals must have positive duration")
        if domain:
            start, end = max(start, domain[0]), min(end, domain[1])
        if start < end:
            spans.append((start, end))
    for start, end in sorted(spans):
        if result and start <= result[-1][1]:
            result[-1] = (result[-1][0], max(end, result[-1][1]))
        else:
            result.append((start, end))
    return result


def difference(domain: list[Span], covered: list[Span]) -> list[Span]:
    remaining = union(domain)
    for left, right in union(covered):
        next_spans = []
        for start, end in remaining:
            if right <= start or left >= end:
                next_spans.append((start, end))
            else:
                if start < left:
                    next_spans.append((start, left))
                if right < end:
                    next_spans.append((right, end))
        remaining = next_spans
    return remaining


def serialized(spans: list[Span]) -> list[list[str]]:
    return [[str(start), str(end)] for start, end in spans]


def coverage(domain: list[Span], observed: list[Span]) -> dict[str, Any]:
    denominator = sum((end - start for start, end in union(domain)), Fraction())
    missing = difference(domain, observed)
    missing_seconds = sum((end - start for start, end in missing), Fraction())
    numerator = denominator - missing_seconds
    return {
        "denominator_seconds": str(denominator),
        "numerator_seconds": str(numerator),
        "fraction": float(numerator / denominator) if denominator else None,
        "not_applicable": denominator == 0,
        "uncovered_intervals": serialized(missing),
    }


class EvidenceError(Exception):
    def __init__(self, reason: str, status: str = "UNVERIFIED"):
        super().__init__(reason)
        self.status = status


class Evaluator:
    def __init__(self, project: Path, render_id: str, contract_path: Path, repo: Path):
        self.project = project.resolve()
        self.repo = repo.resolve()
        self.render_id = render_id
        self.contract_path = contract_path.resolve()
        self.identity = code_identity(repo)
        self.index: dict[str, Any] = {}
        self.deps: dict[str, Any] = {"code_tree_hash": self.identity["code_tree_hash"]}
        self.criteria: dict[str, dict[str, Any]] = {
            key: {
                "id": key,
                "description": value,
                "status": "UNVERIFIED",
                "checks": [],
                "evidence_refs": [],
            }
            for key, value in CRITERIA.items()
        }
        self.coverage: dict[str, Any] = {}
        self.invalid_evidence: list[dict[str, Any]] = []
        self.provider_findings: list[dict[str, Any]] = []
        self.valid_reviews: list[dict[str, Any]] = []
        self.sources: dict[str, Any] = {}
        self.source_domain: Span | None = None
        self.output_domain: Span | None = None
        self.deletions: list[Span] = []
        self.seams: list[Fraction] = []
        self.retained: list[Span] = []
        self.timeline: dict[str, Any] = {}
        self.render: dict[str, Any] = {}
        self.analysis: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}
        self.artifact_cache: dict[tuple[str, str], Any] = {}
        self.measurement_cache: dict[str, Any] = {}

    def add(
        self,
        criterion: str,
        name: str,
        status: str,
        reason: str,
        measurements: Any = None,
    ) -> None:
        self.criteria[criterion]["checks"].append(
            {
                "check_id": name,
                "status": status,
                "reason": reason,
                "measurements": measurements,
            }
        )

    def check(self, criterion: str, name: str, operation: Any) -> Any:
        try:
            result = operation()
            self.add(criterion, name, "PASS", "Verified from current artifacts", result)
            return result
        except EvidenceError as exc:
            self.add(criterion, name, exc.status, str(exc))
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            OSError,
            ZeroDivisionError,
        ) as exc:
            self.add(
                criterion, name, "UNVERIFIED", f"Invalid or incomplete evidence: {exc}"
            )
        return None

    def path(self, name: str) -> Path:
        path = Path(name)
        return path if path.is_absolute() else self.project / path

    def artifact(self, ref: Any, *, json_value: bool = True) -> Any:
        if not isinstance(ref, dict) or not ref.get("path") or not ref.get("sha256"):
            raise EvidenceError("Required hashed artifact reference is missing")
        path = self.path(ref["path"])
        if not path.is_file():
            raise EvidenceError(f"Required artifact is missing: {path.name}")
        # Rehash on every evaluator run; cache only inside this evaluation.
        key = (str(path.resolve()), ref["sha256"])
        if key not in self.artifact_cache:
            if file_hash(path) != ref["sha256"]:
                raise EvidenceError(f"Stale or changed artifact: {path.name}", "FAIL")
            if "bytes" in ref and path.stat().st_size != ref["bytes"]:
                raise EvidenceError(
                    f"Artifact byte count mismatch: {path.name}", "FAIL"
                )
            self.artifact_cache[key] = (
                json.loads(path.read_text()) if json_value else path
            )
        value = self.artifact_cache[key]
        if json_value and isinstance(value, Path):
            value = json.loads(path.read_text())
        return value if json_value else path

    def require(self, condition: Any, reason: str, status: str = "FAIL") -> None:
        if not condition:
            raise EvidenceError(reason, status)

    def dependencies(
        self, value: dict[str, Any], names: list[str] | None = None
    ) -> None:
        recorded = value.get("dependencies", {})
        for name in names or list(self.deps):
            self.require(
                name in self.deps and self.deps[name] is not None,
                f"Current dependency is unavailable: {name}",
                "UNVERIFIED",
            )
            self.require(
                name in recorded,
                f"Evidence dependency is missing: {name}",
                "UNVERIFIED",
            )
            self.require(
                recorded[name] == self.deps[name], f"Stale evidence dependency: {name}"
            )

    def receipt(
        self,
        ref: Any,
        *,
        dependency_names: list[str] | None = None,
        provider: bool = False,
    ) -> dict[str, Any]:
        value = self.artifact(ref)
        if provider and value.get("schema_version") == "composite-review-receipt/v1":
            from .review import _receipt

            verified = _receipt(ref)
            self.dependencies(verified, dependency_names)
            return verified
        self.require(
            not str(value.get("model_revision", "")).startswith("composite/")
            and "composite_graph" not in value,
            "Composite provider must validate its actual execution graph",
            "UNVERIFIED",
        )
        self.require(
            value.get("schema_version") == "execution-receipt/v1",
            "Execution receipt schema is missing",
            "UNVERIFIED",
        )
        self.require(
            value.get("run_id")
            and value.get("started_at")
            and value.get("finished_at"),
            "Execution identity/timestamps missing",
            "UNVERIFIED",
        )
        self.require(
            value.get("completed") is True
            and value.get("exit_code") == 0
            and value.get("exit_code") is not False,
            "Execution did not complete successfully",
        )
        self.require(
            not value.get("test_only")
            and not value.get("mock")
            and not value.get("synthetic"),
            "Test/mock receipt cannot certify real DGIST evidence",
        )
        self.require(
            value.get("executor") and value.get("tool_version"),
            "Actual executor/tool version missing",
            "UNVERIFIED",
        )
        self.require(
            isinstance(value.get("command"), list) and bool(value["command"]),
            "Executed argument vector missing",
            "UNVERIFIED",
        )
        log = self.artifact(value.get("log"), json_value=False)
        self.require(log.stat().st_size > 0, "Empty execution log", "UNVERIFIED")
        self.dependencies(value, dependency_names)
        if provider:
            self.require(
                value.get("provider_request_id")
                and value.get("model_revision")
                and value.get("prompt_sha256"),
                "Provider execution/model/prompt provenance missing",
                "UNVERIFIED",
            )
            self.artifact(value.get("prompt"), json_value=False)
            self.require(
                value["prompt"]["sha256"] == value["prompt_sha256"],
                "Provider prompt hash mismatch",
            )
            self.artifact(value.get("request"))
            self.artifact(value.get("response"))
        return value

    def measured_check(self, check_id: str) -> dict[str, Any]:
        evidence = self.artifact(self.index.get("checks", {}).get(check_id))
        self.require(
            evidence.get("schema_version") == "measurement-check/v1"
            and evidence.get("check_id") == check_id,
            "Measurement check identity missing",
            "UNVERIFIED",
        )
        self.dependencies(evidence)
        execution = self.receipt(evidence.get("receipt"))
        measured = evidence.get("measurements", {})
        self.require(
            execution.get("operation") == f"check:{check_id}",
            "Receipt executed an unrelated operation",
            "UNVERIFIED",
        )
        result = self.artifact(execution.get("result"))
        stdout = self.artifact(execution.get("stdout"))
        self.require(
            result == stdout, "Measurement result differs from actual executed stdout"
        )
        self.require(
            result.get("schema_version") == "measurement-result/v1"
            and result.get("check_id") == check_id,
            "Executed result belongs to another measurement check",
            "UNVERIFIED",
        )
        self.dependencies(result)
        self.require(
            result.get("measurements") == measured
            and result.get("evidence_refs") == evidence.get("evidence_refs"),
            "Hand-entered measurements or references differ from executed check result",
        )
        recomputed = self.recompute_measurement(check_id, evidence, execution, result)
        self.require(
            recomputed == measured,
            "Reported measurements differ from direct raw evidence verification",
        )
        for key, expected in CHECK_REQUIREMENTS[check_id].items():
            actual = measured.get(key)
            self.require(
                actual is not None,
                f"Measurement is absent: {check_id}.{key}",
                "UNVERIFIED",
            )
            if isinstance(expected, dict):
                if expected.get("nonempty"):
                    valid = isinstance(actual, str) and bool(actual.strip())
                else:
                    valid = (
                        isinstance(actual, (int, float))
                        and not isinstance(actual, bool)
                        and math.isfinite(actual)
                    )
                    if valid and "max" in expected:
                        valid = 0 <= actual <= expected["max"]
                    if valid and "min" in expected:
                        valid = actual >= expected["min"]
            else:
                valid = type(actual) is type(expected) and actual == expected
            self.require(
                valid,
                f"Measurement violates frozen criterion: {check_id}.{key}={actual!r}, expected {expected!r}",
            )
        self.require(
            bool(evidence.get("evidence_refs")),
            "Measured results require underlying artifacts",
            "UNVERIFIED",
        )
        for ref in evidence["evidence_refs"]:
            self.artifact(ref, json_value=False)
        return measured

    def recompute_measurement(
        self,
        check_id: str,
        evidence: dict[str, Any],
        execution: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Only implemented raw evidence verifiers may certify measurements.

        Matching schema/operation/stdout labels do not prove recovery or quality.
        Unsupported producers stay UNVERIFIED until typed raw evidence can be
        independently computed here; callers cannot register PASS adapters.
        """
        raw_ref = evidence.get("raw_inputs")
        self.require(
            raw_ref == result.get("raw_inputs")
            and raw_ref in execution.get("input_artifacts", []),
            "Executed checker does not bind its raw inputs",
            "UNVERIFIED",
        )
        self.require(
            isinstance(raw_ref, dict),
            "Typed raw input reference is required",
            "UNVERIFIED",
        )
        assert isinstance(raw_ref, dict)
        return self.compute_measurement(check_id, raw_ref)

    def compute_measurement(
        self, check_id: str, raw_ref: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a known raw verifier without needing a pre-existing receipt.

        A measurement command captures this result from the actual subprocess;
        acceptance reuses this same dispatcher and independently checks raw data.
        Missing fields remain null and never become supplied PASS defaults.
        """
        self.require(
            check_id
            in {
                "baseline",
                "recovery",
                "workflow_e2e",
                "sync",
                "boundaries",
                "reproducibility",
                "geometry_audio",
                "output_technical",
                "evaluator_negative",
                "release_privacy",
                "failure_injection",
                "editorial_fixture",
            },
            f"Direct raw evidence verifier is not implemented for {check_id}; receipt labels cannot certify this check",
            "UNVERIFIED",
        )
        raw = self.artifact(raw_ref)
        if check_id == "failure_injection":
            from .failure_checks import verify_failure_checks

            return verify_failure_checks(
                raw, self.repo, self.project / "evidence" / "failure-rechecks"
            )
        if check_id == "editorial_fixture":
            from .editorial_checks import verify_editorial_fixtures

            return verify_editorial_fixtures(
                raw, self.repo, self.project / "evidence" / "editorial-rechecks"
            )
        if check_id == "evaluator_negative":
            from .evaluator_negative import verify_evaluator_negatives

            return verify_evaluator_negatives(
                raw, repo_root=self.repo, dependencies=self.deps
            )
        if check_id == "release_privacy":
            from .privacy_checks import verify_release_privacy

            return verify_release_privacy(
                raw_ref,
                self.repo,
                project_dir=self.project,
                expected_source_hashes=self.deps.get("source_hashes", {}),
            )["measurements"]
        if check_id == "sync":
            from .sync_checks import verify_sync_inputs

            return verify_sync_inputs(
                raw, project_dir=self.project, dependencies=self.deps
            )
        if check_id == "boundaries":
            from .boundary_checks import verify_boundary_fixture

            self.require(
                raw.get("schema_version") == "boundary-input/v1",
                "Typed boundary fixture inputs are missing",
                "UNVERIFIED",
            )
            return verify_boundary_fixture(raw["fixture"], self.repo)
        if check_id == "reproducibility":
            from .reproducibility_checks import verify_reproducibility

            return verify_reproducibility(raw_ref, self.repo)["measurements"]
        if check_id in {"geometry_audio", "output_technical"}:
            from .quality_checks import verify_quality

            return verify_quality(
                raw,
                check_id=check_id,
                project_dir=self.project,
                dependencies=self.deps,
                validated_reviews=self.valid_reviews,
                evaluation_cache=self.measurement_cache,
            )
        if check_id == "recovery":
            from .measurement_checks import verify_recovery

            return verify_recovery(
                raw,
                project_dir=self.project,
                expected_source_hashes=self.deps.get("source_hashes", {}),
                source_domain=self.source_domain,
            )
        if check_id == "workflow_e2e":
            from .measurement_checks import verify_workflow

            return verify_workflow(
                raw, project_dir=self.project, dependencies=self.deps
            )
        self.require(
            raw.get("schema_version") == "baseline-input/v1",
            "Typed baseline inputs are missing",
            "UNVERIFIED",
        )
        self.require(
            raw.get("source_inspection")
            == self.index.get("source_inspections", {}).get("screen"),
            "Baseline source inspection differs from current registered screen",
        )
        self.require(
            self.source_domain is not None,
            "Baseline requires the complete measured source domain",
            "UNVERIFIED",
        )
        inspection = self.artifact(raw["source_inspection"])
        timeline = self.artifact(raw.get("timeline"))
        native = self.artifact(raw.get("native_render"))
        output = self.artifact(native.get("output"), json_value=False)
        self.require(
            native.get("schema_version") == "render/v1"
            and native.get("complete") is True
            and native.get("status") == "succeeded",
            "Baseline renderer did not successfully complete",
        )
        self.require(
            native.get("timeline_hash") == timeline.get("timeline_hash"),
            "Baseline native execution used a different timeline",
        )
        for role in ("screen", "speaker"):
            self.require(
                native.get("sources", {}).get(role, {}).get("sha256")
                == self.deps.get("source_hashes", {}).get(role),
                "Baseline source identity differs",
            )
        actual_domain = (
            rational(timeline["domain"]["start"]),
            rational(timeline["domain"]["end"]),
        )
        retained = [
            (rational(item["source_start"]), rational(item["source_end"]))
            for item in timeline.get("retained", [])
        ]
        whole_source = (
            actual_domain == self.source_domain
            and retained == [self.source_domain]
            and not timeline.get("deletions")
        )
        self.require(whole_source, "Baseline omits registered source content")
        from .render import validate_render

        validated = validate_render(output, timeline, native["layout"])
        streams = [
            item for item in validated["streams"] if item["codec_type"] == "video"
        ]
        video = inspection["video"]
        full_resolution = (
            len(streams) == 1
            and streams[0]["width"] == video["width"]
            and streams[0]["height"] == video["height"]
        )
        return {
            "whole_source": whole_source,
            "full_resolution": full_resolution,
            "complete_decode": validated["decode"]["exit_code"] == 0
            and not validated["decode"]["stderr"],
        }

    def load_contract(self) -> dict[str, Any]:
        value = json.loads(self.contract_path.read_text())
        errors = verify_contract(value, self.repo)
        self.require(not errors, "; ".join(errors))
        self.deps["contract_hash"] = file_hash(self.contract_path)
        return {"contract_hash": self.deps["contract_hash"], **self.identity}

    def load_sources(self) -> dict[str, Any]:
        registration = self.artifact(self.index.get("registration"))
        self.require(
            registration.get("schema_version") == "source-registration/v1",
            "Source registration schema missing",
            "UNVERIFIED",
        )
        self.require(
            registration.get("dataset") == "dgist-w02"
            and registration.get("source_kind") == "real",
            "Synthetic/sample data cannot stand in for registered DGIST",
        )
        handoff = json.loads((self.project / "goal-handoff.local.json").read_text())
        self.require(
            handoff.get("schema_version") == "talkcut-goal-handoff/v1",
            "Original owner handoff unavailable",
            "UNVERIFIED",
        )
        originals = {item["role"]: item for item in handoff["sources"]}
        excluded = {
            str(Path(item["path"]).resolve())
            for item in handoff.get("exclude_sources", [])
        }
        self.sources = registration.get("sources", {})
        for role in ("screen", "speaker", "comparison_baseline"):
            item = self.sources.get(role, {})
            current = self.artifact(item.get("durable"), json_value=False)
            original = self.artifact(item.get("original"), json_value=False)
            self.require(
                str(original.resolve()) == str(Path(originals[role]["path"]).resolve()),
                "Registered source differs from owner-provided original",
            )
            self.require(
                str(original.resolve()) not in excluded,
                "Excluded incomplete source selected",
            )
            self.require(
                original.stat().st_size == originals[role]["observed_bytes"],
                "Source differs from owner's full-size input",
            )
            self.require(
                item["original"]["sha256"] == item["durable"]["sha256"],
                "Preservation copy differs from original",
            )
            self.require(
                current.resolve() != original.resolve()
                and not str(current.resolve()).startswith(
                    ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")
                ),
                "Required durable preservation copy is absent",
            )
        self.deps["source_hashes"] = {
            role: item["durable"]["sha256"] for role, item in self.sources.items()
        }
        return {"source_hashes": self.deps["source_hashes"]}

    def source_inspections(self) -> dict[str, Any]:
        self.require(
            bool(self.sources), "Registered real sources unavailable", "UNVERIFIED"
        )
        reports = {}
        for role in ("screen", "speaker", "comparison_baseline"):
            inspected = self.artifact(
                self.index.get("source_inspections", {}).get(role)
            )
            self.require(
                inspected.get("schema_version") == "source-inspection/v1",
                "Source inspection schema missing",
                "UNVERIFIED",
            )
            self.require(
                inspected.get("sha256") == self.sources[role]["durable"]["sha256"],
                "Inspection source hash differs",
            )
            self.require(
                inspected.get("full_decode") is True
                and inspected.get("support_findings") == [],
                "Full supported selected-stream decode is absent",
                "UNVERIFIED",
            )
            self.require(
                str(self.path(inspected["path"]).resolve())
                == str(self.path(self.sources[role]["durable"]["path"]).resolve()),
                "Inspected path is not the preserved source",
            )
            self.artifact(inspected.get("probe"))
            for tool in ("ffmpeg", "ffprobe"):
                observed_tool = (
                    inspected.get("toolchain", {}).get("tools", {}).get(tool, {})
                )
                self.artifact(observed_tool, json_value=False)
                self.require(
                    bool(observed_tool.get("build")),
                    "Inspection tool build not identified",
                    "UNVERIFIED",
                )
            video, audio = inspected.get("video", {}), inspected.get("audio", {})
            for kind, stream in (("video", video), ("audio", audio)):
                self.require(
                    isinstance(stream.get("index"), int) and stream.get("time_base"),
                    "Actual stream/timebase missing",
                    "UNVERIFIED",
                )
                self.require(
                    stream.get("exit_code") == 0
                    and stream.get("missing_pts_count") == 0
                    and stream.get("frame_count", 0) > 0,
                    "Complete decoded PTS/sample coverage missing",
                    "UNVERIFIED",
                )
                self.require(
                    stream.get("anomalies") == [],
                    "Unresolved source stream coverage gap",
                    "UNVERIFIED",
                )
                stderr = self.artifact(stream.get("stderr"), json_value=False)
                self.require(
                    not stderr.read_text().strip(),
                    "Frame inventory emitted decode errors",
                )
                raw = self.artifact(stream.get("raw_frames"), json_value=False)
                parsed = []
                for line in raw.read_text().splitlines():
                    values = dict(
                        pair.split("=", 1)
                        for pair in line.strip().split("|")
                        if "=" in pair
                    )
                    if not values:
                        continue
                    self.require(
                        values.get("pts", "N/A") != "N/A",
                        "Raw frame inventory contains missing PTS",
                    )
                    item = {
                        "pts": int(values["pts"]),
                        "duration": int(
                            values.get("duration") or values.get("pkt_duration") or "0"
                        ),
                    }
                    if "nb_samples" in values:
                        item["nb_samples"] = int(values["nb_samples"])
                    parsed.append(item)
                self.require(
                    parsed == stream.get("frames")
                    and len(parsed) == stream["frame_count"],
                    "Declared inventory differs from actual raw ffprobe frames",
                )
                self.require(
                    all(item["duration"] > 0 for item in parsed),
                    "Unknown frame duration",
                    "UNVERIFIED",
                )
                self.require(
                    all(
                        left["pts"] + left["duration"] == right["pts"]
                        for left, right in pairwise(parsed)
                    ),
                    "Actual PTS gap/overlap",
                    "UNVERIFIED",
                )
                tb = rational(stream["time_base"])
                measured_domain = (
                    parsed[0]["pts"] * tb,
                    (parsed[-1]["pts"] + parsed[-1]["duration"]) * tb,
                )
                self.require(
                    [rational(value) for value in stream["coverage"]]
                    == list(measured_domain),
                    "Declared coverage differs from raw full frame inventory",
                )
                if role == "screen" and kind == "video":
                    self.source_domain = measured_domain
                if kind == "audio":
                    self.require(
                        sum(frame["nb_samples"] for frame in parsed)
                        == stream["decoded_samples"],
                        "Audio decoded sample count differs from raw inventory",
                    )
            decode = inspected.get("decode", {})
            errors = self.artifact(decode.get("stderr"), json_value=False)
            progress = self.artifact(decode.get("progress"), json_value=False)
            values = dict(
                line.split("=", 1)
                for line in progress.read_text().splitlines()
                if "=" in line
            )
            self.require(
                decode.get("exit_code") == 0
                and not errors.read_text().strip()
                and values.get("progress") == "end",
                "Actual full decode did not finish cleanly",
            )
            self.require(
                int(values.get("frame", "0")) == video["frame_count"],
                "Actual full decode frame count differs from source inventory",
            )
            command = decode.get("command", [])
            self.require(
                inspected["path"] in command
                and "-xerror" in command
                and f"0:{video['index']}" in command
                and f"0:{audio['index']}" in command,
                "Full decode did not use the registered streams",
            )
            if role == "screen":
                assert self.source_domain is not None
                self.require(
                    self.source_domain[0] < self.source_domain[1],
                    "Empty source video domain",
                )
            reports[role] = {
                "video_frames": video["frame_count"],
                "audio_samples": audio["decoded_samples"],
            }
        return reports

    def load_timeline_render(self) -> dict[str, Any]:
        self.require(
            self.source_domain is not None,
            "Measured source domain unavailable",
            "UNVERIFIED",
        )
        timeline = self.artifact(self.index.get("timeline"))
        self.timeline = timeline
        self.deps["timeline_hash"] = self.index["timeline"]["sha256"]
        domain = (
            rational(timeline["domain"]["start"]),
            rational(timeline["domain"]["end"]),
        )
        self.require(
            domain == self.source_domain,
            "Timeline drops or invents part of the measured screen source",
        )
        retained = [
            (rational(item["source_start"]), rational(item["source_end"]))
            for item in timeline["retained"]
        ]
        self.require(bool(retained), "No retained lecture content")
        previous_source = domain[0]
        previous_output = Fraction()
        for item, (start, end) in zip(timeline["retained"], retained, strict=True):
            output_start, output_end = (
                rational(item["output_start"]),
                rational(item["output_end"]),
            )
            self.require(
                domain[0] <= start < end <= domain[1] and start >= previous_source,
                "Retained source intervals overlap, reorder, or exceed source",
            )
            self.require(
                output_start == previous_output
                and output_end - output_start == end - start,
                "Source/output mapping is incomplete or changes duration",
            )
            previous_source, previous_output = end, output_end
        self.retained = retained
        self.deletions = difference([domain], retained)
        claimed = [
            (rational(item["start"]), rational(item["end"]))
            for item in timeline.get("deletions", [])
        ]
        self.require(
            union(claimed) == self.deletions,
            "Actual source deletions differ from explicit deletion ledger",
        )
        self.require(
            rational(timeline["duration"]) == previous_output,
            "Timeline duration disagrees with retained content",
        )
        # Every source discontinuity creates a seam; leading/trailing trims are
        # deletion reviews but do not create an internal join.
        self.seams = [
            rational(item["output_start"])
            for index, item in enumerate(timeline["retained"])
            if index > 0 and retained[index - 1][1] != retained[index][0]
        ]
        render = self.artifact(self.index.get("render"))
        self.render = render
        self.require(render.get("render_id") == self.render_id, "Wrong render identity")
        self.require(
            render.get("complete") is True and render.get("status") == "complete",
            "Incomplete/cancelled render cannot be promoted",
        )
        self.require(
            not render.get("test_only") and render.get("profile") == "master",
            "Preview/sample/test-only output cannot be final master",
        )
        output = self.artifact(render.get("output"), json_value=False)
        self.require(
            output.suffix == ".mp4" and ".partial" not in output.name,
            "Partial/non-MP4 output cannot be final master",
        )
        self.deps["output_hash"] = render["output"]["sha256"]
        self.require(
            render.get("timeline_hash")
            in (self.deps["timeline_hash"], timeline.get("timeline_hash")),
            "Render refers to a different timeline",
        )
        self.bind_plan_timeline()
        self.dependencies(render)
        self.receipt(render.get("receipt"))
        native = self.artifact(render.get("native_render"))
        self.require(
            native.get("schema_version") == "render/v1"
            and native.get("status") == "succeeded"
            and native.get("complete") is True
            and native.get("exit_code") == 0,
            "Native renderer has no successful completed execution",
        )
        self.require(
            native.get("output") == render.get("output")
            and native.get("timeline_hash") == timeline.get("timeline_hash"),
            "Native renderer output/timeline differs from acceptance wrapper",
        )
        from .measurement_checks import verify_acceptance_render
        from .project import load_project

        executed = verify_acceptance_render(
            render, load_project(self.project), self.repo, project_dir=self.project
        )
        self.measurement_cache["acceptance_native_validation"] = executed
        validation = native.get("validation", {})
        self.require(
            executed["validation"] == validation,
            "Actual current worker media differs from recorded native validation",
        )
        self.require(
            validation.get("scope") == "full_decode_and_technical_timing_only"
            and validation.get("decode", {}).get("exit_code") == 0
            and not validation.get("decode", {}).get("stderr"),
            "Native full output decode failed or is unavailable",
            "UNVERIFIED",
        )
        self.output_domain = (Fraction(), previous_output)
        actual = render.get("actual", {})
        self.require(
            actual.get("frame_count")
            == validation.get("frame_count")
            == timeline["frame_count"],
            "Final frame count differs from complete resolved timeline",
        )
        self.require(
            rational(actual.get("valid_audio_samples"))
            == rational(validation.get("sample_count"))
            and abs(rational(actual["valid_audio_samples"]) - timeline["sample_count"])
            <= 1,
            "Final valid audio samples differ from complete resolved timeline",
        )
        self.require(
            rational(actual["video_end_pts"]) == rational(validation.get("video_end"))
            and abs(rational(actual["video_end_pts"]) - previous_output)
            <= rational(validation.get("video_time_base")),
            "Final video coverage differs from complete retained duration",
        )
        self.require(
            abs(rational(actual["audio_end_pts"]) - previous_output)
            <= Fraction(1, int(timeline["sample_rate"])),
            "Final audio does not cover the resolved timeline",
        )
        return {
            "source_domain": serialized([domain]),
            "retained_intervals": serialized(retained),
            "actual_deletions": serialized(self.deletions),
            "actual_seams": [str(value) for value in self.seams],
            "output_domain": serialized([self.output_domain]),
        }

    def bind_plan_timeline(self) -> dict[str, Any]:
        """Bind canonical plan content to the current actual project timeline."""
        from .plan import compile_plan
        from .project import content_hash, load_project

        project = load_project(self.project)
        plan_ref, timeline_ref = (
            project.get("active_plan"),
            project.get("active_timeline"),
        )
        plan, timeline = self.artifact(plan_ref), self.artifact(timeline_ref)
        assert isinstance(timeline_ref, dict)
        self.require(
            not self.index.get("timeline") or self.index["timeline"] == timeline_ref,
            "Acceptance timeline is not the current committed project timeline",
        )
        self.require(
            compile_plan(project, plan) == timeline,
            "Current timeline differs from source PTS/plan recompilation",
        )
        digest = content_hash(plan)
        self.require(
            timeline.get("plan_hash") == digest,
            "Timeline canonical plan hash differs from current plan content",
        )
        self.deps["plan_hash"] = digest
        self.deps["timeline_hash"] = timeline_ref["sha256"]
        self.timeline = timeline
        return {"plan": plan_ref, "timeline": timeline_ref, "plan_hash": digest}

    def load_capability(self, ref: dict[str, Any]) -> dict[str, Any]:
        from .review import _capability

        value = self.artifact(ref)
        self.require(
            value.get("schema_version") == "review-capability/v1",
            "Reviewer capability schema missing",
            "UNVERIFIED",
        )
        actual_capability = _capability(value, precision_required=False)
        self.require(
            not value.get("mock") and not value.get("self_attested_only"),
            "Mock/self-declared capability is insufficient",
            "UNVERIFIED",
        )
        receipt = self.receipt(
            value.get("receipt"),
            dependency_names=["code_tree_hash", "contract_hash"],
            provider=True,
        )
        self.require(
            value.get("model_revision") == receipt["model_revision"],
            "Capability model differs from actual provider",
        )
        challenge = self.artifact(value.get("challenge"))
        observed = self.artifact(value.get("observations"))
        for modality in ("audio", "video"):
            self.require(
                modality in value.get("modalities", []),
                f"Reviewer cannot process required {modality} modality",
                "UNVERIFIED",
            )
            self.require(
                challenge.get(f"{modality}_events")
                and observed.get(f"{modality}_events")
                == challenge[f"{modality}_events"],
                f"Known {modality} capability challenge was not correctly observed",
                "UNVERIFIED",
            )
        for clip in value.get("input_clips", []):
            self.artifact(clip, json_value=False)
        self.require(
            bool(value.get("input_clips")) and value.get("continuous_video") is True,
            "Continuous audio/video capability not demonstrated",
            "UNVERIFIED",
        )
        self.require(
            isinstance(value.get("temporal_resolution_ms"), (float, int))
            and actual_capability["max_actual_frame_gap_ms"]
            <= value["temporal_resolution_ms"]
            and math.isfinite(value["temporal_resolution_ms"]),
            "Unknown or understated actual capability sampling resolution",
            "UNVERIFIED",
        )
        value = {
            **value,
            "precision_supported": actual_capability["precision_supported"],
            "max_actual_frame_gap_ms": actual_capability["max_actual_frame_gap_ms"],
            "sampling_limitations": actual_capability["sampling_limitations"],
        }
        self.capabilities[ref["sha256"]] = value
        return {
            "model_revision": value["model_revision"],
            "modalities": value["modalities"],
            "temporal_resolution_ms": value["temporal_resolution_ms"],
            "precision_supported": value["precision_supported"],
            "sampling_limitations": value["sampling_limitations"],
        }

    def load_review(self, ref: dict[str, Any]) -> dict[str, Any]:
        from .context_collection import proposer_ids, proposer_prompts
        from .review import precision_review_required, validate_review_request

        record = self.artifact(ref)
        self.require(
            record.get("schema_version") == "multimodal-review/v1",
            "Multimodal review schema missing",
            "UNVERIFIED",
        )
        self.require(
            record.get("reviewer_role") == "adversarial_reviewer"
            and record.get("owner_acceptance", "pending") == "pending",
            "A proposer/AI cannot sign owner acceptance or its own review",
        )
        self.require(
            not record.get("test_only") and not record.get("synthetic"),
            "Fixture/test-only review cannot certify DGIST",
        )
        self.dependencies(record)
        receipt = self.receipt(record.get("receipt"), provider=True)
        self.require(
            proposer_ids(record) and receipt.get("run_id") not in proposer_ids(record),
            "Proposal and review must be separate identified executions",
        )
        self.require(
            proposer_prompts(record)
            and record.get("prompt_sha256") not in proposer_prompts(record),
            "Proposal/review must use separate instructions",
        )
        self.require(
            record.get("prompt_sha256") == receipt.get("prompt_sha256"),
            "Review prompt provenance differs",
        )
        capability_hash = record.get("capability", {}).get("sha256")
        capability = self.capabilities.get(capability_hash)
        self.require(
            capability is not None,
            "Valid executed reviewer capability unavailable",
            "UNVERIFIED",
        )
        assert capability is not None
        self.require(
            capability["model_revision"] == receipt["model_revision"],
            "Review uses an untested model revision",
            "UNVERIFIED",
        )
        request = self.artifact(receipt["request"])
        if precision_review_required(request):
            self.require(
                capability.get("precision_supported") is True
                and capability["max_actual_frame_gap_ms"] <= 40
                and capability["temporal_resolution_ms"] <= 40,
                "Lip/sync/seam/dense-motion review requires actual <=40 ms timing capability",
                "UNVERIFIED",
            )
        response = self.artifact(receipt.get("response"))
        if capability.get("precision_supported") is False:
            self.require(
                isinstance(response.get("sampling_limitations"), str)
                and len(response["sampling_limitations"].strip()) >= 30
                and response.get("dense_motion_and_lip_verified") is False,
                "Semantic review cannot certify unobserved dense motion/lip timing",
                "UNVERIFIED",
            )
        self.require(
            response.get("verdict") in ("PASS", "FAIL", "UNVERIFIED"),
            "Invalid/empty/truncated provider review response",
            "UNVERIFIED",
        )
        self.require(
            response.get("verdict") == "PASS",
            "Actual provider review is not PASS",
            response["verdict"],
        )
        self.require(
            isinstance(response.get("reason"), str)
            and len(response["reason"].strip()) >= 30,
            "Review has no substantive observation evidence",
            "UNVERIFIED",
        )
        self.require(
            isinstance(response.get("findings"), list)
            and isinstance(response.get("needs_source_comparison"), bool),
            "Review response lacks findings/source comparison decision",
            "UNVERIFIED",
        )
        self.require(
            not response["needs_source_comparison"],
            "Requested source comparison has not been resolved",
            "UNVERIFIED",
        )
        self.require(
            all(
                item.get("resolved") is True or item.get("severity") not in ("P0", "P1")
                for item in response["findings"]
            ),
            "Unresolved P0/P1 review findings",
        )
        modalities = response.get("observed_modalities", [])
        self.require(
            {"audio", "video"}.issubset(modalities),
            "Transcript-only/image-only review cannot cover audio/video",
            "UNVERIFIED",
        )
        self.require(
            response.get("continuous_video_observed") is True,
            "Continuous motion was not observed",
            "UNVERIFIED",
        )
        validate_review_request(record, receipt)
        kind = record.get("scope")
        self.require(
            kind in ("output", "deletion", "seam", "analysis", "layout", "lip_sync"),
            "Unknown review scope",
            "UNVERIFIED",
        )
        intervals = [
            (rational(span[0]), rational(span[1]))
            for span in response.get("observed_intervals", [])
        ]
        self.require(
            bool(intervals),
            "Provider did not identify observed intervals",
            "UNVERIFIED",
        )
        domain = (
            self.source_domain
            if kind in ("deletion", "analysis")
            else self.output_domain
        )
        self.require(
            domain is not None
            and all(domain[0] <= a < b <= domain[1] for a, b in intervals),
            "Provider review timestamps are outside actual media",
        )
        inputs = record.get("inputs", [])
        self.require(
            bool(inputs), "Review has no actual media input clips", "UNVERIFIED"
        )
        submitted: list[Span] = []
        for item in inputs:
            clip = self.artifact(item.get("clip"), json_value=False)
            self.require(
                item.get("parent_sha256")
                == (
                    self.deps["source_hashes"]["screen"]
                    if kind in ("deletion", "analysis")
                    else self.deps["output_hash"]
                ),
                "Review clip derives from different source/output",
            )
            extraction = self.receipt(item.get("extraction_receipt"))
            self.require(
                extraction.get("output_sha256") == item["clip"]["sha256"]
                and extraction.get("input_sha256") == item["parent_sha256"],
                "Review extraction provenance does not bind clip to parent",
            )
            span = (rational(item["interval"][0]), rational(item["interval"][1]))
            self.require(span[0] < span[1], "Invalid clip interval")
            submitted.append(span)
            # Actual streams, not a declared modality list, establish media type.
            proc = subprocess.run(
                ["ffprobe", "-v", "error", "-show_streams", "-of", "json", str(clip)],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.require(
                proc.returncode == 0, "Review input clip cannot be decoded/probed"
            )
            streams = json.loads(proc.stdout).get("streams", [])
            self.require(
                {"audio", "video"}.issubset(
                    {stream.get("codec_type") for stream in streams}
                ),
                "Actual clip lacks audio/video streams",
                "UNVERIFIED",
            )
            for stream in streams:
                if stream.get("codec_type") in ("audio", "video"):
                    self.require(
                        "duration" in stream
                        and abs(rational(stream["duration"]) - (span[1] - span[0]))
                        <= Fraction(1, 10),
                        "Clip duration differs from claimed observation span",
                    )
        self.require(
            not difference(intervals, submitted),
            "Claimed observation exceeds actual submitted clip coverage",
        )
        request = self.artifact(receipt["request"])
        self.require(
            set(request.get("input_clip_hashes", []))
            == {item["clip"]["sha256"] for item in inputs},
            "Actual provider request does not identify the reviewed clips",
        )
        self.require(
            response.get("observed_frame_count") is None
            or isinstance(response.get("observed_frame_count"), int),
            "Invalid observed frame count",
        )
        normalized = {
            "scope": kind,
            "intervals": intervals,
            "response": response,
            "request": request,
            "receipt": receipt,
            "ref": ref,
            "run_id": receipt["run_id"],
            "proposer_run_ids": proposer_ids(record),
            "temporal_resolution_ms": capability["temporal_resolution_ms"],
            "precision_supported": capability.get("precision_supported", False),
            "max_actual_frame_gap_ms": capability.get("max_actual_frame_gap_ms"),
            "sampling_limitations": capability.get("sampling_limitations"),
        }
        self.valid_reviews.append(normalized)
        return normalized

    def collect_provider_findings(self, ref: dict[str, Any]) -> None:
        """A current failed review blocks readiness even without valid coverage."""
        try:
            record = self.artifact(ref)
            self.dependencies(record)
            execution = self.receipt(record.get("receipt"), provider=True)
            response = self.artifact(execution["response"])
            findings = response.get("findings", [])
            for item in findings if isinstance(findings, list) else []:
                if isinstance(item, dict) and item.get("severity") in ("P0", "P1"):
                    self.provider_findings.append(
                        {
                            **item,
                            "review_ref": ref,
                            "provider_response_ref": execution["response"],
                            "resolved": False,
                            "reason": "Current provider finding requires verified repair/review evidence",
                        }
                    )
            if response.get("verdict") == "FAIL":
                self.provider_findings.append(
                    {
                        "id": f"provider-fail-{ref['sha256'][:16]}",
                        "severity": "P1",
                        "resolved": False,
                        "review_ref": ref,
                        "provider_response_ref": execution["response"],
                        "reason": response.get("reason")
                        or "Current provider review failed",
                    }
                )
        except (EvidenceError, ValueError, KeyError, TypeError, OSError):
            return

    def verify_finding_change(self, finding: dict[str, Any], change: str) -> bool:
        """Severity/repair decisions need an actual separately bound review."""
        try:
            evidence = self.artifact(
                finding.get("independent_review_ref")
                if change == "severity"
                else finding.get("resolution_ref")
            )
            self.dependencies(evidence)
            execution = self.receipt(evidence.get("receipt"), provider=True)
            request = self.artifact(execution["request"])
            response = self.artifact(execution["response"])
            self.dependencies(request)
            self.require(
                evidence.get("reviewer_role") == "independent_auditor"
                and evidence.get("reviewer_run_id") == execution["run_id"]
                and execution["run_id"] != finding.get("reporter_run_id"),
                "Finding change lacks a separate reviewer",
            )
            self.require(
                request.get("scope") == f"finding_{change}"
                and request.get("finding_id")
                == finding.get("id")
                == response.get("finding_id"),
                "Actual finding review concerns a different issue",
            )
            self.require(
                response.get("verdict") == "PASS"
                and response.get("reason")
                and response.get("change_approved") is True,
                "Finding change was not actually approved",
            )
            refs = request.get("evidence_refs", [])
            self.require(bool(refs), "Finding change lacks original/repair evidence")
            for ref in refs:
                self.artifact(ref, json_value=False)
            if change == "severity":
                self.require(
                    request.get("from_severity") == finding.get("original_severity")
                    and request.get("to_severity")
                    == finding.get("severity")
                    == response.get("to_severity"),
                    "Severity review does not approve the recorded change",
                )
            else:
                self.require(response.get("resolved") is True, "Repair is not verified")
            return True
        except (EvidenceError, ValueError, KeyError, TypeError, OSError):
            return False

    def review_coverage(self) -> dict[str, Any]:
        self.require(
            self.source_domain is not None and self.output_domain is not None,
            "Actual source/output domains unavailable",
            "UNVERIFIED",
        )
        assert self.source_domain is not None and self.output_domain is not None
        output_spans = [
            span
            for review in self.valid_reviews
            if review["scope"] == "output"
            for span in review["intervals"]
        ]
        deletion_spans = [
            span
            for review in self.valid_reviews
            if review["scope"] == "deletion"
            for span in review["intervals"]
        ]
        analysis_spans = [
            span
            for review in self.valid_reviews
            if review["scope"] == "analysis"
            for span in review["intervals"]
        ]
        self.coverage["output_audio"] = coverage([self.output_domain], output_spans)
        self.coverage["output_video"] = coverage([self.output_domain], output_spans)
        self.coverage["deleted_source"] = coverage(self.deletions, deletion_spans)
        self.coverage["source_analysis"] = coverage(
            [self.source_domain], analysis_spans
        )
        self.coverage["observed_frame_count"] = sum(
            review["response"].get("observed_frame_count") or 0
            for review in self.valid_reviews
        )
        self.coverage["observed_frame_count_unknown_runs"] = sum(
            review["response"].get("observed_frame_count") is None
            for review in self.valid_reviews
        )
        checked_deletions = 0
        for left, right in self.deletions:
            context = (
                max(self.source_domain[0], left - 5),
                min(self.source_domain[1], right + 5),
            )
            if any(
                review["scope"] == "deletion"
                and not difference([context], review["intervals"])
                and review["response"].get("complete_sentence_context") is True
                for review in self.valid_reviews
            ):
                checked_deletions += 1
        self.coverage["deletion_count"] = {
            "denominator": len(self.deletions),
            "numerator": checked_deletions,
            "not_applicable": not self.deletions,
        }
        checked_seams = []
        for seam in self.seams:
            context = (
                max(self.output_domain[0], seam - 5),
                min(self.output_domain[1], seam + 5),
            )
            if any(
                review["scope"] == "seam"
                and not difference([context], review["intervals"])
                and str(seam) in review["response"].get("seam_times", [])
                and review["response"].get("audio_and_frame_edges_checked") is True
                for review in self.valid_reviews
            ):
                checked_seams.append(seam)
        self.coverage["seams"] = {
            "denominator": len(self.seams),
            "numerator": len(checked_seams),
            "not_applicable": not self.seams,
            "uncovered_times": [
                str(value) for value in self.seams if value not in checked_seams
            ],
        }
        for name in (
            "output_audio",
            "output_video",
            "deleted_source",
            "source_analysis",
        ):
            self.require(
                not self.coverage[name]["uncovered_intervals"],
                f"Required {name} review coverage is incomplete",
                "UNVERIFIED",
            )
        self.require(
            checked_deletions == len(self.deletions),
            "Some actual deletions lack complete source and sentence context review",
            "UNVERIFIED",
        )
        self.require(
            len(checked_seams) == len(self.seams),
            "Some actual seams lack audio/frame review",
            "UNVERIFIED",
        )
        # Adjacent whole-output windows must overlap. Union alone would permit
        # opaque partitioning with no continuity check at each boundary.
        ordered = sorted(set(output_spans))
        edge = ordered[0][1] if ordered else Fraction()
        for left, right in ordered[1:]:
            if right > edge:
                self.require(
                    edge - left >= min(Fraction(5), right - left),
                    "Output audit windows lack the required continuity overlap",
                    "UNVERIFIED",
                )
                edge = right
        return self.coverage

    def analysis_check(self) -> dict[str, Any]:
        from .editorial_binding import verify_editorial_binding

        analysis = self.artifact(self.index.get("analysis"))
        self.analysis = analysis
        binding = self.artifact(self.index.get("editorial"))
        verified = verify_editorial_binding(
            self.index["editorial"], self.project, self.repo
        )
        self.dependencies(verified)
        # This is a captured local command receipt, not an aggregate provider.
        # verify_editorial_binding replays the original single/collection child
        # executions and every separate current candidate-specific AV review.
        self.receipt(binding.get("receipt"))
        self.require(
            verified["analysis"] == self.index["analysis"]
            and verified["timeline"] == self.index.get("timeline")
            and verified["output"] == self.render.get("output"),
            "Editorial binding differs from the indexed analysis/timeline/output",
            "UNVERIFIED",
        )
        self.require(
            verified["actual_deletions"] == serialized(self.deletions),
            "Editorial effective cuts differ from the evaluated retained timeline",
        )
        self.require(
            all(
                any(review["ref"] == ref for review in self.valid_reviews)
                for ref in verified["review_records"]
            ),
            "Editorial binding cites audiovisual evidence missing from current valid reviews",
            "UNVERIFIED",
        )
        disposition = verified["edit_disposition"]
        self.require(
            self.index.get("edit_disposition") == disposition,
            "Indexed edit disposition differs from the actual compiled cuts",
            "UNVERIFIED",
        )
        return {
            "segments": verified["segment_count"],
            "candidates": verified["candidate_count"],
            "protected": verified["protected_count"],
            "disposition": disposition,
        }

    def audit_handoff(self) -> dict[str, Any]:
        snapshot = self.artifact(self.index.get("snapshot"))
        self.dependencies(snapshot)
        self.require(
            snapshot.get("schema_version") == "acceptance-snapshot/v1"
            and snapshot.get("immutable") is True,
            "Immutable pre-audit evidence snapshot missing",
            "UNVERIFIED",
        )
        refs = snapshot.get("artifacts", [])
        self.require(bool(refs), "Empty audit snapshot", "UNVERIFIED")
        forbidden = {
            self.index.get(name, {}).get("sha256")
            for name in ("audit", "snapshot", "release")
        }
        for ref in refs:
            self.require(
                ref["sha256"] not in forbidden,
                "Audit snapshot is cyclic or includes later release/audit",
            )
            self.artifact(ref, json_value=False)
        required_refs = [
            self.index.get(name)
            for name in (
                "registration",
                "timeline",
                "render",
                "analysis",
                "editorial",
                "handoff",
            )
        ]
        required_refs += (
            list(self.index.get("checks", {}).values())
            + self.index.get("reviews", [])
            + self.index.get("capabilities", [])
        )
        self.require(
            all(
                ref and ref["sha256"] in {item["sha256"] for item in refs}
                for ref in required_refs
            ),
            "Snapshot does not include all final evidence and prepared handoff",
            "UNVERIFIED",
        )
        audit = self.artifact(self.index.get("audit"))
        self.dependencies(audit)
        receipt = self.receipt(audit.get("receipt"), provider=True)
        response = self.artifact(receipt["response"])
        request = self.artifact(receipt["request"])
        self.dependencies(request)
        self.require(
            request.get("scope") == "independent_audit"
            and request.get("snapshot_hash") == self.index["snapshot"]["sha256"],
            "Actual auditor request targets a different evidence snapshot",
        )
        submitted_refs = request.get("input_artifacts", [])
        self.require(
            bool(submitted_refs),
            "Auditor request has no actual evidence inputs",
            "UNVERIFIED",
        )
        for submitted in submitted_refs:
            self.artifact(submitted, json_value=False)
        submitted_hashes = {item["sha256"] for item in submitted_refs}
        self.require(
            self.index["snapshot"]["sha256"] in submitted_hashes
            and all(item["sha256"] in submitted_hashes for item in refs),
            "Auditor did not receive the snapshot and all frozen evidence artifacts",
            "UNVERIFIED",
        )
        self.require(
            response.get("snapshot_hash") == self.index["snapshot"]["sha256"],
            "Actual audit response does not identify the reviewed snapshot",
        )
        self.require(
            audit.get("snapshot_hash") == self.index["snapshot"]["sha256"],
            "Audit covers a different snapshot",
        )
        self.require(
            audit.get("reviewer_role") == "independent_auditor"
            and audit.get("reviewer_run_id") == receipt["run_id"],
            "Separate auditor identity missing",
            "UNVERIFIED",
        )
        from .context_collection import proposer_ids

        prohibited_runs = set(proposer_ids(self.analysis)) | set(
            snapshot.get("implementation_run_ids", [])
        )
        self.require(
            bool(snapshot.get("implementation_run_ids"))
            and receipt["run_id"] not in prohibited_runs,
            "Implementation and final audit executions are not separate",
            "UNVERIFIED",
        )
        self.require(
            response.get("verdict") == "PASS"
            and response.get("evaluator_reviewed") is True
            and response.get("fixed_fixture_expectations_reviewed") is True
            and response.get("media_and_logs_rechecked") is True
            and response.get("open_P0_P1") == 0
            and response.get("reason"),
            "Independent audit is incomplete or failed",
            "UNVERIFIED",
        )
        handoff = self.artifact(self.index.get("handoff"))
        self.dependencies(handoff)
        self.require(
            handoff.get("owner_acceptance") == "pending",
            "Owner acceptance cannot be pre-signed",
        )
        self.require(
            handoff.get("final_output_path")
            == str(self.path(self.render["output"]["path"]).resolve()),
            "Handoff final MP4 is not the evaluated master",
        )
        for key in (
            "rerun_commands",
            "restore_commands",
            "actual_measurements",
            "cost_usage",
            "unfulfilled_ac",
            "checkpoint",
        ):
            self.require(
                key in handoff and handoff[key] is not None,
                f"Handoff field unavailable: {key}",
                "UNVERIFIED",
            )
        self.artifact(handoff["checkpoint"], json_value=False)
        return {
            "snapshot_hash": self.index["snapshot"]["sha256"],
            "audit_hash": self.index["audit"]["sha256"],
            "handoff_hash": self.index["handoff"]["sha256"],
        }

    def release_check(self) -> dict[str, Any]:
        release = self.artifact(self.index.get("release"))
        self.dependencies(release)
        receipt = self.receipt(release.get("receipt"))
        self.require(
            receipt.get("executor") == "github-verification",
            "Release must include captured GitHub verification execution",
            "UNVERIFIED",
        )
        remote = self.artifact(release.get("remote_snapshot"))
        self.require(
            receipt.get("operation") == "github:verify-release",
            "Receipt executed an unrelated release verification operation",
            "UNVERIFIED",
        )
        self.require(
            receipt.get("result") == release.get("remote_snapshot")
            and self.artifact(receipt.get("stdout")) == remote,
            "Normalized release evidence differs from actual verification stdout/result",
        )
        self.require(
            remote.get("repository") == "https://github.com/alohays/talkcut",
            "Unexpected release repository",
        )
        self.require(
            remote.get("pr", {}).get("state") == "MERGED"
            and remote["pr"].get("reviewed") is True,
            "Pull request not reviewed and merged",
            "UNVERIFIED",
        )
        checks = remote.get("required_checks", [])
        self.require(
            bool(checks)
            and all(item.get("conclusion") == "SUCCESS" for item in checks),
            "Required public CI has not passed",
            "UNVERIFIED",
        )
        self.require(
            remote.get("protection_bypassed") is False,
            "Repository protection must not be bypassed",
            "UNVERIFIED",
        )
        revision = remote["pr"].get("merge_commit")
        self.require(
            isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision),
            "Release merge identity is not a full Git commit",
        )
        self.require(
            revision
            and revision
            == remote.get("tag_commit")
            == remote.get("release", {}).get("target_commit"),
            "PR/tag/release identities disagree",
        )
        self.require(
            remote.get("code_tree_hash") == self.identity["code_tree_hash"],
            "Released code differs from evaluated/tested code",
        )
        self.require(
            remote.get("release", {}).get("prerelease") is True
            and "alpha" in remote["release"].get("tag", ""),
            "Verified first alpha release missing",
            "UNVERIFIED",
        )
        for url in (remote["pr"].get("url"), remote["release"].get("url")):
            self.require(
                isinstance(url, str)
                and url.startswith("https://github.com/alohays/talkcut/"),
                "Public PR/release URL missing",
                "UNVERIFIED",
            )
        self.verify_live_release(remote)
        self.measured_check("release_privacy")
        return remote

    def verify_live_release(self, remote: dict[str, Any]) -> None:
        """Read GitHub and Git objects directly; normalized JSON is not authority."""

        def gh(arguments: list[str]) -> Any:
            try:
                process = subprocess.run(
                    ["gh", *arguments],
                    cwd=self.repo,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise EvidenceError(
                    f"Live GitHub verification unavailable: {exc}"
                ) from exc
            self.require(
                process.returncode == 0,
                "Live GitHub verification could not complete",
                "UNVERIFIED",
            )
            return json.loads(process.stdout)

        number = remote["pr"].get("number")
        self.require(
            type(number) is int and number > 0,
            "Verified PR number missing",
            "UNVERIFIED",
        )
        pr = gh(
            [
                "pr",
                "view",
                str(number),
                "--repo",
                "alohays/talkcut",
                "--json",
                "number,state,url,mergeCommit,reviewDecision,statusCheckRollup",
            ]
        )
        self.require(
            pr.get("state") == "MERGED"
            and pr.get("url") == remote["pr"]["url"]
            and pr.get("mergeCommit", {}).get("oid") == remote["pr"]["merge_commit"],
            "Live GitHub PR identity differs from release evidence",
        )
        self.require(
            pr.get("reviewDecision") not in ("CHANGES_REQUESTED", "REVIEW_REQUIRED"),
            "Live PR has unfulfilled review requirements",
            "UNVERIFIED",
        )
        live_checks = pr.get("statusCheckRollup", [])
        self.require(
            bool(live_checks), "Live public CI evidence is absent", "UNVERIFIED"
        )
        for required in remote["required_checks"]:
            matches = [
                item
                for item in live_checks
                if item.get("name", item.get("context")) == required.get("name")
            ]
            self.require(
                bool(matches)
                and all(
                    item.get("conclusion", item.get("state")) == "SUCCESS"
                    for item in matches
                ),
                "Actual public CI does not prove all required checks passed",
                "UNVERIFIED",
            )
        self.require(
            all(
                item.get("conclusion", item.get("state"))
                in ("SUCCESS", "SKIPPED", "NEUTRAL")
                for item in live_checks
            ),
            "Live public CI includes a failed or incomplete check",
            "UNVERIFIED",
        )
        tag = remote["release"]["tag"]
        self.require(
            isinstance(tag, str) and re.fullmatch(r"[A-Za-z0-9._-]+", tag),
            "Invalid alpha tag name",
        )
        released = gh(["api", f"repos/alohays/talkcut/releases/tags/{tag}"])
        self.require(
            released.get("draft") is False
            and released.get("prerelease") is True
            and released.get("tag_name") == tag
            and released.get("html_url") == remote["release"]["url"],
            "Live public alpha release differs from claimed release",
        )
        reference = gh(["api", f"repos/alohays/talkcut/git/ref/tags/{tag}"])["object"]
        if reference["type"] == "tag":
            reference = gh(
                ["api", f"repos/alohays/talkcut/git/tags/{reference['sha']}"]
            )["object"]
        self.require(
            reference.get("type") == "commit"
            and reference.get("sha") == remote["pr"]["merge_commit"],
            "Actual remote tag does not identify the merged code",
        )
        revision = remote["pr"]["merge_commit"]
        listing = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", revision],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )
        self.require(
            listing.returncode == 0,
            "Merged release commit is unavailable locally for byte verification",
            "UNVERIFIED",
        )
        release_files = {
            name
            for name in listing.stdout.splitlines()
            if name.startswith(("src/", "tests/", "schemas/", ".github/", "examples/"))
            and "__pycache__" not in Path(name).parts
            and not name.endswith((".pyc", ".pyo"))
            or name
            in (
                "pyproject.toml",
                "uv.lock",
                ".python-version",
                "pytest.ini",
                "mypy.ini",
                "ruff.toml",
                ".ruff.toml",
            )
        }
        self.require(
            release_files == set(self.identity["files"]),
            "Release code file set differs from currently evaluated code",
        )
        for name, digest in self.identity["files"].items():
            result = subprocess.run(
                ["git", "show", f"{revision}:{name}"],
                cwd=self.repo,
                capture_output=True,
                check=False,
            )
            self.require(
                result.returncode == 0
                and hashlib.sha256(result.stdout).hexdigest() == digest,
                "Release commit source bytes differ from current evaluated code",
            )

    def evaluate(self) -> dict[str, Any]:
        index_path = self.project / "acceptance.local.json"
        if index_path.is_file():
            self.index = json.loads(index_path.read_text())
            errors = sorted(
                Draft202012Validator(MANIFEST_SCHEMA).iter_errors(self.index),
                key=lambda err: str(err.path),
            )
            if errors:
                raise ValueError(
                    "Invalid acceptance index: "
                    + "; ".join(error.message for error in errors)
                )
        self.check("AC01", "frozen_contract", self.load_contract)
        self.check("AC02", "registered_originals", self.load_sources)
        self.check("AC02", "full_decode_pts", self.source_inspections)
        self.check(
            "AC04", "source_conservation_and_final_mapping", self.load_timeline_render
        )
        for ref in self.index.get("capabilities", []):
            self.check(
                "AC01",
                "executed_reviewer_capability",
                lambda ref=ref: self.load_capability(ref),
            )
        if not self.capabilities:
            self.add(
                "AC01",
                "executed_reviewer_capability",
                "UNVERIFIED",
                "No valid audio/video reviewer capability demonstration",
            )
        for ref in self.index.get("reviews", []):
            self.collect_provider_findings(ref)
            try:
                self.load_review(ref)
            except (
                EvidenceError,
                ValueError,
                TypeError,
                KeyError,
                OSError,
                subprocess.SubprocessError,
            ) as exc:
                self.invalid_evidence.append(
                    {
                        "ref": ref,
                        "reason": str(exc),
                        "status": getattr(exc, "status", "UNVERIFIED"),
                    }
                )
        # Invalid old records remain in the ledger but cannot contribute coverage.
        self.check("AC08", "multimodal_union_coverage", self.review_coverage)
        self.check("AC06", "real_source_editorial_analysis", self.analysis_check)
        mappings = {
            "AC03": ["workflow_e2e", "baseline"],
            "AC04": ["sync", "boundaries"],
            "AC05": ["geometry_audio"],
            "AC06": ["editorial_fixture"],
            "AC07": ["recovery"],
            "AC09": ["output_technical"],
            "AC10": ["failure_injection", "evaluator_negative"],
            "AC11": ["reproducibility"],
        }
        for criterion, names in mappings.items():
            for name in names:
                self.check(criterion, name, lambda name=name: self.measured_check(name))
        self.check("AC12", "independent_audit_and_handoff", self.audit_handoff)
        release_evidence = self.check(
            "AC13", "verified_public_release", self.release_check
        )
        findings = self.index.get("findings", []) + self.provider_findings
        open_findings = [
            item
            for item in findings
            if item.get("severity") in ("P0", "P1")
            and (
                item.get("resolved") is not True
                or not self.verify_finding_change(item, "resolution")
            )
        ]
        for item in findings:
            if (
                item.get("original_severity") in ("P0", "P1")
                and item.get("severity") not in ("P0", "P1")
                and not (
                    item.get("severity_change_reason")
                    and self.verify_finding_change(item, "severity")
                )
            ):
                open_findings.append(
                    {
                        **item,
                        "severity": item["original_severity"],
                        "reason": "Unsupported severity downgrade",
                    }
                )
        self.add(
            "AC09",
            "open_P0_P1",
            "FAIL" if open_findings else "PASS",
            "Unresolved P0/P1 must be zero",
            {"count": len(open_findings)},
        )
        for criterion_result in self.criteria.values():
            statuses = [item["status"] for item in criterion_result["checks"]]
            criterion_result["status"] = (
                "FAIL"
                if "FAIL" in statuses
                else "PASS"
                if statuses and all(status == "PASS" for status in statuses)
                else "UNVERIFIED"
            )
        # G0–G5 dependencies are enforced even if a technical output record says
        # PASS; no caller-supplied READY state is considered.
        media_ids = ["AC01", "AC02", "AC04", "AC05", "AC06", "AC07", "AC08"]
        media_dependencies_ok = all(
            self.criteria[key]["status"] == "PASS" for key in media_ids
        )
        if not media_dependencies_ok and self.criteria["AC09"]["status"] == "PASS":
            self.criteria["AC09"]["status"] = "UNVERIFIED"
            self.add(
                "AC09",
                "G0_G5_dependencies",
                "UNVERIFIED",
                "Final master requires all preceding media gates",
            )
        release_ready = all(
            self.criteria[f"AC{i:02}"]["status"] == "PASS" for i in range(1, 13)
        )
        achieved = release_ready and self.criteria["AC13"]["status"] == "PASS"
        status = (
            "PASS"
            if achieved
            else "FAIL"
            if any(item["status"] == "FAIL" for item in self.criteria.values())
            else "UNVERIFIED"
        )
        return {
            "schema_version": EVALUATOR_VERSION,
            "status": status,
            "release_ready": release_ready,
            "goal_achieved": achieved,
            "media_state": "READY_FOR_OWNER"
            if media_dependencies_ok and self.criteria["AC09"]["status"] == "PASS"
            else "BLOCKED",
            "goal_contract_hash": self.deps.get("contract_hash"),
            **self.identity,
            "evaluator_version": EVALUATOR_VERSION,
            "source_hashes": self.deps.get("source_hashes", {}),
            "output_hash": self.deps.get("output_hash"),
            "edit_disposition": self.index.get("edit_disposition"),
            "criteria": list(self.criteria.values()),
            "coverage": self.coverage,
            "uncovered_intervals": [
                {"metric": key, "intervals": value["uncovered_intervals"]}
                for key, value in self.coverage.items()
                if isinstance(value, dict) and value.get("uncovered_intervals")
            ],
            "invalid_evidence": self.invalid_evidence,
            "open_findings": open_findings,
            "independent_audit_ref": self.index.get("audit"),
            "code_release_evidence": release_evidence,
            "owner_acceptance": "pending",
            "provenance_limitations": "Hashes prove byte identity, not semantic truth or provider authenticity; a separate audit of actual media, provider execution records and evaluator is mandatory.",
        }


def evaluate(
    project_dir: str | Path,
    render_id: str,
    contract_path: str | Path,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    return Evaluator(
        Path(project_dir),
        render_id,
        Path(contract_path),
        Path(repo_root) if repo_root else Path.cwd(),
    ).evaluate()


def exit_code(report: dict[str, Any]) -> int:
    """CLI: exceptions/schema errors are 2; incomplete evaluation is always 1."""
    return (
        0
        if report.get("goal_achieved") is True
        and report.get("status") == "PASS"
        and len(report.get("criteria", [])) == 13
        and all(item.get("status") == "PASS" for item in report["criteria"])
        else 1
    )


def empty_index() -> dict[str, Any]:
    return {
        "schema_version": "acceptance-index/v1",
        "source_inspections": {},
        "reviews": [],
        "capabilities": [],
        "checks": {},
        "findings": [],
        "edit_disposition": "ANALYSIS_UNAVAILABLE",
        "owner_acceptance": "pending",
    }


def measurement_evidence_from_receipt(
    receipt_ref: dict[str, str], output_path: str | Path
) -> dict[str, str]:
    """Wrap an executed check's raw result; this helper never certifies a PASS.

    Producers emit this JSON to stdout and save identical bytes as ``result``::

        {"schema_version": "measurement-result/v1", "check_id": "baseline",
         "dependencies": {"code_tree_hash": "...", "contract_hash": "...",
                          "source_hashes": {}, "timeline_hash": "...",
                          "output_hash": "..."},
         "raw_inputs": {"path": "...", "sha256": "..."},
         "measurements": {"whole_source": true, "full_resolution": true,
                          "complete_decode": true}, "evidence_refs": []}

    Values must be computed by the executed producer, never copied from the
    contract. Its execution-receipt/v1 stores operation ``check:baseline``, the
    actual command/start/end/exit/log, matching dependencies, stdout/result refs,
    and raw_inputs in input_artifacts. baseline-input/v1 contains hashed refs
    named source_inspection, timeline and native_render. Evaluation re-decodes
    the actual output. Other check-specific raw verifiers remain UNVERIFIED;
    writing a correctly shaped receipt cannot enable an unsupported producer.
    """
    from .project import artifact_ref, atomic_json, verified_json

    execution = verified_json(receipt_ref)
    result = verified_json(execution.get("result", {}))
    stdout = verified_json(execution.get("stdout", {}))
    check_id = result.get("check_id")
    if (
        result != stdout
        or result.get("schema_version") != "measurement-result/v1"
        or check_id not in CHECK_REQUIREMENTS
    ):
        raise ValueError(
            "Executed stdout/result must identify a supported contract check"
        )
    if (
        execution.get("operation") != f"check:{check_id}"
        or execution.get("completed") is not True
        or type(execution.get("exit_code")) is not int
        or execution["exit_code"] != 0
    ):
        raise ValueError("An actually completed matching check execution is required")
    value = {
        "schema_version": "measurement-check/v1",
        "check_id": check_id,
        "receipt": receipt_ref,
        "dependencies": result.get("dependencies"),
        "raw_inputs": result.get("raw_inputs"),
        "measurements": result.get("measurements"),
        "evidence_refs": result.get("evidence_refs"),
    }
    destination = Path(output_path)
    if destination.exists():
        raise ValueError("Measurement evidence is immutable; choose a new output path")
    atomic_json(destination, value)
    return artifact_ref(destination)
