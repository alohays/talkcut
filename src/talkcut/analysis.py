"""Acoustic candidate discovery plus a conservative, evidence-driven policy.

Silence is an observation, never permission to remove learning activity. Real
source context must come from a recorded audiovisual execution; unavailable
context produces explicit keeps and ANALYSIS_UNAVAILABLE.
"""

from __future__ import annotations

import re
import subprocess
import time
from fractions import Fraction
from pathlib import Path
from typing import Any
from uuid import uuid4

from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    now,
    read_json,
    sha256,
)
from .timeline import as_fraction, subtract_intervals, union_intervals

PROTECTED_KINDS = {
    "demo",
    "question_wait",
    "reading",
    "execution_wait",
    "negation",
    "correction",
    "emphasis",
    "definition",
    "assignment",
    "introduction",
}
CONTEXT_KINDS = PROTECTED_KINDS | {
    "preparation",
    "disposable_pause",
    "disfluency",
    "lecture",
    "uncertain",
}


def _span(value: Any) -> tuple[Fraction, Fraction]:
    if isinstance(value, dict):
        result = as_fraction(value["start"]), as_fraction(value["end"])
    else:
        result = as_fraction(value[0]), as_fraction(value[1])
    if result[0] >= result[1]:
        raise TalkCutError("INVALID_INTERVAL", "Analysis intervals must be positive")
    return result


def _verify_source(source: dict[str, Any]) -> Path:
    path = Path(source["path"]).resolve()
    if not path.is_file() or sha256(path) != source["sha256"]:
        raise TalkCutError("SOURCE_CHANGED", "Analysis source bytes differ")
    return path


def detect_silence(
    source: dict[str, Any],
    stream_index: int,
    domain: Any,
    output_dir: str | Path,
    *,
    noise_db: float = -40,
    min_seconds: float = 3,
    offset: Any = "0",
    timeout: float = 14400,
) -> dict[str, Any]:
    """Decode the entire selected audio stream and record acoustic observations.

    ``offset`` maps absolute audio PTS to source-domain times. It must come from
    an explicit synchronization model; duration similarity is not such a model.
    """
    if not -100 <= noise_db <= -10 or not 0.1 <= min_seconds <= 60:
        raise TalkCutError(
            "INVALID_POLICY", "Acoustic detector parameters out of range"
        )
    path = _verify_source(source)
    start, end = _span(domain)
    shift = as_fraction(offset)
    directory = Path(output_dir) / f"silence-{uuid4().hex}"
    directory.mkdir(parents=True)
    log = directory / "ffmpeg.log"
    command = [
        "ffmpeg",
        "-hide_banner",
        "-nostdin",
        "-copyts",
        "-xerror",
        "-i",
        str(path),
        "-map",
        f"0:{stream_index}",
        "-vn",
        "-af",
        f"silencedetect=noise={noise_db}dB:d={min_seconds}",
        "-progress",
        "pipe:1",
        "-f",
        "null",
        "-",
    ]
    started = now()
    clock = time.monotonic()
    try:
        with log.open("x") as handle:
            process = subprocess.run(
                command, stdout=handle, stderr=handle, timeout=timeout, check=False
            )
        returncode = process.returncode
    except subprocess.TimeoutExpired:
        returncode = 124
    _verify_source(source)
    text = log.read_text()
    completed = returncode == 0 and "progress=end" in text
    observations: list[tuple[Fraction, Fraction]] = []
    pending: Fraction | None = None
    for line in text.splitlines():
        left = re.search(r"silence_start:\s*([-+\d.eE]+)", line)
        right = re.search(r"silence_end:\s*([-+\d.eE]+)", line)
        if left:
            pending = Fraction(left.group(1)) + shift
        if right and pending is not None:
            stop = Fraction(right.group(1)) + shift
            a, b = max(start, pending), min(end, stop)
            if a < b:
                observations.append((a, b))
            pending = None
    # An unterminated silence record is not extrapolated to source end.
    report = {
        "schema_version": "acoustic-analysis/v1",
        "run_id": directory.name,
        "source_sha256": source["sha256"],
        "source_path": str(path),
        "stream_index": stream_index,
        "domain": [str(start), str(end)],
        "offset": str(shift),
        "noise_db": noise_db,
        "min_seconds": min_seconds,
        "command": command,
        "exit_code": returncode,
        "started_at": started,
        "finished_at": now(),
        "wall_seconds": time.monotonic() - clock,
        "log": artifact_ref(log),
        "completed": completed,
        "status": "PASS" if completed and pending is None else "UNVERIFIED",
        "intervals": [
            {"start": str(a), "end": str(b), "kind": "acoustic_silence"}
            for a, b in union_intervals(observations)
        ],
        "coverage": {
            "audio_decoded_entire_stream": completed,
            "semantic_context": "UNVERIFIED",
            "unterminated_silence": pending is not None,
        },
        "owner_acceptance": "pending",
    }
    atomic_json(directory / "analysis.json", report)
    return {**report, "artifact_ref": artifact_ref(directory / "analysis.json")}


def analyze_source(
    source: dict[str, Any],
    domain: Any,
    acoustic: dict[str, Any],
    context: dict[str, Any] | None = None,
    *,
    source_kind: str = "real",
    transcript: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a complete keep/protection/candidate ledger without applying cuts.

    Context is a versioned import with real provider receipts. Explicit fixture
    context supports policy regression but is permanently marked test-only.
    """
    from .review import verify_context_execution

    start, end = _span(domain)
    if source_kind not in ("real", "fixture"):
        raise TalkCutError(
            "INVALID_SOURCE_KIND", "Use real or explicitly test-only fixture"
        )
    _verify_source(source)
    if acoustic.get("source_sha256") != source["sha256"] or [
        as_fraction(x) for x in acoustic.get("domain", [])
    ] != [start, end]:
        raise TalkCutError(
            "STALE_ANALYSIS", "Acoustic analysis belongs to another source/domain"
        )
    acoustic_ref = acoustic.get("artifact_ref")
    acoustic_valid = (
        acoustic.get("completed") is True and acoustic.get("status") == "PASS"
    )
    if source_kind == "real" and (
        not acoustic_ref or sha256(acoustic_ref["path"]) != acoustic_ref["sha256"]
    ):
        raise TalkCutError(
            "STALE_ANALYSIS", "Recorded acoustic execution artifact missing or changed"
        )
    if source_kind == "real":
        assert acoustic_ref is not None
        if read_json(acoustic_ref["path"]) != {
            key: value for key, value in acoustic.items() if key != "artifact_ref"
        }:
            raise TalkCutError(
                "STALE_ANALYSIS", "Acoustic observations differ from recorded execution"
            )
    context_error = "No executed audiovisual context analysis was supplied"
    context_valid = False
    observations: list[dict[str, Any]] = []
    if context:
        if (
            context.get("schema_version") != "lecture-context/v1"
            or context.get("source_sha256") != source["sha256"]
        ):
            raise TalkCutError(
                "INVALID_CONTEXT", "Context schema/source identity differs"
            )
        if source_kind == "fixture" and context.get("test_only") is True:
            context_valid = True
        else:
            result = verify_context_execution(context)
            context_valid = result["status"] == "PASS"
            context_error = result.get(
                "reason", "Audiovisual context execution unavailable"
            )
        for item in context.get("segments", []):
            a, b = _span(item)
            if (
                not start <= a < b <= end
                or item.get("kind") not in CONTEXT_KINDS
                or not item.get("reason")
            ):
                raise TalkCutError(
                    "INVALID_CONTEXT",
                    "Context contains invalid time, kind, or empty reason",
                )
            observations.append(item)
        if subtract_intervals(
            (start, end), [(item["start"], item["end"]) for item in observations]
        ):
            context_valid = False
            context_error = "Context observations do not cover the whole source"
    if transcript:
        if (
            transcript.get("schema_version") != "transcript/v1"
            or transcript.get("source_sha256") != source["sha256"]
        ):
            raise TalkCutError(
                "INVALID_TRANSCRIPT", "Transcript schema/source identity differs"
            )
        for item in transcript.get("segments", []):
            a, b = _span(item)
            if not start <= a < b <= end or not isinstance(item.get("text"), str):
                raise TalkCutError(
                    "INVALID_TRANSCRIPT", "Transcript has invalid timestamps or text"
                )
    protected = [
        {
            "start": item["start"],
            "end": item["end"],
            "reason": item["reason"],
            "kind": item["kind"],
            "evidence_refs": item.get("evidence_refs", []),
        }
        for item in observations
        if item["kind"] in PROTECTED_KINDS
    ]
    candidates: list[dict[str, Any]] = []
    proposer = context.get("proposer_run_id") if context else acoustic.get("run_id")
    acoustic_spans = [_span(item) for item in acoustic.get("intervals", [])]
    suggestions = [(a, b, "silence") for a, b in acoustic_spans]
    suggestions += [
        (*_span(item), "preparation" if item["kind"] == "preparation" else "disfluency")
        for item in observations
        if item["kind"] in ("preparation", "disfluency")
    ]
    for a, b, kind in suggestions:
        action, reason = "keep", context_error
        matched = [
            item for item in observations if _span(item)[0] <= a and _span(item)[1] >= b
        ]
        intersects_protection = any(
            a < _span(item)[1] and b > _span(item)[0] for item in protected
        )
        refs = ([acoustic_ref] if acoustic_ref else []) + [
            ref for item in matched for ref in item.get("evidence_refs", [])
        ]
        if context_valid and context and source_kind == "real":
            refs += [context["receipt"], context["capability"]]
        if intersects_protection:
            reason = "Preserved: candidate overlaps a demonstrated learning activity or meaningful statement"
        elif context_valid and acoustic_valid and matched:
            observation = matched[0]
            evidence = observation.get("positive_evidence", {})
            if (
                kind == "preparation"
                and a == start
                and observation["kind"] == "preparation"
                and evidence.get("before_first_substantive_content") is True
                and evidence.get("contains_introduction_or_instruction") is False
            ):
                action, reason = (
                    "auto_apply",
                    "Audiovisual context confirms preparation before the first substantive content",
                )
            elif (
                kind == "silence"
                and observation["kind"] == "disposable_pause"
                and evidence.get("no_speech") is True
                and evidence.get("no_learning_activity") is True
                and evidence.get("complete_context_checked") is True
            ):
                action, reason = (
                    "auto_apply",
                    "Acoustic non-speech and audiovisual context jointly establish a disposable pause",
                )
            elif kind == "disfluency" and observation["kind"] == "disfluency":
                action, reason = (
                    "requires_review",
                    "Speech disfluency requires a separate executed reviewer before application",
                )
            else:
                reason = "Preserved: duration or label alone does not establish a safe deletion"
        elif context_valid and not acoustic_valid:
            reason = "Preserved: the full acoustic execution is incomplete"
        candidates.append(
            {
                "id": "candidate-" + content_hash([str(a), str(b), kind])[:16],
                "start": str(a),
                "end": str(b),
                "kind": kind,
                "policy_action": action,
                "reason": reason,
                "evidence_refs": refs,
                "proposer_run_id": proposer,
                "test_only": source_kind == "fixture",
            }
        )
    candidate_spans = [(item["start"], item["end"]) for item in candidates]
    segments = [
        {
            "start": str(a),
            "end": str(b),
            "action": "keep",
            "reason": "Retained source content; no substantiated deletion candidate"
            if context_valid
            else context_error,
        }
        for a, b in subtract_intervals((start, end), candidate_spans)
    ]
    segments += [
        {
            "start": item["start"],
            "end": item["end"],
            "action": "candidate" if item["policy_action"] != "keep" else "keep",
            "reason": item["reason"],
        }
        for item in candidates
    ]
    return {
        "schema_version": "source-analysis/v1",
        "source_kind": source_kind,
        "source_hashes": {source.get("role", "screen"): source["sha256"]},
        "source_sha256": source["sha256"],
        "domain": [str(start), str(end)],
        "status": "ANALYZED"
        if context_valid and acoustic_valid
        else "ANALYSIS_UNAVAILABLE",
        "edit_disposition": "CANDIDATES_REQUIRE_REVIEW"
        if context_valid and acoustic_valid
        else "ANALYSIS_UNAVAILABLE",
        "coverage": {
            "source_domain": [str(start), str(end)],
            "acoustic_full_stream": acoustic_valid,
            "audiovisual_context_complete": context_valid,
            "uncovered_context": [] if context_valid else [[str(start), str(end)]],
        },
        "proposer_run_id": proposer,
        "prompt_sha256": context.get("prompt_sha256") if context else None,
        "segments": sorted(segments, key=lambda item: as_fraction(item["start"])),
        "protected_intervals": protected,
        "protected": protected,
        "candidates": candidates,
        "acoustic_ref": acoustic_ref,
        "context": context,
        "transcript": transcript,
        "owner_acceptance": "pending",
        "test_only": source_kind == "fixture",
    }


def authorize_automatic_candidate(
    analysis_ref: dict[str, str], candidate: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    """Re-execute policy from original acoustic/context evidence before a cut."""
    from .project import verified_json

    recorded = verified_json(analysis_ref)
    if (
        recorded.get("schema_version") != "source-analysis/v1"
        or recorded.get("source_kind") != "real"
        or recorded.get("test_only")
    ):
        raise TalkCutError(
            "REVIEW_REQUIRED",
            "Real executed source analysis is required for automatic deletion",
        )
    if candidate.get("test_only") or recorded.get("source_hashes") != plan.get(
        "source_hashes"
    ):
        raise TalkCutError(
            "STALE_ANALYSIS", "Automatic candidate belongs to another source or fixture"
        )
    inspected = verified_json(plan.get("inspection_refs", {}).get("screen", {}))
    if inspected.get("sha256") != plan["source_hashes"]["screen"]:
        raise TalkCutError("STALE_ANALYSIS", "Current screen inspection changed")
    origin = as_fraction(plan.get("timing", {}).get("screen_origin", "0"))
    measured_domain = [
        as_fraction(value) - origin for value in inspected["video"]["coverage"]
    ]
    if [as_fraction(value) for value in recorded["domain"]] != measured_domain:
        raise TalkCutError(
            "STALE_ANALYSIS", "Automatic analysis omits part of the measured source"
        )
    acoustic = verified_json(recorded.get("acoustic_ref", {}))
    acoustic["artifact_ref"] = recorded["acoustic_ref"]
    source = {"path": acoustic["source_path"], "sha256": acoustic["source_sha256"]}
    if source["sha256"] not in plan["source_hashes"].values():
        raise TalkCutError(
            "SOURCE_CHANGED", "Acoustic source is not in the current plan"
        )
    regenerated = analyze_source(
        source,
        recorded["domain"],
        acoustic,
        recorded.get("context"),
        transcript=recorded.get("transcript"),
    )
    if regenerated["status"] != "ANALYZED":
        raise TalkCutError(
            "REVIEW_REQUIRED",
            "Original audiovisual context can no longer authorize automatic edits",
        )
    if plan.get("protected_intervals") != regenerated["protected_intervals"]:
        raise TalkCutError(
            "STALE_ANALYSIS", "Current plan changed the source protection evidence"
        )
    current = next(
        (
            item
            for item in regenerated["candidates"]
            if item["id"] == candidate.get("id")
        ),
        None,
    )
    if current is None or current["policy_action"] != "auto_apply":
        raise TalkCutError(
            "REVIEW_REQUIRED",
            "Recomputed policy does not permit this automatic deletion",
        )
    if any(
        current.get(key) != candidate.get(key)
        for key in ("id", "kind", "proposer_run_id", "policy_action")
    ) or _span(current) != _span(candidate):
        raise TalkCutError(
            "STALE_ANALYSIS", "Current candidate differs from recomputed source policy"
        )
    return {
        "actor": "delegated_policy",
        "analysis_ref": analysis_ref,
        "candidate_id": current["id"],
        "requested_interval": [current["start"], current["end"]],
        "source_hashes": plan["source_hashes"],
        "recomputed_policy_action": current["policy_action"],
        "at": now(),
    }
