"""Explicit common-clock drafts with reversible edge trims and technical QC."""

from __future__ import annotations

import re
from fractions import Fraction
from pathlib import Path
from typing import Any

from .audio_processing import audio_processing_for, verify_audio_processing_binding
from .plan import compile_plan, persist_plan
from .project import (
    TalkCutError,
    artifact_ref,
    content_hash,
    load_project,
    now,
    project_lock,
    sha256,
    store_artifact,
    verified_json,
)
from .render import build_render_command, validate_render
from .timeline import as_fraction

SCOPE = "explicit_common_clock_edge_trim"
LIMITATIONS = [
    "Common clock and constant offsets are explicitly assumed, not verified audiovisual synchronization.",
    "Only requested edge trims are applied; no internal speech or semantic deletion is inferred.",
    "Technical decode, geometry and timing checks do not certify listening, content quality or owner acceptance.",
]


def _time(value: str, label: str) -> Fraction:
    if (not isinstance(value, str) or len(value) > 64
            or not re.fullmatch(r"-?[0-9]+(?:/[1-9][0-9]*|\.[0-9]+)?", value)):
        raise TalkCutError("INVALID_DRAFT_TIME", f"{label} requires a bounded exact rational time")
    result = Fraction(value)
    if abs(result) > 86400 or result.denominator > 1_000_000:
        raise TalkCutError("INVALID_DRAFT_TIME", f"{label} exceeds the one-day or microsecond rational bound")
    return result


def _inspections(project: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for role in ("screen", "speaker"):
        ref = project.get("inspections", {}).get(role)
        if not ref:
            raise TalkCutError("INPUT_UNVERIFIED", "Inspect both sources with --full-decode first")
        value = verified_json(ref)
        if (value.get("sha256") != project["sources"][role]["sha256"]
                or value.get("full_decode") is not True or value.get("status") != "PASS"
                or value.get("decode", {}).get("status") != "PASS"
                or any(value.get(k, {}).get("status") != "PASS" for k in ("audio", "video"))):
            raise TalkCutError("INPUT_UNVERIFIED", "Current complete source decode and stream inventories are required")
        result[role] = value
    return result


def validate_draft_plan(project: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    """Keep the explicit draft route separate from legacy reviewed plans."""
    _inspections(project)
    if (plan.get("draft_scope") != SCOPE or plan.get("test_only") is not False
            or plan.get("timing", {}).get("status") != "ASSUMED_COMMON_CLOCK"
            or plan.get("analysis_ref") is not None or plan.get("protected_intervals") != []):
        raise TalkCutError("DRAFT_REQUIRED", "This operation requires an explicit common-clock edge-trim draft")
    if plan.get("inspection_refs") != project["inspections"]:
        raise TalkCutError("STALE_INSPECTION", "Draft inspection references differ from the current project")
    timing = plan["timing"]
    if (timing.get("audio_source") not in {"screen", "speaker"}
            or any(timing.get(k) != "0" for k in ("screen_origin", "speaker_origin", "audio_origin"))
            or any(timing.get(k) != "1" for k in ("speaker_rate", "audio_rate"))):
        raise TalkCutError("INVALID_DRAFT", "Draft timing must retain the declared common source clock")
    for key in ("speaker_offset", "audio_offset"):
        _time(timing.get(key), key)
    timeline = compile_plan(project, plan)
    domain = timeline["domain"]
    start, end = as_fraction(domain["start"]), as_fraction(domain["end"])
    candidates = plan.get("candidates")
    if not isinstance(candidates, list) or len(candidates) > 2:
        raise TalkCutError("INVALID_DRAFT", "A draft permits only two edge trims")
    seen = set()
    for candidate in candidates:
        edge = candidate.get("edge")
        if (edge not in {"start", "end"} or edge in seen
                or candidate.get("kind") != "explicit_edge_trim"
                or candidate.get("decision") not in {"accepted", "restored", "kept"}
                or candidate.get("test_only") is not False):
            raise TalkCutError("INVALID_DRAFT", "Draft candidates must remain explicit edge trims")
        a, b = as_fraction(candidate["start"]), as_fraction(candidate["end"])
        if not start <= a < b <= end or (a != start if edge == "start" else b != end):
            raise TalkCutError("INVALID_DRAFT", "An internal deletion cannot enter the edge-trim draft")
        seen.add(edge)
    return timeline


def build_draft(directory: str | Path, *, audio_source: str, speaker_offset: str,
                audio_offset: str, trim_start: str, trim_end: str, reason: str,
                expected_revision: int) -> dict[str, Any]:
    directory = Path(directory)
    if audio_source not in {"screen", "speaker"}:
        raise TalkCutError("INVALID_AUDIO_SOURCE", "Choose exactly screen or speaker audio")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
        raise TalkCutError("INVALID_REASON", "A nonempty draft reason of at most 4000 characters is required")
    offsets = {key: _time(value, key) for key, value in (
        ("speaker_offset", speaker_offset), ("audio_offset", audio_offset))}
    trims = {key: _time(value, key) for key, value in (("start", trim_start), ("end", trim_end))}
    with project_lock(directory):
        project = load_project(directory)
        if type(expected_revision) is not int or project["revision"] != expected_revision:
            raise TalkCutError("REVISION_CONFLICT", "Reopen the project before building a draft")
        inspections = _inspections(project)
        screen = inspections["screen"]["video"]
        start, end = map(as_fraction, screen["coverage"])
        duration = end - start
        if (duration <= 0 or any(value < 0 for value in trims.values())
                or sum(trims.values()) >= duration):
            raise TalkCutError("INVALID_DRAFT_TRIM", "Nonnegative edge trims must leave source material")
        if any(abs(value) >= duration for value in offsets.values()):
            raise TalkCutError("INVALID_DRAFT_OFFSET", "Offsets must be smaller than the source screen duration")
        speaker_start, speaker_end = map(as_fraction, inspections["speaker"]["video"]["coverage"])
        if max(start + trims["start"], speaker_start + offsets["speaker_offset"]) >= min(
                end - trims["end"], speaker_end + offsets["speaker_offset"]):
            raise TalkCutError("SPEAKER_UNCOVERED", "The selected speaker offset leaves no retained speaker coverage")
        candidates = []
        for edge, amount in trims.items():
            if not amount:
                continue
            a, b = (start, start + amount) if edge == "start" else (end - amount, end)
            candidates.append({
                "id": "draft-" + edge + "-" + content_hash({"start": str(a), "end": str(b)})[:16],
                "edge": edge, "start": str(a), "end": str(b), "kind": "explicit_edge_trim",
                "policy_action": "explicit_draft_request", "decision": "accepted", "test_only": False,
                "reason": reason.strip(), "decision_evidence": {"actor": "explicit_draft_request", "at": now()},
            })
        plan = {
            "schema_version": "edit-plan/v1", "created_at": now(), "parent": project["active_plan"],
            "source_hashes": {key: value["sha256"] for key, value in project["sources"].items()},
            "contract_hash": artifact_ref(directory / "frozen-contract.local.json")["sha256"]
            if (directory / "frozen-contract.local.json").exists() else None,
            "inspection_refs": project["inspections"], "analysis_ref": None,
            "timing": {"audio_source": audio_source, "screen_origin": "0", "audio_origin": "0",
                       "speaker_origin": "0", "audio_rate": "1", "speaker_rate": "1",
                       **{key: str(value) for key, value in offsets.items()}, "status": "ASSUMED_COMMON_CLOCK"},
            "layout": project["layout"], "audio_processing": audio_processing_for(project),
            "audio_processing_reason": project.get("audio_processing_reason", "Original audio; no level processing"),
            "test_only": False, "draft_scope": SCOPE, "draft_reason": reason.strip(),
            "requested_edge_trims": {key: str(value) for key, value in trims.items()},
            "limitations": LIMITATIONS, "protected_intervals": [], "candidates": candidates,
            "edit_disposition": "EXPLICIT_EDGE_TRIMS" if candidates else "COMPOSITION_ONLY", "owner_acceptance": "pending",
        }
        validate_draft_plan(project, plan)
        return {**persist_plan(directory, project, plan, "draft_build"), "draft_scope": SCOPE,
                "timing_status": "ASSUMED_COMMON_CLOCK", "limitations": LIMITATIONS}


def evaluate_draft(directory: str | Path) -> dict[str, Any]:
    """Recheck the active draft and fully decode its exact current render."""
    from .contracts import code_identity

    directory = Path(directory)
    with project_lock(directory):
        code = code_identity(Path.cwd())
        project = load_project(directory)
        if not project.get("active_plan"):
            raise TalkCutError("DRAFT_REQUIRED", "Build an explicit draft before evaluating it")
        plan = verified_json(project["active_plan"])
        timeline = validate_draft_plan(project, plan)
        if timeline != verified_json(project["active_timeline"]):
            raise TalkCutError("STALE_TIMELINE", "The current draft no longer compiles to the rendered timeline")
        if not project.get("active_render"):
            raise TalkCutError("RENDER_REQUIRED", "Render the draft before evaluating it")
        success = verified_json(project["active_render"])
        native = verified_json(success["native_render"])
        settings = success["settings"]
        if (success.get("profile") != "draft" or success.get("test_only") is not False
                or success.get("status") != "RENDERED" or success.get("render_id") != content_hash(settings)
                or settings.get("plan") != project["active_plan"] or settings.get("timeline") != project["active_timeline"]
                or settings.get("profile") != "draft" or settings.get("layout") != plan["layout"]
                or native.get("status") != "succeeded" or native.get("complete") is not True
                or native.get("exit_code") != 0 or native.get("timeline_hash") != timeline["timeline_hash"]
                or native.get("output") != success.get("output")):
            raise TalkCutError("STALE_RENDER", "Draft output must match the complete current plan and native render")
        verify_audio_processing_binding(plan, timeline, settings, native)
        inspections = _inspections(project)
        sources = {role: {"path": project["sources"][role]["path"], "sha256": project["sources"][role]["sha256"],
                         "stream_index": inspections[role]["video"]["index"],
                         "width": inspections[role]["video"]["width"], "height": inspections[role]["video"]["height"],
                         "sar": inspections[role]["video"]["sample_aspect_ratio"]} for role in ("screen", "speaker")}
        audio_role = plan["timing"]["audio_source"]
        sources["audio"] = {"path": project["sources"][audio_role]["path"], "sha256": project["sources"][audio_role]["sha256"],
                            "stream_index": inspections[audio_role]["audio"]["index"], "sample_rate": timeline["sample_rate"]}
        expected_fingerprints = {role: {"path": str(Path(source["path"]).resolve()), "sha256": source["sha256"],
                                        "bytes": Path(source["path"]).stat().st_size} for role, source in sources.items()}
        if native.get("sources") != expected_fingerprints:
            raise TalkCutError("STALE_RENDER", "Rendered tracks differ from the explicitly chosen draft sources")
        recipe = build_render_command(timeline, sources, native["command"][-1], plan["layout"],
                                      ffmpeg=native["command"][0], preset=settings["preset"], crf=settings["crf"])
        if any(recipe[key] != native.get(key) for key in ("command", "filtergraph", "layout", "audio_processing")):
            raise TalkCutError("STALE_RENDER", "Rendered recipe differs from the current draft")
        implementation = {name: sha256(Path(__file__).with_name(name))
                          for name in ("render.py", "timeline.py", "audio_processing.py")}
        if settings.get("implementation") != implementation:
            raise TalkCutError("STALE_RENDER", "Rendering implementation changed after this output")
        refs = [artifact_ref(directory / "project.json"), project["active_plan"], project["active_timeline"],
                project["active_render"], success["native_render"], *project["inspections"].values(),
                *({"path": s["path"], "sha256": s["sha256"]} for s in project["sources"].values()),
                {"path": native["output"]["path"], "sha256": native["output"]["sha256"]}]
        for ref in refs:
            if artifact_ref(ref["path"]) != ref:
                raise TalkCutError("SOURCE_CHANGED", "A draft input or output changed before evaluation")
        technical = validate_render(native["output"]["path"], timeline, native["layout"], timeout=14400)
        for ref in refs:
            if artifact_ref(ref["path"]) != ref:
                raise TalkCutError("SOURCE_CHANGED", "A draft input or output changed during evaluation")
        if code_identity(Path.cwd()) != code:
            raise TalkCutError("SOURCE_CHANGED", "Code changed during draft evaluation")
        report = {"schema_version": "draft-evaluation/v1", "status": "DRAFT_TECHNICALLY_READY",
                  "draft_scope": SCOPE, "project_revision": project["revision"], "plan": project["active_plan"],
                  "timeline": project["active_timeline"], "workflow_render": project["active_render"],
                  "native_render": success["native_render"], "output": native["output"], "technical": technical,
                  "timing": plan["timing"], "requested_edge_trims": plan["requested_edge_trims"],
                  "applied_edge_trims": timeline["cuts"], "speaker_omissions": timeline["speaker_omissions"],
                  "input_refs": refs, "code_identity": code, "source_hashes": plan["source_hashes"],
                  "limitations": LIMITATIONS, "ai_review": "UNVERIFIED", "owner_acceptance": "pending"}
        return {**report, "artifact_ref": store_artifact(directory, "reports", report)}
