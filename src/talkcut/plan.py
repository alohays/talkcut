"""Immutable edit revisions compiled onto one measured source timeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .audio_processing import audio_processing_for, validate_audio_processing
from .project import (
    TalkCutError,
    artifact_ref,
    content_hash,
    load_project,
    now,
    project_lock,
    save_revision,
    store_artifact,
    verified_json,
)
from .timeline import as_fraction, compile_timeline


def compile_plan(project: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    sources = project["sources"]
    if plan["source_hashes"] != {k: v["sha256"] for k, v in sources.items()}:
        raise TalkCutError("SOURCE_CHANGED", "Plan depends on different source bytes")
    inspections = {
        k: verified_json(project["inspections"][k]) for k in ("screen", "speaker")
    }
    for role, value in inspections.items():
        if value["sha256"] != sources[role]["sha256"] or value["status"] != "PASS":
            raise TalkCutError(
                "INPUT_UNVERIFIED", "A complete current source inspection is required"
            )
    screen, speaker = inspections["screen"], inspections["speaker"]
    settings = plan["timing"]
    audio_role = settings["audio_source"]
    if audio_role not in inspections:
        raise TalkCutError(
            "AUDIO_UNVERIFIED", "Choose exactly one inspected audio source"
        )
    audio = inspections[audio_role]["audio"]
    selected = [
        candidate
        for candidate in plan["candidates"]
        if candidate["decision"] == "accepted"
    ]
    timeline = compile_timeline(
        screen["video"]["frames"],
        screen["video"]["time_base"],
        settings["screen_origin"],
        [
            {"id": item["id"], "start": item["start"], "end": item["end"]}
            for item in selected
        ],
        protected=plan["protected_intervals"],
        sample_rate=audio["sample_rate"],
        audio={
            "origin": settings["audio_origin"],
            "offset": settings["audio_offset"],
            "rate": settings["audio_rate"],
            "start": audio["coverage"][0],
            "end": audio["coverage"][1],
        },
        speaker={
            "origin": settings["speaker_origin"],
            "offset": settings["speaker_offset"],
            "rate": settings["speaker_rate"],
            "start": speaker["video"]["coverage"][0],
            "end": speaker["video"]["coverage"][1],
        },
        plan_hash=content_hash(plan),
    )
    if "audio_processing" in plan:
        import hashlib
        import json

        timeline["audio_processing"] = validate_audio_processing(plan["audio_processing"])
        timeline.pop("timeline_hash")
        timeline["timeline_hash"] = hashlib.sha256(json.dumps(timeline, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return timeline


def persist_plan(
    directory: Path, project: dict[str, Any], plan: dict[str, Any], action: str
) -> dict[str, Any]:
    timeline = compile_plan(project, plan)
    timeline_ref = store_artifact(directory, "timelines", timeline)
    plan_ref = store_artifact(directory, "plans", plan)
    project["active_plan"] = plan_ref
    project["active_timeline"] = timeline_ref
    project["active_render"] = None
    project["owner_acceptance"] = "pending"
    save_revision(
        directory,
        project,
        project["revision"],
        action,
        {
            "plan": plan_ref,
            "timeline": timeline_ref,
            "invalidated": ["output_qc", "all_seams", "whole_output_review", "ready"],
        },
    )
    return {
        "schema_version": "plan-operation/v1",
        "status": "DRAFT",
        "project_revision": project["revision"],
        "plan": plan_ref,
        "timeline": timeline_ref,
        "test_only": plan["test_only"],
        "applied_cuts": sum(c["decision"] == "accepted" for c in plan["candidates"]),
    }


def build_plan(
    directory: str | Path,
    *,
    diagnostic: bool = False,
    analysis_ref: dict[str, str] | None = None,
) -> dict[str, Any]:
    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        if diagnostic:
            settings = {
                "audio_source": "screen",
                "screen_origin": "0",
                "audio_origin": "0",
                "audio_offset": "0",
                "audio_rate": "1",
                "speaker_origin": "0",
                "speaker_offset": "0",
                "speaker_rate": "1",
                "status": "UNVERIFIED",
            }
        else:
            if project.get("sync") is None:
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Import verified track mapping before a final edit plan",
                )
            from .sync import verify_sync_model

            sync = verify_sync_model(project["sync"], project)
            settings = sync["timing"]
        candidates, protected = [], []
        if analysis_ref:
            analysis = verified_json(analysis_ref)
            if analysis.get("source_hashes") != {
                k: v["sha256"] for k, v in project["sources"].items()
            }:
                raise TalkCutError(
                    "SOURCE_CHANGED", "Analysis belongs to different source bytes"
                )
            protected = analysis["protected_intervals"]
            candidates = [
                {
                    **candidate,
                    "decision": "proposed"
                    if candidate["policy_action"] != "keep"
                    else "kept",
                }
                for candidate in analysis["candidates"]
            ]
        plan = {
            "schema_version": "edit-plan/v1",
            "created_at": now(),
            "parent": project["active_plan"],
            "source_hashes": {k: v["sha256"] for k, v in project["sources"].items()},
            "contract_hash": artifact_ref(directory / "frozen-contract.local.json")[
                "sha256"
            ]
            if (directory / "frozen-contract.local.json").exists()
            else None,
            "inspection_refs": project["inspections"],
            "analysis_ref": analysis_ref,
            "timing": settings,
            "layout": project["layout"],
            "audio_processing": audio_processing_for(project),
            "audio_processing_reason": project.get("audio_processing_reason", "Original audio; no level processing"),
            "test_only": diagnostic,
            "protected_intervals": protected,
            "candidates": candidates,
            "edit_disposition": "COMPOSITION_ONLY"
            if not analysis_ref
            else "PENDING_REVIEW",
            "owner_acceptance": "pending",
        }
        return persist_plan(directory, project, plan, "plan_build")


def add_test_cut(
    directory: str | Path, start: str, end: str, expected_revision: int
) -> dict[str, Any]:
    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        if project["revision"] != expected_revision:
            raise TalkCutError(
                "REVISION_CONFLICT",
                "Reopen the latest project before adding a test cut",
            )
        plan = verified_json(project["active_plan"])
        if not plan["test_only"]:
            raise TalkCutError(
                "TEST_PLAN_REQUIRED",
                "Roundtrip experiments require a separate diagnostic plan",
            )
        if as_fraction(end) <= as_fraction(start):
            raise TalkCutError("INVALID_SPAN", "Test cut must have positive duration")
        candidate_id = "test-" + content_hash({"start": start, "end": end})[:16]
        if any(c["id"] == candidate_id for c in plan["candidates"]):
            raise TalkCutError(
                "CANDIDATE_EXISTS",
                "Use decide or restore on the existing test candidate",
            )
        plan["parent"] = project["active_plan"]
        plan["candidates"].append(
            {
                "id": candidate_id,
                "start": start,
                "end": end,
                "kind": "test_only",
                "policy_action": "requires_review",
                "decision": "proposed",
                "test_only": True,
                "reason": "Explicit reversible timing experiment; never eligible for final master",
            }
        )
        result = persist_plan(directory, project, plan, "test_cut_proposed")
        return {**result, "candidate_id": candidate_id}


def decide(
    directory: str | Path,
    candidate_id: str,
    decision: str,
    expected_revision: int,
    review_ref: dict[str, str] | None = None,
) -> dict[str, Any]:
    if decision not in ("accept", "keep", "restore"):
        raise TalkCutError("INVALID_DECISION", decision)
    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        if project["revision"] != expected_revision:
            raise TalkCutError(
                "REVISION_CONFLICT", "Decision would overwrite a newer project revision"
            )
        plan = verified_json(project["active_plan"])
        candidate = next(
            (c for c in plan["candidates"] if c["id"] == candidate_id), None
        )
        if candidate is None:
            raise TalkCutError("CANDIDATE_MISSING", candidate_id)
        actor = "workflow_restore" if decision == "restore" else "workflow_keep"
        if decision == "accept":
            if plan["test_only"] and candidate.get("test_only"):
                actor = "test_only_experiment"
            elif candidate["policy_action"] == "auto_apply" and candidate.get(
                "evidence_refs"
            ):
                from .analysis import authorize_automatic_candidate

                authorize_automatic_candidate(plan["analysis_ref"], candidate, plan)
                actor = "delegated_policy"
            else:
                if review_ref is None:
                    raise TalkCutError(
                        "REVIEW_REQUIRED",
                        "This deletion needs a separate audiovisual review",
                    )
                from .review import authorize_candidate_review

                authorize_candidate_review(review_ref, candidate, plan)
                actor = "delegated_ai_reviewer"
        candidate["decision"] = {
            "accept": "accepted",
            "keep": "kept",
            "restore": "restored",
        }[decision]
        candidate["decision_evidence"] = {
            "actor": actor,
            "review": review_ref,
            "at": now(),
        }
        plan["parent"] = project["active_plan"]
        return persist_plan(directory, project, plan, f"candidate_{decision}")


def set_audio_profile(directory: str | Path, gain_db: str, reason: str, expected_revision: int) -> dict[str, Any]:
    """Revise the plan, preserving prior outputs and invalidating derived review."""
    profile = validate_audio_processing({"schema_version": "audio-processing/v1", "gain_db": gain_db})
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
        raise TalkCutError("INVALID_REASON", "A nonempty audio-profile reason is required (maximum 4000 characters)")
    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        if type(expected_revision) is not int or project["revision"] != expected_revision:
            raise TalkCutError("REVISION_CONFLICT", "Audio profile would overwrite a newer project revision")
        if not project.get("active_plan"):
            raise TalkCutError("PLAN_REQUIRED", "Build a plan before setting its audio profile")
        plan = verified_json(project["active_plan"])
        previous = audio_processing_for(plan)
        plan["parent"] = project["active_plan"]
        plan["audio_processing"] = profile
        plan["audio_processing_reason"] = reason.strip()
        plan["audio_processing_change"] = {"previous": previous, "at": now(), "reason": reason.strip()}
        project["audio_processing"] = profile
        project["audio_processing_reason"] = reason.strip()
        result = persist_plan(directory, project, plan, "audio_profile_changed")
        return {**result, "audio_processing": profile, "reason": reason.strip()}
