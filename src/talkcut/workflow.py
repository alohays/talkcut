"""Application API joining immutable plans, rendering and technical QC."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    load_project,
    project_lock,
    save_revision,
    sha256,
    store_artifact,
    verified_json,
)
from .render import build_render_command, render, validate_render


def render_project(
    directory: str | Path,
    profile: str = "diagnostic",
    *,
    preset: str = "medium",
    crf: int = 18,
) -> dict[str, Any]:
    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        plan = verified_json(project["active_plan"])
        from .audio_processing import audio_processing_for

        audio_profile = audio_processing_for(plan)
        if audio_profile != audio_processing_for(project):
            raise TalkCutError("STALE_AUDIO_PROFILE", "Active plan and current project audio profiles differ")
        timeline = verified_json(project["active_timeline"])
        if ("audio_processing" in plan and "audio_processing" not in timeline) or audio_processing_for(timeline) != audio_profile:
            raise TalkCutError("STALE_AUDIO_PROFILE", "Active timeline audio profile differs from its immutable plan")
        if timeline["plan_hash"] != content_hash(plan):
            raise TalkCutError(
                "STALE_TIMELINE", "Resolved timeline depends on a different plan"
            )
        if profile == "draft":
            from .draft import validate_draft_plan

            if validate_draft_plan(project, plan) != timeline:
                raise TalkCutError("STALE_TIMELINE", "Draft timeline differs from its complete plan")
        if profile == "master" and (
            plan["test_only"] or plan["timing"]["status"] != "PASS"
        ):
            raise TalkCutError(
                "SYNC_UNVERIFIED",
                "Diagnostic or unverified plans cannot render a master",
            )
        inspections = {
            role: verified_json(project["inspections"][role])
            for role in ("screen", "speaker")
        }
        sources = {
            role: {
                "path": project["sources"][role]["path"],
                "sha256": project["sources"][role]["sha256"],
                "stream_index": inspections[role]["video"]["index"],
                "width": inspections[role]["video"]["width"],
                "height": inspections[role]["video"]["height"],
                "sar": inspections[role]["video"]["sample_aspect_ratio"],
            }
            for role in ("screen", "speaker")
        }
        audio_role = plan["timing"]["audio_source"]
        sources["audio"] = {
            "path": project["sources"][audio_role]["path"],
            "sha256": project["sources"][audio_role]["sha256"],
            "stream_index": inspections[audio_role]["audio"]["index"],
            "sample_rate": timeline["sample_rate"],
        }
        # Rendering implementation is part of the cache identity. A former
        # successful artifact remains on disk when the renderer changes.
        implementation = {
            name: sha256(Path(__file__).with_name(name))
            for name in ("render.py", "timeline.py", "audio_processing.py")
        }
        from .media import doctor

        toolchain = doctor()
        settings = {
            "plan": project["active_plan"],
            "timeline": project["active_timeline"],
            "layout": plan["layout"],
            "audio_processing": audio_profile,
            "implementation": implementation,
            "toolchain": toolchain,
            "profile": profile,
            "preset": preset,
            "crf": crf,
        }
        key = content_hash(settings)
        destination = directory / "renders" / key
        success_path = destination / "success.json"
        if success_path.exists():
            from .project import read_json

            success = read_json(success_path)
            native = verified_json(success["native_render"])
            if (
                success.get("render_id") != key
                or success.get("settings") != settings
                or native.get("timeline_hash") != timeline["timeline_hash"]
                or native.get("audio_processing") != audio_profile
                or success.get("profile") != profile
                or success.get("test_only") != plan["test_only"]
                or success.get("output") != native.get("output")
                or native.get("status") != "succeeded"
                or native.get("exit_code") != 0
            ):
                raise TalkCutError(
                    "STALE_RENDER",
                    "Cached render is not bound to this plan, timeline and profile",
                )
            for role, source in sources.items():
                old = native.get("sources", {}).get(role, {})
                if (
                    old.get("sha256") != source["sha256"]
                    or Path(old.get("path", "")).resolve()
                    != Path(source["path"]).resolve()
                ):
                    raise TalkCutError(
                        "STALE_RENDER", "Cached render used different source inputs"
                    )
            recipe = build_render_command(timeline, sources, native["command"][-1], plan["layout"],
                                          ffmpeg=native["command"][0], preset=preset, crf=crf)
            if any(recipe[key] != native.get(key) for key in ("command", "filtergraph", "layout", "audio_processing")):
                raise TalkCutError("STALE_RENDER", "Cached command differs from the exact plan-bound audio/render recipe")
            output = native["output"]
            if sha256(output["path"]) != output["sha256"] or not native.get("complete"):
                raise TalkCutError(
                    "STALE_RENDER", "Former output or render manifest changed"
                )
            project["active_render"] = artifact_ref(success_path)
            save_revision(
                directory,
                project,
                project["revision"],
                "render_cache_reused",
                {"render": project["active_render"]},
            )
            return {
                **success,
                "cache_hit": True,
                "project_revision": project["revision"],
            }
        destination.mkdir(parents=True, exist_ok=True)
        native = render(
            timeline,
            sources,
            destination / f"{profile}.mp4",
            plan["layout"],
            preset=preset,
            crf=crf,
            timeout=14400,
        )
        success = {
            "schema_version": "workflow-render/v1",
            "render_id": key,
            "native_render": artifact_ref(native["manifest_path"]),
            "settings": settings,
            "output": native["output"],
            "profile": profile,
            "test_only": plan["test_only"],
            "status": "RENDERED",
            "ai_review": "UNVERIFIED",
            "owner_acceptance": "pending",
        }
        atomic_json(success_path, success)
        project["active_render"] = artifact_ref(success_path)
        save_revision(
            directory,
            project,
            project["revision"],
            "render_completed",
            {"render": project["active_render"]},
        )
        return {**success, "cache_hit": False, "project_revision": project["revision"]}


def qc_project(directory: str | Path) -> dict[str, Any]:
    directory = Path(directory)
    project = load_project(directory)
    success = verified_json(project["active_render"])
    native = verified_json(success["native_render"])
    output = native["output"]
    if sha256(output["path"]) != output["sha256"]:
        raise TalkCutError("STALE_RENDER", "Output hash changed")
    timeline = verified_json(project["active_timeline"])
    plan = verified_json(project["active_plan"])
    from .audio_processing import verify_audio_processing_binding

    verify_audio_processing_binding(plan, timeline, success["settings"], native)
    if native["timeline_hash"] != timeline["timeline_hash"]:
        raise TalkCutError(
            "STALE_TIMELINE", "Current plan is different from rendered plan"
        )
    result = validate_render(output["path"], timeline, native["layout"], timeout=14400)
    report = {
        "schema_version": "workflow-qc/v1",
        "output": output,
        "timeline": project["active_timeline"],
        "native_render": success["native_render"],
        "technical": result,
        "status": "UNVERIFIED",
        "reason": "Technical timing/decode passed; audiovisual and source-difference checks are separate",
        "owner_acceptance": "pending",
    }
    ref = store_artifact(directory, "reports", report)
    return {**report, "artifact_ref": ref}


def compare_source(
    directory: str | Path, render_manifest: Path | None = None
) -> dict[str, Any]:
    """Measure all actual retained media; detections require separate resolution."""
    from uuid import uuid4

    from .quality import compare_render

    directory = Path(directory)
    project = load_project(directory)
    ref = artifact_ref(render_manifest) if render_manifest else project["active_render"]
    return compare_render(ref, directory / "quality" / uuid4().hex)


def analyze_project(
    directory: str | Path, context: Path | None = None, transcript: Path | None = None
) -> dict[str, Any]:
    from .analysis import analyze_source, detect_silence
    from .contracts import code_identity
    from .project import read_json

    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        inspected = verified_json(project["inspections"]["screen"])
        source = project["sources"]["screen"]
        domain = inspected["video"]["coverage"]
        acoustic = detect_silence(
            source, inspected["audio"]["index"], domain, directory / "analysis"
        )
        result = analyze_source(
            source,
            domain,
            acoustic,
            read_json(context) if context else None,
            transcript=read_json(transcript) if transcript else None,
            expected_dependencies={
                "source_hashes": {
                    k: v["sha256"] for k, v in project["sources"].items()
                },
                "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
                "contract_hash": artifact_ref(directory / "frozen-contract.local.json")[
                    "sha256"
                ]
                if (directory / "frozen-contract.local.json").exists()
                else None,
            },
        )
        result["source_hashes"] = {
            k: v["sha256"] for k, v in project["sources"].items()
        }
        ref = store_artifact(directory, "analysis", result)
        project["analysis"] = ref
        save_revision(
            directory,
            project,
            project["revision"],
            "source_analysis",
            {"analysis": ref},
        )
        # Preserve the original proposal artifact. Final decisions live in the
        # immutable active plan and require a new editorial command binding.
        index_path = directory / "acceptance.local.json"
        index = (
            read_json(index_path)
            if index_path.exists()
            else {
                "schema_version": "acceptance-index/v1",
                "checks": {},
                "reviews": [],
                "capabilities": [],
                "findings": [],
                "owner_acceptance": "pending",
            }
        )
        if (
            index.get("schema_version") != "acceptance-index/v1"
            or index.get("owner_acceptance", "pending") != "pending"
        ):
            raise TalkCutError("INDEX_INVALID", "Existing acceptance index is invalid")
        index["owner_acceptance"] = "pending"
        if index_path.exists():
            previous = artifact_ref(index_path)
            backup = (
                directory / "evidence" / "index-history" / f"{previous['sha256']}.json"
            )
            backup.parent.mkdir(parents=True, exist_ok=True)
            if not backup.exists():
                with backup.open("xb") as handle:
                    handle.write(index_path.read_bytes())
            if sha256(backup) != previous["sha256"]:
                raise TalkCutError(
                    "INDEX_CHANGED", "Previous acceptance index backup differs"
                )
        index["analysis"] = ref
        index.pop("editorial", None)
        index.pop("edit_disposition", None)
        atomic_json(index_path, index)
        return {
            "schema_version": "analysis-operation/v1",
            "status": result["status"],
            "artifact_ref": ref,
            "candidate_count": len(result["candidates"]),
            "protected_count": len(result["protected_intervals"]),
            "coverage": result["coverage"],
            "project_revision": project["revision"],
        }


def collect_contexts(
    directory: Path,
    children: list[Path],
    contract: Path,
    capability: Path,
    output: Path,
) -> dict[str, Any]:
    """Read a current project and construct verified child context references."""
    from .context_collection import build_context_collection
    from .contracts import code_identity

    project = load_project(directory)
    inspected = verified_json(project["inspections"]["screen"])
    if inspected.get("sha256") != project["sources"]["screen"]["sha256"]:
        raise TalkCutError(
            "STALE_CONTEXT", "Context source inspection differs from registered source"
        )
    if not children:
        raise TalkCutError(
            "CONTEXT_MISSING", "Original child context paths are required"
        )
    refs = [artifact_ref(path) for path in children]
    first = verified_json(refs[0])
    dependencies = first.get("dependencies", {})
    expected = {
        "source_hashes": {k: v["sha256"] for k, v in project["sources"].items()},
        "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
        "contract_hash": artifact_ref(contract)["sha256"],
    }
    if any(dependencies.get(key) != value for key, value in expected.items()):
        raise TalkCutError(
            "STALE_CONTEXT", "Child source/code/contract differs from current project"
        )
    if "output_hash" in dependencies:
        rendered = verified_json(project.get("active_render", {}))
        if rendered.get("output", {}).get("sha256") != dependencies["output_hash"]:
            raise TalkCutError(
                "STALE_CONTEXT", "Context references a different current render"
            )
    if (
        "timeline_hash" in dependencies
        and project.get("active_timeline", {}).get("sha256")
        != dependencies["timeline_hash"]
    ):
        raise TalkCutError(
            "STALE_CONTEXT", "Context references a different current timeline"
        )
    return build_context_collection(
        refs,
        source_sha256=project["sources"]["screen"]["sha256"],
        domain=inspected["video"]["coverage"],
        dependencies=dependencies,
        contract=artifact_ref(contract),
        capability=artifact_ref(capability),
        output=output,
    )


def build_reviews(directory: str | Path) -> dict[str, Any]:
    from .contracts import code_identity
    from .review import build_review_bundle

    directory = Path(directory)
    project = load_project(directory)
    plan = verified_json(project["active_plan"])
    timeline = verified_json(project["active_timeline"])
    success = verified_json(project["active_render"])
    native = verified_json(success["native_render"])
    if native["timeline_hash"] != timeline["timeline_hash"]:
        raise TalkCutError(
            "STALE_RENDER", "Build review clips only from the current actual render"
        )
    deps = {
        "source_hashes": plan["source_hashes"],
        "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
        "contract_hash": plan["contract_hash"],
        "plan_hash": content_hash(plan),
        "timeline_hash": project["active_timeline"]["sha256"],
        "output_hash": success["output"]["sha256"],
    }
    return build_review_bundle(
        directory,
        timeline,
        project["sources"]["screen"],
        success["output"],
        directory / "review",
        deps,
    )


def prepare_release(directory: str | Path, contract: str | Path) -> dict[str, Any]:
    from .acceptance import evaluate
    from .contracts import code_identity
    from .project import read_json

    directory = Path(directory)
    project = load_project(directory)
    success = verified_json(project["active_render"])
    report = evaluate(directory, success["render_id"], contract, repo_root=Path.cwd())
    report_ref = store_artifact(directory, "reports", report)
    if report["media_state"] != "READY_FOR_OWNER":
        return {
            "schema_version": "prepare-release/v1",
            "status": "UNVERIFIED",
            "acceptance": report_ref,
            "reason": "Required G0–G5 evidence is incomplete or invalid",
            "owner_acceptance": "pending",
        }
    plan = verified_json(project["active_plan"])
    native = verified_json(success["native_render"])
    checkpoint_path = directory / "checkpoint.local.json"
    if not checkpoint_path.is_file():
        raise TalkCutError(
            "CHECKPOINT_REQUIRED", "A private checkpoint is required for handoff"
        )
    checkpoint = read_json(checkpoint_path)
    checkpoint_ref = store_artifact(directory, "releases/checkpoints", checkpoint)
    dependencies = {
        "code_tree_hash": code_identity(Path.cwd())["code_tree_hash"],
        "contract_hash": artifact_ref(contract)["sha256"],
        "source_hashes": {k: v["sha256"] for k, v in project["sources"].items()},
        "timeline_hash": project["active_timeline"]["sha256"],
        "output_hash": success["output"]["sha256"],
    }
    private_project = str(directory.resolve())
    prefix = ["uv", "run", "--locked", "talkcut"]
    rerun_commands = [
        prefix + ["status", private_project, "--json"],
        prefix
        + [
            "render",
            private_project,
            "--profile",
            "master",
            "--preset",
            success["settings"]["preset"],
            "--crf",
            str(success["settings"]["crf"]),
            "--json",
        ],
        prefix + ["qc", private_project, "--json"],
        prefix
        + [
            "acceptance",
            "evaluate",
            private_project,
            "--render",
            success["render_id"],
            "--contract",
            str(Path(contract).resolve()),
            "--json",
        ],
    ]
    restore_commands = [
        {
            "candidate_id": candidate["id"],
            "read_latest_revision_with": prefix + ["status", private_project, "--json"],
            "argv": prefix
            + [
                "plan",
                "restore",
                private_project,
                "--candidate",
                candidate["id"],
                "--expected-revision",
                "<revision returned by status>",
                "--json",
            ],
            "after_restore": "Render the changed plan, regenerate affected reviews and all final output gates",
        }
        for candidate in plan["candidates"]
        if candidate["decision"] == "accepted"
    ]
    manifest = {
        "schema_version": "private-handoff/v1",
        "status": "READY_FOR_OWNER",
        "dependencies": dependencies,
        "output": success["output"],
        "final_output_path": success["output"]["path"],
        "native_render": success["native_render"],
        "plan": project["active_plan"],
        "timeline": project["active_timeline"],
        "project_path": private_project,
        "command_working_directory": str(Path.cwd()),
        "rerun_commands": rerun_commands,
        "restore_commands": restore_commands,
        "restore_disposition": "No accepted deletion to restore"
        if not restore_commands
        else "Per-candidate restore",
        "actual_measurements": {
            "technical": native["validation"],
            "coverage": report["coverage"],
        },
        "cost_usage": checkpoint.get("cost_usage", {"status": "unavailable"}),
        "unfulfilled_ac": [
            item["id"] for item in report["criteria"] if item["status"] != "PASS"
        ],
        "checkpoint": checkpoint_ref,
        "owner_acceptance": "pending",
    }
    ref = store_artifact(directory, "releases", manifest)
    # The frozen handoff contains direct evidence, not the aggregate report that
    # will later include this handoff and the independent auditor's verdict.
    with project_lock(directory):
        current = load_project(directory)
        if current["revision"] != project["revision"]:
            raise TalkCutError(
                "REVISION_CONFLICT", "Project changed during handoff preparation"
            )
        index_path = directory / "acceptance.local.json"
        index = read_json(index_path)
        index["handoff"] = ref
        atomic_json(index_path, index)
    return {**manifest, "artifact_ref": ref, "acceptance": report_ref}
