"""Recompute recovery and workflow facts from their underlying artifacts.

``recovery-input/v1`` contains ``real_roundtrip`` (dgist-roundtrip/v1),
``fixture_roundtrip`` (recovery-example/v1), and optionally ``review_cycle``.
The last reference uses recovery-review-cycle/v1 with ``before`` and ``after``
lists of actual review-import/v1 references for the cut and reapplied outputs.
Missing review execution produces a null measurement, never an inferred PASS.

``workflow-input/v1`` contains ``project`` (absolute directory), ``steps``
(ordered {stage, argv, exit_code, stdout, stderr} execution records), and
``review_imports``. Commands are never executed from a receipt. Known CLI
outputs are checked against the preserved project, native media, and reviews.

Hashes identify preserved bytes; they cannot prove that a process was honest.
Direct recompilation, decoding and provider revalidation reduce that trust
boundary; the independent audit remains mandatory.
"""

from __future__ import annotations

from datetime import datetime
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .project import (
    TalkCutError,
    content_hash,
    load_project,
    read_json,
    sha256,
)
from .timeline import as_fraction


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise TalkCutError("MEASUREMENT_UNVERIFIED", message)


def _file(ref: Any) -> Path:
    _require(
        isinstance(ref, dict) and ref.get("path") and ref.get("sha256"),
        "A hashed raw artifact reference is required",
    )
    path = Path(ref["path"])
    _require(path.is_absolute() and path.is_file(), "Raw artifact is missing")
    _require(sha256(path) == ref["sha256"], "Raw artifact bytes changed")
    if "bytes" in ref:
        _require(path.stat().st_size == ref["bytes"], "Raw artifact size changed")
    return path


def _json(ref: Any) -> Any:
    return read_json(_file(ref))


def _cli(step: dict[str, Any], project: Path) -> tuple[list[str], Any]:
    """Parse only the supported CLI entry points, never arbitrary shell text."""
    argv = step.get("argv", [])
    _require(
        isinstance(argv, list) and all(isinstance(x, str) for x in argv),
        "Actual CLI argv is required",
    )
    if len(argv) >= 4 and argv[1:3] == ["-m", "talkcut"]:
        _require(Path(argv[0]).name.startswith("python"), "Unknown CLI executable")
        args = argv[3:]
    elif len(argv) >= 5 and argv[1:4] == ["run", "--locked", "talkcut"]:
        _require(Path(argv[0]).name == "uv", "Unknown locked CLI executable")
        args = argv[4:]
    elif argv and Path(argv[0]).name == "talkcut":
        args = argv[1:]
    else:
        raise TalkCutError(
            "MEASUREMENT_UNVERIFIED", "Unrelated execution is not a TalkCut CLI step"
        )
    _require(
        str(project.resolve()) in args and "--json" in args,
        "CLI did not operate on the recorded project with JSON output",
    )
    _require(type(step.get("exit_code")) is int, "Missing actual process exit code")
    _file(step.get("stderr"))
    return args, _json(step.get("stdout"))


def _history(project: dict[str, Any]) -> bool:
    """load_project checked the event hashes; reject inferred owner events too."""
    _require(
        project.get("owner_acceptance") == "pending",
        "Recovery cannot fabricate owner acceptance",
    )
    for event in project["events"]:
        _require(
            "owner" not in event["action"].lower(),
            "Unexpected owner decision in autonomous history",
        )
        _require(
            event.get("details", {}).get("owner_acceptance", "pending") == "pending",
            "Owner acceptance was inserted into a machine event",
        )
    return True


def _source_inventory(project: dict[str, Any]) -> None:
    """Read actual source stream metadata/PTS; never trust relabelled frames."""
    from .media import frame_inventory, probe

    checked = set()
    for role, source in project["sources"].items():
        inspection = _json(project["inspections"][role])
        identity = (source["sha256"], project["inspections"][role]["sha256"])
        if identity in checked:
            continue
        metadata = probe(source["path"])
        with TemporaryDirectory(prefix="talkcut-verify-source-") as directory:
            for kind in ("video", "audio"):
                streams = [s for s in metadata["streams"] if s["codec_type"] == kind]
                _require(
                    len(streams) == 1,
                    "Recovery sources must have one selected audio/video stream",
                )
                stream = streams[0]
                actual = frame_inventory(Path(source["path"]), stream, Path(directory))
                recorded = inspection[kind]
                for key in ("index", "time_base", "coverage", "frames", "frame_count"):
                    _require(
                        actual[key] == recorded[key],
                        f"Actual source {kind} {key} differs from recorded inspection",
                    )
                _require(
                    actual["status"] == "PASS", "Actual source frame inventory failed"
                )
        checked.add(identity)


def _stored_render(value: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    for event in project["events"]:
        ref = event.get("details", {}).get("render")
        if ref:
            stored = _json(ref)
            if stored.get("render_id") == value.get("render_id"):
                transport = {"execution", "acceptance_render"}
                supplied = transport.intersection(value)
                if supplied:
                    _require(
                        supplied == transport, "Incomplete render transport evidence"
                    )
                    process = _json(value["execution"])
                    wrapper = _json(value["acceptance_render"])
                    receipt = _json(wrapper["receipt"])
                    worker = _json(process["stdout"])
                    _require(
                        process.get("schema_version") == "render-process/v1"
                        and process.get("exit_code") == 0
                        and process.get("failure") is None
                        and process.get("before", {}).get("code_tree_hash")
                        == process.get("after", {}).get("code_tree_hash")
                        and {k: v for k, v in value.items() if k not in transport}
                        == worker
                        and wrapper.get("schema_version") == "render-evidence/v1"
                        and wrapper.get("workflow_render") == ref
                        and wrapper.get("native_render") == stored.get("native_render")
                        and wrapper.get("output") == stored.get("output")
                        and wrapper.get("profile") == stored.get("profile")
                        and wrapper.get("test_only") == stored.get("test_only")
                        and receipt.get("operation") == "render"
                        and receipt.get("completed") is True
                        and receipt.get("exit_code") == 0
                        and receipt.get("log") == value["execution"]
                        and receipt.get("stdout") == process["stdout"]
                        and receipt.get("result") == process["stdout"],
                        "Render transport differs from actual worker execution and stored native output",
                    )
                _require(
                    {
                        k: v
                        for k, v in value.items()
                        if k not in {"cache_hit", "project_revision", *transport}
                    }
                    == stored,
                    "CLI render output differs from the committed render artifact",
                )
                revision = value.get("project_revision")
                _require(
                    type(revision) is int and 0 < revision <= project["revision"],
                    "Render stdout has no matching actual project revision",
                )
                assert isinstance(revision, int)
                rendered_event = project["events"][revision - 1]
                _require(
                    rendered_event["details"].get("render") == ref
                    and rendered_event["action"]
                    == (
                        "render_cache_reused"
                        if value.get("cache_hit")
                        else "render_completed"
                    ),
                    "Render stdout revision/cache status differs from the project event",
                )
                return stored
    raise TalkCutError(
        "MEASUREMENT_UNVERIFIED", "Render has no preserved project event"
    )


def verify_render(value: dict[str, Any], project: dict[str, Any]) -> dict[str, Any]:
    """Recompile every edit and decode the complete current MP4 once per call."""
    from .plan import compile_plan
    from .render import validate_render

    stored = _stored_render(value, project)
    _require(
        stored.get("schema_version") == "workflow-render/v1"
        and stored.get("status") == "RENDERED",
        "Workflow render did not complete",
    )
    settings = stored["settings"]
    plan = _json(settings.get("plan"))
    timeline = _json(settings.get("timeline"))
    _require(
        plan.get("inspection_refs") == project.get("inspections"),
        "Render plan source inspections are not the current measured inputs",
    )
    _require(
        compile_plan(project, plan) == timeline,
        "Stored timeline differs from recompilation of actual source PTS and decisions",
    )
    native = _json(stored.get("native_render"))
    _require(
        native.get("schema_version") == "render/v1"
        and native.get("complete") is True
        and native.get("status") == "succeeded"
        and native.get("exit_code") == 0,
        "Native render did not successfully complete",
    )
    _require(
        native.get("output") == stored.get("output")
        and native.get("timeline_hash") == timeline.get("timeline_hash"),
        "Native render output or timeline differs from committed output",
    )
    _require(
        set(native.get("sources", {})) == {"screen", "speaker", "audio"},
        "Native render must use exactly screen, speaker and one audio input",
    )
    audio_role = plan["timing"]["audio_source"]
    _require(
        audio_role in {"screen", "speaker"},
        "Comparison-only media cannot be selected as final audio",
    )
    for role, source_role in (
        ("screen", "screen"),
        ("speaker", "speaker"),
        ("audio", audio_role),
    ):
        source = project["sources"][source_role]
        recorded = native["sources"][role]
        _require(
            recorded.get("sha256") == source["sha256"]
            and Path(recorded.get("path", "")).resolve()
            == Path(source["path"]).resolve(),
            "Native render uses different source media",
        )
        _file(recorded)
    command = native.get("command", [])
    _require(
        command
        and Path(command[0]).name == "ffmpeg"
        and native.get("filtergraph") in command,
        "Native execution command does not bind its filtergraph",
    )
    _require(
        Path(native.get("log_path", "")).is_file(), "Native execution log is missing"
    )
    output = _file(stored["output"])
    validation = validate_render(output, timeline, native["layout"], timeout=14400)
    _require(
        validation == native.get("validation"),
        "Actual decode/PTS differs from the native execution result",
    )
    return {
        "render": stored,
        "plan": plan,
        "timeline": timeline,
        "validation": validation,
    }


def _decision_event(
    result: dict[str, Any], args: list[str], project: dict[str, Any]
) -> None:
    revision = result.get("project_revision")
    _require(
        type(revision) is int and 0 < revision <= project["revision"],
        "CLI revision is outside the preserved history",
    )
    assert isinstance(revision, int)
    event = project["events"][revision - 1]
    expected = (
        "test_cut_proposed"
        if args[:2] == ["plan", "add-test-cut"]
        else (
            "candidate_restore"
            if args[:2] == ["plan", "restore"]
            else "candidate_accept"
        )
    )
    _require(
        event["action"] == expected,
        "Decision stdout does not match the actual project event",
    )
    details = event["details"]
    _require(
        details.get("plan") == result.get("plan")
        and details.get("timeline") == result.get("timeline"),
        "Decision stdout references another plan or timeline",
    )
    _require(
        set(details.get("invalidated", []))
        >= {"output_qc", "all_seams", "whole_output_review", "ready"},
        "Changed cuts did not invalidate dependent review/ready state",
    )
    if "--expected-revision" in args:
        _require(
            int(args[args.index("--expected-revision") + 1]) == revision - 1,
            "CLI expected revision differs from the committed event",
        )
    _json(result["plan"])
    _json(result["timeline"])
    preceding = [
        e["details"]["plan"]
        for e in project["events"][: revision - 1]
        if "plan" in e["details"]
    ]
    _require(
        preceding and _json(result["plan"]).get("parent") == preceding[-1],
        "Decision did not preserve the immediately preceding plan revision",
    )


def verify_roundtrip(
    run: dict[str, Any],
    *,
    project_dir: Path | None = None,
    expected_source_hashes: dict[str, str] | None = None,
    source_domain: tuple[Fraction, Fraction] | None = None,
) -> dict[str, Any]:
    """Verify real or generated technical cut/restore/reapply without AI claims."""
    real = run.get("schema_version") == "dgist-roundtrip/v1"
    _require(
        real or run.get("schema_version") == "recovery-example/v1",
        "Unsupported recovery producer schema",
    )
    _require(
        run.get("test_only") is True and run.get("owner_acceptance") == "pending",
        "The arbitrary recovery experiment must remain test-only and owner-pending",
    )
    if real:
        _require(
            run.get("status") in {"COMPLETE", "UNVERIFIED"}
            and isinstance(run.get("started_at"), str)
            and isinstance(run.get("ended_at"), str),
            "The real DGIST roundtrip has not completed",
        )
        _require(
            datetime.fromisoformat(run["started_at"])
            < datetime.fromisoformat(run["ended_at"]),
            "Real roundtrip completion timestamps are invalid",
        )
    directory = Path(run.get("project", project_dir or ""))
    _require(directory.is_absolute(), "Recovery project directory is missing")
    if project_dir is not None:
        _require(
            directory.resolve() == project_dir.resolve(),
            "Recovery belongs to another project",
        )
    project = load_project(directory)
    _history(project)
    hashes = {role: item["sha256"] for role, item in project["sources"].items()}
    if expected_source_hashes is not None:
        _require(
            all(
                expected_source_hashes.get(role) == digest
                for role, digest in hashes.items()
            ),
            "Recovery did not use the registered real DGIST source bytes",
        )
    _source_inventory(project)
    steps = run.get("steps") if real else _json(run.get("executions"))
    _require(
        isinstance(steps, list) and steps, "Actual recovery CLI executions are missing"
    )
    assert isinstance(steps, list)
    _require(
        len(steps) == (10 if real else 14),
        "Recovery producer execution ledger is incomplete",
    )
    outputs = {**run.get("outputs", {})}
    if "baseline" not in outputs and run.get("baseline"):
        outputs["baseline"] = run["baseline"]
    _require(
        set(outputs) == {"baseline", "cut", "restored", "reapplied"},
        "All four successful recovery renders must be preserved",
    )
    observed_renders: list[dict[str, Any]] = []
    decisions: list[tuple[list[str], dict[str, Any]]] = []
    status_results = []
    cached_results = []
    for step in steps:
        if not real and step.get("name") == "01-generate":
            _require(
                step.get("exit_code") == 0
                and Path(step.get("argv", [""])[0]).name == "ffmpeg",
                "The public fixture generator did not complete",
            )
            _file(step.get("stdout"))
            _file(step.get("stderr"))
            continue
        args, result = _cli(step, directory)
        _require(step["exit_code"] == 0, "Recovery CLI step failed")
        if args[0] == "render":
            observed_renders.append(result)
            _stored_render(result, project)
            if result.get("cache_hit") is True:
                cached_results.append(result)
        elif args[:2] in (
            ["plan", "add-test-cut"],
            ["plan", "decide"],
            ["plan", "restore"],
        ):
            _decision_event(result, args, project)
            decisions.append((args, result))
        elif args[0] == "status":
            _require(
                result.get("schema_version") == "talkcut-status/v1"
                and result.get("source_hashes") == hashes,
                "Reopen stdout does not identify the same source files",
            )
            status_results.append(result)
        else:
            _require(
                not real and args[0] in {"init", "inspect", "plan"},
                "Unexpected recovery command",
            )
    for stage in ("cut", "restored", "reapplied"):
        _require(
            outputs[stage] in observed_renders,
            f"{stage} render lacks its actual CLI stdout",
        )
    if not real:
        _require(
            outputs["baseline"] in observed_renders,
            "Fixture baseline lacks actual CLI stdout",
        )
    _require(
        len(decisions) == 4
        and [args[:2] for args, _ in decisions]
        == [
            ["plan", "add-test-cut"],
            ["plan", "decide"],
            ["plan", "restore"],
            ["plan", "decide"],
        ],
        "Recovery must propose, accept, restore, then reapply the same cut",
    )
    candidate = decisions[0][1].get("candidate_id")
    _require(
        candidate
        and all(
            args[args.index("--candidate") + 1] == candidate
            for args, _ in decisions[1:]
        ),
        "Recovery decisions refer to different candidates",
    )
    checked = {stage: verify_render(value, project) for stage, value in outputs.items()}
    for stage, (_, decision) in zip(
        ("cut", "restored", "reapplied"), decisions[1:], strict=True
    ):
        _require(
            checked[stage]["render"]["settings"]["plan"] == decision["plan"],
            "Recovery render was not built from the corresponding decision revision",
        )
    baseline, cut, restored, reapplied = (
        checked[stage] for stage in ("baseline", "cut", "restored", "reapplied")
    )
    for first, second in ((baseline, restored), (cut, reapplied)):
        for key in (
            "domain",
            "frames",
            "retained",
            "duration",
            "sample_count",
            "sample_rate",
            "speaker_omissions",
        ):
            _require(
                first["timeline"][key] == second["timeline"][key],
                f"Recovery changed {key}",
            )
        _require(
            first["render"]["output"]["sha256"] == second["render"]["output"]["sha256"],
            "Identical recovered media schedules produced different output bytes",
        )
    base_tl, cut_tl = baseline["timeline"], cut["timeline"]
    domain = tuple(as_fraction(base_tl["domain"][key]) for key in ("start", "end"))
    _require(
        source_domain is None or domain == source_domain,
        "DGIST recovery used only a short source sample",
    )
    _require(
        not base_tl["deletions"]
        and len(base_tl["retained"]) == 1
        and as_fraction(base_tl["retained"][0]["source_start"]) == domain[0]
        and as_fraction(base_tl["retained"][0]["source_end"]) == domain[1],
        "Baseline recovery output does not preserve the complete source domain",
    )
    _require(
        cut_tl["deletions"]
        and len(cut_tl["frames"]) < len(base_tl["frames"])
        and as_fraction(cut_tl["sample_count"]) < as_fraction(base_tl["sample_count"]),
        "The recovery experiment applied no actual cut",
    )
    for stage, decision_name in (
        ("cut", "accepted"),
        ("restored", "restored"),
        ("reapplied", "accepted"),
    ):
        matched = [
            x for x in checked[stage]["plan"]["candidates"] if x["id"] == candidate
        ]
        _require(
            len(matched) == 1 and matched[0]["decision"] == decision_name,
            "Recovered plan candidate state does not match the CLI decision",
        )
    final_render = reapplied["render"]
    _require(
        cached_results and cached_results[-1]["render_id"] == final_render["render_id"],
        "Unchanged rerun did not reuse the actual successful reapplied render",
    )
    _require(
        status_results and status_results[-1].get("active_render") is not None,
        "Successful render was not reopened through the CLI",
    )
    reopened = _json(status_results[-1]["active_render"])
    _require(reopened == final_render, "Reopened project selected another render")
    cache_events = [
        event
        for event in project["events"]
        if event["action"] == "render_cache_reused"
        and _json(event["details"]["render"]) == final_render
    ]
    _require(cache_events, "Unchanged rerun has no cache reuse history event")
    return {
        "technical_roundtrip": True,
        "project": project,
        "renders": checked,
        "candidate_id": candidate,
        "reopen": True,
        "unchanged_rerun": True,
        "timing_preserved": True,
        "history_preserved": True,
        "owner_event_fabricated": False,
        "restore_at": project["events"][decisions[2][1]["project_revision"] - 1]["at"],
        "reapply_at": project["events"][decisions[3][1]["project_revision"] - 1]["at"],
    }


def _review_coverage(
    imports: list[dict[str, str]],
    render: dict[str, Any],
    source_hashes: dict[str, str],
    *,
    before: str | None = None,
    after: str | None = None,
) -> set[str]:
    from .acceptance import difference, union
    from .review import verify_imported_review

    _require(imports, "Actual audiovisual review imports are missing")
    timeline = render["timeline"]
    settings = render["render"]["settings"]
    expected = {
        "source_hashes": source_hashes,
        "plan_hash": content_hash(render["plan"]),
        "timeline_hash": settings["timeline"]["sha256"],
        "output_hash": render["render"]["output"]["sha256"],
    }
    covered: dict[str, list[tuple[Fraction, Fraction]]] = {
        "output": [],
        "seam": [],
        "deletion": [],
    }
    run_ids = set()
    for ref in imports:
        review = verify_imported_review(ref)
        request, record = review["request"], review["record"]
        _require(
            not record.get("test_only") and not record.get("synthetic"),
            "Synthetic review cannot certify real recovery media",
        )
        execution = review["receipt"]
        if before:
            _require(
                datetime.fromisoformat(execution["finished_at"])
                <= datetime.fromisoformat(before),
                "The original review did not exist before restore invalidated it",
            )
        if after:
            _require(
                datetime.fromisoformat(execution["started_at"])
                >= datetime.fromisoformat(after),
                "Regenerated review predates the reapplied edit",
            )
        _require(
            all(
                request.get("dependencies", {}).get(k) == v for k, v in expected.items()
            ),
            "Regenerated review belongs to another source, plan, timeline or output",
        )
        scope = request.get("scope")
        _require(
            scope in covered,
            "Recovery requires output, seam and deletion review scopes",
        )
        covered[scope].extend(
            (as_fraction(a), as_fraction(b))
            for a, b in review["response"]["observed_intervals"]
        )
        run_ids.add(review["receipt"]["run_id"])
    output_domain = [(Fraction(), as_fraction(timeline["duration"]))]
    _require(
        not difference(output_domain, covered["output"]),
        "Whole recovered output review coverage is incomplete",
    )
    source_start = as_fraction(timeline["domain"]["start"])
    source_end = as_fraction(timeline["domain"]["end"])
    deletions = [
        (
            max(source_start, as_fraction(d["start"]) - 5),
            min(source_end, as_fraction(d["end"]) + 5),
        )
        for d in timeline["deletions"]
    ]
    _require(
        not difference(deletions, covered["deletion"]),
        "Recovery deletion review coverage is incomplete",
    )
    seams = [as_fraction(x["output_start"]) for x in timeline["retained"][1:]]
    seam_windows = [
        (max(Fraction(), point - 5), min(output_domain[0][1], point + 5))
        for point in seams
    ]
    _require(
        not difference(seam_windows, union(covered["seam"])),
        "Recovered output seams were not all reviewed",
    )
    return run_ids


def verify_recovery(
    raw: dict[str, Any],
    *,
    project_dir: Path,
    expected_source_hashes: dict[str, str],
    source_domain: tuple[Fraction, Fraction] | None,
) -> dict[str, Any]:
    _require(
        raw.get("schema_version") == "recovery-input/v1",
        "Typed recovery inputs are missing",
    )
    _require(
        source_domain is not None, "Complete real DGIST source domain is unavailable"
    )
    real = verify_roundtrip(
        _json(raw.get("real_roundtrip")),
        project_dir=project_dir,
        expected_source_hashes=expected_source_hashes,
        source_domain=source_domain,
    )
    fixture = verify_roundtrip(_json(raw.get("fixture_roundtrip")))
    _require(
        _json(raw["real_roundtrip"])["schema_version"] == "dgist-roundtrip/v1"
        and _json(raw["fixture_roundtrip"])["schema_version"] == "recovery-example/v1",
        "Real-source and public-fixture recovery roles were substituted",
    )
    reviews: bool | None = None
    if raw.get("review_cycle"):
        cycle = _json(raw["review_cycle"])
        _require(
            cycle.get("schema_version") == "recovery-review-cycle/v1",
            "Unknown recovery review-cycle schema",
        )
        hashes = {k: v["sha256"] for k, v in real["project"]["sources"].items()}
        before = _review_coverage(
            cycle.get("before", []),
            real["renders"]["cut"],
            hashes,
            before=real["restore_at"],
        )
        after = _review_coverage(
            cycle.get("after", []),
            real["renders"]["reapplied"],
            hashes,
            after=real["reapply_at"],
        )
        _require(
            before.isdisjoint(after),
            "Old provider execution was relabelled as regenerated review",
        )
        reviews = True
    return {
        "real_dgist_cut_restore_reapply": real["technical_roundtrip"],
        "fixture_roundtrip": fixture["technical_roundtrip"],
        **{
            key: real[key] and fixture[key]
            for key in (
                "reopen",
                "unchanged_rerun",
                "timing_preserved",
                "history_preserved",
            )
        },
        "review_invalidated_and_regenerated": reviews,
        "owner_event_fabricated": False,
    }


def verify_workflow(
    raw: dict[str, Any], *, project_dir: Path, dependencies: dict[str, Any]
) -> dict[str, Any]:
    """Validate M1–M7 execution without substituting a synthetic CLI transcript."""
    from .analysis import authorize_automatic_candidate, verify_analysis_report
    from .review import authorize_candidate_review
    from .sync import verify_sync_model

    _require(
        raw.get("schema_version") == "workflow-input/v1",
        "Typed workflow inputs are missing",
    )
    _require(
        Path(raw.get("project", "")).resolve() == project_dir.resolve(),
        "Workflow belongs to another project",
    )
    project = load_project(project_dir)
    _history(project)
    _source_inventory(project)
    source_hashes = {k: v["sha256"] for k, v in project["sources"].items()}
    _require(
        all(
            dependencies.get("source_hashes", {}).get(k) == v
            for k, v in source_hashes.items()
        ),
        "Workflow does not use the registered actual DGIST sources",
    )
    required = [
        "inspect",
        "sync",
        "analysis",
        "plan",
        "review",
        "render",
        "qc",
        "prepare-release",
    ]
    steps = raw.get("steps", [])
    _require(
        len(steps) == len(required)
        and {step.get("stage") for step in steps} == set(required),
        "All eight actual workflow CLI steps are required",
    )
    results: dict[str, Any] = {}
    allowed = {
        "inspect": ["inspect"],
        "sync": ["sync", "import"],
        "analysis": ["analyze"],
        "plan": ["plan"],
        "review": ["review", "import"],
        "render": ["render"],
        "qc": ["qc"],
        "prepare-release": ["prepare-release"],
    }
    for step in steps:
        stage = step["stage"]
        args, value = _cli(step, project_dir)
        prefix = allowed[stage]
        _require(
            args[: len(prefix)] == prefix,
            f"Unrelated CLI command cannot certify workflow {stage}",
        )
        # qc deliberately exits 1 while separate semantic acceptance is pending.
        _require(
            step["exit_code"] == 0 or (stage == "qc" and step["exit_code"] == 1),
            f"Workflow {stage} CLI step failed",
        )
        results[stage] = value
    inspections = results["inspect"]
    _require(
        inspections.get("schema_version") == "talkcut-inspect/v1"
        and inspections.get("artifact_refs") == project["inspections"],
        "Workflow inspect selected different source inspections",
    )
    for ref in inspections["artifact_refs"].values():
        inspected = _json(ref)
        _require(
            inspected.get("status") == "PASS" and inspected.get("full_decode") is True,
            "Whole-source decode evidence is missing",
        )
    _require(
        results["sync"].get("schema_version") == "sync-import/v1"
        and results["sync"].get("sync") == project.get("sync"),
        "Workflow sync stdout does not identify the active model",
    )
    verify_sync_model(project["sync"], project)
    analysis_ref = results["analysis"].get("artifact_ref")
    analysis = _json(analysis_ref)
    _require(
        analysis.get("status") == "ANALYZED"
        and analysis.get("source_hashes") == source_hashes,
        "Whole-source contextual analysis was not successfully completed",
    )
    plan_ref = results["plan"].get("plan")
    plan = _json(plan_ref)
    _require(
        plan_ref == project.get("active_plan")
        and plan.get("test_only") is False
        and plan.get("analysis_ref") == analysis_ref,
        "Workflow plan is not the final analyzed plan",
    )
    verify_analysis_report(analysis_ref, plan)
    for candidate in plan["candidates"]:
        if candidate.get("decision") == "accepted":
            if candidate.get("policy_action") == "auto_apply":
                authorize_automatic_candidate(analysis_ref, candidate, plan)
            else:
                authorize_candidate_review(
                    candidate.get("decision_evidence", {}).get("review"),
                    candidate,
                    plan,
                )
    rendered = verify_render(results["render"], project)
    _require(
        rendered["render"].get("profile") == "master"
        and rendered["render"].get("test_only") is False
        and rendered["render"]["output"]["sha256"] == dependencies.get("output_hash"),
        "Workflow did not render the actual final master",
    )
    imports = raw.get("review_imports", [])
    _require(
        any(
            _json(ref)
            == {k: v for k, v in results["review"].items() if k != "artifact_ref"}
            for ref in imports
        ),
        "Actual imported review stdout is absent from workflow evidence",
    )
    _review_coverage(imports, rendered, source_hashes)
    qc = results["qc"]
    _require(
        qc.get("schema_version") == "workflow-qc/v1"
        and qc.get("output") == rendered["render"]["output"]
        and qc.get("technical") == rendered["validation"],
        "Workflow QC does not match the actual final MP4 decode",
    )
    handoff = results["prepare-release"]
    _require(
        handoff.get("schema_version") == "private-handoff/v1"
        and handoff.get("owner_acceptance") == "pending",
        "Private ready handoff was not actually prepared",
    )
    _require(
        {k: v for k, v in handoff.items() if k not in {"artifact_ref", "acceptance"}}
        == _json(handoff.get("artifact_ref")),
        "Handoff CLI stdout differs from preserved handoff",
    )
    _require(
        all(
            handoff.get("dependencies", {}).get(k) == v for k, v in dependencies.items()
        ),
        "Prepared handoff is stale against the final dependencies",
    )
    return {"steps_completed": required, "real_media": True, "mock_provider": False}


def verify_acceptance_render(
    record: dict[str, Any],
    project: dict[str, Any],
    repo_root: Path,
    *,
    expected_profile: str = "master",
    project_dir: Path | None = None,
) -> dict[str, Any]:
    """Rebind actual render-worker execution and fully decode its current media.

    The diagnostic option is only a technical positive control. Final acceptance
    always calls the default master profile and separately requires all AV gates.
    """
    import sys

    from .contracts import code_identity

    workflow_ref = project.get("active_render")
    workflow = _json(workflow_ref)
    _require(
        record.get("schema_version") == "render-evidence/v1"
        and record.get("workflow_render") == workflow_ref
        and record.get("render_id") == workflow["render_id"]
        and record.get("native_render") == workflow["native_render"]
        and record.get("output") == workflow["output"]
        and record.get("profile") == workflow.get("profile") == expected_profile
        and record.get("test_only") is workflow.get("test_only")
        and workflow.get("test_only") is (expected_profile != "master")
        and record.get("status") == "complete"
        and record.get("complete") is True,
        "Acceptance render was relabelled from another workflow, profile or output",
    )
    receipt = _json(record.get("receipt"))
    execution = _json(receipt.get("log"))
    worker = _json(receipt.get("stdout"))
    command = receipt.get("command", [])
    settings = workflow["settings"]
    _require(
        len(command) == 12
        and Path(command[0]).resolve() == Path(sys.executable).resolve()
        and command[1:4] == ["-m", "talkcut", "render-worker"]
        and Path(command[4]).is_absolute()
        and (project_dir is None or Path(command[4]).resolve() == project_dir.resolve())
        and command[5:]
        == [
            "--profile",
            expected_profile,
            "--preset",
            settings["preset"],
            "--crf",
            str(settings["crf"]),
            "--json",
        ],
        "Render receipt was not the supported actual worker invocation",
    )
    # Project.json bytes and its source/event history were validated by caller.
    _require(
        load_project(command[4]) == project
        and Path(execution.get("cwd", "/")).resolve() == repo_root.resolve(),
        "Render worker executed against another project or repository",
    )
    current = code_identity(repo_root)
    _require(
        receipt.get("schema_version") == "execution-receipt/v1"
        and receipt.get("operation") == "render"
        and receipt.get("completed") is True
        and receipt.get("exit_code") == 0
        and receipt.get("test_only") is workflow["test_only"]
        and receipt.get("result") == receipt.get("stdout") == execution.get("stdout")
        and receipt.get("stderr") == execution.get("stderr")
        and receipt.get("command") == execution.get("command")
        and receipt.get("run_id") == execution.get("run_id")
        and receipt.get("started_at") == execution.get("started_at")
        and receipt.get("finished_at") == execution.get("finished_at")
        and execution.get("schema_version") == "render-process/v1"
        and execution.get("exit_code") == 0
        and execution.get("failure") is None
        and execution.get("before", {}).get("code_tree_hash")
        == execution.get("after", {}).get("code_tree_hash")
        == current["code_tree_hash"],
        "Render envelope is unrelated to the actual successful current-code execution",
    )
    _file(receipt["stderr"])
    plan = _json(project["active_plan"])
    expected_deps = {
        "code_tree_hash": current["code_tree_hash"],
        "contract_hash": plan["contract_hash"],
        "source_hashes": {
            role: source["sha256"] for role, source in project["sources"].items()
        },
        "plan_hash": content_hash(plan),
        "timeline_hash": project["active_timeline"]["sha256"],
        "output_hash": workflow["output"]["sha256"],
    }
    _require(
        record.get("dependencies") == receipt.get("dependencies") == expected_deps
        and settings["plan"] == project["active_plan"]
        and settings["timeline"] == project["active_timeline"]
        and settings["profile"] == expected_profile,
        "Actual worker dependencies/settings differ from the current project",
    )
    verified = verify_render(worker, project)
    _require(
        verified["render"] == workflow,
        "Actual worker stdout differs from indexed current render",
    )
    return verified
