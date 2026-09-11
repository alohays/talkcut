"""Derive geometry and output checks from actual media and validated reviews.

``quality-input/v1`` binds a workflow_render, render_execution_stdout,
comparison, and quality_reviews.
The caller supplies reviews already validated by Evaluator.load_review. Their
raw provider response must include quality_observations with explicit integer
counts for important_occlusions, new_audio_defects, and
new_drop_freeze_black_silence. A missing count remains unknown.

Every source/output pixel and valid PCM sample is recomputed, with results
cached only within one evaluation. A heuristic's absence is never approval.
"""

from __future__ import annotations

from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import Any

from .contracts import object_hash
from .geometry import measure_geometry
from .measurement_checks import _file, _json, _require, verify_render
from .media import doctor, probe
from .project import load_project
from .quality import DETECTORS, compare_render
from .render import build_render_command
from .timeline import as_fraction


def _covers(domain: tuple[Fraction, Fraction], intervals: list[Any]) -> bool:
    cursor = domain[0]
    for start, end in sorted((as_fraction(a), as_fraction(b)) for a, b in intervals):
        _require(
            domain[0] <= start < end <= domain[1],
            "Quality review exceeds actual domain",
        )
        if start > cursor:
            return False
        cursor = max(cursor, end)
    return cursor == domain[1]


def _observed(row: dict[str, Any], span: list[Any]) -> bool:
    domain = as_fraction(span[0]), as_fraction(span[1])
    clipped = [
        (max(domain[0], as_fraction(a)), min(domain[1], as_fraction(b)))
        for a, b in row["intervals"]
        if max(domain[0], as_fraction(a)) < min(domain[1], as_fraction(b))
    ]
    return _covers(domain, clipped)


def _resolves(
    raw: dict[str, Any],
    reviews: list[dict[str, Any]],
    row: dict[str, Any],
    finding: dict[str, Any],
) -> bool:
    """Require the two actual executions to inspect this particular finding."""
    resolutions = row["response"].get("quality_finding_resolutions", [])
    if not resolutions:
        return False
    binding = {
        "finding_hash": object_hash(finding),
        "comparison": raw["comparison"],
        "source_interval": finding["source_interval"],
        "output_interval": finding["output_interval"],
    }
    if not _observed(row, finding["output_interval"]):
        return False
    for resolution in resolutions:
        if (
            any(resolution.get(k) != v for k, v in binding.items())
            or resolution.get("disposition") != "source_compared_false_positive"
            or not isinstance(resolution.get("reason"), str)
            or len(resolution["reason"].strip()) < 30
        ):
            continue
        source_ref = resolution.get("source_review")
        if source_ref not in raw.get("source_comparison_reviews", []):
            continue
        if {**binding, "source_review": source_ref} not in row.get("request", {}).get(
            "details", {}
        ).get("quality_investigations", []):
            continue
        for source in reviews:
            if (
                source.get("ref") != source_ref
                or source.get("scope") not in {"analysis", "deletion"}
                or source.get("run_id") == row.get("run_id")
                or not _observed(source, finding["source_interval"])
            ):
                continue
            if binding not in source.get("request", {}).get("details", {}).get(
                "quality_investigations", []
            ):
                continue
            try:
                source_finished = datetime.fromisoformat(
                    source["receipt"]["finished_at"]
                )
                output_started = datetime.fromisoformat(row["receipt"]["started_at"])
                if (
                    source_finished.tzinfo is None
                    or output_started.tzinfo is None
                    or source_finished > output_started
                ):
                    continue
            except (KeyError, ValueError, TypeError):
                continue
            for observation in source["response"].get(
                "quality_source_observations", []
            ):
                if (
                    all(observation.get(k) == v for k, v in binding.items())
                    and observation.get("disposition")
                    in {"original_source_artifact", "no_source_defect_observed"}
                    and isinstance(observation.get("observed_source_behavior"), str)
                    and len(observation["observed_source_behavior"].strip()) >= 30
                ):
                    return True
    return False


def _visual_states_checked(
    raw: dict[str, Any],
    selected: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    report: dict[str, Any],
    domain: tuple[Fraction, Fraction],
) -> bool | None:
    """Keep state inspection separate from a numeric occlusion observation.

    The executed semantic request and response bind ``visual_state_inspection``
    to {comparison, output_hash, scope:'all_visible_states_in_requested_intervals'}.
    Its response lists positive, timed ``visual_state_observations`` with
    observed_behavior and a boolean rapid_or_suspect. Those intervals must cover
    the complete output. Every marked state needs a separate validated dense
    request/response bound by ``visual_state_recheck`` to that exact state hash
    and original state-review ref. Automatic video findings also require dense
    coverage, regardless of the semantic reviewer's rapid_or_suspect label.
    No number of zero-count window responses establishes these observations.
    """
    comparison = raw.get("comparison")
    output_hash = report.get("dependencies", {}).get("output_hash")
    if not comparison or not output_hash:
        return None
    binding = {
        "comparison": comparison,
        "output_hash": output_hash,
        "scope": "all_visible_states_in_requested_intervals",
    }
    covered: list[tuple[Fraction, Fraction]] = []
    dense_covered: list[tuple[Fraction, Fraction]] = []
    for row in selected:
        if (
            row.get("request", {}).get("details", {}).get("visual_state_inspection")
            != binding
            or row["response"].get("visual_state_inspection") != binding
        ):
            continue
        states = row["response"].get("visual_state_observations", [])
        if not states:
            continue
        for state in states:
            interval = state.get("interval", [])
            if (
                not isinstance(interval, list)
                or len(interval) != 2
                or not isinstance(state.get("observed_behavior"), str)
                or len(state["observed_behavior"].strip()) < 30
                or type(state.get("rapid_or_suspect")) is not bool
            ):
                return None
            a, b = (as_fraction(value) for value in interval)
            if not domain[0] <= a < b <= domain[1] or not _observed(row, interval):
                return None
            needs_dense = state["rapid_or_suspect"]
            dense_binding = {
                "comparison": comparison,
                "output_hash": output_hash,
                "state_hash": object_hash(state),
                "state_review": row["ref"],
            }
            dense = [
                item
                for item in reviews
                if item.get("ref") in raw.get("visual_state_reviews", [])
                and item.get("scope") in {"output", "layout"}
                and item.get("run_id") != row.get("run_id")
                and item.get("precision_supported") is True
                and item.get("request", {})
                .get("details", {})
                .get("requires_dense_video")
                is True
                and item["request"]["details"].get("visual_state_recheck")
                == dense_binding
                and item["response"].get("visual_state_recheck") == dense_binding
                and len(item["response"].get("observed_state_behavior", "").strip())
                >= 30
                and _observed(item, interval)
            ]
            if dense:
                for item in dense:
                    _file(item["ref"])
                dense_covered.append((a, b))
            if needs_dense and not dense:
                return None
            covered.append((a, b))
    if not covered or not _covers(domain, covered):
        return None
    for finding in report.get("findings", []):
        if "audio" in finding.get("kind", "") or "audible" in finding.get("kind", ""):
            continue
        span = finding.get("output_interval")
        if not span or not _observed({"intervals": dense_covered}, span):
            return None
    return True


def review_counts(
    raw: dict[str, Any],
    reviews: list[dict[str, Any]],
    report: dict[str, Any],
    timeline: dict[str, Any],
) -> dict[str, Any]:
    """Consume only independently validated rows, never envelope PASS labels."""
    refs = raw.get("quality_reviews", [])
    selected = []
    for ref in refs:
        _file(ref)
        matches = [item for item in reviews if item.get("ref") == ref]
        _require(len(matches) == 1, "Quality evidence has no unique validated review")
        row = matches[0]
        _require(
            row["scope"] in {"layout", "output"},
            "Unrelated review cannot certify quality",
        )
        selected.append(row)
    whole_video = (Fraction(), as_fraction(timeline["duration"]))
    whole_audio = (
        Fraction(),
        Fraction(timeline["sample_count"], timeline["sample_rate"]),
    )
    result: dict[str, Any] = {}
    for key, domain in (
        ("important_occlusions", whole_video),
        ("new_audio_defects", whole_audio),
        ("new_drop_freeze_black_silence", whole_video),
    ):
        eligible: list[tuple[Fraction, Fraction]] = []
        counts = []
        for row in selected:
            count = row["response"].get("quality_observations", {}).get(key)
            if type(count) is int and count >= 0:
                counts.append(count)
                eligible.extend(
                    (max(domain[0], as_fraction(a)), min(domain[1], as_fraction(b)))
                    for a, b in row["intervals"]
                    if max(domain[0], as_fraction(a)) < min(domain[1], as_fraction(b))
                )
        result[key] = sum(counts) if counts and _covers(domain, eligible) else None
    result["all_visual_states_checked"] = (
        _visual_states_checked(raw, selected, reviews, report, whole_video)
        if result["important_occlusions"] is not None
        else None
    )
    # A model must explicitly investigate each measured trigger. Changing a
    # severity label or asserting a clean output does not resolve that trigger.
    for finding in report["findings"]:
        resolved = any(_resolves(raw, reviews, row, finding) for row in selected)
        if not resolved:
            result["new_drop_freeze_black_silence"] = None
            if "audio" in finding["kind"] or "audible" in finding["kind"]:
                result["new_audio_defects"] = None
    return result


def verify_quality(
    raw: dict[str, Any],
    *,
    check_id: str,
    project_dir: Path,
    dependencies: dict[str, Any],
    validated_reviews: list[dict[str, Any]],
    evaluation_cache: dict[str, Any],
) -> dict[str, Any]:
    """Verify current input bytes and recompute complete media differences."""
    _require(
        check_id in {"geometry_audio", "output_technical"}, "Unknown quality check"
    )
    _require(
        raw.get("schema_version") == "quality-input/v1", "Typed quality input missing"
    )
    workflow = _json(raw.get("workflow_render"))
    report = _json(raw.get("comparison"))
    _require(
        report.get("schema_version") == "source-output-quality/v1",
        "Wrong comparison schema",
    )
    for key in (
        "code_tree_hash",
        "contract_hash",
        "source_hashes",
        "timeline_hash",
        "output_hash",
    ):
        _require(
            report.get("dependencies", {}).get(key) == dependencies.get(key),
            f"Quality dependency changed: {key}",
        )
    _require(
        report.get("execution_status") == "PASS"
        and report.get("coverage_status") == "PASS"
        and report.get("whole_retained_source_compared") is True,
        "Partial or failed comparison cannot certify full output",
    )
    _require(
        report.get("detectors") == DETECTORS, "Source-difference detectors changed"
    )
    _require(report.get("toolchain") == doctor(), "Quality toolchain changed")
    _require(
        report["input_refs"]["workflow"] == raw["workflow_render"],
        "Comparison uses another render",
    )
    # The comparison records the plan file's byte hash; timeline/review record
    # the canonical plan content hash. Verify both, without equating encodings.
    _require(
        report["dependencies"]["plan_hash"] == report["input_refs"]["plan"]["sha256"]
        and report["input_refs"]["plan"] == workflow["settings"]["plan"],
        "Quality plan artifact identity differs",
    )
    key = object_hash(
        {
            "workflow": raw["workflow_render"],
            "comparison": raw["comparison"],
            "dependencies": dependencies,
        }
    )
    if key not in evaluation_cache:
        project = load_project(project_dir)
        executed_render = _json(raw.get("render_execution_stdout"))
        checked = verify_render(executed_render, project)
        _require(
            checked["render"] == workflow,
            "Render command output belongs to another workflow",
        )
        repeated = compare_render(
            raw["workflow_render"], project_dir / "evidence" / "quality-rechecks"
        )
        for modality in ("audio", "video"):
            old, new = report[modality], repeated[modality]
            _file(old["metrics"])
            _require(
                old["metrics"]["sha256"] == new["metrics"]["sha256"],
                "Reported per-frame/sample measurements differ from current decoded bytes",
            )
            _require(
                {k: v for k, v in old.items() if k not in {"metrics", "decoders"}}
                == {k: v for k, v in new.items() if k not in {"metrics", "decoders"}},
                "Reported coverage/aggregate differs from full independent recomputation",
            )
        _require(
            report["findings"] == repeated["findings"],
            "Measured quality findings were omitted or altered",
        )
        evaluation_cache[key] = checked
    checked = evaluation_cache[key]
    timeline, plan, validation = (
        checked[name] for name in ("timeline", "plan", "validation")
    )
    native = _json(workflow["native_render"])
    command = native["command"]
    source_parameters = {}
    for role in ("screen", "speaker"):
        source = native["sources"][role]
        actual_streams = probe(str(_file(source)))["streams"]
        source_video = [s for s in actual_streams if s["codec_type"] == "video"]
        _require(len(source_video) == 1, "Source video selection is ambiguous")
        measured_geometry = measure_geometry(source["path"], source_video[0])
        source_parameters[role] = {
            **source,
            **source_video[0],
            "sample_aspect_ratio": measured_geometry["sample_aspect_ratio"],
            "stream_index": source_video[0]["index"],
        }
    selected = native["sources"][plan["timing"]["audio_source"]]
    _require(
        native["sources"]["audio"] == selected,
        "Rendered audio is not the selected single source",
    )
    audio_inputs = [
        s for s in probe(str(_file(selected)))["streams"] if s["codec_type"] == "audio"
    ]
    _require(len(audio_inputs) == 1, "Source audio selection is ambiguous")
    source_parameters["audio"] = {
        **selected,
        "stream_index": audio_inputs[0]["index"],
        "sample_rate": int(audio_inputs[0]["sample_rate"]),
    }
    from .audio_processing import verify_audio_processing_binding

    audio_profile = verify_audio_processing_binding(plan, timeline, workflow["settings"], native)
    recipe = build_render_command(
        timeline,
        source_parameters,
        command[-1],
        plan["layout"],
        crf=workflow["settings"]["crf"],
        preset=workflow["settings"]["preset"],
        ffmpeg=command[0],
    )
    _require(
        recipe["command"] == command
        and recipe["filtergraph"] == native["filtergraph"]
        and recipe["layout"] == native["layout"]
        and recipe["audio_processing"] == audio_profile,
        "Actual render recipe changes full-frame composition or audio",
    )
    streams = probe(str(_file(workflow["output"])))["streams"]
    video, audio = (
        [s for s in streams if s["codec_type"] == kind] for kind in ("video", "audio")
    )
    _require(
        len(video) == len(audio) == 1 and len(streams) == 2,
        "Output stream inventory differs",
    )
    geometry = measure_geometry(workflow["output"]["path"], video[0])
    layout = native["layout"]
    semantics = review_counts(raw, validated_reviews, report, timeline)
    full_resolution = (video[0]["width"], video[0]["height"]) == (
        layout["canvas_width"],
        layout["canvas_height"],
    )
    if check_id == "output_technical":
        return {
            "complete_decode": validation["decode"]["exit_code"] == 0
            and not validation["decode"]["stderr"],
            "actual_pts_verified": True,
            "retained_mapping_verified": True,
            "new_drop_freeze_black_silence": semantics["new_drop_freeze_black_silence"],
            "audio_streams": len(audio),
            "video_streams": len(video),
            "full_resolution": full_resolution,
        }
    return {
        "screen_full_frame": layout["preserve_screen_frame"],
        "screen_canvas_preserved": full_resolution,
        "screen_dar_preserved": Fraction(
            geometry["display_aspect_ratio"].replace(":", "/")
        )
        == as_fraction(layout["screen_dar"]),
        "speaker_full_frame": layout["preserve_speaker_frame"],
        "speaker_dar_preserved": Fraction(layout["width"], layout["height"])
        * as_fraction(layout["screen_sar"])
        == Fraction(
            source_parameters["speaker"]["width"],
            source_parameters["speaker"]["height"],
        )
        * as_fraction(layout["speaker_sar"]),
        "speaker_top_right": layout["position"] == "top-right",
        "output_audio_streams": len(audio),
        **{
            k: semantics[k]
            for k in (
                "important_occlusions",
                "new_audio_defects",
                "all_visual_states_checked",
            )
        },
    }
