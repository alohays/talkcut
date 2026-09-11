"""Actual synthetic media controls; no fixture can certify DGIST AI quality."""

import copy
import subprocess
import sys
from pathlib import Path

import pytest

from talkcut.__main__ import execute, parser_for_cli
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    load_project,
    verified_json,
)
from talkcut.quality import compare_render
from talkcut.quality_checks import review_counts, verify_quality


def command(*args):
    return execute(parser_for_cli().parse_args([str(arg) for arg in args]))


@pytest.fixture(scope="module")
def measured(tmp_path_factory):
    directory = tmp_path_factory.mktemp("typed-quality")
    source = directory / "synthetic.mp4"
    subprocess.run([
        "ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=160x96:rate=10:duration=2",
        "-f", "lavfi", "-i", "sine=frequency=700:sample_rate=44100:duration=2.2",
        "-map", "1:a", "-map", "0:v", "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(source)
    ], check=True, timeout=30)
    project = directory / "project"
    command("init", project, "--screen", source, "--speaker", source)
    command("inspect", project, "--full-decode")
    command("plan", "build", project, "--diagnostic")
    rendered = subprocess.run([sys.executable, "-m", "talkcut", "render", str(project),
                               "--profile", "diagnostic", "--preset", "ultrafast", "--json"],
                              check=True, timeout=60, capture_output=True)
    execution_stdout = directory / "render.stdout.json"
    execution_stdout.write_bytes(rendered.stdout)
    workflow = load_project(project)["active_render"]
    comparison = compare_render(workflow, directory / "comparison")
    raw = {"schema_version": "quality-input/v1", "workflow_render": workflow,
           "render_execution_stdout": artifact_ref(execution_stdout),
           "comparison": comparison["artifact_ref"], "quality_reviews": []}
    return project, raw, comparison["dependencies"]


def test_recomputed_media_does_not_invent_semantic_approval(measured):
    project, raw, deps = measured
    cache = {}
    technical = verify_quality(raw, check_id="output_technical", project_dir=project,
                               dependencies=deps, validated_reviews=[], evaluation_cache=cache)
    assert technical == {"complete_decode": True, "actual_pts_verified": True,
                         "retained_mapping_verified": True, "new_drop_freeze_black_silence": None,
                         "audio_streams": 1, "video_streams": 1, "full_resolution": True}
    geometry = verify_quality(raw, check_id="geometry_audio", project_dir=project,
                              dependencies=deps, validated_reviews=[], evaluation_cache=cache)
    assert geometry["screen_full_frame"] and geometry["speaker_full_frame"]
    assert geometry["screen_dar_preserved"] and geometry["speaker_dar_preserved"]
    assert geometry["speaker_top_right"] and geometry["output_audio_streams"] == 1
    assert all(geometry[key] is None for key in ("important_occlusions", "new_audio_defects", "all_visual_states_checked"))
    assert len(cache) == 1


def test_changed_metrics_are_recomputed_from_media_not_accepted(measured, tmp_path):
    project, raw, deps = measured
    bad = copy.deepcopy(raw)
    report = verified_json(raw["comparison"])
    metrics = Path(report["video"]["metrics"]["path"]).read_text()
    changed_metrics = tmp_path / "forged.jsonl"
    changed_metrics.write_text(metrics.replace('"source_frame": 0', '"source_frame": 1', 1))
    report["video"]["metrics"] = artifact_ref(changed_metrics)
    altered = tmp_path / "forged-comparison.json"
    atomic_json(altered, report)
    bad["comparison"] = artifact_ref(altered)
    with pytest.raises(TalkCutError, match="per-frame/sample"):
        verify_quality(bad, check_id="output_technical", project_dir=project,
                       dependencies=deps, validated_reviews=[], evaluation_cache={})


def test_partial_comparison_and_missing_review_are_rejected(measured, tmp_path):
    project, raw, deps = measured
    report = verified_json(raw["comparison"])
    report["coverage_status"] = "UNVERIFIED"
    changed = tmp_path / "partial.json"
    atomic_json(changed, report)
    with pytest.raises(TalkCutError, match="Partial"):
        verify_quality({**raw, "comparison": artifact_ref(changed)}, check_id="output_technical",
                       project_dir=project, dependencies=deps, validated_reviews=[], evaluation_cache={})
    with pytest.raises(TalkCutError, match="unique validated review"):
        review_counts({"quality_reviews": [raw["comparison"]]}, [], {"findings": []},
                      {"duration": "2", "sample_count": 88200, "sample_rate": 44100})


def test_explicit_unknown_and_incomplete_review_coverage_stay_unknown(tmp_path):
    # These already-validated-row stand-ins exercise interval aggregation only.
    # They are not provider receipts and cannot pass Evaluator.load_review.
    path = tmp_path / "row.json"
    atomic_json(path, {"fixture": "aggregation only"})
    ref = artifact_ref(path)
    row = {"ref": ref, "scope": "output", "intervals": [["0", "1"]],
           "response": {"quality_observations": {"important_occlusions": 0, "new_audio_defects": 0,
                                                 "new_drop_freeze_black_silence": 0}}}
    raw = {"quality_reviews": [ref]}
    timeline = {"duration": "2", "sample_count": 88200, "sample_rate": 44100}
    assert all(value is None for value in review_counts(raw, [row], {"findings": []}, timeline).values())
    row["intervals"] = [["0", "2"]]
    assert review_counts(raw, [row], {"findings": []}, timeline)["important_occlusions"] == 0
    row["response"]["quality_observations"]["new_audio_defects"] = False
    assert review_counts(raw, [row], {"findings": []}, timeline)["new_audio_defects"] is None


def test_detector_trigger_cannot_be_erased_by_a_clean_review(tmp_path):
    path = tmp_path / "row.json"
    atomic_json(path, {"fixture": "aggregation only"})
    ref = artifact_ref(path)
    row = {"ref": ref, "scope": "output", "intervals": [["0", "2"]],
           "response": {"quality_observations": {"important_occlusions": 0, "new_audio_defects": 0,
                                                 "new_drop_freeze_black_silence": 0}}}
    counts = review_counts({"quality_reviews": [ref]}, [row],
                           {"findings": [{"kind": "possible_new_audio_click"}]},
                           {"duration": "2", "sample_count": 88200, "sample_rate": 44100})
    assert counts["new_audio_defects"] is counts["new_drop_freeze_black_silence"] is None
