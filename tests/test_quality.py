"""Real source/output comparisons on public synthetic audiovisual fixtures.

These regressions exercise observations and their coverage. They never turn
synthetic media or a detector's silence into DGIST audiovisual approval.
"""

import copy
import json
import shutil
import subprocess
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


def command(*args):
    return execute(parser_for_cli().parse_args([str(arg) for arg in args]))


@pytest.fixture(scope="module")
def quality_media(tmp_path_factory):
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        pytest.skip("Quality integration requires the actual FFmpeg toolchain")
    directory = tmp_path_factory.mktemp("source-quality")
    source = directory / "public-moving-pattern-and-tone.mp4"
    subprocess.run(
        ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=10:duration=4",
         "-f", "lavfi", "-i", "sine=frequency=700:sample_rate=44100:duration=4.2",
         "-map", "1:a", "-map", "0:v", "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(source)],
        check=True, timeout=60,
    )
    project = directory / "project"
    command("init", project, "--screen", source, "--speaker", source)
    inspected, code = command("inspect", project, "--full-decode")
    assert code == 0 and inspected["status"] == "PASS"
    command("plan", "build", project, "--diagnostic")
    command("render", project, "--profile", "diagnostic", "--preset", "ultrafast")
    baseline = load_project(project)["active_render"]
    candidate, _ = command("plan", "add-test-cut", project, "--start", "1", "--end", "2",
                           "--expected-revision", load_project(project)["revision"])
    command("plan", "decide", project, "--candidate", candidate["candidate_id"], "--decision", "accept",
            "--expected-revision", candidate["project_revision"])
    command("render", project, "--profile", "diagnostic", "--preset", "ultrafast")
    return {"baseline": baseline, "cut": load_project(project)["active_render"], "source": source}


def rows(ref):
    return [json.loads(line) for line in Path(ref["path"]).read_text().splitlines()]


def test_entire_retained_video_and_audio_are_measured_after_actual_cut(quality_media, tmp_path):
    report = compare_render(quality_media["cut"], tmp_path)
    timeline = verified_json(report["input_refs"]["timeline"])
    assert report["status"] == "UNVERIFIED"
    assert report["coverage_status"] == "PASS" and report["whole_retained_source_compared"]
    assert report["owner_acceptance"] == "pending"
    assert report["ai_audio_listening"] == report["ai_visual_occlusion"] == "UNVERIFIED"
    video, audio = report["video"], report["audio"]
    assert video["coverage"]["numerator"] == video["coverage"]["denominator"] == timeline["frame_count"] == 30
    assert audio["coverage"]["numerator"] == audio["coverage"]["denominator"] == timeline["sample_count"] == 132300
    video_rows = rows(video["metrics"])
    assert [row["source_frame"] for row in video_rows] == list(range(10)) + list(range(20, 40))
    assert video["mean_mae_yuv_code_values"] < 5
    audio_rows = rows(audio["metrics"])
    assert audio_rows[0]["output_sample_start"] == 0 and audio_rows[-1]["output_sample_end"] == 132300
    assert any(row["source_sample_start"] == 88200 and row["output_sample_start"] == 44100 for row in audio_rows)
    assert len(audio["seam_measurements"]) == 1
    assert audio["seam_measurements"][0]["listening_review"] == "UNVERIFIED"
    for decoder in video["decoders"] + audio["decoders"]:
        assert decoder["exit_code"] == 0 and not decoder["intentional_partial_stop"]
        assert Path(decoder["stderr"]["path"]).read_bytes() == b""
    assert report["dependencies"]["timeline_hash"] == report["input_refs"]["timeline"]["sha256"]
    receipt = verified_json(report["receipt"])
    assert receipt["operation"] == "quality:compare" and receipt["result"] == report["artifact_ref"]
    assert "stdout" not in receipt  # In-process execution must not invent subprocess stdout.


def test_explicit_partial_limits_never_claim_whole_coverage(quality_media, tmp_path):
    report = compare_render(quality_media["baseline"], tmp_path, max_video_frames=2, max_audio_samples=4096)
    assert report["status"] == report["coverage_status"] == "UNVERIFIED"
    assert not report["whole_retained_source_compared"]
    assert report["video"]["coverage"]["numerator"] == 2
    assert report["video"]["coverage"]["denominator"] == 40
    assert report["audio"]["coverage"]["numerator"] == 4096
    assert report["audio"]["coverage"]["denominator"] == 176400
    assert len(rows(report["video"]["metrics"])) == 2
    for decoder in report["video"]["decoders"] + report["audio"]["decoders"]:
        assert decoder["intentional_partial_stop"]


def fault_workflow(original_ref, destination, *, video_filter, audio_filter):
    """Produce actual corrupted media; only the test wrapper's provenance is copied.

    A copied successful manifest is explicitly marked as test fault injection.
    The comparer is expected to observe the real media defect and cannot approve
    quality based on that manifest's inherited rendering status.
    """
    original = verified_json(original_ref)
    native = verified_json(original["native_render"])
    output = destination / "actual-fault.mp4"
    subprocess.run(
        ["ffmpeg", "-v", "error", "-i", original["output"]["path"], "-map", "0:v", "-map", "0:a",
         "-vf", video_filter, "-af", audio_filter, "-fps_mode", "passthrough", "-c:v", "libx264", "-bf", "0",
         "-preset", "ultrafast", "-c:a", "aac", str(output)],
        check=True, timeout=60,
    )
    changed = copy.deepcopy(native)
    changed["output"] = artifact_ref(output) | {"bytes": output.stat().st_size}
    changed["test_fault_injection"] = "Actual encoded defect, not trusted render provenance"
    native_path = destination / "fault-native.json"
    atomic_json(native_path, changed)
    wrapper = copy.deepcopy(original)
    wrapper["output"], wrapper["native_render"] = changed["output"], artifact_ref(native_path)
    wrapper["test_fault_injection"] = changed["test_fault_injection"]
    wrapper_path = destination / "fault-workflow.json"
    atomic_json(wrapper_path, wrapper)
    return artifact_ref(wrapper_path)


def test_actual_new_black_and_silence_produce_unresolved_investigation_ranges(quality_media, tmp_path):
    fault_ref = fault_workflow(quality_media["cut"], tmp_path,
                              video_filter="lut=y=16:u=128:v=128", audio_filter="volume=0")
    report = compare_render(fault_ref, tmp_path / "measurements")
    kinds = {finding["kind"] for finding in report["findings"]}
    assert {"possible_new_black", "possible_new_audio_silence", "large_screen_difference"} <= kinds
    assert report["audio"]["output_rms"] == 0 and report["audio"]["source_rms"] > 0.01
    assert report["whole_retained_source_compared"] and report["status"] == "UNVERIFIED"
    assert all(finding["verdict"] == "UNVERIFIED" and not finding["resolved"] for finding in report["findings"])
    assert all(finding["output_interval"][0] != finding["output_interval"][1] for finding in report["findings"])


def test_actual_new_freeze_and_gain_are_compared_to_moving_source(quality_media, tmp_path):
    fault_ref = fault_workflow(quality_media["cut"], tmp_path,
                              video_filter="loop=loop=-1:size=1:start=0,trim=end_frame=30", audio_filter="volume=12")
    report = compare_render(fault_ref, tmp_path / "measurements")
    kinds = {finding["kind"] for finding in report["findings"]}
    assert "possible_new_freeze" in kinds
    assert "possible_audio_gain_change" in kinds
    assert "possible_new_audio_clipping" in kinds
    assert report["status"] == "UNVERIFIED"


def test_modified_artifact_is_rejected_before_claiming_measurement(quality_media, tmp_path):
    ref = dict(quality_media["baseline"], sha256="0" * 64)
    with pytest.raises(TalkCutError):
        compare_render(ref, tmp_path)
    assert not list(tmp_path.rglob("comparison.json"))


def test_original_static_black_and_silence_are_not_invented_output_defects(tmp_path):
    source = tmp_path / "public-static-black-and-silence.mp4"
    subprocess.run(
        ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "color=black:size=320x180:rate=10:duration=2",
         "-f", "lavfi", "-i", "anullsrc=channel_layout=mono:sample_rate=44100:duration=2.2",
         "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(source)],
        check=True, timeout=60,
    )
    project = tmp_path / "project"
    command("init", project, "--screen", source, "--speaker", source)
    command("inspect", project, "--full-decode")
    command("plan", "build", project, "--diagnostic")
    command("render", project, "--profile", "diagnostic", "--preset", "ultrafast")
    report = compare_render(load_project(project)["active_render"], tmp_path / "measurements")
    assert report["findings"] == []
    assert report["video"]["mean_mse_yuv_code_values"] == 0
    assert report["audio"]["source_rms"] == report["audio"]["output_rms"] == 0
    assert report["status"] == "UNVERIFIED"  # Exact pixels/silence still are not AI approval.


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_limits_do_not_silently_change_denominators(quality_media, tmp_path, limit):
    with pytest.raises(TalkCutError, match="positive integers"):
        compare_render(quality_media["baseline"], tmp_path, max_video_frames=limit)
