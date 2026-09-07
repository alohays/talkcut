"""Authored synthetic AAC/PCM execution; not listening, DGIST or AI approval."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from talkcut.__main__ import execute, parser_for_cli
from talkcut.audio_processing import (
    audio_filter_suffix,
    validate_audio_processing,
    verify_audio_processing_binding,
)
from talkcut.measurement_checks import verify_render
from talkcut.plan import build_plan, set_audio_profile
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    load_project,
    read_json,
    sha256,
    verified_json,
)
from talkcut.render import RenderError, build_render_command
from talkcut.workflow import qc_project, render_project


def command(*args):
    return execute(parser_for_cli().parse_args([str(arg) for arg in args]))


def profile(gain):
    return {"schema_version": "audio-processing/v1", "gain_db": gain}


@pytest.mark.parametrize(
    "gain",
    [
        None,
        True,
        0,
        -1.0,
        "",
        "1",
        "+1",
        "-13",
        "-1/0",
        "-0",
        "00",
        "0/1",
        "-2/2",
        "-1.0",
        "-.5",
        "NaN",
        "-inf",
        "1e300",
        "-1;anull",
        "-1dB",
        "-1/2:eval=frame",
        "-" + "9" * 70,
    ],
)
def test_gain_rejects_noncanonical_numeric_or_filter_input(gain):
    with pytest.raises(TalkCutError, match="canonical|between"):
        validate_audio_processing(profile(gain))


@pytest.mark.parametrize(
    "value",
    [
        None,
        {},
        {"schema_version": "audio-processing/v2", "gain_db": "0"},
        {**profile("-1"), "denoise": True},
        {"gain_db": "0"},
    ],
)
def test_profile_is_closed(value):
    with pytest.raises(TalkCutError):
        validate_audio_processing(value)


def test_constant_attenuation_only_and_no_render_override():
    assert validate_audio_processing() == profile("0")
    assert audio_filter_suffix(profile("0")) == ""
    for value in ("-1", "-3/2", "-12"):
        assert validate_audio_processing(profile(value)) == profile(value)
        suffix = audio_filter_suffix(profile(value))
        assert suffix == f",volume=volume='pow(10,({value})/20)':precision=float"
    with pytest.raises(SystemExit):
        parser_for_cli().parse_args(["render", "P", "--gain-db", "-1"])


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    path = tmp_path_factory.mktemp("audio-profile-source") / "authored-stereo.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-n",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=160x96:rate=30:duration=6",
            "-f",
            "lavfi",
            "-i",
            "aevalsrc=0.91*sin(2*PI*700*t)|0.61*sin(2*PI*1100*t):s=44100:d=6.25",
            "-map",
            "1:a",
            "-map",
            "0:v",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            str(path),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return artifact_ref(path)


@pytest.fixture
def project(tmp_path, source):
    directory = tmp_path / "project"
    command("init", directory, "--screen", source["path"], "--speaker", source["path"])
    inspected, code = command("inspect", directory, "--full-decode")
    assert code == 0 and inspected["status"] == "PASS"
    build_plan(directory, diagnostic=True)
    return directory


def pcm(path):
    result = subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-xerror",
            "-i",
            str(path),
            "-map",
            "0:a:0",
            "-c:a",
            "pcm_f32le",
            "-f",
            "f32le",
            "-",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    return np.frombuffer(result.stdout, dtype="<f4").reshape(-1, 2)


def filter_pcm(native):
    # Execute the exact complete audio/video graph with a lossless PCM sink.
    # Only output codecs/muxers change; no cut, filter or source is rewritten.
    command = native["command"][: native["command"].index("-map")]
    command += [
        "-map",
        "[vout]",
        "-f",
        "null",
        "-",
        "-map",
        "[aout]",
        "-c:a",
        "pcm_f32le",
        "-f",
        "f32le",
        "pipe:1",
    ]
    result = subprocess.run(command, check=True, capture_output=True, timeout=30)
    return np.frombuffer(result.stdout, dtype="<f4").reshape(-1, 2)


def video_facts(path):
    decoded = subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-xerror",
            "-i",
            str(path),
            "-map",
            "0:v:0",
            "-fps_mode",
            "passthrough",
            "-f",
            "framemd5",
            "-",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    probe = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_streams",
            "-show_frames",
            "-of",
            "json",
            str(path),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    data = json.loads(probe.stdout)
    return (
        decoded.stdout,
        [
            (f["pts"], f.get("duration", f.get("pkt_duration")))
            for f in data["frames"]
            if f["media_type"] == "video"
        ],
        next(s for s in data["streams"] if s["codec_type"] == "audio"),
    )


def test_actual_stereo_cut_attenuation_samples_channels_pts_cache_and_restore(
    project, source, tmp_path
):
    original_hash = sha256(source["path"])
    added, _ = command(
        "plan",
        "add-test-cut",
        project,
        "--start",
        "1",
        "--end",
        "2",
        "--expected-revision",
        load_project(project)["revision"],
    )
    command(
        "plan",
        "decide",
        project,
        "--candidate",
        added["candidate_id"],
        "--decision",
        "accept",
        "--expected-revision",
        added["project_revision"],
    )
    zero_timeline = verified_json(load_project(project)["active_timeline"])
    baseline = render_project(project, "diagnostic", preset="ultrafast")
    baseline_hash = sha256(baseline["output"]["path"])
    changed, code = command(
        "plan",
        "set-audio-profile",
        project,
        "--gain-db",
        "-1",
        "--reason",
        "Authored execution tests a measured fixed attenuation; no quality approval.",
        "--expected-revision",
        load_project(project)["revision"],
    )
    assert code == 0 and changed["audio_processing"] == profile("-1")
    current = load_project(project)
    assert current["active_render"] is None and current["owner_acceptance"] == "pending"
    assert "ready" in current["events"][-1]["details"]["invalidated"]
    timeline = verified_json(current["active_timeline"])
    for key in (
        "frames",
        "retained",
        "duration",
        "sample_count",
        "frame_count",
        "audio",
    ):
        assert timeline[key] == zero_timeline[key]
    assert timeline["timeline_hash"] != zero_timeline["timeline_hash"]
    rendered = subprocess.run(
        [
            sys.executable,
            "-m",
            "talkcut",
            "render",
            str(project),
            "--profile",
            "review",
            "--preset",
            "ultrafast",
            "--json",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    stdout_path = tmp_path / "attenuated-render.stdout.json"
    stdout_path.write_bytes(rendered.stdout)
    reduced = json.loads(rendered.stdout)
    assert not reduced["cache_hit"]
    checked = verify_render(reduced, load_project(project))
    assert verified_json(checked["render"]["native_render"])[
        "audio_processing"
    ] == profile("-1")
    assert (
        checked["plan"]["audio_processing"] == reduced["settings"]["audio_processing"]
    )
    assert qc_project(project)["technical"]["status"] == "PASS"
    count = timeline["sample_count"]
    a, b = pcm(baseline["output"]["path"]), pcm(reduced["output"]["path"])
    assert len(a) == len(b) and 0 <= len(a) - count < 1024
    a, b = a[:count], b[:count]
    decoded_source = pcm(source["path"])
    reference = np.concatenate(
        [
            decoded_source[
                row["audio_source_sample_start"] : row["audio_source_sample_end"]
            ]
            for row in timeline["retained"]
        ]
    )
    assert len(reference) == count
    gain = 10 ** (-1 / 20)
    rms = lambda values: np.sqrt(np.mean(values.astype(np.float64) ** 2, axis=0))
    assert np.allclose(rms(b) / rms(a), gain, atol=0.003, rtol=0)
    assert np.allclose(rms(b) / rms(reference), gain, atol=0.004, rtol=0)
    before_encoder = filter_pcm(verified_json(baseline["native_render"]))
    after_encoder_input = filter_pcm(verified_json(reduced["native_render"]))
    assert len(before_encoder) == len(after_encoder_input) == count
    assert np.array_equal(before_encoder, reference)
    assert np.allclose(
        after_encoder_input, before_encoder * np.float32(gain), atol=1e-7, rtol=0
    )
    assert np.allclose(
        np.max(np.abs(after_encoder_input), axis=0)
        / np.max(np.abs(before_encoder), axis=0),
        gain,
        atol=1e-7,
        rtol=0,
    )
    # AAC is lossy and nonlinear: output peaks must be measured separately.
    # This same high-level synthetic input exposed a decoded AAC overshoot;
    # attenuation never grants a clipping or listening PASS.
    assert np.isfinite(b).all()
    from talkcut.quality import compare_render
    from talkcut.quality_checks import verify_quality

    comparison = compare_render(
        load_project(project)["active_render"], tmp_path / "comparison"
    )
    assert comparison["status"] == "UNVERIFIED"
    observed_new = int(np.sum((np.abs(b) > 1) & (np.abs(reference) <= 1)))
    if observed_new:
        assert any(
            item["kind"] == "possible_new_audio_clipping" and not item.get("resolved")
            for item in comparison["findings"]
        )
    raw = {
        "schema_version": "quality-input/v1",
        "workflow_render": load_project(project)["active_render"],
        "render_execution_stdout": artifact_ref(stdout_path),
        "comparison": comparison["artifact_ref"],
        "quality_reviews": [],
    }
    quality = verify_quality(
        raw,
        check_id="geometry_audio",
        project_dir=project,
        dependencies=comparison["dependencies"],
        validated_reviews=[],
        evaluation_cache={},
    )
    assert quality["new_audio_defects"] is None
    correlations = [
        np.corrcoef(reference[:, channel], b[:, channel])[0, 1] for channel in (0, 1)
    ]
    assert min(correlations) > 0.995
    assert abs(np.corrcoef(reference[:, 0], b[:, 1])[0, 1]) < 0.02
    va, ptsa, aa = video_facts(baseline["output"]["path"])
    vb, ptsb, ab = video_facts(reduced["output"]["path"])
    assert va == vb and ptsa == ptsb
    assert (
        aa["channels"] == ab["channels"] == 2
        and aa["sample_rate"] == ab["sample_rate"] == "44100"
    )
    assert aa["duration_ts"] == ab["duration_ts"] and aa["time_base"] == ab["time_base"]
    cached = render_project(project, "review", preset="ultrafast")
    assert cached["cache_hit"] and cached["output"] == reduced["output"]
    before = load_project(project)
    with pytest.raises(TalkCutError, match="newer project revision"):
        set_audio_profile(
            project, "0", "Stale revision must be refused", before["revision"] - 1
        )
    assert load_project(project) == before
    set_audio_profile(
        project,
        "0",
        "Revert the fixed gain for the same exact cuts",
        before["revision"],
    )
    zero_again = render_project(project, "review", preset="ultrafast")
    assert zero_again["output"]["sha256"] == baseline_hash
    set_audio_profile(
        project,
        "-1",
        "Reapply the same fixed profile",
        load_project(project)["revision"],
    )
    before = load_project(project)
    command(
        "plan",
        "restore",
        project,
        "--candidate",
        added["candidate_id"],
        "--expected-revision",
        before["revision"],
    )
    assert verified_json(load_project(project)["active_plan"])[
        "audio_processing"
    ] == profile("-1")
    build_plan(project, diagnostic=True)
    assert verified_json(load_project(project)["active_plan"])[
        "audio_processing"
    ] == profile("-1")
    set_audio_profile(
        project,
        "0",
        "Restore unprocessed audio, preserving successful prior outputs",
        load_project(project)["revision"],
    )
    restored = render_project(project, "review", preset="ultrafast")
    assert (
        restored["settings"]["audio_processing"] == profile("0")
        and not restored["cache_hit"]
    )
    assert (
        sha256(baseline["output"]["path"]) == baseline_hash
        and sha256(source["path"]) == original_hash
    )
    assert sha256(reduced["output"]["path"]) == reduced["output"]["sha256"]
    assert (
        restored["ai_review"] == "UNVERIFIED"
        and load_project(project)["owner_acceptance"] == "pending"
    )
    # Save computed fixture observations, never a listening/semantic verdict.
    atomic_json(
        tmp_path / "actual-audio-measurements.json",
        {
            "scope": "synthetic test only",
            "samples": count,
            "rms_ratio": (rms(b) / rms(a)).tolist(),
            "channel_correlations": correlations,
            "source_peak": np.max(np.abs(reference), axis=0).tolist(),
            "zero_peak": np.max(np.abs(a), axis=0).tolist(),
            "attenuated_peak": np.max(np.abs(b), axis=0).tolist(),
            "video_pts_equal": ptsa == ptsb,
            "pre_encoder_max_error": float(
                np.max(np.abs(after_encoder_input - before_encoder * np.float32(gain)))
            ),
            "aac_new_over_1_samples": observed_new,
            "quality_report": comparison["artifact_ref"],
            "accepted_av_seconds": 0,
        },
    )


def test_exact_profile_metadata_command_and_cache_refuse_tampering(project):
    set_audio_profile(
        project, "-1", "Synthetic binding test", load_project(project)["revision"]
    )
    result = render_project(project, "review", preset="ultrafast")
    project_data = load_project(project)
    plan = verified_json(result["settings"]["plan"])
    timeline = verified_json(result["settings"]["timeline"])
    native = verified_json(result["native_render"])
    for index in range(3):
        values = [
            copy.deepcopy(timeline),
            copy.deepcopy(result["settings"]),
            copy.deepcopy(native),
        ]
        values[index]["audio_processing"] = profile("0")
        with pytest.raises(TalkCutError, match="audio profile differs"):
            verify_audio_processing_binding(plan, *values)
        values[index].pop("audio_processing")
        with pytest.raises(TalkCutError, match="missing"):
            verify_audio_processing_binding(plan, *values)
    success_path = Path(project_data["active_render"]["path"])
    native_path = Path(result["native_render"]["path"])
    original_success, original_native = (
        success_path.read_bytes(),
        native_path.read_bytes(),
    )
    changed = copy.deepcopy(native)
    suffix = audio_filter_suffix(profile("-1"))
    changed["filtergraph"] = changed["filtergraph"].replace(suffix, "")
    changed["command"][changed["command"].index("-filter_complex") + 1] = changed[
        "filtergraph"
    ]
    atomic_json(native_path, changed)
    success = read_json(success_path)
    success["native_render"] = artifact_ref(native_path)
    atomic_json(success_path, success)
    try:
        with pytest.raises(TalkCutError, match="exact plan-bound"):
            render_project(project, "review", preset="ultrafast")
    finally:
        native_path.write_bytes(original_native)
        success_path.write_bytes(original_success)
    assert (
        verify_render(result, load_project(project))["validation"]["status"] == "PASS"
    )


def test_zero_graph_legacy_compatibility_and_master_gate(project, tmp_path):
    result = render_project(project, "diagnostic", preset="ultrafast")
    checked = verify_render(result, load_project(project))
    timeline = checked["timeline"]
    native = verified_json(checked["render"]["native_render"])
    assert "volume=" not in native["filtergraph"]
    with pytest.raises(TalkCutError, match="cannot render a master"):
        render_project(project, "master", preset="ultrafast")
    with pytest.raises(TypeError):
        render_project(project, "review", gain_db="-1")
    inspected = {
        role: verified_json(load_project(project)["inspections"][role])
        for role in ("screen", "speaker")
    }
    inputs = {
        role: {
            **native["sources"][role],
            "stream_index": inspected[role]["video"]["index"],
            "width": inspected[role]["video"]["width"],
            "height": inspected[role]["video"]["height"],
            "sar": inspected[role]["video"]["sample_aspect_ratio"],
        }
        for role in ("screen", "speaker")
    }
    audio_role = checked["plan"]["timing"]["audio_source"]
    inputs["audio"] = {
        **native["sources"]["audio"],
        "stream_index": inspected[audio_role]["audio"]["index"],
        "sample_rate": timeline["sample_rate"],
    }
    from talkcut.project import content_hash

    legacy = copy.deepcopy(timeline)
    legacy.pop("audio_processing")
    legacy.pop("timeline_hash")
    legacy["timeline_hash"] = content_hash(legacy)
    recipe = build_render_command(
        legacy,
        inputs,
        native["command"][-1],
        checked["plan"]["layout"],
        preset="ultrafast",
    )
    assert (
        recipe["filtergraph"] == native["filtergraph"]
        and recipe["command"] == native["command"]
    )
    broken = copy.deepcopy(timeline)
    broken["audio_processing"]["gain_db"] = "-1;anull"
    broken.pop("timeline_hash")
    broken["timeline_hash"] = content_hash(broken)
    with pytest.raises(RenderError, match="canonical"):
        build_render_command(broken, inputs, tmp_path / "injected.mp4")


def test_profile_change_rejects_invalid_reason_and_does_not_repair_project(project):
    before = load_project(project)
    for gain, reason in (
        ("-1", ""),
        ("-1", " " * 2),
        ("1", "No amplification"),
        ("-13", "Out of range"),
    ):
        with pytest.raises(TalkCutError):
            set_audio_profile(project, gain, reason, before["revision"])
        assert load_project(project) == before
    for value in (None, profile("-13")):
        altered = copy.deepcopy(before)
        altered["audio_processing"] = value
        atomic_json(project / "project.json", altered)
        try:
            with pytest.raises(ValueError):
                load_project(project)
        finally:
            atomic_json(project / "project.json", before)


def test_first_render_rejects_different_timeline_profile_before_media_execution(
    project, monkeypatch
):
    set_audio_profile(
        project,
        "-1",
        "Synthetic timeline binding test",
        load_project(project)["revision"],
    )
    current = load_project(project)
    timeline = verified_json(current["active_timeline"])
    timeline["audio_processing"] = profile("0")
    from talkcut.project import content_hash

    timeline.pop("timeline_hash")
    timeline["timeline_hash"] = content_hash(timeline)
    # This hash-valid altered synthetic timeline must still fail the plan binding.
    changed_path = project / "changed-timeline.json"
    atomic_json(changed_path, timeline)
    current["active_timeline"] = artifact_ref(changed_path)
    atomic_json(project / "project.json", current)

    def forbidden(*args, **kwargs):
        raise AssertionError("Media execution must not begin for a different profile")

    monkeypatch.setattr("talkcut.workflow.render", forbidden)
    with pytest.raises(TalkCutError, match="timeline audio profile differs"):
        render_project(project, "review")
