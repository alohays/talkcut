"""Independent synthetic validation; no native/AV acceptance is claimed."""
import copy
import subprocess
from pathlib import Path

import numpy as np
import pytest

from talkcut.acceptance import Evaluator, EvidenceError
from talkcut.audio_processing import audio_filter_suffix, validate_audio_processing
from talkcut.measurement_checks import verify_render
from talkcut.media import inspect_source
from talkcut.plan import add_test_cut, build_plan, decide, set_audio_profile
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    init_project,
    load_project,
    project_lock,
    save_revision,
    sha256,
    store_artifact,
    verified_json,
)
from talkcut.workflow import qc_project, render_project


def profile(value):
    return {"schema_version": "audio-processing/v1", "gain_db": value}


@pytest.fixture(scope="module")
def source(tmp_path_factory):
    directory = tmp_path_factory.mktemp("independent-stereo-48000")
    path = directory / "source.mp4"
    args = ["ffmpeg", "-nostdin", "-v", "error", "-n", "-f", "lavfi", "-i",
        "testsrc2=size=160x96:rate=30:duration=4", "-f", "lavfi", "-i",
        "aevalsrc=0.4*sin(2*PI*431*t)*(0.25+0.75*t/4.25)|0.27*sin(2*PI*997*t):s=48000:d=4.25",
        "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-preset", "ultrafast",
        "-c:a", "aac", "-b:a", "192k", str(path)]
    run = subprocess.run(args, check=True, capture_output=True, timeout=30)
    inspection = inspect_source(path, directory / "inspection")
    assert inspection["status"] == "PASS"
    atomic_json(directory / "generator.local.json", {"argv": args, "exit_code": run.returncode,
        "source": artifact_ref(path), "scope": "Independent generated fixture; not lecture or acceptance evidence"})
    return path, inspection


@pytest.fixture
def project(tmp_path, source):
    path, inspection = source
    directory = tmp_path / "project"
    init_project(directory, path, path)
    with project_lock(directory):
        value = load_project(directory)
        ref = store_artifact(directory, "inspections", inspection)
        value["inspections"] = {role: ref for role in ("screen", "speaker")}
        save_revision(directory, value, value["revision"], "attach_actual_independent_fixture_inspection", {})
    build_plan(directory, diagnostic=True)
    return directory


@pytest.mark.parametrize("value", [
    "-1\n", "−1", "-١", "-1/0002", "-1/-2", "-24/2", "-12000000000001/1000000000000",
    "-1/2.0", "-1\\,aecho=1", "-1'", "-1\x00", "-1/2;[aout]", "-1:e=frame",
    {"gain_db": "-1"}, ["-1"], b"-1",
])
def test_independent_injection_canonical_and_type_controls(value):
    with pytest.raises(TalkCutError):
        validate_audio_processing(profile(value))


@pytest.mark.parametrize("value", ["0", "-12", "-11999/1000", "-1/1000000000000000000000000000000", "-3/2"])
def test_independent_valid_rational_boundaries(value):
    assert validate_audio_processing(profile(value)) == profile(value)
    assert audio_filter_suffix(profile(value)).count("volume=") == (0 if value == "0" else 2)


@pytest.mark.parametrize("kind", ["float_revision", "string_revision", "bool_revision", "none_revision", "long_reason", "none_reason"])
def test_rejected_transaction_has_no_project_or_plan_side_effect(project, kind):
    state = load_project(project)
    revision, reason = state["revision"], "Independent measured-profile mutation control"
    if kind == "float_revision": revision = float(revision)
    elif kind == "string_revision": revision = str(revision)
    elif kind == "bool_revision": revision = True
    elif kind == "none_revision": revision = None
    elif kind == "long_reason": reason = "x" * 4001
    elif kind == "none_reason": reason = None
    before = {str(path.relative_to(project)): sha256(path) for path in project.rglob("*") if path.is_file()}
    with pytest.raises(TalkCutError):
        set_audio_profile(project, "-3/2", reason, revision)
    after = {str(path.relative_to(project)): sha256(path) for path in project.rglob("*") if path.is_file()}
    assert before == after and load_project(project) == state


def decode_pcm(path):
    run = subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-xerror", "-i", str(path), "-map", "0:a:0",
        "-c:a", "pcm_f32le", "-f", "f32le", "pipe:1"], check=True, capture_output=True, timeout=30)
    return np.frombuffer(run.stdout, dtype="<f4").reshape(-1, 2)


def pre_encoder(native):
    args = native["command"][:native["command"].index("-map")]
    args += ["-map", "[vout]", "-f", "null", "-", "-map", "[aout]", "-c:a", "pcm_f32le", "-f", "f32le", "pipe:1"]
    run = subprocess.run(args, check=True, capture_output=True, timeout=30)
    return np.frombuffer(run.stdout, dtype="<f4").reshape(-1, 2)


def video_frames(path):
    run = subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-xerror", "-i", str(path), "-map", "0:v:0",
        "-fps_mode", "passthrough", "-f", "framemd5", "pipe:1"], check=True, capture_output=True, timeout=30)
    return [line for line in run.stdout.decode().splitlines() if not line.startswith("#")]


def test_independent_full_pcm_multicut_rational_gain_and_old_evidence(project, source, tmp_path):
    for start, end in (("1/2", "1"), ("2", "5/2")):
        added = add_test_cut(project, start, end, load_project(project)["revision"])
        decide(project, added["candidate_id"], "accept", added["project_revision"])
    old_state = load_project(project)
    zero = render_project(project, "review", preset="ultrafast")
    zero_state = load_project(project)
    zero_native = verified_json(zero["native_render"])
    zero_timeline = verified_json(zero_state["active_timeline"])
    old_refs = [zero_state["active_plan"], zero_state["active_timeline"], zero_state["active_render"], zero["native_render"], zero["output"]]
    before = [artifact_ref(Path(ref["path"])) for ref in old_refs]
    set_audio_profile(project, "-3/2", "Measured synthetic signal: independent rational attenuation test", zero_state["revision"])
    state = load_project(project)
    assert state["events"][:-1] == zero_state["events"]
    assert state["active_render"] is None and state["owner_acceptance"] == "pending"
    assert set(state["events"][-1]["details"]["invalidated"]) == {"output_qc", "all_seams", "whole_output_review", "ready"}
    plan = verified_json(state["active_plan"])
    assert plan["parent"] == zero_state["active_plan"]
    assert plan["audio_processing_change"]["previous"] == profile("0")
    assert plan["audio_processing_change"]["reason"] == plan["audio_processing_reason"]
    timeline = verified_json(state["active_timeline"])
    for field in ("frames", "retained", "duration", "sample_count", "sample_rate", "audio", "speaker"):
        assert timeline[field] == zero_timeline[field]
    assert timeline["timeline_hash"] != zero_timeline["timeline_hash"]
    evaluator = Evaluator(project, zero["render_id"], tmp_path / "unused-contract.json", Path.cwd())
    evaluator.index = {"timeline": zero_state["active_timeline"]}
    with pytest.raises(EvidenceError, match="current committed project timeline"):
        evaluator.bind_plan_timeline()
    reduced = render_project(project, "review", preset="ultrafast")
    assert not reduced["cache_hit"] and reduced["render_id"] != zero["render_id"]
    verified = verify_render(reduced, load_project(project))
    assert verified["validation"]["status"] == "PASS"
    assert qc_project(project)["status"] == "UNVERIFIED"
    reduced_native = verified_json(reduced["native_render"])
    original_pcm = decode_pcm(source[0])
    reference = np.concatenate([original_pcm[row["audio_source_sample_start"]:row["audio_source_sample_end"]] for row in timeline["retained"]])
    zero_pcm, reduced_pcm = pre_encoder(zero_native), pre_encoder(reduced_native)
    assert zero_pcm.shape == reduced_pcm.shape == reference.shape == (144000, 2)
    assert np.array_equal(reference, zero_pcm)
    expected = reference * np.float32(10 ** (-1.5 / 20))
    assert np.array_equal(reduced_pcm, expected)
    assert video_frames(zero["output"]["path"]) == video_frames(reduced["output"]["path"])
    decoded = decode_pcm(reduced["output"]["path"])[:len(reference)]
    correlations = [float(np.corrcoef(reference[:, channel], decoded[:, channel])[0, 1]) for channel in (0, 1)]
    assert min(correlations) > 0.995
    assert abs(np.corrcoef(reference[:, 0], decoded[:, 1])[0, 1]) < 0.03
    cached = render_project(project, "review", preset="ultrafast")
    assert cached["cache_hit"] and cached["output"] == reduced["output"]
    with pytest.raises(TalkCutError, match="cannot render a master"):
        render_project(project, "master", preset="ultrafast")
    set_audio_profile(project, "0", "Independent exact same-cut zero-profile restoration", load_project(project)["revision"])
    restored = render_project(project, "review", preset="ultrafast")
    assert restored["output"]["sha256"] == zero["output"]["sha256"]
    assert before == [artifact_ref(Path(ref["path"])) for ref in old_refs]
    assert artifact_ref(source[0])["sha256"] == old_state["sources"]["screen"]["sha256"]
    atomic_json(tmp_path / "independent-measurements.local.json", {"sample_frames": len(reference), "channels": 2,
        "sample_rate": 48000, "retained_spans": len(timeline["retained"]), "gain_db": "-3/2", "pre_encoder_max_error": float(np.max(np.abs(reduced_pcm - expected))),
        "channel_correlations": correlations, "video_frames_and_pts_equal": True, "zero_restore_sha_equal": True,
        "old_artifacts_unchanged": True, "scope": "Independent synthetic PCM/byte checks only", "accepted_av_seconds": 0})


@pytest.mark.parametrize("damage", ["remove_volume", "double_volume", "swap_channels", "resample", "native_profile", "settings_profile", "missing_native_profile"])
def test_hash_consistent_relabelled_native_command_still_refuses(project, tmp_path, damage):
    set_audio_profile(project, "-3/2", "Independent native command integrity control", load_project(project)["revision"])
    rendered = render_project(project, "review", preset="ultrafast")
    state = load_project(project)
    native = verified_json(rendered["native_render"])
    supplied = copy.deepcopy(rendered)
    suffix = audio_filter_suffix(profile("-3/2"))
    if damage == "remove_volume": native["filtergraph"] = native["filtergraph"].replace(suffix, "")
    elif damage == "double_volume": native["filtergraph"] = native["filtergraph"].replace(suffix, suffix + suffix)
    elif damage == "swap_channels": native["filtergraph"] = native["filtergraph"].replace(suffix, suffix + ",pan=stereo|c0=c1|c1=c0")
    elif damage == "resample": native["filtergraph"] = native["filtergraph"].replace(suffix, suffix + ",aresample=48000")
    elif damage == "native_profile": native["audio_processing"] = profile("-1")
    elif damage == "settings_profile": supplied["settings"]["audio_processing"] = profile("-1")
    elif damage == "missing_native_profile": native.pop("audio_processing")
    native["command"][native["command"].index("-filter_complex") + 1] = native["filtergraph"]
    native_path = tmp_path / "forged-native.json"
    atomic_json(native_path, native)
    supplied["native_render"] = artifact_ref(native_path)
    saved = {key: value for key, value in supplied.items() if key not in ("cache_hit", "project_revision")}
    saved_path = tmp_path / "forged-success.json"
    atomic_json(saved_path, saved)
    # Simulate fully rewritten hashes/history: the independent recipe must still reject.
    state["events"][-1]["details"]["render"] = artifact_ref(saved_path)
    with pytest.raises(TalkCutError, match="audio profile|exact plan-bound|missing"):
        verify_render(supplied, state)


def test_project_profile_disagreement_never_reaches_media_execution(project, monkeypatch):
    state = load_project(project)
    state["audio_processing"] = profile("-3/2")
    atomic_json(project / "project.json", state)
    def forbidden(*args, **kwargs):
        raise AssertionError("Renderer reached after mismatched project/plan profile")
    monkeypatch.setattr("talkcut.workflow.render", forbidden)
    with pytest.raises(TalkCutError, match="current project audio profiles differ"):
        render_project(project, "review")
