"""Known actual A/V bytes after an isolated provider gate; no real AI claims."""

import subprocess

import pytest

from talkcut.project import TalkCutError, artifact_ref, atomic_json
from talkcut.review import _capability, precision_review_required


def capability(tmp_path, monkeypatch, *, limitations=True):
    audio = tmp_path / "audio.wav"
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
            "sine=frequency=440:sample_rate=48000:duration=1",
            str(audio),
        ],
        check=True,
        capture_output=True,
    )
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
            "testsrc2=s=64x64:rate=4:duration=1",
            "-frames:v",
            "4",
            str(tmp_path / "frame-%02d.png"),
        ],
        check=True,
        capture_output=True,
    )
    frames = [artifact_ref(path) for path in sorted(tmp_path.glob("frame-*.png"))]
    timestamps = ["0", "1/4", "1/2", "3/4"]
    request = {
        "input_modalities": ["audio", "image_sequence"],
        "input_audio_hash": artifact_ref(audio)["sha256"],
        "input_frame_hashes": [ref["sha256"] for ref in frames],
        "input_frame_timestamps": timestamps,
    }
    challenge = {
        "audio_events": ["authored tone"],
        "video_events": ["authored moving pattern"],
    }
    atomic_json(tmp_path / "request.json", request)
    atomic_json(tmp_path / "challenge.json", challenge)
    observation = {
        "audio_continuous": True,
        "video_frame_timestamps": timestamps,
        "frame_artifacts": frames,
        "audio_artifact": artifact_ref(audio),
        "request_sha256": artifact_ref(tmp_path / "request.json")["sha256"],
    }
    if limitations:
        observation["sampling_limitations"] = (
            "Only timestamped four-fps samples were provided; rapid motion and lip timing remain unverified."
        )
    atomic_json(tmp_path / "observation.json", observation)
    execution = {
        "model_revision": "isolated-role-binding-test",
        "request": artifact_ref(tmp_path / "request.json"),
        "response": artifact_ref(tmp_path / "challenge.json"),
    }
    monkeypatch.setattr("talkcut.review._receipt", lambda ref: execution)
    return {
        "schema_version": "review-capability/v1",
        "model_revision": execution["model_revision"],
        "challenge": artifact_ref(tmp_path / "challenge.json"),
        "observations": artifact_ref(tmp_path / "challenge.json"),
        "input_observation": artifact_ref(tmp_path / "observation.json"),
        "temporal_resolution_ms": 250,
    }


def test_semantic_sampling_does_not_claim_lip_precision(tmp_path, monkeypatch):
    value = capability(tmp_path, monkeypatch)
    measured = _capability(value, precision_required=False)
    assert measured["max_actual_frame_gap_ms"] == 250
    assert measured["precision_supported"] is False
    assert measured["audio_continuous"] is True
    with pytest.raises(TalkCutError, match="too sparse"):
        _capability(value, precision_required=True)


def test_sparse_semantic_input_must_disclose_limits(tmp_path, monkeypatch):
    with pytest.raises(TalkCutError, match="disclose sampling limits"):
        _capability(
            capability(tmp_path, monkeypatch, limitations=False),
            precision_required=False,
        )


@pytest.mark.parametrize("scope", ["source_sync", "seam", "lip_sync"])
def test_timing_and_seam_roles_retain_precision_requirement(scope):
    assert precision_review_required({"scope": scope})


@pytest.mark.parametrize("scope", ["analysis", "output", "deletion", "layout"])
def test_semantic_scope_and_explicit_fast_state_rereview_are_separate(scope):
    assert not precision_review_required({"scope": scope})
    assert precision_review_required(
        {"scope": scope, "details": {"requires_dense_video": True}}
    )
