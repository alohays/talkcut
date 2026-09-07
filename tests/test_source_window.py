"""Actual generated media/physical controls; no provider or semantic approval."""
import copy
import json
import subprocess
from fractions import Fraction
from pathlib import Path

import pytest

from talkcut.project import TalkCutError, artifact_ref, atomic_json
from talkcut.review import _clip, validate_review_request
from talkcut.source_window import prepare_source_window, verify_source_window


@pytest.fixture(scope="module")
def native_source(tmp_path_factory):
    path = tmp_path_factory.mktemp("window-source") / "generated.mp4"
    subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
        "testsrc2=size=64x48:rate=59/2:duration=4", "-f", "lavfi", "-i",
        "sine=frequency=600:sample_rate=44100:duration=4", "-c:v", "libx264",
        "-c:a", "aac", "-pix_fmt", "yuv420p", str(path)], capture_output=True, check=True, timeout=30)
    return artifact_ref(path)


def test_actual_native_expansion_exact_pcm_and_reconstruction(native_source, tmp_path):
    proof = prepare_source_window(native_source, ["1", "3"], ["0", "4"], tmp_path / "proof")
    value = verify_source_window(proof, source=native_source, domain=["0", "4"])
    assert value["observed_interval"] == ["58/59", "3"]
    assert 0 <= Fraction(value["audio"]["start_quantization_offset"]) < Fraction(1, 44100)
    interval = tuple(map(Fraction, value["observed_interval"]))
    deps = {"source_hashes": {"screen": native_source["sha256"]}}
    clip = _clip(native_source, interval, tmp_path / "clip", deps, source_window=proof)
    assert clip["clip"]["path"].endswith(".mov")
    streams = clip["streams"]
    assert all(Fraction(row["start_time"]) == 0 for row in streams)
    assert next(row for row in streams if row["codec_type"] == "audio")["codec_name"] == "pcm_s16le"
    request = {"schema_version": "review-request/v1", "scope": "analysis", "source_window": proof,
               "dependencies": deps, "inputs": [clip], "input_clip_hashes": [clip["clip"]["sha256"]],
               "intervals": [value["observed_interval"]]}
    path = tmp_path / "request.json"
    atomic_json(path, request)
    assert validate_review_request({"scope": "analysis", "dependencies": deps, "inputs": [clip]},
            {"request": artifact_ref(path), "dependencies": deps}) == request


@pytest.mark.parametrize("mutation", ["requested", "observed", "source_domain", "video_pts", "video_duration", "video_end",
    "audio_start", "audio_end", "audio_time", "audio_offset", "audio_rate", "normalization", "precision", "bool_pts", "float_pts", "extra"])
def test_native_clock_and_request_aliases_rejected(native_source, tmp_path, mutation):
    proof = prepare_source_window(native_source, ["1", "3"], ["0", "4"], tmp_path / "proof")
    value = copy.deepcopy(json.loads(Path(proof["path"]).read_text()))
    if mutation == "requested":
        value["requested_interval"] = ["0", "3"]
    elif mutation == "observed":
        value["observed_interval"] = ["1", "3"]
    elif mutation == "source_domain":
        value["source_domain"] = ["0", "5"]
    elif mutation in {"video_pts", "video_duration", "video_end"}:
        key = {"video_pts": "first_pts", "video_duration": "first_end_pts", "video_end": "trim_end_pts"}[mutation]
        value["video"][key] += 1
    elif mutation in {"audio_start", "audio_end", "audio_rate"}:
        key = {"audio_start": "start_sample", "audio_end": "end_sample", "audio_rate": "sample_rate"}[mutation]
        value["audio"][key] += 1
    elif mutation == "audio_time":
        value["audio"]["first_sample_parent_time"] = value["observed_interval"][0]
    elif mutation == "audio_offset":
        value["audio"]["start_quantization_offset"] = "0"
    elif mutation == "normalization":
        value["normalization"] = "pretend"
    elif mutation == "precision":
        value["precision_supported"] = 0
    elif mutation == "bool_pts":
        value["video"]["first_pts"] = True
    elif mutation == "float_pts":
        value["video"]["first_pts"] = float(value["video"]["first_pts"])
    else:
        value["approved"] = True
    path = tmp_path / "mutated.json"
    atomic_json(path, value)
    with pytest.raises((TalkCutError, ValueError)):
        verify_source_window(artifact_ref(path), source=native_source, domain=["0", "4"])


@pytest.mark.parametrize("interval", [[0, 3], ["3", "1"], ["-1", "3"], ["0", "5"]])
def test_requested_clock_is_typed_and_within_actual_domain(native_source, tmp_path, interval):
    with pytest.raises((TalkCutError, ValueError)):
        prepare_source_window(native_source, interval, ["0", "4"], tmp_path / "proof")


def test_legacy_extraction_still_reconstructs_exactly(native_source, tmp_path):
    left = _clip(native_source, (Fraction(0), Fraction(2)), tmp_path / "old-a", {})
    right = _clip(native_source, (Fraction(0), Fraction(2)), tmp_path / "old-b", {})
    assert left["clip"]["sha256"] == right["clip"]["sha256"]
    assert left["clip"]["path"].endswith(".mp4")
    assert "source_window" not in left
    assert next(row for row in left["streams"] if row["codec_type"] == "audio")["codec_name"] == "aac"
