"""Independent native-clock controls using generated media and actual consumers."""

import json
import subprocess
from fractions import Fraction
from itertools import pairwise

import pytest

from talkcut.project import TalkCutError, artifact_ref, atomic_json
from talkcut.review import _clip, validate_review_request
from talkcut.source_window import prepare_source_window, verify_source_window


@pytest.mark.parametrize("gap", [False, True], ids=["contiguous", "half-second-gap"])
def test_source_window_must_preserve_actual_native_audio_parent_clock(tmp_path, gap):
    path = tmp_path / "source.mp4"
    command = [
        "ffmpeg", "-nostdin", "-v", "error", "-n", "-f", "lavfi", "-i",
        "testsrc2=size=64x48:rate=59/2:duration=4", "-f", "lavfi", "-i",
        "aevalsrc=0.2*sin(2*PI*(317*t+71*t*t)):s=48000:d=4",
    ]
    if gap:
        command += ["-filter_complex", "[1:a]asetpts=PTS+gte(T\\,0.5)*0.5/TB[a]",
                    "-map", "0:v:0", "-map", "[a]"]
    command += ["-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(path)]
    subprocess.run(command, check=True, capture_output=True, timeout=30)
    source = artifact_ref(path)
    raw = subprocess.check_output([
        "ffprobe", "-v", "error", "-show_streams", "-show_frames", "-of", "json", str(path)
    ])
    (tmp_path / "full-native.json").write_bytes(raw)
    native = json.loads(raw)
    audio = next(row for row in native["streams"] if row["codec_type"] == "audio")
    assert audio["start_pts"] == 0 and audio["time_base"] == "1/48000"
    frames = [row for row in native["frames"] if row["media_type"] == "audio"]
    discontinuities = [
        b["pts"] - a["pts"] - a["nb_samples"] for a, b in pairwise(frames)
        if b["pts"] != a["pts"] + a["nb_samples"]
    ]
    assert discontinuities == ([24000] if gap else [])
    try:
        proof = prepare_source_window(source, ["1", "3"], ["0", "4"], tmp_path / "proof")
        value = verify_source_window(proof, source=source, domain=["0", "4"])
    except TalkCutError:
        # Refusing the unsupported discontinuous clock is a valid safe result.
        assert gap
        return
    target, cumulative = value["audio"]["start_sample"], 0
    for frame in frames:
        if cumulative <= target < cumulative + frame["nb_samples"]:
            actual_parent_time = Fraction(frame["pts"] + target - cumulative, 48000)
            break
        cumulative += frame["nb_samples"]
    else:
        pytest.fail("Declared selected audio sample is absent from actual native source")
    left, right = map(Fraction, value["observed_interval"])
    deps = {"source_hashes": {"screen": source["sha256"]}}
    clip = _clip(source, (left, right), tmp_path / "clip", deps, source_window=proof)
    request = {
        "schema_version": "review-request/v1", "scope": "analysis", "source_window": proof,
        "dependencies": deps, "inputs": [clip], "input_clip_hashes": [clip["clip"]["sha256"]],
        "intervals": [value["observed_interval"]],
    }
    atomic_json(tmp_path / "request.json", request)
    assert validate_review_request(
        {"scope": "analysis", "dependencies": deps, "inputs": [clip]},
        {"request": artifact_ref(tmp_path / "request.json"), "dependencies": deps},
    ) == request
    atomic_json(tmp_path / "clock-observed.json", {
        "source": source, "proof": proof, "clip": clip["clip"], "gap": gap,
        "declared_parent_time": value["audio"]["first_sample_parent_time"],
        "actual_parent_time": str(actual_parent_time),
        "error": str(actual_parent_time - Fraction(value["audio"]["first_sample_parent_time"])),
        "review_request_accepted": True, "accepted_av_seconds": 0,
    })
    assert Fraction(value["audio"]["first_sample_parent_time"]) == actual_parent_time
