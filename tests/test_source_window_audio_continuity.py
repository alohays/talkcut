"""Whole native sample clocks are required even beyond the selected window."""

import copy
import json
import subprocess
from pathlib import Path

import pytest
from test_source_window import native_source as native_source_fixture

from talkcut import source_window as window
from talkcut.project import TalkCutError, artifact_ref, atomic_json

native_source = native_source_fixture


@pytest.fixture(scope="module")
def complete(native_source):
    return window.probe(native_source, ["1", "3"], ["0", "4"])[0]


@pytest.mark.parametrize("damage", [
    "missing_timeline", "missing_frames", "empty_frames", "missing_prefix", "missing_interior",
    "gap_after_window", "overlap", "reorder", "bool_pts", "float_samples", "zero_samples",
    "missing_pts", "wrong_stream", "wrong_media", "wrong_rate", "wrong_time_base",
    "wrong_origin", "short_denominator",
])
def test_derive_requires_every_native_audio_frame(complete, native_source, damage):
    value = copy.deepcopy(complete)
    timeline = value["audio_timeline"]
    frames = timeline["frames"]
    if damage == "missing_timeline":
        value.pop("audio_timeline")
    elif damage == "missing_frames":
        timeline.pop("frames")
    elif damage == "empty_frames":
        timeline["frames"] = []
    elif damage == "missing_prefix":
        frames.pop(0)
    elif damage == "missing_interior":
        frames.pop(len(frames) // 2)
    elif damage == "gap_after_window":
        assert frames[-1]["pts"] > 3 * 44100
        frames[-1]["pts"] += 1
    elif damage == "overlap":
        frames[1]["pts"] -= 1
    elif damage == "reorder":
        frames[1], frames[2] = frames[2], frames[1]
    elif damage == "bool_pts":
        frames[0]["pts"] = False
    elif damage == "float_samples":
        frames[0]["nb_samples"] = float(frames[0]["nb_samples"])
    elif damage == "zero_samples":
        frames[0]["nb_samples"] = 0
    elif damage == "missing_pts":
        frames[-1].pop("pts")
    elif damage == "wrong_stream":
        frames[-1]["stream_index"] += 1
    elif damage == "wrong_media":
        frames[-1]["media_type"] = "video"
    elif damage == "wrong_rate":
        timeline["streams"][0]["sample_rate"] = "48000"
    elif damage == "wrong_time_base":
        timeline["streams"][0]["time_base"] = "1/1000"
    elif damage == "wrong_origin":
        timeline["streams"][0]["start_pts"] = 1
    else:
        timeline["frames"] = frames[:10]
    with pytest.raises(TalkCutError):
        window.derive(value, native_source, ["1", "3"], ["0", "4"])


@pytest.mark.parametrize("damage", [
    "truncated_after_window", "gap_after_window", "read_interval", "wrong_selector",
    "failure_exit", "stderr", "missing_record", "summary_count", "summary_digest", "summary_bool",
])
def test_verifier_replays_full_recorded_audio_denominator(native_source, tmp_path, damage):
    proof = window.prepare_source_window(native_source, ["1", "3"], ["0", "4"], tmp_path / "proof")
    body = json.loads(Path(proof["path"]).read_bytes())
    record_path = Path(body["probe"]["path"])
    record = json.loads(record_path.read_bytes())
    audio = record["audio_timeline"]
    if damage in {"truncated_after_window", "gap_after_window"}:
        path = Path(audio["stdout"]["path"])
        value = json.loads(path.read_bytes())
        assert value["frames"][-1]["pts"] > 3 * 44100
        if damage == "truncated_after_window":
            value["frames"].pop()
        else:
            value["frames"][-1]["pts"] += 1
        atomic_json(path, value)
        audio["stdout"] = artifact_ref(path)
    elif damage == "read_interval":
        audio["argv"][1:1] = ["-read_intervals", "0%3"]
    elif damage == "wrong_selector":
        audio["argv"][audio["argv"].index("a:0")] = "v:0"
    elif damage == "failure_exit":
        audio["exit_code"] = False
    elif damage == "stderr":
        path = Path(audio["stderr"]["path"])
        path.write_text("Unresolved native audio decoding warning\n")
        audio["stderr"] = artifact_ref(path)
    elif damage == "missing_record":
        record.pop("audio_timeline")
    elif damage == "summary_count":
        body["audio"]["native_clock"]["sample_count"] += 1
    elif damage == "summary_digest":
        body["audio"]["native_clock"]["frame_table_sha256"] = "f" * 64
    else:
        body["audio"]["native_clock"]["first_pts"] = False
    atomic_json(record_path, record)
    body["probe"] = artifact_ref(record_path)
    atomic_json(Path(proof["path"]), body)
    with pytest.raises(TalkCutError):
        window.verify_source_window(artifact_ref(proof["path"]), source=native_source, domain=["0", "4"])


def test_actual_late_gap_is_refused_and_complete_probe_is_preserved(tmp_path):
    path = tmp_path / "late-gap.mp4"
    cmd = ["ffmpeg", "-nostdin", "-v", "error", "-n", "-f", "lavfi", "-i",
           "testsrc2=size=64x48:rate=25:duration=4", "-f", "lavfi", "-i",
           "sine=frequency=440:sample_rate=48000:duration=4", "-filter_complex",
           "[1:a]asetpts=PTS+gte(T\\,3.5)*0.5/TB[a]", "-map", "0:v:0", "-map", "[a]",
           "-c:v", "libx264", "-preset", "ultrafast", "-c:a", "aac", str(path)]
    subprocess.run(cmd, check=True, capture_output=True, timeout=30)
    directory = tmp_path / "proof"
    with pytest.raises(TalkCutError, match="discontinuous"):
        window.prepare_source_window(artifact_ref(path), ["1", "3"], ["0", "4"], directory)
    assert not (directory / "source-window.local.json").exists()
    record = json.loads((directory / "probe.local.json").read_bytes())
    assert "-read_intervals" not in record["audio_timeline"]["argv"]
    frames = json.loads(Path(record["audio_timeline"]["stdout"]["path"]).read_bytes())["frames"]
    cumulative = 0
    gaps = []
    for frame in frames:
        if frame["pts"] != cumulative:
            gaps.append(frame["pts"] - cumulative)
        cumulative += frame["nb_samples"]
    assert gaps and set(gaps) == {24000}
