"""Actual FFmpeg interruption/retry and additional measured timing fixtures.

Faults are isolated to test processes or the promotion syscall. They do not
replace the media encoder, decoder, or timing validation with successful mocks.
"""

import errno
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from fractions import Fraction
from pathlib import Path

import pytest

import talkcut.render as renderer
from talkcut.project import sha256
from talkcut.timeline import compile_timeline


def command(args):
    return subprocess.run(args, capture_output=True, check=True)


def measured_timeline(video, audio, *, origin="0", cuts=()):
    probe = json.loads(command(["ffprobe", "-v", "error", "-show_frames", "-show_streams", "-of", "json", str(video)]).stdout)
    stream = probe["streams"][0]
    frames = [{"pts": frame["best_effort_timestamp"],
               "duration": frame.get("duration", frame.get("pkt_duration"))} for frame in probe["frames"]]
    tb = Fraction(stream["time_base"])
    start = frames[0]["pts"] * tb
    end = (frames[-1]["pts"] + frames[-1]["duration"]) * tb
    timeline = compile_timeline(
        frames, stream["time_base"], origin, cuts,
        audio={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": 6},
        speaker={"origin": origin, "offset": 0, "rate": 1, "start": start, "end": end},
    )
    visual = {"path": str(video), "stream_index": 0, "width": stream["width"],
              "height": stream["height"], "sar": stream["sample_aspect_ratio"]}
    sources = {"screen": visual, "speaker": dict(visual),
               "audio": {"path": str(audio), "stream_index": 0, "sample_rate": 44100}}
    return timeline, sources


@pytest.fixture(scope="module")
def recovery_media(tmp_path_factory):
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        pytest.skip("Actual fault-injection integration requires FFmpeg and ffprobe")
    directory = tmp_path_factory.mktemp("render-recovery")
    video, audio = directory / "source.mp4", directory / "audio.wav"
    command(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=s=640x360:r=24000/1001",
             "-frames:v", "96", "-c:v", "libx264", "-preset", "ultrafast", "-video_track_timescale", "24000", str(video)])
    command(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=700:sample_rate=44100:duration=6",
             "-c:a", "pcm_s16le", str(audio)])
    timeline, sources = measured_timeline(video, audio)
    success = renderer.render(timeline, sources, directory / "previous-success.mp4", preset="ultrafast")
    hashes = {str(path): sha256(path) for path in (video, audio, Path(success["output"]["path"]))}
    return timeline, sources, hashes


def assert_preserved(hashes):
    assert {path: sha256(path) for path in hashes} == hashes


def test_actual_sigint_preserves_partial_and_success_then_retry(recovery_media, tmp_path):
    timeline, sources, hashes = recovery_media
    output = tmp_path / "interrupted.mp4"
    config = tmp_path / "job.json"
    config.write_text(json.dumps({"timeline": timeline, "sources": sources, "output": str(output)}))
    # Readrate changes wall time only, making cancellation deterministic even
    # on a fast CI runner. The child still invokes the real FFmpeg executable.
    script = """
import json, sys
import talkcut.render as module
job = json.load(open(sys.argv[1]))
original = module.build_render_command
def paced(*args, **kwargs):
    spec = original(*args, **kwargs)
    index = spec['command'].index('-i')
    spec['command'][index:index] = ['-readrate', '0.1']
    return spec
module.build_render_command = paced
try:
    module.render(job['timeline'], job['sources'], job['output'], preset='ultrafast')
except KeyboardInterrupt:
    sys.exit(130)
"""
    log = tmp_path / "child.log"
    with log.open("wb") as handle:
        process = subprocess.Popen([sys.executable, "-c", script, str(config)], stdout=handle, stderr=handle)
        try:
            deadline = time.monotonic() + 15
            partials = []
            while time.monotonic() < deadline and process.poll() is None:
                partials = list(tmp_path.glob("interrupted.mp4.*.partial"))
                if partials:
                    break
                time.sleep(0.01)
            assert partials and process.poll() is None, log.read_text()
            os.kill(process.pid, signal.SIGINT)
            assert process.wait(timeout=15) == 130
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    receipt = json.loads(next(tmp_path.glob("interrupted.mp4.*.render.json")).read_text())
    assert receipt["status"] == "interrupted"
    assert receipt["complete"] is False
    assert not output.exists()
    assert Path(receipt["partial_path"]).exists()
    partial_hash = sha256(receipt["partial_path"])
    assert_preserved(hashes)
    resumed = renderer.render(timeline, sources, output, preset="ultrafast")
    assert resumed["complete"] is True
    assert sha256(receipt["partial_path"]) == partial_hash
    assert_preserved(hashes)


@pytest.mark.parametrize("fault", ["timeout", "subprocess_failure", "disk_full_promotion"])
def test_actual_failed_runs_preserve_success_and_retry(recovery_media, tmp_path, monkeypatch, fault):
    timeline, sources, hashes = recovery_media
    output = tmp_path / "candidate.mp4"
    build = renderer.build_render_command

    def injected(*args, **kwargs):
        spec = build(*args, **kwargs)
        if fault == "timeout":
            index = spec["command"].index("-i")
            spec["command"][index:index] = ["-readrate", "0.1"]
        elif fault == "subprocess_failure":
            spec["command"].insert(1, "-talkcut-injected-invalid-ffmpeg-option")
        return spec

    def full_disk(*args, **kwargs):
        raise OSError(errno.ENOSPC, "Injected no space left during atomic promotion")

    with monkeypatch.context() as patch:
        patch.setattr(renderer, "build_render_command", injected)
        if fault == "disk_full_promotion":
            patch.setattr(renderer.os, "link", full_disk)
        with pytest.raises(renderer.RenderError) as caught:
            renderer.render(timeline, sources, output, preset="ultrafast", timeout=0.5 if fault == "timeout" else 30)
    receipt = json.loads(caught.value.manifest_path.read_text())
    assert receipt["status"] == "failed" and receipt["complete"] is False
    assert not output.exists()
    if fault == "timeout":
        assert receipt["error"]["type"] == "TimeoutExpired"
    elif fault == "subprocess_failure":
        assert receipt["exit_code"] != 0
        assert "Unrecognized option" in Path(receipt["log_path"]).read_text()
    else:
        assert receipt["validation"]["status"] == "PASS"
        assert Path(receipt["partial_path"]).is_file()
    assert_preserved(hashes)
    resumed = renderer.render(timeline, sources, output, preset="ultrafast")
    assert resumed["complete"] is True
    assert resumed["validation"]["frame_count"] == timeline["frame_count"]
    assert_preserved(hashes)


@pytest.mark.parametrize("fps,origin,vfr", [("30000/1001", "2", False), ("24000/1001", "0", True)])
def test_actual_fractional_rate_nonzero_origin_and_vfr(recovery_media, tmp_path, fps, origin, vfr):
    _, original_sources, _ = recovery_media
    video = tmp_path / "measured-vfr.mp4"
    args = ["ffmpeg", "-v", "error", "-f", "lavfi", "-i", f"testsrc2=s=160x90:r={fps}", "-frames:v", "36"]
    if vfr:
        args += ["-vf", "setpts='if(lt(N,12),PTS,PTS+0.2/TB)'"]
    args += ["-fps_mode", "passthrough", "-c:v", "libx264", "-preset", "ultrafast",
             "-output_ts_offset", origin, str(video)]
    command(args)
    timeline, sources = measured_timeline(video, Path(original_sources["audio"]["path"]), origin=origin,
                                           cuts=[{"id": "fixture-cut", "start": "1/10", "end": "1/5"}])
    result = renderer.render(timeline, sources, tmp_path / "timed.mp4", preset="ultrafast")
    assert result["complete"] is True
    assert result["validation"]["max_frame_pts_error"] == {"num": 0, "den": 1}
    if vfr:
        assert len({(frame["duration"]["num"], frame["duration"]["den"]) for frame in timeline["frames"]}) > 1
