import json
import shutil
import subprocess
from fractions import Fraction as F
from hashlib import sha256

import pytest

from talkcut.render import RenderError, build_render_command, render, resolve_layout
from talkcut.timeline import as_fraction, compile_timeline


def run(command):
    return subprocess.run(command, check=True, capture_output=True, text=True)


@pytest.fixture(scope="module")
def media(tmp_path_factory):
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        pytest.skip("FFmpeg and ffprobe are required for actual media integration")
    directory = tmp_path_factory.mktemp("actual-media")
    screen, speaker, audio = [directory / name for name in ("screen.mp4", "speaker.mp4", "audio.wav")]
    raw_screen = directory / "screen-before-terminal-duration.mp4"
    for path, color, count in ((raw_screen, "testsrc2", 400), (speaker, "testsrc", 350)):
        run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", f"{color}=size=320x180:rate=1000/33",
             "-frames:v", str(count), "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p",
             "-video_track_timescale", "45000", str(path)])
    # The actual DGIST recording's terminal frame lasts 34,922 ticks, not
    # one nominal 1,485-tick frame. Exercise this real failure mode publicly.
    run(["ffmpeg", "-v", "error", "-i", str(raw_screen), "-c", "copy",
         "-bsf:v", "setts=duration='if(eq(N,399),34922,DURATION)'",
         "-video_track_timescale", "45000", str(screen)])
    run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "sine=frequency=880:sample_rate=44100:duration=14",
         "-c:a", "pcm_s16le", str(audio)])
    sources = {
        "screen": {"path": str(screen), "stream_index": 0, "width": 320, "height": 180, "sar": "1:1"},
        "speaker": {"path": str(speaker), "stream_index": 0, "width": 320, "height": 180, "sar": "1:1"},
        "audio": {"path": str(audio), "stream_index": 0, "sample_rate": 44100},
    }
    probe = json.loads(run(["ffprobe", "-v", "error", "-show_frames", "-show_streams", "-of", "json", str(screen)]).stdout)
    frames = [{"pts": f["best_effort_timestamp"], "duration": f.get("duration", f.get("pkt_duration"))} for f in probe["frames"]]
    def compile(cuts=()):
        return compile_timeline(frames, probe["streams"][0]["time_base"], 0, cuts,
            audio={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": 14},
            speaker={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": "231/20"})
    return directory, sources, compile


def test_geometry_full_frames_and_non_square_sar():
    screen = {"width": 1920, "height": 1080, "sar": "4:3"}
    speaker = {"width": 1920, "height": 1080, "sar": "1:1"}
    layout = resolve_layout(screen, speaker)
    assert layout["canvas_width"] == 1920
    assert as_fraction(layout["screen_sar"]) == F(4, 3)
    assert F(layout["width"], layout["height"]) * F(4, 3) == F(16, 9)
    assert layout["x"] > 960 and layout["y"] < 108
    with pytest.raises(RenderError):
        resolve_layout({**screen, "rotation": 90}, speaker)
    with pytest.raises(RenderError, match="UNVERIFIED_GEOMETRY"):
        resolve_layout({"width": 1920, "height": 1080}, speaker)


def test_real_baseline_and_hundred_cut_render_schedule(media, tmp_path):
    _, sources, compile = media
    cuts = [{"id": f"cut-{i}", "start": F(3 * i + 1) * F(33, 1000),
             "end": F(3 * i + 2) * F(33, 1000)} for i in range(100)]
    baseline = render(compile(), sources, tmp_path / "baseline.mp4", preset="ultrafast")
    edited = render(compile(cuts), sources, tmp_path / "edited.mp4", preset="ultrafast")
    assert baseline["complete"] and edited["complete"]
    assert baseline["validation"]["frame_count"] == 400
    assert edited["validation"]["frame_count"] == 300
    assert as_fraction(edited["validation"]["sample_count"]) == 469358
    assert as_fraction(edited["validation"]["max_frame_pts_error"]) == 0
    assert edited["ai_review"] == "UNVERIFIED"
    assert edited["owner_acceptance"] == "pending"
    assert len(compile(cuts)["speaker_omissions"]) == 1


def test_command_uses_one_audio_and_rejects_stale_timeline(media, tmp_path):
    _, sources, compile = media
    timeline = compile()
    command = build_render_command(timeline, sources, tmp_path / "a.mp4")
    assert command["command"].count("-map") == 2
    assert "amix" not in command["filtergraph"]
    assert "repeatlast=1:shortest=0" in command["filtergraph"]
    assert "lt(t,11.55)" in command["filtergraph"]
    timeline["sample_count"] += 1
    with pytest.raises(RenderError, match="hash mismatch"):
        build_render_command(timeline, sources, tmp_path / "a.mp4")


def test_failure_timeout_disk_and_previous_output_preserved(media, tmp_path):
    _, sources, compile = media
    previous = tmp_path / "previous.mp4"
    previous.write_bytes(b"successful artifact must remain")
    digest = sha256(previous.read_bytes()).hexdigest()
    with pytest.raises(RenderError, match="OUTPUT_EXISTS"):
        render(compile(), sources, previous)
    assert sha256(previous.read_bytes()).hexdigest() == digest
    with pytest.raises(RenderError, match="DISK_SPACE"):
        render(compile(), sources, tmp_path / "disk.mp4", min_free_bytes=2**100)
    for executable, timeout, name in (("/usr/bin/false", None, "failed"), ("ffmpeg", 0.001, "timeout")):
        with pytest.raises(RenderError) as error:
            render(compile(), sources, tmp_path / f"{name}.mp4", ffmpeg=executable, timeout=timeout)
        assert error.value.manifest_path is not None
        manifest = json.loads(error.value.manifest_path.read_text())
        assert manifest["complete"] is False
        assert manifest["status"] == "failed"
        assert not (tmp_path / f"{name}.mp4").exists()
    assert sha256(previous.read_bytes()).hexdigest() == digest


def test_source_hash_change_rejected(media, tmp_path):
    _, sources, compile = media
    changed = {**sources, "audio": {**sources["audio"], "sha256": "0" * 64}}
    with pytest.raises(RenderError, match="SOURCE_CHANGED"):
        render(compile(), changed, tmp_path / "changed.mp4")


def test_actual_speaker_terminal_duration_and_exact_omission_boundary(media, tmp_path):
    # Pixel evidence, not merely graph string assertions: the source's valid
    # extended final frame must be present until 3.5s and absent from 3.5s.
    for name, count, color in (("screen", 5, "black"), ("speaker-raw", 2, "white")):
        run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", f"color={color}:s=160x90:r=1",
             "-frames:v", str(count), "-c:v", "libx264", "-preset", "ultrafast",
             "-video_track_timescale", "1000", str(tmp_path / f"{name}.mp4")])
    run(["ffmpeg", "-v", "error", "-i", str(tmp_path / "speaker-raw.mp4"), "-c", "copy",
         "-bsf:v", "setts=duration='if(eq(N,1),2500,DURATION)'", "-video_track_timescale", "1000",
         str(tmp_path / "speaker.mp4")])
    _, original_sources, _ = media
    sources = {role: {"path": str(tmp_path / f"{role}.mp4"), "stream_index": 0,
                      "width": 160, "height": 90, "sar": "1:1"} for role in ("screen", "speaker")}
    sources["audio"] = original_sources["audio"]
    timeline = compile_timeline(
        [{"pts": i * 1000, "duration": 1000} for i in range(5)], "1/1000", 0,
        audio={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": 14},
        speaker={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": "7/2"},
    )
    assert timeline["retained_source_frame_count"] == 5
    assert timeline["frame_count"] == 6
    assert as_fraction(timeline["inserted_frames"][0]["source_time"]) == F(7, 2)
    manifest = render(timeline, sources, tmp_path / "exact-end.mp4", preset="ultrafast")
    raw = subprocess.check_output(["ffmpeg", "-v", "error", "-i", manifest["output"]["path"],
                                   "-map", "0:v", "-fps_mode", "passthrough", "-pix_fmt", "rgb24", "-f", "rawvideo", "-"])
    layout = manifest["layout"]
    x, y = layout["x"] + layout["width"] // 2, layout["y"] + layout["height"] // 2
    samples = [raw[i * 160 * 90 * 3 + (y * 160 + x) * 3] for i in range(6)]
    assert samples == [255, 255, 255, 255, 0, 0]
