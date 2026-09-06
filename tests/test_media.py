import shutil
import subprocess

import pytest

from talkcut.media import inspect_source, support_findings


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="FFmpeg not installed")
def test_real_33ms_audio_stream_zero_full_decode(tmp_path):
    source = tmp_path / "fixture.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=900:sample_rate=44100:duration=2",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=320x180:rate=1000/33:duration=2",
            "-map",
            "0:a",
            "-map",
            "1:v",
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            "-video_track_timescale",
            "45000",
            str(source),
        ],
        check=True,
        timeout=60,
    )
    report = inspect_source(source, tmp_path / "evidence")
    assert report["status"] == "PASS"
    assert report["audio"]["index"] == 0
    assert report["video"]["index"] == 1
    assert report["video"]["frame_count"] == 61
    assert report["decode"]["frame_count"] == 61
    assert report["video"]["frames"][1]["pts"] == 1485


def test_unsupported_geometry_is_explicit():
    v = {
        "codec_type": "video",
        "codec_name": "h264",
        "pix_fmt": "yuv420p",
        "sample_aspect_ratio": "4:3",
    }
    a = {"codec_type": "audio", "codec_name": "aac", "channels": 2}
    assert "Non-square pixels are not supported" in support_findings(
        {"streams": [v, a]}
    )
