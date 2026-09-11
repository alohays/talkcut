"""Actual sparse AV encoding regression; generated media is not review approval."""

import json
import subprocess
from fractions import Fraction
from pathlib import Path

from talkcut.project import artifact_ref
from talkcut.review import _clip


def run(command):
    return subprocess.run(command, capture_output=True, check=True, timeout=60).stdout


def test_sparse_clip_reconstructs_exact_bytes_and_preserves_all_packets(tmp_path):
    source = tmp_path / "generated.mp4"
    run([
        "ffmpeg", "-nostdin", "-v", "error", "-f", "lavfi", "-i",
        "testsrc2=size=64x48:rate=2:duration=60", "-f", "lavfi", "-i",
        "sine=frequency=600:sample_rate=8000:duration=60", "-c:v", "libx264",
        "-c:a", "aac", "-pix_fmt", "yuv420p", str(source),
    ])
    source_ref = artifact_ref(source)
    clips = [
        _clip(source_ref, (Fraction(0), Fraction(30)), tmp_path / str(i), {})
        for i in range(4)
    ]
    assert len({row["clip"]["sha256"] for row in clips}) == 1
    assert artifact_ref(source) == source_ref
    receipt = json.loads(Path(clips[0]["extraction_receipt"]["path"]).read_text())
    original_command = receipt["command"][:]
    index = original_command.index("-max_interleave_delta")
    del original_command[index:index + 2]
    original = tmp_path / "original-interleave.mp4"
    original_command[-1] = str(original)
    run(original_command)

    def packet_streams(path):
        packets = json.loads(run([
            "ffprobe", "-v", "error", "-show_packets", "-show_data_hash",
            "sha256", "-of", "json", str(path),
        ]))["packets"]
        return {
            i: [{k: v for k, v in row.items() if k != "pos"}
                for row in packets if row["stream_index"] == i]
            for i in (0, 1)
        }

    current = clips[0]["clip"]["path"]
    packets = packet_streams(current)
    assert packets == packet_streams(original)
    assert len(packets[0]) == 60
    for options in (
        ["-map", "0:v", "-pix_fmt", "yuv420p", "-f", "rawvideo"],
        ["-map", "0:a", "-c:a", "pcm_f32le", "-f", "f32le"],
    ):
        def decoded(path, options=options):
            return run(["ffmpeg", "-nostdin", "-v", "error", "-xerror", "-i",
                        str(path), *options, "-"])
        assert decoded(current) == decoded(original)
