import json
import shutil
import struct
import subprocess

import pytest

from talkcut.geometry import IDENTITY_MATRIX, GeometryError, measure_geometry


def box(kind, payload):
    return struct.pack(">I4s", len(payload) + 8, kind) + payload


def container(*, version=0, movie_matrix=IDENTITY_MATRIX, track_matrix=IDENTITY_MATRIX,
              display_width=1920, display_height=1080, extensions=b"", tracks=1):
    mvhd = bytearray(112 if version else 100)
    mvhd[0] = version
    struct.pack_into(">9i", mvhd, 48 if version else 36, *movie_matrix)
    tkhd = bytearray(96 if version else 84)
    tkhd[0] = version
    struct.pack_into(">I", tkhd, 20 if version else 12, 2)
    offset = 52 if version else 40
    struct.pack_into(">9iII", tkhd, offset, *track_matrix, display_width << 16, display_height << 16)
    visual = bytearray(78)
    struct.pack_into(">HH", visual, 24, 1920, 1080)
    stsd = box(b"stsd", bytes(4) + struct.pack(">I", 1) + box(b"avc1", visual + extensions))
    mdia = box(b"mdia", box(b"hdlr", bytes(8) + b"vide")
               + box(b"minf", box(b"stbl", stsd)))
    trak = box(b"trak", box(b"tkhd", tkhd) + mdia)
    return box(b"moov", box(b"mvhd", mvhd) + trak * tracks)


STREAM = {"codec_name": "h264", "codec_type": "video", "id": "0x2", "width": 1920, "height": 1080}


@pytest.mark.parametrize("version", [0, 1])
def test_track_geometry_proves_sar_without_an_implicit_default(tmp_path, version):
    path = tmp_path / "container-geometry.mp4"
    path.write_bytes(container(version=version))
    result = measure_geometry(path, STREAM)
    assert result["sample_aspect_ratio"] == "1:1"
    assert result["display_aspect_ratio"] == "16:9"
    assert result["container_evidence"]["track_width_16_16"] == 1920 << 16
    assert result["container_evidence"]["track_matrix"] == list(IDENTITY_MATRIX)
    assert len(result["container_evidence"]["tkhd_payload_sha256"]) == 64


def test_measure_non_square_without_claiming_renderer_support(tmp_path):
    path = tmp_path / "anamorphic.mp4"
    path.write_bytes(container(display_width=2560, extensions=box(b"pasp", struct.pack(">II", 4, 3))))
    result = measure_geometry(path, STREAM)
    assert result["sample_aspect_ratio"] == "4:3"
    assert result["display_aspect_ratio"] == "64:27"


@pytest.mark.parametrize("options", [
    {"display_width": 0},
    {"movie_matrix": (0, 65536, 0, -65536, 0, 0, 0, 0, 1073741824)},
    {"track_matrix": (0, 65536, 0, -65536, 0, 0, 0, 0, 1073741824)},
    {"extensions": box(b"pasp", struct.pack(">II", 4, 3))},
    {"extensions": box(b"pasp", struct.pack(">II", 0, 1))},
    {"extensions": box(b"clap", bytes(32))},
    {"tracks": 2},
])
def test_transforms_missing_dimensions_and_conflicts_fail_closed(tmp_path, options):
    path = tmp_path / "unsupported.mp4"
    path.write_bytes(container(**options))
    with pytest.raises(GeometryError):
        measure_geometry(path, STREAM)


@pytest.mark.parametrize("change", [{"id": "0x3"}, {"width": 1280},
                                    {"sample_aspect_ratio": "4:3"}, {"display_aspect_ratio": "4:3"}])
def test_ffprobe_mismatch_is_rejected(tmp_path, change):
    path = tmp_path / "conflict.mp4"
    path.write_bytes(container())
    with pytest.raises(GeometryError):
        measure_geometry(path, {**STREAM, **change})


@pytest.mark.parametrize("data", [b"", b"bad", struct.pack(">I4s", 4, b"moov"),
                                  struct.pack(">I4s", 100000, b"moov"), struct.pack(">I4s", 1, b"moov")])
def test_malformed_box_bounds_are_rejected(tmp_path, data):
    path = tmp_path / "truncated.mp4"
    path.write_bytes(data)
    with pytest.raises(GeometryError):
        measure_geometry(path, STREAM)


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="Actual FFmpeg fixture requires FFmpeg")
def test_real_encoded_container_matches_decoder_dimensions(tmp_path):
    path = tmp_path / "real.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc2=s=320x180:r=25",
                    "-frames:v", "2", "-c:v", "libx264", str(path)], check=True)
    probe = json.loads(subprocess.check_output(["ffprobe", "-v", "error", "-show_streams", "-of", "json", str(path)]))
    stream = probe["streams"][0]
    result = measure_geometry(path, stream)
    assert result["sample_aspect_ratio"] == "1:1"
    assert result["display_aspect_ratio"] == "16:9"
    assert result["container_evidence"]["sample_entry_width"] == 320
