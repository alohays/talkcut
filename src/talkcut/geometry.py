"""Bounded MP4 track geometry inspection when ffprobe leaves SAR unspecified.

The evidence comes from the actual movie/track display matrices, fixed-point
track dimensions and visual sample entry. This is not a default to square pixels.
The field interpretation is independently implemented from ISO-BMFF layouts;
FFmpeg's mov_read_tkhd/mov_read_pasp and track finalization corroborate it:
https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/mov.c
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from fractions import Fraction
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO

IDENTITY_MATRIX = (65536, 0, 0, 0, 65536, 0, 0, 0, 1073741824)


class GeometryError(ValueError):
    """A container is malformed, ambiguous, transformed or unsupported."""


@dataclass(frozen=True)
class _Box:
    kind: bytes
    start: int
    payload: int
    end: int


def _boxes(handle: BinaryIO, start: int, end: int) -> list[_Box]:
    boxes: list[_Box] = []
    cursor = start
    while cursor < end:
        if end - cursor < 8 or len(boxes) >= 10000:
            raise GeometryError("Invalid or excessive MP4 box inventory")
        handle.seek(cursor)
        header = handle.read(8)
        if len(header) != 8:
            raise GeometryError("Truncated MP4 box header")
        size, kind = struct.unpack(">I4s", header)
        header_size = 8
        if size == 1:
            extended = handle.read(8)
            if len(extended) != 8:
                raise GeometryError("Truncated MP4 extended size")
            size = struct.unpack(">Q", extended)[0]
            header_size = 16
        elif size == 0:
            size = end - cursor
        if size < header_size or size > end - cursor:
            raise GeometryError("MP4 box size exceeds its containing box")
        boxes.append(_Box(kind, cursor, cursor + header_size, cursor + size))
        cursor += size
    return boxes


def _one(boxes: list[_Box], kind: bytes) -> _Box:
    matches = [box for box in boxes if box.kind == kind]
    if len(matches) != 1:
        raise GeometryError(f"Exactly one {kind.decode(errors='replace')} box is required")
    return matches[0]


def _read(handle: BinaryIO, box: _Box, limit: int = 65536) -> bytes:
    size = box.end - box.payload
    if size > limit:
        raise GeometryError("Geometry metadata exceeds bounded read limit")
    handle.seek(box.payload)
    data = handle.read(size)
    if len(data) != size:
        raise GeometryError("Truncated geometry metadata")
    return data


def _matrix(data: bytes, base: int) -> tuple[int, ...]:
    if len(data) < base + 36:
        raise GeometryError("Truncated display matrix")
    return struct.unpack_from(">9i", data, base)


def _version(data: bytes) -> int:
    if len(data) < 4 or data[0] not in (0, 1):
        raise GeometryError("Unknown or truncated MP4 full-box version")
    return data[0]


def _ratio(value: Any) -> Fraction | None:
    if value in (None, "N/A", "0:1", "0/1"):
        return None
    try:
        result = Fraction(str(value).replace(":", "/"))
    except (ValueError, ZeroDivisionError) as exc:
        raise GeometryError("Invalid ffprobe aspect ratio") from exc
    if result <= 0:
        raise GeometryError("Aspect ratio must be positive")
    return result


def _colon(value: Fraction) -> str:
    return f"{value.numerator}:{value.denominator}"


def measure_geometry(path: str | Path, video_stream: Mapping[str, Any]) -> dict[str, Any]:
    """Measure untransformed AVC MP4 geometry or fail closed.

    Only one visual sample description and one video track are accepted.
    Nonidentity movie/track matrices, clean-aperture crops, contradictory pasp
    or codec ratios, and dimensions disagreeing with the decoder are rejected.
    This function measures geometry; the caller still enforces format support.
    """
    path = Path(path)
    if video_stream.get("codec_name") != "h264" or video_stream.get("codec_type", "video") != "video":
        raise GeometryError("Only an inspected AVC video stream is supported")
    with path.open("rb") as handle:
        root = _boxes(handle, 0, path.stat().st_size)
        if any(box.kind == b"moof" for box in root):
            raise GeometryError("Fragmented MP4 geometry is outside this measurement profile")
        moov = _one(root, b"moov")
        movie_boxes = _boxes(handle, moov.payload, moov.end)
        mvhd = _one(movie_boxes, b"mvhd")
        movie_data = _read(handle, mvhd)
        movie_matrix = _matrix(movie_data, 48 if _version(movie_data) else 36)
        if movie_matrix != IDENTITY_MATRIX:
            raise GeometryError("Nonidentity movie display matrix is not supported")
        video_tracks = []
        for track in [box for box in movie_boxes if box.kind == b"trak"]:
            track_boxes = _boxes(handle, track.payload, track.end)
            mdia = _one(track_boxes, b"mdia")
            media_boxes = _boxes(handle, mdia.payload, mdia.end)
            handler_data = _read(handle, _one(media_boxes, b"hdlr"))
            if len(handler_data) < 12:
                raise GeometryError("Truncated MP4 media handler")
            if handler_data[8:12] == b"vide":
                video_tracks.append((track_boxes, media_boxes))
        if len(video_tracks) != 1:
            raise GeometryError("Exactly one video track is required for unambiguous geometry")
        track_boxes, media_boxes = video_tracks[0]
        if any(box.kind == b"tapt" for box in track_boxes):
            raise GeometryError("QuickTime aperture transformations are not supported")
        tkhd = _one(track_boxes, b"tkhd")
        track_data = _read(handle, tkhd)
        version = _version(track_data)
        matrix_offset = 52 if version else 40
        track_matrix = _matrix(track_data, matrix_offset)
        if track_matrix != IDENTITY_MATRIX:
            raise GeometryError("Nonidentity track display matrix is not supported")
        if len(track_data) < matrix_offset + 44:
            raise GeometryError("Truncated track dimensions")
        track_id = struct.unpack_from(">I", track_data, 20 if version else 12)[0]
        if not track_id:
            raise GeometryError("Video track id must be nonzero")
        stream_id = video_stream.get("id")
        if stream_id is not None and int(str(stream_id), 0) != track_id:
            raise GeometryError("ffprobe stream id does not match the measured video track")
        display_w, display_h = struct.unpack_from(">II", track_data, matrix_offset + 36)
        if not display_w or not display_h:
            raise GeometryError("Track display dimensions are unspecified")
        minf = _one(media_boxes, b"minf")
        stbl = _one(_boxes(handle, minf.payload, minf.end), b"stbl")
        stsd = _one(_boxes(handle, stbl.payload, stbl.end), b"stsd")
        handle.seek(stsd.payload)
        stsd_header = handle.read(8)
        if len(stsd_header) != 8 or stsd_header[:4] != bytes(4) or struct.unpack_from(">I", stsd_header, 4)[0] != 1:
            raise GeometryError("Exactly one version-zero visual sample description is required")
        entries = _boxes(handle, stsd.payload + 8, stsd.end)
        if len(entries) != 1 or entries[0].kind not in (b"avc1", b"avc3"):
            raise GeometryError("Only one AVC visual sample entry is supported")
        entry = entries[0]
        if entry.end - entry.payload < 78:
            raise GeometryError("Truncated AVC visual sample entry")
        handle.seek(entry.payload)
        visual_header = handle.read(78)
        coded_w, coded_h = struct.unpack_from(">HH", visual_header, 24)
        if not coded_w or not coded_h or (coded_w, coded_h) != (video_stream.get("width"), video_stream.get("height")):
            raise GeometryError("Sample-entry dimensions differ from the decoded full frame")
        extensions = _boxes(handle, entry.payload + 78, entry.end)
        if any(box.kind == b"clap" for box in extensions):
            raise GeometryError("Clean aperture cropping is not supported")
        pasp_boxes = [box for box in extensions if box.kind == b"pasp"]
        if len(pasp_boxes) > 1:
            raise GeometryError("Duplicate pixel aspect ratio boxes")
        pasp = None
        if pasp_boxes:
            pasp_data = _read(handle, pasp_boxes[0])
            if len(pasp_data) != 8:
                raise GeometryError("Malformed pixel aspect ratio box")
            numerator, denominator = struct.unpack(">II", pasp_data)
            if not numerator or not denominator:
                raise GeometryError("Pixel aspect ratio components must be positive")
            pasp = Fraction(numerator, denominator)
        dar = Fraction(display_w, display_h)
        sar = dar / Fraction(coded_w, coded_h)
        if pasp is not None and pasp != sar:
            raise GeometryError("Pixel aspect and track display dimensions disagree")
        reported_sar = _ratio(video_stream.get("sample_aspect_ratio"))
        reported_dar = _ratio(video_stream.get("display_aspect_ratio"))
        if (reported_sar is not None and reported_sar != sar) or (reported_dar is not None and reported_dar != dar):
            raise GeometryError("Codec/ffprobe aspect ratio contradicts MP4 track geometry")
        return {
            "schema_version": "mp4-geometry/v1", "status": "PASS",
            "sample_aspect_ratio": _colon(sar), "display_aspect_ratio": _colon(dar),
            "method": "identity_movie_and_track_matrices_plus_track_dimensions_and_visual_sample_entry",
            "container_evidence": {
                "track_id": track_id, "tkhd_offset": tkhd.start, "tkhd_payload_sha256": sha256(track_data).hexdigest(),
                "tkhd_payload_hex": track_data.hex(), "track_matrix": list(track_matrix),
                "movie_matrix": list(movie_matrix), "mvhd_offset": mvhd.start,
                "mvhd_payload_sha256": sha256(movie_data).hexdigest(),
                "track_width_16_16": display_w, "track_height_16_16": display_h,
                "sample_entry": entry.kind.decode(), "sample_entry_offset": entry.start,
                "sample_entry_width": coded_w, "sample_entry_height": coded_h,
                "pasp": _colon(pasp) if pasp is not None else None,
                "geometry_extensions": [box.kind.decode(errors="replace") for box in extensions],
            },
            "limitations": ["One untransformed AVC track only", "Geometry measurement does not certify visual occlusion"],
        }
