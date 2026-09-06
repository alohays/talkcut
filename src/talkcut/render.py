"""One PTS-preserving compositor, with atomic promotion after technical checks.

Successful rendering is a technical result, never an AI or owner sign-off.
Failed/interrupted runs retain their log, manifest and partial file. No source or
previously successful output is overwritten.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Mapping
from fractions import Fraction
from hashlib import sha256
from math import lcm
from pathlib import Path
from typing import Any
from uuid import uuid4

from .timeline import as_fraction, fraction_json, round_fraction


class RenderError(RuntimeError):
    def __init__(self, message: str, manifest_path: Path | None = None):
        super().__init__(message)
        self.manifest_path = manifest_path


def _hash(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decimal(value: Any) -> str:
    q = as_fraction(value)
    # Decimal expansion is only for FFmpeg options; canonical evidence is rational.
    from decimal import Decimal, localcontext
    with localcontext() as context:
        context.prec = 30
        return format(Decimal(q.numerator) / Decimal(q.denominator), "f")


def _ticks(value: Any, time_base: Fraction) -> int:
    q = as_fraction(value) / time_base
    if q.denominator != 1:
        raise RenderError("Exact timestamp cannot be represented by render time base")
    return q.numerator


def _balanced_sum(expressions: list[str]) -> str:
    """FFmpeg's expression parser has a depth limit; avoid a linear 100-cut sum."""
    if len(expressions) == 1:
        return expressions[0]
    midpoint = len(expressions) // 2
    return f"({_balanced_sum(expressions[:midpoint])}+{_balanced_sum(expressions[midpoint:])})"


def _balanced_mapping(spans: list[tuple[int, int, int]]) -> str:
    if len(spans) == 1:
        start, _, target = spans[0]
        return f"PTS-({start})+({target})"
    midpoint = len(spans) // 2
    return (f"if(gte(PTS,{spans[midpoint][0]}),"
            f"{_balanced_mapping(spans[midpoint:])},{_balanced_mapping(spans[:midpoint])})")


def _sar(source: Mapping[str, Any]) -> Fraction:
    value = source.get("sar", source.get("sample_aspect_ratio"))
    if value is None or value in ("N/A", "0:1", "0/1"):
        raise RenderError("UNVERIFIED_GEOMETRY: measured sample aspect ratio is required")
    if isinstance(value, str):
        value = value.replace(":", "/")
    result = as_fraction(value)
    if result <= 0:
        raise RenderError("Measured sample aspect ratio must be positive")
    return result


def resolve_layout(
    screen: Mapping[str, Any], speaker: Mapping[str, Any],
    layout: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    settings = dict(layout or {})
    if settings.get("position", "top-right") != "top-right":
        raise RenderError("Only a full-frame top-right speaker overlay is supported")
    for source in (screen, speaker):
        if source.get("rotation", 0) not in (0, "0", None):
            raise RenderError("UNSUPPORTED_FORMAT: rotated video requires explicit support")
        if any(type(source.get(key)) is not int or source[key] <= 0 for key in ("width", "height")):
            raise RenderError("Measured source dimensions are required")
    width_fraction = as_fraction(settings.get("width_fraction", "1/8"))
    margin_fraction = as_fraction(settings.get("margin_fraction", "1/100"))
    if not 0 < width_fraction <= Fraction(1, 4) or not 0 <= margin_fraction <= Fraction(1, 10):
        raise RenderError("Overlay width must be in (0, 1/4], margin in [0, 1/10]")
    screen_sar, speaker_sar = _sar(screen), _sar(speaker)
    # Exact integer dimensions preserve the speaker display ratio within the
    # screen pixel grid; no face crop, screen shrink, or aspect approximation.
    pixel_ratio = Fraction(speaker["width"], speaker["height"]) * speaker_sar / screen_sar
    unit_w, unit_h = pixel_ratio.numerator, pixel_ratio.denominator
    desired_width = screen["width"] * width_fraction
    scale_units = max(1, round_fraction(desired_width / unit_w))
    overlay_w, overlay_h = unit_w * scale_units, unit_h * scale_units
    margin_x = 2 * round_fraction(screen["width"] * margin_fraction / 2)
    margin_y = 2 * round_fraction(screen["height"] * margin_fraction / 2)
    x = 2 * ((screen["width"] - overlay_w - margin_x) // 2)
    y = margin_y
    if overlay_w > screen["width"] / 4 or x < 0 or y + overlay_h > screen["height"]:
        raise RenderError("Exact full-frame speaker ratio cannot fit the configured small overlay")
    if screen["width"] % 2 or screen["height"] % 2:
        raise RenderError("UNSUPPORTED_FORMAT: H.264 yuv420p canvas requires even dimensions")
    return {
        "canvas_width": screen["width"], "canvas_height": screen["height"],
        "screen_sar": fraction_json(screen_sar),
        "screen_dar": fraction_json(Fraction(screen["width"], screen["height"]) * screen_sar),
        "speaker_sar": fraction_json(speaker_sar),
        "requested_width_fraction": fraction_json(width_fraction),
        "actual_width_fraction": fraction_json(Fraction(overlay_w, screen["width"])),
        "x": x, "y": y, "width": overlay_w, "height": overlay_h,
        "preserve_screen_frame": True, "preserve_speaker_frame": True,
        "position": "top-right", "occlusion_review": "UNVERIFIED",
    }


def build_render_command(
    timeline: Mapping[str, Any], sources: Mapping[str, Mapping[str, Any]],
    output: str | Path, layout: Mapping[str, Any] | None = None, *,
    ffmpeg: str = "ffmpeg", crf: int = 18, preset: str = "medium",
) -> dict[str, Any]:
    if timeline.get("schema_version") != "timeline/v1":
        raise RenderError("Unsupported timeline schema")
    canonical = dict(timeline)
    declared_hash = canonical.pop("timeline_hash", None)
    actual_hash = sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if declared_hash != actual_hash:
        raise RenderError("SOURCE_CHANGED: resolved timeline hash mismatch")
    if set(sources) != {"screen", "speaker", "audio"}:
        raise RenderError("Exactly screen, speaker and one selected audio source are required")
    if type(crf) is not int or not 0 <= crf <= 51:
        raise RenderError("CRF must be an integer between 0 and 51")
    if preset not in {"ultrafast", "superfast", "veryfast", "faster", "fast", "medium", "slow", "slower", "veryslow"}:
        raise RenderError("Unknown libx264 preset")
    geometry = resolve_layout(sources["screen"], sources["speaker"], layout)
    inputs: list[str] = []
    labels = {}
    output_path = Path(output).resolve()
    for role in ("screen", "speaker", "audio"):
        source = sources[role]
        path = str(Path(source["path"]).resolve())
        if Path(path) == output_path:
            raise RenderError("Output cannot replace any source")
        if type(source.get("stream_index")) is not int or source["stream_index"] < 0:
            raise RenderError("Every selected stream requires its measured absolute index")
        if path not in inputs:
            inputs.append(path)
        labels[role] = f"{inputs.index(path)}:{source['stream_index']}"
    rate = timeline["sample_rate"]
    if sources["audio"].get("sample_rate") != rate:
        raise RenderError("Selected decoded PCM sample rate must match the schedule")
    tb = as_fraction(timeline["render_time_base"])
    movie_timescale = lcm(tb.denominator, rate)
    if movie_timescale > 2**31 - 1:
        raise RenderError("UNSUPPORTED_TIMING: exact MP4 movie timescale exceeds integer limits")
    origin_ticks = _ticks(timeline["screen_origin"], tb)
    speaker_shift = as_fraction(timeline["speaker"]["offset"]) - as_fraction(timeline["speaker"]["origin"])
    speaker_shift_ticks = _ticks(speaker_shift, tb)
    sar = as_fraction(geometry["screen_sar"])
    graph = [
        f"[{labels['screen']}]settb=expr={tb},setpts=PTS-({origin_ticks})[source-screen]",
        (f"[{labels['speaker']}]settb=expr={tb},setpts=PTS+({speaker_shift_ticks}),"
         f"scale={geometry['width']}:{geometry['height']}:flags=lanczos,setsar={sar}[speaker]"),
    ]
    inserted = timeline.get("inserted_frames", [])
    if inserted:
        graph.append(f"[source-screen]split={len(inserted) + 1}[ordinary-screen]" + "".join(f"[copy{i}]" for i in range(len(inserted))))
        for i, frame in enumerate(inserted):
            graph.append(f"[copy{i}]trim=start_frame={frame['source_index']}:end_frame={frame['source_index'] + 1},"
                         f"setpts={_ticks(frame['source_time'], tb)}[extra{i}]")
        graph.append("[ordinary-screen]" + "".join(f"[extra{i}]" for i in range(len(inserted)))
                     + f"interleave=nb_inputs={len(inserted) + 1}:duration=longest,settb=expr={tb}[screen]")
    else:
        graph.append("[source-screen]null[screen]")
    start = as_fraction(timeline["speaker"]["start"]) + speaker_shift
    end = as_fraction(timeline["speaker"]["end"]) + speaker_shift
    enabled = f"gte(t,{_decimal(start)})*lt(t,{_decimal(end)})"
    for gap in timeline.get("speaker_gaps", ()):
        enabled += f"*not(gte(t,{_decimal(gap['start'])})*lt(t,{_decimal(gap['end'])}))"
    graph.append(
        f"[screen][speaker]overlay=x={geometry['x']}:y={geometry['y']}:"
        f"eof_action=repeat:repeatlast=1:shortest=0:enable='{enabled}',settb=expr={tb}[composite]"
    )
    # Select source PTS after compositing: both visual tracks therefore receive
    # the exact same deletion. PTS arithmetic is integer at a common exact base.
    selectors = []
    mapping_spans = []
    for span in timeline["retained"]:
        a, b = _ticks(span["source_start"], tb), _ticks(span["source_end"], tb)
        target = _ticks(span["output_start"], tb)
        selectors.append(f"gte(pts,{a})*lt(pts,{b})")
        mapping_spans.append((a, b, target))
    graph.append(
        f"[composite]select='{_balanced_sum(selectors)}',setpts='{_balanced_mapping(mapping_spans)}',"
        f"setsar={sar},format=yuv420p[vout]"
    )
    spans = timeline["retained"]
    if len(spans) > 1:
        graph.append(f"[{labels['audio']}]asplit={len(spans)}" + "".join(f"[as{i}]" for i in range(len(spans))))
    for i, span in enumerate(spans):
        audio_label = f"as{i}" if len(spans) > 1 else labels["audio"]
        graph.append(
            f"[{audio_label}]atrim=start_sample={span['audio_source_sample_start']}:"
            f"end_sample={span['audio_source_sample_end']},asetpts=N/SR/TB[a{i}]"
        )
    if len(spans) > 1:
        graph.append("".join(f"[a{i}]" for i in range(len(spans))) + f"concat=n={len(spans)}:v=0:a=1,asetpts=N/SR/TB[aout]")
    else:
        graph.append("[a0]anull[aout]")
    filtergraph = ";\n".join(graph)
    command = [ffmpeg, "-nostdin", "-hide_banner", "-v", "warning", "-n", "-copyts"]
    for path in inputs:
        command.extend(["-noautorotate", "-i", path])
    command.extend([
        "-filter_complex", filtergraph, "-map", "[vout]", "-map", "[aout]",
        "-map_metadata", "-1", "-c:v", "libx264", "-preset", preset, "-crf", str(crf),
        "-bf", "0", "-fps_mode:v", "passthrough", "-enc_time_base:v", str(tb),
        "-bsf:v", f"setts=duration='if(eq(N,{timeline['frame_count'] - 1}),{_ticks(timeline['frames'][-1]['duration'], tb)},DURATION)'",
        "-video_track_timescale", str(tb.denominator), "-movie_timescale", str(movie_timescale),
        "-c:a", "aac", "-b:a", "192k",
        "-ar", str(rate), "-movflags", "+faststart", "-f", "mp4", str(output_path),
    ])
    return {"command": command, "filtergraph": filtergraph, "layout": geometry,
            "timeline_hash": declared_hash, "output": str(output_path)}


def _run_json(command: list[str], timeout: float | None) -> dict[str, Any]:
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)
    return json.loads(result.stdout)


def validate_render(
    path: str | Path, timeline: Mapping[str, Any], geometry: Mapping[str, Any], *,
    ffmpeg: str = "ffmpeg", ffprobe: str = "ffprobe", timeout: float | None = None,
) -> dict[str, Any]:
    """Decode the entire artifact and compare measured PTS/valid PCM to schedule.

    AAC padding is recorded separately from the valid MP4 audio duration. This
    check does not certify semantic edits, occlusion, listening quality or sync.
    """
    path = Path(path)
    decode = subprocess.run(
        [ffmpeg, "-nostdin", "-v", "error", "-xerror", "-i", str(path),
         "-map", "0:v", "-map", "0:a", "-f", "null", "-"],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if decode.returncode:
        raise RenderError(f"Output full decode failed: {decode.stderr[-2000:]}")
    probe = _run_json([ffprobe, "-v", "error", "-show_streams", "-show_frames",
                       "-show_entries", "stream=index,codec_type,width,height,sample_aspect_ratio,time_base,sample_rate,duration_ts,start_pts:frame=media_type,best_effort_timestamp,duration,pkt_duration,nb_samples",
                       "-of", "json", str(path)], timeout)
    videos = [stream for stream in probe["streams"] if stream["codec_type"] == "video"]
    audios = [stream for stream in probe["streams"] if stream["codec_type"] == "audio"]
    if len(videos) != 1 or len(audios) != 1 or len(probe["streams"]) != 2:
        raise RenderError("Output must contain exactly one video and one audio stream")
    video, audio = videos[0], audios[0]
    if (video["width"], video["height"]) != (geometry["canvas_width"], geometry["canvas_height"]):
        raise RenderError("Output changed the screen canvas")
    if _sar(video) != as_fraction(geometry["screen_sar"]):
        raise RenderError("Output changed the screen sample/display aspect ratio")
    video_frames = [frame for frame in probe["frames"] if frame["media_type"] == "video"]
    audio_frames = [frame for frame in probe["frames"] if frame["media_type"] == "audio"]
    if len(video_frames) != timeline["frame_count"]:
        raise RenderError(f"Output frame count {len(video_frames)} differs from expected {timeline['frame_count']}")
    video_tb = as_fraction(video["time_base"])
    errors = []
    for measured, expected in zip(video_frames, timeline["frames"], strict=True):
        errors.append(abs(int(measured["best_effort_timestamp"]) * video_tb - as_fraction(expected["output_pts"])))
    if max(errors, default=Fraction(0)) > video_tb:
        raise RenderError("Output video presentation timestamps differ from resolved schedule")
    last = video_frames[-1]
    last_duration = last.get("duration", last.get("pkt_duration"))
    if last_duration is None:
        raise RenderError("UNVERIFIED: output final frame duration was not measured")
    actual_video_end = (int(last["best_effort_timestamp"]) + int(last_duration)) * video_tb
    if abs(actual_video_end - as_fraction(timeline["duration"])) > video_tb:
        raise RenderError("Output final video edge differs from retained source duration")
    sample_rate = int(audio["sample_rate"])
    if sample_rate != timeline["sample_rate"] or int(audio.get("start_pts", -1)) != 0:
        raise RenderError("Output PCM rate or initial presentation time changed")
    effective_samples = as_fraction(audio["time_base"]) * int(audio["duration_ts"]) * sample_rate
    if abs(effective_samples - timeline["sample_count"]) > 1:
        raise RenderError(f"Output valid audio samples {effective_samples} differ from cumulative schedule {timeline['sample_count']}")
    decoded_samples = sum(int(frame["nb_samples"]) for frame in audio_frames)
    padding = decoded_samples - effective_samples
    if padding < 0 or padding >= 1024:
        raise RenderError("Unexplained audio coverage or AAC padding")
    return {
        "status": "PASS", "scope": "full_decode_and_technical_timing_only",
        "decode": {"exit_code": decode.returncode, "stderr": decode.stderr,
                   "video_frame_count": len(video_frames), "decoded_audio_samples": decoded_samples},
        "frame_count": len(video_frames), "sample_count": fraction_json(effective_samples),
        "video_end": fraction_json(actual_video_end), "audio_padding_samples": fraction_json(padding),
        "max_frame_pts_error": fraction_json(max(errors, default=Fraction(0))),
        "video_time_base": fraction_json(video_tb), "streams": probe["streams"],
        "ai_review": "UNVERIFIED", "owner_acceptance": "pending",
    }


def _write_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    partial = path.with_name(path.name + ".writing")
    with partial.open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(partial, path)


def render(
    timeline: Mapping[str, Any], sources: Mapping[str, Mapping[str, Any]],
    output: str | Path, layout: Mapping[str, Any] | None = None, *,
    ffmpeg: str = "ffmpeg", ffprobe: str = "ffprobe", crf: int = 18,
    preset: str = "medium", timeout: float | None = None,
    min_free_bytes: int = 256 * 1024 * 1024,
) -> dict[str, Any]:
    output = Path(output).resolve()
    if output.exists():
        raise RenderError("OUTPUT_EXISTS: successful artifacts are immutable; choose a new revision")
    output.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(output.parent).free < min_free_bytes:
        raise RenderError("DISK_SPACE: insufficient free space before rendering")
    run_id = uuid4().hex
    partial = output.with_name(f"{output.name}.{run_id}.partial")
    manifest_path = output.with_name(f"{output.name}.{run_id}.render.json")
    log_path = output.with_name(f"{output.name}.{run_id}.log")
    spec = build_render_command(timeline, sources, partial, layout, ffmpeg=ffmpeg, crf=crf, preset=preset)
    fingerprints: dict[str, dict[str, Any]] = {}
    for role, source in sources.items():
        path = Path(source["path"]).resolve()
        if not path.is_file():
            raise RenderError(f"SOURCE_MISSING: {role}")
        actual = _hash(path)
        if source.get("sha256") and source["sha256"] != actual:
            raise RenderError(f"SOURCE_CHANGED: {role}")
        fingerprints[role] = {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}
    start = time.monotonic()
    manifest: dict[str, Any] = {
        "schema_version": "render/v1", "run_id": run_id, "status": "running", "complete": False,
        "timeline_hash": timeline["timeline_hash"], "sources": fingerprints,
        "command": spec["command"], "filtergraph": spec["filtergraph"], "layout": spec["layout"],
        "partial_path": str(partial), "log_path": str(log_path), "manifest_path": str(manifest_path),
        "requested_output": str(output), "owner_acceptance": "pending", "ai_review": "UNVERIFIED",
    }
    _write_manifest(manifest_path, manifest)
    try:
        version = subprocess.run([ffmpeg, "-version"], capture_output=True, text=True, check=True, timeout=30)
        manifest["toolchain"] = {"ffmpeg_version": version.stdout}
        with log_path.open("x", encoding="utf-8") as log:
            process = subprocess.run(spec["command"], stdout=log, stderr=log, timeout=timeout, check=False)
        manifest["exit_code"] = process.returncode
        if process.returncode:
            raise RenderError(f"RENDER_FAILED: FFmpeg exited {process.returncode}")
        if not partial.is_file() or partial.stat().st_size == 0:
            raise RenderError("RENDER_FAILED: encoder did not create an output")
        manifest["validation"] = validate_render(partial, timeline, spec["layout"], ffmpeg=ffmpeg, ffprobe=ffprobe, timeout=timeout)
        # Check source identity again before promoting a long-running render.
        for role, fingerprint in fingerprints.items():
            if _hash(Path(fingerprint["path"])) != fingerprint["sha256"]:
                raise RenderError(f"SOURCE_CHANGED during render: {role}")
        digest, size = _hash(partial), partial.stat().st_size
        # link() is an atomic, no-replace promotion on the same filesystem. A
        # concurrent writer cannot be clobbered between exists() and rename().
        os.link(partial, output)
        partial.unlink()
        manifest.update({"status": "succeeded", "complete": True,
                         "output": {"path": str(output), "sha256": digest, "bytes": size}})
    except BaseException as exc:
        manifest.update({"status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                         "complete": False, "error": {"type": type(exc).__name__, "message": str(exc)}})
        manifest["wall_seconds"] = time.monotonic() - start
        _write_manifest(manifest_path, manifest)
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise RenderError(str(exc), manifest_path) from exc
    manifest["wall_seconds"] = time.monotonic() - start
    _write_manifest(manifest_path, manifest)
    return manifest
