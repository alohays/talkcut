"""Real ffprobe frame inventories and complete FFmpeg decode receipts."""

from __future__ import annotations

import json
import platform
import resource
import shutil
import subprocess
import time
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any

from .project import TalkCutError, artifact_ref, atomic_json, content_hash, now, sha256


def inspector_hash() -> str:
    return content_hash(
        {
            name: sha256(Path(__file__).with_name(name))
            for name in ("media.py", "project.py", "geometry.py")
        }
    )


def inspection_is_current(
    report: dict[str, Any], source_hash: str, decode: bool
) -> bool:
    if not (
        report.get("sha256") == source_hash
        and report.get("full_decode") == decode
        and report.get("status") == "PASS"
        and report.get("inspector_hash") == inspector_hash()
        and report.get("toolchain") == doctor()
    ):
        return False
    refs = [report["probe"]]
    for kind in ("video", "audio"):
        refs.extend([report[kind]["raw_frames"], report[kind]["stderr"]])
    if decode:
        refs.extend([report["decode"]["stderr"], report["decode"]["progress"]])
    return all(
        Path(ref["path"]).is_file() and sha256(ref["path"]) == ref["sha256"]
        for ref in refs
    )


def doctor() -> dict[str, Any]:
    tools = {}
    for name in ("ffmpeg", "ffprobe"):
        path = shutil.which(name)
        if path is None:
            raise TalkCutError("DEPENDENCY_MISSING", f"Install {name} separately")
        result = subprocess.run(
            [path, "-version"], capture_output=True, text=True, check=True, timeout=30
        )
        tools[name] = {"path": path, "build": result.stdout, "sha256": sha256(path)}
    return {
        "schema_version": "talkcut-doctor/v1",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "tools": tools,
        "status": "PASS",
        "ai_media_capability": "UNVERIFIED",
    }


def probe(path: str | Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_streams",
            "-show_format",
            "-of",
            "json",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise TalkCutError("PROBE_FAILED", result.stderr)
    return json.loads(result.stdout)


def support_findings(metadata: dict[str, Any]) -> list[str]:
    streams = metadata["streams"]
    videos = [s for s in streams if s["codec_type"] == "video"]
    audios = [s for s in streams if s["codec_type"] == "audio"]
    if len(videos) != 1 or len(audios) != 1:
        return ["Exactly one video and one audio stream per source required"]
    v, a = videos[0], audios[0]
    errors = []
    if v["codec_name"] != "h264" or v.get("pix_fmt") != "yuv420p":
        errors.append("Only H.264 8-bit yuv420p is supported")
    if v.get("sample_aspect_ratio") != "1:1":
        errors.append("Non-square pixels are not supported")
    if v.get("color_transfer") in ("smpte2084", "arib-std-b67"):
        errors.append("HDR is not supported")
    if (
        any(s.get("rotation", 0) != 0 for s in v.get("side_data_list", []))
        or v.get("tags", {}).get("rotate", "0") != "0"
    ):
        errors.append("Rotated video is not supported")
    if v.get("field_order", "progressive") not in ("progressive", "unknown"):
        errors.append("Interlaced video is not supported")
    if a["codec_name"] != "aac" or a.get("channels") not in (1, 2):
        errors.append("Only mono/stereo AAC input is supported")
    return errors


def frame_inventory(
    path: Path, stream: dict[str, Any], directory: Path
) -> dict[str, Any]:
    kind = stream["codec_type"]
    output = directory / f"{kind}-frames.compact"
    errors = directory / f"{kind}-frames.stderr"
    command = [
        "ffprobe",
        "-v",
        "error",
        "-select_streams",
        str(stream["index"]),
        "-show_frames",
        "-show_entries",
        "frame=pts,best_effort_timestamp,duration,pkt_duration,nb_samples",
        "-of",
        "compact=p=0:nk=0",
        str(path),
    ]
    start = time.monotonic()
    with output.open("w") as out, errors.open("w") as err:
        result = subprocess.run(
            command, stdout=out, stderr=err, timeout=7200, check=False
        )
    frames: list[dict[str, int]] = []
    missing = 0
    with output.open() as handle:
        for line in handle:
            values = dict(
                pair.split("=", 1) for pair in line.strip().split("|") if "=" in pair
            )
            if not values:
                continue
            if values.get("pts", "N/A") == "N/A":
                missing += 1
                continue
            frame = {"pts": int(values["pts"])}
            duration = values.get("duration", values.get("pkt_duration", "0"))
            frame["duration"] = int(duration) if duration != "N/A" else 0
            if "nb_samples" in values:
                frame["nb_samples"] = int(values["nb_samples"])
            frames.append(frame)
    tb = Fraction(stream["time_base"])
    anomalies = []
    durations: Counter[int] = Counter()
    for index, frame in enumerate(frames):
        durations[frame["duration"]] += 1
        if frame["duration"] <= 0:
            anomalies.append(
                {"frame": index, "kind": "unknown_duration", "pts": frame["pts"]}
            )
        if index:
            prev = frames[index - 1]
            delta = frame["pts"] - prev["pts"]
            if delta <= 0:
                anomalies.append(
                    {"frame": index, "kind": "nonmonotonic_pts", "delta": delta}
                )
            if delta != prev["duration"]:
                anomalies.append(
                    {
                        "frame": index,
                        "kind": "gap_or_overlap",
                        "ticks": delta - prev["duration"],
                    }
                )
    valid = (
        result.returncode == 0
        and not errors.read_text().strip()
        and frames
        and missing == 0
    )
    coverage = (
        [
            str(frames[0]["pts"] * tb),
            str((frames[-1]["pts"] + frames[-1]["duration"]) * tb),
        ]
        if frames
        else None
    )
    inventory = {
        "index": stream["index"],
        "time_base": str(tb),
        "frames": frames,
        "frame_count": len(frames),
        "coverage": coverage,
        "duration_counts": dict(durations),
        "anomalies": anomalies,
        "missing_pts_count": missing,
        "exit_code": result.returncode,
        "command": command,
        "wall_seconds": time.monotonic() - start,
        "raw_frames": artifact_ref(output),
        "stderr": artifact_ref(errors),
        "status": "PASS" if valid and not anomalies else "UNVERIFIED",
    }
    if kind == "video":
        inventory.update(
            {
                k: stream.get(k)
                for k in (
                    "width",
                    "height",
                    "sample_aspect_ratio",
                    "display_aspect_ratio",
                )
            }
        )
    else:
        inventory["sample_rate"] = int(stream["sample_rate"])
        inventory["decoded_samples"] = sum(f.get("nb_samples", 0) for f in frames)
        inventory["sample_coverage_end"] = (
            str(
                frames[-1]["pts"] * tb
                + Fraction(frames[-1].get("nb_samples", 0), int(stream["sample_rate"]))
            )
            if frames
            else None
        )
        inventory["padding_note"] = (
            "Frame nb_samples may include codec end padding; presentation duration and samples reported separately"
        )
    return inventory


def full_decode(
    path: Path, directory: Path, video_index: int, audio_index: int
) -> dict[str, Any]:
    command = [
        "ffmpeg",
        "-hide_banner",
        "-nostdin",
        "-v",
        "error",
        "-xerror",
        "-err_detect",
        "explode",
        "-i",
        str(path),
        "-map",
        f"0:{video_index}",
        "-map",
        f"0:{audio_index}",
        "-progress",
        "pipe:1",
        "-fps_mode",
        "passthrough",
        "-f",
        "null",
        "-",
    ]
    log, progress = directory / "decode.stderr", directory / "decode.progress"
    start = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with log.open("w") as err, progress.open("w") as out:
        try:
            result = subprocess.run(
                command, stderr=err, stdout=out, timeout=14400, check=False
            )
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    values = dict(
        line.split("=", 1) for line in progress.read_text().splitlines() if "=" in line
    )
    return {
        "schema_version": "full-decode/v1",
        "command": command,
        "exit_code": code,
        "status": "PASS"
        if code == 0 and not log.read_text().strip() and values.get("progress") == "end"
        else "FAIL",
        "wall_seconds": time.monotonic() - start,
        "cpu_user_seconds": after.ru_utime - before.ru_utime,
        "cpu_system_seconds": after.ru_stime - before.ru_stime,
        "peak_rss_process_children": after.ru_maxrss,
        "peak_rss_note": "RUSAGE_CHILDREN high water, platform units; not isolated command peak",
        "frame_count": int(values.get("frame", "0")),
        "last_progress": values,
        "stderr": artifact_ref(log),
        "progress": artifact_ref(progress),
    }


def inspect_source(
    path: str | Path, artifact_dir: str | Path, decode: bool = True
) -> dict[str, Any]:
    path, directory = Path(path).resolve(), Path(artifact_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    digest = sha256(path)
    metadata = probe(path)
    atomic_json(directory / "probe.json", metadata)
    from .geometry import measure_geometry

    effective_streams = [dict(stream) for stream in metadata["streams"]]
    geometry = None
    geometry_error = None
    for stream in effective_streams:
        if stream["codec_type"] == "video":
            try:
                geometry = measure_geometry(path, stream)
                stream["sample_aspect_ratio"] = geometry["sample_aspect_ratio"]
                stream["display_aspect_ratio"] = geometry["display_aspect_ratio"]
            except ValueError as exc:
                geometry_error = str(exc)
    findings = support_findings({**metadata, "streams": effective_streams})
    if geometry_error:
        findings.append(geometry_error)
    report: dict[str, Any] = {
        "schema_version": "source-inspection/v1",
        "path": str(path),
        "sha256": digest,
        "bytes": path.stat().st_size,
        "inspected_at": now(),
        "streams": metadata["streams"],
        "geometry_evidence": geometry,
        "probe": artifact_ref(directory / "probe.json"),
        "support_findings": findings,
        "toolchain": doctor(),
        "status": "UNVERIFIED",
        "full_decode": decode,
        "inspector_hash": inspector_hash(),
    }
    if findings:
        report["status"] = "FAIL"
    else:
        for kind in ("video", "audio"):
            stream = next(s for s in effective_streams if s["codec_type"] == kind)
            report[kind] = frame_inventory(path, stream, directory)
        if decode:
            report["decode"] = full_decode(
                path, directory, report["video"]["index"], report["audio"]["index"]
            )
            if report["decode"]["status"] == "PASS" and all(
                report[k]["status"] == "PASS" for k in ("video", "audio")
            ):
                report["status"] = "PASS"
    if sha256(path) != digest:
        raise TalkCutError(
            "SOURCE_CHANGED", "Source identity changed during inspection"
        )
    atomic_json(directory / "inspection.json", report)
    return report
