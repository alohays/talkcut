"""Actual native presentation expansion for a bounded source-analysis window.

The requested contract grid remains separate from the full observed extraction.
Audio sample quantization is explicit; it is not a precision or semantic claim.
Legacy review extraction and its validated bytes are unchanged.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import math
import subprocess
from fractions import Fraction
from pathlib import Path
from typing import Any

from .project import TalkCutError, artifact_ref, atomic_json, now


def require(value: Any, reason: str) -> None:
    if not value:
        raise TalkCutError("SOURCE_WINDOW_UNVERIFIED", reason)


def span(value: Any) -> tuple[Fraction, Fraction]:
    require(isinstance(value, list) and len(value) == 2
            and all(isinstance(item, str) for item in value), "Typed rational source-window interval required")
    left, right = map(Fraction, value)
    require(left < right, "Positive source-window interval required")
    return left, right


def checked(ref: Any) -> dict[str, Any]:
    require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}, "Exact source artifact reference required")
    actual = artifact_ref(Path(ref["path"]))
    require(actual == ref, "Source-window artifact changed")
    return actual


def probe(source: dict[str, Any], requested: list[str], domain: list[str]) -> tuple[dict[str, Any], dict[str, Any]]:
    source = checked(source)
    left, right = span(requested)
    domain_left, domain_right = span(domain)
    require(domain_left <= left < right <= domain_right, "Requested source window is outside the measured domain")
    begin, end = max(domain_left, left - 1), min(domain_right, left + 1)
    argv = ["ffprobe", "-v", "error", "-read_intervals", f"{float(begin):.12f}%{float(end):.12f}",
            "-show_streams", "-show_frames", "-of", "json", source["path"]]
    started = now()
    process = subprocess.run(argv, capture_output=True, timeout=120, check=False)
    require(process.returncode == 0 and not process.stderr.strip(), "Actual source native PTS probe failed")
    value = json.loads(process.stdout)
    audio_argv = ["ffprobe", "-v", "error", "-select_streams", "a:0", "-show_streams", "-show_frames",
                  "-show_entries", "frame=media_type,stream_index,pts,nb_samples:stream=index,codec_type,time_base,start_pts,sample_rate",
                  "-of", "json", source["path"]]
    audio_started = now()
    audio_process = subprocess.run(audio_argv, capture_output=True, timeout=120, check=False)
    require(audio_process.returncode == 0 and not audio_process.stderr.strip(),
            "Complete native source audio PTS probe failed")
    value["audio_timeline"] = json.loads(audio_process.stdout)
    require(checked(source) == source, "Source changed during native PTS probe")
    return value, {"argv": argv, "started_at": started, "finished_at": now(), "exit_code": process.returncode,
                   "stdout": process.stdout, "stderr": process.stderr,
                   "audio_timeline": {"argv": audio_argv, "started_at": audio_started, "finished_at": now(),
                                      "exit_code": audio_process.returncode,
                                      "stdout": audio_process.stdout, "stderr": audio_process.stderr}}


def audio_clock(value: Any, stream: dict[str, Any], rate: int) -> dict[str, Any]:
    """Require every decoded native audio frame to follow the cumulative clock.

    The caller obtains this complete table without a read interval. A window
    probe or zero-origin stream header cannot authorize sample-index trimming.
    """
    require(isinstance(value, dict) and isinstance(value.get("streams"), list)
            and len(value["streams"]) == 1, "Complete native audio stream timeline required")
    actual = value["streams"][0]
    require(isinstance(actual, dict) and actual.get("codec_type") == "audio"
            and type(actual.get("index")) is int and actual["index"] == stream.get("index")
            and type(actual.get("start_pts")) is int and actual["start_pts"] == 0
            and actual.get("sample_rate") == stream.get("sample_rate")
            and rate > 0 and Fraction(actual["time_base"]) == Fraction(1, rate),
            "Complete native audio timeline differs from the selected source stream")
    frames = value.get("frames")
    require(isinstance(frames, list) and frames, "Complete native audio frame table is absent")
    cumulative = 0
    table = []
    for frame in frames:
        require(isinstance(frame, dict) and frame.get("media_type") == "audio"
                and type(frame.get("stream_index")) is int and frame["stream_index"] == actual["index"]
                and type(frame.get("pts")) is int and type(frame.get("nb_samples")) is int
                and frame["nb_samples"] > 0,
                "Native audio frame PTS/sample count is missing, untyped or belongs to another stream")
        require(frame["pts"] == cumulative,
                "Native source audio PTS are discontinuous or differ from cumulative sample counts")
        table.append([frame["pts"], frame["nb_samples"]])
        cumulative += frame["nb_samples"]
    return {"time_base": str(Fraction(1, rate)), "frame_count": len(table), "sample_count": cumulative,
            "first_pts": 0, "end_pts": cumulative,
            "frame_table_sha256": hashlib.sha256(json.dumps(table, separators=(",", ":")).encode()).hexdigest(),
            "mapping": "native_pts_equal_cumulative_samples"}


def derive(value: dict[str, Any], source: dict[str, Any], requested: list[str], domain: list[str]) -> dict[str, Any]:
    left, right = span(requested)
    domain_left, domain_right = span(domain)
    require(domain_left <= left < right <= domain_right, "Requested source window is outside measured source")
    streams = value.get("streams", [])
    video = [row for row in streams if row.get("codec_type") == "video"]
    audio = [row for row in streams if row.get("codec_type") == "audio"]
    require(len(video) == len(audio) == 1, "Source-window extraction needs one native video and audio stream")
    require(video[0].get("start_pts") == audio[0].get("start_pts") == 0,
            "Nonzero native source origins need a separate explicit clock adapter")
    tb = Fraction(video[0]["time_base"])
    rate = int(audio[0]["sample_rate"])
    require(Fraction(audio[0]["time_base"]) == Fraction(1, rate), "Native source audio clock is not a sample clock")
    clock = audio_clock(value.get("audio_timeline"), audio[0], rate)
    require(domain_left == 0 and Fraction(video[0]["duration_ts"]) * tb == domain_right,
            "Measured source domain differs from actual native stream denominator")
    frames = sorted((row for row in value.get("frames", []) if row.get("media_type") == "video"), key=lambda row: row["pts"])
    require(frames and all(type(row.get("pts")) is int for row in frames), "Actual native source frame PTS absent")
    pts = [row["pts"] for row in frames]
    require(len(set(pts)) == len(pts), "Repeated native source presentation timestamp")
    index = bisect.bisect_right(pts, left / tb) - 1
    require(index >= 0, "Bounded probe omits the native frame holding the requested start")
    first = frames[index]
    end_pts = pts[index + 1] if index + 1 < len(pts) else first["pts"] + int(first["duration"])
    observed_left = first["pts"] * tb
    require(domain_left <= observed_left <= left < end_pts * tb <= domain_right,
            "Actual selected source presentation does not contain requested start")
    sample_start, sample_end = math.ceil(observed_left * rate), math.ceil(right * rate)
    require(0 <= sample_start < sample_end <= clock["sample_count"],
            "Requested source window exceeds the complete native audio sample denominator")
    return {"schema_version": "source-window-native-intake/v1", "source": source,
            "requested_interval": requested, "observed_interval": [str(observed_left), str(right)], "source_domain": domain,
            "video": {"time_base": str(tb), "first_pts": first["pts"], "first_end_pts": end_pts,
                      "trim_end_pts": math.ceil(right / tb)},
            "audio": {"sample_rate": rate, "start_sample": sample_start, "end_sample": sample_end,
                      "native_clock": clock,
                      "first_sample_parent_time": str(Fraction(sample_start, rate)),
                      "start_quantization_offset": str(Fraction(sample_start, rate) - observed_left),
                      "end_quantization_offset": str(Fraction(sample_end, rate) - right)},
            "normalization": "native_integer_video_pts_and_mono_pcm16_16000_mov/v1",
            "precision_supported": False}


def prepare_source_window(source: dict[str, Any], requested: list[str], domain: list[str], directory: Path) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=False)
    value, execution = probe(source, requested, domain)
    for name, record in (("probe", execution), ("audio", execution["audio_timeline"])):
        for key in ("stdout", "stderr"):
            path = directory / (name + "." + key)
            path.write_bytes(record[key])
            record[key] = artifact_ref(path)
    atomic_json(directory / "probe.local.json", execution)
    # Keep both complete probe records even when the clock gate refuses input.
    body = derive(value, source, requested, domain)
    body["probe"] = artifact_ref(directory / "probe.local.json")
    path = directory / "source-window.local.json"
    atomic_json(path, body)
    return artifact_ref(path)


def verify_source_window(ref: dict[str, Any], *, source: dict[str, Any] | None = None,
                         domain: list[str] | None = None) -> dict[str, Any]:
    checked(ref)
    body = json.loads(Path(ref["path"]).read_text())
    require(isinstance(body, dict) and set(body) == {"schema_version", "source", "requested_interval", "observed_interval",
            "source_domain", "video", "audio", "normalization", "precision_supported", "probe"}, "Closed source-window intake schema required")
    if source is not None:
        require(body["source"] == source, "Source-window proof belongs to another source")
    if domain is not None:
        require(body["source_domain"] == domain, "Source-window proof changes measured domain")
    value, actual_execution = probe(body["source"], body["requested_interval"], body["source_domain"])
    expected = derive(value, body["source"], body["requested_interval"], body["source_domain"])
    # Canonical JSON prevents bool/int, float/int, and numeric string aliases.
    require(json.dumps({key: val for key, val in body.items() if key != "probe"}, sort_keys=True)
            == json.dumps(expected, sort_keys=True), "Source-window clocks/expansion/quantization differ from actual native media")
    checked(body["probe"])
    recorded = json.loads(Path(body["probe"]["path"]).read_text())
    require(recorded.get("argv") == actual_execution["argv"] and type(recorded.get("exit_code")) is int
            and recorded["exit_code"] == 0, "Source-window probe command differs")
    for key in ("stdout", "stderr"):
        checked(recorded[key])
    require(not Path(recorded["stderr"]["path"]).read_bytes().strip(), "Source-window probe stderr is nonempty")
    original = json.loads(Path(recorded["stdout"]["path"]).read_text())
    audio_record = recorded.get("audio_timeline")
    require(isinstance(audio_record, dict) and set(audio_record) == {
            "argv", "started_at", "finished_at", "exit_code", "stdout", "stderr"}
            and audio_record["argv"] == actual_execution["audio_timeline"]["argv"]
            and type(audio_record["exit_code"]) is int and audio_record["exit_code"] == 0,
            "Complete native audio probe command/record differs")
    for key in ("stdout", "stderr"):
        checked(audio_record[key])
    require(not Path(audio_record["stderr"]["path"]).read_bytes().strip(),
            "Complete native audio probe stderr is nonempty")
    original["audio_timeline"] = json.loads(Path(audio_record["stdout"]["path"]).read_text())
    require(derive(original, body["source"], body["requested_interval"], body["source_domain"]) == expected,
            "Recorded source native PTS differ from actual media")
    checked(ref)
    return body


def filtergraph(value: dict[str, Any]) -> str:
    video, audio = value["video"], value["audio"]
    return (f"[0:v:0]trim=start_pts={video['first_pts']}:end_pts={video['trim_end_pts']},"
            f"setpts=PTS-{video['first_pts']}[v];"
            f"[0:a:0]atrim=start_sample={audio['start_sample']}:end_sample={audio['end_sample']},"
            "asetpts=PTS-STARTPTS,aresample=16000[a]")
