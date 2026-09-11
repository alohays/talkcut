"""Streaming source/output measurements; detector observations are not AI QC.

Every retained presentation frame and valid PCM sample is compared by default.
The review protocol specifies no acceptable lossy pixel/waveform error, so this
module never converts an arbitrary PSNR/correlation cutoff into a quality PASS.
Fixed detector settings only identify ranges needing audiovisual investigation.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import time
from collections.abc import Mapping
from fractions import Fraction
from pathlib import Path
from typing import Any
from uuid import uuid4

import numpy as np

from .contracts import code_identity
from .media import doctor
from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    now,
    sha256,
    verified_json,
)
from .render import resolve_layout
from .timeline import as_fraction

DETECTORS: dict[str, Any] = {
    "version": "source-difference-observations/v1",
    "purpose": "uncalibrated investigation triggers, never acceptance thresholds",
    "video_luma_black_max": 20,
    "video_black_fraction_min": 0.995,
    "source_nonblack_fraction_max": 0.9,
    "source_motion_mean_abs_min": 1.0,
    "output_freeze_mean_abs_max": 0.05,
    "video_low_psnr_db": 25.0,
    "audio_block_samples": 4096,
    "audio_source_active_rms_min": 0.01,
    "audio_output_silent_rms_max": 0.00001,
    "audio_clip_absolute_min": 0.999,
    "audio_correlation_low": 0.7,
    "audio_gain_ratio_low": 0.5,
    "audio_gain_ratio_high": 2.0,
    "audio_output_jump_min": 0.5,
    "audio_source_jump_max": 0.2,
    "seam_jump_investigation_min": 0.2,
}


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise TalkCutError("QUALITY_UNVERIFIED", message)


def _verify_binary(ref: Mapping[str, Any]) -> Path:
    path = Path(ref["path"])
    _require(path.is_file() and sha256(path) == ref["sha256"], "Source/output artifact is missing or changed")
    return path


class _Decode:
    """Bounded pipe reader with logs and explicit intentional partial termination."""

    def __init__(self, command: list[str], log: Path):
        self.command, self.log = command, log
        self._log = log.open("xb")
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self._log)
        except BaseException:
            self._log.close()
            raise
        self.bytes_read = 0
        self.started_at = now()
        self.receipt: dict[str, Any] | None = None

    def read(self, count: int) -> bytes:
        assert self.process.stdout is not None
        value = self.process.stdout.read(count)
        self.bytes_read += len(value)
        return value

    def finish(self, *, partial: bool = False) -> dict[str, Any]:
        if self.receipt is not None:
            return self.receipt
        if partial:
            # A decoder can block writing to a full pipe while handling SIGTERM.
            # Closing our read end first breaks that backpressure immediately.
            if self.process.stdout:
                self.process.stdout.close()
            if self.process.poll() is None:
                self.process.terminate()
        else:
            while self.read(1024 * 1024):
                pass
        try:
            code = self.process.wait(timeout=5 if partial else 30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            code = self.process.wait(timeout=10)
        if self.process.stdout and not self.process.stdout.closed:
            self.process.stdout.close()
        self._log.close()
        receipt = {"command": self.command, "exit_code": code, "decoded_bytes_read": self.bytes_read,
                   "started_at": self.started_at, "finished_at": now(), "stderr": artifact_ref(self.log),
                   "intentional_partial_stop": partial}
        self.receipt = receipt
        if not partial:
            _require(code == 0 and not self.log.read_bytes().strip(), "Full source/output decoder failed; see stderr artifact")
        return receipt


def _decode_command(path: str, stream: int, media: str) -> list[str]:
    args = ["ffmpeg", "-v", "error", "-xerror", "-nostdin", "-noautorotate", "-i", path,
            "-map", f"0:{stream}"]
    if media == "video":
        args += ["-an", "-fps_mode", "passthrough", "-pix_fmt", "yuv420p", "-f", "rawvideo", "pipe:1"]
    else:
        args += ["-vn", "-c:a", "pcm_f32le", "-f", "f32le", "pipe:1"]
    return args


def _decode_pair(source: Mapping[str, Any], output: Mapping[str, Any], media: str,
                 directory: Path) -> tuple[_Decode, _Decode]:
    original = _Decode(_decode_command(source["path"], source["stream_index"], media), directory / f"{media}-source.stderr")
    try:
        encoded = _Decode(_decode_command(output["path"], output["stream_index"], media), directory / f"{media}-output.stderr")
    except BaseException:
        original.finish(partial=True)
        raise
    return original, encoded


def _finding(findings: dict[str, list[dict[str, Any]]], kind: str, left: Fraction, right: Fraction,
             source_left: Fraction, source_right: Fraction, metric: Mapping[str, Any]) -> None:
    rows = findings.setdefault(kind, [])
    if rows and as_fraction(rows[-1]["output_interval"][1]) == left and as_fraction(rows[-1]["source_interval"][1]) == source_left:
        rows[-1]["output_interval"][1] = str(right)
        rows[-1]["source_interval"][1] = str(source_right)
        rows[-1]["observation_count"] += 1
    else:
        rows.append({"kind": kind, "severity": "P1", "verdict": "UNVERIFIED", "resolved": False,
                     "output_interval": [str(left), str(right)], "source_interval": [str(source_left), str(source_right)],
                     "first_measurement": dict(metric), "observation_count": 1,
                     "reason": "Measured source/output difference requires audiovisual investigation; detector is not a diagnosis"})


def _video_compare(timeline: dict[str, Any], source: Mapping[str, Any], output: Mapping[str, Any],
                   geometry: Mapping[str, Any], directory: Path, findings: dict[str, list[dict[str, Any]]],
                   maximum: int | None) -> dict[str, Any]:
    width, height = geometry["canvas_width"], geometry["canvas_height"]
    _require(width % 2 == 0 and height % 2 == 0, "Only measured even YUV420 canvases are supported")
    masks = []
    x, y, w, h = [geometry[key] for key in ("x", "y", "width", "height")]
    _require(0 <= x < x + w <= width and 0 <= y < y + h <= height, "PiP exclusion rectangle is invalid")
    for factor in (1, 2, 2):
        mask = np.ones((height // factor, width // factor), dtype=bool)
        mask[y // factor: math.ceil((y + h) / factor), x // factor: math.ceil((x + w) / factor)] = False
        masks.append(mask.ravel())
    mask = np.concatenate(masks)
    ymask = masks[0]
    frame_bytes = width * height * 3 // 2
    limit = min(timeline["frame_count"], maximum) if maximum is not None else timeline["frame_count"]
    partial = limit < timeline["frame_count"]
    original, encoded = _decode_pair(source, output, "video", directory)
    stats_path = directory / "video-frames.jsonl"
    source_index, source_frame = -1, b""
    previous_source, previous_output, previous_index = None, None, None
    compared, squared_sum, absolute_sum, max_error = 0, 0.0, 0.0, 0
    minimum_psnr: float | None = None
    decoder_receipts = []
    try:
        with stats_path.open("x") as log:
            for expected in timeline["frames"][:limit]:
                target = expected["source_index"]
                _require(target >= source_index, "Resolved source frames are reordered")
                while source_index < target:
                    source_frame = original.read(frame_bytes)
                    _require(len(source_frame) == frame_bytes, "Source decode ended before a retained frame")
                    source_index += 1
                output_frame = encoded.read(frame_bytes)
                _require(len(output_frame) == frame_bytes, "Output dropped a scheduled presentation frame")
                source_array = np.frombuffer(source_frame, dtype=np.uint8)
                output_array = np.frombuffer(output_frame, dtype=np.uint8)
                a, b = source_array[mask].astype(np.int16), output_array[mask].astype(np.int16)
                delta = a - b
                mse = float(np.mean(np.square(delta, dtype=np.float64)))
                mae = float(np.mean(np.abs(delta)))
                peak = int(np.max(np.abs(delta)))
                psnr = 10 * math.log10(255**2 / mse) if mse else None
                source_black = float(np.mean(source_array[:width * height][ymask] <= DETECTORS["video_luma_black_max"]))
                output_black = float(np.mean(output_array[:width * height][ymask] <= DETECTORS["video_luma_black_max"]))
                source_motion = output_motion = None
                if previous_source is not None and previous_index is not None and target == previous_index + 1:
                    source_motion = float(np.mean(np.abs(a - previous_source)))
                    output_motion = float(np.mean(np.abs(b - previous_output)))
                row = {"output_frame": compared, "source_frame": target, "output_pts": expected["output_pts"],
                       "mse_yuv_code_values": mse, "mae_yuv_code_values": mae, "max_abs_error": peak,
                       "psnr_db": psnr, "lossless_match": mse == 0, "source_black_luma_fraction": source_black,
                       "output_black_luma_fraction": output_black, "source_motion_mae": source_motion,
                       "output_motion_mae": output_motion}
                log.write(json.dumps(row, allow_nan=False) + "\n")
                left = as_fraction(expected["output_pts"])
                right = left + as_fraction(expected["duration"])
                source_left = as_fraction(expected["presentation_source_time"])
                source_right = source_left + as_fraction(expected["duration"])
                if output_black >= DETECTORS["video_black_fraction_min"] and source_black < DETECTORS["source_nonblack_fraction_max"]:
                    _finding(findings, "possible_new_black", left, right, source_left, source_right, row)
                if source_motion is not None and output_motion is not None and source_motion >= DETECTORS["source_motion_mean_abs_min"] and output_motion <= DETECTORS["output_freeze_mean_abs_max"]:
                    _finding(findings, "possible_new_freeze", left, right, source_left, source_right, row)
                if psnr is not None and psnr < DETECTORS["video_low_psnr_db"]:
                    _finding(findings, "large_screen_difference", left, right, source_left, source_right, row)
                compared += 1
                squared_sum += mse
                absolute_sum += mae
                max_error = max(max_error, peak)
                if psnr is not None:
                    minimum_psnr = psnr if minimum_psnr is None else min(minimum_psnr, psnr)
                previous_source, previous_output, previous_index = a, b, target
            if not partial:
                _require(not encoded.read(frame_bytes), "Output has frames absent from the resolved mapping")
        decoder_receipts = [original.finish(partial=partial), encoded.finish(partial=partial)]
    except BaseException:
        for reader in (original, encoded):
            reader.finish(partial=True)
        raise
    expected_end = (as_fraction(timeline["frames"][compared - 1]["output_pts"]) + as_fraction(timeline["frames"][compared - 1]["duration"])) if compared else Fraction()
    return {"status": "MEASURED" if not partial else "PARTIAL", "coverage": {"numerator": compared,
            "denominator": timeline["frame_count"], "unit": "presentation_frames", "output_intervals": [["0", str(expected_end)]],
            "full_retained_timeline": not partial, "width": width, "height": height,
            "compared_yuv_values_per_frame": int(np.sum(mask)), "excluded_pip_rectangle": {key: geometry[key] for key in ("x", "y", "width", "height")},
            "chroma_exclusion": "round rectangle outward on native subsampled chroma grid"},
            "mean_mse_yuv_code_values": squared_sum / compared, "mean_mae_yuv_code_values": absolute_sum / compared,
            "minimum_frame_psnr_db": minimum_psnr, "max_abs_error": max_error,
            "metrics": artifact_ref(stats_path), "decoders": decoder_receipts,
            "limitations": ["Speaker rectangle is excluded", "Pixel errors are measurements, not readability or occlusion approval", "Motion triggers do not prove absence of all visual defects"]}


def _audio_compare(timeline: dict[str, Any], source: Mapping[str, Any], output: Mapping[str, Any],
                   directory: Path, findings: dict[str, list[dict[str, Any]]], maximum: int | None) -> dict[str, Any]:
    channels, rate = source["channels"], timeline["sample_rate"]
    _require(channels == output["channels"] and source["sample_rate"] == output["sample_rate"] == rate,
             "Output audio channel count or PCM rate differs from selected source")
    limit = min(timeline["sample_count"], maximum) if maximum is not None else timeline["sample_count"]
    partial = limit < timeline["sample_count"]
    original, encoded = _decode_pair(source, output, "audio", directory)
    metrics_path = directory / "audio-blocks.jsonl"
    source_cursor = compared = 0
    square_error = source_energy = output_energy = 0.0
    source_clipped = output_clipped = 0
    previous_source = previous_output = None
    seam_measurements = []
    try:
        with metrics_path.open("x") as log:
            for index, span in enumerate(timeline["retained"]):
                if compared >= limit:
                    break
                start = span["audio_source_sample_start"]
                _require(start >= source_cursor, "Audio sample schedule is reordered")
                discard = start - source_cursor
                while discard:
                    amount = min(discard, 65536)
                    _require(len(original.read(amount * channels * 4)) == amount * channels * 4, "Source ended inside a discarded interval")
                    discard -= amount
                    source_cursor += amount
                remaining = min(span["output_sample_end"] - span["output_sample_start"], limit - compared)
                first_block = True
                while remaining:
                    amount = min(remaining, DETECTORS["audio_block_samples"])
                    raw_source, raw_output = original.read(amount * channels * 4), encoded.read(amount * channels * 4)
                    _require(len(raw_source) == len(raw_output) == amount * channels * 4, "Source/output PCM ended before the cumulative sample schedule")
                    a = np.frombuffer(raw_source, dtype="<f4").reshape(-1, channels).astype(np.float64)
                    b = np.frombuffer(raw_output, dtype="<f4").reshape(-1, channels).astype(np.float64)
                    _require(np.all(np.isfinite(a)) and np.all(np.isfinite(b)), "Non-finite decoded audio values")
                    aa, bb, error = np.sum(a * a, axis=0), np.sum(b * b, axis=0), np.sum((a - b) ** 2, axis=0)
                    rms_a, rms_b = np.sqrt(aa / amount), np.sqrt(bb / amount)
                    correlations = [float(np.sum(a[:, c] * b[:, c]) / math.sqrt(aa[c] * bb[c])) if aa[c] and bb[c] else None for c in range(channels)]
                    clipped_a = np.abs(a) >= DETECTORS["audio_clip_absolute_min"]
                    clipped_b = np.abs(b) >= DETECTORS["audio_clip_absolute_min"]
                    clips_a = int(np.count_nonzero(clipped_a))
                    clips_b = int(np.count_nonzero(clipped_b))
                    newly_clipped = int(np.count_nonzero(clipped_b & ~clipped_a))
                    jumps_a, jumps_b = np.diff(a, axis=0), np.diff(b, axis=0)
                    if previous_source is not None:
                        jumps_a = np.vstack([a[0] - previous_source, jumps_a])
                        jumps_b = np.vstack([b[0] - previous_output, jumps_b])
                    jump_a = float(np.max(np.abs(jumps_a))) if len(jumps_a) else 0.0
                    jump_b = float(np.max(np.abs(jumps_b))) if len(jumps_b) else 0.0
                    new_jump_values = int(np.count_nonzero((np.abs(jumps_b) >= DETECTORS["audio_output_jump_min"])
                                                          & (np.abs(jumps_a) <= DETECTORS["audio_source_jump_max"])))
                    row = {"output_sample_start": compared, "output_sample_end": compared + amount,
                           "source_sample_start": source_cursor, "source_sample_end": source_cursor + amount,
                           "source_rms_by_channel": rms_a.tolist(), "output_rms_by_channel": rms_b.tolist(),
                           "waveform_correlation_by_channel": correlations, "mse_by_channel": (error / amount).tolist(),
                           "source_peak": float(np.max(np.abs(a))), "output_peak": float(np.max(np.abs(b))),
                           "source_clipped_values": clips_a, "output_clipped_values": clips_b,
                           "output_clipped_values_absent_at_mapped_source_sample": newly_clipped,
                           "possible_new_jump_values": new_jump_values,
                           "source_max_sample_jump": jump_a, "output_max_sample_jump": jump_b}
                    log.write(json.dumps(row, allow_nan=False) + "\n")
                    left, right = Fraction(compared, rate), Fraction(compared + amount, rate)
                    # Findings use the exact common time of the selected decoded
                    # sample, including measured origin/offset and quantization.
                    audio_map = timeline["audio"]
                    source_left = (as_fraction(audio_map["start"]) - as_fraction(audio_map["origin"])
                                   + as_fraction(audio_map["offset"]) + Fraction(source_cursor, rate))
                    source_right = source_left + Fraction(amount, rate)
                    if any(rms_a[c] >= DETECTORS["audio_source_active_rms_min"] and rms_b[c] <= DETECTORS["audio_output_silent_rms_max"] for c in range(channels)):
                        _finding(findings, "possible_new_audio_silence", left, right, source_left, source_right, row)
                    if newly_clipped:
                        _finding(findings, "possible_new_audio_clipping", left, right, source_left, source_right, row)
                    if any(value is not None and value < DETECTORS["audio_correlation_low"] and rms_a[c] >= DETECTORS["audio_source_active_rms_min"] for c, value in enumerate(correlations)):
                        _finding(findings, "possible_audio_misalignment_or_dropout", left, right, source_left, source_right, row)
                    if any(rms_a[c] >= DETECTORS["audio_source_active_rms_min"] and not DETECTORS["audio_gain_ratio_low"] <= rms_b[c] / rms_a[c] <= DETECTORS["audio_gain_ratio_high"] for c in range(channels)):
                        _finding(findings, "possible_audio_gain_change", left, right, source_left, source_right, row)
                    if new_jump_values:
                        _finding(findings, "possible_new_audio_click", left, right, source_left, source_right, row)
                    if first_block and index and previous_output is not None:
                        seam_jump = float(np.max(np.abs(b[0] - previous_output)))
                        seam_measurements.append({"output_sample": compared, "source_before": timeline["retained"][index - 1]["source_end"],
                                                  "source_after": span["source_start"], "output_jump": seam_jump,
                                                  "constructed_reference_jump": float(np.max(np.abs(a[0] - previous_source))),
                                                  "listening_review": "UNVERIFIED"})
                        if seam_jump >= DETECTORS["seam_jump_investigation_min"]:
                            _finding(findings, "possible_audible_join", left, right, source_left, source_right, row)
                    first_block = False
                    previous_source, previous_output = a[-1], b[-1]
                    compared += amount
                    source_cursor += amount
                    remaining -= amount
                    square_error += float(np.sum(error))
                    source_energy += float(np.sum(aa))
                    output_energy += float(np.sum(bb))
                    source_clipped += clips_a
                    output_clipped += clips_b
        trailing_samples = None
        if not partial:
            trailing = b""
            while chunk := encoded.read(65536):
                trailing += chunk
                _require(len(trailing) <= 1024 * channels * 4, "Unexpected audio beyond known AAC frame padding")
            _require(len(trailing) % (channels * 4) == 0, "Incomplete output PCM sample")
            trailing_samples = len(trailing) // (channels * 4)
            _require(trailing_samples < 1024, "Unexpected complete AAC block beyond valid audio schedule")
        decoders = [original.finish(partial=partial), encoded.finish(partial=partial)]
    except BaseException:
        for reader in (original, encoded):
            reader.finish(partial=True)
        raise
    return {"status": "PARTIAL" if partial else "MEASURED", "coverage": {"numerator": compared, "denominator": timeline["sample_count"],
            "unit": "sample_frames", "channels": channels, "sample_rate": rate, "full_retained_timeline": not partial,
            "output_intervals": [["0", str(Fraction(compared, rate))]]}, "decoded_trailing_padding_samples": trailing_samples,
            "mean_squared_waveform_error": square_error / (compared * channels), "source_rms": math.sqrt(source_energy / (compared * channels)),
            "output_rms": math.sqrt(output_energy / (compared * channels)), "source_clipped_values": source_clipped,
            "output_clipped_values": output_clipped, "seam_measurements": seam_measurements,
            "metrics": artifact_ref(metrics_path), "decoders": decoders,
            "limitations": ["Continuous waveform measurements do not constitute listening", "AAC error and codec overshoot require interpretation", "Semantic and phonetic preservation remain UNVERIFIED"]}


def compare_render(workflow_render_ref: dict[str, str], output_dir: str | Path, *,
                   max_video_frames: int | None = None, max_audio_samples: int | None = None) -> dict[str, Any]:
    """Read immutable workflow evidence and write a new, fully bound comparison.

    Limits are intended for diagnostic runs. Their literal compared frame/sample
    counts are reported; neither partial work nor heuristic silence/PSNR checks
    can be promoted to whole-output quality approval.
    """
    for limit in (max_video_frames, max_audio_samples):
        _require(limit is None or type(limit) is int and limit > 0, "Comparison limits must be positive integers")
    workflow = verified_json(workflow_render_ref)
    native = verified_json(workflow["native_render"])
    timeline_ref, plan_ref = workflow["settings"]["timeline"], workflow["settings"]["plan"]
    timeline, plan = verified_json(timeline_ref), verified_json(plan_ref)
    _require(timeline["frame_count"] == len(timeline["frames"]) > 0 and timeline["sample_count"] > 0,
             "Timeline measurement denominators disagree with the resolved schedule")
    _require(native.get("complete") is True and native.get("status") == "succeeded", "Only completed native renders can be compared")
    _require(native["timeline_hash"] == timeline["timeline_hash"] and timeline["plan_hash"] == content_hash(plan), "Plan/timeline/native render identities disagree")
    canonical_timeline = dict(timeline)
    declared = canonical_timeline.pop("timeline_hash")
    # The timeline compiler uses ASCII canonical serialization for this hash.
    import hashlib
    _require(declared == hashlib.sha256(json.dumps(canonical_timeline, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "Resolved timeline content hash changed")
    _require(workflow["output"] == native["output"], "Workflow points to a different native output")
    output_path = _verify_binary(native["output"])
    for source in native["sources"].values():
        _verify_binary(source)
    inspections = {role: verified_json(plan["inspection_refs"][role]) for role in ("screen", "speaker")}
    for role, inspection in inspections.items():
        _require(inspection["sha256"] == native["sources"][role]["sha256"] == plan["source_hashes"][role], "Inspection/source dependency changed")
    _require(native["layout"] == resolve_layout(inspections["screen"]["video"], inspections["speaker"]["video"], plan["layout"]),
             "PiP measurement exclusion differs from the source geometry and requested layout")
    selected_audio = plan["timing"]["audio_source"]
    _require(native["sources"]["audio"]["sha256"] == native["sources"][selected_audio]["sha256"], "Selected audio differs from rendered source")
    run_id = "quality-" + uuid4().hex
    directory = Path(output_dir).resolve() / run_id
    directory.mkdir(parents=True)
    started, clock = now(), time.monotonic()
    toolchain = doctor()
    deps = {"code_tree_hash": code_identity(Path.cwd())["code_tree_hash"], "contract_hash": plan.get("contract_hash"),
            "source_hashes": plan["source_hashes"], "timeline_hash": timeline_ref["sha256"],
            "resolved_timeline_hash": timeline["timeline_hash"], "output_hash": native["output"]["sha256"], "plan_hash": plan_ref["sha256"]}
    try:
        probe_command = ["ffprobe", "-v", "error", "-show_streams", "-of", "json", str(output_path)]
        probe = subprocess.run(probe_command, capture_output=True, text=True, timeout=60, check=True)
        probe_path = directory / "output-probe.stdout.json"
        probe_path.write_text(probe.stdout)
        streams = json.loads(probe.stdout)["streams"]
        video_streams, audio_streams = [[stream for stream in streams if stream["codec_type"] == kind] for kind in ("video", "audio")]
        _require(len(streams) == 2 and len(video_streams) == len(audio_streams) == 1, "Output must contain one video and one audio stream")
        video, audio = video_streams[0], audio_streams[0]
        geometry = native["layout"]
        _require((video["width"], video["height"], video.get("pix_fmt")) == (geometry["canvas_width"], geometry["canvas_height"], "yuv420p"), "Output canvas or pixel format changed")
        source_audio_stream = next(stream for stream in inspections[selected_audio]["streams"] if stream["index"] == inspections[selected_audio]["audio"]["index"])
        findings: dict[str, list[dict[str, Any]]] = {}
        video_result = _video_compare(timeline,
            {**native["sources"]["screen"], "stream_index": inspections["screen"]["video"]["index"]},
            {**native["output"], "stream_index": video["index"]}, geometry, directory, findings, max_video_frames)
        audio_result = _audio_compare(timeline,
            {**native["sources"]["audio"], "stream_index": source_audio_stream["index"], "channels": source_audio_stream["channels"], "sample_rate": int(source_audio_stream["sample_rate"])},
            {**native["output"], "stream_index": audio["index"], "channels": audio["channels"], "sample_rate": int(audio["sample_rate"])},
            directory, findings, max_audio_samples)
        for source in native["sources"].values():
            _verify_binary(source)
        _verify_binary(native["output"])
        for ref in (workflow_render_ref, workflow["native_render"], timeline_ref, plan_ref, *plan["inspection_refs"].values()):
            verified_json(ref)
        _require(code_identity(Path.cwd())["code_tree_hash"] == deps["code_tree_hash"], "Code changed during quality measurement; repeat against a fixed code snapshot")
        _require(doctor() == toolchain, "Media toolchain changed during quality measurement")
        full = video_result["coverage"]["full_retained_timeline"] and audio_result["coverage"]["full_retained_timeline"]
        report = {"schema_version": "source-output-quality/v1", "run_id": run_id, "dependencies": deps,
                  "status": "UNVERIFIED", "execution_status": "PASS", "coverage_status": "PASS" if full else "UNVERIFIED",
                  "whole_retained_source_compared": full, "video": video_result, "audio": audio_result,
                  "findings": [item for rows in findings.values() for item in rows], "detectors": DETECTORS,
                  "ai_visual_occlusion": "UNVERIFIED", "ai_audio_listening": "UNVERIFIED", "semantic_preservation": "UNVERIFIED",
                  "owner_acceptance": "pending", "started_at": started, "finished_at": now(), "wall_seconds": time.monotonic() - clock,
                  "input_refs": {"workflow": workflow_render_ref, "native_render": workflow["native_render"], "timeline": timeline_ref, "plan": plan_ref},
                  "toolchain": toolchain, "output_probe": {"command": probe_command, "exit_code": probe.returncode, "stdout": artifact_ref(probe_path)},
                  "reason": "All reported comparisons were measured; the protocol provides no lossy-error acceptance cutoff and AI review remains required"}
        result_path = directory / "comparison.json"
        atomic_json(result_path, report)
        receipt = {"schema_version": "execution-receipt/v1", "operation": "quality:compare", "run_id": run_id,
                   "executor": "local_python_in_process", "python_executable": sys.executable,
                   "started_at": started, "finished_at": now(), "completed": True, "exit_code": 0,
                   "dependencies": deps, "result": artifact_ref(result_path),
                   "decoder_receipts": video_result["decoders"] + audio_result["decoders"],
                   "note": "The calling CLI must capture its actual stdout for measurement-check binding; this in-process receipt does not invent stdout"}
        receipt_path = directory / "receipt.json"
        atomic_json(receipt_path, receipt)
        return {**report, "artifact_ref": artifact_ref(result_path), "receipt": artifact_ref(receipt_path)}
    except BaseException as exc:
        atomic_json(directory / "failure.json", {"schema_version": "quality-failure/v1", "run_id": run_id, "dependencies": deps,
                    "status": "FAIL", "completed": False, "error": str(exc), "started_at": started, "finished_at": now(),
                    "owner_acceptance": "pending", "partial_metrics_not_approved": True})
        raise
