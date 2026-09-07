"""Actual audiovisual review clips and strict, preserved provider imports.

Building clips requests review; it does not execute a model or approve media.
Unknown capabilities, incomplete responses and sparse motion inputs stay
UNVERIFIED. Imported JSON is data and is never executed as a command.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from typing import Any
from uuid import uuid4

from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    now,
    read_json,
    sha256,
)
from .timeline import as_fraction, subtract_intervals


def _artifact(ref: Any, *, binary: bool = False) -> Any:
    if not isinstance(ref, dict) or not ref.get("path") or not ref.get("sha256"):
        raise TalkCutError(
            "REVIEW_EVIDENCE_MISSING", "A hashed artifact reference is required"
        )
    path = Path(ref["path"])
    if not path.is_file() or sha256(path) != ref["sha256"]:
        raise TalkCutError(
            "STALE_REVIEW", "Referenced review artifact is missing or changed"
        )
    return path if binary else read_json(path)


def _require(value: Any, reason: str) -> None:
    if not value:
        raise TalkCutError("REVIEW_UNVERIFIED", reason)


def _uncovered(
    domain: tuple[Fraction, Fraction], covered: list[tuple[Fraction, Fraction]]
) -> list[tuple[Fraction, Fraction]]:
    clipped = [
        (max(domain[0], a), min(domain[1], b))
        for a, b in covered
        if a < domain[1] and b > domain[0]
    ]
    return subtract_intervals(domain, clipped)


def _media_streams(
    ref: dict[str, str], required: set[str], *, decode: bool = False
) -> list[dict[str, Any]]:
    """Read actual media streams; a filename or modality claim is not evidence."""
    path = _artifact(ref, binary=True)
    probe = subprocess.run(
        ["ffprobe", "-v", "error", "-show_streams", "-of", "json", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    _require(probe.returncode == 0, "Claimed media artifact cannot be probed")
    streams = json.loads(probe.stdout).get("streams", [])
    _require(
        required.issubset({item.get("codec_type") for item in streams}),
        "Actual artifact lacks claimed media modality",
    )
    if decode:
        process = subprocess.run(
            [
                "ffmpeg",
                "-nostdin",
                "-v",
                "error",
                "-xerror",
                "-err_detect",
                "explode",
                "-i",
                str(path),
                "-f",
                "null",
                "-",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        _require(
            process.returncode == 0 and not process.stderr.strip(),
            "Claimed media artifact does not completely decode",
        )
    return streams


def _receipt(ref: Any) -> dict[str, Any]:
    value = _artifact(ref)
    if value.get("schema_version") == "composite-review-receipt/v1":
        from .composite_review import verify_composite_receipt

        return verify_composite_receipt(ref)
    _require(
        not str(value.get("model_revision", "")).startswith("composite/")
        and "composite_graph" not in value,
        "Composite cannot bypass its typed execution graph",
    )
    _require(
        value.get("schema_version") == "execution-receipt/v1",
        "Provider execution receipt missing",
    )
    _require(
        value.get("completed") is True
        and type(value.get("exit_code")) is int
        and value["exit_code"] == 0,
        "Provider execution failed or did not finish",
    )
    _require(
        not value.get("mock") and not value.get("test_only"),
        "Mock/test receipts cannot validate actual review",
    )
    for key in (
        "run_id",
        "provider_request_id",
        "model_revision",
        "prompt_sha256",
        "started_at",
        "finished_at",
    ):
        _require(value.get(key), f"Provider provenance missing: {key}")
    _require(
        _artifact(value.get("log"), binary=True).stat().st_size > 0,
        "Provider execution log is empty",
    )
    _artifact(value.get("prompt"), binary=True)
    _require(value["prompt"]["sha256"] == value["prompt_sha256"], "Prompt hash differs")
    _artifact(value.get("request"))
    _artifact(value.get("response"))
    return value


PRECISION_REVIEW_SCOPES = {"source_sync", "seam", "lip_sync"}


def precision_review_required(request: dict[str, Any]) -> bool:
    return (
        request.get("scope") in PRECISION_REVIEW_SCOPES
        or request.get("details", {}).get("requires_dense_video") is True
    )


def _capability(
    value: dict[str, Any], *, precision_required: bool = True
) -> dict[str, Any]:
    _require(
        value.get("schema_version") == "review-capability/v1",
        "Executed capability record missing",
    )
    execution = _receipt(value.get("receipt"))
    if execution.get("_composite_verified"):
        from .composite_review import verify_composite_receipt

        execution = verify_composite_receipt(
            value["receipt"],
            precision_required=precision_required,
            forbidden_artifacts=[value["challenge"]],
        )
    _require(
        value.get("model_revision") == execution["model_revision"],
        "Capability model differs from execution",
    )
    expected, observed = (
        _artifact(value.get("challenge")),
        _artifact(value.get("observations")),
    )
    actual_response = _artifact(execution["response"])
    for modality in ("audio", "video"):
        _require(
            expected.get(f"{modality}_events")
            and expected[f"{modality}_events"] == observed.get(f"{modality}_events"),
            f"Known {modality} challenge was not correctly observed",
        )
        _require(
            observed.get(f"{modality}_events")
            == actual_response.get(f"{modality}_events"),
            "Capability observations are not the actual provider response",
        )
    observation = _artifact(value.get("input_observation"))
    _require(
        observation.get("audio_continuous") is True,
        "Continuous audio was not actually supplied",
    )
    timestamps = [
        as_fraction(item) for item in observation.get("video_frame_timestamps", [])
    ]
    _require(
        len(timestamps) >= 2 and all(b > a for a, b in pairwise(timestamps)),
        "Actual observed frame timestamps unavailable",
    )
    gap = max(b - a for a, b in pairwise(timestamps))
    if precision_required:
        _require(
            gap <= Fraction(40, 1000),
            "Actual supplied frames are too sparse for lip/seam timing; model uncertainty cannot override sampling",
        )
    elif gap > Fraction(40, 1000):
        _require(
            isinstance(observation.get("sampling_limitations"), str)
            and len(observation["sampling_limitations"].strip()) >= 30,
            "Semantic AV capability must disclose sampling limits; it does not certify dense motion or lip timing",
        )
    _require(
        observation.get("request_sha256") == execution["request"]["sha256"],
        "Observed input sampling is not bound to executed request",
    )
    _require(
        observation.get("frame_artifacts"), "Actual sampled frame artifacts are missing"
    )
    _require(
        len(observation["frame_artifacts"]) == len(timestamps),
        "Frame count differs from sampling timestamps",
    )
    for ref in observation["frame_artifacts"]:
        _media_streams(ref, {"video"}, decode=True)
    audio_streams = _media_streams(
        observation.get("audio_artifact"), {"audio"}, decode=True
    )
    audio_stream = next(item for item in audio_streams if item["codec_type"] == "audio")
    _require(
        "duration" in audio_stream
        and Fraction(audio_stream["duration"]) >= timestamps[-1] - timestamps[0],
        "Supplied audio does not span the sampled video sequence",
    )
    request = _artifact(execution["request"])
    _require(
        "audio" in request.get("input_modalities", [])
        and bool(
            {"video", "image_sequence"} & set(request.get("input_modalities", []))
        ),
        "Actual capability request was transcript-only or lacked audiovisual inputs",
    )
    _require(
        request.get("input_audio_hash") == observation["audio_artifact"]["sha256"]
        and request.get("input_frame_hashes")
        == [ref["sha256"] for ref in observation["frame_artifacts"]],
        "Capability request does not bind actual audio and ordered frame bytes",
    )
    _require(
        [as_fraction(value) for value in request.get("input_frame_timestamps", [])]
        == timestamps,
        "Capability request sampling differs from the claimed temporal resolution",
    )
    return {
        "model_revision": execution["model_revision"],
        "max_actual_frame_gap_ms": float(gap * 1000),
        "audio_continuous": True,
        "precision_supported": gap <= Fraction(40, 1000)
        and execution.get("_composite_precision_verified", True),
        "sampling_limitations": observation.get(
            "sampling_limitations",
            "Known timestamped frame sequence; no claim about unobserved events between samples",
        ),
    }


def verify_context_execution(context: dict[str, Any]) -> dict[str, Any]:
    """Validate executed audiovisual source context, preserving honest failure."""
    try:
        _require(
            not context.get("test_only"), "Fixture context cannot certify real source"
        )
        capability = _capability(
            _artifact(context.get("capability")), precision_required=False
        )
        execution = _receipt(context.get("receipt"))
        _require(
            execution["model_revision"] == capability["model_revision"],
            "Context model capability was not demonstrated",
        )
        request = _artifact(execution["request"])
        response = _artifact(execution["response"])
        _require(
            request.get("source_sha256") == context["source_sha256"],
            "Executed request is for another source",
        )
        _require(
            request.get("input_clip_hashes"),
            "No actual audiovisual source inputs were recorded",
        )
        for ref in context.get("input_clips", []):
            _artifact(ref, binary=True)
        _require(
            set(request["input_clip_hashes"])
            == {ref["sha256"] for ref in context.get("input_clips", [])},
            "Context source clip hashes differ from actual request",
        )
        _require(
            response.get("segments") == context.get("segments")
            and bool(response.get("segments")),
            "Imported context is not the actual nonempty provider response",
        )
        _require(
            {"audio", "video"}.issubset(response.get("observed_modalities", [])),
            "Transcript-only context cannot authorize cuts",
        )
        _require(
            context.get("proposer_run_id") == execution["run_id"]
            and context.get("prompt_sha256") == execution["prompt_sha256"],
            "Proposal provenance differs from actual execution",
        )
        _require(
            request.get("scope") == "analysis"
            and _executed_request_schema(request, execution),
            "Source analysis must identify the actual bounded AV request",
        )
        _require(
            context.get("dependencies")
            == request.get("dependencies")
            == execution.get("dependencies"),
            "Source context dependencies differ from actual provider inputs",
        )
        inputs = request.get("inputs", [])
        _require(
            inputs and [item["clip"] for item in inputs] == context.get("input_clips"),
            "Source context clip order or actual extraction provenance is missing",
        )
        _require(
            all(
                item.get("parent_sha256") == context["source_sha256"] for item in inputs
            ),
            "Context was produced from different source media",
        )
        # A proposal is not an adversarial-review verdict, but its executed
        # media inputs require the same byte/clock/extraction verification.
        validate_review_request(
            {
                "scope": "analysis",
                "dependencies": context["dependencies"],
                "inputs": inputs,
            },
            execution,
        )
        submitted = [(as_fraction(a), as_fraction(b)) for a, b in request["intervals"]]
        for segment in response["segments"]:
            span = (as_fraction(segment["start"]), as_fraction(segment["end"]))
            _require(
                span[0] < span[1] and not _uncovered(span, submitted),
                "Context claims source time that the provider did not receive",
            )
        return {"status": "PASS", "capability": capability}
    except (
        TalkCutError,
        ValueError,
        KeyError,
        TypeError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        return {"status": "UNVERIFIED", "reason": str(exc)}


def windows(
    domain: Any, window_seconds: Any = "30", overlap_seconds: Any = "5"
) -> list[tuple[Fraction, Fraction]]:
    start, end = as_fraction(domain[0]), as_fraction(domain[1])
    width, overlap = as_fraction(window_seconds), as_fraction(overlap_seconds)
    if not start < end or not 0 <= overlap < width:
        raise TalkCutError(
            "INVALID_REVIEW_WINDOW",
            "Positive domain and overlap smaller than window required",
        )
    result = []
    cursor = start
    while cursor < end:
        right = min(end, cursor + width)
        result.append((cursor, right))
        if right == end:
            break
        cursor += width - overlap
    return result


def _executed_request_schema(
    request: dict[str, Any], execution: dict[str, Any]
) -> bool:
    if request.get("schema_version") == "review-request/v1":
        return True
    if request.get("schema_version") != "composite-review-request/v1":
        return False
    # Never trust a manually copied internal marker on an arbitrary receipt.
    from .composite_review import verify_composite_receipt

    ref = execution.get("_composite_receipt")
    _require(isinstance(ref, dict), "Composite receipt reference missing")
    assert isinstance(ref, dict)
    verified = verify_composite_receipt(ref)
    return verified == execution and _artifact(verified["request"]) == request


def validate_review_request(
    record: dict[str, Any], execution: dict[str, Any]
) -> dict[str, Any]:
    """Bind a ledger entry to the executed scope, intervals and current media."""
    request = _artifact(execution["request"])
    _require(
        _executed_request_schema(request, execution),
        "Executed request schema is missing",
    )
    _require(
        request.get("scope") == record.get("scope")
        and request.get("scope")
        in {
            "output",
            "deletion",
            "seam",
            "analysis",
            "layout",
            "lip_sync",
            "source_sync",
        },
        "Ledger scope differs from actual provider request",
    )
    _require(
        request.get("dependencies")
        == record.get("dependencies")
        == execution.get("dependencies"),
        "Provider request/receipt/ledger dependencies differ",
    )
    inputs = request.get("inputs", [])
    _require(
        bool(inputs) and inputs == record.get("inputs"),
        "Ledger inputs differ from actual submitted media",
    )
    _require(
        request.get("input_clip_hashes") == [item["clip"]["sha256"] for item in inputs],
        "Actual ordered provider clip hashes differ",
    )
    requested = [
        (as_fraction(a), as_fraction(b)) for a, b in request.get("intervals", [])
    ]
    _require(
        bool(requested) and all(a < b for a, b in requested),
        "Executed request has invalid or empty intervals",
    )
    clip_intervals: list[tuple[Fraction, Fraction]] = []
    deps = request["dependencies"]
    for item in inputs:
        _require(len(item["interval"]) == 2, "Invalid claimed clip interval")
        clip_interval = (
            as_fraction(item["interval"][0]),
            as_fraction(item["interval"][1]),
        )
        _require(
            len(clip_interval) == 2 and clip_interval[0] < clip_interval[1],
            "Invalid claimed clip interval",
        )
        clip_intervals.append(clip_interval)
        parent = item.get("parent_media")
        _artifact(parent, binary=True)
        _require(
            parent["sha256"] == item["parent_sha256"],
            "Clip parent reference/hash mismatch",
        )
        expected = (
            set(deps.get("source_hashes", {}).values())
            if request["scope"] in {"deletion", "analysis", "source_sync"}
            else {deps.get("output_hash")}
        )
        _require(
            item["parent_sha256"] in expected,
            "Review clips came from a different source/output",
        )
        extraction = _artifact(item["extraction_receipt"])
        _require(
            extraction.get("schema_version") == "execution-receipt/v1"
            and extraction.get("executor") == "ffmpeg-review-extraction"
            and extraction.get("completed") is True
            and type(extraction.get("exit_code")) is int
            and extraction["exit_code"] == 0,
            "No successful actual clip extraction",
        )
        _require(
            extraction.get("dependencies") == deps
            and extraction.get("parent_media") == parent
            and extraction.get("input_sha256") == item["parent_sha256"]
            and extraction.get("output_sha256") == item["clip"]["sha256"],
            "Clip extraction dependencies and media identity differ",
        )
        _require(
            tuple(as_fraction(value) for value in extraction.get("interval", []))
            == clip_interval,
            "Claimed clip interval differs from actual extraction",
        )
        clock = extraction.get("video_clock", {})
        _require(
            as_fraction(clock.get("rate", "0")) == 1,
            "Extraction source clock is unverified",
        )
        shift = as_fraction(clock["origin"]) - as_fraction(clock["offset"])
        native_video = [clip_interval[0] + shift, clip_interval[1] + shift]
        _require(
            [
                as_fraction(value)
                for value in extraction.get("video_native_interval", [])
            ]
            == native_video,
            "Source clock/extraction interval mismatch",
        )
        alternate_audio = extraction.get("audio_source")
        native_audio = native_video
        audio_index = "0:a:0"
        if alternate_audio:
            _artifact(alternate_audio, binary=True)
            _require(
                alternate_audio.get("mapping_verified") is True
                and as_fraction(alternate_audio.get("rate", "1")) == 1,
                "Alternate review audio mapping is unverified",
            )
            audio_shift = as_fraction(alternate_audio.get("origin", "0")) - as_fraction(
                alternate_audio["offset"]
            )
            native_audio = [
                clip_interval[0] + audio_shift,
                clip_interval[1] + audio_shift,
            ]
            audio_index = (
                f"1:{alternate_audio['stream_index']}"
                if "stream_index" in alternate_audio
                else "1:a:0"
            )
        _require(
            [
                as_fraction(value)
                for value in extraction.get("audio_native_interval", [])
            ]
            == native_audio,
            "Audio extraction interval differs from source clock",
        )
        decimal = lambda value: f"{float(value):.12f}"
        graph = f"[0:v:0]trim=start={decimal(native_video[0])}:end={decimal(native_video[1])},setpts=PTS-({decimal(native_video[0])})/TB[v];[{audio_index}]atrim=start={decimal(native_audio[0])}:end={decimal(native_audio[1])},asetpts=PTS-({decimal(native_audio[0])})/TB[a]"
        command = extraction.get("command", [])
        _require(
            extraction.get("filtergraph") == graph
            and "-filter_complex" in command
            and command[command.index("-filter_complex") + 1] == graph
            and str(Path(parent["path"]).resolve()) in command,
            "Executed extraction command does not match claimed interval/media",
        )
        _require(
            "progress=end" in _artifact(extraction.get("log"), binary=True).read_text(),
            "Clip extraction did not reach completion",
        )
        streams = _media_streams(item["clip"], {"audio", "video"})
        for stream in streams:
            if stream["codec_type"] in {"audio", "video"}:
                _require(
                    "duration" in stream
                    and abs(
                        Fraction(stream["duration"])
                        - (clip_interval[1] - clip_interval[0])
                    )
                    <= Fraction(1, 10),
                    "Actual clip duration differs from requested interval",
                )
        # Receipts are local records, not cryptographic attestations from
        # FFmpeg. Reconstruct with our fixed safe renderer (never execute the
        # receipt's command) to reject media from another source/time relabelled
        # beneath a freshly fabricated receipt. Temporary verification media
        # is discarded; both original parent and successful review clip remain.
        with tempfile.TemporaryDirectory(prefix="talkcut-review-verify-") as temporary:
            verified_source = {**parent, **clock, "mapping_verified": True}
            reconstructed = _clip(
                verified_source,
                clip_interval,
                Path(temporary) / "clip",
                deps,
                audio_source=alternate_audio,
            )
            _require(
                reconstructed["clip"]["sha256"] == item["clip"]["sha256"],
                "Actual review clip bytes do not reproduce from the recorded parent interval and toolchain",
            )
    for interval in requested:
        _require(
            not _uncovered(interval, clip_intervals),
            "Requested interval is not present in actual clips",
        )
    for interval in clip_intervals:
        _require(
            not _uncovered(interval, requested),
            "Ledger clip scope differs from executed request intervals",
        )
    return request


def _clip(
    source: dict[str, Any],
    interval: tuple[Fraction, Fraction],
    directory: Path,
    dependencies: dict[str, Any],
    *,
    audio_source: dict[str, Any] | None = None,
    timeout: float = 3600,
) -> dict[str, Any]:
    source_path = _artifact(source, binary=True)
    left, right = interval
    _require(
        as_fraction(source.get("rate", "1")) == 1,
        "Review clip drift/rate correction is unsupported",
    )
    video_shift = as_fraction(source.get("origin", "0")) - as_fraction(
        source.get("offset", "0")
    )
    _require(
        video_shift == 0 or source.get("mapping_verified") is True,
        "Source review clock origin/offset is unverified",
    )
    video_left, video_right = left + video_shift, right + video_shift
    clip_path = directory / "clip.mp4"
    partial = directory / "clip.partial.mp4"
    log = directory / "ffmpeg.log"
    directory.mkdir(parents=True)
    command = [
        "ffmpeg",
        "-hide_banner",
        "-nostdin",
        "-v",
        "error",
        "-xerror",
        "-copyts",
        "-i",
        str(source_path),
    ]
    audio_index = "0:a:0"
    audio_left, audio_right = video_left, video_right
    if audio_source:
        audio_path = _artifact(audio_source, binary=True)
        _require(
            "offset" in audio_source and audio_source.get("mapping_verified") is True,
            "Alternate source review audio requires a verified explicit PTS mapping offset",
        )
        _require(
            as_fraction(audio_source.get("rate", "1")) == 1,
            "Review clip audio drift/rate correction is unsupported",
        )
        shift = as_fraction(audio_source["offset"]) - as_fraction(
            audio_source.get("origin", "0")
        )
        audio_left, audio_right = left - shift, right - shift
        command += ["-i", str(audio_path)]
        audio_index = (
            f"1:{audio_source['stream_index']}"
            if "stream_index" in audio_source
            else "1:a:0"
        )
    # Rational boundaries are converted only at the FFmpeg expression boundary;
    # the request preserves exact source/output times and clip durations.
    decimal = lambda value: f"{float(value):.12f}"
    graph = f"[0:v:0]trim=start={decimal(video_left)}:end={decimal(video_right)},setpts=PTS-({decimal(video_left)})/TB[v];[{audio_index}]atrim=start={decimal(audio_left)}:end={decimal(audio_right)},asetpts=PTS-({decimal(audio_left)})/TB[a]"
    command += [
        "-filter_complex",
        graph,
        "-map",
        "[v]",
        "-map",
        "[a]",
        "-c:v",
        "libx264",
        "-preset",
        "fast",
        "-crf",
        "18",
        "-fps_mode",
        "passthrough",
        "-enc_time_base:v",
        "filter",
        "-c:a",
        "aac",
        "-b:a",
        "192k",
        "-movflags",
        "+faststart",
        "-progress",
        "pipe:1",
        str(partial),
    ]
    started = now()
    try:
        with log.open("x") as handle:
            execution = subprocess.run(
                command, stdout=handle, stderr=handle, timeout=timeout, check=False
            )
        _require(
            execution.returncode == 0 and "progress=end" in log.read_text(),
            "Review clip extraction did not finish",
        )
        metadata = subprocess.run(
            ["ffprobe", "-v", "error", "-show_streams", "-of", "json", str(partial)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        _require(metadata.returncode == 0, "Extracted review clip cannot be probed")
        streams = json.loads(metadata.stdout)["streams"]
        _require(
            {"audio", "video"}.issubset({item["codec_type"] for item in streams}),
            "Actual extracted clip lacks audio/video",
        )
        _require(
            all(
                abs(Fraction(item["duration"]) - (right - left)) <= Fraction(1, 10)
                for item in streams
                if item["codec_type"] in ("audio", "video")
            ),
            "Actual clip duration differs from requested scope",
        )
        _artifact(source, binary=True)
        if audio_source:
            _artifact(audio_source, binary=True)
        partial.rename(clip_path)
        receipt = {
            "schema_version": "execution-receipt/v1",
            "run_id": directory.name,
            "started_at": started,
            "finished_at": now(),
            "completed": True,
            "exit_code": 0,
            "executor": "ffmpeg-review-extraction",
            "tool_version": subprocess.run(
                ["ffmpeg", "-version"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            ).stdout.splitlines()[0],
            "command": command,
            "log": artifact_ref(log),
            "dependencies": dependencies,
            "input_sha256": source["sha256"],
            "output_sha256": sha256(clip_path),
            "interval": [str(left), str(right)],
            "parent_media": artifact_ref(source_path),
            "audio_source": audio_source,
            "video_clock": {
                "origin": str(as_fraction(source.get("origin", "0"))),
                "offset": str(as_fraction(source.get("offset", "0"))),
                "rate": "1",
            },
            "video_native_interval": [str(video_left), str(video_right)],
            "audio_native_interval": [str(audio_left), str(audio_right)],
            "filtergraph": graph,
        }
        atomic_json(directory / "receipt.json", receipt)
        return {
            "clip": artifact_ref(clip_path),
            "parent_sha256": source["sha256"],
            "parent_media": artifact_ref(source_path),
            "interval": [str(left), str(right)],
            "input_modalities": ["audio", "video"],
            "streams": streams,
            "extraction_receipt": artifact_ref(directory / "receipt.json"),
            "selected_audio_sha256": audio_source["sha256"]
            if audio_source
            else source["sha256"],
        }
    except (subprocess.SubprocessError, TalkCutError, OSError, ValueError, KeyError):
        atomic_json(
            directory / "failure.json",
            {
                "schema_version": "review-extraction-failure/v1",
                "status": "UNVERIFIED",
                "command": command,
                "started_at": started,
                "finished_at": now(),
                "partial": str(partial),
                "owner_acceptance": "pending",
            },
        )
        raise


def build_review_bundle(
    project_dir: str | Path,
    timeline: dict[str, Any],
    source: dict[str, Any],
    output: dict[str, Any],
    output_dir: str | Path,
    dependencies: dict[str, Any],
    *,
    audio_source: dict[str, Any] | None = None,
    context_intervals: list[Any] | None = None,
    include_source_analysis: bool = True,
) -> dict[str, Any]:
    """Materialize every deletion, seam and overlapping full-output A/V clip.

    ``context_intervals`` may expand deletion handles to complete sentences or
    activities. Default five-second handles remain pending semantic review.
    """
    _artifact(source, binary=True)
    _artifact(output, binary=True)
    domain = (
        as_fraction(timeline["domain"]["start"]),
        as_fraction(timeline["domain"]["end"]),
    )
    output_domain = Fraction(), as_fraction(timeline["duration"])
    retained = [
        (item["source_start"], item["source_end"]) for item in timeline["retained"]
    ]
    actual_deletions = subtract_intervals(domain, retained)
    directory = Path(output_dir) / f"review-{uuid4().hex}"
    directory.mkdir(parents=True)
    requests: list[dict[str, Any]] = []
    specs: list[tuple[str, tuple[Fraction, Fraction], dict[str, Any]]] = []
    for left, right in actual_deletions:
        span = max(domain[0], left - 5), min(domain[1], right + 5)
        for expanded in context_intervals or []:
            a, b = as_fraction(expanded[0]), as_fraction(expanded[1])
            if a <= left and b >= right:
                span = max(domain[0], min(span[0], a)), min(domain[1], max(span[1], b))
        matching = [
            cut
            for cut in timeline.get("cuts", [])
            if cut.get("status") == "applied"
            and as_fraction(cut["start"]) < right
            and as_fraction(cut["end"]) > left
        ]
        for cut in matching or [None]:
            details: dict[str, Any] = {
                "deleted_interval": [str(left), str(right)],
                "source_domain": [str(domain[0]), str(domain[1])],
                "complete_sentence_context": "UNVERIFIED",
            }
            candidate_span = span
            if cut:
                requested = (
                    as_fraction(cut["requested_start"]),
                    as_fraction(cut["requested_end"]),
                )
                details.update(
                    {
                        "candidate_id": cut["id"],
                        "requested_interval": [str(requested[0]), str(requested[1])],
                    }
                )
                candidate_span = (
                    max(domain[0], min(span[0], requested[0] - 5)),
                    min(domain[1], max(span[1], requested[1] + 5)),
                )
            specs.append(("deletion", candidate_span, details))
    for before, after in pairwise(timeline["retained"]):
        if as_fraction(before["source_end"]) != as_fraction(after["source_start"]):
            seam = as_fraction(after["output_start"])
            specs.append(
                (
                    "seam",
                    (max(Fraction(), seam - 5), min(output_domain[1], seam + 5)),
                    {"seam_time": str(seam)},
                )
            )
    specs += [("output", span, {}) for span in windows(output_domain)]
    if include_source_analysis:
        specs += [("analysis", span, {}) for span in windows(domain)]
    for index, (scope, span, details) in enumerate(specs):
        parent = (
            {
                **source,
                "origin": timeline.get("screen_origin", "0"),
                "offset": "0",
                "mapping_verified": True,
            }
            if scope in ("deletion", "analysis")
            else output
        )
        clip = _clip(
            parent,
            span,
            directory / f"{index:04}-{scope}",
            dependencies,
            audio_source=audio_source if scope in ("deletion", "analysis") else None,
        )
        request = {
            "schema_version": "review-request/v1",
            "request_id": f"{directory.name}-{index:04}",
            "scope": scope,
            "source_sha256": source["sha256"],
            "output_sha256": output["sha256"],
            "input_clip_hashes": [clip["clip"]["sha256"]],
            "inputs": [clip],
            "intervals": [[str(span[0]), str(span[1])]],
            "details": details,
            "dependencies": dependencies,
            "required_modalities": ["audio", "video"],
            "required_response_fields": [
                "observed_intervals",
                "observed_modalities",
                "continuous_video_observed",
                "observed_frame_count",
                "findings",
                "needs_source_comparison",
                "verdict",
                "reason",
            ],
            "status": "UNVERIFIED",
            "owner_acceptance": "pending",
        }
        atomic_json(directory / f"request-{index:04}.json", request)
        requests.append(artifact_ref(directory / f"request-{index:04}.json"))
    bundle = {
        "schema_version": "review-bundle/v1",
        "project_dir": str(Path(project_dir).resolve()),
        "dependencies": dependencies,
        "requests": requests,
        "actual_deletions": [[str(a), str(b)] for a, b in actual_deletions],
        "requested_output_coverage": [
            [str(a), str(b)] for a, b in windows(output_domain)
        ],
        "verified_review_coverage": [],
        "status": "UNVERIFIED",
        "owner_acceptance": "pending",
    }
    atomic_json(directory / "bundle.json", bundle)
    return {**bundle, "artifact_ref": artifact_ref(directory / "bundle.json")}


def import_review(
    response_path: str | Path,
    request_path: str | Path,
    capability_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Preserve raw imports; validate traceability before counting any coverage.

    ``response_path`` is a multimodal-review/v1 envelope identifying an actual
    execution receipt. Its raw provider response is read through that receipt.
    Failed imports are retained with UNVERIFIED/FAIL, never normalized to PASS.
    """
    directory = Path(output_dir) / f"import-{uuid4().hex}"
    directory.mkdir(parents=True)
    refs = {}
    for name, path in (
        ("record", response_path),
        ("request", request_path),
        ("capability", capability_path),
    ):
        target = directory / f"{name}.original.json"
        shutil.copyfile(path, target)
        refs[name] = artifact_ref(target)
    result: dict[str, Any] = {
        "schema_version": "review-import/v1",
        "imported_at": now(),
        "artifact_refs": refs,
        "status": "UNVERIFIED",
        "coverage": [],
        "owner_acceptance": "pending",
    }
    try:
        record, request, capability_record = (
            _artifact(refs[name]) for name in ("record", "request", "capability")
        )
        _require(
            record.get("schema_version") == "multimodal-review/v1",
            "Actual multimodal execution envelope required",
        )
        _require(
            record.get("reviewer_role") == "adversarial_reviewer"
            and record.get("owner_acceptance", "pending") == "pending",
            "Separate AI reviewer cannot claim owner approval",
        )
        capability = _capability(
            capability_record, precision_required=precision_review_required(request)
        )
        execution = _receipt(record.get("receipt"))
        _require(
            execution["model_revision"] == capability["model_revision"],
            "Actual review model capability is unavailable",
        )
        _require(
            record.get("proposer_run_id")
            and record["proposer_run_id"] != execution["run_id"],
            "Proposal and review executions must be separate",
        )
        _require(
            record.get("proposer_prompt_sha256")
            and record["proposer_prompt_sha256"] != execution["prompt_sha256"],
            "Proposal and review instructions must differ",
        )
        executed_request = _artifact(execution["request"])
        _require(
            executed_request.get("input_clip_hashes")
            == request.get("input_clip_hashes")
            and bool(request.get("input_clip_hashes")),
            "Executed request differs from actual review clips",
        )
        _require(
            record.get("dependencies")
            == request.get("dependencies")
            == execution.get("dependencies"),
            "Review artifact dependencies differ",
        )
        for item in request.get("inputs", []):
            _artifact(item["clip"], binary=True)
            _artifact(item["extraction_receipt"])
        response = _artifact(execution["response"])
        if capability.get("precision_supported") is False:
            _require(
                isinstance(response.get("sampling_limitations"), str)
                and len(response["sampling_limitations"].strip()) >= 30
                and response.get("dense_motion_and_lip_verified") is False,
                "Semantic-only response must preserve unknown dense motion/lip inspection and disclose sampling limits",
            )
        _require(
            response.get("verdict") in ("PASS", "FAIL", "UNVERIFIED"),
            "Empty, truncated or malformed review response",
        )
        _require(
            {"audio", "video"}.issubset(response.get("observed_modalities", []))
            and response.get("continuous_video_observed") is True,
            "Actual audiovisual observation missing",
        )
        _require(
            isinstance(response.get("reason"), str)
            and len(response["reason"].strip()) >= 30
            and isinstance(response.get("findings"), list)
            and isinstance(response.get("needs_source_comparison"), bool),
            "Review lacks substantive timed observations/findings",
        )
        expected = [(as_fraction(a), as_fraction(b)) for a, b in request["intervals"]]
        observed = [
            (as_fraction(a), as_fraction(b))
            for a, b in response.get("observed_intervals", [])
        ]
        _require(
            bool(observed) and all(a < b for a, b in observed),
            "No valid observed intervals",
        )
        for span in observed:
            _require(
                not _uncovered(span, expected),
                "Observed timestamp outside actual clip input",
            )
        for span in expected:
            _require(
                not _uncovered(span, observed),
                "Provider response leaves requested media unreviewed",
            )
        _require(
            response.get("needs_source_comparison") is False,
            "Requested source comparison is still unresolved",
        )
        _require(
            not any(
                item.get("severity") in ("P0", "P1")
                and item.get("resolved") is not True
                for item in response["findings"]
            ),
            "Unresolved P0/P1 review finding",
        )
        _require(
            {
                "source_hashes",
                "contract_hash",
                "code_tree_hash",
                "timeline_hash",
                "output_hash",
            }.issubset(request.get("dependencies", {})),
            "Required source/code/contract/timeline/output dependencies are missing",
        )
        _require(
            record.get("capability", {}).get("sha256") == refs["capability"]["sha256"],
            "Review envelope refers to another capability execution",
        )
        _require(
            bool(request.get("inputs"))
            and {item["clip"]["sha256"] for item in request["inputs"]}
            == set(request["input_clip_hashes"]),
            "Actual input clips are missing from review request",
        )
        for item in request["inputs"]:
            extraction = _artifact(item["extraction_receipt"])
            _require(
                extraction.get("completed") is True
                and extraction.get("exit_code") == 0
                and extraction.get("output_sha256") == item["clip"]["sha256"]
                and extraction.get("input_sha256") == item["parent_sha256"],
                "Clip extraction does not bind observed bytes to the claimed parent",
            )
        validate_review_request(record, execution)
        result.update(
            {
                "status": response["verdict"],
                "coverage": response["observed_intervals"]
                if response["verdict"] == "PASS"
                else [],
                "provider_execution": record["receipt"],
                "reason": response["reason"],
            }
        )
    except (
        TalkCutError,
        ValueError,
        KeyError,
        TypeError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        result["reason"] = str(exc)
    atomic_json(directory / "import.json", result)
    return {**result, "artifact_ref": artifact_ref(directory / "import.json")}


def authorize_candidate_review(
    import_ref: dict[str, str], candidate: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    """Revalidate current media/provider evidence and bind it to this exact cut.

    An old import's PASS is never trusted. Revalidation preserves a new receipt
    while the original provider request and response remain immutable.
    """
    from .contracts import code_identity

    proof = verify_imported_review(import_ref)
    _require(
        not plan.get("test_only") and not candidate.get("test_only"),
        "Fixture review cannot authorize final edits",
    )
    record, request, execution, response = (
        proof[key] for key in ("record", "request", "receipt", "response")
    )
    _require(
        request.get("scope") == "deletion",
        "An unrelated output review cannot authorize a deletion",
    )
    details = request.get("details", {})
    requested = as_fraction(candidate["start"]), as_fraction(candidate["end"])
    _require(
        details.get("candidate_id") == candidate.get("id")
        and [as_fraction(value) for value in details.get("requested_interval", [])]
        == list(requested),
        "Review request targets a different candidate or boundary",
    )
    _require(
        record.get("proposer_run_id") == candidate.get("proposer_run_id")
        and execution["run_id"] != candidate.get("proposer_run_id"),
        "Review is not separate from this candidate's actual proposal",
    )
    deps = request.get("dependencies", {})
    _require(
        deps.get("source_hashes") == plan.get("source_hashes")
        and bool(plan.get("source_hashes")),
        "Review source identities differ from current plan",
    )
    _require(
        deps.get("plan_hash") == content_hash(plan),
        "Review was executed for a different plan revision",
    )
    _require(
        deps.get("code_tree_hash") == code_identity(Path.cwd())["code_tree_hash"],
        "Review execution code has changed",
    )
    contract_hash = plan.get("contract_hash") or plan.get("dependencies", {}).get(
        "contract_hash"
    )
    _require(
        contract_hash and deps.get("contract_hash") == contract_hash,
        "Review contract differs from current frozen plan contract",
    )
    inspected = _artifact(plan.get("inspection_refs", {}).get("screen"))
    _require(
        inspected.get("sha256") == plan["source_hashes"]["screen"],
        "Plan source inspection is stale",
    )
    origin = as_fraction(plan.get("timing", {}).get("screen_origin", "0"))
    domain = [as_fraction(value) - origin for value in inspected["video"]["coverage"]]
    _require(
        [as_fraction(value) for value in details.get("source_domain", [])] == domain,
        "Review source denominator differs from measured screen",
    )
    context = max(domain[0], requested[0] - 5), min(domain[1], requested[1] + 5)
    intervals = [
        (as_fraction(a), as_fraction(b)) for a, b in request.get("intervals", [])
    ]
    _require(
        not _uncovered(context, intervals),
        "Review clips omit required complete candidate context",
    )
    _require(
        response.get("candidate_id") == candidate["id"]
        and response.get("candidate_decision") == "approve_deletion"
        and response.get("complete_sentence_context") is True,
        "Provider did not explicitly approve this deletion with complete sentence context",
    )
    for protected in plan.get("protected_intervals", []):
        _require(
            requested[1] <= as_fraction(protected["start"])
            or requested[0] >= as_fraction(protected["end"]),
            "Reviewed deletion overlaps protected learning activity",
        )
    for item in request["inputs"]:
        _require(
            item.get("parent_sha256") == plan["source_hashes"]["screen"],
            "Deletion clip is not derived from current screen source",
        )
    return {
        "actor": "delegated_ai_reviewer",
        "candidate_id": candidate["id"],
        "requested_interval": [str(value) for value in requested],
        "review": import_ref,
        "revalidated_import": proof["import"]["artifact_ref"],
        "provider_execution": record["receipt"],
        "source_hashes": plan["source_hashes"],
        "plan_hash": content_hash(plan),
        "run_id": execution["run_id"],
        "at": now(),
    }


def verify_imported_review(import_ref: dict[str, str]) -> dict[str, Any]:
    """Revalidate raw immutable provider inputs for candidate or sync decisions."""
    imported = _artifact(import_ref)
    _require(
        imported.get("schema_version") == "review-import/v1",
        "A preserved validated review import is required",
    )
    refs = imported.get("artifact_refs", {})
    for name in ("record", "request", "capability"):
        _artifact(refs.get(name))
    revalidated = import_review(
        refs["record"]["path"],
        refs["request"]["path"],
        refs["capability"]["path"],
        Path(import_ref["path"]).parent / "revalidations",
    )
    _require(
        revalidated["status"] == "PASS",
        "Original provider review failed current validation: "
        + revalidated.get("reason", "missing proof"),
    )
    record = _artifact(refs["record"])
    execution = _receipt(record["receipt"])
    return {
        "import": revalidated,
        "record": record,
        "request": _artifact(refs["request"]),
        "capability": _artifact(refs["capability"]),
        "receipt": execution,
        "response": _artifact(execution["response"]),
    }


def verify_artifact_audit(
    audit_ref: dict[str, str],
    *,
    scope: str,
    snapshot_ref: dict[str, str],
    input_refs: list[dict[str, str]],
    dependencies: dict[str, Any],
    excluded_run_ids: set[str],
) -> dict[str, Any]:
    """Bind a separate artifact auditor to the exact submitted snapshot bytes.

    This validates preserved provider provenance, not a cryptographic attestation
    of remote execution. Callers must still validate the audit's domain-specific
    observations (for example every inventory classification). Media judgments
    additionally require the audiovisual review/capability path.
    """
    from datetime import datetime

    envelope = _artifact(audit_ref)
    _require(
        envelope.get("schema_version") == "artifact-audit/v1"
        and envelope.get("reviewer_role") == "independent_auditor",
        "Typed independent artifact audit is missing",
    )
    snapshot = _artifact(snapshot_ref)
    _require(isinstance(snapshot, dict), "Audit snapshot must be an object")
    _require(bool(input_refs), "Audit cannot certify an empty input inventory")
    for ref in input_refs:
        _artifact(ref, binary=True)
    execution = _receipt(envelope.get("receipt"))
    request, response = (
        _artifact(execution["request"]),
        _artifact(execution["response"]),
    )
    _require(
        bool(excluded_run_ids)
        and execution["run_id"] not in excluded_run_ids
        and execution["run_id"] == envelope.get("reviewer_run_id"),
        "Auditor is not separate from the actual implementation/proposal",
    )
    started, finished = (
        datetime.fromisoformat(execution[key]) for key in ("started_at", "finished_at")
    )
    _require(
        started.tzinfo is not None
        and finished.tzinfo is not None
        and finished >= started,
        "Auditor execution times are incomplete or reversed",
    )
    _require(
        dependencies
        and envelope.get("dependencies")
        == execution.get("dependencies")
        == request.get("dependencies")
        == dependencies,
        "Audit dependency snapshot differs from the current inputs",
    )
    _require(
        request.get("scope") == scope
        and request.get("snapshot_hash")
        == response.get("snapshot_hash")
        == envelope.get("snapshot_hash")
        == snapshot_ref["sha256"],
        "Actual auditor request/response targets a different snapshot or scope",
    )
    submitted = request.get("input_artifacts", [])
    _require(isinstance(submitted, list) and submitted, "No actual audit inputs")
    for ref in submitted:
        _artifact(ref, binary=True)
    expected = {ref["sha256"] for ref in [snapshot_ref, *input_refs]}
    actual = {ref["sha256"] for ref in submitted}
    _require(
        expected == actual
        and len(actual) == len(submitted)
        and set(response.get("inspected_artifact_hashes", [])) == expected,
        "Auditor did not receive and inspect the entire exact artifact inventory",
    )
    _require(
        response.get("verdict") == "PASS"
        and isinstance(response.get("reason"), str)
        and len(response["reason"].strip()) >= 30
        and isinstance(response.get("findings"), list),
        "Audit has no substantive completed findings",
    )
    _require(
        all(
            isinstance(finding, dict)
            and finding.get("severity") in {"P0", "P1", "P2", "P3"}
            and finding.get("reason")
            and finding.get("severity") not in {"P0", "P1"}
            for finding in response["findings"]
        ),
        "Artifact audit retains unresolved or unrecognized findings",
    )
    return {
        "envelope": envelope,
        "snapshot": snapshot,
        "receipt": execution,
        "request": request,
        "response": response,
    }


def register_review_import(
    project_dir: Path, import_ref: dict[str, str], repo_root: Path
) -> dict[str, Any]:
    """Index revalidated actual review/capability refs without issuing readiness.

    The original index is preserved before an atomic, revision-checked update.
    Source-sync reviews remain source-anchor evidence and do not acquire final
    output coverage by being indexed.
    """
    from .contracts import code_identity, verify_contract
    from .project import load_project, project_lock

    project_dir, repo_root = project_dir.resolve(), repo_root.resolve()
    project_path, index_path = (
        project_dir / "project.json",
        project_dir / "acceptance.local.json",
    )
    initial_hash = sha256(project_path)
    project = load_project(project_dir)
    identity = code_identity(repo_root)
    contract_path = project_dir / "frozen-contract.local.json"
    contract = read_json(contract_path)
    _require(
        not verify_contract(contract, repo_root), "Current frozen contract is invalid"
    )
    proof = verify_imported_review(import_ref)
    record, request = proof["record"], proof["request"]
    _require(
        record.get("schema_version") == "multimodal-review/v1"
        and record.get("reviewer_role") == "adversarial_reviewer"
        and record.get("owner_acceptance", "pending") == "pending"
        and not record.get("test_only")
        and not record.get("synthetic"),
        "Only actual adversarial imports can enter the project review index",
    )
    expected = {
        "source_hashes": {
            role: item["sha256"] for role, item in project["sources"].items()
        },
        "code_tree_hash": identity["code_tree_hash"],
        "contract_hash": sha256(contract_path),
    }
    deps = request["dependencies"]
    _require(
        all(deps.get(key) == value for key, value in expected.items()),
        "Imported review does not belong to current registered sources/code/contract",
    )
    scope = request.get("scope")
    _require(
        scope
        in {
            "output",
            "deletion",
            "seam",
            "analysis",
            "layout",
            "lip_sync",
            "source_sync",
        },
        "Unknown project review scope",
    )
    if scope != "source_sync":
        plan_ref, timeline_ref, render_ref = (
            project[key] for key in ("active_plan", "active_timeline", "active_render")
        )
        plan, timeline, render = (
            _artifact(ref) for ref in (plan_ref, timeline_ref, render_ref)
        )
        _artifact(render["output"], binary=True)
        _require(
            deps.get("plan_hash") == content_hash(plan)
            and deps.get("timeline_hash") == timeline_ref["sha256"]
            and deps.get("output_hash") == render["output"]["sha256"]
            and timeline.get("plan_hash") == content_hash(plan)
            and render.get("settings", {}).get("timeline") == timeline_ref
            and render.get("settings", {}).get("plan") == plan_ref,
            "Imported review targets an old plan, timeline or output",
        )
    imported = _artifact(import_ref)
    record_ref = imported["artifact_refs"]["record"]
    capability_ref = imported["artifact_refs"]["capability"]
    # The same authority used by final evaluation validates the capability. This
    # never constructs a capability PASS from the import envelope's status.
    from .acceptance import Evaluator

    validator = Evaluator(
        project_dir, "review-index-registration", contract_path, repo_root
    )
    validator.deps = {**deps}
    validator.load_capability(capability_ref)
    if scope != "source_sync":
        validator.index = read_json(index_path)
        validator.bind_plan_timeline()
        validator.source_domain = (
            as_fraction(validator.timeline["domain"]["start"]),
            as_fraction(validator.timeline["domain"]["end"]),
        )
        validator.output_domain = (
            Fraction(),
            as_fraction(validator.timeline["duration"]),
        )
        validator.load_review(record_ref)
    with project_lock(project_dir):
        _require(
            sha256(project_path) == initial_hash,
            "Project changed while the review was revalidated",
        )
        _require(
            code_identity(repo_root)["code_tree_hash"] == identity["code_tree_hash"],
            "Code changed while the review was revalidated",
        )
        index = read_json(index_path)
        _require(
            index.get("schema_version") == "acceptance-index/v1"
            and index.get("owner_acceptance", "pending") == "pending",
            "Existing private acceptance index is invalid",
        )
        before = artifact_ref(index_path)
        backup = project_dir / "evidence" / "index-history" / f"{before['sha256']}.json"
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            with backup.open("xb") as handle:
                handle.write(index_path.read_bytes())
        _require(sha256(backup) == before["sha256"], "Acceptance index backup differs")
        if capability_ref not in index.setdefault("capabilities", []):
            index["capabilities"].append(capability_ref)
        if scope != "source_sync" and record_ref not in index.setdefault("reviews", []):
            index["reviews"].append(record_ref)
        atomic_json(index_path, index)
    result = {
        "schema_version": "review-registration/v1",
        "status": "INDEXED",
        "import": import_ref,
        "record": record_ref,
        "capability": capability_ref,
        "scope": scope,
        "project_revision": project["revision"],
        "previous_index": artifact_ref(backup),
        "index": artifact_ref(index_path),
        "acceptance_status": "UNVERIFIED",
        "owner_acceptance": "pending",
    }
    directory = project_dir / "review" / f"registration-{uuid4().hex}"
    atomic_json(directory / "registration.json", result)
    return {**result, "artifact_ref": artifact_ref(directory / "registration.json")}
