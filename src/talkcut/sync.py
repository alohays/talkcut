"""Measured audio correlation anchors; never substitutes for visual/lip sync."""

from __future__ import annotations

import subprocess
import time
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from typing import Any

import numpy as np

from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    load_project,
    now,
    project_lock,
    save_revision,
    verified_json,
)


def pcm_window(
    path: str,
    stream_index: int,
    start: Fraction,
    duration: int = 20,
    sample_rate: int = 16000,
) -> np.ndarray:
    result = subprocess.run(
        [
            "ffmpeg",
            "-v",
            "error",
            "-nostdin",
            "-ss",
            str(float(start)),
            "-i",
            path,
            "-map",
            f"0:{stream_index}",
            "-t",
            str(duration),
            "-ac",
            "1",
            "-ar",
            str(sample_rate),
            "-f",
            "f32le",
            "pipe:1",
        ],
        capture_output=True,
        timeout=120,
        check=False,
    )
    if result.returncode:
        raise TalkCutError(
            "AUDIO_EXTRACTION_FAILED", result.stderr.decode(errors="replace")
        )
    return np.frombuffer(result.stdout, dtype="<f4").astype(np.float64)


def correlate(
    reference: np.ndarray, other: np.ndarray, rate: int, max_lag: float = 1
) -> dict[str, Any]:
    size = min(len(reference), len(other))
    if size < rate:
        raise TalkCutError(
            "ANCHOR_TOO_SHORT", "At least one second of shared audio required"
        )
    x, y = reference[:size].copy(), other[:size].copy()
    x -= x.mean()
    y -= y.mean()
    energy = np.linalg.norm(x) * np.linalg.norm(y)
    if energy < 1e-10:
        return {"status": "UNVERIFIED", "reason": "No measurable audio energy"}
    n = 1 << (2 * size - 1).bit_length()
    values = np.fft.irfft(np.fft.rfft(x, n) * np.conj(np.fft.rfft(y, n)), n)
    limit = int(max_lag * rate)
    lags = np.arange(-limit, limit + 1)
    correlations = values[lags % n] / energy
    best = int(np.argmax(correlations))
    lag = int(lags[best])
    alternatives = correlations[np.abs(lags - lag) > rate * 0.01]
    secondary_peak = float(np.max(alternatives)) if len(alternatives) else 0.0
    ambiguous = secondary_peak >= float(correlations[best]) * 0.98
    # Re-estimate independent subwindows; variation is a measured bound, not confidence.
    block_lags = []
    if size >= rate * 4:
        for start in range(0, size - rate * 2 + 1, rate * 2):
            a, b = x[start : start + rate * 2], y[start : start + rate * 2]
            m = 1 << (4 * rate - 1).bit_length()
            v = np.fft.irfft(np.fft.rfft(a, m) * np.conj(np.fft.rfft(b, m)), m)
            block_lags.append(int(lags[int(np.argmax(v[lags % m]))]))
    spread = max((abs(v - lag) for v in block_lags), default=0)
    return {
        "status": "PASS"
        if correlations[best] >= 0.9 and spread <= rate * 0.005 and not ambiguous
        else "UNVERIFIED",
        "ambiguous_repeated_signal": ambiguous,
        "secondary_peak_outside_10ms": secondary_peak,
        "lag_samples": lag,
        "lag_seconds": str(Fraction(lag, rate)),
        "normalized_correlation": float(correlations[best]),
        "uncertainty_seconds": str(Fraction(spread + 1, rate)),
        "uncertainty_method": "Maximum independent two-second subwindow lag deviation plus one resampled sample",
        "subwindow_lags": block_lags,
        "sample_rate": rate,
    }


def analyze_project(directory: str | Path) -> dict[str, Any]:
    directory = Path(directory)
    with project_lock(directory):
        project = load_project(directory)
        if not all(role in project["inspections"] for role in ("screen", "speaker")):
            raise TalkCutError("INSPECTION_REQUIRED", "Run inspect --full-decode first")
        inspections = {
            role: verified_json(project["inspections"][role])
            for role in ("screen", "speaker")
        }
        if any(value["status"] != "PASS" for value in inspections.values()):
            raise TalkCutError(
                "INPUT_UNVERIFIED", "Resolve source decode/PTS findings first"
            )
        for role, inspected in inspections.items():
            if inspected.get("sha256") != project["sources"][role]["sha256"]:
                raise TalkCutError(
                    "SOURCE_CHANGED", "Inspection belongs to different source bytes"
                )
            if any(
                Fraction(inspected[kind]["coverage"][0]) != 0
                for kind in ("audio", "video")
            ):
                raise TalkCutError(
                    "UNSUPPORTED_TIMING",
                    "Audio anchor analysis currently requires measured zero source origins; nonzero timing is not silently normalized",
                )
        end = min(Fraction(v["audio"]["coverage"][1]) for v in inspections.values())
        if end < 45:
            raise TalkCutError(
                "ANCHOR_DOMAIN_TOO_SHORT",
                "This full-lecture audio anchor profile requires at least 45 seconds",
            )
        points = sorted(
            {
                Fraction(10),
                *[Fraction(t) for t in range(300, int(end) - 25, 300)],
                end - 25,
            }
        )
        started = time.monotonic()
        anchors = []
        for index, start in enumerate(points):
            signals = {
                role: pcm_window(
                    project["sources"][role]["path"], value["audio"]["index"], start
                )
                for role, value in inspections.items()
            }
            result = correlate(signals["screen"], signals["speaker"], 16000)
            anchors.append(
                {
                    "start": str(start),
                    "end": str(start + 20),
                    "role": "fit" if index % 2 == 0 else "holdout",
                    **result,
                }
            )
        good = [a for a in anchors if a["status"] == "PASS"]
        fit = [a for a in good if a["role"] == "fit"]
        offset = (
            sorted(Fraction(a["lag_seconds"]) for a in fit)[len(fit) // 2]
            if fit
            else None
        )
        for anchor in good:
            anchor["residual_seconds"] = (
                str(Fraction(anchor["lag_seconds"]) - offset)
                if offset is not None
                else None
            )
        report = {
            "schema_version": "audio-sync-analysis/v1",
            "created_at": now(),
            "status": "UNVERIFIED",
            "source_hashes": {k: v["sha256"] for k, v in project["sources"].items()},
            "inspection_refs": project["inspections"],
            "anchors": anchors,
            "speaker_audio_to_screen_audio_offset": str(offset)
            if offset is not None
            else None,
            "sign_convention": "positive lag places speaker audio event later on screen audio presentation timeline",
            "audio_source_selection": None,
            "speaker_video_mapping": None,
            "lip_sync": "UNVERIFIED",
            "visual_event_sync": "UNVERIFIED",
            "wall_seconds": time.monotonic() - started,
            "limitations": [
                "Audio correlation is not video synchronization",
                "Subsample lip alignment requires a capable audiovisual reviewer",
            ],
        }
        path = directory / "evidence" / f"audio-sync-r{project['revision']}.json"
        atomic_json(path, report)
        project["sync_analysis"] = artifact_ref(path)
        save_revision(
            directory,
            project,
            project["revision"],
            "sync_analyze",
            {"report": artifact_ref(path)},
        )
        return report


def verify_sync_model(ref: dict[str, str], project: dict[str, Any]) -> dict[str, Any]:
    """Adopt only measured mapping with separate executed AV anchor review.

    This is a source synchronization gate. Output anchors remain mandatory in
    final acceptance; an approved source model never certifies rendered sync.
    """
    from .review import verify_imported_review
    from .timeline import as_fraction

    model = verified_json(ref)
    source_hashes = {k: v["sha256"] for k, v in project["sources"].items()}
    if (
        model.get("schema_version") != "sync-model/v1"
        or model.get("source_hashes") != source_hashes
        or model.get("status") != "PASS"
        or model.get("test_only")
    ):
        raise TalkCutError(
            "SYNC_UNVERIFIED",
            "A current measured audiovisual sync-model/v1 is required",
        )
    timing = model.get("timing", {})
    if timing.get("status") != "PASS" or timing.get("audio_source") not in (
        "screen",
        "speaker",
    ):
        raise TalkCutError(
            "AUDIO_UNVERIFIED", "Select one verified source audio stream"
        )
    for key in ("audio_rate", "speaker_rate"):
        if as_fraction(timing.get(key)) != 1:
            raise TalkCutError(
                "UNSUPPORTED_TIMING",
                "Drift correction is not implemented; a non-unit clock rate cannot be adopted",
            )
    inspections = {
        role: verified_json(project["inspections"][role])
        for role in ("screen", "speaker")
    }
    domain_end = as_fraction(inspections["screen"]["video"]["coverage"][1])
    # This profile does not quietly normalize nonzero source origins.
    for key in ("screen_origin", "audio_origin", "speaker_origin"):
        if as_fraction(timing.get(key)) != 0:
            raise TalkCutError(
                "UNSUPPORTED_TIMING",
                "Verified source model currently requires zero shared origins",
            )
    for key in ("audio_offset", "speaker_offset"):
        as_fraction(timing.get(key))
    anchors = model.get("anchors", [])
    seen_ids: set[str] = set()
    seen_requests: set[tuple[str, str]] = set()
    for kind, residual_limit in (("audio", 20), ("lip", 80), ("visual", 40)):
        selected = [a for a in anchors if a.get("kind") == kind]
        if not selected or not {"fit", "holdout"}.issubset(
            {a.get("role") for a in selected}
        ):
            raise TalkCutError(
                "SYNC_UNVERIFIED",
                f"Separate fit and holdout {kind} anchors are required",
            )
        times = sorted(as_fraction(a["time"]) for a in selected)
        if (
            times[0] < 0
            or times[-1] > domain_end
            or times[0] > 60
            or times[-1] < domain_end - 60
            or any(b - a > 600 for a, b in pairwise(times))
        ):
            raise TalkCutError(
                "SYNC_UNVERIFIED",
                f"Beginning/middle/end {kind} anchor coverage is incomplete",
            )
        residuals = []
        local_frame_bounds = []
        for anchor in selected:
            reviewed = verify_imported_review(anchor["review_ref"])
            request, response = reviewed["request"], reviewed["response"]
            details = request.get("details", {})
            measured = response.get("measurements", {})
            anchor_time = as_fraction(anchor["time"])
            anchor_id = anchor.get("id")
            request_identity = (kind, str(request.get("request_id")))
            if (
                not isinstance(anchor_id, str)
                or not anchor_id
                or anchor_id in seen_ids
                or request_identity in seen_requests
                or not request.get("request_id")
            ):
                raise TalkCutError(
                    "SYNC_UNVERIFIED", "Duplicate or missing anchor/request identity"
                )
            seen_ids.add(anchor_id)
            seen_requests.add(request_identity)
            if (
                details.get("kind") != kind
                or details.get("role") != anchor.get("role")
                or as_fraction(details.get("anchor_time")) != anchor_time
                or not any(
                    as_fraction(a) <= anchor_time < as_fraction(b)
                    for a, b in request.get("intervals", [])
                )
            ):
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Anchor time/kind/fit role is not the actually reviewed interval",
                )
            parent_hashes = {
                item.get("parent_sha256") for item in request.get("inputs", [])
            }
            if not {source_hashes["screen"], source_hashes["speaker"]}.issubset(
                parent_hashes
            ):
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Synchronization requires current screen and speaker source evidence",
                )
            if (
                request.get("scope") != "sync"
                or details.get("anchor_id") != anchor.get("id")
                or request.get("dependencies", {}).get("source_hashes") != source_hashes
                or details.get("timing") != timing
                or response.get("verdict") != "PASS"
                or measured != anchor.get("measurements")
            ):
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Anchor is not bound to the reviewed source, mapping and actual measurements",
                )
            if not measured.get("uncertainty_method"):
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Measurement uncertainty requires an observation method",
                )
            residual = Fraction(str(measured["residual_ms"]))
            uncertainty = Fraction(str(measured["uncertainty_ms"]))
            local_frame = Fraction(str(measured["local_frame_duration_ms"]))
            frame_limits = []
            for role in ("screen", "speaker"):
                video = inspections[role]["video"]
                tb = as_fraction(video["time_base"])
                source_time = anchor_time - (
                    as_fraction(timing["speaker_offset"]) if role == "speaker" else 0
                )
                frame = next(
                    (
                        f
                        for f in video["frames"]
                        if f["pts"] * tb
                        <= source_time
                        < (f["pts"] + f["duration"]) * tb
                    ),
                    None,
                )
                if frame is None:
                    raise TalkCutError(
                        "SYNC_UNVERIFIED",
                        "Anchor falls outside measured source frame coverage",
                    )
                frame_limits.append(frame["duration"] * tb * 1000)
            if local_frame != min(frame_limits):
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Reported local frame bound differs from actual source PTS schedule",
                )
            if (
                uncertainty < 0
                or local_frame <= 0
                or abs(residual) + uncertainty > residual_limit
                or (kind == "lip" and uncertainty > 40)
            ):
                raise TalkCutError(
                    "SYNC_UNVERIFIED",
                    "Anchor residual/uncertainty exceeds the frozen sync criteria",
                )
            residuals.append((residual, uncertainty))
            local_frame_bounds.append(local_frame)
        drift_bound = max(r + u for r, u in residuals) - min(
            r - u for r, u in residuals
        )
        if drift_bound > min(Fraction(40), min(local_frame_bounds)):
            raise TalkCutError(
                "SYNC_UNVERIFIED",
                "Observed drift bound exceeds one local frame or 40ms",
            )
    return model
