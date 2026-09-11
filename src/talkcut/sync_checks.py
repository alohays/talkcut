"""Cross-check actual source and final-output synchronization anchors.

sync-input/v1 contains project, model, workflow_render and output_anchors refs.
output-sync-anchors/v1 contains dependencies and output anchor records with
kind/role/id/source_time/output_time/review_ref/measurements. Audio anchors also
require audio_measurement pointing to output-audio-anchor/v1 raw PCM evidence.
Source/audio correlation alone cannot authorize lip or visual synchronization.
"""

from __future__ import annotations

import subprocess
from fractions import Fraction
from itertools import pairwise
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import numpy as np

from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    load_project,
    now,
    sha256,
    verified_json,
)
from .review import verify_imported_review
from .sync import correlate, verify_sync_model
from .timeline import as_fraction, source_to_output


def _require(condition: Any, reason: str) -> None:
    if not condition:
        raise TalkCutError("SYNC_UNVERIFIED", reason)


def _file(ref: dict[str, Any]) -> Path:
    path = Path(ref["path"])
    _require(
        path.is_absolute() and path.is_file() and sha256(path) == ref["sha256"],
        "Sync artifact is missing or stale",
    )
    return path


def _pcm(
    path: Path,
    stream: int,
    start: Fraction,
    duration: Fraction,
    directory: Path,
    name: str,
) -> tuple[np.ndarray, dict[str, Any]]:
    target, log = directory / f"{name}.f32le", directory / f"{name}.stderr.log"
    command = [
        "ffmpeg",
        "-v",
        "error",
        "-nostdin",
        "-n",
        "-ss",
        str(float(start)),
        "-i",
        str(path),
        "-map",
        f"0:{stream}",
        "-t",
        str(float(duration)),
        "-ac",
        "1",
        "-ar",
        "16000",
        "-f",
        "f32le",
        str(target),
    ]
    started = now()
    with log.open("wb") as err:
        result = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=err, timeout=120, check=False
        )
    receipt = {
        "command": command,
        "started_at": started,
        "finished_at": now(),
        "exit_code": result.returncode,
        "parent": artifact_ref(path),
        "interval": [str(start), str(start + duration)],
        "stream_index": stream,
        "sample_rate": 16000,
        "stderr": artifact_ref(log),
    }
    _require(result.returncode == 0, "Actual PCM anchor extraction failed")
    receipt["output"] = artifact_ref(target)
    return np.fromfile(target, dtype="<f4").astype(np.float64), receipt


def _window(
    project: dict[str, Any], render: dict[str, Any], source_interval: list[Any]
) -> dict[str, Any]:
    plan = verified_json(render["settings"]["plan"])
    timeline = verified_json(render["settings"]["timeline"])
    a, b = (as_fraction(x) for x in source_interval)
    _require(
        a < b and b - a >= 4,
        "At least four continuous retained seconds are required for audio uncertainty",
    )
    retained = next(
        (
            span
            for span in timeline["retained"]
            if as_fraction(span["source_start"])
            <= a
            < b
            <= as_fraction(span["source_end"])
        ),
        None,
    )
    _require(
        retained is not None,
        "Audio anchor window crosses a deletion or lies outside retained source",
    )
    assert retained is not None
    timing = plan["timing"]
    _require(
        as_fraction(timing["audio_rate"]) == 1, "Unsupported output audio clock rate"
    )
    role = timing["audio_source"]
    source = project["sources"][role]
    audio = verified_json(project["inspections"][role])["audio"]
    output_start = (
        as_fraction(retained["output_start"])
        + a
        - as_fraction(retained["source_start"])
    )
    native_start = (
        a - as_fraction(timing["audio_offset"]) + as_fraction(timing["audio_origin"])
    )
    native = verified_json(render["native_render"])
    output_stream = next(
        stream["index"]
        for stream in native["validation"]["streams"]
        if stream["codec_type"] == "audio"
    )
    return {
        "source": source,
        "source_stream": audio["index"],
        "source_start": native_start,
        "output_stream": output_stream,
        "output_start": output_start,
        "duration": b - a,
        "dependencies": {
            "source_hashes": {k: v["sha256"] for k, v in project["sources"].items()},
            "plan_hash": content_hash(plan),
            "timeline_hash": render["settings"]["timeline"]["sha256"],
            "output_hash": render["output"]["sha256"],
        },
    }


def measure_output_audio(
    project_dir: Path,
    workflow_render_ref: dict[str, str],
    source_interval: list[Any],
    directory: Path,
) -> dict[str, Any]:
    project, workflow = load_project(project_dir), verified_json(workflow_render_ref)
    window = _window(project, workflow, source_interval)
    _require(
        not directory.exists() or not any(directory.iterdir()),
        "Choose a new anchor directory",
    )
    directory.mkdir(parents=True, exist_ok=True)
    source, source_receipt = _pcm(
        _file(window["source"]),
        window["source_stream"],
        window["source_start"],
        window["duration"],
        directory,
        "source",
    )
    output, output_receipt = _pcm(
        _file(workflow["output"]),
        window["output_stream"],
        window["output_start"],
        window["duration"],
        directory,
        "output",
    )
    measurements = correlate(source, output, 16000, max_lag=0.1)
    value = {
        "schema_version": "output-audio-anchor/v1",
        "status": measurements["status"],
        "workflow_render": workflow_render_ref,
        "source_interval": [str(as_fraction(x)) for x in source_interval],
        "output_interval": [
            str(window["output_start"]),
            str(window["output_start"] + window["duration"]),
        ],
        "dependencies": window["dependencies"],
        "source_pcm": source_receipt,
        "output_pcm": output_receipt,
        "measurements": measurements,
        "source_to_output_only": True,
        "lip_sync": "UNVERIFIED",
        "owner_acceptance": "pending",
    }
    atomic_json(directory / "anchor.json", value)
    return {**value, "artifact_ref": artifact_ref(directory / "anchor.json")}


def _verify_audio(
    ref: dict[str, str], project: dict[str, Any], render: dict[str, Any]
) -> dict[str, Any]:
    raw = verified_json(ref)
    _require(
        raw.get("schema_version") == "output-audio-anchor/v1",
        "Actual source/output PCM anchor is required",
    )
    _require(
        verified_json(raw["workflow_render"]) == render,
        "Audio measurement belongs to another actual workflow render",
    )
    window = _window(project, render, raw["source_interval"])
    _require(
        raw.get("dependencies") == window["dependencies"],
        "Audio anchor mapping or media dependencies changed",
    )
    actual_output = [
        str(window["output_start"]),
        str(window["output_start"] + window["duration"]),
    ]
    _require(
        raw.get("output_interval") == actual_output,
        "Audio anchor output window is not the retained source mapping",
    )
    arrays = []
    with TemporaryDirectory(prefix="talkcut-verify-audio-") as directory:
        for name, path, stream, start in (
            (
                "source",
                _file(window["source"]),
                window["source_stream"],
                window["source_start"],
            ),
            (
                "output",
                _file(render["output"]),
                window["output_stream"],
                window["output_start"],
            ),
        ):
            recorded = raw[f"{name}_pcm"]
            array, execution = _pcm(
                path, stream, start, window["duration"], Path(directory), name
            )
            _require(
                recorded.get("exit_code") == 0
                and recorded.get("parent") == execution["parent"]
                and recorded.get("interval") == execution["interval"]
                and recorded.get("stream_index") == stream,
                "PCM receipt was relabelled to a different media interval",
            )
            _file(recorded["stderr"])
            _require(
                sha256(_file(recorded["output"])) == execution["output"]["sha256"],
                "Recorded PCM bytes differ from actual media re-extraction",
            )
            arrays.append(array)
    measured = correlate(arrays[0], arrays[1], 16000, max_lag=0.1)
    _require(
        measured == raw.get("measurements") and measured["status"] == "PASS",
        "Actual audio correlation is uncertain or differs from reported result",
    )
    return measured


def _bind_audio_anchor(
    raw: dict[str, Any], source_time: Fraction, output_time: Fraction
) -> None:
    _require(
        as_fraction(raw["source_interval"][0])
        <= source_time
        < as_fraction(raw["source_interval"][1])
        and as_fraction(raw["output_interval"][0])
        <= output_time
        < as_fraction(raw["output_interval"][1]),
        "Audio PCM measurement did not observe this source/output anchor event",
    )


def _frame_bound(
    project: dict[str, Any], timing: dict[str, Any], source_time: Fraction
) -> Fraction:
    bounds = []
    for role in ("screen", "speaker"):
        video = verified_json(project["inspections"][role])["video"]
        tb = as_fraction(video["time_base"])
        native = source_time - as_fraction(
            timing["speaker_offset"] if role == "speaker" else 0
        )
        frame = next(
            (
                f
                for f in video["frames"]
                if f["pts"] * tb <= native < (f["pts"] + f["duration"]) * tb
            ),
            None,
        )
        _require(
            frame is not None,
            "Output anchor has no actual source frame at its mapped time",
        )
        assert frame is not None
        bounds.append(frame["duration"] * tb * 1000)
    return min(bounds)


def _anchor_coverage(
    anchors: list[dict[str, Any]], end: Fraction, clock: str
) -> Fraction:
    times = sorted(as_fraction(a[clock]) for a in anchors)
    _require(
        times
        and times[0] >= 0
        and times[-1] <= end
        and times[0] <= 60
        and times[-1] >= end - 60,
        "Beginning/end synchronization anchors are missing",
    )
    gaps = [b - a for a, b in pairwise(times)]
    _require(
        not gaps or max(gaps) <= 600, "Synchronization anchor gap exceeds ten minutes"
    )
    holdouts = [as_fraction(a[clock]) for a in anchors if a.get("role") == "holdout"]
    _require(
        all(
            any(
                end * i / 3 <= time < end * (i + 1) / 3 or (i == 2 and time == end)
                for time in holdouts
            )
            for i in range(3)
        ),
        "Separate start/middle/end holdout anchors are missing",
    )
    return max(gaps, default=Fraction())


def verify_sync_inputs(
    raw: dict[str, Any], *, project_dir: Path, dependencies: dict[str, Any]
) -> dict[str, Any]:
    _require(
        raw.get("schema_version") == "sync-input/v1",
        "Typed source/output sync evidence is required",
    )
    _require(
        Path(raw.get("project", "")).resolve() == project_dir.resolve(),
        "Sync check belongs to another project",
    )
    project = load_project(project_dir)
    _require(
        raw.get("model") == project.get("sync"),
        "Sync check does not use the current imported model",
    )
    model = verify_sync_model(raw["model"], project)
    _require(
        raw.get("workflow_render") == project.get("active_render"),
        "Synchronization must inspect the current committed workflow render",
    )
    render = verified_json(raw["workflow_render"])
    _require(
        render.get("schema_version") == "workflow-render/v1"
        and render.get("profile") == "master"
        and not render.get("test_only"),
        "Output anchors must inspect the final real master",
    )
    _file(render["output"])
    timeline = verified_json(render["settings"]["timeline"])
    _require(
        render["output"]["sha256"] == dependencies.get("output_hash")
        and render["settings"]["timeline"]["sha256"]
        == dependencies.get("timeline_hash"),
        "Output sync check is stale against the actual final master",
    )
    output = verified_json(raw["output_anchors"])
    _require(
        output.get("schema_version") == "output-sync-anchors/v1"
        and all(
            output.get("dependencies", {}).get(k) == v for k, v in dependencies.items()
        ),
        "Output anchor evidence dependencies differ",
    )
    source_end = as_fraction(timeline["domain"]["end"])
    output_end = as_fraction(timeline["duration"])
    source_anchors = model["anchors"]
    output_anchors = output.get("anchors", [])
    values: dict[str, list[tuple[Fraction, Fraction]]] = {
        kind: [] for kind in ("audio", "lip", "visual")
    }
    local_bounds = []
    methods = set()
    max_gap = Fraction()
    used_ids = set()
    used_requests = set()
    for kind, residual_values in values.items():
        sources = [a for a in source_anchors if a.get("kind") == kind]
        targets = [a for a in output_anchors if a.get("kind") == kind]
        max_gap = max(
            max_gap,
            _anchor_coverage(sources, source_end, "time"),
            _anchor_coverage(targets, output_end, "output_time"),
        )
        for anchor in sources:
            measured = anchor["measurements"]
            residual_values.append(
                (
                    Fraction(str(measured["residual_ms"])),
                    Fraction(str(measured["uncertainty_ms"])),
                )
            )
            local_bounds.append(Fraction(str(measured["local_frame_duration_ms"])))
            methods.add(measured["uncertainty_method"])
        for anchor in targets:
            source_time, out_time = (
                as_fraction(anchor["source_time"]),
                as_fraction(anchor["output_time"]),
            )
            _require(
                source_to_output(timeline, source_time) == out_time,
                "Output anchor time is not the actual retained source mapping",
            )
            review = verify_imported_review(anchor["review_ref"])
            request, response, execution = (
                review["request"],
                review["response"],
                review["receipt"],
            )
            details = request.get("details", {})
            identity = (execution["run_id"], request.get("request_id"))
            _require(
                anchor.get("id")
                and anchor["id"] not in used_ids
                and identity not in used_requests,
                "Duplicate output anchor/review cannot inflate verification coverage",
            )
            used_ids.add(anchor["id"])
            used_requests.add(identity)
            _require(
                request.get("scope") == "lip_sync"
                and all(
                    request.get("dependencies", {}).get(k) == v
                    for k, v in dependencies.items()
                ),
                "Output sync review did not inspect current master dependencies",
            )
            _require(
                details.get("anchor_id") == anchor["id"]
                and details.get("kind") == kind
                and details.get("role") == anchor.get("role")
                and as_fraction(details.get("source_time")) == source_time
                and as_fraction(details.get("output_time")) == out_time
                and details.get("timing") == model["timing"],
                "Output anchor was relabelled from another event or timing model",
            )
            _require(
                any(
                    as_fraction(a) <= out_time < as_fraction(b)
                    for a, b in request["intervals"]
                ),
                "Actual reviewed clip does not cover the output anchor",
            )
            measured = response.get("measurements", {})
            _require(
                measured == anchor.get("measurements"),
                "Hand-entered output measurements differ from executed reviewer response",
            )
            residual, uncertainty = (
                Fraction(str(measured["residual_ms"])),
                Fraction(str(measured["uncertainty_ms"])),
            )
            bound = _frame_bound(project, model["timing"], source_time)
            _require(
                Fraction(str(measured["local_frame_duration_ms"])) == bound
                and uncertainty >= 0
                and measured.get("uncertainty_method"),
                "Output uncertainty/local frame bound lacks measured source provenance",
            )
            if kind == "audio":
                _bind_audio_anchor(
                    verified_json(anchor["audio_measurement"]), source_time, out_time
                )
                measured_pcm = _verify_audio(
                    anchor["audio_measurement"], project, render
                )
                pcm_residual = as_fraction(measured_pcm["lag_seconds"]) * 1000
                pcm_uncertainty = (
                    as_fraction(measured_pcm["uncertainty_seconds"]) * 1000
                )
                _require(
                    residual == pcm_residual and uncertainty >= pcm_uncertainty,
                    "Output audio residual/uncertainty understates actual source-to-output PCM measurement",
                )
            residual_values.append((residual, uncertainty))
            local_bounds.append(bound)
            methods.add(measured["uncertainty_method"])
    drift = max(
        (
            max(r + u for r, u in group) - min(r - u for r, u in group)
            for group in values.values()
        ),
        default=Fraction(),
    )
    return {
        "max_audio_residual_with_uncertainty_ms": float(
            max(abs(r) + u for r, u in values["audio"])
        ),
        "max_lip_residual_with_uncertainty_ms": float(
            max(abs(r) + u for r, u in values["lip"])
        ),
        "max_lip_uncertainty_ms": float(max(u for _, u in values["lip"])),
        "max_drift_change_ms": float(drift),
        "drift_within_local_frame": drift <= min(local_bounds),
        "max_anchor_gap_seconds": float(max_gap),
        "start_middle_end_holdouts": True,
        "output_anchors_checked": True,
        "uncertainty_method": "; ".join(sorted(methods)),
    }
