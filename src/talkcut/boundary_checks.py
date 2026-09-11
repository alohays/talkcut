"""Actual hundred-cut media fixture and independent boundary recomputation.

This public mathematical fixture can certify technical boundaries only. It
never supplies DGIST editorial, visual quality, synchronization or owner PASS.
The raw schema boundary-fixture/v1 retains generation commands, ffprobe bytes,
requested cuts, both native renders and every source/output hash.
"""

from __future__ import annotations

import json
import subprocess
from fractions import Fraction
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .contracts import code_identity
from .project import TalkCutError, artifact_ref, atomic_json, now, sha256, verified_json
from .render import render, validate_render
from .timeline import as_fraction, compile_timeline


def _require(condition: Any, reason: str) -> None:
    if not condition:
        raise TalkCutError("BOUNDARIES_UNVERIFIED", reason)


def _file(ref: dict[str, Any]) -> Path:
    path = Path(ref["path"])
    _require(
        path.is_absolute() and path.is_file() and sha256(path) == ref["sha256"],
        "Boundary input artifact is absent or changed",
    )
    return path


def _command(argv: list[str], directory: Path, name: str) -> dict[str, Any]:
    stdout, stderr = directory / f"{name}.stdout.json", directory / f"{name}.stderr.log"
    started = now()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        completed = subprocess.run(
            argv, stdout=out, stderr=err, timeout=1200, check=False
        )
    result = {
        "argv": argv,
        "started_at": started,
        "finished_at": now(),
        "exit_code": completed.returncode,
        "stdout": artifact_ref(stdout),
        "stderr": artifact_ref(stderr),
    }
    atomic_json(directory / f"{name}.execution.json", result)
    _require(completed.returncode == 0, f"Actual fixture process failed: {name}")
    return result


def _probe(path: Path) -> dict[str, Any]:
    result = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-show_streams",
            "-show_frames",
            "-of",
            "json",
            str(path),
        ],
        capture_output=True,
        text=True,
        timeout=1200,
        check=False,
    )
    _require(result.returncode == 0, "Cannot read actual fixture frame PTS")
    return json.loads(result.stdout)


def run_boundary_fixture(directory: Path, repo_root: Path) -> dict[str, Any]:
    directory = directory.resolve()
    _require(
        not directory.exists() or not any(directory.iterdir()),
        "Choose a new fixture directory; preserved outputs cannot be overwritten",
    )
    directory.mkdir(parents=True, exist_ok=True)
    before = code_identity(repo_root)
    screen, speaker, audio = [
        directory / name for name in ("screen.mp4", "speaker.mp4", "audio.wav")
    ]
    raw_screen = directory / "screen-before-terminal.mp4"
    executions = []
    for name, destination, pattern, count in (
        ("screen", raw_screen, "testsrc2", 400),
        ("speaker", speaker, "testsrc", 350),
    ):
        executions.append(
            _command(
                [
                    "ffmpeg",
                    "-v",
                    "error",
                    "-nostdin",
                    "-n",
                    "-f",
                    "lavfi",
                    "-i",
                    f"{pattern}=size=320x180:rate=1000/33",
                    "-frames:v",
                    str(count),
                    "-c:v",
                    "libx264",
                    "-preset",
                    "ultrafast",
                    "-pix_fmt",
                    "yuv420p",
                    "-video_track_timescale",
                    "45000",
                    str(destination),
                ],
                directory,
                name,
            )
        )
    executions.append(
        _command(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-n",
                "-i",
                str(raw_screen),
                "-c",
                "copy",
                "-bsf:v",
                "setts=duration='if(eq(N,399),34922,DURATION)'",
                "-video_track_timescale",
                "45000",
                str(screen),
            ],
            directory,
            "terminal-duration",
        )
    )
    executions.append(
        _command(
            [
                "ffmpeg",
                "-v",
                "error",
                "-nostdin",
                "-n",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=880:sample_rate=44100:duration=14",
                "-c:a",
                "pcm_s16le",
                str(audio),
            ],
            directory,
            "audio",
        )
    )
    sources = {
        "screen": {
            **artifact_ref(screen),
            "stream_index": 0,
            "width": 320,
            "height": 180,
            "sar": "1:1",
        },
        "speaker": {
            **artifact_ref(speaker),
            "stream_index": 0,
            "width": 320,
            "height": 180,
            "sar": "1:1",
        },
        "audio": {**artifact_ref(audio), "stream_index": 0, "sample_rate": 44100},
    }
    probe = _probe(screen)
    atomic_json(directory / "source-probe.json", probe)
    tb = Fraction(probe["streams"][0]["time_base"])
    frames = [
        {
            "pts": f["best_effort_timestamp"],
            "duration": f.get("duration", f.get("pkt_duration")),
        }
        for f in probe["frames"]
    ]
    cuts = [
        {
            "id": f"cut-{i}",
            "start": str(
                frames[3 * i]["pts"] * tb + frames[3 * i]["duration"] * tb / 4
            ),
            "end": str(
                frames[3 * i + 2]["pts"] * tb + frames[3 * i + 2]["duration"] * tb / 4
            ),
        }
        for i in range(100)
    ]
    native_refs, timelines = {}, {}
    for stage, selected in (("baseline", []), ("edited", cuts)):
        timeline = compile_timeline(
            frames,
            str(tb),
            0,
            selected,
            audio={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": 14},
            speaker={"origin": 0, "offset": 0, "rate": 1, "start": 0, "end": "231/20"},
        )
        path = directory / f"{stage}-timeline.json"
        atomic_json(path, timeline)
        timelines[stage] = artifact_ref(path)
        native = render(
            timeline, sources, directory / f"{stage}.mp4", preset="ultrafast", crf=0
        )
        native_refs[stage] = artifact_ref(native["manifest_path"])
    report = {
        "schema_version": "boundary-fixture/v1",
        "test_only": True,
        "status": "UNVERIFIED",
        "owner_acceptance": "pending",
        "ai_review": "UNVERIFIED",
        "sources": sources,
        "executions": executions,
        "source_probe": artifact_ref(directory / "source-probe.json"),
        "requested_cuts": cuts,
        "timelines": timelines,
        "native_renders": native_refs,
        "code_identity_before": before,
        "code_identity_after": code_identity(repo_root),
        "producer": {
            "path": "src/talkcut/boundary_checks.py",
            "sha256": sha256(__file__),
        },
    }
    atomic_json(directory / "fixture.json", report)
    return {**report, "artifact_ref": artifact_ref(directory / "fixture.json")}


def _rounded(value: Fraction) -> int:
    _require(value >= 0, "Negative fixture sample boundary")
    return (2 * value.numerator + value.denominator) // (2 * value.denominator)


def verify_boundary_fixture(raw_ref: dict[str, str], repo_root: Path) -> dict[str, Any]:
    raw = verified_json(raw_ref)
    _require(
        raw.get("schema_version") == "boundary-fixture/v1"
        and raw.get("test_only") is True
        and raw.get("owner_acceptance") == "pending",
        "Actual technical boundary fixture is required",
    )
    identity = code_identity(repo_root)
    _require(
        raw.get("code_identity_before") == raw.get("code_identity_after") == identity,
        "Boundary fixture was not executed against current unchanged code",
    )
    _require(
        raw.get("producer")
        == {"path": "src/talkcut/boundary_checks.py", "sha256": sha256(__file__)},
        "Unknown or changed boundary fixture producer",
    )
    _require(
        len(raw.get("executions", [])) == 4,
        "Fixture generation execution ledger is incomplete",
    )
    for execution in raw["executions"]:
        argv = execution.get("argv", [])
        _require(
            argv and Path(argv[0]).name == "ffmpeg" and execution.get("exit_code") == 0,
            "Unrelated receipt cannot certify fixture generation",
        )
        _file(execution["stdout"])
        _file(execution["stderr"])
    sources = raw["sources"]
    for source in sources.values():
        _file(source)
    source_probe = _probe(Path(sources["screen"]["path"]))
    _require(
        source_probe == verified_json(raw["source_probe"]),
        "Stored frame inventory differs from actual source bytes",
    )
    video = next(s for s in source_probe["streams"] if s["codec_type"] == "video")
    tb = Fraction(video["time_base"])
    frames = [
        (f["best_effort_timestamp"] * tb, f.get("duration", f.get("pkt_duration")) * tb)
        for f in source_probe["frames"]
        if f["media_type"] == "video"
    ]
    _require(
        len(frames) == 400 and frames[0][0] == 0,
        "Boundary fixture source recipe or full extent changed",
    )
    edges = [a for a, _ in frames] + [frames[-1][0] + frames[-1][1]]
    requested = raw.get("requested_cuts", [])
    _require(
        len(requested) == 100 and len({c["id"] for c in requested}) == 100,
        "The fixture must execute one hundred distinct requested cuts",
    )
    resolved = []
    max_edge_error = Fraction()
    for cut in requested:
        a, b = as_fraction(cut["start"]), as_fraction(cut["end"])
        left = next((i for i, edge in enumerate(edges) if edge >= a), None)
        right = next((i for i in range(len(edges) - 1, -1, -1) if edges[i] <= b), None)
        _require(
            left is not None and right is not None and left < right,
            "The requested cut did not delete actual frames",
        )
        assert left is not None and right is not None
        resolved.append((left, right))
        max_edge_error = max(
            max_edge_error,
            (edges[left] - a) / frames[max(0, left - 1)][1],
            (b - edges[right]) / frames[min(right, len(frames) - 1)][1],
        )
    _require(
        all(a[1] < b[0] for a, b in zip(sorted(resolved), sorted(resolved)[1:])),
        "Overlapping/adjacent cuts cannot inflate the actual cut denominator",
    )
    removed = {i for a, b in resolved for i in range(a, b)}
    expected_indices = [i for i in range(len(frames)) if i not in removed]
    edited = verified_json(raw["timelines"]["edited"])
    _require(
        [f["source_index"] for f in edited["frames"]] == expected_indices,
        "Compiled output does not retain exactly the independently reconstructed source frames",
    )
    expected_time = Fraction()
    for output_frame, source_index in zip(
        edited["frames"], expected_indices, strict=True
    ):
        _require(
            as_fraction(output_frame["output_pts"]) == expected_time
            and as_fraction(output_frame["duration"]) == frames[source_index][1],
            "Output frame timestamps differ from independent source retention reconstruction",
        )
        expected_time += frames[source_index][1]
    sample_rate = sources["audio"]["sample_rate"]
    max_sample_error = Fraction()
    for span in edited["retained"]:
        out_start, out_end = (
            as_fraction(span["output_start"]),
            as_fraction(span["output_end"]),
        )
        s0, s1 = _rounded(out_start * sample_rate), _rounded(out_end * sample_rate)
        expected_source = _rounded(as_fraction(span["source_start"]) * sample_rate)
        _require(
            span["output_sample_start"] == s0
            and span["output_sample_end"] == s1
            and span["audio_source_sample_start"] == expected_source
            and span["audio_source_sample_end"] == expected_source + s1 - s0,
            "Actual PCM filter sample schedule differs from independently rounded source mapping",
        )
        max_sample_error = max(
            max_sample_error,
            abs(s0 - out_start * sample_rate),
            abs(s1 - out_end * sample_rate),
        )
    _require(
        edited["sample_count"] == _rounded(expected_time * sample_rate),
        "Cumulative samples drift after repeated cuts",
    )
    for stage in ("baseline", "edited"):
        timeline = verified_json(raw["timelines"][stage])
        native = verified_json(raw["native_renders"][stage])
        _require(
            native.get("complete") is True
            and native.get("exit_code") == 0
            and native.get("status") == "succeeded"
            and native.get("timeline_hash") == timeline["timeline_hash"],
            "Native fixture render did not complete on this timeline",
        )
        actual = validate_render(_file(native["output"]), timeline, native["layout"])
        _require(
            actual == native.get("validation"),
            "Actual output frame/sample decode differs from native result",
        )
        # Re-execute the known renderer, not a receipt command. This binds actual
        # AAC bytes to the independently verified source PCM sample schedule.
        with TemporaryDirectory(prefix="talkcut-boundary-rerender-") as temporary:
            replay = render(
                timeline,
                sources,
                Path(temporary) / "replay.mp4",
                preset="ultrafast",
                crf=0,
            )
            _require(
                replay["output"]["sha256"] == native["output"]["sha256"],
                "Actual fixture output differs from deterministic source-to-output reexecution",
            )
        if stage == "edited":
            actual_probe = _probe(Path(native["output"]["path"]))
            out_video = next(
                s for s in actual_probe["streams"] if s["codec_type"] == "video"
            )
            out_tb = Fraction(out_video["time_base"])
            out_frames = [
                f for f in actual_probe["frames"] if f["media_type"] == "video"
            ]
            _require(
                len(out_frames) == len(expected_indices),
                "Actual output frame count differs from retained source frames",
            )
            for actual_frame, planned, source_index in zip(
                out_frames, edited["frames"], expected_indices, strict=True
            ):
                error = abs(
                    actual_frame["best_effort_timestamp"] * out_tb
                    - as_fraction(planned["output_pts"])
                )
                max_edge_error = max(max_edge_error, error / frames[source_index][1])
            valid_samples = as_fraction(actual["sample_count"])
            max_sample_error = max(
                max_sample_error,
                abs(valid_samples - _rounded(expected_time * sample_rate)),
            )
            padding = as_fraction(actual["audio_padding_samples"])
            _require(
                padding >= 0
                and actual["decode"]["decoded_audio_samples"] - valid_samples
                == padding,
                "AAC padding was not separated from the valid PCM duration",
            )
    return {
        "video_error_local_frames": float(max_edge_error),
        "audio_error_samples": float(max_sample_error),
        "fixture_cut_count": len(resolved),
        "actual_pts_verified": True,
        "aac_padding_separated": True,
    }
