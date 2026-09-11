"""Exact, conservative source-to-output timing. No editorial decisions live here.

All intervals are half open. Source timestamps are absolute PTS seconds; the
common lecture time is ``(absolute - origin) * rate + offset``. The first
renderer supports measured constant offsets, not drift correction.
"""

from __future__ import annotations

import itertools
import json
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from fractions import Fraction
from hashlib import sha256
from math import lcm
from typing import Any


class TimelineError(ValueError):
    """A timing contract cannot be satisfied without inventing media."""


def as_fraction(value: Any) -> Fraction:
    """Read exact JSON rational values; binary floating point is never inferred."""
    if isinstance(value, (bool, float)):
        raise TimelineError("Times must be exact integers, rational strings or {num, den}")
    if isinstance(value, Mapping):
        if set(value) != {"num", "den"}:
            raise TimelineError("A rational requires exactly num and den")
        if type(value["num"]) is not int or type(value["den"]) is not int:
            raise TimelineError("Rational components must be integers")
        return Fraction(value["num"], value["den"])
    try:
        return Fraction(value)
    except (TypeError, ValueError, ZeroDivisionError) as exc:
        raise TimelineError(f"Invalid exact time: {value!r}") from exc


def fraction_json(value: Any) -> dict[str, int]:
    q = as_fraction(value)
    return {"num": q.numerator, "den": q.denominator}


def round_fraction(value: Any) -> int:
    """Nearest integer, with ties away from zero; independent of Python float."""
    q = as_fraction(value)
    sign = -1 if q < 0 else 1
    q = abs(q)
    return sign * ((2 * q.numerator + q.denominator) // (2 * q.denominator))


def _span(value: Any) -> tuple[Fraction, Fraction]:
    if isinstance(value, Mapping):
        start, end = value["start"], value["end"]
    else:
        start, end = value
    a, b = as_fraction(start), as_fraction(end)
    if b <= a:
        raise TimelineError("Intervals must have positive duration")
    return a, b


def union_intervals(intervals: Iterable[Any]) -> list[tuple[Fraction, Fraction]]:
    result: list[tuple[Fraction, Fraction]] = []
    for a, b in sorted(_span(span) for span in intervals):
        if result and a <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], b))
        else:
            result.append((a, b))
    return result


def subtract_intervals(domain: Any, removed: Iterable[Any]) -> list[tuple[Fraction, Fraction]]:
    a, b = _span(domain)
    cursor = a
    result = []
    for left, right in union_intervals(removed):
        if left < a or right > b:
            raise TimelineError("An interval is outside the source domain")
        if cursor < left:
            result.append((cursor, left))
        cursor = max(cursor, right)
    if cursor < b:
        result.append((cursor, b))
    return result


def restore_cut(cuts: Sequence[Mapping[str, Any]], cut_id: str) -> list[dict[str, Any]]:
    """Return a new cut list; the original decision ledger remains unchanged."""
    if not any(cut.get("id") == cut_id for cut in cuts):
        raise TimelineError(f"Unknown cut id: {cut_id}")
    return [deepcopy(dict(cut)) for cut in cuts if cut.get("id") != cut_id]


def _track(value: Mapping[str, Any], name: str) -> dict[str, Fraction]:
    required = {"origin", "offset", "rate", "start", "end"}
    if not required <= value.keys():
        raise TimelineError(f"{name} requires explicit origin, offset, rate and coverage")
    result = {key: as_fraction(value[key]) for key in required}
    if result["rate"] != 1:
        raise TimelineError(f"UNSUPPORTED_TIMING: {name} drift correction is not implemented")
    if result["end"] <= result["start"]:
        raise TimelineError(f"{name} coverage must have positive duration")
    return result


def compile_timeline(
    screen_frames: Sequence[Mapping[str, int]],
    screen_time_base: Any,
    screen_origin: Any,
    cuts: Sequence[Mapping[str, Any]] = (),
    *,
    protected: Sequence[Any] = (),
    sample_rate: int = 44100,
    audio: Mapping[str, Any],
    speaker: Mapping[str, Any],
    plan_hash: str | None = None,
) -> dict[str, Any]:
    """Compile one source domain into exact video and cumulative PCM schedules.

    Deletions snap *inward* to measured screen frame edges, so quantization can
    only preserve additional material. Uncovered selected audio is fatal.
    Speaker gaps may be supplied as absolute PTS ``gaps`` and become explicit
    screen-only omissions; the renderer does not repeat a final speaker frame.
    """
    if not screen_frames:
        raise TimelineError("A fully measured screen frame schedule is required")
    if type(sample_rate) is not int or sample_rate <= 0:
        raise TimelineError("sample_rate must be a positive integer")
    tb, origin = as_fraction(screen_time_base), as_fraction(screen_origin)
    if tb <= 0:
        raise TimelineError("time_base must be positive")
    audio_map, speaker_map = _track(audio, "audio"), _track(speaker, "speaker")
    starts: list[Fraction] = []
    ends: list[Fraction] = []
    for frame in screen_frames:
        if type(frame["pts"]) is not int or type(frame["duration"]) is not int:
            raise TimelineError("PTS and frame durations must be integer ticks")
        if frame["duration"] <= 0:
            raise TimelineError("Last and intermediate frame durations must be measured")
        start = frame["pts"] * tb - origin
        end = (frame["pts"] + frame["duration"]) * tb - origin
        if ends and start != ends[-1]:
            raise TimelineError("UNSUPPORTED_TIMING: screen has overlapping frames or a PTS gap")
        starts.append(start)
        ends.append(end)
    edges = starts + [ends[-1]]
    domain = edges[0], edges[-1]
    protected_spans = union_intervals(protected)
    for a, b in protected_spans:
        if a < domain[0] or b > domain[1]:
            raise TimelineError("Protected interval outside source domain")
    resolved_cuts, applied = [], []
    ids = set()
    for cut in cuts:
        cut_id = cut.get("id")
        if not isinstance(cut_id, str) or not cut_id or cut_id in ids:
            raise TimelineError("Every cut must have a unique nonempty source-linked id")
        ids.add(cut_id)
        a, b = _span(cut)
        if a < domain[0] or b > domain[1]:
            raise TimelineError("Cut outside source domain")
        if any(a < right and b > left for left, right in protected_spans):
            raise TimelineError("PROTECTED_SPAN: requested deletion overlaps protected content")
        actual_a = edges[bisect_left(edges, a)]
        actual_b = edges[bisect_right(edges, b) - 1]
        record = {
            "id": cut_id, "requested_start": fraction_json(a),
            "requested_end": fraction_json(b), "start": fraction_json(actual_a),
            "end": fraction_json(actual_b),
            "status": "applied" if actual_b > actual_a else "kept_below_frame_resolution",
        }
        resolved_cuts.append(record)
        if actual_b > actual_a:
            applied.append((actual_a, actual_b))
    deletions = union_intervals(applied)
    kept = subtract_intervals(domain, deletions)
    if not kept:
        raise TimelineError("Deleting the complete source is not a lecture output")
    audio_start = audio_map["start"] - audio_map["origin"] + audio_map["offset"]
    audio_end = audio_map["end"] - audio_map["origin"] + audio_map["offset"]
    audio_gaps = [
        (a - audio_map["origin"] + audio_map["offset"],
         b - audio_map["origin"] + audio_map["offset"])
        for a, b in union_intervals(audio.get("gaps", ()))
    ]
    speaker_start = speaker_map["start"] - speaker_map["origin"] + speaker_map["offset"]
    speaker_end = speaker_map["end"] - speaker_map["origin"] + speaker_map["offset"]
    speaker_gaps = [
        (a - speaker_map["origin"] + speaker_map["offset"],
         b - speaker_map["origin"] + speaker_map["offset"])
        for a, b in union_intervals(speaker.get("gaps", ()))
    ]
    speaker_edges = sorted({speaker_start, speaker_end, *(x for gap in speaker_gaps for x in gap)})
    inserted_frames = []
    omissions = []
    retained: list[dict[str, Any]] = []
    frames: list[dict[str, Any]] = []
    cursor = Fraction(0)
    for a, b in kept:
        if a < audio_start or b > audio_end or any(a < y and b > x for x, y in audio_gaps):
            raise TimelineError("AUDIO_UNCOVERED: selected audio does not cover retained interval")
        output_end = cursor + b - a
        n0, n1 = round_fraction(cursor * sample_rate), round_fraction(output_end * sample_rate)
        source_sample_start = round_fraction((a - audio_start) * sample_rate)
        source_sample_end = source_sample_start + n1 - n0
        if source_sample_end > round_fraction((audio_end - audio_start) * sample_rate):
            raise TimelineError("AUDIO_UNCOVERED: cumulative PCM schedule exceeds decoded coverage")
        i0, i1 = bisect_left(edges, a), bisect_left(edges, b)
        retained.append({
            "source_start": fraction_json(a), "source_end": fraction_json(b),
            "output_start": fraction_json(cursor), "output_end": fraction_json(output_end),
            "frame_start": i0, "frame_end": i1,
            "output_sample_start": n0, "output_sample_end": n1,
            "audio_source_sample_start": source_sample_start,
            "audio_source_sample_end": source_sample_end,
        })
        for i in range(i0, i1):
            # An omission can begin inside a long presentation frame. Insert a
            # second presentation of exactly that screen frame at the measured
            # boundary, so PiP stops at its true coverage edge instead of being
            # frozen beyond EOF or hidden for the whole extended screen frame.
            interior = [edge for edge in speaker_edges if starts[i] < edge < ends[i]]
            presentation_edges = [starts[i], *interior, ends[i]]
            for part_start, part_end in itertools.pairwise(presentation_edges):
                inserted = part_start != starts[i]
                frames.append({
                    "source_index": i, "source_pts": screen_frames[i]["pts"],
                    "presentation_source_time": fraction_json(part_start),
                    "output_pts": fraction_json(cursor + part_start - a),
                    "duration": fraction_json(part_end - part_start),
                    "inserted_reason": "speaker_coverage_boundary" if inserted else None,
                })
                if inserted:
                    inserted_frames.append({"source_index": i, "source_time": fraction_json(part_start),
                                            "reason": "speaker_coverage_boundary"})
        missing = []
        if a < speaker_start:
            missing.append((a, min(b, speaker_start)))
        if b > speaker_end:
            missing.append((max(a, speaker_end), b))
        for x, y in speaker_gaps:
            if a < y and b > x:
                missing.append((max(a, x), min(b, y)))
        for x, y in union_intervals(missing):
            omissions.append({
                "source_start": fraction_json(x), "source_end": fraction_json(y),
                "output_start": fraction_json(cursor + x - a),
                "output_end": fraction_json(cursor + y - a),
                "reason": "speaker_source_uncovered", "review_required": True,
            })
        cursor = output_end
    render_scale = lcm(tb.denominator, origin.denominator,
                       speaker_map["origin"].denominator, speaker_map["offset"].denominator,
                       *(edge.denominator for edge in speaker_edges))
    if render_scale > 2**31 - 1:
        raise TimelineError("UNSUPPORTED_TIMING: exact render time base exceeds FFmpeg limits")
    if inserted_frames and render_scale > 1_000_000:
        raise TimelineError("UNSUPPORTED_TIMING: frame insertion needs a time base no finer than FFmpeg interleave precision")
    result: dict[str, Any] = {
        "schema_version": "timeline/v1", "plan_hash": plan_hash,
        "domain": {"start": fraction_json(domain[0]), "end": fraction_json(domain[1])},
        "screen_time_base": fraction_json(tb), "screen_origin": fraction_json(origin),
        "render_time_base": fraction_json(Fraction(1, render_scale)),
        "rounding": "nearest_ties_away_from_zero; deletion_edges_inward",
        "audio": {key: fraction_json(value) for key, value in audio_map.items()},
        "speaker": {key: fraction_json(value) for key, value in speaker_map.items()},
        "speaker_gaps": [{"start": fraction_json(a), "end": fraction_json(b)} for a, b in speaker_gaps],
        "sample_rate": sample_rate, "duration": fraction_json(cursor),
        "sample_count": round_fraction(cursor * sample_rate), "frame_count": len(frames),
        "retained_source_frame_count": sum(span["frame_end"] - span["frame_start"] for span in retained),
        "inserted_frames": inserted_frames,
        "cuts": resolved_cuts,
        "deletions": [{"start": fraction_json(a), "end": fraction_json(b),
                       "cut_ids": [c["id"] for c in resolved_cuts if c["status"] == "applied"
                                   and as_fraction(c["start"]) < b and as_fraction(c["end"]) > a]}
                      for a, b in deletions],
        "retained": retained, "frames": frames, "speaker_omissions": omissions,
        "seams": [{"id": f"seam-{i}", "output_time": span["output_start"],
                   "left_source_end": retained[i - 1]["source_end"],
                   "right_source_start": span["source_start"]}
                  for i, span in enumerate(retained) if i],
    }
    result["timeline_hash"] = sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return result


def source_to_output(timeline: Mapping[str, Any], source_time: Any) -> Fraction | None:
    t = as_fraction(source_time)
    for span in timeline["retained"]:
        a, b = as_fraction(span["source_start"]), as_fraction(span["source_end"])
        if a <= t < b:
            return as_fraction(span["output_start"]) + t - a
    return None


def output_to_source(timeline: Mapping[str, Any], output_time: Any) -> Fraction | None:
    t = as_fraction(output_time)
    for span in timeline["retained"]:
        a, b = as_fraction(span["output_start"]), as_fraction(span["output_end"])
        if a <= t < b:
            return as_fraction(span["source_start"]) + t - a
    return None
