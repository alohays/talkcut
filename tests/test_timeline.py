from fractions import Fraction as F

import pytest

from talkcut.timeline import (
    TimelineError,
    as_fraction,
    compile_timeline,
    output_to_source,
    restore_cut,
    round_fraction,
    source_to_output,
    subtract_intervals,
    union_intervals,
)


def timeline(cuts=(), **kwargs):
    defaults = {
        "screen_frames": [{"pts": i * 1485, "duration": 1485} for i in range(600)],
        "screen_time_base": "1/45000", "screen_origin": 0, "cuts": cuts,
        "audio": {"start": 0, "end": 20, "origin": 0, "offset": 0, "rate": 1},
        "speaker": {"start": 0, "end": 19, "origin": 0, "offset": 0, "rate": 1},
    }
    defaults.update(kwargs)
    return compile_timeline(**defaults)


def test_exact_rationals_and_ties():
    assert as_fraction({"num": 1001, "den": 30000}) == F(1001, 30000)
    assert [round_fraction(v) for v in (F(1, 2), F(-1, 2), F(3, 2))] == [1, -1, 2]
    with pytest.raises(TimelineError):
        as_fraction(0.033)


def test_union_difference_and_endpoint_semantics():
    assert union_intervals([(1, 2), (2, 4), (3, 5)]) == [(F(1), F(5))]
    assert subtract_intervals((0, 6), [(1, 2), (2, 4), (3, 5)]) == [(F(0), F(1)), (F(5), F(6))]
    with pytest.raises(TimelineError):
        subtract_intervals((0, 1), [(1, 1)])
    with pytest.raises(TimelineError):
        subtract_intervals((0, 1), [(-1, 1)])


def test_inward_quantization_protects_requested_material():
    result = timeline([{"id": "cut", "start": "1/100", "end": "1/10"}])
    cut = result["cuts"][0]
    assert as_fraction(cut["start"]) == F(33, 1000)
    assert as_fraction(cut["end"]) == F(99, 1000)
    assert source_to_output(result, F(2, 1000)) == F(2, 1000)
    assert source_to_output(result, F(33, 1000)) is None
    assert source_to_output(result, F(99, 1000)) == F(33, 1000)
    assert output_to_source(result, F(33, 1000)) == F(99, 1000)


def test_hundred_cut_cumulative_sample_schedule_and_restore():
    cuts = [{"id": f"cut-{i}", "start": F(3 * i + 1, 1) * F(33, 1000),
             "end": F(3 * i + 2, 1) * F(33, 1000)} for i in range(100)]
    result = timeline(cuts)
    assert len(result["deletions"]) == 100
    assert len(result["seams"]) == 100
    assert result["retained_source_frame_count"] == 500
    assert result["frame_count"] == 501  # exact speaker end inside one screen frame
    assert as_fraction(result["duration"]) == F(33, 2)
    assert result["sample_count"] == 727650
    prior = 0
    for span in result["retained"]:
        assert span["output_sample_start"] == prior
        prior = span["output_sample_end"]
        assert abs(F(prior) - as_fraction(span["output_end"]) * 44100) <= F(1, 2)
        time = as_fraction(span["source_start"]) + F(1, 10000)
        assert output_to_source(result, source_to_output(result, time)) == time
    assert prior == result["sample_count"]
    original = list(cuts)
    for cut in original:
        cuts = restore_cut(cuts, cut["id"])
    assert timeline(cuts) == timeline()
    assert len(original) == 100


def test_nonzero_pts_origin_and_explicit_offset_sign():
    frames = [{"pts": 450000 + i * 1485, "duration": 1485} for i in range(30)]
    track = {"start": 8, "end": 10, "origin": 10, "offset": 2, "rate": 1}
    result = timeline(screen_frames=frames, screen_origin=10, audio=track, speaker=track)
    assert as_fraction(result["domain"]["start"]) == 0
    assert result["retained"][0]["audio_source_sample_start"] == 0
    assert result["speaker_omissions"] == []


def test_speaker_shortfall_and_internal_gap_are_explicit():
    speaker = {"start": 1, "end": 18, "origin": 0, "offset": 0, "rate": 1,
               "gaps": [{"start": 5, "end": 6}]}
    result = timeline(speaker=speaker)
    omissions = result["speaker_omissions"]
    assert [(as_fraction(v["source_start"]), as_fraction(v["source_end"])) for v in omissions] == [
        (F(0), F(1)), (F(5), F(6)), (F(18), F(99, 5))]
    assert all(v["review_required"] for v in omissions)
    assert len(result["inserted_frames"]) == 4


@pytest.mark.parametrize("kwargs", [
    {"cuts": [{"id": "cut", "start": 1, "end": 2}], "protected": [(1, 3)]},
    {"cuts": [{"id": "cut", "start": 0, "end": "99/5"}]},
    {"cuts": [{"id": "cut", "start": 1, "end": 1}]},
    {"audio": {"start": 0, "end": 19, "origin": 0, "offset": 0, "rate": 1}},
    {"audio": {"start": 0, "end": 20, "origin": 0, "offset": 0, "rate": "1001/1000"}},
    {"audio": {"start": 0, "end": 20, "origin": 0, "offset": 0, "rate": 1, "gaps": [(1, 2)]}},
    {"speaker": {"start": 0, "end": 20, "origin": 0, "rate": 1}},
    {"screen_frames": [{"pts": 0, "duration": 100}, {"pts": 200, "duration": 100}]},
])
def test_unsupported_or_unsafe_timing_is_rejected(kwargs):
    with pytest.raises(TimelineError):
        timeline(**kwargs)


def test_vfr_and_fractional_rates_use_measured_edges():
    frames = [{"pts": 9000, "duration": 3003}, {"pts": 12003, "duration": 9000},
              {"pts": 21003, "duration": 3003}]
    result = timeline(screen_frames=frames, screen_time_base="1/90000", screen_origin="1/10")
    assert as_fraction(result["frames"][1]["duration"]) == F(1, 10)
    assert as_fraction(result["duration"]) == F(15006, 90000)
