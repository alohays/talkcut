"""Independent tests of finding-resolution binding after the AV receipt gate.

The row stand-ins isolate the aggregation contract. They are not provider
receipts, cannot pass load_review, and certify no real media review.
"""

import copy

import pytest

from talkcut.contracts import object_hash
from talkcut.project import artifact_ref, atomic_json
from talkcut.quality_checks import review_counts


def fixture(tmp_path):
    refs = {}
    for name in ("source", "output", "comparison"):
        path = tmp_path / f"{name}.json"
        atomic_json(path, {"test_only": True, "kind": name})
        refs[name] = artifact_ref(path)
    finding = {
        "kind": "possible_new_audio_clipping",
        "source_interval": ["1", "2"],
        "output_interval": ["0", "1"],
        "severity": "P1",
        "status": "unresolved",
    }
    binding = {
        "finding_hash": object_hash(finding),
        "comparison": refs["comparison"],
        "source_interval": finding["source_interval"],
        "output_interval": finding["output_interval"],
    }
    source = {
        "ref": refs["source"],
        "scope": "analysis",
        "run_id": "source-inspection",
        "intervals": [["0", "4"]],
        "receipt": {"finished_at": "2026-01-01T00:01:00+00:00"},
        "request": {"details": {"quality_investigations": [copy.deepcopy(binding)]}},
        "response": {
            "quality_source_observations": [
                {
                    **copy.deepcopy(binding),
                    "disposition": "original_source_artifact",
                    "observed_source_behavior": "Explicit source observation tied to this measured fixture event; test only.",
                }
            ]
        },
    }
    output = {
        "ref": refs["output"],
        "scope": "output",
        "run_id": "later-output-inspection",
        "intervals": [["0", "4"]],
        "receipt": {"started_at": "2026-01-01T00:02:00+00:00"},
        "request": {
            "details": {
                "quality_investigations": [
                    {**copy.deepcopy(binding), "source_review": refs["source"]}
                ]
            }
        },
        "response": {
            "quality_observations": {
                "important_occlusions": 0,
                "new_audio_defects": 0,
                "new_drop_freeze_black_silence": 0,
            },
            "quality_finding_resolutions": [
                {
                    **copy.deepcopy(binding),
                    "source_review": refs["source"],
                    "disposition": "source_compared_false_positive",
                    "reason": "Explicit comparative output observation tied to the executed source investigation; test only.",
                }
            ],
        },
    }
    raw = {
        "quality_reviews": [refs["output"]],
        "source_comparison_reviews": [refs["source"]],
        "comparison": refs["comparison"],
    }
    timeline = {"duration": "4", "sample_count": 176400, "sample_rate": 44100}
    return raw, [source, output], {"findings": [finding]}, timeline


def test_correctly_bound_aggregation_control(tmp_path):
    raw, rows, report, timeline = fixture(tmp_path)
    assert review_counts(raw, rows, report, timeline)["new_audio_defects"] == 0


@pytest.mark.parametrize(
    "side,location,key",
    [
        (side, location, key)
        for side in (0, 1)
        for location in ("request", "response")
        for key in ("finding_hash", "comparison", "source_interval", "output_interval")
    ],
)
def test_every_request_and_response_binding_is_required(tmp_path, side, location, key):
    raw, rows, report, timeline = fixture(tmp_path)
    row = rows[side]
    target = (
        row["request"]["details"]["quality_investigations"][0]
        if location == "request"
        else row["response"][
            "quality_source_observations"
            if side == 0
            else "quality_finding_resolutions"
        ][0]
    )
    del target[key]
    assert review_counts(raw, rows, report, timeline)["new_audio_defects"] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "generic_source",
        "same_run",
        "reversed_time",
        "naive_time",
        "wrong_source_review",
        "missing_source_coverage",
        "missing_output_coverage",
    ],
)
def test_generic_coverage_and_relabelled_execution_cannot_resolve(tmp_path, mutation):
    raw, rows, report, timeline = fixture(tmp_path)
    source, output = rows
    if mutation == "generic_source":
        source["response"] = {
            "reason": "General source review without the measured finding."
        }
    elif mutation == "same_run":
        source["run_id"] = output["run_id"]
    elif mutation == "reversed_time":
        source["receipt"]["finished_at"] = "2026-01-01T00:03:00+00:00"
    elif mutation == "naive_time":
        source["receipt"]["finished_at"] = "2026-01-01T00:01:00"
    elif mutation == "wrong_source_review":
        output["request"]["details"]["quality_investigations"][0]["source_review"] = (
            raw["comparison"]
        )
    elif mutation == "missing_source_coverage":
        source["intervals"] = [["0", "1"]]
    else:
        output["intervals"] = [["1", "4"]]
    assert review_counts(raw, rows, report, timeline)["new_audio_defects"] is None


def test_zero_counts_and_semantic_coverage_do_not_certify_all_visual_states(tmp_path):
    raw, rows, report, timeline = fixture(tmp_path)
    rows[1]["precision_supported"] = False
    # Even a pasted positive field in the numeric observation has no state proof.
    rows[1]["response"]["quality_observations"]["all_visual_states_checked"] = True
    result = review_counts(raw, rows, report, timeline)
    assert result["important_occlusions"] == 0
    assert result["all_visual_states_checked"] is None


def test_observed_static_states_do_not_require_all_frames_to_be_model_inputs(tmp_path):
    raw, rows, report, timeline = fixture(tmp_path)
    report["dependencies"] = {"output_hash": "isolated-actual-review-row-gate"}
    binding = {
        "comparison": raw["comparison"],
        "output_hash": report["dependencies"]["output_hash"],
        "scope": "all_visible_states_in_requested_intervals",
    }
    rows[1]["request"]["details"]["visual_state_inspection"] = binding
    rows[1]["response"]["visual_state_inspection"] = binding
    rows[1]["response"]["visual_state_observations"] = [
        {
            "interval": ["0", "4"],
            "observed_behavior": "Explicit static-state observation in this isolated aggregation fixture; not actual media review.",
            "rapid_or_suspect": False,
        }
    ]
    rows[1]["precision_supported"] = False
    assert (
        review_counts(raw, rows, report, timeline)["all_visual_states_checked"] is True
    )
    rows[1]["response"]["visual_state_observations"][0]["rapid_or_suspect"] = True
    assert (
        review_counts(raw, rows, report, timeline)["all_visual_states_checked"] is None
    )
