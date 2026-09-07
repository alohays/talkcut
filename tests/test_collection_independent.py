"""Independent role-boundary controls on generated media and isolated unit gates."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from test_context_collection import PAUSE, all_activity, analysis, verify
from test_context_collection import (
    scenario as scenario,  # noqa: PLC0414 - pytest fixture export
)
from test_context_collection import (
    source as source,  # noqa: PLC0414 - pytest fixture export
)

from talkcut.analysis import verify_analysis_report
from talkcut.project import TalkCutError, artifact_ref, atomic_json, read_json


def bind_two_current_sources(case, *, observed_is_screen, screen_key="screen"):
    """Rebind an authored graph bottom-up; all execution dependencies stay exact."""
    second = case["root"] / "other-generated-source.mp4"
    second.write_bytes(Path(case["source"]["path"]).read_bytes() + b"\0" * 16)
    other_hash = artifact_ref(second)["sha256"]
    actual_hash = case["source"]["sha256"]
    hashes = {
        screen_key: actual_hash if observed_is_screen else other_hash,
        "speaker": other_hash if observed_is_screen else actual_hash,
    }
    old_dependencies = copy.deepcopy(case["deps"])
    dependencies = {**old_dependencies, "source_hashes": hashes}
    memo = {}

    def rebind(value):
        if isinstance(value, dict):
            if value == old_dependencies:
                return copy.deepcopy(dependencies)
            if {"path", "sha256"} <= set(value):
                path = Path(value["path"])
                if path.suffix == ".json" and path.is_relative_to(case["root"]):
                    if path not in memo:
                        before = read_json(path)
                        after = rebind(before)
                        if after != before:
                            atomic_json(path, after)
                        memo[path] = artifact_ref(path)
                    return {**value, **memo[path]}
            return {key: rebind(child) for key, child in value.items()}
        if isinstance(value, list):
            return [rebind(child) for child in value]
        return value

    case["collection"] = rebind(case["collection"])
    case["deps"] = dependencies
    return hashes


@pytest.mark.parametrize("observed_is_screen", [True, False])
def test_collection_requires_primary_screen_not_any_source_member(
    scenario, observed_is_screen
):
    bind_two_current_sources(scenario, observed_is_screen=observed_is_screen)
    if observed_is_screen:
        assert verify(scenario)["status"] == "PASS"
    else:
        with pytest.raises(TalkCutError):
            verify(scenario)


@pytest.mark.parametrize("observed_is_screen", [True, False])
def test_analysis_recompute_requires_primary_screen_not_any_source_member(
    scenario, observed_is_screen
):
    hashes = bind_two_current_sources(scenario, observed_is_screen=observed_is_screen)
    all_activity(scenario, "disposable_pause", PAUSE)
    report = analysis(scenario)
    assert report["status"] == (
        "ANALYZED" if observed_is_screen else "ANALYSIS_UNAVAILABLE"
    )
    report["source_hashes"] = hashes
    report_path = scenario["root"] / "bound-source-analysis.json"
    atomic_json(report_path, report)
    inspection = scenario["root"] / "primary-screen-inspection.json"
    atomic_json(
        inspection, {"sha256": hashes["screen"], "video": {"coverage": ["0", "60"]}}
    )
    plan = {
        "source_hashes": hashes,
        "contract_hash": scenario["deps"]["contract_hash"],
        "inspection_refs": {"screen": artifact_ref(inspection)},
        "protected_intervals": report["protected_intervals"],
    }
    if observed_is_screen:
        assert (
            verify_analysis_report(artifact_ref(report_path), plan)["status"]
            == "ANALYZED"
        )
    else:
        with pytest.raises(TalkCutError) as error:
            verify_analysis_report(artifact_ref(report_path), plan)

        assert error.value.code == "SOURCE_CHANGED"


@pytest.mark.parametrize("screen_key", ["Screen", "primary", "video"])
def test_collection_does_not_infer_primary_screen_from_role_alias(scenario, screen_key):
    hashes = bind_two_current_sources(
        scenario, observed_is_screen=True, screen_key=screen_key
    )
    assert "screen" not in hashes
    assert scenario["source"]["sha256"] in hashes.values()
    with pytest.raises(TalkCutError, match="source or executing code identity"):
        verify(scenario)
