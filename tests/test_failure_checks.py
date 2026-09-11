"""Real renderer failures, with raw JUnit omissions rejected separately."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from talkcut.failure_checks import _measure, run_failure_checks
from talkcut.project import TalkCutError


@pytest.fixture(scope="module")
def actual_controls(tmp_path_factory):
    root = Path(__file__).resolve().parents[1]
    result = run_failure_checks(root, tmp_path_factory.mktemp("fault-control-run"))
    assert result["technical_controls_executed"], result
    assert result["exit_code"] == 0
    return result


def test_actual_controls_keep_provider_capability_unknown(actual_controls):
    result = actual_controls
    assert result["status"] == "UNVERIFIED"
    assert result["owner_acceptance"] == "pending"
    values = result["measurements"]
    for key in ("provider_timeout", "modality_missing", "invalid_review_timestamp",
                "empty_review", "truncated_review", "budget_exhaustion"):
        assert values[key] is None
    for key in ("sigint", "subprocess_failure", "timeout", "disk_full", "corrupt_json",
                "source_replacement", "stale_cache", "concurrent_revision",
                "partial_not_promoted", "previous_success_preserved", "source_unchanged",
                "resume_verified"):
        assert values[key] is True


def test_actual_junit_missing_one_cache_control_is_rejected(actual_controls, tmp_path):
    tree = ET.parse(actual_controls["junit"]["path"])
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    node = next(n for n in suite.findall("testcase")
                if n.get("name") == "test_cache_rejects_valid_hash_from_wrong_render[foreign_profile]")
    suite.remove(node)
    altered = tmp_path / "missing-case.xml"
    tree.write(altered)
    with pytest.raises(TalkCutError, match="complete fixed control set"):
        _measure(altered)
