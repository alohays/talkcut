"""Oppose complete check-row construction through real synthetic artifacts."""

import pytest
from acceptance_origin_fixture import fixture, observe, refresh

from talkcut.project import TalkCutError


@pytest.mark.parametrize("mode", ["checkpoint", "python"])
@pytest.mark.parametrize("location", [(1, 0), (2, 0), (5, 0), (7, 0), (11, 0), (12, 0)])
def test_non_writer_success_reason_cannot_hide_behind_unselected_description(tmp_path, mode, location):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    row = parts["report"]["criteria"][location[0]]
    check = row["checks"][location[1]]
    check.update(status="PASS", reason="A success reason absent from the original check writer", measurements=None)
    row["status"] = "PASS" if all(item["status"] == "PASS" for item in row["checks"]) else "UNVERIFIED"
    refresh(parts)
    with pytest.raises(TalkCutError, match="successful check reason"):
        observe(parts)


@pytest.mark.parametrize("mode", ["checkpoint", "python"])
@pytest.mark.parametrize("value", [{}, {"retained": True}, [], False, 0, "unverified result"])
def test_exception_path_cannot_emit_a_returned_measurement(tmp_path, mode, value):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    parts["report"]["criteria"][1]["checks"][0]["measurements"] = value
    refresh(parts)
    with pytest.raises(TalkCutError, match="exception check carries measurements"):
        observe(parts)


@pytest.mark.parametrize("mode", ["checkpoint", "python"])
def test_failed_exception_also_has_no_measurements(tmp_path, mode):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    parts["report"]["criteria"][3]["checks"][0]["measurements"] = {}
    refresh(parts)
    with pytest.raises(TalkCutError, match="exception check carries measurements"):
        observe(parts)


@pytest.mark.parametrize("mode", ["checkpoint", "python"])
def test_successful_check_constructor_keeps_callback_result_without_approval(tmp_path, mode):
    parts = fixture(tmp_path, mode)
    assert observe(parts)
    check = parts["report"]["criteria"][1]["checks"][0]
    check.update(status="PASS", reason="Verified from current artifacts", measurements={"source_hashes": {}})
    refresh(parts)
    result = observe(parts)
    assert result[0]["claim_status"] == "UNVERIFIED"
    assert result[0]["commands"] == []
    assert parts["report"]["status"] == "FAIL"
