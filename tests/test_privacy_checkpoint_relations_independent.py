"""Independent private checkpoint relations; no historical producer execution."""

import copy
from pathlib import Path

import pytest
from checkpoint_data_origin_fixture import (
    fixture,
    locator,
    observe,
    rebind_authority,
    refresh,
    write,
)
from report_data_origin_fixture import refresh as refresh_data

from talkcut.project import TalkCutError


def add_cohort(p, count):
    retained = copy.deepcopy(p["retained"])
    authority = copy.deepcopy(p["authority"])
    raw = Path(p["original"]["path"]).read_bytes()
    for i in range(1, count):
        original = write(p["folder"] / f"cohort-{i}.json", raw)
        snapshot = write(p["temporary"] / f"cohort-{i}-saved.json", raw)
        case = copy.deepcopy(retained["cases"][0])
        case["parent"] = {"kind": "review", **original}
        for row in case["rows"]:
            row["original_origin_index"] += 27 * i
        retained["cases"].append(case)
        authority["parents"].append(
            {
                **copy.deepcopy(authority["parents"][0]),
                "original": original,
                "snapshot": snapshot,
                "retained_case": i,
            }
        )
    p["retained"] = retained
    p["authority"] = authority
    persist(p)


def persist(p):
    p["authority"]["retained_copies"] = write(
        p["folder"] / "cohort-retained.json", p["retained"]
    )
    rebind_authority(p)


@pytest.mark.parametrize("count", [2, 4])
def test_all_declared_same_byte_parents_have_distinct_retained_authority(
    count, tmp_path
):
    p = fixture(tmp_path)
    add_cohort(p, count)
    selected = [
        dict(locator(p), parent=pair["original"]) for pair in p["authority"]["parents"]
    ]
    values = observe(p, selected)
    assert len(values) == count and all(
        x["claim_status"] == "UNVERIFIED" for x in values
    )
    assert len({x["parent"]["path"] for x in values}) == count
    assert len({x["parent"]["sha256"] for x in values}) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "cross_origin_duplicate",
        "cross_snapshot_collision",
        "wrong_unselected_source",
        "wrong_unselected_full_row",
        "unknown_unselected_field",
    ],
)
def test_unselected_declared_parent_cannot_escape_complete_verification(
    tmp_path, fault
):
    p = fixture(tmp_path)
    add_cohort(p, 4)
    assert observe(p)
    last = p["retained"]["cases"][-1]
    pair = p["authority"]["parents"][-1]
    if fault == "cross_origin_duplicate":
        last["rows"][0]["original_origin_index"] = 0
    elif fault == "cross_snapshot_collision":
        pair["snapshot"] = p["authority"]["parents"][0]["snapshot"]
    elif fault == "wrong_unselected_source":
        last["source_report"]["sha256"] = "f" * 64
    elif fault == "wrong_unselected_full_row":
        last["rows"][1]["criterion_id"] = "AC13"
    elif fault == "unknown_unselected_field":
        pair["approve_private"] = True
    persist(p)
    with pytest.raises(TalkCutError):
        observe(p)  # Only the first parent is selected.


@pytest.mark.parametrize(
    "namespace", ["sources", "transcripts", "renders", "reviews", "review", "analysis"]
)
@pytest.mark.parametrize("physical", ["original", "snapshot"])
def test_upstream_original_and_snapshot_namespaces_both_remain_protected(
    tmp_path, namespace, physical
):
    p = fixture(tmp_path)
    assert observe(p)
    up = p["upstream"]
    if physical == "original":
        up["stdout"]["path"] = str(p["directory"] / namespace / "upstream-report.json")
    else:
        up["archived"] = True
        up["temporary"] = p["directory"] / namespace / "preserved"
    refresh_data(up)
    refresh(p)
    if physical == "snapshot":
        p["authority"]["parents"][0]["upstream_parent"] = up["parents"][0]["snapshot"]
        rebind_authority(p)
    with pytest.raises(TalkCutError, match="Checkpoint upstream report"):
        observe(p)


def test_upstream_original_outside_project_refuses(tmp_path):
    p = fixture(tmp_path)
    assert observe(p)
    p["upstream"]["stdout"]["path"] = str(tmp_path / "outside-project-report.json")
    refresh_data(p["upstream"])
    refresh(p)
    with pytest.raises(TalkCutError, match="Checkpoint upstream report"):
        observe(p)


def test_explicit_saved_body_does_not_require_old_path_survival(tmp_path):
    p = fixture(tmp_path, "preserved_report_summary")
    baseline = observe(p)
    historical = Path(p["parent"]["actual_latest_acceptance"]["path"])
    assert historical.read_bytes() != Path(p["source"]["path"]).read_bytes()
    historical.unlink()  # Only this synthetic fixture file.
    result = observe(p)
    assert result == baseline and result[0]["claim_status"] == "UNVERIFIED"
    assert not historical.exists()


@pytest.mark.parametrize(
    "fault", ["wrong_original_digest", "unbound_equal_saved_path", "missing_saved_body"]
)
def test_explicit_historical_to_saved_body_edge_is_exact(tmp_path, fault):
    p = fixture(tmp_path, "preserved_report_summary")
    assert observe(p)
    if fault == "missing_saved_body":
        Path(p["source"]["path"]).unlink()
    else:

        def mutate(record):
            edge = record["cases"][0]["copy_edges"][0]
            if fault == "wrong_original_digest":
                edge["original_reference"]["sha256"] = "f" * 64
            else:
                edge["preserved_reference"] = write(
                    p["temporary"] / "unbound-equal.json",
                    Path(p["source"]["path"]).read_bytes(),
                )

        p["retained_mutator"] = mutate
        refresh(p)
    with pytest.raises(TalkCutError):
        observe(p)


@pytest.mark.parametrize(
    "target", ["upstream_authority", "checkpoint_authority", "snapshot"]
)
def test_final_dependency_identity_is_still_checked_after_projection(
    tmp_path, monkeypatch, target
):
    from talkcut import privacy_checks as privacy

    p = fixture(tmp_path)
    assert observe(p)
    selected = {
        "upstream_authority": p["upstream_authority"],
        "checkpoint_authority": p["authority_ref"],
        "snapshot": p["snapshot"],
    }[target]
    original = privacy.privacy_checkpoint_origins.project_field
    fired = []

    def changed(*args):
        result = original(*args)
        path = Path(selected["path"])
        path.write_bytes(path.read_bytes() + b" ")
        fired.append(True)
        return result

    monkeypatch.setattr(privacy.privacy_checkpoint_origins, "project_field", changed)
    with pytest.raises(TalkCutError):
        observe(p)
    assert fired == [True]
