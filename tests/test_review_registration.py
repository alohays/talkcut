"""Private index transactions after an explicitly isolated provider gate.

No fixture in this file can certify source media, real AI capability or AC12.
"""

from pathlib import Path

import pytest

from talkcut.acceptance import Evaluator
from talkcut.contracts import code_identity, freeze_contract
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    init_project,
    read_json,
)
from talkcut.review import register_review_import

REPO = Path(__file__).parents[1]


def fixture(tmp_path, monkeypatch, *, mutation=None):
    source = tmp_path / "unit-source.bin"
    source.write_bytes(
        b"Explicitly isolated unit fixture for index transaction, not media."
    )
    project_dir = tmp_path / "project"
    project = init_project(project_dir, source, source)
    freeze_contract(REPO, project_dir / "frozen-contract.local.json")
    deps = {
        "source_hashes": {
            role: ref["sha256"] for role, ref in project["sources"].items()
        },
        "code_tree_hash": code_identity(REPO)["code_tree_hash"],
        "contract_hash": artifact_ref(project_dir / "frozen-contract.local.json")[
            "sha256"
        ],
    }
    record = {
        "schema_version": "multimodal-review/v1",
        "reviewer_role": "adversarial_reviewer",
        "owner_acceptance": "pending",
    }
    request = {"scope": "source_sync", "dependencies": deps}
    if mutation:
        mutation(record, request)
    for name, value in (
        ("record", record),
        ("request", request),
        ("capability", {"unit_fixture": True}),
    ):
        atomic_json(tmp_path / f"{name}.json", value)
    imported = {
        "schema_version": "review-import/v1",
        "artifact_refs": {
            name: artifact_ref(tmp_path / f"{name}.json")
            for name in ("record", "request", "capability")
        },
    }
    atomic_json(tmp_path / "import.json", imported)
    index = {
        "schema_version": "acceptance-index/v1",
        "owner_acceptance": "pending",
        "findings": [
            {
                "severity": "P1",
                "reason": "Existing independent finding must survive registration",
            }
        ],
    }
    atomic_json(project_dir / "acceptance.local.json", index)
    monkeypatch.setattr(
        "talkcut.review.verify_imported_review",
        lambda ref: {"record": record, "request": request},
    )
    monkeypatch.setattr(Evaluator, "load_capability", lambda *args: None)
    return project_dir, artifact_ref(tmp_path / "import.json"), index


def test_source_anchor_registration_preserves_index_and_does_not_add_output_coverage(
    tmp_path, monkeypatch
):
    project_dir, ref, before = fixture(tmp_path, monkeypatch)
    result = register_review_import(project_dir, ref, REPO)
    after = read_json(project_dir / "acceptance.local.json")
    assert result["status"] == "INDEXED"
    assert result["acceptance_status"] == "UNVERIFIED"
    assert after["findings"] == before["findings"]
    assert not after.get("reviews")
    assert len(after["capabilities"]) == 1
    assert read_json(result["previous_index"]["path"]) == before
    duplicate = register_review_import(project_dir, ref, REPO)
    assert duplicate["index"]["sha256"] == result["index"]["sha256"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record, request: request["dependencies"].update(
            source_hashes={"screen": "b" * 64}
        ),
        lambda record, request: request["dependencies"].update(code_tree_hash="c" * 64),
        lambda record, request: record.update(test_only=True),
        lambda record, request: record.update(owner_acceptance="accepted"),
        lambda record, request: record.update(reviewer_role="proposer"),
    ],
)
def test_foreign_or_test_review_cannot_enter_current_index(
    tmp_path, monkeypatch, mutation
):
    project_dir, ref, before = fixture(tmp_path, monkeypatch, mutation=mutation)
    with pytest.raises(TalkCutError):
        register_review_import(project_dir, ref, REPO)
    assert read_json(project_dir / "acceptance.local.json") == before
