"""Independent failed-byte controls; all subprocess fixtures use invented inputs."""

import hashlib
from pathlib import Path

import pytest
from test_privacy_failed_measurement import (
    NAMES,
    observe,
    publication,
    read,
    rewrite,
)
from test_privacy_failed_measurement import failed as failed_fixture
from test_privacy_failed_measurement import repository as repository_fixture

from talkcut import privacy_checks as privacy
from talkcut.contracts import object_hash
from talkcut.project import TalkCutError, artifact_ref, atomic_json

failed = failed_fixture
repository = repository_fixture


@pytest.mark.parametrize("destination", ["pr_body", "release_body", "wheel", "sdist"])
def test_exact_boilerplate_in_error_message_is_still_private(failed, repository, tmp_path, destination):
    text = read(failed[2], "run.json")["reason"]
    output = read(failed[2], "stdout.json")
    output["message"] = text
    rewrite(failed[2], "stdout.json", output)
    _, phrases, graph = privacy._known_private_inventory(failed[0], failed[1], repository)
    assert text in phrases
    assert graph["failed_cli_measurement_observations"][0]["claim_status"] == "UNVERIFIED"
    result = publication(failed, repository, tmp_path, destination, text)
    assert result["status"] == "FAIL" and result["user_ready"] is False
    assert any(row.get("matched_sha256") == hashlib.sha256(text.encode()).hexdigest()
               for row in result["findings"])


@pytest.mark.parametrize("slot,value", [
    (0, "python3"), (1, "-c"), (2, "another_package"), (4, "measure"),
    (5, "/another/project"), (6, "--check=baseline"), (8, "--input=raw.json"),
    (10, "--contract=contract.json"), (12, "--json "),
])
def test_hash_consistent_command_rewrite_cannot_change_worker_grammar(failed, slot, value):
    receipt = read(failed[2], "receipt.json")
    receipt["command"][slot] = value
    if slot == 0:
        receipt["executor"] = value
    rewrite(failed[2], "receipt.json", receipt)
    log = read(failed[2], "execution.json")
    log["command"] = receipt["command"]
    rewrite(failed[2], "execution.json", log)
    with pytest.raises(TalkCutError):
        observe(failed)


@pytest.mark.parametrize("name", NAMES)
def test_hash_consistent_input_cannot_reference_its_own_five_sidecars(failed, name):
    receipt = read(failed[2], "receipt.json")
    receipt["command"][9] = str(failed[2] / name)
    receipt["input_artifacts"] = [artifact_ref(failed[2] / name)]
    rewrite(failed[2], "receipt.json", receipt)
    log = read(failed[2], "execution.json")
    log["command"] = receipt["command"]
    rewrite(failed[2], "execution.json", log)
    with pytest.raises(TalkCutError):
        observe(failed)


@pytest.mark.parametrize("kind", ["symlink", "dot", "traversal"])
def test_current_input_aliases_reject_even_when_receipt_and_command_match(failed, tmp_path, kind):
    receipt = read(failed[2], "receipt.json")
    original = Path(receipt["input_artifacts"][0]["path"])
    if kind == "symlink":
        alias = tmp_path / "raw-alias.json"
        alias.symlink_to(original)
        spelling = str(alias)
    elif kind == "dot":
        spelling = str(original.parent) + "/./" + original.name
    else:
        sibling = original.parent / "sibling"
        sibling.mkdir()
        spelling = str(sibling) + "/../" + original.name
    receipt["command"][9] = spelling
    receipt["input_artifacts"][0]["path"] = spelling
    rewrite(failed[2], "receipt.json", receipt)
    log = read(failed[2], "execution.json")
    log["command"] = receipt["command"]
    rewrite(failed[2], "execution.json", log)
    with pytest.raises(TalkCutError):
        observe(failed)


def test_additional_measurement_file_remains_in_denominator_and_refuses(failed, repository):
    atomic_json(failed[2] / "extra.json", {"schema_version": "measurement-check/v1"})
    with pytest.raises(TalkCutError, match="Unknown new measurement"):
        privacy.build_private_inventory(failed[0], failed[1], repository)


def test_changed_recorded_code_is_not_promoted_to_success(failed, repository):
    log = read(failed[2], "execution.json")
    log["after"]["files"] = {"src/invented.py": "a" * 64}
    log["after"]["code_tree_hash"] = object_hash(log["after"]["files"])
    rewrite(failed[2], "execution.json", log)
    assert observe(failed)["claim_status"] == "UNVERIFIED"
    inventory = privacy.build_private_inventory(failed[0], failed[1], repository)
    assert inventory["classification_status"] == "UNVERIFIED"
    assert inventory["known_graph"]["failed_cli_measurement_observations"][0]["claim_status"] == "UNVERIFIED"


def test_second_inventory_observation_detects_authority_change(failed, repository, monkeypatch):
    original = privacy._failed_cli_measurement
    calls = 0

    def changing(path, directory):
        nonlocal calls
        calls += 1
        if calls == 2:
            body = read(failed[2], "stdout.json")
            body["message"] += " Changed current failure detail."
            rewrite(failed[2], "stdout.json", body)
        return original(path, directory)

    monkeypatch.setattr(privacy, "_failed_cli_measurement", changing)
    with pytest.raises(TalkCutError, match="changed during inventory"):
        privacy._known_private_inventory(failed[0], failed[1], repository)
