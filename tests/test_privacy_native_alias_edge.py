"""Explicit current alias-byte edges never authorize history or execution."""
import json
import shutil
from pathlib import Path

import pytest
from test_privacy_native_runtime_observation import native_fixture
from test_privacy_runtime_alias import compiled as compiled_fixture

from talkcut import privacy_checks as privacy
from talkcut.native_provenance import verify_native_bundle
from talkcut.project import TalkCutError, artifact_ref, atomic_json

compiled = compiled_fixture


def fixture(tmp_path, compiled):
    parts = native_fixture(tmp_path, compiled)
    parent = parts[0] / "evidence" / "diagnostic.json"
    parent.parent.mkdir()
    value = json.loads(parts[2].read_bytes())["runtime_libraries"][0]
    atomic_json(parent, {"frames": [{"ref": value}], "private_note": "This invented diagnostic note must remain protected as complete private metadata bytes."})
    locator = {"parent": artifact_ref(parent), "pointer": "/frames/0/ref", "authority_request": artifact_ref(parts[2]), "library_index": 0}
    return parts, parent, locator


def collect(parts, locators):
    return privacy.build_private_inventory(parts[0], parts[1], Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])],
        native_runtime_alias_reobservations=locators)


def test_exact_alias_edge_preserves_full_private_and_link_denominators(tmp_path, compiled):
    parts, parent, locator = fixture(tmp_path, compiled)
    result = collect(parts, [locator])
    entries = {row["path"]: row for row in result["entries"]}
    assert entries[str(parent)]["classification"] == "review"
    assert entries[str(parts[2])]["classification"] == "review"
    assert all(entries[str(path)]["classification"] == "UNCLASSIFIED" for path in parts[3:])
    assert len(result["known_graph"]["native_runtime_alias_reobservations"]) == 1
    assert not result["known_graph"]["auxiliary_runtime_reobservations"]
    row = result["known_graph"]["native_runtime_alias_reobservations"][0]
    assert row["parent"] == locator["parent"] and row["edge"] == ["frames", 0, "ref"]
    assert row["claim_status"] == row["execution_status"] == "UNVERIFIED"
    assert row["history_supported"] is False
    assert row["library_identity"]["target"] == artifact_ref(parts[-1])
    assert len(row["library_identity"]["hops"]) == 2
    known, phrases, _ = privacy._known_private_inventory(parts[0], parts[1], Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])], native_runtime_alias_reobservations=[locator])
    assert known[artifact_ref(parent)["sha256"]] == "review"
    assert json.loads(parent.read_bytes())["private_note"] in phrases
    assert result["classification_status"] == "UNVERIFIED"
    assert result["entries"] == collect(parts, [locator])["entries"]
    with pytest.raises(TalkCutError, match="Legacy native records"):
        verify_native_bundle(artifact_ref(parts[2]), artifact_ref(parts[2]), {}, {})
    with pytest.raises(TalkCutError, match="Immutable"):
        privacy._auxiliary_json(parts[2], Path.cwd(), set(parts[1].values()))


@pytest.mark.parametrize("damage", [
    "none", "sibling", "pointer_index", "library_index", "index_bool", "wrong_authority",
    "parent_changed", "other_parent", "new_parent_hash", "parent_alias", "outside_parent",
    "dotdot_parent", "protected_namespace", "protected_identity", "nested_formal", "transcript",
    "root_formal", "extra_keys", "duplicate", "historical_locator", "pointer_missing", "pointer_escape",
    "pointer_noncanonical_index", "pointer_scalar", "target_hash", "target_changed", "alias_dotdot", "alias_cycle",
])
def test_repeated_native_alias_scope_mutations_reject(tmp_path, compiled, damage):
    parts, parent, locator = fixture(tmp_path, compiled)
    payload = json.loads(parent.read_bytes())
    locators = [locator]
    if damage == "none":
        locators = []
        atomic_json(parts[0] / "checkpoint.local.json", {"diagnostic": artifact_ref(parent)})
    elif damage == "sibling":
        payload["frames"].append(payload["frames"][0])
    elif damage == "pointer_index": locator["pointer"] = "/frames/1/ref"
    elif damage == "library_index": locator["library_index"] = 1
    elif damage == "index_bool": locator["library_index"] = False
    elif damage == "wrong_authority": locator["authority_request"] = artifact_ref(parent)
    elif damage == "parent_changed": parent.write_bytes(parent.read_bytes() + b" ")
    elif damage == "other_parent":
        other = parent.with_name("other.json")
        shutil.copyfile(parent, other)
        locator["parent"] = artifact_ref(other)
        atomic_json(parts[0] / "checkpoint.local.json", {"diagnostic": artifact_ref(parent)})
    elif damage == "new_parent_hash": locator["parent"]["sha256"] = "f" * 64
    elif damage == "parent_alias":
        alias = parent.with_name("alias.json"); alias.symlink_to(parent.name)
        locator["parent"]["path"] = str(alias)
    elif damage == "outside_parent":
        other = tmp_path / "outside.json"; shutil.copyfile(parent, other)
        locator["parent"] = artifact_ref(other)
    elif damage == "dotdot_parent": locator["parent"]["path"] = str(parent.parent / ".." / parent.parent.name / parent.name)
    elif damage == "protected_namespace":
        other = parts[0] / "transcripts" / "diagnostic.json"; other.parent.mkdir(); shutil.copyfile(parent, other)
        locator["parent"] = artifact_ref(other)
    elif damage == "protected_identity":
        # Register the actual target as private media: a locator cannot relabel it.
        parts = (parts[0], {role: artifact_ref(parts[-1])["sha256"] for role in parts[1]}, *parts[2:])
    elif damage == "nested_formal": payload["nested"] = {"schema_version": "review-request/v1"}
    elif damage == "transcript": payload["nested"] = {"schema_version": "transcript/v1", "source_sha256": parts[1]["screen"], "text": "Authored source-bound transcript must remain private even when it embeds an alias."}
    elif damage == "root_formal": payload["schema_version"] = "local-audio-calibration-request/v1"
    elif damage == "extra_keys": locator["history"] = True
    elif damage == "duplicate": locators *= 2
    elif damage == "historical_locator": locator["parent"] = {"origin": artifact_ref(parent), "snapshot": artifact_ref(parent)}
    elif damage == "pointer_missing": locator["pointer"] = "/no/such/edge"
    elif damage == "pointer_escape": locator["pointer"] = "/frames/0/ref~2"
    elif damage == "pointer_noncanonical_index": locator["pointer"] = "/frames/00/ref"
    elif damage == "pointer_scalar": locator["pointer"] = "/private_note/ref"
    elif damage == "target_hash": payload["frames"][0]["ref"]["sha256"] = "f" * 64
    elif damage == "target_changed": parts[-1].write_bytes(parts[-1].read_bytes() + b"different")
    elif damage == "alias_dotdot": parts[4].unlink(); parts[4].symlink_to("../runtime/" + parts[-1].name)
    elif damage == "alias_cycle": parts[4].unlink(); parts[4].symlink_to(parts[3].name)
    if damage in {"sibling", "nested_formal", "transcript", "root_formal", "target_hash"}:
        atomic_json(parent, payload); locator["parent"] = artifact_ref(parent)
    with pytest.raises(TalkCutError):
        collect(parts, locators)


@pytest.mark.parametrize("damage", ["same_link_replacement", "different_target_same_bytes", "parent_rewrite"])
def test_current_identity_changes_after_first_observation_reject(tmp_path, compiled, monkeypatch, damage):
    parts, parent, locator = fixture(tmp_path, compiled)
    original = privacy._native_runtime_alias_inventory
    calls = 0
    def mutate(*args, **kwargs):
        nonlocal calls
        value = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            if damage == "parent_rewrite":
                parent.write_bytes(parent.read_bytes() + b" ")
            elif damage == "same_link_replacement":
                parts[4].unlink(); parts[4].symlink_to(parts[-1].name)
            else:
                other = parts[-1].with_name("another.data"); shutil.copyfile(parts[-1], other)
                parts[4].unlink(); parts[4].symlink_to(other.name)
        return value
    monkeypatch.setattr(privacy, "_native_runtime_alias_inventory", mutate)
    with pytest.raises(TalkCutError): collect(parts, [locator])
