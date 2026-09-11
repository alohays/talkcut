"""Independent synthetic controls for current build alias byte inventory only."""

import copy
import json
import shutil
from pathlib import Path

import pytest
from test_privacy_native_build_alias import collect, fixture
from test_privacy_runtime_alias import compiled as compiled_fixture

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

compiled = compiled_fixture


def rebind(parts, parent, locators, payload=None, request=None):
    if payload is not None:
        atomic_json(parent, payload)
    if request is None:
        request = json.loads(parts[2].read_bytes())
    request["build_receipt"] = artifact_ref(parent)
    atomic_json(parts[2], request)
    for locator in locators:
        locator["parent"] = artifact_ref(parent)
        locator["authority_request"] = artifact_ref(parts[2])
    atomic_json(parts[0] / "checkpoint.local.json", {
        "source_sha256": parts[1]["screen"], "request": artifact_ref(parts[2]),
    })


def full_fixture(tmp_path, compiled):
    parts, parent, locator = fixture(tmp_path, compiled)
    parts[3].unlink()
    parts[4].unlink()
    request = json.loads(parts[2].read_bytes())
    rows = []
    observed_paths = []
    for index in range(8):
        target = parent.parent / f"library-{index}.dylib"
        target.write_bytes(compiled.read_bytes() + bytes([index]))
        middle = target.with_name(f"middle-{index}.dylib")
        first = target.with_name(f"alias-{index}.dylib")
        middle.symlink_to(target.name)
        first.symlink_to(middle.name)
        for path in (target, middle, first):
            rows.append({"path": str(path), "sha256": artifact_ref(target)["sha256"],
                         "bytes": target.stat().st_size})
            observed_paths.append(path)
    request["runtime_libraries"] = rows
    payload = json.loads(parent.read_bytes())
    payload["runtime_libraries"] = copy.deepcopy(rows)
    locators = [{**locator, "pointer": f"/runtime_libraries/{index}", "library_index": index}
                for index in range(24) if index % 3]
    rebind(parts, parent, locators, payload, request)
    return parts, parent, locators, observed_paths


def test_full_twenty_four_rows_sixteen_aliases_remain_private(tmp_path, compiled):
    parts, parent, locators, paths = full_fixture(tmp_path, compiled)
    result = collect(parts, locators)
    graph = result["known_graph"]
    libraries = graph["native_runtime_request_observations"][0]["libraries"]
    assert len(libraries) == 24
    assert sum(bool(row["hops"]) for row in libraries) == 16
    aliases = graph["native_runtime_alias_reobservations"]
    assert len(aliases) == 16
    assert {row["library_index"] for row in aliases} == {i for i in range(24) if i % 3}
    entries = {row["path"]: row for row in result["entries"]}
    assert {str(path) for path in paths} <= entries.keys()
    assert sum(entries[str(path)]["entry_type"] == "symlink" for path in paths) == 16
    assert all(entries[str(path)]["classification"] == "UNCLASSIFIED" for path in paths)
    assert entries[str(parent)]["classification"] == "review"
    assert entries[str(parts[2])]["classification"] == "review"
    assert all(row["claim_status"] == row["execution_status"] == "UNVERIFIED"
               and row["history_supported"] is False for row in aliases)
    assert result["classification_status"] == "UNVERIFIED"
    assert not result["unresolved"]


@pytest.mark.parametrize("damage", [
    "unselected_regular_removed", "unselected_regular_changed", "reordered_regulars",
    "unselected_alias_removed", "unselected_alias_changed", "missing_last_locator",
    "extra_unobserved_alias", "alias_target_changed", "alias_link_changed",
    "all_rows_shrunk_in_parent", "unselected_extra_field", "unselected_bytes_float",
])
def test_full_denominator_damage_is_rejected(tmp_path, compiled, damage):
    parts, parent, locators, paths = full_fixture(tmp_path, compiled)
    payload = json.loads(parent.read_bytes())
    if damage == "unselected_regular_removed":
        del payload["runtime_libraries"][21]
    elif damage == "unselected_regular_changed":
        payload["runtime_libraries"][21]["sha256"] = "f" * 64
    elif damage == "reordered_regulars":
        rows = payload["runtime_libraries"]
        rows[0], rows[21] = rows[21], rows[0]
    elif damage == "unselected_alias_removed":
        del payload["runtime_libraries"][23]
    elif damage == "unselected_alias_changed":
        payload["runtime_libraries"][23]["path"] = payload["runtime_libraries"][22]["path"]
    elif damage == "missing_last_locator":
        locators.pop()
    elif damage == "extra_unobserved_alias":
        payload["commands"] = [copy.deepcopy(payload["runtime_libraries"][23])]
    elif damage == "alias_target_changed":
        paths[21].write_bytes(paths[21].read_bytes() + b"changed")
    elif damage == "alias_link_changed":
        paths[23].unlink()
        paths[23].symlink_to(paths[0].name)
    elif damage == "all_rows_shrunk_in_parent":
        payload["runtime_libraries"] = payload["runtime_libraries"][:3]
        locators = locators[:2]
    elif damage == "unselected_extra_field":
        payload["runtime_libraries"][21]["approved"] = True
    elif damage == "unselected_bytes_float":
        row = payload["runtime_libraries"][21]
        row["bytes"] = float(row["bytes"])
    rebind(parts, parent, locators, payload)
    with pytest.raises(TalkCutError):
        collect(parts, locators)


@pytest.mark.parametrize("field", [
    "source_acquisition", "patch", "patch_manifest", "runner", "source_before",
    "source_after", "commands", "binary", "status",
])
def test_nested_formal_claim_in_any_build_field_is_rejected(tmp_path, compiled, field):
    parts, parent, locator = fixture(tmp_path, compiled)
    payload = json.loads(parent.read_bytes())
    payload[field] = {"envelope": [{"schema_version": "execution-receipt/v1"}]}
    rebind(parts, parent, [locator], payload)
    with pytest.raises(TalkCutError, match="Nested formal"):
        collect(parts, [locator])


@pytest.mark.parametrize("location", ["external", "in_task"])
def test_other_valid_non_alias_edges_are_included_with_complete_private_text(tmp_path, compiled, location):
    parts, parent, locator = fixture(tmp_path, compiled)
    external = (tmp_path if location == "external" else parent.parent) / "explicit-companion.json"
    note = "Invented private companion metadata must remain in the complete denominator."
    atomic_json(external, {"note": note})
    payload = json.loads(parent.read_bytes())
    payload["runner"] = artifact_ref(external)
    rebind(parts, parent, [locator], payload)
    result = collect(parts, [locator])
    entries = {row["path"]: row for row in result["entries"]}
    assert entries[str(external)]["sha256"] == artifact_ref(external)["sha256"]
    assert entries[str(external)]["classification"] == ("UNCLASSIFIED" if location == "external" else "review")
    _, phrases, _ = privacy._known_private_inventory(parts[0], parts[1], Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])],
        native_runtime_alias_reobservations=[locator])
    if location == "in_task":
        assert note in phrases
    assert result["classification_status"] == "UNVERIFIED"


@pytest.mark.parametrize("damage", ["same_byte_other_formal", "formal_sibling_alias",
                                    "copied_unlinked_build", "different_authority"])
def test_authority_cannot_spread_to_other_parent_or_sibling(tmp_path, compiled, damage):
    parts, parent, locator = fixture(tmp_path, compiled)
    payload = json.loads(parent.read_bytes())
    request = json.loads(parts[2].read_bytes())
    other = parent.with_name("other.json")
    shutil.copyfile(parent, other)
    if damage == "same_byte_other_formal":
        locator["parent"] = artifact_ref(other)
    elif damage == "formal_sibling_alias":
        atomic_json(other, {"schema_version": "execution-receipt/v1",
                            "runtime_libraries": payload["runtime_libraries"]})
        payload["runner"] = artifact_ref(other)
        rebind(parts, parent, [locator], payload)
    elif damage == "copied_unlinked_build":
        request["build_receipt"] = artifact_ref(other)
        atomic_json(parts[2], request)
        locator["authority_request"] = artifact_ref(parts[2])
    else:
        other_request = parts[2].with_name("other-request.json")
        atomic_json(other_request, request)
        locator["authority_request"] = artifact_ref(other_request)
    with pytest.raises(TalkCutError):
        collect(parts, [locator])


def test_oversized_build_rejected_before_json_payload_read(tmp_path, compiled, monkeypatch):
    parts, parent, locator = fixture(tmp_path, compiled)
    payload = json.loads(parent.read_bytes())
    payload["status"] = "x" * 8192
    rebind(parts, parent, [locator], payload)
    original = Path.read_bytes
    def guarded(path):
        assert path != parent, "Oversized build JSON payload read occurred"
        return original(path)
    monkeypatch.setattr(privacy, "MAX_UNIT_BYTES", parent.stat().st_size - 1)
    monkeypatch.setattr(Path, "read_bytes", guarded)
    with pytest.raises(TalkCutError, match="byte bound"):
        collect(parts, [locator])


def test_duplicate_nested_key_rejected(tmp_path, compiled):
    parts, parent, locator = fixture(tmp_path, compiled)
    parent.write_text(parent.read_text().replace('"commands":[]', '"commands":[{"claim":1,"claim":2}]'))
    assert '"claim":1,"claim":2' in parent.read_text()
    rebind(parts, parent, [locator])
    with pytest.raises(TalkCutError, match="not bounded JSON"):
        collect(parts, [locator])


@pytest.mark.parametrize("change", ["parent", "request", "unselected_target"])
def test_end_of_walk_reobservation_rejects_changes(tmp_path, compiled, monkeypatch, change):
    parts, parent, locators, paths = full_fixture(tmp_path, compiled)
    original = privacy._native_runtime_alias_inventory
    calls = 0
    def mutate(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            changed = parent if change == "parent" else parts[2] if change == "request" else paths[21]
            changed.write_bytes(changed.read_bytes() + b" ")
        return result
    monkeypatch.setattr(privacy, "_native_runtime_alias_inventory", mutate)
    with pytest.raises(TalkCutError):
        collect(parts, locators)
