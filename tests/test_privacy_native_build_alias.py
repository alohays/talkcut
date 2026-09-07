"""A request-linked build's current library bytes do not prove a build ran."""

import json
import shutil
from pathlib import Path

import pytest
from test_privacy_native_runtime_observation import native_fixture
from test_privacy_runtime_alias import compiled as compiled_fixture

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

compiled = compiled_fixture


def fixture(tmp_path, compiled):
    parts = native_fixture(tmp_path, compiled)
    request = json.loads(parts[2].read_bytes())
    parent = parts[0] / "runtime" / "build.json"
    payload = {
        "schema_version": "private-runtime-build/v1",
        "source_acquisition": None,
        "patch": None,
        "patch_manifest": None,
        "runner": None,
        "source_before": None,
        "source_after": None,
        "source_unchanged_during_build": False,
        "commands": [],
        "binary": None,
        "runtime_libraries": request["runtime_libraries"],
        "status": "FAILED; synthetic current bytes only, never a build approval",
    }
    atomic_json(parent, payload)
    request["build_receipt"] = artifact_ref(parent)
    atomic_json(parts[2], request)
    atomic_json(parts[0] / "checkpoint.local.json", {"source_sha256": parts[1]["screen"], "request": artifact_ref(parts[2])})
    locator = {
        "parent": artifact_ref(parent),
        "pointer": "/runtime_libraries/0",
        "authority_request": artifact_ref(parts[2]),
        "library_index": 0,
    }
    return parts, parent, locator


def collect(parts, locators):
    return privacy.build_private_inventory(
        parts[0], parts[1], Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])],
        native_runtime_alias_reobservations=locators,
    )


def test_request_linked_build_bytes_keep_complete_denominator_and_failed_claim(tmp_path, compiled):
    parts, parent, locator = fixture(tmp_path, compiled)
    result = collect(parts, [locator])
    row = result["known_graph"]["native_runtime_alias_reobservations"][0]
    assert row["parent_role"] == "current_native_build_runtime_bytes"
    assert row["claim_status"] == row["execution_status"] == "UNVERIFIED"
    assert row["history_supported"] is False
    assert row["edge"] == ["runtime_libraries", 0]
    entries = {row["path"]: row for row in result["entries"]}
    assert entries[str(parent)]["classification"] == "review"
    assert entries[str(parts[2])]["classification"] == "review"
    assert all(str(path) in entries for path in parts[3:])
    assert result["classification_status"] == "UNVERIFIED"
    assert result["entries"] == collect(parts, [locator])["entries"]
    known, phrases, _ = privacy._known_private_inventory(
        parts[0], parts[1], Path.cwd(),
        native_runtime_request_observations=[artifact_ref(parts[2])],
        native_runtime_alias_reobservations=[locator],
    )
    assert known[artifact_ref(parent)["sha256"]] == "review"
    assert json.loads(parent.read_bytes())["status"] in phrases
    with pytest.raises(TalkCutError, match="Immutable"):
        privacy._auxiliary_json(parent, Path.cwd(), set(parts[1].values()))


@pytest.mark.parametrize("damage", [
    "no_link", "stale_link", "other_link", "link_bytes_bool", "link_bytes_wrong", "link_extra",
    "schema", "missing_field", "extra_field", "nested_formal", "source_transcript",
    "library_removed", "library_extra", "library_bytes_bool", "library_hash", "duplicate_keys",
    "other_pointer", "noncanonical_pointer", "index_bool", "duplicate_locator", "missing_locator",
    "unobserved_other_edge", "parent_link", "registered_build",
])
def test_current_build_alias_mutations_reject(tmp_path, compiled, damage):
    parts, parent, locator = fixture(tmp_path, compiled)
    request = json.loads(parts[2].read_bytes())
    payload = json.loads(parent.read_bytes())
    rewrite_payload = False
    if damage == "no_link": request.pop("build_receipt")
    elif damage == "stale_link": request["build_receipt"]["sha256"] = "f" * 64
    elif damage == "other_link":
        other = parent.with_name("other.json")
        shutil.copyfile(parent, other)
        request["build_receipt"] = artifact_ref(other)
    elif damage == "link_bytes_bool": request["build_receipt"]["bytes"] = True
    elif damage == "link_bytes_wrong": request["build_receipt"]["bytes"] = 1
    elif damage == "link_extra": request["build_receipt"]["approved"] = True
    elif damage == "schema": payload["schema_version"] = "review-request/v1"; rewrite_payload = True
    elif damage == "missing_field": payload.pop("patch"); rewrite_payload = True
    elif damage == "extra_field": payload["approved"] = True; rewrite_payload = True
    elif damage == "nested_formal": payload["commands"] = [{"schema_version": "execution-receipt/v1"}]; rewrite_payload = True
    elif damage == "source_transcript":
        payload["commands"] = [{"schema_version": "transcript/v1", "source_sha256": parts[1]["screen"]}]
        rewrite_payload = True
    elif damage == "library_removed": payload["runtime_libraries"] = []; rewrite_payload = True
    elif damage == "library_extra": payload["runtime_libraries"] *= 2; rewrite_payload = True
    elif damage == "library_bytes_bool": payload["runtime_libraries"][0]["bytes"] = True; rewrite_payload = True
    elif damage == "library_hash": payload["runtime_libraries"][0]["sha256"] = "f" * 64; rewrite_payload = True
    elif damage == "other_pointer": locator["pointer"] = "/runner"
    elif damage == "noncanonical_pointer": locator["pointer"] = "/runtime_libraries/00"
    elif damage == "index_bool": locator["library_index"] = False
    elif damage == "unobserved_other_edge":
        payload["runner"] = {"path": str(parent.with_name("missing.py")), "sha256": "f" * 64}
        rewrite_payload = True
    elif damage == "parent_link":
        linked = parent.with_name("linked.json"); linked.symlink_to(parent.name)
        locator["parent"]["path"] = str(linked)
        request["build_receipt"]["path"] = str(linked)
    elif damage == "registered_build": parts = (parts[0], {role: artifact_ref(parent)["sha256"] for role in parts[1]}, *parts[2:])
    if rewrite_payload:
        atomic_json(parent, payload)
        locator["parent"] = artifact_ref(parent)
        request["build_receipt"] = artifact_ref(parent)
    if damage == "duplicate_keys":
        parent.write_text(parent.read_text().replace('"status":', '"status": "duplicate", "status":'))
        locator["parent"] = request["build_receipt"] = artifact_ref(parent)
    atomic_json(parts[2], request)
    locator["authority_request"] = artifact_ref(parts[2])
    atomic_json(parts[0] / "checkpoint.local.json", {"source_sha256": parts[1]["screen"], "request": artifact_ref(parts[2])})
    locators = [] if damage == "missing_locator" else [locator] * (2 if damage == "duplicate_locator" else 1)
    with pytest.raises(TalkCutError):
        collect(parts, locators)
