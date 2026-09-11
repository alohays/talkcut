"""Nested exact observation context, using synthetic complete source trees."""
import json
from pathlib import Path

import pytest
from test_privacy_source_copy import collect, fixture, refresh

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, atomic_json


def nested(tmp_path):
    parts, parent, locator = fixture(tmp_path)
    initial = json.loads(parent.read_bytes())
    observation = {"manifest_value": initial["tree"], "parents": [{"note": "private"}, initial["recorder"]]}
    body = {"observations": [observation], "private_note": initial["private_note"]}
    locator.update(pointer="/observations/0/manifest_value", recorder_pointer="/observations/0/parents/1")
    return parts, parent, locator, body


@pytest.mark.parametrize("layout", ["actual_shape", "deeper", "escaped_keys", "numeric_object_key"])
def test_nested_recorder_exact_selected_object_preserves_full_denominator(tmp_path, layout):
    parts, parent, locator, body = nested(tmp_path)
    owner = body["observations"][0]
    if layout == "deeper":
        owner["parents"] = {"producer": {"original": owner["parents"][1]}}
        locator["recorder_pointer"] = "/observations/0/parents/producer/original"
    elif layout == "escaped_keys":
        body = {"opaque/nest": {"row~one": owner}}
        locator.update(pointer="/opaque~1nest/row~0one/manifest_value", recorder_pointer="/opaque~1nest/row~0one/parents/1")
    elif layout == "numeric_object_key":
        body["observations"] = {"0": owner}
    atomic_json(parent, body)
    refresh(parts, parent, locator)
    first = collect(parts, locator)
    assert first["entries"] == collect(parts, locator)["entries"]
    observed = first["known_graph"]["auxiliary_source_tree_reobservations"][0]
    assert observed["row_count"] == 3
    assert observed["claim_status"] == observed["execution_status"] == observed["classification_status"] == "UNVERIFIED"
    entries = {entry["path"]: entry for entry in first["entries"]}
    assert entries[str(parent)]["classification"] == "review"
    assert all(str(path) in entries for path in parts[3].rglob("*") if path.is_file())
    with pytest.raises(TalkCutError):
        collect(parts, locator, locators=[])


@pytest.mark.parametrize("damage", [
    "other_array_row", "sibling_object", "numeric_prefix", "word_prefix", "escaped_slash_prefix",
    "noncanonical_index", "negative_index", "bool_index", "bad_escape", "inside_manifest",
    "same_pointer", "ancestor", "array_owner", "empty_owner", "shorter_context",
])
def test_nested_recorder_rejects_non_descendant_or_ambiguous_context(tmp_path, damage):
    parts, parent, locator, body = nested(tmp_path)
    owner = body["observations"][0]
    recorder = owner["parents"][1]
    if damage == "other_array_row":
        body["observations"].append({"parents": [recorder]})
        locator["recorder_pointer"] = "/observations/1/parents/0"
    elif damage == "sibling_object":
        body["neighbor"] = {"parents": [recorder]}
        locator["recorder_pointer"] = "/neighbor/parents/0"
    elif damage == "numeric_prefix":
        body["observations"] = {"0": owner, "00": {"parents": [recorder]}}
        locator["recorder_pointer"] = "/observations/00/parents/0"
    elif damage == "word_prefix":
        body["observation"] = owner
        locator["pointer"] = "/observation/manifest_value"
    elif damage == "escaped_slash_prefix":
        body["observations/0"] = owner
        locator["pointer"] = "/observations~10/manifest_value"
    elif damage == "noncanonical_index": locator["recorder_pointer"] = "/observations/00/parents/1"
    elif damage == "negative_index": locator["recorder_pointer"] = "/observations/-1/parents/1"
    elif damage == "bool_index": locator["recorder_pointer"] = "/observations/false/parents/1"
    elif damage == "bad_escape": locator["recorder_pointer"] = "/observations/0/parents~2/1"
    elif damage == "inside_manifest": locator["recorder_pointer"] = "/observations/0/manifest_value/files/0"
    elif damage == "same_pointer": locator["recorder_pointer"] = locator["pointer"]
    elif damage == "ancestor": locator["recorder_pointer"] = "/observations/0"
    elif damage == "array_owner":
        body["observations"] = [owner["manifest_value"], {"parents": [recorder]}]
        locator.update(pointer="/observations/0", recorder_pointer="/observations/1/parents/0")
    elif damage == "empty_owner":
        body = {"tree": owner["manifest_value"], "nested": {"recorder": recorder}}
        locator.update(pointer="/tree", recorder_pointer="/nested/recorder")
    elif damage == "shorter_context":
        body["recorder"] = recorder
        locator["recorder_pointer"] = "/recorder"
    atomic_json(parent, body)
    refresh(parts, parent, locator)
    authorities = privacy._auxiliary_source_tree_inventory([parts[-1]], parts[0], Path.cwd(), set(parts[1].values()))
    with pytest.raises(TalkCutError):
        privacy._source_tree_reobservation_inventory([locator], authorities, parts[0], Path.cwd(), set(parts[1].values()))
