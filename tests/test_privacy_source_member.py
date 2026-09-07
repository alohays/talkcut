"""Explicit source member byte observations preserve complete source denominators."""
import copy
import json
import os
import shutil
from pathlib import Path

import pytest
from _privacy_source_tree import fixture as source_fixture
from _privacy_source_tree import privacy
from test_privacy_historical_source_tree import snapshot

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def fixture(tmp_path, *, historical=False, full=False, index=0):
    parts = source_fixture(tmp_path)
    history = None
    if historical:
        history, _ = snapshot(parts)
        (parts[3] / "main.cpp").write_text("changed current bytes; historical bytes remain separate\n")
    row = json.loads(parts[5].read_bytes())["files"][index]
    value = dict(row) if full else {key: row[key] for key in ("path", "sha256")}
    parent = parts[2] / "diagnostic.json"
    atomic_json(parent, {"frames": [{"value": value, "origin_path": str(parts[5])}],
        "private_note": "This authored confidential diagnostic remains private and provides no evidence that the original execution ran."})
    locator = {"parent": artifact_ref(parent), "pointer": "/frames/0/value", "authority_build": artifact_ref(parts[4]),
        "authority_manifest": artifact_ref(parts[5]), "manifest_row_index": index, "origin_pointer": "/frames/0/origin_path"}
    refresh(parts, parent, locator)
    return parts, parent, locator, history


def refresh(parts, parent, locator):
    locator["parent"] = artifact_ref(parent)
    checkpoint = json.loads((parts[0] / "checkpoint.local.json").read_bytes())
    checkpoint["private_member"] = artifact_ref(parent)
    atomic_json(parts[0] / "checkpoint.local.json", checkpoint)


def collect(parts, locator, history=None, *, locators=None, authorities=None):
    return privacy.build_private_inventory(parts[0], parts[1], Path.cwd(),
        auxiliary_source_trees=([parts[-1]] if history is None else []) if authorities is None else authorities,
        auxiliary_historical_source_trees=[history] if history else [],
        source_tree_member_reobservations=[locator] if locators is None else locators)


def observe(parts, locator, history=None, *, locators=None):
    authorities = (privacy._auxiliary_historical_source_tree_inventory([history], parts[0], Path.cwd(), set(parts[1].values()))
        if history else privacy._auxiliary_source_tree_inventory([parts[-1]], parts[0], Path.cwd(), set(parts[1].values())))
    return privacy._source_tree_member_reobservation_inventory([locator] if locators is None else locators,
        authorities, parts[0], Path.cwd(), set(parts[1].values()))


@pytest.mark.parametrize("historical", [False, True])
@pytest.mark.parametrize("full", [False, True])
@pytest.mark.parametrize("index", [0, 1, 2])
def test_member_keeps_complete_tree_and_actual_private_context(tmp_path, historical, full, index):
    parts, parent, locator, history = fixture(tmp_path, historical=historical, full=full, index=index)
    with pytest.raises(TalkCutError):
        privacy._file(json.loads(parent.read_bytes())["frames"][0]["value"])
    if index == 0:
        with pytest.raises(TalkCutError):
            collect(parts, locator, history, locators=[])
    result = collect(parts, locator, history)
    row = result["known_graph"]["source_tree_member_reobservations"][0]
    assert row["row_count"] == 3 and row["manifest_row_index"] == index
    assert row["authority_kind"] == ("historical" if historical else "current")
    assert row["claim_status"] == row["execution_status"] == row["classification_status"] == "UNVERIFIED"
    assert row["member"]["actual"] == artifact_ref(Path(row["member"]["actual"]["path"]))
    entries = {row["path"]: row for row in result["entries"]}
    roots = [parts[3]]
    if history:
        roots.append(Path(history["snapshot"]["path"]).parent / "source")
        assert row["current_row_count"] == 3
        assert row["member"]["actual"]["path"].startswith(str(roots[-1]))
        assert not result["known_graph"]["auxiliary_source_trees"]
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file():
                assert entries[str(path)]["sha256"] == artifact_ref(path)["sha256"]
    assert entries[str(parent)]["classification"] == "review"
    _, phrases, _ = privacy._known_private_inventory(parts[0], parts[1], Path.cwd(),
        auxiliary_source_trees=[] if history else [parts[-1]], auxiliary_historical_source_trees=[history] if history else [],
        source_tree_member_reobservations=[locator])
    assert json.loads(parent.read_bytes())["private_note"] in phrases
    assert result["classification_status"] == "UNVERIFIED" and not result["excluded_directories"]
    assert json.loads(parts[4].read_bytes())["status"] == "AUTHORED_NOT_EXECUTED"
    assert result["entries"] == collect(parts, locator, history)["entries"]


@pytest.mark.parametrize("damage", [
    "parent_hash", "build_hash", "manifest_hash", "build_same_byte_copy", "manifest_same_byte_copy", "no_authority",
    "index_bool", "index_float", "index_negative", "index_large", "index_wrong", "row_path", "row_hash", "row_bytes_bool",
    "row_bytes_float", "row_bytes_wrong", "row_extra", "row_missing", "row_absolute", "row_dotdot", "row_dot", "row_double_slash",
    "origin_wrong", "origin_same_byte_manifest", "sibling_frame", "nested_origin", "same_pointer", "pointer_scalar", "bad_escape",
    "leading_zero", "negative_pointer", "bool_pointer", "escaped_prefix", "array_owner", "extra_locator", "duplicate_locator",
    "source_change", "nonmember_change", "extra_source", "manifest_change", "nested_formal", "current_execution", "transcript",
    "protected_parent", "outside_parent", "parent_symlink", "parent_directory_alias", "parent_hardlink", "parent_dotdot",
    "parent_extra_ref_field", "parent_bytes_bool", "authority_extra_ref_field", "stale_parent", "member_alias", "manifest_alias",
    "unconsumed_tool_context", "overlap_full_tree", "registered_parent",
])
def test_member_wrong_context_authority_row_or_bytes_refuses(tmp_path, damage):
    parts, parent, locator, history = fixture(tmp_path)
    data = json.loads(parent.read_bytes()); row = data["frames"][0]["value"]
    locators = [locator]; authorities = None; changed = False
    if damage in ("parent_hash", "build_hash", "manifest_hash"):
        key = {"parent_hash": "parent", "build_hash": "authority_build", "manifest_hash": "authority_manifest"}[damage]
        locator[key]["sha256"] = "f" * 64
    elif damage in ("build_same_byte_copy", "manifest_same_byte_copy"):
        key, original = ("authority_build", parts[4]) if damage.startswith("build") else ("authority_manifest", parts[5])
        other = parent.with_name("copied-authority.json"); shutil.copyfile(original, other); locator[key] = artifact_ref(other)
    elif damage == "no_authority": authorities = []
    elif damage.startswith("index_"):
        locator["manifest_row_index"] = {"index_bool": False, "index_float": 0.0, "index_negative": -1, "index_large": 3, "index_wrong": 1}[damage]
    elif damage.startswith("row_"):
        changed = True
        if damage == "row_path": row["path"] = "main.cpp"
        elif damage == "row_hash": row["sha256"] = "f" * 64
        elif damage == "row_bytes_bool": row["bytes"] = False
        elif damage == "row_bytes_float": row["bytes"] = 0.0
        elif damage == "row_bytes_wrong": row["bytes"] = 1
        elif damage == "row_extra": row["claim_status"] = "PASS"
        elif damage == "row_missing": row.pop("sha256")
        elif damage == "row_absolute": row["path"] = str(parts[3] / ".gitmodules")
        elif damage == "row_dotdot": row["path"] = "../source/.gitmodules"
        elif damage == "row_dot": row["path"] = "./.gitmodules"
        elif damage == "row_double_slash": row["path"] = "sub//metadata.json"
    elif damage == "origin_wrong": data["frames"][0]["origin_path"] = str(parts[4]); changed = True
    elif damage == "origin_same_byte_manifest":
        other = parent.with_name("copied-manifest.json"); shutil.copyfile(parts[5], other)
        data["frames"][0]["origin_path"] = str(other); changed = True
    elif damage == "sibling_frame":
        data["frames"].append(copy.deepcopy(data["frames"][0])); locator["origin_pointer"] = "/frames/1/origin_path"; changed = True
    elif damage == "nested_origin":
        data["frames"][0]["nested"] = {"origin": str(parts[5])}; locator["origin_pointer"] = "/frames/0/nested/origin"; changed = True
    elif damage == "same_pointer": locator["origin_pointer"] = locator["pointer"]
    elif damage == "pointer_scalar": locator["pointer"] = "/private_note/row"
    elif damage == "bad_escape": locator["pointer"] = "/frames/0/~2value"
    elif damage == "leading_zero": locator["pointer"] = "/frames/00/value"
    elif damage == "negative_pointer": locator["pointer"] = "/frames/-1/value"
    elif damage == "bool_pointer": locator["pointer"] = "/frames/false/value"
    elif damage == "escaped_prefix":
        data["frames/0"] = {"origin_path": str(parts[5])}; locator["origin_pointer"] = "/frames~10/origin_path"; changed = True
    elif damage == "array_owner":
        data["frames"] = [row, str(parts[5])]; locator.update(pointer="/frames/0", origin_pointer="/frames/1"); changed = True
    elif damage == "extra_locator": locator["root"] = str(parts[3])
    elif damage == "duplicate_locator": locators *= 2
    elif damage == "source_change": (parts[3] / ".gitmodules").write_text("changed")
    elif damage == "nonmember_change": (parts[3] / "main.cpp").write_text("changed")
    elif damage == "extra_source": (parts[3] / "extra.cpp").write_text("new unlisted bytes")
    elif damage == "manifest_change": parts[5].write_text("{}")
    elif damage == "nested_formal": data["nested"] = {"schema_version": "multimodal-review/v1"}; changed = True
    elif damage == "current_execution": data["schema_version"] = "execution-receipt/v1"; changed = True
    elif damage == "transcript": data.update(schema_version="transcript/v1", source_sha256=parts[1]["screen"]); changed = True
    elif damage in ("protected_parent", "outside_parent", "parent_symlink", "parent_directory_alias", "parent_hardlink", "parent_dotdot"):
        if damage == "protected_parent": target = parts[0] / "transcripts/diagnostic.json"
        elif damage == "outside_parent": target = tmp_path / "diagnostic.json"
        elif damage == "parent_directory_alias":
            alias = parts[0] / "alias"; alias.symlink_to(parts[2], target_is_directory=True); target = alias / parent.name
        elif damage == "parent_dotdot": target = parent.parent / "source/../diagnostic.json"
        else: target = parent.with_name("alias.json")
        if damage == "parent_symlink": target.symlink_to(parent.name)
        elif damage == "parent_hardlink": os.link(parent, target)
        elif damage not in ("parent_directory_alias", "parent_dotdot"): shutil.copyfile(parent, target)
        locator["parent"] = {"path": str(target), "sha256": artifact_ref(parent)["sha256"]}
    elif damage == "parent_extra_ref_field": locator["parent"]["approved"] = True
    elif damage == "parent_bytes_bool": locator["parent"]["bytes"] = True
    elif damage == "authority_extra_ref_field": locator["authority_build"]["root"] = str(parts[3])
    elif damage == "stale_parent": parent.write_bytes(parent.read_bytes() + b"\n")
    elif damage == "member_alias":
        member = parts[3] / ".gitmodules"; member.unlink(); member.symlink_to(parts[0] / "transcripts/empty.stderr.txt")
    elif damage == "manifest_alias":
        parts[5].unlink(); parts[5].symlink_to("source-before.local.json")
    elif damage == "unconsumed_tool_context":
        data = {"producer": data}; locator.update(pointer="/producer/frames/0/value", origin_pointer="/producer/frames/0/origin_path"); changed = True
    elif damage == "overlap_full_tree":
        parent = parts[6]; data = json.loads(parent.read_bytes()); locator.update(parent=artifact_ref(parent),
            pointer="/runtime/actual_build_source_tree/files/0", origin_pointer="/runtime/build_source_after/path")
    elif damage == "registered_parent":
        authority = privacy._auxiliary_source_tree_inventory([parts[-1]], parts[0], Path.cwd(), set(parts[1].values()))
        with pytest.raises(TalkCutError):
            privacy._source_tree_member_reobservation_inventory([locator], authority, parts[0], Path.cwd(), {artifact_ref(parent)["sha256"]})
        return
    if changed:
        atomic_json(parent, data); refresh(parts, parent, locator)
    with pytest.raises(TalkCutError):
        collect(parts, locator, history, locators=locators, authorities=authorities)


@pytest.mark.parametrize("field", ["value", "schema_version", "origin_path", "authority_manifest", "authority_build"])
def test_member_duplicate_json_keys_refuse_even_if_last_value_is_valid(tmp_path, field):
    parts, parent, locator, _history = fixture(tmp_path)
    if field.startswith("authority_"):
        path = Path(locator[field]["path"])
        data = json.loads(path.read_bytes()); key = "files" if field.endswith("manifest") else "schema_version"
        path.write_text("{" + json.dumps(key) + ":null," + json.dumps(data)[1:])
        if field.endswith("manifest"):
            before = parts[2] / "build-execution-synthetic/source-before.local.json"
            shutil.copyfile(path, before)
            build = json.loads(parts[4].read_bytes()); build.update(source_before=artifact_ref(before), source_after=artifact_ref(path))
            atomic_json(parts[4], build)
        locator.update(authority_build=artifact_ref(parts[4]), authority_manifest=artifact_ref(parts[5]))
        # Preserve the duplicate bytes while obtaining a fresh complete authority.
        authority_locator = {"build": locator["authority_build"], "manifest": locator["authority_manifest"]}
        authority = privacy._auxiliary_source_tree_inventory([authority_locator], parts[0], Path.cwd(), set(parts[1].values()))
        with pytest.raises(TalkCutError, match="duplicate"):
            privacy._source_tree_member_reobservation_inventory([locator], authority, parts[0], Path.cwd(), set(parts[1].values()))
        return
    data = json.loads(parent.read_bytes())
    if field == "schema_version":
        data["schema_version"] = "authored-private-observation/v1"
        parent.write_text('{"schema_version":"execution-receipt/v1",' + json.dumps(data)[1:])
    else:
        owner = data["frames"][0]
        encoded = "{" + json.dumps(field) + ':"hidden different value",' + json.dumps(owner)[1:]
        parent.write_text('{"frames":[' + encoded + "]}")
    refresh(parts, parent, locator)
    with pytest.raises(TalkCutError, match="duplicate"):
        collect(parts, locator)


@pytest.mark.parametrize("role", ["parent", "build", "manifest", "producer", "member"])
def test_member_same_byte_replacement_between_observations_refuses(tmp_path, monkeypatch, role):
    parts, parent, locator, _history = fixture(tmp_path)
    paths = {"parent": parent, "build": parts[4], "manifest": parts[5], "producer": parts[2] / "producer.py", "member": parts[3] / ".gitmodules"}
    original = privacy._source_tree_member_reobservation_inventory; calls = 0
    def replace(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs); calls += 1
        if calls == 1:
            path = paths[role]; other = path.with_name("replacement.bin"); other.write_bytes(path.read_bytes()); other.replace(path)
        return result
    monkeypatch.setattr(privacy, "_source_tree_member_reobservation_inventory", replace)
    with pytest.raises(TalkCutError, match="changed during inventory"):
        collect(parts, locator)


@pytest.mark.parametrize("damage", ["current_swap", "missing_snapshot", "snapshot_change", "snapshot_nonmember", "current_extra", "duplicate_authority"])
def test_historical_member_preserves_snapshot_and_current_authority_separation(tmp_path, damage):
    parts, _parent, locator, history = fixture(tmp_path, historical=True)
    if damage == "current_swap":
        with pytest.raises(TalkCutError): collect(parts, locator)
        return
    if damage == "missing_snapshot": Path(history["snapshot"]["path"]).unlink()
    elif damage == "snapshot_change": (Path(history["snapshot"]["path"]).parent / "source/.gitmodules").write_text("changed")
    elif damage == "snapshot_nonmember": (Path(history["snapshot"]["path"]).parent / "source/main.cpp").write_text("changed")
    elif damage == "current_extra":
        # Current extra files are part of the denominator, not a snapshot escape.
        extra = parts[3] / "new-current.cpp"; extra.write_text("new current bytes\n")
        result = collect(parts, locator, history)
        assert str(extra) in {row["path"] for row in result["entries"]}
        assert result["known_graph"]["source_tree_member_reobservations"][0]["current_row_count"] == 4
        return
    elif damage == "duplicate_authority":
        authorities = privacy._auxiliary_historical_source_tree_inventory([history], parts[0], Path.cwd(), set(parts[1].values()))
        with pytest.raises(TalkCutError, match="one exact"):
            privacy._source_tree_member_reobservation_inventory([locator], authorities * 2, parts[0], Path.cwd(), set(parts[1].values()))
        return
    with pytest.raises(TalkCutError): collect(parts, locator, history)
