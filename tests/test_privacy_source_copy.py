"""Full small source trees with authored build claims; byte observations only."""
import json
import shutil
from pathlib import Path

import pytest
from _privacy_source_tree import fixture as source_fixture
from _privacy_source_tree import privacy

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def fixture(tmp_path):
    parts = source_fixture(tmp_path)
    parent = parts[2] / "source-preservation.json"
    build = json.loads(parts[4].read_bytes())
    atomic_json(parent, {"tree": json.loads(parts[5].read_bytes()), "recorder": build["runner"],
        "private_note": "This invented private source-copy context must be preserved without any execution or publication approval."})
    locator = {"parent": artifact_ref(parent), "pointer": "/tree", "authority_build": artifact_ref(parts[4]), "recorder_pointer": "/recorder"}
    checkpoint = json.loads((parts[0] / "checkpoint.local.json").read_bytes())
    checkpoint["private_source_copy"] = artifact_ref(parent)
    atomic_json(parts[0] / "checkpoint.local.json", checkpoint)
    return parts, parent, locator


def refresh(parts, parent, locator):
    locator["parent"] = artifact_ref(parent)
    checkpoint = json.loads((parts[0] / "checkpoint.local.json").read_bytes())
    checkpoint["private_source_copy"] = artifact_ref(parent)
    atomic_json(parts[0] / "checkpoint.local.json", checkpoint)


def collect(parts, locator, *, locators=None, authorities=None):
    return privacy.build_private_inventory(parts[0], parts[1], Path.cwd(),
        auxiliary_source_trees=[parts[-1]] if authorities is None else authorities,
        auxiliary_source_tree_reobservations=[locator] if locators is None else locators)


def test_exact_source_copy_keeps_full_tree_and_private_parent_without_build_approval(tmp_path):
    parts, parent, locator = fixture(tmp_path)
    result = collect(parts, locator)
    row = result["known_graph"]["auxiliary_source_tree_reobservations"][0]
    assert row["row_count"] == 3
    assert row["claim_status"] == row["execution_status"] == row["classification_status"] == "UNVERIFIED"
    entries = {row["path"]: row for row in result["entries"]}
    assert entries[str(parent)]["classification"] == "review"
    for source in parts[3].rglob("*"):
        if source.is_file(): assert entries[str(source)]["sha256"] == artifact_ref(source)["sha256"]
    _, phrases, _ = privacy._known_private_inventory(parts[0], parts[1], Path.cwd(),
        auxiliary_source_trees=[parts[-1]], auxiliary_source_tree_reobservations=[locator])
    assert json.loads(parent.read_bytes())["private_note"] in phrases
    assert result["entries"] == collect(parts, locator)["entries"]
    assert result["classification_status"] == "UNVERIFIED"
    assert json.loads(parts[4].read_bytes())["status"] == "AUTHORED_NOT_EXECUTED"
    with pytest.raises(TalkCutError): collect(parts, locator, locators=[])
    attempted = json.loads(json.dumps(parts[-1]));attempted["copies"].append({"parent": artifact_ref(parent), "pointer": "/tree"})
    with pytest.raises(TalkCutError, match="explicit runtime tree role"):
        privacy._auxiliary_source_tree_inventory([attempted], parts[0], Path.cwd(), set(parts[1].values()))


@pytest.mark.parametrize("damage", [
    "parent_hash", "authority_hash", "authority_copy", "no_current_authority", "wrong_recorder_path_same_bytes", "recorder_hash",
    "wrong_pointer", "wrong_recorder_pointer", "pointer_scalar", "pointer_bad_escape", "pointer_array_bool", "non_sibling", "same_pointer",
    "changed_manifest_hash", "missing_row", "extra_row", "row_bytes_bool", "relative_escape", "extra_manifest_field", "duplicate", "extra_locator",
    "protected_parent", "outside_parent", "symlink_parent", "nested_formal", "source_transcript_parent", "registered_parent", "protected_recorder",
    "recorder_extra_field", "parent_shadow_history", "source_bytes_change", "authority_schema_change",
])
def test_source_copy_wrong_current_identity_origin_or_context_refuses(tmp_path, damage):
    parts, parent, locator = fixture(tmp_path)
    body = json.loads(parent.read_bytes());locators=[locator];authorities=[parts[-1]];changed=False
    if damage == "parent_hash": locator["parent"]["sha256"] = "f" * 64
    elif damage == "authority_hash": locator["authority_build"]["sha256"] = "f" * 64
    elif damage == "authority_copy":
        copied = parent.with_name("same-build.json");shutil.copyfile(parts[4], copied);locator["authority_build"] = artifact_ref(copied)
    elif damage == "no_current_authority": authorities=[]
    elif damage == "wrong_recorder_path_same_bytes":
        copied=parent.with_name("same-recorder.py");shutil.copyfile(Path(body["recorder"]["path"]),copied);body["recorder"]=artifact_ref(copied);changed=True
    elif damage == "recorder_hash": body["recorder"]["sha256"]="f"*64;changed=True
    elif damage == "wrong_pointer": locator["pointer"]="/other_tree"
    elif damage == "wrong_recorder_pointer": locator["recorder_pointer"]="/other_recorder"
    elif damage == "pointer_scalar": locator["pointer"]="/private_note/path"
    elif damage == "pointer_bad_escape": locator["pointer"]="/tree/~2"
    elif damage == "pointer_array_bool": locator["pointer"]="/tree/files/false"
    elif damage == "non_sibling": body["nested"]={"recorder":body.pop("recorder")};locator["recorder_pointer"]="/nested/recorder";changed=True
    elif damage == "same_pointer": locator["recorder_pointer"]="/tree"
    elif damage == "changed_manifest_hash": body["tree"]["sha256"]="f"*64;changed=True
    elif damage == "missing_row": body["tree"]["files"].pop();changed=True
    elif damage == "extra_row": body["tree"]["files"].append(body["tree"]["files"][0]);changed=True
    elif damage == "row_bytes_bool": assert body["tree"]["files"][0]["bytes"]==0;body["tree"]["files"][0]["bytes"]=False;changed=True
    elif damage == "relative_escape": body["tree"]["files"][0]["path"]="../escape";changed=True
    elif damage == "extra_manifest_field": body["tree"]["text"]="Private speech cannot be converted into a source manifest.";changed=True
    elif damage == "duplicate": locators *= 2
    elif damage == "extra_locator": locator["root"]=str(parts[3])
    elif damage in {"protected_parent", "outside_parent", "symlink_parent"}:
        if damage == "protected_parent": copied=parts[0]/'transcripts'/'copy.json'
        else: copied=(tmp_path if damage == "outside_parent" else parent.parent)/'alias.json'
        if damage == "symlink_parent": copied.symlink_to(parent.name)
        else: shutil.copyfile(parent,copied)
        locator["parent"]={"path":str(copied),"sha256":artifact_ref(copied)["sha256"]}
    elif damage == "nested_formal": body["nested"]={"schema_version":"execution-receipt/v1"};changed=True
    elif damage == "source_transcript_parent": body.update(schema_version="transcript/v1",source_sha256=parts[1]["screen"],text="Invented protected lecture words remain private.");changed=True
    elif damage == "registered_parent":
        observed=privacy._auxiliary_source_tree_inventory(authorities,parts[0],Path.cwd(),set(parts[1].values()))
        with pytest.raises(TalkCutError): privacy._source_tree_reobservation_inventory(locators,observed,parts[0],Path.cwd(),{locator['parent']['sha256']})
        return
    elif damage == "protected_recorder":
        copied=parts[0]/'transcripts'/'producer.py';shutil.copyfile(Path(body['recorder']['path']),copied);body['recorder']=artifact_ref(copied);changed=True
    elif damage == "recorder_extra_field": body['recorder']['approved']=True;changed=True
    elif damage == "parent_shadow_history":
        body['extra']='New current version';atomic_json(parent,body)
    elif damage == "source_bytes_change": (parts[3]/'main.cpp').write_text('changed actual file bytes\n')
    elif damage == "authority_schema_change":
        build=json.loads(parts[4].read_bytes());build['schema_version']='execution-receipt/v1';atomic_json(parts[4],build);locator['authority_build']=artifact_ref(parts[4]);authorities[0]['build']=artifact_ref(parts[4])
    if changed: atomic_json(parent,body);refresh(parts,parent,locator)
    with pytest.raises(TalkCutError): collect(parts,locator,locators=locators,authorities=authorities)


@pytest.mark.parametrize('role', ['parent','recorder','authority','manifest'])
def test_source_copy_same_byte_replacement_between_full_observations_refuses(tmp_path, monkeypatch, role):
    parts,parent,locator=fixture(tmp_path)
    paths={'parent':parent,'recorder':Path(json.loads(parent.read_bytes())['recorder']['path']),'authority':parts[4],'manifest':parts[5]}
    original=privacy._source_tree_reobservation_inventory;calls=0
    def replace(*args,**kwargs):
        nonlocal calls
        result=original(*args,**kwargs);calls+=1
        if calls==1:
            path=paths[role];other=path.with_name('replacement.bin');other.write_bytes(path.read_bytes());other.replace(path)
        return result
    monkeypatch.setattr(privacy,'_source_tree_reobservation_inventory',replace)
    with pytest.raises(TalkCutError,match='changed during inventory'):
        collect(parts,locator)


@pytest.mark.parametrize('field', ['tree', 'schema_version'])
def test_source_copy_duplicate_json_keys_cannot_hide_different_context(tmp_path, field):
    parts,parent,locator=fixture(tmp_path)
    body=json.loads(parent.read_bytes())
    if field=='tree': prefix='"tree":{"unexpected":"duplicate context"},'
    else:
        prefix='"schema_version":"execution-receipt/v1",'
        body['schema_version']='authored-private-observation/v1'
    parent.write_text('{'+prefix+json.dumps(body,separators=(',',':'))[1:]+'\n')
    refresh(parts,parent,locator)
    with pytest.raises(TalkCutError,match='duplicate'):
        collect(parts,locator)
