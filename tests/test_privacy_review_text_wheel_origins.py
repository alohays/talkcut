"""Complete synthetic ZIP extraction under separately registered inspection roots."""
import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest
from test_privacy_review_text_origins import fixture as inspection_fixture
from test_privacy_review_text_origins import observe

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

NAME = "synthetic_package-1.0.dist-info/entry_points.txt"


def fixture(tmp_path, members=None):
    parts = inspection_fixture(tmp_path)
    root, directory, registered, parent, old = parts
    archive = directory / "synthetic.whl"
    with zipfile.ZipFile(archive, "w") as output:
        for name, payload in members or [(NAME, b"Synthetic entry point metadata\n"), ("package/__init__.py", b"# Synthetic package\n")]:
            output.writestr(name, payload)
    authority = json.loads(Path(old["authority"]["path"]).read_bytes())
    selected = {k: Path(authority[k]["path"]) for k in ("verification", "snapshot", "request", "execution", "response")}
    report = json.loads(selected["verification"].read_bytes())
    report["validations"] = {"wheel": {"artifact": artifact_ref(archive)}}
    atomic_json(selected["verification"], report)
    snapshot = json.loads(selected["snapshot"].read_bytes())
    snapshot["verification"] = artifact_ref(selected["verification"])
    snapshot["dependencies"]["verification_hash"] = artifact_ref(selected["verification"])["sha256"]
    snapshot["input_refs"].append(artifact_ref(archive))
    atomic_json(selected["snapshot"], snapshot)
    request = json.loads(selected["request"].read_bytes())
    request.update(snapshot_hash=artifact_ref(selected["snapshot"])["sha256"], dependencies=snapshot["dependencies"],
                   input_artifacts=[artifact_ref(selected["snapshot"]), *snapshot["input_refs"]])
    atomic_json(selected["request"], request)
    inspection = json.loads(parent.read_bytes())
    inspection.update(request=artifact_ref(selected["request"]), snapshot=artifact_ref(selected["snapshot"]),
                      inspected_artifacts=[{**ref, "bytes": Path(ref["path"]).stat().st_size} for ref in request["input_artifacts"]])
    with zipfile.ZipFile(archive) as stored:
        rows = [{"name": m.filename, "bytes": m.file_size, "sha256": hashlib.sha256(stored.read(m)).hexdigest()} for m in stored.infolist() if not m.is_dir()]
    inspection["archives"] = {"wheel": {"artifact": artifact_ref(archive), "members": rows, "all_payloads_utf8": True,
                                        "repository_license_bytes_match": False, "embedded_private_media_or_executable_observed": False}}
    atomic_json(parent, inspection)
    locator = {"schema_version": "review-text-origin/v1", "kind": "wheel_member_name", "parent": artifact_ref(parent),
               "selector": ["archives", "wheel", "members", 0, "name"], "archive": artifact_ref(archive), "authority": old["authority"]}
    result = root, directory, registered, parent, locator
    rebind(result)
    return result


def rebind(parts):
    _, directory, _, parent, locator = parts
    root_path = Path(locator["authority"]["path"])
    authority = json.loads(root_path.read_bytes())
    for name in ("verification", "snapshot", "request"):
        authority[name] = artifact_ref(Path(authority[name]["path"]))
    authority["inspection"] = artifact_ref(parent)
    execution_path = Path(authority["execution"]["path"])
    execution = json.loads(execution_path.read_bytes())
    stdout = Path(execution["stdout"]["path"])
    atomic_json(stdout, {"stage": "inspection_completed_without_issuing_audit_verdict", "result": artifact_ref(parent)})
    execution["stdout"] = artifact_ref(stdout)
    atomic_json(execution_path, execution)
    authority["execution"] = artifact_ref(execution_path)
    response_path = Path(authority["response"]["path"])
    response = json.loads(response_path.read_bytes())
    response.update(inspection=artifact_ref(parent), actual_inspection_execution=artifact_ref(execution_path))
    atomic_json(response_path, response)
    authority["response"] = artifact_ref(response_path)
    atomic_json(root_path, authority)
    locator.update(parent=artifact_ref(parent), authority=artifact_ref(root_path))
    atomic_json(directory / "checkpoint.local.json", {"ref": artifact_ref(parent)})


def test_member_name_uses_complete_archive_and_preserves_all_original_rows(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, _, locator = parts
    before = privacy.build_private_inventory(directory, registered, root)
    _, old, _ = observe(parts, [])
    _, new, graph = observe(parts)
    assert NAME in old and NAME not in new
    observation = graph["review_text_origins"][0]
    assert len(observation["archive_members"]) == 2 and observation["claim_status"] == "UNVERIFIED"
    after = privacy.build_private_inventory(directory, registered, root, review_text_origins=[locator], review_text_origin_authorities=[locator["authority"]])
    rows = {row["path"]: row for row in after["entries"]}
    assert all(rows[row["path"]] == row for row in before["entries"])
    assert all(ref["path"] in rows for ref in observation["authority_refs"])


@pytest.mark.parametrize("mutation", ["missing", "extra", "hash", "bytes_bool", "name", "order", "extra_key"])
def test_complete_member_row_mutation_is_refused(tmp_path, mutation):
    parts = fixture(tmp_path)
    parent = json.loads(parts[-2].read_bytes())
    rows = parent["archives"]["wheel"]["members"]
    if mutation == "missing":
        rows.pop()
    elif mutation == "extra":
        rows.append(dict(rows[0]))
    elif mutation == "order":
        rows.reverse()
    elif mutation == "extra_key":
        rows[0]["public"] = True
    else:
        key, value = {"hash": ("sha256", "0" * 64), "bytes_bool": ("bytes", True), "name": ("name", "arbitrary-private-name")}[mutation]
        rows[0][key] = value
    atomic_json(parts[-2], parent)
    rebind(parts)
    with pytest.raises(TalkCutError, match="member"):
        observe(parts)


@pytest.mark.parametrize("mutation", ["traversal", "absolute", "backslash", "duplicate", "symlink", "binary"])
def test_whole_archive_unsafe_or_incomplete_member_structure_is_refused(tmp_path, mutation):
    name = {"traversal": "../outside", "absolute": "/outside", "backslash": "dir\\outside"}.get(mutation, NAME)
    if mutation == "symlink":
        info = zipfile.ZipInfo(NAME)
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        name = info
    members = [(name, b"\xff" if mutation == "binary" else b"synthetic")]
    if mutation == "duplicate":
        members.append(members[0])
    if mutation == "duplicate":
        with pytest.warns(UserWarning, match="Duplicate name"):
            parts = fixture(tmp_path, members)
    else:
        parts = fixture(tmp_path, members)
    with pytest.raises(TalkCutError, match="wheel"):
        observe(parts)


def test_private_prose_with_same_member_name_remains_protected(tmp_path):
    parts = fixture(tmp_path)
    parent = json.loads(parts[-2].read_bytes())
    parent["private_reason"] = NAME
    atomic_json(parts[-2], parent)
    rebind(parts)
    _, phrases, _ = observe(parts)
    assert NAME in phrases
