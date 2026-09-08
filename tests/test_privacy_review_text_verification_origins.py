"""Synthetic typed JUnit origins retain source, whole-file and mixed-prose gates."""
import copy
import json
import sys
from pathlib import Path

import pytest
from test_privacy_checks import commit, git
from test_privacy_replay import project
from test_privacy_review_text_origins import PHRASE, PROSE, observe

from talkcut import privacy_checks as privacy
from talkcut import verification
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def fixture(tmp_path):
    """Synthetic retained records; no provider or test command is executed."""
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    source = root / "tests/test_generated.py"
    source.parent.mkdir()
    source.write_text(f"def {PHRASE}():\n    return 1\n")
    producer = root / "src/talkcut/verification.py"
    producer.parent.mkdir(parents=True)
    producer.write_bytes(Path(verification.__file__).read_bytes())
    commit(root)
    preserved = tmp_path / "preserved-test.py"
    preserved.write_bytes(source.read_bytes())
    producer_copy = tmp_path / "preserved-producer.py"
    producer_copy.write_bytes(producer.read_bytes())
    directory, registered = project(tmp_path)
    folder = directory / "verification/synthetic"
    folder.mkdir(parents=True)
    xml = folder / "pytest.junit.xml"
    xml.write_text('<testsuite tests="1" errors="0" failures="0" skipped="0"><testcase classname="tests.test_generated" name="' + PHRASE + '" time="0.01"/></testsuite>')
    stdout, stderr = folder / "pytest.stdout", folder / "pytest.stderr"
    stdout.write_text("Explicitly synthetic command fixture; no claimed execution.\n")
    stderr.write_text("")
    command = {"schema_version": "verification-command/v1", "name": "pytest", "argv": [str(Path(sys.executable)), "run", "--locked", "pytest", "-q", "tests", "--junitxml", str(xml), "--basetemp", str(folder / "pytest-basetemp")],
               "cwd": str(root), "exit_code": 0, "error": None, "interrupted": False, "timed_out": False,
               "status": "PASS", "started_at": "synthetic-start", "finished_at": "synthetic-end", "timeout_seconds": 30, "wall_seconds": 0.01,
               "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr)}
    atomic_json(folder / "pytest.command.json", command)
    command["receipt"] = artifact_ref(folder / "pytest.command.json")
    atomic_json(folder / "executions.json", [command])
    files = {"tests/test_generated.py": artifact_ref(source)["sha256"], "src/talkcut/verification.py": artifact_ref(producer)["sha256"]}
    identity = {"code_revision": git(root, "rev-parse", "HEAD"), "files": files, "code_tree_hash": privacy.object_hash(files)}
    before = {"code_identity": identity, "documentation_example_files": {}, "documentation_example_hash": privacy.object_hash({})}
    parent = folder / "result.json"
    atomic_json(parent, {"schema_version": "oss-verification/v1", "run_id": "synthetic-unit", "repo_root": str(root), "directory": str(folder),
                        "producer": {"path": "src/talkcut/verification.py", "sha256": artifact_ref(producer)["sha256"]},
                        "before": before, "after": before, "executions": [command], "validations": {"junit": verification._junit(xml)}, "private_reason": PROSE})
    atomic_json(folder / "receipt.json", {"schema_version": "execution-receipt/v1", "operation": "verification:run", "run_id": "synthetic-unit",
                                          "result": artifact_ref(parent), "commands": artifact_ref(folder / "executions.json"),
                                          "dependencies": {"code_tree_hash": identity["code_tree_hash"], "documentation_example_hash": before["documentation_example_hash"]}})
    authority = {"schema_version": "review-verification-source-authority/v1", "report": artifact_ref(parent),
                 "receipt": artifact_ref(folder / "receipt.json"), "producer": artifact_ref(producer_copy), "copies": []}
    atomic_json(folder / "origin-authority.json", authority)
    locator = {"schema_version": "review-text-origin/v1", "kind": "junit_test_name", "parent": artifact_ref(parent),
               "authority": artifact_ref(folder / "origin-authority.json"), "selector": ["validations", "junit", "nodes", 0, "name"],
               "source": {"original_path": str(source), "snapshot": artifact_ref(preserved), "git_revision": identity["code_revision"],
                          "git_path": "tests/test_generated.py", "git_blob": git(root, "rev-parse", "HEAD:tests/test_generated.py")}}
    atomic_json(directory / "checkpoint.local.json", {"source_sha256": registered["screen"], "ref": artifact_ref(parent)})
    return root, directory, registered, parent, locator


def rebind(parts):
    """Rebind synthetic provenance to reach a specific content predicate."""
    _, directory, registered, parent, locator = parts
    root_path = Path(locator["authority"]["path"])
    authority = json.loads(root_path.read_bytes())
    receipt_path = Path(authority["receipt"]["path"])
    receipt = json.loads(receipt_path.read_bytes())
    receipt["result"] = artifact_ref(parent)
    report = json.loads(parent.read_bytes())
    receipt["dependencies"]["code_tree_hash"] = report["before"]["code_identity"]["code_tree_hash"]
    atomic_json(receipt_path, receipt)
    authority.update(report=artifact_ref(parent), receipt=artifact_ref(receipt_path))
    atomic_json(root_path, authority)
    locator.update(parent=artifact_ref(parent), authority=artifact_ref(root_path))
    atomic_json(directory / "checkpoint.local.json", {"source_sha256": registered["screen"], "ref": artifact_ref(parent)})


def test_complete_junit_origin_retains_all_original_rows_and_authority(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, parent, locator = parts
    before = privacy.build_private_inventory(directory, registered, root)
    _, phrases_before, _ = observe(parts, [])
    _, phrases_after, _ = observe(parts)
    assert PHRASE in phrases_before and PHRASE not in phrases_after and PROSE in phrases_after
    after = privacy.build_private_inventory(directory, registered, root, review_text_origins=[locator], review_text_origin_authorities=[locator["authority"]])
    new = {row["path"]: row for row in after["entries"]}
    assert all(new[row["path"]] == row for row in before["entries"])
    assert new[locator["authority"]["path"]]["sha256"] == locator["authority"]["sha256"]
    assert new[str(parent)]["classification"] == "review"


@pytest.mark.parametrize("private_key", ["reason", "rationale", "details", "transcript", "owner_note"])
def test_junit_name_never_overrides_another_private_origin(tmp_path, private_key):
    parts = fixture(tmp_path)
    value = json.loads(parts[-2].read_bytes())
    value[private_key] = PHRASE
    atomic_json(parts[-2], value)
    rebind(parts)
    _, phrases, _ = observe(parts)
    assert PHRASE in phrases


@pytest.mark.parametrize("mutation", ["extra_node", "missing_node", "name", "classname", "bool_seconds", "counts", "parameter", "details", "xml"])
def test_junit_complete_xml_table_is_not_a_caller_label(tmp_path, mutation):
    parts = fixture(tmp_path)
    value = json.loads(parts[-2].read_bytes())
    junit = value["validations"]["junit"]
    if mutation == "extra_node":
        junit["nodes"].append(copy.deepcopy(junit["nodes"][0]))
    elif mutation == "missing_node":
        junit["nodes"].clear()
    elif mutation == "counts":
        junit["counts"]["tests"] = True
    elif mutation == "xml":
        path = Path(junit["raw"]["path"])
        path.write_text(path.read_text().replace('time="0.01"', 'time="0.02"'))
        junit["raw"] = artifact_ref(path)
    else:
        field = {"name": "name", "classname": "classname", "bool_seconds": "seconds", "parameter": "name", "details": "details"}[mutation]
        junit["nodes"][0][field] = PHRASE + "[private]" if mutation == "parameter" else [PROSE] if mutation == "details" else True if mutation == "bool_seconds" else PROSE
    atomic_json(parts[-2], value)
    rebind(parts)
    with pytest.raises(TalkCutError, match="JUnit"):
        observe(parts)


@pytest.mark.parametrize("part", [True, 0.0, "0", -1, 100000])
def test_junit_selector_requires_an_exact_integer(tmp_path, part):
    parts = fixture(tmp_path)
    parts[-1]["selector"][3] = part
    with pytest.raises(TalkCutError, match="selector"):
        observe(parts)


def test_xml_and_report_agreement_cannot_invent_a_source_function(tmp_path):
    parts = fixture(tmp_path)
    value = json.loads(parts[-2].read_bytes())
    xml = Path(value["validations"]["junit"]["raw"]["path"])
    xml.write_text(xml.read_text().replace(PHRASE, PHRASE + "_forged"))
    value["validations"]["junit"] = verification._junit(xml)
    atomic_json(parts[-2], value)
    rebind(parts)
    with pytest.raises(TalkCutError, match="exact unparameterized original function"):
        observe(parts)
