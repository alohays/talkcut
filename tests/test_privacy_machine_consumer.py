"""Actual consumer traversal of complete synthetic source and artifact records.

Synthetic historical records exercise attribution, never an AV or execution claim.
All files followed by the real consumer exist with truthful content hashes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from test_privacy_checks import commit, git
from test_privacy_machine_wrapper_flow_aligned import authority as machine_fixture
from test_privacy_replay import project

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

PHRASE = "Synthetic machine code input requires its complete content inspection."


def fixture(tmp_path, origin=None):
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--initial-branch=main")
    (root / "README.md").write_text("Synthetic source authority test repository.\n")
    commit(root)
    directory, registered = project(root)
    folder = directory / "audits" / "machine"
    folder.mkdir(parents=True)
    source, raw, output, stderr = machine_fixture.__wrapped__(folder)
    ordinary = folder / "ordinary.py"
    ordinary.write_text("value = 1\n")
    body = json.loads(Path(output["path"]).read_bytes())
    inventory = body["private_inventory"]
    for collection in ("public_work_candidates", "unfollowed_refs"):
        inventory[collection][0].update(artifact_ref(ordinary))
    scope = PHRASE if origin == "same_parent_scope" else "Synthetic complete wrapper observation."
    body["staged_execution"]["scope"] = scope
    atomic_json(output["path"], body)
    output = artifact_ref(output["path"])
    script = folder / "wrapper.py"
    script.write_text('''import importlib.util
import json
import sys
from pathlib import Path
from talkcut.project import artifact_ref
root=Path.cwd()
directory=Path(__file__).parent
module_path=directory/'producer.py'
before=artifact_ref(module_path)
spec=importlib.util.spec_from_file_location('talkcut.privacy_checks_staged',module_path)
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
input_path=directory/'input.json'
project=directory.parent.parent
sources={r:s['sha256'] for r,s in json.loads((project/'project.json').read_text())['sources'].items()}
result=module.verify_release_privacy(artifact_ref(input_path),root,project_dir=project,expected_source_hashes=sources)
assert before==artifact_ref(module_path)
result['staged_execution']={'module':before,'module_unchanged':True,'public_code_modified':False,'scope':''' + repr(scope) + '''}
print(json.dumps(result,indent=2))
''')
    command_path = folder / "command.json"
    atomic_json(command_path, {
        "argv": [sys.executable, str(script)], "cwd": str(root), "error": None, "exit_code": 0,
        "finished_at": "2000-01-01T00:00:01Z", "interrupted": False, "name": "synthetic-origin-control",
        "schema_version": "verification-command/v1", "started_at": "2000-01-01T00:00:00Z",
        "status": "PASS", "stderr": stderr, "stdout": output, "timed_out": False,
        "timeout_seconds": 1, "wall_seconds": 1,
    })
    command = artifact_ref(command_path)
    record_path = folder / "record.json"
    atomic_json(record_path, {
        "schema_version": "private-staged-privacy-handoff/v1", "staged_source": source,
        "actual_scan": {"driver": artifact_ref(script), "input": raw, "receipt": command, "stdout": output},
    })
    authority_path = folder / "authority.json"
    atomic_json(authority_path, {
        "schema_version": "review-machine-field-authority/v1", "family": "staged_privacy_scan",
        "record": artifact_ref(record_path), "source": source, "script": artifact_ref(script), "input": raw,
        "command": command, "output": output,
    })
    authority = artifact_ref(authority_path)
    locators = [{"schema_version": "review-text-origin/v1", "kind": "machine_inventory_field",
                 "parent": output, "selector": ["private_inventory", collection, 0, "reason"], "authority": authority}
                for collection in ("public_work_candidates", "unfollowed_refs")]
    atomic_json(directory / "checkpoint.local.json", {"parent": output})
    if origin in {"separate_review", "transcript"}:
        path = directory / ("transcripts" if origin == "transcript" else "evidence") / "private.json"
        path.parent.mkdir(exist_ok=True)
        atomic_json(path, {"schema_version": "transcript/v1" if origin == "transcript" else "private-review/v1",
                           "source_sha256": registered["screen"], "text": PHRASE})
    return root, directory, registered, output, authority, locators


def observe(parts, locators=None):
    root, directory, registered, _, authority, defaults = parts
    chosen = defaults if locators is None else locators
    return privacy._known_private_inventory(directory, registered, root,
        review_text_origins=chosen, review_text_origin_authorities=[authority] if chosen else [])


def test_machine_leaf_integration_keeps_entire_private_parent_and_artifact_denominator(tmp_path):
    parts = fixture(tmp_path)
    root, directory, registered, parent, authority, locators = parts
    old_known, old_phrases, _ = observe(parts, [])
    known, phrases, graph = observe(parts)
    assert PHRASE in old_phrases and PHRASE not in phrases
    assert all(known[key] == value for key, value in old_known.items())
    assert known[parent["sha256"]] == "review"
    assert len(graph["review_text_origins"]) == 2
    assert all(row["claim_status"] == "UNVERIFIED" for row in graph["review_text_origins"])
    before = privacy.build_private_inventory(directory, registered, root)
    after = privacy.build_private_inventory(directory, registered, root, review_text_origins=locators,
        review_text_origin_authorities=[authority], archive_dir=tmp_path / "preserved")
    previous = {row["path"]: row for row in before["entries"]}
    current = {row["path"]: row for row in after["entries"]}
    assert all(current[name] == row for name, row in previous.items())
    assert len(current) >= len(previous) and not after["unresolved"]
    preserved = after["preserved_private_inputs"][parent["path"]]
    assert Path(preserved["path"]).read_bytes() == Path(parent["path"]).read_bytes()
    assert preserved["sha256"] == parent["sha256"]


@pytest.mark.parametrize("origin", ["one_unselected_copy", "same_parent_scope", "separate_review", "transcript"])
def test_machine_unselected_same_phrase_stays_protected_by_real_consumer(tmp_path, origin):
    parts = fixture(tmp_path, origin)
    selected = parts[-1][:1] if origin == "one_unselected_copy" else parts[-1]
    _, phrases, _ = observe(parts, selected)
    assert PHRASE in phrases
    scan = privacy.Scan({}, phrases)
    scan.payload(PHRASE.encode(), "synthetic-public-counterfactual")
    assert any(row["kind"] == "protected_transcript_phrase" for row in scan.findings)


@pytest.mark.parametrize("mutation", ["wrong_kind", "container", "boolean_index", "duplicate", "extra_field"])
def test_machine_consumer_refuses_unbound_or_nonleaf_requests(tmp_path, mutation):
    parts = fixture(tmp_path)
    selected = parts[-1]
    if mutation == "wrong_kind":
        selected[0]["kind"] = "retention_inventory_field"
    elif mutation == "container":
        selected[0]["selector"] = selected[0]["selector"][:-1]
    elif mutation == "boolean_index":
        selected[0]["selector"][2] = False
    elif mutation == "duplicate":
        selected.append(dict(selected[0]))
    else:
        selected[0]["source"] = {"path": "unused", "sha256": "a" * 64}
    with pytest.raises(TalkCutError):
        observe(parts, selected)
