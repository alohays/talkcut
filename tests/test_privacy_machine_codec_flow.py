"""Synthetic coding-declaration opposition; no supplied producer executes."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from talkcut import privacy_machine_origins as machine
from talkcut.project import TalkCutError


def write(path, value):
    raw = value.encode() if isinstance(value, str) else json.dumps(value).encode()
    path.write_bytes(raw)
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


def read(reference):
    path = Path(reference["path"])
    raw = path.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == reference["sha256"]
    return path, raw


def document(reference):
    return json.loads(read(reference)[1])


@pytest.fixture
def authority(tmp_path, request):
    fixture = (Path(__file__).parent / "fixtures/machine_inventory_writer.py.txt").read_text()
    producer = fixture + '''
def verify_release_privacy(raw_ref, repo_root, **kwargs):
    raw = _json(raw_ref)
    known, phrases, inventory = _known_private_inventory(repo_root, publication_bodies={role: raw[role] for role in ("pr_body", "release_body")})
    submitted = set()
    inventory["missing_from_submitted_corpus"] = sorted(set(known) - submitted)
    return {"schema_version": "synthetic-privacy-result/v1", "private_inventory": inventory, "evidence_refs": [raw_ref]}
'''
    source = write(tmp_path / "producer.py", request.param + producer)
    raw = write(tmp_path / "input.json", {
        role: write(tmp_path / (role + ".txt"), "Synthetic publication text")
        for role in ("pr_body", "release_body")
    })
    row = {"path": str(tmp_path / "ordinary.py"), "sha256": "b" * 64,
           "classification": "UNCLASSIFIED",
           "reason": "Synthetic machine code input requires its complete content inspection.",
           "matching_git_source_bytes": []}
    known = {"completeness": "UNVERIFIED", "known_refs": [], "known_ref_count": 0,
             "public_work_candidates": [row],
             "unfollowed_refs": [{key: row[key] for key in ("path", "sha256", "reason")}],
             "synthetic_failure_fixtures": [], "missing_from_submitted_corpus": []}
    output = write(tmp_path / "output.json", {
        "schema_version": "synthetic-privacy-result/v1", "private_inventory": known,
        "evidence_refs": [raw], "staged_execution": {"module": source, "module_unchanged": True, "public_code_modified": False, "scope": "Synthetic complete wrapper observation."},
    })
    stderr = write(tmp_path / "stderr.txt", "")
    return source, raw, output, stderr, request.param


@pytest.mark.parametrize("authority", [
    "",
    "# coding: talkcut_missing_codec\n",
    "# coding: utf-16\n",
], indirect=True)
def test_source_codec_must_match_actual_loader_decoding(tmp_path, authority):
    source, raw, output, stderr, suffix = authority
    wrapper = '''import importlib.util
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
project=directory/'project'
sources={r:s['sha256'] for r,s in json.loads((project/'project.json').read_text())['sources'].items()}
result=module.verify_release_privacy(artifact_ref(input_path),root,project_dir=project,expected_source_hashes=sources)
assert before==artifact_ref(module_path)
result['staged_execution']={'module':before,'module_unchanged':True,'public_code_modified':False,'scope':'Synthetic complete wrapper observation.'}
print(json.dumps(result,indent=2))
'''
    script = write(tmp_path / "wrapper.py", wrapper)
    command = write(tmp_path / "command.json", {
        "argv": [sys.executable, script["path"]], "cwd": str(tmp_path),
        "error": None, "exit_code": 0, "finished_at": "2000-01-01T00:00:01Z",
        "interrupted": False, "name": "synthetic-origin-control",
        "schema_version": "verification-command/v1", "started_at": "2000-01-01T00:00:00Z",
        "status": "PASS", "stderr": stderr, "stdout": output, "timed_out": False,
        "timeout_seconds": 1, "wall_seconds": 1,
    })
    record = write(tmp_path / "record.json", {
        "schema_version": "private-staged-privacy-handoff/v1", "staged_source": source,
        "actual_scan": {"driver": script, "input": raw, "receipt": command, "stdout": output},
    })
    selected = {"schema_version": "review-machine-field-authority/v1", "family": "staged_privacy_scan",
                "record": record, "source": source, "script": script, "input": raw,
                "command": command, "output": output}
    if suffix:
        with pytest.raises(TalkCutError, match="Machine origin producer"):
            machine.verify_privacy_scan(selected, tmp_path, read, document)
    else:
        bound = machine.verify_privacy_scan(selected, tmp_path, read, document)
        result = machine.fixed_inventory_field(
            bound, output, ["private_inventory", "public_work_candidates", 0, "reason"],
        )
        assert result["value"] == "Synthetic machine code input requires its complete content inspection."
