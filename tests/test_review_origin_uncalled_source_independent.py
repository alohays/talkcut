"""Synthetic original command selection must agree with the selected source field."""

import copy
import json
from pathlib import Path

import pytest
from test_privacy_checks import commit, git
from test_privacy_review_text_origins import PHRASE, observe
from test_privacy_review_text_verification_origins import fixture

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def integration_fixture(tmp_path, selected_in_command):
    parts = fixture(tmp_path)
    root, directory, _, parent, locator = parts
    other = root / "tests/test_other.py"
    other.write_text("def test_other_generated_case():\n    pass\n")
    commit(root)
    report = json.loads(parent.read_bytes())
    identity = report["before"]["code_identity"]
    identity["files"]["tests/test_other.py"] = artifact_ref(other)["sha256"]
    identity["code_revision"] = git(root, "rev-parse", "HEAD")
    identity["code_tree_hash"] = privacy.object_hash(identity["files"])
    report["after"] = copy.deepcopy(report["before"])
    command = report["executions"][0]
    xml = report["validations"]["junit"]["raw"]["path"]
    command["argv"] = [command["argv"][0], "-m", "pytest", "-q",
                       "tests/test_generated.py" if selected_in_command else "tests/test_other.py",
                       "--basetemp=" + str(parent.parent / "synthetic-basetemp"), "--junitxml=" + xml]
    command_path = Path(command["receipt"]["path"])
    atomic_json(command_path, {k: v for k, v in command.items() if k != "receipt"})
    command["receipt"] = artifact_ref(command_path)
    report["schema_version"] = "public-integration-validation/v1"
    report["commands"] = report.pop("executions")
    report["junit"] = report.pop("validations")["junit"]
    atomic_json(parent, report)
    authority_path = Path(locator["authority"]["path"])
    authority = json.loads(authority_path.read_bytes())
    authority.update(report=artifact_ref(parent), receipt=None)
    atomic_json(authority_path, authority)
    locator.update(parent=artifact_ref(parent), authority=artifact_ref(authority_path),
                   selector=["junit", "nodes", 0, "name"])
    locator["source"]["git_revision"] = identity["code_revision"]
    atomic_json(directory / "checkpoint.local.json", {"ref": artifact_ref(parent)})
    return parts


def test_selected_source_in_exact_integration_command_is_valid_metadata(tmp_path):
    parts = integration_fixture(tmp_path, True)
    _, protected, graph = observe(parts)
    assert PHRASE not in protected
    assert graph["review_text_origins"][0]["claim_status"] == "UNVERIFIED"


def test_uncalled_source_cannot_authorize_a_junit_name(tmp_path):
    parts = integration_fixture(tmp_path, False)
    with pytest.raises(TalkCutError):
        observe(parts)
