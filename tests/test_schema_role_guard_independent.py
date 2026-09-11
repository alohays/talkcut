"""Independent schema-role controls; synthetic metadata, no historical execution."""

import ast
import copy
import json
import shutil
from pathlib import Path

import pytest
from schema_role_independent_constants import (
    FORMAL_SCHEMAS,
    HISTORICAL_METADATA_SCHEMAS,
)
from test_privacy_inventory_alias_rows_mutations import local_case

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def explicitly_declare(repo, names):
    """Add literal reviewed policy in synthetic source without executing it."""
    owner = repo / "src/talkcut/independent_schema_owner.py"
    owner.write_text('raise RuntimeError("Never execute declaration owner")\n')
    policy = repo / "src/talkcut/formal_schemas.py"
    source = policy.read_text()
    nodes = [node for node in ast.parse(source).body
             if isinstance(node, ast.AnnAssign)
             and isinstance(node.target, ast.Name)
             and node.target.id == "FORMAL_SCHEMA_DECLARATIONS"]
    assert len(nodes) == 1
    value = nodes[0].value
    entries = ast.literal_eval(value)
    added = tuple({"schema": name, "owner": "talkcut.independent_schema_owner",
                   "role": "formal_artifact"} for name in names)
    lines = source.splitlines(keepends=True)
    start = sum(map(len, lines[:value.lineno - 1])) + value.col_offset
    end = sum(map(len, lines[:value.end_lineno - 1])) + value.end_col_offset
    policy.write_text(source[:start] + repr(entries + added) + source[end:])


def wrapped(value):
    return (value, {"unrelated": "kept", "nested": value}, [False, {"deeper": [value]}])


@pytest.mark.parametrize("schema", FORMAL_SCHEMAS)
def test_every_reviewed_formal_contract_remains_protected(schema):
    assert len(FORMAL_SCHEMAS) == len(set(FORMAL_SCHEMAS)) == 146
    for repo in (None, Path.cwd()):
        for value in wrapped({"schema_version": schema, "status": "UNVERIFIED"}):
            assert privacy._contains_formal_schema(value, repo, set()) is True


@pytest.mark.parametrize("schema", HISTORICAL_METADATA_SCHEMAS)
def test_historical_metadata_name_alone_does_not_declare_formal_role(schema):
    for value in wrapped({"schema_version": schema, "private_note": "Synthetic unverified note"}):
        assert privacy._contains_formal_schema(value, Path.cwd(), set()) is False


@pytest.mark.parametrize("schema", HISTORICAL_METADATA_SCHEMAS)
def test_metadata_role_never_removes_nested_formal_protection(schema):
    for formal in ("transcript/v1", "multimodal-review/v1", "execution-receipt/v1"):
        value = {"schema_version": schema, "metadata": {"parts": [{"schema_version": formal}]}}
        assert privacy._contains_formal_schema(value, Path.cwd(), {"a" * 64}) is True


def test_schema_like_text_and_dictionary_keys_do_not_make_type_claims():
    for schema in ("transcript/v1", "multimodal-review/v1", "execution-receipt/v1"):
        value = {schema: "a literal key", "note": schema, "nested": [schema]}
        assert privacy._contains_formal_schema(value, Path.cwd(), set()) is False


@pytest.fixture
def copied_schema_repo(tmp_path):
    """Complete source/declaration context; never import copied source."""
    repo = tmp_path / "source-context"
    for name in ("src", "schemas"):
        shutil.copytree(Path.cwd() / name, repo / name, ignore=shutil.ignore_patterns("__pycache__"))
    return repo


@pytest.mark.parametrize("mention", [
    '# synthetic-history/v9 is only a comment\n',
    'LABEL = "synthetic-history/v9"\n',
    'def recognizes(value):\n    return value.get("schema_version") == "synthetic-history/v9"\n',
    'EXPRESSION = "result.get(\\\"schema_version\\\") == \\\"synthetic-history/v9\\\""\n',
    'GRAMMAR = "dict(schema_version=synthetic-history/v9)"\n',
])
def test_incidental_new_mentions_cannot_change_existing_metadata_role(copied_schema_repo, mention):
    payload = {"schema_version": "synthetic-history/v9", "private_note": "Synthetic test only"}
    assert privacy._contains_formal_schema(payload, copied_schema_repo, set()) is False
    module = copied_schema_repo / "src/talkcut/synthetic_unexecuted_mentions.py"
    module.write_text(mention + '\nraise RuntimeError("This source must never execute")\n')
    assert privacy._contains_formal_schema(payload, copied_schema_repo, set()) is False
    for formal in ("terminal-ai-request/v1", "terminal-ai-execution/v1", "composite-review-receipt/v1"):
        assert privacy._contains_formal_schema({"schema_version": formal}, copied_schema_repo, set()) is True


@pytest.mark.parametrize("declaration", [
    {"const": "synthetic-new-formal/v7"},
    {"enum": ["synthetic-new-formal/v7", "synthetic-new-formal/v8"]},
])
def test_schema_requires_explicit_policy_before_extending_formal_protection(copied_schema_repo, declaration):
    schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
              "properties": {"schema_version": declaration}, "required": ["schema_version"]}
    target = copied_schema_repo / "schemas/independent-extension.schema.json"
    target.write_text(json.dumps(schema))
    names = declaration.get("enum", [declaration.get("const")])
    with pytest.raises(TalkCutError, match="malformed or uncovered"):
        privacy._contains_formal_schema({"schema_version": names[0]}, copied_schema_repo, set())
    explicitly_declare(copied_schema_repo, names)
    for name in names:
        for value in wrapped({"schema_version": name}):
            assert privacy._contains_formal_schema(value, copied_schema_repo, set()) is True
    assert privacy._contains_formal_schema({"schema_version": "transcript/v1"}, copied_schema_repo, set()) is True


def test_nested_real_schema_definition_remains_a_declaration(copied_schema_repo):
    target = copied_schema_repo / "schemas/independent-nested.schema.json"
    target.write_text(json.dumps({"$defs": {"entry": {"type": "object", "properties": {
        "schema_version": {"const": "synthetic-nested-formal/v7"}}, "required": ["schema_version"]}}}))
    with pytest.raises(TalkCutError, match="malformed or uncovered"):
        privacy._contains_formal_schema([{"schema_version": "synthetic-nested-formal/v7"}], copied_schema_repo, set())
    explicitly_declare(copied_schema_repo, ["synthetic-nested-formal/v7"])
    assert privacy._contains_formal_schema([{"schema_version": "synthetic-nested-formal/v7"}], copied_schema_repo, set()) is True


def test_schema_document_description_is_not_a_type_declaration(copied_schema_repo):
    target = copied_schema_repo / "schemas/independent-description.schema.json"
    target.write_text(json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema",
                                  "description": "Historical diagnostic synthetic-description/v7", "type": "object"}))
    assert privacy._contains_formal_schema({"schema_version": "synthetic-description/v7"}, copied_schema_repo, set()) is False


@pytest.mark.parametrize("payload", [
    '{"properties":{"schema_version":{"const":"synthetic-bad/v7"}}',
    '{"properties":{"schema_version":{"const":"synthetic-bad/v7","const":"synthetic-other/v7"}}}',
])
def test_malformed_or_duplicate_schema_declarations_fail_closed(copied_schema_repo, payload):
    target = copied_schema_repo / "schemas/independent-malformed.schema.json"
    target.write_text(payload)
    with pytest.raises(TalkCutError):
        privacy._contains_formal_schema({"schema_version": "synthetic-bad/v7"}, copied_schema_repo, set())


@pytest.mark.parametrize("layout", ["standalone_report", "nested_review_copy"])
def test_exact_synthetic_alias_metadata_stays_private_and_unverified(tmp_path, monkeypatch, layout):
    _, _, origin_path, request, origin = local_case(tmp_path, monkeypatch)
    typed = copy.deepcopy(origin["entries"][0])
    report = {"schema_version": "independent-execution-tool-alias-inventory/v1",
              "alias_checks": [{"inventory_entry": typed}], "note": "Private synthetic note"}
    pointer = "/alias_checks/0/inventory_entry"
    if layout == "nested_review_copy":
        report = {"schema_version": "independent-staged-privacy-review/v1", "copied": report}
        pointer = "/copied" + pointer
    parent = tmp_path / "synthetic-report.json"
    atomic_json(parent, report)
    before = (origin_path.read_bytes(), parent.read_bytes())
    request.update(parent=artifact_ref(parent), pointer=pointer)
    result = privacy._inventory_alias_row_inventory([request], tmp_path, Path.cwd(), set(), artifact_ref(origin_path))
    assert len(result) == 1 and result[0]["value"] == typed
    assert result[0]["claim_status"] == result[0]["execution_status"] == "UNVERIFIED"
    assert result[0]["history_supported"] is False
    assert before == (origin_path.read_bytes(), parent.read_bytes())
    assert json.loads(origin_path.read_bytes())["entry_count"] == 2


@pytest.mark.parametrize("damage", ["nested_transcript", "nested_review", "nested_execution", "registered_parent", "changed_row"])
def test_alias_metadata_role_preserves_formal_source_and_row_guards(tmp_path, monkeypatch, damage):
    _, _, origin_path, request, origin = local_case(tmp_path, monkeypatch)
    report = {"schema_version": "independent-staged-privacy-review/v1",
              "copied": {"schema_version": "independent-execution-tool-alias-inventory/v1",
                         "rows": [copy.deepcopy(origin["entries"][0])]}}
    if damage.startswith("nested_"):
        formal = {"nested_transcript": "transcript/v1", "nested_review": "multimodal-review/v1",
                  "nested_execution": "execution-receipt/v1"}[damage]
        report["copied"]["unrelated_formal_claim"] = [{"schema_version": formal}]
    elif damage == "changed_row":
        report["copied"]["rows"][0]["classification"] = "media"
    parent = tmp_path / "synthetic-report.json"
    atomic_json(parent, report)
    request.update(parent=artifact_ref(parent), pointer="/copied/rows/0")
    registered = {artifact_ref(parent)["sha256"]} if damage == "registered_parent" else set()
    expected = ("Formal or private source" if damage.startswith("nested_") else
                "parent is protected" if damage == "registered_parent" else "Bare inventory alias copy")
    with pytest.raises(TalkCutError, match=expected):
        privacy._inventory_alias_row_inventory([request], tmp_path, Path.cwd(), registered, artifact_ref(origin_path))
