"""Contract-based declaration tests; no supplied Python source is executed."""

import ast
import json
from pathlib import Path

import pytest
from schema_role_independent_constants import (
    FORMAL_SCHEMAS as HISTORICAL_FORMAL_SCHEMAS,
)
from test_schema_role_guard_independent import copied_schema_repo as repository_fixture

from talkcut import formal_schemas, privacy_checks
from talkcut.project import TalkCutError

copied_schema_repo = repository_fixture
FORMAL_SCHEMAS = (*HISTORICAL_FORMAL_SCHEMAS, "draft-evaluation/v1")


def declaration_value(path, name):
    source = path.read_text()
    tree = ast.parse(source)
    nodes = [n for n in tree.body if
             isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)
             or isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id == name]
    assert len(nodes) == 1
    return source, nodes[0].value


def replace_value(path, name, new_source):
    source, value = declaration_value(path, name)
    lines = source.splitlines(keepends=True)
    start = sum(len(line) for line in lines[:value.lineno - 1]) + value.col_offset
    end = sum(len(line) for line in lines[:value.end_lineno - 1]) + value.end_col_offset
    path.write_text(source[:start] + new_source + source[end:])


def add_declaration(repo, schema, role="formal_artifact"):
    policy = repo / "src/talkcut/formal_schemas.py"
    _, value = declaration_value(policy, "FORMAL_SCHEMA_DECLARATIONS")
    entries = ast.literal_eval(value)
    assert isinstance(entries, tuple)
    new_entry = {"schema": schema, "owner": "talkcut.independent_future_contract", "role": role}
    replace_value(policy, "FORMAL_SCHEMA_DECLARATIONS", repr((*entries, new_entry)))


def test_installed_floor_is_exact_and_available_without_a_repository():
    installed = formal_schemas.formal_schema_types(None)
    assert isinstance(installed, frozenset)
    assert installed == frozenset(FORMAL_SCHEMAS)
    assert len(formal_schemas.LEGACY_SCHEMA_TYPES) == 140


@pytest.mark.parametrize("role", ["formal_artifact", "control_contract"])
def test_new_explicit_contract_extends_but_never_replaces_installed_floor(copied_schema_repo, role):
    schema = "independent-future-contract/v7"
    source = copied_schema_repo / "src/talkcut/independent_future_contract.py"
    source.write_text('def accepts(value):\n    return value.get("schema_version") == "independent-future-contract/v7"\n'
                      '\nraise RuntimeError("Declaration discovery must never import this module")\n')
    add_declaration(copied_schema_repo, schema, role)
    declared = formal_schemas.formal_schema_types(copied_schema_repo)
    assert declared.issuperset(FORMAL_SCHEMAS)
    assert schema in declared
    for value in ({"schema_version": schema}, {"nested": [{"schema_version": schema}]}):
        assert privacy_checks._contains_formal_schema(value, copied_schema_repo, set()) is True
    assert formal_schemas.formal_schema_types(None) == frozenset(FORMAL_SCHEMAS)


@pytest.mark.parametrize("damage", ["missing_declarations", "nonliteral_declarations", "duplicate_assignment", "bad_role", "conflicting_installed_role"])
def test_missing_malformed_or_conflicting_caller_policy_fails_closed(copied_schema_repo, damage):
    policy = copied_schema_repo / "src/talkcut/formal_schemas.py"
    if damage == "missing_declarations":
        source = policy.read_text()
        policy.write_text(source.replace("FORMAL_SCHEMA_DECLARATIONS", "MISSING_SCHEMA_DECLARATIONS"))
    elif damage == "nonliteral_declarations":
        replace_value(policy, "FORMAL_SCHEMA_DECLARATIONS", "get_untrusted_declarations()")
    elif damage == "duplicate_assignment":
        policy.write_text(policy.read_text() + "\nFORMAL_SCHEMA_DECLARATIONS = ()\n")
    elif damage == "bad_role":
        add_declaration(copied_schema_repo, "independent-invalid-role/v7", "metadata_role_typo")
    else:
        add_declaration(copied_schema_repo, "transcript/v1", "historical_metadata")
    with pytest.raises(TalkCutError):
        formal_schemas.formal_schema_types(copied_schema_repo)
    assert formal_schemas.formal_schema_types(None) == frozenset(FORMAL_SCHEMAS)


def test_caller_cannot_remove_installed_contracts(copied_schema_repo):
    policy = copied_schema_repo / "src/talkcut/formal_schemas.py"
    replace_value(policy, "LEGACY_SCHEMA_TYPES", "frozenset()")
    # Refusal or an unchanged installed union are both conservative outcomes.
    try:
        declared = formal_schemas.formal_schema_types(copied_schema_repo)
    except TalkCutError:
        pass
    else:
        assert declared.issuperset(FORMAL_SCHEMAS)
    assert privacy_checks._contains_formal_schema({"schema_version": "transcript/v1"}, None, set()) is True


def test_two_valid_but_conflicting_declarations_fail_closed(copied_schema_repo):
    path = copied_schema_repo / "src/talkcut/independent_future_contract.py"
    path.write_text('# Independent declaration fixture; no execution.\n')
    add_declaration(copied_schema_repo, "independent-conflicting-contract/v7", "formal_artifact")
    add_declaration(copied_schema_repo, "independent-conflicting-contract/v7", "control_contract")
    with pytest.raises(TalkCutError):
        formal_schemas.formal_schema_types(copied_schema_repo)


@pytest.mark.parametrize("source", [
    'def emit():\n    return {"schema_version": "independent-undeclared-output/v7"}\n',
    'def emit():\n    return dict(schema_version="independent-undeclared-output/v7")\n',
    'OUTPUT_SCHEMA = "independent-undeclared-output/v7"\ndef emit():\n    return {"schema_version": OUTPUT_SCHEMA}\n',
])
def test_new_undeclared_actual_output_fails_coverage(copied_schema_repo, source):
    path = copied_schema_repo / "src/talkcut/independent_future_contract.py"
    path.write_text(source)
    with pytest.raises(TalkCutError):
        formal_schemas.validate_schema_coverage(copied_schema_repo, frozenset(FORMAL_SCHEMAS))


def test_declared_output_passes_static_coverage_without_execution(copied_schema_repo):
    schema = "independent-declared-output/v7"
    path = copied_schema_repo / "src/talkcut/independent_future_contract.py"
    path.write_text('OUTPUT_SCHEMA = "independent-declared-output/v7"\ndef emit():\n'
                    '    return {"schema_version": OUTPUT_SCHEMA}\n'
                    '\nraise RuntimeError("Static coverage must never execute supplied source")\n')
    add_declaration(copied_schema_repo, schema)
    declared = formal_schemas.formal_schema_types(copied_schema_repo)
    formal_schemas.validate_schema_coverage(copied_schema_repo, declared)
    assert schema in declared


def test_unknown_output_expression_fails_closed(copied_schema_repo):
    path = copied_schema_repo / "src/talkcut/independent_future_contract.py"
    path.write_text('def emit():\n    return {"schema_version": dynamic_schema()}\n')
    with pytest.raises(TalkCutError):
        formal_schemas.validate_schema_coverage(copied_schema_repo, frozenset(FORMAL_SCHEMAS))


def test_three_existing_named_outputs_are_explicitly_covered():
    resolved = {
        ("acceptance.py", "EVALUATOR_VERSION"): "goal-acceptance/v1",
        ("context_collection.py", "COLLECTION_SCHEMA"): "lecture-context-collection/v1",
        ("contracts.py", "CONTRACT_VERSION"): "dgist-first-lecture/v1",
    }
    for (filename, name), expected in resolved.items():
        source = Path.cwd() / "src/talkcut" / filename
        _, value = declaration_value(source, name)
        assert ast.literal_eval(value) == expected
        assert expected in formal_schemas.formal_schema_types(None)
    formal_schemas.validate_schema_coverage(Path.cwd(), formal_schemas.formal_schema_types(None))


def test_absent_caller_policy_retains_installed_floor_with_covered_inputs(copied_schema_repo):
    policy = copied_schema_repo / "src/talkcut/formal_schemas.py"
    policy.unlink()
    assert formal_schemas.formal_schema_types(copied_schema_repo) == frozenset(FORMAL_SCHEMAS)
    for schema in FORMAL_SCHEMAS:
        assert privacy_checks._contains_formal_schema(
            {"nested": [{"schema_version": schema}]}, copied_schema_repo, set()) is True
    assert formal_schemas.formal_schema_types(None) == frozenset(FORMAL_SCHEMAS)


@pytest.mark.parametrize("origin", ["literal_output", "constant_output", "schema_const", "schema_enum", "nested_schema"])
def test_removing_policy_cannot_hide_a_previously_declared_output_or_schema(copied_schema_repo, origin):
    schema = "independent-removed-policy/v7"
    module = copied_schema_repo / "src/talkcut/independent_future_contract.py"
    module.write_text('# Synthetic owner; no supplied code executes.\n')
    if origin == "literal_output":
        module.write_text('def emit():\n    return {"schema_version": "independent-removed-policy/v7"}\n')
    elif origin == "constant_output":
        module.write_text('VERSION = "independent-removed-policy/v7"\ndef emit():\n    return dict(schema_version=VERSION)\n')
    else:
        target = copied_schema_repo / "schemas/removed-policy.schema.json"
        if origin == "nested_schema":
            target = copied_schema_repo / "schemas/independent_nested/child.json"
            target.parent.mkdir()
        declaration = {"enum": [schema]} if origin == "schema_enum" else {"const": schema}
        target.write_text(json.dumps({"properties": {"schema_version": declaration}}))
    add_declaration(copied_schema_repo, schema)
    assert schema in formal_schemas.formal_schema_types(copied_schema_repo)
    for payload in ({"schema_version": schema}, [{"nested": {"schema_version": schema}}]):
        assert privacy_checks._contains_formal_schema(payload, copied_schema_repo, set()) is True
    (copied_schema_repo / "src/talkcut/formal_schemas.py").unlink()
    with pytest.raises(TalkCutError, match="malformed or uncovered"):
        formal_schemas.formal_schema_types(copied_schema_repo)
    assert formal_schemas.formal_schema_types(None) == frozenset(FORMAL_SCHEMAS)
