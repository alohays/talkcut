"""Bounded recursive discovery controls; generated source is never executed."""

import json

import pytest
from schema_role_independent_constants import FORMAL_SCHEMAS
from test_schema_role_guard_independent import copied_schema_repo as repository_fixture
from test_schema_role_guard_independent import explicitly_declare

from talkcut import formal_schemas, privacy_checks
from talkcut.project import TalkCutError

copied_schema_repo = repository_fixture


def schema_bytes(name):
    return json.dumps({"type": "object", "properties": {"schema_version": {"const": name}}})


def test_nested_python_undeclared_output_is_not_skipped(copied_schema_repo):
    path = copied_schema_repo / "src/talkcut/independent_nested/child.py"
    path.parent.mkdir()
    path.write_text('def emit():\n    return {"schema_version": "nested-undeclared-output/v7"}\n')
    with pytest.raises(TalkCutError):
        formal_schemas.validate_schema_coverage(copied_schema_repo, frozenset(FORMAL_SCHEMAS))


def test_nested_json_declaration_protects_new_formal_type(copied_schema_repo):
    path = copied_schema_repo / "schemas/independent_nested/child.schema.json"
    path.parent.mkdir()
    path.write_text(schema_bytes("nested-explicit-formal/v7"))
    with pytest.raises(TalkCutError, match="malformed or uncovered"):
        formal_schemas.formal_schema_types(copied_schema_repo)
    explicitly_declare(copied_schema_repo, ["nested-explicit-formal/v7"])
    assert privacy_checks._contains_formal_schema(
        {"metadata": [{"schema_version": "nested-explicit-formal/v7"}]}, copied_schema_repo, set()) is True


@pytest.mark.parametrize("namespace", ["src/talkcut", "schemas"])
def test_alias_directory_cannot_hide_recursive_policy_inputs(copied_schema_repo, tmp_path, namespace):
    target = tmp_path / "external-directory"
    target.mkdir()
    (target / ("child.py" if namespace.startswith("src") else "child.json")).write_text(
        '# Synthetic source, never imported.\n' if namespace.startswith("src") else '{}')
    (copied_schema_repo / namespace / "linked-directory").symlink_to(target, target_is_directory=True)
    with pytest.raises(TalkCutError):
        formal_schemas.formal_schema_types(copied_schema_repo)


def test_nested_schema_added_after_inventory_is_not_silently_omitted(copied_schema_repo, monkeypatch):
    actual = formal_schemas._read
    fired = []

    def add_after_first_read(row):
        data = actual(row)
        if not fired:
            path = copied_schema_repo / "schemas/added_during_read/child.json"
            path.parent.mkdir()
            path.write_text(schema_bytes("transcript/v1"))
            fired.append(True)
        return data

    monkeypatch.setattr(formal_schemas, "_read", add_after_first_read)
    with pytest.raises(TalkCutError):
        formal_schemas.validate_schema_coverage(copied_schema_repo, frozenset(FORMAL_SCHEMAS))
    assert fired == [True]


def test_directory_alias_substitution_during_read_is_rejected(copied_schema_repo, monkeypatch):
    directory = copied_schema_repo / "schemas/directory_under_read"
    directory.mkdir()
    path = directory / "child.json"
    path.write_text(schema_bytes("transcript/v1"))
    actual = formal_schemas._read
    fired = []

    def replace_after_selected_read(row):
        data = actual(row)
        if row[0] == str(path) and not fired:
            held = directory.with_name("retained_original_directory")
            directory.rename(held)
            directory.symlink_to(held, target_is_directory=True)
            fired.append(True)
        return data

    monkeypatch.setattr(formal_schemas, "_read", replace_after_selected_read)
    with pytest.raises(TalkCutError):
        formal_schemas.validate_schema_coverage(copied_schema_repo, frozenset(FORMAL_SCHEMAS))
    assert fired == [True]


def test_cache_rechecks_new_recursive_files(copied_schema_repo):
    assert formal_schemas.formal_schema_types(copied_schema_repo).issuperset(FORMAL_SCHEMAS)
    path = copied_schema_repo / "src/talkcut/added_after_cache/child.py"
    path.parent.mkdir()
    path.write_text('def emit():\n    return {"schema_version": "uncached-new-output/v7"}\n')
    with pytest.raises(TalkCutError):
        formal_schemas.formal_schema_types(copied_schema_repo)
