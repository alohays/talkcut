"""Explicit type ownership, recursive protection and compatibility policy."""
import ast
import json
from pathlib import Path

import pytest

from talkcut import formal_schemas as policy
from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, atomic_json

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures/formal_schema_policy'
LEGACY = json.loads((FIXTURES / 'legacy140.json').read_bytes())
OWNED = json.loads((FIXTURES / 'owned6.json').read_bytes())
HISTORICAL = json.loads((FIXTURES / 'historical11.json').read_bytes())
DRAFT = {'schema': 'draft-evaluation/v1', 'owner': 'talkcut.draft', 'role': 'formal_artifact'}
PROTECTED = [*LEGACY, *[row['schema'] for row in OWNED], DRAFT['schema']]


@pytest.mark.parametrize('schema', PROTECTED)
@pytest.mark.parametrize('nested', [False, True])
def test_each_old_and_explicit_type_stays_private(tmp_path, schema, nested):
    body = {'schema_version': schema, 'status': 'UNVERIFIED'}
    if nested:
        body = {'metadata': [{'deep': body}]}
    assert privacy._contains_formal_schema(body, ROOT, set())
    path = tmp_path / 'history.json'
    atomic_json(path, body)
    with pytest.raises(TalkCutError, match='Immutable source/transcript'):
        privacy._auxiliary_json(path, ROOT, set())


def test_exact_policy_floor_and_explicit_owners():
    assert len(LEGACY) == len(set(LEGACY)) == 140
    assert tuple(LEGACY) == policy.LEGACY_SCHEMA_TYPES
    assert (*OWNED, DRAFT) == policy.FORMAL_SCHEMA_DECLARATIONS
    assert len(policy.formal_schema_types()) == 147
    assert set(LEGACY) <= policy.formal_schema_types()


@pytest.mark.parametrize('schema', HISTORICAL)
def test_incidental_comparison_and_grammar_mentions_are_not_declarations(tmp_path, schema):
    repo = tmp_path / 'repo'
    source = repo / 'src/talkcut/reader.py'
    source.parent.mkdir(parents=True)
    source.write_text(f'"""Retained grammar: {schema}"""\ndef read(value):\n    return value.get("schema_version") == {schema!r}\n')
    body = {'schema_version': schema, 'status': 'UNVERIFIED'}
    assert not privacy._contains_formal_schema(body, repo, set())
    path = tmp_path / 'historical.json'
    atomic_json(path, body)
    assert privacy._auxiliary_json(path, repo, set()) == body
    # Incidental metadata status never exempts a nested formal claim.
    body['nested'] = [{'schema_version': 'review-request/v1'}]
    atomic_json(path, body)
    with pytest.raises(TalkCutError, match='Immutable source/transcript'):
        privacy._auxiliary_json(path, repo, set())


@pytest.mark.parametrize('schema', ['transcript/v1', 'multimodal-review/v1', 'review-capability/v1',
                                   'terminal-ai-request/v1', 'terminal-ai-execution/v1', 'execution-receipt/v1'])
def test_imported_contract_protection_needs_no_local_constructor(tmp_path, schema):
    assert not list(tmp_path.iterdir())
    assert privacy._contains_formal_schema({'nested': [{'schema_version': schema}]}, tmp_path, set())
    assert privacy._contains_formal_schema({'schema_version': schema}, None, set())


def test_new_explicit_declaration_protects_without_source_constructor(monkeypatch, tmp_path):
    declaration = {'schema': 'new-formal-contract/v1', 'owner': 'talkcut.review', 'role': 'control_contract'}
    monkeypatch.setattr(policy, 'FORMAL_SCHEMA_DECLARATIONS', (*policy.FORMAL_SCHEMA_DECLARATIONS, declaration))
    assert privacy._contains_formal_schema({'schema_version': declaration['schema']}, tmp_path, set())
    assert privacy._contains_formal_schema({'wrapper': [{'schema_version': declaration['schema']}]}, None, set())


@pytest.mark.parametrize('damage', ['missing_owner', 'extra_key', 'bad_schema', 'empty_owner', 'unknown_role',
                                   'duplicate', 'legacy_duplicate', 'wrong_container', 'wrong_row', 'lost_floor'])
def test_malformed_or_unknown_declarations_refuse_before_metadata(monkeypatch, damage):
    declarations = [dict(row) for row in policy.FORMAL_SCHEMA_DECLARATIONS]
    if damage == 'missing_owner':
        del declarations[0]['owner']
    elif damage == 'extra_key':
        declarations[0]['historical'] = 'true'
    elif damage == 'bad_schema':
        declarations[0]['schema'] = 'not-a-schema'
    elif damage == 'empty_owner':
        declarations[0]['owner'] = ''
    elif damage == 'unknown_role':
        declarations[0]['role'] = 'allow_private_metadata'
    elif damage == 'duplicate':
        declarations.append(declarations[0])
    elif damage == 'legacy_duplicate':
        declarations[0]['schema'] = 'transcript/v1'
    elif damage == 'wrong_container':
        monkeypatch.setattr(policy, 'FORMAL_SCHEMA_DECLARATIONS', declarations)
    elif damage == 'wrong_row':
        declarations[0] = 'bad row'
    else:
        monkeypatch.setattr(policy, 'LEGACY_SCHEMA_TYPES', policy.LEGACY_SCHEMA_TYPES[:-1])
    if damage != 'wrong_container':
        monkeypatch.setattr(policy, 'FORMAL_SCHEMA_DECLARATIONS', tuple(declarations))
    with pytest.raises(TalkCutError, match='Formal schema declarations are malformed'):
        privacy._contains_formal_schema({'schema_version': 'ordinary-metadata/v1'}, None, set())


def test_registered_transcript_stays_protected_inside_historical_metadata():
    source_hash = 'a' * 64
    body = {'schema_version': HISTORICAL[0], 'metadata': [{'schema_version': 'transcript/v1',
                                                       'source_sha256': source_hash, 'text': 'private fixture words'}]}
    assert privacy._contains_formal_schema(body, None, {source_hash})


def local_writer_labels(source):
    """Coverage alarm only; never used to classify runtime metadata."""
    values = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and key.value == 'schema_version' and isinstance(value, ast.Constant):
                    assert isinstance(value.value, str)
                    values.add(value.value)
        if isinstance(node, ast.Call):
            for key in node.keywords:
                if key.arg == 'schema_version' and isinstance(key.value, ast.Constant):
                    assert isinstance(key.value.value, str)
                    values.add(key.value.value)
    return values


def json_schema_labels(value):
    labels = []
    if isinstance(value, dict):
        if isinstance(value.get('properties'), dict) and 'schema_version' in value['properties']:
            declaration = value['properties']['schema_version']
            assert isinstance(declaration, dict)
            if 'const' in declaration:
                assert isinstance(declaration['const'], str)
                labels.append(declaration['const'])
            if 'enum' in declaration:
                assert isinstance(declaration['enum'], list) and all(isinstance(x, str) for x in declaration['enum'])
                labels.extend(declaration['enum'])
        for child in value.values():
            labels.extend(json_schema_labels(child))
    elif isinstance(value, list):
        for child in value:
            labels.extend(json_schema_labels(child))
    return labels


def test_actual_local_writers_and_json_schema_declarations_are_covered():
    # Imported contracts are independently protected by the explicit registry.
    # This check additionally makes newly authored literal outputs require a
    # reviewed policy declaration instead of silently allowing them as history.
    writers = set().union(*(local_writer_labels(path.read_bytes()) for path in (ROOT / 'src/talkcut').glob('*.py')))
    schema_rows = [label for path in (ROOT / 'schemas').glob('*.json')
                   for label in json_schema_labels(json.loads(path.read_bytes()))]
    assert len(schema_rows) == 3
    assert writers and writers <= policy.formal_schema_types()
    assert set(schema_rows) <= policy.formal_schema_types()


def test_new_writer_coverage_requires_a_separate_declaration(monkeypatch):
    labels = local_writer_labels(b'def produce():\n    return {"schema_version": "new-output-fixture/v1"}\n')
    assert labels - policy.formal_schema_types() == {'new-output-fixture/v1'}
    monkeypatch.setattr(policy, 'FORMAL_SCHEMA_DECLARATIONS', (*policy.FORMAL_SCHEMA_DECLARATIONS,
                       {'schema': 'new-output-fixture/v1', 'owner': 'talkcut.review', 'role': 'formal_artifact'}))
    assert labels <= policy.formal_schema_types()


def write_repo_policy(repo, rows=None, legacy=None):
    path = repo / 'src/talkcut/formal_schemas.py'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('LEGACY_SCHEMA_TYPES = ' + repr(policy.LEGACY_SCHEMA_TYPES if legacy is None else legacy)
                    + '\nLEGACY_SCHEMA_TYPES_SHA256 = ' + repr(policy.LEGACY_SCHEMA_TYPES_SHA256)
                    + '\nFORMAL_SCHEMA_DECLARATIONS = ' + repr(policy.FORMAL_SCHEMA_DECLARATIONS if rows is None else rows) + '\n')
    return path


def test_repo_can_extend_but_cannot_replace_installed_policy(tmp_path):
    new = {'schema': 'new-input-fixture/v1', 'owner': 'talkcut.review', 'role': 'control_contract'}
    write_repo_policy(tmp_path, (*policy.FORMAL_SCHEMA_DECLARATIONS, new))
    types = policy.formal_schema_types(tmp_path)
    assert types == policy.formal_schema_types() | {new['schema']}
    assert privacy._contains_formal_schema({'deep': [{'schema_version': new['schema']}]}, tmp_path, set())
    assert privacy._contains_formal_schema({'schema_version': 'transcript/v1'}, tmp_path, set())


@pytest.mark.parametrize('damage', ['missing_six', 'lost_floor', 'duplicate_field', 'duplicate_assignment',
                                   'dynamic', 'conflicting_role', 'unknown_owner', 'unhashable_role'])
def test_supplied_policy_damage_refuses_without_execution(tmp_path, damage):
    rows = [dict(row) for row in policy.FORMAL_SCHEMA_DECLARATIONS]
    path = write_repo_policy(tmp_path)
    if damage == 'missing_six':
        write_repo_policy(tmp_path, tuple(rows[1:]))
    elif damage == 'lost_floor':
        write_repo_policy(tmp_path, legacy=policy.LEGACY_SCHEMA_TYPES[:-1])
    elif damage == 'duplicate_field':
        path.write_text(path.read_text().replace("'role': 'formal_artifact'", "'role': 'control_contract', 'role': 'formal_artifact'"))
    elif damage == 'duplicate_assignment':
        path.write_text(path.read_text() + '\nFORMAL_SCHEMA_DECLARATIONS = ()\n')
    elif damage == 'dynamic':
        path.write_text(path.read_text() + '\nFORMAL_SCHEMA_DECLARATIONS += ()\n')
    else:
        if damage == 'conflicting_role':
            rows[0]['role'] = 'control_contract'
        elif damage == 'unknown_owner':
            rows.append({'schema': 'unknown-input/v1', 'owner': 'talkcut.missing_owner', 'role': 'control_contract'})
        else:
            rows[0]['role'] = []
        write_repo_policy(tmp_path, tuple(rows))
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)


@pytest.mark.parametrize('form', ['literal', 'keyword', 'assignment', 'constant'])
def test_new_supported_writer_requires_owned_declaration(tmp_path, form):
    schema = 'new-output-fixture/v1'
    source = tmp_path / 'src/talkcut/producer.py'
    source.parent.mkdir(parents=True)
    expressions = {'literal': f'return {{"schema_version": {schema!r}}}',
                   'keyword': f'return dict(schema_version={schema!r})',
                   'assignment': f'value = {{}}\n    value["schema_version"] = {schema!r}\n    return value',
                   'constant': 'return {"schema_version": OUTPUT_TYPE}'}
    source.write_text(f'OUTPUT_TYPE = {schema!r}\ndef produce():\n    {expressions[form]}\n')
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)
    write_repo_policy(tmp_path, (*policy.FORMAL_SCHEMA_DECLARATIONS,
                      {'schema': schema, 'owner': 'talkcut.producer', 'role': 'formal_artifact'}))
    assert schema in policy.formal_schema_types(tmp_path)
    policy.validate_schema_coverage(tmp_path, policy.formal_schema_types(tmp_path))


@pytest.mark.parametrize('expression', ['dynamic()', 'MISSING', '"new-" + "output/v1"'])
def test_unsupported_output_expression_fails_closed(tmp_path, expression):
    source = tmp_path / 'src/talkcut/producer.py'
    source.parent.mkdir(parents=True)
    source.write_text(f'def produce():\n    return {{"schema_version": {expression}}}\n')
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)


@pytest.mark.parametrize('name,value', [('EVALUATOR_VERSION', 'goal-acceptance/v1'),
                                       ('CONTRACT_VERSION', 'dgist-first-lecture/v1'),
                                       ('COLLECTION_SCHEMA', 'lecture-context-collection/v1')])
def test_three_module_constant_outputs_are_covered(tmp_path, name, value):
    source = tmp_path / 'src/talkcut/producer.py'
    source.parent.mkdir(parents=True)
    source.write_text(f'{name} = {value!r}\ndef produce():\n    return {{"schema_version": {name}}}\n')
    assert value in policy.formal_schema_types(tmp_path)
    source.write_text(source.read_text().replace('def produce():', f'def produce():\n    {name} = "unowned-output/v1"'))
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)


@pytest.mark.parametrize('declaration', [{'const': 'new-schema-fixture/v1'}, {'enum': ['new-schema-fixture/v1']},
                                        {'const': 'new-schema-fixture/v1', 'enum': ['new-schema-fixture/v1']}])
def test_json_schema_types_require_explicit_policy_in_nested_defs(tmp_path, declaration):
    schema = tmp_path / 'schemas/fixture.json'
    schema.parent.mkdir()
    atomic_json(schema, {'$defs': {'entry': {'properties': {'schema_version': declaration}}}})
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)
    write_repo_policy(tmp_path, (*policy.FORMAL_SCHEMA_DECLARATIONS,
                      {'schema': 'new-schema-fixture/v1', 'owner': 'talkcut.review', 'role': 'control_contract'}))
    assert 'new-schema-fixture/v1' in policy.formal_schema_types(tmp_path)


@pytest.mark.parametrize('data', [b'{', b'{"properties":{"schema_version":{"const":"transcript/v1","const":"review-request/v1"}}}',
                                 b'{"properties":{"schema_version":{"enum":[]}}}',
                                 b'{"properties":{"schema_version":{"enum":["transcript/v1","transcript/v1"]}}}',
                                 b'{"properties":{"schema_version":{"const":1}}}',
                                 b'{"properties":{"schema_version":{"type":"string"}}}',
                                 b'{"properties":{"schema_version":{"const":"transcript/v1","enum":["review-request/v1"]}}}',
                                 b'{"maximum":NaN}'])
def test_malformed_schema_json_refuses(tmp_path, data):
    schema = tmp_path / 'schemas/fixture.json'
    schema.parent.mkdir()
    schema.write_bytes(data)
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)
    with pytest.raises(TalkCutError):
        policy.validate_schema_coverage(tmp_path, policy.formal_schema_types())


def test_malformed_source_refuses_without_import(tmp_path):
    source = tmp_path / 'src/talkcut/producer.py'
    source.parent.mkdir(parents=True)
    source.write_bytes(b'# coding: missing_codec\nx = 1\n')
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)


def test_cache_rechecks_added_changed_and_removed_sources(tmp_path):
    assert len(policy.formal_schema_types(tmp_path)) == 147
    source = tmp_path / 'src/talkcut/producer.py'
    source.parent.mkdir(parents=True)
    source.write_text('def produce():\n    return {"schema_version": "transcript/v1"}\n')
    assert len(policy.formal_schema_types(tmp_path)) == 147
    source.write_text(source.read_text().replace('transcript/v1', 'unowned-output/v1'))
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)
    source.unlink()
    assert len(policy.formal_schema_types(tmp_path)) == 147


@pytest.mark.parametrize('kind', ['python', 'schema'])
def test_recursive_new_output_is_covered(tmp_path, kind):
    if kind == 'python':
        path = tmp_path / 'src/talkcut/nested/deeper/producer.py'
        data = b'def produce():\n    return {"schema_version": "nested-output-fixture/v1"}\n'
    else:
        path = tmp_path / 'schemas/nested/deeper/output.json'
        data = b'{"properties":{"schema_version":{"const":"nested-output-fixture/v1"}}}'
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)
    write_repo_policy(tmp_path, (*policy.FORMAL_SCHEMA_DECLARATIONS,
                      {'schema': 'nested-output-fixture/v1', 'owner': 'talkcut.review', 'role': 'formal_artifact'}))
    assert 'nested-output-fixture/v1' in policy.formal_schema_types(tmp_path)


@pytest.mark.parametrize('relative', ['src/talkcut', 'schemas'])
def test_recursive_directory_alias_refuses_even_after_cache(tmp_path, relative):
    repo, external = tmp_path / 'repo', tmp_path / 'external'
    folder = repo / relative
    folder.mkdir(parents=True)
    external.mkdir()
    assert len(policy.formal_schema_types(repo)) == 147
    (folder / 'nested').symlink_to(external, target_is_directory=True)
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(repo)


def test_cached_read_rechecks_all_sources_after_lookup(tmp_path, monkeypatch):
    source = tmp_path / 'src/talkcut/producer.py'
    source.parent.mkdir(parents=True)
    source.write_text('def produce():\n    return {"schema_version": "transcript/v1"}\n')
    assert len(policy.formal_schema_types(tmp_path)) == 147
    original, calls, fired = policy._files, 0, False
    def mutation(repo):
        nonlocal calls, fired
        rows = original(repo)
        calls += 1
        if calls == 1:
            source.write_text(source.read_text().replace('transcript/v1', 'unowned-output/v1'))
            fired = True
        return rows
    monkeypatch.setattr(policy, '_files', mutation)
    with pytest.raises(TalkCutError):
        policy.formal_schema_types(tmp_path)
    assert fired and calls == 2
