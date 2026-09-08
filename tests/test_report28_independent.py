"""Independent bounded constructor/consumer opposition; no producer is executed."""
from __future__ import annotations

import ast
import builtins
import copy
import json
from pathlib import Path

import pytest
from report_canonical_profile_fixture import fixture, refresh
from report_data_origin_fixture import PHRASE, inventory, locator, observe, write

from talkcut import privacy_acceptance_origins as acceptance
from talkcut import privacy_machine_origins as machine
from talkcut import privacy_report_data_origins as report_data
from talkcut.project import TalkCutError


def trees(parts):
    return {name: machine.syntax(Path(ref['path']).read_bytes()) for name, ref in parts['sources'].items() if name.endswith('.py')}


def method(parsed, name):
    owner = next(n for n in parsed['src/talkcut/acceptance.py'].body if isinstance(n, ast.ClassDef) and n.name == 'Evaluator')
    return next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == name)


def rebind_serialized_parent(parts, transform):
    authority = parts['data_authority']
    maps = json.loads(Path(authority['source_maps']['path']).read_bytes())
    for pair, case in zip(authority['parents'], maps['cases'], strict=True):
        raw = transform(Path(pair['original']['path']).read_bytes())
        pair['original'] = write(pair['original']['path'], raw)
        pair['snapshot'] = write(pair['snapshot']['path'], raw)
        case['parent'] = {'kind': 'review', **pair['original']}
    authority['source_maps'] = write(authority['source_maps']['path'], maps)
    parts['data_authority_ref'] = write(parts['data_authority_ref']['path'], authority)
    parts['parents'] = authority['parents']


def test_constructor_does_not_import_recorded_callback(tmp_path, monkeypatch):
    parts = fixture(tmp_path)
    original = builtins.__import__
    seen = []
    def prevent(name, *args, **kwargs):
        if name.endswith('editorial_binding'):
            seen.append(name)
            raise AssertionError('Recorded callback import must never execute here')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', prevent)
    observations = observe(parts, [locator(parts, selector=['criteria', 5, 'checks', 0, 'reason'])])
    assert len(observations) == 1 and seen == []
    assert observations[0]['claim_status'] == 'UNVERIFIED' and observations[0]['commands'] == []
    assert observations[0]['associated_row'] == parts['reports'][0]['criteria'][5]['checks'][0]


def test_default_off_and_enabled_path_do_not_rewrite_original_ast(tmp_path):
    parts = fixture(tmp_path)
    parsed = trees(parts)
    before = {k: ast.dump(v, include_attributes=True) for k, v in parsed.items()}
    with pytest.raises(TalkCutError):
        acceptance.source_recipe(parsed)
    recipe = acceptance.source_recipe(parsed, allow_analysis_import=True)
    assert recipe['criteria']['AC01'] == PHRASE
    assert before == {k: ast.dump(v, include_attributes=True) for k, v in parsed.items()}
    assert isinstance(method(parsed, 'analysis_check').body[0], ast.ImportFrom)


@pytest.mark.parametrize('target', ['audit_handoff', 'release_check'])
def test_opt_in_never_skips_imports_in_other_selected_methods(tmp_path, target):
    parts = fixture(tmp_path)
    parsed = trees(parts)
    assert acceptance.source_recipe(parsed, allow_analysis_import=True)
    method(parsed, target).body.insert(0, copy.deepcopy(method(parsed, 'analysis_check').body[0]))
    with pytest.raises(TalkCutError, match='original artifact'):
        acceptance.source_recipe(parsed, allow_analysis_import=True)


@pytest.mark.parametrize('prefix', ['pass', 'assert True', '"docstring"', 'try:\n from .editorial_binding import verify_editorial_binding\nexcept ImportError:\n pass', 'from ..editorial_binding import verify_editorial_binding', 'from .editorial_binding import *', 'from .editorial_binding import verify_editorial_binding as verify_editorial_binding'])
def test_explicit_prelude_requires_exact_first_statement(tmp_path, prefix):
    parts = fixture(tmp_path)
    parsed = trees(parts)
    assert acceptance.source_recipe(parsed, allow_analysis_import=True)
    selected = method(parsed, 'analysis_check')
    selected.body[0] = ast.parse(prefix).body[0]
    with pytest.raises(TalkCutError, match='import prelude'):
        acceptance.source_recipe(parsed, allow_analysis_import=True)


@pytest.mark.parametrize('location', ['authority', 'locator'])
def test_import_option_is_not_an_external_locator_override(tmp_path, location):
    parts = fixture(tmp_path)
    assert observe(parts)
    if location == 'authority':
        parts['data_authority']['allow_analysis_import'] = True
        parts['data_authority_ref'] = write(parts['data_authority_ref']['path'], parts['data_authority'])
        selected = locator(parts)
    else:
        selected = locator(parts)
        selected['allow_analysis_import'] = True
    with pytest.raises(TalkCutError):
        observe(parts, [selected])


@pytest.mark.parametrize('change', ['after_lookup_import', 'after_lookup_assignment', 'check_reason', 'contract_description'])
def test_unchanged_prefix_cannot_bypass_complete_source_tuple(tmp_path, change):
    parts = fixture(tmp_path)
    assert observe(parts)
    role = 'src/talkcut/contracts.py' if change == 'contract_description' else 'src/talkcut/acceptance.py'
    p = Path(parts['sources'][role]['path'])
    data = p.read_text()
    if change == 'contract_description':
        assert PHRASE in data
        data = data.replace(PHRASE, 'Unreviewed replacement description', 1)
    elif change == 'check_reason':
        assert 'Verified from current artifacts' in data
        data = data.replace('Verified from current artifacts', 'Unreviewed success text', 1)
    else:
        marker = '        analysis = self.artifact(self.index.get("analysis"))\n'
        assert data.count(marker) == 1
        suffix = '        import other_callback\n' if change == 'after_lookup_import' else '        analysis = None\n'
        data = data.replace(marker, marker + suffix)
    p.write_text(data)
    refresh(parts)
    with pytest.raises(TalkCutError, match='source profile'):
        observe(parts)


@pytest.mark.parametrize('role', sorted(report_data.CANONICAL_SOURCE_PROFILE))
def test_all_six_role_relocations_preserve_only_source_data_claim(tmp_path, role):
    parts = fixture(tmp_path)
    baseline = observe(parts)
    old = parts['sources'][role]
    new = write(parts['temporary'] / (str(len(role)) + '-relocated-source.data'), Path(old['path']).read_bytes())
    parts['sources'][role] = new
    refresh(parts)
    found = observe(parts)
    assert found[0]['selected_value'] == baseline[0]['selected_value']
    assert found[0]['associated_row'] == baseline[0]['associated_row']
    assert found[0]['commands'] == [] and found[0]['claim_status'] == 'UNVERIFIED'
    assert any(row['snapshot'] == new for row in found[0]['source_dependencies'])


@pytest.mark.parametrize('form', ['pretty', 'extra_lf', 'space_prefix', 'bom'])
def test_canonical_declaration_does_not_accept_equivalent_other_bytes(tmp_path, form):
    parts = fixture(tmp_path, archived=True)
    assert observe(parts)
    def change(raw):
        if form == 'pretty':
            return json.dumps(json.loads(raw), ensure_ascii=False, allow_nan=False, indent=2).encode() + b'\n'
        if form == 'extra_lf': return raw + b'\n'
        if form == 'space_prefix': return b' ' + raw
        return b'\xef\xbb\xbf' + raw
    rebind_serialized_parent(parts, change)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_selected_description_does_not_clear_unselected_same_value(tmp_path):
    parts = fixture(tmp_path)
    parts['reports'][0]['source_hashes'] = {'unselected_private_text': PHRASE}
    refresh(parts)
    before, phrases_before, _ = inventory(parts, [])
    after, phrases_after, graph = inventory(parts, [locator(parts)])
    assert PHRASE in phrases_before and PHRASE in phrases_after
    assert all(after[key] == value for key, value in before.items())
    assert after[parts['parents'][0]['original']['sha256']] == 'review'
    assert len(graph['review_text_origins']) == 1


def test_speech_marker_in_unselected_source_hashes_refuses_whole_parent(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    parts['reports'][0]['source_hashes'] = {'sibling': {'schema_version': 'transcript/v1', 'text': PHRASE}}
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_full_source_map_value_not_only_source_roles_is_checked(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    authority = parts['data_authority']
    maps = json.loads(Path(authority['source_maps']['path']).read_bytes())
    assert len(maps['cases'][0]['members']) == 128
    maps['cases'][0]['members'][-1]['expected_sha256'] = 'f' * 64
    authority['source_maps'] = write(authority['source_maps']['path'], maps)
    parts['data_authority_ref'] = write(parts['data_authority_ref']['path'], authority)
    with pytest.raises(TalkCutError, match='complete retained map'):
        observe(parts)
