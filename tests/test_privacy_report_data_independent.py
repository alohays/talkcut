"""Independent report-data construction and exact-reference boundary controls."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from report_data_origin_fixture import fixture, locator, observe, refresh, write

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError


@pytest.mark.parametrize('archived', [False, True])
@pytest.mark.parametrize('serialization', ['pretty_json_lf', 'canonical_json_lf'])
def test_original_modes_and_six_parent_scope(tmp_path, archived, serialization):
    parts = fixture(tmp_path, serialization, count=6, archived=archived)
    observations = observe(parts, [locator(parts, index=i) for i in range(6)])
    assert len(observations) == 6
    assert all(row['claim_status'] == 'UNVERIFIED' and row['commands'] == [] for row in observations)
    assert all(len(row['source_dependencies']) == 6 for row in observations)


@pytest.mark.parametrize('target', ['original', 'snapshot'])
@pytest.mark.parametrize('delta', [0, -1, 1])
def test_declared_parent_byte_count_is_exact(tmp_path, target, delta):
    parts = fixture(tmp_path, archived=True)
    assert observe(parts)
    size = Path(parts['parents'][0][target]['path']).stat().st_size
    def mutate(authority):
        authority['parents'][0][target]['bytes'] = size + delta
    parts['data_authority_mutator'] = mutate
    refresh(parts)
    selected = locator(parts)
    selected['parent'] = {key: selected['parent'][key] for key in ('path', 'sha256')}
    if delta == 0:
        assert observe(parts, [selected])
    else:
        with pytest.raises(TalkCutError):
            observe(parts, [selected])


@pytest.mark.parametrize('target', ['sources', 'source_maps'])
def test_other_declared_reference_byte_count_is_exact(tmp_path, target):
    parts = fixture(tmp_path)
    assert observe(parts)
    def mutate(authority):
        selected = authority['sources']['src/talkcut/acceptance.py'] if target == 'sources' else authority[target]
        selected['bytes'] = Path(selected['path']).stat().st_size + 1
    parts['data_authority_mutator'] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('role', ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/project.py',
                                 'src/talkcut/__main__.py', 'src/talkcut/__init__.py'])
@pytest.mark.parametrize('header', [b'# coding: unknown-private-codec\n', b'# coding: utf-16\n'])
def test_complete_source_uses_python_byte_decoding(tmp_path, role, header):
    parts = fixture(tmp_path)
    assert observe(parts)
    # Use the actual five frozen Python roles rather than executing their code.
    path = Path(parts['sources'][role]['path'])
    path.write_bytes(header + path.read_bytes())
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['unapproved', 'duplicate_locator', 'copied_unbound_parent', 'same_hash_other_path'])
def test_root_and_parent_authority_are_required(tmp_path, fault):
    parts = fixture(tmp_path, archived=True)
    assert observe(parts)
    selected = locator(parts)
    roots = [parts['data_authority_ref']]
    selections = [selected]
    if fault == 'unapproved':
        roots = []
    elif fault == 'duplicate_locator':
        selections.append(copy.deepcopy(selected))
    else:
        path = parts['directory'] / ('unbound-copy.json' if fault == 'copied_unbound_parent' else 'other.json')
        selected['parent'] = write(path, Path(selected['parent']['path']).read_bytes())
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory(selections, parts['directory'], parts['root'],
                                             set(parts['registered'].values()), roots)


@pytest.mark.parametrize('fault', ['case_swap', 'unbound_extra_source', 'declared_case_bool', 'case_wrong_kind'])
def test_complete_independent_map_relations(tmp_path, fault):
    parts = fixture(tmp_path, count=2)
    assert observe(parts)
    if fault == 'case_swap':
        parts['data_authority_mutator'] = lambda authority: authority['parents'][0].update(retained_case=1)
    elif fault == 'declared_case_bool':
        parts['data_authority_mutator'] = lambda authority: authority['parents'][0].update(retained_case=False)
    elif fault == 'unbound_extra_source':
        parts['map_mutator'] = lambda maps: maps['cases'][0]['members'].append({'name': 'uncalled.py', 'expected_sha256': 'a' * 64})
    else:
        parts['map_mutator'] = lambda maps: maps['cases'][0]['parent'].update(kind='transcript')
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('value', [None, False, 0, '', [], {'opaque': 'unchanged private callback result'}])
def test_ordinary_callback_result_is_not_reexecuted(tmp_path, value):
    parts = fixture(tmp_path)
    row = parts['reports'][0]['criteria'][1]
    row['checks'][0].update(status='PASS', reason='Verified from current artifacts', measurements=value)
    assert row['status'] == 'UNVERIFIED' and len(row['checks']) > 1
    refresh(parts)
    assert observe(parts)
