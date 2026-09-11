"""Closed six-source report profile and unchanged consumer protection."""
from __future__ import annotations

import copy
import itertools
from pathlib import Path

import pytest
from report_canonical_profile_fixture import REPLACEMENTS, fixture, refresh
from report_data_origin_fixture import (
    PHRASE,
    coverage_value,
    inventory,
    locator,
    observe,
    write,
)

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError

ROLES = ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/project.py',
         'src/talkcut/__main__.py', 'src/talkcut/__init__.py', 'pyproject.toml']


@pytest.mark.parametrize('archived', [False, True])
@pytest.mark.parametrize('original', [False, True])
def test_complete_canonical_original_or_archive(tmp_path, archived, original):
    parts = fixture(tmp_path, archived=archived)
    selected = [locator(parts, original=original, selector=selector) for selector in
                (['criteria', 0, 'description'], ['criteria', 2, 'checks', 0, 'reason'], ['provenance_limitations'])]
    before, _, _ = inventory(parts, [])
    observations = observe(parts, selected)
    assert len(parts['reports'][0]['files']) == 128
    assert len(observations) == 3
    assert all(row['claim_status'] == 'UNVERIFIED' and row['commands'] == [] for row in observations)
    assert all(len(row['source_dependencies']) == 6 for row in observations)
    after, _, graph = inventory(parts, selected)
    assert all(after[digest] == kind for digest, kind in before.items())
    assert after[parts['parents'][0]['original']['sha256']] == 'review'
    assert len(graph['review_text_origins']) == 3


@pytest.mark.parametrize('old_roles', [list(group) for size in (1, 2) for group in itertools.combinations(REPLACEMENTS, size)])
def test_individually_reviewed_roles_cannot_be_mixed(tmp_path, old_roles):
    parts = fixture(tmp_path)
    assert observe(parts)
    for role in old_roles:
        Path(parts['sources'][role]['path']).write_bytes(parts['previous_sources'][role])
    refresh(parts)
    with pytest.raises(TalkCutError, match='source profile'):
        observe(parts)


@pytest.mark.parametrize('role', ROLES)
def test_new_profile_requires_full_source_bytes_even_for_comments(tmp_path, role):
    parts = fixture(tmp_path)
    assert observe(parts)
    path = Path(parts['sources'][role]['path'])
    path.write_bytes(path.read_bytes() + b'\n# Unreviewed source variation\n')
    refresh(parts)
    with pytest.raises(TalkCutError, match='source profile'):
        observe(parts)


def test_old_profile_and_both_serializers_still_work(tmp_path):
    parts = fixture(tmp_path)
    for role in REPLACEMENTS:
        Path(parts['sources'][role]['path']).write_bytes(parts['previous_sources'][role])
    for serialization in ('pretty_json_lf', 'canonical_json_lf'):
        parts['serialization'] = serialization
        refresh(parts)
        assert observe(parts)


def test_new_profile_does_not_enter_historical_cli_authority(tmp_path):
    from acceptance_origin_fixture import observe as cli_observe
    from acceptance_origin_fixture import refresh as cli_refresh
    parts = fixture(tmp_path)
    assert observe(parts)
    cli_refresh(parts)
    with pytest.raises(TalkCutError):
        cli_observe(parts)


def test_new_profile_requires_canonical_serialization(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    parts['serialization'] = 'pretty_json_lf'
    refresh(parts)
    with pytest.raises(TalkCutError, match='canonical serializer'):
        observe(parts)


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('guard', ['registered', 'transcript'])
def test_all_six_private_dependency_guards(tmp_path, role, guard):
    parts = fixture(tmp_path)
    assert observe(parts)
    ref = parts['sources'][role]
    if guard == 'registered':
        with pytest.raises(TalkCutError, match='Registered'):
            observe(parts, registered={ref['sha256']})
    else:
        write(parts['directory'] / 'transcripts/private-source.txt', Path(ref['path']).read_bytes())
        with pytest.raises(TalkCutError, match='Known private'):
            inventory(parts)


@pytest.mark.parametrize('fault', ['member_missing', 'member_extra', 'member_duplicate', 'member_hash', 'map_revision', 'case_parent',
                                  'original_size', 'snapshot_size', 'source_size', 'source_missing'])
def test_complete_map_and_exact_references(tmp_path, fault):
    parts = fixture(tmp_path, archived=True)
    assert observe(parts)
    def map_mutator(case):
        if fault == 'member_missing': case['members'].pop()
        elif fault == 'member_extra': case['members'].append({'name': 'docs/extra.txt', 'expected_sha256': '0' * 64})
        elif fault == 'member_duplicate': case['members'].append(copy.deepcopy(case['members'][0]))
        elif fault == 'member_hash': case['members'][-1]['expected_sha256'] = '0' * 64
        elif fault == 'map_revision': case['revision'] = '0' * 40
        elif fault == 'case_parent': case['parent']['path'] += '-unbound'
    def authority_mutator(authority):
        if fault in {'original_size', 'snapshot_size'}:
            ref = authority['parents'][0][fault.removesuffix('_size')]
            ref['bytes'] = Path(ref['path']).stat().st_size + 1
        elif fault == 'source_size':
            ref = authority['sources'][ROLES[0]]
            ref['bytes'] = Path(ref['path']).stat().st_size + 1
        elif fault == 'source_missing': authority['sources'].pop(ROLES[0])
    parts.update(full_map_mutator=map_mutator, full_authority_mutator=authority_mutator)
    refresh(parts)
    selected = locator(parts)
    selected['parent'] = {key: selected['parent'][key] for key in ('path', 'sha256')}
    with pytest.raises(TalkCutError):
        observe(parts, [selected])


@pytest.mark.parametrize('fault', ['pass_reason', 'error_measurement', 'order', 'evidence_refs', 'aggregate',
                                  'late_branch', 'coverage_shape', 'coverage_order', 'release_return', 'provenance'])
def test_unselected_complete_constructor_fields_are_still_checked(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    report = parts['reports'][0]
    if fault == 'pass_reason': report['criteria'][1]['checks'][0].update(status='PASS', reason='Unwritten success reason')
    elif fault == 'error_measurement': report['criteria'][1]['checks'][0]['measurements'] = {}
    elif fault == 'order': report['criteria'][2]['checks'].reverse()
    elif fault == 'evidence_refs': report['criteria'][0]['evidence_refs'] = [{'unwritten': True}]
    elif fault == 'aggregate': report['criteria'][0]['status'] = 'PASS'
    elif fault == 'late_branch':
        report['criteria'][8]['checks'][0].update(status='PASS', reason='Verified from current artifacts', measurements={})
    elif fault == 'coverage_shape': report['coverage'] = {'output_audio': 'Private prose in a generated dictionary slot'}
    elif fault == 'coverage_order':
        report['coverage'] = {'output_audio': coverage_value([[0, 1]]), 'output_video': coverage_value([]),
                              'deleted_source': coverage_value([[2, 3]])}
        report['uncovered_intervals'] = [{'metric': key, 'intervals': value['uncovered_intervals']}
                                        for key, value in report['coverage'].items() if value['uncovered_intervals']][::-1]
    elif fault == 'release_return': report['code_release_evidence'] = {'unwritten': True}
    else: report['provenance_limitations'] = 'Private replacement prose'
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_canonical_coverage_keeps_source_order_and_callback_relation(tmp_path):
    parts = fixture(tmp_path)
    report = parts['reports'][0]
    report['coverage'] = {'output_audio': coverage_value([[0, 1]]), 'output_video': coverage_value([]),
                          'deleted_source': coverage_value([[2, 3]])}
    report['uncovered_intervals'] = [{'metric': key, 'intervals': value['uncovered_intervals']}
                                    for key, value in report['coverage'].items() if value['uncovered_intervals']]
    report['criteria'][12]['checks'][0].update(status='PASS', reason='Verified from current artifacts', measurements={'private': 1})
    report['criteria'][12]['status'] = 'PASS'
    report['code_release_evidence'] = {'private': 1}
    refresh(parts)
    assert observe(parts)


@pytest.mark.parametrize('fault', ['unapproved', 'same_bytes_other_path', 'duplicate', 'transcript_marker'])
def test_occurrence_authority_and_recursive_speech(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    selected = locator(parts)
    roots = [parts['data_authority_ref']]
    locators = [selected]
    if fault == 'unapproved': roots = []
    elif fault == 'same_bytes_other_path':
        selected['parent'] = write(parts['directory'] / 'unbound.json', Path(selected['parent']['path']).read_bytes())
    elif fault == 'duplicate': locators.append(copy.deepcopy(selected))
    else:
        parts['reports'][0]['invalid_evidence'] = [{'schema_version': 'transcript/v1', 'text': PHRASE}]
        refresh(parts)
        locators = [locator(parts)]
        roots = [parts['data_authority_ref']]
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory(locators, parts['directory'], parts['root'],
                                             set(parts['registered'].values()), roots)


def test_unselected_same_phrase_copies_and_transcripts_stay_protected(tmp_path):
    parts = fixture(tmp_path, count=2, archived=True)
    parts['reports'][0]['invalid_evidence'] = [{'reason': PHRASE}]
    refresh(parts)
    write(parts['directory'] / 'transcripts/unselected.txt', PHRASE.encode())
    write(parts['directory'] / 'checkpoint.local.json', {'parents': [p['original'] for p in parts['parents']],
                                                       'archive': parts['parents'][1]['snapshot']})
    before, phrases, _ = inventory(parts, [])
    assert PHRASE in phrases
    after, phrases, graph = inventory(parts, [locator(parts)])
    assert PHRASE in phrases and all(after[digest] == kind for digest, kind in before.items())
    assert len(graph['review_text_origins']) == 1


@pytest.mark.parametrize('role', ROLES[:-1])
@pytest.mark.parametrize('header', [b'# coding: unknown-private-codec\n', b'# coding: utf-16\n'])
def test_original_python_byte_decoding_gate(tmp_path, role, header):
    parts = fixture(tmp_path)
    assert observe(parts)
    path = Path(parts['sources'][role]['path'])
    path.write_bytes(header + path.read_bytes())
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('target', ['parent', 'authority', 'source_map', 'source'])
def test_fired_final_mutation_preserves_refusal(tmp_path, target, monkeypatch):
    from talkcut import privacy_report_data_origins as report_data
    parts = fixture(tmp_path)
    assert observe(parts)
    original = report_data.project_field
    ref = {'parent': parts['parents'][0]['original'], 'authority': parts['data_authority_ref'],
           'source_map': parts['data_authority']['source_maps'],
           'source': parts['sources']['src/talkcut/contracts.py']}[target]
    fired = []
    def mutate(*args):
        result = original(*args)
        path = Path(ref['path'])
        path.write_bytes(path.read_bytes() + b' ')
        fired.append(True)
        return result
    monkeypatch.setattr(report_data, 'project_field', mutate)
    with pytest.raises(TalkCutError):
        observe(parts)
    assert fired == [True]


@pytest.mark.parametrize('fault', [None, 'default_off', 'level', 'module', 'name', 'alias', 'extra_name',
                                  'extra_import', 'dormant_import', 'different_artifact', 'missing_assignment'])
def test_explicit_import_prelude_does_not_skip_other_statements(tmp_path, fault):
    import ast

    from talkcut import privacy_acceptance_origins as acceptance
    from talkcut import privacy_machine_origins as machine
    parts = fixture(tmp_path)
    trees = {role: machine.syntax(Path(ref['path']).read_bytes())
             for role, ref in parts['sources'].items() if role.endswith('.py')}
    if fault == 'default_off':
        with pytest.raises(TalkCutError):
            acceptance.source_recipe(trees)
        return
    owner = next(node for node in trees[ROLES[0]].body if isinstance(node, ast.ClassDef) and node.name == 'Evaluator')
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == 'analysis_check')
    prelude = method.body[0]
    assert isinstance(prelude, ast.ImportFrom)
    if fault == 'level': prelude.level = 0
    elif fault == 'module': prelude.module = 'other_binding'
    elif fault == 'name': prelude.names[0].name = 'other_verifier'
    elif fault == 'alias': prelude.names[0].asname = 'replacement'
    elif fault == 'extra_name': prelude.names.append(ast.alias(name='extra'))
    elif fault == 'extra_import': method.body.insert(1, copy.deepcopy(prelude))
    elif fault == 'dormant_import': method.body[0] = ast.parse('if False:\n from .editorial_binding import verify_editorial_binding').body[0]
    elif fault == 'different_artifact': method.body[1] = ast.parse("analysis = self.artifact(self.index.get('editorial'))").body[0]
    elif fault == 'missing_assignment': method.body.pop(1)
    if fault is None:
        assert acceptance.source_recipe(trees, allow_analysis_import=True)['criteria']['AC01'] == PHRASE
    else:
        with pytest.raises(TalkCutError):
            acceptance.source_recipe(trees, allow_analysis_import=True)
