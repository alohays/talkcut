"""Checkpoint projections retain source, row and occurrence authority boundaries."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from acceptance_origin_fixture import refresh as refresh_cli
from checkpoint_data_origin_fixture import (
    MODES,
    PHRASE,
    fixture,
    inventory,
    locator,
    observe,
    rebind_authority,
    refresh,
    write,
)
from report_data_origin_fixture import refresh as refresh_data

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref


@pytest.mark.parametrize('mode,native', [(mode, False) for mode in MODES] + [('preserved_report_summary', True)])
def test_full_original_checkpoint_projection(tmp_path, mode, native):
    p = fixture(tmp_path, mode, native=native)
    result = observe(p)
    assert len(result) == 1 and result[0]['selected_value'] == PHRASE
    assert result[0]['parent'] == p['original'] and result[0]['claim_status'] == 'UNVERIFIED'
    assert len(result[0]['source_dependencies']) == 6
    assert result[0]['associated_row'] == p['upstream']['report']['criteria'][0]
    if mode == 'preserved_report_summary':
        historical = p['parent']['actual_latest_acceptance']
        assert artifact_ref(historical['path'])['sha256'] != historical['sha256']
    saved = observe(p, [locator(p, snapshot=True)])
    assert saved[0]['parent'] == p['snapshot'] and saved[0]['associated_row'] == result[0]['associated_row']


@pytest.mark.parametrize('mode', MODES)
def test_all_retained_original_leaf_rows(tmp_path, mode):
    p = fixture(tmp_path, mode)
    selectors = []
    for row in p['case']['rows']:
        selectors.append([int(s) if s.isdecimal() else s for s in row['pointer'].split('/')[1:]])
    result = observe(p, [locator(p, selector) for selector in selectors])
    assert len(result) == 27 and [r['selected_value'] for r in result] == [r['value'] for r in p['case']['rows']]


@pytest.mark.parametrize('mode', MODES)
def test_original_whole_parent_and_unselected_phrase_stay_private(tmp_path, mode):
    p = fixture(tmp_path, mode);p['private_notes'] = PHRASE;refresh(p)
    # This whole-graph positive uses physically present historical references.
    # The separate adapter positive retains an overwritten historical path.
    if mode == 'command_summary':
        command = json.loads(Path(p['upstream']['command']['path']).read_text())
        write(command['current_report']['path'], Path(p['upstream']['saved_path']).read_bytes())
    elif mode == 'preserved_report_summary':
        write(p['parent']['actual_latest_acceptance']['path'], Path(p['source']['path']).read_bytes())
    known, phrases, result = inventory(p)
    assert PHRASE in phrases and known[p['original']['sha256']] == 'review'
    assert known[p['snapshot']['sha256']] == 'review'
    assert p['source']['sha256'] in known
    assert result['review_text_origins'][0]['claim_status'] == 'UNVERIFIED'


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('which', ['upstream', 'checkpoint'])
def test_both_separately_approved_roots_required(tmp_path, mode, which):
    p = fixture(tmp_path, mode);assert observe(p)
    kept = p['authority_ref'] if which == 'upstream' else p['upstream_authority']
    with pytest.raises(TalkCutError):observe(p, approved=[kept])


@pytest.mark.parametrize('selector', [[], ['criteria'], ['criteria', 0], ['criteria', -1, 'description'],
    ['criteria', True, 'description'], ['criteria', {}, 'description'], ['criteria', [], 'description'],
    ['private_notes'], ['scope'], ['criteria', 2, 'description']])
def test_only_retained_string_leaf_selectors(tmp_path, selector):
    p = fixture(tmp_path, 'preserved_report_summary');assert observe(p)
    with pytest.raises(TalkCutError):observe(p, [locator(p, selector)])


@pytest.mark.parametrize('mutation', ['missing_row', 'extra_row', 'row_order', 'check_order', 'description',
    'evidence_refs', 'measurements', 'status', 'late_check', 'extra_check_field'])
def test_entire_checkpoint_array_must_equal_approved_report(tmp_path, mutation):
    p = fixture(tmp_path);assert observe(p)
    def change(parent):
        rows = parent['acceptance']['criteria']
        if mutation == 'missing_row':rows.pop()
        elif mutation == 'extra_row':rows.append(copy.deepcopy(rows[-1]))
        elif mutation == 'row_order':rows.reverse()
        elif mutation == 'check_order':rows[0]['checks'].reverse()
        elif mutation == 'description':rows[1]['description'] = 'Different private description'
        elif mutation == 'evidence_refs':rows[1]['evidence_refs'] = ['private']
        elif mutation == 'measurements':rows[1]['checks'][0]['measurements'] = {'private': True}
        elif mutation == 'status':rows[1]['status'] = 'PASS'
        elif mutation == 'late_check':rows[8]['checks'].append(copy.deepcopy(rows[8]['checks'][0]))
        else:rows[1]['checks'][0]['extra'] = 'private'
    p['parent_mutator'] = change;refresh(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('mode', MODES)
@pytest.mark.parametrize('fault', ['summary', 'link', 'size'])
def test_complete_summary_and_original_link(tmp_path, mode, fault):
    p = fixture(tmp_path, mode);assert observe(p)
    def change(parent):
        if fault == 'summary':
            container = parent['acceptance'] if mode == 'evidence_summary' else parent['actual_latest_acceptance'] if mode == 'command_summary' else parent
            container['goal_achieved'] = True
        else:
            ref = parent['evidence'][5] if mode == 'evidence_summary' else parent['evidence']['actual_acceptance_stdout'] if mode == 'command_summary' else parent['actual_latest_acceptance']
            ref['bytes' if fault == 'size' else 'sha256'] = 1 if fault == 'size' else 'f' * 64
    p['parent_mutator'] = change;refresh(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('field', ['original', 'snapshot', 'upstream_parent'])
def test_declared_reference_sizes(tmp_path, field):
    p = fixture(tmp_path);assert observe(p)
    p['authority']['parents'][0][field]['bytes'] = 1;rebind_authority(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('fault', ['parent', 'source', 'index', 'duplicate', 'pointer', 'value', 'hash', 'criterion', 'status'])
def test_retained_case_occurrence_binding(tmp_path, fault):
    p = fixture(tmp_path);assert observe(p)
    def change(record):
        c = record['cases'][0];row = c['rows'][0]
        if fault == 'parent':c['parent']['sha256'] = 'f' * 64
        elif fault == 'source':c['source_report']['path'] += '.other'
        elif fault == 'index':row['original_origin_index'] = True
        elif fault == 'duplicate':c['rows'].append(copy.deepcopy(row))
        elif fault == 'pointer':row['source_pointer'] = '/criteria/1/description'
        elif fault == 'value':row['value'] = 'Different private text';row['phrase_sha256'] = hashlib.sha256(row['value'].encode()).hexdigest()
        elif fault == 'hash':row['phrase_sha256'] = 'f' * 64
        elif fault == 'criterion':row['criterion_id'] = 'AC13'
        else:row['status'] = 'PASS'
    p['retained_mutator'] = change;refresh(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('role', ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/project.py',
                                'src/talkcut/__main__.py', 'src/talkcut/__init__.py', 'pyproject.toml'])
def test_all_upstream_source_dependencies_keep_registered_private_guard(tmp_path, role):
    p = fixture(tmp_path);assert observe(p)
    with pytest.raises(TalkCutError):observe(p, registered={p['upstream']['sources'][role]['sha256']})


@pytest.mark.parametrize('who', ['parent', 'upstream'])
@pytest.mark.parametrize('location', ['root', 'sibling', 'criterion'])
def test_recursive_transcript_refusal(tmp_path, who, location):
    p = fixture(tmp_path);assert observe(p)
    marker = {'schema_version': 'transcript/v1', 'segments': [{'text': 'Synthetic private speech.'}]}
    if who == 'parent':
        def change(parent):
            if location == 'root':parent['schema_version'] = 'transcript/v1'
            elif location == 'sibling':parent['private_notes'] = marker
            else:parent['acceptance']['criteria'][0]['evidence_refs'] = [marker]
        p['parent_mutator'] = change
    else:
        report = p['upstream']['reports'][0]
        if location == 'root':report['schema_version'] = 'transcript/v1'
        elif location == 'sibling':report['invalid_evidence'] = [marker]
        else:report['criteria'][0]['evidence_refs'] = [marker]
        refresh_data(p['upstream'])
    refresh(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('mode', MODES)
def test_upstream_whole_report_constructor_not_bypassed(tmp_path, mode):
    p = fixture(tmp_path, mode);assert observe(p)
    up = p['upstream'];report = up['report'] if mode == 'command_summary' else up['reports'][0]
    report['criteria'][1]['checks'][0].update(status='PASS', reason='Impossible successful check reason')
    (refresh_cli if mode == 'command_summary' else refresh_data)(up);refresh(p)
    with pytest.raises(TalkCutError):observe(p)


def test_new_equal_checkpoint_not_in_retained_original_case(tmp_path):
    p = fixture(tmp_path);assert observe(p)
    unbound = write(p['folder'] / 'new-equal-checkpoint.json', Path(p['original']['path']).read_bytes())
    chosen = locator(p);chosen['parent'] = unbound
    with pytest.raises(TalkCutError):observe(p, [chosen])


@pytest.mark.parametrize('mode', ['partial_criterion_projection', 'new_command_receipt', 'unknown'])
def test_unsupported_remaining_projection_routes(tmp_path, mode):
    p = fixture(tmp_path);assert observe(p)
    p['authority']['parents'][0]['projection'] = mode;rebind_authority(p)
    with pytest.raises(TalkCutError):observe(p)


def test_duplicate_locator(tmp_path):
    p = fixture(tmp_path);assert observe(p)
    with pytest.raises(TalkCutError):observe(p, [locator(p), locator(p)])


def test_upstream_cycle_cannot_self_authorize(tmp_path):
    p = fixture(tmp_path);assert observe(p)
    fake = write(p['folder'] / 'recursive.json', {'schema_version': 'review-machine-field-authority/v1',
                                               'family': 'acceptance_checkpoint_data'})
    p['authority']['upstream_authority'] = fake;rebind_authority(p)
    with pytest.raises(TalkCutError):observe(p, approved=[p['authority_ref'], fake])


def test_final_parent_mutation_is_detected(tmp_path, monkeypatch):
    p = fixture(tmp_path);assert observe(p)
    original = privacy.privacy_checkpoint_origins.project_field;fired = []
    def mutate(*args):
        result = original(*args)
        Path(p['original']['path']).write_bytes(Path(p['original']['path']).read_bytes() + b' ')
        fired.append(True)
        return result
    monkeypatch.setattr(privacy.privacy_checkpoint_origins, 'project_field', mutate)
    with pytest.raises(TalkCutError):observe(p)
    assert fired == [True]


@pytest.mark.parametrize('target', ['source', 'upstream_report', 'retained_cases'])
def test_final_dependency_mutation_is_detected(tmp_path, monkeypatch, target):
    p = fixture(tmp_path);assert observe(p)
    ref = p['upstream']['sources']['src/talkcut/contracts.py'] if target == 'source' else p['source'] if target == 'upstream_report' else p['authority']['retained_copies']
    original = privacy.privacy_checkpoint_origins.project_field;fired = []
    def mutate(*args):
        result = original(*args);path = Path(ref['path']);path.write_bytes(path.read_bytes() + b' ');fired.append(True)
        return result
    monkeypatch.setattr(privacy.privacy_checkpoint_origins, 'project_field', mutate)
    with pytest.raises(TalkCutError):observe(p)
    assert fired == [True]


@pytest.mark.parametrize('fault', ['module_binding', 'codec', 'missing_role', 'map', 'upstream_project'])
def test_closed_upstream_source_and_command_relations(tmp_path, fault):
    p = fixture(tmp_path, 'command_summary' if fault == 'upstream_project' else 'evidence_summary');assert observe(p)
    up = p['upstream']
    if fault in ('module_binding', 'codec'):
        source = Path(up['sources']['src/talkcut/acceptance.py']['path'])
        source.write_bytes(source.read_bytes() + b'\nEvaluator = None\n' if fault == 'module_binding'
                           else b'# coding: missing_checkpoint_codec\n' + source.read_bytes())
        refresh_data(up)
    elif fault == 'missing_role':
        up['data_authority_mutator'] = lambda a: a['sources'].pop('src/talkcut/contracts.py')
        refresh_data(up)
    elif fault == 'map':
        up['map_mutator'] = lambda r: r['cases'][0]['members'][0].update(expected_sha256='f' * 64)
        refresh_data(up)
    else:
        up['command_mutator'] = lambda c: c['argv'].__setitem__(6, str(p['directory'] / 'other-project'))
        refresh_cli(up)
    refresh(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('namespace', ['sources', 'transcripts', 'renders', 'reviews', 'review', 'analysis'])
def test_selected_original_namespace_guard(tmp_path, namespace):
    p = fixture(tmp_path);assert observe(p)
    p['original_path'] = p['directory'] / namespace / 'checkpoint.json';refresh(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('which', ['checkpoint', 'upstream'])
def test_registered_private_whole_parent_guard(tmp_path, which):
    p = fixture(tmp_path);assert observe(p)
    ref = p['original'] if which == 'checkpoint' else p['source']
    with pytest.raises(TalkCutError):observe(p, registered={ref['sha256']})


@pytest.mark.parametrize('fault', ['empty', 'too_many', 'duplicate', 'case_bool', 'case_missing', 'unknown_field', 'rows_bound'])
def test_authority_closed_bounds(tmp_path, fault):
    p = fixture(tmp_path);assert observe(p)
    if fault == 'empty':p['authority']['parents'] = []
    elif fault == 'too_many':p['authority']['parents'] *= 5
    elif fault == 'duplicate':p['authority']['parents'] *= 2
    elif fault == 'case_bool':p['authority']['parents'][0]['retained_case'] = True
    elif fault == 'case_missing':p['authority']['parents'][0]['retained_case'] = 100
    elif fault == 'unknown_field':p['authority']['trust_equal_bytes'] = True
    else:
        record = copy.deepcopy(p['retained']);record['cases'][0]['rows'] = [record['cases'][0]['rows'][0]] * 20001
        p['authority']['retained_copies'] = write(p['folder'] / 'oversized-case.json', record)
    rebind_authority(p)
    with pytest.raises(TalkCutError):observe(p)


@pytest.mark.parametrize('family', [None, [], {}, 'contract_template', 'acceptance_checkpoint_data'])
def test_upstream_family_is_closed_and_malformed_values_refuse(tmp_path, family):
    p = fixture(tmp_path);assert observe(p)
    fake = write(p['folder'] / 'bad-upstream.json', {'schema_version': 'review-machine-field-authority/v1', 'family': family})
    p['authority']['upstream_authority'] = fake;rebind_authority(p)
    with pytest.raises(TalkCutError):observe(p, approved=[p['authority_ref'], fake])


def test_same_phrase_in_another_original_checkpoint_remains_protected(tmp_path):
    p = fixture(tmp_path)
    other = write(p['directory'] / 'other-checkpoint.json', {'private_notes': PHRASE})
    write(p['directory'] / 'checkpoint.local.json', {'selected': p['original'], 'other': other, 'archive': p['snapshot']})
    known, phrases, _ = inventory(p)
    assert PHRASE in phrases and known[other['sha256']] == 'review'


def test_snapshot_reference_cannot_select_an_unbound_same_hash_copy(tmp_path):
    p = fixture(tmp_path);assert observe(p)
    new = write(p['temporary'] / 'not-declared.json', Path(p['snapshot']['path']).read_bytes())
    selected = locator(p, snapshot=True);selected['parent'] = new
    with pytest.raises(TalkCutError):observe(p, [selected])


@pytest.mark.parametrize('role', ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/project.py',
                                'src/talkcut/__main__.py', 'src/talkcut/__init__.py', 'pyproject.toml'])
def test_all_dependencies_keep_known_private_transcript_guard(tmp_path, role):
    p = fixture(tmp_path);assert observe(p)
    ref = p['upstream']['sources'][role]
    write(p['directory'] / 'transcripts/private-source.txt', Path(ref['path']).read_bytes())
    with pytest.raises(TalkCutError, match='Known private'):inventory(p)


@pytest.mark.parametrize('role', ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/project.py',
                                'src/talkcut/__main__.py', 'src/talkcut/__init__.py', 'pyproject.toml'])
@pytest.mark.parametrize('kind', ['review', 'transcript', 'media', 'credentials'])
def test_every_dependency_keeps_explicit_private_corpus_guard(tmp_path, role, kind):
    from test_privacy_checks import publication_input
    p = fixture(tmp_path);assert observe(p)
    raw_ref = publication_input(p['root'], tmp_path)
    raw = json.loads(Path(raw_ref['path']).read_bytes());corpus_path = Path(raw['private_corpus']['path'])
    corpus = json.loads(corpus_path.read_bytes())
    corpus['file_hashes'].append({'sha256': p['upstream']['sources'][role]['sha256'], 'kind': kind})
    raw.update(private_corpus=write(corpus_path, corpus), review_text_origins=[locator(p)],
               review_text_origin_authorities=[p['authority_ref'], p['upstream_authority']])
    write(raw_ref['path'], raw)
    with pytest.raises(TalkCutError, match='Explicit or audited private corpus bytes'):
        privacy.verify_release_privacy(artifact_ref(raw_ref['path']), p['root'],
            project_dir=p['directory'], expected_source_hashes=p['registered'])
