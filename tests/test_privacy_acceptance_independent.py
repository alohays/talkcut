"""Independent bounded metadata relationships; never execute original producers."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from acceptance_origin_fixture import (
    PHRASE,
    fixture,
    inventory,
    locator,
    observe,
    refresh,
    write,
)

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref


def observed_or_preserve(parts, selector, path):
    """Keep any actually accepted full observation before the refusal assertion."""
    result = observe(parts, selector)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n')
    return result


@pytest.mark.parametrize('role', [
    'src/talkcut/acceptance.py', 'src/talkcut/contracts.py',
    'src/talkcut/__main__.py', 'src/talkcut/project.py',
    'src/talkcut/__init__.py', 'pyproject.toml',
])
def test_every_bound_producer_dependency_keeps_registered_private_guard(tmp_path, role):
    parts = fixture(tmp_path, 'python')
    assert observe(parts)[0]['selected_value'] == PHRASE
    registered = set(parts['registered'].values()) | {parts['sources'][role]['sha256']}
    with pytest.raises(TalkCutError):
        rows = privacy._review_text_origin_inventory(
            [locator(parts)], parts['directory'], parts['root'], registered,
            [parts['authority']],
        )
        (tmp_path / 'unexpected-registered-source-observation.json').write_text(
            json.dumps({'registered_role': role, 'observations': rows}, indent=2) + '\n'
        )


@pytest.mark.parametrize('fault', [
    'contradictory_criterion_status', 'duplicate_fixed_check',
    'missing_fixed_sibling', 'reordered_fixed_checks',
    'unwritten_criterion_evidence_refs', 'extra_unwritten_check',
])
def test_full_original_criterion_writer_relation_cannot_be_fabricated(tmp_path, fault):
    parts = fixture(tmp_path, 'python')
    selector = ['criteria', 2, 'checks', 0, 'reason']
    assert observe(parts, selector)
    row = parts['report']['criteria'][2]
    if fault == 'contradictory_criterion_status':
        row['status'] = 'PASS'  # Both original checks are still UNVERIFIED.
    elif fault == 'duplicate_fixed_check':
        row['checks'].append(copy.deepcopy(row['checks'][0]))
    elif fault == 'missing_fixed_sibling':
        row['checks'].pop()
    elif fault == 'reordered_fixed_checks':
        row['checks'].reverse()
        selector[3] = 1  # Still names exactly the original workflow_e2e reason.
    elif fault == 'unwritten_criterion_evidence_refs':
        row['evidence_refs'].append({'authored_note': 'Synthetic private note'})
    else:
        row['checks'].append({'check_id': 'unwritten_private_check', 'status': 'UNVERIFIED',
                              'reason': 'Synthetic private authored check', 'measurements': None})
    refresh(parts)
    with pytest.raises(TalkCutError):
        observed_or_preserve(parts, selector, tmp_path / 'unexpected-writer-observation.json')


@pytest.mark.parametrize('fault', ['unapproved_authority', 'duplicate_selector', 'stale_stdout', 'duplicate_json_key'])
def test_exact_consumer_binding_and_closed_json_boundary(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    item = locator(parts)
    approved = [parts['authority']]
    selected = [item]
    if fault == 'unapproved_authority':
        approved = []
    elif fault == 'duplicate_selector':
        selected.append(copy.deepcopy(item))
    elif fault == 'stale_stdout':
        p = Path(parts['stdout']['path']);p.write_bytes(p.read_bytes() + b' ')
    else:
        p = Path(parts['stdout']['path']);raw = p.read_bytes()
        p.write_bytes(raw.replace(b'{\n', b'{\n  "status": "FAIL",\n', 1))
        item['parent'] = artifact_ref(p)
        parts['selected']['stdout'] = item['parent']
        command = json.loads(Path(parts['command']['path']).read_bytes())
        command['stdout'] = item['parent']
        parts['selected']['command'] = write(Path(parts['command']['path']), command)
        item['authority'] = write(Path(parts['authority']['path']), parts['selected'])
        approved = [item['authority']]
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory(selected, parts['directory'], parts['root'],
                                             set(parts['registered'].values()), approved)




@pytest.mark.parametrize('selector', [
    ['criteria', 0, 'description'],
    ['criteria', 2, 'checks', 0, 'reason'],
    ['provenance_limitations'],
])
def test_positive_full_associated_rows_are_actual_parent_rows(tmp_path, selector):
    parts = fixture(tmp_path)
    observation = observe(parts, selector, saved=True)[0]
    associated = parts['report']
    for part in selector[:-1]:
        associated = associated[part]
    assert observation['associated_row'] == associated
    assert observation['selected_value'] == associated[selector[-1]]
    assert observation['extractions'] == [{'edge': selector, 'value': associated[selector[-1]]}]
    assert observation['parent'] == artifact_ref(parts['saved_path'])
    assert observation['claim_status'] == 'UNVERIFIED'


def test_registered_external_copy_cannot_use_snapshot_exception(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts, saved=True)
    parent = artifact_ref(parts['saved_path'])
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory([locator(parts, saved=True)], parts['directory'],
            parts['root'], set(parts['registered'].values()) | {parent['sha256']}, [parts['authority']])


def test_unselected_already_private_complete_copy_retains_phrase(tmp_path):
    parts = fixture(tmp_path)
    parts['saved_path'] = parts['directory'] / 'evidence' / 'retained-complete-copy.json'
    refresh(parts)
    saved = artifact_ref(parts['saved_path'])
    write(parts['directory'] / 'checkpoint.local.json', {'report': parts['stdout'], 'saved': saved})
    before_bytes = Path(saved['path']).read_bytes()
    before_known, before_phrases, _ = inventory(parts, [])
    assert before_known[saved['sha256']] == 'review' and PHRASE in before_phrases
    known, phrases, graph = inventory(parts, [locator(parts)])
    assert PHRASE in phrases and known[saved['sha256']] == 'review'
    assert len(graph['review_text_origins']) == 1
    assert graph['review_text_origins'][0]['claim_status'] == 'UNVERIFIED'
    assert Path(saved['path']).read_bytes() == before_bytes
