"""Complete recorded writer relations; synthetic metadata grants no approval."""
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
)
from test_privacy_checks import publication_input

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError, artifact_ref, atomic_json

ROLES = ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/__main__.py',
         'src/talkcut/project.py', 'src/talkcut/__init__.py', 'pyproject.toml']


@pytest.mark.parametrize('role', ROLES)
def test_all_bound_dependencies_keep_known_private_guard(tmp_path, role):
    parts = fixture(tmp_path, 'python')
    assert inventory(parts)[2]['review_text_origins']
    source = Path(parts['sources'][role]['path'])
    private = parts['directory'] / 'transcripts' / 'private-dependency.txt'
    private.parent.mkdir(exist_ok=True)
    private.write_bytes(source.read_bytes())
    with pytest.raises(TalkCutError, match='Known private bytes'):
        inventory(parts)


@pytest.mark.parametrize('role', ROLES)
@pytest.mark.parametrize('kind', ['review', 'transcript', 'media', 'credentials'])
def test_all_bound_dependencies_keep_explicit_corpus_guard(tmp_path, role, kind):
    parts = fixture(tmp_path, 'python')
    assert observe(parts)
    raw_ref = publication_input(parts['root'], tmp_path)
    raw = json.loads(Path(raw_ref['path']).read_bytes())
    corpus_path = Path(raw['private_corpus']['path'])
    corpus = json.loads(corpus_path.read_bytes())
    corpus['file_hashes'].append({'sha256': parts['sources'][role]['sha256'], 'kind': kind})
    atomic_json(corpus_path, corpus)
    raw.update(private_corpus=artifact_ref(corpus_path), review_text_origins=[locator(parts)],
               review_text_origin_authorities=[parts['authority']])
    atomic_json(raw_ref['path'], raw)
    with pytest.raises(TalkCutError, match='Explicit or audited private corpus bytes'):
        privacy.verify_release_privacy(artifact_ref(raw_ref['path']), parts['root'],
            project_dir=parts['directory'], expected_source_hashes=parts['registered'])


def test_all_source_roles_are_bound_separately_from_private_authority_records(tmp_path):
    parts = fixture(tmp_path, 'python')
    observation = observe(parts)[0]
    assert observation['source_dependencies'] == [
        {'original_path': str(parts['root'] / role), 'snapshot': parts['sources'][role]}
        for role in sorted(ROLES)
    ]
    assert observation['selected_value'] == PHRASE and observation['claim_status'] == 'UNVERIFIED'
    assert not any(row['snapshot'] in [parts['command'], parts['stdout'], parts['authority']]
                   for row in observation['source_dependencies'])


def dependency_fixture(tmp_path):
    parts = fixture(tmp_path, 'python')
    checks = parts['report']['criteria'][8]['checks']
    checks[0].update(status='PASS', reason='Verified from current artifacts', measurements={})
    checks.append({'check_id': 'G0_G5_dependencies', 'status': 'UNVERIFIED',
                   'reason': 'Final master requires all preceding media gates', 'measurements': None})
    refresh(parts)
    assert observe(parts)
    return parts


@pytest.mark.parametrize('fault', ['missing', 'duplicate', 'wrong_status', 'wrong_reason', 'wrong_measurements',
                                  'unneeded', 'contradictory_criterion'])
def test_conditional_output_row_follows_original_writer(tmp_path, fault):
    parts = dependency_fixture(tmp_path)
    row = parts['report']['criteria'][8]
    if fault == 'missing':
        row['checks'].pop()
    elif fault == 'duplicate':
        row['checks'].append(copy.deepcopy(row['checks'][-1]))
    elif fault.startswith('wrong_'):
        field = fault.removeprefix('wrong_')
        row['checks'][-1][field] = {'status': 'PASS', 'reason': 'Synthetic authored reason', 'measurements': {}}[field]
    elif fault == 'unneeded':
        row['checks'][0].update(status='UNVERIFIED', reason='Required hashed artifact reference is missing', measurements=None)
    else:
        row['status'] = 'PASS'
    refresh(parts)
    with pytest.raises(TalkCutError, match='Acceptance'):
        observe(parts)


@pytest.mark.parametrize('fault', ['count', 'bool_count', 'status', 'reason', 'extra_measurement'])
def test_recorded_findings_row_keeps_exact_count_constructor(tmp_path, fault):
    parts = fixture(tmp_path, 'python')
    assert observe(parts)
    row = parts['report']['criteria'][8]['checks'][1]
    if fault == 'count':
        row['measurements']['count'] = 1
    elif fault == 'bool_count':
        row['measurements']['count'] = False
    elif fault == 'status':
        row['status'] = 'FAIL'
    elif fault == 'reason':
        row['reason'] = 'Synthetic authored finding reason'
    else:
        row['measurements']['private_note'] = 'Synthetic prose'
    refresh(parts)
    with pytest.raises(TalkCutError, match='original count relation'):
        observe(parts)


def test_original_variable_capability_multiplicity_is_retained(tmp_path):
    parts = fixture(tmp_path, 'python')
    assert observe(parts)
    row = parts['report']['criteria'][0]
    row['checks'].insert(1, {'check_id': 'executed_reviewer_capability', 'status': 'UNVERIFIED',
                            'reason': 'Required hashed artifact reference is missing', 'measurements': None})
    refresh(parts)
    result = observe(parts)[0]
    assert result['associated_row'] == row and len(row['checks']) == 3
    assert result['claim_status'] == 'UNVERIFIED'
