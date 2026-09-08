from __future__ import annotations

import copy
from pathlib import Path

import pytest
from retention_fixture import fixture, rebound, verify

from talkcut import privacy_retention_origins as retention
from talkcut.project import TalkCutError


def project(context: dict, edge: list) -> dict:
    bound = verify(context)
    return retention.retention_field(bound, context['selected']['result'], edge)


@pytest.mark.parametrize('variant', [0, 1])
def test_duplicate_same_media_rows_are_retained(tmp_path: Path, variant: int) -> None:
    context = fixture(tmp_path, variant)
    known = context['report']['current_inventory']
    row = {'path': str(context['project'] / 'same.mp4'), 'sha256': '8' * 64, 'kind': 'media'}
    known['known_refs'].extend([row, copy.deepcopy(row)])
    known['known_ref_count'] += 2
    rebound(context)
    before = copy.deepcopy(context['report'])
    bound = verify(context)
    assert bound['parent'] == before
    assert bound['parent']['current_inventory']['known_refs'][-2:] == [row, row]
    assert project(context, ['current_inventory', 'scope'])['status'] == 'UNVERIFIED'


def test_original_preservation_reference_hash_must_match_snapshot(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    candidate = context['report']['current_inventory']['public_work_candidates'][1]
    assert candidate['sha256'] == candidate['original_reference']['sha256']
    baseline = project(context, ['current_inventory', 'public_work_candidates', 1, 'preservation'])
    assert baseline['status'] == 'UNVERIFIED'
    candidate['original_reference']['sha256'] = '9' * 64
    rebound(context)
    with pytest.raises(TalkCutError):
        project(context, ['current_inventory', 'public_work_candidates', 1, 'preservation'])


@pytest.mark.parametrize('fault', ['false_retention', 'wrong_kind'])
def test_descriptor_retention_facts_must_match_known_hash_map(tmp_path: Path, fault: str) -> None:
    context = fixture(tmp_path)
    descriptor = context['report']['transcript_files_checked'][11]
    known = context['report']['current_inventory']['known_refs']
    assert [r['kind'] for r in known if r['sha256'] == descriptor['artifact']['sha256']] == ['transcript']
    assert descriptor['speech_fields'] and descriptor['private_exact_hash_retained']
    assert project(context, ['current_inventory', 'scope'])['status'] == 'UNVERIFIED'
    if fault == 'false_retention':
        descriptor['private_exact_hash_retained'] = False
    else:
        descriptor['assigned_kind'] = 'media'
    rebound(context)
    with pytest.raises(TalkCutError):
        project(context, ['current_inventory', 'scope'])


@pytest.mark.parametrize('target', ['script', 'source'])
@pytest.mark.parametrize('suffix', ['\nif True:\n    raise RuntimeError("unreachable")\n', '\n_known_private_inventory = lambda *args: None\n'])
def test_added_whole_module_control_flow_is_refused(tmp_path: Path, target: str, suffix: str) -> None:
    context = fixture(tmp_path)
    assert project(context, ['current_inventory', 'scope'])['status'] == 'UNVERIFIED'
    context[target].write_bytes(context[target].read_bytes() + suffix.encode())
    rebound(context)
    with pytest.raises(TalkCutError, match='complete supported original module'):
        verify(context)


@pytest.mark.parametrize('fault', ['byte_boolean', 'line_zero', 'source_not_registered', 'descriptor_count', 'hash_type'])
def test_descriptor_independent_type_and_source_refusals(tmp_path: Path, fault: str) -> None:
    context = fixture(tmp_path)
    descriptor = context['report']['transcript_files_checked'][11]
    if fault == 'byte_boolean':
        descriptor['bytes'] = True
    elif fault == 'line_zero':
        descriptor['plain_transcript_lines'] = [{'line': 0, 'characters': 1, 'qualifies_40_chars': False, 'sha256': '7' * 64}]
    elif fault == 'source_not_registered':
        descriptor['source_sha256'] = '8' * 64
    elif fault == 'descriptor_count':
        context['report']['transcript_files_checked'].append(copy.deepcopy(descriptor))
    else:
        descriptor['artifact']['sha256'] = True
    rebound(context)
    with pytest.raises(TalkCutError):
        verify(context)


@pytest.mark.parametrize('selector', [['current_inventory', 'unfollowed_refs', True, 'reason'], ['current_inventory', 'public_work_candidates', 0, 'matching_git_source_bytes', 0, 'git_path']])
def test_other_projections_remain_refused(tmp_path: Path, selector: list) -> None:
    context = fixture(tmp_path)
    with pytest.raises(TalkCutError):
        project(context, selector)
