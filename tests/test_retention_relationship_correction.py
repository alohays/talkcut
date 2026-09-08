from pathlib import Path

import pytest
from retention_fixture import fixture, rebound, verify

from talkcut.project import TalkCutError


def test_speech_descriptor_requires_complete_retention_even_with_consistent_absence(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    descriptor = context['report']['transcript_files_checked'][11]
    known = context['report']['current_inventory']
    known['known_refs'] = [r for r in known['known_refs'] if r['sha256'] != descriptor['artifact']['sha256']]
    known['known_ref_count'] = len(known['known_refs'])
    descriptor.update(private_exact_hash_retained=False, assigned_kind=None)
    rebound(context)
    with pytest.raises(TalkCutError, match='complete-retention assertion'):
        verify(context)


def test_empty_descriptor_can_truthfully_record_absence(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    descriptor = context['report']['transcript_files_checked'][0]
    assert not descriptor['speech_fields'] and not descriptor['plain_transcript_lines']
    known = context['report']['current_inventory']
    known['known_refs'] = [r for r in known['known_refs'] if r['sha256'] != descriptor['artifact']['sha256']]
    known['known_ref_count'] = len(known['known_refs'])
    descriptor.update(private_exact_hash_retained=False, assigned_kind=None)
    rebound(context)
    assert verify(context)['parent'] == context['report']


def test_descriptor_kind_uses_complete_original_hash_rank(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    descriptor = context['report']['transcript_files_checked'][11]
    known = context['report']['current_inventory']
    known['known_refs'].append({'path': str(tmp_path / 'same-hash-media.bin'), 'sha256': descriptor['artifact']['sha256'], 'kind': 'media'})
    known['known_ref_count'] += 1
    descriptor['assigned_kind'] = 'media'
    rebound(context)
    assert verify(context)['parent']['transcript_files_checked'][11]['assigned_kind'] == 'media'
    descriptor['assigned_kind'] = 'transcript'
    rebound(context)
    with pytest.raises(TalkCutError, match='complete original private hash map'):
        verify(context)
