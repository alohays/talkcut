from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest
from retention_fixture import document, fixture, read, rebound, ref, verify, write

from talkcut import privacy_retention_origins as retention
from talkcut.project import TalkCutError


@pytest.mark.parametrize('variant', [0, 1])
def test_original_complete_shapes_and_leaf_only_projection(tmp_path: Path, variant: int) -> None:
    context = fixture(tmp_path, variant)
    before = copy.deepcopy(context['report'])
    bound = verify(context)
    selectors = [['current_inventory', 'scope'], ['current_inventory', 'reason'],
                 ['current_inventory', 'public_work_candidates', 0, 'reason'],
                 ['current_inventory', 'unfollowed_refs', 0, 'reason'],
                 ['current_inventory', 'unfollowed_refs', 1, 'reason']]
    if variant == 0:
        selectors.append(['current_inventory', 'public_work_candidates', 1, 'preservation'])
    rows = retention.retention_fields(bound, context['selected']['result'], selectors)
    assert rows == retention.retention_fields(bound, context['selected']['result'], selectors)
    assert all(row['status'] == 'UNVERIFIED' and row['extractions'] == [{'edge': edge, 'value': row['value']}]
               for row, edge in zip(rows, selectors, strict=True))
    assert context['report'] == bound['parent'] == before
    assert retention.speech_marker(bound['parent'])
    assert len(bound['parent']['current_inventory']['known_refs']) == 19


@pytest.mark.parametrize('target', ['source', 'script'])
@pytest.mark.parametrize('prefix', [b'# coding: missing_retention_codec\n', b'# coding: utf-16\n'])
def test_byte_codec_refusal_after_complete_reference_rebinding(tmp_path: Path, target: str, prefix: bytes) -> None:
    context = fixture(tmp_path)
    path = context[target]
    path.write_bytes(prefix + path.read_bytes())
    rebound(context)
    with pytest.raises(TalkCutError, match='source bytes'):
        verify(context)


@pytest.mark.parametrize('target', ['source', 'script'])
def test_valid_utf8_bom_preserves_loader_ast(tmp_path: Path, target: str) -> None:
    context = fixture(tmp_path, 1)
    context[target].write_bytes(b'\xef\xbb\xbf' + context[target].read_bytes())
    rebound(context)
    verify(context)


@pytest.mark.parametrize('suffix', ['\n_known_private_inventory=None\n', '\nraise RuntimeError("closed")\n',
                                   '\nfrom builtins import dict as _known_private_inventory\n'])
def test_source_module_binding_refusal(tmp_path: Path, suffix: str) -> None:
    context = fixture(tmp_path)
    context['source'].write_text(context['source'].read_text() + suffix)
    rebound(context)
    with pytest.raises(TalkCutError, match='complete supported original module'):
        verify(context)


@pytest.mark.parametrize('mutation', ['rebind', 'early_raise', 'clear_output', 'replace_output', 'dormant_call', 'wrong_import'])
def test_complete_direct_reproducer_flow_refusal(tmp_path: Path, mutation: str) -> None:
    context = fixture(tmp_path)
    path = context['script']
    text = path.read_text()
    needle = 'known, phrases, inventory = _known_private_inventory('
    if mutation == 'rebind':
        text = text.replace(needle, '_known_private_inventory = None\n' + needle)
    elif mutation == 'early_raise':
        text = text.replace(needle, 'raise RuntimeError("closed")\n' + needle)
    elif mutation == 'clear_output':
        text = text.replace('report = {', 'inventory.clear()\nreport = {')
    elif mutation == 'replace_output':
        text = text.replace('report = {', 'inventory = {}\nreport = {')
    elif mutation == 'dormant_call':
        line = next(line for line in text.splitlines() if line.startswith(needle))
        text = text.replace(line, 'def uncalled():\n    ' + line)
    else:
        text = text.replace('from talkcut.privacy_checks import _known_private_inventory',
                            'from talkcut.other import _known_private_inventory')
    assert text != path.read_text()
    path.write_text(text)
    rebound(context)
    with pytest.raises(TalkCutError, match='complete supported original module'):
        verify(context)


@pytest.mark.parametrize('location', ['root', 'inventory', 'associated_row', 'selected_value', 'other_sibling', 'nested_descriptor'])
def test_transcript_schema_outside_exact_descriptor_sibling_refused(tmp_path: Path, location: str) -> None:
    context = fixture(tmp_path)
    report = context['report']
    marker = {'schema_version': 'transcript/v1', 'source_sha256': '1' * 64, 'text': 'Synthetic private words remain protected.'}
    if location == 'root':
        report['schema_version'] = 'transcript/v1'
    elif location == 'inventory':
        report['current_inventory']['schema_version'] = 'transcript/v1'
    elif location == 'associated_row':
        report['current_inventory']['public_work_candidates'][0].update(marker)
    elif location == 'selected_value':
        report['current_inventory']['public_work_candidates'][0]['reason'] = marker
    elif location == 'other_sibling':
        report['expected_speech_strings'] = [marker]
    else:
        report['transcript_files_checked'][11]['speech_fields'][0]['extra'] = marker
    rebound(context)
    with pytest.raises(TalkCutError):
        verify(context)


@pytest.mark.parametrize('mutation', ['extra_text', 'wrong_source', 'duplicate_descriptor', 'float_count', 'bool_line', 'drop_row'])
def test_descriptor_family_is_closed(tmp_path: Path, mutation: str) -> None:
    context = fixture(tmp_path)
    row = context['report']['transcript_files_checked'][11]
    if mutation == 'extra_text':
        row['speech_fields'][0]['text'] = 'Private text must never become a descriptor exemption.'
    elif mutation == 'wrong_source':
        row['source_sha256'] = '9' * 64
    elif mutation == 'duplicate_descriptor':
        row['speech_fields'].append(copy.deepcopy(row['speech_fields'][0]))
    elif mutation == 'float_count':
        row['speech_fields'][0]['characters'] = 80.0
    elif mutation == 'bool_line':
        row['plain_transcript_lines'] = [{'line': True, 'characters': 0, 'sha256': '4' * 64, 'qualifies_40_chars': False}]
    else:
        context['report']['transcript_files_checked'].pop()
    rebound(context)
    with pytest.raises(TalkCutError):
        verify(context)


@pytest.mark.parametrize('selector', [[], ['current_inventory'], ['current_inventory', 'public_work_candidates'],
    ['current_inventory', 'public_work_candidates', 0], ['current_inventory', 'public_work_candidates', True, 'reason'],
    ['current_inventory', 'public_work_candidates', 0.0, 'reason'], ['current_inventory', 'public_work_candidates', '0', 'reason'],
    ['current_inventory', 'public_work_candidates', -1, 'reason'], ['current_inventory', 'public_work_candidates', 0, 'classification'],
    ['current_inventory', 'public_work_candidates', 0, 'matching_git_source_bytes'], ['scope'],
    ['transcript_files_checked', 11, 'speech_fields', 0, 'sha256']])
def test_selector_type_scope_and_container_refusals(tmp_path: Path, selector: list[object]) -> None:
    context = fixture(tmp_path)
    bound = verify(context)
    with pytest.raises(TalkCutError):
        retention.retention_field(bound, context['selected']['result'], selector)


def test_same_phrase_unselected_private_prose_remains_in_full_parent(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    phrase = context['report']['current_inventory']['public_work_candidates'][0]['reason']
    context['report']['unexplained_removed'] = [{'text_private_only': phrase, 'sha256': hashlib.sha256(phrase.encode()).hexdigest(), 'origins': []}]
    context['report']['unexplained_removed_count'] = 1
    rebound(context)
    before = copy.deepcopy(context['report'])
    bound = verify(context)
    edge = ['current_inventory', 'public_work_candidates', 0, 'reason']
    result = retention.retention_field(bound, context['selected']['result'], edge)
    assert result['extractions'] == [{'edge': edge, 'value': phrase}]
    assert bound['parent'] == before
    assert bound['parent']['unexplained_removed'][0]['text_private_only'] == phrase


def test_duplicate_projection_and_wrong_parent_refused(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    bound = verify(context)
    edge = ['current_inventory', 'scope']
    with pytest.raises(TalkCutError, match='duplicated'):
        retention.retention_fields(bound, context['selected']['result'], [edge, edge])
    other = write(tmp_path / 'same-byte-other-parent.json', context['report'])
    with pytest.raises(TalkCutError, match='unbound'):
        retention.retention_field(bound, other, edge)


def test_changed_full_parent_after_binding_refused(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    bound = verify(context)
    bound['parent']['expected_speech_strings'] = [{'text': 'Other private prose'}]
    with pytest.raises(TalkCutError, match='changed after'):
        retention.retention_field(bound, context['selected']['result'], ['current_inventory', 'scope'])


@pytest.mark.parametrize('field', ['classification', 'reason', 'extra', 'preservation'])
def test_complete_candidate_row_refusals(tmp_path: Path, field: str) -> None:
    context = fixture(tmp_path)
    context['report']['current_inventory']['public_work_candidates'][0][field] = 'PUBLIC' if field == 'classification' else 'forged'
    rebound(context)
    bound = verify(context)
    with pytest.raises(TalkCutError):
        retention.retention_field(bound, context['selected']['result'], ['current_inventory', 'public_work_candidates', 0, 'reason'])


def test_original_output_path_binding(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    context['selected']['result'] = write(tmp_path / 'relocated-result.json', context['report'])
    with pytest.raises(TalkCutError, match='UUID output'):
        verify(context)


def test_old_scanner_bytes_and_git_identity(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    old = Path(context['selected']['previous_scanner']['path'])
    old.write_bytes(old.read_bytes() + b'\n# different Git blob\n')
    context['selected']['previous_scanner'] = ref(old)
    context['report']['previous_scanner'].update(ref(old))
    rebound(context)
    with pytest.raises(TalkCutError, match='Git blob'):
        verify(context)


def test_cross_source_script_pair_is_rejected(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    other = fixture(tmp_path / 'other', 1)
    context['source'].write_bytes(other['source'].read_bytes())
    old_hash = context['report']['source_before']['sha256']
    new_hash = ref(context['source'])['sha256']
    context['script'].write_text(context['script'].read_text().replace(old_hash, new_hash))
    rebound(context)
    with pytest.raises(TalkCutError, match='compatible pair'):
        verify(context)


def test_original_whole_hash_and_aggregate_mutation_refusal(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    fired = False
    def changing_read(value: dict[str, str]) -> tuple[Path, bytes]:
        nonlocal fired
        answer = read(value)
        if value == context['selected']['previous_scanner'] and not fired:
            fired = True
            context['result'].write_text(context['result'].read_text() + ' ')
        return answer
    with pytest.raises(TalkCutError, match='digest differs'):
        retention.verify_retention_inventory(context['selected'], context['root'], changing_read, document)
    assert fired


def test_duplicate_json_is_not_a_whole_parent_authority(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    text = context['result'].read_text()
    context['result'].write_text(text.replace('{', '{"schema_version":"forged",', 1))
    context['selected']['result'] = ref(context['result'])
    with pytest.raises(TalkCutError, match='Duplicate JSON'):
        verify(context)


@pytest.mark.parametrize('field,value', [('missing_speech_count', 1), ('unexplained_removed_count', True),
    ('added_phrase_hashes', ['bad']), ('expected_speech_strings', None), ('wall_seconds', -1),
    ('current_phrase_count', 4), ('protected_project_files_unchanged', []), ('status', 'PASS')])
def test_original_parent_type_and_count_refusals(tmp_path: Path, field: str, value: object) -> None:
    context = fixture(tmp_path)
    context['report'][field] = value
    rebound(context)
    with pytest.raises(TalkCutError):
        verify(context)


def test_whole_original_duplicate_rows_are_conserved(tmp_path: Path) -> None:
    context = fixture(tmp_path)
    rows = context['report']['current_inventory']['known_refs']
    rows.append(copy.deepcopy(rows[0]))
    context['report']['current_inventory']['known_ref_count'] += 1
    rebound(context)
    bound = verify(context)
    assert len(bound['parent']['current_inventory']['known_refs']) == 20
    assert bound['parent']['current_inventory']['known_refs'] == rows
    rows[-1]['kind'] = 'review'
    rebound(context)
    with pytest.raises(TalkCutError, match='conflicting'):
        verify(context)
