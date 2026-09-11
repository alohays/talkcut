"""Exact report writer scope, preserving mixed descriptors and private prose."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest
from retention_consumer_fixture import PRIVATE_PROSE, consumer_fixture, observe
from retention_fixture import fixture, rebound, ref, verify, write

from talkcut import privacy_checks as privacy
from talkcut import privacy_retention_origins as retention
from talkcut.project import TalkCutError


@pytest.mark.parametrize('variant', [0, 1])
def test_report_scope_uses_the_complete_report_writer(tmp_path: Path, variant: int) -> None:
    context = fixture(tmp_path, variant)
    bound = verify(context)
    before = copy.deepcopy(bound['parent'])
    projection = retention.retention_field(bound, context['selected']['result'], ['scope'])
    assert projection['source'] == context['selected']['reproducer']
    assert projection['source'] != context['selected']['source_snapshot']
    assert projection['row'] == bound['parent'] == before
    assert retention.speech_marker(projection['row'])
    assert projection['extractions'] == [{'edge': ['scope'], 'value': before['scope']}]
    assert projection['status'] == 'UNVERIFIED'


def bind_root_scope(context: dict) -> None:
    rebound(context)
    context['authority'] = write(Path(context['authority']['path']), context['selected'])
    context['locator'].update(parent=ref(context['result']), selector=['scope'], authority=context['authority'])
    context['selected_phrase'] = context['report']['scope']


@pytest.mark.parametrize('variant', [0, 1])
@pytest.mark.parametrize('same_private_text', [False, True])
def test_complete_consumer_scopes_one_root_leaf_and_conserves_private_graph(
    tmp_path: Path, variant: int, same_private_text: bool,
) -> None:
    context = consumer_fixture(tmp_path, variant)
    phrase = context['report']['scope']
    if same_private_text:
        context['report']['unexplained_removed'] = [
            {'text_private_only': phrase, 'sha256': hashlib.sha256(phrase.encode()).hexdigest(), 'origins': []},
        ]
        context['report']['unexplained_removed_count'] = 1
    bind_root_scope(context)
    original = context['result'].read_bytes()
    before_known, before_phrases, before_graph = observe(context, False)
    after_known, after_phrases, after_graph = observe(context, True)
    assert phrase in before_phrases
    assert (phrase in after_phrases) == same_private_text
    assert PRIVATE_PROSE in after_phrases and set(context['private_texts']) <= set(after_phrases)
    assert all(after_known[digest] == kind for digest, kind in before_known.items())
    assert after_known[ref(context['result'])['sha256']] == 'review'
    before_rows = {(row['path'], row['sha256'], row['kind']) for row in before_graph['known_refs']}
    after_rows = {(row['path'], row['sha256'], row['kind']) for row in after_graph['known_refs']}
    assert before_rows <= after_rows
    assert context['result'].read_bytes() == original
    assert len(after_graph['review_text_origins']) == 1
    projection = after_graph['review_text_origins'][0]
    assert projection['source_snapshot'] == context['selected']['reproducer']
    assert projection['source']['original_path'] == context['selected']['reproducer']['path']
    assert projection['associated_row'] == context['report']
    assert projection['extractions'] == [{'edge': ['scope'], 'value': phrase}]
    assert projection['claim_status'] == 'UNVERIFIED'
    write(tmp_path / 'scope-consumer-observed.json', {'before': before_graph, 'after': after_graph,
        'known_before': before_known, 'known_after': after_known,
        'phrases_before': before_phrases, 'phrases_after': after_phrases,
        'same_phrase_in_unselected_private_text': same_private_text})


@pytest.mark.parametrize('mutation', ['root_scope', 'descriptor_text', 'other_speech', 'script_writer', 'wrong_path', 'after_binding'])
def test_root_scope_does_not_relax_original_report_binding(tmp_path: Path, mutation: str) -> None:
    context = fixture(tmp_path)
    report = context['report']
    if mutation == 'root_scope':
        report['scope'] = 'Synthetic private speech is never an original fixed report scope.'
    elif mutation == 'descriptor_text':
        report['transcript_files_checked'][11]['speech_fields'][0]['text'] = 'Synthetic private speech.'
    elif mutation == 'other_speech':
        report['unexplained_removed'] = [{'schema_version': 'transcript/v1', 'text': 'Synthetic private speech.'}]
    elif mutation == 'script_writer':
        script = context['script']
        script.write_text(script.read_text() + '\nreport["scope"] = "Synthetic replacement scope"\n')
    rebound(context)
    if mutation == 'wrong_path':
        context['selected']['result'] = write(tmp_path / 'same-report-copy.json', report)
    with pytest.raises(TalkCutError):
        bound = verify(context)
        if mutation == 'after_binding':
            bound['parent']['unexplained_removed'] = [{'text_private_only': 'Changed private context'}]
        retention.retention_field(bound, context['selected']['result'], ['scope'])


@pytest.mark.parametrize('selector', [['scope', 'text'], ['scope', 0], ['status'], ['schema_version'],
    ['transcript_files_checked', 11, 'schema_version'], ['unexplained_removed', 0, 'text_private_only']])
def test_other_root_fields_and_private_values_remain_unsupported(tmp_path: Path, selector: list) -> None:
    context = fixture(tmp_path)
    bound = verify(context)
    with pytest.raises(TalkCutError):
        retention.retention_field(bound, context['selected']['result'], selector)


@pytest.mark.parametrize('kind', ['machine_inventory_field', 'retention_inventory_field'])
def test_consumer_root_scope_cannot_move_to_an_unbound_parent(tmp_path: Path, kind: str) -> None:
    context = consumer_fixture(tmp_path, 0)
    bind_root_scope(context)
    context['locator']['kind'] = kind
    context['locator']['parent'] = write(context['project'] / 'same-report-copy.json', context['report'])
    reason = 'differs from its bound authority family' if kind == 'machine_inventory_field' else 'unbound'
    with pytest.raises(TalkCutError, match=reason):
        privacy._review_text_origin_inventory([context['locator']], context['project'], context['root'],
            set(context['registered'].values()), [context['authority']])
