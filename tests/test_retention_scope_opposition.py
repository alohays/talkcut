"""Independent exact-scope controls; synthetic files, no past execution claim."""
import copy
import hashlib

import pytest
from retention_consumer_fixture import PRIVATE_PROSE, consumer_fixture, observe
from retention_fixture import fixture, rebound, ref, verify, write

from talkcut import privacy_checks as privacy
from talkcut import privacy_retention_origins as retention
from talkcut.project import TalkCutError


def scope(context):
    rebound(context)
    context['authority'] = write(context['project'] / 'authority/retention-root.json', context['selected'])
    context['locator'].update(authority=context['authority'], parent=ref(context['result']), selector=['scope'])
    context['selected_phrase'] = context['report']['scope']


def direct(context, locators=None, registered=None):
    return privacy._review_text_origin_inventory(
        [context['locator']] if locators is None else locators,
        context['project'], context['root'],
        set(context['registered'].values()) if registered is None else registered,
        [context['authority']],
    )


@pytest.mark.parametrize('variant', [0, 1])
@pytest.mark.parametrize('unselected', ['none', 'whole_parent_copy', 'missing_speech'])
def test_valid_scope_does_not_clear_copied_parent_or_failure_prose(tmp_path, variant, unselected):
    context = consumer_fixture(tmp_path, variant)
    phrase = context['report']['scope']
    if unselected == 'missing_speech':
        context['report']['missing_speech_strings'] = [
            {'text_private_only': phrase, 'sha256': hashlib.sha256(phrase.encode()).hexdigest(), 'origins': []}]
        context['report']['missing_speech_count'] = 1
        context['report']['status'] = 'P1_MISSING_TRANSCRIPT_PHRASE'
    scope(context)
    if unselected == 'whole_parent_copy':
        write(context['project'] / 'reports/unselected-complete-copy.json', context['report'])
    original = context['result'].read_bytes()
    old_known, old_phrases, old_graph = observe(context, False)
    new_known, new_phrases, new_graph = observe(context, True)
    assert phrase in old_phrases
    assert (phrase in new_phrases) == (unselected != 'none')
    assert PRIVATE_PROSE in new_phrases and set(context['private_texts']) <= set(new_phrases)
    assert old_known.items() <= new_known.items()
    assert new_known[ref(context['result'])['sha256']] == 'review'
    old_rows = {(r['path'],r['sha256'],r['kind']) for r in old_graph['known_refs']}
    new_rows = {(r['path'],r['sha256'],r['kind']) for r in new_graph['known_refs']}
    assert old_rows <= new_rows
    assert context['result'].read_bytes() == original
    observations = new_graph['review_text_origins']
    assert len(observations) == 1
    row = observations[0]
    assert row['associated_row'] == context['report']
    assert row['selected_value'] == phrase and row['extractions'] == [{'edge':['scope'],'value':phrase}]
    assert row['source_snapshot'] == context['selected']['reproducer']
    assert row['source_snapshot'] != context['selected']['source_snapshot']
    assert row['claim_status'] == 'UNVERIFIED' and row['commands'] == []
    assert len(context['report']['transcript_files_checked']) == 19
    write(tmp_path / 'observed-scope.json', {'before':old_graph,'after':new_graph,
          'phrases_before':old_phrases,'phrases_after':new_phrases,'mode':unselected})


@pytest.mark.parametrize('variant', [0, 1])
@pytest.mark.parametrize('mutation', ['scope_writer', 'later_assignment', 'codec', 'nested_speech', 'descriptor_speech'])
def test_scope_exception_cannot_bypass_complete_writer_or_sibling_grammar(tmp_path, variant, mutation):
    context = fixture(tmp_path, variant)
    if mutation == 'scope_writer':
        old = context['report']['scope']
        new = 'This synthetic private utterance is not an approved fixed writer field.'
        data = context['script'].read_text()
        assert old in data
        context['script'].write_text(data.replace(old, new))
        context['report']['scope'] = new
    elif mutation == 'later_assignment':
        context['script'].write_text(context['script'].read_text() + '\nreport["scope"] = "altered"\n')
    elif mutation == 'codec':
        context['script'].write_bytes(b'# coding: undefined-encoding\n' + context['script'].read_bytes())
    elif mutation == 'nested_speech':
        phrase = context['report']['scope']
        context['report']['unexplained_removed'] = [{'text_private_only':phrase,
            'sha256':hashlib.sha256(phrase.encode()).hexdigest(),
            'origins':[{'schema_version':'transcript/v1','text':'Synthetic speech sibling.'}]}]
        context['report']['unexplained_removed_count'] = 1
    else:
        context['report']['transcript_files_checked'][11]['speech_fields'][0]['transcript'] = 'Synthetic unscoped speech.'
    rebound(context)
    with pytest.raises(TalkCutError):
        bound = verify(context)
        retention.retention_field(bound, context['selected']['result'], ['scope'])


@pytest.mark.parametrize('mutation', ['registered_writer', 'duplicate', 'different_parent', 'different_kind'])
def test_exact_consumer_authority_and_selector_boundaries_remain(tmp_path, mutation):
    context = consumer_fixture(tmp_path, 0)
    scope(context)
    registered = set(context['registered'].values())
    locators = [copy.deepcopy(context['locator'])]
    if mutation == 'registered_writer':
        registered.add(context['selected']['reproducer']['sha256'])
    elif mutation == 'duplicate':
        locators.append(copy.deepcopy(locators[0]))
    elif mutation == 'different_parent':
        locators[0]['parent'] = write(context['project'] / 'reports/other-parent.json', context['report'])
    else:
        locators[0]['kind'] = 'machine_inventory_field'
    with pytest.raises(TalkCutError):
        direct(context, locators, registered)


@pytest.mark.parametrize('selector', [['scope',0], ['current_inventory','scope'], ['transcript_files_checked',11,'schema_version']])
def test_only_root_scope_uses_report_source(tmp_path, selector):
    context = fixture(tmp_path)
    bound = verify(context)
    if selector == ['current_inventory','scope']:
        projection = retention.retention_field(bound, context['selected']['result'], selector)
        assert projection['source'] == context['selected']['source_snapshot']
        assert projection['source'] != bound['report_source']
    else:
        with pytest.raises(TalkCutError):
            retention.retention_field(bound, context['selected']['result'], selector)
