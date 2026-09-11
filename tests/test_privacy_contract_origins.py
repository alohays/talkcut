"""Closed synthetic construction data; no original producer is executed."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from contract_origin_fixture import (
    PHRASE,
    fixture,
    inventory,
    locator,
    observe,
    refresh,
    write,
)

from talkcut.project import TalkCutError

CONTEXTS = [('canonical', False), ('native_fixture', False), ('native_fixture', True), ('negative_run', False)]


@pytest.mark.parametrize(('recipe', 'embedded'), CONTEXTS)
def test_complete_constructor_consumer_preserves_every_parent(tmp_path, recipe, embedded):
    parts = fixture(tmp_path, recipe, embedded)
    selected = [locator(parts, index, ['criteria', criterion, 'description'])
                for index in range(len(parts['parents'])) for criterion in range(13)]
    observations = observe(parts, selected)
    assert len(observations) == len(parts['parents']) * 13
    for observation, chosen in zip(observations, selected, strict=True):
        assert observation['selected_value'] == parts['values'][selected.index(chosen) // 13]['criteria'][chosen['selector'][1]]['description']
        assert observation['claim_status'] == 'UNVERIFIED'
        assert observation['classification'] == 'review'
        assert observation['associated_row'] == parts['values'][selected.index(chosen) // 13]['criteria'][chosen['selector'][1]]
    files, _, graph = inventory(parts, selected)
    for pair in parts['parents']:
        assert files[pair['original']['sha256']] == 'review'
    assert len(graph['review_text_origins']) == len(selected)
    if recipe == 'negative_run':
        assert observations[26]['associated_row']['required'] is False
        assert parts['values'][1]['checks']['sync']['max_lip_residual_with_uncertainty_ms']['max'] == 800
        assert parts['values'][3]['unresolved_P0_P1'] == 1


@pytest.mark.parametrize('selector', [[], ['criteria'], ['criteria', True, 'description'], ['criteria', -1, 'description'],
    ['criteria', 13, 'description'], ['criteria', {}, 'description'], ['criteria', [], 'description'],
    ['criteria', 0, 'required'], ['criteria', 0, 'description', 'extra'], {'criteria': 0}])
def test_only_exact_description_leaves(tmp_path, selector):
    parts = fixture(tmp_path)
    assert observe(parts)
    with pytest.raises(TalkCutError):
        observe(parts, [locator(parts, selector=selector)])


@pytest.mark.parametrize('recipe', ['canonical', 'native_fixture', 'negative_run'])
@pytest.mark.parametrize('fault', ['description', 'required', 'id', 'reorder', 'duplicate', 'extra', 'threshold', 'top_prose'])
def test_full_original_contract_construction_is_required(tmp_path, recipe, fault):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    value = parts['values'][0]
    if fault in {'description', 'required', 'id'}:
        value['criteria'][0][fault] = {'description': 'Unverified private description text', 'required': False, 'id': 'AC99'}[fault]
    elif fault == 'reorder':
        value['criteria'].reverse()
    elif fault == 'duplicate':
        value['criteria'].append(copy.deepcopy(value['criteria'][0]))
    elif fault == 'extra':
        value['criteria'][0]['verdict'] = 'PASS'
    elif fault == 'threshold':
        value['checks']['sync']['max_lip_residual_with_uncertainty_ms']['max'] = 800
    else:
        value['notes'] = PHRASE
    refresh(parts)
    with pytest.raises(TalkCutError, match='Contract'):
        observe(parts)


@pytest.mark.parametrize(('recipe', 'role'), [('canonical', 'contracts'), ('native_fixture', 'contracts'),
    ('native_fixture', 'caller'), ('negative_run', 'contracts'), ('negative_run', 'project'), ('negative_run', 'negative')])
@pytest.mark.parametrize('guard', ['registered', 'known'])
def test_all_source_dependencies_stay_private_guarded(tmp_path, recipe, role, guard):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    ref = parts['authority']['sources'][role]['snapshot']
    if guard == 'registered':
        with pytest.raises(TalkCutError, match='Registered'):
            observe(parts, registered={ref['sha256']})
    else:
        write(parts['directory'] / 'transcripts' / 'private-dependency.txt', Path(ref['path']).read_bytes())
        with pytest.raises(TalkCutError, match='Known private'):
            inventory(parts)


@pytest.mark.parametrize(('recipe', 'role'), [('canonical', 'contracts'), ('native_fixture', 'caller'),
    ('negative_run', 'project'), ('negative_run', 'negative')])
@pytest.mark.parametrize('fault', ['rebind', 'codec'])
def test_complete_bound_module_and_decoding_are_required(tmp_path, recipe, role, fault):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    path = Path(parts['snapshots'][role]['path'])
    data = path.read_bytes()
    path.write_bytes(data + b'\nexpected_contract = None\n' if fault == 'rebind' else b'# coding: missing_codec\n' + data)
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['missing', 'extra', 'purpose', 'source_hash', 'audio_path'])
def test_native_complete_launch_field_relationship(tmp_path, fault):
    parts = fixture(tmp_path, 'native_fixture')
    assert observe(parts)
    def mutate(value):
        if fault == 'missing':
            value.pop('source_artifacts')
        elif fault == 'extra':
            value['approval'] = True
        elif fault == 'purpose':
            value['purpose'] = 'Other author text'
        elif fault == 'source_hash':
            value['dependencies']['source_hashes']['screen'] = '0' * 64
        else:
            value['audio']['path'] += '.other'
    parts['launch_mutator'] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError, match='Contract native launch'):
        observe(parts)


@pytest.mark.parametrize('fault', ['argv', 'source', 'input_path', 'pair_order', 'missing_branch', 'duplicate_artifact', 'input_prose'])
def test_negative_complete_original_branch_relationship(tmp_path, fault):
    parts = fixture(tmp_path, 'negative_run')
    assert observe(parts)
    def mutate(value):
        pair = value['cases']['threshold_tamper']['pairs'][0]
        if fault == 'argv':
            pair['control']['argv'][-1] += '.unused'
        elif fault == 'source':
            pair['control']['argv'][1] += '.unused'
        elif fault == 'input_path':
            pair['control_input']['path'] += '.other'
        elif fault == 'pair_order':
            value['cases']['threshold_tamper']['pairs'].reverse()
        elif fault == 'missing_branch':
            value['cases']['threshold_tamper']['pairs'].pop()
        elif fault == 'duplicate_artifact':
            value['artifacts'].append(copy.deepcopy(value['artifacts'][0]))
        else:
            ref = pair['control_input']
            import json
            payload = json.loads(Path(ref['path']).read_bytes())
            payload['notes'] = PHRASE
            replacement = write(Path(ref['path']), payload)
            for artifact in value['artifacts']:
                if artifact['path'] == ref['path']:
                    artifact.update(replacement)
            ref.update(replacement)
    parts['result_mutator'] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError, match='Contract'):
        observe(parts)


def test_unselected_same_phrase_transcript_and_private_copy_readd(tmp_path):
    parts = fixture(tmp_path)
    _, phrases, _ = inventory(parts)
    assert PHRASE not in phrases
    write(parts['directory'] / 'transcripts' / 'unselected.txt', PHRASE.encode())
    _, phrases, _ = inventory(parts)
    assert PHRASE in phrases


@pytest.mark.parametrize('recipe', ['canonical', 'native_fixture', 'negative_run'])
def test_parent_speech_claim_cannot_pass_template_family(tmp_path, recipe):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    parts['values'][0]['speech'] = {'schema_version': 'transcript/v1', 'text': PHRASE}
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_projection_does_not_accept_fabricated_parent_identity(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    chosen = locator(parts)
    chosen['parent'] = write(parts['folder'] / 'unbound-copy.json', Path(chosen['parent']['path']).read_bytes())
    with pytest.raises(TalkCutError):
        observe(parts, [chosen])


@pytest.mark.parametrize(('recipe', 'role'), [('canonical', 'contracts'), ('native_fixture', 'contracts'),
    ('native_fixture', 'caller'), ('negative_run', 'contracts'), ('negative_run', 'project'), ('negative_run', 'negative')])
@pytest.mark.parametrize('kind', ['review', 'transcript', 'media', 'credentials'])
def test_all_dependencies_keep_explicit_corpus_guard(tmp_path, recipe, role, kind):
    import json

    from test_privacy_checks import publication_input

    from talkcut import privacy_checks as privacy
    from talkcut.project import artifact_ref
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    raw_ref = publication_input(parts['root'], tmp_path)
    raw = json.loads(Path(raw_ref['path']).read_bytes())
    corpus_path = Path(raw['private_corpus']['path'])
    corpus = json.loads(corpus_path.read_bytes())
    corpus['file_hashes'].append({'sha256': parts['authority']['sources'][role]['snapshot']['sha256'], 'kind': kind})
    raw.update(private_corpus=write(corpus_path, corpus), review_text_origins=[locator(parts)],
               review_text_origin_authorities=[parts['authority_ref']])
    write(Path(raw_ref['path']), raw)
    with pytest.raises(TalkCutError, match='Explicit or audited private corpus bytes'):
        privacy.verify_release_privacy(artifact_ref(raw_ref['path']), parts['root'],
            project_dir=parts['directory'], expected_source_hashes=parts['registered'])


@pytest.mark.parametrize('recipe', ['canonical', 'native_fixture', 'negative_run'])
def test_final_parent_readback_detects_fired_mutation(tmp_path, recipe, monkeypatch):
    from talkcut import privacy_contract_origins as contract
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    original = contract.project_field
    fired = []
    def mutated(*args):
        result = original(*args)
        path = Path(parts['parents'][0]['original']['path'])
        path.write_bytes(path.read_bytes() + b' ')
        fired.append(True)
        return result
    monkeypatch.setattr(contract, 'project_field', mutated)
    with pytest.raises(TalkCutError):
        observe(parts)
    assert fired == [True]


def test_unselected_original_and_archived_copy_both_keep_phrase(tmp_path):
    parts = fixture(tmp_path, 'native_fixture')
    unselected = parts['parents'][1]['original']
    archived = write(parts['folder'] / 'existing-archive.json', Path(unselected['path']).read_bytes())
    write(parts['directory'] / 'checkpoint.local.json', {'parents': [pair['original'] for pair in parts['parents']], 'archive': archived})
    before, phrases_before, _ = inventory(parts, [])
    after, phrases_after, graph = inventory(parts, [locator(parts, 0)])
    assert PHRASE in phrases_before and PHRASE in phrases_after
    assert all(after[digest] == kind for digest, kind in before.items())
    assert after[archived['sha256']] == after[unselected['sha256']] == 'review'
    assert len(graph['review_text_origins']) == 1


@pytest.mark.parametrize('fault', ['recipe_list', 'sources_missing', 'parent_duplicate', 'parent_hash', 'unbound_source_path'])
def test_closed_authority_and_original_identity(tmp_path, fault):
    parts = fixture(tmp_path, 'negative_run')
    assert observe(parts)
    def mutate(value):
        if fault == 'recipe_list':
            value['recipe'] = []
        elif fault == 'sources_missing':
            value['sources'].pop('project')
        elif fault == 'parent_duplicate':
            value['parents'][1] = copy.deepcopy(value['parents'][0])
        elif fault == 'parent_hash':
            value['parents'][0]['original']['sha256'] = '0' * 64
        else:
            value['sources']['negative']['original']['path'] += '.unused'
    parts['authority_mutator'] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['cases_list', 'threshold_list', 'pairs_string', 'pair_scalar', 'artifacts_dict'])
def test_malformed_negative_record_containers_refuse(tmp_path, fault):
    parts = fixture(tmp_path, 'negative_run')
    assert observe(parts)
    def mutate(value):
        if fault == 'cases_list':
            value['cases'] = []
        elif fault == 'threshold_list':
            value['cases']['threshold_tamper'] = []
        elif fault == 'pairs_string':
            value['cases']['threshold_tamper']['pairs'] = 'Private unverified prose'
        elif fault == 'pair_scalar':
            value['cases']['threshold_tamper']['pairs'][0] = None
        else:
            value['artifacts'] = {}
    parts['result_mutator'] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)
