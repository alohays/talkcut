"""Bounded acceptance source/row/copy controls using real synthetic files."""
from __future__ import annotations

import hashlib
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


@pytest.mark.parametrize('mode', ['checkpoint', 'python', 'uv'])
def test_original_forms_keep_full_parent_private_and_unverified(tmp_path, mode):
    parts = fixture(tmp_path, mode)
    original = Path(parts['stdout']['path']).read_bytes()
    observed = observe(parts)[0]
    assert observed['selected_value'] == PHRASE
    assert observed['associated_row'] == parts['report']['criteria'][0]
    assert observed['extractions'] == [{'edge': ['criteria', 0, 'description'], 'value': PHRASE}]
    assert observed['claim_status'] == 'UNVERIFIED' and observed['classification'] == 'review'
    assert Path(parts['stdout']['path']).read_bytes() == original
    if mode == 'checkpoint':
        saved = observe(parts, saved=True)[0]
        assert saved['associated_row'] == observed['associated_row']
        assert saved['parent'] != observed['parent']
        assert not Path(parts['selected']['saved_copies'][0]['original']['path']).exists()


@pytest.mark.parametrize('selector', [
    ['criteria', 0, 'checks', 1, 'reason'], ['criteria', 2, 'checks', 0, 'reason'],
    ['criteria', 3, 'checks', 0, 'reason'], ['criteria', 7, 'checks', 0, 'reason'],
    ['criteria', 11, 'checks', 0, 'reason'], ['criteria', 12, 'checks', 0, 'reason'], ['provenance_limitations'],
])
def test_source_called_writer_recipes(tmp_path, selector):
    parts = fixture(tmp_path)
    result = observe(parts, selector)[0]
    assert result['selector'] == selector and result['claim_status'] == 'UNVERIFIED'
    assert result['extractions'] == [{'edge': selector, 'value': result['selected_value']}]


@pytest.mark.parametrize('selector', [None, [], [{}], [[]], [True], ['criteria', -1, 'description'],
                                     ['criteria', 99, 'description'], ['criteria', 0], ['status'], ['open_findings']])
def test_invalid_or_unowned_selectors_refuse(tmp_path, selector):
    parts = fixture(tmp_path)
    assert observe(parts)
    selected = locator(parts);selected['selector'] = selector
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory([selected], parts['directory'], parts['root'],
                                             set(parts['registered'].values()), [parts['authority']])


@pytest.mark.parametrize('role,addition', [
    ('src/talkcut/acceptance.py', '\nEvaluator = None\n'),
    ('src/talkcut/acceptance.py', '\nraise RuntimeError("synthetic interruption")\n'),
    ('src/talkcut/__main__.py', '\nexecute = None\n'),
    ('src/talkcut/contracts.py', '\nCRITERIA = {}\n'),
    ('src/talkcut/project.py', '\natomic_json = None\n'),
    ('src/talkcut/__init__.py', '\nfrom . import acceptance\nacceptance.Evaluator = None\n'),
])
def test_original_source_module_binding_cannot_be_rebound(tmp_path, role, addition):
    parts = fixture(tmp_path)
    assert observe(parts)
    source = Path(parts['sources'][role]['path']);source.write_text(source.read_text() + addition)
    refresh(parts)
    with pytest.raises(TalkCutError, match='complete original source module'):
        observe(parts)


@pytest.mark.parametrize('coding', ['talkcut_missing_codec', 'utf-16'])
def test_loader_codec_refusal(tmp_path, coding):
    parts = fixture(tmp_path)
    assert observe(parts)
    source = Path(parts['sources']['src/talkcut/acceptance.py']['path'])
    source.write_bytes(('# coding: ' + coding + '\n').encode() + source.read_bytes())
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_bom_original_source_shape_is_supported(tmp_path):
    parts = fixture(tmp_path)
    source = Path(parts['sources']['src/talkcut/acceptance.py']['path'])
    source.write_bytes(b'\xef\xbb\xbf' + source.read_bytes());refresh(parts)
    assert observe(parts)


def test_console_entrypoint_must_select_the_original_cli(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    source = Path(parts['sources']['pyproject.toml']['path'])
    source.write_text(source.read_text().replace('talkcut.__main__:main', 'talkcut.acceptance:evaluate'))
    refresh(parts)
    with pytest.raises(TalkCutError, match='console entry point'):
        observe(parts)


@pytest.mark.parametrize('fault', ['extra_source', 'missing_source', 'unused_source', 'stale_map'])
def test_complete_source_map_and_selected_roles(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    if fault == 'extra_source':
        parts['sources']['src/talkcut/extra.py'] = write(parts['root'] / 'src/talkcut/extra.py', b'value = 1\n')
    elif fault == 'missing_source':
        del parts['sources']['src/talkcut/project.py']
    elif fault == 'unused_source':
        parts['sources']['src/talkcut/acceptance.py'] = parts['sources']['src/talkcut/contracts.py']
    else:
        parts['authority_mutator'] = lambda root: root['sources'].__setitem__('src/talkcut/acceptance.py', parts['sources']['src/talkcut/contracts.py'])
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['unlocked', 'another_subcommand', 'extra_argument', 'another_root', 'another_project'])
def test_exact_original_command_selection(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    def change(command):
        if fault == 'unlocked':
            command['argv'].remove('--locked')
        elif fault == 'another_subcommand':
            command['argv'][5] = 'freeze'
        elif fault == 'extra_argument':
            command['argv'].append('--test-only')
        elif fault == 'another_root':
            command['cwd'] = str(tmp_path)
        else:
            command['argv'][6] = str(tmp_path)
    parts['command_mutator'] = change;refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['wrong_id', 'extra_row_key', 'different_reason', 'prose_status', 'verdict_flag', 'prose_container'])
def test_selected_and_complete_row_shape(tmp_path, fault):
    parts = fixture(tmp_path)
    selector = ['criteria', 2, 'checks', 0, 'reason']
    assert observe(parts, selector)
    report = parts['report'];check = report['criteria'][2]['checks'][0]
    if fault == 'wrong_id':
        check['check_id'] = 'unrelated_private_review'
    elif fault == 'extra_row_key':
        check['private_prose'] = check['reason']
    elif fault == 'different_reason':
        check['reason'] = 'Unrelated authored private prose must remain protected.'
    elif fault == 'prose_status':
        check['status'] = {'private_prose': check['reason']}
    elif fault == 'verdict_flag':
        report['goal_achieved'] = True
    else:
        report['open_findings'] = 'Synthetic prose is not a list from the original output.'
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts, selector)


@pytest.mark.parametrize('fault', ['changed_snapshot', 'wrong_destination', 'duplicate_pair'])
def test_saved_copy_requires_complete_canonical_original_relationship(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts, saved=True)
    if fault == 'changed_snapshot':
        parts['saved_path'].write_bytes(parts['saved_path'].read_bytes() + b' ')
        selected = parts['selected'];selected['saved_copies'][0]['snapshot'] = artifact_ref(parts['saved_path'])
    else:
        selected = parts['selected']
        if fault == 'wrong_destination':
            selected['saved_copies'][0]['original']['path'] = str(parts['directory'] / 'transcripts/forged.json')
            command = json.loads(Path(parts['command']['path']).read_bytes());command['current_report'] = selected['saved_copies'][0]['original']
            selected['command'] = write(Path(parts['command']['path']), command)
        else:
            selected['saved_copies'].append(selected['saved_copies'][0])
    parts['authority'] = write(Path(parts['authority']['path']), selected)
    with pytest.raises(TalkCutError):
        observe(parts, saved=True)


@pytest.mark.parametrize('location', ['root', 'row', 'outside_selector'])
def test_generic_transcript_context_is_never_scoped(tmp_path, location):
    parts = fixture(tmp_path)
    assert observe(parts)
    transcript = {'schema_version': 'transcript/v1', 'source_sha256': next(iter(parts['registered'].values())), 'text': PHRASE}
    if location == 'root':
        parts['report']['schema_version'] = 'transcript/v1'
    elif location == 'row':
        parts['report']['criteria'][0]['checks'][0]['measurements'] = transcript
    else:
        parts['report']['invalid_evidence'].append(transcript)
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_final_source_mutation_is_detected(tmp_path, monkeypatch):
    parts = fixture(tmp_path)
    assert observe(parts)
    target = Path(parts['sources']['src/talkcut/acceptance.py']['path']);original = Path.read_bytes;fired = []
    def read(path):
        data = original(path)
        if path == target and not fired:
            fired.append(str(path));path.write_bytes(data + b'\n')
        return data
    monkeypatch.setattr(Path, 'read_bytes', read)
    with pytest.raises(TalkCutError, match='bytes or identity changed'):
        observe(parts)
    assert fired == [str(target)]


def test_real_private_inventory_preserves_parent_and_all_unselected_phrases(tmp_path):
    parts = fixture(tmp_path, 'python')
    before = Path(parts['stdout']['path']).read_bytes()
    parts['report']['invalid_evidence'].append({'reason': PHRASE});refresh(parts)
    known, phrases, graph = inventory(parts)
    assert PHRASE in phrases and known[parts['stdout']['sha256']] == 'review'
    assert graph['review_text_origins'][0]['claim_status'] == 'UNVERIFIED'
    assert graph['review_text_origins'][0]['extractions'] == [{'edge': ['criteria', 0, 'description'], 'value': PHRASE}]
    assert Path(parts['stdout']['path']).read_bytes() != before
    current = Path(parts['stdout']['path']).read_bytes()
    result = privacy.build_private_inventory(parts['directory'], parts['registered'], parts['root'],
        review_text_origins=[locator(parts)], review_text_origin_authorities=[parts['authority']], archive_dir=tmp_path / 'archive')
    saved = result['preserved_private_inputs'][parts['stdout']['path']]
    assert Path(saved['path']).read_bytes() == current
    assert hashlib.sha256(current).hexdigest() == saved['sha256']


@pytest.mark.parametrize('role', ['project', 'scripts'])
def test_malformed_console_tables_are_structured_refusals(tmp_path, role):
    parts = fixture(tmp_path)
    assert observe(parts)
    path = Path(parts['sources']['pyproject.toml']['path'])
    path.write_text('project = "synthetic malformed table"\n' if role == 'project' else '[project]\nscripts = "synthetic malformed table"\n')
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('field', ['original', 'snapshot'])
@pytest.mark.parametrize('value', ['invalid-ref', {}, {'path': [], 'sha256': 'a' * 64}])
def test_malformed_saved_refs_are_structured_refusals(tmp_path, field, value):
    parts = fixture(tmp_path)
    assert observe(parts, saved=True)
    selected = parts['selected'];selected['saved_copies'][0][field] = value
    if field == 'original':
        command = json.loads(Path(parts['command']['path']).read_bytes());command['current_report'] = value
        selected['command'] = write(Path(parts['command']['path']), command)
    parts['authority'] = write(Path(parts['authority']['path']), selected)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('field,value', [('status', 'PASS'), ('wall_seconds', 'private prose'), ('timeout_seconds', -1)])
def test_recorded_command_container_and_result_shape(tmp_path, field, value):
    parts = fixture(tmp_path, 'python')
    assert observe(parts)
    parts['command_mutator'] = lambda command: command.__setitem__(field, value)
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


def test_all_exact_copy_leaves_scope_only_their_occurrences(tmp_path):
    parts = fixture(tmp_path)
    old_known, old_phrases, _ = inventory(parts, [])
    selected = [locator(parts), locator(parts, saved=True)]
    known, phrases, graph = inventory(parts, selected)
    assert PHRASE in old_phrases and PHRASE not in phrases
    assert all(known[digest] == kind for digest, kind in old_known.items())
    assert known[parts['stdout']['sha256']] == known[artifact_ref(parts['saved_path'])['sha256']] == 'review'
    assert len(graph['review_text_origins']) == 2
    assert parts['report']['goal_achieved'] is False and parts['report']['release_ready'] is False
    assert len(parts['report']['criteria']) == 13


@pytest.mark.parametrize('kind', ['review', 'transcript'])
def test_identical_phrase_from_other_real_private_origin_remains_protected(tmp_path, kind):
    parts = fixture(tmp_path, 'python')
    directory = parts['directory'];path = directory / ('transcripts' if kind == 'transcript' else 'evidence') / 'unselected.json'
    write(path, {'schema_version': 'transcript/v1' if kind == 'transcript' else 'private-review/v1',
                 'source_sha256': next(iter(parts['registered'].values())), 'text': PHRASE})
    known, phrases, _ = inventory(parts)
    assert PHRASE in phrases and known[artifact_ref(path)['sha256']] in {'review', 'transcript'}
    scan = privacy.Scan({}, phrases);scan.payload(PHRASE.encode(), 'synthetic-public-phrase-body')
    assert any(row['kind'] == 'protected_transcript_phrase' for row in scan.findings)


@pytest.mark.parametrize('target', ['source', 'parent'])
def test_registered_private_digest_cannot_supply_origin_authority(tmp_path, target):
    parts = fixture(tmp_path)
    assert observe(parts)
    ref = parts['sources']['src/talkcut/acceptance.py'] if target == 'source' else parts['stdout']
    registered = set(parts['registered'].values()) | {ref['sha256']}
    with pytest.raises(TalkCutError):
        privacy._review_text_origin_inventory([locator(parts)], parts['directory'], parts['root'], registered, [parts['authority']])


def test_verified_copy_in_actual_transcript_namespace_still_refuses(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts, saved=True)
    destination = parts['directory'] / 'transcripts' / 'saved-copy.json'
    snapshot = write(destination, parts['saved_path'].read_bytes())
    selected = parts['selected'];selected['saved_copies'][0]['snapshot'] = snapshot
    parts['authority'] = write(Path(parts['authority']['path']), selected)
    parts['saved_path'] = destination
    with pytest.raises(TalkCutError, match='namespaces'):
        observe(parts, saved=True)


def test_generic_external_parent_cannot_use_the_saved_copy_scope(tmp_path):
    parts = fixture(tmp_path)
    assert observe(parts)
    other = write(tmp_path / 'unbound-report.json', Path(parts['stdout']['path']).read_bytes())
    item = locator(parts);item['parent'] = other
    with pytest.raises(TalkCutError, match='original output relation'):
        privacy._review_text_origin_inventory([item], parts['directory'], parts['root'], set(parts['registered'].values()), [parts['authority']])
