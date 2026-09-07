"""Actual public fixture replays preserve false claims and truthful private bytes."""
import copy
import json
import shutil
from pathlib import Path

import pytest

from talkcut.evaluator_negative import _probe_command, run_evaluator_negatives
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    init_project,
    verified_json,
)

ROOT = Path.cwd()
from talkcut import privacy_checks as privacy


@pytest.fixture(scope='module')
def actual_run(tmp_path_factory):
    directory = tmp_path_factory.mktemp('actual-public-fault-fixture')
    return run_evaluator_negatives(ROOT, directory)['result']


@pytest.fixture(scope='module')
def actual_replay(tmp_path_factory):
    directory=tmp_path_factory.mktemp('preserved-replay')/'archive'
    return privacy.prepare_synthetic_failure_replay(ROOT,directory)


def project(tmp_path):
    # Registration identity fixture; not presented as decoded media or AV evidence.
    screen, speaker = tmp_path/'screen.bin', tmp_path/'speaker.bin'
    screen.write_bytes(b'generated private registration screen identity')
    speaker.write_bytes(b'generated private registration speaker identity')
    directory = tmp_path/'private-project'
    value = init_project(directory, screen, speaker)
    return directory, {role: source['sha256'] for role, source in value['sources'].items()}


def pair_refs(run_ref):
    raw = verified_json(run_ref)
    pairs = raw['cases']['wrong_hashes']['pairs']
    a, b = verified_json(pairs[0]['control_input']), verified_json(pairs[0]['mutation_input'])
    original = json.loads((Path(a['project'])/'project.json').read_text())
    mutant = json.loads((Path(b['project'])/'project.json').read_text())
    source = mutant['sources']['screen']
    output = verified_json(pairs[1]['mutation_input'])['output']
    return [{'path':source['path'],'sha256':source['sha256']}, output], original, raw


@pytest.mark.parametrize('order', ['old_first','current_first'])
def test_actual_fault_claims_resolve_to_truthful_unclassified_entries(tmp_path,actual_run,actual_replay,order):
    directory, sources = project(tmp_path)
    stale, original, raw = pair_refs(actual_run)
    actual = [artifact_ref(ref['path']) for ref in stale]
    refs = stale+actual if order=='old_first' else actual+stale
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'references':refs})
    result = privacy.build_private_inventory(directory,sources,ROOT,synthetic_negative_runs=[actual_run],synthetic_replay=actual_replay)
    entries = {row['path']:row for row in result['entries']}
    for ref in actual+[artifact_ref(original['sources']['screen']['path']),raw['fixture']]:
        if ref['path'] in entries:
            assert entries[ref['path']]['sha256']==ref['sha256']
    for ref in actual:
        assert entries[ref['path']]['classification']=='UNCLASSIFIED'
    assert result['classification_status']=='UNVERIFIED'
    assert result['known_graph']['completeness']=='UNVERIFIED'
    rows=result['known_graph']['synthetic_failure_fixtures'][0]['rows']
    assert {row['case'] for row in rows}=={'wrong_hashes.source_bytes','wrong_hashes.output_bytes'}
    assert all(row['classification']=='UNCLASSIFIED' for row in rows)
    assert not result['unresolved']
    assert not any(row['path']==stale[0]['path'] and row['sha256']==stale[0]['sha256'] for row in result['known_graph']['known_refs'])


def test_missing_provenance_does_not_authorize_stale_reference(tmp_path,actual_run,actual_replay):
    directory,sources=project(tmp_path);stale,_,_=pair_refs(actual_run)
    # Local canonical path so ordinary strict private graph attempts the real ref.
    local=directory/'unregistered-mutant.mp4';shutil.copyfile(stale[0]['path'],local)
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'ref':{'path':str(local),'sha256':stale[0]['sha256']}})
    with pytest.raises(TalkCutError,match='registered hash'):
        privacy.build_private_inventory(directory,sources,ROOT)


def test_registered_source_digest_cannot_be_reclassified(actual_run,actual_replay):
    stale,_,_=pair_refs(actual_run)
    with pytest.raises(TalkCutError,match='Registered private source'):
        privacy._synthetic_failure_inventory([actual_run],ROOT,{stale[0]['sha256']},replay_ref=actual_replay)


def test_explicit_transcript_provenance_wins_over_mathematical_bytes(tmp_path,actual_run,actual_replay):
    directory,sources=project(tmp_path);stale,_,_=pair_refs(actual_run)
    atomic_json(directory/'checkpoint.local.json',{'schema_version':'transcript/v1','source_sha256':sources['screen'],'ref':stale[0]})
    with pytest.raises(TalkCutError,match='Private source/transcript'):
        privacy.build_private_inventory(directory,sources,ROOT,synthetic_negative_runs=[actual_run],synthetic_replay=actual_replay)


@pytest.mark.parametrize('order',['private_first','private_last'])
def test_already_private_review_digest_wins_in_both_orders(tmp_path,actual_run,actual_replay,order):
    directory,sources=project(tmp_path);stale,original,_=pair_refs(actual_run)
    private=directory/'reviews'/'private-original.mp4';private.parent.mkdir();shutil.copyfile(original['sources']['screen']['path'],private)
    refs=[artifact_ref(private),stale[0]]
    if order=='private_last':refs.reverse()
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'refs':refs})
    with pytest.raises(TalkCutError,match='Known private media/review/transcript'):
        privacy.build_private_inventory(directory,sources,ROOT,synthetic_negative_runs=[actual_run],synthetic_replay=actual_replay)


def forged_run(tmp_path,run_ref,change):
    raw=copy.deepcopy(verified_json(run_ref));change(raw)
    result=tmp_path/'result.json';atomic_json(result,raw)
    receipt=copy.deepcopy(verified_json(artifact_ref(Path(run_ref['path']).parent/'receipt.json')));receipt['result']=artifact_ref(result)
    atomic_json(tmp_path/'receipt.json',receipt)
    return artifact_ref(result)


def test_forged_attack_response_cannot_supply_expected_failure(tmp_path,actual_run,actual_replay):
    def change(raw):
        pair=raw['cases']['wrong_hashes']['pairs'][0]
        response=verified_json(pair['attack']['stdout']);response['reason']='SOURCE_CHANGED but fabricated response'
        output=tmp_path/'forged.stdout.json';atomic_json(output,response);pair['attack']['stdout']=artifact_ref(output)
    ref=forged_run(tmp_path,actual_run,change)
    with pytest.raises(TalkCutError,match='actual fixed probe replay'):
        privacy._synthetic_failure_inventory([ref],ROOT,set(),replay_ref=actual_replay)


def test_missing_supported_output_control_is_rejected(tmp_path,actual_run,actual_replay):
    ref=forged_run(tmp_path,actual_run,lambda raw:raw['cases']['wrong_hashes']['pairs'].pop())
    with pytest.raises(TalkCutError,match='Both fixed source/output'):
        privacy._synthetic_failure_inventory([ref],ROOT,set(),replay_ref=actual_replay)


def test_noncanonical_mutation_cannot_borrow_expected_source_changed(tmp_path,actual_run,actual_replay):
    def change(raw):
        pair=raw['cases']['wrong_hashes']['pairs'][0]
        data=verified_json(pair['mutation_input']);old=Path(data['project'])
        new=tmp_path/'different-mutation';new.mkdir()
        manifest=json.loads((old/'project.json').read_text())
        source=new/'changed.mp4';source.write_bytes(Path(manifest['sources']['screen']['path']).read_bytes()+b'EXTRA_UNAUTHORIZED_CHANGE')
        manifest['sources']['screen']['path']=str(source);atomic_json(new/'project.json',manifest)
        data['project']=str(new);input_file=tmp_path/'mutation.input.json';atomic_json(input_file,data)
        pair['mutation_input']=artifact_ref(input_file);pair['attack']['argv']=_probe_command('wrong_hashes',input_file,ROOT)
    ref=forged_run(tmp_path,actual_run,change)
    with pytest.raises(TalkCutError,match='Source mutation does not match'):
        privacy._synthetic_failure_inventory([ref],ROOT,set(),replay_ref=actual_replay)


def test_missing_replay_requires_preparation_without_regeneration(actual_run):
    with pytest.raises(TalkCutError,match='run preparation first'):
        privacy._synthetic_failure_inventory([actual_run],ROOT,set())


def test_preserved_replay_is_reused_and_fully_in_the_inventory(tmp_path,actual_run,actual_replay):
    directory,sources=project(tmp_path)
    archive=Path(actual_replay['path']).parent
    before={str(p):artifact_ref(p) for p in archive.rglob('*') if p.is_file()}
    first=privacy.build_private_inventory(directory,sources,ROOT,synthetic_negative_runs=[actual_run],synthetic_replay=actual_replay)
    second=privacy.build_private_inventory(directory,sources,ROOT,synthetic_negative_runs=[actual_run],synthetic_replay=actual_replay)
    after={str(p):artifact_ref(p) for p in archive.rglob('*') if p.is_file()}
    assert before==after
    entries={entry['path']:entry for entry in first['entries']}
    assert set(before)<=set(entries)
    assert all(entries[path]['sha256']==ref['sha256'] for path,ref in before.items())
    assert first['entries']==second['entries']
    replay=first['known_graph']['synthetic_failure_fixtures'][0]['current_reproduction']
    for ref in replay['external_inputs']:
        assert entries[ref['path']]['sha256']==ref['sha256']
    for link in replay['external_tool_links']:
        assert entries[link['link_path']]['entry_type']=='symlink'
        assert entries[link['link_path']]['sha256']==link['link_bytes_sha256']
    fixture=privacy._json(privacy._json(actual_replay)['fixture'])
    assert len(privacy._json(fixture['executions']))==14
    assert all(Path(ref['path']).is_file() for ref in before.values())


@pytest.mark.parametrize('damage',['missing_media','changed_media','unlisted_file','symlink','missing_log','forged_command','stale_identity','outside_evidence','external_step_stdout'])
def test_preserved_replay_rejects_tampered_artifacts(tmp_path,actual_replay,damage):
    # Use an exact backup and restore in finally; each mutation is verified in isolation.
    bundle=privacy._json(actual_replay);archive=Path(actual_replay['path']).parent
    originals={};created=[]
    def replace(path,data):
        path=Path(path);originals[path]=path.read_bytes();path.write_bytes(data)
    try:
        if damage in {'missing_media','changed_media'}:
            path=archive/'generated/synthetic.mp4';originals[path]=path.read_bytes()
            if damage=='missing_media':path.unlink()
            else:path.write_bytes(originals[path]+b'actual byte mutation')
        elif damage=='unlisted_file':
            path=archive/'unlisted.py';path.write_text('print("unlisted")');created.append(path)
        elif damage=='symlink':
            path=archive/'link';path.symlink_to(archive/'before.json');created.append(path)
        elif damage=='missing_log':
            path=Path(privacy._json(bundle['execution'])['stdout']['path']);originals[path]=path.read_bytes();path.unlink()
        else:
            if damage=='forged_command':
                path=Path(bundle['execution']['path']);data=privacy._json(bundle['execution']);data['argv'][1]='unrelated-generator.py';replace(path,json.dumps(data).encode())
                bundle['execution']=artifact_ref(path)
            elif damage=='stale_identity':
                path=Path(bundle['before']['path']);data=privacy._json(bundle['before']);data['toolchain']={};replace(path,json.dumps(data).encode())
                bundle['before']=artifact_ref(path)
            elif damage=='external_step_stdout':
                external=tmp_path/'external-step-stdout.json';external.write_text('ghp_'+'X'*40)
                fixture_path=Path(bundle['fixture']['path']);fixture=privacy._json(bundle['fixture'])
                ledger_path=Path(fixture['executions']['path']);ledger=privacy._json(fixture['executions'])
                ledger[0]['stdout']=artifact_ref(external);replace(ledger_path,json.dumps(ledger).encode())
                fixture['executions']=artifact_ref(ledger_path);replace(fixture_path,json.dumps(fixture).encode())
                bundle['fixture']=artifact_ref(fixture_path)
                bundle['artifacts']=[artifact_ref(ref['path']) if ref['path'] in {str(ledger_path),str(fixture_path)} else ref for ref in bundle['artifacts']]
                target=Path(actual_replay['path']);replace(target,json.dumps(bundle).encode())
                with pytest.raises(TalkCutError,match='artifact closure'):
                    privacy._verified_synthetic_replay(artifact_ref(target),ROOT)
                return
            else:
                path=tmp_path/'outside-before.json';path.write_bytes(Path(bundle['before']['path']).read_bytes());bundle['before']=artifact_ref(path)
                # A consistent new envelope cannot reclassify evidence outside its archive.
                target=Path(actual_replay['path']);replace(target,json.dumps(bundle).encode());ref=artifact_ref(target)
                with pytest.raises(TalkCutError):privacy._verified_synthetic_replay(ref,ROOT)
                return
            bundle['artifacts']=[artifact_ref(ref['path']) if ref['path']==str(path) else ref for ref in bundle['artifacts']]
            target=Path(actual_replay['path']);replace(target,json.dumps(bundle).encode())
        ref=artifact_ref(actual_replay['path'])
        with pytest.raises(TalkCutError):privacy._verified_synthetic_replay(ref,ROOT)
    finally:
        for path in created:path.unlink()
        for path,data in originals.items():path.write_bytes(data)


@pytest.mark.parametrize('role,suffix,size_delta,nested_external', [
    ('stdout', '.bin', 288, True),  # Original >16MiB valid-JSON attack.
    ('stdout', '.json', 288, True),
    ('stdout', '.bin', -16_000_000, True),
    ('stdout', '.bin', 0, False),
    ('stdout', '.bin', 1, False),
    ('stderr', '.bin', 0, False),
    ('stderr', '.bin', 1, False),
    ('metadata', '.bin', 0, False),
    ('metadata', '.bin', 1, False),
    ('stdout', '.mp4', 1, True),
])
def test_replay_typed_metadata_bound_does_not_depend_on_extension(
        tmp_path, actual_replay, role, suffix, size_delta, nested_external):
    bundle = privacy._json(actual_replay)
    archive = Path(actual_replay['path']).parent
    fixture_path = Path(bundle['fixture']['path'])
    fixture = privacy._json(bundle['fixture'])
    ledger_path = Path(fixture['executions']['path'])
    ledger = privacy._json(fixture['executions'])
    originals = {path: path.read_bytes() for path in (Path(actual_replay['path']), fixture_path, ledger_path)}
    payload_path = archive / ('authored-boundary-payload' + suffix)
    external = tmp_path / 'outside-private-credential.txt'
    external.write_text('ghp_' + 'Z' * 40)
    value = {'producer': {'nested_actual_ref': artifact_ref(external)}} if nested_external else {'scope': 'authored bound control'}
    data = json.dumps(value, separators=(',', ':')).encode()
    size = privacy.MAX_UNIT_BYTES + size_delta
    # Whitespace padding keeps the complete file valid JSON at the exact bound.
    assert size >= len(data)
    payload_path.write_bytes(data + b' ' * (size - len(data)))
    try:
        if role in {'stdout', 'stderr'}:
            ledger[0][role] = artifact_ref(payload_path)
            atomic_json(ledger_path, ledger)
            fixture['executions'] = artifact_ref(ledger_path)
        else:
            fixture['producer'] = artifact_ref(payload_path)
        atomic_json(fixture_path, fixture)
        bundle['fixture'] = artifact_ref(fixture_path)
        bundle['artifacts'] = [artifact_ref(ref['path']) for ref in bundle['artifacts']] + [artifact_ref(payload_path)]
        bundle['artifact_count'] = len(bundle['artifacts'])
        atomic_json(Path(actual_replay['path']), bundle)
        if size > privacy.MAX_UNIT_BYTES:
            with pytest.raises(TalkCutError, match='inspection bound'):
                privacy._verified_synthetic_replay(artifact_ref(actual_replay['path']), ROOT)
        elif nested_external:
            with pytest.raises(TalkCutError, match='artifact closure'):
                privacy._verified_synthetic_replay(artifact_ref(actual_replay['path']), ROOT)
        else:
            result = privacy._verified_synthetic_replay(artifact_ref(actual_replay['path']), ROOT)
            assert artifact_ref(payload_path) in result['artifacts']
            assert result['technical_validation']['audiovisual_review'] == 'UNVERIFIED'
    finally:
        payload_path.unlink()
        for path, data in originals.items():
            path.write_bytes(data)


@pytest.mark.parametrize('borrow_as_stdout', [False, True])
def test_replay_media_exception_cannot_override_execution_log_role(actual_replay, monkeypatch, borrow_as_stdout):
    bundle = privacy._json(actual_replay)
    archive = Path(actual_replay['path']).parent
    fixture_path = Path(bundle['fixture']['path'])
    fixture = privacy._json(bundle['fixture'])
    ledger_path = Path(fixture['executions']['path'])
    ledger = privacy._json(fixture['executions'])
    originals = {path: path.read_bytes() for path in (Path(actual_replay['path']), fixture_path, ledger_path)}
    media = artifact_ref(archive / 'generated/synthetic.mp4')
    # Keep the injected limit below the real media and above its metadata.
    # The bundle grows with checkout/basetemp paths, so a fixed small limit
    # can reject unrelated metadata before exercising the media/log roles.
    media_size = Path(media['path']).stat().st_size
    limit = media_size - 1
    assert 0 < limit < privacy.MAX_UNIT_BYTES
    assert Path(actual_replay['path']).stat().st_size <= limit
    monkeypatch.setattr(privacy, 'MAX_UNIT_BYTES', limit)
    assert media_size > privacy.MAX_UNIT_BYTES
    try:
        if borrow_as_stdout:
            ledger[0]['stdout'] = media
            atomic_json(ledger_path, ledger)
            fixture['executions'] = artifact_ref(ledger_path)
            atomic_json(fixture_path, fixture)
            bundle['fixture'] = artifact_ref(fixture_path)
            bundle['artifacts'] = [artifact_ref(ref['path']) for ref in bundle['artifacts']]
            atomic_json(Path(actual_replay['path']), bundle)
            with pytest.raises(TalkCutError, match='inspection bound'):
                privacy._verified_synthetic_replay(artifact_ref(actual_replay['path']), ROOT)
        else:
            result = privacy._verified_synthetic_replay(actual_replay, ROOT)
            assert media in result['artifacts']
            assert result['technical_validation']['status'] == 'PASS'
    finally:
        for path, data in originals.items():
            path.write_bytes(data)
