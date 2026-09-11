"""Auxiliary bytes enter privacy inventory without certifying their claims."""
import json

import pytest
from test_privacy_replay import ROOT, privacy, project

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def history(tmp_path, directory, sources, *, schema=None):
    canonical=directory/'capability'/'another-provider'/'progress.json'
    canonical.parent.mkdir(parents=True)
    child=directory/'evidence'/'old-only.json';child.parent.mkdir()
    atomic_json(child,{'source_sha256':sources['screen'],'private_metadata':'Old preserved runtime child metadata.'})
    phrase='This is a generated private auxiliary observation sentence about three violet stars and a blue moon.'
    old={'state':'working','source_sha256':sources['screen'],'private_note':phrase,'child':artifact_ref(child)}
    if schema:old['schema_version']=schema
    atomic_json(canonical,old);expected=artifact_ref(canonical)
    preserved=tmp_path/'actual-old-bytes';preserved.write_bytes(canonical.read_bytes())
    current={'state':'done','source_sha256':sources['screen'],'owner_acceptance':'pending'}
    if schema:current['schema_version']=schema
    atomic_json(canonical,current)
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'old_metadata':expected})
    return canonical, preserved, child, phrase, {'original':expected,'snapshot':artifact_ref(preserved)}


@pytest.mark.parametrize('schema',[None,'external-runtime-progress/v1'])
def test_all_actual_old_current_bytes_private_but_claim_unverified(tmp_path,schema):
    directory,sources=project(tmp_path)
    canonical,preserved,child,phrase,locator=history(tmp_path,directory,sources,schema=schema)
    result=privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[locator])
    entries={row['path']:row for row in result['entries']}
    for path in (canonical,preserved,child):
        assert entries[str(path)]['sha256']==artifact_ref(path)['sha256']
        assert entries[str(path)]['classification']=='review'
    assert not result['unresolved']
    assert result['classification_status']=='UNVERIFIED'
    observation=result['known_graph']['auxiliary_metadata_history'][0]
    assert observation['bytes_status']=='OBSERVED' and observation['claim_status']=='UNVERIFIED'
    assert observation['preserved_ref']==artifact_ref(preserved)
    known,phrases,graph=privacy._known_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[locator])
    assert all(artifact_ref(p)['sha256'] in known for p in (canonical,preserved,child))
    assert phrase in phrases
    assert not graph['historical_unresolved']


@pytest.mark.parametrize('damage',['missing_snapshot','wrong_bytes','symlink','no_locator','changed_child'])
def test_missing_or_changed_recursive_bytes_never_become_resolved(tmp_path,damage):
    directory,sources=project(tmp_path);_,snapshot,child,_,locator=history(tmp_path,directory,sources)
    locators=[locator]
    if damage=='missing_snapshot':snapshot.unlink()
    elif damage=='wrong_bytes':snapshot.write_text('{}')
    elif damage=='symlink':
        target=tmp_path/'separate-old';target.write_bytes(snapshot.read_bytes());snapshot.unlink();snapshot.symlink_to(target)
    elif damage=='no_locator':locators=[]
    else:atomic_json(child,{'changed':'actual immutable child changed'})
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=locators)


@pytest.mark.parametrize('schema',['source-inspection/v1','render/v1','workflow-render/v1','review-import/v1','multimodal-review/v1','execution-receipt/v1','measurement-result/v1','artifact-audit/v1','transcript/v1'])
def test_formal_immutable_evidence_never_uses_auxiliary_history(tmp_path,schema):
    directory,sources=project(tmp_path);_,_,_,_,locator=history(tmp_path,directory,sources,schema=schema)
    with pytest.raises(TalkCutError,match='Immutable source/transcript/review/measurement/render'):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[locator])


def test_non_json_media_history_is_strict(tmp_path):
    directory,sources=project(tmp_path)
    media=directory/'capability'/'changed.mp4';media.parent.mkdir();media.write_bytes(b'old synthetic binary payload')
    old=artifact_ref(media);snapshot=tmp_path/'old-binary';snapshot.write_bytes(media.read_bytes());media.write_bytes(b'new synthetic binary payload')
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'binary':old})
    with pytest.raises(TalkCutError,match='registered hash|bounded JSON'):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[{'original':old,'snapshot':artifact_ref(snapshot)}])


def test_registered_transcript_nested_in_auxiliary_container_remains_immutable(tmp_path):
    directory,sources=project(tmp_path);_canonical,snapshot,_,_,locator=history(tmp_path,directory,sources)
    old=json.loads(snapshot.read_text());old['transcript']={'schema_version':'transcript/v1','source_sha256':sources['screen'],'text':'A generated source-bound private transcript must remain protected.'}
    atomic_json(snapshot,old);locator['snapshot']=artifact_ref(snapshot);locator['original']['sha256']=locator['snapshot']['sha256']
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'old_metadata':locator['original']})
    with pytest.raises(TalkCutError,match='Immutable source/transcript/review/measurement/render'):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[locator])


@pytest.mark.parametrize('schema',['multimodal-review/v1','execution-receipt/v1','measurement-result/v1'])
def test_nested_formal_immutable_claim_cannot_be_wrapped_as_auxiliary(tmp_path,schema):
    directory,sources=project(tmp_path)
    _current,snapshot,_,_,locator=history(tmp_path,directory,sources)
    old=json.loads(snapshot.read_text())
    old['wrapper']=[{'schema_version':schema,'claim':'preserved immutable evidence'}]
    atomic_json(snapshot,old)
    locator['snapshot']=artifact_ref(snapshot);locator['original']['sha256']=locator['snapshot']['sha256']
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'old_metadata':locator['original']})
    with pytest.raises(TalkCutError,match='Immutable source/transcript/review/measurement/render'):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[locator])
