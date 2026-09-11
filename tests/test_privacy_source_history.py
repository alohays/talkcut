"""Exact private execution-source locators never approve code or review claims."""
import json
from pathlib import Path

import pytest
from test_privacy_replay import ROOT, privacy, project

from talkcut.project import TalkCutError, artifact_ref, atomic_json


def source_history(tmp_path, directory, sources, *, old_text='print("old")\n',current_text='print("current")\n'):
    canonical=directory/'capability'/'runtime'/'run.py';canonical.parent.mkdir(parents=True)
    canonical.write_text(old_text);old=artifact_ref(canonical)
    snapshot=tmp_path/'old-source.py';snapshot.write_bytes(canonical.read_bytes())
    metadata=canonical.parent/'progress.json';atomic_json(metadata,{'state':'working','source_sha256':sources['screen'],'runner':old})
    old_metadata=artifact_ref(metadata);archive=tmp_path/'old-progress';archive.write_bytes(metadata.read_bytes())
    canonical.write_text(current_text);atomic_json(metadata,{'state':'done','owner_acceptance':'pending'})
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'old_progress':old_metadata})
    return canonical,snapshot,metadata,{'original':old_metadata,'snapshot':artifact_ref(archive)},{'original':old,'snapshot':artifact_ref(snapshot),'scope':'auxiliary_execution_source'}


@pytest.mark.parametrize('edge_key',['runner','producer','toolchain','code_identity','tools_before','tools_after'])
def test_old_and_current_execution_source_stay_unclassified(tmp_path,edge_key):
    directory,sources=project(tmp_path);current,old,_,metadata,source=source_history(tmp_path,directory,sources)
    archive=Path(metadata['snapshot']['path']);body=json.loads(archive.read_text())
    body[edge_key]=body.pop('runner');atomic_json(archive,body)
    metadata['snapshot']=artifact_ref(archive);metadata['original']['sha256']=metadata['snapshot']['sha256']
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'old_progress':metadata['original']})
    result=privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])
    entries={entry['path']:entry for entry in result['entries']}
    for path in (old,current):
        assert entries[str(path)]['sha256']==artifact_ref(path)['sha256']
        assert entries[str(path)]['classification']=='UNCLASSIFIED'
    observed=result['known_graph']['auxiliary_execution_sources'][0]
    assert observed['current_ref']==artifact_ref(current) and observed['preserved_ref']==artifact_ref(old)
    assert result['classification_status']=='UNVERIFIED' and not result['unresolved']


@pytest.mark.parametrize('edge_key',['runner','producer','toolchain','code_identity','tools_before','tools_after'])
def test_explicit_metadata_locator_preserves_bytes_and_phrases_beneath_every_edge(tmp_path,edge_key):
    directory,sources=project(tmp_path);current,old,metadata_current,metadata,source=source_history(tmp_path,directory,sources)
    archive=Path(metadata['snapshot']['path']);body=json.loads(archive.read_text())
    phrase='A generated private auxiliary utterance about six violet satellites must remain protected under every edge.'
    body['utterance']=phrase;atomic_json(archive,body)
    metadata['snapshot']=artifact_ref(archive);metadata['original']['sha256']=metadata['snapshot']['sha256']
    atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],edge_key:metadata['original']})
    result=privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])
    entries={entry['path']:entry for entry in result['entries']}
    for path in (metadata_current,archive):
        assert entries[str(path)]['sha256']==artifact_ref(path)['sha256'] and entries[str(path)]['classification']=='review'
    assert {str(current),str(old)}<=set(entries)
    _,phrases,_=privacy._known_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])
    assert phrase in phrases
    scanner=privacy.Scan({},phrases);scanner.payload(phrase.encode(),'copied-private-utterance',path='pr-body.md')
    assert len(scanner.transcripts)==1 and not result['unresolved']


@pytest.mark.parametrize('damage',['missing_scope','no_metadata_edge','wrong_old_bytes','old_symlink','outside_task'])
def test_auxiliary_source_requires_exact_actual_edge_and_bytes(tmp_path,damage):
    directory,sources=project(tmp_path);current,old,_,metadata,source=source_history(tmp_path,directory,sources)
    if damage=='missing_scope':source.pop('scope')
    elif damage=='no_metadata_edge':
        data=privacy._json(metadata['snapshot']);data.pop('runner');atomic_json(metadata['snapshot']['path'],data)
        metadata['snapshot']=artifact_ref(metadata['snapshot']['path']);metadata['original']['sha256']=metadata['snapshot']['sha256']
        atomic_json(directory/'checkpoint.local.json',{'source_sha256':sources['screen'],'old_progress':metadata['original']})
    elif damage=='wrong_old_bytes':old.write_text('print("wrong")')
    elif damage=='old_symlink':
        target=tmp_path/'actual-bytes';target.write_bytes(old.read_bytes());old.unlink();old.symlink_to(target)
    else:
        source['original']['path']=str(tmp_path/'outside.py');Path(source['original']['path']).write_bytes(current.read_bytes())
    with pytest.raises(TalkCutError):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])


@pytest.mark.parametrize('schema',['multimodal-review/v1','execution-receipt/v1','measurement-result/v1','transcript/v1'])
def test_fake_runner_edge_cannot_relabel_formal_immutable_evidence(tmp_path,schema):
    directory,sources=project(tmp_path)
    body=json.dumps({'schema_version':schema,'source_sha256':sources['screen'],'value':'old'})
    _,_,_,metadata,source=source_history(tmp_path,directory,sources,old_text=body)
    with pytest.raises(TalkCutError,match='Immutable source/transcript/review/measurement/render'):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])


def test_registered_media_sha_renamed_py_cannot_become_execution_source(tmp_path):
    directory,sources=project(tmp_path)
    # These exact private registration bytes deliberately do not become Python just by naming them .py.
    data=privacy._json(artifact_ref(directory/'project.json'))
    original=Path(data['sources']['screen']['path']).read_text()
    _,_,_,metadata,source=source_history(tmp_path,directory,sources,old_text=original)
    with pytest.raises(TalkCutError,match='Registered media/source'):
        privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])


def test_runtime_source_has_no_credential_transcript_or_private_path_scan_exemption(tmp_path):
    directory,sources=project(tmp_path)
    phrase='A generated private transcript phrase about seven turquoise stars must still be caught in copied code.'
    # Synthetic token only, deliberately matched by the same publication credential scanner.
    token='ghp_'+'X'*40
    body=f'credential = "{token}"\ntranscript = "{phrase}"\n'
    current,old,_,metadata,source=source_history(tmp_path,directory,sources,old_text=body)
    result=privacy.build_private_inventory(directory,sources,ROOT,auxiliary_metadata_history=[metadata],source_snapshots=[source])
    assert {entry['path'] for entry in result['entries']} >= {str(old),str(current)}
    scanner=privacy.Scan({},[phrase]);scanner.payload(old.read_bytes(),'actual-copied-source',path='runner.py')
    assert scanner.credentials and scanner.transcripts
    scanner.payload(current.read_bytes(),'actual-private-member',path='projects/private-task/runner.py')
    assert scanner.unknown
