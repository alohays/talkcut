"""Complete source-data rows and private occurrence boundaries."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
from report_data_origin_fixture import (
    PHRASE,
    coverage_value,
    fixture,
    inventory,
    locator,
    observe,
    refresh,
    write,
)

from talkcut.project import TalkCutError


@pytest.mark.parametrize('serialization',['pretty_json_lf','canonical_json_lf'])
@pytest.mark.parametrize('archived',[False,True])
def test_exact_physical_original_or_snapshot_data_retains_private_parents(tmp_path,serialization,archived):
    parts=fixture(tmp_path,serialization,archived=archived)
    selected=[locator(parts,selector=['criteria',0,'description']),locator(parts,selector=['criteria',2,'checks',0,'reason']),
              locator(parts,selector=['provenance_limitations'])]
    observations=observe(parts,selected)
    assert len(observations)==3 and all(row['claim_status']=='UNVERIFIED' for row in observations)
    assert all('invocation' in row['scope'] for row in observations)
    assert observations[0]['selected_value']==PHRASE
    assert len(observations[0]['source_dependencies'])==6
    known,_,graph=inventory(parts,selected)
    assert known[parts['parents'][0]['original']['sha256']]=='review'
    assert len(graph['review_text_origins'])==3
    assert observe(parts,[locator(parts,original=True)])[0]['parent']==parts['parents'][0]['original']


@pytest.mark.parametrize('fault',['pass_reason','error_measurements','check_duplicate','check_missing','check_order','criterion_status',
    'criterion_evidence','finding_count','release_flag','provenance','coverage_projection','release_return'])
def test_complete_report_constructor_rejects_inconsistent_unselected_rows(tmp_path,fault):
    parts=fixture(tmp_path);assert observe(parts)
    report=parts['reports'][0]
    check=report['criteria'][1]['checks'][0]
    if fault=='pass_reason':check.update(status='PASS',reason='This reason is not the fixed successful check constructor')
    elif fault=='error_measurements':check['measurements']={'private':'Unwritten on this caught error route'}
    elif fault=='check_duplicate':report['criteria'][2]['checks'].append(copy.deepcopy(report['criteria'][2]['checks'][0]))
    elif fault=='check_missing':report['criteria'][2]['checks'].pop()
    elif fault=='check_order':report['criteria'][2]['checks'].reverse()
    elif fault=='criterion_status':report['criteria'][2]['status']='PASS'
    elif fault=='criterion_evidence':report['criteria'][2]['evidence_refs']=[{'private':'Unwritten criterion evidence'}]
    elif fault=='finding_count':report['criteria'][8]['checks'][1]['measurements']['count']=1
    elif fault=='release_flag':report['release_ready']=True
    elif fault=='provenance':report['provenance_limitations']='Unverified private prose in a fixed field'
    elif fault=='coverage_projection':report['coverage']={'metric':{'uncovered_intervals':[[0,1]]}}
    else:report['code_release_evidence']={'private':'Not returned by this failed release check'}
    refresh(parts)
    with pytest.raises(TalkCutError):observe(parts)


def late_fixture(tmp_path):
    parts=fixture(tmp_path);report=parts['reports'][0];row=report['criteria'][8]
    row['checks'][0].update(status='PASS',reason='Verified from current artifacts',measurements={})
    row['checks'].append({'check_id':'G0_G5_dependencies','status':'UNVERIFIED',
      'reason':'Final master requires all preceding media gates','measurements':None})
    refresh(parts);assert observe(parts)
    return parts


@pytest.mark.parametrize('fault',['missing','duplicate','status','reason','measurements','unneeded','aggregate'])
def test_exact_late_dependency_branch(tmp_path,fault):
    parts=late_fixture(tmp_path);row=parts['reports'][0]['criteria'][8]
    if fault=='missing':row['checks'].pop()
    elif fault=='duplicate':row['checks'].append(copy.deepcopy(row['checks'][-1]))
    elif fault in {'status','reason','measurements'}:row['checks'][-1][fault]={'status':'PASS','reason':'Private substitute','measurements':{}}[fault]
    elif fault=='unneeded':row['checks'][0].update(status='UNVERIFIED',reason='Required hashed artifact reference is missing',measurements=None)
    else:row['status']='PASS'
    refresh(parts)
    with pytest.raises(TalkCutError):observe(parts)


def test_visible_coverage_and_release_return_positive(tmp_path):
    parts=fixture(tmp_path);report=parts['reports'][0]
    report['coverage']={'output_audio':coverage_value([[0,1]]),'output_video':coverage_value([])}
    report['uncovered_intervals']=[{'metric':'output_audio','intervals':[['0','1']]}]
    value={'private':'Preserved opaque callback return'}
    report['criteria'][12]['checks'][0].update(status='PASS',reason='Verified from current artifacts',measurements=value)
    report['criteria'][12]['status']='PASS';report['code_release_evidence']=copy.deepcopy(value)
    refresh(parts);assert observe(parts)


@pytest.mark.parametrize('serialization', ['pretty_json_lf', 'canonical_json_lf'])
def test_coverage_projection_preserves_array_order_across_object_serialization(tmp_path, serialization):
    parts = fixture(tmp_path, serialization)
    report = parts['reports'][0]
    report['coverage'] = {'output_audio': coverage_value([[0, 1]]),
                          'output_video': coverage_value([]),
                          'deleted_source': coverage_value([[2, 3]])}
    report['uncovered_intervals'] = [{'metric': key, 'intervals': value['uncovered_intervals']}
                                     for key, value in report['coverage'].items() if value['uncovered_intervals']]
    refresh(parts)
    assert observe(parts)


@pytest.mark.parametrize('role',['src/talkcut/acceptance.py','src/talkcut/contracts.py','src/talkcut/project.py',
 'src/talkcut/__main__.py','src/talkcut/__init__.py','pyproject.toml'])
@pytest.mark.parametrize('guard',['registered','known'])
def test_every_bound_source_dependency_keeps_private_guard(tmp_path,role,guard):
    parts=fixture(tmp_path);assert observe(parts)
    ref=parts['sources'][role]
    if guard=='registered':
        with pytest.raises(TalkCutError,match='Registered'):observe(parts,registered={ref['sha256']})
    else:
        write(parts['directory']/'transcripts/private-source.txt',Path(ref['path']).read_bytes())
        with pytest.raises(TalkCutError,match='Known private'):inventory(parts)


@pytest.mark.parametrize('fault',['parent_hash','map_hash','revision','missing_member','duplicate_member','wrong_case','missing_source','other_profile'])
def test_original_parent_and_entire_map_authority(tmp_path,fault):
    parts=fixture(tmp_path);assert observe(parts)
    if fault=='missing_source':
        parts['data_authority_mutator']=lambda root:root['sources'].pop('src/talkcut/project.py')
    elif fault=='other_profile':
        Path(parts['sources']['src/talkcut/acceptance.py']['path']).write_bytes((Path(__file__).parent/'fixtures/acceptance-evaluator-b.py.txt').read_bytes())
    else:
        def mutate(root):
            case=root['cases'][0]
            if fault=='parent_hash':case['parent']['sha256']='0'*64
            elif fault=='map_hash':case['members'][0]['expected_sha256']='0'*64
            elif fault=='revision':case['revision']='0'*40
            elif fault=='missing_member':case['members'].pop()
            elif fault=='duplicate_member':case['members'].append(copy.deepcopy(case['members'][0]))
            else:case['parent']['path']+='-other'
        parts['map_mutator']=mutate
    refresh(parts)
    with pytest.raises(TalkCutError):observe(parts)


@pytest.mark.parametrize('selector',[[],['criteria',True,'description'],['criteria',-1,'description'],['criteria',{},'description'],
 ['criteria',0],['criteria',0,'status'],['criteria',2,'checks',0],['criteria',2,'checks',0,'measurements']])
def test_exact_leaf_only(tmp_path,selector):
    parts=fixture(tmp_path);assert observe(parts)
    with pytest.raises(TalkCutError):observe(parts,[locator(parts,selector=selector)])


def test_unselected_original_and_archive_occurrences_remain_private(tmp_path):
    parts=fixture(tmp_path,count=2,archived=True)
    write(parts['directory']/'checkpoint.local.json',{'parents':[p['original'] for p in parts['parents']],
       'old_archive':parts['parents'][1]['snapshot']})
    before,phrases,_=inventory(parts,[]);assert PHRASE in phrases
    after,phrases,graph=inventory(parts,[locator(parts,0)])
    assert PHRASE in phrases and all(after[d]==k for d,k in before.items())
    assert len(graph['review_text_origins'])==1


@pytest.mark.parametrize('role', ['src/talkcut/acceptance.py', 'src/talkcut/contracts.py', 'src/talkcut/project.py',
    'src/talkcut/__main__.py', 'src/talkcut/__init__.py', 'pyproject.toml'])
@pytest.mark.parametrize('kind', ['review', 'transcript', 'media', 'credentials'])
def test_every_dependency_keeps_explicit_corpus_guard(tmp_path, role, kind):
    import json

    from test_privacy_checks import publication_input

    from talkcut import privacy_checks as privacy
    from talkcut.project import artifact_ref
    parts = fixture(tmp_path)
    assert observe(parts)
    raw_ref = publication_input(parts['root'], tmp_path)
    raw = json.loads(Path(raw_ref['path']).read_bytes())
    corpus_path = Path(raw['private_corpus']['path'])
    corpus = json.loads(corpus_path.read_bytes())
    corpus['file_hashes'].append({'sha256': parts['sources'][role]['sha256'], 'kind': kind})
    raw.update(private_corpus=write(corpus_path, corpus), review_text_origins=[locator(parts)],
               review_text_origin_authorities=[parts['data_authority_ref']])
    write(Path(raw_ref['path']), raw)
    with pytest.raises(TalkCutError, match='Explicit or audited private corpus bytes'):
        privacy.verify_release_privacy(artifact_ref(raw_ref['path']), parts['root'],
            project_dir=parts['directory'], expected_source_hashes=parts['registered'])


@pytest.mark.parametrize('target', ['parent', 'authority', 'source_map', 'source'])
def test_final_closure_refuses_fired_mutation(tmp_path, target, monkeypatch):
    from talkcut import privacy_report_data_origins as report_data
    parts = fixture(tmp_path)
    assert observe(parts)
    original = report_data.project_field
    fired = []
    ref = {'parent': parts['parents'][0]['original'], 'authority': parts['data_authority_ref'],
           'source_map': parts['data_authority']['source_maps'],
           'source': parts['sources']['src/talkcut/contracts.py']}[target]
    def mutated(*args):
        result = original(*args)
        path = Path(ref['path'])
        path.write_bytes(path.read_bytes() + b' ')
        fired.append(True)
        return result
    monkeypatch.setattr(report_data, 'project_field', mutated)
    with pytest.raises(TalkCutError):
        observe(parts)
    assert fired == [True]


@pytest.mark.parametrize('location', ['root', 'row', 'check', 'other_row'])
def test_speech_markers_in_complete_parent_still_refuse(tmp_path, location):
    parts = fixture(tmp_path)
    assert observe(parts)
    report = parts['reports'][0]
    target = {'root': report, 'row': report['criteria'][0], 'check': report['criteria'][0]['checks'][0],
              'other_row': report['criteria'][1]}[location]
    target['schema_version'] = 'transcript/v1'
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['duplicate', 'missing', 'extra', 'wrong_value', 'wrong_type', 'extra_key'])
def test_canonical_coverage_preserves_complete_unique_projection(tmp_path, fault):
    parts = fixture(tmp_path, 'canonical_json_lf')
    report = parts['reports'][0]
    report['coverage'] = {'output_audio': coverage_value([[0, 1]])}
    report['uncovered_intervals'] = [{'metric': 'output_audio', 'intervals': [['0', '1']]}]
    refresh(parts)
    assert observe(parts)
    rows = report['uncovered_intervals']
    if fault == 'duplicate': rows.append(copy.deepcopy(rows[0]))
    elif fault == 'missing': rows.clear()
    elif fault == 'extra': rows.append({'metric': 'other', 'intervals': [[0, 1]]})
    elif fault == 'wrong_value': rows[0]['intervals'] = [[0, 2]]
    elif fault == 'wrong_type': rows[0]['metric'] = []
    else: rows[0]['private_prose'] = PHRASE
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('serialization', ['pretty_json_lf', 'canonical_json_lf'])
@pytest.mark.parametrize('fault', ['array_order', 'metric_gap', 'unknown_metric'])
def test_coverage_source_order_cannot_be_replaced_by_set_equivalence(tmp_path, serialization, fault):
    parts = fixture(tmp_path, serialization)
    report = parts['reports'][0]
    report['coverage'] = {'output_audio': coverage_value([[0, 1]]),
                          'output_video': coverage_value([[2, 3]])}
    report['uncovered_intervals'] = [{'metric': key, 'intervals': value['uncovered_intervals']}
                                     for key, value in report['coverage'].items()]
    refresh(parts)
    assert observe(parts)
    if fault == 'array_order': report['uncovered_intervals'].reverse()
    elif fault == 'metric_gap': report['coverage'].pop('output_audio')
    else: report['coverage']['private_metric'] = None
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['positive', 'different_return', 'missing_late_metric'])
def test_successful_coverage_return_matches_entire_recorded_coverage(tmp_path, fault):
    parts = fixture(tmp_path)
    report = parts['reports'][0]
    value = {'denominator_seconds': '0', 'numerator_seconds': '0', 'fraction': None,
             'not_applicable': True, 'uncovered_intervals': []}
    report['coverage'] = {key: copy.deepcopy(value) for key in
                         ('output_audio', 'output_video', 'deleted_source', 'source_analysis')}
    report['coverage'].update(observed_frame_count=0, observed_frame_count_unknown_runs=0,
        deletion_count={'denominator': 0, 'numerator': 0, 'not_applicable': True},
        seams={'denominator': 0, 'numerator': 0, 'not_applicable': True, 'uncovered_times': []})
    row = report['criteria'][7]
    row['checks'][0].update(status='PASS', reason='Verified from current artifacts',
                             measurements=copy.deepcopy(report['coverage']))
    row['status'] = 'PASS'
    refresh(parts)
    assert observe(parts)
    if fault == 'positive': return
    if fault == 'different_return': row['checks'][0]['measurements']['observed_frame_count'] = 1
    else:
        report['coverage'].pop('seams')
        row['checks'][0]['measurements'] = copy.deepcopy(report['coverage'])
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['undeclared_root', 'duplicate_parent', 'duplicate_case', 'wrong_serialization',
    'noncanonical_member', 'unexpected_family', 'map_bound'])
def test_closed_declaration_and_finite_map_bounds(tmp_path, fault, monkeypatch):
    from talkcut import privacy_checks as privacy
    from talkcut import privacy_report_data_origins as report_data
    parts = fixture(tmp_path)
    assert observe(parts)
    if fault == 'undeclared_root':
        with pytest.raises(TalkCutError):
            privacy._review_text_origin_inventory([locator(parts)], parts['directory'], parts['root'],
                set(parts['registered'].values()), [])
        return
    if fault == 'map_bound':
        monkeypatch.setattr(report_data, 'MAX_ROWS', 5)
    elif fault == 'noncanonical_member':
        parts['map_mutator'] = lambda maps: maps['cases'][0]['members'][0].update(name='../outside.py')
    else:
        def mutate(authority):
            if fault in {'duplicate_parent', 'duplicate_case'}:
                pair = copy.deepcopy(authority['parents'][0])
                if fault == 'duplicate_case': pair['original']['path'] += '-other'
                authority['parents'].append(pair)
            elif fault == 'wrong_serialization': authority['parents'][0]['serialization'] = 'canonical_json_lf'
            else: authority['family'] = 'acceptance_cli_report'
        parts['data_authority_mutator'] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['prose', 'missing_key', 'extra_key', 'denominator_type', 'numerator_type',
    'fraction_type', 'boolean_type', 'intervals_type', 'span_shape', 'edge_type'])
def test_source_owned_coverage_value_constructor(tmp_path, fault):
    parts = fixture(tmp_path)
    report = parts['reports'][0]
    value = coverage_value([[0, 1]])
    report['coverage'] = {'output_audio': value}
    report['uncovered_intervals'] = [{'metric': 'output_audio', 'intervals': copy.deepcopy(value['uncovered_intervals'])}]
    refresh(parts)
    assert observe(parts)
    if fault == 'prose': report['coverage']['output_audio'] = 'Synthetic source-inconsistent prose'
    elif fault == 'missing_key': value.pop('fraction')
    elif fault == 'extra_key': value['private_prose'] = PHRASE
    elif fault == 'denominator_type': value['denominator_seconds'] = 3
    elif fault == 'numerator_type': value['numerator_seconds'] = 0
    elif fault == 'fraction_type': value['fraction'] = 0
    elif fault == 'boolean_type': value['not_applicable'] = 0
    elif fault == 'intervals_type': value['uncovered_intervals'] = 'Private prose'
    elif fault == 'span_shape': value['uncovered_intervals'] = [['0', '1', '2']]
    else: value['uncovered_intervals'] = [[0, 1]]
    if fault == 'prose': report['uncovered_intervals'] = []
    else: report['uncovered_intervals'][0]['intervals'] = copy.deepcopy(value['uncovered_intervals'])
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('fault', ['count_type', 'unknown_count_type', 'late_prose', 'late_extra_key',
    'late_count_type', 'late_boolean_type', 'seam_times_type', 'seam_element_type'])
def test_source_owned_late_coverage_containers(tmp_path, fault):
    parts = fixture(tmp_path)
    report = parts['reports'][0]
    report['coverage'] = {key: coverage_value([]) for key in
                         ('output_audio', 'output_video', 'deleted_source', 'source_analysis')}
    report['coverage'].update(observed_frame_count=0, observed_frame_count_unknown_runs=0,
        deletion_count={'denominator': 0, 'numerator': 0, 'not_applicable': True},
        seams={'denominator': 0, 'numerator': 0, 'not_applicable': True, 'uncovered_times': []})
    refresh(parts)
    assert observe(parts)
    metrics = report['coverage']
    if fault == 'count_type': metrics['observed_frame_count'] = {}
    elif fault == 'unknown_count_type': metrics['observed_frame_count_unknown_runs'] = True
    elif fault == 'late_prose': metrics['deletion_count'] = PHRASE
    elif fault == 'late_extra_key': metrics['deletion_count']['extra'] = PHRASE
    elif fault == 'late_count_type': metrics['seams']['numerator'] = '0'
    elif fault == 'late_boolean_type': metrics['seams']['not_applicable'] = 1
    elif fault == 'seam_times_type': metrics['seams']['uncovered_times'] = PHRASE
    else: metrics['seams']['uncovered_times'] = [1]
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize('target', ['original', 'snapshot'])
@pytest.mark.parametrize('delta', [0, -1, 1])
def test_declared_parent_size_matches_equal_hash_bytes(tmp_path, target, delta):
    parts = fixture(tmp_path, archived=True)
    assert observe(parts)
    size = Path(parts['parents'][0][target]['path']).stat().st_size
    parts['data_authority_mutator'] = lambda authority: authority['parents'][0][target].update(bytes=size + delta)
    refresh(parts)
    selected = locator(parts)
    selected['parent'] = {key: selected['parent'][key] for key in ('path', 'sha256')}
    if delta == 0: assert observe(parts, [selected])
    else:
        with pytest.raises(TalkCutError):
            observe(parts, [selected])
