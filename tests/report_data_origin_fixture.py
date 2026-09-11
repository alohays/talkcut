"""Synthetic retained-report data; no recorded producer or source is executed."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from acceptance_origin_fixture import encoded, write
from acceptance_origin_fixture import fixture as cli_fixture

from talkcut import privacy_checks as privacy
from talkcut.project import artifact_ref

PHRASE = 'Execution contract and identified tools/reviewers'


def coverage_value(intervals):
    return {'denominator_seconds': '3' if intervals else '0', 'numerator_seconds': '0',
            'fraction': 0.0 if intervals else None, 'not_applicable': not bool(intervals),
            'uncovered_intervals': [[str(edge) for edge in span] for span in intervals]}


def fixture(tmp_path, serialization='pretty_json_lf', count=1, archived=False):
    parts=cli_fixture(tmp_path)
    parts.update(serialization=serialization,count=count,archived=archived,
                 reports=[copy.deepcopy(parts['report']) for _ in range(count)],temporary=tmp_path)
    refresh(parts)
    return parts


def refresh(parts):
    sources={name:artifact_ref(ref['path']) for name,ref in parts['sources'].items()}
    files={name:ref['sha256'] for name,ref in sources.items()}
    identity={'files':files,'code_tree_hash':hashlib.sha256(encoded(files)).hexdigest(),'code_revision':parts['revision']}
    parents=[];cases=[]
    for index,report in enumerate(parts['reports']):
        report.update(identity)
        raw=(json.dumps(report,ensure_ascii=False,allow_nan=False,indent=2).encode()
             if parts['serialization']=='pretty_json_lf' else encoded(report))+b'\n'
        path=Path(parts['stdout']['path']) if index==0 else parts['folder']/f'report-{index}.json'
        original=write(path,raw)
        snapshot=write(parts['temporary']/f'preserved-report-{index}.json',raw) if parts['archived'] else original
        parents.append({'original':original,'snapshot':snapshot,'retained_case':index,'serialization':parts['serialization']})
        cases.append({'parent':{'kind':'review',**original},'revision':identity['code_revision'],
          'declared_code_tree_hash':identity['code_tree_hash'],'map_hash_matches':True,
          'members':[{'name':name,'expected_sha256':digest,'argv':[], 'returncode':None,'observed_sha256':None,
                      'bytes':0,'stderr':'Synthetic map declaration, not a Git execution','matches':False,'snapshot':None}
                     for name,digest in files.items()],
          'selected_origin_indices':[],'source_map_equal_original_commit':False,
          'scope':'Synthetic original-source data map; no historical command/execution claim'})
    maps={'schema':'root-original-acceptance-source-map-readback/v1','cases':cases,
          'scope':'Synthetic retained metadata for bounded consumer tests; no Git/producer execution'}
    if 'map_mutator' in parts:parts['map_mutator'](maps)
    map_ref=write(parts['folder']/'source-maps.json',maps)
    authority={'schema_version':'review-machine-field-authority/v1','family':'acceptance_report_data',
               'source_maps':map_ref,'sources':sources,'parents':parents}
    if 'data_authority_mutator' in parts:parts['data_authority_mutator'](authority)
    authority_ref=write(parts['folder']/'data-authority.json',authority)
    parts.update(data_authority=authority,data_authority_ref=authority_ref,parents=parents,sources=sources)
    write(parts['directory']/'checkpoint.local.json',{'original_reports':[pair['original'] for pair in parents]})


def locator(parts,index=0,selector=None,original=False):
    return {'schema_version':'review-text-origin/v1','kind':'machine_inventory_field',
            'parent':parts['parents'][index]['original' if original else 'snapshot'],
            'selector':['criteria',0,'description'] if selector is None else selector,'authority':parts['data_authority_ref']}


def observe(parts,selected=None,registered=None):
    return privacy._review_text_origin_inventory([locator(parts)] if selected is None else selected,
       parts['directory'],parts['root'],set(parts['registered'].values()) if registered is None else registered,
       [parts['data_authority_ref']])


def inventory(parts,selected=None):
    chosen=[locator(parts)] if selected is None else selected
    return privacy._known_private_inventory(parts['directory'],parts['registered'],parts['root'],
        review_text_origins=chosen,review_text_origin_authorities=[parts['data_authority_ref']] if chosen else [])
