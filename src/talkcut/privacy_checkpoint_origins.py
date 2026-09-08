"""Retained checkpoint data projections; never historical execution or copying."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import privacy_acceptance_origins as acceptance
from . import privacy_machine_origins as machine
from . import privacy_report_data_origins as reports

MAX_ROWS = 20000
SUMMARY_FIELDS = ('status', 'release_ready', 'goal_achieved', 'criteria', 'owner_acceptance')
COMMAND_FIELDS = ('code_revision', 'code_tree_hash', 'criteria', 'status', 'release_ready', 'goal_achieved',
                  'media_state', 'owner_acceptance', 'output_hash', 'open_findings', 'uncovered_intervals')


def pointer(value: Any) -> list[str | int]:
    """Only the two fixed criterion leaf shapes, with canonical integer indices."""
    machine.require(isinstance(value, str) and bool(re.fullmatch(
        r'/(?:acceptance/|actual_latest_acceptance/)?criteria/(?:0|[1-9][0-9]*)/(?:description|checks/(?:0|[1-9][0-9]*)/reason)', value)),
        'Checkpoint retained selector is not a supported criterion leaf')
    try:
        return [int(part) if part.isdecimal() else part for part in value.split('/')[1:]]
    except ValueError as exc:
        raise machine.TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED',
                                   'Checkpoint retained selector integer exceeds the parser limit') from exc


def at(value: Any, selector: list[str | int]) -> Any:
    try:
        for part in selector:
            value = value[part]
    except (KeyError, IndexError, TypeError) as exc:
        raise machine.TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Checkpoint projection field does not exist') from exc
    return value


def same(left: Any, right: Any) -> bool:
    return acceptance.canonical(left) == acceptance.canonical(right)


def verify(selected: dict[str, Any], upstream: dict[str, Any], upstream_declaration: dict[str, Any],
           read: machine.Read, document: machine.Document) -> dict[str, Any]:
    """The caller independently approves and validates the upstream authority first."""
    machine.require(set(selected) == {'schema_version', 'family', 'retained_copies', 'upstream_authority', 'parents'}
                    and selected['schema_version'] == 'review-machine-field-authority/v1'
                    and selected['family'] == 'acceptance_checkpoint_data'
                    and isinstance(upstream_declaration.get('family'), str)
                    and upstream_declaration['family'] in {'acceptance_cli_report', 'acceptance_report_data'},
                    'Unsupported checkpoint data authority')
    refs: list[dict[str, str]] = []

    def data(value: Any) -> tuple[Path, bytes]:
        ref = reports.reference(value)
        path, content = read(ref)
        machine.require('bytes' not in value or value['bytes'] == len(content), 'Checkpoint reference size differs')
        refs.append(ref)
        return path, content

    def doc(value: Any) -> dict[str, Any]:
        data(value)
        return document(reports.reference(value))

    machine.require(doc(selected['upstream_authority']) == upstream_declaration,
                    'Checkpoint upstream declaration differs from the separately approved authority')
    retained = doc(selected['retained_copies'])
    machine.require(retained.get('schema') == 'root-original-checkpoint-copy-fields/v1'
                    and isinstance(retained.get('cases'), list) and 0 < len(retained['cases']) <= MAX_ROWS,
                    'Checkpoint lacks its independently retained original case and source relation')
    declared = selected['parents']
    machine.require(isinstance(declared, list) and 0 < len(declared) <= 4,
                    'Checkpoint parent denominator is unsupported')
    parents: dict[str, Any] = {}
    originals: set[str] = set()
    cases_seen: set[int] = set()
    origins: set[int] = set()
    upstream_parents: dict[str, Any] = {}
    for pair in declared:
        machine.require(isinstance(pair, dict)
                        and set(pair) == {'original', 'snapshot', 'retained_case', 'upstream_parent', 'projection'}
                        and type(pair['retained_case']) is int and 0 <= pair['retained_case'] < len(retained['cases'])
                        and pair['retained_case'] not in cases_seen and isinstance(pair['projection'], str)
                        and pair['projection'] in {'evidence_summary', 'command_summary', 'preserved_report_summary'},
                        'Checkpoint requires one closed original case and supported projection')
        cases_seen.add(pair['retained_case'])
        original, snapshot = reports.reference(pair['original']), reports.reference(pair['snapshot'])
        machine.require(original['path'] not in originals and original['sha256'] == snapshot['sha256'],
                        'Checkpoint physical parent identity is changed or duplicated')
        originals.add(original['path'])
        case = retained['cases'][pair['retained_case']]
        machine.require(isinstance(case, dict) and isinstance(case.get('parent'), dict)
                        and set(case['parent']) == {'kind', 'path', 'sha256'} and case['parent']['kind'] == 'review'
                        and {key: case['parent'][key] for key in ('path', 'sha256')} == original,
                        'Checkpoint differs from its independently retained original parent')
        _, raw = data(pair['snapshot'])
        machine.require('bytes' not in pair['original'] or pair['original']['bytes'] == len(raw),
                        'Checkpoint original size differs from its exact preserved bytes')
        parent = document(snapshot)
        machine.require(raw == (json.dumps(parent, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode(),
                        'Checkpoint differs from the supported observed JSON spelling')
        source = reports.reference(pair['upstream_parent'])
        source_original = acceptance.original_parent(upstream, source)
        report = upstream['parents'][source['path']]['report']
        _, source_bytes = data(pair['upstream_parent'])
        machine.require(reports.reference(case.get('source_report')) == source_original
                        and ('bytes' not in case['source_report'] or case['source_report']['bytes'] == len(source_bytes))
                        and case.get('source_code_revision') == report['code_revision'],
                        'Checkpoint selected report differs from its retained source-parent mapping')
        upstream_parents[source['path']] = {'ref': source, 'original': source_original}
        edges = case.get('copy_edges')
        machine.require(isinstance(edges, list) and len(edges) == 1 and isinstance(edges[0], dict),
                        'Checkpoint original report relationship is absent or ambiguous')
        edge = edges[0]
        mode = pair['projection']
        if mode == 'evidence_summary':
            machine.require(upstream_declaration['family'] == 'acceptance_report_data'
                            and parent.get('schema_version') == 'goal-stage-checkpoint/v1'
                            and edge == {'kind': 'original_checkpoint_explicit_evidence', 'pointer': '/evidence/5'}
                            and isinstance(parent.get('evidence'), list) and 5 < len(parent['evidence']) <= MAX_ROWS,
                            'Checkpoint evidence-summary relationship is unsupported')
            reference = parent['evidence'][5]
            machine.require(reports.reference(reference) == source_original,
                            'Checkpoint evidence selects another original report')
            data(reference)
            prefix: list[str | int] = ['acceptance']
            machine.require(same(parent.get('acceptance'), {key: report[key] for key in SUMMARY_FIELDS}),
                            'Checkpoint complete acceptance summary differs from the report')
        elif mode == 'command_summary':
            machine.require(upstream_declaration['family'] == 'acceptance_cli_report'
                            and parent.get('schema_version') == 'talkcut-append-only-checkpoint/v1'
                            and set(edge) == {'kind', 'command'} and edge['kind'] == 'original_checkpoint_command_stdout'
                            and isinstance(parent.get('evidence'), dict),
                            'Checkpoint command-summary relationship is unsupported')
            command_ref = reports.reference(edge['command'])
            command = doc(edge['command'])
            machine.require(command_ref == upstream_declaration['command']
                            and reports.reference(parent['evidence'].get('actual_acceptance_command')) == command_ref
                            and reports.reference(parent['evidence'].get('actual_acceptance_stdout')) == source_original
                            and command['stdout'] == source_original and upstream_declaration['stdout'] == source_original,
                            'Checkpoint command and stdout do not select the approved original report')
            data(parent['evidence']['actual_acceptance_command'])
            data(parent['evidence']['actual_acceptance_stdout'])
            prefix = ['actual_latest_acceptance']
            machine.require(same(parent.get('actual_latest_acceptance'), {key: report[key] for key in COMMAND_FIELDS}),
                            'Checkpoint complete command summary differs from the report')
        else:
            machine.require(upstream_declaration['family'] == 'acceptance_report_data'
                            and parent.get('schema_version') in {'goal-stage-checkpoint/v1', 'goal-checkpoint/v1'}
                            and set(edge) == {'kind', 'original_reference', 'preserved_reference'}
                            and edge['kind'] == 'original_explicit_report_ref_with_exact_preserved_bytes',
                            'Checkpoint preserved-report relationship is unsupported')
            historical = reports.reference(edge['original_reference'])
            machine.require(parent.get('actual_latest_acceptance') == edge['original_reference']
                            and reports.reference(edge['preserved_reference']) == source_original
                            and historical['sha256'] == source_original['sha256']
                            and ('bytes' not in edge['original_reference']
                                 or edge['original_reference']['bytes'] == len(source_bytes)),
                            'Checkpoint historical report lacks its explicit exact preserved-body mapping')
            # The historical path can now contain another report. The retained
            # mapping authorizes only these preserved bytes, not path survival.
            data(edge['preserved_reference'])
            prefix = []
            machine.require(same(parent.get('criteria'), report['criteria'])
                            and same(parent.get('acceptance_status'), report['status'])
                            and all(same(parent.get(key), report[key]) for key in
                                    ('release_ready', 'goal_achieved', 'owner_acceptance')),
                            'Checkpoint complete criterion and report summary differ')
        criteria = at(parent, [*prefix, 'criteria'])
        machine.require(isinstance(criteria, list) and len(criteria) == 13 and same(criteria, report['criteria'])
                        and case.get('original_goal_status') == report['status']
                        and case.get('original_goal_achieved') is report['goal_achieved']
                        and case.get('original_owner_acceptance') == report['owner_acceptance'],
                        'Checkpoint original complete criterion order or report verdict differs')
        rows = case.get('rows')
        machine.require(isinstance(rows, list) and 0 < len(rows) <= MAX_ROWS,
                        'Checkpoint retained occurrence table is absent or unbounded')
        projections: dict[tuple[str | int, ...], Any] = {}
        for row in rows:
            machine.require(isinstance(row, dict) and set(row) == {'original_origin_index', 'pointer', 'source_pointer',
                            'criterion_id', 'value', 'phrase_sha256', 'status'}
                            and type(row['original_origin_index']) is int and row['original_origin_index'] >= 0
                            and row['original_origin_index'] not in origins
                            and isinstance(row['value'], str)
                            and row['phrase_sha256'] == hashlib.sha256(row['value'].encode()).hexdigest()
                            and row['status'] == 'EXACT_ORIGINAL_REPORT_COPY_FIELD',
                            'Checkpoint retained occurrence is malformed or duplicated')
            origins.add(row['original_origin_index'])
            selector, source_selector = pointer(row['pointer']), pointer(row['source_pointer'])
            machine.require(source_selector[0] == 'criteria' and selector == prefix + source_selector
                            and tuple(selector) not in projections,
                            'Checkpoint retained selector maps another source field')
            projection = acceptance.project_field(upstream, source, source_selector)
            machine.require(row['criterion_id'] == report['criteria'][source_selector[1]]['id']
                            and row['value'] == projection['value'] == at(parent, selector)
                            and same(projection['row'], at(parent, selector[:-1])),
                            'Checkpoint retained full row or literal differs from the approved source constructor')
            projections[tuple(selector)] = {'value': projection['value'], 'row': at(parent, selector[:-1]),
                                           'extractions': [{'edge': selector, 'value': projection['value']}]}
        for ref in (snapshot, original):
            value = {'ref': ref, 'original': original, 'projections': projections}
            machine.require(ref['path'] not in parents or parents[ref['path']] == value,
                            'Checkpoint physical paths overlap another parent')
            parents[ref['path']] = value
    return {'source': upstream['source'], 'original_source': upstream['original_source'],
            'source_dependencies': upstream['source_dependencies'], 'refs': refs, 'parents': parents,
            'upstream_parents': list(upstream_parents.values()), 'project': upstream.get('project'),
            'scope': 'Retained checkpoint data projection only; no historical execution, copying or acceptance approval'}


def original_parent(bound: dict[str, Any], parent: Any) -> dict[str, str]:
    return acceptance.original_parent(bound, reports.reference(parent))


def project_field(bound: dict[str, Any], parent: Any, selector: Any) -> dict[str, Any]:
    machine.require(isinstance(selector, list) and selector and all(type(part) in {str, int} for part in selector),
                    'Checkpoint selected leaf is malformed')
    original_parent(bound, parent)
    projection = bound['parents'][parent['path']]['projections'].get(tuple(selector))
    machine.require(projection is not None, 'Checkpoint selected leaf is outside its retained original occurrences')
    return projection
