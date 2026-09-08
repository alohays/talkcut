"""Original reported-data constructors; never historical invocation or copying."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any, cast

from . import privacy_acceptance_grammar as grammar
from . import privacy_acceptance_origins as acceptance
from . import privacy_machine_origins as machine

MAX_ROWS = 20000
ORIGINAL_EVALUATOR_SHAPE = '0748ecdb2e58d3272ef3a3b8117d3052d9c8d44adfc077eff1dd9e7e736bc27a'
ROLES = set(grammar.MODULE_SHAPES) | {'pyproject.toml'}


def reference(value: Any) -> dict[str, str]:
    machine.require(isinstance(value, dict) and set(value) in ({'path', 'sha256'}, {'path', 'sha256', 'bytes'})
                    and isinstance(value['path'], str) and Path(value['path']).is_absolute()
                    and isinstance(value['sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sha256'])
                    and ('bytes' not in value or type(value['bytes']) is int and value['bytes'] >= 0),
                    'Original report requires a closed exact artifact reference')
    return {key: value[key] for key in ('path', 'sha256')}


def validate_report(report: dict[str, Any], recipe: dict[str, Any], serialization: str) -> None:
    """Visible constructor consistency, not the truth of the underlying evidence."""
    machine.require(set(report) == recipe['report_fields'] and report['schema_version'] == recipe['schema']
                    and report['evaluator_version'] == recipe['schema'], 'Original report has another complete output shape')
    files = report['files']
    machine.require(isinstance(files, dict) and 0 < len(files) <= MAX_ROWS
                    and all(isinstance(name, str) and not Path(name).is_absolute() and '..' not in Path(name).parts
                            and isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest) for name, digest in files.items())
                    and hashlib.sha256(acceptance.canonical(files)).hexdigest() == report['code_tree_hash']
                    and isinstance(report['code_revision'], str) and re.fullmatch('[a-f0-9]{40}', report['code_revision']),
                    'Original report source map is malformed or inconsistent')
    criteria = report['criteria']
    machine.require(isinstance(criteria, list) and len(criteria) == 13, 'Original report criterion denominator differs')
    for row, (identifier, description) in zip(criteria, recipe['criteria'].items(), strict=True):
        machine.require(isinstance(row, dict) and set(row) == {'id', 'description', 'status', 'checks', 'evidence_refs'}
                        and row['id'] == identifier and row['description'] == description
                        and isinstance(row['status'], str) and row['status'] in {'PASS', 'FAIL', 'UNVERIFIED'}
                        and isinstance(row['checks'], list) and 0 < len(row['checks']) <= MAX_ROWS
                        and row['evidence_refs'] == [], 'Original report has another complete criterion constructor')
        for check in row['checks']:
            machine.require(isinstance(check, dict) and set(check) == {'check_id', 'status', 'reason', 'measurements'}
                            and isinstance(check['check_id'], str) and isinstance(check['reason'], str)
                            and isinstance(check['status'], str) and check['status'] in {'PASS', 'FAIL', 'UNVERIFIED'},
                            'Original report has malformed check constructor fields')
            if check['check_id'] not in {'open_P0_P1', 'G0_G5_dependencies'}:
                machine.require((check['status'] != 'PASS' or check['reason'] == recipe['success_reason'])
                                and (check['status'] == 'PASS' or check['measurements'] is None),
                                'Original report check differs from its success or caught-error constructor')
    acceptance.criterion_writers(report, recipe)
    states = {row['id']: row['status'] for row in criteria}
    ready = all(states[f'AC{i:02}'] == 'PASS' for i in range(1, 13))
    achieved = ready and states['AC13'] == 'PASS'
    status = 'PASS' if achieved else 'FAIL' if 'FAIL' in states.values() else 'UNVERIFIED'
    media = all(states[key] == 'PASS' for key in ('AC01', 'AC02', 'AC04', 'AC05', 'AC06', 'AC07', 'AC08', 'AC09'))
    machine.require(report['release_ready'] is ready and report['goal_achieved'] is achieved and report['status'] == status
                    and report['media_state'] == ('READY_FOR_OWNER' if media else 'BLOCKED')
                    and report['owner_acceptance'] == 'pending' and report['provenance_limitations'] == recipe['provenance']
                    and isinstance(report['source_hashes'], dict) and isinstance(report['coverage'], dict)
                    and all(isinstance(report[name], list) and len(report[name]) <= MAX_ROWS
                            for name in ('uncovered_intervals', 'invalid_evidence', 'open_findings')),
                    'Original report differs from its complete returned constructor fields')
    # Canonical serialization sorts object keys, but the source fixes metric
    # insertion order. A caught callback failure can leave only a prefix.
    metric_order = recipe['coverage_order'][:len(report['coverage'])]
    machine.require(set(report['coverage']) == set(metric_order)
                    and (serialization == 'canonical_json_lf' or list(report['coverage']) == metric_order),
                    'Original report coverage differs from the source metric insertion order')
    for position, key in enumerate(metric_order):
        value = report['coverage'][key]
        if position < 4:
            machine.require(isinstance(value, dict) and set(value) == recipe['coverage_fields']
                            and isinstance(value['denominator_seconds'], str) and isinstance(value['numerator_seconds'], str)
                            and (value['fraction'] is None or type(value['fraction']) is float)
                            and type(value['not_applicable']) is bool
                            and isinstance(value['uncovered_intervals'], list)
                            and len(value['uncovered_intervals']) <= MAX_ROWS
                            and all(isinstance(span, list) and len(span) == 2
                                    and all(isinstance(edge, str) for edge in span) for span in value['uncovered_intervals']),
                            'Original report coverage differs from the fixed coverage value constructor')
        elif position < 6:
            machine.require(type(value) is int, 'Original report coverage count is not the original integer container')
        else:
            machine.require(isinstance(value, dict) and set(value) == recipe['coverage_late_fields'][key]
                            and type(value['denominator']) is int and type(value['numerator']) is int
                            and type(value['not_applicable']) is bool
                            and (position != 7 or isinstance(value['uncovered_times'], list)
                                 and len(value['uncovered_times']) <= MAX_ROWS
                                 and all(isinstance(edge, str) for edge in value['uncovered_times'])),
                            'Original report coverage differs from the fixed late metric constructor')
    uncovered = [{'metric': key, 'intervals': report['coverage'][key]['uncovered_intervals']} for key in metric_order
                 if isinstance(report['coverage'][key], dict) and report['coverage'][key].get('uncovered_intervals')]
    machine.require(acceptance.canonical(report['uncovered_intervals']) == acceptance.canonical(uncovered),
                    'Original report uncovered intervals differ from its recorded coverage projection')
    coverage_check = criteria[7]['checks'][0]
    machine.require(coverage_check['status'] != 'PASS'
                    or len(report['coverage']) == len(recipe['coverage_order'])
                    and acceptance.canonical(coverage_check['measurements']) == acceptance.canonical(report['coverage']),
                    'Original report coverage differs from its successful callback return')
    release = criteria[12]['checks'][0]
    machine.require(acceptance.canonical(report['code_release_evidence'])
                    == acceptance.canonical(release['measurements'] if release['status'] == 'PASS' else None),
                    'Original report release evidence differs from its check return')


def verify(selected: dict[str, Any], root: Path, read: machine.Read, document: machine.Document) -> dict[str, Any]:
    machine.require(set(selected) == {'schema_version', 'family', 'source_maps', 'sources', 'parents'}
                    and selected['schema_version'] == 'review-machine-field-authority/v1'
                    and selected['family'] == 'acceptance_report_data', 'Unsupported original report data authority')
    refs: list[dict[str, str]] = []

    def data(value: Any) -> tuple[Path, bytes]:
        ref = reference(value);path, content = read(ref)
        machine.require('bytes' not in value or value['bytes'] == len(content), 'Original report reference size differs')
        refs.append(ref)
        return path, content

    def doc(value: Any) -> dict[str, Any]:
        data(value)
        return document(reference(value))

    sources = selected['sources']
    machine.require(isinstance(sources, dict) and set(sources) == ROLES, 'Original report source dependency closure is incomplete')
    trees = {}
    for name, ref in sources.items():
        _, content = data(ref)
        if name == 'pyproject.toml':
            try:
                metadata = tomllib.loads(content.decode('utf-8'))
            except (UnicodeError, ValueError) as exc:
                raise machine.TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Original report console metadata is malformed') from exc
            machine.require(isinstance(metadata.get('project'), dict)
                            and isinstance(metadata['project'].get('scripts'), dict)
                            and metadata['project']['scripts'].get('talkcut') == 'talkcut.__main__:main',
                            'Original report console source selects another entry point')
        else:
            tree = machine.syntax(content)
            shape = hashlib.sha256(ast.dump(tree).encode()).hexdigest()
            allowed = {ORIGINAL_EVALUATOR_SHAPE} if name == 'src/talkcut/acceptance.py' else set(grammar.MODULE_SHAPES[name])
            machine.require(shape in allowed, 'Original report complete source profile is unsupported')
            trees[name] = tree
    recipe = acceptance.source_recipe(trees)
    owner = acceptance.one([node for node in trees['src/talkcut/acceptance.py'].body
                            if isinstance(node, ast.ClassDef) and node.name == 'Evaluator'],
                           'Original report evaluator class is absent')
    check = acceptance.method(owner, 'check')
    success = acceptance.one([node for node in ast.walk(check) if isinstance(node, ast.Call)
                              and machine.matches(node.func, 'self.add') and len(node.args) == 5
                              and machine.matches(node.args[2], "'PASS'")],
                             'Original report success constructor is ambiguous')
    machine.require(not success.keywords and machine.matches(success.args[0], 'criterion')
                    and machine.matches(success.args[1], 'name') and machine.matches(success.args[4], 'result'),
                    'Original report success constructor uses another callback result')
    recipe['success_reason'] = acceptance.literal(success.args[3])
    machine.require(isinstance(recipe['success_reason'], str), 'Original report success reason is not literal')
    coverage_writer = acceptance.method(owner, 'review_coverage')
    coverage_assignments = [node for node in coverage_writer.body if isinstance(node, ast.Assign)
                            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Subscript)
                            and machine.matches(node.targets[0].value, 'self.coverage')]
    recipe['coverage_order'] = [acceptance.literal(cast(ast.Subscript, node.targets[0]).slice) for node in coverage_assignments]
    machine.require(len(recipe['coverage_order']) == 8
                    and all(isinstance(value, str) for value in recipe['coverage_order'])
                    and len(set(recipe['coverage_order'])) == 8,
                    'Original report coverage assignment order is unsupported')
    coverage_function = acceptance.one([node for node in trees['src/talkcut/acceptance.py'].body
                                        if isinstance(node, ast.FunctionDef) and node.name == 'coverage'],
                                       'Original report coverage function is absent')
    coverage_return = acceptance.one([node.value for node in coverage_function.body if isinstance(node, ast.Return)],
                                     'Original report coverage value return is ambiguous')
    machine.require(isinstance(coverage_return, ast.Dict), 'Original report coverage value is not a literal dictionary')
    recipe['coverage_fields'] = set(machine.dict_fields(cast(ast.Dict, coverage_return)))
    recipe['coverage_late_fields'] = {recipe['coverage_order'][position]: set(machine.dict_fields(cast(ast.Dict, coverage_assignments[position].value)))
                                     for position in (6, 7)}
    retained = doc(selected['source_maps'])
    machine.require(retained.get('schema') == 'root-original-acceptance-source-map-readback/v1'
                    and isinstance(retained.get('cases'), list) and 0 < len(retained['cases']) <= MAX_ROWS,
                    'Original report lacks its separately retained full source-map record')
    declared = selected['parents']
    machine.require(isinstance(declared, list) and 0 < len(declared) <= 6, 'Original report parent denominator is unsupported')
    parents: dict[str, Any] = {}
    originals = set()
    cases_seen = set()
    for pair in declared:
        machine.require(isinstance(pair, dict) and set(pair) == {'original', 'snapshot', 'retained_case', 'serialization'}
                        and type(pair['retained_case']) is int and 0 <= pair['retained_case'] < len(retained['cases'])
                        and pair['retained_case'] not in cases_seen
                        and pair['serialization'] in ('pretty_json_lf', 'canonical_json_lf'),
                        'Original report parent requires one closed retained-map case and serialization')
        cases_seen.add(pair['retained_case'])
        original, snapshot = reference(pair['original']), reference(pair['snapshot'])
        machine.require(original['path'] not in originals and original['sha256'] == snapshot['sha256'],
                        'Original report physical parent identity is changed or duplicated')
        originals.add(original['path'])
        case = retained['cases'][pair['retained_case']]
        machine.require(isinstance(case, dict) and isinstance(case.get('parent'), dict)
                        and set(case['parent']) == {'kind', 'path', 'sha256'} and case['parent']['kind'] == 'review'
                        and {key: case['parent'][key] for key in ('path', 'sha256')} == original
                        and isinstance(case.get('members'), list) and 0 < len(case['members']) <= MAX_ROWS,
                        'Original report does not match its independently retained parent/source-map case')
        mapping = {}
        for member in case['members']:
            machine.require(isinstance(member, dict) and isinstance(member.get('name'), str)
                            and not Path(member['name']).is_absolute() and '..' not in Path(member['name']).parts
                            and member['name'] not in mapping and isinstance(member.get('expected_sha256'), str)
                            and re.fullmatch('[a-f0-9]{64}', member['expected_sha256']),
                            'Original report retained complete source map is malformed or duplicated')
            mapping[member['name']] = member['expected_sha256']
        _, content = data(pair['snapshot'])
        machine.require('bytes' not in pair['original'] or pair['original']['bytes'] == len(content),
                        'Original report original reference size differs from its exact snapshot bytes')
        report = document(snapshot)
        validate_report(report, recipe, pair['serialization'])
        machine.require(report['files'] == mapping and report['code_revision'] == case.get('revision')
                        and report['code_tree_hash'] == case.get('declared_code_tree_hash')
                        and all(report['files'].get(name) == reference(ref)['sha256'] for name, ref in sources.items()),
                        'Original report differs from its complete retained map or exact source snapshots')
        expected = (json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2).encode()
                    if pair['serialization'] == 'pretty_json_lf' else acceptance.canonical(report)) + b'\n'
        machine.require(content == expected, 'Original report differs from its declared deterministic serializer')
        for ref in (snapshot, original):
            existing = parents.get(ref['path'])
            value = {'ref': ref, 'report': report, 'original': original}
            machine.require(existing is None or existing == value, 'Original report physical paths overlap another parent')
            parents[ref['path']] = value
    return {'source': reference(sources['src/talkcut/acceptance.py']),
            'original_source': {'path': str(root / 'src/talkcut/acceptance.py'), 'sha256': sources['src/talkcut/acceptance.py']['sha256']},
            'source_dependencies': [{'original_path': str(root / name), 'snapshot': reference(sources[name])} for name in sorted(sources)],
            'refs': refs, 'parents': parents, 'recipe': recipe,
            'scope': 'Literal original reported-data construction only; no invocation, copying or acceptance approval'}


def original_parent(bound: dict[str, Any], parent: Any) -> dict[str, str]:
    return acceptance.original_parent(bound, reference(parent))


def project_field(bound: dict[str, Any], parent: Any, selector: Any) -> dict[str, Any]:
    return acceptance.project_field(bound, reference(parent), selector)
