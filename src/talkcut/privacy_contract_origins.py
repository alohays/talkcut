"""Closed contract data constructors; no validity or historical execution credit."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from . import privacy_contract_grammar as grammar
from . import privacy_machine_origins as machine

MAX_ROWS = 20000


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def reference(value: Any) -> dict[str, str]:
    machine.require(isinstance(value, dict) and set(value) in ({'path', 'sha256'}, {'path', 'sha256', 'bytes'})
                    and isinstance(value['path'], str) and Path(value['path']).is_absolute()
                    and isinstance(value['sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['sha256'])
                    and ('bytes' not in value or type(value['bytes']) is int and value['bytes'] >= 0),
                    'Contract construction requires a closed original artifact reference')
    return {key: value[key] for key in ('path', 'sha256')}


def unique(nodes: list[Any], reason: str) -> Any:
    machine.require(len(nodes) == 1, reason)
    return nodes[0]


def function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return unique([node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name],
                  'Contract source lacks one original constructor')


def literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError, SyntaxError) as exc:
        raise machine.TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Contract constructor has unsupported data expressions') from exc


def expected_contract(tree: ast.Module) -> dict[str, Any]:
    constants = {}
    for name in ('CONTRACT_VERSION', 'DOCUMENT_HASHES', 'CRITERIA'):
        constants[name] = literal(machine.assignment(tree, name))
    constants['CHECK_REQUIREMENTS'] = literal(unique([node.value for node in tree.body
        if isinstance(node, ast.AnnAssign) and machine.matches(node.target, 'CHECK_REQUIREMENTS')],
        'Contract check requirements have no unique original table'))
    constructor = function(tree, 'expected_contract')
    machine.require(len(constructor.body) == 1 and isinstance(constructor.body[0], ast.Return),
                    'Contract constructor has unsupported control flow')
    returned_statement = constructor.body[0]
    assert isinstance(returned_statement, ast.Return)
    returned = returned_statement.value
    machine.require(isinstance(returned, ast.Call) and machine.matches(returned.func, 'json.loads')
                    and len(returned.args) == 1 and not returned.keywords,
                    'Contract constructor has another canonical roundtrip')
    assert isinstance(returned, ast.Call)
    wrapped = returned.args[0]
    machine.require(isinstance(wrapped, ast.Call) and machine.matches(wrapped.func, 'canonical_bytes')
                    and len(wrapped.args) == 1 and not wrapped.keywords and isinstance(wrapped.args[0], ast.Dict),
                    'Contract constructor does not return its complete fixed dictionary')
    assert isinstance(wrapped, ast.Call)
    fields = machine.dict_fields(wrapped.args[0])
    result = {}
    for name, value in fields.items():
        if isinstance(value, ast.Name) and value.id in constants:
            result[name] = copy.deepcopy(constants[value.id])
        elif name == 'criteria':
            machine.require(machine.matches(value, "[{'id': key, 'required': True, 'description': value} for key, value in CRITERIA.items()]"),
                            'Contract criterion rows have another original construction')
            result[name] = [{'id': key, 'required': True, 'description': description}
                            for key, description in constants['CRITERIA'].items()]
        elif name == 'requirements':
            machine.require(machine.matches(value, "[f'R{i:02}' for i in range(1, 15)]"),
                            'Contract requirement denominator changed')
            result[name] = [f'R{i:02}' for i in range(1, 15)]
        else:
            result[name] = literal(value)
    machine.require(len(result['criteria']) == 13 and [row['id'] for row in result['criteria']] == [f'AC{i:02}' for i in range(1, 14)],
                    'Contract complete criterion denominator changed')
    # This is the literal constructor's deterministic JSON roundtrip, not source execution.
    return json.loads(canonical(result))


def mutations(tree: ast.Module, base: dict[str, Any]) -> dict[str, dict[str, Any]]:
    writer = function(tree, 'run_evaluator_negatives')
    control = unique([node for node in writer.body if isinstance(node, ast.Assign)
                      and any(machine.matches(target, 'contract_ref') for target in node.targets)],
                     'Contract control is not produced by the original negative writer')
    machine.require(machine.matches(control.value, "_save(root / 'contract-control.json', expected_contract())"),
                    'Contract control has another constructor or destination')
    loop = unique([node for node in writer.body if isinstance(node, ast.For)
                   and machine.matches(node.iter, "PAIR_NAMES['threshold_tamper']")],
                  'Contract mutations lack their original branch loop')
    expected = ast.parse("""for name in PAIR_NAMES['threshold_tamper']:
    changed_contract = expected_contract()
    if name == 'numeric_limit':
        changed_contract['checks']['sync']['max_lip_residual_with_uncertainty_ms']['max'] = 800
    elif name == 'required_flag':
        changed_contract['criteria'][0]['required'] = False
    else:
        changed_contract['unresolved_P0_P1'] = 1
    ref = _save(root / f'contract-{name}.json', changed_contract)
    pair('threshold_tamper', name, {'contract': contract_ref}, {'contract': ref})
""").body[0]
    machine.require(ast.dump(loop) == ast.dump(expected), 'Contract negative branch or complete writer changed')
    names = literal(machine.assignment(tree, 'PAIR_NAMES'))['threshold_tamper']
    machine.require(tuple(names) == ('numeric_limit', 'required_flag', 'blocker_limit'),
                    'Contract negative branch denominator changed')
    result = {'control': copy.deepcopy(base)}
    for name in names:
        value = copy.deepcopy(base)
        if name == 'numeric_limit':
            value['checks']['sync']['max_lip_residual_with_uncertainty_ms']['max'] = 800
        elif name == 'required_flag':
            value['criteria'][0]['required'] = False
        else:
            value['unresolved_P0_P1'] = 1
        result[name] = value
    return result


def verify(selected: dict[str, Any], root: Path, read: machine.Read, document: machine.Document) -> dict[str, Any]:
    machine.require(set(selected) == {'schema_version', 'family', 'recipe', 'sources', 'parents', 'records'}
                    and selected['schema_version'] == 'review-machine-field-authority/v1'
                    and selected['family'] == 'contract_template', 'Unsupported contract construction authority')
    recipe = selected['recipe']
    machine.require(isinstance(recipe, str) and recipe in {'canonical', 'native_fixture', 'negative_run'}, 'Unsupported contract construction recipe')
    roles = {'contracts'} | ({'caller'} if recipe == 'native_fixture' else {'project', 'negative'} if recipe == 'negative_run' else set())
    sources = selected['sources']
    machine.require(isinstance(sources, dict) and set(sources) == roles, 'Contract source dependency closure is incomplete')
    refs: list[dict[str, str]] = []

    def data(ref: Any) -> tuple[Path, bytes]:
        normalized = reference(ref)
        path, content = read(normalized)
        machine.require('bytes' not in ref or ref['bytes'] == len(content), 'Contract recorded artifact size differs')
        refs.append(normalized)
        return path, content

    def doc(ref: Any) -> dict[str, Any]:
        data(ref)
        return document(reference(ref))

    trees = {}
    source_dependencies: list[dict[str, Any]] = []
    for role, pair in sources.items():
        machine.require(isinstance(pair, dict) and set(pair) == {'original', 'snapshot'}, 'Contract source must retain its original and snapshot identities')
        original, snapshot = reference(pair['original']), reference(pair['snapshot'])
        machine.require(original['sha256'] == snapshot['sha256'], 'Contract source snapshot differs from its original identity')
        _, content = data(pair['snapshot'])
        tree = machine.syntax(content)
        allowed = grammar.NATIVE if role == 'caller' else {getattr(grammar, role.upper())}
        machine.require(hashlib.sha256(ast.dump(tree).encode()).hexdigest() in allowed,
                        'Contract complete source module is unsupported')
        if role in {'contracts', 'project'}:
            machine.require(original['path'] == str(root / 'src/talkcut' / (role + '.py')),
                            'Contract dependency original source path is unrelated')
        if role == 'negative':
            machine.require(original['path'] == str(root / 'src/talkcut/evaluator_negative.py'),
                            'Contract original negative source path is unrelated')
        trees[role] = tree
        source_dependencies.append({'original_path': original['path'], 'snapshot': snapshot})
    base = expected_contract(trees['contracts'])
    variants = mutations(trees['negative'], base) if recipe == 'negative_run' else {'canonical': base}
    declared = selected['parents']
    count = {'canonical': 1, 'native_fixture': 2, 'negative_run': 4}[recipe]
    machine.require(isinstance(declared, list) and len(declared) == count,
                    'Contract complete original parent denominator differs')
    parents = {}
    originals = {}
    for pair in declared:
        machine.require(isinstance(pair, dict) and set(pair) == {'original', 'snapshot'}, 'Contract parent must retain its exact original snapshot pair')
        original, snapshot = reference(pair['original']), reference(pair['snapshot'])
        machine.require(original['sha256'] == snapshot['sha256'] and original['path'] not in originals
                        and snapshot['path'] not in parents, 'Contract parent identity is changed or duplicated')
        path, content = data(pair['snapshot'])
        value = document(snapshot)
        parents[str(path)] = {'ref': snapshot, 'original': original, 'value': value, 'bytes': content}
        originals[original['path']] = parents[str(path)]
    records = selected['records']
    branches: dict[str, str] = {}
    if recipe == 'canonical':
        machine.require(records is None, 'Canonical construction cannot invent an execution record')
        branches = {name: 'canonical' for name in originals}
    elif recipe == 'negative_run':
        machine.require(isinstance(records, dict) and set(records) == {'request', 'result', 'receipt'},
                        'Contract negative record closure differs')
        request, result, receipt = [doc(records[name]) for name in ('request', 'result', 'receipt')]
        machine.require(request.get('schema_version') == 'evaluator-negative-request/v1'
                        and result.get('schema_version') == 'evaluator-negative-run/v1'
                        and receipt.get('schema_version') == 'evaluator-negative-receipt/v1'
                        and result.get('request') == receipt.get('request') == reference(records['request'])
                        and receipt.get('result') == reference(records['result'])
                        and request.get('harness') == result.get('harness') == receipt.get('harness') == reference(sources['negative']['original']),
                        'Contract original negative request/result/receipt relationship differs')
        code = request.get('code_identity')
        machine.require(isinstance(code, dict) and set(code) == {'code_revision', 'code_tree_hash', 'files'}
                        and isinstance(code['files'], dict) and 0 < len(code['files']) <= MAX_ROWS
                        and hashlib.sha256(canonical(code['files'])).hexdigest() == code['code_tree_hash']
                        and all(code['files'].get('src/talkcut/' + name + '.py') == sources[role]['original']['sha256']
                                for role, name in [('contracts', 'contracts'), ('project', 'project'), ('negative', 'evaluator_negative')]),
                        'Contract negative sources differ from the complete original code map')
        for item in (request, result, receipt):
            machine.require(item.get('final_ac12_audit') is False, 'Contract negative record cannot grant audit credit')
        machine.require(request.get('actual_dgist_acceptance') is False and result.get('actual_dgist_acceptance') is False
                        and result.get('test_only') is True and receipt.get('test_only') is True,
                        'Contract negative record changed its original control scope')
        artifacts = result.get('artifacts')
        machine.require(isinstance(artifacts, list) and 0 < len(artifacts) <= MAX_ROWS,
                        'Contract original artifact table is missing or oversized')
        assert isinstance(artifacts, list)
        inventory = [reference(ref) for ref in artifacts]
        machine.require(len({(ref['path'], ref['sha256']) for ref in inventory}) == len(inventory),
                        'Contract original artifact table contains duplicate entries')
        cases = result.get('cases')
        machine.require(isinstance(cases, dict) and isinstance(cases.get('threshold_tamper'), dict),
                        'Contract threshold case container is malformed')
        assert isinstance(cases, dict)
        pairs = cases['threshold_tamper'].get('pairs')
        machine.require(isinstance(pairs, list) and all(isinstance(pair, dict) for pair in pairs) and [pair.get('name') for pair in pairs] == ['numeric_limit', 'required_flag', 'blocker_limit'],
                        'Contract threshold input pairs are incomplete or reordered')
        assert isinstance(pairs, list)
        directory = Path(reference(records['request'])['path']).parent
        for pair in pairs:
            machine.require(set(pair) == {'attack', 'control', 'control_input', 'mutation', 'mutation_input', 'name'},
                            'Contract threshold pair has unrelated fields')
            machine.require(pair['mutation'] == {}, 'Contract threshold pair has an unrelated input mutation')
            for key, branch in [('control_input', 'control'), ('mutation_input', pair['name'])]:
                input_path = directory / 'cases/threshold_tamper' / pair['name'] / ('control.input.json' if key == 'control_input' else 'mutation.input.json')
                machine.require(reference(pair[key])['path'] == str(input_path),
                                'Contract threshold input is outside its original branch destination')
                value = doc(pair[key])
                machine.require(set(value) == {'contract'}, 'Contract threshold input differs from its complete constructor')
                ref = reference(value['contract'])
                expected_path = str(directory / ('contract-' + branch + '.json'))
                machine.require(ref['path'] == expected_path and ref['path'] in originals
                                and originals[ref['path']]['original'] == ref and ref in inventory,
                                'Contract threshold branch does not bind the exact original parent')
                machine.require(reference(pair[key]) in inventory, 'Contract threshold input is absent from the full original artifact table')
                process = pair['control' if key == 'control_input' else 'attack']
                machine.require(isinstance(process, dict)
                                and set(process) == {'argv', 'cwd', 'exit_code', 'finished_at', 'schema_version', 'started_at',
                                                     'stderr', 'stdout', 'timed_out', 'timeout_seconds', 'wall_seconds'}
                                and process['schema_version'] == 'negative-process/v1' and process['cwd'] == str(root)
                                and process['argv'] == [str(root / '.venv/bin/python3'), sources['negative']['original']['path'],
                                                       'probe', '--repo', str(root), '--case', 'threshold_tamper', '--input', str(input_path)]
                                and type(process['exit_code']) is int and type(process['timed_out']) is bool
                                and all(reference(process[stream]) in inventory for stream in ('stdout', 'stderr')),
                                'Contract threshold process selects another original source or input')
                branches[ref['path']] = branch
    else:
        machine.require(isinstance(records, dict) and set(records) == {'handoff', 'test_record', 'junit', 'launches', 'identity_record'},
                        'Contract native recorded construction closure differs')
        handoff = doc(records['handoff'])
        record = records['test_record']
        machine.require(isinstance(record, dict) and set(record) == {'parent', 'selector'}
                        and record['selector'] in ([], ['tests']), 'Contract native test record selector is unsupported')
        captured = doc(record['parent'])
        if record['selector']:
            machine.require(reference(record['parent']) == reference(records['handoff']), 'Contract embedded test record belongs to another handoff')
            captured = captured['tests']
        else:
            machine.require(reference(record['parent']) in [reference(handoff[key]) for key in ('tests', 'test_receipt')
                                                            if isinstance(handoff.get(key), dict) and 'path' in handoff[key]],
                            'Contract native handoff does not bind its original test record')
        machine.require(isinstance(captured, dict), 'Contract native test record container is malformed')
        tests = captured.get('test_sources', [captured.get('test_source')])
        machine.require(isinstance(tests, list) and 0 < len(tests) <= MAX_ROWS,
                        'Contract native source record is incomplete')
        caller = reference(sources['caller']['original'])
        caller_snapshot = reference(sources['caller']['snapshot'])
        machine.require(sum(reference(ref) in (caller, caller_snapshot) for ref in tests) == 1,
                        'Contract native record does not bind its original caller source')
        caller_path = Path(reference(records['handoff'])['path']).parent / 'test_native_audio.py'
        machine.require(caller['path'] == str(caller_path), 'Contract original caller path differs from its recorded test role')
        if 'command' in captured:
            command = captured['command']
            machine.require(isinstance(command, list) and len(command) >= 11 and all(isinstance(arg, str) for arg in command)
                            and command[:6] == [str(root / '.venv/bin/python3'), '-I', '-B', '-m', 'pytest', '-q']
                            and command[-4] == '--basetemp' and Path(command[-3]).is_absolute()
                            and command[-2:] == ['--junitxml', reference(records['junit'])['path']]
                            and str(caller_path) in command[6:-4],
                            'Contract recorded native test command selects another caller')
        machine.require(reference(captured.get('junit')) == reference(records['junit']), 'Contract native record selects another JUnit artifact')
        _, xml = data(records['junit'])
        machine.require(b'<!DOCTYPE' not in xml and b'<!ENTITY' not in xml, 'Contract native JUnit cannot declare entities')
        try:
            table = ET.fromstring(xml)
        except ET.ParseError as exc:
            raise machine.TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Contract native JUnit is malformed') from exc
        cases = [node for node in table.iter('testcase') if node.get('name', '').startswith('test_actual_tiny_child_transport_case_and_summary_binding[')]
        machine.require(len(cases) == 2 and {node.get('name') for node in cases}
                        == {'test_actual_tiny_child_transport_case_and_summary_binding[False]', 'test_actual_tiny_child_transport_case_and_summary_binding[True]'},
                        'Contract native caller cases are incomplete')
        caller_tree = trees['caller']
        launch = function(caller_tree, 'launch_fixture')
        machine.require(any(isinstance(node, ast.Expr) and machine.matches(node.value, 'freeze_contract(native.ROOT, contract)') for node in launch.body),
                        'Contract native caller does not reach the original constructor')
        test = function(caller_tree, 'test_actual_tiny_child_transport_case_and_summary_binding')
        machine.require(isinstance(test.body[0], ast.Assign) and machine.matches(test.body[0].value, 'launch_fixture(tmp_path)'),
                        'Contract native test does not call its original fixture')
        identity_record = doc(records['identity_record'])
        identity = identity_record.get('public_code_identity')
        machine.require(isinstance(identity, dict) and set(identity) == {'code_revision', 'code_tree_hash', 'files'}
                        and isinstance(identity['files'], dict) and 0 < len(identity['files']) <= MAX_ROWS
                        and hashlib.sha256(canonical(identity['files'])).hexdigest() == identity['code_tree_hash']
                        and identity['files'].get('src/talkcut/contracts.py') == sources['contracts']['original']['sha256'],
                        'Contract native constructor source has no recorded code-map relation')
        assert isinstance(identity, dict)
        launches = records['launches']
        machine.require(isinstance(launches, list) and len(launches) == 2, 'Contract native launch denominator differs')
        for ref in launches:
            path, _ = data(ref)
            value = doc(ref)
            machine.require(set(value) == {'schema_version', 'purpose', 'audio', 'source_artifacts', 'contract', 'dependencies'}
                            and value['purpose'] == 'binding test only'
                            and isinstance(value['source_artifacts'], dict) and set(value['source_artifacts']) == {'screen'}
                            and isinstance(value['dependencies'], dict)
                            and set(value['dependencies']) == {'source_hashes', 'contract_hash', 'code_tree_hash'},
                            'Contract native launch has another complete recorded field shape')
            audio = reference(value['audio'])
            screen = reference(value['source_artifacts']['screen'])
            machine.require(audio['path'] == str(path.parent / 'audio.wav')
                            and screen['path'] == str(path.parent / 'source.bin')
                            and value['dependencies']['source_hashes'] == {'screen': screen['sha256']},
                            'Contract native launch has unrelated source dependency fields')
            parent = reference(value.get('contract'))
            machine.require(parent['path'] == str(path.parent / 'contract.json') and parent['path'] in originals
                            and parent == originals[parent['path']]['original'] and parent['path'] not in branches
                            and value.get('schema_version') == 'private-native-audio-launch/v1'
                            and value.get('dependencies', {}).get('contract_hash') == parent['sha256']
                            and value.get('dependencies', {}).get('code_tree_hash') == identity['code_tree_hash'],
                            'Contract native launch does not bind its original constructed parent')
            branches[parent['path']] = 'canonical'
    machine.require(set(branches) == set(originals), 'Contract original branch coverage is incomplete')
    for name, complete_parent in originals.items():
        expected = variants[branches[name]]
        encoded = canonical(expected) + b'\n' if recipe == 'negative_run' else (json.dumps(expected, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode()
        machine.require(canonical(complete_parent['value']) == canonical(expected) and complete_parent['bytes'] == encoded,
                        'Contract complete parent or original serialization differs from its construction')
    dependencies = sorted(source_dependencies, key=lambda item: item['original_path'])
    source = sources['contracts']
    return {'source': reference(source['snapshot']), 'original_source': reference(source['original']),
            'source_dependencies': dependencies, 'refs': refs, 'parents': parents, 'originals': originals,
            'scope': 'Exact original source-data construction only; no contract, invocation or physical-copy approval'}


def original_parent(bound: dict[str, Any], parent: Any) -> dict[str, str]:
    normalized = reference(parent)
    found = bound['originals'].get(normalized['path'])
    if found is not None and found['original'] == normalized:
        return found['original']
    found = bound['parents'].get(normalized['path'])
    machine.require(found is not None and found['ref'] == normalized,
                    'Contract selected parent is outside its complete original construction')
    return found['original']


def project_field(bound: dict[str, Any], parent: Any, selector: Any) -> dict[str, Any]:
    machine.require(isinstance(selector, list) and len(selector) == 3 and selector[0] == 'criteria'
                    and type(selector[1]) is int and 0 <= selector[1] < 13 and selector[2] == 'description',
                    'Contract construction only supports an exact criterion description leaf')
    original = original_parent(bound, parent)
    row = bound['originals'][original['path']]['value']['criteria'][selector[1]]
    value = row['description']
    return {'value': value, 'row': row, 'extractions': [{'edge': selector, 'value': value}]}
