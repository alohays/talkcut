"""Closed original acceptance-field writers; no evaluation or verdict approval."""
from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import tomllib
from pathlib import Path
from typing import Any

from . import privacy_acceptance_grammar as grammar
from . import privacy_machine_origins as machine

MAX_ROWS = 20000
IDENTITY_FIELDS = {"code_revision", "code_tree_hash", "files"}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def method(owner: ast.ClassDef, name: str) -> ast.FunctionDef:
    found = [node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == name]
    machine.require(len(found) == 1, "Acceptance origin lacks a unique original method")
    return found[0]


def one(values: list[Any], reason: str) -> Any:
    machine.require(len(values) == 1, reason)
    return values[0]


def literal(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError) as exc:
        raise machine.TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Acceptance origin writer is not literal") from exc


def calls(function: ast.FunctionDef, target: str) -> list[ast.Call]:
    return [node for node in ast.walk(function) if isinstance(node, ast.Call) and machine.matches(node.func, target)]


def body_call(function: ast.FunctionDef, target: str) -> list[ast.Call]:
    result = []
    for statement in function.body:
        value = statement.value if isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)) else None
        if isinstance(value, ast.Call) and machine.matches(value.func, target):
            result.append(value)
    return result


def source_recipe(trees: dict[str, ast.Module]) -> dict[str, Any]:
    acceptance = trees["src/talkcut/acceptance.py"]
    contracts = trees["src/talkcut/contracts.py"]
    owner = one([node for node in acceptance.body if isinstance(node, ast.ClassDef) and node.name == "Evaluator"],
                "Acceptance origin lacks its complete evaluator class")
    evaluator = method(owner, "evaluate")
    initial = method(owner, "__init__")
    criteria = literal(machine.assignment(contracts, "CRITERIA"))
    machine.require(isinstance(criteria, dict) and list(criteria) == [f"AC{i:02}" for i in range(1, 14)]
                    and all(isinstance(v, str) for v in criteria.values()), "Acceptance original criteria table is incomplete")
    constructor = one([s.value for s in initial.body if isinstance(s, ast.AnnAssign)
                       and machine.matches(s.target, "self.criteria")], "Acceptance criteria constructor is ambiguous")
    machine.require(machine.matches(constructor, "{key: {'id': key, 'description': value, 'status': 'UNVERIFIED', 'checks': [], 'evidence_refs': []} for key, value in CRITERIA.items()}"),
                    "Acceptance criteria no longer derive from the original imported table")
    add = method(owner, "add")
    machine.require(len(add.body) == 1 and isinstance(add.body[0], ast.Expr)
                    and machine.matches(add.body[0].value, "self.criteria[criterion]['checks'].append({'check_id': name, 'status': status, 'reason': reason, 'measurements': measurements})"),
                    "Acceptance check row differs from its original writer")
    # The complete checked module binds check()'s exception path and its callers;
    # these explicit edges expose which selected field recipe is being used.
    checker = method(owner, "check")
    machine.require(any(machine.matches(call, "self.add(criterion, name, exc.status, str(exc))") for call in calls(checker, "self.add")),
                    "Acceptance exception reason is not copied through the original check writer")
    artifact = method(owner, "artifact")
    guard = artifact.body[0]
    machine.require(isinstance(guard, ast.If) and machine.matches(guard.test, "not isinstance(ref, dict) or not ref.get('path') or not ref.get('sha256')")
                    and len(guard.body) == 1 and isinstance(guard.body[0], ast.Raise),
                    "Acceptance original artifact guard is unsupported")
    assert isinstance(guard, ast.If) and isinstance(guard.body[0], ast.Raise)
    raised = guard.body[0].exc
    machine.require(isinstance(raised, ast.Call) and machine.matches(raised.func, "EvidenceError")
                    and len(raised.args) == 1 and not raised.keywords,
                    "Acceptance artifact reason does not use the original error writer")
    assert isinstance(raised, ast.Call)
    missing = literal(raised.args[0])
    mappings = literal(machine.assignment(evaluator, "mappings"))
    measured = method(owner, "measured_check")
    machine.require(isinstance(measured.body[0], ast.Assign)
                    and machine.matches(measured.body[0].value, "self.artifact(self.index.get('checks', {}).get(check_id))"),
                    "Acceptance measured check does not reach its original artifact input")
    loop = one([s for s in evaluator.body if isinstance(s, ast.For) and machine.matches(s.iter, "mappings.items()")],
               "Acceptance original measured-check dispatcher is absent")
    machine.require(machine.matches(loop.target, "(criterion, names)") and len(loop.body) == 1
                    and isinstance(loop.body[0], ast.For) and machine.matches(loop.body[0].iter, "names")
                    and len(loop.body[0].body) == 1 and isinstance(loop.body[0].body[0], ast.Expr)
                    and machine.matches(loop.body[0].body[0].value, "self.check(criterion, name, lambda name=name: self.measured_check(name))"),
                    "Acceptance measured checks differ from the complete original dispatch loop")
    reasons: dict[tuple[str, str], tuple[str, str]] = {}
    for criterion, names in mappings.items():
        for name in names:
            reasons[(criterion, name)] = (missing, "UNVERIFIED")
    for criterion, name, invoked, expression in [
        ("AC06", "real_source_editorial_analysis", "analysis_check", "self.artifact(self.index.get('analysis'))"),
        ("AC12", "independent_audit_and_handoff", "audit_handoff", "self.artifact(self.index.get('snapshot'))"),
        ("AC13", "verified_public_release", "release_check", "self.artifact(self.index.get('release'))"),
    ]:
        dispatcher = one([c for c in body_call(evaluator, "self.check") if len(c.args) == 3
                          and machine.matches(c.args[0], repr(criterion)) and machine.matches(c.args[1], repr(name))],
                         "Acceptance selected check has no original dispatcher")
        machine.require(machine.matches(dispatcher.args[2], "self." + invoked), "Acceptance selected check calls another source method")
        function = method(owner, invoked)
        machine.require(isinstance(function.body[0], ast.Assign) and machine.matches(function.body[0].value, expression),
                        "Acceptance selected check does not read its original artifact input")
        reasons[(criterion, name)] = (missing, "UNVERIFIED")
    capability = one([s for s in evaluator.body if isinstance(s, ast.If) and machine.matches(s.test, "not self.capabilities")],
                     "Acceptance original capability branch is absent")
    machine.require(len(capability.body) == 1 and isinstance(capability.body[0], ast.Expr)
                    and isinstance(capability.body[0].value, ast.Call), "Acceptance capability branch has another writer")
    cap = capability.body[0].value
    machine.require(machine.matches(cap.func, "self.add") and len(cap.args) == 4 and not cap.keywords
                    and [literal(v) for v in cap.args[:3]] == ["AC01", "executed_reviewer_capability", "UNVERIFIED"],
                    "Acceptance capability reason has unrelated field identities")
    reasons[("AC01", "executed_reviewer_capability")] = (literal(cap.args[3]), "UNVERIFIED")
    for criterion, check, invoked, condition, status in [
        ("AC04", "source_conservation_and_final_mapping", "load_timeline_render", "not render.get('test_only') and render.get('profile') == 'master'", "FAIL"),
        ("AC08", "multimodal_union_coverage", "review_coverage", "self.source_domain is not None and self.output_domain is not None", "UNVERIFIED"),
    ]:
        one([c for c in body_call(evaluator, "self.check") if len(c.args) == 3
             and machine.matches(c.args[0], repr(criterion)) and machine.matches(c.args[1], repr(check))
             and machine.matches(c.args[2], "self." + invoked)], "Acceptance guard lacks its exact original check dispatcher")
        call = one([c for c in body_call(method(owner, invoked), "self.require") if c.args and machine.matches(c.args[0], condition)],
                   "Acceptance selected reason is not its original guard")
        machine.require(len(call.args) in {2, 3} and not call.keywords
                        and (literal(call.args[2]) if len(call.args) == 3 else "FAIL") == status,
                        "Acceptance original guard status differs")
        reasons[(criterion, check)] = (literal(call.args[1]), status)
    returned = one([s.value for s in evaluator.body if isinstance(s, ast.Return)], "Acceptance complete output writer is ambiguous")
    machine.require(isinstance(returned, ast.Dict), "Acceptance complete output is not a dictionary")
    assert isinstance(returned, ast.Dict)
    unpacked = [v for k, v in zip(returned.keys, returned.values, strict=True) if k is None]
    machine.require(len(unpacked) == 1 and machine.matches(unpacked[0], "self.identity"), "Acceptance output has unrelated unpacked fields")
    fields = machine.dict_fields(returned)
    machine.require(machine.matches(fields["criteria"], "list(self.criteria.values())"), "Acceptance output omits original criteria rows")
    order: dict[str, list[str]] = {key: [] for key in criteria}
    for call in body_call(evaluator, "self.check"):
        order[literal(call.args[0])].append(literal(call.args[1]))
    for identifier, names in mappings.items():
        order[identifier].extend(names)
    order["AC01"].append("executed_reviewer_capability")
    order["AC09"].append("open_P0_P1")
    finding = one([c for c in body_call(evaluator, "self.add")
                   if machine.matches(c.args[1], "'open_P0_P1'")],
                  "Acceptance finding row lacks its original writer")
    machine.require(machine.matches(finding, "self.add('AC09', 'open_P0_P1', 'FAIL' if open_findings else 'PASS', 'Unresolved P0/P1 must be zero', {'count': len(open_findings)})"),
                    "Acceptance finding row differs from its original count writer")
    aggregate = one([s for s in evaluator.body if isinstance(s, ast.For)
                     and machine.matches(s.iter, "self.criteria.values()")],
                    "Acceptance criterion aggregation is absent")
    expected_aggregate = ast.parse("for criterion_result in self.criteria.values():\n statuses = [item['status'] for item in criterion_result['checks']]\n criterion_result['status'] = 'FAIL' if 'FAIL' in statuses else 'PASS' if statuses and all(status == 'PASS' for status in statuses) else 'UNVERIFIED'").body[0]
    machine.require(ast.dump(aggregate) == ast.dump(expected_aggregate),
                    "Acceptance criterion aggregation differs from the original writer")
    dependency = one([s for s in evaluator.body if isinstance(s, ast.If)
                      and machine.matches(s.test, "not media_dependencies_ok and self.criteria['AC09']['status'] == 'PASS'")],
                     "Acceptance media dependency writer is absent")
    expected_dependency = ast.parse("if not media_dependencies_ok and self.criteria['AC09']['status'] == 'PASS':\n self.criteria['AC09']['status'] = 'UNVERIFIED'\n self.add('AC09', 'G0_G5_dependencies', 'UNVERIFIED', 'Final master requires all preceding media gates')").body[0]
    machine.require(ast.dump(dependency) == ast.dump(expected_dependency),
                    "Acceptance media dependency row differs from its original writer")
    return {"criteria": criteria, "reasons": reasons, "provenance": literal(fields["provenance_limitations"]),
            "check_order": order, "media_ids": literal(machine.assignment(evaluator, "media_ids")),
            "finding_reason": literal(finding.args[3]),
            "dependency_reason": literal(dependency.body[1].value.args[3]),
            "report_fields": set(fields) | IDENTITY_FIELDS,
            "schema": literal(machine.assignment(acceptance, "EVALUATOR_VERSION"))}


def criterion_writers(report: dict[str, Any], recipe: dict[str, Any]) -> None:
    """Check recorded row construction only; never evaluate its evidence."""
    rows = {row["id"]: row for row in report["criteria"]}
    aggregated = {}
    for identifier, row in rows.items():
        checks = row["checks"]
        names = [check["check_id"] for check in checks]
        expected = recipe["check_order"][identifier]
        if identifier == "AC01":
            machine.require(len(names) >= len(expected) and names[:1] == expected[:1]
                            and all(name == expected[-1] for name in names[1:]),
                            "Acceptance capability check sequence differs from its original dispatcher")
        elif identifier == "AC09":
            machine.require(names == expected or names == [*expected, "G0_G5_dependencies"],
                            "Acceptance output check sequence differs from its original dispatcher")
        else:
            machine.require(names == expected, "Acceptance fixed check sequence differs from its original dispatcher")
        machine.require(row["evidence_refs"] == [], "Acceptance criterion evidence refs have no original writer")
        # The dependency row is appended after the original criterion reduction.
        initial = checks[:-1] if identifier == "AC09" and names[-1] == "G0_G5_dependencies" else checks
        statuses = [check["status"] for check in initial]
        aggregated[identifier] = ("FAIL" if "FAIL" in statuses else "PASS"
                                  if statuses and all(status == "PASS" for status in statuses) else "UNVERIFIED")
    machine.require(isinstance(report["open_findings"], list) and len(report["open_findings"]) <= MAX_ROWS,
                    "Acceptance finding table is malformed or oversized")
    finding = rows["AC09"]["checks"][recipe["check_order"]["AC09"].index("open_P0_P1")]
    expected_finding = {"check_id": "open_P0_P1", "status": "FAIL" if report["open_findings"] else "PASS",
                        "reason": recipe["finding_reason"], "measurements": {"count": len(report["open_findings"])}}
    machine.require(canonical(finding) == canonical(expected_finding),
                    "Acceptance finding row differs from its recorded original count relation")
    needs_dependency = (not all(aggregated[key] == "PASS" for key in recipe["media_ids"])
                        and aggregated["AC09"] == "PASS")
    output_checks = rows["AC09"]["checks"]
    machine.require((output_checks[-1]["check_id"] == "G0_G5_dependencies") is needs_dependency,
                    "Acceptance output dependency row differs from its original conditional writer")
    if needs_dependency:
        machine.require(output_checks[-1] == {"check_id": "G0_G5_dependencies", "status": "UNVERIFIED",
                                              "reason": recipe["dependency_reason"], "measurements": None},
                        "Acceptance output dependency row differs from its complete original constructor")
        aggregated["AC09"] = "UNVERIFIED"
    machine.require(all(row["status"] == aggregated[identifier] for identifier, row in rows.items()),
                    "Acceptance criterion status differs from its original check aggregation")


def declared_ref(value: Any) -> bool:
    return (isinstance(value, dict) and set(value) == {"path", "sha256"}
            and isinstance(value["path"], str) and Path(value["path"]).is_absolute()
            and isinstance(value["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", value["sha256"]) is not None)


def verify(selected: dict[str, Any], root: Path, read: machine.Read, document: machine.Document) -> dict[str, Any]:
    machine.require(set(selected) == {"schema_version", "family", "command", "stdout", "sources", "saved_copies"}
                    and selected["schema_version"] == "review-machine-field-authority/v1"
                    and selected["family"] == "acceptance_cli_report", "Unsupported acceptance field authority")
    sources = selected["sources"]
    machine.require(isinstance(sources, dict) and set(sources) == set(grammar.MODULE_SHAPES) | {"pyproject.toml"},
                    "Acceptance original source closure is incomplete")
    refs = [selected["command"], selected["stdout"], *sources.values()]
    trees = {}
    for name, source in sources.items():
        _, data = read(source)
        if name == "pyproject.toml":
            try:
                metadata = tomllib.loads(data.decode("utf-8"))
            except (ValueError, UnicodeError) as exc:
                raise machine.TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Acceptance original console metadata is malformed") from exc
            project_metadata = metadata.get("project")
            machine.require(isinstance(project_metadata, dict) and isinstance(project_metadata.get("scripts"), dict)
                            and project_metadata["scripts"].get("talkcut") == "talkcut.__main__:main",
                            "Acceptance original console entry point selects another producer")
            continue
        tree = machine.syntax(data)
        machine.require(hashlib.sha256(ast.dump(tree).encode()).hexdigest() in grammar.MODULE_SHAPES[name],
                        "Acceptance complete original source module is unsupported")
        trees[name] = tree
    recipe = source_recipe(trees)
    report = document(selected["stdout"])
    machine.require(set(report) == recipe["report_fields"] and report["schema_version"] == recipe["schema"]
                    and report["evaluator_version"] == recipe["schema"], "Acceptance report differs from its complete original output shape")
    files = report["files"]
    machine.require(isinstance(files, dict) and 0 < len(files) <= MAX_ROWS
                    and all(isinstance(k, str) and not Path(k).is_absolute() and '..' not in Path(k).parts
                            and isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for k, v in files.items())
                    and hashlib.sha256(canonical(files)).hexdigest() == report["code_tree_hash"]
                    and isinstance(report["code_revision"], str) and re.fullmatch(r"[a-f0-9]{40}", report["code_revision"]),
                    "Acceptance complete recorded source identity is malformed")
    machine.require(all(files.get(name) == source["sha256"] for name, source in sources.items()),
                    "Acceptance supplied source differs from its original recorded map")
    criteria = report["criteria"]
    machine.require(isinstance(criteria, list) and len(criteria) == len(recipe["criteria"]), "Acceptance full criterion denominator differs")
    for row, (identifier, description) in zip(criteria, recipe["criteria"].items(), strict=True):
        machine.require(isinstance(row, dict) and set(row) == {"id", "description", "status", "checks", "evidence_refs"}
                        and row["id"] == identifier and row["description"] == description
                        and isinstance(row["status"], str) and row["status"] in {"PASS", "FAIL", "UNVERIFIED"}
                        and isinstance(row["checks"], list) and len(row["checks"]) <= MAX_ROWS
                        and isinstance(row["evidence_refs"], list) and len(row["evidence_refs"]) <= MAX_ROWS,
                        "Acceptance criterion differs from its complete original row constructor")
        for check in row["checks"]:
            machine.require(isinstance(check, dict) and set(check) == {"check_id", "status", "reason", "measurements"}
                            and isinstance(check["check_id"], str) and isinstance(check["reason"], str)
                            and isinstance(check["status"], str) and check["status"] in {"PASS", "FAIL", "UNVERIFIED"}, "Acceptance check has malformed original row fields")
    criterion_writers(report, recipe)
    states = {row["id"]: row["status"] for row in criteria}
    ready = all(states[f"AC{i:02}"] == "PASS" for i in range(1, 13))
    achieved = ready and states["AC13"] == "PASS"
    status = "PASS" if achieved else "FAIL" if "FAIL" in states.values() else "UNVERIFIED"
    media = all(states[key] == "PASS" for key in ("AC01", "AC02", "AC04", "AC05", "AC06", "AC07", "AC08", "AC09"))
    machine.require(report["release_ready"] is ready and report["goal_achieved"] is achieved and report["status"] == status
                    and report["media_state"] == ("READY_FOR_OWNER" if media else "BLOCKED")
                    and report["owner_acceptance"] == "pending"
                    and isinstance(report["source_hashes"], dict) and isinstance(report["coverage"], dict)
                    and all(isinstance(report[name], list) and len(report[name]) <= MAX_ROWS
                            for name in ("uncovered_intervals", "invalid_evidence", "open_findings")),
                    "Acceptance recorded output is inconsistent with its finite original row/flag writer")
    command = document(selected["command"])
    machine.require(command.get("stdout") == selected["stdout"] and command.get("cwd") == str(root)
                    and type(command.get("exit_code")) is int and command["exit_code"] == (0 if achieved else 1)
                    and isinstance(command.get("started_at"), str) and isinstance(command.get("finished_at"), str),
                    "Acceptance original command does not bind its exact output and root")
    argv = command.get("argv")
    machine.require(isinstance(argv, list) and all(isinstance(v, str) for v in argv), "Acceptance original command argv is malformed")
    assert isinstance(argv, list)
    if command.get("schema_version") == "actual-cli-checkpoint/v1":
        machine.require(set(command) == {"argv", "code_after", "code_before", "current_report", "cwd", "exit_code", "finished_at", "previous_report", "schema_version", "source_project_modified", "started_at", "stderr", "stdout"}
                        and command["code_before"] == command["code_after"] == {k: report[k] for k in IDENTITY_FIELDS}
                        and command["source_project_modified"] is False
                        and declared_ref(command["current_report"]) and declared_ref(command["previous_report"])
                        and argv[:6] == ["uv", "run", "--locked", "talkcut", "acceptance", "evaluate"],
                        "Acceptance original checkpoint command/source identity differs")
        tail = argv[6:]
    else:
        machine.require(command.get("schema_version") == "verification-command/v1"
                        and set(command) == {"argv", "cwd", "error", "exit_code", "finished_at", "interrupted", "name", "schema_version", "started_at", "status", "stderr", "stdout", "timed_out", "timeout_seconds", "wall_seconds"}
                        and command["error"] is None and command["interrupted"] is False and command["timed_out"] is False
                        and command["status"] == ("PASS" if command["exit_code"] == 0 else "FAIL")
                        and isinstance(command["name"], str) and bool(command["name"])
                        and all(type(command[name]) in {int, float} and math.isfinite(command[name]) and command[name] >= 0
                                for name in ("timeout_seconds", "wall_seconds"))
                        and (argv[:5] == [str(root / '.venv/bin/python3'), "-m", "talkcut", "acceptance", "evaluate"]
                             or argv[:6] == ["uv", "run", "--locked", "talkcut", "acceptance", "evaluate"]),
                        "Acceptance original verification command is unsupported")
        tail = argv[6:] if argv[0] == "uv" else argv[5:]
    machine.require(len(tail) == 6 and Path(tail[0]).is_absolute() and tail[1] == '--render'
                    and re.fullmatch(r'[a-f0-9]{64}', tail[2]) and tail[3] == '--contract'
                    and Path(tail[4]).is_absolute() and tail[5] == '--json', "Acceptance command does not select the exact evaluate form")
    project = Path(tail[0])
    _, stdout_bytes = read(selected['stdout'])
    _, stderr = read(command['stderr'])
    refs.append(command['stderr'])
    machine.require(not stderr and stdout_bytes == (json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2) + '\n').encode(),
                    "Acceptance stdout differs from its complete original CLI serializer")
    # The exact complete module shapes bind parser -> execute -> evaluate ->
    # atomic_json/print. This field validator never runs that original chain.
    parents = {selected['stdout']['path']: {'ref': selected['stdout'], 'report': report, 'original': selected['stdout']}}
    copies = selected['saved_copies']
    machine.require(isinstance(copies, list) and len(copies) <= 1, "Acceptance saved copies are not the bounded original output")
    for copy in copies:
        machine.require(isinstance(copy, dict) and set(copy) == {'original', 'snapshot'}
                        and declared_ref(copy['original']) and declared_ref(copy['snapshot'])
                        and command.get('current_report') == copy['original']
                        and copy['original']['path'] == str(project / 'reports/acceptance-latest.local.json')
                        and copy['original']['sha256'] == copy['snapshot']['sha256'], "Acceptance saved copy lacks its original command destination")
        path, raw = read(copy['snapshot'])
        machine.require(raw == canonical(report) + b'\n' and str(path) not in parents,
                        "Acceptance saved copy differs from the complete original canonical writer")
        parents[str(path)] = {'ref': copy['snapshot'], 'report': report, 'original': copy['original']}
        refs.append(copy['snapshot'])
    return {'source': sources['src/talkcut/acceptance.py'],
            'original_source': {'path': str(root / 'src/talkcut/acceptance.py'), 'sha256': sources['src/talkcut/acceptance.py']['sha256']},
            'source_dependencies': [{'original_path': str(root / name), 'snapshot': sources[name]} for name in sorted(sources)],
            'refs': refs, 'parents': parents, 'recipe': recipe, 'project': project}


def original_parent(bound: dict[str, Any], parent: Any) -> dict[str, str]:
    machine.require(isinstance(parent, dict) and isinstance(parent.get('path'), str)
                    and parent['path'] in bound['parents'] and bound['parents'][parent['path']]['ref'] == parent,
                    "Acceptance selected parent is outside its original output relation")
    return bound['parents'][parent['path']]['original']


def project_field(bound: dict[str, Any], parent: Any, selector: Any) -> dict[str, Any]:
    machine.require(isinstance(selector, list) and selector and all(type(v) in {str, int} for v in selector),
                    "Acceptance field selector is malformed")
    original_parent(bound, parent)
    report = bound['parents'][parent['path']]['report'];recipe = bound['recipe']
    row: Any = report
    try:
        for part in selector[:-1]:
            machine.require(not isinstance(part, int) or part >= 0, "Acceptance selector has a negative index")
            row = row[part]
        value = row[selector[-1]]
    except (KeyError, IndexError, TypeError) as exc:
        raise machine.TalkCutError('PUBLICATION_PRIVACY_UNVERIFIED', 'Acceptance field selector does not exist') from exc
    supported = False
    if selector == ['provenance_limitations']:
        supported = value == recipe['provenance']
    elif len(selector) == 3 and selector[0] == 'criteria' and type(selector[1]) is int and selector[2] == 'description':
        supported = value == recipe['criteria'].get(row['id'])
    elif len(selector) == 5 and selector[0] == 'criteria' and type(selector[1]) is int and selector[2] == 'checks' and type(selector[3]) is int and selector[4] == 'reason':
        criterion = report['criteria'][selector[1]]['id']
        expected = recipe['reasons'].get((criterion, row['check_id']))
        supported = expected is not None and (value, row['status']) == expected and row['measurements'] is None
    machine.require(supported and isinstance(value, str), 'Acceptance field is not a supported original literal/call-row relation')
    return {'value': value, 'row': row, 'extractions': [{'edge': selector, 'value': value}]}
