"""Attribute exact original oversized-inventory fields without executing producers."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from . import privacy_machine_origins as machine
from . import privacy_oversized_grammar as grammar


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def original_return(tree: ast.Module, name: str) -> dict[str, ast.expr]:
    function = machine.named_function(tree, name)
    machine.require(isinstance(function.body[-1], ast.Return) and isinstance(function.body[-1].value, ast.Dict),
                    "Oversized original producer has no final direct dictionary return")
    assert isinstance(function.body[-1], ast.Return) and isinstance(function.body[-1].value, ast.Dict)
    return machine.dict_fields(function.body[-1].value)


def verify(selected: dict[str, Any], root: Path, read: machine.Read,
           document: machine.Document) -> dict[str, Any]:
    fields = {"schema_version", "family", "review", "result", "source", "script", "helper", "challenge"}
    machine.require(set(selected) == fields and selected["schema_version"] == "review-machine-field-authority/v1"
                    and selected["family"] == "oversized_stdout_inventory", "Unsupported oversized origin authority fields")
    review, result, challenge = (document(selected[key]) for key in ("review", "result", "challenge"))
    machine.require(review.get("schema_version") == "independent-staged-privacy-review/v1"
                    and review.get("source_before") == review.get("source_after") == selected["source"],
                    "Oversized original review does not bind the unchanged source")
    executions = review.get("independent_executions")
    machine.require(isinstance(executions, list), "Oversized original independent execution list is absent")
    assert isinstance(executions, list)
    owned = machine.references(executions)
    machine.require(all(selected[key] in owned for key in ("result", "script", "helper", "challenge")),
                    "Oversized input, script, helper or result is outside its original review")
    commands = [row for row in executions if isinstance(row, dict)
                and row.get("result") == selected["result"] and row.get("script") == selected["script"]]
    machine.require(len(commands) == 1 and set(commands[0]) == {
        "local_tool_session_id", "observed_exit_code", "result", "script", "stdout", "stderr"}
        and type(commands[0]["observed_exit_code"]) is int and commands[0]["observed_exit_code"] == 0,
        "Oversized result has no exact original independent output record")
    command = commands[0]
    _, stderr = read(command["stderr"])
    stdout = document(command["stdout"])
    machine.require(not stderr and set(stdout) == {"report", "binary_named_stdout_in_inventory",
                    "external_reference_in_inventory", "unresolved", "classification_status"}
                    and stdout["report"] == selected["result"], "Oversized original stdout/result relation is incomplete")
    machine.require(set(result) == {"schema_version", "at", "source", "script", "challenge", "inventory",
                    "binary_named_stdout_in_inventory", "external_reference_in_inventory", "unresolved",
                    "classification_status", "scope"}
                    and result["schema_version"] == "independent-oversized-stdout-inventory-probe/v1"
                    and all(result[key] == selected[key] for key in ("source", "script", "challenge"))
                    and isinstance(result["at"], str) and result["at"]
                    and all(stdout[key] == result[key] for key in stdout if key != "report"),
                    "Oversized original report fields differ from its complete recorded writer")
    script_path, script_bytes = read(selected["script"])
    helper_path, helper_bytes = read(selected["helper"])
    _, source_bytes = read(selected["source"])
    source = machine.syntax(source_bytes)
    machine.require_invocation_shape(source, "module")
    machine.require(hashlib.sha256(machine.invocation_shape(source, "module").encode()).hexdigest() == grammar.SOURCE_MODULE,
                    "Oversized source differs from the complete original source grammar")
    script = machine.syntax(script_bytes)
    boot = machine.expression('exec((HERE / "probe_auxiliary.py").read_text().split("for key in [\'runner\'")[0])')
    boots = [n.value for n in script.body if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
             and ast.dump(n.value) == ast.dump(boot)]
    machine.require(len(boots) == 1 and helper_path == script_path.parent / "probe_auxiliary.py",
                    "Oversized helper bootstrap is not the exact original read-text prefix")
    prefix = machine.helper_prefix(helper_bytes, "for key in ['runner'")
    machine.require_invocation_shape(prefix, "helper")
    module = machine.loader(prefix, root, script_path, selected["source"])
    machine.require(module == "privacy", "Oversized original loaded module binding differs")
    machine.direct_script_control_flow(prefix)
    machine.direct_script_control_flow(script, original_exec=boots[0])
    machine.preserve_binding(prefix, module, assignment_count=1)
    machine.preserve_binding(script, module, assignment_count=0, mutable_methods={"build_private_inventory"})
    paths = machine.path_assignments(script, root, script_path)
    paths.update({k: v for k, v in machine.path_assignments(prefix, root, script_path).items() if k not in paths})
    machine.require(paths.get("ROOT") == root, "Oversized helper repository root differs")
    case_path = machine.independent_case_path(script, prefix, root, script_path)
    run_call = machine.assignment(script, "runref")
    machine.require(isinstance(run_call, ast.Call) and machine.matches(run_call.func, "artifact_ref")
                    and len(run_call.args) == 1 and not run_call.keywords,
                    "Oversized original failure-run reference is not a fixed artifact expression")
    assert isinstance(run_call, ast.Call)
    run_path = machine.path_value(run_call.args[0], paths, root, script_path)
    normalized = copy.deepcopy(script)
    assignments = [n for n in normalized.body if isinstance(n, ast.Assign) and len(n.targets) == 1
                   and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "runref"]
    machine.require(len(assignments) == 1, "Oversized original failure-run binding is duplicated")
    assignments[0].value = ast.Name(id="VERIFIED_FAILURE_RUN", ctx=ast.Load())
    machine.require(ast.dump(normalized) == ast.dump(machine.syntax_text(grammar.PROBE)),
                    "Oversized probe differs from its complete original invocation and output grammar")
    report_fields = machine.dict_fields(machine.assignment(script, "report"))
    machine.require(result["scope"] == machine.literal(report_fields["scope"]),
                    "Oversized result scope differs from its original report writer")
    machine.require(selected["result"]["path"] == str(script_path.parent / "oversized-stdout-inventory-result.json")
                    and selected["challenge"]["path"] == str(script_path.parent / "bounded-closure-results.json")
                    and result["inventory"]["path"] == str(script_path.parent / "oversized-stdout-inventory.json"),
                    "Oversized original input or output path differs from the complete probe writer")
    machine.require(challenge.get("source") == selected["source"] and isinstance(challenge.get("cases"), list),
                    "Oversized challenge is not bound to its original source")
    cases = [r for r in challenge["cases"] if isinstance(r, dict) and r.get("case") == "oversized_binary_named_stdout"]
    machine.require(len(cases) == 1, "Oversized probe does not select one exact original challenge case")
    case = cases[0]
    for key in ("input", "actual_stdout", "actual_external_ref"):
        machine.row_identity(case.get(key))
    parent_ref = result["inventory"]
    parent = document(parent_ref)
    builder = machine.named_function(source, "build_private_inventory")
    machine.require_invocation_shape(builder, "builder")
    output = original_return(source, "build_private_inventory")
    machine.require(set(parent) == set(output) and parent["schema_version"] == machine.literal(output["schema_version"])
                    and parent["project"] == str(case_path / "project")
                    and parent["classification_status"] == result["classification_status"] == "UNVERIFIED"
                    and parent["unresolved"] == result["unresolved"], "Oversized parent is not the complete original inventory output")
    bindings = [n for n in builder.body if isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Tuple) and isinstance(n.value, ast.Call)
                and machine.matches(n.value.func, "_known_private_inventory")]
    machine.require(len(bindings) == 1 and machine.matches(bindings[0].targets[0], "(_, _, known)")
                    and machine.matches(output["known_graph"], "known"),
                    "Oversized builder does not return its original invoked known graph")
    project_ref = {"path": str(case_path / "project/project.json"), "sha256": parent["dependencies"]["project_hash"]}
    project = document(project_ref)
    sources = {k: v["sha256"] for k, v in project["sources"].items()}
    known = parent["known_graph"]
    machine.require(parent["dependencies"]["source_hashes"] == sources == known.get("source_hashes")
                    and known.get("project") == parent["project"], "Oversized original project/source identities differ")
    entries = parent["entries"]
    machine.require(isinstance(entries, list) and all(isinstance(r, dict) and isinstance(r.get("path"), str) for r in entries)
                    and [r["path"] for r in entries] == sorted({r["path"] for r in entries})
                    and type(parent["entry_count"]) is int and parent["entry_count"] == len(entries)
                    and parent["mandatory_private_count"] == sum(r.get("classification") != "UNCLASSIFIED" for r in entries),
                    "Oversized original complete entry denominator differs")
    by_path = {r["path"]: r for r in entries}
    for key, field in (("actual_stdout", "binary_named_stdout_in_inventory"),
                       ("actual_external_ref", "external_reference_in_inventory")):
        actual = case[key]
        machine.require(type(result[field]) is bool and result[field] == (actual["path"] in by_path),
                        "Oversized report boolean differs from its exact complete entry projection")
        if actual["path"] in by_path:
            machine.require(by_path[actual["path"]]["sha256"] == actual["sha256"],
                            "Oversized report's selected entry has another digest")
    observations = known.get("synthetic_failure_fixtures")
    machine.require(isinstance(observations, list) and len(observations) == 1 and isinstance(observations[0], dict),
                    "Oversized original inventory must retain its single failure observation")
    observation = observations[0]
    run_ref = observation["run"]
    machine.require(run_ref["path"] == str(run_path) and observation["current_reproduction"]["bundle"] == case["input"],
                    "Oversized call's original failure run or selected replay input differs")
    raw_run = document(run_ref)
    replay = document(case["input"])
    machine.require(observation["request"] == raw_run["request"] and observation["harness"] == raw_run["harness"]
                    and raw_run.get("test_only") is True and raw_run.get("actual_dgist_acceptance") is False
                    and observation.get("completeness") == "UNVERIFIED"
                    and replay.get("schema_version") == "synthetic-privacy-replay/v1" and replay.get("test_only") is True,
                    "Oversized failure/replay metadata was relabeled or changed")
    auxiliary = known.get("auxiliary_execution_sources")
    metadata = known.get("auxiliary_metadata_history")
    machine.require(isinstance(auxiliary, list) and len(auxiliary) == 1
                    and isinstance(metadata, list) and len(metadata) == 1,
                    "Oversized original setup's exact auxiliary inputs are incomplete")
    original_source = case_path / "project/capability/runtime/runner.py"
    original_metadata = case_path / "project/capability/state.json"
    machine.require(auxiliary[0]["original_reference"]["path"] == str(original_source)
                    and auxiliary[0]["preserved_ref"]["path"] == str(case_path / "preserved-old-source.py")
                    and metadata[0]["original_reference"]["path"] == str(original_metadata)
                    and metadata[0]["preserved_ref"]["path"] == str(case_path / "preserved-old-metadata"),
                    "Oversized helper-return kwargs differ from its original setup paths")
    refs = [selected[k] for k in ("review", "result", "source", "script", "helper", "challenge")]
    refs += [command["stdout"], command["stderr"], parent_ref, project_ref, run_ref, case["input"]]
    bound = {"source": selected["source"], "source_tree": source, "source_data": source_bytes,
            "parents": {parent_ref["path"]: {"ref": parent_ref, "prefix": ["known_graph"], "value": parent}},
            "refs": refs, "oversized": True, "parent_ref": parent_ref, "parent": parent,
            "parent_content": canonical(parent), "run": raw_run, "replay": replay,
            "challenge_case": case, "read": read, "document": document}
    bound["extra_projections"] = extra_fields(bound)
    return bound


def project_field(bound: dict[str, Any], parent_ref: dict[str, Any], selector: list[Any]) -> dict[str, Any]:
    machine.require(parent_ref == bound["parent_ref"] and canonical(bound["parent"]) == bound["parent_content"],
                    "Oversized original parent changed or is outside its authority")
    machine.require(isinstance(selector, list) and bool(selector) and all(type(part) in {str, int} for part in selector),
                    "Oversized field selector must be a nonempty list of exact string or integer members")
    extra = bound["extra_projections"].get(tuple(selector))
    if extra is not None:
        return extra
    return machine.fixed_inventory_field(bound, parent_ref, selector)


def extra_fields(bound: dict[str, Any]) -> dict[tuple[Any, ...], dict[str, Any]]:
    """Six literal leaves from the already bound complete original call chain.

    Replay metadata is retained as recorded input. This attributes its fixed scope;
    it neither reruns historical controls nor validates their acceptance verdicts.
    """
    parent, tree = bound["parent"], bound["source_tree"]
    known = parent["known_graph"]
    observations = known["synthetic_failure_fixtures"]
    observation, raw, replay = observations[0], bound["run"], bound["replay"]
    projections: dict[tuple[Any, ...], dict[str, Any]] = {}

    def emit(edge: list[Any], row: dict[str, Any], value: str) -> None:
        machine.require(isinstance(value, str) and row.get(edge[-1]) == value,
                        "Oversized extra field differs from its original literal writer")
        projections[tuple(edge)] = {"value": value, "row": row, "source": bound["source"],
                                   "extractions": [{"edge": edge, "value": value}]}

    def data(ref: dict[str, Any]) -> Any:
        result = bound["document"](ref)
        if ref not in bound["refs"]:
            bound["refs"].append(ref)
        return result

    def bytes_ref(ref: dict[str, Any]) -> None:
        machine.row_identity(ref)
        machine.require(set(ref) == {"path", "sha256"}, "Oversized byte reference has extra fields")
        bound["read"](ref)
        if ref not in bound["refs"]:
            bound["refs"].append(ref)

    emit(["scope"], parent, machine.literal(original_return(tree, "build_private_inventory")["scope"]))
    producer = machine.named_function(tree, "_known_private_inventory")
    add = machine.named_function(producer, "add")
    assignments = [n for n in ast.walk(add) if isinstance(n, ast.Assign) and len(n.targets) == 1
                   and machine.matches(n.targets[0], "auxiliary_observations[key]")]
    machine.require(len(assignments) == 1, "Oversized metadata has no unique original row writer")
    fields = machine.dict_fields(assignments[0].value)
    row = known["auxiliary_metadata_history"][0]
    machine.require(set(row) == set(fields), "Oversized metadata complete row has unrelated fields")
    for key in ("bytes_status", "claim_status", "classification", "scope"):
        machine.require(row[key] == machine.literal(fields[key]), "Oversized metadata literal relationship differs")
    old, saved, current = (row[k] for k in ("original_reference", "preserved_ref", "current_ref"))
    machine.row_identity(old)
    machine.require(set(old) == {"path", "sha256"} and old["sha256"] == saved["sha256"]
                    and old["path"] == current["path"] and old["sha256"] != current["sha256"],
                    "Oversized metadata original/preserved/current relationship differs")
    bytes_ref(saved)
    bytes_ref(current)
    emit(["known_graph", "auxiliary_metadata_history", 0, "scope"], row, machine.literal(fields["scope"]))

    # The input rows, complete project source maps and actual artifact table
    # determine all three original failure rows, including an unchanged speaker.
    artifacts = raw.get("artifacts")
    artifact_limit = ast.literal_eval(machine.assignment(tree, "MAX_UNITS"))
    machine.require(type(artifact_limit) is int and artifact_limit > 0
                    and isinstance(artifacts, list) and 0 < len(artifacts) <= artifact_limit,
                    "Oversized original failure artifact denominator is absent")
    by_path: dict[str, dict[str, Any]] = {}
    for ref in artifacts:
        machine.row_identity(ref)
        machine.require(set(ref) == {"path", "sha256"} and ref["path"] not in by_path,
                        "Oversized original failure artifact table is ambiguous")
        by_path[ref["path"]] = ref
    pairs = raw.get("cases", {}).get("wrong_hashes", {}).get("pairs")
    machine.require(isinstance(pairs, list) and [p.get("name") for p in pairs] == ["source_bytes", "output_bytes"],
                    "Oversized original wrong-hash pair order differs")
    failure = machine.named_function(tree, "_synthetic_failure_inventory")
    row_writers = [n.value for n in ast.walk(failure) if isinstance(n, ast.Assign) and len(n.targets) == 1
                   and machine.matches(n.targets[0], "row")]
    machine.require(len(row_writers) == 1, "Oversized original failure row writer is ambiguous")
    written = machine.dict_fields(row_writers[0])
    reason = machine.literal(written["reason"])
    expected_rows = []
    for pair in pairs:
        a, b = data(pair["control_input"]), data(pair["mutation_input"])
        if pair["name"] == "source_bytes":
            project_refs = [by_path.get(str(Path(value["project"]) / "project.json")) for value in (a, b)]
            machine.require(all(ref is not None for ref in project_refs),
                            "Oversized original wrong-hash project is outside its artifact table")
            projects = []
            for ref in project_refs:
                assert ref is not None
                projects.append(data(ref))
            original, mutant = projects
            machine.require(set(original["sources"]) == set(mutant["sources"]) == {"screen", "speaker"},
                            "Oversized wrong-hash complete source roles differ")
            changes = [(mutant["sources"][role], original["sources"][role]) for role in original["sources"]]
        else:
            changes = [(b["output"], a["output"])]
        for declared, original in changes:
            declared = {key: declared[key] for key in ("path", "sha256")}
            original = {key: original[key] for key in ("path", "sha256")}
            actual = by_path.get(declared["path"])
            machine.require(actual is not None and by_path.get(original["path"]) == original
                            and original["sha256"] == declared["sha256"],
                            "Oversized wrong-hash original/current bytes are not exact artifact members")
            assert actual is not None
            bytes_ref(original)
            bytes_ref(actual)
            expected_rows.append({"declared_reference": declared, "preserved_original": original,
                                  "actual_current": actual, "case": "wrong_hashes." + pair["name"],
                                  "historical_run": observation["run"], "classification": "UNCLASSIFIED",
                                  "status": "MEASURED", "reason": reason})
    machine.require(len(expected_rows) == 3 and observation["rows"] == expected_rows,
                    "Oversized original synthetic rows differ from their complete input projections")
    for index, row in enumerate(expected_rows):
        emit(["known_graph", "synthetic_failure_fixtures", 0, "rows", index, "reason"], row, reason)

    reproduction = observation["current_reproduction"]
    fields = original_return(tree, "_verified_synthetic_replay")
    machine.require(set(reproduction) == set(fields), "Oversized recorded replay output has unrelated fields")
    for name in ("external_inputs", "external_tool_links"):
        machine.require(machine.matches(fields[name], "list(" + name + ".values())")
                        and isinstance(reproduction[name], list),
                        "Oversized recorded replay external table differs from its original list writer")
    before, after = data(replay["before"]), data(replay["after"])
    fixture = data(replay["fixture"])
    _, steps_bytes = bound["read"](fixture["executions"])
    bound["refs"].append(fixture["executions"])

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        machine.require(len(pairs) == len(dict(pairs)), "Oversized execution ledger has duplicate JSON keys")
        return dict(pairs)

    try:
        steps = json.loads(steps_bytes, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as exc:
        raise machine.TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Oversized execution ledger is not bounded JSON") from exc
    machine.require(before == after and reproduction["artifacts"] == replay["artifacts"]
                    and replay["artifact_count"] == len(replay["artifacts"])
                    and reproduction["execution"] == replay["execution"]
                    and reproduction["fixture"] == replay["fixture"]
                    and reproduction["executions"] == fixture["executions"]
                    and reproduction["generator"] == before["generator"]
                    and reproduction["harness"] == before["harness"]
                    and reproduction["code_tree_hash"] == before["code_identity"]["code_tree_hash"]
                    and reproduction["technical_validation"] == bound["challenge_case"]["technical_validation"]
                    and isinstance(steps, list) and len(steps) == 14
                    and steps[0]["name"] == "01-generate"
                    and reproduction["generator_argv_prefix"] == steps[0]["argv"][:-1]
                    and reproduction["output_hashes"] == {stage: value["output"]["sha256"] for stage, value in fixture["outputs"].items()},
                    "Oversized recorded replay scope lacks its complete original input relationships")
    source_path = str(Path(replay["fixture"]["path"]).parent / "synthetic.mp4")
    matches = [ref for ref in replay["artifacts"] if ref["path"] == source_path]
    machine.require(len(matches) == 1 and matches[0]["sha256"] == reproduction["source_sha256"],
                    "Oversized recorded replay source identity differs")
    emit(["known_graph", "synthetic_failure_fixtures", 0, "current_reproduction", "scope"],
         reproduction, machine.literal(fields["scope"]))
    return projections
