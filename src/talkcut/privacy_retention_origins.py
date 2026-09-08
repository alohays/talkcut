"""Unwired, closed retention-audit machine leaves; no execution or approval.

The caller's independently reviewed roots are trust inputs. This module verifies
recorded source/writer/whole-parent relations, not historical execution. All
unselected values and original file hashes remain private inputs.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

from . import privacy_retention_grammar as grammar
from .privacy_machine_origins import (
    Document,
    Read,
    assignment,
    block_matches,
    dict_fields,
    instantiate,
    lexical,
    literal,
    matches,
    named_function,
    path_assignments,
    require,
    row_identity,
    syntax,
)

MAX_RETENTION_BYTES = 16 * 1024 * 1024


def reference(value: Any) -> None:
    row_identity(value)
    require(set(value) == {"path", "sha256"} and Path(value["path"]).is_absolute(),
            "Retention authority is not an exact absolute artifact reference")


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def script_shape(tree: ast.Module) -> str:
    shaped = copy.deepcopy(tree)
    for node in shaped.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {"PROJECT", "raw_input_path", "previous_path", "current_r3_path", "runtime"}):
            node.value = ast.Name(id="BOUND_" + node.targets[0].id, ctx=ast.Load())
        if (isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare)
                and matches(node.test.left, 'source_before["sha256"]')):
            node.test.comparators = [ast.Name(id="BOUND_SOURCE_SHA", ctx=ast.Load())]
    for walked in ast.walk(shaped):
        if (isinstance(walked, ast.Compare) and matches(walked.left, "p.name") and len(walked.comparators) == 1
                and isinstance(walked.comparators[0], ast.Constant)):
            walked.comparators = [ast.Name(id="BOUND_PLAIN_TRANSCRIPT_NAME", ctx=ast.Load())]
    return ast.dump(shaped)


def shape(tree: ast.Module, role: str) -> None:
    rendered = script_shape(tree) if role == "script" else ast.dump(tree)
    allowed = {"script": grammar.SCRIPT_SHAPES, "source": grammar.SOURCE_SHAPES,
               "old_scanner": grammar.OLD_SCANNER_SHAPES}[role]
    require(hashlib.sha256(rendered.encode()).hexdigest() in allowed,
            "Retention producer differs from its complete supported original module grammar")


def speech_marker(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("schema_version") == "transcript/v1" or any(speech_marker(v) for v in value.values())
    return isinstance(value, list) and any(speech_marker(v) for v in value)


def descriptors(parent: dict[str, Any], source_hashes: dict[str, Any], plain_name: str) -> None:
    """Only this original descriptor sibling can carry a transcript marker."""
    rows = parent.get("transcript_files_checked")
    require(isinstance(rows, list), "Retention parent lacks its original transcript descriptor table")
    assert isinstance(rows, list)
    paths: set[str] = set()
    for row in rows:
        base = {"artifact", "bytes", "speech_fields", "plain_transcript_lines", "private_exact_hash_retained", "assigned_kind"}
        require(isinstance(row, dict) and set(row) in (base, base | {"schema_version", "source_sha256"}),
                "Retention transcript descriptor has unsupported fields")
        reference(row["artifact"])
        name = row["artifact"]["path"]
        require(name not in paths and type(row["bytes"]) is int and row["bytes"] >= 0
                and type(row["private_exact_hash_retained"]) is bool
                and row["assigned_kind"] in {"review", "transcript", "media", None},
                "Retention transcript descriptor identity or metadata is malformed")
        paths.add(name)
        for key, location in (("speech_fields", "pointer"), ("plain_transcript_lines", "line")):
            table = row[key]
            require(isinstance(table, list), "Retention descriptor projection is not a complete list")
            seen: set[Any] = set()
            for item in table:
                require(isinstance(item, dict) and set(item) == {location, "characters", "sha256", "qualifies_40_chars"},
                        "Retention descriptor contains speech values or extra fields")
                position = item[location]
                require((type(position) is int and position > 0) if location == "line" else
                        (isinstance(position, str) and position.startswith("/")),
                        "Retention descriptor location has an unsupported type")
                require(position not in seen and type(item["characters"]) is int and item["characters"] >= 0
                        and type(item["qualifies_40_chars"]) is bool
                        and (not item["qualifies_40_chars"] or item["characters"] >= 40)
                        and isinstance(item["sha256"], str) and re.fullmatch("[a-f0-9]{64}", item["sha256"]),
                        "Retention descriptor is malformed or duplicated")
                seen.add(position)
            if key == "plain_transcript_lines" and table:
                require(Path(name).name == plain_name, "Retention plain descriptor differs from its exact original filename branch")
        if row.get("schema_version") == "transcript/v1":
            require(row.get("source_sha256") in source_hashes.values(),
                    "Retention transcript descriptor source is not originally registered")
        require(not any(speech_marker(v) for k, v in row.items() if k != "schema_version"),
                "Retention descriptor has a nested speech schema")
    require(not any(speech_marker(v) for k, v in parent.items() if k != "transcript_files_checked"),
            "Retention root or another sibling contains a speech schema")


def known_output(tree: ast.Module, known: Any) -> tuple[ast.FunctionDef, dict[str, ast.expr]]:
    producer = named_function(tree, "_known_private_inventory")
    require(isinstance(producer.body[-1], ast.Return), "Retention inventory lacks its exact final return")
    assert isinstance(producer.body[-1], ast.Return)
    returned = producer.body[-1].value
    require(isinstance(returned, ast.Tuple) and len(returned.elts) == 3 and isinstance(returned.elts[2], ast.Dict),
            "Retention inventory has another tuple output")
    assert isinstance(returned, ast.Tuple)
    fields = dict_fields(returned.elts[2])
    require(isinstance(known, dict) and set(known) == set(fields), "Retention inventory dropped or added original fields")
    require(known["completeness"] == literal(fields["completeness"])
            and isinstance(known["known_refs"], list) and type(known["known_ref_count"]) is int
            and known["known_ref_count"] == len(known["known_refs"]),
            "Retention inventory does not conserve its original private denominator")
    for row in known["known_refs"]:
        row_identity(row)
        require(set(row) == {"path", "sha256", "kind"} and row["kind"] in {"review", "transcript", "media"},
                "Retention original private row has another classification")
    by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for row in known["known_refs"]:
        key = (row["path"], row["sha256"])
        require(key not in by_identity or by_identity[key] == row,
                "Retention repeated private identity has conflicting complete rows")
        by_identity[key] = row
    return producer, fields


def parent_types(report: dict[str, Any], project: Path) -> None:
    counts = {"added_phrase_count", "current_phrase_count", "prior_r3_phrase_count", "previous_exact_phrase_count",
              "previous_saved_phrase_count", "independent_expected_unique_speech_strings", "independent_expected_speech_occurrences",
              "missing_speech_count", "removed_phrase_count", "unexplained_removed_count"}
    require(all(type(report[k]) is int and report[k] >= 0 for k in counts),
            "Retention parent counters have unsupported types")
    require(all(isinstance(report[k], str) and report[k] for k in ("started_at", "finished_at"))
            and type(report["wall_seconds"]) in {int, float} and math.isfinite(report["wall_seconds"])
            and report["wall_seconds"] >= 0 and type(report["public_code_unchanged_during_execution"]) is bool,
            "Retention parent timing/source fields have unsupported types")
    lists = {"expected_speech_strings", "missing_speech_strings", "unexplained_removed", "added_phrase_hashes",
             "previous_transcript_node_files", "protected_project_files_unchanged"}
    require(all(isinstance(report[k], list) for k in lists), "Retention parent collection field is not a complete list")
    for counter, rows in (("added_phrase_count", "added_phrase_hashes"), ("missing_speech_count", "missing_speech_strings"),
                          ("unexplained_removed_count", "unexplained_removed"),
                          ("independent_expected_unique_speech_strings", "expected_speech_strings")):
        require(report[counter] == len(report[rows]), "Retention parent counter differs from its complete original list")
    require(all(isinstance(h, str) and re.fullmatch("[a-f0-9]{64}", h) for h in report["added_phrase_hashes"])
            and report["added_phrase_hashes"] == sorted(set(report["added_phrase_hashes"])),
            "Retention added-hash table differs from its original sorted unique projection")
    expected_status = "P1_MISSING_TRANSCRIPT_PHRASE" if report["missing_speech_strings"] else "EXACT_TRANSCRIPT_RETENTION_CONFIRMED"
    require(report["status"] == expected_status, "Retention status differs from its original conditional writer")
    for row in report["expected_speech_strings"]:
        require(isinstance(row, dict) and set(row) == {"sha256", "characters", "origins", "exact_string_retained"}
                and type(row["characters"]) is int and row["characters"] >= 0
                and type(row["exact_string_retained"]) is bool and isinstance(row["origins"], list)
                and isinstance(row["sha256"], str) and re.fullmatch("[a-f0-9]{64}", row["sha256"]),
                "Retention expected-speech descriptor differs from its complete original writer")
    require(report["independent_expected_speech_occurrences"] == sum(len(row["origins"]) for row in report["expected_speech_strings"]),
            "Retention speech occurrence denominator differs from its complete original descriptors")
    for key in ("missing_speech_strings", "unexplained_removed"):
        for row in report[key]:
            require(isinstance(row, dict) and set(row) == {"text_private_only", "sha256", "origins"}
                    and isinstance(row["text_private_only"], str) and isinstance(row["origins"], list)
                    and hashlib.sha256(row["text_private_only"].encode()).hexdigest() == row["sha256"],
                    "Retention unselected private prose differs from its complete original writer")
    for row in report["previous_transcript_node_files"]:
        row_identity(row)
        require(set(row) == {"path", "sha256", "bytes", "within_original_text_inspection_bound"}
                and type(row["bytes"]) is int and row["bytes"] >= 0
                and type(row["within_original_text_inspection_bound"]) is bool,
                "Retention previous node descriptor differs from its complete original writer")
    protected = report["protected_project_files_unchanged"]
    require(len(protected) == 3, "Retention original protected file denominator differs")
    for row, name in zip(protected, ("project.json", "acceptance.local.json", "checkpoint.local.json"), strict=True):
        reference(row)
        require(row["path"] == str(project / name), "Retention protected original path differs from its writer")


def verify_retention_inventory(selected: dict[str, Any], root: Path, read: Read, document: Document) -> dict[str, Any]:
    require(set(selected) == {"schema_version", "family", "result", "reproducer", "source_snapshot", "input", "previous_scanner"}
            and selected["schema_version"] == "review-machine-field-authority/v1"
            and selected["family"] == "transcript_corpus_inventory", "Unsupported retention authority root")
    observed: list[tuple[dict[str, Any], bytes]] = []

    def read_bound(ref: Any) -> tuple[Path, bytes]:
        reference(ref)
        path, data = read(ref)
        require(str(path) == ref["path"] and len(data) <= MAX_RETENTION_BYTES
                and hashlib.sha256(data).hexdigest() == ref["sha256"], "Retention source/input bytes differ from the bound reference")
        observed.append((copy.deepcopy(ref), data))
        return path, data

    def json_bound(ref: Any) -> dict[str, Any]:
        _, data = read_bound(ref)
        value = document(ref)
        # The caller's strict document reader supplies duplicate-key refusal;
        # this comparison additionally prevents a substituted decoded object.
        require(isinstance(value, dict) and canonical(json.loads(data)) == canonical(value),
                "Retention parent differs from its complete original bytes")
        return value

    report = json_bound(selected["result"])
    require(report.get("schema_version") == "transcript-corpus-retention-audit/v1"
            and report.get("reproducer") == selected["reproducer"]
            and report.get("source_before") == report.get("source_after"),
            "Retention report lacks its original unchanged source/reproducer relationship")
    original = report["source_before"]
    reference(original)
    require(original["path"] == str(root / "src/talkcut/privacy_checks.py")
            and original["sha256"] == selected["source_snapshot"]["sha256"],
            "Retention snapshot is not the originally recorded import source")
    script_path, script_data = read_bound(selected["reproducer"])
    _, source_data = read_bound(selected["source_snapshot"])
    script, source = syntax(script_data), syntax(source_data)
    shape(script, "script")
    shape(source, "source")
    pair = (hashlib.sha256(script_shape(script).encode()).hexdigest(),
            hashlib.sha256(ast.dump(source).encode()).hexdigest())
    require(pair in grammar.SCRIPT_SOURCE_PAIRS, "Retention script and imported source are not an original compatible pair")
    paths = path_assignments(script, root, script_path)
    project = paths.get("PROJECT")
    require(project is not None and project.is_absolute() and project.is_relative_to(root)
            and paths.get("source") == Path(original["path"]), "Retention source/project paths differ from the original expressions")
    assert project is not None
    report_path = Path(selected["result"]["path"])
    output = report_path.parent
    require(report_path.name == "result.local.json" and re.fullmatch("[a-f0-9]{32}", output.name)
            and output.parent == project / "evidence/transcript-corpus-independent",
            "Retention result is not at the original UUID output expression")
    written = dict_fields(assignment(script, "report"))
    require(set(report) == set(written) and matches(written["current_inventory"], "inventory"),
            "Retention parent differs from its complete original report writer")
    for key, fixed_node in written.items():
        if isinstance(fixed_node, ast.Constant):
            require(type(report[key]) is type(fixed_node.value) and report[key] == fixed_node.value,
                    "Retention fixed report field differs from its original writer")
    for node in script.body:
        if (isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare)
                and matches(node.test.left, 'source_before["sha256"]')):
            require(len(node.test.comparators) == 1 and literal(node.test.comparators[0]) == original["sha256"],
                    "Retention source assertion names another original digest")
    inputs = report["actual_current_inventory_inputs"]
    require(isinstance(inputs, dict) and set(inputs) == {"registered_source_hashes", "raw_privacy_input"}
            and inputs["raw_privacy_input"] == selected["input"]
            and paths.get("raw_input_path") == Path(selected["input"]["path"]),
            "Retention input differs from the original called input expression")
    source_hashes = inputs["registered_source_hashes"]
    require(isinstance(source_hashes, dict) and source_hashes and all(isinstance(k, str) and isinstance(v, str)
            and re.fullmatch("[a-f0-9]{64}", v) for k, v in source_hashes.items()), "Retention registered source map is malformed")
    json_bound(selected["input"])
    for variable, field in (("previous_path", "previous_diagnostic"), ("current_r3_path", "latest_prior_r3"), ("runtime", "runtime_origin_parent")):
        reference(report[field])
        require(paths.get(variable) == Path(report[field]["path"]) and paths[variable].is_relative_to(project),
                "Retention supporting original path differs from its emitted reference")
        # These are retained authority dependencies, not replayed/private text exemptions.
        read_bound(report[field])
    old = report["previous_scanner"]
    require(isinstance(old, dict) and set(old) == {"git_blob_oid", "path", "sha256"}
            and {k: old[k] for k in ("path", "sha256")} == selected["previous_scanner"]
            and old["path"] == str(output / "old-scanner.gitblob.local.py")
            and old["git_blob_oid"] == literal(assignment(script, "old_blob_oid")),
            "Retention later old-scanner dependency has another identity or output path")
    _, old_data = read_bound(selected["previous_scanner"])
    git_object = b"blob " + str(len(old_data)).encode() + b"\0" + old_data
    require(hashlib.sha1(git_object, usedforsecurity=False).hexdigest() == old["git_blob_oid"],
            "Retention preserved old scanner is not the originally requested Git blob")
    shape(syntax(old_data), "old_scanner")
    for field, filename in (("current_phrase_ref", "current-phrases.private.json"), ("removed_phrase_ref", "removed-runtime-phrases.private.json")):
        reference(report[field])
        require(report[field]["path"] == str(output / filename), "Retention sibling output reference has another original target")
    names = [literal(n.comparators[0]) for n in ast.walk(script) if isinstance(n, ast.Compare) and matches(n.left, "p.name")]
    require(len(names) == 1 and Path(names[0]).name == names[0] and names[0].endswith(".txt"),
            "Retention plain transcript branch has no supported literal basename")
    counts = [n.test.comparators[0].value for n in script.body if isinstance(n, ast.Assert)
              and isinstance(n.test, ast.Compare) and matches(n.test.left, "len(transcript_paths)")
              and len(n.test.comparators) == 1 and isinstance(n.test.comparators[0], ast.Constant)]
    require(len(counts) == 1 and isinstance(report["transcript_files_checked"], list)
            and len(report["transcript_files_checked"]) == counts[0],
            "Retention original transcript descriptor denominator differs from the recorded producer assertion")
    descriptors(report, source_hashes, names[0])
    parent_types(report, project)
    producer, fields = known_output(source, report["current_inventory"])
    require(report["current_inventory"]["project"] == str(project)
            and report["current_inventory"]["source_hashes"] == source_hashes
            and report["current_inventory"]["derived_phrase_count"] == report["current_phrase_count"],
            "Retention returned inventory is not bound to the original project/source arguments")
    require(matches(assignment(producer, "rank"), '{"review": 0, "transcript": 1, "media": 2}'),
            "Retention original private-kind ranking differs from the supported producer")
    rank = {"review": 0, "transcript": 1, "media": 2}
    known_kinds: dict[str, str] = {}
    for private_row in report["current_inventory"]["known_refs"]:
        digest, kind = private_row["sha256"], private_row["kind"]
        if rank[kind] > rank.get(known_kinds.get(digest, ""), -1):
            known_kinds[digest] = kind
    for descriptor in report["transcript_files_checked"]:
        digest = descriptor["artifact"]["sha256"]
        require(descriptor["private_exact_hash_retained"] == (digest in known_kinds)
                and descriptor["assigned_kind"] == known_kinds.get(digest),
                "Retention descriptor facts differ from the complete original private hash map")
        require(not (descriptor["speech_fields"] or descriptor["plain_transcript_lines"])
                or descriptor["private_exact_hash_retained"],
                "Retention speech-bearing descriptor violates the original complete-retention assertion")
    writers = legacy_inventory_writers(producer, fields)
    for ref, data in observed:
        _, current = read(ref)
        require(current == data, "Retention authority changed during complete verification")
    return {"source": selected["source_snapshot"], "original_source": original, "source_tree": source,
            "parent": copy.deepcopy(report), "parent_ref": copy.deepcopy(selected["result"]),
            "parent_content": canonical(report), "writers": writers,
            "refs": [ref for ref, _ in observed],
            "scope": "Recorded source/writer/parent relationship only; no historical execution or phrase clearance"}


def legacy_inventory_writers(producer: ast.FunctionDef, known_fields: dict[str, ast.expr]) -> dict[str, Any]:
    walk = named_function(producer, "walk")
    collectors = [node for node in producer.body if isinstance(node, ast.FunctionDef) and node.name == "collect_candidate"]
    require(len(collectors) <= 1, "Machine original fixed candidate writer is ambiguous")
    collector = collectors[0] if collectors else walk
    assignments = [node.value for node in lexical(collector) if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and matches(node.targets[0], "candidate") and isinstance(node.value, ast.Dict)]
    require(len(assignments) == 1, "Machine original fixed candidate lacks its unique dictionary writer")
    written = dict_fields(assignments[0])
    require(set(written) == {"classification", "reason", "matching_git_source_bytes"},
            "Machine original fixed candidate has unrelated fields")
    strings = {"CODE_REASON": literal(written["reason"])}
    if collectors:
        preserves = [node.value for node in lexical(collector) if isinstance(node, ast.Assign) and len(node.targets) == 1
                     and matches(node.targets[0], 'candidate["preservation"]')]
        require(len(preserves) == 1, "Machine fixed candidate has no original preservation writer")
        strings["PRESERVATION"] = literal(preserves[0])
    for node in lexical(walk):
        if isinstance(node, ast.Dict):
            fields = dict_fields(node)
            if "reason" not in fields or not isinstance(fields["reason"], ast.Constant) or "matching_git_source_bytes" in fields:
                continue
            key = "UNRESOLVED_REASON" if "current_ref" in fields else "EXTERNAL_REASON"
            require(key not in strings, "Machine fixed walk has ambiguous field writers")
            strings[key] = literal(fields["reason"])
    require("EXTERNAL_REASON" in strings, "Machine fixed walk lacks the complete original external-reference projection")
    template = grammar.FIXED_WALK if collectors else grammar.INLINE_WALK
    require(ast.dump(walk) == ast.dump(instantiate(template, strings)),
            "Machine fixed walk differs from its complete original source-field grammar")
    if collectors:
        require(ast.dump(collector) == ast.dump(instantiate(grammar.FIXED_CANDIDATE, strings)),
                "Machine fixed candidate differs from its complete original source-field grammar")
    pending = [node for node in producer.body if isinstance(node, ast.While) and matches(node.test, "pending")]
    require(len(pending) == 1 and block_matches(pending, """
while pending:
    path, kind = pending.pop()
    try:
        value = json.loads(path.read_text())
    except (ValueError, UnicodeDecodeError):
        continue
    """ + ("walk(value)" if collectors else 'walk(value, kind == "transcript")')),
            "Machine fixed walker is not called by its original direct input loop")
    allowed = [walk, collector, known_fields["public_work_candidates"], known_fields["unfollowed_refs"]]
    for node in producer.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in {"public_candidates", "unfollowed"}:
            require(node.value is not None and matches(node.value, "{}" if node.target.id == "public_candidates" else "[]"),
                    "Machine fixed collection has an unrelated initializer")
            allowed.append(node)
    permitted = {id(node) for subtree in allowed for node in ast.walk(subtree)}
    require(all(id(node) in permitted for node in ast.walk(producer)
                if isinstance(node, ast.Name) and node.id in {"public_candidates", "unfollowed"}),
            "Machine fixed inventory contains an unrelated collection writer or alias")
    return {**strings, "classification": literal(written["classification"])}

def candidate_reason(producer: ast.FunctionDef, known_fields: dict[str, ast.expr], row: Any) -> str:
    strings = legacy_inventory_writers(producer, known_fields)
    row_identity(row)
    base_keys = {"path", "sha256", "classification", "reason", "matching_git_source_bytes"}
    extra_keys = ({"publication_role"} if "publication_role" in row else set()) | ({"original_reference", "preservation"} if "original_reference" in row else set())
    require(set(row) == base_keys | extra_keys and row["classification"] == strings["classification"]
            and isinstance(row["matching_git_source_bytes"], list), "Machine candidate row differs from its complete original schema")
    git_rows = row["matching_git_source_bytes"]
    for origin in git_rows:
        require(isinstance(origin, dict) and set(origin) == {"commit", "git_path", "git_blob"}
                and all(isinstance(origin[key], str) and re.fullmatch(r"[a-f0-9]{40}", origin[key]) for key in ("commit", "git_blob"))
                and isinstance(origin["git_path"], str) and origin["git_path"] and not Path(origin["git_path"]).is_absolute()
                and all(part not in {"", ".", ".."} for part in origin["git_path"].split("/")),
                "Machine candidate original Git member row is malformed")
    require(len({json.dumps(value, sort_keys=True) for value in git_rows}) == len(git_rows),
            "Machine candidate original Git member rows are duplicated")
    if "original_reference" in row:
        row_identity(row["original_reference"])
        require(set(row["original_reference"]) == {"path", "sha256"}
                and row["original_reference"]["sha256"] == row["sha256"]
                and "PRESERVATION" in strings and row["preservation"] == strings["PRESERVATION"],
                "Machine candidate original reference or preservation differs from its complete writer")
    if "publication_role" in row:
        require("BODY_REASON" in strings and row["publication_role"] in {"pr_body", "release_body"}, "Machine candidate publication role is not an original supported value")
    return str(strings["BODY_REASON"] if "publication_role" in row else strings["CODE_REASON"])

def retention_field(bound: dict[str, Any], parent_ref: dict[str, Any], selector: list[Any]) -> dict[str, Any]:
    require(parent_ref == bound["parent_ref"] and canonical(bound["parent"]) == bound["parent_content"],
            "Retention selected parent is unbound or changed after verification")
    require(isinstance(selector, list) and len(selector) >= 2 and all(type(v) in {str, int} for v in selector)
            and selector[0] == "current_inventory", "Retention selector is outside the exact machine subtree")
    parent = bound["parent"]
    known = parent["current_inventory"]
    require(not speech_marker(known), "Retention selected inventory contains a transcript schema")
    producer, fields = known_output(bound["source_tree"], known)
    edge = selector[1:]
    if len(edge) == 1 and edge[0] in {"scope", "reason"}:
        derived = literal(fields[edge[0]])
        require(type(known[edge[0]]) is str and known[edge[0]] == derived,
                "Retention inventory leaf differs from its original return writer")
        row = known
    else:
        require(len(edge) == 3 and edge[0] in {"public_work_candidates", "unfollowed_refs", "unresolved_source_candidates"}
                and type(edge[1]) is int and edge[1] >= 0 and edge[2] in {"reason", "preservation"}
                and (edge[2] != "preservation" or edge[0] == "public_work_candidates"),
                "Retention selector is not a permitted exact string leaf")
        rows = known.get(edge[0])
        require(isinstance(rows, list) and edge[1] < len(rows), "Retention selected row is absent")
        row = rows[edge[1]]
        require(isinstance(row, dict) and not speech_marker(row), "Retention associated row contains a transcript schema")
        strings = bound["writers"]
        if edge[0] == "public_work_candidates":
            derived = candidate_reason(producer, fields, row)
            require(row["reason"] == derived, "Retention candidate reason differs from the original complete writer")
            if edge[2] == "preservation":
                require("preservation" in row, "Retention selected candidate has no original preservation leaf")
                derived = row["preservation"]
        elif edge[0] == "unresolved_source_candidates":
            row_identity(row)
            require(set(row) == {"path", "sha256", "classification", "status", "current_ref", "reason"}
                    and row["classification"] == "UNCLASSIFIED" and row["status"] == "UNVERIFIED",
                    "Retention unresolved source differs from its complete original row")
            reference(row["current_ref"])
            require(row["current_ref"]["path"] == row["path"] and row["current_ref"]["sha256"] != row["sha256"],
                    "Retention unresolved source has an inconsistent original identity")
            derived = strings["UNRESOLVED_REASON"]
        else:
            row_identity(row)
            require(set(row) == {"path", "sha256", "reason"}, "Retention reference row has extra or missing fields")
            candidates = [v for v in known["public_work_candidates"] if isinstance(v, dict)
                          and v.get("path") == row["path"] and v.get("sha256") == row["sha256"]]
            require(len(candidates) <= 1, "Retention reference row has ambiguous candidate origins")
            if candidates:
                derived = candidate_reason(producer, fields, candidates[0])
            elif row["reason"] == strings["CODE_REASON"]:
                private = [v for v in known["known_refs"] if v["sha256"] == row["sha256"]]
                require(private, "Retention filtered candidate lacks its original private hash row")
                derived = strings["CODE_REASON"]
            else:
                # The complete original module has one remaining append writer,
                # with this closed three-field projection. No copied prose field
                # or arbitrary diagnostic reason is an accepted output location.
                derived = strings["EXTERNAL_REASON"]
        require(type(row.get(edge[2])) is str and row[edge[2]] == derived,
                "Retention selected leaf differs from its original typed writer")
    return {"value": derived, "row": copy.deepcopy(row), "source": bound["source"],
            "parent": parent_ref, "extractions": [{"edge": list(selector), "value": derived}],
            "status": "UNVERIFIED"}


def retention_fields(bound: dict[str, Any], parent_ref: dict[str, Any], selectors: list[list[Any]]) -> list[dict[str, Any]]:
    require(isinstance(selectors, list) and len(selectors) <= 20000,
            "Retention selector list exceeds the finite projection bound")
    encoded: set[str] = set()
    result = []
    for selector in selectors:
        key = canonical(selector)
        require(key not in encoded, "Retention selectors are duplicated")
        encoded.add(key)
        result.append(retention_field(bound, parent_ref, selector))
    return result
