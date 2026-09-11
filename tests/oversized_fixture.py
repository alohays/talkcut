"""Portable, inert original-shaped records with real files and truthful hashes.

The stored producer/probe/helper is parsed only. These synthetic records do not
claim that the old producer, FFmpeg commands, or technical controls executed.
"""
from __future__ import annotations

import json
from pathlib import Path

from talkcut import privacy_oversized_grammar as grammar
from talkcut.project import artifact_ref, atomic_json, init_project

REASON = "Code/archive or matching source bytes require independent content and provenance classification"
SCOPE = "Preserved actual fixed-generator replay; historical execution identities remain unchanged"


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    elif isinstance(value, str):
        path.write_text(value)
    else:
        atomic_json(path, value)
    return artifact_ref(path)


def fixture(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    outer_screen = write(root / "screen.bin", b"Outer registered screen")
    outer_speaker = write(root / "speaker.bin", b"Outer registered speaker")
    outer = root / "task"
    outer_project = init_project(outer, outer_screen["path"], outer_speaker["path"])
    folder = outer / "audit"
    folder.mkdir()
    source = write(root / "producer.py", (Path(__file__).parent / "fixtures/oversized-source.py.txt").read_bytes())
    helper_text = (Path(__file__).parent / "fixtures/oversized-helper.py.txt").read_text()
    helper_text = helper_text.replace("FIXTURE_ROOT", "Path(" + repr(str(root)) + ")")
    helper_text = helper_text.replace("FIXTURE_SOURCE_SHA", repr(source["sha256"]))
    helper_text = helper_text.replace("FIXTURE_SOURCE", "ROOT / 'producer.py'")
    helper = write(folder / "probe_auxiliary.py", helper_text)
    script = write(folder / "probe_accepted_bound_inventory.py", grammar.PROBE.replace(
        "VERIFIED_FAILURE_RUN", "artifact_ref(ROOT / 'failure/result.json')"))
    case = folder / "oversized-stdout-inventory"
    screen = write(case / "screen.bin", b"authored private screen identity " + case.name.encode())
    speaker = write(case / "speaker.bin", b"authored private speaker identity " + case.name.encode())
    directory = case / "project"
    project = init_project(directory, screen["path"], speaker["path"])
    source_hashes = {role: ref["sha256"] for role, ref in project["sources"].items()}
    old_source = write(case / "preserved-old-source.py", '# A deliberately authored private observation about five copper birds entering an indigo room.\nprint("old local run")\n')
    current_source = write(directory / "capability/runtime/runner.py", 'print("current local run")\n')
    original_source = {"path": current_source["path"], "sha256": old_source["sha256"]}
    old_metadata = write(case / "preserved-old-metadata", {"state": "running", "source_sha256": source_hashes["screen"], "runner": original_source})
    current_metadata = write(directory / "capability/state.json", {"state": "done"})
    original_metadata = {"path": current_metadata["path"], "sha256": old_metadata["sha256"]}

    # Minimal real input/artifact closure for the two fixed pair projections.
    original = {role: write(root / "failure/original" / (role + ".bin"), ("Synthetic old " + role).encode()) for role in ("screen", "speaker")}
    current = {role: write(root / "failure/changed" / (role + ".bin"), ("Synthetic changed " + role).encode()) for role in original}
    declared = {role: {"path": current[role]["path"], "sha256": original[role]["sha256"]} for role in original}
    cp = write(root / "failure/control/project.json", {"sources": original})
    mp = write(root / "failure/mutant/project.json", {"sources": declared})
    old_output = write(root / "failure/original-output.bin", b"Synthetic old output")
    output = write(root / "failure/changed-output.bin", b"Synthetic changed output")
    pairs = [
        {"name": "source_bytes", "control_input": write(root / "failure/source-control.json", {"project": str(Path(cp["path"]).parent)}),
         "mutation_input": write(root / "failure/source-mutant.json", {"project": str(Path(mp["path"]).parent)})},
        {"name": "output_bytes", "control_input": write(root / "failure/output-control.json", {"output": old_output}),
         "mutation_input": write(root / "failure/output-mutant.json", {"output": {"path": output["path"], "sha256": old_output["sha256"]}})},
    ]
    run = write(root / "failure/result.json", {"schema_version": "evaluator-negative-run/v1", "test_only": True,
        "actual_dgist_acceptance": False, "request": write(root / "failure/request.json", {"synthetic": True}),
        "harness": source, "cases": {"wrong_hashes": {"pairs": pairs}},
        "artifacts": [cp, mp, *original.values(), *current.values(), old_output, output]})
    failure_rows = [{"declared_reference": declared[role], "preserved_original": original[role], "actual_current": current[role],
                     "case": "wrong_hashes.source_bytes", "historical_run": run, "classification": "UNCLASSIFIED", "status": "MEASURED",
                     "reason": "Exact reproduced synthetic failure fixture; separate classification audit required"} for role in original]
    failure_rows.append({**failure_rows[0], "declared_reference": {"path": output["path"], "sha256": old_output["sha256"]},
                         "preserved_original": old_output, "actual_current": output, "case": "wrong_hashes.output_bytes"})
    archive = root / "archive"
    synthetic = write(archive / "generated/synthetic.mp4", b"Synthetic fixture media bytes, not executable media")
    outputs = {stage: {"output": write(archive / (stage + ".bin"), ("Synthetic " + stage).encode())} for stage in ("baseline", "cut", "restored", "reapplied")}
    steps = write(archive / "generated/executions.json", [{"name": "01-generate", "argv": ["synthetic-never-executed", synthetic["path"]]}, *[{"name": "synthetic-step"}] * 13])
    fixture_ref = write(archive / "generated/result.json", {"executions": steps, "outputs": outputs})
    identity = {"code_identity": {"code_tree_hash": source["sha256"]}, "generator": source, "harness": source}
    before = write(archive / "before.json", identity)
    after = write(archive / "after.json", identity)
    execution = write(archive / "command.json", {"synthetic": True})
    captured = write(archive / "captured.bin", b"Opaque synthetic captured bytes")
    external = write(root / "external.txt", "Synthetic external unselected text")
    bundle = write(archive / "bundle.json", {"schema_version": "synthetic-privacy-replay/v1", "test_only": True,
        "before": before, "after": after, "fixture": fixture_ref, "execution": execution,
        "artifacts": [synthetic, captured], "artifact_count": 2})
    validation = {"scope": "Synthetic metadata projection only; no measured technical claim"}
    reproduction = {"bundle": bundle, "artifacts": [synthetic, captured], "external_inputs": [], "external_tool_links": [],
        "execution": execution, "fixture": fixture_ref, "executions": steps, "technical_validation": validation,
        "generator": source, "harness": source, "code_tree_hash": source["sha256"], "source_sha256": synthetic["sha256"],
        "generator_argv_prefix": ["synthetic-never-executed"], "output_hashes": {k: v["output"]["sha256"] for k, v in outputs.items()}, "scope": SCOPE}
    challenge = write(folder / "bounded-closure-results.json", {"source": source, "cases": [{"case": "oversized_binary_named_stdout",
        "input": bundle, "actual_stdout": captured, "actual_external_ref": external, "technical_validation": validation}]})
    auxiliary = {"original_reference": original_source, "preserved_ref": old_source, "current_ref": current_source,
        "classification": "UNCLASSIFIED", "scope": "Auxiliary execution source bytes only; independent content classification required"}
    metadata = {"original_reference": original_metadata, "preserved_ref": old_metadata, "current_ref": current_metadata,
        "classification": "review", "bytes_status": "OBSERVED", "claim_status": "UNVERIFIED",
        "scope": "Private byte inventory only; no acceptance evidence validation"}
    candidate = {**write(folder / "ordinary.py", "x = 1\n"), "classification": "UNCLASSIFIED", "reason": REASON, "matching_git_source_bytes": []}
    known = {"auxiliary_execution_sources": [auxiliary], "auxiliary_metadata_history": [metadata], "completeness": "UNVERIFIED",
        "derived_phrase_count": 0, "historical_refs": [], "historical_unresolved": [], "known_ref_count": 0, "known_refs": [],
        "project": str(directory), "public_source_candidate_commands": [], "public_work_candidates": [candidate],
        "reason": "Mandatory graph collected; exact task file inventory and separate classification audit have not yet been verified",
        "scope": "Registered task project files and source/derived provenance references", "source_hashes": source_hashes,
        "synthetic_failure_fixtures": [{"run": run, "request": json.loads(Path(run["path"]).read_bytes())["request"], "harness": source,
            "current_reproduction": reproduction, "completeness": "UNVERIFIED", "rows": failure_rows}],
        "unfollowed_refs": [{k: candidate[k] for k in ("path", "sha256", "reason")}], "unresolved_source_candidates": []}
    body = {"schema_version": "private-task-inventory/v1", "project": str(directory),
        "dependencies": {"project_hash": artifact_ref(directory / "project.json")["sha256"], "source_hashes": source_hashes},
        "classification_status": "UNVERIFIED", "entries": [{**captured, "classification": "UNCLASSIFIED"}], "entry_count": 1,
        "mandatory_private_count": 0, "excluded_directories": [], "limits": {}, "preserved_private_inputs": {}, "unresolved": [],
        "known_graph": known, "scope": "All files and symlinks in the registered task project, original/durable sources and recursively referenced task artifacts; unrelated computer files are outside scope"}
    parent = write(folder / "oversized-stdout-inventory.json", body)
    result_body = {"schema_version": "independent-oversized-stdout-inventory-probe/v1", "at": "2000-01-01T00:00:00Z",
        "source": source, "script": script, "challenge": challenge, "inventory": parent,
        "binary_named_stdout_in_inventory": True, "external_reference_in_inventory": False, "unresolved": [],
        "classification_status": "UNVERIFIED", "scope": "Authored bounded metadata adversarial probe only; no final private corpus approval."}
    parts = {"root": root, "directory": outer, "case_directory": directory, "registered": {k: v["sha256"] for k, v in outer_project["sources"].items()}, "body": body, "result_body": result_body,
             "source": source, "script": script, "helper": helper, "challenge": challenge}
    refresh(parts)
    return parts


def refresh(parts):
    """Rebind complete synthetic parent/report/review references after one mutation."""
    folder = Path(parts["script"]["path"]).parent
    for key in ("source", "script", "helper", "challenge"):
        parts[key] = artifact_ref(parts[key]["path"])
    parent = write(folder / "oversized-stdout-inventory.json", parts["body"])
    parts["result_body"].update({key: parts[key] for key in ("source", "script", "challenge")})
    parts["result_body"]["inventory"] = parent
    result = write(folder / "oversized-stdout-inventory-result.json", parts["result_body"])
    stdout = write(folder / "stdout.json", {"report": result, **{k: parts["result_body"][k] for k in (
        "binary_named_stdout_in_inventory", "external_reference_in_inventory", "unresolved", "classification_status")}})
    review = write(folder / "review.json", {"schema_version": "independent-staged-privacy-review/v1",
        "source_before": parts["source"], "source_after": parts["source"], "independent_executions": [
            {"helper": parts["helper"], "challenge": parts["challenge"]},
            {"local_tool_session_id": 1, "observed_exit_code": 0, "result": result, "script": parts["script"], "stdout": stdout,
             "stderr": write(folder / "stderr.txt", "")}]})
    authority = write(folder / "authority.json", {"schema_version": "review-machine-field-authority/v1", "family": "oversized_stdout_inventory",
        "review": review, "result": result, **{k: parts[k] for k in ("source", "script", "helper", "challenge")}})
    parts.update(parent=parent, authority=authority)


def observe(parts, selector=None):
    from talkcut.privacy_checks import _review_text_origin_inventory
    locator = {"schema_version": "review-text-origin/v1", "kind": "machine_inventory_field", "parent": parts["parent"],
               "authority": parts["authority"], "selector": selector or ["known_graph", "public_work_candidates", 0, "reason"]}
    return _review_text_origin_inventory([locator], parts["directory"], parts["root"], set(parts["registered"].values()), [parts["authority"]])
