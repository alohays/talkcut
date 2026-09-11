"""Synthetic source/row controls; these never execute a historical producer."""
from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path

import pytest

from talkcut import privacy_machine_origins as machine
from talkcut.project import TalkCutError

CODE = "Synthetic machine code input requires its complete content inspection."
BODY = "Declared publication body needs its separate content inspection."
PRESERVATION = "Exact source snapshot only; no execution or publication approval."
EXTERNAL = "External source reference needs a separate origin and privacy classification."
LINK = "Explicit original synthetic tool link and canonical target are both retained."


@pytest.fixture
def context(tmp_path):
    text = (Path(__file__).parent / "fixtures/machine_inventory_writer.py.txt").read_text()
    source = {"path": str(tmp_path / "original-producer.py"), "sha256": hashlib.sha256(text.encode()).hexdigest()}
    row = {"path": str(tmp_path / "ordinary.py"), "sha256": "b" * 64,
           "classification": "UNCLASSIFIED", "reason": CODE, "matching_git_source_bytes": []}
    known = {"completeness": "UNVERIFIED", "known_refs": [], "known_ref_count": 0,
             "public_work_candidates": [row], "unfollowed_refs": [{key: row[key] for key in ("path", "sha256", "reason")}],
             "synthetic_failure_fixtures": []}
    parent_ref = {"path": str(tmp_path / "original-inventory.json"), "sha256": "c" * 64}
    bound = {"source": source, "source_tree": ast.parse(text),
             "parents": {parent_ref["path"]: {"ref": parent_ref, "prefix": ["known_graph"], "value": {"known_graph": known}}},
             "publication_bodies": {role: {"path": str(tmp_path / role), "sha256": "d" * 64} for role in ("pr_body", "release_body")}}
    return text, bound, parent_ref, known


def select(context, collection="public_work_candidates", index=0):
    _, bound, parent_ref, _ = context
    return machine.fixed_inventory_field(bound, parent_ref, ["known_graph", collection, index, "reason"])


@pytest.mark.parametrize("kind", ["candidate", "copy", "body", "preserved", "external", "filtered", "literal_link"])
def test_complete_original_writer_projections(context, kind):
    _, _, _, known = context
    row = known["public_work_candidates"][0]
    collection, expected = "public_work_candidates", CODE
    if kind == "copy":
        collection = "unfollowed_refs"
    elif kind == "body":
        row.update(publication_role="pr_body", reason=BODY)
        expected = BODY
    elif kind == "preserved":
        row.update(original_reference={"path": row["path"] + ".old", "sha256": row["sha256"]}, preservation=PRESERVATION)
    elif kind == "external":
        known["public_work_candidates"] = []
        known["unfollowed_refs"][0]["reason"] = EXTERNAL
        collection, expected = "unfollowed_refs", EXTERNAL
    elif kind == "filtered":
        known["public_work_candidates"] = []
        known["known_refs"] = [{"path": row["path"], "sha256": row["sha256"], "kind": "media"}]
        known["known_ref_count"] = 1
        collection = "unfollowed_refs"
    elif kind == "literal_link":
        link_text = "../tools/decoder"
        digest = hashlib.sha256(link_text.encode()).hexdigest()
        known["public_work_candidates"] = []
        known["unfollowed_refs"] = [{"path": row["path"], "sha256": digest, "reason": LINK}]
        known["synthetic_failure_fixtures"] = [{"current_reproduction": {"external_tool_links": [{
            "link_path": row["path"], "link_target": link_text, "link_bytes_sha256": digest,
            "actual_target": {"path": row["path"] + ".target", "sha256": "e" * 64}, "declared_target_sha256": "e" * 64}]}}]
        collection, expected = "unfollowed_refs", LINK
    before = copy.deepcopy(known)
    result = select(context, collection)
    assert result["value"] == expected
    assert result["row"] == known[collection][0]
    assert result["extractions"] == [{"edge": ["known_graph", collection, 0, "reason"], "value": expected}]
    assert known == before
    assert known["completeness"] == "UNVERIFIED"


@pytest.mark.parametrize(("old", "new"), [
    ("    while pending:", "    def dormant():\n        while pending:"),
    ("    while pending:", "    if False:\n        while pending:"),
    ("candidate = {**ref,", "candidate = {**ref, **unrelated,"),
    ("public_candidates[str(actual_path)] = candidate", "if False:\n                public_candidates[str(actual_path)] = candidate"),
    ("unfollowed.append({**ref, 'reason': candidate['reason']})", "unfollowed.append({**ref, 'reason': 'Copied private prose'})"),
    ("    return known,", "    public_candidates.clear()\n    return known,"),
    ("    return known,", "    unfollowed.append({'path': 'x', 'sha256': 'b', 'reason': 'Extra writer'})\n    return known,"),
    ("    return known,", "    alias = unfollowed\n    return known,"),
    ("if contains_transcript(candidate_body):", "if False:"),
    ("if ref is not original_ref:", "if False:"),
    ("candidate['publication_role'] = role", "candidate['publication_role'] = 'pr_body'"),
    ("'matching_git_source_bytes': source_candidates.get(ref['sha256'], [])", "'matching_git_source_bytes': []"),
])
def test_dormant_or_unrelated_original_writers_refuse(context, old, new):
    text, bound, _, _ = context
    assert text.count(old) == 1
    changed = text.replace(old, new)
    if "while pending" in old:
        # Nest the entire loop, preserving valid source syntax, to prove that
        # the verifier refuses the call route rather than a parser error.
        start = changed.index("        while pending:")
        end = changed.index("    return known,", start)
        lines = changed[start:end].splitlines()
        changed = changed[:start] + lines[0] + "\n" + "\n".join("    " + line for line in lines[1:]) + "\n" + changed[end:]
    bound["source_tree"] = ast.parse(changed)
    with pytest.raises(TalkCutError):
        select(context)


@pytest.mark.parametrize("fault", ["reason", "classification", "extra", "git_extra", "git_duplicate", "git_traversal", "preservation", "role"])
def test_complete_candidate_row_refuses_forgery(context, fault):
    _, _, _, known = context
    row = known["public_work_candidates"][0]
    if fault == "reason":
        row["reason"] = "An unrelated private reason with enough content to remain protected."
    elif fault == "classification":
        row["classification"] = "public_work"
    elif fault == "extra":
        row["prose"] = CODE
    elif fault.startswith("git_"):
        origin = {"commit": "a" * 40, "git_blob": "b" * 40, "git_path": "docs/example.md"}
        row["matching_git_source_bytes"] = [origin]
        if fault == "git_extra":
            origin["reason"] = CODE
        elif fault == "git_duplicate":
            row["matching_git_source_bytes"].append(dict(origin))
        else:
            origin["git_path"] = "../private.md"
    elif fault == "preservation":
        row.update(original_reference={"path": row["path"], "sha256": row["sha256"]}, preservation=CODE)
    else:
        row.update(publication_role="transcript", reason=BODY)
    with pytest.raises(TalkCutError):
        select(context)


@pytest.mark.parametrize("index", [True, False, "0", -1, 1, 0.0])
def test_exact_integer_and_complete_row_selection(context, index):
    with pytest.raises(TalkCutError):
        select(context, index=index)


@pytest.mark.parametrize("fault", ["no_private_row", "body_hash", "body_missing", "private_extra", "different_parent", "different_selector"])
def test_filtered_reason_requires_every_original_relation(context, fault):
    _, bound, parent_ref, known = context
    row = known["public_work_candidates"].pop()
    known["known_refs"] = [{"path": row["path"], "sha256": row["sha256"], "kind": "media"}]
    known["known_ref_count"] = 1
    if fault == "no_private_row":
        known.update(known_refs=[], known_ref_count=0)
    elif fault == "body_hash":
        bound["publication_bodies"]["pr_body"]["sha256"] = row["sha256"]
    elif fault == "body_missing":
        bound.pop("publication_bodies")
    elif fault == "private_extra":
        known["known_refs"][0]["prose"] = CODE
    elif fault == "different_parent":
        parent_ref = {**parent_ref, "sha256": "a" * 64}
    selector = ["known_graph", "unfollowed_refs", 0, "reason"]
    if fault == "different_selector":
        selector[-1] = "prose"
    with pytest.raises(TalkCutError):
        machine.fixed_inventory_field(bound, parent_ref, selector)


@pytest.mark.parametrize("field", ["scope", "reason"])
@pytest.mark.parametrize("mutated", [False, True])
def test_direct_inventory_return_metadata(context, field, mutated):
    text, bound, parent_ref, known = context
    value = "Synthetic original machine inventory metadata with a fixed output field."
    bound["source_tree"] = ast.parse(text.replace('"completeness": "UNVERIFIED",',
                                                   repr(field) + ": " + repr(value) + ', "completeness": "UNVERIFIED",'))
    known[field] = value + (" changed private prose" if mutated else "")
    if mutated:
        with pytest.raises(TalkCutError):
            machine.fixed_inventory_field(bound, parent_ref, ["known_graph", field])
    else:
        assert machine.fixed_inventory_field(bound, parent_ref, ["known_graph", field])["value"] == value


@pytest.mark.parametrize("mutated", [False, True])
def test_preservation_field_selects_exact_complete_candidate(context, mutated):
    _, bound, parent_ref, known = context
    row = known["public_work_candidates"][0]
    row.update(original_reference={"path": row["path"] + ".old", "sha256": row["sha256"]},
               preservation=CODE if mutated else PRESERVATION)
    if mutated:
        with pytest.raises(TalkCutError):
            machine.fixed_inventory_field(bound, parent_ref, ["known_graph", "public_work_candidates", 0, "preservation"])
    else:
        assert machine.fixed_inventory_field(bound, parent_ref, ["known_graph", "public_work_candidates", 0, "preservation"])["value"] == PRESERVATION


@pytest.mark.parametrize("mutated", [False, True])
def test_unresolved_reason_keeps_exact_status_and_full_row(context, mutated):
    text, bound, parent_ref, known = context
    value = "Historical source input has no preserved bytes and remains unresolved."
    bound["source_tree"] = ast.parse(text.replace('"completeness": "UNVERIFIED",',
                                                   '"unresolved_source_candidates": list(unresolved_sources.values()), "completeness": "UNVERIFIED",'))
    row = known["public_work_candidates"][0]
    known["unresolved_source_candidates"] = [{"path": row["path"], "sha256": row["sha256"], "reason": value,
        "classification": "UNCLASSIFIED", "status": "PASS" if mutated else "UNVERIFIED", "current_ref": {"path": row["path"], "sha256": "f" * 64}}]
    if mutated:
        with pytest.raises(TalkCutError):
            machine.fixed_inventory_field(bound, parent_ref, ["known_graph", "unresolved_source_candidates", 0, "reason"])
    else:
        assert machine.fixed_inventory_field(bound, parent_ref, ["known_graph", "unresolved_source_candidates", 0, "reason"])["value"] == value


@pytest.mark.parametrize("mutated", [False, True])
def test_auxiliary_scope_keeps_all_original_locator_relationships(context, mutated):
    text, bound, parent_ref, known = context
    value = "Auxiliary source observation has no original execution or publication approval."
    writer = '''    for locator in source_snapshots or []:
        original, snapshot = locator["original"], locator["snapshot"]
        origin = Path(original["path"])
        if locator.get("scope") == "auxiliary_execution_source":
            auxiliary_source_current.append({"original_reference": original, "preserved_ref": snapshot, "current_ref": artifact_ref(origin), "classification": "UNCLASSIFIED", "scope": ''' + repr(value) + '''})
'''
    text = text.replace("    while pending:", writer + "    while pending:")
    text = text.replace('"completeness": "UNVERIFIED",', '"auxiliary_execution_sources": auxiliary_source_current, "completeness": "UNVERIFIED",')
    bound["source_tree"] = ast.parse(text)
    row = known["public_work_candidates"][0]
    known["auxiliary_execution_sources"] = [{"original_reference": {"path": row["path"], "sha256": row["sha256"]},
        "preserved_ref": {"path": row["path"] + ".copy", "sha256": "a" * 64 if mutated else row["sha256"]},
        "current_ref": {"path": row["path"], "sha256": "f" * 64}, "classification": "UNCLASSIFIED", "scope": value}]
    if mutated:
        with pytest.raises(TalkCutError):
            machine.fixed_inventory_field(bound, parent_ref, ["known_graph", "auxiliary_execution_sources", 0, "scope"])
    else:
        assert machine.fixed_inventory_field(bound, parent_ref, ["known_graph", "auxiliary_execution_sources", 0, "scope"])["value"] == value
