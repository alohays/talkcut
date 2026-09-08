"""Independent closed-construction checks; never execute recorded producers."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from contract_origin_fixture import (
    PHRASE,
    encoded,
    fixture,
    inventory,
    locator,
    observe,
    refresh,
    write,
)

from talkcut import privacy_checks as privacy
from talkcut.project import TalkCutError


@pytest.mark.parametrize("recipe", ["canonical", "native_fixture", "negative_run"])
@pytest.mark.parametrize("field", ["documents", "requirements", "unrelated_limit"])
def test_unselected_complete_document_cannot_be_replaced(tmp_path, recipe, field):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    value = parts["values"][0]
    if field == "documents":
        value["document_hashes"][next(iter(value["document_hashes"]))] = "0" * 64
    elif field == "requirements":
        value["requirements"].reverse()
    else:
        value["unresolved_P0_P1"] = 42
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize(("recipe", "role", "suffix"), [
    ("canonical", "contracts", "\nDOCUMENT_HASHES = {}\n"),
    ("canonical", "contracts", "\nexpected_contract = lambda: {}\n"),
    ("native_fixture", "caller", "\nlaunch_fixture = None\n"),
    ("negative_run", "project", "\natomic_json = None\n"),
    ("negative_run", "negative", "\nPAIR_NAMES = {}\n"),
])
def test_late_source_rebinding_is_not_constructor_proof(tmp_path, recipe, role, suffix):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    source = Path(parts["snapshots"][role]["path"])
    source.write_bytes(source.read_bytes() + suffix.encode())
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("recipe", ["canonical", "native_fixture", "negative_run"])
def test_registered_whole_parent_is_refused(tmp_path, recipe):
    parts = fixture(tmp_path, recipe)
    assert observe(parts)
    with pytest.raises(TalkCutError):
        observe(parts, registered={parts["parents"][0]["original"]["sha256"]})


@pytest.mark.parametrize("recipe", ["canonical", "native_fixture", "negative_run"])
def test_selected_leaf_never_removes_private_whole_parent_hash(tmp_path, recipe):
    parts = fixture(tmp_path, recipe)
    selected = [locator(parts, i, ["criteria", j, "description"])
                for i in range(len(parts["parents"])) for j in range(13)]
    private, phrases, graph = inventory(parts, selected)
    assert len(graph["review_text_origins"]) == len(selected)
    for pair in parts["parents"]:
        original = pair["original"]
        assert private[original["sha256"]] == "review"
        scan = privacy.Scan(private, phrases)
        scan.payload(Path(original["path"]).read_bytes(), "synthetic ordinary publication blob")
        assert any(row.get("sha256") == original["sha256"] for row in scan.findings)


def test_selected_snapshot_does_not_select_original_or_other_copy(tmp_path):
    parts = fixture(tmp_path)
    original = parts["parents"][0]["original"]
    snapshot = write(parts["folder"] / "separate-snapshot.json", Path(original["path"]).read_bytes())
    def mutate(value):
        value["parents"][0]["snapshot"] = snapshot
    parts["authority_mutator"] = mutate
    refresh(parts)
    chosen = locator(parts)
    chosen["parent"] = snapshot
    assert observe(parts, [chosen])[0]["parent"] == snapshot
    before, before_phrases, _ = inventory(parts, [])
    after, after_phrases, graph = inventory(parts, [chosen])
    assert PHRASE in before_phrases and PHRASE in after_phrases
    assert all(after[key] == value for key, value in before.items())
    assert len(graph["review_text_origins"]) == 1


@pytest.mark.parametrize("fault", ["duplicate_key", "whitespace", "compact", "truncated"])
def test_exact_original_serialization_is_not_silently_repaired(tmp_path, fault):
    parts = fixture(tmp_path)
    assert observe(parts)
    data = Path(parts["parents"][0]["original"]["path"]).read_bytes()
    if fault == "duplicate_key":
        data = data.replace(b'{', b'{"schema_version":"bad",', 1)
    elif fault == "whitespace":
        data += b" "
    elif fault == "compact":
        data = encoded(parts["values"][0])
    else:
        data = data[:-4]
    ref = write(Path(parts["parents"][0]["original"]["path"]), data)
    authority = copy.deepcopy(parts["authority"])
    authority["parents"][0] = {"original": ref, "snapshot": ref}
    parts["authority_ref"] = write(Path(parts["authority_ref"]["path"]), authority)
    chosen = locator(parts)
    chosen["parent"] = ref
    with pytest.raises(TalkCutError):
        observe(parts, [chosen])


@pytest.mark.parametrize("fault", ["missing_caller", "duplicate_caller", "different_junit", "different_constructor_map"])
def test_native_recorded_source_edges_are_required(tmp_path, fault):
    parts = fixture(tmp_path, "native_fixture", embedded=True)
    assert observe(parts)
    def mutate(authority):
        records = authority["records"]
        handoff = json.loads(Path(records["handoff"]["path"]).read_bytes())
        if fault == "missing_caller":
            handoff["tests"]["test_sources"] = []
        elif fault == "duplicate_caller":
            handoff["tests"]["test_sources"] *= 2
        elif fault == "different_junit":
            handoff["tests"]["junit"] = write(parts["folder"] / "other.xml", b"<testsuites/>")
        else:
            identity = handoff["public_code_identity"]
            identity["files"]["src/talkcut/contracts.py"] = "0" * 64
            identity["code_tree_hash"] = hashlib.sha256(json.dumps(identity["files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        ref = write(Path(records["handoff"]["path"]), handoff)
        records["handoff"] = records["test_record"]["parent"] = records["identity_record"] = ref
    parts["authority_mutator"] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("fault", ["swap_branch", "wrong_input_contract", "missing_artifact"])
def test_negative_rows_need_exact_branch_relations(tmp_path, fault):
    parts = fixture(tmp_path, "negative_run")
    assert observe(parts)
    def mutate(result):
        pairs = result["cases"]["threshold_tamper"]["pairs"]
        if fault == "swap_branch":
            pairs[0]["mutation_input"], pairs[1]["mutation_input"] = pairs[1]["mutation_input"], pairs[0]["mutation_input"]
        elif fault == "missing_artifact":
            result["artifacts"] = [ref for ref in result["artifacts"] if ref != pairs[0]["mutation_input"]]
        else:
            old = pairs[0]["mutation_input"]
            new = write(Path(old["path"]), {"contract": parts["parents"][2]["original"]})
            result["artifacts"] = [new if ref == old else ref for ref in result["artifacts"]]
            pairs[0]["mutation_input"] = new
    parts["result_mutator"] = mutate
    refresh(parts)
    with pytest.raises(TalkCutError):
        observe(parts)


@pytest.mark.parametrize("recipe", ["canonical", "native_fixture", "negative_run"])
def test_dependency_comments_do_not_claim_execution(tmp_path, recipe):
    parts = fixture(tmp_path, recipe)
    path = Path(parts["snapshots"]["contracts"]["path"])
    path.write_bytes(path.read_bytes() + b"\n# Inert synthetic comment, never execution evidence.\n")
    refresh(parts)
    observed = observe(parts)
    assert observed[0]["commands"] == []
    assert observed[0]["claim_status"] == "UNVERIFIED"
    assert "invocation and physical copying are not approved" in observed[0]["scope"]
