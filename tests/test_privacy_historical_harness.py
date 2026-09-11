"""Synthetic Git boundaries, not completed fixture or provider execution claims."""
import ast
import copy
import json
import subprocess
from pathlib import Path

import pytest

from talkcut import evaluator_negative as negative
from talkcut import privacy_checks as privacy
from talkcut.contracts import code_identity
from talkcut.project import TalkCutError, artifact_ref


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return artifact_ref(path)


def git(repo, *args):
    return subprocess.check_output(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", *args], cwd=repo, stderr=subprocess.DEVNULL, text=True).strip()


@pytest.fixture
def authority(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    harness = repo / "src/talkcut/evaluator_negative.py"
    harness.parent.mkdir(parents=True)
    data = Path(negative.__file__).read_bytes()
    harness.write_bytes(data)
    generator = repo / "examples/recovery.py"
    generator.parent.mkdir()
    generator.write_bytes((Path(privacy.__file__).resolve().parents[2] / "examples/recovery.py").read_bytes())
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "Synthetic source boundary")
    identity = code_identity(repo)
    snapshot = tmp_path / "snapshot.py"
    snapshot.write_bytes(data)
    monkeypatch.setattr(negative, "__file__", str(harness))
    directory = tmp_path / "run"
    directory.mkdir()
    origin = artifact_ref(harness)
    deps = {"code_tree_hash": identity["code_tree_hash"]}
    request = {"harness": origin, "code_identity": identity, "dependencies": deps}
    raw = {"harness": origin, "status": "UNVERIFIED", "dependencies": deps}
    receipt = {"harness": origin, "status": "UNVERIFIED", "dependencies": deps, "test_only": True, "final_ac12_audit": False}
    locator = {"original": origin, "snapshot": artifact_ref(snapshot), "historical_synthetic_harness": {"schema_version": "historical-synthetic-harness/v1", "git_revision": identity["code_revision"], "runs": []}}

    def write():
        raw["request"] = save(directory / "request.json", request)
        run = save(directory / "result.json", raw)
        receipt.update(result=run, request=raw["request"])
        save(directory / "receipt.json", receipt)
        locator["historical_synthetic_harness"]["runs"] = [run]
        return run

    return {"repo": repo, "harness": harness, "snapshot": snapshot, "request": request, "raw": raw, "receipt": receipt, "locator": locator, "write": write, "run": write()}


def checked(a, locators=None, runs=None, registered=None):
    return privacy._historical_synthetic_harnesses([a["locator"]] if locators is None else locators, [a["run"]] if runs is None else runs, a["repo"], set() if registered is None else registered)


def test_exact_source_is_only_unclassified_origin(authority):
    row = next(iter(checked(authority).values()))
    assert row["historical_code_identity"] == authority["request"]["code_identity"]
    assert row["classification"] == "UNCLASSIFIED" and row["execution_status"] == "UNVERIFIED"
    assert checked(authority) == checked(authority)


def test_ordinary_snapshot_is_unchanged(authority):
    assert checked(authority, [{k: authority["locator"][k] for k in ("original", "snapshot")}]) == {}


@pytest.mark.parametrize("mutation", ["extra_locator", "wrong_schema", "extra_binding", "missing_runs", "revision_type", "revision_expression", "unknown_revision", "origin_path", "origin_hash", "snapshot_hash", "unscoped_run", "duplicate_binding", "duplicate_runs", "registered_source", "snapshot_changed", "snapshot_alias", "origin_alias", "extra_origin"])
def test_closed_locator_refusals(authority, mutation):
    a = authority
    loc = a["locator"]
    bind = loc["historical_synthetic_harness"]
    locators, runs, registered = [loc], [a["run"]], set()
    if mutation == "extra_locator":
        loc["classification"] = "PUBLIC_APPROVED"
    elif mutation == "wrong_schema":
        bind["schema_version"] = "generic/v1"
    elif mutation == "extra_binding":
        bind["argv"] = ["supplied"]
    elif mutation == "missing_runs":
        bind["runs"] = []
    elif mutation == "revision_type":
        bind["git_revision"] = True
    elif mutation == "revision_expression":
        bind["git_revision"] = "HEAD^{commit}"
    elif mutation == "unknown_revision":
        bind["git_revision"] = "0" * 40
    elif mutation == "origin_path":
        loc["original"] = {**loc["original"], "path": str(a["repo"] / "src/copied.py")}
    elif mutation == "origin_hash":
        loc["original"] = {**loc["original"], "sha256": "0" * 64}
    elif mutation == "snapshot_hash":
        loc["snapshot"] = {**loc["snapshot"], "sha256": "0" * 64}
    elif mutation == "unscoped_run":
        runs = []
    elif mutation == "duplicate_binding":
        locators.append(copy.deepcopy(loc))
    elif mutation == "duplicate_runs":
        runs.append(copy.deepcopy(a["run"]))
    elif mutation == "registered_source":
        registered.add(loc["original"]["sha256"])
    elif mutation == "snapshot_changed":
        a["snapshot"].write_bytes(a["snapshot"].read_bytes() + b"\n# changed\n")
    elif mutation == "snapshot_alias":
        alias = a["snapshot"].with_name("alias.py")
        alias.symlink_to(a["snapshot"])
        loc["snapshot"] = {**loc["snapshot"], "path": str(alias)}
    elif mutation == "origin_alias":
        loc["original"] = {**loc["original"], "path": str(a["repo"] / "src/talkcut/../talkcut/evaluator_negative.py")}
    elif mutation == "extra_origin":
        loc["original"] = {**loc["original"], "role": "public"}
    with pytest.raises((TalkCutError, KeyError, TypeError)):
        checked(a, locators, runs, registered)


@pytest.mark.parametrize("mutation", ["identity_hash", "identity_member", "identity_denominator", "revision", "request_harness", "raw_harness", "receipt_harness", "receipt_pass", "receipt_test_only", "receipt_final_audit"])
def test_exact_record_bindings(authority, mutation):
    a = authority
    identity = a["request"]["code_identity"]
    if mutation == "identity_hash":
        identity["code_tree_hash"] = "0" * 64
    elif mutation == "identity_member":
        identity["files"]["src/talkcut/evaluator_negative.py"] = "0" * 64
    elif mutation == "identity_denominator":
        identity["files"]["src/extra.py"] = "0" * 64
    elif mutation == "revision":
        identity["code_revision"] = "0" * 40
    elif mutation.endswith("_harness"):
        record = a[mutation.removesuffix("_harness")]
        record["harness"] = {**record["harness"], "sha256": "0" * 64}
    elif mutation == "receipt_pass":
        a["receipt"]["status"] = "PASS"
    elif mutation == "receipt_test_only":
        a["receipt"]["test_only"] = False
    else:
        a["receipt"]["final_ac12_audit"] = True
    a["run"] = a["write"]()
    with pytest.raises(TalkCutError, match="identities do not agree"):
        checked(a)


def test_wrong_real_commit(authority):
    a = authority
    (a["repo"] / "src/new.py").write_text("x = 1\n")
    git(a["repo"], "add", ".")
    git(a["repo"], "commit", "-qm", "Different revision")
    a["locator"]["historical_synthetic_harness"]["git_revision"] = git(a["repo"], "rev-parse", "HEAD")
    with pytest.raises(TalkCutError, match="identities do not agree"):
        checked(a)


def test_unsupported_git_bound_mutation(authority):
    a = authority
    current = a["harness"].read_text()
    changed = current.replace('SOURCE_MUTATION = b"\\nTALKCUT_SYNTHETIC_NEGATIVE_SOURCE_MUTATION\\n"', 'SOURCE_MUTATION = b"unsupported"')
    assert changed != current
    a["harness"].write_text(changed)
    git(a["repo"], "add", ".")
    git(a["repo"], "commit", "-qm", "Unsupported grammar")
    identity = code_identity(a["repo"])
    a["snapshot"].write_text(changed)
    a["locator"].update(original=artifact_ref(a["harness"]), snapshot=artifact_ref(a["snapshot"]))
    a["locator"]["historical_synthetic_harness"]["git_revision"] = identity["code_revision"]
    a["harness"].write_text(current)
    with pytest.raises(TalkCutError, match="technical grammar differs"):
        checked(a)


def test_duplicate_json(authority):
    a = authority
    req = Path(a["raw"]["request"]["path"])
    req.write_text(req.read_text().strip()[:-1] + ',"dependencies":' + json.dumps(a["request"]["dependencies"]) + '}\n')
    a["raw"]["request"] = artifact_ref(req)
    a["run"] = save(Path(a["run"]["path"]), a["raw"])
    a["receipt"].update(result=a["run"], request=a["raw"]["request"])
    save(req.parent / "receipt.json", a["receipt"])
    a["locator"]["historical_synthetic_harness"]["runs"] = [a["run"]]
    with pytest.raises(TalkCutError, match="not JSON") as failure:
        checked(a)
    assert isinstance(failure.value.__cause__, TalkCutError)
    assert "duplicate keys" in str(failure.value.__cause__)


def test_no_current_replay(authority):
    a = authority
    with pytest.raises(TalkCutError, match="Preserved synthetic replay bundle is required"):
        privacy._synthetic_failure_inventory([a["run"]], a["repo"], set(), source_snapshots=[a["locator"]])


def test_no_selected_run(authority):
    a = authority
    with pytest.raises(TalkCutError, match="no selected synthetic runs"):
        privacy._synthetic_failure_inventory([], a["repo"], set(), source_snapshots=[a["locator"]])


@pytest.mark.parametrize("field", ["code_revision", "code_tree_hash", "files", "contract_hash", "extra_fact"])
@pytest.mark.parametrize("side", ["historical", "current"])
def test_production_threshold_gate_rejects_forged_facts(field, side):
    tree = ast.parse(Path(privacy.__file__).read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_replay_historical_synthetic_controls")
    gate = next(n for n in ast.walk(fn) if isinstance(n, ast.If) and ast.unparse(n.test) == "case_id == 'threshold_tamper' and side == 'control'")
    old = {"code_revision": "old", "code_tree_hash": "old-tree", "files": {"a": "old"}}
    current = {"code_revision": "current", "code_tree_hash": "new-tree", "files": {"a": "new"}}
    observed, actual = {"facts": {**old, "contract_hash": "same"}}, {"facts": {**current, "contract_hash": "same"}}
    (observed if side == "historical" else actual)["facts"][field] = "forged"
    values = {"case_id": "threshold_tamper", "side": "control", "observed": observed, "actual_response": actual, "history": {"historical_code_identity": old}, "current_code": current, "_require": privacy._require}
    with pytest.raises(TalkCutError, match="exact code and contract facts"):
        exec(compile(ast.fix_missing_locations(ast.Module(body=[gate], type_ignores=[])), "production-threshold-gate", "exec"), values)  # noqa: S102 - inspected production AST only
