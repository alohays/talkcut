"""Adversarial raw verification parsers; no whole-suite runner recursion."""

import copy
import zipfile
from pathlib import Path

import pytest

from talkcut.project import TalkCutError, artifact_ref, atomic_json
from talkcut.reproducibility_checks import (
    _commands,
    _expected_commands,
    _license_support_audit,
    _license_support_findings,
    _locked_runtime,
    _requirements,
    verify_reproducibility,
)
from talkcut.verification import _snapshot


@pytest.fixture
def ledger(tmp_path):
    root, run, outside = [tmp_path / name for name in ("repo", "run", "outside")]
    for path in (root, run, outside, run / "pytest-basetemp"):
        path.mkdir()
    report = {"directory": str(run), "outside_cwd": str(outside),
              "tools_before": {"uv": {"path": "/unit-fixture/uv"}},
              "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:01:00+00:00"}
    rows = []
    for index, (name, argv, cwd) in enumerate(_expected_commands(report, root)):
        stdout, stderr = run / f"{name}.stdout", run / f"{name}.stderr"
        stdout.write_text("Parser fixture; not an actual verification execution\n")
        stderr.write_text("")
        record = {"schema_version": "verification-command/v1", "name": name, "argv": argv, "cwd": str(cwd),
                  "started_at": f"2026-01-01T00:00:{index * 2 + 1:02d}+00:00",
                  "finished_at": f"2026-01-01T00:00:{index * 2 + 2:02d}+00:00",
                  "status": "PASS", "exit_code": 0, "timed_out": False, "interrupted": False, "error": None,
                  "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr)}
        receipt = run / f"{name}.json"
        atomic_json(receipt, record)
        rows.append({**record, "receipt": artifact_ref(receipt)})
    report["executions"] = rows
    return root, report


def test_missing_verification_command_cannot_reduce_denominator(ledger):
    root, report = ledger
    report["executions"].pop()
    with pytest.raises(TalkCutError, match="denominator"):
        _commands(report, root)


@pytest.mark.parametrize("replacement", [["python", "-c", "print(1+1)"], ["uv", "run", "pytest", "-q", "-k", "one_test"]])
def test_canned_success_or_subset_command_cannot_borrow_expected_labels(ledger, replacement):
    root, report = ledger
    report["executions"][4]["argv"] = replacement
    with pytest.raises(TalkCutError, match="required complete"):
        _commands(report, root)


def test_unbounded_root_collection_is_rejected(ledger):
    root, report = ledger
    report["executions"][4]["argv"].remove("tests")
    with pytest.raises(TalkCutError, match="required complete"):
        _commands(report, root)


def test_command_row_cannot_relabel_its_preserved_receipt(ledger):
    root, report = ledger
    report["executions"][0]["exit_code"] = 1
    with pytest.raises(TalkCutError, match="preserved execution receipt"):
        _commands(report, root)


def test_raw_stdout_bytes_are_rehashed(ledger):
    root, report = ledger
    Path(report["executions"][0]["stdout"]["path"]).write_text("Changed after execution")
    with pytest.raises(TalkCutError, match="missing or changed"):
        _commands(report, root)


def test_install_check_cwd_cannot_be_inside_checkout(ledger):
    root, report = ledger
    report["outside_cwd"] = str(root / "pretend-isolated")
    with pytest.raises(TalkCutError, match="outside the checkout"):
        _commands(report, root)


def test_actual_runner_failure_never_becomes_reproducibility_pass(tmp_path):
    verification, receipt, raw = [tmp_path / name for name in ("verification.json", "receipt.json", "raw.json")]
    atomic_json(verification, {"schema_version": "oss-verification/v1", "status": "FAIL",
                              "technical_execution_pass": False, "errors": ["pytest collection failed"]})
    atomic_json(receipt, {"schema_version": "execution-receipt/v1", "exit_code": 0, "completed": True})
    atomic_json(raw, {"schema_version": "reproducibility-input/v1",
                     "verification": artifact_ref(verification), "receipt": artifact_ref(receipt)})
    with pytest.raises(TalkCutError, match="did not complete successfully"):
        verify_reproducibility(artifact_ref(raw), tmp_path)


def test_current_documentation_must_match_actual_verified_snapshot(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("Original support claims")
    before = _snapshot(root)
    verification, receipt, raw = [tmp_path / name for name in ("verification.json", "receipt.json", "raw.json")]
    atomic_json(verification, {"schema_version": "oss-verification/v1", "status": "PASS",
                              "technical_execution_pass": True, "unchanged_inputs_and_tools": True,
                              "interrupted": False, "errors": [], "before": before, "after": copy.deepcopy(before)})
    atomic_json(receipt, {})
    atomic_json(raw, {"schema_version": "reproducibility-input/v1",
                     "verification": artifact_ref(verification), "receipt": artifact_ref(receipt)})
    (root / "README.md").write_text("Different support claims")
    with pytest.raises(TalkCutError, match="stale"):
        verify_reproducibility(artifact_ref(raw), root)


@pytest.mark.parametrize("text", [
    "demo>=1\n", "demo==1\n", "demo==1 ; sys_platform == 'linux'\n",
    "demo==1\n --hash=sha256:" + "a" * 64 + "\ndemo==1\n --hash=sha256:" + "a" * 64,
])
def test_unpinned_unhashed_unknown_marker_or_duplicate_runtime_is_rejected(text):
    with pytest.raises(TalkCutError):
        _requirements(text)


def test_known_python312_typing_extensions_marker_is_explicitly_supported():
    result = _requirements("typing-extensions==4.16.0 ; python_full_version < '3.13' \\\n --hash=sha256:" + "a" * 64)
    assert result == {"typing-extensions": ("4.16.0", {"a" * 64})}


@pytest.fixture
def locked_runtime(tmp_path):
    root, site = tmp_path / "repo", tmp_path / "site-packages"
    root.mkdir()
    site.mkdir()
    for name, version in (("talkcut", "0.1.0"), ("demo-dep", "1.0")):
        directory = site / (name.replace("-", "_") + "-" + version + ".dist-info")
        directory.mkdir()
        (directory / "METADATA").write_text(f"Name: {name}\nVersion: {version}\n")
    (site / "talkcut").mkdir()
    (site / "demo_dep").mkdir()
    (site / "demo_dep/__init__.py").write_text("FIXTURE_VALUE = 1\n")
    archive = tmp_path / "demo_dep-1.0-py3-none-any.whl"
    with zipfile.ZipFile(archive, "w") as wheel:
        for path in [site / "demo_dep/__init__.py", site / "demo_dep-1.0.dist-info/METADATA"]:
            wheel.write(path, str(path.relative_to(site)))
    archive_ref = artifact_ref(archive)
    lock = '[[package]]\nname="talkcut"\nversion="0.1.0"\nsource={editable="."}\ndependencies=[{name="demo-dep"}]\n'
    lock += '[[package]]\nname="demo-dep"\nversion="1.0"\nwheels=[{hash="sha256:' + archive_ref["sha256"] + '"}]\n'
    (root / "uv.lock").write_text(lock)
    export = tmp_path / "requirements.txt"
    export.write_text("demo-dep==1.0 \\\n --hash=sha256:" + archive_ref["sha256"] + "\n")
    installed = {"package_directory": str(site / "talkcut"), "version": "0.1.0",
                 "python": "3.12.13 parser fixture", "installed_distributions": [["talkcut", "0.1.0"], ["demo-dep", "1.0"]]}
    return root, export, installed, [archive_ref]


def test_runtime_lock_matches_both_export_hashes_and_actual_dist_metadata(locked_runtime):
    assert _locked_runtime(*locked_runtime) == {"demo-dep": "1.0"}


def test_wrong_exported_wheel_hash_cannot_claim_locked_install(locked_runtime):
    root, export, installed, archives = locked_runtime
    export.write_text(export.read_text().replace(archives[0]["sha256"], "b" * 64))
    with pytest.raises(TalkCutError, match="hashes differ"):
        _locked_runtime(root, export, installed)


def test_changed_installed_runtime_version_is_detected(locked_runtime):
    root, export, installed, _ = locked_runtime
    metadata = Path(installed["package_directory"]).parent / "demo_dep-1.0.dist-info/METADATA"
    metadata.write_text("Name: demo-dep\nVersion: 2.0\n")
    with pytest.raises(TalkCutError, match="Actual isolated"):
        _locked_runtime(root, export, installed)


def test_missing_transitive_dependency_cannot_be_removed_from_denominator(locked_runtime):
    root, export, installed, _ = locked_runtime
    lock = root / "uv.lock"
    lock.write_text(lock.read_text().replace('dependencies=[{name="demo-dep"}]', 'dependencies=[{name="demo-dep"},{name="missing-dep"}]'))
    with pytest.raises(TalkCutError, match="omits"):
        _locked_runtime(root, export, installed)


@pytest.fixture
def license_support_findings(tmp_path):
    """Domain-parser control, not an executed provider or an OSS certificate."""
    document, fixture, license_path, junit = [tmp_path / name for name in ("README.md", "fixture.py", "LICENSE", "junit.xml")]
    document.write_text("Generated fixtures verify reversible cuts. Other platforms remain unverified.\n")
    fixture.write_text("# Authored mathematical fixture; no private recording or human ground truth.\nVALUE = 1\n")
    license_path.write_text("MIT License\nAuthored license parsing fixture; not a legal opinion.\n")
    junit.write_text('<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="fixture" name="test_restore"/></testsuite></testsuites>')
    document_ref, fixture_ref, license_ref, junit_ref = [artifact_ref(path) for path in (document, fixture, license_path, junit)]
    snapshot = {"fixture_files": [fixture_ref], "documentation_files": [document_ref], "license": license_ref,
                "declared_license_id": "MIT",
                "passing_test_nodes": ["fixture::test_restore"], "junit": junit_ref,
                "execution_evidence_hashes": [], "scope": "authored domain-parser unit control"}
    response = {"inspected_artifact_hashes": [ref["sha256"] for ref in (document_ref, fixture_ref, license_ref, junit_ref)],
                "fixture_licenses": [{**fixture_ref, "origin": "authored_synthetic", "license_id": "MIT", "license_refs": [license_ref],
                                      "reason": "Authored unit fixture source is bound to the exact declared repository license."}],
                "documentation_reviews": [{**document_ref, "all_support_claims_accounted_for": True,
                    "reason": "This parser control connects an exact source quote to an actual named JUnit record.",
                    "claims": [{"quote": "Generated fixtures verify reversible cuts.", "disposition": "tested_support",
                                "reason": "Named test and its original JUnit bytes provide the execution reference for this unit case.",
                                "test_nodes": ["fixture::test_restore"], "evidence_refs": [junit_ref]},
                               {"quote": "Other platforms remain unverified.", "disposition": "explicitly_unverified",
                                "reason": "The document expressly leaves other platforms unverified; this does not grant platform support."}]}]}
    return snapshot, response


def test_license_support_domain_positive_preserves_explicitly_unverified_claims(license_support_findings):
    snapshot, response = license_support_findings
    assert _license_support_findings(snapshot, response) == {"support_claims_match_tests": True, "public_fixture_license_checked": True}
    assert response["documentation_reviews"][0]["claims"][1]["disposition"] == "explicitly_unverified"


@pytest.mark.parametrize("mutation", [
    lambda value: value.update(fixture_licenses=[]),
    lambda value: value.update(documentation_reviews=[]),
    lambda value: value["fixture_licenses"][0].update(license_refs=[]),
    lambda value: value["fixture_licenses"][0].update(sha256="0" * 64),
    lambda value: value["fixture_licenses"][0].update(license_id="Different-License"),
    lambda value: value["documentation_reviews"][0].update(claims=[]),
    lambda value: value["documentation_reviews"][0]["claims"][0].update(quote="A claim absent from the actual current source document"),
    lambda value: value["documentation_reviews"][0]["claims"][0].update(test_nodes=["fixture::unexecuted_test"]),
    lambda value: value["documentation_reviews"][0]["claims"][0].update(evidence_refs=[]),
    lambda value: value.update(inspected_artifact_hashes=[]),
])
def test_license_support_missing_or_fabricated_rows_cannot_close_metrics(license_support_findings, mutation):
    snapshot, response = license_support_findings
    mutation(response)
    with pytest.raises(TalkCutError):
        _license_support_findings(snapshot, response)


def test_document_byte_mutation_invalidates_license_support_claims(license_support_findings):
    snapshot, response = license_support_findings
    Path(snapshot["documentation_files"][0]["path"]).write_text("Changed support policy after the actual audit")
    with pytest.raises(TalkCutError, match="changed"):
        _license_support_findings(snapshot, response)


def test_missing_independent_license_support_audit_keeps_both_metrics_null(tmp_path):
    result = _license_support_audit({}, tmp_path)
    assert result["status"] == "UNVERIFIED"
    assert result["measurements"] == {"support_claims_match_tests": None, "public_fixture_license_checked": None}


def test_license_support_adapter_binds_current_snapshot_and_calls_executed_audit(tmp_path, monkeypatch, license_support_findings):
    # Only the provider transport and prior whole-OSS execution are controlled
    # here; this exercises adapter binding without forging real certifications.
    snapshot, response = license_support_findings
    snapshot.update({"implementation_run_ids": ["authored-verification-run"], "input_refs": [snapshot["license"]],
                     "dependencies": {"code_tree_hash": "authored-unit-control"}})
    path = tmp_path / "snapshot.json"
    atomic_json(path, snapshot)
    from talkcut import reproducibility_checks, review
    monkeypatch.setattr(reproducibility_checks, "build_reproducibility_audit_snapshot", lambda *args: snapshot)
    observed = {}
    def provider_control(audit_ref, **kwargs):
        observed.update(kwargs)
        return {"response": response}
    monkeypatch.setattr(review, "verify_artifact_audit", provider_control)
    inputs = {"verification": {"authored": True}, "audit_snapshot": artifact_ref(path), "independent_audit": {"authored": True}}
    result = _license_support_audit(inputs, tmp_path)
    assert result["status"] == "PASS" and result["semantic_ground_truth"] == "UNVERIFIED"
    assert observed["scope"] == "reproducibility_license_support"
    assert observed["excluded_run_ids"] == {"authored-verification-run"}
    snapshot["dependencies"] = {"code_tree_hash": "changed-code"}
    with pytest.raises(TalkCutError, match="stale"):
        _license_support_audit(inputs, tmp_path)
