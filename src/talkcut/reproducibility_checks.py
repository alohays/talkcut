"""Recompute OSS facts from executed verification artifacts.

Input reproducibility-input/v1 binds verification and its receipt; an independent
audit is optional. Hashes alone cannot prove a process was honest. This verifier
checks current code, exact argv, raw results, installed bytes and actual recovery
media. It never executes a command copied from an evidence record.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
import tomllib
import zipfile
from datetime import datetime
from email.parser import BytesParser
from pathlib import Path
from typing import Any

import jsonschema

from .measurement_checks import verify_roundtrip
from .project import TalkCutError, artifact_ref, sha256
from .verification import (
    PROBE_SCRIPT,
    _doctor_probe,
    _environment_inventory,
    _installed_probe,
    _junit,
    _recovery_result,
    _snapshot,
    _tool_snapshot,
    _wheel_inventory,
)


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise TalkCutError("REPRODUCIBILITY_UNVERIFIED", message)


def _file(ref: Any) -> Path:
    _require(isinstance(ref, dict) and isinstance(ref.get("path"), str) and isinstance(ref.get("sha256"), str),
             "A hashed reproducibility artifact is required")
    path = Path(ref["path"])
    _require(path.is_absolute() and path.is_file() and sha256(path) == ref["sha256"], "Reproducibility artifact is missing or changed")
    if "bytes" in ref:
        _require(path.stat().st_size == ref["bytes"], "Reproducibility artifact size changed")
    return path


def _json(ref: Any) -> Any:
    return json.loads(_file(ref).read_text())


def _window(value: dict[str, Any]) -> tuple[datetime, datetime]:
    begin, end = datetime.fromisoformat(value["started_at"]), datetime.fromisoformat(value["finished_at"])
    _require(begin.tzinfo is not None and end.tzinfo is not None and begin < end, "Execution timestamps are incomplete or reversed")
    return begin, end


def _expected_commands(report: dict[str, Any], root: Path) -> list[tuple[str, list[str], Path]]:
    directory, outside = Path(report["directory"]), Path(report["outside_cwd"])
    _require(directory.is_absolute() and outside.is_absolute() and not outside.resolve().is_relative_to(root), "Installed checks did not use a directory outside the checkout")
    uv = report["tools_before"]["uv"]["path"]
    _require(isinstance(uv, str) and Path(uv).is_absolute(), "Executed uv path is missing")
    prefix, dist = directory / "isolated-env", directory / "fresh-dist"
    python = str(prefix / "bin" / "python")
    return [
        ("uv-version", [uv, "--version"], root),
        ("locked-sync", [uv, "sync", "--locked", "--python", "3.12"], root),
        ("ruff", [uv, "run", "--locked", "ruff", "check", "src", "tests", "examples"], root),
        ("mypy", [uv, "run", "--locked", "mypy", "src/talkcut"], root),
        ("pytest", [uv, "run", "--locked", "pytest", "-q", "tests", "--junitxml",
                    str(directory / "pytest.junit.xml"), "--basetemp", str(directory / "pytest-basetemp")], root),
        ("build", [uv, "build", "--out-dir", str(dist), "--no-create-gitignore"], root),
        ("locked-runtime-export", [uv, "export", "--locked", "--no-dev", "--no-emit-project", "--format",
                                  "requirements.txt", "--output-file", str(directory / "runtime-requirements.txt")], root),
        ("isolated-venv", [uv, "venv", "--no-project", "--python", "3.12", str(prefix)], outside),
        ("isolated-install", [uv, "pip", "sync", "--python", python, "--require-hashes", "--strict",
                              str(directory / "runtime-requirements.txt"), str(directory / "wheel-requirements.txt")], outside),
        ("installed-version", [python, "-I", "-m", "talkcut", "--version"], outside),
        ("installed-doctor", [python, "-I", "-m", "talkcut", "doctor", "--json"], outside),
        ("installed-probe", [python, "-I", str(outside / "probe.py")], outside),
        ("documented-recovery", [python, "-I", str(outside / "recovery.py"), str(directory / "recovery-example")], outside),
    ]


def _commands(report: dict[str, Any], root: Path) -> dict[str, dict[str, Any]]:
    expected = _expected_commands(report, root)
    actual = report["executions"]
    _require(len(actual) == len(expected), "Verification command denominator changed")
    run_start, run_end = _window(report)
    previous = run_start
    results = {}
    for row, (name, argv, cwd) in zip(actual, expected, strict=True):
        _require(row.get("name") == name and row.get("argv") == argv and row.get("cwd") == str(cwd),
                 f"Executed command is not the required complete verification step: {name}")
        receipt = _json(row.get("receipt"))
        _require(receipt == {key: value for key, value in row.items() if key != "receipt"},
                 "Command record differs from its preserved execution receipt")
        _require(receipt.get("schema_version") == "verification-command/v1"
                 and receipt.get("status") == "PASS" and type(receipt.get("exit_code")) is int
                 and receipt["exit_code"] == 0 and receipt.get("timed_out") is False
                 and receipt.get("interrupted") is False and receipt.get("error") is None,
                 f"Verification command did not execute successfully: {name}")
        start, end = _window(receipt)
        _require(previous <= start < end <= run_end, "Sequential command is outside its actual verification execution window")
        previous = end
        for kind in ("stdout", "stderr"):
            _file(row[kind])
        results[name] = row
    _require((Path(report["directory"]) / "pytest-basetemp").is_dir(), "Actual test artifacts were not preserved")
    return results


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requirements(text: str) -> dict[str, tuple[str, set[str]]]:
    """Exact pins for the mandated Python 3.12 run; unknown markers fail closed."""
    records: dict[str, tuple[str, set[str]]] = {}
    active = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # uv's current lock exports this conditional typing-extensions pin.
        # It applies to every required Python 3.12 execution. Other markers
        # require explicit implementation instead of guessing their semantics.
        pin = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)(?:\s*;\s*python_full_version\s*<\s*'3\.13')?\s*\\?", line)
        digest = re.fullmatch(r"--hash=sha256:([a-f0-9]{64})\s*\\?", line)
        if pin:
            name = _normalize(pin.group(1))
            _require(name not in records, "Locked runtime export repeats a package")
            records[name] = (pin.group(2), set())
            active = name
        elif digest and active is not None:
            records[active][1].add(digest.group(1))
        else:
            raise TalkCutError("REPRODUCIBILITY_UNVERIFIED", "Unsupported or unpinned locked runtime requirement")
    _require(records and all(hashes for _, hashes in records.values()), "Every locked runtime dependency needs actual artifact hashes")
    return records


def _wheel_payloads(site: Path, versions: dict[str, str], records: dict[str, tuple[str, set[str]]],
                    wheel_archives: list[dict[str, Any]] | None) -> dict[str, str]:
    """Compare frozen locked archives with every installed package payload.

    Installed RECORD is mutable and is never the expected-file authority.
    Installer-generated dist-info records and bytecode have separate origins;
    source/native/data payloads and unexpected package files are checked here.
    Unknown wheel relocation/link layouts fail closed.
    """
    _require(isinstance(wheel_archives, list) and wheel_archives, "Preserved locked wheel archives are required to verify installed dependency bytes")
    assert wheel_archives is not None
    expected: dict[str, str] = {}
    selected: set[str] = set()
    metadata_dirs: set[str] = set()
    roots: set[str] = set()
    for ref in wheel_archives:
        archive_path = _file(ref)
        with zipfile.ZipFile(archive_path) as archive:
            infos = [row for row in archive.infolist() if not row.is_dir()]
            names = [row.filename for row in infos]
            _require(names and len(names) == len(set(names))
                     and all(not Path(name).is_absolute() and ".." not in Path(name).parts for name in names),
                     "Locked wheel contains duplicate or unsafe paths")
            _require(all((row.external_attr >> 16) & 0o170000 != 0o120000 and row.file_size <= 512 * 1024 * 1024 for row in infos),
                     "Locked wheel contains unsupported links or oversized payloads")
            metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
            _require(len(metadata) == 1, "Locked wheel metadata identity is ambiguous")
            parsed = BytesParser().parsebytes(archive.read(metadata[0]))
            name, version = _normalize(parsed["Name"]), parsed["Version"]
            _require(name in versions and name not in selected and versions[name] == version
                     and ref["sha256"] in records[name][1], "Preserved dependency wheel is duplicate, unrelated or outside the exact lock hashes")
            selected.add(name)
            metadata_dir = metadata[0].split("/")[0]
            metadata_dirs.add(metadata_dir)
            for member in names:
                parts = Path(member).parts
                _require(not parts[0].endswith(".data"), "Relocated wheel data/scripts require an explicitly supported verifier")
                roots.add(parts[0])
                if member == metadata_dir + "/RECORD":
                    continue  # uv rewrites this installer ledger; it is not trusted.
                digest = hashlib.sha256(archive.read(member)).hexdigest()
                _require(member not in expected or expected[member] == digest, "Locked wheels disagree on shared installed bytes")
                expected[member] = digest
    _require(selected == set(versions), "Preserved wheel denominator omits a locked installed dependency")
    for member, digest in expected.items():
        path = site / member
        _require(path.is_file() and not path.is_symlink() and sha256(path) == digest,
                 "Actual installed dependency bytes differ from the frozen locked wheel")
    allowed_generated = {directory + "/" + name for directory in metadata_dirs
                         for name in ("RECORD", "INSTALLER", "REQUESTED", "direct_url.json", "uv_cache.json")}
    observed: set[str] = set()
    for name in roots:
        path = site / name
        candidates = path.rglob("*") if path.is_dir() else [path]
        for candidate in candidates:
            _require(not candidate.is_symlink(), "Installed dependency tree contains an unsupported symlink")
            if candidate.is_file():
                member = str(candidate.relative_to(site))
                if "__pycache__" in candidate.parts and candidate.suffix == ".pyc":
                    continue
                observed.add(member)
    _require(observed - allowed_generated == set(expected), "Installed dependency tree contains missing or unregistered payload files")
    return expected


def _locked_runtime(root: Path, export: Path, installed: dict[str, Any],
                    wheel_archives: list[dict[str, Any]] | None = None,
                    seed_files: dict[str, str] | None = None) -> dict[str, str]:
    _require(installed["python"].split()[0].split(".")[:2] == ["3", "12"],
             "Runtime export verification requires the executed Python 3.12 profile")
    records = _requirements(export.read_text())
    packages = tomllib.loads((root / "uv.lock").read_text())["package"]
    versions = {}
    for name, (version, hashes) in records.items():
        matching = [row for row in packages if _normalize(row["name"]) == name and row["version"] == version]
        _require(len(matching) == 1, "Runtime pin is absent or ambiguous in the current lockfile")
        locked = matching[0]
        known = {item["hash"].removeprefix("sha256:") for item in locked.get("wheels", [])}
        if locked.get("sdist"):
            known.add(locked["sdist"]["hash"].removeprefix("sha256:"))
        _require(hashes == known and known, "Export hashes differ from the current locked artifacts")
        versions[name] = version
    package_path = Path(installed["package_directory"])
    observed = {_normalize(dist.metadata["Name"]): dist.version
                for dist in importlib.metadata.distributions(path=[str(package_path.parent)])}
    expected = {**versions, "talkcut": installed["version"]}
    _require(observed == expected, "Actual isolated environment package versions differ from locked runtime plus wheel")
    reported = {_normalize(name): version for name, version in installed["installed_distributions"]}
    _require(reported == observed, "Reported isolated dependencies differ from actual installed metadata")
    # Every transitive locked dependency is required, not only hand-listed pins.
    roots = [row for row in packages if row["name"] == "talkcut" and row.get("source", {}).get("editable") == "."]
    _require(len(roots) == 1, "Current lock does not identify one project")
    pending = [item["name"] for item in roots[0].get("dependencies", [])]
    required = set()
    while pending:
        name = _normalize(pending.pop())
        if name in required:
            continue
        _require(name in versions, "Runtime export omits a locked dependency")
        required.add(name)
        selected = next(row for row in packages if _normalize(row["name"]) == name and row["version"] == versions[name])
        pending.extend(item["name"] for item in selected.get("dependencies", []))
    _require(required == set(versions), "Runtime export contains unrelated or missing packages")
    payloads = _wheel_payloads(package_path.parent, versions, records, wheel_archives)
    site = package_path.parent
    seed_files = seed_files or {}
    for name, digest in seed_files.items():
        path = site / name
        _require(not Path(name).is_absolute() and ".." not in Path(name).parts and path.is_file()
                 and not path.is_symlink() and sha256(path) == digest, "Installer startup seed bytes changed")
    allowed_roots = {Path(name).parts[0] for name in [*payloads, *seed_files]}
    allowed_roots |= {"talkcut", "__pycache__"}
    allowed_roots |= {path.name for path in site.glob("talkcut-*.dist-info")}
    _require(all(path.name in allowed_roots for path in site.iterdir()),
             "Isolated site-packages contains unregistered startup or module payloads")
    return versions


def build_reproducibility_audit_snapshot(verification_ref: dict[str, str], repo_root: str | Path) -> dict[str, Any]:
    """Freeze pre-audit OSS inputs; never include later acceptance/audit reports."""
    root = Path(repo_root).resolve()
    report, current = _json(verification_ref), _snapshot(root)
    _require(report.get("schema_version") == "oss-verification/v1" and report.get("technical_execution_pass") is True
             and report.get("status") == "PASS", "License/support snapshot requires an actual completed OSS verification")
    _require(all(report[key]["input_hash"] == current["input_hash"] for key in ("before", "after")),
             "License/support snapshot is stale against current code and documentation")
    public = {**current["code_identity"]["files"], **current["documentation_example_files"]}
    public_refs = [{"path": str(root / name), "sha256": digest} for name, digest in sorted(public.items())]
    fixtures = [ref for ref in public_refs if Path(ref["path"]).relative_to(root).parts[0] in {"tests", "examples"}]
    documents = [ref for ref in public_refs if Path(ref["path"]).suffix == ".md"]
    _require(fixtures and documents and "LICENSE" in public, "Public fixture, documentation or license inventory is incomplete")
    declared_license = tomllib.loads((root / "pyproject.toml").read_text())["project"].get("license")
    _require(isinstance(declared_license, str) and declared_license, "An explicit current project license identifier is required")
    refs = [verification_ref, *public_refs]
    for row in report["executions"]:
        refs.extend(row[kind] for kind in ("stdout", "stderr", "receipt"))
    validation = report["validations"]
    refs.extend([validation["junit"]["raw"], validation["wheel"]["artifact"], validation["sdist"]["artifact"],
                 validation["installed_probe"]["raw"], validation["installed_doctor"]["raw"],
                 validation["recovery"]["raw"], validation["recovery"]["executions"],
                 *validation["recovery"]["outputs"].values()])
    for row in _json(validation["recovery"]["executions"]):
        refs.extend(row[kind] for kind in ("stdout", "stderr"))
    runtime = validation["runtime_wheels"]
    refs.extend([*runtime["archives"], runtime["downloads"], runtime["seed_site_files"]])
    unique = {}
    for ref in refs:
        _file(ref)
        unique[ref["sha256"]] = {"path": ref["path"], "sha256": ref["sha256"]}
    junit = _junit(_file(validation["junit"]["raw"]))
    _require(junit["status"] == "PASS", "Audited support claims require actual passing JUnit nodes")
    nodes = [row["classname"] + "::" + row["name"] for row in junit["nodes"]]
    return {"schema_version": "reproducibility-audit-snapshot/v1", "verification": verification_ref,
            "dependencies": {"code_tree_hash": current["code_identity"]["code_tree_hash"],
                             "documentation_example_hash": current["documentation_example_hash"], "verification_hash": verification_ref["sha256"]},
            "implementation_run_ids": [report["run_id"]], "input_refs": [unique[key] for key in sorted(unique)],
            "fixture_files": fixtures, "documentation_files": documents, "license": artifact_ref(root / "LICENSE"),
            "declared_license_id": declared_license,
            "passing_test_nodes": sorted(nodes), "junit": validation["junit"]["raw"],
            "execution_evidence_hashes": sorted({row[kind]["sha256"] for row in report["executions"] for kind in ("stdout", "stderr", "receipt")}),
            "scope": "Declared public fixture provenance/licenses and documented supported, rejected, planned or explicitly unverified behavior against the actual OSS execution. No lecture semantic correctness, AC06, human ground truth or media acceptance is certified."}


def _license_support_findings(snapshot: dict[str, Any], response: dict[str, Any]) -> dict[str, bool]:
    """Reconcile actual auditor findings with the frozen complete input lists."""
    inspected = set(response.get("inspected_artifact_hashes", []))
    def evidence(refs: Any) -> set[str]:
        _require(isinstance(refs, list) and refs, "Audit finding has no inspected source evidence")
        result = set()
        for ref in refs:
            _file(ref)
            _require(ref["sha256"] in inspected, "Audit finding cites an artifact outside the actual inspected inputs")
            result.add(ref["sha256"])
        return result
    expected = {ref["path"]: ref for ref in snapshot["fixture_files"]}
    rows = response.get("fixture_licenses", [])
    _require(isinstance(rows, list) and len(rows) == len(expected) and {row.get("path") for row in rows} == set(expected),
             "Fixture license audit omits or duplicates public fixture files")
    for row in rows:
        _require(row.get("sha256") == expected[row["path"]]["sha256"] and row.get("origin") in {"authored_synthetic", "licensed_external"}
                 and isinstance(row.get("reason"), str) and len(row["reason"].strip()) >= 30,
                 "Fixture origin/license finding is stale or unsubstantiated")
        license_hashes = evidence(row.get("license_refs"))
        _require(isinstance(row.get("license_id"), str) and row["license_id"], "Fixture license identity is missing")
        if row["origin"] == "authored_synthetic":
            _require(snapshot["license"]["sha256"] in license_hashes and row["license_id"] == snapshot["declared_license_id"],
                     "Authored fixture license differs from the actual declared repository license")
        else:
            quote = row.get("license_grant_quote")
            _require(isinstance(quote, str) and len(quote.strip()) >= 30
                     and any(quote in _file(ref).read_text() for ref in row["license_refs"]),
                     "External fixture license grant is not present in the actual inspected license source")
    expected = {ref["path"]: ref for ref in snapshot["documentation_files"]}
    reviews = response.get("documentation_reviews", [])
    _require(isinstance(reviews, list) and len(reviews) == len(expected) and {row.get("path") for row in reviews} == set(expected),
             "Support audit omits or duplicates current documentation")
    for row in reviews:
        _require(row.get("sha256") == expected[row["path"]]["sha256"] and row.get("all_support_claims_accounted_for") is True
                 and isinstance(row.get("reason"), str) and len(row["reason"].strip()) >= 30
                 and isinstance(row.get("claims"), list) and row["claims"],
                 "Support audit lacks complete current-document observations")
        text = _file(expected[row["path"]]).read_text()
        for claim in row["claims"]:
            _require(isinstance(claim.get("quote"), str) and len(claim["quote"].strip()) >= 10 and claim["quote"] in text
                     and claim.get("disposition") in {"tested_support", "tested_rejection", "explicitly_unverified", "planned_requirement"}
                     and isinstance(claim.get("reason"), str) and len(claim["reason"].strip()) >= 30,
                     "Audited support claim is absent from current source text or lacks a bounded disposition")
            if claim["disposition"] in {"tested_support", "tested_rejection"}:
                nodes = claim.get("test_nodes", [])
                _require(isinstance(nodes, list) and nodes and set(nodes).issubset(snapshot["passing_test_nodes"]),
                         "Supported/rejected behavior cites missing or non-passing actual test nodes")
                cited = evidence(claim.get("evidence_refs"))
                _require(bool(cited & {snapshot["junit"]["sha256"], *snapshot["execution_evidence_hashes"]}),
                         "Support claim has no actual test/command execution evidence")
    return {"support_claims_match_tests": True, "public_fixture_license_checked": True}


def _license_support_audit(inputs: dict[str, Any], root: Path) -> dict[str, Any]:
    if not inputs.get("independent_audit"):
        return {"status": "UNVERIFIED", "measurements": {"support_claims_match_tests": None, "public_fixture_license_checked": None},
                "evidence_refs": [], "reason": "A separately executed final fixture/license/support audit is absent"}
    snapshot_ref = inputs.get("audit_snapshot")
    snapshot = _json(snapshot_ref)
    assert isinstance(snapshot_ref, dict)
    current = build_reproducibility_audit_snapshot(inputs["verification"], root)
    _require(snapshot == current, "License/support audit snapshot is stale or its input denominator was changed")
    excluded = set(snapshot["implementation_run_ids"]) | set(inputs.get("implementation_run_ids", []))
    from .review import verify_artifact_audit
    checked = verify_artifact_audit(inputs["independent_audit"], scope="reproducibility_license_support", snapshot_ref=snapshot_ref,
                                   input_refs=snapshot["input_refs"], dependencies=snapshot["dependencies"], excluded_run_ids=excluded)
    measurements = _license_support_findings(snapshot, checked["response"])
    return {"status": "PASS", "measurements": measurements, "scope": snapshot["scope"],
            "evidence_refs": [snapshot_ref, inputs["independent_audit"], *snapshot["input_refs"]], "semantic_ground_truth": "UNVERIFIED"}


def verify_reproducibility(raw_ref: dict[str, Any], repo_root: str | Path) -> dict[str, Any]:
    """Return mechanical measurements; absent independent audits stay null."""
    root = Path(repo_root).resolve()
    inputs = _json(raw_ref)
    _require(inputs.get("schema_version") == "reproducibility-input/v1", "Typed reproducibility inputs are required")
    report = _json(inputs.get("verification"))
    receipt = _json(inputs.get("receipt"))
    _require(report.get("schema_version") == "oss-verification/v1"
             and report.get("technical_execution_pass") is True and report.get("status") == "PASS"
             and report.get("unchanged_inputs_and_tools") is True and report.get("interrupted") is False
             and not report.get("errors"), "Whole OSS verification did not complete successfully")
    current = _snapshot(root)
    for snapshot in (report["before"], report["after"]):
        _require(snapshot["input_hash"] == current["input_hash"]
                 and snapshot["code_identity"]["files"] == current["code_identity"]["files"]
                 and snapshot["code_identity"]["code_tree_hash"] == current["code_identity"]["code_tree_hash"]
                 and snapshot["documentation_example_files"] == current["documentation_example_files"],
                 "OSS verification is stale against current code, tests, documentation or examples")
    _require(report.get("producer") == {"path": "src/talkcut/verification.py", "sha256": sha256(root / "src/talkcut/verification.py")},
             "OSS result was not produced by the current verifier")
    _require(Path(report["repo_root"]).resolve() == root, "OSS verification targets a different checkout")
    _require(receipt.get("schema_version") == "execution-receipt/v1" and receipt.get("operation") == "verification:run"
             and receipt.get("run_id") == report.get("run_id") and receipt.get("completed") is True
             and type(receipt.get("exit_code")) is int and receipt["exit_code"] == 0
             and receipt.get("result") == inputs["verification"], "OSS execution receipt does not bind the successful raw result")
    _require(receipt["dependencies"]["code_tree_hash"] == current["code_identity"]["code_tree_hash"]
             and receipt["dependencies"]["documentation_example_hash"] == current["documentation_example_hash"],
             "OSS execution receipt dependencies changed")
    _require(_json(receipt["commands"]) == report["executions"], "OSS command ledger differs from actual execution result")
    actual_tools = _tool_snapshot()
    _require(report["tools_before"] == report["tools_after"], "Toolchain changed during OSS verification")
    for name in ("uv", "ffmpeg", "ffprobe"):
        _require(report["tools_before"][name] == actual_tools[name], "Verification media/build executable changed")
    runner = report["tools_before"]["runner_python"]
    _require(sha256(runner["path"]) == runner["sha256"], "Original verification Python executable changed")
    commands = _commands(report, root)
    directory, outside = Path(report["directory"]), Path(report["outside_cwd"])
    validations = report["validations"]
    junit_path = _file(validations["junit"]["raw"])
    _require(junit_path == directory / "pytest.junit.xml", "JUnit was borrowed from another execution")
    measured_junit = _junit(junit_path)
    _require(measured_junit == validations["junit"] and measured_junit["status"] == "PASS",
             "Actual JUnit nodes differ, failed, were skipped or were never executed")
    wheels, sdists = list((directory / "fresh-dist").glob("*.whl")), list((directory / "fresh-dist").glob("*.tar.gz"))
    _require(len(wheels) == len(sdists) == 1, "Fresh package build artifact count differs")
    wheel = _wheel_inventory(wheels[0], root)
    _require(wheel == validations["wheel"], "Wheel bytes or inventory differ from the original build")
    _require(_file(validations["sdist"]["artifact"]) == sdists[0], "Source distribution differs from the fresh build")
    expected_requirement = f"talkcut @ {wheels[0].as_uri()} --hash=sha256:{sha256(wheels[0])}\n"
    _require((directory / "wheel-requirements.txt").read_text() == expected_requirement, "Installed wheel requirement was changed or unpinned")
    runtime = directory / "runtime-requirements.txt"
    _require(runtime.read_bytes() == _file(commands["locked-runtime-export"]["stdout"]).read_bytes(), "Installed runtime requirements differ from actual locked export stdout")
    _require((outside / "probe.py").read_text() == PROBE_SCRIPT, "Executed installed probe code was changed")
    measured_probe = _installed_probe(_file(commands["installed-probe"]["stdout"]), directory / "isolated-env", wheel)
    _require(measured_probe == validations["installed_probe"], "Installed probe differs from its original raw stdout")
    installed = measured_probe["measurements"]
    prefix = directory / "isolated-env"
    package = Path(installed["package_directory"])
    actual_files = {str(path.relative_to(package)): sha256(path) for path in package.rglob("*")
                    if path.is_file() and "__pycache__" not in path.parts}
    _require(actual_files == installed["package_files"], "Installed package bytes changed after verification")
    for value in installed["schemas"].values():
        schema = json.loads(_file(value).read_text())
        jsonschema.validators.validator_for(schema).check_schema(schema)
    preserved_runtime = validations.get("runtime_wheels", {})
    _require(preserved_runtime.get("status") == "PASS", "Installed dependency wheel bytes were not preserved and verified")
    seed_ref = preserved_runtime.get("seed_site_files")
    _require(_file(seed_ref) == directory / "environment-seed.json", "Installer seed snapshot belongs to another execution")
    seed_files = _json(seed_ref)
    _require(validations.get("environment_seed") == {"status": "PASS", "files": seed_files}, "Installer seed snapshot differs from its measured pre-install state")
    runtime_versions = _locked_runtime(root, runtime, installed, preserved_runtime.get("archives"), seed_files)
    _require(_environment_inventory(prefix) == preserved_runtime.get("environment_files"),
             "Current isolated environment files/interpreter differ from the completed verification")
    _require(_file(preserved_runtime.get("interpreter")) == prefix / "bin/python", "Preserved interpreter belongs to another environment")
    _file(preserved_runtime.get("downloads"))
    measured_doctor = _doctor_probe(_file(commands["installed-doctor"]["stdout"]), actual_tools)
    _require(measured_doctor == validations["installed_doctor"], "Installed doctor raw output was changed")
    _require(sha256(outside / "recovery.py") == sha256(root / "examples/recovery.py"), "Executed documentation example differs from current source")
    recovery_path = directory / "recovery-example/result.json"
    recovery = _recovery_result(recovery_path)
    _require(recovery == validations["recovery"], "Documented recovery facts differ from actual artifacts")
    _require(Path(json.loads(_file(commands["documented-recovery"]["stdout"]).read_text())["result"]) == recovery_path,
             "Documented example stdout points to another roundtrip")
    # Re-open history, recompile schedules and re-decode actual MP4s.
    roundtrip = verify_roundtrip(json.loads(recovery_path.read_text()))
    _require(roundtrip["technical_roundtrip"] and all(roundtrip[key] for key in
             ("reopen", "unchanged_rerun", "timing_preserved", "history_preserved")),
             "Current actual public fixture roundtrip failed")
    audit = _license_support_audit(inputs, root)
    refs = [raw_ref, inputs["verification"], inputs["receipt"], validations["junit"]["raw"],
            wheel["artifact"], validations["sdist"]["artifact"], measured_probe["raw"], measured_doctor["raw"], recovery["raw"]]
    refs.extend([*preserved_runtime["archives"], preserved_runtime["downloads"], preserved_runtime["interpreter"], seed_ref])
    refs.extend(audit["evidence_refs"])
    _require(_snapshot(root)["input_hash"] == current["input_hash"], "Code/documentation changed while raw evidence was being verified")
    return {"schema_version": "recomputed-reproducibility/v1", "status": audit["status"],
            "measurements": {"clean_install": True, "locked_dependencies": True, "tests": True, "package_build": True,
                             "synthetic_e2e": True, "recovery_documentation_executed": True,
                             **audit["measurements"]},
            "dependencies": {"code_tree_hash": current["code_identity"]["code_tree_hash"],
                             "documentation_example_hash": current["documentation_example_hash"]},
            "evidence_refs": refs, "test_counts": measured_junit["counts"], "runtime_versions": runtime_versions,
            "independent_audit": audit, "user_ready": False}
