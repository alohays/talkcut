"""Runner failure barriers, using bounded subprocesses and parser fixtures.

The suite never launches whole-suite verification recursively. Injected runners
below fail or omit required artifacts; none certifies an installation or media.
"""

import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

from talkcut import verification
from talkcut.project import TalkCutError, atomic_json, sha256, verified_json


@pytest.fixture
def small_repo(tmp_path):
    root = tmp_path / "repo"
    package = root / "src" / "talkcut"
    (package / "schemas").mkdir(parents=True)
    (root / "examples").mkdir()
    (root / "docs").mkdir()
    (package / "__init__.py").write_text('__version__ = "0.0.0"\n')
    for name in ("project-v1.schema.json", "acceptance-manifest.schema.json"):
        atomic_json(package / "schemas" / name, {"type": "object"})
    (root / "pyproject.toml").write_text('[project]\nname = "negative-fixture"\nversion = "0"\n')
    (root / "uv.lock").write_text("# Deliberately not an installable lockfile\n")
    (root / "LICENSE").write_text("Public parser-test fixture, not an audited software license\n")
    (root / "README.md").write_text("Synthetic negative-runner repository\n")
    (root / "examples" / "recovery.py").write_text('raise RuntimeError("Must not execute this fake example")\n')
    return root


def injected_small_command(monkeypatch, *, exit_code, mutate=None):
    actual = verification._run_command
    requested = []

    def injected(name, argv, cwd, directory, env, *, timeout):
        requested.append((name, argv, cwd))
        if mutate is not None:
            mutate(name)
        # Real tiny subprocess receipts, but deliberately no build/install,
        # JUnit or recovery artifacts. Whole verification must remain FAIL.
        return actual(name, [sys.executable, "-c", f"raise SystemExit({exit_code})"],
                      cwd, directory, env, timeout=5)

    monkeypatch.setattr(verification, "_run_command", injected)
    return requested


def test_failed_sync_blocks_dependents_and_preserves_real_failure_logs(small_repo, tmp_path, monkeypatch):
    calls = injected_small_command(monkeypatch, exit_code=7)
    report = verification.run_verification(small_repo, tmp_path / "evidence")
    assert report["status"] == "FAIL" and not report["technical_execution_pass"]
    assert not report["user_ready"]
    assert report["public_fixture_license_checked"] == report["support_claims_match_tests"] == "UNVERIFIED"
    states = {item["name"]: item for item in report["executions"]}
    assert states["locked-sync"]["exit_code"] == 7
    assert states["ruff"]["status"] == states["pytest"]["status"] == "NOT_RUN"
    assert states["isolated-install"]["status"] == "NOT_RUN"
    assert not verified_json(report["receipt"])["completed"]
    assert "--locked" in next(argv for name, argv, _ in calls if name == "locked-sync")
    for execution in report["executions"]:
        if execution["status"] != "NOT_RUN":
            assert verified_json(execution["receipt"])["exit_code"] == 7
            assert Path(execution["stdout"]["path"]).is_file()


def test_zero_exits_without_actual_artifacts_cannot_pass(small_repo, tmp_path, monkeypatch):
    calls = injected_small_command(monkeypatch, exit_code=0)
    report = verification.run_verification(small_repo, tmp_path / "evidence")
    assert report["status"] == "FAIL" and not report["technical_execution_pass"]
    assert report["validations"]["junit"]["status"] == "FAIL"
    assert report["validations"]["wheel"]["status"] == "FAIL"
    assert report["validations"]["recovery"]["status"] == "FAIL"
    pytest_args = next(argv for name, argv, _ in calls if name == "pytest")
    assert "--junitxml" in pytest_args and "--basetemp" in pytest_args
    assert pytest_args[pytest_args.index("-q") + 1] == "tests"
    assert not any(part in pytest_args for part in ("-k", "-m", "--lf", "--last-failed"))


def test_documentation_mutation_is_stale_even_if_commands_return_zero(small_repo, tmp_path, monkeypatch):
    def mutate(name):
        if name == "uv-version":
            (small_repo / "README.md").write_text("Changed during execution\n")
    injected_small_command(monkeypatch, exit_code=0, mutate=mutate)
    report = verification.run_verification(small_repo, tmp_path / "evidence")
    assert not report["unchanged_inputs_and_tools"]
    assert report["before"]["documentation_example_hash"] != report["after"]["documentation_example_hash"]
    assert report["status"] == "FAIL"


def test_repository_evidence_still_uses_a_cwd_outside_checkout(small_repo, monkeypatch):
    injected_small_command(monkeypatch, exit_code=7)
    report = verification.run_verification(small_repo, small_repo / "projects" / "evidence")
    assert not Path(report["outside_cwd"]).is_relative_to(small_repo)
    assert Path(report["directory"]).is_relative_to(small_repo / "projects")


def test_evidence_cannot_mutate_test_or_source_inputs(small_repo):
    with pytest.raises(TalkCutError, match="cannot change verified"):
        verification.run_verification(small_repo, small_repo / "src" / "evidence")


def test_actual_command_records_stdout_stderr_and_exit(tmp_path):
    argv = [sys.executable, "-c", "import sys; print('actual stdout'); print('actual stderr', file=sys.stderr); sys.exit(7)"]
    result = verification._run_command("negative", argv, tmp_path, tmp_path, dict(os.environ), timeout=5)
    assert result["argv"] == argv and result["exit_code"] == 7 and result["status"] == "FAIL"
    assert Path(result["stdout"]["path"]).read_text() == "actual stdout\n"
    assert Path(result["stderr"]["path"]).read_text() == "actual stderr\n"
    assert verified_json(result["receipt"])["stdout"]["sha256"] == sha256(result["stdout"]["path"])


def test_timeout_stops_grandchild_even_if_it_ignores_sigterm(tmp_path):
    marker = tmp_path / "orphan-was-not-killed"
    child_code = "import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(1); pathlib.Path(" + repr(str(marker)) + ").write_text('bad')"
    code = "import subprocess,sys,time; subprocess.Popen([sys.executable, '-c', " + repr(child_code) + "]); time.sleep(30)"
    result = verification._run_command("timeout", [sys.executable, "-c", code], tmp_path, tmp_path, dict(os.environ), timeout=0.15)
    assert result["timed_out"] and result["status"] == "FAIL" and result["exit_code"] != 0
    time.sleep(1.1)
    assert not marker.exists()


def junit_file(tmp_path, *, nodes, tests=1, failures=0, errors=0, skipped=0):
    path = tmp_path / "junit.xml"
    path.write_text(f'<testsuites><testsuite tests="{tests}" failures="{failures}" errors="{errors}" skipped="{skipped}">{nodes}</testsuite></testsuites>')
    return path


def test_junit_preserves_measured_test_nodes(tmp_path):
    path = junit_file(tmp_path, nodes='<testcase classname="tests.test_example" name="test_actual_case[param]" time="0.03"/>')
    result = verification._junit(path)
    assert result["status"] == "PASS" and result["counts"]["tests"] == 1
    assert result["nodes"][0]["name"] == "test_actual_case[param]"
    assert result["raw"]["sha256"] == sha256(path)


@pytest.mark.parametrize("tag,count", [("skipped", "skipped"), ("failure", "failures"), ("error", "errors")])
def test_junit_skip_failure_and_error_each_prevent_pass(tmp_path, tag, count):
    path = junit_file(tmp_path, nodes=f'<testcase classname="suite" name="case"><{tag} message="real detail"/></testcase>', **{count: 1})
    assert verification._junit(path)["status"] == "FAIL"


def test_empty_or_dishonest_junit_denominators_cannot_pass(tmp_path):
    assert verification._junit(junit_file(tmp_path, nodes="", tests=0))["status"] == "FAIL"
    path = junit_file(tmp_path, nodes='<testcase classname="suite" name="case"/>', tests=2)
    with pytest.raises(TalkCutError, match="actual nodes"):
        verification._junit(path)
    path = junit_file(tmp_path, nodes='<testcase classname="suite" name="case"/>' * 2, tests=2)
    with pytest.raises(TalkCutError, match="repeats"):
        verification._junit(path)


def make_wheel(root, path, *, wrong_source=False, wrong_license=False):
    with zipfile.ZipFile(path, "w") as archive:
        for source in (root / "src" / "talkcut").rglob("*"):
            if source.is_file():
                archive.writestr("talkcut/" + str(source.relative_to(root / "src" / "talkcut")),
                                 b"changed" if wrong_source and source.name == "__init__.py" else source.read_bytes())
        archive.writestr("talkcut-0.0.0.dist-info/METADATA", "Name: talkcut\nVersion: 0.0.0\n")
        archive.writestr("talkcut-0.0.0.dist-info/licenses/LICENSE", b"changed" if wrong_license else (root / "LICENSE").read_bytes())


@pytest.mark.parametrize("fault", ["wrong_source", "wrong_license"])
def test_built_wheel_must_match_current_source_and_license_bytes(small_repo, tmp_path, fault):
    path = tmp_path / "fixture.whl"
    make_wheel(small_repo, path, **{fault: True})
    with pytest.raises(TalkCutError):
        verification._wheel_inventory(path, small_repo)


def test_installed_probe_cannot_borrow_source_checkout_files(small_repo, tmp_path):
    path = tmp_path / "fixture.whl"
    make_wheel(small_repo, path)
    wheel = verification._wheel_inventory(path, small_repo)
    probe = tmp_path / "probe.json"
    atomic_json(probe, {"schema_version": "installed-package-probe/v1", "status": "PASS", "prefix": str(tmp_path / "venv"),
                        "package_directory": str(small_repo / "src" / "talkcut")})
    with pytest.raises(TalkCutError, match="outside"):
        verification._installed_probe(probe, tmp_path / "venv", wheel)


def test_canned_recovery_pass_is_not_actual_roundtrip_evidence(tmp_path):
    path = tmp_path / "result.json"
    atomic_json(path, {"schema_version": "recovery-example/v1", "test_only": True,
                       "technical_roundtrip": "PASS", "audiovisual_review": "UNVERIFIED"})
    with pytest.raises(KeyError):
        verification._recovery_result(path)


def test_schema_probe_script_compiles_without_executing_package_install():
    # Syntax validation only; this cannot count as the installed package probe.
    compile(verification.PROBE_SCRIPT, "installed-probe.py", "exec")
