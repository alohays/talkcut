"""Execute and preserve local OSS verification without certifying a lecture.

The runner uses fresh environments and artifacts. A zero shell exit alone is
insufficient: JUnit nodes, installed package bytes, schemas and recovery outputs
are inspected. Independent license/support audits remain separate obligations.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any
from uuid import uuid4

from .contracts import code_identity
from .project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    content_hash,
    now,
    sha256,
    verified_json,
)

PROBE_SCRIPT = '''import hashlib, importlib, importlib.metadata, json, pkgutil, sys
from pathlib import Path
import jsonschema, talkcut
package = Path(talkcut.__file__).resolve().parent
assert package.is_relative_to(Path(sys.prefix).resolve()), "Import escaped isolated environment"
modules = {}
for item in pkgutil.iter_modules([str(package)], "talkcut."):
    if not item.ispkg:
        module = importlib.import_module(item.name)
        modules[item.name] = str(Path(module.__file__).resolve())
schemas = {}
for name in ("project-v1.schema.json", "acceptance-manifest.schema.json"):
    path = package / "schemas" / name
    schema = json.loads(path.read_text())
    jsonschema.validators.validator_for(schema).check_schema(schema)
    schemas[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
files = {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in sorted(package.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
print(json.dumps({"schema_version": "installed-package-probe/v1", "status": "PASS",
      "python": sys.version, "executable": sys.executable, "prefix": sys.prefix,
      "package_directory": str(package), "version": importlib.metadata.version("talkcut"),
      "modules": modules, "schemas": schemas, "package_files": files,
      "installed_distributions": sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions())}, sort_keys=True))
'''


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise TalkCutError("VERIFICATION_UNVERIFIED", message)


def _snapshot(root: Path) -> dict[str, Any]:
    files = []
    for name in ("README.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md"):
        if (root / name).is_file():
            files.append(root / name)
    for name in ("docs", "examples"):
        files += [path for path in (root / name).rglob("*")
                  if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo")]
    extra = {str(path.relative_to(root)): sha256(path) for path in sorted(files)}
    code = code_identity(root)
    return {"code_identity": code, "documentation_example_files": extra,
            "documentation_example_hash": content_hash(extra),
            "input_hash": content_hash({"code_tree_hash": code["code_tree_hash"], "documentation_example_files": extra})}


def _tool_snapshot() -> dict[str, Any]:
    result = {}
    for name in ("uv", "ffmpeg", "ffprobe"):
        path = shutil.which(name)
        result[name] = {"path": path, "sha256": sha256(path) if path else None}
    result["runner_python"] = {"path": sys.executable, "version": sys.version, "sha256": sha256(sys.executable)}
    return result


def _terminate_group(process: subprocess.Popen) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait(timeout=10)
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
        # The group leader can exit while a descendant still ignores SIGTERM.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _run_command(name: str, argv: list[str], cwd: Path, directory: Path,
                 env: dict[str, str], *, timeout: float = 1800) -> dict[str, Any]:
    """One actual command; timeout/interrupt terminates its whole process group."""
    stdout, stderr = directory / f"{name}.stdout", directory / f"{name}.stderr"
    receipt_path = directory / f"{name}.command.json"
    started, clock = now(), time.monotonic()
    code, error, timed_out, interrupted = None, None, False, False
    process: subprocess.Popen | None = None
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=out, stderr=err, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_group(process)
                code = process.returncode
            except KeyboardInterrupt:
                interrupted = True
                _terminate_group(process)
                code = process.returncode
    except OSError as exc:
        error = str(exc)
    finally:
        if process is not None and process.poll() is None:
            _terminate_group(process)
        # Only our explicit non-secret settings are recorded. Ambient credential
        # values are never copied into the evidence bundle.
        result = {"schema_version": "verification-command/v1", "name": name, "argv": argv, "cwd": str(cwd),
                  "started_at": started, "finished_at": now(), "wall_seconds": time.monotonic() - clock,
                  "timeout_seconds": timeout, "exit_code": code, "timed_out": timed_out, "interrupted": interrupted,
                  "error": error, "status": "PASS" if code == 0 and not (error or timed_out or interrupted) else "FAIL",
                  "stdout": artifact_ref(stdout), "stderr": artifact_ref(stderr)}
        atomic_json(receipt_path, result)
    if interrupted:
        raise KeyboardInterrupt
    return {**result, "receipt": artifact_ref(receipt_path)}


def _junit(path: Path) -> dict[str, Any]:
    """Retain every actual node; skipped/xfail/empty/inconsistent XML cannot pass."""
    root = ET.fromstring(path.read_bytes())
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    _require(suites and root.tag in ("testsuite", "testsuites"), "JUnit contains no test suites")
    nodes = []
    counts = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in suites:
        children = list(suite.findall("testcase"))
        local = {"tests": len(children), "failures": 0, "errors": 0, "skipped": 0}
        for case in children:
            statuses = [tag for tag in ("failure", "error", "skipped") if case.find(tag) is not None]
            for tag in statuses:
                local[{"failure": "failures", "error": "errors", "skipped": "skipped"}[tag]] += 1
            nodes.append({"classname": case.get("classname"), "name": case.get("name"), "seconds": case.get("time"),
                          "file": case.get("file"), "line": case.get("line"),
                          "status": statuses[0].upper() if statuses else "PASS",
                          "details": [{"kind": child.tag, "message": child.get("message"), "text": child.text}
                                      for child in case if child.tag in ("failure", "error", "skipped")]})
        for key, measured in local.items():
            _require(suite.get(key) is not None and int(suite.attrib[key]) == measured,
                     f"JUnit declared {key} does not match actual nodes")
            counts[key] += measured
    _require(all(node["classname"] and node["name"] for node in nodes), "JUnit node identity is missing")
    identities = [(node["classname"], node["name"]) for node in nodes]
    _require(len(identities) == len(set(identities)), "JUnit repeats a test node")
    success = counts["tests"] > 0 and not any(counts[key] for key in ("failures", "errors", "skipped"))
    return {"status": "PASS" if success else "FAIL", "counts": counts, "nodes": nodes, "raw": artifact_ref(path)}


def _wheel_inventory(wheel: Path, root: Path) -> dict[str, Any]:
    expected = {"talkcut/" + str(path.relative_to(root / "src" / "talkcut")): sha256(path)
                for path in (root / "src" / "talkcut").rglob("*")
                if path.is_file() and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo")}
    with zipfile.ZipFile(wheel) as archive:
        names = [info.filename for info in archive.infolist() if not info.is_dir()]
        _require(len(names) == len(set(names)), "Wheel has duplicate member paths")
        _require(all(not Path(name).is_absolute() and ".." not in Path(name).parts for name in names), "Wheel has unsafe member paths")
        inventory = {name: hashlib.sha256(archive.read(name)).hexdigest() for name in names}
        package = {name: value for name, value in inventory.items() if name.startswith("talkcut/")}
        _require(package == expected, "Built wheel package bytes differ from the measured source tree")
        other = [name for name in names if not name.startswith("talkcut/")]
        _require(other and all(".dist-info/" in name and len(Path(name).parts) >= 2 for name in other), "Wheel contains unexpected top-level payload")
        licenses = [name for name in names if name.endswith(".dist-info/licenses/LICENSE")]
        _require(len(licenses) == 1 and inventory[licenses[0]] == sha256(root / "LICENSE"), "Wheel license bytes differ from repository LICENSE")
    return {"status": "PASS", "artifact": artifact_ref(wheel), "bytes": wheel.stat().st_size,
            "members": inventory, "source_package_bytes_match": True,
            "license_file_bytes_match": True, "license_legal_audit": "UNVERIFIED"}


def _installed_probe(path: Path, prefix: Path, wheel: dict[str, Any]) -> dict[str, Any]:
    data = json.loads(path.read_text())
    _require(data.get("schema_version") == "installed-package-probe/v1" and data.get("status") == "PASS", "Installed probe did not complete")
    _require(Path(data["prefix"]).resolve() == prefix.resolve() and Path(data["package_directory"]).resolve().is_relative_to(prefix.resolve()), "Installed probe imported outside the fresh environment")
    expected = {name.removeprefix("talkcut/"): digest for name, digest in wheel["members"].items() if name.startswith("talkcut/")}
    _require(data["package_files"] == expected, "Installed package files differ from the built wheel")
    _require(set(data["schemas"]) == {"project-v1.schema.json", "acceptance-manifest.schema.json"}, "Installed schema validation is incomplete")
    return {"status": "PASS", "raw": artifact_ref(path), "measurements": data}


def _environment_inventory(prefix: Path) -> dict[str, Any]:
    """Freeze current installed files, including generated bytecode and scripts."""
    files: dict[str, Any] = {}
    for path in sorted(prefix.rglob("*")):
        name = str(path.relative_to(prefix))
        if path.is_symlink():
            _require(path.is_file(), "Installed environment has a broken or directory symlink")
            files[name] = {"type": "symlink", "target": os.readlink(path), "target_sha256": sha256(path)}
        elif path.is_file():
            files[name] = {"type": "file", "sha256": sha256(path), "bytes": path.stat().st_size}
        elif not path.is_dir():
            raise TalkCutError("VERIFICATION_UNVERIFIED", "Installed environment contains an unsupported special file")
    _require(files, "Installed environment byte inventory is empty")
    return files


def _seed_site_files(prefix: Path) -> dict[str, str]:
    """Capture uv-created startup files before any dependency installation."""
    site = prefix / "lib/python3.12/site-packages"
    _require(site.is_dir(), "Fresh Python 3.12 environment has no site-packages")
    return {str(path.relative_to(site)): sha256(path) for path in site.rglob("*") if path.is_file()}


def _runtime_archives(root: Path, runtime: Path, installed: dict[str, Any], directory: Path,
                      seed_ref: dict[str, str]) -> dict[str, Any]:
    """Preserve the actual locked wheel bytes matching this isolated platform.

    Downloads are selected from the repository's lockfile and checked against
    its SHA256 before use. An installed mutable RECORD is never the authority.
    The current profile uses wheels; an unavailable matching wheel fails closed.
    """
    from .reproducibility_checks import _locked_runtime, _normalize, _requirements
    records = _requirements(runtime.read_text())
    packages = tomllib.loads((root / "uv.lock").read_text())["package"]
    site = Path(installed["package_directory"]).parent
    distributions = {_normalize(dist.metadata["Name"]): dist for dist in importlib.metadata.distributions(path=[str(site)])}
    directory.mkdir(exist_ok=False)
    refs, requests = [], []
    for name, (version, hashes) in sorted(records.items()):
        matching = [item for item in packages if _normalize(item["name"]) == name and item["version"] == version]
        _require(len(matching) == 1 and name in distributions, "Cannot identify one installed locked dependency")
        wheel_text = distributions[name].read_text("WHEEL")
        _require(wheel_text is not None, "Installed dependency has no wheel platform metadata")
        assert wheel_text is not None
        tags = {line.removeprefix("Tag: ") for line in wheel_text.splitlines() if line.startswith("Tag: ")}
        candidates = []
        for candidate in matching[0].get("wheels", []):
            url = urllib.parse.urlsplit(candidate.get("url", ""))
            filename = urllib.parse.unquote(Path(url.path).name)
            parts = filename.removesuffix(".whl").split("-")
            if len(parts) < 5 or not filename.endswith(".whl"):
                continue
            offered = {f"{python}-{abi}-{platform}" for python in parts[-3].split(".")
                       for abi in parts[-2].split(".") for platform in parts[-1].split(".")}
            if offered == tags:
                candidates.append((candidate, url, filename))
        _require(len(candidates) == 1, "Exact installed wheel tag is absent or ambiguous in the lockfile")
        candidate, url, filename = candidates[0]
        digest = candidate["hash"].removeprefix("sha256:")
        _require(digest in hashes and url.scheme == "https" and url.hostname == "files.pythonhosted.org"
                 and not (url.username or url.password or url.query or url.fragment),
                 "Locked wheel download has an unsupported origin or identity")
        path, partial = directory / filename, directory / (filename + ".partial")
        started, count = now(), 0
        with urllib.request.urlopen(candidate["url"], timeout=60) as response, partial.open("xb") as output:
            _require(response.status == 200, "Locked wheel download failed")
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                _require(count <= 512 * 1024 * 1024, "Locked wheel download exceeds the declared byte bound")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        _require(sha256(partial) == digest, "Downloaded dependency wheel differs from the lockfile hash")
        os.link(partial, path)
        partial.unlink()
        ref = artifact_ref(path)
        refs.append(ref)
        requests.append({"url": candidate["url"], "method": "GET", "status": 200, "started_at": started,
                         "finished_at": now(), "bytes": count, "artifact": ref})
        atomic_json(directory / "downloads.json", requests)
    versions = _locked_runtime(root, runtime, installed, refs, verified_json(seed_ref))
    prefix = Path(installed["prefix"])
    return {"status": "PASS", "archives": refs, "downloads": artifact_ref(directory / "downloads.json"),
            "versions": versions, "environment_files": _environment_inventory(prefix),
            "interpreter": {"path": str(prefix / "bin/python"), "sha256": sha256(prefix / "bin/python")}, "seed_site_files": seed_ref,
            "scope": "Every locked wheel source/native/data member matches the installed tree; no unregistered package payload. Installer records, scripts and bytecode are separately frozen in the complete environment inventory."}


def _doctor_probe(path: Path, tools: dict[str, Any]) -> dict[str, Any]:
    data = json.loads(path.read_text())
    _require(data.get("schema_version") == "talkcut-doctor/v1" and data.get("status") == "PASS", "Installed doctor result is incomplete")
    for name in ("ffmpeg", "ffprobe"):
        measured = data["tools"][name]
        _require(measured["path"] == tools[name]["path"] and measured["sha256"] == tools[name]["sha256"]
                 and measured.get("build"), "Installed doctor used a different or unidentified media tool")
    return {"status": "PASS", "raw": artifact_ref(path), "measurements": data}


def _recovery_result(path: Path) -> dict[str, Any]:
    report = json.loads(path.read_text())
    _require(report.get("schema_version") == "recovery-example/v1" and report.get("test_only") is True
             and report.get("technical_roundtrip") == "PASS" and report.get("audiovisual_review") == "UNVERIFIED", "Recovery example did not report its bounded actual roundtrip")
    executions = verified_json(report["executions"])
    expected = ["01-generate", "02-init", "03-inspect", "04-plan", "05-baseline", "06-propose", "07-accept",
                "08-cut", "09-restore", "10-restored", "11-reapply", "12-reapplied", "13-unchanged", "14-reopen"]
    _require([item["name"] for item in executions] == expected and all(item["exit_code"] == 0 for item in executions), "Recovery command coverage is incomplete or failed")
    for item in executions:
        for kind in ("stdout", "stderr"):
            _require(sha256(item[kind]["path"]) == item[kind]["sha256"], "Recovery command log changed")
    outputs = report["outputs"]
    _require(set(outputs) == {"baseline", "cut", "restored", "reapplied"}, "Recovery output coverage is incomplete")
    timelines = {}
    for name, render in outputs.items():
        _require(sha256(render["output"]["path"]) == render["output"]["sha256"], "Recovery successful output changed")
        native = verified_json(render["native_render"])
        _require(native.get("complete") is True and native.get("status") == "succeeded" and native["output"] == render["output"], "Recovery output lacks a completed matching render")
        timelines[name] = verified_json(render["settings"]["timeline"])
    for first, second in (("baseline", "restored"), ("cut", "reapplied")):
        _require(outputs[first]["output"]["sha256"] == outputs[second]["output"]["sha256"], "Recovery output bytes were not restored/reapplied")
        for key in ("frames", "retained", "duration", "sample_count", "speaker_omissions"):
            _require(timelines[first][key] == timelines[second][key], "Recovery mapping changed")
    _require(timelines["cut"]["sample_count"] < timelines["baseline"]["sample_count"], "Recovery example applied no actual cut")
    return {"status": "PASS", "raw": artifact_ref(path), "executions": report["executions"],
            "outputs": {name: value["output"] for name, value in outputs.items()}, "test_only": True,
            "audiovisual_review": "UNVERIFIED"}


def run_verification(repo_root: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Run the documented whole-suite/build/install/recovery checks, preserving all artifacts."""
    root, destination = Path(repo_root).resolve(), Path(output_dir).resolve()
    _require(os.name == "posix", "Verification currently supports the documented Linux/macOS process model")
    _require(all((root / name).is_file() for name in ("pyproject.toml", "uv.lock", "LICENSE", "examples/recovery.py")), "Required repository inputs are missing")
    _require(not any(destination.is_relative_to(root / name) for name in ("src", "tests", "examples", "docs", ".github", "schemas")), "Evidence destination cannot change verified code or documentation")
    run_id = "verification-" + uuid4().hex
    directory = destination / run_id
    directory.mkdir(parents=True)
    commands = directory / "commands"
    commands.mkdir()
    before, tools_before = _snapshot(root), _tool_snapshot()
    atomic_json(directory / "inputs-before.json", before)
    env = dict(os.environ)
    removed = [key for key in ("PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "PYTEST_PLUGINS", "VIRTUAL_ENV",
                              "UV_PYTHON", "UV_PROJECT", "UV_WORKING_DIR", "UV_PROJECT_ENVIRONMENT", "UV_NO_SYNC", "UV_FROZEN") if key in env]
    for key in removed:
        env.pop(key)
    overrides = {"UV_PROJECT_ENVIRONMENT": str(directory / "development-env"), "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    env.update(overrides)
    outside = (Path(tempfile.mkdtemp(prefix=run_id + "-cwd-")).resolve()
               if directory.is_relative_to(root) else directory / "outside-cwd")
    outside.mkdir(exist_ok=True)
    _require(not outside.is_relative_to(root), "Installed checks must run outside the repository tree")
    dist, prefix = directory / "fresh-dist", directory / "isolated-env"
    dist.mkdir()
    python = prefix / "bin" / "python"
    uv = tools_before["uv"]["path"] or "uv"
    executions: list[dict[str, Any]] = []
    validations: dict[str, Any] = {}
    errors: list[str] = []
    started, clock = now(), time.monotonic()

    def step(name: str, argv: list[str], *, cwd: Path = root, needs: tuple[str, ...] = (), timeout: int = 1800) -> dict[str, Any]:
        blocked = [key for key in needs if not any(row["name"] == key and row["status"] == "PASS" for row in executions)]
        if blocked:
            result = {"name": name, "argv": argv, "cwd": str(cwd), "status": "NOT_RUN", "exit_code": None, "blocked_by": blocked}
        else:
            result = _run_command(name, argv, cwd, commands, env, timeout=timeout)
        executions.append(result)
        atomic_json(directory / "executions.json", executions)
        return result

    def inspect(name: str, callback) -> None:
        try:
            validations[name] = callback()
        except (OSError, ValueError, KeyError, TalkCutError, ET.ParseError, zipfile.BadZipFile) as exc:
            validations[name] = {"status": "FAIL", "error": str(exc)}
            errors.append(f"{name}: {exc}")

    interrupted = False
    try:
        step("uv-version", [uv, "--version"])
        step("locked-sync", [uv, "sync", "--locked", "--python", "3.12"])
        step("ruff", [uv, "run", "--locked", "ruff", "check", "src", "tests", "examples"], needs=("locked-sync",))
        step("mypy", [uv, "run", "--locked", "mypy", "src/talkcut"], needs=("locked-sync",))
        junit = directory / "pytest.junit.xml"
        step("pytest", [uv, "run", "--locked", "pytest", "-q", "tests", "--junitxml", str(junit), "--basetemp", str(directory / "pytest-basetemp")], needs=("locked-sync",), timeout=7200)
        inspect("junit", lambda: _junit(junit))
        step("build", [uv, "build", "--out-dir", str(dist), "--no-create-gitignore"])
        wheels, sdists = sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))
        if len(wheels) == len(sdists) == 1:
            inspect("wheel", lambda: _wheel_inventory(wheels[0], root))
            validations["sdist"] = {"status": "MEASURED", "artifact": artifact_ref(sdists[0]), "bytes": sdists[0].stat().st_size}
        else:
            validations["wheel"] = {"status": "FAIL", "error": "Fresh build must produce exactly one wheel and one sdist"}
        runtime = directory / "runtime-requirements.txt"
        step("locked-runtime-export", [uv, "export", "--locked", "--no-dev", "--no-emit-project", "--format", "requirements.txt", "--output-file", str(runtime)])
        created = step("isolated-venv", [uv, "venv", "--no-project", "--python", "3.12", str(prefix)], cwd=outside)
        seed_path = directory / "environment-seed.json"
        if created["status"] == "PASS":
            inspect("environment_seed", lambda: {"status": "PASS", "files": _seed_site_files(prefix)})
            if validations["environment_seed"]["status"] == "PASS":
                atomic_json(seed_path, validations["environment_seed"]["files"])
        if validations["wheel"]["status"] == "PASS":
            wheel_requirements = directory / "wheel-requirements.txt"
            wheel_requirements.write_text(f"talkcut @ {wheels[0].as_uri()} --hash=sha256:{sha256(wheels[0])}\n")
            step("isolated-install", [uv, "pip", "sync", "--python", str(python), "--require-hashes", "--strict", str(runtime), str(wheel_requirements)],
                 cwd=outside, needs=("build", "locked-runtime-export", "isolated-venv"))
        else:
            executions.append({"name": "isolated-install", "status": "NOT_RUN", "exit_code": None, "blocked_by": ["wheel-validation"]})
        step("installed-version", [str(python), "-I", "-m", "talkcut", "--version"], cwd=outside, needs=("isolated-install",))
        doctor_result = step("installed-doctor", [str(python), "-I", "-m", "talkcut", "doctor", "--json"], cwd=outside, needs=("isolated-install",))
        if doctor_result["status"] == "PASS":
            inspect("installed_doctor", lambda: _doctor_probe(Path(doctor_result["stdout"]["path"]), tools_before))
        else:
            validations["installed_doctor"] = {"status": "UNVERIFIED", "reason": "Installed doctor did not run successfully"}
        probe_script = outside / "probe.py"
        probe_script.write_text(PROBE_SCRIPT)
        probe = step("installed-probe", [str(python), "-I", str(probe_script)], cwd=outside, needs=("isolated-install",))
        if probe["status"] == "PASS":
            inspect("installed_probe", lambda: _installed_probe(Path(probe["stdout"]["path"]), prefix, validations["wheel"]))
        else:
            validations["installed_probe"] = {"status": "UNVERIFIED", "reason": "Installed probe did not run successfully"}
        example = outside / "recovery.py"
        shutil.copyfile(root / "examples" / "recovery.py", example)
        _require(sha256(example) == before["documentation_example_files"]["examples/recovery.py"], "Executable example changed before execution")
        step("documented-recovery", [str(python), "-I", str(example), str(directory / "recovery-example")], cwd=outside, needs=("isolated-install",), timeout=7200)
        inspect("recovery", lambda: _recovery_result(directory / "recovery-example" / "result.json"))
        validations["example_copy"] = {"status": "PASS", "artifact": artifact_ref(example), "source_sha256": before["documentation_example_files"]["examples/recovery.py"]}
        if validations.get("installed_probe", {}).get("status") == "PASS" and seed_path.is_file():
            inspect("runtime_wheels", lambda: _runtime_archives(root, runtime, validations["installed_probe"]["measurements"], directory / "locked-wheels", artifact_ref(seed_path)))
        else:
            validations["runtime_wheels"] = {"status": "UNVERIFIED", "reason": "Installed runtime cannot be bound to locked wheel bytes"}
    except KeyboardInterrupt:
        interrupted = True
        errors.append("Verification interrupted; partial execution cannot pass")
    except (OSError, ValueError, KeyError, TalkCutError, subprocess.SubprocessError, RuntimeError, TypeError) as exc:
        errors.append(f"Runner aborted: {type(exc).__name__}: {exc}")
    after, tools_after = _snapshot(root), _tool_snapshot()
    atomic_json(directory / "inputs-after.json", after)
    atomic_json(directory / "executions.json", executions)
    stable = before["input_hash"] == after["input_hash"] and tools_before == tools_after
    required = ("junit", "wheel", "installed_probe", "installed_doctor", "recovery", "example_copy", "runtime_wheels")
    passed = (not errors and not interrupted and stable and len(executions) == 13
              and all(row["status"] == "PASS" for row in executions)
              and all(validations.get(name, {}).get("status") == "PASS" for name in required))
    report = {"schema_version": "oss-verification/v1", "run_id": run_id,
              "producer": {"path": "src/talkcut/verification.py", "sha256": before["code_identity"]["files"].get("src/talkcut/verification.py")},
              "repo_root": str(root), "directory": str(directory), "outside_cwd": str(outside), "status": "PASS" if passed else "FAIL",
              "technical_execution_pass": passed, "unchanged_inputs_and_tools": stable,
              "user_ready": False, "audiovisual_review": "UNVERIFIED", "owner_acceptance": "pending",
              "public_fixture_license_checked": "UNVERIFIED", "support_claims_match_tests": "UNVERIFIED",
              "independent_audits": {"status": "UNVERIFIED", "reason": "An independent bound license/support audit is required; command success does not supply it"},
              "before": before, "after": after, "tools_before": tools_before, "tools_after": tools_after,
              "environment_overrides": overrides, "removed_ambient_variable_names": removed,
              "executions": executions, "validations": validations, "errors": errors, "interrupted": interrupted,
              "started_at": started, "finished_at": now(), "wall_seconds": time.monotonic() - clock,
              "scope": "Local whole-suite, build, isolated installation and documented synthetic recovery execution; no AI media review or remote CI/release attestation"}
    result_path = directory / "result.json"
    atomic_json(result_path, report)
    receipt_path = directory / "receipt.json"
    receipt = {"schema_version": "execution-receipt/v1", "operation": "verification:run", "run_id": run_id,
               "executor": "local_python_in_process", "started_at": started, "finished_at": now(),
               "completed": not interrupted and len(executions) == 13 and all(row["status"] != "NOT_RUN" for row in executions), "exit_code": 0 if passed else 1,
               "dependencies": {"code_tree_hash": before["code_identity"]["code_tree_hash"], "documentation_example_hash": before["documentation_example_hash"]},
               "result": artifact_ref(result_path), "commands": artifact_ref(directory / "executions.json"),
               "note": "No subprocess stdout is fabricated for this in-process API; the caller may capture actual CLI stdout"}
    atomic_json(receipt_path, receipt)
    if interrupted:
        raise KeyboardInterrupt
    return {**report, "artifact_ref": artifact_ref(result_path), "receipt": artifact_ref(receipt_path)}
