"""Independent process/installed-byte controls, never actual media acceptance.

The lifecycle fixture supplies an authored worker to isolate terminal-state
handling. The dependency fixture installs real generated local wheels. Neither
supplies DGIST source, AV reviewer receipts, or a whole-acceptance PASS.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest

from talkcut.contracts import code_identity
from talkcut.project import (
    TalkCutError,
    artifact_ref,
    atomic_json,
    sha256,
    verified_json,
)
from talkcut.reproducibility_checks import _locked_runtime

REPO = Path(__file__).resolve().parents[1]
WORKER = """import json, os, signal, time
from pathlib import Path
signal.signal(signal.SIGTERM, lambda *_: exit(0))
print(Path(os.environ["LIFECYCLE_PAYLOAD"]).read_text(), flush=True)
Path(os.environ["LIFECYCLE_READY"]).write_text("ready")
if os.environ["LIFECYCLE_MODE"] == "wait":
    while True:
        time.sleep(0.05)
"""
PARENT = """import json, os, subprocess, sys
from pathlib import Path
from talkcut.measurements import run_measurement
os.environ["PYTHONPATH"] = sys.argv[1]
if os.environ.get("LIFECYCLE_SHORT_TIMEOUT") == "1":
    original_wait = subprocess.Popen.wait
    def bounded_wait(self, timeout=None):
        # Exercise real Popen timeout/kill/wait without a four-hour test.
        return original_wait(self, timeout=0.5 if timeout == 14400 else timeout)
    subprocess.Popen.wait = bounded_wait
result = run_measurement(Path(sys.argv[2]), "baseline", Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]))
print(json.dumps(result), flush=True)
"""


def lifecycle_run(tmp_path, *, interrupt, short_timeout=False):
    root, worker = tmp_path / "isolated-receipt-fixture", tmp_path / "worker"
    root.mkdir()
    package = worker / "talkcut"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text(WORKER)
    raw, payload, ready = [
        tmp_path / name for name in ("raw.json", "payload.json", "ready")
    ]
    atomic_json(raw, {"test_only": True, "scope": "authored worker lifecycle control"})
    atomic_json(
        payload,
        {
            "schema_version": "measurement-result/v1",
            "check_id": "baseline",
            "dependencies": {"code_tree_hash": code_identity(root)["code_tree_hash"]},
            "raw_inputs": artifact_ref(raw),
            "measurements": {},
            "evidence_refs": [artifact_ref(raw)],
            "subject_test_only": True,
            "acceptance_status": "UNVERIFIED",
            "owner_acceptance": "pending",
        },
    )
    command = [
        sys.executable,
        "-c",
        PARENT,
        str(worker),
        str(tmp_path / "project"),
        str(raw),
        str(tmp_path / "unused-contract.json"),
        str(root),
    ]
    env = {
        **os.environ,
        "PYTHONPATH": str(REPO / "src"),
        "LIFECYCLE_PAYLOAD": str(payload),
        "LIFECYCLE_READY": str(ready),
        "LIFECYCLE_MODE": "wait" if interrupt or short_timeout else "exit",
        "LIFECYCLE_SHORT_TIMEOUT": "1" if short_timeout else "0",
    }
    process = subprocess.Popen(
        command,
        cwd=REPO,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        if interrupt:
            deadline = time.monotonic() + 8
            while (
                not ready.exists()
                and process.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            assert ready.exists(), "Actual child did not reach the signal control point"
            process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert process.returncode == 0, stderr
    result = json.loads(stdout)
    atomic_json(
        tmp_path / "observed-parent.json",
        {
            "argv": command,
            "exit_code": process.returncode,
            "stdout": result,
            "stderr": stderr,
            "actual_sigint_sent": interrupt,
            "actual_wait_timeout_seconds": 0.5 if short_timeout else None,
        },
    )
    return result, verified_json(result["receipt"])


@pytest.mark.parametrize("stop", ["interrupt", "timeout"])
def test_actual_cancel_cannot_promote_a_child_that_handles_term_with_exit_zero(
    tmp_path, stop
):
    control_path, mutant_path = tmp_path / "control", tmp_path / "cancelled"
    control_path.mkdir()
    mutant_path.mkdir()
    control, success = lifecycle_run(control_path, interrupt=False)
    assert control["status"] == "MEASURED" and success["completed"] is True
    assert success["exit_code"] == 0
    cancelled, receipt = lifecycle_run(
        mutant_path, interrupt=stop == "interrupt", short_timeout=stop == "timeout"
    )
    assert cancelled["interrupted"] is (stop == "interrupt")
    assert receipt["exit_code"] == 0  # The actual child deliberately handled TERM.
    assert verified_json(receipt["log"])["failure"]["type"] == (
        "KeyboardInterrupt" if stop == "interrupt" else "TimeoutExpired"
    )
    assert cancelled["status"] == "FAIL"
    assert cancelled["evidence"] is None and receipt["completed"] is False


def wheel(directory, name, package, version):
    dist = name.replace("-", "_") + "-" + version + ".dist-info"
    members = {
        package + "/__init__.py": b"SYNTHETIC_FIXTURE_VALUE = 1\n",
        dist
        + "/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        dist
        + "/WHEEL": b"Wheel-Version: 1.0\nGenerator: talkcut-independent-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    records = []
    for path, data in members.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode()
        )
        records.append(f"{path},sha256={digest},{len(data)}")
    members[dist + "/RECORD"] = (
        "\n".join(records) + "\n" + dist + "/RECORD,,\n"
    ).encode()
    path = directory / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w") as archive:
        for member_name, data in members.items():
            archive.writestr(member_name, data)
    return path


@pytest.mark.parametrize(
    "mutation", ["code_only", "code_and_record", "extra_module", "startup_pth"]
)
def test_actual_installed_dependency_byte_change_invalidates_locked_runtime(
    tmp_path, mutation
):
    uv = shutil.which("uv")
    assert uv, "The supported locked-install test requires uv"
    prefix, root = tmp_path / "venv", tmp_path / "repo"
    root.mkdir()
    project_wheel = wheel(tmp_path, "talkcut", "talkcut", "0.1.0")
    dependency_wheel = wheel(tmp_path, "demo-dep", "demo_dep", "1.0")
    commands = [
        [uv, "venv", "--no-project", "--python", sys.executable, str(prefix)],
        [
            uv,
            "pip",
            "install",
            "--no-deps",
            "--python",
            str(prefix / "bin/python"),
            str(project_wheel),
            str(dependency_wheel),
        ],
    ]
    executions = []
    seed_files = {}
    for command_index, command in enumerate(commands):
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=60
        )
        executions.append(
            {
                "argv": command,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        assert result.returncode == 0, result.stderr
        if command_index == 0:
            seed_site = prefix / "lib/python3.12/site-packages"
            seed_files = {
                str(path.relative_to(seed_site)): sha256(path)
                for path in seed_site.rglob("*")
                if path.is_file()
            }
    probe = subprocess.run(
        [
            str(prefix / "bin/python"),
            "-I",
            "-c",
            (
                "import importlib.metadata,json,sys,talkcut;from pathlib import Path;"
                "print(json.dumps({'package_directory':str(Path(talkcut.__file__).parent),"
                "'version':importlib.metadata.version('talkcut'),'python':sys.version,"
                "'installed_distributions':sorted((d.metadata['Name'],d.version) for d in importlib.metadata.distributions())}))"
            ),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    installed = json.loads(probe.stdout)
    digest = sha256(dependency_wheel)
    (root / "uv.lock").write_text(
        '[[package]]\nname="talkcut"\nversion="0.1.0"\nsource={editable="."}\ndependencies=[{name="demo-dep"}]\n'
        '[[package]]\nname="demo-dep"\nversion="1.0"\nwheels=[{hash="sha256:'
        + digest
        + '"}]\n'
    )
    export = tmp_path / "requirements.txt"
    export.write_text("demo-dep==1.0 \\\n --hash=sha256:" + digest + "\n")
    wheel_archives = [artifact_ref(dependency_wheel)]
    assert _locked_runtime(root, export, installed, wheel_archives, seed_files) == {
        "demo-dep": "1.0"
    }
    changed = Path(installed["package_directory"]).parent / "demo_dep/__init__.py"
    before = (
        artifact_ref(changed)
        if mutation not in {"extra_module", "startup_pth"}
        else None
    )
    if mutation == "extra_module":
        changed = changed.with_name("unregistered_payload.py")
    changed.write_text("SYNTHETIC_FIXTURE_VALUE = 999\n")
    if mutation == "startup_pth":
        # Restore the normal wheel payload; isolate one new startup input.
        changed.write_text("SYNTHETIC_FIXTURE_VALUE = 1\n")
        changed = changed.parent.parent / "unregistered_payload.pth"
        changed.write_text(
            "import os; os.environ['TALKCUT_INDEPENDENT_PTH_EXECUTED'] = '1'\n"
        )
        actual = subprocess.run(
            [
                str(prefix / "bin/python"),
                "-I",
                "-c",
                "import os; print(os.environ.get('TALKCUT_INDEPENDENT_PTH_EXECUTED'))",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        assert actual.stdout.strip() == "1", (
            "The actual isolated Python did not consume the added startup code"
        )
    if mutation == "code_and_record":
        record = changed.parent.parent / "demo_dep-1.0.dist-info/RECORD"
        data = changed.read_bytes()
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode()
        )
        rows = [
            f"demo_dep/__init__.py,sha256={digest},{len(data)}"
            if row.startswith("demo_dep/__init__.py,")
            else row
            for row in record.read_text().splitlines()
        ]
        record.write_text("\n".join(rows) + "\n")
    atomic_json(
        tmp_path / "installed-byte-mutation.json",
        {
            "executions": executions,
            "installed_probe": installed,
            "pre_install_seed_files": seed_files,
            "before": before,
            "after": artifact_ref(changed),
            "mutation": mutation,
            "scope": "actual generated local wheel installation; no external assets or media",
        },
    )
    with pytest.raises(TalkCutError):
        _locked_runtime(root, export, installed, wheel_archives, seed_files)
