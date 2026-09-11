"""Exercise actual measurement subprocess failures, not fabricated receipts."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from talkcut.project import verified_json


@pytest.mark.parametrize("check", ["baseline", "unknown-contract-check"])
def test_failed_actual_worker_preserves_logs_and_cannot_create_evidence(tmp_path, check):
    raw = tmp_path / "raw.json"
    raw.write_text('{"schema_version":"baseline-input/v1"}\n')
    original = raw.read_bytes()
    command = [sys.executable, "-m", "talkcut", "acceptance", "measure", str(tmp_path / "missing-project"),
               "--check", check, "--input", str(raw), "--contract", str(tmp_path / "missing-contract"), "--json"]
    process = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert process.returncode == 1
    result = json.loads(process.stdout)
    assert result["status"] == "FAIL" and result["evidence"] is None and result["measurements"] is None
    assert result["acceptance_status"] == "UNVERIFIED" and result["owner_acceptance"] == "pending"
    receipt = verified_json(result["receipt"])
    assert not receipt["completed"] and receipt["exit_code"] == 2
    actual_stdout = verified_json(receipt["stdout"])
    assert actual_stdout["schema_version"] == "talkcut-error/v1"
    assert actual_stdout["status"] == "FAIL"
    log = verified_json(receipt["log"])
    assert log["exit_code"] == 2 and "measure-worker" in log["command"]
    assert Path(receipt["stderr"]["path"]).exists()
    assert raw.read_bytes() == original
    repeated = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert repeated.returncode == 1
    assert json.loads(repeated.stdout)["run_id"] != result["run_id"]
    assert verified_json(result["receipt"]) == receipt
