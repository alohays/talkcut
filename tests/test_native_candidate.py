"""Candidate refusal/serialization controls, not native execution evidence.

Two serialization controls stub only the heavyweight native bundle boundary.
The actual intake trace validator processes generated PCM and byte-bound logs.
A separate actual-run recheck is required for any native intake observation.
"""

import copy
import json

import pytest
from test_composite_review import media as media_fixture
from test_composite_review import native_trace_control

from talkcut import composite_registration as registration
from talkcut import composite_review as cr
from talkcut import native_candidate as candidate
from talkcut.project import TalkCutError, artifact_ref, atomic_json

media = media_fixture


def put(path, value):
    atomic_json(path, value)
    return artifact_ref(path)


def fixture_input(tmp_path, media):
    call, _pcm, events, raw = native_trace_control(media, tmp_path)
    stdout = tmp_path / "stdout"
    stdout.write_bytes(raw)
    stderr = tmp_path / "stderr"
    stderr.write_text("\n".join(cr.TRACE_PREFIX + json.dumps(e) for e in events) + "\n")
    deps = {
        "source_hashes": {"screen": "1" * 64},
        "contract_hash": "2" * 64,
        "code_tree_hash": "3" * 64,
    }
    source_manifest = put(tmp_path / "source.json", {"files": []})
    build = put(tmp_path / "build.json", {"source_before": source_manifest})
    original_call = {
        "dependencies": deps,
        "input": call["audio"],
        "prompt": call["prompt"],
        "model_refs": [],
        "argv": call["argv"],
        "environment_overrides": {"TALKCUT_INTAKE_NONCE": call["trace_nonce"]},
        "runtime": {"path": "/synthetic-native", "sha256": "4" * 64},
        "runtime_libraries": [],
        "build_receipt": build,
        "runner": {"path": "/synthetic-runner", "sha256": "5" * 64},
    }
    process = {
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "exit_code": 0,
        "stdout": artifact_ref(stdout),
        "stderr": artifact_ref(stderr),
    }
    process_ref = put(tmp_path / "process.json", process)
    original = {
        "completed": True,
        "run_id": "synthetic-intake",
        "supervisor_execution": process_ref,
        "request": put(tmp_path / "original-request.json", original_call),
    }
    case_ref = put(tmp_path / "case.json", original)
    run_ref = put(tmp_path / "run.json", {"schema_version": "synthetic-test-only/v1"})
    envelope = {
        "schema_version": "private-unregistered-native-policy-input/v1",
        "status": "UNREGISTERED_INTAKE_ONLY",
        "accepted_av_seconds": 0,
        "original_case": case_ref,
        "original_run": run_ref,
        "dependencies": deps,
        "policy": {},
    }
    envelope_ref = put(tmp_path / "input.json", envelope)
    verified = {
        "case": original,
        "run": {},
        "request": original_call,
        "process": process,
    }
    return envelope_ref, envelope, verified, events, call, raw


@pytest.mark.parametrize(
    "damage", ["status", "accepted", "schema", "extra_registration"]
)
def test_supplied_policy_cannot_claim_registration_or_acceptance(tmp_path, damage):
    value = {
        "schema_version": "private-unregistered-native-policy-input/v1",
        "status": "UNREGISTERED_INTAKE_ONLY",
        "accepted_av_seconds": 0,
        "original_case": {},
        "original_run": {},
        "dependencies": {},
        "policy": {},
    }
    if damage == "status":
        value["status"] = "REGISTERED"
    elif damage == "accepted":
        value["accepted_av_seconds"] = 1
    elif damage == "schema":
        value["schema_version"] = "native-registration/v1"
    else:
        value["registration_ref"] = {}
    out = tmp_path / "candidate"
    with pytest.raises(TalkCutError, match="explicitly unregistered"):
        candidate.prepare_native_intake_candidate(
            put(tmp_path / "input.json", value), out
        )
    assert not out.exists() and registration._CURRENT.get() is None


def test_actual_bundle_validator_rejects_legacy_without_writing_candidate(
    tmp_path, media
):
    ref, *_ = fixture_input(tmp_path, media)
    with pytest.raises(TalkCutError, match="Legacy native records"):
        candidate.prepare_native_intake_candidate(ref, tmp_path / "candidate")
    assert not (tmp_path / "candidate").exists() and registration._CURRENT.get() is None


def test_candidate_is_exact_normalization_and_not_registered(
    tmp_path, media, monkeypatch
):
    ref, envelope, verified, *_ = fixture_input(tmp_path, media)
    seen = []

    def bundle(case, run, deps, policy):
        seen.append(copy.deepcopy(deps))
        assert case == envelope["original_case"] and run == envelope["original_run"]
        return copy.deepcopy(verified)

    monkeypatch.setattr(candidate.native, "verify_native_bundle", bundle)
    result_ref = candidate.prepare_native_intake_candidate(ref, tmp_path / "candidate")
    result = cr.artifact(result_ref)
    node = cr.artifact(result["node"])
    execution = cr.artifact(result["normalized_execution"])
    assert (
        result["status"] == "UNREGISTERED_INTAKE_ONLY"
        and result["accepted_av_seconds"] == 0
    )
    assert result["registration_status"] == result["semantic_status"] == "UNVERIFIED"
    assert (
        result["dependencies"] == envelope["dependencies"]
        and "output_hash" not in result["dependencies"]
    )
    assert (
        execution["stdout"] == verified["process"]["stdout"]
        and execution["native_execution"] == envelope["original_case"]
    )
    assert execution["completed"] is True and node["sample_range"] == [0, 16000]
    assert (
        seen == [envelope["dependencies"], envelope["dependencies"]]
        and registration._CURRENT.get() is None
    )
    with pytest.raises(TalkCutError, match="durable"):
        cr.adapt_native_execution(
            envelope["original_case"],
            envelope["dependencies"],
            tmp_path / "registered",
            run_summary_ref=envelope["original_run"],
        )
    # Pure serialization equivalence with the existing registered normalizer;
    # its heavyweight registration/leaf boundaries are stubs in this control.
    monkeypatch.setattr(cr, "native_policy", lambda _: {})
    monkeypatch.setattr(cr, "_audio_node", lambda *_: None)
    other = cr._adapt_native_execution(
        envelope["original_case"],
        envelope["dependencies"],
        tmp_path / "equivalent",
        run_summary_ref=envelope["original_run"],
    )
    other_value = cr.artifact(other)
    assert cr.artifact(other_value["request"]) == cr.artifact(
        result["normalized_request"]
    )
    execution.pop("request")
    other_value.pop("request")
    assert execution == other_value


@pytest.mark.parametrize(
    "damage",
    [
        "no_trace",
        "eog_missing",
        "missing_chunk",
        "wrong_pcm",
        "wrong_stdout",
        "nonce",
        "dependency",
        "changed_second_read",
    ],
)
def test_trace_and_scope_refusals_do_not_emit_candidates(
    tmp_path, media, monkeypatch, damage
):
    ref, _envelope, verified, events, _call, raw = fixture_input(tmp_path, media)
    if damage == "no_trace":
        events = []
    elif damage == "eog_missing":
        events[-1]["stop_reason"] = "limit"
    elif damage == "missing_chunk":
        events = [e for e in events if e["event"] != "audio_chunk_evaluated"]
    elif damage == "wrong_pcm":
        next(e for e in events if e["event"] == "audio_decoded")["float_pcm_sha256"] = (
            "f" * 64
        )
    elif damage == "nonce":
        events[0]["run_nonce"] = "other-invocation"
    if damage in {"no_trace", "eog_missing", "missing_chunk", "wrong_pcm", "nonce"}:
        path = tmp_path / "stderr-mutated"
        path.write_text(
            "\n".join(cr.TRACE_PREFIX + json.dumps(e) for e in events) + "\n"
        )
        verified["process"]["stderr"] = artifact_ref(path)
    if damage == "wrong_stdout":
        path = tmp_path / "stdout-mutated"
        path.write_bytes(raw + b"altered model response")
        verified["process"]["stdout"] = artifact_ref(path)
    if damage == "dependency":
        verified["request"]["dependencies"] = {"output_hash": "f" * 64}
    calls = 0

    def bundle(*_):
        nonlocal calls
        calls += 1
        result = copy.deepcopy(verified)
        if damage == "changed_second_read" and calls == 2:
            result["case"]["run_id"] = "changed-run"
        return result

    monkeypatch.setattr(candidate.native, "verify_native_bundle", bundle)
    out = tmp_path / "candidate"
    with pytest.raises(TalkCutError):
        candidate.prepare_native_intake_candidate(ref, out)
    assert not out.exists() and registration._CURRENT.get() is None


def test_existing_destination_is_preserved_without_validation(tmp_path, monkeypatch):
    out = tmp_path / "candidate"
    out.mkdir()
    marker = out / "keep"
    marker.write_bytes(b"preserve")
    monkeypatch.setattr(
        candidate.native,
        "verify_native_bundle",
        lambda *_: pytest.fail("destination checked first"),
    )
    with pytest.raises(TalkCutError, match="new canonical"):
        candidate.prepare_native_intake_candidate({}, out)
    assert marker.read_bytes() == b"preserve"


@pytest.mark.parametrize("damage", ["failed_run", "incomplete_case"])
def test_real_bundle_final_gate_precedes_candidate_creation(tmp_path, damage):
    case = {
        "schema_version": "private-native-audio-case/v1",
        "execution_status": "COMPLETED",
        "completed": damage != "incomplete_case",
        "bindings_unchanged": True,
    }
    case_ref = put(tmp_path / "case.json", case)
    run = {
        "schema_version": "private-native-audio-run/v1",
        "status": "FAILED"
        if damage == "failed_run"
        else "UNVERIFIED_PENDING_SEPARATE_REVIEW",
        "error": None,
        "execution_status": "COMPLETED",
        "completed": True,
        "bindings_unchanged": True,
        "cases": [case_ref],
    }
    envelope = {
        "schema_version": "private-unregistered-native-policy-input/v1",
        "status": "UNREGISTERED_INTAKE_ONLY",
        "accepted_av_seconds": 0,
        "original_case": case_ref,
        "original_run": put(tmp_path / "run.json", run),
        "dependencies": {},
        "policy": {},
    }
    with pytest.raises(TalkCutError, match="Final native case/run failed"):
        candidate.prepare_native_intake_candidate(
            put(tmp_path / "input.json", envelope), tmp_path / "candidate"
        )
    assert not (tmp_path / "candidate").exists()
