"""Synthetic registration boundaries. No fake artifact audit is accepted as real AI."""

import copy
import json
from pathlib import Path

import pytest

from talkcut import composite_registration as reg
from talkcut import review
from talkcut.project import TalkCutError, artifact_ref


def put(directory, name, value):
    path = directory / name
    path.write_text(json.dumps(value))
    return artifact_ref(path)


@pytest.fixture
def registration(tmp_path, monkeypatch):
    # Isolate only already-validated independent audit boundary. Domain checks,
    # filesystem metadata and actual SHA checks continue to run in this fixture.
    home = tmp_path / "codex-home"
    sessions = home / "sessions"
    sessions.mkdir(parents=True)
    monkeypatch.setenv("CODEX_HOME", str(home))
    sid = "synthetic-child"
    meta = {
        "type": "session_meta",
        "payload": {
            "id": sid,
            "source": {
                "subagent": {
                    "thread_spawn": {
                        "parent_thread_id": "synthetic-parent",
                        "agent_path": "/root/synthetic-review",
                    }
                }
            },
        },
    }
    raw = (json.dumps(meta) + "\n").encode()
    log = sessions / ("rollout-" + sid + ".jsonl")
    log.write_bytes(raw)
    metadata = tmp_path / "metadata"
    metadata.write_bytes(raw)
    slice_path = tmp_path / "slice"
    slice_path.write_bytes(b"{}\n")
    capture = put(
        tmp_path,
        "capture.json",
        {
            "schema_version": "codex-session-slice/v1",
            "session_id": sid,
            "slice": artifact_ref(slice_path),
        },
    )
    deps = {
        "source_hashes": {"screen": "a" * 64},
        "code_tree_hash": "b" * 64,
        "contract_hash": "c" * 64,
    }
    request = put(tmp_path, "request.json", {"dependencies": deps})
    recipe = put(tmp_path, "recipe.json", {"recipe": "fixture"})
    evidence = {}
    for name in (
        "runtime",
        "runner",
        "prompt",
        "model",
        "projector",
        "build_receipt",
        "source_manifest",
        "source_review",
        "runner_review",
        "trace_review",
    ):
        p = tmp_path / name
        p.write_text("synthetic " + name)
        evidence[name] = artifact_ref(p)
    profile = {
        "runtime_sha256": evidence["runtime"]["sha256"],
        "runner_sha256": evidence["runner"]["sha256"],
        "model_sha256s": [evidence[k]["sha256"] for k in ("model", "projector")],
        "prompt_sha256": evidence["prompt"]["sha256"],
        "argv_template": ["synthetic"],
        "environment_keys": ["TALKCUT_INTAKE_NONCE"],
        "native_child_scope": {
            "task": "audio_semantics_only",
            "scope": "synthetic fixture",
        },
    }
    policy = {
        **{k: v for k, v in evidence.items() if k not in ("model", "projector")},
        "models": [evidence["model"], evidence["projector"]],
        "profile": profile,
        "source_manifest_sha256": evidence["source_manifest"]["sha256"],
        "build_receipt_sha256": evidence["build_receipt"]["sha256"],
        "supervisor_policy": {"timeout_seconds": 300},
        "leaf_scope": "audio_semantics_only",
        "precision_supported": False,
        "repo_root": str(tmp_path),
    }
    session = {
        "session_id": sid,
        "source_log": str(log),
        "metadata": artifact_ref(metadata),
        "capture": capture,
        "parent_thread_id": "synthetic-parent",
        "agent_path": "/root/synthetic-review",
        "model_revision": "synthetic-requested-model",
    }
    snapshot = {
        "schema_version": "composite-registration-snapshot/v1",
        "dependencies": deps,
        "request": request,
        "recipe": recipe,
        "native_builds": [policy],
        "codex_sessions": [session],
        "implementation_run_ids": ["author-run", "native-run"],
    }
    receipt = put(
        tmp_path,
        "audit-receipt.json",
        {"schema_version": "execution-receipt/v1", "run_id": "separate-auditor"},
    )
    audit = put(tmp_path, "audit.json", {"receipt": receipt})
    state = {
        "snapshot": snapshot,
        "receipt": receipt,
        "audit": audit,
        "request": request,
        "recipe": recipe,
        "dependencies": deps,
        "policy": policy,
        "session": session,
        "directory": tmp_path,
    }

    def save():
        return put(
            tmp_path,
            "registration.json",
            {
                "schema_version": "composite-registration/v1",
                "snapshot": put(tmp_path, "snapshot.json", state["snapshot"]),
                "audit": state["audit"],
            },
        )

    state["save"] = save

    def observed(*_args, **kwargs):
        assert kwargs["scope"] == "composite_registration"
        assert kwargs["dependencies"] == deps and kwargs["excluded_run_ids"] == {
            "author-run",
            "native-run",
        }
        for ref in kwargs["input_refs"]:
            assert artifact_ref(Path(ref["path"]))["sha256"] == ref["sha256"]
        return {
            "response": {
                "registration_observations": copy.deepcopy(
                    state.get(
                        "observations",
                        {
                            "request_sha256": request["sha256"],
                            "recipe_sha256": recipe["sha256"],
                            "native_profiles": [
                                {
                                    "profile": profile,
                                    "source_manifest_sha256": policy[
                                        "source_manifest_sha256"
                                    ],
                                    "build_receipt_sha256": policy[
                                        "build_receipt_sha256"
                                    ],
                                    "leaf_scope": "audio_semantics_only",
                                    "precision_supported": False,
                                }
                            ],
                            "terminal_captures": [
                                {
                                    "session_id": sid,
                                    "capture_sha256": capture["sha256"],
                                    "metadata_sha256": session["metadata"]["sha256"],
                                    "model_revision": session["model_revision"],
                                }
                            ],
                            "reason": "Synthetic already-validated audit boundary isolation: domain observations still match exact hashes and scope.",
                            "no_expected_answer_input_verified": True,
                            "native_trace_hooks_verified": True,
                            "terminal_transport_bytes_verified": True,
                            "independent_context_verified": True,
                        },
                    )
                )
            }
        }

    monkeypatch.setattr(review, "verify_artifact_audit", observed)
    return state


def test_registration_does_not_leak_to_next_request_or_after_exception(registration):
    s = registration
    r = s["save"]()
    with (
        pytest.raises(RuntimeError),
        reg.registration_scope(r, s["request"], s["recipe"], s["dependencies"]),
    ):
        assert (
            reg.native_policy(s["policy"]["profile"]["runtime_sha256"]) == s["policy"]
        )
        assert (
            reg.session_path(s["session"]["session_id"], s["session"]["capture"])
            == s["session"]["source_log"]
        )
        raise RuntimeError("synthetic downstream failure")
    assert reg._CURRENT.get() is None and reg._VALIDATING.get() is False
    with pytest.raises(TalkCutError, match="scoped"):
        reg.native_policy(s["policy"]["profile"]["runtime_sha256"])
    wrong = put(s["directory"], "other-request.json", {"other": True})
    with pytest.raises(TalkCutError, match="different current request"):
        reg.validate_registration(r, wrong, s["recipe"], s["dependencies"])


@pytest.mark.parametrize(
    "mutation",
    [
        "dependency",
        "recipe",
        "profile",
        "context",
        "capture",
        "same_run",
        "composite_bootstrap",
        "missing_audit",
        "changed_meta",
        "wrong_parent",
    ],
)
def test_registration_rejects_stale_scope_and_bootstrap_forgery(registration, mutation):
    s = registration
    if mutation == "dependency":
        s["snapshot"]["dependencies"] = {}
    elif mutation == "recipe":
        s["snapshot"]["recipe"] = s["request"]
    elif mutation == "profile":
        s["policy"]["profile"]["prompt_sha256"] = "d" * 64
    elif mutation == "context":
        s["observations"] = {}
    elif mutation == "capture":
        s["session"]["capture"] = s["request"]
    elif mutation in ("same_run", "composite_bootstrap"):
        value = {
            "schema_version": "execution-receipt/v1",
            "run_id": "author-run" if mutation == "same_run" else "separate-auditor",
        }
        if mutation == "composite_bootstrap":
            value["model_revision"] = "composite/" + "e" * 64
        s["audit"] = put(
            s["directory"],
            "changed-audit.json",
            {"receipt": put(s["directory"], "changed-receipt.json", value)},
        )
    elif mutation == "missing_audit":
        s["audit"] = {"path": str(s["directory"] / "missing"), "sha256": "f" * 64}
    elif mutation == "changed_meta":
        Path(s["session"]["source_log"]).write_text("{}\n")
    else:
        s["session"]["parent_thread_id"] = "other-parent"
    with pytest.raises(TalkCutError):
        reg.validate_registration(
            s["save"](), s["request"], s["recipe"], s["dependencies"]
        )
    assert reg._CURRENT.get() is None and reg._VALIDATING.get() is False


def test_registration_audit_must_use_real_common_validator_when_not_isolated(
    registration, monkeypatch
):
    s = registration
    # Restore actual public validator: the fixture's hand-written receipt has no
    # real executed audit evidence and must fail, despite matching domain labels.
    import importlib

    actual = importlib.reload(review).verify_artifact_audit
    monkeypatch.setattr(review, "verify_artifact_audit", actual)
    with pytest.raises(TalkCutError):
        reg.validate_registration(
            s["save"](), s["request"], s["recipe"], s["dependencies"]
        )


def test_registration_cannot_recursively_bootstrap_its_audit(registration, monkeypatch):
    s = registration
    r = s["save"]()
    monkeypatch.setattr(
        review,
        "verify_artifact_audit",
        lambda *_a, **_k: reg.validate_registration(
            r, s["request"], s["recipe"], s["dependencies"]
        ),
    )
    with pytest.raises(TalkCutError, match="bootstrap cycle"):
        reg.validate_registration(r, s["request"], s["recipe"], s["dependencies"])
    assert reg._VALIDATING.get() is False
