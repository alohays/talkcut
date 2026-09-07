"""Authored CLI format controls, not AI evidence; registration is isolated here."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from talkcut import codex_cli_transport as cli
from talkcut import composite_registration as registration
from talkcut.contracts import code_identity
from talkcut.project import TalkCutError, artifact_ref, atomic_json


def fixture(tmp_path, monkeypatch):
    tmp_path = tmp_path.resolve()
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/code.py").write_text("AUTHORED = True\n")

    def put(name, value):
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, bytes):
            p.write_bytes(value)
        elif isinstance(value, str):
            p.write_text(value)
        else:
            atomic_json(p, value)
        return artifact_ref(p)

    deps = {
        "source_hashes": {"screen": put("source.bin", b"authored source")["sha256"]},
        "contract_hash": put("contract.json", {})["sha256"],
        "output_hash": put("output.bin", b"authored output")["sha256"],
        "code_tree_hash": code_identity(repo)["code_tree_hash"],
    }
    png = put("frame.png", b"\x89PNG\r\n\x1a\nauthored parser header only")
    frames = [
        {
            "artifact": png,
            "frame_index": i,
            "timestamp": str(i),
            "duration": "1",
            "mime_type": "image/png",
        }
        for i in range(2)
    ]
    child = put(
        "child.txt",
        "An authored synthetic observation, no real media or model execution.",
    )
    outputs = [
        {
            "node_id": "child",
            "artifact_sha256": child["sha256"],
            "text": Path(child["path"]).read_text(),
        }
    ]
    base = put(
        "base.txt",
        "Return authored calibration JSON using only actual observations, no tools.",
    )
    prompt = cli.terminal_cli_prompt(Path(base["path"]).read_text(), frames, outputs)
    prefix = [
        {
            "type": "message",
            "role": "developer",
            "content": [{"type": "input_text", "text": text}],
        }
        for text in [
            "authored skills",
            "authored readonly permission",
            "authored default mode",
        ]
    ]
    preview = prefix + [
        {
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "authored environment"}],
        },
        {
            "type": "message",
            "role": "user",
            "content": cli.cli_user_content(prompt, frames),
        },
    ]
    binary = put("codex", b"authored binary")
    config = put("config.toml", "authored = true\n")
    instructions = put(
        "base-instructions.json", {"text": "authored system instructions"}
    )
    model = "authored-model"
    version = "authored-cli"
    cwd = str(tmp_path)
    renderer = {
        "schema_version": "codex-cli-render/v1",
        "argv": cli.renderer_argv(binary["path"], frames, prompt),
        "cwd": cwd,
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:00:01+00:00",
        "exit_code": 0,
        "stdout": put("preview.json", preview),
        "stderr": put("preview.stderr", b""),
    }
    call = {
        "schema_version": "terminal-ai-request/v1",
        "transport_kind": cli.KIND,
        "dependencies": deps,
        "input_modalities": ["image_sequence", "tool_results_as_text", "text"],
        "frames": frames,
        "tool_outputs": [child],
        "tool_output_packets": outputs,
        "prompt": base,
        "rendered_prompt": put("prompt.txt", prompt),
        "renderer": put("renderer.json", renderer),
        "created_at": "2026-01-01T00:00:02+00:00",
        "cli_binary": binary,
        "config": config,
        "base_instructions": instructions,
        "model_revision": model,
        "cli_version": version,
        "cwd": cwd,
        "repo_root": str(repo),
        "supervisor_runner": put("runner.py", 'print("authored supervisor")\n'),
        "supervisor_policy": {"timeout_seconds": 300},
        "environment_overrides": {},
        "dependency_artifacts": [
            artifact_ref(tmp_path / n)
            for n in ["source.bin", "contract.json", "output.bin"]
        ],
        "composite_request": put(
            "composite.json", {"dependencies": deps, "frames": frames}
        ),
    }
    renderer["bindings_before"] = [
        binary,
        config,
        base,
        call["rendered_prompt"],
        *[row["artifact"] for row in frames],
        child,
    ]
    renderer["bindings_after"] = copy.deepcopy(renderer["bindings_before"])
    call["renderer"] = put("renderer.json", renderer)
    call["recipe"] = put(
        "recipe.json",
        {
            "schema_version": "composite-review-recipe/v1",
            "component_profiles": {"terminal_ai": cli.cli_profile(call)},
        },
    )
    final = json.dumps(
        {
            "reason": "This is an authored response, never actual model evidence.",
            "component_outputs": {"child": child["sha256"]},
            "modality_attribution": {
                "audio_semantics": ["child"],
                "physical_signal": [],
                "video": "terminal",
            },
        }
    )
    final_ref = put("final.txt", final)
    call["argv"] = cli.cli_argv(
        binary["path"], cwd, final_ref["path"], frames, prompt, model
    )
    call_ref = put("request.json", call)
    sid = "authored-session"
    tid = "authored-turn"
    now = "2026-01-01T00:00:04+00:00"

    def row(kind, payload):
        return {"timestamp": now, "type": kind, "payload": payload}

    meta = {
        "id": sid,
        "session_id": sid,
        "source": "exec",
        "thread_source": "user",
        "cli_version": version,
        "cwd": cwd,
        "base_instructions": {"text": "authored system instructions"},
    }
    user_mirror = [
        {"type": "local_image", "path": f["artifact"]["path"]} for f in frames
    ] + [{"type": "text", "text": prompt, "text_elements": []}]
    rows = [
        row("session_meta", meta),
        row("event_msg", {"type": "task_started", "turn_id": tid}),
        *[row("response_item", m) for m in preview[:-1]],
        row("world_state", {"full": True, "state": {}}),
        row(
            "turn_context",
            {
                "turn_id": tid,
                "model": model,
                "cwd": cwd,
                "approval_policy": "never",
                "sandbox_policy": {"type": "read-only"},
            },
        ),
        row("response_item", preview[-1]),
    ]

    def mirror(item):
        return row(
            "event_msg",
            {"type": "item_completed", "thread_id": sid, "turn_id": tid, "item": item},
        )

    rows += [
        mirror({"type": "UserMessage", "id": "user", "content": user_mirror}),
        mirror(
            {
                "type": "Reasoning",
                "id": "reasoning",
                "summary_text": [],
                "raw_content": [],
            }
        ),
        row(
            "response_item",
            {
                "type": "reasoning",
                "id": "reasoning",
                "summary": [],
                "encrypted_content": "opaque reasoning is not intake",
            },
        ),
        mirror(
            {
                "type": "AgentMessage",
                "id": "answer",
                "phase": "final_answer",
                "content": [{"type": "Text", "text": final}],
            }
        ),
        row(
            "response_item",
            {
                "type": "message",
                "id": "answer",
                "role": "assistant",
                "phase": "final_answer",
                "content": [{"type": "output_text", "text": final}],
            },
        ),
        row("token_usage_record", {"thread_id": sid, "turn_id": tid}),
        row("event_msg", {"type": "token_count"}),
    ]
    rows.append(
        {
            "timestamp": "2026-01-01T00:00:05+00:00",
            "type": "event_msg",
            "payload": {
                "type": "task_complete",
                "turn_id": tid,
                "last_agent_message": final,
            },
        }
    )
    session = b"".join((json.dumps(r) + "\n").encode() for r in rows)
    session_ref = put("session.jsonl", session)
    stdout = b"".join(
        (json.dumps(r) + "\n").encode()
        for r in [
            {"type": "thread.started", "thread_id": sid},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "id": "item0", "text": final},
            },
            {"type": "turn.completed", "usage": {}},
        ]
    )
    execution = {
        "schema_version": "private-bounded-process-execution/v1",
        "request": call_ref,
        "argv": call["argv"],
        "cwd": cwd,
        "execution_status": "COMPLETED",
        "exit_code": 0,
        "termination_reason": None,
        "received_signals": [],
        "cleanup": {
            "status": "VERIFIED_EMPTY",
            "remaining_process_group_pids": [],
            "observation_errors": False,
        },
        "started_at": "2026-01-01T00:00:03+00:00",
        "finished_at": "2026-01-01T00:00:06+00:00",
        "pid": 123,
        "pgid": 123,
        "elapsed_seconds": 3,
        "policy": call["supervisor_policy"],
        "environment_overrides": {},
        "stdout": put("stdout.jsonl", stdout),
        "stderr": put("stderr.txt", b""),
        "runner_errors": put("errors.txt", b""),
        "process_samples": put("samples.jsonl", b'{"authored":true}\n'),
    }
    required = [
        call_ref,
        call["composite_request"],
        call["recipe"],
        base,
        call["rendered_prompt"],
        call["renderer"],
        renderer["stdout"],
        renderer["stderr"],
        binary,
        config,
        instructions,
        call["supervisor_runner"],
        child,
        *[f["artifact"] for f in frames],
        *call["dependency_artifacts"],
    ]
    run = {
        "schema_version": "private-codex-cli-run/v1",
        "execution": execution,
        "raw_final": final_ref,
        "bindings_before": required,
        "bindings_after": copy.deepcopy(required),
    }
    run_ref = put("run.json", run)
    capture = {
        "schema_version": "codex-cli-session/v1",
        "session_id": sid,
        "turn_id": tid,
        "start_byte": 0,
        "end_byte": len(session),
        "session": session_ref,
    }
    capture_ref = put("capture.json", capture)
    home = tmp_path / "codex-home"
    log = home / "sessions" / f"rollout-{sid}.jsonl"
    log.parent.mkdir(parents=True)
    log.write_bytes(session)
    monkeypatch.setenv("CODEX_HOME", str(home))
    registered = {
        "terminal_request": call_ref,
        "cli_run": run_ref,
        "renderer": call["renderer"],
        "origin": "exec",
        "session_id": sid,
        "source_log": str(log),
        "metadata": put("meta.jsonl", session.splitlines(keepends=True)[0]),
        "capture": capture_ref,
        "model_revision": model,
        "profile": cli.cli_profile(call),
        "bootstrap_context": put(
            "bootstrap.json",
            {
                "base_instructions": meta["base_instructions"],
                "world_state": [{"full": True, "state": {}}],
            },
        ),
    }
    # Domain controls isolate the separately executed registration audit. Other
    # tests below leave this unset and prove authored data cannot self-register.
    monkeypatch.setattr(
        registration,
        "_CURRENT",
        __import__("contextvars").ContextVar(
            "authored-registration",
            default={
                "sessions": {sid: registered},
                "request": call["composite_request"],
                "recipe": call["recipe"],
            },
        ),
    )
    return locals()


def verify(f):
    return cli.verify_cli_exchange(
        f["capture_ref"],
        call_ref=f["call_ref"],
        run_ref=f["run_ref"],
        model_revision=f["model"],
        request_id=f"codex-cli:{f['sid']}/turn:{f['tid']}",
        dependencies=f["deps"],
        frames=f["frames"],
        outputs=f["outputs"],
        output_refs=[f["child"]],
    )


def test_authored_registered_domain_positive_has_explicit_text_delivery(
    tmp_path, monkeypatch
):
    f = fixture(tmp_path, monkeypatch)
    result = verify(f)
    assert result["request"]["input_delivery"] == "tool_results_as_text"
    assert result["response"]["raw_text"] == f["final"]
    assert result["observed_execution"]["provider_process_exit_code"] is None
    assert result["observed_execution"]["cli_process_exit_code"] == 0


def test_authored_data_without_independent_registration_rejects(tmp_path, monkeypatch):
    f = fixture(tmp_path, monkeypatch)
    registration._CURRENT.set(None)
    with pytest.raises(TalkCutError, match="registration"):
        verify(f)


def test_renderer_after_hash_claim_cannot_omit_actual_pre_render_bindings(
    tmp_path, monkeypatch
):
    f = fixture(tmp_path, monkeypatch)
    renderer = copy.deepcopy(f["renderer"])
    renderer.pop("bindings_before")
    changed_renderer = f["put"]("renderer-missing-preflight.json", renderer)
    call = copy.deepcopy(f["call"])
    call["renderer"] = changed_renderer
    changed_call = f["put"]("changed-call.json", call)
    run = copy.deepcopy(f["run"])
    run["execution"]["request"] = changed_call
    for key in ("bindings_before", "bindings_after"):
        run[key] = [
            changed_renderer
            if r == f["call"]["renderer"]
            else changed_call
            if r == f["call_ref"]
            else r
            for r in run[key]
        ]
    f["call_ref"] = changed_call
    f["run_ref"] = f["put"]("changed-run.json", run)
    f["registered"].update(
        terminal_request=changed_call, cli_run=f["run_ref"], renderer=changed_renderer
    )
    with pytest.raises(TalkCutError, match="before and after rendering"):
        verify(f)


def test_terminal_branch_preserves_actual_text_role_and_child_attribution(
    tmp_path, monkeypatch
):
    from talkcut.composite_review import VerifiedNode, _terminal

    f = fixture(tmp_path, monkeypatch)
    exchange = verify(f)
    execution = {
        "schema_version": "terminal-ai-execution/v1",
        "completed": True,
        "completion_basis": "actual_assistant_final",
        "dependencies": f["deps"],
        "started_at": exchange["observed_execution"]["started_at"],
        "finished_at": exchange["observed_execution"]["finished_at"],
        "request": f["call_ref"],
        "prompt_sha256": f["base"]["sha256"],
        "exchange": f["put"]("exchange.json", exchange),
        "session_capture": f["capture_ref"],
        "cli_run": f["run_ref"],
        "model_revision": f["model"],
        "provider_request_id": f"codex-cli:{f['sid']}/turn:{f['tid']}",
        "response": f["final_ref"],
    }
    child = VerifiedNode(
        "child",
        "local_audio_ai",
        f["child"],
        f["outputs"][0]["text"],
        None,
        None,
        "authored-child",
        cli.utc("2026-01-01T00:00:00+00:00"),
        cli.utc("2026-01-01T00:00:01+00:00"),
    )
    node = {
        "id": "terminal",
        "kind": "terminal_ai",
        "depends_on": ["child"],
        "execution": f["put"]("terminal.json", execution),
    }
    _, response = _terminal(
        node, {"dependencies": f["deps"], "frames": f["frames"]}, {"child": child}
    )
    assert response["component_outputs"] == {"child": f["child"]["sha256"]}


@pytest.mark.parametrize(
    "mutation",
    ["fake_parent", "fake_agent", "wrong_origin", "stale_bootstrap", "stale_metadata"],
)
def test_exec_registration_never_fabricates_child_origin(
    tmp_path, monkeypatch, mutation
):
    f = fixture(tmp_path, monkeypatch)
    if mutation == "fake_parent":
        f["registered"]["parent_thread_id"] = "fabricated"
    elif mutation == "fake_agent":
        f["registered"]["agent_path"] = "/fabricated"
    elif mutation == "wrong_origin":
        f["registered"]["origin"] = "subagent"
    elif mutation == "stale_bootstrap":
        Path(f["registered"]["bootstrap_context"]["path"]).write_text("{}")
    elif mutation == "stale_metadata":
        Path(f["registered"]["metadata"]["path"]).write_text("{}\n")
    with pytest.raises(TalkCutError):
        verify(f)


@pytest.mark.parametrize(
    "mutation",
    [
        "png",
        "prompt",
        "deps",
        "frame_order_same_png",
        "raw_child",
        "profile",
        "failed_exit",
        "cleanup",
        "late_preview",
        "argv",
        "bindings",
        "base_instructions",
        "final",
        "missing_dependency",
        "session_extra",
    ],
)
def test_formal_mutations_reject(tmp_path, monkeypatch, mutation):
    f = fixture(tmp_path, monkeypatch)
    if mutation == "png":
        Path(f["png"]["path"]).write_bytes(b"changed")
    elif mutation == "prompt":
        Path(f["base"]["path"]).write_text("changed")
    elif mutation == "deps":
        f["deps"]["output_hash"] = "f" * 64
    elif mutation == "frame_order_same_png":
        f["frames"].reverse()
    elif mutation == "raw_child":
        f["outputs"][0]["text"] += "changed"
    elif mutation == "profile":
        f["registered"]["profile"]["cli_version"] = "other"
    elif mutation == "base_instructions":
        Path(f["instructions"]["path"]).write_text("{}")
    elif mutation == "final":
        Path(f["final_ref"]["path"]).write_text("changed")
    elif mutation == "session_extra":
        f["log"].write_bytes(f["session"] + b'{"type":"extra"}\n')
    else:
        run = copy.deepcopy(f["run"])
        if mutation == "failed_exit":
            run["execution"]["exit_code"] = 1
        elif mutation == "cleanup":
            run["execution"]["cleanup"]["remaining_process_group_pids"] = [123]
        elif mutation == "late_preview":
            run["execution"]["started_at"] = "2025-12-31T00:00:00+00:00"
        elif mutation == "argv":
            run["execution"]["argv"].insert(2, "resume")
        elif mutation == "bindings":
            run["bindings_after"] = run["bindings_after"][:-1]
        elif mutation == "missing_dependency":
            run["bindings_before"] = run["bindings_before"][:-1]
            run["bindings_after"] = run["bindings_after"][:-1]
        f["run_ref"] = f["put"]("mutated-run.json", run)
        f["registered"]["cli_run"] = f["run_ref"]
    with pytest.raises(TalkCutError):
        verify(f)


@pytest.mark.parametrize(
    "mutation",
    [
        "extra_user",
        "encrypted_user",
        "tool",
        "agent",
        "compaction",
        "no_complete",
        "wrong_phase",
        "wrong_model",
        "wrong_permission",
        "mirror",
        "stdout",
        "raw_final",
        "readonly_preview",
        "image_order",
        "extra_metadata",
    ],
)
def test_parser_adversarial_intake_rejects(tmp_path, monkeypatch, mutation):
    f = fixture(tmp_path, monkeypatch)
    rows = copy.deepcopy(f["rows"])
    preview = copy.deepcopy(f["preview"])
    stdout = f["stdout"]
    final = f["final"].encode()
    if mutation == "extra_user":
        rows.insert(9, copy.deepcopy(rows[8]))
    elif mutation == "encrypted_user":
        rows[8]["payload"]["encrypted_content"] = "opaque input"
    elif mutation == "tool":
        rows[11]["payload"] = {"type": "function_call", "name": "read"}
    elif mutation == "agent":
        rows[11]["payload"] = {"type": "agent_message", "message": "another agent"}
    elif mutation == "compaction":
        rows[6]["type"] = "compacted"
    elif mutation == "no_complete":
        rows.pop()
    elif mutation == "wrong_phase":
        rows[13]["payload"]["phase"] = "final"
    elif mutation == "wrong_model":
        rows[7]["payload"]["model"] = "different"
    elif mutation == "wrong_permission":
        rows[7]["payload"]["sandbox_policy"] = {"type": "danger-full-access"}
    elif mutation == "mirror":
        rows[9]["payload"]["item"]["content"][0]["path"] = "different"
    elif mutation == "stdout":
        stdout = stdout.replace(b"agent_message", b"tool_message")
    elif mutation == "raw_final":
        final += b"\n"
    elif mutation == "readonly_preview":
        preview[1]["content"][0]["text"] = "danger-full-access"
    elif mutation == "image_order":
        rows[8]["payload"]["content"][0]["text"] = "wrong image path/index"
    elif mutation == "extra_metadata":
        rows.insert(9, copy.deepcopy(rows[0]))
    session = b"".join((json.dumps(r) + "\n").encode() for r in rows)
    with pytest.raises(TalkCutError):
        cli.parse_cli_intake(
            session,
            preview,
            prompt=f["prompt"],
            frames=f["frames"],
            model_revision=f["model"],
            cli_version=f["version"],
            cwd=f["cwd"],
            stdout=stdout,
            final=final,
        )


@pytest.mark.parametrize("target", ["canonical", "capture"])
def test_exec_registration_bounds_before_full_session_read(tmp_path, monkeypatch, target):
    from talkcut import composite_registration as registration

    f = fixture(tmp_path, monkeypatch)
    path = f["log"] if target == "canonical" else Path(f["session_ref"]["path"])
    with path.open("r+b") as stream:
        stream.truncate(cli.INTAKE_LIMIT + 1)
    if target == "capture":
        capture = copy.deepcopy(f["capture"])
        capture["session"] = artifact_ref(path)
        capture["end_byte"] = path.stat().st_size
        f["registered"]["capture"] = f["put"]("oversized-capture.json", capture)
    original = Path.read_bytes

    def read(selected):
        assert selected != path, "Oversized session read before bound"
        return original(selected)

    monkeypatch.setattr(Path, "read_bytes", read)
    with pytest.raises(TalkCutError, match="bound"):
        registration._session(f["registered"])


@pytest.mark.parametrize("target", ["renderer", "execution"])
def test_boolean_exit_is_not_integer_zero(tmp_path, monkeypatch, target):
    f = fixture(tmp_path, monkeypatch)
    if target == "execution":
        run = copy.deepcopy(f["run"])
        run["execution"]["exit_code"] = False
        f["run_ref"] = f["put"]("boolean-exit.json", run)
        f["registered"]["cli_run"] = f["run_ref"]
    else:
        renderer = cli.loads(cli.raw(f["call"]["renderer"]))
        renderer["exit_code"] = False
        # Keep its bound path so the intended type check is the first rejection.
        Path(f["call"]["renderer"]["path"]).write_text(json.dumps(renderer))
        call = copy.deepcopy(f["call"])
        call["renderer"] = artifact_ref(Path(call["renderer"]["path"]))
        f["call_ref"] = f["put"]("boolean-renderer-call.json", call)
        f["registered"]["terminal_request"] = f["call_ref"]
        f["registered"]["renderer"] = call["renderer"]
    with pytest.raises(TalkCutError):
        verify(f)
