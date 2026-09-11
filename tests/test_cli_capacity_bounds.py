"""Generated transport controls only; never media or model execution evidence."""

from __future__ import annotations

import base64
import copy
from pathlib import Path

import pytest
from test_codex_cli_transport import fixture, verify

from talkcut import codex_cli_transport as cli
from talkcut import composite_registration as registration
from talkcut.project import TalkCutError, artifact_ref

MIB = 1024 * 1024


@pytest.mark.parametrize("limit", [32 * MIB, 128 * MIB])
def test_exact_artifact_bound_is_inclusive(tmp_path, limit):
    path = (tmp_path / "generated-bound.bin").resolve()
    with path.open("wb") as stream:
        stream.truncate(limit)
    assert len(cli.raw(artifact_ref(path), limit=limit)) == limit


@pytest.mark.parametrize("limit", [32 * MIB, 128 * MIB])
def test_oversized_artifact_is_rejected_before_open(tmp_path, monkeypatch, limit):
    path = (tmp_path / "generated-oversize.bin").resolve()
    with path.open("wb") as stream:
        stream.truncate(limit + MIB)
    original = Path.open

    def guarded(selected, *args, **kwargs):
        assert selected != path, "Oversized artifact opened before rejection"
        return original(selected, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    with pytest.raises(TalkCutError, match="inspection bound"):
        cli.raw({"path": str(path), "sha256": "0" * 64}, limit=limit)


@pytest.mark.parametrize("target", ["canonical", "capture"])
def test_full_session_129_mib_is_rejected_before_open(tmp_path, monkeypatch, target):
    f = fixture(tmp_path, monkeypatch)
    path = f["log"] if target == "canonical" else Path(f["session_ref"]["path"])
    with path.open("r+b") as stream:
        stream.truncate(129 * MIB)
    original = Path.open

    def guarded(selected, *args, **kwargs):
        assert selected != path, "Oversized session opened before rejection"
        return original(selected, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    with pytest.raises(TalkCutError, match="bound"):
        registration._session(f["registered"])


def test_oversized_session_is_rejected_before_json_decoding(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Session JSON decoded before capacity rejection")

    monkeypatch.setattr(cli, "loads", forbidden)
    with pytest.raises(TalkCutError, match="truncated/oversized"):
        cli.parse_cli_intake(
            b" " * (129 * MIB - 1) + b"\n",
            None,
            prompt="",
            frames=[],
            model_revision="authored-model",
            cli_version="authored-cli",
            cwd="",
            stdout=b"",
            final=b"",
        )


@pytest.mark.parametrize(
    "target",
    ["png", "final", "config", "renderer", "execution_stdout", "prompt", "capture", "request", "run"],
)
def test_ordinary_cli_artifacts_keep_32_mib_before_open(tmp_path, monkeypatch, target):
    f = fixture(tmp_path, monkeypatch)
    refs = {
        "png": f["png"], "final": f["final_ref"], "config": f["config"],
        "renderer": f["call"]["renderer"], "execution_stdout": f["execution"]["stdout"],
        "prompt": f["base"], "capture": f["capture_ref"], "request": f["call_ref"], "run": f["run_ref"],
    }
    path = Path(refs[target]["path"])
    with path.open("r+b") as stream:
        stream.truncate(32 * MIB + 1)
    original = Path.open

    def guarded(selected, *args, **kwargs):
        assert selected != path, "Ordinary CLI artifact opened above 32 MiB"
        return original(selected, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    with pytest.raises(TalkCutError, match="bound"):
        if target == "png":
            cli.cli_user_content(f["prompt"], f["frames"])
        elif target == "config":
            cli.raw(refs[target])
        else:
            verify(f)


@pytest.mark.parametrize("target", ["terminal_request", "cli_run", "renderer", "bootstrap_context"])
@pytest.mark.parametrize("mutation", ["oversize", "duplicate_json", "wrong_hash", "wrong_bytes"])
def test_exec_registration_headers_are_bounded_strict_and_current(
    tmp_path, monkeypatch, target, mutation
):
    f = fixture(tmp_path, monkeypatch)
    ref = dict(f["registered"][target])
    f["registered"][target] = ref
    path = Path(ref["path"])
    if mutation == "oversize":
        with path.open("r+b") as stream:
            stream.truncate(33 * MIB)
        original = Path.open

        def guarded(selected, *args, **kwargs):
            assert selected != path, "Registration header opened above 32 MiB"
            return original(selected, *args, **kwargs)

        monkeypatch.setattr(Path, "open", guarded)
        expected = "bound"
    elif mutation == "duplicate_json":
        path.write_bytes(b'{"authored_duplicate":1,"authored_duplicate":2}')
        ref.update(artifact_ref(path))
        expected = "CLI JSON is unreadable"
    elif mutation == "wrong_hash":
        ref["sha256"] = "0" * 64
        expected = "bytes changed"
    else:
        ref["bytes"] = path.stat().st_size + 1
        expected = "bytes changed"
    with pytest.raises(TalkCutError, match=expected) as error:
        registration._session(f["registered"])
    if mutation == "duplicate_json":
        assert isinstance(error.value.__cause__, TalkCutError)
        assert str(error.value.__cause__) == "Duplicate CLI JSON key"


def _large_generated_fixture(tmp_path, monkeypatch):
    """Extend the authored fixture with generated PNG-signature parser bytes."""
    f = fixture(tmp_path, monkeypatch)
    # These bytes exercise transport capacity only, not an image decoder.
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"authored-padding" * MIB
    png = f["put"]("large-generated.png", png_bytes)
    frames = [{**frame, "artifact": png} for frame in f["frames"]]
    prompt = cli.terminal_cli_prompt(Path(f["base"]["path"]).read_text(), frames, f["outputs"])
    preview = copy.deepcopy(f["preview"])
    preview[-1]["content"] = cli.cli_user_content(prompt, frames)
    call = copy.deepcopy(f["call"])
    call.update(
        frames=frames,
        rendered_prompt=f["put"]("large-prompt.txt", prompt),
        composite_request=f["put"]("large-composite.json", {"dependencies": f["deps"], "frames": frames}),
    )
    renderer = copy.deepcopy(f["renderer"])
    renderer.update(
        argv=cli.renderer_argv(call["cli_binary"]["path"], frames, prompt),
        stdout=f["put"]("large-preview.json", preview),
    )
    renderer["bindings_before"] = [
        *[call[k] for k in ("cli_binary", "config", "prompt", "rendered_prompt")],
        *[row["artifact"] for row in frames], f["child"],
    ]
    renderer["bindings_after"] = copy.deepcopy(renderer["bindings_before"])
    call["renderer"] = f["put"]("large-renderer.json", renderer)
    call["argv"] = cli.cli_argv(
        call["cli_binary"]["path"], f["cwd"], f["final_ref"]["path"], frames, prompt, f["model"]
    )
    profile = cli.cli_profile(call)
    call["recipe"] = f["put"]("large-recipe.json", {
        "schema_version": "composite-review-recipe/v1", "component_profiles": {"terminal_ai": profile},
    })
    call_ref = f["put"]("large-request.json", call)
    rows = copy.deepcopy(f["rows"])
    rows[8]["payload"] = preview[-1]
    rows[9]["payload"]["item"]["content"] = [
        *[{"type": "local_image", "path": row["artifact"]["path"]} for row in frames],
        {"type": "text", "text": prompt, "text_elements": []},
    ]
    session = b"".join((cli.canonical(row) + "\n").encode() for row in rows)
    session_ref = f["put"]("large-session.jsonl", session)
    f["log"].write_bytes(session)
    capture = {**f["capture"], "session": session_ref, "end_byte": len(session)}
    capture_ref = f["put"]("large-capture.json", capture)
    run = copy.deepcopy(f["run"])
    run["execution"].update(request=call_ref, argv=call["argv"])
    required = [
        call_ref,
        *[call[k] for k in ("composite_request", "recipe", "prompt", "rendered_prompt", "renderer")],
        renderer["stdout"], renderer["stderr"],
        *[call[k] for k in ("cli_binary", "config", "base_instructions", "supervisor_runner")],
        f["child"], *[row["artifact"] for row in frames], *call["dependency_artifacts"],
    ]
    run.update(bindings_before=required, bindings_after=copy.deepcopy(required))
    run_ref = f["put"]("large-run.json", run)
    f["registered"].update(
        terminal_request=call_ref, cli_run=run_ref, renderer=call["renderer"],
        capture=capture_ref, profile=profile,
        metadata=f["put"]("large-meta.jsonl", session.splitlines(keepends=True)[0]),
    )
    scope = registration._CURRENT.get()
    assert scope is not None
    scope.update(request=call["composite_request"], recipe=call["recipe"])
    f.update(
        frames=frames, prompt=prompt, preview=preview, call=call, call_ref=call_ref,
        renderer=renderer, rows=rows, session=session, session_ref=session_ref,
        capture=capture, capture_ref=capture_ref, run=run, run_ref=run_ref,
        generated_png=png_bytes,
    )
    return f


def test_generated_envelope_above_32_mib_preserves_complete_current_intake(tmp_path, monkeypatch):
    f = _large_generated_fixture(tmp_path, monkeypatch)
    assert cli.LIMIT == 32 * MIB
    assert cli.INTAKE_LIMIT == 128 * MIB
    assert cli.LIMIT < len(f["session"]) < cli.INTAKE_LIMIT
    assert cli.LIMIT < Path(f["renderer"]["stdout"]["path"]).stat().st_size < cli.INTAKE_LIMIT
    canonical_before = artifact_ref(f["log"])
    capture_before = artifact_ref(Path(f["session_ref"]["path"]))
    registration._session(f["registered"])
    result = verify(f)
    assert result["request"]["content"] == f["preview"][-1]["content"]
    assert result["response"]["raw_text"] == f["final"]
    assert result["request"]["input_delivery"] == "tool_results_as_text"
    for item in result["request"]["content"]:
        if item["type"] == "input_image":
            assert base64.b64decode(item["image_url"].split(",", 1)[1], validate=True) == f["generated_png"]
    assert artifact_ref(f["log"]) == canonical_before
    assert artifact_ref(Path(f["session_ref"]["path"])) == capture_before
    with pytest.raises(TalkCutError, match="inspection bound"):
        cli.raw(f["renderer"]["stdout"])
    with pytest.raises(TalkCutError, match="bytes changed"):
        cli.raw({**f["renderer"]["stdout"], "sha256": "0" * 64}, limit=cli.INTAKE_LIMIT)
    with f["log"].open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(TalkCutError, match="bytes changed"):
        verify(f)
    assert artifact_ref(Path(f["session_ref"]["path"])) == capture_before
