"""Fail-closed provenance for composite reviewers; no inference or semantic PASS.

This staged adapter requires a fresh instrumented native audio execution and a
captured terminal exchange containing actual image bytes and raw tool outputs.
Legacy calibration records cannot acquire intake evidence after execution.
Hashes bind bytes, not provider authenticity; independent execution audit is
still necessary. No native build is trusted before its instrumentation is audited.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import math
import struct
import subprocess
import wave
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import Any

from .project import TalkCutError, read_json, sha256
from .timeline import as_fraction

TRACE_PREFIX = "TALKCUT_INTAKE_V1 "
from .composite_registration import native_policy, registration_scope

DEPENDENCY_KEYS = {"source_hashes", "contract_hash", "code_tree_hash"}


def require(condition: Any, message: str) -> None:
    if not condition:
        raise TalkCutError("COMPOSITE_UNVERIFIED", message)


def artifact(ref: Any, *, raw: bool = False, verify_only: bool = False) -> Any:
    require(isinstance(ref, dict), "Hashed composite artifact missing")
    path = Path(ref.get("path", ""))
    require(path.is_absolute() and path.is_file(), "Composite input is missing")
    require(sha256(path) == ref.get("sha256"), "Stale composite artifact")
    if "bytes" in ref:
        require(path.stat().st_size == ref["bytes"], "Artifact byte count differs")
    if verify_only:
        return path
    return path.read_bytes() if raw else read_json(path)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def interval(value: Any) -> tuple[Fraction, Fraction]:
    require(isinstance(value, list) and len(value) == 2, "Interval missing")
    start, end = map(as_fraction, value)
    require(start < end, "Empty interval")
    return start, end


def utc(value: Any) -> datetime:
    require(isinstance(value, str), "Execution time missing")
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None, "Execution time is not timezone aware")
    return result


def pcm16(ref: dict[str, Any]) -> dict[str, Any]:
    """Read every sample; version1 supports normalized mono PCM16 16kHz WAV."""
    artifact(ref, raw=True)
    with wave.open(str(ref["path"]), "rb") as reader:
        require(
            reader.getnchannels() == 1 and reader.getsampwidth() == 2,
            "Composite v1 requires mono PCM16 WAV",
        )
        require(
            reader.getframerate() == 16000 and reader.getcomptype() == "NONE",
            "Composite v1 requires uncompressed 16kHz input",
        )
        count = reader.getnframes()
        data = reader.readframes(count + 1)
    require(count > 0 and len(data) == count * 2, "Incomplete PCM input")
    values = [sample[0] for sample in struct.iter_unpack("<h", data)]
    float_bytes = b"".join(struct.pack("<f", value / 32768) for value in values)
    return {
        "samples": values,
        "bytes": data,
        "float_bytes": float_bytes,
        "count": count,
        "rate": 16000,
        "float_sha256": digest(float_bytes),
    }


def physical_observations(ref: dict[str, Any]) -> dict[str, Any]:
    pcm = pcm16(ref)
    values = pcm["samples"]
    support: list[list[int]] = []
    for index, value in enumerate(values):
        if value:
            if support and support[-1][1] == index:
                support[-1][1] = index + 1
            else:
                support.append([index, index + 1])
    return {
        "schema_version": "physical-pcm-observations/v1",
        "input_sha256": ref["sha256"],
        "sample_rate": pcm["rate"],
        "sample_count": pcm["count"],
        "float_pcm_sha256": pcm["float_sha256"],
        "nonzero_support": support,
        "peak": max(abs(value) for value in values) / 32768,
        "dc": sum(values) / len(values) / 32768,
        "rms": math.sqrt(sum(value * value for value in values) / len(values)) / 32768,
        "semantics": "UNVERIFIED",
        "audibility": "UNVERIFIED",
    }


@dataclass(frozen=True)
class VerifiedNode:
    node_id: str
    kind: str
    output: dict[str, Any]
    text: str
    input_sha256: str | None
    sample_range: tuple[int, int] | None
    run_id: str
    started_at: datetime
    finished_at: datetime


def _base_execution(
    node: dict[str, Any], dependencies: dict[str, Any]
) -> dict[str, Any]:
    execution = artifact(node.get("execution"))
    require(
        execution.get("completed") is True
        and type(execution.get("exit_code")) is int
        and execution["exit_code"] == 0,
        "Component execution did not complete successfully",
    )
    require(
        not execution.get("test_only") and not execution.get("mock"),
        "Test/mock component cannot validate review",
    )
    require(
        execution.get("dependencies") == dependencies,
        "Component source/output/timeline dependencies differ",
    )
    require(
        execution.get("run_id")
        and utc(execution.get("started_at")) <= utc(execution.get("finished_at")),
        "Component execution identity/timing invalid",
    )
    require(
        node.get("depends_on") == [],
        "Leaf component cannot reuse another node output as media",
    )
    return execution


def _audio_node(
    node: dict[str, Any], request: dict[str, Any], root_pcm: dict[str, Any]
) -> VerifiedNode:
    execution = _base_execution(node, request["dependencies"])
    require(
        execution.get("schema_version") == "native-audio-execution/v1",
        "Legacy audio receipt has no actual native intake trace",
    )
    runtime = execution.get("runtime", {})
    artifact(runtime, raw=True)
    policy = native_policy(runtime.get("sha256", ""))
    require(
        execution.get("source_manifest", {}).get("sha256")
        == policy["source_manifest_sha256"],
        "Native source manifest differs from audited build",
    )
    artifact(execution["source_manifest"])
    call = artifact(execution.get("request"))
    require(
        call.get("schema_version") == "native-audio-request/v1",
        "Native actual request missing",
    )
    require(
        call.get("dependencies") == request["dependencies"],
        "Native request dependencies differ",
    )
    require(
        call.get("input_modalities") == ["audio"],
        "Native semantic child must consume audio",
    )
    require(
        call.get("input_artifacts") == [call.get("audio"), call.get("prompt")],
        "Native request has undeclared/extra input artifacts",
    )
    audio = call["audio"]
    prompt = artifact(call["prompt"], raw=True).decode("utf-8")
    require(prompt.strip(), "Audio instruction is empty")
    actual_pcm = pcm16(audio)
    bounds = node.get("sample_range")
    require(
        isinstance(bounds, list)
        and len(bounds) == 2
        and all(type(v) is int for v in bounds),
        "Actual audio sample mapping missing",
    )
    assert isinstance(bounds, list)
    start, end = bounds
    require(
        0 <= start < end <= root_pcm["count"], "Audio child is outside requested source"
    )
    require(
        actual_pcm["bytes"] == root_pcm["bytes"][start * 2 : end * 2],
        "Child audio bytes do not match requested source samples",
    )
    argv = call.get("argv", [])
    require(
        isinstance(argv, list) and all(isinstance(v, str) for v in argv),
        "Native argv missing",
    )
    if argv[:2] == ["/usr/bin/time", "-l"]:
        argv = argv[2:]
    require(
        argv and argv[0] == runtime["path"], "Native executable differs from request"
    )
    for flag in ("--audio", "-p", "-m", "--mmproj"):
        require(
            argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv),
            "Ambiguous native media/prompt argument",
        )
    require(
        argv[argv.index("--audio") + 1] == audio["path"]
        and argv[argv.index("-p") + 1] == prompt,
        "Audio file or instruction was not supplied to actual command",
    )
    require(
        not any(
            flag in argv for flag in ("--video", "--image", "-f", "--file", "--prompt")
        ),
        "Undeclared native input option",
    )
    models = call.get("models", [])
    require(
        [ref["sha256"] for ref in models] == policy["profile"]["model_sha256s"],
        "Native model/projector differ",
    )
    require(
        [ref["path"] for ref in models]
        == [argv[argv.index("-m") + 1], argv[argv.index("--mmproj") + 1]],
        "Model references were not actually selected",
    )
    for ref in models:
        artifact(ref, verify_only=True)
    from .native_provenance import verify_native_bundle

    verified = verify_native_bundle(
        execution.get("native_execution"),
        execution.get("native_run"),
        request["dependencies"],
        policy,
    )
    original, original_call, process = (
        verified["case"],
        verified["request"],
        verified["process"],
    )
    require(
        original_call.get("runtime") == execution["runtime"]
        and original_call.get("runtime_libraries") == execution["libraries"]
        and original_call.get("model_refs") == call["models"]
        and original_call.get("input") == call["audio"]
        and original_call.get("prompt") == call["prompt"]
        and original_call.get("argv") == call["argv"]
        and original_call.get("environment_overrides")
        == {"TALKCUT_INTAKE_NONCE": call["trace_nonce"]},
        "Normalized native execution differs from actual original input/argv/runtime",
    )
    require(
        execution.get("process") == original["supervisor_execution"]
        and execution.get("run_id") == original["run_id"],
        "Native process/case identity differs",
    )
    for key in ("started_at", "finished_at", "exit_code", "stdout", "stderr"):
        require(
            process.get(key) == execution.get(key),
            "Normalized native process changed original " + key,
        )
    raw = artifact(execution.get("stdout"), raw=True)
    text = raw.decode("utf-8")
    require(
        text.strip() and not text.lstrip().startswith(("Traceback", "error:")),
        "Audio AI response empty/failed",
    )
    require(
        process.get("stdout") == execution["stdout"]
        and process.get("stderr") == execution.get("stderr"),
        "Native output refs differ from process capture",
    )
    stderr = artifact(execution.get("stderr"), raw=True).decode("utf-8")
    events = [
        json.loads(line[len(TRACE_PREFIX) :])
        for line in stderr.splitlines()
        if line.startswith(TRACE_PREFIX)
    ]
    _native_trace(events, call, actual_pcm, raw)
    return VerifiedNode(
        node["id"],
        node["kind"],
        execution["stdout"],
        text,
        audio["sha256"],
        (start, end),
        execution["run_id"],
        utc(execution["started_at"]),
        utc(execution["finished_at"]),
    )


def _native_trace(
    events: list[dict[str, Any]],
    call: dict[str, Any],
    pcm: dict[str, Any],
    output_bytes: bytes,
) -> None:
    require(events and len(events) < 10000, "Actual native intake trace is absent")
    nonce = call.get("trace_nonce")
    media_id = call["audio"]["sha256"]
    require(
        isinstance(nonce, str) and len(nonce) >= 16, "Native invocation nonce missing"
    )
    require(
        [e.get("sequence") for e in events] == list(range(len(events))),
        "Native trace sequence missing/reordered",
    )
    require(
        all(e.get("run_nonce") == nonce for e in events),
        "Native trace is from another invocation",
    )
    require(
        all(
            type(e.get("monotonic_ms")) in (float, int)
            and math.isfinite(e["monotonic_ms"])
            and e["monotonic_ms"] >= 0
            for e in events
        ),
        "Native monotonic timestamps are not actual finite numbers",
    )
    require(
        all(
            a.get("monotonic_ms", -1) <= b.get("monotonic_ms", -1)
            for a, b in itertools.pairwise(events)
        ),
        "Native trace chronology invalid",
    )

    def one(kind: str) -> dict[str, Any]:
        found = [e for e in events if e.get("event") == kind]
        require(len(found) == 1, "Missing/duplicate native event: " + kind)
        return found[0]

    invocation = one("invocation")
    argv = call.get("argv", [])
    if argv[:2] == ["/usr/bin/time", "-l"]:
        argv = argv[2:]
    original_prompt = artifact(call["prompt"], raw=True).decode("utf-8")
    require(
        invocation.get("argv") == argv
        and invocation.get("cli_prompt_utf8") == original_prompt
        and invocation.get("cli_prompt_sha256") == digest(original_prompt.encode()),
        "Native invocation argv or original instruction differs",
    )
    allowed_events = {
        "invocation",
        "file_loaded",
        "audio_decoded",
        "audio_preprocessed",
        "audio_encoded",
        "audio_chunk_evaluated",
        "text_chunk_evaluated",
        "user_prompt_evaluated",
        "generation_finished",
    }
    require(
        all(
            e.get("schema") == "talkcut-native-intake/v1"
            and e.get("event") in allowed_events
            for e in events
        ),
        "Unknown or unsupported native intake event",
    )
    loaded, decoded, preprocessed = (
        one("file_loaded"),
        one("audio_decoded"),
        one("audio_preprocessed"),
    )
    require(
        loaded.get("sha256") == call["audio"]["sha256"]
        and loaded.get("bytes") == len(artifact(call["audio"], raw=True))
        and loaded.get("path") == call["audio"]["path"]
        and loaded.get("placeholder") is False,
        "Native did not read selected file bytes",
    )
    require(
        decoded.get("sample_count") == pcm["count"]
        and decoded.get("sample_rate") == pcm["rate"]
        and decoded.get("float_pcm_sha256") == pcm["float_sha256"]
        and decoded.get("bytes") == pcm["count"] * 4
        and decoded.get("channels") == 1
        and decoded.get("sample_format") == "native_float32",
        "Native did not consume complete actual float PCM",
    )
    require(
        preprocessed.get("float_pcm_sha256") == pcm["float_sha256"]
        and preprocessed.get("sample_count") == pcm["count"]
        and preprocessed.get("sample_rate") == pcm["rate"]
        and preprocessed.get("placeholder") is False,
        "Preprocessor used another PCM buffer",
    )
    require(
        all(
            e.get("media_id") == media_id
            for e in events
            if e.get("event")
            not in (
                "invocation",
                "text_chunk_evaluated",
                "user_prompt_evaluated",
                "generation_finished",
            )
        ),
        "Native component refers to another media buffer",
    )
    chunks = preprocessed.get("chunks", [])
    require(
        chunks and [row.get("index") for row in chunks] == list(range(len(chunks))),
        "Native preprocessing chunks missing",
    )
    total_mel = pcm["count"] // 160
    expected_mels = [min(800, total_mel - start) for start in range(0, total_mel, 800)]
    require(
        total_mel > 0 and [c.get("mel_frames") for c in chunks] == expected_mels,
        "Qwen3 preprocessing omitted or padded actual valid mel frames",
    )
    require(
        [c.get("expected_embedding_tokens") for c in chunks]
        == [(n // 100) * 13 + (n % 100 + 7) // 8 for n in expected_mels],
        "Qwen3 valid embedding denominator was changed",
    )
    for chunk in chunks:
        require(
            chunk.get("mel_bins") == 128
            and chunk.get("mel_original_frames") == chunk["mel_frames"]
            and chunk.get("mel_bytes") == chunk["mel_frames"] * 128 * 4
            and len(chunk.get("mel_sha256", "")) == 64
            and chunk.get("placeholder") is False,
            "Actual valid mel buffer receipt missing",
        )
    encoded = [e for e in events if e.get("event") == "audio_encoded"]
    evaluated = [e for e in events if e.get("event") == "audio_chunk_evaluated"]
    require(
        len(encoded) == len(evaluated) == len(chunks),
        "An actual audio chunk was not encoded/evaluated",
    )
    for chunk, enc, ev in zip(chunks, encoded, evaluated):
        require(
            enc.get("chunk_index") == ev.get("chunk_index") == chunk["index"],
            "Audio chunk reused/reordered",
        )
        require(
            preprocessed["sequence"] < enc["sequence"] < ev["sequence"],
            "Audio encode/eval chronology differs",
        )
        require(
            enc.get("global_chunk_index") == ev.get("global_chunk_index")
            and enc.get("embedding_dimension") == 2048
            and enc.get("embedding_bytes") == enc.get("embedding_tokens", 0) * 2048 * 4
            and len(enc.get("embedding_sha256", "")) == 64,
            "Actual embedding buffer/context identity missing",
        )
        count = chunk.get("expected_embedding_tokens")
        require(
            type(count) is int and count > 0 and enc.get("embedding_tokens") == count,
            "Actual embedding count differs from preprocessing",
        )
        require(
            enc.get("return_status") == ev.get("return_status") == 0
            and ev.get("context_end", 0) - ev.get("context_start", 0) == count,
            "Audio embeddings were not completely evaluated",
        )
    prompt = one("user_prompt_evaluated")
    original_prompt = artifact(call["prompt"], raw=True).decode("utf-8")
    user_content = (
        original_prompt
        if "<__media__>" in original_prompt
        else "<__media__>" + original_prompt
    )
    require(
        user_content.count("<__media__>") == 1, "Ambiguous native media marker count"
    )
    require(
        prompt.get("media_ids") == [media_id] and prompt.get("role") == "user",
        "Prompt refers to different input media or role",
    )
    expected_template = (
        "<|im_start|>user\n" + user_content + "<|im_end|>\n<|im_start|>assistant\n"
    )
    require(
        prompt.get("posttemplate_sha256") == digest(expected_template.encode("utf-8"))
        and prompt.get("posttemplate_utf8") == expected_template,
        "Actual posttemplate user instruction was changed or truncated",
    )
    require(
        prompt.get("prompt_sha256") == digest(user_content.encode("utf-8"))
        and prompt.get("prompt_utf8") == user_content
        and prompt.get("all_input_chunks_evaluated") is True,
        "User instructions or input chunks were not evaluated",
    )
    context = prompt.get("context_chunks", [])
    require(
        context
        and context[0].get("start") == 0
        and all(a.get("end") == b.get("start") for a, b in itertools.pairwise(context)),
        "Native context has missing/overlapping input chunks",
    )
    require(
        all(
            type(row.get("start")) is int
            and type(row.get("end")) is int
            and row["start"] < row["end"]
            for row in context
        ),
        "Invalid native context ranges",
    )
    context_events = [
        e
        for e in events
        if e.get("event") in ("text_chunk_evaluated", "audio_chunk_evaluated")
    ]
    require(
        len(context_events) == len(context) == prompt.get("input_chunk_count")
        and prompt.get("context_end") == context[-1]["end"]
        and [r.get("global_chunk_index") for r in context] == list(range(len(context))),
        "Input context/chunk denominator differs",
    )
    for row, event in zip(context, context_events):
        require(
            event.get("global_chunk_index") == row["global_chunk_index"]
            and event.get("chunk_index") == row.get("chunk_index")
            and event.get("context_start") == row["start"]
            and event.get("context_end") == row["end"]
            and event.get("return_status") == 0
            and row.get("n_positions")
            == row.get("n_tokens")
            == row["end"] - row["start"]
            and event["sequence"] < prompt["sequence"],
            "Actual successful context evaluation differs",
        )
        require(
            event.get("event") == row["kind"] + "_chunk_evaluated"
            and event.get("media_id")
            == row.get("media_id")
            == (media_id if row["kind"] == "audio" else ""),
            "Context text/audio identity was relabeled",
        )
        if row.get("kind") == "text":
            ids = row.get("token_ids", [])
            require(
                len(ids) == row["end"] - row["start"]
                and all(type(token) is int and token >= 0 for token in ids),
                "Actual evaluated text token IDs are missing",
            )
            require(
                row.get("token_ids_sha256")
                == digest(b"".join(struct.pack("<i", token) for token in ids)),
                "Actual text token buffer hash differs",
            )
        else:
            require(row.get("kind") == "audio", "Undeclared native context modality")
    audio_context = [row for row in context if row.get("kind") == "audio"]
    require(
        [(row.get("start"), row.get("end")) for row in audio_context]
        == [(row.get("context_start"), row.get("context_end")) for row in evaluated],
        "Native prompt coverage excludes/reuses audio chunks",
    )
    finish = one("generation_finished")
    emitted = finish.get("emitted_text_utf8")
    require(
        isinstance(emitted, str) and emitted.strip(), "Native emitted response is empty"
    )
    assert isinstance(emitted, str)
    emitted_bytes = emitted.encode("utf-8")
    ids = finish.get("token_ids", [])
    require(
        type(finish.get("tokens_decoded")) is int
        and finish["tokens_decoded"] > 0
        and finish.get("n_predict", 0) > finish["tokens_decoded"]
        and len(ids) == finish["tokens_decoded"] + 1
        and all(type(token) is int and token >= 0 for token in ids)
        and ids[-1] in (151643, 151645)
        and finish.get("context_end")
        == prompt["context_end"] + finish["tokens_decoded"]
        and finish.get("emitted_text_bytes") == len(emitted_bytes),
        "Actual nonempty generation token/context denominator differs",
    )
    require(
        finish.get("stop_reason") == "eog"
        and finish.get("emitted_text_sha256") == digest(emitted_bytes)
        and finish.get("media_ids") == [media_id],
        "Native response truncated or from a different input",
    )
    require(
        emitted_bytes in output_bytes
        and not output_bytes.replace(emitted_bytes, b"", 1).strip(),
        "Wrapper stdout is not the native emitted text with console whitespace",
    )

    require(
        invocation["sequence"] == 0
        and loaded["sequence"]
        < decoded["sequence"]
        < preprocessed["sequence"]
        < prompt["sequence"]
        < finish["sequence"],
        "Native events contradict execution order",
    )


def _physical_node(
    node: dict[str, Any], request: dict[str, Any], root_pcm: dict[str, Any]
) -> VerifiedNode:
    execution = _base_execution(node, request["dependencies"])
    require(
        execution.get("schema_version") == "physical-pcm-execution/v1",
        "Physical measurement receipt missing",
    )
    require(
        execution.get("audio") == request["audio"],
        "Physical observations target different audio",
    )
    result = artifact(execution.get("result"))
    require(
        result == physical_observations(request["audio"]),
        "Physical observations were not measured from actual PCM",
    )
    require(
        execution.get("claim_scope") == "physical_signal_only",
        "PCM cannot certify semantics or audibility",
    )
    raw = artifact(execution["result"], raw=True).decode("utf-8")
    return VerifiedNode(
        node["id"],
        node["kind"],
        execution["result"],
        raw,
        request["audio"]["sha256"],
        (0, root_pcm["count"]),
        execution["run_id"],
        utc(execution["started_at"]),
        utc(execution["finished_at"]),
    )


def _terminal(
    node: dict[str, Any], request: dict[str, Any], children: dict[str, VerifiedNode]
) -> tuple[dict[str, Any], dict[str, Any]]:
    execution = artifact(node.get("execution"))
    require(
        execution.get("schema_version") == "terminal-ai-execution/v1"
        and execution.get("completed") is True
        and execution.get("completion_basis") == "actual_assistant_final"
        and not execution.get("mock")
        and not execution.get("test_only"),
        "Terminal AI execution missing/failed",
    )
    require(
        execution.get("dependencies") == request["dependencies"],
        "Terminal source/output dependencies differ",
    )
    require(
        set(node.get("depends_on", [])) == set(children),
        "Terminal omits a component output",
    )
    require(
        all(
            child.finished_at <= utc(execution.get("started_at"))
            for child in children.values()
        ),
        "Terminal AI ran before its evidence existed",
    )
    call = artifact(execution.get("request"))
    require(
        call.get("schema_version") == "terminal-ai-request/v1"
        and call.get("dependencies") == request["dependencies"],
        "Terminal actual request missing/stale",
    )
    cli_transport = call.get("transport_kind") == "codex_cli_direct_images/v1"
    require(
        call.get("input_modalities")
        == [
            "image_sequence",
            "tool_results_as_text" if cli_transport else "tool_results",
            "text",
        ],
        "Terminal must declare actual own modalities, not pretend it directly consumed audio",
    )
    require(
        not any(
            key in call
            for key in (
                "audio",
                "input_audio_hash",
                "audio_events",
                "expected",
                "ground_truth",
            )
        ),
        "Terminal request carries spoofed audio intake or expected answer",
    )
    prompt = artifact(call.get("prompt"), raw=True).decode("utf-8")
    require(
        prompt.strip() and execution.get("prompt_sha256") == call["prompt"]["sha256"],
        "Terminal prompt differs",
    )
    exchange = artifact(execution.get("exchange"))
    require(
        exchange.get("schema_version") == "captured-ai-exchange/v1",
        "Actual terminal transport exchange missing",
    )
    from .codex_transport import terminal_tool_code, verify_session_exchange

    tool_outputs = [
        {
            "node_id": key,
            "artifact_sha256": children[key].output["sha256"],
            "text": children[key].text,
        }
        for key in node["depends_on"]
    ]
    if cli_transport:
        from .codex_cli_transport import verify_cli_exchange

        actual_exchange = verify_cli_exchange(
            execution.get("session_capture"),
            call_ref=execution["request"],
            run_ref=execution["cli_run"],
            model_revision=execution.get("model_revision"),
            request_id=execution.get("provider_request_id"),
            dependencies=request["dependencies"],
            frames=request["frames"],
            outputs=tool_outputs,
            output_refs=[children[n].output for n in node["depends_on"]],
        )
    else:
        actual_exchange = verify_session_exchange(
            execution.get("session_capture"),
            code=terminal_tool_code(prompt, request["frames"], tool_outputs),
            model_revision=execution.get("model_revision"),
            request_id=execution.get("provider_request_id"),
        )
    require(
        exchange == actual_exchange,
        "Normalized exchange differs from actual Codex session transport",
    )
    observed_execution = exchange["observed_execution"]
    require(
        utc(observed_execution["started_at"]) == utc(execution.get("started_at"))
        and utc(observed_execution["finished_at"]) == utc(execution.get("finished_at")),
        "Terminal execution timing differs from actual session events",
    )
    transmitted = exchange.get("request", {})
    received = exchange.get("response", {})
    require(
        transmitted.get("request_id")
        == received.get("request_id")
        == execution.get("provider_request_id")
        and transmitted.get("model_revision") == execution.get("model_revision"),
        "Terminal exchange identity differs",
    )
    require(
        received.get("completed") is True
        and received.get("completion_basis") == "actual_assistant_final",
        "Terminal response empty/truncated",
    )
    content = transmitted.get("content", [])
    frames = request.get("frames", [])
    expected: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    for frame in frames:
        raw = artifact(frame["artifact"], raw=True)
        expected.append(
            {
                "type": "image",
                "mime_type": frame["mime_type"],
                "data_base64": base64.b64encode(raw).decode("ascii"),
                "timestamp": frame["timestamp"],
            }
        )
    for node_id in node["depends_on"]:
        child = children[node_id]
        expected.append(
            {
                "type": "tool_result",
                "node_id": node_id,
                "artifact_sha256": child.output["sha256"],
                "text": child.text,
            }
        )
    if cli_transport:
        from .codex_cli_transport import cli_user_content, terminal_cli_prompt

        expected = cli_user_content(
            terminal_cli_prompt(prompt, frames, tool_outputs), frames
        )
        require(
            transmitted.get("input_delivery") == "tool_results_as_text",
            "CLI modality delivery was relabeled",
        )
    require(
        content == expected,
        "Terminal did not receive exact ordered image bytes and raw component observations",
    )
    require(
        call.get("frames") == frames
        and call.get("tool_outputs")
        == [children[n].output for n in node["depends_on"]],
        "Terminal request substitutes or omits actual evidence",
    )
    raw_response = artifact(execution.get("response"), raw=True).decode("utf-8")
    require(
        received.get("raw_text") == raw_response and raw_response.strip(),
        "Final response differs from actual terminal output",
    )
    response = json.loads(raw_response)
    require(
        isinstance(response, dict) and len(response.get("reason", "").strip()) >= 30,
        "Terminal response is empty or not substantive",
    )
    require(
        response.get("component_outputs")
        == {key: value.output["sha256"] for key, value in children.items()},
        "Final AI response does not identify actual component observations",
    )
    require(
        response.get("modality_attribution")
        == {
            "audio_semantics": sorted(
                k for k, v in children.items() if v.kind == "local_audio_ai"
            ),
            "video": node["id"],
            "physical_signal": sorted(
                k for k, v in children.items() if v.kind == "pcm_analysis"
            ),
        },
        "Final response hides tool-derived modality attribution",
    )
    return execution, response


def _verify_clip_media(request: dict[str, Any], pcm: dict[str, Any]) -> None:
    """Bind supplied waveform and frames to one actual normalized review clip.

    v1 deliberately rejects nonzero stream origins; it never erases an offset.
    Existing review-request extraction validation still binds this clip to source.
    """
    parent = request.get("media_clip")
    artifact(parent, verify_only=True)
    assert isinstance(parent, dict)
    require(
        request.get("input_clip_hashes") == [parent["sha256"]],
        "Composite v1 requires one exact actual review clip per graph",
    )

    def run(args: list[str]) -> bytes:
        process = subprocess.run(args, capture_output=True, timeout=120, check=False)
        require(
            process.returncode == 0 and not process.stderr.strip(),
            "Actual composite media decode failed",
        )
        return process.stdout

    probe = json.loads(
        run(
            [
                "ffprobe",
                "-v",
                "error",
                "-show_streams",
                "-show_frames",
                "-of",
                "json",
                parent["path"],
            ]
        )
    )
    streams = probe.get("streams", [])
    video = [row for row in streams if row.get("codec_type") == "video"]
    audio = [row for row in streams if row.get("codec_type") == "audio"]
    require(
        len(video) == len(audio) == 1,
        "Composite clip requires one audio and video stream",
    )
    require(
        Fraction(video[0].get("start_time", "-1"))
        == Fraction(audio[0].get("start_time", "-1"))
        == 0,
        "Composite v1 cannot silently reset nonaligned stream origins",
    )
    decoded = run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-xerror",
            "-i",
            parent["path"],
            "-map",
            "0:a:0",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-f",
            "s16le",
            "-",
        ]
    )
    require(
        decoded == pcm["bytes"], "Supplied audio is not the complete selected clip PCM"
    )
    actual_frames = [
        row for row in probe.get("frames", []) if row.get("media_type") == "video"
    ]
    require(actual_frames, "Actual parent frames unavailable")
    origin = interval(request["audio_interval"])[0]
    time_base = Fraction(video[0]["time_base"])
    for supplied in request["frames"]:
        index = supplied.get("frame_index")
        require(
            type(index) is int and 0 <= index < len(actual_frames),
            "Frame source index missing/outside clip",
        )
        actual = actual_frames[index]
        pts = int(actual["pts"]) * time_base
        require(
            as_fraction(supplied["timestamp"]) == origin + pts,
            "Frame timestamp was relabeled",
        )
        width, height = video[0]["width"], video[0]["height"]
        actual_pixels = run(
            [
                "ffmpeg",
                "-nostdin",
                "-v",
                "error",
                "-xerror",
                "-i",
                parent["path"],
                "-vf",
                f"select=eq(n\\,{index})",
                "-fps_mode",
                "passthrough",
                "-frames:v",
                "1",
                "-pix_fmt",
                "rgb24",
                "-f",
                "rawvideo",
                "-",
            ]
        )
        supplied_pixels = run(
            [
                "ffmpeg",
                "-nostdin",
                "-v",
                "error",
                "-xerror",
                "-i",
                supplied["artifact"]["path"],
                "-frames:v",
                "1",
                "-pix_fmt",
                "rgb24",
                "-f",
                "rawvideo",
                "-",
            ]
        )
        require(
            len(actual_pixels) == width * height * 3
            and supplied_pixels == actual_pixels,
            "Terminal frame pixels are not from the claimed actual clip position",
        )
        actual_duration = (
            int(actual_frames[index + 1]["pts"]) * time_base - pts
            if index + 1 < len(actual_frames)
            else Fraction(
                actual.get("duration_time", actual.get("pkt_duration_time", "0"))
            )
        )
        require(
            actual_duration > 0
            and as_fraction(supplied["duration"]) == actual_duration,
            "Frame duration was inflated to invent coverage",
        )


def _verify_audio_recipe(execution: dict[str, Any], profile: dict[str, Any]) -> None:
    from .native_provenance import native_profile

    actual_call = artifact(artifact(execution.get("native_execution"))["request"])
    expected_profile = {
        **native_profile(actual_call),
        "source_manifest_sha256": execution.get("source_manifest", {}).get("sha256"),
        "leaf_scope": "audio_semantics_only",
        "precision_supported": False,
    }
    require(
        profile == expected_profile,
        "Audio execution differs from calibrated composite recipe",
    )


def validate_task_context(request: dict[str, Any], recipe: dict[str, Any]) -> None:
    """Bind optional semantic task metadata to the actual clip and fixed role."""
    context = request.get("review_context")
    policy = recipe.get("review_context_policy")
    frames = request.get("frames", [])
    frame_contexts = [
        index for index, row in enumerate(frames) if "review_context" in row
    ]
    if (
        "review_context" not in request
        and "review_context_policy" not in recipe
        and not frame_contexts
    ):
        return  # Legacy registered recipes have no per-call task metadata.
    require(
        isinstance(policy, dict)
        and set(policy) == {"schema_version", "role"}
        and policy["schema_version"] == "terminal-review-context-policy/v1"
        and policy["role"] in {"proposer", "adversarial"},
        "Semantic task metadata needs an explicit fixed recipe policy",
    )
    assert isinstance(policy, dict)
    require(
        isinstance(context, dict)
        and set(context)
        == {
            "schema_version",
            "task",
            "role",
            "scope",
            "intervals",
            "clip_to_parent_offset",
            "input_clip_hashes",
            "source_kind",
            "precision_required",
            "details",
        }
        and context["schema_version"] == "terminal-review-context/v1"
        and context["role"] == policy["role"]
        and type(context["precision_required"]) is bool
        and type(request.get("precision_required")) is bool
        and context["precision_required"] == request["precision_required"],
        "Semantic task context schema or fixed role differs",
    )
    assert isinstance(context, dict)
    require(
        frame_contexts == [0]
        and canonical(frames[0]["review_context"]) == canonical(context),
        "Terminal did not receive the exact single task context",
    )
    require(
        context["input_clip_hashes"] == request.get("input_clip_hashes")
        and context["input_clip_hashes"]
        == [request.get("media_clip", {}).get("sha256")],
        "Task metadata identifies different media",
    )
    require(
        isinstance(context["details"], dict)
        and canonical(context["details"]) == canonical(request.get("details", {})),
        "Task metadata changes the actual scoped details",
    )
    audio_domain = interval(request.get("audio_interval"))
    task = context["task"]
    if task == "calibration":
        require(
            context["scope"] == "generated_calibration"
            and context["source_kind"] == "generated_calibration"
            and canonical(context["intervals"]) == canonical([request["audio_interval"]])
            and context["details"] == {}
            and isinstance(context["clip_to_parent_offset"], str)
            and as_fraction(context["clip_to_parent_offset"]) == 0
            and not any(key in request for key in ("scope", "inputs", "source_sha256")),
            "Calibration task was relabeled as a real review",
        )
        return
    require(
        (
            task == "analysis"
            and policy["role"] == "proposer"
            and context["scope"] == "analysis"
        )
        or (
            task == "adversarial_review"
            and policy["role"] == "adversarial"
            and context["scope"]
            in {
                "analysis",
                "deletion",
                "output",
                "seam",
                "layout",
                "lip_sync",
                "source_sync",
            }
        ),
        "Semantic task is not supported by the calibrated role",
    )
    require(
        context["source_kind"] == "real"
        and context["scope"] == request.get("scope")
        and canonical(context["intervals"]) == canonical(request.get("intervals")),
        "Task metadata changes the actual requested scope or intervals",
    )
    inputs = request.get("inputs")
    require(
        isinstance(inputs, list)
        and len(inputs) == 1
        and isinstance(inputs[0], dict)
        and inputs[0].get("clip") == request.get("media_clip"),
        "Task context requires the one actual extraction input",
    )
    assert isinstance(inputs, list)
    clip_domain = interval(inputs[0].get("interval"))
    require(
        isinstance(context["clip_to_parent_offset"], str)
        and as_fraction(context["clip_to_parent_offset"])
        == clip_domain[0] - audio_domain[0]
        and isinstance(context["intervals"], list)
        and len(context["intervals"]) == 1
        and isinstance(context["intervals"][0], list)
        and len(context["intervals"][0]) == 2
        and all(isinstance(value, str) for value in context["intervals"][0])
        and interval(context["intervals"][0]) == clip_domain,
        "Task metadata changes the actual clip-to-parent clock",
    )
    if context["scope"] == "deletion":
        details = context["details"]
        require(
            {"candidate_id", "requested_interval", "source_domain"} <= set(details)
            <= {"candidate_id", "requested_interval", "source_domain",
                "deleted_interval", "complete_sentence_context"}
            and details.get("complete_sentence_context", "UNVERIFIED") == "UNVERIFIED"
            and isinstance(details.get("candidate_id"), str)
            and bool(details["candidate_id"].strip())
            and all(
                isinstance(details.get(key), list)
                and len(details[key]) == 2
                and all(isinstance(value, str) for value in details[key])
                for key in ("requested_interval", "source_domain")
            ),
            "Deletion task lacks an exact candidate and source interval",
        )
        requested = interval(details["requested_interval"])
        source_domain = interval(details["source_domain"])
        require(
            source_domain[0] <= clip_domain[0] <= requested[0]
            < requested[1] <= clip_domain[1] <= source_domain[1]
            and clip_domain[0] <= max(source_domain[0], requested[0] - 5)
            and clip_domain[1] >= min(source_domain[1], requested[1] + 5),
            "Deletion task omits the exact candidate or its bounded context",
        )
        if "deleted_interval" in details:
            deleted = details["deleted_interval"]
            require(
                isinstance(deleted, list) and len(deleted) == 2
                and all(isinstance(value, str) for value in deleted),
                "Deletion metadata has an invalid applied interval",
            )
            applied = interval(deleted)
            require(
                clip_domain[0] <= applied[0] < applied[1] <= clip_domain[1]
                and applied[0] < requested[1] and applied[1] > requested[0],
                "Deletion metadata applied interval is outside the actual candidate context",
            )
    elif context["scope"] == "seam":
        details = context["details"]
        require(
            set(details) == {"seam_time"}
            and isinstance(details["seam_time"], str)
            and clip_domain[0] <= as_fraction(details["seam_time"]) <= clip_domain[1],
            "Seam task requires only its exact observed seam time",
        )
    else:
        require(context["details"] == {}, "This task does not accept auxiliary claims")



def verify_composite_receipt(
    ref: dict[str, Any],
    *,
    precision_required: bool = False,
    forbidden_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    value = artifact(ref)
    request = artifact(value.get("request"))
    with registration_scope(
        value.get("registration"),
        value.get("request"),
        value.get("recipe"),
        request.get("dependencies"),
    ):
        return _verify_composite_receipt(
            ref,
            precision_required=precision_required,
            forbidden_artifacts=forbidden_artifacts,
        )


def _verify_composite_receipt(
    ref: dict[str, Any],
    *,
    precision_required: bool = False,
    forbidden_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate actual intake DAG; returned completion never assigns semantic PASS."""
    value = artifact(ref)
    require(
        value.get("schema_version") == "composite-review-receipt/v1",
        "Composite receipt schema missing",
    )
    require(
        not value.get("test_only") and not value.get("mock"),
        "Test composite cannot approve media",
    )
    request = artifact(value.get("request"))
    require(
        request.get("schema_version") == "composite-review-request/v1",
        "Composite request missing",
    )
    require(
        isinstance(request.get("dependencies"), dict)
        and DEPENDENCY_KEYS <= request["dependencies"].keys(),
        "Composite source/contract/code identity missing",
    )
    require(
        value.get("dependencies") == request["dependencies"],
        "Composite dependencies differ",
    )
    require(
        not any(k in request for k in ("expected", "ground_truth", "expected_events")),
        "Expected answer injected into review input",
    )
    root_pcm = pcm16(request.get("audio"))
    domain = interval(request.get("audio_interval"))
    require(
        domain[1] - domain[0] == Fraction(root_pcm["count"], root_pcm["rate"]),
        "Claimed audio interval differs from samples",
    )
    frames = request.get("frames", [])
    require(2 <= len(frames) <= 4000, "Actual ordered video frames missing")
    timestamps = [as_fraction(row["timestamp"]) for row in frames]
    require(
        timestamps[0] == domain[0]
        and all(a < b for a, b in itertools.pairwise(timestamps)),
        "Frame clock/order differs",
    )
    require(
        timestamps[-1] + as_fraction(frames[-1]["duration"]) >= domain[1],
        "Frame sequence misses end of requested window",
    )
    require(
        all(domain[0] <= t < domain[1] for t in timestamps),
        "Frame timestamp outside actual audio window",
    )
    from .review import _media_streams

    for row in frames:
        _media_streams(row["artifact"], {"video"}, decode=True)
    require(
        request.get("input_audio_hash") == request["audio"]["sha256"]
        and request.get("input_frame_hashes")
        == [r["artifact"]["sha256"] for r in frames]
        and request.get("input_frame_timestamps") == [r["timestamp"] for r in frames],
        "Composite request does not bind actual media bytes/order/time",
    )
    _verify_clip_media(request, root_pcm)
    recipe = artifact(value.get("recipe"))
    require(
        recipe.get("schema_version") == "composite-review-recipe/v1",
        "Frozen composite recipe missing",
    )
    validate_task_context(request, recipe)
    require(
        value.get("model_revision") == "composite/" + value["recipe"]["sha256"],
        "Composite revision does not bind recipe",
    )
    node_refs = value.get("nodes", [])
    require(
        1 < len(node_refs) <= 64
        and len({r["sha256"] for r in node_refs}) == len(node_refs),
        "Missing/reused graph nodes",
    )
    nodes = [artifact(r) for r in node_refs]
    by_id = {node.get("id"): node for node in nodes}
    require(
        None not in by_id and len(by_id) == len(nodes),
        "Duplicate/missing graph node IDs",
    )
    visited: set[str] = set()
    active: set[str] = set()

    def walk(node_id: str) -> None:
        require(node_id in by_id, "Missing graph child")
        require(node_id not in active, "Composite graph cycle")
        if node_id in visited:
            return
        active.add(node_id)
        for child in by_id[node_id].get("depends_on", []):
            walk(child)
        active.remove(node_id)
        visited.add(node_id)

    terminal_id = value.get("terminal_node")
    require(isinstance(terminal_id, str), "Terminal node missing")
    walk(terminal_id)
    require(visited == set(by_id), "Graph contains unconsumed/unreachable component")
    require(
        recipe.get("node_kinds") == {k: v.get("kind") for k, v in by_id.items()},
        "Graph differs from frozen recipe",
    )
    profiles = recipe.get("component_profiles", {})
    require(
        set(profiles) == {node["kind"] for node in nodes},
        "Recipe component profiles are incomplete",
    )
    for node in nodes:
        execution = artifact(node.get("execution"))
        profile = profiles[node["kind"]]
        if node["kind"] == "local_audio_ai":
            _verify_audio_recipe(execution, profile)
        elif node["kind"] == "terminal_ai":
            require(
                profile.get("model_revision") == execution.get("model_revision")
                and profile.get("transport_schema") == "captured-ai-exchange/v1",
                "Terminal model/transport differs from calibrated composite recipe",
            )
            terminal_call = artifact(execution.get("request"))
            if terminal_call.get("transport_kind") == "codex_cli_direct_images/v1":
                from .codex_cli_transport import cli_profile

                require(
                    profile == cli_profile(terminal_call),
                    "CLI runtime/renderer differs from calibrated recipe",
                )
        elif node["kind"] == "pcm_analysis":
            require(
                profile.get("implementation_sha256") == sha256(Path(__file__)),
                "Physical measurement code differs from calibrated recipe",
            )
    consumed_refs = [value["request"], value["recipe"], *node_refs]

    def collect(obj: Any) -> None:
        if isinstance(obj, dict):
            if "path" in obj and "sha256" in obj:
                consumed_refs.append(obj)
            else:
                for sub in obj.values():
                    collect(sub)
        elif isinstance(obj, list):
            for sub in obj:
                collect(sub)

    collect(request)
    for node in nodes:
        collect(node)
        execution = artifact(node.get("execution"))
        collect(execution)
        if execution.get("request"):
            collect(artifact(execution["request"]))
    forbidden = {r["sha256"] for r in forbidden_artifacts or []}
    require(
        not (forbidden & {r["sha256"] for r in consumed_refs}),
        "Expected challenge artifact leaked into actual inputs",
    )
    children: dict[str, VerifiedNode] = {}
    for node in nodes:
        if node["id"] == terminal_id:
            require(node.get("kind") == "terminal_ai", "Terminal is not an AI reviewer")
        elif node.get("kind") == "local_audio_ai":
            children[node["id"]] = _audio_node(node, request, root_pcm)
        elif node.get("kind") == "pcm_analysis":
            children[node["id"]] = _physical_node(node, request, root_pcm)
        else:
            require(False, "Unsupported composite component/precision producer")
    audio = [node for node in children.values() if node.kind == "local_audio_ai"]
    require(audio, "Composite lacks actual audio-consuming semantic AI")
    spans = sorted(node.sample_range for node in audio if node.sample_range is not None)
    cursor = 0
    for start, end in spans:
        require(start <= cursor, "Audio semantic coverage has a missing chunk")
        cursor = max(cursor, end)
    require(
        cursor == root_pcm["count"],
        "Audio semantic coverage does not reach complete source",
    )
    require(
        len({node.run_id for node in children.values()}) == len(children),
        "Component execution reused across graph roles",
    )
    terminal_execution, response = _terminal(by_id[terminal_id], request, children)
    require(
        terminal_execution.get("run_id")
        not in {node.run_id for node in children.values()},
        "Terminal reused an audio execution",
    )
    require(
        value.get("run_id")
        and value.get("response") == terminal_execution.get("response"),
        "Composite response was rewritten after terminal AI",
    )
    require(
        utc(value.get("started_at")) <= utc(terminal_execution["started_at"])
        and utc(value.get("finished_at")) >= utc(terminal_execution["finished_at"]),
        "Composite time range excludes terminal execution",
    )
    require(
        all(
            utc(value["started_at"]) <= child.started_at
            and utc(value["finished_at"]) >= child.finished_at
            for child in children.values()
        ),
        "Composite time range excludes a child execution",
    )
    # Dense frame supply alone cannot establish calibrated measurement uncertainty.
    require(
        not precision_required,
        "Composite precision adapter/calibration is not implemented; confidence cannot supply uncertainty",
    )
    require(
        response.get("dense_motion_and_lip_verified") is False,
        "Composite semantic proof cannot claim precision approval",
    )
    return {
        "schema_version": "execution-receipt/v1",
        "completed": True,
        "exit_code": 0,
        "run_id": value["run_id"],
        "model_revision": value["model_revision"],
        "provider_request_id": terminal_execution["provider_request_id"],
        "request": value["request"],
        "response": value["response"],
        "dependencies": request["dependencies"],
        "prompt": terminal_execution["prompt"],
        "prompt_sha256": terminal_execution["prompt_sha256"],
        "log": terminal_execution["exchange"],
        "started_at": value["started_at"],
        "finished_at": value["finished_at"],
        "_composite_verified": True,
        "_composite_precision_verified": False,
        "_composite_receipt": ref,
        "component_outputs": {k: v.output for k, v in children.items()},
        "normalization": {
            "executor": "talkcut-composite-validator",
            "exit_code_scope": "adapter_validation_only",
            "provider_process_exit_code": None,
            "provider_finish_reason": None,
            "terminal_model_scope": "requested_model_from_turn_context",
        },
        "provenance_limitations": "Captured bytes and audited adapters do not cryptographically authenticate external execution; independent audit remains required.",
    }


def adapt_native_execution(
    original_ref: dict[str, Any],
    dependencies: dict[str, Any],
    output_dir: Path,
    *,
    run_summary_ref: dict[str, Any] | None = None,
    registration_ref: dict[str, Any] | None = None,
    composite_request_ref: dict[str, Any] | None = None,
    recipe_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    require(
        registration_ref is not None
        and composite_request_ref is not None
        and recipe_ref is not None,
        "Native adaptation requires durable request-scoped independent registration",
    )
    assert (
        registration_ref is not None
        and composite_request_ref is not None
        and recipe_ref is not None
    )
    with registration_scope(
        registration_ref, composite_request_ref, recipe_ref, dependencies
    ):
        return _adapt_native_execution(
            original_ref, dependencies, output_dir, run_summary_ref=run_summary_ref
        )


def _adapt_native_execution(
    original_ref: dict[str, Any],
    dependencies: dict[str, Any],
    output_dir: Path,
    *,
    run_summary_ref: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive a typed leaf from fresh instrumented raw execution, then revalidate.

    Required dependencies must already exist in the actual pre-execution request.
    This intentionally cannot upgrade any historical control without that input.
    No inference runs and no semantic result is assigned by this adapter.
    """
    from .project import artifact_ref

    original = artifact(original_ref)
    original_request = artifact(original.get("request"))
    require(
        original_request.get("dependencies") == dependencies,
        "Actual native request did not capture this dependency scope before execution",
    )
    require(run_summary_ref is not None, "Final native run summary is required")
    from .native_provenance import verify_native_bundle

    verified = verify_native_bundle(
        original_ref,
        run_summary_ref,
        dependencies,
        native_policy(original_request.get("runtime", {}).get("sha256", "")),
    )
    process = verified["process"]
    build = artifact(original_request.get("build_receipt"))
    output_dir.mkdir(parents=True, exist_ok=False)
    call = {
        "schema_version": "native-audio-request/v1",
        "dependencies": dependencies,
        "input_modalities": ["audio"],
        "input_artifacts": [original_request["input"], original_request["prompt"]],
        "audio": original_request["input"],
        "prompt": original_request["prompt"],
        "models": original_request["model_refs"],
        "argv": original_request["argv"],
        "trace_nonce": original_request["environment_overrides"][
            "TALKCUT_INTAKE_NONCE"
        ],
    }
    call_path = output_dir / "native-request.json"
    call_path.write_text(json.dumps(call, ensure_ascii=False, indent=2) + "\n")
    execution = {
        "schema_version": "native-audio-execution/v1",
        "dependencies": dependencies,
        "completed": original.get("completed") is True,
        "run_id": original["run_id"],
        "native_execution": original_ref,
        "native_run": run_summary_ref,
        "request": artifact_ref(call_path),
        "process": original["supervisor_execution"],
        "runtime": original_request["runtime"],
        "source_manifest": build["source_before"],
        "libraries": original_request["runtime_libraries"],
        **{
            k: process[k]
            for k in (
                "started_at",
                "finished_at",
                "exit_code",
                "stdout",
                "stderr",
            )
        },
    }
    path = output_dir / "native-execution.json"
    path.write_text(json.dumps(execution, ensure_ascii=False, indent=2) + "\n")
    ref = artifact_ref(path)
    pcm = pcm16(call["audio"])
    node = {
        "id": "native-audio",
        "kind": "local_audio_ai",
        "depends_on": [],
        "sample_range": [0, pcm["count"]],
        "execution": ref,
    }
    _audio_node(node, {"dependencies": dependencies}, pcm)
    return ref
