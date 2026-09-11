"""Synthetic graph/parser controls; never an executed AV capability or review.

Only the audio-AI leaf is stubbed in graph controls. Actual FFmpeg clip/frame/
PCM comparisons and byte-bearing terminal exchange parsing run unchanged.
The production native-build allowlist remains empty and rejects legacy/fake AI.
"""

import base64
import copy
import json
import subprocess
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

import pytest

from talkcut import codex_transport as ct
from talkcut import composite_review as cr
from talkcut.project import TalkCutError, artifact_ref, sha256


def write(directory, name, value):
    path = directory / name
    path.write_text(json.dumps(value, sort_keys=True))
    return artifact_ref(path)


@pytest.fixture(scope="module")
def media(tmp_path_factory):
    d = tmp_path_factory.mktemp("actual-composite-media")
    clip = d / "clip.mkv"
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=64x48:rate=25:duration=1",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=731:sample_rate=16000:duration=1",
            "-c:v",
            "ffv1",
            "-c:a",
            "pcm_s16le",
            str(clip),
        ],
        check=True,
    )
    audio = d / "audio.wav"
    subprocess.run(
        [
            "ffmpeg",
            "-nostdin",
            "-v",
            "error",
            "-i",
            str(clip),
            "-map",
            "0:a:0",
            "-ac",
            "1",
            "-ar",
            "16000",
            "-c:a",
            "pcm_s16le",
            str(audio),
        ],
        check=True,
    )
    frames = []
    for index in (0, 12, 24):
        p = d / f"frame{index}.png"
        subprocess.run(
            [
                "ffmpeg",
                "-nostdin",
                "-v",
                "error",
                "-i",
                str(clip),
                "-vf",
                f"select=eq(n\\,{index})",
                "-fps_mode",
                "passthrough",
                "-frames:v",
                "1",
                str(p),
            ],
            check=True,
        )
        frames.append(
            {
                "artifact": artifact_ref(p),
                "frame_index": index,
                "timestamp": str(index / 25),
                "duration": "1/25",
                "mime_type": "image/png",
            }
        )
    return artifact_ref(clip), artifact_ref(audio), frames


class Graph:
    def __init__(self, path, media):
        self.path = path
        clip, audio, frames = media
        self.deps = {
            "source_hashes": {"screen": clip["sha256"]},
            "contract_hash": "c" * 64,
            "code_tree_hash": "d" * 64,
            "output_hash": clip["sha256"],
            "timeline_hash": "e" * 64,
        }
        self.request = {
            "schema_version": "composite-review-request/v1",
            "dependencies": self.deps,
            "audio": audio,
            "audio_interval": ["0", "1"],
            "frames": copy.deepcopy(frames),
            "input_audio_hash": audio["sha256"],
            "input_frame_hashes": [f["artifact"]["sha256"] for f in frames],
            "input_frame_timestamps": [f["timestamp"] for f in frames],
            "media_clip": clip,
            "input_clip_hashes": [clip["sha256"]],
        }
        self.prompt = self.path / "prompt.txt"
        self.prompt.write_text(
            "Inspect actual ordered frames and raw audio tool evidence. Report limitations and disagreements."
        )
        self.audio_output = self.path / "audio-raw.txt"
        self.audio_output.write_text(
            "Synthetic placeholder only: no audio model execution occurred in this parser test."
        )
        self.nodes = {
            "audio": {
                "id": "audio",
                "kind": "local_audio_ai",
                "depends_on": [],
                "sample_range": [0, 16000],
            },
            "physical": {"id": "physical", "kind": "pcm_analysis", "depends_on": []},
            "terminal": {
                "id": "terminal",
                "kind": "terminal_ai",
                "depends_on": ["audio", "physical"],
            },
        }
        self.physical = cr.physical_observations(audio)
        self.response = {
            "verdict": "UNVERIFIED",
            "reason": "Synthetic parser fixture only. No actual AI capability has been executed or approved.",
            "dense_motion_and_lip_verified": False,
            "modality_attribution": {
                "audio_semantics": ["audio"],
                "video": "terminal",
                "physical_signal": ["physical"],
            },
        }
        self.terminal_call = {
            "schema_version": "terminal-ai-request/v1",
            "dependencies": self.deps,
            "input_modalities": ["image_sequence", "tool_results", "text"],
            "prompt": artifact_ref(self.prompt),
        }
        self.exchange = {
            "schema_version": "captured-ai-exchange/v1",
            "request": {
                "request_id": "codex-session:parser-session/turn:parser-turn/call:parser-exchange",
                "model_revision": "synthetic-parser-fixture",
            },
            "response": {
                "request_id": "codex-session:parser-session/turn:parser-turn/call:parser-exchange",
                "completed": True,
                "completion_basis": "actual_assistant_final",
            },
        }
        self.exchange["observed_execution"] = {
            "session_id": "parser-session",
            "turn_id": "parser-turn",
            "call_id": "parser-exchange",
            "started_at": "2026-09-07T00:00:02+00:00",
            "finished_at": "2026-09-07T00:00:03+00:00",
            "model_identifier_scope": "requested_model_from_turn_context",
            "provider_model_snapshot": None,
            "provider_finish_reason": None,
            "provider_process_exit_code": None,
        }
        self.top_extra = {}
        self.mutate_exchange = lambda value: None
        self.mutate_call = lambda value: None
        self.mutate_execution = lambda value: None
        self.mutate_session = lambda value: None
        self.mutate_capture = lambda value: None

    def save(self):
        phy_ref = write(self.path, "physical-result.json", self.physical)
        outputs = {"audio": artifact_ref(self.audio_output), "physical": phy_ref}
        self.response["component_outputs"] = {
            n: r["sha256"] for n, r in outputs.items()
        }
        response_ref = write(self.path, "response.json", self.response)
        base = {
            "completed": True,
            "exit_code": 0,
            "dependencies": self.deps,
            "started_at": "2026-09-07T00:00:00+00:00",
            "finished_at": "2026-09-07T00:00:01+00:00",
        }
        audio_exec = {
            **base,
            "schema_version": "legacy-synthetic-placeholder/v1",
            "run_id": "audio-run",
            "stdout": outputs["audio"],
        }
        audio_exec["runtime"] = outputs["audio"]
        audio_exec["source_manifest"] = outputs["physical"]
        self.nodes["audio"]["execution"] = write(
            self.path, "audio-execution.json", audio_exec
        )
        physical_exec = {
            **base,
            "schema_version": "physical-pcm-execution/v1",
            "run_id": "pcm-run",
            "audio": self.request["audio"],
            "result": phy_ref,
            "claim_scope": "physical_signal_only",
        }
        self.nodes["physical"]["execution"] = write(
            self.path, "pcm-execution.json", physical_exec
        )
        call = copy.deepcopy(self.terminal_call)
        call["frames"] = self.request["frames"]
        call["tool_outputs"] = [
            outputs[n] for n in self.nodes["terminal"]["depends_on"] if n in outputs
        ]
        self.mutate_call(call)
        terminal_call_ref = write(self.path, "terminal-request.json", call)
        exchange = copy.deepcopy(self.exchange)
        content = [{"type": "text", "text": self.prompt.read_text()}]
        for row in self.request["frames"]:
            content.append(
                {
                    "type": "image",
                    "mime_type": row["mime_type"],
                    "data_base64": base64.b64encode(
                        Path(row["artifact"]["path"]).read_bytes()
                    ).decode(),
                    "timestamp": row["timestamp"],
                }
            )
        for n in self.nodes["terminal"]["depends_on"]:
            if n in outputs:
                content.append(
                    {
                        "type": "tool_result",
                        "node_id": n,
                        "artifact_sha256": outputs[n]["sha256"],
                        "text": Path(outputs[n]["path"]).read_text(),
                    }
                )
        exchange["request"]["content"] = content
        exchange["response"]["raw_text"] = Path(response_ref["path"]).read_text()
        session_code = ct.terminal_tool_code(
            self.prompt.read_text(),
            self.request["frames"],
            [
                {
                    "node_id": n,
                    "artifact_sha256": outputs[n]["sha256"],
                    "text": Path(outputs[n]["path"]).read_text(),
                }
                for n in self.nodes["terminal"]["depends_on"]
                if n in outputs
            ],
        )
        parts = [
            {
                "type": "input_text",
                "text": "Script completed\nWall time 0.1 seconds\nOutput:\n",
            }
        ]
        for item in content:
            if item["type"] == "image":
                import hashlib

                data = base64.b64decode(item["data_base64"])
                meta = ct.packet(
                    "frame_metadata",
                    sha256=hashlib.sha256(data).hexdigest(),
                    timestamp=item["timestamp"],
                    mime_type=item["mime_type"],
                )
                parts += [
                    {"type": "input_text", "text": json.dumps(meta)},
                    {
                        "type": "input_image",
                        "image_url": "data:"
                        + item["mime_type"]
                        + ";base64,"
                        + item["data_base64"],
                    },
                ]
            else:
                value = (
                    ct.packet("prompt", text=item["text"])
                    if item["type"] == "text"
                    else ct.packet(
                        "tool_result", **{k: v for k, v in item.items() if k != "type"}
                    )
                )
                parts.append({"type": "input_text", "text": json.dumps(value)})
        rows = [
            {
                "type": "turn_context",
                "payload": {
                    "turn_id": "parser-turn",
                    "model": "synthetic-parser-fixture",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "parser-exchange",
                    "name": "exec",
                    "input": session_code,
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "parser-exchange",
                    "output": parts,
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "final-parser",
                    "role": "assistant",
                    "phase": "final",
                    "content": [
                        {
                            "type": "output_text",
                            "text": exchange["response"]["raw_text"],
                        }
                    ],
                },
            },
        ]
        for row in rows:
            row["timestamp"] = "2026-09-07T00:00:02+00:00"
        rows[-1]["timestamp"] = "2026-09-07T00:00:03+00:00"
        self.mutate_session(rows)
        session = self.path / "rollout-parser-session.jsonl"
        session.write_text("".join(json.dumps(r) + "\n" for r in rows))
        saved = self.path / "session-slice.jsonl"
        saved.write_bytes(session.read_bytes())
        capture = {
            "schema_version": "codex-session-slice/v1",
            "session_id": "parser-session",
            "start_byte": 0,
            "end_byte": session.stat().st_size,
            "slice": artifact_ref(saved),
            "turn_id": "parser-turn",
            "tool_call_id": "parser-exchange",
            "response_item_id": "final-parser",
        }
        self.mutate_capture(capture)
        capture_ref = write(self.path, "session-capture.json", capture)
        self.mutate_exchange(exchange)
        exchange_ref = write(self.path, "exchange.json", exchange)
        terminal_exec = {
            **base,
            "schema_version": "terminal-ai-execution/v1",
            "run_id": "terminal-run",
            "started_at": "2026-09-07T00:00:02+00:00",
            "finished_at": "2026-09-07T00:00:03+00:00",
            "request": terminal_call_ref,
            "response": response_ref,
            "exchange": exchange_ref,
            "session_capture": capture_ref,
            "prompt": artifact_ref(self.prompt),
            "prompt_sha256": artifact_ref(self.prompt)["sha256"],
            "provider_request_id": "codex-session:parser-session/turn:parser-turn/call:parser-exchange",
            "completion_basis": "actual_assistant_final",
            "model_revision": "synthetic-parser-fixture",
        }
        self.mutate_execution(terminal_exec)
        self.nodes["terminal"]["execution"] = write(
            self.path, "terminal-execution.json", terminal_exec
        )
        node_refs = [
            write(self.path, n + "-node.json", v) for n, v in self.nodes.items()
        ]
        recipe = write(
            self.path,
            "recipe.json",
            {
                "schema_version": "composite-review-recipe/v1",
                "node_kinds": {n: v["kind"] for n, v in self.nodes.items()},
                "component_profiles": {
                    "local_audio_ai": {
                        "runtime_sha256": outputs["audio"]["sha256"],
                        "source_manifest_sha256": outputs["physical"]["sha256"],
                    },
                    "pcm_analysis": {
                        "implementation_sha256": sha256(Path(cr.__file__))
                    },
                    "terminal_ai": {
                        "model_revision": "synthetic-parser-fixture",
                        "transport_schema": "captured-ai-exchange/v1",
                    },
                },
            },
        )
        request = write(self.path, "request.json", self.request)
        top = {
            "schema_version": "composite-review-receipt/v1",
            "model_revision": "composite/" + recipe["sha256"],
            "recipe": recipe,
            "request": request,
            "nodes": node_refs,
            "terminal_node": "terminal",
            "response": response_ref,
            "dependencies": self.deps,
            "run_id": "composite-parser-control",
            "started_at": "2026-09-07T00:00:00+00:00",
            "finished_at": "2026-09-07T00:00:04+00:00",
            **self.top_extra,
        }
        return write(self.path, "top.json", top)


@pytest.fixture
def graph(tmp_path, media, monkeypatch):
    g = Graph(tmp_path, media)
    monkeypatch.setattr(
        ct,
        "_registered_session",
        lambda _sid, _ref: str(tmp_path / "rollout-parser-session.jsonl"),
    )

    monkeypatch.setattr(cr, "registration_scope", lambda *_args: nullcontext())
    monkeypatch.setattr(
        cr,
        "_verify_audio_recipe",
        lambda execution, profile: cr.require(
            profile
            == {
                "runtime_sha256": execution["runtime"]["sha256"],
                "source_manifest_sha256": execution["source_manifest"]["sha256"],
            },
            "Audio execution differs from calibrated composite recipe",
        ),
    )

    def isolated_audio_leaf(node, request, pcm):
        # Explicitly isolated graph boundary; production adapter rejects this fixture.
        e = cr.artifact(node["execution"])
        return cr.VerifiedNode(
            node["id"],
            node["kind"],
            e["stdout"],
            cr.artifact(e["stdout"], raw=True).decode(),
            request["audio"]["sha256"],
            tuple(node["sample_range"]),
            e["run_id"],
            datetime(2026, 9, 7, tzinfo=UTC),
            datetime(2026, 9, 7, 0, 0, 1, tzinfo=UTC),
        )

    monkeypatch.setattr(cr, "_audio_node", isolated_audio_leaf)
    return g


def test_actual_media_and_transport_parser_control_never_claims_capability(graph):
    result = cr.verify_composite_receipt(graph.save())
    assert result["_composite_verified"]
    assert result["_composite_precision_verified"] is False
    assert cr.artifact(result["response"])["verdict"] == "UNVERIFIED"


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("cycle", "cycle"),
        ("missing_child", "Missing graph child"),
        ("unused_child", "omits a component|unreachable"),
        ("missing_audio_chunk", "missing chunk"),
        ("short_audio", "complete source"),
        ("stale_source", "Stale"),
        ("frame_relabel", "timestamp was relabeled"),
        ("frame_substitution", "frame pixels"),
        ("duration_inflation", "duration was inflated"),
        ("terminal_text_only", "own modalities"),
        ("terminal_spoof_audio", "spoofed audio"),
        ("transport_missing_frame", "actual Codex session"),
        ("transport_changed_frame", "actual Codex session"),
        ("transport_changed_tool", "actual Codex session"),
        ("terminal_before_child", "before its evidence"),
        ("rewritten_response", "differs from actual"),
        ("truncated_response", "actual Codex session"),
        ("physical_values_copied", "not measured"),
        ("expected_values", "Expected answer"),
        ("precision_confidence", "semantic proof cannot claim precision"),
    ],
)
def test_adversarial_graph_mutations_reject_at_the_specific_gate(
    graph, mutation, reason
):
    if mutation == "cycle":
        graph.nodes["audio"]["depends_on"] = ["terminal"]
    elif mutation == "missing_child":
        graph.nodes["terminal"]["depends_on"].append("absent")
    elif mutation == "unused_child":
        graph.nodes["terminal"]["depends_on"] = ["audio"]
    elif mutation == "missing_audio_chunk":
        graph.nodes["audio"]["sample_range"] = [1, 16000]
    elif mutation == "short_audio":
        graph.nodes["audio"]["sample_range"] = [0, 15999]
    elif mutation == "stale_source":
        graph.request["audio"] = {**graph.request["audio"], "sha256": "0" * 64}
    elif mutation == "frame_relabel":
        graph.request["frames"][1]["timestamp"] = "0.49"
        graph.request["input_frame_timestamps"][1] = "0.49"
    elif mutation == "frame_substitution":
        graph.request["frames"][1]["artifact"] = graph.request["frames"][0]["artifact"]
        graph.request["input_frame_hashes"][1] = graph.request["input_frame_hashes"][0]
    elif mutation == "duration_inflation":
        graph.request["frames"][-1]["duration"] = "1"
    elif mutation == "terminal_text_only":
        graph.mutate_call = lambda v: v.update(input_modalities=["text"])
    elif mutation == "terminal_spoof_audio":
        graph.mutate_call = lambda v: v.update(
            input_audio_hash=graph.request["input_audio_hash"]
        )
    elif mutation == "transport_missing_frame":
        graph.mutate_exchange = lambda v: v["request"]["content"].pop(1)
    elif mutation == "transport_changed_frame":
        graph.mutate_exchange = lambda v: v["request"]["content"][1].update(
            data_base64=base64.b64encode(b"fake image").decode()
        )
    elif mutation == "transport_changed_tool":
        graph.mutate_exchange = lambda v: v["request"]["content"][-1].update(
            text="expected answer inserted"
        )
    elif mutation == "terminal_before_child":
        graph.mutate_execution = lambda v: v.update(
            started_at="2026-09-06T23:59:00+00:00"
        )
    elif mutation == "rewritten_response":
        graph.mutate_exchange = lambda v: v["response"].update(
            raw_text='{"verdict":"PASS"}'
        )
    elif mutation == "truncated_response":
        graph.mutate_exchange = lambda v: v["response"].update(finish_reason="length")
    elif mutation == "physical_values_copied":
        graph.physical["sample_count"] += 1
    elif mutation == "expected_values":
        graph.request["expected_events"] = ["an injected expected answer"]
    elif mutation == "precision_confidence":
        graph.response.update(
            dense_motion_and_lip_verified=True, uncertainty_ms=0.1, confidence=0.99
        )
    with pytest.raises(TalkCutError, match=reason):
        cr.verify_composite_receipt(graph.save())


def test_dense_inputs_do_not_turn_confidence_into_precision(graph):
    with pytest.raises(TalkCutError, match="precision adapter"):
        cr.verify_composite_receipt(graph.save(), precision_required=True)


def test_expected_challenge_artifact_in_terminal_inputs_rejected(graph):
    expected = write(
        graph.path,
        "expected.json",
        {"audio_events": ["answer"], "video_events": ["answer"]},
    )
    graph.mutate_call = lambda v: v.update(undeclared_expected_artifact=expected)
    with pytest.raises(TalkCutError, match="Expected challenge artifact leaked"):
        cr.verify_composite_receipt(graph.save(), forbidden_artifacts=[expected])


def test_legacy_raw_audio_cannot_be_retroactively_declared_native(
    tmp_path, media, monkeypatch
):
    g = Graph(tmp_path, media)
    monkeypatch.setattr(
        ct,
        "_registered_session",
        lambda _sid, _ref: str(tmp_path / "rollout-parser-session.jsonl"),
    )
    g.save()
    with pytest.raises(TalkCutError, match="Legacy audio receipt"):
        cr._audio_node(g.nodes["audio"], g.request, cr.pcm16(g.request["audio"]))


def test_unsupported_native_build_cannot_certify_a_fake_trace(
    tmp_path, media, monkeypatch
):
    g = Graph(tmp_path, media)
    monkeypatch.setattr(
        ct,
        "_registered_session",
        lambda _sid, _ref: str(tmp_path / "rollout-parser-session.jsonl"),
    )
    g.save()
    e = cr.artifact(g.nodes["audio"]["execution"])
    e["schema_version"] = "native-audio-execution/v1"
    e["runtime"] = artifact_ref(g.audio_output)
    e["stderr"] = artifact_ref(g.audio_output)
    g.nodes["audio"]["execution"] = write(tmp_path, "claimed-native.json", e)
    with pytest.raises(TalkCutError, match="independently audited registration"):
        cr._audio_node(g.nodes["audio"], g.request, cr.pcm16(g.request["audio"]))


def test_renamed_generic_receipt_cannot_skip_composite_validation(tmp_path):
    from talkcut.review import _receipt

    fake = write(
        tmp_path,
        "fake.json",
        {"schema_version": "execution-receipt/v1", "model_revision": "composite/fake"},
    )
    with pytest.raises(TalkCutError, match="cannot bypass"):
        _receipt(fake)


def native_trace_control(media, tmp_path):
    import struct

    _, audio, _ = media
    prompt = tmp_path / "native-prompt.txt"
    prompt.write_text("Inspect this synthetic parser fixture.")
    call = {
        "audio": audio,
        "prompt": artifact_ref(prompt),
        "argv": [
            "/synthetic-native",
            "--audio",
            audio["path"],
            "-p",
            prompt.read_text(),
        ],
        "trace_nonce": "synthetic-parser-nonce",
    }
    pcm = cr.pcm16(audio)
    user = "<__media__>" + prompt.read_text()
    formatted = "<|im_start|>user\n" + user + "<|im_end|>\n<|im_start|>assistant\n"
    emitted = "Synthetic parser response, never capability evidence."
    context = [
        {
            "kind": "text",
            "start": 0,
            "end": 4,
            "token_ids": [151644, 872, 198, 151669],
            "chunk_index": 0,
        },
        {"kind": "audio", "start": 4, "end": 17, "chunk_index": 0},
        {
            "kind": "text",
            "start": 17,
            "end": 18,
            "token_ids": [151670],
            "chunk_index": 2,
        },
    ]
    for i, c in enumerate(context):
        c.update(
            global_chunk_index=i,
            n_positions=c["end"] - c["start"],
            n_tokens=c["end"] - c["start"],
            media_id=audio["sha256"] if c["kind"] == "audio" else "",
        )
        if "token_ids" in c:
            c["token_ids_sha256"] = cr.digest(
                b"".join(struct.pack("<i", t) for t in c["token_ids"])
            )

    def evaluated(i):
        c = context[i]
        return {
            "event": c["kind"] + "_chunk_evaluated",
            "media_id": c["media_id"],
            "global_chunk_index": i,
            "chunk_index": c["chunk_index"],
            "context_start": c["start"],
            "context_end": c["end"],
            "return_status": 0,
        }

    events = [
        {
            "event": "invocation",
            "argv": call["argv"],
            "cli_prompt_utf8": prompt.read_text(),
            "cli_prompt_sha256": sha256(prompt),
        },
        {
            "event": "file_loaded",
            "sha256": audio["sha256"],
            "path": audio["path"],
            "bytes": Path(audio["path"]).stat().st_size,
            "placeholder": False,
        },
        {
            "event": "audio_decoded",
            "float_pcm_sha256": pcm["float_sha256"],
            "sample_count": pcm["count"],
            "sample_rate": 16000,
            "bytes": pcm["count"] * 4,
            "channels": 1,
            "sample_format": "native_float32",
        },
        {
            "event": "audio_preprocessed",
            "float_pcm_sha256": pcm["float_sha256"],
            "sample_count": pcm["count"],
            "sample_rate": 16000,
            "placeholder": False,
            "chunks": [
                {
                    "index": 0,
                    "mel_frames": 100,
                    "mel_original_frames": 100,
                    "mel_bins": 128,
                    "mel_bytes": 51200,
                    "mel_sha256": "a" * 64,
                    "placeholder": False,
                    "expected_embedding_tokens": 13,
                }
            ],
        },
        evaluated(0),
        {
            "event": "audio_encoded",
            "chunk_index": 0,
            "global_chunk_index": 1,
            "embedding_tokens": 13,
            "embedding_dimension": 2048,
            "embedding_bytes": 106496,
            "embedding_sha256": "b" * 64,
            "return_status": 0,
        },
        evaluated(1),
        evaluated(2),
        {
            "event": "user_prompt_evaluated",
            "role": "user",
            "prompt_sha256": cr.digest(user.encode()),
            "prompt_utf8": user,
            "posttemplate_sha256": cr.digest(formatted.encode()),
            "posttemplate_utf8": formatted,
            "all_input_chunks_evaluated": True,
            "context_chunks": context,
            "context_end": 18,
            "input_chunk_count": 3,
        },
        {
            "event": "generation_finished",
            "stop_reason": "eog",
            "emitted_text_utf8": emitted,
            "emitted_text_sha256": cr.digest(emitted.encode()),
            "emitted_text_bytes": len(emitted.encode()),
            "token_ids": [123, 151645],
            "tokens_decoded": 1,
            "n_predict": 256,
            "context_end": 19,
        },
    ]
    for i, e in enumerate(events):
        e.update(
            schema="talkcut-native-intake/v1",
            sequence=i,
            run_nonce=call["trace_nonce"],
            monotonic_ms=i,
        )
        if e["event"] in ("user_prompt_evaluated", "generation_finished"):
            e["media_ids"] = [audio["sha256"]]
        elif e["event"] not in ("invocation", "text_chunk_evaluated"):
            e["media_id"] = audio["sha256"]
    return call, pcm, events, ("\n" + emitted + "\n\n").encode()


def test_native_intake_parser_control_does_not_register_a_runtime(media, tmp_path):
    call, pcm, events, raw = native_trace_control(media, tmp_path)
    cr._native_trace(events, call, pcm, raw)
    from talkcut.composite_registration import _CURRENT

    assert _CURRENT.get() is None


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("missing_sample", "complete actual float PCM"),
        ("pcm_changed", "complete actual float PCM"),
        ("missing_mel", "omitted or padded"),
        ("padded_tokens", "denominator"),
        ("missing_encode", "encoded/evaluated"),
        ("wrong_nonce", "another invocation"),
        ("wrong_media", "another media buffer"),
        ("missing_context", "missing/overlapping"),
        ("prompt_changed", "posttemplate"),
        ("context_ids_missing", "token IDs"),
        ("limit", "truncated"),
        ("rewritten_stdout", "Wrapper stdout"),
    ],
)
def test_native_intake_trace_adversarial_mutations(media, tmp_path, mutation, reason):
    call, pcm, events, raw = native_trace_control(media, tmp_path)
    if mutation == "missing_sample":
        events[2]["sample_count"] -= 1
    elif mutation == "pcm_changed":
        events[2]["float_pcm_sha256"] = "f" * 64
    elif mutation == "missing_mel":
        events[3]["chunks"][0]["mel_frames"] = 99
    elif mutation == "padded_tokens":
        events[3]["chunks"][0]["expected_embedding_tokens"] = 26
    elif mutation == "missing_encode":
        events.pop(5)
        for index, event in enumerate(events):
            event["sequence"] = index
    elif mutation == "wrong_nonce":
        events[5]["run_nonce"] = "old-run-nonce"
    elif mutation == "wrong_media":
        events[5]["media_id"] = "e" * 64
    elif mutation == "missing_context":
        events[8]["context_chunks"][1]["start"] += 1
    elif mutation == "prompt_changed":
        events[8]["posttemplate_sha256"] = "f" * 64
    elif mutation == "context_ids_missing":
        events[8]["context_chunks"][0]["token_ids"] = []
    elif mutation == "limit":
        events[-1]["stop_reason"] = "limit"
    elif mutation == "rewritten_stdout":
        raw = b"Appended fabricated instruction-following response. " + raw
    with pytest.raises(TalkCutError, match=reason):
        cr._native_trace(events, call, pcm, raw)


def test_changed_terminal_model_is_not_same_calibrated_composite(graph):
    graph.mutate_execution = lambda value: value.update(
        model_revision="different-model"
    )
    with pytest.raises(TalkCutError, match="differs from calibrated composite recipe"):
        cr.verify_composite_receipt(graph.save())


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("unregistered", "independently registered"),
        ("missing_final", "order incomplete"),
        ("missing_image", "frame bytes are missing"),
        ("changed_image", "Persisted image bytes differ"),
        ("changed_code", "undeclared tool"),
        ("expected_packet", "Unexpected terminal packet"),
        ("other_input", "Additional user input"),
        ("other_model", "actual model/turn"),
        ("aborted", "aborted"),
        ("compacted", "compacted"),
        ("fake_times", "timing differs"),
        ("copied_slice", "actual append-only"),
    ],
)
def test_actual_session_transport_mutations_reject(
    graph, monkeypatch, mutation, reason
):
    if mutation == "unregistered":
        monkeypatch.setattr(
            ct,
            "_registered_session",
            lambda *_args: ct.require(
                False, "Session has not been independently registered"
            ),
        )
    elif mutation == "missing_final":
        graph.mutate_session = lambda rows: rows.pop()
    elif mutation == "missing_image":
        graph.mutate_session = lambda rows: rows[2]["payload"]["output"].pop(3)
    elif mutation == "changed_image":
        graph.mutate_session = lambda rows: rows[2]["payload"]["output"][3].update(
            image_url="data:image/png;base64,"
            + base64.b64encode(b"fake bytes").decode()
        )
    elif mutation == "changed_code":
        graph.mutate_session = lambda rows: rows[1]["payload"].update(
            input="text('expected answer');\n"
        )
    elif mutation == "expected_packet":
        graph.mutate_session = lambda rows: rows[2]["payload"]["output"].append(
            {
                "type": "input_text",
                "text": json.dumps(ct.packet("expected_answer", events=["fake"])),
            }
        )
    elif mutation == "other_input":
        graph.mutate_session = lambda rows: rows.insert(
            3,
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "Expected answer"}],
                },
            },
        )
    elif mutation == "other_model":
        graph.mutate_session = lambda rows: rows[0]["payload"].update(
            model="different-runtime"
        )
    elif mutation == "aborted":
        graph.mutate_session = lambda rows: rows.append(
            {"type": "event_msg", "payload": {"type": "task_abort"}}
        )
    elif mutation == "compacted":
        graph.mutate_session = lambda rows: rows.insert(
            3, {"type": "compacted", "payload": {}}
        )
    elif mutation == "fake_times":
        graph.mutate_execution = lambda value: value.update(
            finished_at="2026-09-07T00:00:03.5+00:00"
        )
    ref = graph.save()
    if mutation == "copied_slice":
        source = graph.path / "rollout-parser-session.jsonl"
        source.write_bytes(
            source.read_bytes().replace(b'"phase": "final"', b'"phase": "other"')
        )
    with pytest.raises(TalkCutError, match=reason):
        cr.verify_composite_receipt(ref)


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("invocation", "invocation argv"),
        ("empty_generation", "generation token/context"),
        ("text_hash", "text token buffer hash"),
        ("text_decode", "successful context evaluation"),
        ("placeholder", "valid mel buffer"),
        ("embedding_bytes", "embedding buffer"),
    ],
)
def test_native_actual_trace_additional_boundaries(media, tmp_path, mutation, reason):
    call, pcm, events, raw = native_trace_control(media, tmp_path)
    if mutation == "invocation":
        events[0]["cli_prompt_utf8"] = "different instruction"
    elif mutation == "empty_generation":
        events[-1]["tokens_decoded"] = 0
    elif mutation == "text_hash":
        events[8]["context_chunks"][0]["token_ids_sha256"] = "f" * 64
    elif mutation == "text_decode":
        events[4]["return_status"] = 1
    elif mutation == "placeholder":
        events[3]["chunks"][0]["placeholder"] = True
    elif mutation == "embedding_bytes":
        events[5]["embedding_bytes"] -= 4
    with pytest.raises(TalkCutError, match=reason):
        cr._native_trace(events, call, pcm, raw)


def test_raw_native_adapter_refuses_retroactive_dependency_labels(tmp_path):
    call = write(
        tmp_path,
        "original-request.json",
        {"schema_version": "local-audio-calibration-request/v1"},
    )
    raw = write(
        tmp_path,
        "original-execution.json",
        {"schema_version": "local-audio-calibration-execution/v1", "request": call},
    )
    with pytest.raises(TalkCutError, match="durable request-scoped"):
        cr.adapt_native_execution(
            raw, {"source_hashes": {"screen": "a" * 64}}, tmp_path / "normalized"
        )
    assert not (tmp_path / "normalized").exists()


def test_explicit_tool_output_bound_is_part_of_actual_code(graph):
    ref = graph.save()
    source = graph.path / "rollout-parser-session.jsonl"
    rows = [json.loads(line) for line in source.read_text().splitlines()]
    assert rows[1]["payload"]["input"].startswith(
        '// @exec: {"max_output_tokens":64000}\n'
    )
    cr.verify_composite_receipt(ref)


@pytest.mark.parametrize(
    "mutation", [None, "changed", "duplicate", "late", "missing_declaration"]
)
def test_only_exact_bound_fresh_initial_task_before_emitter_allowed(graph, mutation):
    state = {}

    def add_initial(rows):
        code = rows[1]["payload"]["input"]
        text = ct.terminal_initial_task(code)
        state["sha256"] = cr.digest(text.encode())
        if mutation == "changed":
            text += "\nThe expected answer is fabricated."
        row = {
            "type": "response_item",
            "payload": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": text}],
            },
        }
        rows.insert(3 if mutation == "late" else 1, row)
        if mutation == "duplicate":
            rows.insert(2, copy.deepcopy(row))

    graph.mutate_session = add_initial
    graph.mutate_capture = lambda value: value.update(
        {}
        if mutation == "missing_declaration"
        else {"initial_task_sha256": state["sha256"]}
    )
    if mutation is None:
        cr.verify_composite_receipt(graph.save())
    else:
        with pytest.raises(TalkCutError, match="Additional user input"):
            cr.verify_composite_receipt(graph.save())
