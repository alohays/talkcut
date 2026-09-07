"""Read-only verification of bounded native process and immutable binding records.

These checks never run the registered runner and never infer semantic success.
The native intake trace is validated separately against real PCM and output.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import deque
from pathlib import Path
from typing import Any

from .project import sha256


def _helpers():
    from .composite_review import artifact, require

    return artifact, require


def alias_snapshot(raw: str) -> dict[str, Any]:
    """Follow components in kernel order, including directory aliases before '..'."""
    artifact, require = _helpers()
    require(
        isinstance(raw, str) and raw.startswith("/"),
        "Runtime alias path is not absolute",
    )
    current, pending, seen = Path("/"), deque(raw.split("/")), set()
    hops: list[dict[str, Any]] = []
    while pending:
        require(
            len(hops) <= 40 and len(pending) <= 4096,
            "Runtime alias resolution limit exceeded",
        )
        state = (str(current), tuple(pending))
        require(state not in seen, "Runtime alias cycle")
        seen.add(state)
        part = pending.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        candidate = current / part
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            text = os.readlink(candidate)
            hops.append(
                {
                    "path": str(candidate),
                    "link_text": text,
                    "link_bytes_sha256": hashlib.sha256(os.fsencode(text)).hexdigest(),
                    "lstat_device": info.st_dev,
                    "lstat_inode": info.st_ino,
                }
            )
            if os.path.isabs(text):
                current = Path("/")
            pending.extendleft(reversed(text.split("/")))
        else:
            require(
                not pending or stat.S_ISDIR(info.st_mode),
                "Runtime alias traverses non-directory",
            )
            current = candidate
    before = os.stat(raw)
    final = current.stat()
    require(
        stat.S_ISREG(final.st_mode)
        and (before.st_dev, before.st_ino) == (final.st_dev, final.st_ino),
        "Runtime alias differs from kernel target",
    )
    target = {"path": str(current), "sha256": sha256(current), "bytes": final.st_size}
    artifact(target, verify_only=True)
    for hop in hops:
        info = os.lstat(hop["path"])
        require(
            (info.st_dev, info.st_ino) == (hop["lstat_device"], hop["lstat_inode"])
            and os.readlink(hop["path"]) == hop["link_text"],
            "Runtime alias changed during observation",
        )
    after = os.stat(raw)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(
        identity(before) == identity(after), "Runtime target changed during observation"
    )
    return {"requested_path": raw, "hops": hops, "target": target}


def native_profile(call: dict[str, Any]) -> dict[str, Any]:
    """Normalize only explicit per-run audio/model path and prompt value slots."""
    artifact, require = _helpers()
    argv = call.get("argv")
    require(
        isinstance(argv, list) and all(isinstance(s, str) for s in argv),
        "Native argv is missing",
    )
    assert isinstance(argv, list)
    argv = list(argv)
    require(
        argv[:2] == ["/usr/bin/time", "-l"] and argv[2] == call["runtime"]["path"],
        "Native timing wrapper/runtime differs",
    )
    argv[2] = "<runtime>"
    models = call["model_refs"]
    require(len(models) == 2, "Exactly one model/projector pair is required")
    for flag, expected, replacement in (
        ("-m", models[0]["path"], "<model>"),
        ("--mmproj", models[1]["path"], "<projector>"),
        ("--audio", call["input"]["path"], "<audio>"),
        ("-p", artifact(call["prompt"], raw=True).decode("utf-8"), "<prompt>"),
    ):
        require(
            argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv),
            "Native argument is duplicated/missing",
        )
        index = argv.index(flag) + 1
        require(argv[index] == expected, "Actual selected native input differs")
        argv[index] = replacement
    scope = call.get("native_child_scope")
    require(
        isinstance(scope, dict) and scope.get("task") == "audio_semantics_only",
        "Native actual request does not declare its semantic-only child scope",
    )
    return {
        "runtime_sha256": call["runtime"]["sha256"],
        "runner_sha256": call["runner"]["sha256"],
        "model_sha256s": [row["sha256"] for row in models],
        "prompt_sha256": call["prompt"]["sha256"],
        "argv_template": argv,
        "environment_keys": ["TALKCUT_INTAKE_NONCE"],
        "native_child_scope": scope,
    }


def _supervisor(
    ref: dict[str, Any], request_ref: dict[str, Any], argv: list[str]
) -> dict[str, Any]:
    artifact, require = _helpers()
    value = artifact(ref)
    cleanup = value.get("cleanup", {})
    require(
        value.get("schema_version") == "private-bounded-process-execution/v1"
        and value.get("execution_status") == "COMPLETED"
        and type(value.get("exit_code")) is int
        and value["exit_code"] == 0
        and value.get("termination_reason") is None
        and cleanup.get("status") == "VERIFIED_EMPTY"
        and cleanup.get("remaining_process_group_pids") == []
        and cleanup.get("observation_errors", False) is False
        and value.get("received_signals") == [],
        "Actual native supervisor failed or cleanup is incomplete",
    )
    require(
        value.get("request") == request_ref and value.get("argv") == argv,
        "Native supervisor request/argv differs",
    )
    require(
        type(value.get("pid")) is int
        and value["pid"] > 0
        and value.get("pgid") == value["pid"]
        and value.get("elapsed_seconds", -1) > 0,
        "Native supervisor process identity/timing missing",
    )
    from .composite_review import utc

    require(
        utc(value.get("started_at")) < utc(value.get("finished_at")),
        "Native supervisor timestamps invalid",
    )
    for key in ("stdout", "stderr", "process_samples", "runner_errors"):
        artifact(value.get(key), verify_only=True)
    require(
        not artifact(value["runner_errors"], raw=True).strip(),
        "Native supervisor recorded errors",
    )
    samples = artifact(value["process_samples"], raw=True).splitlines()
    require(
        samples and all(isinstance(json.loads(row), dict) for row in samples),
        "Actual process observations absent",
    )
    return value


def _verify_launch_output(actual_launch, binding, call, dependencies) -> None:
    """Check the output dependency from the original pre-execution launch bytes.

    Legacy audio diagnostics have no output scope and cannot acquire one here.
    Output-bound launches hash the complete actual output using streaming I/O.
    """
    artifact, require = _helpers()
    version = actual_launch.get("schema_version")
    output_bound = version == "private-native-audio-launch/v2"
    require(
        version in {"private-native-audio-launch/v1", "private-native-audio-launch/v2"}
        and set(actual_launch)
        == {
            "schema_version",
            "audio",
            "dependencies",
            "purpose",
            "source_artifacts",
            "contract",
        }
        | ({"output"} if output_bound else set()),
        "Actual native launch schema/fields differ",
    )
    require(
        set(dependencies)
        == {"source_hashes", "contract_hash", "code_tree_hash"}
        | ({"output_hash"} if output_bound else set()),
        "Native launch dependency fields differ",
    )
    if output_bound:
        output = actual_launch["output"]
        require(
            isinstance(output, dict) and isinstance(output.get("path"), str),
            "Native actual output reference is missing",
        )
        path = Path(output["path"])
        require(
            path.is_absolute() and path == path.resolve() and not path.is_symlink(),
            "Native actual output path acquired an alias",
        )
        before = path.stat()
        require(stat.S_ISREG(before.st_mode), "Native actual output is not regular")
        artifact(output, verify_only=True)
        after = path.stat()
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        require(
            identity(before) == identity(after)
            and path == path.resolve()
            and not path.is_symlink(),
            "Native actual output changed while hashing",
        )
        require(
            output == binding.get("output") == call.get("output")
            and output["sha256"] == dependencies["output_hash"],
            "Native actual output dependency differs",
        )
    else:
        require(
            "output" not in binding and "output" not in call,
            "Legacy native launch cannot acquire an output scope",
        )


def verify_native_bundle(
    case_ref: Any,
    run_ref: Any,
    dependencies: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    artifact, require = _helpers()
    case, run = artifact(case_ref), artifact(run_ref)
    require(
        case.get("schema_version") == "private-native-audio-case/v1"
        and run.get("schema_version") == "private-native-audio-run/v1",
        "Legacy native records cannot acquire bounded-run evidence",
    )
    require(
        run.get("status") == "UNVERIFIED_PENDING_SEPARATE_REVIEW"
        and run.get("error") is None
        and run.get("cases") == [case_ref]
        and all(
            v.get("execution_status") == "COMPLETED"
            and v.get("completed") is True
            and v.get("bindings_unchanged") is True
            for v in (case, run)
        ),
        "Final native case/run failed or binding revalidation did not complete",
    )
    require(
        case.get("dependencies") == dependencies
        and case.get("request") == run.get("request")
        and case.get("supervisor_execution") == run.get("execution")
        and case.get("bindings_before") == run.get("bindings_before")
        and case.get("bindings_after") == run.get("bindings_after"),
        "Native final graph differs",
    )
    before, after = (
        artifact(case.get("bindings_before")),
        artifact(case.get("bindings_after")),
    )
    require(
        before == after and set(before) == {"launch", "runtime"},
        "Native final binding snapshots differ",
    )
    launch, runtime = before["launch"], before["runtime"]
    call = artifact(case["request"])
    require(
        call.get("schema_version") == "local-audio-calibration-request/v1"
        and call.get("bindings_before") == case["bindings_before"]
        and call.get("dependencies") == launch.get("dependencies") == dependencies,
        "Native pre-execution request dependencies differ",
    )
    require(
        call.get("input") == case.get("input_after") == launch.get("audio")
        and call.get("source_artifacts") == launch.get("source_artifacts")
        and call.get("contract") == launch.get("contract")
        and call.get("launch_specification") == launch.get("launch")
        and call.get("purpose") == launch.get("purpose"),
        "Native launch inputs were relabelled",
    )
    actual_launch = artifact(launch["launch"])
    require(
        actual_launch.get("schema_version")
        in {"private-native-audio-launch/v1", "private-native-audio-launch/v2"}
        and actual_launch.get("audio") == launch["audio"]
        and actual_launch.get("dependencies") == dependencies
        and actual_launch.get("source_artifacts") == launch["source_artifacts"]
        and actual_launch.get("contract") == launch["contract"]
        and actual_launch.get("purpose") == launch["purpose"],
        "Actual launch file differs from executed request",
    )
    _verify_launch_output(actual_launch, launch, call, dependencies)
    for ref in [
        launch["audio"],
        launch["contract"],
        *launch["source_artifacts"].values(),
    ]:
        artifact(ref, verify_only=True)
    require(
        {k: v["sha256"] for k, v in launch["source_artifacts"].items()}
        == dependencies["source_hashes"]
        and launch["contract"]["sha256"] == dependencies["contract_hash"],
        "Actual source/contract bytes differ",
    )
    from .contracts import code_identity, verify_contract

    repo = Path(policy["repo_root"])
    require(
        launch.get("code_identity") == code_identity(repo)
        and launch["code_identity"]["code_tree_hash"] == dependencies["code_tree_hash"]
        and not verify_contract(artifact(launch["contract"]), repo),
        "Actual code or frozen contract changed",
    )
    require(
        run.get("runner") == call.get("runner") == runtime.get("runner")
        and call.get("runtime") == runtime.get("runtime")
        and call.get("runtime_libraries") == runtime.get("runtime_libraries")
        and call.get("model_refs") == runtime.get("models")
        and call.get("build_receipt") == runtime.get("build_receipt"),
        "Native runtime snapshots differ from actual request",
    )
    profile = native_profile(call)
    require(
        profile == policy.get("profile"),
        "Native runner/model/prompt/argument profile differs from registered recipe",
    )
    for key in (
        "runner",
        "runtime",
        "build_receipt",
        "build_source_before",
        "build_source_after",
        "patch",
        "patch_manifest",
        "build_runner",
        "source_acquisition",
    ):
        artifact(runtime[key], verify_only=True)
    for row in runtime["models"]:
        artifact(row, verify_only=True)
    for observation in [
        runtime[k] for k in ("interpreter", "time_tool", "probe_tool")
    ] + runtime["runtime_libraries"]:
        require(
            alias_snapshot(observation["requested_path"]) == observation,
            "Native actual alias hops/target changed",
        )
    build = artifact(runtime["build_receipt"])
    source_before, source_after = (
        artifact(runtime["build_source_before"]),
        artifact(runtime["build_source_after"]),
    )
    require(
        build.get("schema_version") == "private-runtime-build/v1"
        and build.get("status") == "BUILT_NOT_CAPABILITY_VALIDATED"
        and build.get("source_unchanged_during_build") is True
        and build.get("source_before") == runtime["build_source_before"]
        and build.get("source_after") == runtime["build_source_after"]
        and source_before == source_after == runtime.get("actual_build_source_tree")
        and build.get("binary") == runtime["runtime"],
        "Native built source/binary differs",
    )
    for build_key, runtime_key in (
        ("patch", "patch"),
        ("patch_manifest", "patch_manifest"),
        ("runner", "build_runner"),
        ("source_acquisition", "source_acquisition"),
    ):
        require(
            build.get(build_key) == runtime[runtime_key],
            "Native build provenance edge differs",
        )
    require(
        runtime["build_receipt"]["sha256"] == policy["build_receipt_sha256"]
        and runtime["build_source_before"]["sha256"]
        == policy["source_manifest_sha256"],
        "Native independently audited build differs",
    )
    acquisition = artifact(runtime["source_acquisition"])
    source_root = Path(acquisition.get("copied_source", ""))
    require(
        source_root.is_absolute()
        and source_root.is_dir()
        and not source_root.is_symlink(),
        "Native actual source tree absent",
    )
    rows = []
    for path in sorted(source_root.rglob("*")):
        require(
            not path.is_symlink(), "Native source tree contains unregistered symlink"
        )
        if path.is_file():
            rows.append(
                {
                    "path": str(path.relative_to(source_root)),
                    "sha256": sha256(path),
                    "bytes": path.stat().st_size,
                }
            )
    tree_hash = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    require(
        source_before == {"files": rows, "sha256": tree_hash},
        "Current native source tree differs from built bytes",
    )
    require(
        sorted(str(p) for p in Path(runtime["runtime"]["path"]).parent.glob("*.dylib"))
        == sorted(row["requested_path"] for row in runtime["runtime_libraries"]),
        "Native library denominator changed",
    )
    actual_libraries = {
        row["requested_path"]: row for row in runtime["runtime_libraries"]
    }
    require(
        set(actual_libraries)
        == {row["requested_path"] for row in build["runtime_libraries"]},
        "Native build library denominator differs",
    )
    for row in build["runtime_libraries"]:
        actual = actual_libraries[row["requested_path"]]
        require(
            actual["target"] == row["canonical_file"]
            and bool(actual["hops"]) == row["is_symlink"]
            and (
                not actual["hops"]
                or actual["hops"][0]["link_text"] == row["link_target"]
            ),
            "Built library/alias differs",
        )
    process = _supervisor(run["execution"], case["request"], call["argv"])
    require(
        process["environment_overrides"]
        == call.get("environment_overrides")
        == {"TALKCUT_INTAKE_NONCE": call["run_id"]}
        and process["cwd"] == str(repo)
        and case["run_id"] == call["run_id"]
        and call["run_id"] == run["run_id"] + "/audio",
        "Native actual invocation identity differs",
    )
    require(
        process.get("policy") == policy.get("supervisor_policy"),
        "Native bound/cleanup policy differs",
    )
    probe = artifact(call["input_probe_execution"])
    probe_request = artifact(probe["request"])
    probe_argv = [
        runtime["probe_tool"]["target"]["path"],
        "-v",
        "error",
        "-show_streams",
        "-show_format",
        "-of",
        "json",
        call["input"]["path"],
    ]
    _supervisor(call["input_probe_execution"], probe["request"], probe_argv)
    require(
        probe_request.get("schema_version") == "private-native-probe-request/v1"
        and probe_request.get("input") == call["input"]
        and probe_request.get("bindings_before") == case["bindings_before"]
        and probe["stdout"] == call.get("input_probe_stdout")
        and probe["stderr"] == call.get("input_probe_stderr"),
        "Native actual input probe differs",
    )
    from .composite_review import pcm16

    pcm = pcm16(call["input"])
    metadata = artifact(probe["stdout"], raw=True)
    streams = json.loads(metadata).get("streams", [])
    require(
        len(streams) == 1
        and streams[0].get("codec_type") == "audio"
        and int(streams[0].get("sample_rate", 0)) == pcm["rate"]
        and int(streams[0].get("channels", 0)) == 1,
        "Actual native input probe is not mono audio",
    )
    require(
        call.get("input_modality") == "audio" and call.get("video_input") is None,
        "Native leaf must report audio-only intake",
    )
    return {
        "case": case,
        "run": run,
        "request": call,
        "process": process,
        "bindings": before,
        "profile": profile,
    }
