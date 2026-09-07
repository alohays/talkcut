"""Actual small file-tree observations; authored build claims stay UNVERIFIED."""

import json
import shutil
from pathlib import Path

from talkcut import privacy_checks as privacy
from talkcut.project import artifact_ref, atomic_json, init_project

ROOT = Path.cwd()


def producer_source(command_rows):
    import ast

    template = ast.parse(privacy._SOURCE_TREE_PRODUCER_TEMPLATE)
    slots = {
        "__RUN_DIRECTORY__": "build-execution-synthetic",
        "__ACQUISITION_NAME__": "acquisition.json",
        "__PATCH_NAME__": "change.patch",
        "__PATCH_MANIFEST_NAME__": "patch.json",
        "__DEVELOPER_DIR__": "/synthetic/toolchain",
        "__SDKROOT__": "/synthetic/sdk",
    }
    commands = ast.parse(
        repr([(row["name"], row["argv"]) for row in command_rows]), mode="eval"
    ).body

    class Bind(ast.NodeTransformer):
        def visit_Constant(self, node):
            return (
                ast.copy_location(ast.Constant(slots[node.value]), node)
                if isinstance(node.value, str) and node.value in slots
                else node
            )

        def visit_Assign(self, node):
            if (
                len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "commands"
            ):
                node.value = commands
                return node
            return self.generic_visit(node)

    text = ast.unparse(ast.fix_missing_locations(Bind().visit(template))) + "\n"
    return text.replace(
        "base = Path(__file__).resolve().parent", "base=Path(__file__).resolve().parent"
    ).replace("source = base / 'source'", "source=base/'source'")


def command_record(base, source, name, argv):
    run = base / "build-execution-synthetic"
    out = run / (name + ".stdout.log")
    err = run / (name + ".stderr.log")
    out.write_text(
        "Authored synthetic command metadata; this build was not executed.\n"
    )
    err.write_bytes(b"")
    return {
        "name": name,
        "argv": argv,
        "cwd": str(source),
        "environment_overrides": {
            "DEVELOPER_DIR": "/synthetic/toolchain",
            "SDKROOT": "/synthetic/sdk",
        },
        "stdout": artifact_ref(out),
        "stderr": artifact_ref(err),
        "status": "AUTHORED_NOT_EXECUTED",
    }


def fixture(tmp_path):
    original = tmp_path / "registered-original.bin"
    original.write_bytes(b"Authored registration fixture, not lecture media")
    task = tmp_path / "task"
    project = init_project(task, original, original)
    sources = {k: v["sha256"] for k, v in project["sources"].items()}
    base = task / "capability" / "native"
    source = base / "source"
    (source / "sub").mkdir(parents=True)
    (source / ".gitmodules").write_bytes(b"")
    (source / "main.cpp").write_text("int authored_tree_example() { return 29; }\n")
    atomic_json(
        source / "sub" / "metadata.json",
        {
            "note": "A small authored source data fixture with complete file and byte observations."
        },
    )
    run = base / "build-execution-synthetic"
    run.mkdir()
    rows = [
        {
            "path": str(p.relative_to(source)),
            "sha256": privacy.hashlib.sha256(p.read_bytes()).hexdigest(),
            "bytes": p.stat().st_size,
        }
        for p in sorted(source.rglob("*"))
        if p.is_file()
    ]
    value = {
        "files": rows,
        "sha256": privacy.hashlib.sha256(
            json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    before = run / "source-before.local.json"
    manifest = run / "source-after.local.json"
    atomic_json(before, value)
    atomic_json(manifest, value)
    atomic_json(
        base / "acquisition.json",
        {
            "copied_source": str(source),
            "scope": "Synthetic current byte inventory only",
        },
    )
    (base / "change.patch").write_text(
        "Authored empty change record; no native build.\n"
    )
    atomic_json(base / "patch.json", {"status": "AUTHORED_NOT_EXECUTED"})
    commands = [
        command_record(
            base,
            source,
            "configure",
            ["cmake", "-S", str(source), "-B", str(base / "build")],
        )
    ]
    producer = base / "producer.py"
    producer.write_text(producer_source(commands))
    build = run / "result.local.json"
    atomic_json(
        build,
        {
            "schema_version": "private-runtime-build/v1",
            "source_before": artifact_ref(before),
            "source_after": artifact_ref(manifest),
            "source_acquisition": artifact_ref(base / "acquisition.json"),
            "patch": artifact_ref(base / "change.patch"),
            "patch_manifest": artifact_ref(base / "patch.json"),
            "runner": artifact_ref(producer),
            "source_unchanged_during_build": True,
            "commands": commands,
            "binary": None,
            "runtime_libraries": [],
            "status": "AUTHORED_NOT_EXECUTED",
        },
    )
    data = json.loads(build.read_text())
    owner = {
        "build_receipt": artifact_ref(build),
        "build_source_before": data["source_before"],
        "build_source_after": data["source_after"],
        "build_runner": data["runner"],
        "source_acquisition": data["source_acquisition"],
        "actual_build_source_tree": value,
    }
    copy = base / "binding.json"
    atomic_json(
        copy,
        {
            "runtime": owner,
            "private_note": "This invented confidential source-tree context must remain private in the complete byte inventory.",
        },
    )
    empty = task / "transcripts" / "empty.stderr.txt"
    empty.parent.mkdir()
    empty.write_bytes(b"")
    locator = {
        "build": artifact_ref(build),
        "manifest": artifact_ref(manifest),
        "copies": [
            {
                "parent": artifact_ref(copy),
                "pointer": "/runtime/actual_build_source_tree",
            }
        ],
    }
    refresh(task, sources, build, copy)
    return task, sources, base, source, build, manifest, copy, locator


def set_commands(parts, arguments):
    data = json.loads(parts[4].read_text())
    data["commands"] = [
        command_record(parts[2], parts[3], f"command-{number}", argv)
        for number, argv in enumerate(arguments)
    ]
    atomic_json(parts[4], data)
    (parts[2] / "producer.py").write_text(producer_source(data["commands"]))
    rebind(parts, origin=True)


def refresh(task, sources, build, copy):
    atomic_json(
        task / "checkpoint.local.json",
        {
            "source_sha256": sources["screen"],
            "build": artifact_ref(build),
            "binding": artifact_ref(copy),
        },
    )


def collect(parts):
    return privacy.build_private_inventory(
        parts[0], parts[1], ROOT, auxiliary_source_trees=[parts[-1]]
    )


def rebind(parts, *, manifest=False, origin=False):
    task, sources, base, _source, build, after, copy, locator = parts
    if manifest:
        value = json.loads(after.read_text())
        value["sha256"] = privacy.hashlib.sha256(
            json.dumps(value["files"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        atomic_json(after, value)
        shutil.copyfile(
            after, base / "build-execution-synthetic" / "source-before.local.json"
        )
    data = json.loads(build.read_text())
    if manifest:
        data["source_before"] = artifact_ref(
            base / "build-execution-synthetic" / "source-before.local.json"
        )
        data["source_after"] = artifact_ref(after)
    if origin:
        data["runner"] = artifact_ref(base / "producer.py")
        data["source_acquisition"] = artifact_ref(base / "acquisition.json")
    atomic_json(build, data)
    owner = json.loads(copy.read_text())["runtime"]
    owner.update(
        {
            "build_receipt": artifact_ref(build),
            "build_source_before": data["source_before"],
            "build_source_after": data["source_after"],
            "build_runner": data["runner"],
            "source_acquisition": data["source_acquisition"],
            "actual_build_source_tree": json.loads(after.read_text()),
        }
    )
    atomic_json(copy, {"runtime": owner})
    locator["build"] = artifact_ref(build)
    locator["manifest"] = artifact_ref(after)
    locator["copies"] = [
        {"parent": artifact_ref(copy), "pointer": "/runtime/actual_build_source_tree"}
    ]
    refresh(task, sources, build, copy)
