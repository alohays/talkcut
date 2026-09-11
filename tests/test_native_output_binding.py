"""Synthetic launch provenance controls; no semantic or capability approval."""

import copy

import pytest

from talkcut import native_provenance as native
from talkcut.project import TalkCutError, artifact_ref


def fixture(tmp_path, version=2):
    output = tmp_path / "output.bin"
    output.write_bytes(b"whole authored output\x00\xff")
    ref = artifact_ref(output)
    dependencies = {
        "source_hashes": {"screen": "a" * 64},
        "contract_hash": "b" * 64,
        "code_tree_hash": "c" * 64,
    }
    launch = {
        "schema_version": f"private-native-audio-launch/v{version}",
        "audio": {},
        "dependencies": dependencies,
        "purpose": "Synthetic provenance control",
        "source_artifacts": {},
        "contract": {},
    }
    binding, call = {}, {}
    if version == 2:
        dependencies["output_hash"] = ref["sha256"]
        for value in (launch, binding, call):
            value["output"] = copy.deepcopy(ref)
    return output, launch, binding, call, dependencies


@pytest.mark.parametrize("version", [1, 2])
def test_launch_output_checks_supported_original_scope(tmp_path, version):
    _, launch, binding, call, dependencies = fixture(tmp_path, version)
    native._verify_launch_output(launch, binding, call, dependencies)


@pytest.mark.parametrize("target", ["launch", "binding", "call", "dependencies"])
def test_native_output_scope_cannot_be_added_to_legacy_records(tmp_path, target):
    output, launch, binding, call, dependencies = fixture(tmp_path, 1)
    ref = artifact_ref(output)
    values = {
        "launch": launch,
        "binding": binding,
        "call": call,
        "dependencies": dependencies,
    }
    values[target]["output_hash" if target == "dependencies" else "output"] = (
        ref["sha256"] if target == "dependencies" else ref
    )
    with pytest.raises(TalkCutError):
        native._verify_launch_output(launch, binding, call, dependencies)


@pytest.mark.parametrize("target", ["launch", "binding", "call", "dependencies"])
def test_preexecution_output_ref_cannot_be_omitted(tmp_path, target):
    _, launch, binding, call, dependencies = fixture(tmp_path)
    values = {
        "launch": launch,
        "binding": binding,
        "call": call,
        "dependencies": dependencies,
    }
    del values[target]["output_hash" if target == "dependencies" else "output"]
    with pytest.raises(TalkCutError):
        native._verify_launch_output(launch, binding, call, dependencies)


@pytest.mark.parametrize("target", ["launch", "binding", "call", "dependencies"])
def test_relabelling_with_another_valid_output_is_rejected(tmp_path, target):
    _, launch, binding, call, dependencies = fixture(tmp_path)
    other = tmp_path / "other.bin"
    other.write_bytes(b"other actual output")
    ref = artifact_ref(other)
    values = {
        "launch": launch,
        "binding": binding,
        "call": call,
        "dependencies": dependencies,
    }
    values[target]["output_hash" if target == "dependencies" else "output"] = (
        ref["sha256"] if target == "dependencies" else ref
    )
    with pytest.raises(TalkCutError):
        native._verify_launch_output(launch, binding, call, dependencies)


@pytest.mark.parametrize("change", ["append", "same_size", "delete", "symlink"])
def test_current_complete_output_bytes_must_still_match(tmp_path, change):
    output, launch, binding, call, dependencies = fixture(tmp_path)
    original = output.read_bytes()
    if change == "append":
        output.write_bytes(original + b"changed")
    elif change == "same_size":
        output.write_bytes(b"X" * len(original))
    elif change == "delete":
        output.unlink()
    else:
        other = tmp_path / "alias-target.bin"
        other.write_bytes(original)
        output.unlink()
        output.symlink_to(other)
    with pytest.raises((TalkCutError, OSError)):
        native._verify_launch_output(launch, binding, call, dependencies)


def test_output_is_stream_verified_without_json_decoding(tmp_path):
    _, launch, binding, call, dependencies = fixture(tmp_path)
    native._verify_launch_output(launch, binding, call, dependencies)


@pytest.mark.parametrize("version", [0, 3, None, True])
def test_unknown_launch_schema_cannot_supply_output_scope(tmp_path, version):
    _, launch, binding, call, dependencies = fixture(tmp_path)
    launch["schema_version"] = version
    with pytest.raises(TalkCutError):
        native._verify_launch_output(launch, binding, call, dependencies)


def test_output_mutation_at_end_of_stream_is_rejected(tmp_path, monkeypatch):
    from pathlib import Path

    output, launch, binding, call, dependencies = fixture(tmp_path)
    original_open = Path.open
    initial = output.read_bytes()
    changed = False

    class Observer:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def read(self, size=-1):
            nonlocal changed
            assert 0 < size <= 8 * 1024 * 1024
            value = self.stream.read(size)
            if not value and not changed:
                changed = True
                with original_open(output, "wb") as writer:
                    writer.write(b"Z" * len(initial))
            return value

    def observed_open(path, mode="r", *args, **kwargs):
        stream = original_open(path, mode, *args, **kwargs)
        return Observer(stream) if path == output and mode == "rb" else stream

    monkeypatch.setattr(Path, "open", observed_open)
    with pytest.raises(TalkCutError, match="output changed while hashing"):
        native._verify_launch_output(launch, binding, call, dependencies)
    with original_open(output, "rb") as actual:
        assert changed and actual.read() != initial
