"""Private, content-addressed projects and atomic revision transactions."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class TalkCutError(ValueError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def now() -> str:
    return datetime.now(UTC).isoformat()


def sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path: str | Path) -> Any:
    try:
        return json.loads(
            Path(path).read_text(),
            parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)),
        )
    except (ValueError, OSError) as exc:
        raise TalkCutError("INVALID_ARTIFACT", f"Cannot read {path}: {exc}") from exc


def atomic_json(path: str | Path, value: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def artifact_ref(path: str | Path) -> dict[str, str]:
    path = Path(path).resolve()
    return {"path": str(path), "sha256": sha256(path)}


def verified_json(ref: dict[str, str]) -> Any:
    if (
        not isinstance(ref, dict)
        or not isinstance(ref.get("path"), str)
        or not isinstance(ref.get("sha256"), str)
        or not ref["path"]
        or len(ref["sha256"]) != 64
    ):
        raise TalkCutError(
            "INVALID_ARTIFACT", "A hashed artifact reference is required"
        )
    if sha256(ref["path"]) != ref["sha256"]:
        raise TalkCutError(
            "STALE_ARTIFACT", "Artifact bytes changed after reference was recorded"
        )
    return read_json(ref["path"])


@contextmanager
def project_lock(directory: str | Path) -> Iterator[None]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise TalkCutError(
                "PROJECT_BUSY", "Another writer owns the project lock"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def preserve_source(
    source: str | Path, directory: str | Path, role: str
) -> dict[str, Any]:
    source, directory = Path(source).resolve(), Path(directory).resolve()
    if not source.is_file():
        raise TalkCutError(
            "SOURCE_MISSING", f"Missing registered {role} source: {source}"
        )
    digest = sha256(source)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / f"{role}-{digest[:16]}{source.suffix}"
    if not target.exists():
        partial = target.with_suffix(target.suffix + ".copying")
        try:
            shutil.copy2(source, partial)
            if sha256(partial) != digest or sha256(source) != digest:
                raise TalkCutError(
                    "SOURCE_CHANGED", "Source changed during verified copy"
                )
            partial.chmod(0o444)
            os.replace(partial, target)
        finally:
            partial.unlink(missing_ok=True)
    if sha256(target) != digest:
        raise TalkCutError("SOURCE_CHANGED", "Preserved source hash differs")
    return {
        "role": role,
        "path": str(target),
        "original_path": str(source),
        "sha256": digest,
        "bytes": target.stat().st_size,
        "durable": True,
        "registered_at": now(),
    }


def init_project(
    directory: str | Path, screen: str | Path, speaker: str | Path
) -> dict[str, Any]:
    directory = Path(directory).resolve()
    with project_lock(directory):
        path = directory / "project.json"
        if path.exists():
            raise TalkCutError(
                "PROJECT_EXISTS",
                "Existing projects must be reopened, never overwritten",
            )
        sources = {
            role: preserve_source(source, directory / "sources", role)
            for role, source in (("screen", screen), ("speaker", speaker))
        }
        value = {
            "schema_version": "talkcut-project/v1",
            "revision": 0,
            "created_at": now(),
            "sources": sources,
            "inspections": {},
            "sync": None,
            "audio_source": None,
            "layout": {
                "width_fraction": "1/8",
                "margin_fraction": "1/100",
                "position": "top-right",
            },
            "cloud": {"enabled": False},
            "owner_acceptance": "pending",
            "events": [],
            "active_plan": None,
            "active_render": None,
        }
        atomic_json(path, value)
        return value


def load_project(directory: str | Path, verify_sources: bool = True) -> dict[str, Any]:
    from .contracts import validate_project

    project = read_json(Path(directory) / "project.json")
    if project.get("schema_version") != "talkcut-project/v1":
        raise TalkCutError(
            "UNSUPPORTED_SCHEMA",
            "Only talkcut-project/v1 is supported; draft-0 is not a project",
        )
    validate_project(project)
    events = project["events"]
    if len(events) != project["revision"]:
        raise TalkCutError(
            "CORRUPT_HISTORY", "Revision does not match committed event count"
        )
    for index, event in enumerate(events):
        previous_hash = content_hash(events[index - 1]) if index else None
        if (
            event.get("prior_revision") != index
            or event.get("previous_event_hash") != previous_hash
            or not event.get("action")
            or not event.get("at")
        ):
            raise TalkCutError(
                "CORRUPT_HISTORY", f"Broken decision chain at revision {index}"
            )
    if verify_sources:
        for source in project["sources"].values():
            if (
                not Path(source["path"]).is_file()
                or sha256(source["path"]) != source["sha256"]
            ):
                raise TalkCutError(
                    "SOURCE_CHANGED",
                    f"Registered source bytes changed: {source['role']}",
                )
    return project


def save_revision(
    directory: str | Path,
    project: dict[str, Any],
    expected_revision: int,
    action: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    """Caller holds project_lock. Events and head are committed as one atomic JSON."""
    current = load_project(directory, verify_sources=False)
    if current["revision"] != expected_revision:
        raise TalkCutError(
            "REVISION_CONFLICT",
            f"Expected {expected_revision}, current {current['revision']}",
        )
    event = {
        "prior_revision": expected_revision,
        "action": action,
        "details": details,
        "at": now(),
        "previous_event_hash": content_hash(current["events"][-1])
        if current["events"]
        else None,
    }
    project["events"] = current["events"] + [event]
    project["revision"] = expected_revision + 1
    atomic_json(Path(directory) / "project.json", project)
    return project


def store_artifact(directory: str | Path, kind: str, value: Any) -> dict[str, str]:
    path = Path(directory) / kind / f"{content_hash(value)}.json"
    if path.exists():
        if read_json(path) != value:
            raise TalkCutError("ARTIFACT_COLLISION", str(path))
    else:
        atomic_json(path, value)
    return artifact_ref(path)
