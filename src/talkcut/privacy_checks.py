"""Scan exact Git history and publication bytes without publishing anything.

Unknown binaries, links, unreadable members and exhausted traversal limits stay
UNVERIFIED. Corpus matches and credentials are findings, never printed secrets.
Remote GitHub bytes must match supplied local publication refs before final
publication measurements can pass. No command is executed from an input record.
"""

from __future__ import annotations

import ast
import gzip
import hashlib
import io
import json
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import tarfile
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from .contracts import code_identity, object_hash
from .project import TalkCutError, artifact_ref, load_project, sha256
from .verification import _terminate_group

MAX_UNIT_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_UNITS = 20000
MAX_DEPTH = 5
MAX_COMMITS = 10000
# Finite traversal safeguard, not a quality/coverage denominator. Real preserved
# whole-frame evidence can exceed 100,000 files; every file still enters inventory.
MAX_TASK_FILES = 1000000
# Opaque private preservation has independent finite I/O bounds. Parsing and
# publication scanning retain MAX_UNIT_BYTES and MAX_TOTAL_BYTES unchanged.
MAX_PRIVATE_ARCHIVE_FILE_BYTES = 32 * 1024**3
MAX_PRIVATE_ARCHIVE_TOTAL_BYTES = 64 * 1024**3
PRIVATE_ARCHIVE_CHUNK_BYTES = 1024 * 1024
CREDENTIALS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "api_secret_key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b"),
}


def _require(condition: Any, message: str) -> None:
    if not condition:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", message)


def _file(ref: Any) -> Path:
    _require(isinstance(ref, dict) and ref.get("path") and ref.get("sha256"), "A hashed publication artifact is required")
    path = Path(ref["path"])
    _require(path.is_absolute() and path.is_file() and not path.is_symlink(), "Publication artifact is absent or a symlink")
    _require(sha256(path) == ref["sha256"], "Publication artifact changed")
    if "bytes" in ref:
        _require(path.stat().st_size == ref["bytes"], "Publication artifact byte count changed")
    return path


def _json(ref: Any) -> Any:
    return json.loads(_file(ref).read_text())


def _command(argv: list[str], cwd: Path, traces: list[dict[str, Any]], *, limit: int = MAX_UNIT_BYTES) -> bytes:
    """Read bounded actual stdout, with process-group timeout and no shell."""
    timed_out = threading.Event()
    with tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)

        def stop():
            timed_out.set()
            _terminate_group(process)

        timer = threading.Timer(60, stop)
        timer.daemon = True
        timer.start()
        assert process.stdout is not None
        try:
            output = process.stdout.read(limit + 1)
            if len(output) > limit:
                _terminate_group(process)
            code = process.wait(timeout=10)
        finally:
            timer.cancel()
            process.stdout.close()
            if process.poll() is None:
                _terminate_group(process)
        stderr.seek(0)
        error = stderr.read(MAX_UNIT_BYTES + 1)
    traces.append({"argv": argv, "cwd": str(cwd), "exit_code": code, "timed_out": timed_out.is_set(),
                   "stdout_bytes": len(output), "stdout_sha256": hashlib.sha256(output).hexdigest(),
                   "stderr_bytes": len(error), "stderr_sha256": hashlib.sha256(error).hexdigest()})
    _require(code == 0 and not timed_out.is_set() and len(output) <= limit and len(error) <= MAX_UNIT_BYTES,
             "Actual publication inspection command failed, timed out or exceeded its byte limit")
    return output


@dataclass
class Scan:
    private: dict[str, str]
    phrases: list[str]
    units: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[dict[str, str]] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    credentials: set[str] = field(default_factory=set)
    media: set[str] = field(default_factory=set)
    transcripts: set[str] = field(default_factory=set)
    total_bytes: int = 0
    exhausted: bool = False

    def unverified(self, label: str, reason: str) -> None:
        self.unknown.append({"location": label, "reason": reason})

    def payload(self, data: bytes, label: str, *, depth: int = 0, path: str | None = None) -> None:
        if self.exhausted:
            return
        digest = hashlib.sha256(data).hexdigest()
        if path is not None:
            parts = PurePosixPath(path).parts
            if PurePosixPath(path).is_absolute() or ".." in parts:
                self.unverified(label, "Unsafe publication member path")
                return
            if "projects" in parts or any(part == ".env" or (part.startswith(".env.") and part not in {".env.example", ".env.sample"}) for part in parts):
                self.unverified(label, "Private project/environment path appears in publication payload")
        if digest in self.private:
            kind = self.private[digest]
            if kind == "media":
                self.media.add(digest)
            elif kind in {"transcript", "review"}:
                self.transcripts.add(digest)
            elif kind == "credentials":
                self.credentials.add(digest)
            self.findings.append({"kind": "private_" + kind, "location": label, "sha256": digest})
            return
        if digest in self.seen:
            return
        if depth > MAX_DEPTH or len(self.units) >= MAX_UNITS or len(data) > MAX_UNIT_BYTES or self.total_bytes + len(data) > MAX_TOTAL_BYTES:
            self.unverified(label, "Publication traversal budget exceeded; content was not fully inspected")
            self.exhausted = True
            return
        self.seen.add(digest)
        self.total_bytes += len(data)
        self.units.append({"location": label, "sha256": digest, "bytes": len(data)})
        try:
            if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    entries = archive.infolist()
                    if len(entries) > MAX_UNITS or len({entry.filename for entry in entries}) != len(entries):
                        self.unverified(label, "ZIP has too many or duplicate member paths")
                        return
                    for entry in entries:
                        if self.exhausted:
                            break
                        if entry.is_dir():
                            continue
                        if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                            self.unverified(label + "!" + entry.filename, "Archive symlink was not followed")
                        elif entry.file_size > MAX_UNIT_BYTES:
                            self.unverified(label + "!" + entry.filename, "Archive member exceeds inspection bound")
                        else:
                            self.payload(archive.read(entry), label + "!" + entry.filename, depth=depth + 1, path=entry.filename)
                return
            if data.startswith(b"\x1f\x8b"):
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
                    unpacked = compressed.read(MAX_UNIT_BYTES + 1)
                if len(unpacked) > MAX_UNIT_BYTES:
                    self.unverified(label, "Gzip expansion exceeds inspection bound")
                else:
                    self.payload(unpacked, label + "!gzip", depth=depth + 1)
                return
            if len(data) >= 512 and data[257:262] == b"ustar":
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar_archive:
                    tar_entries = tar_archive.getmembers()
                    if len(tar_entries) > MAX_UNITS or len({entry.name for entry in tar_entries}) != len(tar_entries):
                        self.unverified(label, "TAR has too many or duplicate member paths")
                        return
                    for tar_entry in tar_entries:
                        if self.exhausted:
                            break
                        if tar_entry.isdir():
                            continue
                        if not tar_entry.isfile() or tar_entry.issparse():
                            self.unverified(label + "!" + tar_entry.name, "Archive link or special member was not followed")
                        elif tar_entry.size > MAX_UNIT_BYTES:
                            self.unverified(label + "!" + tar_entry.name, "Archive member exceeds inspection bound")
                        else:
                            handle = tar_archive.extractfile(tar_entry)
                            if handle is None:
                                self.unverified(label + "!" + tar_entry.name, "Archive member cannot be read")
                            else:
                                with handle:
                                    self.payload(handle.read(MAX_UNIT_BYTES + 1), label + "!" + tar_entry.name, depth=depth + 1, path=tar_entry.name)
                return
            text = data.decode("utf-8")
            if "\x00" in text or any(ord(char) < 32 and char not in "\n\r\t\f" for char in text):
                self.unverified(label, "Unknown binary/control-byte payload")
                return
            for kind, pattern in CREDENTIALS.items():
                for match in pattern.finditer(text):
                    secret_hash = hashlib.sha256(match.group().encode()).hexdigest()
                    self.credentials.add(secret_hash)
                    self.findings.append({"kind": kind, "location": label, "matched_sha256": secret_hash})
            for phrase in self.phrases:
                if phrase in text:
                    phrase_hash = hashlib.sha256(phrase.encode()).hexdigest()
                    self.transcripts.add(phrase_hash)
                    self.findings.append({"kind": "protected_transcript_phrase", "location": label, "matched_sha256": phrase_hash})
        except (UnicodeDecodeError, ValueError, OSError, RuntimeError, EOFError, zipfile.BadZipFile, tarfile.TarError) as exc:
            self.unverified(label, f"Unreadable or unsupported payload: {type(exc).__name__}")


def _git_inventory(root: Path, expected_head: str, scanner: Scan, traces: list[dict[str, Any]]) -> dict[str, Any]:
    def git(*args: str, limit: int = MAX_UNIT_BYTES) -> bytes:
        return _command(["git", *args], root, traces, limit=limit)

    head = git("rev-parse", "--verify", "HEAD").decode().strip()
    _require(head == expected_head and re.fullmatch(r"[a-f0-9]{40,64}", head), "Publication HEAD changed")
    refs = git("for-each-ref", "--format=%(refname) %(objectname) %(objecttype)")
    commits = git("rev-list", "--all", "HEAD").decode().splitlines()
    _require(0 < len(commits) <= MAX_COMMITS and len(commits) == len(set(commits)), "Reachable history is empty or exceeds inspection bounds")
    blobs: dict[str, set[str]] = {}
    for commit in commits:
        if scanner.exhausted:
            break
        _require(re.fullmatch(r"[a-f0-9]{40,64}", commit), "Invalid reachable commit identity")
        scanner.payload(git("cat-file", "commit", commit), "git-commit:" + commit)
        tree = git("ls-tree", "-r", "-z", "--full-tree", commit)
        for item in tree.split(b"\0"):
            if not item:
                continue
            header, raw_path = item.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            try:
                name = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                scanner.unverified("git-tree:" + commit, "Non-UTF8 path was not interpreted")
                continue
            if mode not in {"100644", "100755"} or kind != "blob":
                scanner.unverified("git:" + commit + ":" + name, "Git symlink, submodule or unsupported mode")
                continue
            blobs.setdefault(oid, set()).add(name)
            if len(blobs) > MAX_UNITS:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Reachable blob count exceeds inspection bound")
    for oid, paths in blobs.items():
        if scanner.exhausted:
            break
        size = int(git("cat-file", "-s", oid).decode().strip())
        if size > MAX_UNIT_BYTES:
            scanner.unverified("git-blob:" + oid, "Reachable blob exceeds inspection byte bound")
            continue
        content = git("cat-file", "blob", oid)
        _require(len(content) == size, "Git object size changed during inspection")
        for name in sorted(paths):
            scanner.payload(content, "git-blob:" + oid + ":" + name, path=name)
    # Annotated tag messages are public bytes too, including nested annotations.
    pending = [line.split()[1] for line in refs.decode().splitlines() if line.split()[2] == "tag"]
    tags: set[str] = set()
    while pending:
        tag = pending.pop()
        if tag in tags:
            continue
        _require(len(tags) < MAX_UNITS, "Annotated tag traversal exceeds inspection bound")
        tags.add(tag)
        content = git("cat-file", "tag", tag)
        scanner.payload(content, "git-tag:" + tag)
        if b"\ntype tag\n" in content:
            pending.append(content.splitlines()[0].split()[1].decode())
    _require(git("rev-parse", "--verify", "HEAD").decode().strip() == head
             and git("for-each-ref", "--format=%(refname) %(objectname) %(objecttype)") == refs,
             "Git refs changed during publication scanning")
    return {"head": head, "reachable_commits": commits, "reachable_blob_count": len(blobs),
            "blob_paths": {oid: sorted(paths) for oid, paths in blobs.items()},
            "refs_sha256": hashlib.sha256(refs).hexdigest(), "annotated_tags": sorted(tags)}


def _asset_refs(values: Any) -> dict[str, dict[str, Any]]:
    _require(isinstance(values, list), "Explicit publication asset inventory is required")
    refs = {}
    for ref in values:
        _require(isinstance(ref, dict) and isinstance(ref.get("name"), str)
                 and ref["name"] == Path(ref["name"]).name and ref["name"] not in refs, "Publication asset names are absent, unsafe or duplicated")
        _file(ref)
        refs[ref["name"]] = ref
    return refs


def _remote(raw: dict[str, Any], root: Path, assets: dict[str, dict[str, Any]], traces: list[dict[str, Any]]) -> dict[str, Any] | None:
    settings = raw.get("remote_publication")
    if not settings:
        return None
    origin = _command(["git", "remote", "get-url", "origin"], root, traces).decode().strip()
    match = re.fullmatch(r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?", origin)
    _require(match is not None and settings.get("repository") == match.group(1), "Remote publication is not the configured GitHub repository")
    assert match is not None
    repository = match.group(1)
    number, tag = settings.get("pr_number"), settings.get("tag")
    _require(type(number) is int and number > 0 and isinstance(tag, str) and tag, "Exact remote PR number and release tag are required")

    def api(endpoint: str) -> Any:
        return json.loads(_command(["gh", "api", "--hostname", "github.com", endpoint], root, traces))

    pull = api(f"repos/{repository}/pulls/{number}")
    release = api(f"repos/{repository}/releases/tags/{quote(tag, safe='')}")
    tagged = api(f"repos/{repository}/commits/{quote(tag, safe='')}")
    _require(tagged.get("sha") == raw["expected_head"], "Remote release tag does not identify the scanned Git HEAD")
    _require(pull.get("merged_at") and pull.get("merge_commit_sha") == raw["expected_head"], "Merged PR does not identify the final scanned release commit")
    _require((pull.get("body") or "").encode() == _file(raw["pr_body"]).read_bytes()
             and (release.get("body") or "").encode() == _file(raw["release_body"]).read_bytes(),
             "Remote PR/release body bytes differ from scanned publication bodies")
    remote_assets = release.get("assets")
    _require(isinstance(remote_assets, list) and len(remote_assets) == len(assets)
             and {item["name"] for item in remote_assets} == set(assets), "Remote release assets differ from explicit scanned inventory")
    for item in remote_assets:
        ref = assets[item["name"]]
        _require(type(item.get("id")) is int and 0 <= item.get("size", -1) <= MAX_UNIT_BYTES
                 and item["size"] == _file(ref).stat().st_size, "Remote release asset size is unsupported or changed")
        downloaded = _command(["gh", "api", "--hostname", "github.com", "-H", "Accept: application/octet-stream",
                               f"repos/{repository}/releases/assets/{item['id']}"], root, traces)
        _require(hashlib.sha256(downloaded).hexdigest() == ref["sha256"], "Actual remote asset bytes differ from the scanned local file")
    return {"repository": repository, "pr_url": pull["html_url"], "release_url": release["html_url"],
            "release_id": release["id"], "tag": tag, "head": tagged["sha"],
            "asset_ids": {item["name"]: item["id"] for item in remote_assets},
            "body_and_asset_bytes_match": True}


def _public_source_candidates(root: Path | None, registered: set[str]) -> tuple[dict[str, list[dict[str, str]]], list[dict[str, Any]], set[str]]:
    """Find byte identities, never infer privacy or a license from Git membership."""
    if root is None or not (root / ".git").exists():
        return {}, [], set()
    traces: list[dict[str, Any]] = []
    commits = _command(["git", "rev-list", "--all", "HEAD"], root, traces).decode().splitlines()
    _require(len(commits) <= MAX_COMMITS, "Public-source candidate history exceeds inspection bounds")
    objects: dict[str, list[dict[str, str]]] = {}
    for commit in commits:
        tree = _command(["git", "ls-tree", "-r", "-z", "--full-tree", commit], root, traces)
        for row in tree.split(b"\0"):
            if not row:
                continue
            header, raw_path = row.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            name = raw_path.decode("utf-8")
            parts = PurePosixPath(name).parts
            source_path = parts[0] in {"src", "tests", "examples", "docs", "schemas", ".github"} or name in {
                "README.md", "LICENSE", "CONTRIBUTING.md", "SECURITY.md", "pyproject.toml", "uv.lock", "pytest.ini"}
            if source_path and mode in {"100644", "100755"} and kind == "blob":
                objects.setdefault(oid, []).append({"commit": commit, "git_path": name, "git_blob": oid})
    _require(len(objects) <= MAX_UNITS, "Public-source candidate object count exceeds inspection bounds")
    candidates: dict[str, list[dict[str, str]]] = {}
    transcript_hashes: set[str] = set()

    def transcript_body(value: Any) -> bool:
        if isinstance(value, dict):
            return (value.get("schema_version") == "transcript/v1" and value.get("source_sha256") in registered
                    or any(transcript_body(child) for child in value.values()))
        return isinstance(value, list) and any(transcript_body(child) for child in value)
    for oid, origins in objects.items():
        size = int(_command(["git", "cat-file", "-s", oid], root, traces).decode())
        if size > MAX_UNIT_BYTES:
            continue
        data = _command(["git", "cat-file", "blob", oid], root, traces)
        # Binary fixtures are never a source-code privacy exception.
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "\x00" not in decoded:
            digest = hashlib.sha256(data).hexdigest()
            candidates[digest] = origins
            try:
                if transcript_body(json.loads(decoded)):
                    transcript_hashes.add(digest)
            except ValueError:
                pass
    return candidates, traces, transcript_hashes


def _review_text_origin_inventory(locators: Any, directory: Path, root: Path | None,
                                  registered: set[str], authorities: Any = None) -> list[dict[str, Any]]:
    """Observe two closed source extractions; never certify a review or publication."""
    _require(authorities is None or isinstance(authorities, list), "Review text authority roots must be an explicit list")
    if locators is None:
        _require(not authorities, "Review text authority roots have no occurrence observations")
        return []
    _require(isinstance(locators, list) and len(locators) <= MAX_UNITS,
             "Review text origins require a bounded explicit list")
    if not locators:
        _require(not authorities, "Review text authority roots have no occurrence observations")
        return []
    _require(root is not None, "Review text origins require a Git source authority")
    assert root is not None
    result = []
    seen: set[tuple[str, tuple[str | int, ...]]] = set()
    identities: dict[str, tuple[int, ...]] = {}

    def read(ref: Any) -> tuple[Path, bytes]:
        _require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}
                 and isinstance(ref["path"], str) and isinstance(ref["sha256"], str)
                 and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]),
                 "Review text origin requires an exact artifact reference")
        path = Path(ref["path"])
        _require(path.is_absolute() and path == path.resolve() and path.is_file()
                 and not path.is_symlink() and path.stat().st_size <= MAX_UNIT_BYTES,
                 "Review text origin is missing, aliased or oversized")
        before = _source_file_identity(path.lstat())
        _require(str(path) not in identities or identities[str(path)] == before, "Review text origin path identity changed")
        identities[str(path)] = before
        data = path.read_bytes()
        _require(hashlib.sha256(data).hexdigest() == ref["sha256"]
                 and before == _source_file_identity(path.lstat()), "Review text origin bytes or identity changed")
        return path, data

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            _require(key not in value, "Review text parent contains duplicate JSON keys")
            value[key] = child
        return value

    def speech(value: Any) -> bool:
        if isinstance(value, dict):
            return value.get("schema_version") == "transcript/v1" or any(speech(v) for v in value.values())
        return isinstance(value, list) and any(speech(v) for v in value)

    _require(authorities is None or isinstance(authorities, list), "Review text authority roots must be an explicit list")
    approved = authorities or []
    _require(len(approved) <= MAX_UNITS and len({json.dumps(ref, sort_keys=True) for ref in approved}) == len(approved),
             "Review text authority roots are duplicated or oversized")
    for approved_ref in approved:
        read(approved_ref)
    _require(len({ref["sha256"] for ref in approved}) == len(approved), "Review text authority root bytes are duplicated")
    authority_cache: dict[str, dict[str, Any]] = {}

    def document(ref: Any) -> dict[str, Any]:
        _, data = read(ref)
        try:
            value = json.loads(data, object_pairs_hook=object_pairs)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text authority is not bounded JSON") from exc
        _require(isinstance(value, dict), "Review text authority must be an object")
        return value

    def authority(ref: Any) -> dict[str, Any]:
        _require(ref in approved, "Review text observation has no separately bound authority root")
        read(ref)
        if ref["sha256"] in authority_cache:
            return authority_cache[ref["sha256"]]
        selected = document(ref)
        names = {"inspection", "request", "snapshot", "verification", "execution", "producer", "response"}
        _require(set(selected) == {"schema_version", *names}
                 and selected["schema_version"] == "review-text-source-authority/v1",
                 "Review text authority has unsupported fields")
        values = {name: document(selected[name]) for name in names - {"producer"}}
        inspection, request, snapshot, report, execution, response = (
            values[name] for name in ("inspection", "request", "snapshot", "verification", "execution", "response"))
        _require(inspection.get("schema_version") == "independent-oss-inspection/v1"
                 and inspection.get("request") == selected["request"] and inspection.get("snapshot") == selected["snapshot"]
                 and response.get("schema_version") == "artifact-audit-response/v1"
                 and response.get("inspection") == selected["inspection"]
                 and response.get("actual_inspection_execution") == selected["execution"],
                 "Review text authority does not bind its original inspection and response")
        _require(request.get("schema_version") == "artifact-audit-request/v1"
                 and request.get("scope") == "reproducibility_license_support"
                 and request.get("snapshot_hash") == selected["snapshot"]["sha256"]
                 and request.get("reviewer_role") == "independent_auditor"
                 and snapshot.get("schema_version") == "reproducibility-audit-snapshot/v1"
                 and snapshot.get("verification") == selected["verification"],
                 "Review text authority request/snapshot relationship differs")
        _require(report.get("schema_version") == "oss-verification/v1" and report.get("repo_root") == str(root)
                 and isinstance(report.get("before"), dict) and report["before"] == report.get("after"),
                 "Review text authority lacks the unchanged original source observation")
        before = report["before"]
        identity = before.get("code_identity")
        extra = before.get("documentation_example_files")
        _require(isinstance(identity, dict) and set(identity) == {"code_revision", "code_tree_hash", "files"}
                 and isinstance(identity["files"], dict) and isinstance(extra, dict)
                 and identity["code_tree_hash"] == object_hash(identity["files"])
                 and before.get("documentation_example_hash") == object_hash(extra),
                 "Review text authority source maps are incomplete or hash-inconsistent")
        maps = {**identity["files"], **extra}
        _require(all(isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for k, v in maps.items())
                 and all(k not in extra or extra[k] == v for k, v in identity["files"].items()),
                 "Review text authority source maps conflict")
        public_rows = inspection.get("public_files")
        _require(isinstance(public_rows, list) and 0 < len(public_rows) == len(maps) <= MAX_UNITS
                 and all(isinstance(row, dict) and isinstance(row.get("path"), str)
                         and type(row.get("utf8_bytes")) is int and row["utf8_bytes"] >= 0
                         and row.get("is_symlink") is False for row in public_rows)
                 and len({row["path"] for row in public_rows}) == len(public_rows)
                 and {row["path"]: row.get("sha256") for row in public_rows} == {str(root / path): digest for path, digest in maps.items()},
                 "Review text inspection does not retain the complete original source-file map")
        dependencies = {"code_tree_hash": identity["code_tree_hash"],
                        "documentation_example_hash": before["documentation_example_hash"],
                        "verification_hash": selected["verification"]["sha256"]}
        _require(request.get("dependencies") == snapshot.get("dependencies") == dependencies
                 and isinstance(request.get("input_artifacts"), list) and isinstance(snapshot.get("input_refs"), list)
                 and request["input_artifacts"] == [selected["snapshot"], *snapshot["input_refs"]],
                 "Review text authority request inputs or dependencies differ")
        inspected = inspection.get("inspected_artifacts")
        _require(isinstance(inspected, list) and len(inspected) == len(request["input_artifacts"])
                 and all(isinstance(row, dict) and set(row) == {"path", "sha256", "bytes"}
                         and type(row["bytes"]) is int and row["bytes"] >= 0 for row in inspected)
                 and [{"path": row.get("path"), "sha256": row.get("sha256")} for row in inspected] == request["input_artifacts"],
                 "Review text authority inspection omits or replaces original input rows")
        producer_path, producer_bytes = read(selected["producer"])
        argv = execution.get("argv")
        basic = {"argv", "cwd", "exit_code", "started_at", "finished_at", "stdout", "stderr"}
        typed_command = (set(execution) == basic | {"schema_version", "wall_seconds"}
                         and execution.get("schema_version") == "independent-audit-command/v1"
                         and type(execution.get("wall_seconds")) in {int, float}
                         and math.isfinite(execution["wall_seconds"]) and execution["wall_seconds"] >= 0)
        script_command = (set(execution) == basic | {"script", "reviewer_task_id"}
                          and execution.get("script") == selected["producer"]
                          and execution.get("reviewer_task_id") == request.get("reviewer_task_id")
                          and isinstance(request.get("reviewer_task_id"), str))
        _require((typed_command or script_command)
                 and isinstance(argv, list) and len(argv) == 4 and isinstance(argv[0], str)
                 and Path(argv[0]).is_absolute() and argv[1:] == ["-I", "-B", str(producer_path)]
                 and execution.get("cwd") == str(root) and type(execution.get("exit_code")) is int and execution["exit_code"] == 0
                 and isinstance(execution.get("started_at"), str) and isinstance(execution.get("finished_at"), str),
                 "Review text authority command is not its retained fixed inspection")
        try:
            syntax = ast.parse(producer_bytes.decode())
        except (ValueError, UnicodeDecodeError, SyntaxError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text inspection producer is not Python") from exc
        expected_public = ast.parse("public = {**report['before']['code_identity']['files'], **report['before']['documentation_example_files']}").body[0]
        _require(any(ast.dump(node) == ast.dump(expected_public) for node in syntax.body),
                 "Review text inspection producer does not select the original source maps")
        _, stdout = read(execution.get("stdout"))
        _, stderr = read(execution.get("stderr"))
        _require(not stderr, "Review text inspection stderr is not the original clean observation")
        try:
            log = [json.loads(line, object_pairs_hook=object_pairs) for line in stdout.decode().splitlines() if line.strip()]
        except (ValueError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text inspection log is malformed") from exc
        completed = [row for row in log if isinstance(row, dict) and row.get("stage") == "inspection_completed_without_issuing_audit_verdict"]
        _require(len(completed) == 1 and completed[0].get("result") == selected["inspection"],
                 "Review text inspection log does not bind the exact original result")
        observed = {"root": ref, "refs": [ref, *[selected[name] for name in sorted(names)], execution["stdout"], execution["stderr"]],
                    "source_files": maps, "code_identity": identity, "inspection": selected["inspection"],
                    "response": selected["response"], "request_inputs": request["input_artifacts"]}
        authority_cache[ref["sha256"]] = observed
        return observed


    for locator in locators:
        _require(isinstance(locator, dict) and locator.get("kind") in {"python_inspection", "document_paragraph", "document_complete"},
                 "Unsupported review text origin kind")
        paragraph = locator["kind"] != "python_inspection"
        complete_document = locator["kind"] == "document_complete"
        _require(set(locator) == {"schema_version", "kind", "parent", "selector", "source", "authority"}
                 | ({"paragraph_index"} if paragraph and not complete_document else set())
                 and locator["schema_version"] == "review-text-origin/v1", "Unsupported review text origin fields")
        bound = authority(locator["authority"])
        _require(locator["parent"] == bound["response" if paragraph else "inspection"],
                 "Review text parent differs from the separately frozen authority root")
        parent_path, data = read(locator["parent"])
        _require(parent_path.is_relative_to(directory)
                 and not any(parent_path.is_relative_to(directory / name) for name in
                             ("sources", "transcripts", "renders", "reviews", "review", "analysis")),
                 "Review text origin cannot scope source, transcript or audiovisual review namespaces")
        try:
            parent = json.loads(data, object_pairs_hook=object_pairs)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text parent is not bounded JSON") from exc
        _require(isinstance(parent, dict) and not speech(parent)
                 and parent.get("schema_version") == ("artifact-audit-response/v1" if paragraph else "independent-oss-inspection/v1"),
                 "Review text parent has a different schema or transcript context")
        selector = locator["selector"]
        pattern = ["documentation_reviews", int, "claims", int, "quote"] if paragraph else ["public_files", int]
        _require(isinstance(selector, list) and len(selector) == len(pattern)
                 and all((type(part) is int and 0 <= part < MAX_UNITS) if expected is int else
                         (type(part) is str and part == expected) for part, expected in zip(selector, pattern, strict=True)),
                 "Review text selector is outside the closed extraction grammar")
        key = (str(parent_path), tuple(selector))
        _require(key not in seen, "Review text origin selector is duplicated")
        seen.add(key)
        try:
            selected = parent
            for part in selector:
                selected = selected[part]
        except (KeyError, IndexError, TypeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text selector does not exist") from exc
        source = locator["source"]
        _require(isinstance(source, dict) and set(source) == {"original_path", "snapshot", "git_revision", "git_path", "git_blob"}
                 and all(isinstance(source[k], str) for k in ("original_path", "git_revision", "git_path", "git_blob"))
                 and re.fullmatch(r"[a-f0-9]{40}", source["git_revision"])
                 and re.fullmatch(r"[a-f0-9]{40}", source["git_blob"]), "Review text source Git identity is incomplete")
        relative = PurePosixPath(source["git_path"])
        _require(not relative.is_absolute() and relative.as_posix() == source["git_path"]
                 and relative.parts and all(part not in {".", ".."} for part in relative.parts)
                 and source["original_path"] == str(root / relative)
                 and (root / relative).resolve() == root / relative,
                 "Review text source path is noncanonical or outside its Git identity")
        snapshot_path, source_data = read(source["snapshot"])
        _require(source["git_revision"] == bound["code_identity"]["code_revision"]
                 and bound["source_files"].get(source["git_path"]) == source["snapshot"].get("sha256")
                 and {"path": source["original_path"], "sha256": source["snapshot"].get("sha256")} in bound["request_inputs"],
                 "Review text source differs from the original request and verification maps")
        _require(source["snapshot"]["sha256"] not in registered, "Registered media cannot supply review text origins")
        traces: list[dict[str, Any]] = []
        _command(["git", "cat-file", "commit", source["git_revision"]], root, traces)
        tree = _command(["git", "ls-tree", "-z", source["git_revision"], "--", source["git_path"]], root, traces)
        expected = ("100644 blob " + source["git_blob"] + "\t" + source["git_path"] + "\0").encode()
        executable = ("100755 blob " + source["git_blob"] + "\t" + source["git_path"] + "\0").encode()
        _require(tree in {expected, executable}, "Review text source is not the exact regular Git tree member")
        blob = _command(["git", "cat-file", "blob", source["git_blob"]], root, traces)
        _require(blob == source_data, "Review text preserved source differs from its Git blob")
        try:
            content = source_data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text source is not UTF-8") from exc
        exempt = []
        if paragraph:
            quoted_document = parent["documentation_reviews"][selector[1]]
            _require(isinstance(quoted_document, dict) and quoted_document.get("path") == source["original_path"]
                     and quoted_document.get("sha256") == source["snapshot"]["sha256"]
                     and relative.suffix == ".md", "Review text quote names a different source document")
            if complete_document:
                _require(isinstance(selected, str) and len(selected.strip()) >= 10 and selected == content.strip(),
                         "Review text quote is not the exact complete source document")
            else:
                _require(type(locator["paragraph_index"]) is int and 0 <= locator["paragraph_index"] < MAX_UNITS,
                         "Review text paragraph index must be an exact bounded integer")
                pieces = content.split("\n\n")
                index = locator["paragraph_index"]
                _require(index < len(pieces) and isinstance(selected, str) and len(selected.strip()) >= 10
                         and not selected.startswith("#") and selected == pieces[index].strip(),
                         "Review text quote is not the exact selected complete paragraph")
            exempt.append({"edge": selector, "value": selected})
        else:
            _require(relative.parts[0] in {"tests", "examples"} and relative.suffix == ".py",
                     "Review text Python extraction is outside its source grammar")
            try:
                syntax = ast.parse(content)
            except SyntaxError as exc:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Review text source has invalid Python syntax") from exc
            extraction = {"path": source["original_path"], "sha256": source["snapshot"]["sha256"],
                          "utf8_bytes": len(content.encode()), "is_symlink": False,
                          "imports": [ast.unparse(n) for n in syntax.body if isinstance(n, (ast.Import, ast.ImportFrom))],
                          "functions": [n.name for n in syntax.body if isinstance(n, ast.FunctionDef)],
                          "asset_creation_calls": [ast.get_source_segment(content, n) for n in ast.walk(syntax)
                              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                              and n.func.attr in {"write_text", "write_bytes", "run", "writestr", "pack", "pack_into"}]}
            _require(isinstance(selected, dict) and set(selected) == set(extraction)
                     and json.dumps(selected, sort_keys=True, separators=(",", ":"))
                     == json.dumps(extraction, sort_keys=True, separators=(",", ":")),
                     "Review text Python row differs from its complete source extraction")
            for field in ("imports", "functions", "asset_creation_calls"):
                _require(len(extraction[field]) <= MAX_UNITS, "Review text source extraction exceeds its bound")
                for index, value in enumerate(extraction[field]):
                    exempt.append({"edge": [*selector, field, index], "value": value})
        read(locator["parent"])
        read(source["snapshot"])
        result.append({"parent": locator["parent"], "selector": selector, "kind": locator["kind"],
                       "source": source, "source_snapshot": artifact_ref(snapshot_path), "selected_value": selected,
                       "extractions": exempt, "authority": locator["authority"], "authority_refs": bound["refs"],
                       "commands": traces, "classification": "review",
                       "claim_status": "UNVERIFIED", "scope": "Exact source-derived fields only; no review or publication approval"})
    _require(set(authority_cache) == {ref["sha256"] for ref in approved}, "Review text authority root was not consumed")
    for observed_name, identity in identities.items():
        _require(_source_file_identity(Path(observed_name).lstat()) == identity, "Review text authority identity changed after readback")
    return result


def _known_private_inventory(project_dir: Path | None, expected_source_hashes: dict[str, str] | None,
                             repo_root: Path | None = None, *,
                             historical_artifacts: list[dict[str, Any]] | None = None,
                             source_snapshots: list[dict[str, Any]] | None = None,
                             publication_bodies: dict[str, dict[str, Any]] | None = None,
                             synthetic_negative_runs: list[dict[str, Any]] | None = None,
                             synthetic_replay: dict[str, Any] | None = None,
                             auxiliary_metadata_history: list[dict[str, Any]] | None = None,
                             auxiliary_runtime_requests: list[dict[str, Any]] | None = None,
                             native_runtime_request_observations: list[dict[str, Any]] | None = None,
                             native_runtime_alias_reobservations: list[dict[str, Any]] | None = None,
                             inventory_alias_row_reobservations: list[dict[str, Any]] | None = None,
                             review_text_origins: list[dict[str, Any]] | None = None,
                             review_text_origin_authorities: list[dict[str, Any]] | None = None,
                             historical_verification_command_observations: list[dict[str, Any]] | None = None,
                             auxiliary_source_trees: list[dict[str, Any]] | None = None,
                             auxiliary_source_tree_reobservations: list[dict[str, Any]] | None = None,
                             source_tree_member_reobservations: list[dict[str, Any]] | None = None,
                             auxiliary_historical_source_trees: list[dict[str, Any]] | None = None) -> tuple[dict[str, str], list[str], dict[str, Any]]:
    """Derive mandatory exclusions from the evaluator's registered task.

    Project source identities come from the evaluator, never the corpus author.
    This graph supplies mandatory entries. Remaining files in this task project
    and its provenance references need the bounded inventory/classification
    audit below. Unrelated personal files elsewhere on the computer are outside
    this check's scope.
    """
    unavailable = {"completeness": "UNVERIFIED", "known_refs": [], "reason": "Evaluator-bound project and source identities are required"}
    if project_dir is None or not expected_source_hashes:
        return {}, [], unavailable
    directory = project_dir.resolve()
    project = load_project(directory)
    registered = {role: value["sha256"] for role, value in project["sources"].items()}
    _require(all(registered.get(role) == digest for role, digest in expected_source_hashes.items())
             and all(role in expected_source_hashes for role in ("screen", "speaker")),
             "Privacy inventory differs from evaluator-registered sources")
    fixture_claims, fixture_observations = _synthetic_failure_inventory(synthetic_negative_runs, repo_root, set(registered.values()), replay_ref=synthetic_replay, source_snapshots=source_snapshots)
    auxiliary_runtime_observations = _auxiliary_runtime_inventory(auxiliary_runtime_requests, directory, repo_root, set(registered.values()))
    native_runtime_observations = _native_runtime_request_inventory(native_runtime_request_observations, directory, repo_root, set(registered.values()))
    native_reobservations = _native_runtime_alias_inventory(native_runtime_alias_reobservations,
                                                            native_runtime_observations, directory, repo_root, set(registered.values()))
    native_reobservation_edges = {(row["parent"]["path"], tuple(row["edge"])): row for row in native_reobservations}
    native_reobservation_consumed: set[tuple[str, tuple[str | int, ...]]] = set()
    inventory_alias_rows = _inventory_alias_row_inventory(inventory_alias_row_reobservations, directory, repo_root,
                                                         set(registered.values()), synthetic_replay)
    inventory_alias_edges = {(row["parent"]["path"], tuple(row["edge"])): row for row in inventory_alias_rows}
    inventory_alias_consumed: set[tuple[str, tuple[str | int, ...]]] = set()
    command_history = _historical_verification_command_inventory(historical_verification_command_observations,
                                                                 directory, repo_root, set(registered.values()))
    command_history_by_key = {(row["original"]["path"], row["original"]["sha256"]): row for row in command_history}
    command_history_followed: set[tuple[str, str]] = set()
    runtime_observations = [*auxiliary_runtime_observations, *native_runtime_observations]
    _require(len({row["request"]["path"] for row in runtime_observations}) == len(runtime_observations),
             "Runtime request cannot have conflicting auxiliary/native observation roles")
    current_tree_observations = _auxiliary_source_tree_inventory(auxiliary_source_trees, directory, repo_root, set(registered.values()))
    historical_tree_observations = _auxiliary_historical_source_tree_inventory(auxiliary_historical_source_trees, directory, repo_root, set(registered.values()))
    source_tree_observations = [*current_tree_observations, *historical_tree_observations]
    source_tree_reobservations = _source_tree_reobservation_inventory(auxiliary_source_tree_reobservations,
                                                                     current_tree_observations, directory, repo_root, set(registered.values()))
    source_tree_bindings: dict[tuple[str, tuple[str | int, ...]], dict[str, Any]] = {}
    for observation in source_tree_observations:
        for binding in observation["bindings"]:
            binding_key = (binding["parent"]["path"], tuple(binding["edge"]))
            _require(binding_key not in source_tree_bindings, "Conflicting current/historical source tree origin binding")
            source_tree_bindings[binding_key] = observation
    for copied_tree in source_tree_reobservations:
        binding_key = (copied_tree["parent"]["path"], tuple(copied_tree["edge"]))
        _require(binding_key not in source_tree_bindings, "Source tree reobservation conflicts with an existing current/historical binding")
        source_tree_bindings[binding_key] = next(row for row in current_tree_observations if row["build"] == copied_tree["authority_build"])
    source_members = _source_tree_member_reobservation_inventory(source_tree_member_reobservations,
                                                                 source_tree_observations, directory, repo_root, set(registered.values()))
    source_member_edges: dict[tuple[str, tuple[str | int, ...]], dict[str, Any]] = {}
    source_member_consumed: set[tuple[str, tuple[str | int, ...]]] = set()
    for member in source_members:
        name, edge = member["parent"]["path"], tuple(member["edge"])
        for other_name, other_edge in [*source_tree_bindings, *native_reobservation_edges, *source_member_edges]:
            _require(name != other_name or (edge[:len(other_edge)] != other_edge and other_edge[:len(edge)] != edge),
                     "Source member conflicts with another bound observation subtree")
        source_member_edges[(name, edge)] = member
    runtime_edges = {(observation["request"]["path"], library["declared_reference"]["path"], library["declared_reference"]["sha256"]): library
                     for observation in runtime_observations for library in observation["libraries"]}
    # A diagnostic may repeat an already observed alias identity. This map is
    # byte authority only, not a statement that any repeated execution ran.
    runtime_aliases: dict[tuple[str, str], dict[str, Any]] = {}
    runtime_reuses: dict[tuple[str, tuple[str | int, ...]], dict[str, Any]] = {}
    for observation in auxiliary_runtime_observations:
        for library in observation["libraries"]:
            for hop in library["hops"]:
                alias_key = (hop["path"], library["target"]["sha256"])
                row = {"request": observation["request"], "library": library}
                if alias_key in runtime_aliases:
                    previous = runtime_aliases[alias_key]["library"]
                    _require(previous["target"] == library["target"] and previous["target_lstat"] == library["target_lstat"],
                             "Auxiliary runtime alias identities conflict")
                else:
                    runtime_aliases[alias_key] = row
    text_origins = _review_text_origin_inventory(review_text_origins, directory, repo_root, set(registered.values()), review_text_origin_authorities)
    text_origin_edges = {(row["parent"]["path"], tuple(item["edge"])): item["value"]
                         for row in text_origins for item in row["extractions"]}
    text_origins_consumed: set[tuple[str, tuple[str | int, ...]]] = set()
    known: dict[str, str] = {}
    refs: dict[str, dict[str, Any]] = {}
    pending: list[tuple[Path, str]] = []
    json_scheduled: set[str] = set()
    phrases: set[str] = set()
    unfollowed: list[dict[str, Any]] = []
    historical_refs: dict[tuple[str, str], dict[str, Any]] = {}
    auxiliary_observations: dict[tuple[str, str], dict[str, Any]] = {}
    auxiliary_locators: dict[tuple[str, str], dict[str, Any]] = {}
    public_candidates: dict[str, dict[str, Any]] = {}
    unresolved_sources: dict[tuple[str, str], dict[str, Any]] = {}
    source_candidates, source_candidate_commands, git_transcripts = _public_source_candidates(repo_root, set(registered.values()))
    source_paths = {str((repo_root / origin["git_path"]).resolve())
                    for origins in source_candidates.values() for origin in origins} if repo_root else set()
    source_locators: dict[tuple[str, str], dict[str, Any]] = {}
    source_snapshot_hashes: set[str] = set()
    body_candidates: dict[tuple[str, str], str] = {}
    for role, ref in (publication_bodies or {}).items():
        _require(role in {"pr_body", "release_body"}, "Unknown publication body role")
        path = _file(ref)
        body_candidates[(str(path), ref["sha256"])] = role
    auxiliary_source_edges: set[tuple[str, str]] = set()
    auxiliary_source_current: list[dict[str, Any]] = []
    _require(auxiliary_metadata_history is None or isinstance(auxiliary_metadata_history, list),
             "Auxiliary metadata history requires explicit original/snapshot locators")
    def read_auxiliary_edges(value: Any) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                auxiliary_source_edges.add((value["path"], value["sha256"]))
            for child in value.values():
                read_auxiliary_edges(child)
        elif isinstance(value, list):
            for child in value:
                read_auxiliary_edges(child)
    for locator in auxiliary_metadata_history or []:
        read_auxiliary_edges(_auxiliary_json(_file(locator["snapshot"]), repo_root, set(registered.values())))
        _auxiliary_json(Path(locator["original"]["path"]), repo_root, set(registered.values()))
    _require(source_snapshots is None or isinstance(source_snapshots, list), "Source snapshots must be explicit original/snapshot pairs")
    for locator in source_snapshots or []:
        original, snapshot = locator["original"], locator["snapshot"]
        origin = Path(original["path"])
        if locator.get("scope") == "auxiliary_execution_source":
            _require(origin.is_absolute() and origin == origin.resolve() and origin.is_relative_to(directory)
                     and origin.suffix.lower() in {".py", ".pyi"} and origin.is_file() and not origin.is_symlink()
                     and not any(origin.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                     and (str(origin), original["sha256"]) in auxiliary_source_edges,
                     "Auxiliary execution source requires an exact preserved metadata edge and canonical task source path")
            for source_path in (origin, _file(snapshot)):
                _require(source_path.stat().st_size <= MAX_UNIT_BYTES and sha256(source_path) not in set(registered.values()),
                         "Registered media/source cannot become auxiliary execution code")
                try:
                    source_text = source_path.read_text()
                    ast.parse(source_text)
                except (ValueError, SyntaxError, UnicodeDecodeError) as exc:
                    raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary execution source must be inspectable Python source bytes") from exc
                try:
                    json_source = json.loads(source_text)
                except ValueError:
                    json_source = None
                if isinstance(json_source, dict):
                    _auxiliary_json(source_path, repo_root, set(registered.values()))
        else:
            _require(locator.get("scope") is None and repo_root is not None and origin.is_absolute() and origin == origin.resolve() and any(
                origin.is_relative_to(repo_root / name) for name in ("src", "tests", "examples", "docs", "schemas", ".github")),
                "A source snapshot locator must name a canonical public source path")
        _require(original["sha256"] == snapshot["sha256"], "Preserved source snapshot differs from its original digest")
        _file(snapshot)
        source_locators[(str(origin), original["sha256"])] = snapshot
        source_snapshot_hashes.add(original["sha256"])
        if locator.get("scope") == "auxiliary_execution_source":
            auxiliary_source_current.append({"original_reference": original, "preserved_ref": snapshot,
                                             "current_ref": artifact_ref(origin), "classification": "UNCLASSIFIED",
                                             "scope": "Auxiliary execution source bytes only; independent content classification required"})
    preserved_by_hash: dict[str, dict[str, Any]] = {}
    _require(historical_artifacts is None or isinstance(historical_artifacts, list),
             "Historical private artifact locators must be an explicit list")
    for ref in historical_artifacts or []:
        _file(ref)
        preserved_by_hash[ref["sha256"]] = ref
    _require(auxiliary_metadata_history is None or isinstance(auxiliary_metadata_history, list),
             "Auxiliary metadata history requires explicit original/snapshot locators")
    for locator in auxiliary_metadata_history or []:
        original, snapshot = locator["original"], locator["snapshot"]
        original_path = Path(original["path"])
        _require(original_path.is_absolute() and original_path == original_path.resolve()
                 and original_path.is_relative_to(directory) and original_path.is_file() and not original_path.is_symlink(),
                 "Auxiliary metadata origin must be an actual canonical task file")
        _require(original["sha256"] == snapshot["sha256"] and str(_file(snapshot)) != str(original_path),
                 "Auxiliary metadata snapshot does not preserve the declared separate bytes")
        key = (str(original_path), original["sha256"])
        _require(key not in auxiliary_locators or auxiliary_locators[key] == snapshot, "Conflicting auxiliary metadata locators")
        auxiliary_locators[key] = snapshot
    _require(not set(command_history_by_key).intersection(auxiliary_locators),
             "Formal command history cannot also use the auxiliary history role")
    digests = set(registered.values())
    media_suffixes = {".mp4", ".mov", ".webm", ".mkv", ".wav", ".mp3", ".aac", ".m4a", ".flac", ".png", ".jpg", ".jpeg"}
    rank = {"review": 0, "transcript": 1, "media": 2}
    failed_measurements = []
    for path in sorted((directory / "measurements").glob("measurement-*/stdout.json")):
        _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_UNIT_BYTES,
                 "Measurement stdout is missing, linked or oversized")
        try:
            value = json.loads(path.read_bytes())
        except (ValueError, UnicodeDecodeError):
            continue  # Existing pending/malformed bookkeeping still has its own gate.
        if isinstance(value, dict) and value.get("schema_version") == "talkcut-error/v1":
            failed_measurements.append(_failed_cli_measurement(path, directory))
    failed_run_paths = {row["artifacts"]["run.json"]["path"] for row in failed_measurements}

    def explicit_transcript(value: Any) -> bool:
        return (isinstance(value, dict) and value.get("schema_version") == "transcript/v1"
                and value.get("source_sha256") in digests)

    def contains_transcript(value: Any) -> bool:
        if explicit_transcript(value):
            return True
        if isinstance(value, dict):
            return any(contains_transcript(child) for child in value.values())
        return isinstance(value, list) and any(contains_transcript(child) for child in value)

    def protect_values(value: Any, key: str = "", *, origin_path: Path | None = None,
                       edge: tuple[str | int, ...] = ()) -> None:
        """Protect this file's private strings; never follow its artifact refs."""
        selected = (str(origin_path), edge)
        if selected in text_origin_edges:
            _require(value == text_origin_edges[selected], "Review text selected value changed during phrase collection")
            text_origins_consumed.add(selected)
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                protect_values(child, child_key, origin_path=origin_path, edge=(*edge, child_key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                protect_values(child, key, origin_path=origin_path, edge=(*edge, index))
        elif (isinstance(value, str) and len(value.strip()) >= 40 and
              (key in {"text", "word", "utterance", "transcript", "sentence"}
               or (not Path(value).is_absolute() and not re.fullmatch(r"[a-f0-9]{64}", value)))):
            phrases.add(value)

    def inspect_text(path: Path, protect: bool, parse_json: bool = False) -> None:
        if path.stat().st_size > MAX_UNIT_BYTES:
            return
        try:
            body = path.read_text()
        except UnicodeDecodeError:
            return  # Exact binary bytes remain mandatory, without a text claim.
        try:
            value = json.loads(body)
        except ValueError:
            if protect:
                phrases.update(line for line in body.splitlines() if len(line.strip()) >= 40)
        else:
            if protect or explicit_transcript(value):
                # Only this closed run's exact public CLI boilerplate is
                # excluded; its error stdout and all other strings stay private.
                protect_values({key: child for key, child in value.items() if key != "reason"}
                               if str(path) in failed_run_paths else value, origin_path=path)
            if str(path) not in json_scheduled and (protect or parse_json or path.suffix.lower() == ".json"):
                pending.append((path, refs[str(path)]["kind"]))
                json_scheduled.add(str(path))

    def add(path: Path, kind: str, expected: str | None = None, *,
            historical: bool = False, parse_json: bool = False) -> None:
        _require(path.is_absolute() and path.is_file() and not path.is_symlink(), "Known private artifact is missing or is a symlink")
        name = str(path)
        ref = refs.get(name) or artifact_ref(path)
        formal_history = command_history_by_key.get((name, expected)) if expected is not None else None
        if formal_history is not None:
            _require(historical and kind == "review" and ref["sha256"] == formal_history["current"]["sha256"],
                     "Historical command bytes cannot replace current or private source identity")
            assert expected is not None
            key = (name, expected)
            if key in command_history_followed:
                return
            command_history_followed.add(key)
            for actual in (formal_history["current"], formal_history["snapshot"]):
                actual_path = Path(actual["path"])
                add(actual_path, "review", actual["sha256"], parse_json=True)
                inspect_text(actual_path, True, parse_json=True)
            return
        if (expected is not None and ref["sha256"] != expected and historical and kind == "review"
                and path in {directory / relative for relative in (
                    "acceptance.local.json", "checkpoint.local.json", "project.json", "reports/acceptance-latest.local.json")}):
            # A checkpoint can truthfully describe an earlier mutable index.
            # Only these typed bookkeeping paths can have historical versions;
            # source, transcript and render references still require exact bytes.
            _bookkeeping(path, directory)
            _require(re.fullmatch(r"[a-f0-9]{64}", expected), "Historical bookkeeping digest is invalid")
            add(path, kind)
            key = (name, expected)
            if key in historical_refs:
                return
            preserved = preserved_by_hash.get(expected)
            row: dict[str, Any] = {"path": name, "sha256": expected, "kind": kind,
                                   "current_ref": {"path": name, "sha256": ref["sha256"]}}
            historical_refs[key] = row
            if preserved is None:
                # This is a deny-list digest, not an assertion that its bytes
                # were read. No artifact ref is fabricated, and unresolved
                # history prevents an inventory/audit completeness verdict.
                known.setdefault(expected, "review")
                row.update({"status": "UNVERIFIED", "reason": "Historical bookkeeping bytes are not preserved by an explicit verified locator"})
                return
            old_path = _file(preserved)
            _require(old_path.stat().st_size <= MAX_UNIT_BYTES, "Historical bookkeeping exceeds the metadata inspection bound")
            _private_bookkeeping_payload(path.relative_to(directory).as_posix(), old_path.read_bytes(), directory=directory)
            add(old_path, kind, expected, parse_json=True)
            row.update({"status": "RESOLVED", "preserved_ref": {"path": str(old_path), "sha256": expected}})
            return
        auxiliary = auxiliary_locators.get((name, expected)) if expected is not None else None
        if expected is not None and ref["sha256"] != expected and historical and kind == "review" and auxiliary is not None:
            _require(expected not in digests and ref["sha256"] not in digests,
                     "Registered source cannot become auxiliary history")
            old_path = _file(auxiliary)
            _require(path.stat().st_size <= MAX_UNIT_BYTES and old_path.stat().st_size <= MAX_UNIT_BYTES,
                     "Auxiliary metadata exceeds the bounded JSON inspection limit")
            _auxiliary_json(old_path, repo_root, digests)
            _auxiliary_json(path, repo_root, digests)
            _require(sha256(path) == ref["sha256"], "Auxiliary current bytes changed during observation")
            key = (name, expected)
            if key in auxiliary_observations:
                return
            auxiliary_observations[key] = {"original_reference": {"path": name, "sha256": expected},
                                          "preserved_ref": auxiliary, "current_ref": {"path": name, "sha256": ref["sha256"]},
                                          "bytes_status": "OBSERVED", "claim_status": "UNVERIFIED",
                                          "classification": "review", "scope": "Private byte inventory only; no acceptance evidence validation"}
            add(path, kind, parse_json=True)
            add(old_path, kind, expected, parse_json=True)
            # This file's private strings are protected without propagating a
            # speech label to its runtime/source-code asset references.
            inspect_text(path, True, parse_json=True)
            inspect_text(old_path, True, parse_json=True)
            return
        if name in refs:
            _require(expected is None or refs[name]["sha256"] == expected, "Known private reference was relabelled")
            if rank[kind] > rank[refs[name]["kind"]]:
                refs[name]["kind"] = kind
            if rank[kind] > rank.get(known.get(ref["sha256"], ""), -1):
                known[ref["sha256"]] = kind
            if kind == "transcript" or parse_json:
                inspect_text(path, kind in {"transcript", "review"}, parse_json)
            return
        _require(len(refs) < MAX_UNITS, "Known private graph exceeds inspection limits")
        _require(expected is None or ref["sha256"] == expected, "Known private artifact differs from its registered hash")
        refs[name] = {**ref, "kind": kind}
        if rank[kind] > rank.get(known.get(ref["sha256"], ""), -1):
            known[ref["sha256"]] = kind
        if kind == "transcript" or parse_json or path.suffix.lower() == ".json":
            inspect_text(path, kind in {"transcript", "review"}, parse_json)

    def walk(value: Any, transcript: bool = False, key: str = "", *,
             origin_path: Path | None = None, edge: tuple[str | int, ...] = ()) -> None:
        alias_row = inventory_alias_edges.get((str(origin_path), edge))
        if alias_row is not None:
            _require(not transcript and not contains_transcript(value) and refs[str(origin_path)]["kind"] == "review"
                     and refs[str(origin_path)]["sha256"] == alias_row["parent"]["sha256"]
                     and json.dumps(value, sort_keys=True, separators=(",", ":"))
                     == json.dumps(alias_row["value"], sort_keys=True, separators=(",", ":")),
                     "Inventory alias private context, parent or exact row changed")
            protect_values(value)
            inventory_alias_consumed.add((str(origin_path), edge))
            return
        member = source_member_edges.get((str(origin_path), edge))
        if member is not None:
            _require(not transcript and not contains_transcript(value) and refs[str(origin_path)]["kind"] == "review"
                     and refs[str(origin_path)]["sha256"] == member["parent"]["sha256"]
                     and json.dumps(value, sort_keys=True, separators=(",", ":"))
                     == json.dumps(member["value"], sort_keys=True, separators=(",", ":")),
                     "Source member private context, parent or exact typed row changed")
            protect_values(value)
            source_member_consumed.add((str(origin_path), edge))
            return
        tree = source_tree_bindings.get((str(origin_path), edge))
        if tree is not None:
            _require(not transcript and not contains_transcript(value)
                     and refs[str(origin_path)]["kind"] == "review" and value == tree["manifest_value"],
                     "Private/formal source tree context or bound tree value changed")
            # Only this exact manifest/copy subtree has a producer-bound root.
            # Its original body stays private; truthful absolute file refs were
            # already collected in full. No other relative reference changes.
            protect_values(value)
            return
        if key in {"toolchain", "producer", "code_identity", "tools_before", "tools_after"} and not transcript and not contains_transcript(value):
            return
        if isinstance(value, dict):
            transcript = transcript or explicit_transcript(value)
            if transcript:
                protect_values(value)
            if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                path = Path(value["path"])
                code_or_archive = path.suffix.lower() in {".py", ".pyi", ".pyc", ".so", ".dylib", ".whl"} or path.name.endswith(".tar.gz")
                kind = "media" if value["sha256"] in digests else "transcript" if transcript else "media" if path.suffix.lower() in media_suffixes else "review"
                canonical_path = path if path.is_absolute() else (repo_root or directory) / path
                transcript = transcript or value["sha256"] in git_transcripts
                if transcript and kind != "media":
                    kind = "transcript"
                public_code = repo_root is not None and any(
                    canonical_path.resolve() == (repo_root / origin["git_path"]).resolve()
                    for origin in source_candidates.get(value["sha256"], []))
                fixture = fixture_claims.get((str(canonical_path), value["sha256"]))
                runtime = runtime_edges.get((str(origin_path), str(canonical_path), value["sha256"]))
                native_edge = native_reobservation_edges.get((str(origin_path), edge))
                if native_edge is not None:
                    _require(not transcript and kind != "media" and value["sha256"] not in known
                             and value == native_edge["declared_reference"]
                             and refs[str(origin_path)]["kind"] == "review"
                             and refs[str(origin_path)]["sha256"] == native_edge["parent"]["sha256"],
                             "Native repeated alias edge changed or conflicts with private source/transcript identity")
                    library = native_edge["library_identity"]
                    collect_candidate(Path(library["target"]["path"]), library["target"], library["target"])
                    native_reobservation_consumed.add((str(origin_path), edge))
                elif runtime is not None and len(edge) == 2 and edge[0] == "runtime_libraries" and type(edge[1]) is int:
                    _require(not transcript and kind != "media" and value["sha256"] not in known,
                             "Known private source/transcript/review cannot become an auxiliary runtime alias")
                    collect_candidate(Path(runtime["target"]["path"]), runtime["target"], runtime["target"])
                elif (str(canonical_path), value["sha256"]) in runtime_aliases:
                    # Re-use only exact aliases from an explicit actual runtime
                    # request; never infer authority from an extension or a new
                    # parent claim. The entire auxiliary parent stays private.
                    _require(not transcript and kind != "media" and value["sha256"] not in known,
                             "Known private source/transcript/review cannot become an auxiliary runtime alias")
                    _require(origin_path is not None and origin_path == origin_path.resolve()
                             and origin_path.is_relative_to(directory)
                             and not any(origin_path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                             and origin_path.name not in {"project.json", "acceptance.local.json"},
                             "Auxiliary runtime repeated reference has no canonical private auxiliary parent")
                    assert origin_path is not None
                    parent_ref = artifact_ref(origin_path)
                    _require(str(origin_path) in refs and refs[str(origin_path)]["kind"] == "review"
                             and parent_ref["sha256"] == refs[str(origin_path)]["sha256"],
                             "Auxiliary runtime repeated parent is not a current private review artifact")
                    _auxiliary_json(origin_path, repo_root, digests)
                    authority = runtime_aliases[(str(canonical_path), value["sha256"])]
                    library = authority["library"]
                    _require("bytes" not in value or value["bytes"] == library["target_lstat"]["size"],
                             "Auxiliary runtime repeated target byte count differs")
                    inspect_text(origin_path, True, parse_json=True)
                    collect_candidate(Path(library["target"]["path"]), library["target"], library["target"])
                    runtime_reuses[(str(origin_path), edge)] = {
                        "parent": parent_ref, "edge": list(edge), "declared_reference": value,
                        "authority_request": authority["request"], "library_identity": library,
                        "claim_status": "UNVERIFIED",
                        "scope": "Repeated auxiliary alias bytes only; no execution, AI, formal proof or publication approval"}
                elif fixture is not None:
                    _require(not transcript and value["sha256"] not in digests,
                             "Private source/transcript cannot use synthetic failure provenance")
                    for actual_ref in (fixture["preserved_original"], fixture["actual_current"]):
                        collect_candidate(Path(actual_ref["path"]), actual_ref, actual_ref)
                    # The false digest remains a labelled claim; both actual
                    # byte versions use truthful refs and remain in the corpus.
                elif transcript or value["sha256"] in known:
                    # Registered private provenance outranks suffixes, Git byte
                    # coincidences and paths inside public-code directories.
                    add(canonical_path, kind if transcript else known[value["sha256"]], value["sha256"], historical=True)
                elif not public_code and kind != "media" and (code_or_archive or value["sha256"] in source_candidates or value["sha256"] in source_snapshot_hashes
                                                              or (str(canonical_path), value["sha256"]) in body_candidates):
                    # References from an ASR/runtime/audit manifest do not make
                    # copied code or packages lecture content. Keep the exact
                    # files in the denominator as UNCLASSIFIED, never public.
                    candidate_path = path if path.is_absolute() else (repo_root or directory) / path
                    original_ref = {"path": str(candidate_path), "sha256": value["sha256"]}
                    ref = source_locators.get((str(candidate_path), value["sha256"]), original_ref)
                    if (ref is original_ref and str(candidate_path) in source_paths
                            and candidate_path == candidate_path.resolve() and not candidate_path.is_symlink()
                            and candidate_path.is_file() and sha256(candidate_path) != value["sha256"]):
                        _require(re.fullmatch(r"[a-f0-9]{64}", value["sha256"]), "Historical source digest is invalid")
                        # This historical claim has no verified bytes. Keep it
                        # outside actual artifact refs and block completeness;
                        # unrelated payload/known-private observations can run.
                        unresolved_sources[(str(candidate_path), value["sha256"])] = {
                            **original_ref, "classification": "UNCLASSIFIED", "status": "UNVERIFIED",
                            "current_ref": artifact_ref(candidate_path),
                            "reason": "Historical source bytes are not preserved by an explicit verified locator"}
                    else:
                        collect_candidate(candidate_path, original_ref, ref)
                elif not public_code and path.is_absolute() and (path.resolve().is_relative_to(directory) or value["sha256"] in digests or transcript):
                    add(path, kind, value["sha256"], historical=True)
                elif not public_code:
                    unfollowed.append({"path": value["path"], "sha256": value["sha256"], "reason": "External/relative reference is not classified by the known private graph"})
            for child_key, child in value.items():
                walk(child, transcript, child_key, origin_path=origin_path, edge=(*edge, child_key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, transcript, origin_path=origin_path, edge=(*edge, index))

    def collect_candidate(candidate_path: Path, original_ref: dict[str, Any], ref: dict[str, Any]) -> None:
        actual_path = _file(ref)
        # A JSON transcript renamed as code is still private. A
        # source locator cannot restore changed transcript bytes.
        candidate_body = None
        if actual_path.stat().st_size <= MAX_UNIT_BYTES:
            try:
                candidate_body = json.loads(actual_path.read_text())
            except (ValueError, UnicodeDecodeError):
                candidate_body = None
        if contains_transcript(candidate_body):
            add(candidate_path, "transcript", ref["sha256"])
        else:
            role = body_candidates.get((str(candidate_path), ref["sha256"]))
            candidate = {**ref, "classification": "UNCLASSIFIED",
                         "reason": "Declared publication body requires independent content classification" if role else "Code/archive or matching source bytes require independent content and provenance classification",
                         "matching_git_source_bytes": source_candidates.get(ref["sha256"], [])}
            if role:
                candidate["publication_role"] = role
            if ref is not original_ref:
                candidate["original_reference"] = original_ref
                candidate["preservation"] = "Exact historical source bytes; no current-path equivalence or public approval"
            public_candidates[str(actual_path)] = candidate
            unfollowed.append({**ref, "reason": candidate["reason"]})

    def contains_registered(value: Any) -> bool:
        if isinstance(value, str):
            return value in digests
        if isinstance(value, dict):
            return any(contains_registered(child) for child in value.values())
        if isinstance(value, list):
            return any(contains_registered(child) for child in value)
        return False

    if fixture_observations or inventory_alias_rows:
        assert repo_root is not None
        replay = (fixture_observations[0]["current_reproduction"] if fixture_observations
                  else _verified_synthetic_replay(synthetic_replay, repo_root))
        _require(not Path(replay["bundle"]["path"]).is_relative_to(directory),
                 "Synthetic replay archive must be outside the task it inventories")
        for ref in [replay["bundle"], *replay["artifacts"], *replay["external_inputs"]]:
            collect_candidate(Path(ref["path"]), ref, ref)
        for link in replay["external_tool_links"]:
            unfollowed.append({"path": link["link_path"], "sha256": link["link_bytes_sha256"], "reference_type": "symlink_literal",
                               "reason": "Exact current execution-tool alias; link bytes and canonical target both inventoried"})
    for source in auxiliary_source_current:
        original, preserved = source["original_reference"], source["preserved_ref"]
        collect_candidate(Path(original["path"]), original, preserved)
        ref = source["current_ref"]
        collect_candidate(Path(ref["path"]), ref, ref)
    for observation in runtime_observations:
        parent_ref = observation["request"]
        add(Path(parent_ref["path"]), "review", parent_ref["sha256"], parse_json=True)
        inspect_text(Path(parent_ref["path"]), True, parse_json=True)
        for library in observation["libraries"]:
            ref = library["target"]
            collect_candidate(Path(ref["path"]), ref, ref)
    for observation in command_history:
        original = observation["original"]
        add(Path(original["path"]), "review", original["sha256"], historical=True, parse_json=True)
        for actual in [observation["parent"], *observation["log_refs"]]:
            actual_path = Path(actual["path"])
            add(actual_path, "review", actual["sha256"], parse_json=True)
            inspect_text(actual_path, True, parse_json=True)
    for observation in native_reobservations:
        parent_ref = observation["parent"]
        add(Path(parent_ref["path"]), "review", parent_ref["sha256"], parse_json=True)
        inspect_text(Path(parent_ref["path"]), True, parse_json=True)
    for copied_tree in [*source_tree_reobservations, *source_members]:
        parent_ref = copied_tree["parent"]
        add(Path(parent_ref["path"]), "review", parent_ref["sha256"], parse_json=True)
        inspect_text(Path(parent_ref["path"]), True, parse_json=True)
    for observation in source_tree_observations:
        for ref in observation["parents"]:
            path = Path(ref["path"])
            if path.suffix.lower() in {".py", ".pyi"}:
                collect_candidate(path, ref, ref)
            else:
                add(path, "review", ref["sha256"], parse_json=True)
                inspect_text(path, True, parse_json=True)
        for row in [*observation["files"], *observation.get("current_files", [])]:
            ref = row["actual"]
            collect_candidate(Path(ref["path"]), ref, ref)
    # Explicit verified locators are a complete denominator even when the
    # incoming metadata edge is under a normally skipped tool/producer key.
    for (name, expected), snapshot in auxiliary_locators.items():
        path, old_path = Path(name), _file(snapshot)
        add(path, "review", expected, historical=True, parse_json=True)
        add(old_path, "review", expected, parse_json=True)
        inspect_text(path, True, parse_json=True)
        inspect_text(old_path, True, parse_json=True)
    for observation in text_origins:
        for authority_ref in observation["authority_refs"]:
            authority_path = Path(authority_ref["path"])
            collect_candidate(authority_path, authority_ref, authority_ref)
        parent_ref = observation["parent"]
        add(Path(parent_ref["path"]), "review", parent_ref["sha256"], parse_json=True)
        source = observation["source"]
        original = {"path": source["original_path"], "sha256": source["snapshot"]["sha256"]}
        collect_candidate(Path(source["original_path"]), original, source["snapshot"])
    for observation in inventory_alias_rows:
        for parent_ref in (observation["parent"], observation["typed_origin"]["parent"]):
            add(Path(parent_ref["path"]), "review", parent_ref["sha256"], parse_json=True)
        alias_identity = observation["alias_identity"]
        collect_candidate(Path(alias_identity["target"]["path"]), alias_identity["target"], alias_identity["target"])
        for hop in alias_identity["hops"]:
            unfollowed.append({"path": hop["path"], "sha256": hop["link_bytes_sha256"],
                               "reference_type": "symlink_literal",
                               "reason": "Explicit typed inventory row with verified current literal, chain and target"})
    for observation in failed_measurements:
        _require(not any(ref["sha256"] in digests for ref in observation["artifacts"].values()),
                 "Protected source identity cannot become failed CLI metadata")
        for ref in observation["artifacts"].values():
            add(Path(ref["path"]), "review", ref["sha256"], parse_json=True)
    for value in project["sources"].values():
        add(Path(value["path"]), "media", value["sha256"])
        add(Path(value["original_path"]), "media", value["sha256"])
    add(directory / "project.json", "review")
    for name in ("goal-handoff.local.json", "checkpoint.local.json", "preservation.local.json", "source-registration.local.json", "acceptance.local.json"):
        if (directory / name).is_file():
            add(directory / name, "review")
    # This namespace explicitly stores this lecture's transcript artifacts.
    # Generated public code copies and synthetic fixture trees are not inferred
    # to be confidential merely because they share the project parent directory.
    if (directory / "transcripts").is_dir():
        for path in sorted((directory / "transcripts").rglob("*")):
            if path.is_file():
                kind = "media" if path.suffix.lower() in media_suffixes else "transcript"
                add(path.absolute(), kind)
    omitted_public_work = {"implementation-staging", "snapshot", "development-env", "isolated-env", "pytest-basetemp", "recovery-example", "editorial-policy-tmp"}
    for base in ("renders", "reviews", "review", "analysis", "evidence", "capability", "checkpoints", "reports"):
        for path in (directory / base).rglob("*.json"):
            if omitted_public_work.intersection(path.relative_to(directory).parts) or path.stat().st_size > MAX_UNIT_BYTES:
                continue
            try:
                value = json.loads(path.read_text())
            except (ValueError, UnicodeDecodeError):
                continue  # Completeness remains UNVERIFIED, never a zero count.
            if contains_registered(value):
                add(path.absolute(), "transcript" if isinstance(value, dict) and value.get("schema_version") == "transcript/v1" else "review")
    for ref in (publication_bodies or {}).values():
        path = _file(ref)
        if ref["sha256"] in known:
            add(path, known[ref["sha256"]], ref["sha256"])
        else:
            collect_candidate(path, ref, ref)
    while pending:
        path, kind = pending.pop()
        try:
            value = json.loads(path.read_text())
        except (ValueError, UnicodeDecodeError):
            continue
        # Namespace/filename privacy protects this file's body, independently
        # from the provenance of files it references. Only an explicit,
        # source-bound transcript marker propagates across artifact edges.
        walk(value, origin_path=path)
    _require(text_origins_consumed == set(text_origin_edges), "Review text origin did not select a consumed private field")
    _require(text_origins == _review_text_origin_inventory(review_text_origins, directory, repo_root, digests, review_text_origin_authorities),
             "Review text origin or source changed during inventory")
    _require(not any(row["source_snapshot"]["sha256"] in known for row in text_origins),
             "Known private bytes cannot supply review text source authority")
    _require(not any(refs[row["parent"]["path"]]["kind"] != "review" for row in text_origins),
             "Review text origin parent acquired transcript or media classification")
    _require(inventory_alias_consumed == set(inventory_alias_edges),
             "Inventory alias locator did not name a consumed exact metadata edge")
    _require(inventory_alias_rows == _inventory_alias_row_inventory(inventory_alias_row_reobservations, directory,
                                                                   repo_root, digests, synthetic_replay),
             "Inventory alias origin, row, current literal, chain or target changed during inventory")
    _require(not any(row["alias_identity"]["target"]["sha256"] in known for row in inventory_alias_rows),
             "Known private source/transcript/review cannot become inventory alias target bytes")
    _require(failed_measurements == [_failed_cli_measurement(Path(row["artifacts"]["stdout.json"]["path"]), directory)
                                     for row in failed_measurements],
             "Failed CLI measurement bytes changed during inventory")
    _require(current_tree_observations == _auxiliary_source_tree_inventory(auxiliary_source_trees, directory, repo_root, digests)
             and historical_tree_observations == _auxiliary_historical_source_tree_inventory(auxiliary_historical_source_trees, directory, repo_root, digests),
             "Auxiliary current/historical source tree origin, copies or bytes changed during inventory")
    _require(source_tree_reobservations == _source_tree_reobservation_inventory(auxiliary_source_tree_reobservations,
                                                                               current_tree_observations, directory, repo_root, digests),
             "Source tree reobservation parent, recorder or authority changed during inventory")
    _require(not any(known.get(row["parent"]["sha256"]) in {"media", "transcript"} for row in source_tree_reobservations),
             "Protected source/transcript identity cannot become source tree reobservation metadata")
    _require(source_member_consumed == set(source_member_edges), "Source member locator did not name a consumed exact private edge")
    _require(source_members == _source_tree_member_reobservation_inventory(source_tree_member_reobservations,
                                                                           source_tree_observations, directory, repo_root, digests),
             "Source member parent, origin, authority or bytes changed during inventory")
    _require(not any(known.get(row["parent"]["sha256"]) in {"media", "transcript"} for row in source_members),
             "Protected source/transcript identity cannot become source member metadata")
    for reuse in runtime_reuses.values():
        _file(reuse["parent"])
    _require(auxiliary_runtime_observations == _auxiliary_runtime_inventory(auxiliary_runtime_requests, directory, repo_root, digests)
             and native_runtime_observations == _native_runtime_request_inventory(native_runtime_request_observations, directory, repo_root, digests),
             "Current runtime request, link or target changed during inventory")
    _require(native_reobservation_consumed == set(native_reobservation_edges),
             "Native repeated alias locator did not name a consumed exact metadata edge")
    _require(native_reobservations == _native_runtime_alias_inventory(native_runtime_alias_reobservations,
                _native_runtime_request_inventory(native_runtime_request_observations, directory, repo_root, digests),
                directory, repo_root, digests), "Native repeated alias parent, edge or current authority changed during inventory")
    _require(not any(library["target"]["sha256"] in known for observation in runtime_observations for library in observation["libraries"]),
             "Known private source/transcript/review cannot become an auxiliary runtime alias")
    _require(command_history == _historical_verification_command_inventory(historical_verification_command_observations,
                                                                          directory, repo_root, digests),
             "Historical command current/preserved/origin/log bytes changed during inventory")
    _require(not any(known.get(ref["sha256"]) in {"media", "transcript"}
                     for row in command_history for ref in (row["current"], row["snapshot"], row["parent"])),
             "Private media/transcript cannot become historical command metadata")
    fixture_hashes = {ref["sha256"] for observation in fixture_observations for row in observation["rows"]
                      for ref in (row["preserved_original"], row["actual_current"])}
    protected_fixture_hashes = {digest for digest in fixture_hashes if known.get(digest) in {"review", "transcript"}}
    protected_fixture_hashes.update(ref["sha256"] for ref in refs.values() if ref["sha256"] in fixture_hashes and any(
        Path(ref["path"]).is_relative_to(directory / name) for name in ("renders", "reviews", "review", "transcripts")))
    _require(not protected_fixture_hashes, "Known private media/review/transcript cannot use synthetic failure provenance")
    return known, sorted(phrases), {"completeness": "UNVERIFIED", "project": str(directory), "source_hashes": registered,
        "known_refs": list(refs.values()), "known_ref_count": len(refs), "derived_phrase_count": len(phrases),
        "unfollowed_refs": unfollowed,
        "failed_cli_measurement_observations": failed_measurements,
        "historical_refs": list(historical_refs.values()),
        "auxiliary_metadata_history": list(auxiliary_observations.values()),
        "auxiliary_execution_sources": auxiliary_source_current,
        "auxiliary_runtime_requests": auxiliary_runtime_observations,
        "native_runtime_request_observations": native_runtime_observations,
        "native_runtime_alias_reobservations": native_reobservations,
        "inventory_alias_row_reobservations": inventory_alias_rows,
        "review_text_origins": text_origins,
        "historical_verification_command_observations": command_history,
        "auxiliary_runtime_reobservations": list(runtime_reuses.values()),
        "auxiliary_source_trees": current_tree_observations,
        "auxiliary_source_tree_reobservations": source_tree_reobservations,
        "source_tree_member_reobservations": source_members,
        "auxiliary_historical_source_trees": historical_tree_observations,
        "synthetic_failure_fixtures": fixture_observations,
        "historical_unresolved": [row for row in historical_refs.values() if row["status"] != "RESOLVED"],
        "unresolved_source_candidates": list(unresolved_sources.values()),
        "public_work_candidates": [row for row in public_candidates.values() if row["sha256"] not in known],
        "public_source_candidate_commands": source_candidate_commands,
        "scope": "Registered task project files and source/derived provenance references",
        "reason": "Mandatory graph collected; exact task file inventory and separate classification audit have not yet been verified"}


def _private_bookkeeping_payload(name: str, data: bytes, *, directory: Path | None = None) -> None:
    value = json.loads(data)
    schema, content, kind = {"acceptance.local.json": ("acceptance-index/v1", "checks", dict),
                            "checkpoint.local.json": ("goal-checkpoint/v1", "criteria", dict),
                            "reports/acceptance-latest.local.json": ("goal-acceptance/v1", "criteria", list),
                            "project.json": ("talkcut-project/v1", "sources", dict)}[name]
    _require(isinstance(value, dict) and value.get("schema_version") == schema
             and value.get("owner_acceptance") == "pending" and isinstance(value.get(content), kind),
             "Changed canonical metadata is not supported private bookkeeping")
    if name == "project.json":
        from .contracts import validate_project
        validate_project(value)
        _require(directory is not None, "Project history requires the registered project context")
        assert directory is not None
        current = load_project(directory, verify_sources=False)
        identities = ("role", "path", "original_path", "sha256", "bytes", "durable")
        old_sources = {role: {key: source.get(key) for key in identities} for role, source in value["sources"].items()}
        current_sources = {role: {key: source.get(key) for key in identities} for role, source in current["sources"].items()}
        _require(old_sources == current_sources, "Historical project changed registered source identities")
        _require(len(value["events"]) == value["revision"] <= current["revision"]
                 and value["events"] == current["events"][:value["revision"]],
                 "Historical project is not a preserved revision of the current decision chain")


def _failed_cli_measurement(path: Path, directory: Path) -> dict[str, Any]:
    """Observe one closed failed worker record; this does not prove execution."""
    folder = path.parent
    _require(directory == directory.resolve() and folder.parent == directory / "measurements"
             and re.fullmatch(r"measurement-[a-f0-9]{32}", folder.name)
             and path.name in {"stdout.json", "stderr.log", "execution.json", "receipt.json", "run.json"},
             "Failed CLI measurement has a different task/run scope")
    names = ("stdout.json", "stderr.log", "execution.json", "receipt.json", "run.json")
    identities: dict[str, tuple[int, ...]] = {}
    refs: dict[str, dict[str, str]] = {}
    bodies: dict[str, Any] = {}

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            _require(key not in value, "Failed CLI measurement has duplicate JSON keys")
            value[key] = child
        return value

    def nonfinite(value: str) -> Any:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Failed CLI measurement has nonfinite JSON")

    for name in names:
        selected = folder / name
        _require(selected == selected.resolve() and selected.is_file() and not selected.is_symlink()
                 and selected.stat().st_size <= MAX_UNIT_BYTES,
                 "Failed CLI measurement artifact is missing, linked or oversized")
        identities[name] = _source_file_identity(selected.stat())
        data = selected.read_bytes()
        refs[name] = {"path": str(selected), "sha256": hashlib.sha256(data).hexdigest()}
        if name == "stderr.log":
            data.decode("utf-8")
        else:
            bodies[name] = json.loads(data, object_pairs_hook=unique, parse_constant=nonfinite)
            _require(isinstance(bodies[name], dict), "Failed CLI measurement requires JSON objects")
    _require(not (folder / "evidence.json").exists() and not (folder / "evidence.json").is_symlink(),
             "Failed CLI measurement cannot carry measurement evidence")
    output, run, receipt, log = (bodies[name] for name in ("stdout.json", "run.json", "receipt.json", "execution.json"))
    cancelled = output == {"schema_version": "talkcut-error/v1", "status": "FAIL", "code": "CANCELLED"}
    _require(cancelled or (set(output) == {"schema_version", "status", "code", "message", "retryable", "manifest_path"}
             and output["schema_version"] == "talkcut-error/v1" and output["status"] == "FAIL"
             and isinstance(output["code"], str) and bool(output["code"])
             and isinstance(output["message"], str) and output["retryable"] is False
             and output["manifest_path"] is None), "Unsupported failed CLI error payload")
    exit_code = 130 if cancelled else 2
    _require(set(run) == {"schema_version", "status", "interrupted", "run_id", "receipt", "evidence", "measurements",
                          "acceptance_status", "owner_acceptance", "reason"}
             and run["schema_version"] == "measurement-run/v1" and run["status"] == "FAIL"
             and run["interrupted"] is False and run["run_id"] == folder.name and run["receipt"] == refs["receipt.json"]
             and run["evidence"] is None and run["measurements"] is None
             and run["acceptance_status"] == "UNVERIFIED" and run["owner_acceptance"] == "pending"
             and run["reason"] == "Run acceptance evaluate to verify the complete frozen contract; measurement execution is not readiness",
             "Failed CLI run claims success or changes its exact private scope")
    _require(set(receipt) == {"schema_version", "run_id", "operation", "executor", "tool_version", "command", "started_at",
                              "finished_at", "completed", "exit_code", "log", "stdout", "stderr", "result",
                              "input_artifacts", "dependencies", "owner_acceptance"}
             and receipt["schema_version"] == "execution-receipt/v1" and receipt["run_id"] == folder.name
             and receipt["completed"] is False and type(receipt["exit_code"]) is int and receipt["exit_code"] == exit_code
             and receipt["dependencies"] == {} and receipt["owner_acceptance"] == "pending"
             and receipt["log"] == refs["execution.json"] and receipt["stdout"] == receipt["result"] == refs["stdout.json"]
             and receipt["stderr"] == refs["stderr.log"], "Failed CLI receipt is rebound or claims completed evidence")
    command = receipt["command"]
    _require(isinstance(command, list) and len(command) == 13 and all(isinstance(item, str) and item for item in command)
             and command[1:6] == ["-m", "talkcut", "acceptance", "measure-worker", str(directory)]
             and command[6] == "--check" and command[8] == "--input" and command[10] == "--contract" and command[12] == "--json"
             and receipt["executor"] == command[0] and Path(command[0]).is_absolute()
             and receipt["operation"] == "check:" + command[7]
             and isinstance(receipt["tool_version"], str) and receipt["tool_version"].startswith("talkcut ")
             and Path(command[9]).is_absolute() and str(Path(command[9]).resolve()) == command[9]
             and Path(command[11]).is_absolute() and str(Path(command[11]).resolve()) == command[11],
             "Failed CLI command is outside the exact measurement worker scope")
    inputs = receipt["input_artifacts"]
    _require(isinstance(inputs, list) and len(inputs) == 1 and isinstance(inputs[0], dict)
             and set(inputs[0]) == {"path", "sha256"} and inputs[0]["path"] == command[9],
             "Failed CLI input reference differs from its command")
    input_path = _file(inputs[0])
    _require(input_path == input_path.resolve() and input_path not in [folder / name for name in names],
             "Failed CLI input aliases its bookkeeping")
    input_identity = _source_file_identity(input_path.stat())
    _require(set(log) == {"command", "cwd", "started_at", "finished_at", "wall_seconds", "exit_code", "failure",
                          "before", "after", "stdout", "stderr"}
             and log["command"] == command and isinstance(log["cwd"], str) and Path(log["cwd"]).is_absolute()
             and str(Path(log["cwd"]).resolve()) == log["cwd"] and log["failure"] is None
             and type(log["exit_code"]) is int and log["exit_code"] == exit_code
             and log["stdout"] == refs["stdout.json"] and log["stderr"] == refs["stderr.log"]
             and type(log["wall_seconds"]) in {int, float} and math.isfinite(log["wall_seconds"]) and log["wall_seconds"] >= 0
             and all(isinstance(log[key], str) and bool(log[key]) and log[key] == receipt[key]
                     for key in ("started_at", "finished_at")), "Failed CLI log changes its exact recorded scope")
    for key in ("before", "after"):
        identity = log[key]
        _require(isinstance(identity, dict) and set(identity) == {"code_revision", "code_tree_hash", "files"}
                 and (identity["code_revision"] is None or (isinstance(identity["code_revision"], str)
                      and re.fullmatch(r"[a-f0-9]{40,64}", identity["code_revision"])))
                 and isinstance(identity["files"], dict)
                 and all(isinstance(name, str) and name and not Path(name).is_absolute() and ".." not in Path(name).parts
                         and isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
                         for name, digest in identity["files"].items())
                 and identity["code_tree_hash"] == object_hash(identity["files"]),
                 "Failed CLI recorded code identity is malformed")
    for name in names:
        selected = folder / name
        _require(_source_file_identity(selected.stat()) == identities[name] and artifact_ref(selected) == refs[name],
                 "Failed CLI measurement changed during observation")
    _require(_source_file_identity(input_path.stat()) == input_identity and artifact_ref(input_path) == inputs[0],
             "Failed CLI input changed during observation")
    return {"kind": "review", "state": "private_failed_cli_measurement", "claim_status": "UNVERIFIED",
            "scope": "Current failed worker bookkeeping bytes only; no execution, history, measurement or acceptance approval",
            "reported_exit_code": exit_code, "artifacts": refs, "input_artifacts": inputs}


def _bookkeeping(path: Path, directory: Path, *, referenced_input: bool = False) -> dict[str, Any] | None:
    """Recognize bounded private measurement/index bytes; never certify their claims."""
    try:
        relative = path.relative_to(directory)
    except ValueError:
        if referenced_input:
            _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_UNIT_BYTES,
                     "Referenced private measurement input is missing, linked or oversized")
            value = json.loads(path.read_bytes())
            if isinstance(value, dict) and value.get("schema_version") == "publication-privacy-input/v1":
                _require(isinstance(value.get("archives"), list) and isinstance(value.get("release_assets"), list)
                         and value.get("expected_head") and value.get("pr_body") and value.get("release_body"),
                         "Referenced publication input is incomplete")
                return {"kind": "review", "state": "private_referenced_publication_measurement_input"}
        return None
    states = {"acceptance.local.json": "private_acceptance_index", "checkpoint.local.json": "private_goal_checkpoint",
              "project.json": "private_project_revision", "reports/acceptance-latest.local.json": "private_acceptance_report"}
    index = relative.as_posix() in states
    measurement = (len(relative.parts) == 3 and relative.parts[0] == "measurements"
                   and re.fullmatch(r"measurement-[a-f0-9]{32}", relative.parts[1]))
    if not index and not measurement:
        return None
    _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_UNIT_BYTES,
             "Private bookkeeping artifact is missing, linked or oversized")
    data = path.read_bytes()
    if measurement:
        _require(path.name in {"stdout.json", "stderr.log", "execution.json", "receipt.json", "evidence.json", "run.json"},
                 "Unknown new measurement artifact requires another inventory audit")
        if path.name == "stderr.log":
            data.decode("utf-8")
            return {"kind": "review", "state": "private_execution_stderr"}
        if path.name == "stdout.json" and not data:
            return {"kind": "review", "state": "private_pending_stdout"}
    value = json.loads(data)
    _require(isinstance(value, dict), "Private bookkeeping must contain the expected JSON object")
    if index:
        _private_bookkeeping_payload(relative.as_posix(), data, directory=directory)
        return {"kind": "review", "state": states[relative.as_posix()]}
    if path.name == "stdout.json" and value.get("schema_version") == "talkcut-error/v1":
        return _failed_cli_measurement(path, directory)
    schemas = {"stdout.json": "measurement-result/v1", "receipt.json": "execution-receipt/v1",
               "evidence.json": "measurement-check/v1", "run.json": "measurement-run/v1"}
    if path.name == "execution.json":
        _require(isinstance(value.get("command"), list) and value.get("started_at") and value.get("finished_at")
                 and value.get("stdout", {}).get("path") == str(path.parent / "stdout.json")
                 and value.get("stderr", {}).get("path") == str(path.parent / "stderr.log"),
                 "Changed measurement execution log has a different scope")
    else:
        _require(value.get("schema_version") == schemas[path.name], "Changed measurement artifact has an unsupported schema")
        if path.name in {"receipt.json", "run.json"}:
            _require(value.get("run_id") == relative.parts[1], "Measurement bookkeeping run identity differs from its directory")
        if path.name == "receipt.json":
            _require(str(value.get("operation", "")).startswith("check:") and value.get("owner_acceptance") == "pending",
                     "Measurement receipt is outside the private bookkeeping operation")
    return {"kind": "review", "state": "private_measurement_artifact"}


def _private_archive_stream(source_fd: int, size: int, output_fd: int | None = None) -> str:
    """Consume exact opaque bytes with bounded reads; never decode private content."""
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        block = os.read(source_fd, min(PRIVATE_ARCHIVE_CHUNK_BYTES, remaining))
        _require(bool(block), "Private archive source ended before its observed size")
        remaining -= len(block)
        digest.update(block)
        if output_fd is not None:
            pending = memoryview(block)
            while pending:
                written = os.write(output_fd, pending)
                _require(written > 0, "Private archive write made no progress")
                pending = pending[written:]
    _require(not os.read(source_fd, 1), "Private archive source grew beyond its observed size")
    return digest.hexdigest()


def _preserve_private_inputs(entries: dict[str, dict[str, Any]], directory: Path,
                             archive: Path) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    """Preserve the already selected bytes; this provides no content approval.

    Failed partials stay in the private archive for diagnosis. Only complete,
    independently read-back files are published under their digest; an existing
    successful target is never overwritten. Bounds count every selected path,
    including equal-byte copies, before any deduplication or copying.
    """
    selected: list[tuple[dict[str, Any], Path, tuple[int, ...], Path]] = []
    total = 0
    for name, row in entries.items():
        if row["entry_type"] != "file" or row["classification"] not in {"review", "transcript"}:
            continue
        _require(row["path"] == name and isinstance(row["sha256"], str)
                 and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "Private archive row identity is malformed")
        path = Path(name)
        state = path.lstat()
        _require(path.is_absolute() and stat.S_ISREG(state.st_mode), "Private archive source is not a regular file")
        _require(state.st_size <= MAX_PRIVATE_ARCHIVE_FILE_BYTES, "Private archive file exceeds its preservation bound")
        total += state.st_size
        _require(total <= MAX_PRIVATE_ARCHIVE_TOTAL_BYTES, "Private archive paths exceed the total preservation bound")
        resolved = path.resolve(strict=True)
        _require(path == resolved, "Private archive source path must be canonical without ancestor aliases")
        selected.append((row, path, _source_file_identity(state), resolved))
    _require(len(selected) <= MAX_TASK_FILES, "Private archive exceeds the task file-count bound")
    _require(archive.absolute() == archive.resolve(), "Private archive path must be canonical without ancestor aliases")
    archive = archive.resolve()
    _require(not archive.is_relative_to(directory), "Private inventory archive must be outside the task project")
    archive.mkdir(parents=True, exist_ok=True)
    directory_fd = os.open(archive, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_state = os.fstat(directory_fd)

    def directory_identity(state: os.stat_result) -> tuple[int, ...]:
        # Creating archive members changes directory timestamps, not its identity.
        return state.st_dev, state.st_ino, state.st_mode, state.st_uid, state.st_gid

    def check_directory() -> None:
        _require(archive == archive.resolve(strict=True)
                 and directory_identity(archive.lstat()) == directory_identity(directory_state)
                 == directory_identity(os.fstat(directory_fd)), "Private archive directory identity changed")

    def check_source(path: Path, source_fd: int, identity: tuple[int, ...], resolved: Path) -> None:
        _require(path.resolve(strict=True) == resolved
                 and _source_file_identity(path.lstat()) == identity
                 == _source_file_identity(os.fstat(source_fd)), "Private archive source identity changed")

    preserved: dict[str, dict[str, str]] = {}
    observations: list[dict[str, Any]] = []
    verified_targets: dict[str, tuple[int, ...]] = {}
    try:
        for row, path, identity, resolved in selected:
            check_directory()
            source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            partial_fd: int | None = None
            try:
                check_source(path, source_fd, identity, resolved)
                size = os.fstat(source_fd).st_size
                digest = row["sha256"]
                try:
                    os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    # Create relative to the pinned directory, so a replaced
                    # pathname cannot redirect even a failed partial write.
                    partial_name = ".partial-" + secrets.token_hex(16)
                    partial_fd = os.open(partial_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                         0o600, dir_fd=directory_fd)
                    check_directory()
                    source_digest = _private_archive_stream(source_fd, size, partial_fd)
                    os.fsync(partial_fd)
                    _require(source_digest == digest, "Private archive source digest changed")
                    check_source(path, source_fd, identity, resolved)
                    check_directory()
                    partial_state = os.fstat(partial_fd)
                    _require(stat.S_ISREG(partial_state.st_mode) and partial_state.st_nlink == 1
                             and _source_file_identity(os.stat(partial_name, dir_fd=directory_fd, follow_symlinks=False)) == _source_file_identity(partial_state),
                             "Private archive partial identity changed")
                    os.lseek(partial_fd, 0, os.SEEK_SET)
                    _require(_private_archive_stream(partial_fd, size) == digest,
                             "Private archive partial bytes differ from the source")
                    _require(_source_file_identity(os.fstat(partial_fd)) == _source_file_identity(partial_state)
                             == _source_file_identity(os.stat(partial_name, dir_fd=directory_fd, follow_symlinks=False)), "Private archive partial changed during readback")
                    # Hard-link publication is exclusive; never replace a prior
                    # success or follow a target introduced during this copy.
                    os.link(partial_name, digest, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                            follow_symlinks=False)
                    created = True
                else:
                    source_digest = _private_archive_stream(source_fd, size)
                    _require(source_digest == digest, "Private archive source digest changed")
                    check_source(path, source_fd, identity, resolved)
                    created = False
                target_fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                try:
                    target_state = os.fstat(target_fd)
                    _require(digest not in verified_targets or _source_file_identity(target_state) == verified_targets[digest],
                             "Previously preserved private target identity changed")
                    expected_links = 2 if created else 1
                    _require(stat.S_ISREG(target_state.st_mode) and target_state.st_nlink == expected_links
                             and (target_state.st_dev, target_state.st_ino) != (identity[0], identity[1])
                             and _source_file_identity(target_state)
                             == _source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)),
                             "Private archive target is linked, replaced or aliases its source")
                    if partial_fd is not None:
                        _require(_source_file_identity(target_state) == _source_file_identity(os.fstat(partial_fd)),
                                 "Private archive publication differs from its verified partial")
                    _require(target_state.st_size == size and _private_archive_stream(target_fd, size) == digest,
                             "Preserved private audit bytes changed")
                    _require(_source_file_identity(os.fstat(target_fd)) == _source_file_identity(target_state)
                             == _source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)),
                             "Private archive target changed during readback")
                    check_source(path, source_fd, identity, resolved)
                    check_directory()
                    if partial_fd is not None:
                        # This removes only our verified successful staging name.
                        _require(_source_file_identity(os.stat(partial_name, dir_fd=directory_fd, follow_symlinks=False)) == _source_file_identity(os.fstat(partial_fd)),
                                 "Private archive partial changed before completed cleanup")
                        os.unlink(partial_name, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                    final_state = os.fstat(target_fd)
                    _require(final_state.st_nlink == 1 and _source_file_identity(final_state)
                             == _source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)),
                             "Completed private archive target changed")
                    os.lseek(target_fd, 0, os.SEEK_SET)
                    _require(_private_archive_stream(target_fd, size) == digest,
                             "Completed private archive target bytes changed")
                    _require(_source_file_identity(final_state) == _source_file_identity(os.fstat(target_fd))
                             == _source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)),
                             "Completed private archive target identity changed")
                    check_source(path, source_fd, identity, resolved)
                    check_directory()
                    verified_targets[digest] = _source_file_identity(final_state)
                    ref = {"path": str(archive / digest), "sha256": digest}
                    preserved[str(path)] = ref
                    observations.append({"source": {"path": str(path), "sha256": source_digest},
                                         "source_resolved_path": str(resolved), "source_digest_before": source_digest,
                                         "source_identity_before": identity,
                                         "source_identity_after": _source_file_identity(os.fstat(source_fd)),
                                         "target": ref, "target_identity_after": _source_file_identity(final_state),
                                         "verified_target_identity_before": _source_file_identity(target_state),
                                         "bytes": size, "created": created})
                finally:
                    os.close(target_fd)
            finally:
                if partial_fd is not None:
                    os.close(partial_fd)
                os.close(source_fd)
        # A later copy must not invalidate an earlier verified source or target.
        for index, (row, path, identity, resolved) in enumerate(selected):
            source_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                check_source(path, source_fd, identity, resolved)
                _require(_private_archive_stream(source_fd, os.fstat(source_fd).st_size) == row["sha256"],
                         "Private archive source changed before completion")
                check_source(path, source_fd, identity, resolved)
                observations[index]["source_digest_after"] = row["sha256"]
            finally:
                os.close(source_fd)
        for digest, identity in verified_targets.items():
            target_fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                _require(_source_file_identity(os.fstat(target_fd)) == identity
                         == _source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)),
                         "Private archive target changed before completion")
                _require(_private_archive_stream(target_fd, os.fstat(target_fd).st_size) == digest,
                         "Private archive target digest changed before completion")
                _require(_source_file_identity(os.fstat(target_fd)) == identity
                         == _source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)),
                         "Private archive target changed during final readback")
            finally:
                os.close(target_fd)
        # Close the whole measured interval after every potentially long read.
        # These identity checks catch changes to an earlier source/target while
        # the final later object was being hashed, without re-opening that window.
        for _row, path, identity, resolved in selected:
            _require(path.resolve(strict=True) == resolved and _source_file_identity(path.lstat()) == identity,
                     "Private archive source changed at final identity closure")
        for digest, identity in verified_targets.items():
            _require(_source_file_identity(os.stat(digest, dir_fd=directory_fd, follow_symlinks=False)) == identity,
                     "Private archive target changed at final identity closure")
        check_directory()
    finally:
        os.close(directory_fd)
    return preserved, {"schema_version": "private-byte-preservation/v1", "status": "UNVERIFIED",
                       "scope": "Exact private byte preservation only; no classification, parsing, execution or acceptance approval",
                       "selected_path_count": len(selected), "selected_path_bytes": total,
                       "whole_operation_source_and_target_revalidation": True,
                       "unique_target_count": len({ref["sha256"] for ref in preserved.values()}),
                       "limits": {"max_file_bytes": MAX_PRIVATE_ARCHIVE_FILE_BYTES,
                                  "max_total_path_bytes": MAX_PRIVATE_ARCHIVE_TOTAL_BYTES,
                                  "chunk_bytes": PRIVATE_ARCHIVE_CHUNK_BYTES},
                       "observations": observations}


def build_private_inventory(project_dir: str | Path, expected_source_hashes: dict[str, str],
                            repo_root: str | Path, *, archive_dir: str | Path | None = None,
                            historical_artifacts: list[dict[str, Any]] | None = None,
                            source_snapshots: list[dict[str, Any]] | None = None,
                            publication_bodies: dict[str, dict[str, Any]] | None = None,
                            synthetic_negative_runs: list[dict[str, Any]] | None = None,
                             synthetic_replay: dict[str, Any] | None = None,
                            auxiliary_metadata_history: list[dict[str, Any]] | None = None,
                            auxiliary_runtime_requests: list[dict[str, Any]] | None = None,
                             native_runtime_request_observations: list[dict[str, Any]] | None = None,
                             native_runtime_alias_reobservations: list[dict[str, Any]] | None = None,
                             inventory_alias_row_reobservations: list[dict[str, Any]] | None = None,
                             review_text_origins: list[dict[str, Any]] | None = None,
                             review_text_origin_authorities: list[dict[str, Any]] | None = None,
                             historical_verification_command_observations: list[dict[str, Any]] | None = None,
                             auxiliary_source_trees: list[dict[str, Any]] | None = None,
                             auxiliary_source_tree_reobservations: list[dict[str, Any]] | None = None,
                             source_tree_member_reobservations: list[dict[str, Any]] | None = None,
                             auxiliary_historical_source_trees: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Collect the finite task denominator for a separate privacy auditor.

    Save result, audit and optional archive_dir outside the task project. The
    archive preserves private text/metadata inputs which may be updated by
    normal measurement/index writing. Public runtime files, copied code and
    generated fixtures are inventory entries awaiting classification, not
    inferred confidential media. No caller-selected directory exclusion exists.
    """
    directory, root = Path(project_dir).resolve(), Path(repo_root).resolve()
    _, _, known = _known_private_inventory(directory, expected_source_hashes, root,
                                          historical_artifacts=historical_artifacts, source_snapshots=source_snapshots,
                                          publication_bodies=publication_bodies, synthetic_negative_runs=synthetic_negative_runs, synthetic_replay=synthetic_replay,
                                          auxiliary_metadata_history=auxiliary_metadata_history,
                                          auxiliary_runtime_requests=auxiliary_runtime_requests,
                                          native_runtime_request_observations=native_runtime_request_observations,
                                          native_runtime_alias_reobservations=native_runtime_alias_reobservations,
                                          inventory_alias_row_reobservations=inventory_alias_row_reobservations,
                                          review_text_origins=review_text_origins,
                                          review_text_origin_authorities=review_text_origin_authorities,
                                          historical_verification_command_observations=historical_verification_command_observations,
                                          auxiliary_source_trees=auxiliary_source_trees,
                                          auxiliary_source_tree_reobservations=auxiliary_source_tree_reobservations,
                                          source_tree_member_reobservations=source_tree_member_reobservations,
                                          auxiliary_historical_source_trees=auxiliary_historical_source_trees)
    entries = {ref["path"]: {**ref, "entry_type": "file", "classification": ref["kind"]}
               for ref in known["known_refs"]}
    for observation in [*known["auxiliary_runtime_requests"], *known["native_runtime_request_observations"]]:
        for library in observation["libraries"]:
            for hop in library["hops"]:
                row = {"path": hop["path"], "entry_type": "symlink", "target": hop["target"],
                       "sha256": hop["link_bytes_sha256"], "lstat": hop["lstat"], "classification": "UNCLASSIFIED"}
                _require(row["path"] not in entries or entries[row["path"]] == row,
                         "Auxiliary runtime link conflicts with an existing inventory role")
                entries[row["path"]] = row
    names: set[str] = set()
    unresolved: list[dict[str, Any]] = [*known["historical_unresolved"], *known["unresolved_source_candidates"]]

    alias_observations: dict[str, dict[str, Any]] = {}

    def collect(path: Path, expected: str | None = None, *, literal_link: bool = False) -> None:
        name = str(path)
        if expected is not None and not literal_link:
            try:
                aliased = (path.is_symlink() or path.parent != path.parent.resolve()
                           or entries.get(name, {}).get("entry_type") == "symlink" or name in alias_observations)
                if aliased:
                    from .native_provenance import alias_snapshot

                    observed = alias_snapshot(str(path))
                    _require(observed["target"]["sha256"] == expected, "Inventory alias target bytes changed")
                    _require(name not in alias_observations or alias_observations[name] == observed,
                             "Inventory alias chain or target identity changed")
                    alias_observations[name] = observed
                    for hop in observed["hops"]:
                        collect(Path(hop["path"]), hop["link_bytes_sha256"], literal_link=True)
                    collect(Path(observed["target"]["path"]), expected)
                    return
            except (OSError, RuntimeError) as exc:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Inventory alias is missing, cyclic or ambiguous") from exc
        if name in entries:
            row = entries[name]
            if row["entry_type"] == "symlink":
                _require(path.is_symlink() and os.readlink(path) == row["target"], "Inventory link literal changed")
                _require(expected is None or literal_link and row["sha256"] == expected, "Inventory link reference changed")
            else:
                _require(not literal_link and (expected is None or row["sha256"] == expected), "Inventory reference changed")
            return
        _require(not literal_link or path.is_symlink(), "Inventory literal-link reference is not a symlink")
        _require(len(entries) < MAX_TASK_FILES, "Task inventory exceeds the declared file-count bound")
        if path.is_symlink():
            target = os.readlink(path)
            digest = hashlib.sha256(os.fsencode(target)).hexdigest()
            _require(expected is None or literal_link and digest == expected, "Inventory link literal bytes changed")
            entries[name] = {"path": name, "entry_type": "symlink", "target": target,
                             "sha256": digest, "classification": "UNCLASSIFIED"}
        elif path.is_file():
            ref = artifact_ref(path)
            _require(expected is None or ref["sha256"] == expected, "Task provenance reference bytes changed")
            operational = _bookkeeping(path, directory)
            entries[name] = {**ref, "entry_type": "file", "classification": operational["kind"] if operational else "UNCLASSIFIED"}
        else:
            unresolved.append({"path": name, "reason": "Missing or unsupported task provenance artifact"})

    def unreadable_task(error: OSError) -> None:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Task inventory traversal is unreadable") from error

    # os.walk does not follow directory symlinks. Their actual link bytes are
    # still inventoried, and publication scanning rejects links independently.
    for parent, folders, files in os.walk(directory, followlinks=False, onerror=unreadable_task):
        for name in sorted(files + [item for item in folders if (Path(parent) / item).is_symlink()]):
            path = Path(parent) / name
            names.add(str(path))
            collect(path)
    for ref in known["unfollowed_refs"]:
        path = Path(ref["path"])
        collect(path if path.is_absolute() else root / path, ref["sha256"],
                literal_link=ref.get("reference_type") == "symlink_literal")
    current_names = {str(Path(parent) / name) for parent, folders, files in os.walk(directory, followlinks=False, onerror=unreadable_task)
                     for name in files + [item for item in folders if (Path(parent) / item).is_symlink()]}
    _require(names == current_names, "Task inventory changed while being collected")
    preserved: dict[str, dict[str, str]] = {}
    if archive_dir is not None:
        preserved, _ = _preserve_private_inputs(entries, directory, Path(archive_dir))
    return {"schema_version": "private-task-inventory/v1", "project": str(directory),
            "scope": "All files and symlinks in the registered task project, original/durable sources and recursively referenced task artifacts; unrelated computer files are outside scope",
            "dependencies": {"code_tree_hash": code_identity(root)["code_tree_hash"],
                             "source_hashes": expected_source_hashes, "project_hash": sha256(directory / "project.json")},
            "entries": [entries[name] for name in sorted(entries)], "entry_count": len(entries),
            "mandatory_private_count": sum(row["classification"] != "UNCLASSIFIED" for row in entries.values()), "unresolved": unresolved,
            "known_graph": known, "classification_status": "UNVERIFIED",
            "preserved_private_inputs": preserved,
            "limits": {"max_task_files": MAX_TASK_FILES},
            "excluded_directories": []}


def _audited_private_inventory(raw: dict[str, Any], directory: Path | None,
                               expected_sources: dict[str, str] | None, root: Path,
                               private: dict[str, str], refs: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not raw.get("private_inventory_snapshot") or not raw.get("inventory_audit"):
        return None
    _require(directory is not None and expected_sources, "Evaluator-bound task identity is required for the inventory audit")
    assert directory is not None and expected_sources is not None
    snapshot_ref = raw["private_inventory_snapshot"]
    _require(not _file(snapshot_ref).is_relative_to(directory.resolve()), "Inventory snapshot must be outside the project it inventories")
    snapshot = _json(snapshot_ref)
    current = build_private_inventory(directory, expected_sources, root,
                                      historical_artifacts=raw.get("historical_artifacts"), source_snapshots=raw.get("source_snapshots"),
                                      publication_bodies={role: raw[role] for role in ("pr_body", "release_body") if role in raw},
                                      synthetic_negative_runs=raw.get("synthetic_negative_runs"), synthetic_replay=raw.get("synthetic_replay"),
                                      auxiliary_metadata_history=raw.get("auxiliary_metadata_history"),
                                      auxiliary_runtime_requests=raw.get("auxiliary_runtime_requests"),
                                      native_runtime_request_observations=raw.get("native_runtime_request_observations"),
                                      native_runtime_alias_reobservations=raw.get("native_runtime_alias_reobservations"),
                                      inventory_alias_row_reobservations=raw.get("inventory_alias_row_reobservations"),
                                      review_text_origins=raw.get("review_text_origins"),
                                      review_text_origin_authorities=raw.get("review_text_origin_authorities"),
                                      historical_verification_command_observations=raw.get("historical_verification_command_observations"),
                                      auxiliary_source_trees=raw.get("auxiliary_source_trees"),
                                      auxiliary_source_tree_reobservations=raw.get("auxiliary_source_tree_reobservations"),
                                      source_tree_member_reobservations=raw.get("source_tree_member_reobservations"),
                                      auxiliary_historical_source_trees=raw.get("auxiliary_historical_source_trees"))
    _require(snapshot.get("schema_version") == "private-task-inventory/v1" and snapshot.get("project") == current["project"]
             and snapshot.get("scope") == current["scope"] and snapshot.get("dependencies") == current["dependencies"]
             and not snapshot.get("unresolved") and not current["unresolved"],
             "Private inventory snapshot is stale or contains unresolved task references")
    excluded = raw.get("implementation_run_ids")
    _require(isinstance(excluded, list) and excluded and all(isinstance(item, str) and item for item in excluded),
             "Inventory audit must identify its separate implementation runs")
    assert isinstance(excluded, list)
    old_entries = {row["path"]: row for row in snapshot["entries"]}
    current_entries = {row["path"]: row for row in current["entries"]}
    referenced_inputs = {str((Path(ref["path"]) if Path(ref["path"]).is_absolute() else root / ref["path"]).resolve())
                         for ref in current["known_graph"]["unfollowed_refs"]}
    _require(len(old_entries) == snapshot["entry_count"] and set(old_entries).issubset(current_entries),
             "Private inventory snapshot is stale: an audited task artifact was removed")
    for path in set(current_entries) - set(old_entries):
        _require(_bookkeeping(Path(path), directory.resolve(), referenced_input=path in referenced_inputs) is not None and current_entries[path]["entry_type"] == "file",
                 "Private inventory snapshot is stale: new non-bookkeeping artifact needs a fresh audit")
    preserved = snapshot.get("preserved_private_inputs", {})
    input_refs = []
    for row in snapshot["entries"]:
        if row["entry_type"] == "file":
            ref = preserved.get(row["path"], {"path": row["path"], "sha256": row["sha256"]})
            _require(ref.get("sha256") == row["sha256"], "Preserved audit input differs from the audited original bytes")
            _file(ref)
            input_refs.append(ref)
    extra = raw.get("inventory_classification_evidence", [])
    _require(isinstance(extra, list), "Inventory classification evidence must be an explicit artifact list")
    for ref in extra:
        _file(ref)
        input_refs.append(ref)
    from .review import verify_artifact_audit
    checked = verify_artifact_audit(raw["inventory_audit"], scope="private_inventory", snapshot_ref=snapshot_ref,
                                   input_refs=input_refs, dependencies=snapshot["dependencies"], excluded_run_ids=set(excluded))
    response = checked["response"]
    rows = response.get("private_classifications")
    _require(isinstance(rows, list) and len(rows) == snapshot["entry_count"], "Auditor did not classify the complete task denominator")
    assert isinstance(rows, list)
    entries = old_entries
    _require(len({row.get("path") for row in rows}) == len(entries), "Audit classifications are duplicated or incomplete")
    public_count = 0
    transitions = []
    for row in rows:
        entry = entries.get(row.get("path"))
        _require(entry is not None and row.get("sha256") == entry["sha256"] and row.get("reason"), "Auditor classification targets different bytes or lacks a reason")
        assert entry is not None
        kind = row.get("classification")
        _require(kind in {"media", "transcript", "review", "credentials", "public_work"}, "Unsupported inventory classification")
        if entry["classification"] != "UNCLASSIFIED":
            _require(kind == entry["classification"], "Auditor cannot remove a mandatory registered private artifact")
        if kind == "public_work":
            _require(current_entries[row["path"]] == entry, "Audited public-work exclusion changed and needs a fresh audit")
            evidence = row.get("evidence_refs")
            _require(isinstance(evidence, list) and evidence, "Public runtime/fixture/code exclusions require inspected provenance evidence")
            inspected = response.get("inspected_artifact_hashes", [])
            for ref in evidence:
                _file(ref)
                _require(ref["sha256"] in inspected, "Public-work exclusion cites evidence the auditor did not inspect")
                refs.append(ref)
            public_count += 1
        elif entry["entry_type"] == "file":
            private[entry["sha256"]] = kind
            latest = current_entries[row["path"]]
            _require(latest["entry_type"] == "file", "Private artifact type changed after the inventory audit")
            if latest["sha256"] != entry["sha256"]:
                _require(row["path"] in preserved, "Changed private artifact lacks its preserved pre-audit bytes")
                if _bookkeeping(Path(row["path"]), directory.resolve(), referenced_input=row["path"] in referenced_inputs) is None:
                    _require(latest["classification"] == kind, "Changed private artifact has lost its mandatory provenance classification")
                private[latest["sha256"]] = kind
                refs.append({"path": latest["path"], "sha256": latest["sha256"]})
                transitions.append({"path": row["path"], "action": "preserve_old_and_add_current_private_hash",
                                    "before_sha256": entry["sha256"], "after_sha256": latest["sha256"]})
        else:
            _require(current_entries[row["path"]] == entry, "Audited task symlink changed and needs another audit")
            # The link's literal bytes are distinct private content from the
            # regular target, and must enter the same exclusion corpus.
            private[entry["sha256"]] = kind
    for path in sorted(set(current_entries) - set(old_entries)):
        latest = current_entries[path]
        operational = _bookkeeping(Path(path), directory.resolve(), referenced_input=path in referenced_inputs)
        _require(operational is not None and latest["entry_type"] == "file",
                 "Private inventory snapshot is stale: new non-bookkeeping artifact needs a fresh audit")
        assert operational is not None
        private[latest["sha256"]] = "review"
        refs.append({"path": latest["path"], "sha256": latest["sha256"]})
        transitions.append({"path": path, "action": "add_mandatory_private_bookkeeping", "sha256": latest["sha256"], **operational})
    refs.extend([snapshot_ref, raw["inventory_audit"], *input_refs])
    return {"completeness": "PASS", "snapshot": snapshot_ref, "audit": raw["inventory_audit"],
            "audited_entry_count": snapshot["entry_count"], "entry_count": current["entry_count"],
            "public_work_exclusions": public_count, "private_transitions": transitions,
            "scope": current["scope"], "unresolved": []}


def verify_release_privacy(raw_ref: dict[str, Any], repo_root: str | Path, *, project_dir: Path | None = None,
                           expected_source_hashes: dict[str, str] | None = None) -> dict[str, Any]:
    """Scan actual data now. Missing remote binding or unknown bytes stays null."""
    root = Path(repo_root).resolve()
    raw = _json(raw_ref)
    _require(raw.get("schema_version") == "publication-privacy-input/v1", "Typed publication privacy inputs are required")
    before = code_identity(root)
    private: dict[str, str] = {}
    phrases: list[str] = []
    corpus_available = False
    refs = [raw_ref]
    if raw.get("private_corpus"):
        corpus = _json(raw["private_corpus"])
        _require(corpus.get("schema_version") == "private-exclusion-corpus/v1"
                 and isinstance(corpus.get("file_hashes"), list) and corpus["file_hashes"], "Private exclusion corpus is absent or unsupported")
        for row in corpus["file_hashes"]:
            _require(re.fullmatch(r"[a-f0-9]{64}", row.get("sha256", "")) and row.get("kind") in {"media", "transcript", "review", "credentials"}, "Private corpus hash or kind is invalid")
            _require(row["sha256"] not in private or private[row["sha256"]] == row["kind"], "Conflicting private corpus classifications")
            private[row["sha256"]] = row["kind"]
        phrases = corpus.get("protected_transcript_phrases", [])
        _require(isinstance(phrases, list) and all(isinstance(text, str) and len(text.strip()) >= 40 for text in phrases), "Protected transcript phrases must be explicit substantial text")
        corpus_available = True
        refs.append(raw["private_corpus"])
    submitted = set(private)
    known, derived_phrases, private_inventory = _known_private_inventory(project_dir, expected_source_hashes, root,
                                                                      historical_artifacts=raw.get("historical_artifacts"),
                                                                      source_snapshots=raw.get("source_snapshots"),
                                                                      publication_bodies={role: raw[role] for role in ("pr_body", "release_body")},
                                                                      synthetic_negative_runs=raw.get("synthetic_negative_runs"), synthetic_replay=raw.get("synthetic_replay"),
                                                                      auxiliary_metadata_history=raw.get("auxiliary_metadata_history"),
                                                                      auxiliary_runtime_requests=raw.get("auxiliary_runtime_requests"),
                                      native_runtime_request_observations=raw.get("native_runtime_request_observations"),
                                      native_runtime_alias_reobservations=raw.get("native_runtime_alias_reobservations"),
                                      inventory_alias_row_reobservations=raw.get("inventory_alias_row_reobservations"),
                                      review_text_origins=raw.get("review_text_origins"),
                                      review_text_origin_authorities=raw.get("review_text_origin_authorities"),
                                      historical_verification_command_observations=raw.get("historical_verification_command_observations"),
                                      auxiliary_source_trees=raw.get("auxiliary_source_trees"),
                                      auxiliary_source_tree_reobservations=raw.get("auxiliary_source_tree_reobservations"),
                                      source_tree_member_reobservations=raw.get("source_tree_member_reobservations"),
                                      auxiliary_historical_source_trees=raw.get("auxiliary_historical_source_trees"))
    private_inventory["missing_from_submitted_corpus"] = sorted(set(known) - submitted)
    private.update(known)
    phrases = sorted(set(phrases) | set(derived_phrases))
    # Nonempty caller-supplied hashes never establish the denominator. An exact
    # current task inventory plus separately executed classification audit can.
    audited = _audited_private_inventory(raw, project_dir, expected_source_hashes, root, private, refs)
    _require(not any(row["source_snapshot"]["sha256"] in private for row in private_inventory.get("review_text_origins", [])),
             "Explicit or audited private corpus bytes cannot supply review text source authority")
    corpus_complete = audited is not None
    if audited is not None:
        private_inventory["classification_audit"] = audited
        private_inventory["completeness"] = "PASS"
    refs.extend({"path": ref["path"], "sha256": ref["sha256"]} for ref in private_inventory["known_refs"])
    scanner = Scan(private, phrases)
    traces: list[dict[str, Any]] = []
    inventory = _git_inventory(root, raw["expected_head"], scanner, traces)
    git_complete = not scanner.unknown
    archives = _asset_refs(raw.get("archives"))
    _require(any(name.endswith(".whl") for name in archives) and any(name.endswith(".tar.gz") for name in archives), "Both actual wheel and source distribution must be scanned")
    assets = _asset_refs(raw.get("release_assets"))
    for category, items in (("package", archives), ("release_asset", assets)):
        for name, ref in items.items():
            path = _file(ref)
            if path.stat().st_size > MAX_UNIT_BYTES:
                scanner.unverified(category + ":" + name, "Publication artifact exceeds inspection byte bound")
            else:
                scanner.payload(path.read_bytes(), category + ":" + name, path=name)
            refs.append(ref)
    for kind in ("pr_body", "release_body"):
        path = _file(raw.get(kind))
        if path.stat().st_size > MAX_UNIT_BYTES:
            scanner.unverified(kind, "Publication body exceeds inspection bound")
        else:
            scanner.payload(path.read_bytes(), kind)
        refs.append(raw[kind])
    remote = _remote(raw, root, assets, traces)
    final_head = _command(["git", "rev-parse", "--verify", "HEAD"], root, traces).decode().strip()
    _require(final_head == inventory["head"] and code_identity(root)["code_tree_hash"] == before["code_tree_hash"], "Code or publication HEAD changed during scanning")
    complete = not scanner.unknown
    ready = complete and corpus_complete and remote is not None
    measured = {"tracked_content_scanned": True if git_complete else None,
                "assets_scanned": True if complete and remote else None, "body_scanned": True if complete and remote else None,
                "private_media_count": len(scanner.media) if ready else None,
                "private_transcript_count": len(scanner.transcripts) if ready else None,
                "credentials_count": len(scanner.credentials) if ready else None}
    passed = ready and not scanner.findings and all(value is not None for value in measured.values())
    return {"schema_version": "publication-privacy-result/v1", "status": "PASS" if passed else "FAIL" if scanner.findings else "UNVERIFIED",
            "measurements": measured, "dependencies": {"code_tree_hash": before["code_tree_hash"], "public_git_head": inventory["head"]},
            "evidence_refs": refs, "git": inventory, "remote_publication": remote, "units": scanner.units,
            "observed_matches": {"private_media_count": len(scanner.media), "private_transcript_count": len(scanner.transcripts), "credentials_count": len(scanner.credentials)},
            "unknown": scanner.unknown, "findings": [{**item, "severity": "P1", "status": "FAIL"} for item in scanner.findings], "commands": traces,
            "private_inventory": private_inventory,
            "coverage": {"unique_content_units": len(scanner.units), "inspected_bytes": scanner.total_bytes,
                         "all_selected_payloads_read": complete, "private_corpus_available": corpus_available,
                         "private_corpus_complete": True if corpus_complete else None},
            "limits": {"max_unit_bytes": MAX_UNIT_BYTES, "max_total_bytes": MAX_TOTAL_BYTES,
                       "max_units": MAX_UNITS, "max_depth": MAX_DEPTH, "max_commits": MAX_COMMITS},
            "user_ready": False}


def prepare_synthetic_failure_replay(repo_root: str | Path, output_dir: str | Path) -> dict[str, str]:
    """Persist one fixed public generator run; inventory never regenerates it."""
    import sys

    from . import evaluator_negative as negative
    from .project import atomic_json
    from .verification import _recovery_result, _run_command

    repo, archive = Path(repo_root).resolve(), Path(output_dir).absolute()
    _require(archive == archive.resolve() and not archive.exists()
             and not any(archive.is_relative_to(repo / name) for name in ("src", "tests", "schemas", "docs", "examples", ".github")),
             "Synthetic replay requires a new canonical private archive outside public code")
    archive.mkdir(parents=True)
    identity = {"code_identity": code_identity(repo), "producer": artifact_ref(Path(__file__).resolve()),
                "harness": artifact_ref(Path(negative.__file__).resolve()), "generator": artifact_ref(repo / "examples/recovery.py"),
                "python": artifact_ref(Path(sys.executable).resolve()), "toolchain": negative.doctor()}
    atomic_json(archive / "before.json", identity)
    snapshots = []
    for name, digest in identity["code_identity"]["files"].items():
        path = archive / "source" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((repo / name).read_bytes())
        _require(sha256(path) == digest, "Code changed while preserving replay sources")
        snapshots.append({"original": {"path": str(repo / name), "sha256": digest}, "snapshot": artifact_ref(path)})
    producer = archive / "source" / "privacy-producer.py"
    producer.write_bytes(Path(__file__).read_bytes())
    _require(sha256(producer) == identity["producer"]["sha256"], "Replay producer changed while preserving source")
    target = archive / "generated"
    argv = [sys.executable, str(repo / "examples/recovery.py"), str(target)]
    execution = _run_command("fixed-generator", argv, repo, archive, dict(os.environ), timeout=1200)
    _require(execution["exit_code"] == 0 and not execution["timed_out"] and not execution["interrupted"]
             and not _file(execution["stderr"]).read_text().strip(), "Fixed public generator failed; partial archive is preserved")
    _recovery_result(target / "result.json")
    after = {"code_identity": code_identity(repo), "producer": artifact_ref(Path(__file__).resolve()),
             "harness": artifact_ref(Path(negative.__file__).resolve()), "generator": artifact_ref(repo / "examples/recovery.py"),
             "python": artifact_ref(Path(sys.executable).resolve()), "toolchain": negative.doctor()}
    atomic_json(archive / "after.json", after)
    _require(identity == after, "Replay code or toolchain changed during generation")
    artifacts: list[dict[str, str]] = []
    for path in sorted(archive.rglob("*")):
        _require(not path.is_symlink(), "Replay generated a symlink")
        if path.is_file():
            _require(len(artifacts) < MAX_UNITS, "Replay archive exceeds inspection limits")
            artifacts.append(artifact_ref(path))
    bundle = {"schema_version": "synthetic-privacy-replay/v1", "scope": "Fixed generated fixture bytes and execution only; classification and AV remain unverified",
              "completed": True, "test_only": True, "owner_acceptance": "pending", "audiovisual_review": "UNVERIFIED",
              "before": artifact_ref(archive / "before.json"), "after": artifact_ref(archive / "after.json"),
              "source_snapshots": snapshots, "producer_snapshot": artifact_ref(producer),
              "execution": execution["receipt"], "fixture": artifact_ref(target / "result.json"),
              "artifacts": artifacts, "artifact_count": len(artifacts)}
    atomic_json(archive / "bundle.json", bundle)
    return artifact_ref(archive / "bundle.json")


def _verified_synthetic_replay(replay_ref: dict[str, Any] | None, repo: Path) -> dict[str, Any]:
    import sys
    from datetime import datetime

    from . import evaluator_negative as negative
    from .measurement_checks import verify_roundtrip
    from .verification import _recovery_result

    _require(isinstance(replay_ref, dict), "Preserved synthetic replay bundle is required; run preparation first")
    assert replay_ref is not None
    def metadata(ref: dict[str, Any]) -> Any:
        path = _file(ref)
        _require(path.stat().st_size <= MAX_UNIT_BYTES, "Synthetic replay metadata/log exceeds the inspection bound")
        return _json(ref)

    bundle_path = _file(replay_ref)
    archive = bundle_path.parent
    bundle = metadata(replay_ref)
    _require(bundle.get("schema_version") == "synthetic-privacy-replay/v1" and bundle.get("completed") is True
             and bundle.get("test_only") is True and bundle.get("owner_acceptance") == "pending"
             and bundle.get("audiovisual_review") == "UNVERIFIED", "Synthetic replay is not completed bounded fixture evidence")
    expected = {"code_identity": code_identity(repo), "producer": artifact_ref(Path(__file__).resolve()),
                "harness": artifact_ref(Path(negative.__file__).resolve()), "generator": artifact_ref(repo / "examples/recovery.py"),
                "python": artifact_ref(Path(sys.executable).resolve()), "toolchain": negative.doctor()}
    _require(metadata(bundle["before"]) == expected == metadata(bundle["after"]), "Synthetic replay code/harness/toolchain is stale")
    artifacts = bundle.get("artifacts")
    _require(isinstance(artifacts, list) and 0 < len(artifacts) == bundle.get("artifact_count") <= MAX_UNITS,
             "Synthetic replay artifact denominator is invalid")
    paths = set()
    for ref in artifacts:
        path = _file(ref)
        _require(path.is_relative_to(archive) and path != bundle_path and str(path) not in paths,
                 "Synthetic replay artifact is duplicated or outside its archive")
        paths.add(str(path))
    actual_paths = set()
    for path in archive.rglob("*"):
        _require(not path.is_symlink(), "Synthetic replay archive contains a symlink")
        if path.is_file() and path != bundle_path:
            actual_paths.add(str(path))
    _require(paths == actual_paths, "Synthetic replay archive changed or contains unlisted files")
    _require(all(str(_file(bundle[name])) in paths for name in ("before", "after", "execution", "fixture", "producer_snapshot")),
             "Synthetic replay evidence is outside its complete archive")
    snapshots = {row["original"]["path"]: row for row in bundle["source_snapshots"]}
    _require(len(snapshots) == len(bundle["source_snapshots"]) and set(snapshots) == {str(repo / name) for name in expected["code_identity"]["files"]},
             "Synthetic replay source snapshot denominator differs from the executed code")
    for name, digest in expected["code_identity"]["files"].items():
        row = snapshots[str(repo / name)]
        _require(row["original"]["sha256"] == row["snapshot"]["sha256"] == digest
                 and str(_file(row["snapshot"])) in paths, "Synthetic replay source snapshot changed")
    _require(bundle["producer_snapshot"]["sha256"] == expected["producer"]["sha256"]
             and str(_file(bundle["producer_snapshot"])) in paths, "Synthetic replay producer snapshot changed")
    def artifact_edges(value: Any) -> list[dict[str, str]]:
        found = []
        if isinstance(value, dict):
            if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                found.append({"path": value["path"], "sha256": value["sha256"]})
            for child in value.values():
                found.extend(artifact_edges(child))
        elif isinstance(value, list):
            for child in value:
                found.extend(artifact_edges(child))
        return found

    allowed_external = {(ref["path"], ref["sha256"]): ref for ref in artifact_edges(expected)}
    tool_external = {(ref["path"], ref["sha256"]) for ref in artifact_edges(expected["toolchain"])}
    allowed_external.update({(str(repo / name), digest): {"path": str(repo / name), "sha256": digest}
                             for name, digest in expected["code_identity"]["files"].items()})
    source_contents = {row["snapshot"]["path"] for row in bundle["source_snapshots"]} | {bundle["producer_snapshot"]["path"]}
    external_inputs: dict[str, dict[str, str]] = {}
    external_tool_links: dict[str, dict[str, Any]] = {}
    fixture_path = _file(bundle["fixture"])
    target = archive / "generated"
    _require(fixture_path == target / "result.json", "Synthetic replay fixture has an unrelated path")
    fixture = metadata(bundle["fixture"])
    _require(fixture.get("project") == str(target / "project"), "Synthetic replay project has an unrelated path")
    project = metadata(artifact_ref(target / "project" / "project.json"))
    media_paths = {str(target / "synthetic.mp4")}
    for source in project["sources"].values():
        media_paths.update((source["path"], source["original_path"]))
    media_paths.update(value["output"]["path"] for value in fixture["outputs"].values())
    _require(media_paths <= paths, "Synthetic replay media is outside its complete archive")
    # Only the exact declared source/output media (fully decoded below) may be
    # larger than the metadata bound. An extension cannot classify a payload.
    # Logs retain their metadata role even if a reference borrows a media or
    # source-snapshot path. Collect roles before inspecting those payloads.
    payloads: dict[str, Any] = {}
    typed_logs: set[str] = set()

    def log_edges(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"stdout", "stderr"} and isinstance(child, dict) and isinstance(child.get("path"), str):
                    typed_logs.add(str(_file(child)))
                log_edges(child)
        elif isinstance(value, list):
            for child in value:
                log_edges(child)

    for path in [bundle_path, *(Path(name) for name in paths if name not in source_contents)]:
        _require(path.stat().st_size <= MAX_UNIT_BYTES or str(path) in media_paths,
                 "Synthetic replay metadata/log exceeds the inspection bound")
        if path.stat().st_size > MAX_UNIT_BYTES:
            continue  # Exact source/output media remain in the byte denominator.
        try:
            payloads[str(path)] = json.loads(path.read_bytes())
        except (ValueError, UnicodeDecodeError):
            continue
        log_edges(payloads[str(path)])
    pending_logs = set(typed_logs)
    inspected_logs: set[str] = set()
    while pending_logs:
        name = pending_logs.pop()
        path = Path(name)
        _require(name in paths, "Synthetic replay command log is outside its verified artifact closure")
        _require(path.stat().st_size <= MAX_UNIT_BYTES, "Synthetic replay metadata/log exceeds the inspection bound")
        inspected_logs.add(name)
        if name not in payloads:
            try:
                payloads[name] = json.loads(path.read_bytes())
            except (ValueError, UnicodeDecodeError):
                continue
            log_edges(payloads[name])
        pending_logs.update(typed_logs - inspected_logs)
    for payload in payloads.values():
        for ref in artifact_edges(payload):
            if ref["path"] in paths:
                _file(ref)
            else:
                _require((ref["path"], ref["sha256"]) in allowed_external,
                         "Synthetic replay reference is outside its verified artifact closure")
                if Path(ref["path"]).is_symlink():
                    _require((ref["path"], ref["sha256"]) in tool_external,
                             "Only an exact current execution-tool identity may describe an alias")
                    target_ref = artifact_ref(Path(ref["path"]).resolve())
                    _require(target_ref["sha256"] == ref["sha256"], "Execution-tool alias target bytes changed")
                    link_text = os.readlink(ref["path"])
                    external_tool_links[ref["path"]] = {"link_path": ref["path"], "link_target": link_text,
                                                       "link_bytes_sha256": hashlib.sha256(os.fsencode(link_text)).hexdigest(),
                                                       "declared_target_sha256": ref["sha256"], "actual_target": target_ref}
                    external_inputs[target_ref["path"]] = target_ref
                else:
                    _file(ref)
                    external_inputs[ref["path"]] = ref
    execution = metadata(bundle["execution"])
    _require(all(str(_file(execution[name])) in paths for name in ("stdout", "stderr")),
             "Synthetic replay command logs are outside the archive")
    _require(execution.get("schema_version") == "verification-command/v1"
             and execution.get("argv") == [sys.executable, str(repo / "examples/recovery.py"), str(target)]
             and execution.get("cwd") == str(repo) and execution.get("name") == "fixed-generator"
             and execution.get("exit_code") == 0 and execution.get("timed_out") is False
             and execution.get("interrupted") is False and execution.get("error") is None
             and datetime.fromisoformat(execution["started_at"]) <= datetime.fromisoformat(execution["finished_at"]),
             "Synthetic replay command is unrelated, failed, or incomplete")
    _require(not _file(execution["stderr"]).read_text().strip()
             and metadata(execution["stdout"]) == {"technical_roundtrip": "PASS", "result": str(fixture_path), "test_only": True, "audiovisual_review": "UNVERIFIED"},
             "Synthetic replay raw generator output differs from its actual result")
    checked = _recovery_result(fixture_path)
    verify_roundtrip(fixture)
    steps = metadata(fixture["executions"])
    calls = [node for node in ast.walk(ast.parse((repo / "examples/recovery.py").read_text()))
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "command"
             and len(node.args) == 2 and isinstance(node.args[0], ast.Constant) and node.args[0].value == "01-generate"]
    _require(len(calls) == 1 and isinstance(calls[0].args[1], ast.List), "Fixed public generator invocation is ambiguous")
    argv_node = calls[0].args[1]
    assert isinstance(argv_node, ast.List)
    fixed_argv = ast.literal_eval(ast.List(elts=argv_node.elts[:-1], ctx=ast.Load()))
    _require(len(steps) == 14 and steps[0]["name"] == "01-generate" and steps[0]["argv"][-1] == str(target / "synthetic.mp4"),
             "Synthetic replay actual generation ledger is incomplete")
    _require(steps[0]["argv"][:-1] == fixed_argv, "Synthetic replay generation differs from the exact public source command")
    return {"bundle": replay_ref, "artifacts": artifacts, "external_inputs": list(external_inputs.values()),
            "external_tool_links": list(external_tool_links.values()), "execution": bundle["execution"],
            "fixture": bundle["fixture"], "executions": fixture["executions"], "technical_validation": checked,
            "generator": expected["generator"], "harness": expected["harness"], "code_tree_hash": expected["code_identity"]["code_tree_hash"],
            "source_sha256": sha256(target / "synthetic.mp4"), "generator_argv_prefix": steps[0]["argv"][:-1],
            "output_hashes": {stage: value["output"]["sha256"] for stage, value in fixture["outputs"].items()},
            "scope": "Preserved actual fixed-generator replay; historical execution identities remain unchanged"}


def _historical_synthetic_json(ref: Any) -> Any:
    """Bounded canonical historical metadata; duplicate JSON is never authority."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            _require(key not in value, "Historical synthetic JSON contains duplicate keys")
            value[key] = item
        return value

    path = _file(ref)
    _require(path == path.resolve() and path == Path(os.path.abspath(path))
             and path.stat().st_size <= MAX_UNIT_BYTES,
             "Historical synthetic metadata is noncanonical or oversized")
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Historical synthetic metadata is not JSON") from exc


def _historical_synthetic_harnesses(source_snapshots: list[dict[str, Any]] | None,
                                    run_refs: list[dict[str, Any]], repo: Path,
                                    registered: set[str]) -> dict[tuple[str, str], dict[str, Any]]:
    """A source-snapshot extension binds only exact retained historical runs.

    Git bytes, a complete old code identity and current technical grammar are
    origin observations. They do not attest any historical process execution.
    """
    from . import evaluator_negative as negative

    _require(source_snapshots is None or isinstance(source_snapshots, list),
             "Historical synthetic source snapshots must be an explicit list")
    selected = [row for row in source_snapshots or []
                if isinstance(row, dict) and "historical_synthetic_harness" in row]
    _require(len(selected) <= 32, "Historical synthetic harness inventory exceeds its bound")
    known_runs = {(ref["path"], ref["sha256"]) for ref in run_refs}
    _require(not selected or len(known_runs) == len(run_refs), "Historical synthetic run inventory has duplicate references")
    result: dict[tuple[str, str], dict[str, Any]] = {}

    def syntax_nodes(source: bytes) -> dict[str, ast.AST]:
        nodes: dict[str, ast.AST] = {}
        try:
            syntax = ast.parse(source)
        except (SyntaxError, ValueError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Historical harness is not Python source") from exc
        for node in syntax.body:
            name = None
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                name = node.name
            elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                  and isinstance(node.targets[0], ast.Name)):
                name = node.targets[0].id
            if name:
                _require(name not in nodes, "Historical harness has duplicate top-level definitions")
                nodes[name] = node
        return nodes

    current_nodes = syntax_nodes(Path(negative.__file__).read_bytes())
    for locator in selected:
        _require(set(locator) == {"original", "snapshot", "historical_synthetic_harness"},
                 "Historical synthetic source locator has unsupported fields")
        origin, snapshot, binding = locator["original"], locator["snapshot"], locator["historical_synthetic_harness"]
        for ref in (origin, snapshot):
            _require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}
                     and isinstance(ref["path"], str) and isinstance(ref["sha256"], str)
                     and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]) is not None,
                     "Historical synthetic source requires exact typed artifact references")
        expected_path = repo / "src/talkcut/evaluator_negative.py"
        _require(repo == repo.resolve() and expected_path == Path(negative.__file__).resolve(),
                 "Historical harness origin is not the current canonical repository module path")
        _require(origin["path"] == str(expected_path) and expected_path == expected_path.resolve()
                 and origin["sha256"] == snapshot["sha256"] and origin["sha256"] not in registered,
                 "Historical harness original path or preserved digest differs")
        preserved = _file(snapshot)
        _require(preserved != expected_path and preserved == preserved.resolve()
                 and preserved == Path(os.path.abspath(preserved)) and preserved.stat().st_size <= MAX_UNIT_BYTES,
                 "Historical harness requires a separate canonical bounded snapshot")
        _require(isinstance(binding, dict) and set(binding) == {"schema_version", "git_revision", "runs"}
                 and binding["schema_version"] == "historical-synthetic-harness/v1"
                 and isinstance(binding["git_revision"], str)
                 and re.fullmatch(r"[a-f0-9]{40}", binding["git_revision"]) is not None
                 and isinstance(binding["runs"], list) and 0 < len(binding["runs"]) <= 32,
                 "Historical harness needs a closed Git revision and exact run bindings")
        revision = binding["git_revision"]
        traces: list[dict[str, Any]] = []
        _require(_command(["git", "rev-parse", "--verify", revision + "^{commit}"], repo, traces).decode().strip() == revision,
                 "Historical harness revision is not an exact commit")
        listing = _command(["git", "ls-tree", "-r", "-z", "--full-tree", revision], repo, traces)
        files: dict[str, str] = {}
        harness_bytes = None
        total = 0
        for row in listing.split(b"\0"):
            if not row:
                continue
            header, raw_name = row.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split()
            name = raw_name.decode("utf-8")
            path = PurePosixPath(name)
            included = (path.parts[0] in {"src", "tests", "schemas", ".github", "examples"}
                        and "__pycache__" not in path.parts and path.suffix not in {".pyc", ".pyo"}) or name in {
                            "pyproject.toml", "uv.lock", ".python-version", "pytest.ini", "mypy.ini", "ruff.toml", ".ruff.toml"}
            if not included:
                continue
            _require(kind == "blob" and mode in {"100644", "100755"} and name not in files
                     and not path.is_absolute() and ".." not in path.parts and len(files) < MAX_UNITS,
                     "Historical code identity contains a nonregular, duplicate or unsupported member")
            content = _command(["git", "cat-file", "blob", oid], repo, traces)
            total += len(content)
            _require(total <= MAX_TOTAL_BYTES, "Historical code identity exceeds its complete byte bound")
            files[name] = hashlib.sha256(content).hexdigest()
            if name == "src/talkcut/evaluator_negative.py":
                harness_bytes = content
        _require(files.get("src/talkcut/evaluator_negative.py") == origin["sha256"]
                 and harness_bytes == preserved.read_bytes(), "Historical harness snapshot does not match its exact Git blob")
        assert harness_bytes is not None
        old_nodes = syntax_nodes(harness_bytes)
        grammar = ("SCOPES", "PAIR_NAMES", "REASONS", "SOURCE_MUTATION", "MALFORMED_PROJECT",
                   "_file", "_json", "_evaluator", "_ConservationReached", "_TimelineProbe", "_timeline_probe",
                   "_probe_command", "_pair", "_same_except", "_mp4_packet_prefix", "_verify_interrupted_packets", "_mutation")
        _require(all(name in old_nodes and name in current_nodes
                     and ast.dump(old_nodes[name], include_attributes=False) == ast.dump(current_nodes[name], include_attributes=False)
                     for name in grammar), "Historical harness technical grammar differs from the supported current controls")
        missing_node = old_nodes.get("MISSING_CONTROLS")
        _require(isinstance(missing_node, ast.Assign), "Historical missing-control declarations are absent")
        assert isinstance(missing_node, ast.Assign)
        missing = ast.literal_eval(missing_node.value)
        _require(isinstance(missing, dict) and set(missing) == set(negative.MISSING_CONTROLS)
                 and all(isinstance(reason, str) and bool(reason) for reason in missing.values()),
                 "Historical missing controls have an unsupported denominator")
        code = {"code_revision": revision, "code_tree_hash": object_hash(files), "files": files}
        for run_ref in binding["runs"]:
            _require(isinstance(run_ref, dict) and set(run_ref) == {"path", "sha256"}
                     and isinstance(run_ref["path"], str) and isinstance(run_ref["sha256"], str)
                     and (run_ref["path"], run_ref["sha256"]) in known_runs,
                     "Historical harness names an unscoped or malformed run")
            key = (run_ref["path"], run_ref["sha256"])
            _require(key not in result, "Historical synthetic run has duplicate harness bindings")
            raw = _historical_synthetic_json(run_ref)
            request = _historical_synthetic_json(raw["request"])
            receipt_ref = artifact_ref(Path(run_ref["path"]).parent / "receipt.json")
            receipt = _historical_synthetic_json(receipt_ref)
            _require(raw.get("harness") == request.get("harness") == receipt.get("harness") == origin
                     and request.get("code_identity") == code
                     and raw.get("dependencies") == request.get("dependencies") == receipt.get("dependencies")
                     and raw["dependencies"].get("code_tree_hash") == code["code_tree_hash"]
                     and receipt.get("result") == run_ref and receipt.get("request") == raw["request"]
                     and receipt.get("status") == raw.get("status") == "UNVERIFIED"
                     and receipt.get("test_only") is True and receipt.get("final_ac12_audit") is False,
                     "Historical original run/request/receipt/source/Git identities do not agree")
            result[key] = {"locator": locator, "run": run_ref, "request": raw["request"], "receipt": receipt_ref,
                           "original_harness": origin, "snapshot": snapshot, "historical_code_identity": code,
                           "historical_missing_controls": missing, "git_commands": traces,
                           "classification": "UNCLASSIFIED", "execution_status": "UNVERIFIED"}
    return result


def _replay_historical_synthetic_controls(raw: dict[str, Any], fixture: dict[str, Any],
                                         history: dict[str, Any], repo: Path) -> dict[str, Any]:
    """Current fixed technical probes over preserved originals, without AV credit."""
    from datetime import datetime

    from . import evaluator_negative as negative
    from .contracts import CHECK_REQUIREMENTS

    _require(raw.get("positive_controls") is None and raw.get("status") == "UNVERIFIED",
             "Historical diagnostic controls cannot import current positives or aggregate PASS")
    request = _historical_synthetic_json(raw["request"])
    _require(request.get("scope") == negative.SCOPES and request.get("positive_controls") is None,
             "Historical diagnostic scope differs from the seven supported technical controls")
    cases = raw.get("cases")
    _require(isinstance(cases, dict) and set(cases) == set(CHECK_REQUIREMENTS["evaluator_negative"]),
             "Historical synthetic controls must retain the entire ten-case denominator")
    assert isinstance(cases, dict)
    root = Path(history["run"]["path"]).parent
    refs = raw.get("artifacts")
    _require(isinstance(refs, list) and 0 < len(refs) <= MAX_UNITS,
             "Historical synthetic artifact denominator is absent")
    assert isinstance(refs, list)
    current_code = code_identity(repo)

    def snapshot() -> list[dict[str, Any]]:
        observed = []
        names: set[str] = set()
        for ref in refs:
            path = _file(ref)
            _require(path == path.resolve() and path.is_relative_to(root) and str(path) not in names,
                     "Historical synthetic artifact is duplicated, aliased or outside its original run")
            names.add(str(path))
            observed.append({"reference": ref, "identity": _source_file_identity(path.stat())})
        physical = set()
        for path in root.rglob("*"):
            _require(not path.is_symlink(), "Historical synthetic run acquired a linked member")
            if path.is_file():
                physical.add(str(path))
        excluded = {str(root / name) for name in ("attempt.json", "result.json", "receipt.json")}
        _require(names == physical - excluded, "Historical synthetic run has omitted or extra physical artifacts")
        for ref in [history["run"], history["request"], history["receipt"], history["snapshot"], raw["fixture"]]:
            path = _file(ref)
            observed.append({"reference": ref, "identity": _source_file_identity(path.stat())})
        return observed

    before = snapshot()
    artifact_keys = {(ref["path"], ref["sha256"]) for ref in refs}

    def retained(ref: Any) -> None:
        _require(isinstance(ref, dict) and (ref.get("path"), ref.get("sha256")) in artifact_keys,
                 "Historical technical selected proof is outside its complete artifact denominator")

    for ref in [raw["request"], raw["fixture"],
                *[raw[name][key] for name in ("fixture_execution", "identity_initialization") for key in ("stdout", "stderr")]]:
        retained(ref)
    processes = []
    measured: dict[str, bool | None] = {}
    for case_id in CHECK_REQUIREMENTS["evaluator_negative"]:
        case = cases[case_id]
        if case_id in negative.MISSING_CONTROLS:
            _require(case == {"status": "UNVERIFIED", "scope": "unavailable faithful positive control",
                              "reason": history["historical_missing_controls"][case_id], "pairs": []},
                     "Historical missing control was promoted or altered")
            measured[case_id] = None
            continue
        _require(case.get("status") == "UNVERIFIED" and case.get("scope") == negative.SCOPES[case_id]
                 and [pair.get("name") for pair in case.get("pairs", [])] == list(negative.PAIR_NAMES[case_id]),
                 "Historical supported technical pair denominator or scope differs")
        for pair in case["pairs"]:
            for input_key in ("control_input", "mutation_input"):
                retained(pair[input_key])
                _historical_synthetic_json(pair[input_key])
            negative._mutation(case_id, pair, fixture)
            for side, input_key in (("control", "control_input"), ("attack", "mutation_input")):
                process = pair[side]
                for key in ("stdout", "stderr"):
                    retained(process[key])
                command = negative._probe_command(case_id, _file(pair[input_key]), repo)
                _require(process.get("schema_version") == "negative-process/v1"
                         and process.get("argv") == command and process.get("cwd") == str(repo)
                         and process.get("timed_out") is False and type(process.get("exit_code")) is int
                         and datetime.fromisoformat(process["started_at"]) <= datetime.fromisoformat(process["finished_at"])
                         and not _file(process["stderr"]).read_text().strip(),
                         "Historical technical process identity or completion differs from the fixed probe")
                observed = _historical_synthetic_json(process["stdout"])
                actual = subprocess.run(command, cwd=repo, env={**os.environ, "PYTHONPATH": str(repo / "src")},
                                        capture_output=True, text=True, timeout=120, check=False)
                _require(not actual.stderr.strip(), "Current historical diagnostic replay emitted stderr")
                actual_response = json.loads(actual.stdout)
                compared_old, compared_new = observed, actual_response
                if case_id == "threshold_tamper" and side == "control":
                    # This production positive reports its own code identity.
                    # Bind both complete identities, retaining original facts.
                    identity_fields = {"code_revision", "code_tree_hash", "files"}
                    old_facts, new_facts = observed.get("facts"), actual_response.get("facts")
                    _require(isinstance(old_facts, dict) and isinstance(new_facts, dict)
                             and set(old_facts) == set(new_facts) == identity_fields | {"contract_hash"}
                             and {key: old_facts[key] for key in identity_fields} == history["historical_code_identity"]
                             and {key: new_facts[key] for key in identity_fields} == current_code
                             and old_facts["contract_hash"] == new_facts["contract_hash"],
                             "Historical/current threshold positive does not bind its exact code and contract facts")
                    assert isinstance(old_facts, dict) and isinstance(new_facts, dict)
                    compared_old = {**observed, "facts": {"contract_hash": old_facts["contract_hash"]}}
                    compared_new = {**actual_response, "facts": {"contract_hash": new_facts["contract_hash"]}}
                stable_old = re.sub(r"(?<=@ )0x[0-9a-fA-F]+", "0xADDRESS", json.dumps(compared_old, sort_keys=True))
                stable_new = re.sub(r"(?<=@ )0x[0-9a-fA-F]+", "0xADDRESS", json.dumps(compared_new, sort_keys=True))
                _require(actual.returncode == process["exit_code"] and stable_old == stable_new,
                         "Historical technical response differs from current fixed replay")
                if side == "control":
                    _require(actual.returncode == 0 and observed.get("status") == "TECHNICAL_CONTROL_PASS",
                             "Historical technical positive control failed current replay")
                else:
                    reason = negative.REASONS.get(f"{case_id}.{pair['name']}", negative.REASONS.get(case_id))
                    _require(actual.returncode != 0 and reason and reason in observed.get("reason", ""),
                             "Historical technical fault failed at an unsupported gate")
                    if case_id == "duplicate_coverage":
                        _require(observed["facts"]["numerator_seconds"] == "30"
                                 and observed["facts"]["uncovered_intervals"] == [["30", "90"]],
                                 "Historical duplicated coverage changed its actual denominator")
                processes.append({"case_id": case_id, "pair": pair["name"], "side": side,
                                  "argv": command, "recorded": process, "actual_exit_code": actual.returncode,
                                  "actual_stdout": actual.stdout, "actual_stderr": actual.stderr})
            _require(pair["control"]["finished_at"] <= pair["attack"]["started_at"],
                     "Historical mutation predates its technical positive control")
        measured[case_id] = True
    _require(raw.get("measurements") == measured, "Historical technical measurements or nulls were altered")
    after = snapshot()
    _require(before == after and code_identity(repo) == current_code,
             "Historical original artifacts or current code changed during replay")
    return {"historical_code_identity": history["historical_code_identity"], "current_code_identity": current_code,
            "threshold_positive_identity_scope": "Exact old/current code facts bound separately; complete original responses retained",
            "measurements": measured, "case_denominator": len(cases), "technical_case_count": len(negative.SCOPES),
            "pair_count": sum(len(case["pairs"]) for case in cases.values()), "current_processes": processes,
            "original_artifact_count": len(refs), "before": before, "after": after,
            "conservation_equal": True, "classification": "UNCLASSIFIED", "execution_status": "UNVERIFIED"}


def _synthetic_failure_inventory(run_refs: list[dict[str, Any]] | None, repo: Path | None,
                                 registered: set[str], *, replay_ref: dict[str, Any] | None = None,
                                 source_snapshots: list[dict[str, Any]] | None = None) -> tuple[dict[tuple[str, str], dict[str, Any]], list[dict[str, Any]]]:
    """Resolve only fixed, reproduced public-source fault fixtures as UNCLASSIFIED.

    A declared old digest is a test input, never a fabricated artifact ref.
    This does not validate current-code acceptance or confer public approval.
    """
    import sys
    from datetime import datetime

    from . import evaluator_negative as negative

    _require(run_refs is None or isinstance(run_refs, list), "Synthetic failure provenance must be explicit typed run refs")
    claims: dict[tuple[str, str], dict[str, Any]] = {}
    observations: list[dict[str, Any]] = []
    if not run_refs:
        _require(not any(isinstance(row, dict) and "historical_synthetic_harness" in row for row in source_snapshots or []),
                 "Historical harness authority has no selected synthetic runs")
        return claims, observations
    _require(repo is not None, "Synthetic failure provenance requires the public repository")
    assert repo is not None
    _require(len(run_refs) <= 32, "Synthetic failure run inventory exceeds its declared bound")
    histories = _historical_synthetic_harnesses(source_snapshots, run_refs, repo, registered)
    current_harness = artifact_ref(Path(negative.__file__).resolve())
    current_generator = artifact_ref(repo / "examples/recovery.py")
    reproduction = _verified_synthetic_replay(replay_ref, repo)

    def process_facts(process: dict[str, Any], argv: list[str]) -> dict[str, Any]:
        _require(process.get("schema_version") == "negative-process/v1" and process.get("argv") == argv
                 and process.get("cwd") == str(repo) and process.get("timed_out") is False
                 and type(process.get("exit_code")) is int, "Synthetic fixture process receipt is unrelated")
        _require(datetime.fromisoformat(process["started_at"]) <= datetime.fromisoformat(process["finished_at"]),
                 "Synthetic fixture process time is reversed")
        _require(not _file(process["stderr"]).read_text().strip(), "Synthetic fixture process has unexpected stderr")
        return _json(process["stdout"])

    for run_ref in run_refs:
        history = histories.get((run_ref["path"], run_ref["sha256"]))
        raw = _historical_synthetic_json(run_ref) if history else _json(run_ref)
        declared_harness = history["original_harness"] if history else current_harness
        _require(raw.get("schema_version") == "evaluator-negative-run/v1" and raw.get("test_only") is True
                 and raw.get("actual_dgist_acceptance") is False and raw.get("final_ac12_audit") is False
                 and raw.get("audiovisual_review") == "UNVERIFIED" and raw.get("owner_acceptance") == "pending",
                 "Synthetic fault evidence was relabelled as actual private acceptance")
        request = _json(raw["request"])
        _require(raw.get("harness") == declared_harness and request.get("harness") == declared_harness
                 and request.get("fixture_source") == current_generator
                 and request.get("dependencies") == raw.get("dependencies")
                 and request.get("code_identity", {}).get("code_tree_hash") == raw["dependencies"].get("code_tree_hash"),
                 "Historical synthetic harness/generator identity is not the exact supported public implementation")
        _file(history["snapshot"] if history else raw["harness"])
        _file(request["fixture_source"])
        _require(raw.get("toolchain") == negative.doctor(), "Synthetic fixture toolchain cannot reproduce the recorded bytes")
        receipt_path = Path(run_ref["path"]).parent / "receipt.json"
        _require(receipt_path.is_file() and not receipt_path.is_symlink(), "Completed synthetic run receipt is missing")
        receipt = _json(artifact_ref(receipt_path))
        _require(receipt.get("schema_version") == "evaluator-negative-receipt/v1" and receipt.get("result") == run_ref
                 and receipt.get("run_id") == raw.get("run_id") and receipt.get("completed") is True
                 and receipt.get("request") == raw["request"] and receipt.get("harness") == declared_harness
                 and receipt.get("dependencies") == raw["dependencies"] and receipt.get("operation") == "check:evaluator_negative",
                 "Synthetic fault receipt is not bound to this exact historical result")
        _require(isinstance(raw.get("artifacts"), list) and 0 < len(raw["artifacts"]) <= MAX_UNITS,
                 "Synthetic fault artifact denominator is missing")
        artifacts = {(str(_file(ref)), ref["sha256"]) for ref in raw["artifacts"]}
        fixture = _json(raw["fixture"])
        _require(fixture.get("schema_version") == "recovery-example/v1" and fixture.get("test_only") is True
                 and fixture.get("audiovisual_review") == "UNVERIFIED" and fixture.get("owner_acceptance") == "pending",
                 "Synthetic fixture provenance is not a public recovery fixture")
        fixture_directory = Path(fixture["project"]).parent
        execution = raw["fixture_execution"]
        process_facts(execution, [sys.executable, str(repo / "examples/recovery.py"), str(fixture_directory)])
        _require(execution["exit_code"] == 0, "Synthetic fixture generator failed")
        steps = _json(fixture["executions"])
        _require(isinstance(steps, list) and len(steps) == 14 and steps[0].get("name") == "01-generate"
                 and steps[0].get("exit_code") == 0, "Actual synthetic generation ledger is incomplete")
        for name in ("stdout", "stderr"):
            _file(steps[0][name])
        _require(steps[0]["argv"] == [*reproduction["generator_argv_prefix"], str(fixture_directory / "synthetic.mp4")]
                 and sha256(fixture_directory / "synthetic.mp4") == reproduction["source_sha256"],
                 "Recorded source bytes are not the reproduced fixed public generator output")
        _require(all(_file(value["output"]).is_file()
                     and value["output"]["sha256"] == reproduction["output_hashes"].get(stage)
                     for stage, value in fixture["outputs"].items())
                 and set(fixture["outputs"]) == {"baseline", "cut", "restored", "reapplied"},
                 "Recorded fixture renders are not the reproduced public output bytes")
        historical_replay = _replay_historical_synthetic_controls(raw, fixture, history, repo) if history else None
        pairs = raw.get("cases", {}).get("wrong_hashes", {}).get("pairs", [])
        _require([pair.get("name") for pair in pairs] == ["source_bytes", "output_bytes"],
                 "Both fixed source/output mutation controls are required")
        rows = []
        for pair in pairs:
            negative._mutation("wrong_hashes", pair, fixture)
            for side, input_key in (("control", "control_input"), ("attack", "mutation_input")):
                path = _file(pair[input_key])
                command = negative._probe_command("wrong_hashes", path, repo)
                observed = process_facts(pair[side], command)
                actual = subprocess.run(command, cwd=repo, capture_output=True, text=True, timeout=120, check=False)
                _require(not actual.stderr.strip() and actual.returncode == pair[side]["exit_code"]
                         and json.loads(actual.stdout) == observed, "Synthetic fault response differs from actual fixed probe replay")
                if side == "control":
                    _require(actual.returncode == 0 and observed.get("status") == "TECHNICAL_CONTROL_PASS", "Synthetic fault positive control failed")
                else:
                    _require((actual.returncode == (2 if pair["name"] == "source_bytes" else 1)) and negative.REASONS[f"wrong_hashes.{pair['name']}"] in observed.get("reason", ""),
                             "Synthetic fault did not reject for the required reason")
            _require(pair["control"]["finished_at"] <= pair["attack"]["started_at"], "Synthetic mutation predates its control")
            a, b = _json(pair["control_input"]), _json(pair["mutation_input"])
            if pair["name"] == "source_bytes":
                original = load_project(a["project"])
                mutant = _json(artifact_ref(Path(b["project"]) / "project.json"))
                changes = [(mutant["sources"][role], original["sources"][role]) for role in original["sources"]]
                initialization = raw["identity_initialization"]
                process_facts(initialization, [sys.executable, "-m", "talkcut", "init", a["project"], "--screen",
                                              str(fixture_directory / "synthetic.mp4"), "--speaker", str(fixture_directory / "synthetic.mp4"), "--json"])
                _require(initialization["exit_code"] == 0, "Synthetic identity initialization failed")
            else:
                changes = [(b["output"], a["output"])]
            for declared, original in changes:
                preserved = artifact_ref(_file(original))
                current_path = Path(declared["path"])
                _require(current_path.is_absolute() and current_path.is_file() and not current_path.is_symlink(), "Synthetic current artifact is missing or a symlink")
                actual_ref = artifact_ref(current_path)
                _require(preserved["sha256"] == declared["sha256"], "Synthetic old digest lacks preserved original bytes")
                _require(not ({preserved["sha256"], actual_ref["sha256"]} & registered), "Registered private source cannot become a synthetic fixture")
                _require((preserved["path"], preserved["sha256"]) in artifacts and (actual_ref["path"], actual_ref["sha256"]) in artifacts,
                         "Synthetic before/after bytes are outside the actual run artifact inventory")
                row = {"declared_reference": {"path": declared["path"], "sha256": declared["sha256"]},
                       "preserved_original": preserved, "actual_current": actual_ref, "case": "wrong_hashes." + pair["name"],
                       "historical_run": run_ref, "classification": "UNCLASSIFIED", "status": "MEASURED",
                       "reason": "Exact reproduced synthetic failure fixture; separate classification audit required"}
                rows.append(row)
                # Exact current artifact refs and the one deliberate old claim
                # all resolve to truthful current/original inventory entries.
                for key in ((declared["path"], declared["sha256"]), (actual_ref["path"], actual_ref["sha256"]),
                            (preserved["path"], preserved["sha256"])):
                    _require(key not in claims or claims[key]["actual_current"] == actual_ref, "Conflicting synthetic failure provenance")
                    claims[key] = row
        observations.append({"run": run_ref, "receipt": artifact_ref(receipt_path), "request": raw["request"],
                             "harness": declared_harness, "generator": current_generator, "rows": rows,
                             **({"historical_harness": history, "current_harness": current_harness,
                                 "historical_control_replay": historical_replay} if history else {}),
                             "current_reproduction": reproduction, "completeness": "UNVERIFIED"})
    _require(artifact_ref(Path(negative.__file__).resolve()) == current_harness,
             "Current diagnostic harness changed during historical observation")
    return claims, observations


_SOURCE_TREE_PRODUCER_TEMPLATE = r"""from pathlib import Path
import subprocess, hashlib, json, time, datetime, os, sys
base = Path(__file__).resolve().parent
source = base / 'source'
build = base / 'build'
run = base / '__RUN_DIRECTORY__'
run.mkdir()

def ref(p):
    data = p.read_bytes()
    return {'path': str(p), 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}

def tree():
    rows = [{'path': str(p.relative_to(source)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size} for p in sorted(source.rglob('*')) if p.is_file()]
    return {'files': rows, 'sha256': hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
before = tree()
(run / 'source-before.local.json').write_text(json.dumps(before, indent=2) + '\n')
results = []
commands = []
for name, argv in commands:
    out = run / (name + '.stdout.log')
    err = run / (name + '.stderr.log')
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    ts = time.monotonic()
    print(json.dumps({'status': 'STARTED', 'name': name, 'argv': argv}), flush=True)
    with out.open('wb') as o, err.open('wb') as e:
        p = subprocess.run(argv, stdout=o, stderr=e, cwd=source, env={**os.environ, 'DEVELOPER_DIR': '__DEVELOPER_DIR__', 'SDKROOT': '__SDKROOT__'})
    row = {'name': name, 'argv': argv, 'cwd': str(source), 'environment_overrides': {'DEVELOPER_DIR': '__DEVELOPER_DIR__', 'SDKROOT': '__SDKROOT__'}, 'started_at': started, 'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'elapsed_seconds': time.monotonic() - ts, 'exit_code': p.returncode, 'stdout': ref(out), 'stderr': ref(err)}
    results.append(row)
    (run / 'commands.local.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps({'status': 'COMPLETED' if not p.returncode else 'FAILED', 'name': name, 'elapsed_seconds': row['elapsed_seconds'], 'exit_code': p.returncode}), flush=True)
    if p.returncode:
        break
after = tree()
(run / 'source-after.local.json').write_text(json.dumps(after, indent=2) + '\n')
binary = build / 'bin/llama-mtmd-cli'
report = {'schema_version': 'private-runtime-build/v1', 'source_acquisition': ref(base / '__ACQUISITION_NAME__'), 'patch': ref(base / '__PATCH_NAME__'), 'patch_manifest': ref(base / '__PATCH_MANIFEST_NAME__'), 'runner': ref(Path(__file__).resolve()), 'source_before': ref(run / 'source-before.local.json'), 'source_after': ref(run / 'source-after.local.json'), 'source_unchanged_during_build': before == after, 'commands': results, 'binary': ref(binary) if binary.exists() else None, 'runtime_libraries': [{'requested_path': str(p), 'is_symlink': p.is_symlink(), 'link_target': os.readlink(p) if p.is_symlink() else None, 'canonical_file': ref(p.resolve())} for p in sorted((build / 'bin').glob('*.dylib')) if p.is_file()], 'status': 'BUILT_NOT_CAPABILITY_VALIDATED' if len(results) == len(commands) and all((r['exit_code'] == 0 for r in results)) and (before == after) else 'FAILED'}
(run / 'result.local.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'status': report['status'], 'result': ref(run / 'result.local.json')}), flush=True)
"""


def _validate_source_tree_command_roots(commands: Any, source: Path) -> None:
    _require(isinstance(commands, list) and commands
             and all(isinstance(command, dict) and command.get("cwd") == str(source) for command in commands),
             "Auxiliary tree command working directories do not identify the producer source root")
    assert isinstance(commands, list)
    configured_roots: list[str] = []
    for command in commands:
        argv = command.get("argv")
        _require(isinstance(argv, list) and argv and all(isinstance(arg, str) and arg for arg in argv),
                 "Auxiliary tree build has malformed configured source commands")
        assert isinstance(argv, list)
        source_flags = [index for index, arg in enumerate(argv) if arg.startswith("-S")]
        if source_flags:
            _require(Path(argv[0]).name == "cmake" and len(source_flags) == 1
                     and argv[source_flags[0]] == "-S"
                     and argv[source_flags[0] + 1:source_flags[0] + 2] == [str(source)],
                     "Auxiliary tree build has conflicting or unsupported configured source roots")
            # Only the actual producer's explicit configure argument grammar is
            # supported. Positional directories/presets/scripts cannot silently
            # redirect an otherwise matching -S root.
            position = 1
            while position < len(argv):
                argument = argv[position]
                if argument in {"-S", "-B", "-G"}:
                    _require(position + 1 < len(argv) and not argv[position + 1].startswith("-"),
                             "Auxiliary tree configured source command has an incomplete option")
                    position += 2
                else:
                    _require(argument.startswith("-D") and len(argument) > 2 and "=" in argument,
                             "Auxiliary tree configured source command has unsupported root construction arguments")
                    position += 1
            configured_roots.append(argv[source_flags[0] + 1])
        elif Path(argv[0]).name == "cmake":
            _require(argv[1:] == ["--version"] or (len(argv) >= 3 and argv[1] == "--build"),
                     "Auxiliary tree build has a configure command without an explicit source root")
    _require(configured_roots and all(root == str(source) for root in configured_roots),
             "Auxiliary tree build has no matching configured source root")


def _validate_source_tree_producer(syntax: ast.Module, producer: Path,
                                   build_path: Path, build: dict[str, Any]) -> tuple[Path, str]:
    """Accept two closed recorder grammars, never arbitrary Python dataflow.

    This checks the current source program and its referenced byte inventory.
    It does not attest that this program ran, or that its imports/environment
    were trusted during an earlier process execution.
    """
    base = producer.parent
    def literal_directory(name: str) -> str:
        nodes = [node for node in syntax.body if isinstance(node, ast.Assign)
                 and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id == name]
        _require(len(nodes) == 1 and isinstance(nodes[0].value, ast.BinOp)
                 and isinstance(nodes[0].value.op, ast.Div)
                 and isinstance(nodes[0].value.left, ast.Name) and nodes[0].value.left.id == "base"
                 and isinstance(nodes[0].value.right, ast.Constant) and isinstance(nodes[0].value.right.value, str),
                 "Auxiliary source/build roots must be single bounded literal children of producer base")
        node = nodes[0].value
        assert isinstance(node, ast.BinOp) and isinstance(node.right, ast.Constant)
        name_value = node.right.value
        _require(isinstance(name_value, str)
                 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name_value) is not None,
                 "Auxiliary source/build root literal is not one bounded canonical directory component")
        assert isinstance(name_value, str)
        return name_value

    source_name, build_name = literal_directory("source"), literal_directory("build")
    _require(source_name != build_name, "Auxiliary source and build roots collide")
    source, build_directory = base / source_name, base / build_name
    run = build_path.parent
    _require(run.parent == base and run.name not in {source_name, build_name}
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run.name) is not None
             and build_path == run / "result.local.json",
             "Auxiliary source producer result has no supported source construction directory")
    slots = {"__RUN_DIRECTORY__": run.name}
    for field_name, marker in (("source_acquisition", "__ACQUISITION_NAME__"),
                          ("patch", "__PATCH_NAME__"), ("patch_manifest", "__PATCH_MANIFEST_NAME__")):
        _require(isinstance(build.get(field_name), dict), "Auxiliary source producer origin refs are incomplete")
        path = _file(build[field_name])
        _require(path.parent == base and path == path.resolve() and path != producer
                 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", path.name) is not None,
                 "Auxiliary source producer literal origin path does not match its source construction")
        slots[marker] = path.name
    for field_name, name in (("source_before", "source-before.local.json"), ("source_after", "source-after.local.json")):
        _require(isinstance(build.get(field_name), dict) and _file(build[field_name]) == run / name,
                 "Auxiliary source producer manifest paths differ from its fixed construction")
    if build.get("binary") is not None:
        _require(isinstance(build["binary"], dict)
                 and _file(build["binary"]) == build_directory / "bin/llama-mtmd-cli",
                 "Auxiliary source producer binary path differs from its fixed construction")
    recorded = build.get("commands")
    _require(isinstance(recorded, list) and 0 < len(recorded) <= 64
             and all(isinstance(row, dict) for row in recorded),
             "Auxiliary source producer needs bounded recorded source commands")
    assert isinstance(recorded, list)
    environment = recorded[0].get("environment_overrides")
    _require(isinstance(environment, dict) and set(environment) == {"DEVELOPER_DIR", "SDKROOT"}
             and all(isinstance(value, str) and 0 < len(value) <= 4096 and "\x00" not in value
                     for value in environment.values()),
             "Auxiliary source producer environment literal slots are unsupported")
    assert isinstance(environment, dict)
    slots.update({"__DEVELOPER_DIR__": environment["DEVELOPER_DIR"], "__SDKROOT__": environment["SDKROOT"]})
    assignments = [node for node in syntax.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == "commands"]
    _require(len(assignments) == 1 and isinstance(assignments[0].value, ast.List),
             "Auxiliary source producer commands are not one supported literal array")
    command_array = assignments[0].value
    assert isinstance(command_array, ast.List)
    _require(0 < len(command_array.elts) <= 64 and len(recorded) <= len(command_array.elts),
             "Auxiliary source producer command denominator is unsupported")
    declared: list[tuple[str, list[str]]] = []
    for entry in command_array.elts:
        _require(isinstance(entry, ast.Tuple) and len(entry.elts) == 2
                 and isinstance(entry.elts[0], ast.Constant) and isinstance(entry.elts[0].value, str)
                 and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", entry.elts[0].value) is not None
                 and isinstance(entry.elts[1], ast.List) and 0 < len(entry.elts[1].elts) <= 256,
                 "Auxiliary source producer has an unsupported source command row")
        assert isinstance(entry, ast.Tuple) and isinstance(entry.elts[0], ast.Constant)
        assert isinstance(entry.elts[0].value, str)
        assert isinstance(entry.elts[1], ast.List)
        arguments: list[str] = []
        for argument in entry.elts[1].elts:
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                _require(0 < len(argument.value) <= 4096 and "\x00" not in argument.value,
                         "Auxiliary source producer command literal is invalid")
                arguments.append(argument.value)
            else:
                _require(isinstance(argument, ast.Call) and isinstance(argument.func, ast.Name)
                         and argument.func.id == "str" and not argument.keywords and len(argument.args) == 1
                         and isinstance(argument.args[0], ast.Name) and argument.args[0].id in {"source", "build"},
                         "Auxiliary source producer command escapes its literal source construction")
                assert isinstance(argument, ast.Call) and isinstance(argument.args[0], ast.Name)
                arguments.append(str(source if argument.args[0].id == "source" else build_directory))
        declared.append((entry.elts[0].value, arguments))
    _require(len({name for name, _ in declared}) == len(declared),
             "Auxiliary source producer command names are duplicated")
    _validate_source_tree_command_roots(
        [{"cwd": str(source), "argv": arguments} for _, arguments in declared], source)
    for record, (name, arguments) in zip(recorded, declared):
        _require(record.get("name") == name and record.get("argv") == arguments
                 and record.get("cwd") == str(source) and record.get("environment_overrides") == environment,
                 "Auxiliary source producer recorded commands differ from its source construction")
        for field_name, suffix in (("stdout", ".stdout.log"), ("stderr", ".stderr.log")):
            _require(isinstance(record.get(field_name), dict) and _file(record[field_name]) == run / (name + suffix),
                     "Auxiliary source producer command logs differ from its source construction")

    class BindSlots(ast.NodeTransformer):
        def visit_Constant(self, node: ast.Constant) -> ast.AST:
            if isinstance(node.value, str) and node.value in slots:
                return ast.copy_location(ast.Constant(slots[node.value]), node)
            return node

        def visit_Assign(self, node: ast.Assign) -> ast.AST:
            if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in {"source", "build"}):
                assert isinstance(node.value, ast.BinOp)
                node.value.right = ast.Constant(source_name if node.targets[0].id == "source" else build_name)
                return node
            if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == "commands"):
                # Only the previously validated literal array is inserted. All
                # surrounding names, imports, calls, functions and order stay fixed.
                node.value = command_array
                return node
            return self.generic_visit(node)

    expected = BindSlots().visit(ast.parse(_SOURCE_TREE_PRODUCER_TEMPLATE))
    actual_syntax = ast.dump(syntax, include_attributes=False)
    if actual_syntax == ast.dump(expected, include_attributes=False):
        return source, "explicit_runtime_alias_rows/v1"
    # This second fixed row grammar records direct ref(p) values, including
    # historical alias spelling. It grants no runtime-link or execution trust.
    legacy = ast.parse("[ref(p) for p in sorted((build / 'bin').glob('*.dylib')) if p.is_file()]", mode="eval").body
    reports = [node for node in expected.body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == "report" and isinstance(node.value, ast.Dict)]
    assert len(reports) == 1 and isinstance(reports[0].value, ast.Dict)
    report = reports[0].value
    slots_index = [index for index, key in enumerate(report.keys)
                   if isinstance(key, ast.Constant) and key.value == "runtime_libraries"]
    assert len(slots_index) == 1
    report.values[slots_index[0]] = legacy
    _require(actual_syntax == ast.dump(expected, include_attributes=False),
             "Auxiliary source producer does not match either closed supported source construction grammar")
    return source, "legacy_direct_runtime_refs/v1"


def _auxiliary_source_tree_inventory(locators: list[dict[str, Any]] | None, directory: Path,
                                     repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    return _source_tree_inventory(locators, directory, repo, registered, historical=False)


def _auxiliary_historical_source_tree_inventory(locators: list[dict[str, Any]] | None, directory: Path,
                                                repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    return _source_tree_inventory(locators, directory, repo, registered, historical=True)


def _source_file_identity(info: os.stat_result) -> tuple[int, ...]:
    """Read access may update atime; content/ownership/link identity must hold."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _source_tree_inventory(locators: list[dict[str, Any]] | None, directory: Path,
                           repo: Path | None, registered: set[str], *,
                           historical: bool) -> list[dict[str, Any]]:
    """Resolve a whole source-relative list through its exact original producer.

    This proves current byte inventory only. Build/runtime claims remain
    UNVERIFIED, and no root is accepted from the locator author's assertion.
    """
    _require(locators is None or isinstance(locators, list), "Auxiliary source trees require explicit locators")
    _require(len(locators or []) <= 64, "Auxiliary source tree count exceeds its finite bound")
    observations: list[dict[str, Any]] = []
    occupied: set[tuple[str, tuple[str | int, ...]]] = set()
    seen_builds: set[str] = set()
    def canonical(path: Path) -> None:
        _require(path.is_absolute() and path == path.resolve() and path.is_relative_to(directory),
                 "Auxiliary source tree path is noncanonical, linked or outside its task")
        _require(not any(path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                 and path.name not in {"project.json", "acceptance.local.json"},
                 "Protected private/formal paths cannot become auxiliary source tree inventories")

    def read(ref: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
        path = _file(ref)
        canonical(path)
        _require(path.stat().st_size <= MAX_UNIT_BYTES and ref["sha256"] not in registered,
                 "Auxiliary tree metadata is oversized or a registered source")
        _require("bytes" not in ref or ref["bytes"] == path.stat().st_size, "Auxiliary tree metadata byte count changed")
        try:
            value = json.loads(path.read_bytes())
        except (ValueError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary source tree metadata is not bounded JSON") from exc
        _require(isinstance(value, dict), "Auxiliary source tree metadata must be an object")
        return path, value

    def same_ref(left: Any, right: Any) -> bool:
        return (isinstance(left, dict) and isinstance(right, dict)
                and left.get("path") == right.get("path") and left.get("sha256") == right.get("sha256"))

    def pointer(value: dict[str, Any], expression: Any) -> tuple[Any, dict[str, Any], tuple[str | int, ...]]:
        _require(isinstance(expression, str) and expression.startswith("/") and len(expression) <= 2048,
                 "Auxiliary tree copy requires an exact JSON pointer")
        tokens = expression[1:].split("/")
        _require(all(token and re.search(r"~(?![01])", token) is None for token in tokens), "Auxiliary tree copy pointer is malformed")
        edge: list[str | int] = []
        item: Any = value
        parent: Any = None
        for token in tokens:
            token = token.replace("~1", "/").replace("~0", "~")
            parent = item
            if isinstance(item, dict):
                _require(token in item, "Auxiliary tree copy pointer is missing")
                item = item[token]
                edge.append(token)
            elif isinstance(item, list):
                _require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and int(token) < len(item),
                         "Auxiliary tree copy array pointer is invalid")
                item = item[int(token)]
                edge.append(int(token))
            else:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary tree copy pointer crosses a scalar")
        _require(isinstance(parent, dict) and edge[-1] == "actual_build_source_tree",
                 "Auxiliary tree copy is not the explicit runtime tree role")
        return item, parent, tuple(edge)

    for locator in locators or []:
        snapshot_ref = None
        if historical:
            _require(isinstance(locator, dict) and set(locator) == {"origin", "snapshot"}
                     and isinstance(locator["origin"], dict) and isinstance(locator["snapshot"], dict),
                     "Historical source tree requires an explicit original locator and complete snapshot")
            snapshot_ref = locator["snapshot"]
            locator = locator["origin"]
        _require(isinstance(locator, dict) and set(locator) <= {"build", "manifest", "copies", "origin_scope"}
                 and {"build", "manifest"} <= set(locator), "Unsupported auxiliary source tree locator")
        current_only = "origin_scope" in locator
        _require(not current_only or (not historical and locator["origin_scope"] == "current_native_source_bytes/v1"),
                 "Only current native source bytes may use the explicit nonhistorical origin scope")
        build_ref, selected_ref = locator["build"], locator["manifest"]
        build_path, build = read(build_ref)
        _require(str(build_path) not in seen_builds, "Auxiliary source tree build locator is duplicated")
        seen_builds.add(str(build_path))
        _require(build.get("schema_version") == "private-runtime-build/v1"
                 and build.get("source_unchanged_during_build") is True,
                 "Auxiliary tree origin is not an unchanged native build record")
        for key in ("source_before", "source_after", "runner", "source_acquisition"):
            _require(isinstance(build.get(key), dict), "Auxiliary tree build origin is incomplete")
        before_path, before_value = read(build["source_before"])
        after_path, after_value = read(build["source_after"])
        selected_path, value = read(selected_ref)
        _require(same_ref(selected_ref, build["source_before"]) or same_ref(selected_ref, build["source_after"]),
                 "Auxiliary tree manifest is not referenced by its build parent")
        _require(before_path != after_path and build["source_before"]["sha256"] == build["source_after"]["sha256"]
                 and before_value == after_value == value, "Auxiliary build source manifests differ")
        producer = _file(build["runner"])
        canonical(producer)
        _require(producer.stat().st_size <= MAX_UNIT_BYTES and sha256(producer) not in registered,
                 "Auxiliary tree producer is oversized or a registered private source")
        try:
            syntax = ast.parse(producer.read_text())
        except (ValueError, SyntaxError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary tree producer is not inspectable Python") from exc
        source, producer_grammar = _validate_source_tree_producer(syntax, producer, build_path, build)
        canonical(source)
        _require(source.is_dir() and source != directory, "Auxiliary tree origin is not a canonical task source directory")
        acquisition_path, acquisition = read(build["source_acquisition"])
        if current_only:
            # The actual acquisition names an upstream extraction, not a proved
            # later copy. Preserve that distinction; only current root bytes and
            # unchanged original full manifests are inventoried in this role.
            _require(set(acquisition) == {"source_url", "upstream_commit", "archive", "extracted_source",
                     "elapsed_seconds", "finished_at", "original_runtime_unchanged"}
                     and isinstance(acquisition.get("extracted_source"), str)
                     and "copied_source" not in acquisition,
                     "Current native source observation needs the exact upstream-extraction acquisition role")
            extracted = Path(acquisition["extracted_source"])
            canonical(extracted)
            _require(extracted.parent == producer.parent and extracted.is_dir() and extracted != source,
                     "Upstream acquisition extraction must remain a distinct canonical sibling")
            archive = _file(acquisition.get("archive"))
            canonical(archive)
            _require(archive.parent == producer.parent and archive.is_file(),
                     "Upstream acquisition archive is not its preserved canonical sibling artifact")
        else:
            _require(acquisition.get("copied_source") == str(source), "Auxiliary tree acquisition identifies another source root")
        _validate_source_tree_command_roots(build.get("commands"), source)
        _require(set(value) == {"files", "sha256"} and isinstance(value["files"], list)
                 and 0 < len(value["files"]) <= MAX_TASK_FILES, "Auxiliary source tree list is missing or exceeds its bound")
        rows = value["files"]
        _require(hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest() == value["sha256"],
                 "Auxiliary source tree aggregate digest is invalid")
        physical_source = source
        snapshot_path = None
        if historical:
            assert snapshot_ref is not None
            snapshot_path, snapshot = read(snapshot_ref)
            expected_origin = {"build": build_ref, "manifest": selected_ref, "runner": build["runner"],
                               "acquisition": build["source_acquisition"], "logical_source_root": str(source)}
            _require(snapshot_path.name == "snapshot.json" and snapshot_path.stat().st_nlink == 1
                     and set(snapshot) == {"schema_version", "origin", "tree", "claim_status"}
                     and snapshot["schema_version"] == "historical-source-tree-snapshot/v1"
                     and snapshot["origin"] == expected_origin and snapshot["tree"] == value
                     and snapshot["claim_status"] == "UNVERIFIED",
                     "Historical source snapshot differs from its exact original manifest/origin or scope")
            physical_source = snapshot_path.parent / "source"
            canonical(physical_source)
            _require(physical_source.is_dir() and not physical_source.is_relative_to(source)
                     and not source.is_relative_to(physical_source),
                     "Historical physical tree must be a separate canonical complete copy")
        files: list[dict[str, Any]] = []
        names: set[str] = set()
        total_bytes = 0
        for row in rows:
            _require(isinstance(row, dict) and set(row) == {"path", "sha256", "bytes"}
                     and isinstance(row["path"], str) and re.fullmatch(r"[a-f0-9]{64}", str(row["sha256"]))
                     and type(row["bytes"]) is int and row["bytes"] >= 0, "Auxiliary source tree row is malformed")
            relative = Path(row["path"])
            _require(not relative.is_absolute() and str(relative) == row["path"]
                     and all(part not in {"", ".", ".."} for part in row["path"].split("/")),
                     "Auxiliary source tree row is absolute, noncanonical or escapes its root")
            target = physical_source / relative
            canonical(target)
            _require(target.is_relative_to(physical_source) and str(target) not in names and not target.is_symlink()
                     and target.is_file(), "Auxiliary source tree target is duplicate, missing or linked")
            names.add(str(target))
            first = target.stat()
            _require(stat.S_ISREG(first.st_mode) and first.st_size == row["bytes"], "Auxiliary source tree target size/type changed")
            _require(not historical or first.st_nlink == 1, "Historical source snapshot contains a hard link")
            actual = artifact_ref(target)
            _require(_source_file_identity(target.stat()) == _source_file_identity(first) and actual["sha256"] == row["sha256"]
                     and actual["sha256"] not in registered, "Auxiliary source tree target changed or is a registered private source")
            total_bytes += first.st_size
            _require(total_bytes <= MAX_TOTAL_BYTES, "Auxiliary source tree bytes exceed the finite inspection bound")
            observed_file = {"original_relative_path": row["path"], "actual": actual, "bytes": first.st_size}
            if historical:
                observed_file["logical_source_path"] = str(source / relative)
            files.append(observed_file)
        physical: set[str] = set()
        def unreadable_tree(error: OSError) -> None:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary source tree traversal is unreadable") from error
        for parent, folders, children in os.walk(physical_source, followlinks=False, onerror=unreadable_tree):
            _require(not any((Path(parent) / name).is_symlink() for name in folders + children),
                     "Auxiliary source tree contains a directory or file symlink")
            for name in children:
                path = Path(parent) / name
                _require(path.is_file() and stat.S_ISREG(path.stat().st_mode), "Auxiliary source tree contains a nonregular file")
                physical.add(str(path))
                _require(len(physical) <= MAX_TASK_FILES, "Auxiliary current source tree exceeds its finite file bound")
        _require(physical == names, "Auxiliary source tree has missing or extra current files")
        bindings: list[dict[str, Any]] = []
        parents = [artifact_ref(build_path), artifact_ref(producer), artifact_ref(acquisition_path)]
        current_files: list[dict[str, Any]] = []
        current_bytes = 0
        if historical:
            assert snapshot_path is not None
            snapshot_binding_key = (str(snapshot_path), ("tree",))
            _require(snapshot_binding_key not in occupied, "Conflicting historical snapshot tree binding")
            occupied.add(snapshot_binding_key)
            bindings.append({"parent": artifact_ref(snapshot_path), "edge": ["tree"]})
            parents.append(artifact_ref(snapshot_path))
            for current_parent, folders, children in os.walk(source, followlinks=False, onerror=unreadable_tree):
                folders.sort()
                _require(not any((Path(current_parent) / name).is_symlink() for name in folders + children),
                         "Historical logical root current inventory contains a symlink")
                for name in sorted(children):
                    current = Path(current_parent) / name
                    canonical(current)
                    first_current = current.stat()
                    _require(stat.S_ISREG(first_current.st_mode), "Historical logical root has a nonregular current file")
                    current_ref = artifact_ref(current)
                    _require(_source_file_identity(current.stat()) == _source_file_identity(first_current) and current_ref["sha256"] not in registered,
                             "Historical logical root current bytes changed or are a registered private source")
                    current_bytes += first_current.st_size
                    current_files.append({"original_relative_path": str(current.relative_to(source)),
                                          "actual": current_ref, "bytes": first_current.st_size})
                    _require(len(current_files) <= MAX_TASK_FILES and current_bytes <= MAX_TOTAL_BYTES,
                             "Historical logical root current inventory exceeds its finite bounds")
        for manifest_path in (before_path, after_path):
            binding_key = (str(manifest_path), ())
            _require(binding_key not in occupied, "Conflicting auxiliary source tree manifest origin")
            occupied.add(binding_key)
            bindings.append({"parent": artifact_ref(manifest_path), "edge": []})
            parents.append(artifact_ref(manifest_path))
        copies = locator.get("copies", [])
        _require(isinstance(copies, list) and len(copies) <= 512, "Auxiliary tree copy count exceeds its finite bound")
        for copy in copies:
            _require(isinstance(copy, dict) and set(copy) == {"parent", "pointer"}, "Auxiliary tree copy locator is malformed")
            copy_path, copy_value = read(copy["parent"])
            _auxiliary_json(copy_path, repo, registered)
            actual_value, owner, edge = pointer(copy_value, copy["pointer"])
            _require(actual_value == value, "Auxiliary inline tree copy differs from its complete original manifest")
            origin_fields = {"build_receipt": build_ref, "build_source_before": build["source_before"],
                             "build_source_after": build["source_after"], "build_runner": build["runner"],
                             "source_acquisition": build["source_acquisition"]}
            _require(all(same_ref(owner.get(key), ref) for key, ref in origin_fields.items()),
                     "Auxiliary inline source tree copy has a different build origin")
            for ref in origin_fields.values():
                _file(ref)
            copy_key = (str(copy_path), edge)
            _require(copy_key not in occupied, "Duplicate/conflicting auxiliary tree copy pointer")
            occupied.add(copy_key)
            bindings.append({"parent": artifact_ref(copy_path), "edge": list(edge)})
            parents.append(artifact_ref(copy_path))
        for ref in parents:
            _file(ref)
        observation = {"build": build_ref, "selected_manifest": artifact_ref(selected_path), "source_directory": str(source),
                       "manifest_value": value, "parents": parents, "bindings": bindings, "files": files,
                       "row_count": len(rows), "total_bytes": total_bytes, "claim_status": "UNVERIFIED",
                       "scope": "Root-bound auxiliary source bytes only; no build, execution, AI, public classification or publication approval"}
        if current_only:
            observation.update({"origin_scope": "current_native_source_bytes/v1", "producer_grammar": producer_grammar,
                                "acquisition_observation": build["source_acquisition"], "copy_history_status": "UNVERIFIED",
                                "build_status": "UNVERIFIED", "runtime_status": "UNVERIFIED", "av_status": "UNVERIFIED",
                                "scope": "Current complete native source bytes derived from a closed literal producer only; upstream acquisition is preserved, not approval of a later copy/build/runtime/execution/AI/publication"})
        if historical:
            observation.update({"physical_snapshot_directory": str(physical_source), "snapshot": snapshot_ref,
                                "current_files": current_files, "current_total_bytes": current_bytes,
                                "scope": "Complete historical byte relocation plus current logical-root inventory only; no past execution, current runtime, AI, public classification or publication approval"})
        observations.append(observation)
    return observations


def _auxiliary_runtime_inventory(request_refs: list[dict[str, Any]] | None, directory: Path,
                                 repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    """Observe exact auxiliary library edges; protected metadata still rejects."""
    return _runtime_library_inventory(request_refs, directory, repo, registered, native_request=False)


def _native_runtime_request_inventory(request_refs: list[dict[str, Any]] | None, directory: Path,
                                      repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    """Observe the current bytes of one supported request role, never execution.

    This role cannot use metadata history or grant alias authority to another
    parent. Native process, intake, capability and review validators remain
    separate and must reject absent/stale execution evidence independently.
    """
    return _runtime_library_inventory(request_refs, directory, repo, registered, native_request=True)


def _source_tree_reobservation_inventory(locators: list[dict[str, Any]] | None,
                                           authorities: list[dict[str, Any]], directory: Path,
                                           repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    """Bind an explicit private copy to an already observed current tree.

    The original closed producer supplies the root. A copied list never supplies
    a root or certifies a build, runtime, historical execution or public status.
    """
    _require(locators is None or isinstance(locators, list), "Source tree reobservations require explicit locators")
    _require(len(locators or []) <= 512, "Source tree reobservation count exceeds its finite bound")
    observations: list[dict[str, Any]] = []
    occupied: set[tuple[str, tuple[str | int, ...]]] = set()

    def read(ref: Any) -> tuple[Path, os.stat_result]:
        _require(isinstance(ref, dict) and {"path", "sha256"} <= set(ref) <= {"path", "sha256", "bytes"}
                 and isinstance(ref.get("path"), str) and isinstance(ref.get("sha256"), str)
                 and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]) is not None,
                 "Source tree reobservation artifact ref is malformed")
        try:
            identity = Path(ref["path"]).lstat()
        except OSError as error:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Source tree reobservation artifact is unavailable") from error
        path = _file(ref)
        _require(str(path) == ref["path"] and path == path.resolve() and path.is_relative_to(directory)
                 and not any(path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                 and path.name not in {"project.json", "acceptance.local.json"} and ref["sha256"] not in registered,
                 "Source tree reobservation is outside its canonical current auxiliary scope")
        _require(identity.st_size <= MAX_UNIT_BYTES and _source_file_identity(path.stat()) == _source_file_identity(identity)
                 and ("bytes" not in ref or type(ref["bytes"]) is int and ref["bytes"] == identity.st_size),
                 "Source tree reobservation artifact identity, bytes or bound changed")
        return path, identity

    def resolve(value: Any, expression: Any) -> tuple[Any, tuple[str | int, ...]]:
        _require(isinstance(expression, str) and expression.startswith("/") and len(expression) <= 2048,
                 "Source tree reobservation requires bounded exact JSON pointers")
        tokens = expression[1:].split("/")
        _require(all(token and re.search(r"~(?![01])", token) is None for token in tokens), "Source tree reobservation pointer is malformed")
        edge: list[str | int] = []
        for encoded in tokens:
            token = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict):
                _require(token in value, "Source tree reobservation pointer is absent")
                value = value[token]
                edge.append(token)
            elif isinstance(value, list):
                _require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and int(token) < len(value),
                         "Source tree reobservation array pointer is invalid")
                value = value[int(token)]
                edge.append(int(token))
            else:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Source tree reobservation pointer crosses a scalar")
        return value, tuple(edge)

    for locator in locators or []:
        _require(isinstance(locator, dict) and set(locator) == {"parent", "pointer", "authority_build", "recorder_pointer"},
                 "Source tree reobservation locator has unsupported fields")
        parent, parent_identity = read(locator["parent"])
        authority_path, authority_identity = read(locator["authority_build"])
        matches = [row for row in authorities if row["build"].get("path") == str(authority_path)
                   and row["build"].get("sha256") == locator["authority_build"]["sha256"]
                   and "physical_snapshot_directory" not in row]
        _require(len(matches) == 1, "Source tree reobservation lacks one exact already observed current authority")
        authority = matches[0]
        _require(authority["claim_status"] == "UNVERIFIED", "Source tree reobservation cannot inherit an execution approval")
        _auxiliary_json(parent, repo, registered)
        def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            parsed: dict[str, Any] = {}
            for name, value in pairs:
                _require(name not in parsed, "Source tree reobservation parent has duplicate JSON keys")
                parsed[name] = value
            return parsed
        body = json.loads(parent.read_bytes(), object_pairs_hook=unique)
        value, edge = resolve(body, locator["pointer"])
        recorder, recorder_edge = resolve(body, locator["recorder_pointer"])
        owner_edge = edge[:-1]
        same_level = edge != recorder_edge and owner_edge == recorder_edge[:-1]
        owner: Any = body
        for token in owner_edge:
            owner = owner[token]
        nested = (bool(owner_edge) and isinstance(owner, dict)
                  and len(recorder_edge) > len(owner_edge) + 1
                  and recorder_edge[:len(owner_edge)] == owner_edge
                  and recorder_edge[:len(edge)] != edge)
        _require(same_level or nested,
                 "Source tree recorder pointer is outside its exact selected observation context")
        _require(json.dumps(value, sort_keys=True, separators=(",", ":"))
                 == json.dumps(authority["manifest_value"], sort_keys=True, separators=(",", ":")),
                 "Source tree reobservation differs from the full typed current manifest")
        build = _json(locator["authority_build"])
        _require(isinstance(recorder, dict) and isinstance(build.get("runner"), dict)
                 and all(recorder.get(key) == build["runner"].get(key) for key in ("path", "sha256")),
                 "Source tree reobservation recorder is not the exact original producer path and hash")
        recorder_path, recorder_identity = read(recorder)
        manifest_path, manifest_identity = read(authority["selected_manifest"])
        _require(len({parent, authority_path, recorder_path, manifest_path}) == 4,
                 "Source tree reobservation roles must use distinct actual files")
        key = (str(parent), edge)
        _require(key not in occupied, "Duplicate/conflicting source tree reobservation edge")
        occupied.add(key)
        identities = [("parent", parent, parent_identity, locator["parent"]),
                      ("authority", authority_path, authority_identity, locator["authority_build"]),
                      ("recorder", recorder_path, recorder_identity, recorder),
                      ("manifest", manifest_path, manifest_identity, authority["selected_manifest"])]
        for _, path, identity, ref in identities:
            _require(_source_file_identity(path.stat()) == _source_file_identity(identity)
                     and artifact_ref(path)["sha256"] == ref["sha256"], "Source tree reobservation bytes changed during observation")
        observations.append({"parent": artifact_ref(parent), "pointer": locator["pointer"], "edge": list(edge),
                             "authority_build": authority["build"], "recorder_pointer": locator["recorder_pointer"],
                             "recorder_edge": list(recorder_edge), "recorder": artifact_ref(recorder_path),
                             "manifest": authority["selected_manifest"], "row_count": authority["row_count"],
                             "total_bytes": authority["total_bytes"],
                             "file_identities": {role: {"path": str(path), "identity": list(_source_file_identity(identity))}
                                                 for role, path, identity, _ in identities},
                             "claim_status": "UNVERIFIED", "execution_status": "UNVERIFIED", "classification_status": "UNVERIFIED",
                             "scope": "Exact current private source copy and original recorder only; no root assertion, build/runtime/history, public or AV approval"})
    return observations


def _source_tree_member_reobservation_inventory(locators: list[dict[str, Any]] | None,
                                               authorities: list[dict[str, Any]], directory: Path,
                                               repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    """Bind an exact copied row to a fully observed current or historical tree.

    The caller supplies full producer-validated authorities and revalidates them
    after traversal. Neither this locator nor its copied row supplies a root or
    a historical relocation, and the original execution claim stays unverified.
    """
    _require(locators is None or isinstance(locators, list), "Source member observations require explicit locators")
    _require(len(locators or []) <= 512, "Source member observation count exceeds its finite bound")
    observations: list[dict[str, Any]] = []
    occupied: set[tuple[str, tuple[str | int, ...]]] = set()

    def read(ref: Any, *, limit: int = MAX_UNIT_BYTES) -> tuple[Path, os.stat_result]:
        _require(isinstance(ref, dict) and {"path", "sha256"} <= set(ref) <= {"path", "sha256", "bytes"}
                 and isinstance(ref.get("path"), str) and isinstance(ref.get("sha256"), str)
                 and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]) is not None,
                 "Source member artifact ref is malformed")
        try:
            identity = Path(ref["path"]).lstat()
        except OSError as error:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Source member artifact is unavailable") from error
        path = _file(ref)
        _require(str(path) == ref["path"] and path == path.resolve() and path.is_relative_to(directory)
                 and not any(path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                 and path.name not in {"project.json", "acceptance.local.json"} and ref["sha256"] not in registered,
                 "Source member artifact is outside its canonical auxiliary scope")
        _require(stat.S_ISREG(identity.st_mode) and identity.st_nlink == 1 and identity.st_size <= limit
                 and _source_file_identity(path.stat()) == _source_file_identity(identity)
                 and ("bytes" not in ref or type(ref["bytes"]) is int and ref["bytes"] == identity.st_size),
                 "Source member artifact identity, bytes, links or bound changed")
        return path, identity

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for name, value in pairs:
            _require(name not in parsed, "Source member JSON has duplicate keys")
            parsed[name] = value
        return parsed

    def body(path: Path) -> Any:
        try:
            return json.loads(path.read_bytes(), object_pairs_hook=unique)
        except TalkCutError:
            raise
        except (ValueError, UnicodeDecodeError) as error:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Source member metadata is not bounded JSON") from error

    def resolve(value: Any, expression: Any) -> tuple[Any, tuple[str | int, ...]]:
        _require(isinstance(expression, str) and expression.startswith("/") and len(expression) <= 2048,
                 "Source member requires bounded exact JSON pointers")
        tokens = expression[1:].split("/")
        _require(all(token and re.search(r"~(?![01])", token) is None for token in tokens), "Source member pointer is malformed")
        edge: list[str | int] = []
        for encoded in tokens:
            token = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict):
                _require(token in value, "Source member pointer is absent")
                value = value[token]
                edge.append(token)
            elif isinstance(value, list):
                _require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and int(token) < len(value),
                         "Source member array pointer is invalid")
                value = value[int(token)]
                edge.append(int(token))
            else:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Source member pointer crosses a scalar")
        return value, tuple(edge)

    for locator in locators or []:
        _require(isinstance(locator, dict) and set(locator) == {
            "parent", "pointer", "authority_build", "authority_manifest", "manifest_row_index", "origin_pointer"},
            "Source member locator has unsupported fields")
        parent, parent_identity = read(locator["parent"])
        build_path, build_identity = read(locator["authority_build"])
        manifest_path, manifest_identity = read(locator["authority_manifest"])
        matches = [row for row in authorities if all(
            row[key].get("path") == locator[field]["path"] and row[key].get("sha256") == locator[field]["sha256"]
            for key, field in (("build", "authority_build"), ("selected_manifest", "authority_manifest")))]
        _require(len(matches) == 1, "Source member lacks one exact fully observed build and selected manifest authority")
        authority = matches[0]
        _require(authority["claim_status"] == "UNVERIFIED", "Source member cannot inherit an execution approval")
        manifest = body(manifest_path)
        _require(json.dumps(manifest, sort_keys=True, separators=(",", ":"))
                 == json.dumps(authority["manifest_value"], sort_keys=True, separators=(",", ":")),
                 "Source member manifest differs from the full typed authority")
        index = locator["manifest_row_index"]
        _require(type(index) is int and 0 <= index < authority["row_count"], "Source member manifest row index is invalid")
        full_row = manifest["files"][index]
        parent_body = body(parent)
        _auxiliary_json(parent, repo, registered)
        value, edge = resolve(parent_body, locator["pointer"])
        origin, origin_edge = resolve(parent_body, locator["origin_pointer"])
        owner: Any = parent_body
        for token in edge[:-1]:
            owner = owner[token]
        _require(isinstance(owner, dict) and edge != origin_edge and edge[:-1] == origin_edge[:-1]
                 and isinstance(origin, str) and origin == str(manifest_path),
                 "Source member origin is outside its exact selected observation object or manifest")
        _require(isinstance(value, dict) and set(value) in ({"path", "sha256"}, {"path", "sha256", "bytes"})
                 and json.dumps(value, sort_keys=True, separators=(",", ":"))
                 == json.dumps({key: full_row[key] for key in value}, sort_keys=True, separators=(",", ":")),
                 "Source member differs from the exact typed row or closed path/hash projection")
        member = authority["files"][index]
        _require(member["original_relative_path"] == full_row["path"] and member["actual"]["sha256"] == full_row["sha256"]
                 and type(member["bytes"]) is int and member["bytes"] == full_row["bytes"],
                 "Source member physical authority differs from its indexed full manifest row")
        member_path, member_identity = read(member["actual"], limit=MAX_TOTAL_BYTES)
        _require(member_identity.st_size == full_row["bytes"], "Source member physical bytes differ from the full row")
        identities = [(parent, parent_identity, locator["parent"]), (build_path, build_identity, locator["authority_build"]),
                      (manifest_path, manifest_identity, locator["authority_manifest"]), (member_path, member_identity, member["actual"])]
        authority_paths = set()
        for ref in authority["parents"]:
            path, identity = read(ref)
            authority_paths.add(path)
            if path.suffix.lower() == ".json":
                body(path)
            identities.append((path, identity, ref))
        _require(parent not in authority_paths and len({parent, build_path, manifest_path, member_path}) == 4,
                 "Source member parent must be separate from its authority and physical member")
        key = (str(parent), edge)
        _require(key not in occupied, "Duplicate/conflicting source member edge")
        occupied.add(key)
        for path, identity, ref in identities:
            _require(_source_file_identity(path.stat()) == _source_file_identity(identity)
                     and artifact_ref(path)["sha256"] == ref["sha256"], "Source member bytes changed during observation")
        observations.append({"parent": artifact_ref(parent), "pointer": locator["pointer"], "edge": list(edge),
                             "origin_pointer": locator["origin_pointer"], "origin_edge": list(origin_edge),
                             "authority_build": authority["build"], "authority_manifest": authority["selected_manifest"],
                             "authority_kind": "historical" if "physical_snapshot_directory" in authority else "current",
                             "manifest_row_index": index, "full_row": full_row, "value": value, "member": member,
                             "row_count": authority["row_count"], "total_bytes": authority["total_bytes"],
                             "current_row_count": len(authority.get("current_files", [])),
                             "file_identities": {str(path): list(_source_file_identity(identity)) for path, identity, _ in identities},
                             "claim_status": "UNVERIFIED", "execution_status": "UNVERIFIED", "classification_status": "UNVERIFIED",
                             "scope": "Exact private copied source member and full authority bytes only; no original execution, current runtime, publication or AV approval"})
    return observations


def _historical_verification_command_inventory(locators: list[dict[str, Any]] | None,
                                               directory: Path, repo: Path | None,
                                               registered: set[str]) -> list[dict[str, Any]]:
    """Observe preserved command bytes plus the exact returned self-reference.

    A closed structural relation recognizes one serialization update. It never
    certifies that the command ran, its times are true, or its PASS claim holds.
    Existing formal/execution and auxiliary-history validators are unchanged.
    """
    import math
    from datetime import datetime

    _require(locators is None or isinstance(locators, list), "Historical command observation requires explicit locators")
    _require(len(locators or []) <= 512, "Historical command observation exceeds its finite bound")
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    required = {"schema_version", "name", "argv", "cwd", "started_at", "finished_at", "wall_seconds", "timeout_seconds",
                "exit_code", "timed_out", "interrupted", "error", "status", "stdout", "stderr"}

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            _require(key not in result, "Historical command JSON has duplicate keys")
            result[key] = value
        return result

    def actual(ref: Any) -> tuple[Path, os.stat_result]:
        _require(isinstance(ref, dict) and set(ref) == {"path", "sha256"}
                 and isinstance(ref.get("path"), str) and isinstance(ref.get("sha256"), str)
                 and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]) is not None,
                 "Historical command artifact locator is malformed")
        try:
            identity = Path(ref["path"]).lstat()
        except OSError as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Historical command artifact is unavailable") from exc
        path = _file(ref)
        _require(_source_file_identity(path.stat()) == _source_file_identity(identity),
                 "Historical command artifact changed during its initial hash read")
        _require(path == path.resolve() and path == Path(os.path.abspath(path)) and path.is_relative_to(directory)
                 and not any(path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                 and path.name not in {"project.json", "acceptance.local.json"} and ref["sha256"] not in registered,
                 "Historical command bytes are outside their canonical private metadata scope")
        _require(path.stat().st_size <= MAX_UNIT_BYTES, "Historical command metadata exceeds its byte bound")
        return path, identity

    for locator in locators or []:
        _require(isinstance(locator, dict) and set(locator) == {"original", "snapshot", "current", "parent", "pointer"},
                 "Historical command locator has unsupported fields")
        original = locator["original"]
        _require(isinstance(original, dict) and set(original) == {"path", "sha256"}
                 and isinstance(original.get("path"), str) and isinstance(original.get("sha256"), str)
                 and re.fullmatch(r"[a-f0-9]{64}", original["sha256"]) is not None,
                 "Historical command original declaration is malformed")
        paths = {key: actual(locator[key]) for key in ("current", "snapshot", "parent")}
        current, snapshot, parent = (paths[key][0] for key in ("current", "snapshot", "parent"))
        _require(original["path"] == str(current) and original["sha256"] == locator["snapshot"]["sha256"]
                 and original["sha256"] != locator["current"]["sha256"] and len({current, snapshot, parent}) == 3,
                 "Historical command original/current/preserved identity is not separate and exact")
        key = (original["path"], original["sha256"])
        _require(key not in seen, "Duplicate or conflicting historical command observation")
        seen.add(key)
        parent_value = _auxiliary_json(parent, repo, registered)
        expression = locator["pointer"]
        _require(isinstance(expression, str) and expression.startswith("/") and len(expression) <= 4096,
                 "Historical command origin requires an exact bounded JSON pointer")
        tokens = expression[1:].split("/")
        _require(all(token and re.search(r"~(?![01])", token) is None for token in tokens), "Historical command pointer is malformed")
        value: Any = parent_value
        edge: list[str | int] = []
        for encoded in tokens:
            token = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict):
                _require(token in value, "Historical command origin pointer is missing")
                edge.append(token)
                value = value[token]
            elif isinstance(value, list):
                _require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and int(token) < len(value),
                         "Historical command origin array pointer is invalid")
                edge.append(int(token))
                value = value[int(token)]
            else:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Historical command pointer crosses a scalar")
        _require(value == original, "Historical command private origin does not declare the exact original ref")
        try:
            old_value = json.loads(snapshot.read_bytes(), object_pairs_hook=unique)
            current_value = json.loads(current.read_bytes(), object_pairs_hook=unique)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Historical command versions are not valid JSON") from exc
        _require(isinstance(old_value, dict) and set(old_value) == required
                 and old_value.get("schema_version") == "verification-command/v1"
                 and json.dumps(current_value, sort_keys=True, separators=(",", ":"))
                 == json.dumps({**old_value, "receipt": original}, sort_keys=True, separators=(",", ":")),
                 "Unsupported historical command schema or changes beyond its exact original self-reference")
        name, argv = old_value["name"], old_value["argv"]
        _require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]+", name) is not None
                 and current.name == f"{name}.command.json" and isinstance(argv, list) and bool(argv)
                 and all(isinstance(arg, str) and "\x00" not in arg for arg in argv)
                 and repo is not None and old_value["cwd"] == str(repo.resolve()),
                 "Historical command name, argv, receipt path or canonical repository cwd is invalid")
        _require(type(old_value["timed_out"]) is bool and type(old_value["interrupted"]) is bool
                 and (old_value["exit_code"] is None or type(old_value["exit_code"]) is int)
                 and (old_value["error"] is None or isinstance(old_value["error"], str)),
                 "Historical command process record_key types are invalid")
        for record_key in ("wall_seconds", "timeout_seconds"):
            v = old_value[record_key]
            _require(type(v) in (int, float) and math.isfinite(v) and v >= 0
                     and (record_key != "timeout_seconds" or v > 0), "Historical command numeric time fields are invalid")
        try:
            started = datetime.fromisoformat(old_value["started_at"])
            finished = datetime.fromisoformat(old_value["finished_at"])
            _require(started.utcoffset() is not None and finished.utcoffset() is not None and started <= finished,
                     "Historical command timestamps lack timezone or are reversed")
        except (TypeError, ValueError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Historical command timestamps are invalid") from exc
        reported_status = "PASS" if old_value["exit_code"] == 0 and not (old_value["error"] or old_value["timed_out"] or old_value["interrupted"]) else "FAIL"
        _require(old_value["status"] == reported_status, "Historical command declared status contradicts its own fields")
        log_refs = []
        for record_key in ("stdout", "stderr"):
            log_ref = old_value[record_key]
            log_path, identity = actual(log_ref)
            _require(log_path == current.parent / f"{name}.{record_key}", "Historical command log is not the exact recorder path")
            paths[record_key] = (log_path, identity)
            log_refs.append(log_ref)
        for record_key, (path, identity) in paths.items():
            ref = old_value[record_key] if record_key in ("stdout", "stderr") else locator[record_key]
            _require(_source_file_identity(path.stat()) == _source_file_identity(identity) and artifact_ref(path) == ref,
                     "Historical command metadata/log bytes changed during observation")
        results.append({**locator, "edge": edge, "log_refs": log_refs,
                        "file_identities": {k: {"path": str(path), "identity": list(_source_file_identity(identity))}
                                            for k, (path, identity) in paths.items()},
                        "byte_update_relation": "Exact original command record plus original receipt reference only",
                        "claimed_original_status": old_value["status"], "claimed_original_exit_code": old_value["exit_code"],
                        "claim_status": "UNVERIFIED", "execution_status": "UNVERIFIED", "validation_status": "UNVERIFIED",
                        "scope": "Preserved/current formal command bytes and private origin only; no execution, validation, semantic or publication approval"})
    return results


def _native_alias_parent_json(parent: Path, parent_ref: dict[str, Any], authority: dict[str, Any],
                              repo: Path | None, registered: set[str]) -> tuple[dict[str, Any], str]:
    """Inventory a current request's exact build library bytes, without approval.

    Build records remain private and all other graph edges remain mandatory.
    This narrow role neither authenticates the build nor accepts its status,
    command, source-history, execution, capability or review claims.
    """
    request_path = _file(authority["request"])
    request = _native_runtime_request_json(request_path, repo, registered)
    linked = request.get("build_receipt")
    if not (isinstance(linked, dict) and linked.get("path") == str(parent)
            and linked.get("sha256") == parent_ref["sha256"]):
        return _auxiliary_json(parent, repo, registered), "current_auxiliary_diagnostic_bytes"
    _require(set(linked) in ({"path", "sha256"}, {"path", "sha256", "bytes"})
             and parent.stat().st_size <= MAX_UNIT_BYTES
             and ("bytes" not in linked or type(linked["bytes"]) is int and linked["bytes"] == parent.stat().st_size),
             "Native build alias parent reference or byte bound differs")
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            _require(key not in result, "Native build alias parent has duplicate JSON keys")
            result[key] = value
        return result
    try:
        payload = json.loads(parent.read_bytes(), object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Native build alias parent is not bounded JSON") from exc
    _require(isinstance(payload, dict) and set(payload) == {"schema_version", "source_acquisition", "patch",
             "patch_manifest", "runner", "source_before", "source_after", "source_unchanged_during_build",
             "commands", "binary", "runtime_libraries", "status"}
             and payload.get("schema_version") == "private-runtime-build/v1",
             "Native alias parent is not the exact supported current build record role")
    _require(not _contains_formal_schema({key: value for key, value in payload.items() if key != "schema_version"}, repo, registered),
             "Nested formal claims cannot use current native build alias observation")
    expected = [row["declared_reference"] for row in authority["libraries"]]
    _require(json.dumps(payload.get("runtime_libraries"), sort_keys=True, separators=(",", ":"))
             == json.dumps(request.get("runtime_libraries"), sort_keys=True, separators=(",", ":"))
             == json.dumps(expected, sort_keys=True, separators=(",", ":")),
             "Native build alias library list differs from the complete current request authority")
    _require(artifact_ref(parent) == parent_ref and artifact_ref(request_path) == authority["request"],
             "Native build alias parent or request changed during current-byte observation")
    return payload, "current_native_build_runtime_bytes"


def _inventory_alias_row_inventory(locators: list[dict[str, Any]] | None,
                                   directory: Path, repo: Path | None, registered: set[str],
                                   replay_ref: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Observe explicit copied inventory rows using verified current tool bytes.

    The historical parent remains private. Neither its execution nor its
    classification claims become authoritative through current byte equality.
    """
    from .native_provenance import alias_snapshot

    _require(locators is None or isinstance(locators, list), "Inventory alias rows require explicit locators")
    _require(len(locators or []) <= 4096, "Inventory alias row observations exceed their finite bound")
    if not locators:
        return []
    _require(repo is not None and replay_ref is not None, "Inventory alias rows need a current verified tool replay")
    assert repo is not None
    replay = _verified_synthetic_replay(replay_ref, repo)
    tools = replay["external_tool_links"]
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str | int, ...]]] = set()

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("duplicate JSON keys")
            value[key] = child
        return value

    def read(ref: Any) -> tuple[Path, dict[str, Any]]:
        _require(isinstance(ref, dict) and set(ref) == {"path", "sha256"},
                 "Inventory alias parent requires an exact artifact reference")
        path = _file(ref)
        _require(path == path.resolve() and path == Path(os.path.abspath(path))
                 and path.is_relative_to(directory) and path.stat().st_size <= MAX_UNIT_BYTES
                 and path.name not in {"project.json", "acceptance.local.json"}
                 and not any(path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                 and ref["sha256"] not in registered, "Inventory alias parent is protected, linked or outside its task")
        try:
            value = json.loads(path.read_bytes(), object_pairs_hook=unique)
        except (ValueError, UnicodeDecodeError) as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Inventory alias parent is not bounded unique JSON") from exc
        _require(isinstance(value, dict), "Inventory alias parent is not a JSON object")
        assert isinstance(value, dict)
        body = {key: child for key, child in value.items() if key != "schema_version"} if value.get("schema_version") == "private-task-inventory/v1" else value
        _require(not _contains_formal_schema(body, repo, registered),
                 "Formal or private source evidence cannot become inventory alias metadata")
        _require(artifact_ref(path) == ref, "Inventory alias parent changed during observation")
        return path, value

    def select(value: dict[str, Any], expression: Any) -> tuple[Any, tuple[str | int, ...]]:
        _require(isinstance(expression, str) and expression.startswith("/") and len(expression) <= 4096,
                 "Inventory alias row needs an exact bounded JSON pointer")
        tokens = expression[1:].split("/")
        _require(all(token and re.search(r"~(?![01])", token) is None for token in tokens),
                 "Inventory alias pointer is malformed")
        item: Any = value
        edge: list[str | int] = []
        for encoded in tokens:
            token = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(item, dict):
                _require(token in item, "Inventory alias pointer is missing")
                item = item[token]
                edge.append(token)
            elif isinstance(item, list):
                _require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and int(token) < len(item),
                         "Inventory alias array pointer is invalid")
                item = item[int(token)]
                edge.append(int(token))
            else:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Inventory alias pointer crosses a scalar")
        return item, tuple(edge)

    required_inventory = {"schema_version", "project", "scope", "dependencies", "entries", "entry_count",
                          "mandatory_private_count", "unresolved", "known_graph", "classification_status",
                          "preserved_private_inputs", "limits", "excluded_directories"}
    def inventory_rows(origin: dict[str, Any]) -> list[dict[str, Any]]:
        rows = origin.get("entries")
        _require(set(origin) == required_inventory and origin.get("schema_version") == "private-task-inventory/v1"
                 and origin.get("classification_status") == "UNVERIFIED" and origin.get("excluded_directories") == []
                 and isinstance(rows, list) and type(origin.get("entry_count")) is int
                 and 0 < len(rows) == origin["entry_count"] <= MAX_TASK_FILES
                 and isinstance(origin.get("unresolved"), list) and isinstance(origin.get("known_graph"), dict),
                 "Inventory alias origin is not a complete typed unclassified inventory")
        assert isinstance(rows, list)
        _require(all(isinstance(row, dict) and isinstance(row.get("path"), str) and Path(row["path"]).is_absolute()
                     and isinstance(row.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
                     and row.get("entry_type") in {"file", "symlink"}
                     and row.get("classification") in {"UNCLASSIFIED", "media", "transcript", "review", "credentials"}
                     for row in rows) and len({row["path"] for row in rows}) == len(rows)
                 and type(origin.get("mandatory_private_count")) is int
                 and origin["mandatory_private_count"] == sum(row["classification"] != "UNCLASSIFIED" for row in rows),
                 "Inventory alias origin denominator or classifications are invalid")
        return rows

    for locator in locators:
        _require(isinstance(locator, dict) and set(locator) == {"parent", "pointer", "typed_origin", "tool_alias_index"}
                 and isinstance(locator["typed_origin"], dict) and set(locator["typed_origin"]) == {"parent", "pointer"},
                 "Inventory alias row locator is malformed")
        parent, payload = read(locator["parent"])
        origin_path, origin = read(locator["typed_origin"]["parent"])
        rows = inventory_rows(origin)
        if payload.get("schema_version") == "private-task-inventory/v1":
            inventory_rows(payload)
        typed, origin_edge = select(origin, locator["typed_origin"]["pointer"])
        _require(len(origin_edge) == 2 and origin_edge[0] == "entries" and type(origin_edge[1]) is int,
                 "Inventory alias typed origin must name its exact inventory entry")
        index = locator["tool_alias_index"]
        _require(type(index) is int and 0 <= index < len(tools), "Inventory alias tool index is invalid")
        authority = tools[index]
        def target_stat(raw: str) -> list[int]:
            value = os.stat(raw)
            return [value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns]
        target_identity = target_stat(authority["link_path"])
        before = alias_snapshot(authority["link_path"])
        _require({key: before["target"][key] for key in ("path", "sha256")} == authority["actual_target"] and before["hops"],
                 "Inventory alias current tool target changed")
        selected_hop = next((hop for hop in before["hops"] if hop["path"] == authority["link_path"]), None)
        _require(selected_hop is not None and selected_hop["link_text"] == authority["link_target"]
                 and selected_hop["link_bytes_sha256"] == authority["link_bytes_sha256"],
                 "Inventory alias literal differs from verified replay authority")
        by_path = {row["path"]: row for row in rows}
        expected_rows = [{"path": hop["path"], "sha256": hop["link_bytes_sha256"], "entry_type": "symlink",
                          "target": hop["link_text"], "classification": "UNCLASSIFIED"} for hop in before["hops"]]
        _require(all(by_path.get(row["path"]) == row for row in expected_rows),
                 "Inventory alias origin lacks the exact complete current link rows")
        target_row = by_path.get(before["target"]["path"], {})
        _require(target_row.get("entry_type") == "file" and target_row.get("classification") == "UNCLASSIFIED"
                 and target_row.get("sha256") == before["target"]["sha256"],
                 "Inventory alias origin lacks the exact current canonical target")
        expected = next((row for row in expected_rows if row["path"] == authority["link_path"]), None)
        _require(expected is not None and typed == expected, "Inventory alias typed row differs from the current tool alias")
        selected, edge = select(payload, locator["pointer"])
        if selected != typed:
            _require(parent == origin_path and len(edge) == 3 and edge[:2] == ("known_graph", "unfollowed_refs")
                     and type(edge[2]) is int and isinstance(selected, dict)
                     and set(selected) == {"path", "sha256", "reason"} and isinstance(selected["reason"], str)
                     and selected["path"] == typed["path"] and selected["sha256"] == typed["sha256"],
                     "Bare inventory alias copy lacks its exact typed parent and edge")
        key = (str(parent), edge)
        _require(key not in seen, "Duplicate or conflicting inventory alias row observation")
        seen.add(key)
        _require(before == alias_snapshot(authority["link_path"]) and target_identity == target_stat(authority["link_path"])
                 and artifact_ref(parent) == locator["parent"]
                 and artifact_ref(origin_path) == locator["typed_origin"]["parent"],
                 "Inventory alias parent, literal, chain or target changed during observation")
        observations.append({"parent": locator["parent"], "pointer": locator["pointer"], "edge": list(edge),
                             "value": selected, "typed_origin": locator["typed_origin"], "typed_row": typed,
                             "authority_replay": replay["bundle"], "tool_alias_index": index, "alias_identity": before,
                             "target_stat_identity": target_identity,
                             "claim_status": "UNVERIFIED", "execution_status": "UNVERIFIED", "history_supported": False,
                             "scope": "Explicit historical inventory row correspondence and current tool bytes only; entire parent private; no creation, execution, public classification or AV approval"})
    return observations


def _native_runtime_alias_inventory(locators: list[dict[str, Any]] | None,
                                    native_observations: list[dict[str, Any]], directory: Path,
                                    repo: Path | None, registered: set[str]) -> list[dict[str, Any]]:
    """Bind explicit current diagnostic edges to already observed native bytes.

    A locator never authorizes an unlisted parent/sibling, history or execution.
    The caller constructs native observations with the strict current-byte
    reader and repeats that complete kernel/link/target check after graph walk.
    """
    _require(locators is None or isinstance(locators, list), "Native alias repetitions require an explicit locator list")
    _require(len(locators or []) <= 4096, "Native alias repetitions exceed the finite edge inspection bound")
    observations: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str | int, ...]]] = set()
    for locator in locators or []:
        _require(isinstance(locator, dict) and set(locator) == {"parent", "pointer", "authority_request", "library_index"},
                 "Native repeated alias locator has unsupported fields")
        parent = _file(locator["parent"])
        _require(parent == parent.resolve() and parent == Path(os.path.abspath(parent))
                 and parent.is_relative_to(directory) and parent.name not in {"project.json", "acceptance.local.json"}
                 and not any(parent.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts"))
                 and locator["parent"]["sha256"] not in registered,
                 "Native repeated alias parent is noncanonical, outside task or protected")
        matches = [row for row in native_observations if row["request"] == locator["authority_request"]]
        _require(len(matches) == 1, "Native repeated alias has no exact current request authority")
        authority = matches[0]
        payload, parent_role = _native_alias_parent_json(parent, locator["parent"], authority, repo, registered)
        index = locator["library_index"]
        _require(type(index) is int and 0 <= index < len(authority["libraries"]), "Native repeated alias library index is invalid")
        library = authority["libraries"][index]
        _require(bool(library["hops"]), "Native repeated alias authority does not name an actual alias")
        expression = locator["pointer"]
        if parent_role == "current_native_build_runtime_bytes":
            _require(expression == f"/runtime_libraries/{index}",
                     "Native build alias pointer must name its exact runtime library row")
        _require(isinstance(expression, str) and expression.startswith("/") and len(expression) <= 4096,
                 "Native repeated alias requires an exact bounded JSON pointer")
        tokens = expression[1:].split("/")
        _require(all(token and re.search(r"~(?![01])", token) is None for token in tokens),
                 "Native repeated alias JSON pointer is malformed")
        value: Any = payload
        edge: list[str | int] = []
        for encoded in tokens:
            token = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(value, dict):
                _require(token in value, "Native repeated alias pointer is missing")
                edge.append(token)
                value = value[token]
            elif isinstance(value, list):
                _require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None and int(token) < len(value),
                         "Native repeated alias array pointer is invalid")
                edge.append(int(token))
                value = value[int(token)]
            else:
                raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Native repeated alias pointer crosses a scalar")
        _require(isinstance(value, dict) and set(value) in ({"path", "sha256"}, {"path", "sha256", "bytes"})
                 and value["path"] == library["declared_reference"]["path"]
                 and value["sha256"] == library["declared_reference"]["sha256"]
                 and ("bytes" not in value or type(value["bytes"]) is int and value["bytes"] == library["target_lstat"]["size"]),
                 "Native repeated alias edge differs from the exact current declared library")
        key = (str(parent), tuple(edge))
        _require(key not in seen, "Duplicate or conflicting native repeated alias pointer")
        seen.add(key)
        _require(artifact_ref(parent) == locator["parent"], "Native repeated alias parent bytes changed during observation")
        observations.append({"parent_role": parent_role, "parent": locator["parent"], "pointer": expression, "edge": edge,
                             "authority_request": locator["authority_request"], "library_index": index,
                             "declared_reference": value, "library_identity": library,
                             "claim_status": "UNVERIFIED", "execution_status": "UNVERIFIED", "history_supported": False,
                             "scope": "Explicit current auxiliary diagnostic alias bytes only; entire parent private; no history, execution, intake, calibration, review or publication approval"})
    return observations


def _runtime_library_inventory(request_refs: list[dict[str, Any]] | None, directory: Path,
                               repo: Path | None, registered: set[str], *,
                               native_request: bool) -> list[dict[str, Any]]:
    """Current parent and library bytes only; no execution/history approval."""
    _require(request_refs is None or isinstance(request_refs, list), "Auxiliary runtime requests require explicit hashed request locators")
    _require(len(request_refs or []) <= 512, "Auxiliary runtime request count exceeds its finite inspection bound")
    observations: list[dict[str, Any]] = []
    seen_requests: set[str] = set()

    def supported_path(path: Path) -> None:
        _require(path.is_absolute() and path == Path(os.path.abspath(path)) and path.parent == path.parent.resolve(),
                 "Auxiliary runtime path is noncanonical or traverses a directory alias")
        _require(not any(path.is_relative_to(directory / name) for name in ("sources", "renders", "reviews", "review", "transcripts")),
                 "Private source/transcript/render/review paths cannot become auxiliary runtime aliases")

    def status(path: Path) -> dict[str, int]:
        try:
            value = path.lstat()
        except OSError as exc:
            raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary runtime target or alias is missing") from exc
        return {"mode": value.st_mode, "size": value.st_size, "device": value.st_dev, "inode": value.st_ino,
                "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}

    def binary_format(path: Path) -> str:
        with path.open("rb") as handle:
            header = handle.read(64)
        if len(header) >= 32 and header[:4] in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"}:
            endian = "<" if header[0] in {0xCE, 0xCF} else ">"
            _require(struct.unpack(endian + "I", header[12:16])[0] == 6, "Auxiliary runtime target is not a Mach-O shared library")
            return "Mach-O MH_DYLIB"
        if len(header) >= 32 and header[:4] == b"\x7fELF" and header[4] in {1, 2} and header[5] in {1, 2}:
            endian = "<" if header[5] == 1 else ">"
            _require(struct.unpack(endian + "H", header[16:18])[0] == 3, "Auxiliary runtime target is not an ELF dynamic object")
            return "ELF ET_DYN"
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary runtime target lacks a supported shared-library binary header")

    for request_ref in request_refs or []:
        parent = _file(request_ref)
        supported_path(parent)
        _require(parent.is_relative_to(directory) and parent.name not in {"project.json", "acceptance.local.json"}
                 and request_ref["sha256"] not in registered and str(parent) not in seen_requests,
                 "Auxiliary runtime request is outside its task, duplicated or a protected source identity")
        seen_requests.add(str(parent))
        payload = (_native_runtime_request_json(parent, repo, registered) if native_request
                   else _auxiliary_json(parent, repo, registered))
        libraries = payload.get("runtime_libraries")
        _require(isinstance(libraries, list) and 0 < len(libraries) <= 512,
                 "Auxiliary runtime request has no bounded actual runtime_libraries edge")
        assert isinstance(libraries, list)
        rows = []
        declared_paths: set[str] = set()
        for ref in libraries:
            _require(isinstance(ref, dict) and isinstance(ref.get("path"), str)
                     and isinstance(ref.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"])
                     and ref["sha256"] not in registered and ref["path"] not in declared_paths,
                     "Auxiliary runtime edge is duplicated, malformed or a registered private source")
            declared_paths.add(ref["path"])
            path = Path(ref["path"])
            _require(str(path) == ref["path"], "Auxiliary runtime declared path is not canonical")
            original = path
            hops: list[dict[str, Any]] = []
            visited: set[str] = set()
            while True:
                supported_path(path)
                _require(str(path) not in visited and len(visited) < 32, "Auxiliary runtime aliases contain a cycle or exceed the hop bound")
                visited.add(str(path))
                before = status(path)
                if stat.S_ISLNK(before["mode"]):
                    link = os.readlink(path)
                    encoded = os.fsencode(link)
                    # Lexical collapse before following a directory symlink
                    # can point at different bytes than the kernel opens.
                    # Such paths are outside this bounded alias scope.
                    _require(not any(part in {".", ".."} for part in link.split("/")),
                             "Auxiliary runtime link text is noncanonical or traverses a directory alias")
                    _require(status(path) == before and before["size"] == len(encoded), "Auxiliary runtime alias changed while being read")
                    hops.append({"path": str(path), "target": link, "link_bytes_hex": encoded.hex(),
                                 "link_bytes_sha256": hashlib.sha256(encoded).hexdigest(), "lstat": before})
                    path = path.parent / link if not Path(link).is_absolute() else Path(link)
                    continue
                _require(stat.S_ISREG(before["mode"]), "Auxiliary runtime target is not a regular file")
                target = artifact_ref(path)
                _require(target["sha256"] == ref["sha256"] and target["sha256"] not in registered,
                         "Auxiliary runtime target bytes changed or match a registered private source")
                _require("bytes" not in ref or ref["bytes"] == before["size"], "Auxiliary runtime declared target byte count changed")
                kind = binary_format(path)
                _require(status(path) == before, "Auxiliary runtime target changed while being read")
                try:
                    actual_path = original.resolve(strict=True)
                    actual_stat = original.stat()
                    actual_identity = {"mode": actual_stat.st_mode, "size": actual_stat.st_size,
                                       "device": actual_stat.st_dev, "inode": actual_stat.st_ino,
                                       "mtime_ns": actual_stat.st_mtime_ns, "ctime_ns": actual_stat.st_ctime_ns}
                    _require(actual_path == path and actual_identity == before and sha256(original) == target["sha256"],
                             "Auxiliary runtime kernel resolution or opened target bytes changed")
                except OSError as exc:
                    raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary runtime kernel target is unavailable") from exc
                _require(status(path) == before and all(status(Path(hop["path"])) == hop["lstat"] for hop in hops),
                         "Auxiliary runtime alias or target changed during kernel resolution verification")
                rows.append({"declared_reference": ref, "hops": hops, "target": target,
                             "target_lstat": before, "binary_format": kind, "classification": "UNCLASSIFIED"})
                break
        _require(artifact_ref(parent) == {"path": request_ref["path"], "sha256": request_ref["sha256"]},
                 "Auxiliary runtime parent request changed while reading its library edges")
        observation: dict[str, Any] = {"request": request_ref, "libraries": rows, "claim_status": "UNVERIFIED",
                       "scope": "Exact auxiliary runtime request, link text and target byte inventory only; no execution, AI or publication approval"}
        if native_request:
            observation.update({"observation_role": "current_native_runtime_request_bytes",
                                "execution_status": "UNVERIFIED", "history_supported": False,
                                "scope": "Exact current native request and runtime_libraries bytes only; parent remains private; no history, process, intake, capability, review or publication approval"})
        observations.append(observation)
    return observations


def _contains_formal_schema(value: Any, repo: Path | None, registered: set[str]) -> bool:
    reserved: set[str] = set(re.findall(r"[a-z][a-z0-9_-]*/v[0-9]+", Path(__file__).read_text()))
    if repo is not None:
        for base, pattern in ((repo / "src/talkcut", "*.py"), (repo / "schemas", "*.json")):
            for source in base.rglob(pattern):
                reserved.update(re.findall(r"[a-z][a-z0-9_-]*/v[0-9]+", source.read_text()))
    def immutable_claim(item: Any) -> bool:
        if isinstance(item, dict):
            return (item.get("schema_version") in reserved
                    or item.get("schema_version") == "transcript/v1" and item.get("source_sha256") in registered
                    or any(immutable_claim(child) for child in item.values()))
        return isinstance(item, list) and any(immutable_claim(child) for child in item)
    return immutable_claim(value)


def _native_runtime_request_json(path: Path, repo: Path | None, registered: set[str]) -> dict[str, Any]:
    """Read only a current audio-request role; this is not a receipt validator."""
    _require(path.is_absolute() and path == path.resolve() and path.is_file() and not path.is_symlink()
             and path.stat().st_size <= MAX_UNIT_BYTES and sha256(path) not in registered,
             "Current native request is missing, linked, oversized or a registered source")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Current native request is not bounded JSON") from exc
    _require(isinstance(value, dict) and value.get("schema_version") == "local-audio-calibration-request/v1"
             and value.get("input_modality") == "audio" and value.get("video_input") is None,
             "Unsupported current native request role")
    _require(not _contains_formal_schema({key: child for key, child in value.items() if key != "schema_version"}, repo, registered),
             "Nested formal source/review/measurement claims cannot use native runtime byte observation")
    return value


def _auxiliary_json(path: Path, repo: Path | None, registered: set[str]) -> dict[str, Any]:
    """Read auxiliary bytes without accepting a formal artifact's truth claims."""
    _require(path.is_absolute() and path.is_file() and not path.is_symlink()
             and path.stat().st_size <= MAX_UNIT_BYTES, "Auxiliary metadata exceeds the bounded JSON inspection limit")
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeDecodeError) as exc:
        raise TalkCutError("PUBLICATION_PRIVACY_UNVERIFIED", "Auxiliary historical bytes must be bounded JSON metadata") from exc
    _require(isinstance(value, dict) and not _contains_formal_schema(value, repo, registered),
             "Immutable source/transcript/review/measurement/render evidence cannot use auxiliary history")
    return value
