"""Generate public synthetic media and exercise the installed reversible CLI.

This timing/transaction example is test-only. It cannot establish AV review or
READY_FOR_OWNER. Its mathematical test pattern and sine wave contain no private
recording, speech, font, music or third-party visual asset.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from talkcut.project import artifact_ref, atomic_json, load_project, verified_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    directory = args.directory.resolve()
    if directory.exists() and any(directory.iterdir()):
        parser.error(
            "Choose a new or empty directory; successful artifacts are preserved"
        )
    directory.mkdir(parents=True, exist_ok=True)
    project = directory / "project"
    executions = []

    def command(name, argv):
        stdout = directory / (name + ".stdout.json")
        stderr = directory / (name + ".stderr.log")
        started = time.monotonic()
        with stdout.open("wb") as out, stderr.open("wb") as err:
            result = subprocess.run(
                argv, stdout=out, stderr=err, timeout=1200, check=False
            )
        executions.append(
            {
                "name": name,
                "argv": argv,
                "exit_code": result.returncode,
                "wall_seconds": time.monotonic() - started,
                "stdout": artifact_ref(stdout),
                "stderr": artifact_ref(stderr),
            }
        )
        atomic_json(directory / "executions.json", executions)
        if result.returncode:
            raise RuntimeError(f"{name} failed; inspect {stderr}")
        return json.loads(stdout.read_text()) if stdout.stat().st_size else None

    def cli(name, *parts):
        return command(
            name, [sys.executable, "-m", "talkcut", *map(str, parts), "--json"]
        )

    source = directory / "synthetic.mp4"
    command(
        "01-generate",
        [
            "ffmpeg",
            "-v",
            "error",
            "-nostdin",
            "-n",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=320x180:rate=30000/1001:duration=6",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=700:sample_rate=44100:duration=6.2",
            "-map",
            "1:a",
            "-map",
            "0:v",
            "-c:a",
            "aac",
            "-c:v",
            "libx264",
            "-preset",
            "ultrafast",
            "-video_track_timescale",
            "30000",
            str(source),
        ],
    )
    cli("02-init", "init", project, "--screen", source, "--speaker", source)
    cli("03-inspect", "inspect", project, "--full-decode")
    cli("04-plan", "plan", "build", project, "--diagnostic")
    baseline = cli("05-baseline", "render", project, "--preset", "ultrafast")
    baseline_timeline = verified_json(load_project(project)["active_timeline"])
    proposed = cli(
        "06-propose",
        "plan",
        "add-test-cut",
        project,
        "--start",
        "2",
        "--end",
        "3",
        "--expected-revision",
        load_project(project)["revision"],
    )
    candidate = proposed["candidate_id"]

    def decision(name, action):
        parts = [
            "plan",
            "restore" if action == "restore" else "decide",
            project,
            "--candidate",
            candidate,
            "--expected-revision",
            load_project(project)["revision"],
        ]
        if action != "restore":
            parts += ["--decision", "accept"]
        return cli(name, *parts)

    decision("07-accept", "accept")
    cut = cli("08-cut", "render", project, "--preset", "ultrafast")
    cut_timeline = verified_json(load_project(project)["active_timeline"])
    decision("09-restore", "restore")
    restored = cli("10-restored", "render", project, "--preset", "ultrafast")
    restored_timeline = verified_json(load_project(project)["active_timeline"])
    decision("11-reapply", "accept")
    reapplied = cli("12-reapplied", "render", project, "--preset", "ultrafast")
    reapplied_timeline = verified_json(load_project(project)["active_timeline"])
    cached = cli("13-unchanged", "render", project, "--preset", "ultrafast")
    cli("14-reopen", "status", project)
    for key in ("frames", "retained", "duration", "sample_count", "speaker_omissions"):
        assert baseline_timeline[key] == restored_timeline[key], key
        assert cut_timeline[key] == reapplied_timeline[key], key
    assert baseline["output"]["sha256"] == restored["output"]["sha256"]
    assert cut["output"]["sha256"] == reapplied["output"]["sha256"]
    assert cached["cache_hit"] is True
    for render in (baseline, cut, restored, reapplied):
        assert (
            artifact_ref(render["output"]["path"])["sha256"]
            == render["output"]["sha256"]
        )
    report = {
        "schema_version": "recovery-example/v1",
        "test_only": True,
        "technical_roundtrip": "PASS",
        "audiovisual_review": "UNVERIFIED",
        "owner_acceptance": "pending",
        "project": str(project),
        "executions": artifact_ref(directory / "executions.json"),
        "outputs": {
            "baseline": baseline,
            "cut": cut,
            "restored": restored,
            "reapplied": reapplied,
        },
    }
    atomic_json(directory / "result.json", report)
    print(
        json.dumps(
            {
                "technical_roundtrip": "PASS",
                "result": str(directory / "result.json"),
                "test_only": True,
                "audiovisual_review": "UNVERIFIED",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
