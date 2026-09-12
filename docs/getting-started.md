# Make your first edit

This guide takes two local recordings through TalkCut's first-edit alpha: preserve
the screen canvas, place the speaker in the upper-right corner, choose one audio
track, and optionally trim the beginning and end. You will get an MP4 and a report
of its technical checks. Review the video yourself before using it.

The draft workflow assumes a common clock with the constant offsets you supply.
It preserves internal pauses and speech. The draft report leaves AI review
unverified and owner acceptance pending. The [acceptance guide](acceptance.md)
explains both the first-edit handoff and the strict certification workflow.

## 1. Check your environment

Run commands from the repository root. You need Python 3.12+, `uv`, and separately
installed `ffmpeg` and `ffprobe` on your `PATH`. FFmpeg is not bundled.

```sh
uv sync --locked
uv run --locked talkcut doctor --json
```

Check that the report says `"status": "PASS"`. The `ai_media_capability` field
remains `UNVERIFIED`; the local tool check does not execute an AI reviewer.

Use H.264 8-bit progressive SDR video with mono or stereo AAC audio in both input
files, with exactly one video stream and one audio stream per file. Unsupported
geometry, clocks or coverage can stop inspection or planning.
Full decode and rendering read the entire recording, so allow time and disk space
for source copies, outputs and evidence.

## 2. Preserve and inspect the recordings

Replace the two `/path/to/` values with your recordings. Quote paths that contain
spaces. Choose a new project directory; `init` will refuse to overwrite one.
The repository ignores everything under `projects/` in Git.

```sh
uv run --locked talkcut init projects/my-lecture \
  --screen /path/to/screen.mp4 \
  --speaker /path/to/speaker.mp4 \
  --json

uv run --locked talkcut inspect projects/my-lecture --full-decode --json
```

`init` keeps the originals and makes hash-verified copies under the project.
`inspect` records decoded presentation timestamps (PTS), stream geometry and
audio samples. Both sources must pass complete inspection before you can build
a draft.

## 3. Choose the timing and build a draft

Start with a composition of the complete recording when both files already share
the intended timing. Choose the recording whose audio you want to hear. TalkCut
uses that one track throughout the edit.

```sh
uv run --locked talkcut status projects/my-lecture --json
```

Copy the integer in `project_revision` into `REVISION` below. Commands that change
the project can advance this number, including inspection and rendering. Read it
again before making a later edit.

```sh
uv run --locked talkcut draft build projects/my-lecture \
  --audio-source screen \
  --audio-offset 0 \
  --speaker-offset 0 \
  --trim-start 0 \
  --trim-end 0 \
  --reason "Preserve the complete recording for the first composition" \
  --expected-revision REVISION \
  --json
```

All timing values are seconds. Integers, decimals such as `0.5`, and fractions
such as `1/2` are accepted. For a negative fraction, use an equals sign, for
example `--speaker-offset=-1/2`.

| Option | What it means |
| --- | --- |
| `--audio-source screen` or `speaker` | Select the only audio track in the output. Both inputs still need to pass inspection. |
| `--audio-offset` | Place the selected audio on the screen clock. A positive value moves it later. |
| `--speaker-offset` | Place speaker video on the screen clock, independently of audio. A positive value moves it later. |
| `--trim-start` | Duration to remove from the beginning of the screen recording. |
| `--trim-end` | Duration to remove from the end, not an end timestamp. |
| `--reason` | Record why this composition or these reviewed trims are appropriate. |

For example, speaker footage with an event at source time `8` seconds and a
speaker offset of `2` places that event at screen time `10` seconds. Source time
in seconds is `PTS × time_base`. The draft mapping is
`screen time = source time in seconds + offset`; it does not correct clock drift.
Zero offsets retain the common-clock assumption and do not establish audiovisual
alignment.

On a 60-second screen recording, `--trim-start 2 --trim-end 3` requests removal
of the first 2 and last 3 seconds. TalkCut resolves cuts conservatively to actual
frame boundaries, so the applied durations can be smaller than requested. Check
`applied_edge_trims` in the evaluation report. Trims must leave some source
material; offsets must be smaller in magnitude than the screen duration.

The selected audio must cover every retained interval. If speaker video covers
only part of the edit, the overlay is absent outside that coverage; the report
lists these intervals in `speaker_omissions`. A draft with no retained speaker
coverage is rejected.

## 4. Render, evaluate and watch

```sh
uv run --locked talkcut render projects/my-lecture --profile draft --json
uv run --locked talkcut draft evaluate projects/my-lecture --json
```

Keep `--profile draft` explicit: the render command defaults to `diagnostic`.
The draft profile requires a plan from `draft build`.

The evaluation re-decodes the complete output and checks its current source,
plan, geometry and frame/sample schedule. A successful report includes:

| Field | Read it as |
| --- | --- |
| `status: DRAFT_TECHNICALLY_READY` | The draft passed the technical evaluation. |
| `technical` | Measured decode, timing and geometry results. |
| `output.path` | The MP4 to open in your video player. |
| `artifact_ref.path` | The saved evaluation report. |
| `timing` | Your selected audio source and assumed offsets. |
| `ai_review: UNVERIFIED` | Whole-video AI review is still unverified. |
| `owner_acceptance: pending` | Owner approval has not been recorded. |

Watch the actual MP4. Check the beginning and ending, whether the speaker covers
important screen content, and audiovisual alignment across the recording. Listen
to the chosen audio track. Constant offsets cannot fix timing that drifts during
the lecture.

### Find the files later

The MP4 is saved at `projects/my-lecture/renders/<render-id>/draft.mp4`.
Use the exact `output.path` returned by `render` or `draft evaluate`, since the
render ID changes with its inputs and settings.

```text
projects/my-lecture/
├── project.json                 Current revision and artifact references
├── sources/                     Preserved copies of both recordings
├── evidence/                    Source inspection records
├── plans/                       Immutable edit plans
├── timelines/                   Compiled frame and sample schedules
├── renders/<render-id>/
│   ├── draft.mp4                Successful output
│   └── success.json             Render manifest, including output.path
├── reports/                     Draft evaluations and other reports
└── executions/                  CLI worker logs and execution records
```

`status` returns `active_render.path`, which points to `success.json`. It is a
manifest, not the video. Read its `output.path` to locate the active MP4 without
rerunning evaluation.

## 5. Revise or restore the edit

Run `status` again, then repeat `draft build` with your revised values and the
current revision. Use `--trim-start 0 --trim-end 0` to restore both edges. The
command selects a new plan and clears the active render; render and evaluate
again to see the change. Earlier plans and successful MP4s stay on disk.

To restore just one candidate by ID, see [plan decisions](cli-reference.md#plan-decisions).
For a measured level problem, the [audio attenuation guide](audio-processing.md)
explains how to reduce the selected track's gain with a reversible plan change.

## Troubleshooting

| Symptom or report | Next action |
| --- | --- |
| `DEPENDENCY_MISSING` from `doctor` | Read `message` for the missing executable. Install FFmpeg/ffprobe or correct `PATH`, then retry. |
| `PROJECT_EXISTS` | Reopen the project with `status`, or choose a new directory for different inputs. |
| `INPUT_UNVERIFIED` | Run `inspect --full-decode` and read each source's inspection report. A failed or unsupported source needs to be resolved before drafting. |
| `REVISION_CONFLICT` | Run `status`, review the current state, and use its `project_revision` for the next edit. |
| `AUDIO_UNCOVERED` in the error message | Recheck audio selection, offsets and retained coverage. TalkCut does not fill missing audio with silence. Only trim an uncovered edge after reviewing it. |
| `SPEAKER_UNCOVERED` | Recheck the speaker offset and trims; the selected interval must overlap actual speaker video. |
| `INVALID_DRAFT_TIME`, `INVALID_DRAFT_TRIM` or `INVALID_DRAFT_OFFSET` | Use seconds in integer, decimal or fraction form. Keep trims nonnegative and leave material; keep offsets within the screen duration. |
| `DRAFT_REQUIRED` or `RENDER_REQUIRED` | Build the draft first, then render it with `--profile draft`, then evaluate. |
| `STALE_INSPECTION`, `STALE_TIMELINE` or `STALE_RENDER` | Inspect the reported dependency, rebuild the current plan if needed, and render again. Do not edit saved manifests to make them match. |
| Render failed or was interrupted | Read the returned `execution.path` and its stdout/stderr references. Correct the cause and retry; a retry starts a fresh encode. See the [recovery guide](recovery.md). |

`sync analyze` is an optional audio correlation diagnostic. Its current anchor
profile needs zero source origins and at least 45 seconds; it returns exit code
`1` because visual and lip alignment remain unverified. It is not a prerequisite
for the explicit draft workflow. See the [CLI reference](cli-reference.md) for
command-specific exit behavior and the [documentation index](README.md) for the
strict review and acceptance path.
