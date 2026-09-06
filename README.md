# TalkCut

TalkCut is a local, reversible lecture editing CLI. It preserves a screen
recording's full canvas and overlays the speaker's full frame in the upper-right
corner, applying one measured source timeline to video and one audio source.

**Development status: alpha candidate, not a completed lecture-quality release.**
Source preservation, full decode/PTS inspection, container geometry, rational
cut/restore, compositing, technical QC, conservative acoustic analysis, review
clip generation, evidence import and fail-closed acceptance evaluation are
implemented. The first real lecture's complete audiovisual acceptance and public
release are still pending. No owner acceptance is implied.

## Install and verify

Python 3.12+, [uv](https://docs.astral.sh/uv/) and separately installed FFmpeg and
ffprobe are required. Dependencies are locked; FFmpeg is not bundled.

```sh
uv sync --locked
uv run --locked talkcut doctor --json
uv run --locked pytest -q
uv run --locked ruff check src tests examples
uv run --locked mypy src/talkcut
uv build
uv run --locked talkcut verify --output projects/oss-verification --json
```

Tests use generated media, including 100 cuts, fractional frame rates, irregular
PTS, speaker coverage boundaries, AAC padding and process/storage failures.
The measured local development environment is macOS 26.6.2 on Apple Silicon,
Python 3.12.13, uv 0.11.29 and FFmpeg/ffprobe 8.1.2. Other Python versions and
Linux remain unverified until their corresponding execution results are recorded.
Passing fixtures is not a certification of a real lecture or general editorial
accuracy. CI targets Linux and macOS; a configured job is not evidence that its
current remote run passed. The private acceptance report records actual results.

`verify` executes the locked suite in a fresh development environment, builds a
wheel, installs its exact runtime dependencies into another isolated environment,
and runs the recovery example outside the repository. It preserves JUnit, command
logs, installed-file checks and generated media. Its successful exit describes
those technical checks; independent fixture/support audit and lecture acceptance
remain separate.

## Start a private project

Use your own paths. The entire `projects/` directory is ignored by Git.

```sh
uv run --locked talkcut init projects/my-lecture --screen /path/to/screen.mp4 --speaker /path/to/speaker.mp4 --json
uv run --locked talkcut acceptance freeze projects/my-lecture/frozen-contract.local.json --json
uv run --locked talkcut inspect projects/my-lecture --full-decode --json
uv run --locked talkcut sync analyze projects/my-lecture --json
uv run --locked talkcut plan build projects/my-lecture --diagnostic --json
uv run --locked talkcut render projects/my-lecture --profile diagnostic --json
uv run --locked talkcut qc projects/my-lecture --json
uv run --locked talkcut qc projects/my-lecture --compare-source --json
```

`init` makes hash-verified durable copies and retains originals. `inspect` decodes
selected streams completely and inventories actual PTS, durations and samples.
Unknown display geometry is rejected unless MP4 track dimensions and transforms
provide explicit compatible evidence. Reported frame rates alone are not used to
compile a timeline.

Audio correlation reports measured fit/holdout anchors; video alignment and lip
sync remain unverified. This anchor profile currently requires zero source
origins and at least 45 seconds. A diagnostic plan is explicitly test-only and
cannot render a master or become `READY_FOR_OWNER`.

Use `sync import --model verified-sync.json --expected-revision REVISION` to
adopt a source mapping after separate executed audio, visual and lip-sync anchor
reviews. Import validates the exact source bytes and measurements, preserves the
previous artifacts and invalidates derived plans and output reviews. Output
anchors still require their own verification.

## Reversible decisions and review

```sh
uv run --locked talkcut status projects/my-lecture --json
uv run --locked talkcut plan add-test-cut projects/my-lecture --start 10 --end 12 --expected-revision 3 --json
uv run --locked talkcut plan decide projects/my-lecture --candidate CANDIDATE_ID --decision accept --expected-revision 4 --json
uv run --locked talkcut plan restore projects/my-lecture --candidate CANDIDATE_ID --expected-revision 5 --json
```

Use the revision returned by the previous command, rather than copying the example
revision numbers blindly. Test cuts remain excluded from real acceptance. Each
change stores an immutable plan/timeline and invalidates dependent output review.
A stale revision is rejected. Reopening verifies sources and the decision chain.
Failed renders preserve logs, partial files and previous successful outputs.
Rerunning a failed encode starts a fresh encode; identical successful requests
reuse only matching, verified artifacts.

The render CLI preserves the actual worker stdout, stderr and exit status and
registers the resulting media references for acceptance. Successful review imports
also register their verified execution and capability references. These records
retain diagnostic flags and unknown review status; registration is not approval.

The [executable recovery example and failure guide](docs/recovery.md) reproduce
this roundtrip with generated media and preserve the commands and measured results.

`analyze` measures the complete selected source audio and accepts versioned
transcript and audiovisual context imports. Silence duration or an empty
transcript alone never authorizes deletion. Without executed audiovisual context,
the result is `ANALYSIS_UNAVAILABLE`; it is not a verified keep-all edit.
Demonstrations, questions, reading time and meaningful corrections are protected.
Disfluency removal requires a separate reviewer execution bound to the candidate.

`review build` extracts every deletion with context, every seam from the actual
render and overlapping source/output windows. Creating these clips does not
review them. `review import` checks actual provider receipts, clip identities,
modalities, observation coverage and demonstrated capability. Cloud analysis is
disabled by default. No cloud SDK, paid API or automatic provider fallback is
configured. Local ASR also does not substitute for audiovisual review.

`qc --compare-source` streams every retained full-resolution frame outside the
speaker rectangle and every valid PCM sample against the measured source mapping.
It records pixel/waveform differences and potential new black, freeze, silence,
clipping and discontinuity intervals. Detector thresholds identify investigation
candidates; they are not semantic quality thresholds. Full comparison coverage
does not resolve the findings or certify important-content visibility and listening.

## Acceptance boundaries

The [first-lecture plan](docs/plans/0001-dgist-first-lecture.md),
[review protocol](docs/validation/lecture-review-protocol.md) and
[autonomous acceptance contract](docs/plans/0002-autonomous-goal-contract.md)
define the required evidence. The original planning documents remain frozen
contract snapshots. [Implementation decisions](docs/implementation-decisions.md)
record observed constraints and subsequent technical choices.

```sh
uv run --locked talkcut acceptance evaluate projects/my-lecture --render RENDER_ID --contract projects/my-lecture/frozen-contract.local.json --json
uv run --locked talkcut prepare-release projects/my-lecture --contract projects/my-lecture/frozen-contract.local.json --json
```

The first-lecture evaluator is specifically bound to the privately registered
DGIST dataset and AC01–AC13. It is not a generic certificate for arbitrary media.
Missing, stale, incomplete or unsupported evidence cannot pass. Full source,
deletions, seams and actual output coverage are recomputed. Exit codes are
`0` for the requested successful operation, `1` for failed/unverified acceptance,
and `2` for invalid input or execution failure. Technical-only QC returns `1`
until its separate audiovisual obligations are resolved.

`acceptance measure PROJECT --check CHECK_ID --input RAW_INPUTS_JSON --contract
CONTRACT_JSON --json` runs a typed checker in a separate process and preserves
its actual stdout, stderr, exit code and immutable evidence receipt. A zero exit
means measurement execution completed; unknown measurements remain `null`.
It does not promote media or establish acceptance. The input schemas live in
the corresponding `*_checks.py` modules; unrelated success logs and hand-entered
PASS labels cannot substitute for their source artifacts. `acceptance evaluate`
recomputes those measurements before applying AC01–AC13.

`READY_FOR_OWNER` is distinct from `OWNER_ACCEPTED`. Code release additionally
requires independent audit, reproducibility, passing CI, reviewed merge and an
alpha release. Private recordings, transcripts, review evidence and credentials
must never be included in public commits, packages, PRs or release assets.

## Scope and license

The initial source profile is H.264 8-bit progressive SDR with mono/stereo AAC.
Non-square display pixels, rotation/crop transforms, unsupported clocks and
unresolved gaps are explicitly rejected. The renderer preserves source screen
presentation intervals and inserts only documented events needed for speaker
coverage boundaries. It does not claim lossless pixels after compositing.

Subtitles, chapters, slide reconstruction, GUI editing, podcasts and publishing
lectures are outside this first workflow. See [CONTRIBUTING](CONTRIBUTING.md) and
[SECURITY](SECURITY.md). TalkCut code is [MIT licensed](LICENSE); third-party
executables, dependencies, models and recordings retain their own terms.
