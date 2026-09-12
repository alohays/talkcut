# Contributing

Start with [How TalkCut works](docs/architecture.md) for the module map and timing
model. A useful change preserves the ability to trace an output back to its
sources, decisions and measured evidence.

## Set up and check the repository

Install Python 3.12+, uv and FFmpeg/ffprobe. From the repository root:

```sh
uv sync --locked --python 3.12
uv run --locked talkcut doctor --json
```

Run the checks used by [CI](.github/workflows/ci.yml):

```sh
uv run --locked ruff check src tests examples
uv run --locked mypy src/talkcut
uv run --locked pytest -q
uv build
```

CI runs on Ubuntu 24.04 and macOS 15 with Python 3.12. It also executes the
[recovery example](docs/recovery.md) and checks the built wheel in a clean
environment. For a local edit, start with the relevant tests, then run the full
checks before submitting a code change.

For preserved verification records, use a separate destination:

```sh
uv run --locked talkcut verify --output projects/contributor-verification --json
```

The command creates a fresh development environment, builds the wheel, and
installs it with locked runtime dependencies into an isolated environment. The
installed-package probes and copied recovery example run outside the repository.
Its report retains command logs and JUnit results, checks installed files against
the wheel, and verifies that the inputs and tools stayed unchanged. Inspect each
result's scope: technical verification still leaves audiovisual and independent
release checks to their separate evidence.

## Keep fixtures public and generated

TalkCut keeps original recordings and review evidence outside version control.
Use generated media in tests. Do not attach personal recordings, transcripts,
source URLs, credentials or private project diagnostics to issues or pull
requests. The [recovery example](examples/recovery.py) demonstrates a picture and
tone fixture without lecture material.

## Preserve timing and evidence contracts

Timing changes need actual FFmpeg fixture tests with measured PTS and sample
counts. Keep requested and applied boundaries distinct. Tests that reject an
unsupported format do not establish rendering support for that format.

Review criteria are frozen in the [first-lecture goal contract](docs/plans/0002-autonomous-goal-contract.md).
A failing media gate must remain visible while it is investigated. Changes to
sources, render logic, mapping or review inputs invalidate dependent evidence.
Never write a `PASS` solely to make an acceptance evaluation succeed.

## Keep the documentation usable

Update the guide affected by a behavior change in the same pull request:

| Change | Documentation to check |
| --- | --- |
| Installation or a first-run command | [Getting started](docs/getting-started.md), [CLI reference](docs/cli-reference.md), [README](README.md) and this guide |
| Timing, artifacts or invalidation | [Architecture](docs/architecture.md) |
| Audio gain behavior | [Audio processing](docs/audio-processing.md) |
| Restoration, retry or cache behavior | [Recovery](docs/recovery.md) |
| Review requirements or evidence formats | [Acceptance](docs/acceptance.md) and [evidence reference](docs/evidence-reference.md); preserve frozen protocol requirements |

Confirm commands against CLI help and examples against the implementation. Label
synthetic figures and generated media, use relative links, and give each diagram
a nearby text explanation. Show units and distinguish requested values from
measured results. Keep unsupported cases and unverified evidence visible.

For prose or visual changes, check links and inspect the rendered Markdown.
Retain source files for editable diagrams. Add a regression test when behavior
changes, not just to assert that a sentence exists. See
[Maintaining the documentation](docs/documentation.md) for the visual workflow.

## Submit a focused change

Keep changes scoped and explain the trigger, resulting behavior, validation and
remaining limitations. Public releases require successful CI and the evidence
required by their acceptance scope. [RFC 0002](docs/plans/0002-autonomous-goal-contract.md)
defines strict acceptance. The authorized [RFC 0003 amendment](docs/plans/0003-first-edit-mvp.md)
allows the scoped first-edit handoff and tested alpha release under its six MVP
criteria; it leaves the strict evaluator and historical results unchanged.
