# Contributing

TalkCut keeps original recordings and review evidence outside version control.
Use generated media in tests. Do not attach personal recordings, transcripts,
source URLs, credentials, or private project diagnostics to issues or pull requests.

Install Python 3.12+, uv and FFmpeg/ffprobe, then run:

```sh
uv sync --locked
uv run --locked ruff check src tests examples
uv run --locked mypy src/talkcut
uv run --locked pytest -q
uv build
```

Timing changes need actual FFmpeg fixture tests with measured PTS and sample
counts. Keep requested and applied boundaries distinct. Tests that reject an
unsupported format do not establish rendering support for that format.

Review criteria are frozen in the first-lecture contracts. A failing media
gate must remain visible while it is investigated. Changes to sources, render
logic, mapping, or review inputs invalidate dependent evidence. Never write a
PASS solely to make an acceptance evaluation succeed.

Keep changes scoped and explain the trigger, resulting behavior, validation and
remaining limitations. Public releases require successful CI and the private
acceptance process specified in RFC 0002.
