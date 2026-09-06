# Reproduce a reversible edit

Run the executable example from the repository after `uv sync --locked`:

```sh
uv run --locked python examples/recovery.py projects/recovery-example
```

Use a new or empty destination. The example generates a mathematical picture
and tone, then invokes the installed CLI in separate processes to preserve and
inspect sources, render, apply a test cut, restore, reapply, reopen and reuse an
unchanged successful render. It checks the complete frame/sample mappings and
identical encoded bytes after restoration/reapplication. Every command, exit,
log and successful output remains in the destination. This exercise establishes
technical recovery; it does not establish semantic review or final readiness.

For your own project, `talkcut status PROJECT --json` returns the latest revision.
Restore a candidate with `talkcut plan restore PROJECT --candidate ID
--expected-revision REVISION --json`. Reopen the project before making a second
decision so that an intervening change cannot be overwritten. Render again and
regenerate the required output QC, seam and whole-output reviews. Prior plans,
decisions, sources and successful outputs remain available as immutable artifacts.

A render interrupted with Ctrl-C preserves its `.partial`, log and failure
manifest. Running the same render command starts a new encode when no validated
success exists. A previous success is reused only when source hashes, timeline,
layout, renderer, toolchain and settings match. A partial file is never promoted
by renaming it manually.

The generated fault regressions exercise actual FFmpeg interruption, timeout,
command failure and disk-full error injection at promotion:

```sh
uv run --locked pytest tests/test_render_recovery.py tests/test_source_adversarial.py tests/test_plan_adversarial.py -q
```

An ENOSPC result means free space must be made available outside preserved
originals and successful outputs, then the same render command can be retried.
A source hash mismatch requires finding the registered original bytes; replacing
the expected hash is not recovery. Corrupt JSON, unsupported timing and changed
review inputs require explicit repair or fresh evidence. Missing AI capability
keeps acceptance unverified even when every technical recovery test passes.
