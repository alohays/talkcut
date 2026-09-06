# Talkcut

An agent-driven editing workflow for lectures and podcasts, starting with
screen recordings and a small speaker overlay.

**Status: initial scaffold.** Only CLI help and version output are implemented.
This repository does not inspect, transcribe, synchronize, cut, or render media
yet. The configuration example and workflow below describe the intended design.

## Initial workflow

1. Inspect source metadata and establish a common timeline.
2. Validate source synchronization at the beginning, middle, and end.
3. Automatically select clear pre-lecture and long-silence cuts; propose speech
   disfluency cuts for user review through an agent conversation.
4. Apply one edit plan to screen, speaker, and the selected audio track.
5. Render a small speaker overlay on the screen recording and validate the output.

## Composition and synchronization requirements

- Keep the screen's original canvas dimensions, display aspect ratio, and full
  frame. Do not crop, stretch, shrink, or add decorative space around the screen.
- Overlay the speaker's full frame in the top-right corner, preserving its aspect
  ratio. The overlay intentionally covers a small part of the screen rather than
  allocating a separate region. Size and margins are configurable.
- The example starts at 12.5% of screen width and a 1% canvas margin. These are
  provisional preview defaults, not a visually validated final layout. An overlay
  may cover captions or content; inspect placement before rendering.
- Use exactly one verified audio source; do not mix duplicate source audio.
- Use actual presentation timestamps and stream time bases. Do not assume 30 fps
  or that equal durations prove synchronization.
- Treat initial offset, clock drift, and audio/video alignment as separate checks.
  Validate them before editing and again on the rendered output. An unverified
  offset must not silently become zero or a hardcoded universal correction.
- Map the same retained source intervals onto every synchronized track. Retain
  source-to-output time mapping so cuts can be revised without losing sync.
- Define explicit behavior for uncovered intervals and a speaker source that ends
  early. Do not silently freeze its final frame or truncate the screen recording.
- Keeping canvas dimensions and proportions does not imply bit-identical pixels
  or lossless output after compositing and encoding.

Synchronization validation is a requirement for the future implementation, not
a capability or guarantee supplied by this scaffold. Numeric acceptance thresholds
and correction methods remain to be tested on representative footage.

## Editing policy

Clear pre-lecture material and excessively long silence may be removed
automatically. Speech disfluencies mean verbal stumbles, repetitions, and restarts;
their removal requires user review. All cuts must remain traceable and reversible.

Silence duration alone does not establish that a passage is disposable. Protect
silent demos, audience response time, intentional pauses, and meaningful
corrections. Keep ambiguous spans. Detection thresholds, speech boundaries, and
the evidence needed for an automatic cut will be calibrated during implementation.
The sample configuration therefore does not invent a silence threshold or start
time. Cuts are not allowed to reorder the lecture or change its meaning.

## Technology choices

| Layer | Initial direction |
| --- | --- |
| Runtime and environment | Python 3.12+, managed with uv |
| Agent entry point | Command-Line Interface (CLI); standard-library argparse initially |
| Media engine | Locally installed FFmpeg and ffprobe, invoked by Python in a future implementation |
| Project and edit plan | Versioned JSON using source times |
| Speech and contextual analysis | Optional cloud providers for Automatic Speech Recognition (ASR) and language-model analysis |
| Review | Agent conversation initially; a dedicated review interface later |

Composition, timing, and encoding stay local. Cloud analysis will require explicit
configuration; it is disabled in the example. No provider, SDK, model, credential,
or upload path is configured or implemented yet. FFmpeg is a separate executable,
not a bundled Python dependency. The scaffold has no runtime dependencies.

Start with the lecture workflow. Podcast-specific speaker turns, reactions,
overlap, and camera association are later policies on the same timeline, not
implemented features. Desktop and web frontends, slide reconstruction, live event
capture, and a general timeline editor are outside this initial milestone.

## Run the scaffold

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```sh
uv sync --locked
uv run --locked talkcut --help
uv run --locked talkcut --version
```

Only help and version are available. No media or configuration file is consumed.
FFmpeg is not needed for these commands; it will be required for media processing.

## Configuration sketch

[examples/lecture.json](examples/lecture.json) uses fictional relative paths.
Its schema is a draft and is not parsed by the CLI. Paths are intended to resolve
relative to the configuration file. Copy local project files into the ignored
`projects/` directory and adjust paths when processing is implemented.

`audio.source` is unset until a track has been verified. `sync.offset_seconds` is
reserved for a future source/track mapping and remains null until its sign
convention, measurements, and validation results are defined. An empty protected
span list does not imply all silent content is safe to remove.

Original recordings, private transcripts, output files, and credentials belong
outside version control. The example contains no real recordings or download links.

## License

[MIT](LICENSE). Third-party executables, services, models, and assets retain their
own licenses and terms; this project's license does not relicense them.
