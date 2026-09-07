# Implementation decisions

## Exact source timing and terminal frames

The first supported workflow uses measured presentation timestamps and stream
time bases. Source inspection records every decoded frame's PTS and duration,
the audio sample inventory, full-decode exit status and raw tool output. It does
not derive a frame schedule from a nominal frame rate or container duration.

The first real source inspection found a long first video frame. Rendering
must preserve that initial presentation interval as well as interior intervals;
assuming that every frame lasts the nominal frame period would shorten the
lecture. The compiler and renderer therefore validate an explicit presentation
schedule, including its end. Synthetic regression fixtures also exercise long
terminal frames without copying private lecture material.

FFprobe's machine-readable frame inventory and FFmpeg's stream selection,
framesync and timestamp behavior are defined in the upstream
[ffprobe manual](https://ffmpeg.org/ffprobe.html),
[FFmpeg manual](https://ffmpeg.org/ffmpeg.html) and
[filter manual](https://ffmpeg.org/ffmpeg-filters.html).

## Audio correlation and separate visual evidence

Audio offset analysis compares multiple beginning, middle and end windows,
separating fit and holdout anchors. The uncertainty includes the maximum lag
variation in independent subwindows and the sample grid. A high correlation
identifies an audio relationship; it does not establish speaker video alignment
or lip sync. Those conditions remain unverified until measured audiovisual
evidence is available.

## Private projects and successful artifacts

Sources are copied to a durable project directory and the copy is accepted only
after hashes match. Original files remain in place. Each mutable project update
uses an exclusive local lock, an expected revision and an atomic file replacement;
the decision history is committed in the same transaction. Content-addressed
artifacts and prior successful renders are retained for reopening and recovery.

## Evidence must identify the observed media

The acceptance evaluator runs typed checkers over preserved artifacts. It
recompiles timelines, decodes media and compares actual process output; a receipt
containing a successful label cannot replace these inputs. Review extraction is
reconstructed from a fixed recipe and checked against the registered parent
media. Claimed observation intervals must fit inside the actual submitted clips.

Source/output difference detectors produce investigation intervals, not auditory
diagnoses. Closing an investigation requires a separate source observation and
an output observation covering that exact interval, both bound to the comparison
and finding hashes. The source observation must precede the resolving output
review. Generic source coverage cannot resolve a specific new output defect.

Interrupted measurements retain their actual exit code and logs. A child that
handles termination and exits zero is still an interrupted run and cannot create
successful measurement evidence. Failure controls preserve prior successful
media and partial attempts; injected ENOSPC at atomic promotion is explicitly a
filesystem fault test, not a claim that the host disk was filled.

## Verification scope

The installed-package verification runs the documented recovery commands outside
the checkout, using a newly built wheel and locked runtime dependencies. Public
tests are collected explicitly from `tests/`; ignored private audit snapshots
are not part of the public test denominator. Required public tests cannot be
skipped to make a verification run pass.

Synthetic timing and recovery controls establish technical behavior. They do not
establish spoken editorial accuracy, audiovisual capability or final lecture
acceptance. Those measurements remain unknown until their separate required
inputs and executed reviews are available.

## Explicit origins for copied private observations

The privacy inventory distinguishes an observation's copied source metadata from
an executable artifact reference. A copied source tree requires an explicitly
selected parent, an exact full manifest and the original recorder under the same
observation context. The inventory rechecks every source entry against its
registered authority. A recorder in another array element or inside the copied
manifest cannot supply that authority; relative paths never acquire a guessed
repository root.

Preserved verification-command observations also require their original and
current bytes, exact command structure and bound logs. Resolving an observation's
origin does not change the historical command's outcome or certify its execution.
Unknown references and malformed evidence remain failures. These checks support
the inventory; they do not establish that a particular private project is ready
for publication.
