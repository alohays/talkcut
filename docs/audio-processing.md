# Constant audio attenuation

A measured audio-level problem can justify one constant attenuation profile for
an entire plan. The default is `0` dB. `audio-processing/v1` accepts a canonical
rational string between `-12` and `0` dB, such as `-1` or `-3/2`. It does not
accept amplification, arbitrary FFmpeg filters or time-varying gain.

After building a plan, read its current revision with `talkcut status PROJECT`
and revise its profile with a reason:

```sh
talkcut plan set-audio-profile PROJECT --gain-db=-1 --reason "Measured output peaks require a quieter candidate" --expected-revision REVISION --json
```

Replace `PROJECT` and `REVISION` with the project directory and its current
integer revision. A stale revision is rejected. The command creates a new
immutable plan and timeline, records the change in project history, clears the
active render and invalidates output QC, seam review, whole-output review and
readiness. Original media, prior plans, reviews and successful outputs remain
available. Later plan builds inherit the project's profile; restoring a cut
retains that profile. Set `--gain-db=0` through the same command to revert the
level change.

Review and master renders use the profile stored in the same plan. There is no
per-render gain override. The renderer applies the constant gain after all audio
cuts have been concatenated, before AAC encoding. It retains the selected single
audio source, sample rate, channel order, sample schedule and video PTS. Zero gain
adds no filter to the original audio graph. The existing master synchronization
and test-only guards still apply.

The profile participates in the plan, timeline, render settings and cache identity.
QC checks those values against the exact FFmpeg command. An older artifact is
not rewritten or assigned a new execution receipt by this command.

Attenuation is not a clipping or listening approval. Lossy AAC encoding can
produce a larger decoded transient even when every pre-encoder PCM sample is
smaller. Recheck the complete actual encoded candidate and resolve source/output
findings through the normal audiovisual review before preparing an owner handoff.
The synthetic regression suite measures float PCM gain, AAC peaks and RMS, channel
correlation, sample counts, video PTS, exact zero-gain restoration and cache
invalidation; those tests do not certify a lecture's quality.
