"""A constant, plan-bound attenuation; original media and timing are untouched."""

from __future__ import annotations

import re
from fractions import Fraction
from typing import Any

from .project import TalkCutError

_MISSING = object()


def validate_audio_processing(value: Any = _MISSING) -> dict[str, str]:
    """Missing legacy settings mean zero; never silently repair explicit input."""
    if value is _MISSING:
        return {"schema_version": "audio-processing/v1", "gain_db": "0"}
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "gain_db"}
        or value.get("schema_version") != "audio-processing/v1"
        or not isinstance(value.get("gain_db"), str)
        or len(value["gain_db"]) > 64
        or not re.fullmatch(r"(?:0|-[1-9][0-9]*(?:/[1-9][0-9]*)?)", value["gain_db"])
    ):
        raise TalkCutError(
            "INVALID_AUDIO_PROFILE",
            "Use audio-processing/v1 with one canonical gain_db rational string",
        )
    gain = Fraction(value["gain_db"])
    if str(gain) != value["gain_db"] or not -12 <= gain <= 0:
        raise TalkCutError(
            "INVALID_AUDIO_PROFILE",
            "Constant gain must be canonical and between -12 and 0 dB",
        )
    return dict(value)


def audio_processing_for(record: dict[str, Any]) -> dict[str, str]:
    return (
        validate_audio_processing(record["audio_processing"])
        if "audio_processing" in record
        else validate_audio_processing()
    )


def audio_filter_suffix(profile: Any) -> str:
    gain = validate_audio_processing(profile)["gain_db"]
    if gain == "0":
        return ""
    # Only bounded canonical integers/rationals can reach this fixed expression.
    # Evaluation is constant; no frame/sample/time variables or user filters.
    return f",volume=volume='pow(10,({gain})/20)':precision=float"


def verify_audio_processing_binding(
    plan: dict[str, Any],
    timeline: dict[str, Any],
    settings: dict[str, Any],
    native: dict[str, Any],
) -> dict[str, str]:
    expected = audio_processing_for(plan)
    for label, item in (
        ("timeline", timeline),
        ("settings", settings),
        ("native", native),
    ):
        if "audio_processing" in plan and "audio_processing" not in item:
            raise TalkCutError(
                "STALE_AUDIO_PROFILE", f"New plan audio profile is missing from {label}"
            )
        if audio_processing_for(item) != expected:
            raise TalkCutError(
                "STALE_AUDIO_PROFILE", f"Plan audio profile differs from {label}"
            )
    return expected
