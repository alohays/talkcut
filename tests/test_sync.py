from fractions import Fraction

import numpy as np

from talkcut.sync import correlate


def test_audio_offset_sign_and_sample_uncertainty():
    rate = 16000
    rng = np.random.default_rng(814)
    original = rng.normal(0, 0.2, rate * 8)
    delayed = np.concatenate((np.zeros(744), original))[: len(original)]
    result = correlate(delayed, original, rate)
    assert result["lag_samples"] == 744
    assert Fraction(result["lag_seconds"]) == Fraction(93, 2000)
    assert result["status"] == "PASS"
    assert Fraction(result["uncertainty_seconds"]) <= Fraction(1, rate)


def test_silence_does_not_prove_synchronization():
    result = correlate(np.zeros(32000), np.zeros(32000), 16000)
    assert result["status"] == "UNVERIFIED"
