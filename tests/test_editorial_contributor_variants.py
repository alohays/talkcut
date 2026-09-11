"""Candidate contributor subset controls with explicit synthetic provider gates."""

import copy

import pytest
import test_editorial_binding as author_fixtures

from talkcut.project import TalkCutError

inspected = author_fixtures.inspected
scenario = author_fixtures.scenario


@pytest.mark.parametrize("damage", [None, "extra_prompt", "missing_prompt", "proposal_leaf"])
def test_original_candidate_subset_is_distinct_from_whole_analysis(scenario, damage):
    report = copy.deepcopy(scenario["report"])
    report.update(
        proposer_run_id=None,
        proposer_run_ids=["synthetic-proposal", "unrelated-window-proposal"],
        proposer_prompt_sha256s=["a" * 64, "c" * 64],
        context_verification={"children": [{"execution_ids": [
            "synthetic-proposal", "original-candidate-leaf", "unrelated-window-proposal"
        ]}]},
    )
    report["candidates"][0].update(
        proposer_run_id=None,
        proposer_run_ids=["synthetic-proposal"],
        proposer_prompt_sha256s=["a" * 64],
        proposers=[{"execution_ids": ["synthetic-proposal", "original-candidate-leaf"]}],
    )
    scenario["install"](report)

    def claim(proof):
        proof["record"].update(
            proposer_run_id=None, proposer_run_ids=["synthetic-proposal"],
            proposer_prompt_sha256s=["a" * 64],
        )
        if damage == "extra_prompt":
            proof["record"]["proposer_prompt_sha256s"].append("c" * 64)
        elif damage == "missing_prompt":
            proof["record"]["proposer_prompt_sha256s"] = []
        elif damage == "proposal_leaf":
            proof["receipt"]["run_id"] = "original-candidate-leaf"

    review = scenario["review"](change=claim)
    if damage is None:
        result = scenario["verify"]([review])
        assert result["applied_candidate_ids"] == ["synthetic-candidate-1"]
        assert result["edit_disposition"] == "EDITED"
    else:
        with pytest.raises(TalkCutError):
            scenario["verify"]([review])
