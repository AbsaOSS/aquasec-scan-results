#
# Copyright 2026 ABSA Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Tests for BranchComparisonMode module.
"""

import pytest

from src.types import ComparisonResult
from src.modes.branch_comparison_mode import BranchComparisonMode


# run


def test_run_returns_summary_filepath_and_no_new_findings(mocker, monkeypatch):
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/test")
    mocker.patch("src.modes.branch_comparison_mode.get_action_input", return_value="repo-123")
    mock_trigger = mocker.patch("src.modes.branch_comparison_mode.ScanTrigger")
    mock_trigger.return_value.trigger_and_get_scan_id.return_value = "scan-id-123"
    mock_fetcher = mocker.patch("src.modes.branch_comparison_mode.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.side_effect = [{"data": []}, {"data": []}]
    mock_comparator = mocker.patch("src.modes.branch_comparison_mode.BranchComparator")
    mock_comparator.return_value.compute_findings_delta.return_value = ComparisonResult()
    mock_comparator.return_value.build_comparison_summary.return_value = "## Summary"
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("src.modes.branch_comparison_mode.os.path.abspath", return_value="/abs/path/comparison_summary.md")

    summary_file, has_new_findings = BranchComparisonMode("test_token").run()

    assert "/abs/path/comparison_summary.md" == summary_file
    assert has_new_findings is False


def test_run_returns_has_new_findings_true(mocker, monkeypatch):
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/test")
    mocker.patch("src.modes.branch_comparison_mode.get_action_input", return_value="repo-123")
    mock_trigger = mocker.patch("src.modes.branch_comparison_mode.ScanTrigger")
    mock_trigger.return_value.trigger_and_get_scan_id.return_value = "scan-id-123"
    mock_fetcher = mocker.patch("src.modes.branch_comparison_mode.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.side_effect = [{"data": []}, {"data": []}]
    mock_comparator = mocker.patch("src.modes.branch_comparison_mode.BranchComparator")
    mock_comparator.return_value.compute_findings_delta.return_value = ComparisonResult(
        new_findings=[{"result_hash": "h1", "severity": 1}],
    )
    mock_comparator.return_value.build_comparison_summary.return_value = "## Summary"
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("src.modes.branch_comparison_mode.os.path.abspath", return_value="/abs/path/comparison_summary.md")

    _, has_new_findings = BranchComparisonMode("test_token").run()

    assert has_new_findings is True


def test_run_raises_when_github_head_ref_not_set(monkeypatch):
    monkeypatch.delenv("GITHUB_HEAD_REF", raising=False)

    with pytest.raises(ValueError, match="GITHUB_HEAD_REF not available"):
        BranchComparisonMode("test_token").run()


def test_run_raises_when_scan_trigger_fails(mocker, monkeypatch):
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/test")
    mocker.patch("src.modes.branch_comparison_mode.get_action_input", return_value="repo-123")
    mock_trigger = mocker.patch("src.modes.branch_comparison_mode.ScanTrigger")
    mock_trigger.return_value.trigger_and_get_scan_id.side_effect = ValueError("Trigger failed")

    with pytest.raises(ValueError, match="Trigger failed"):
        BranchComparisonMode("test_token").run()
