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

from src.modes.branch_comparison_mode import BranchComparisonMode


# run


def test_run_returns_sarif_when_new_findings(mocker, monkeypatch):
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/test")
    mocker.patch("src.modes.branch_comparison_mode.get_action_input", return_value="repo-123")
    mock_trigger = mocker.patch("src.modes.branch_comparison_mode.ScanTrigger")
    mock_trigger.return_value.trigger_and_get_scan_id.return_value = "scan-id-123"
    mock_fetcher = mocker.patch("src.modes.branch_comparison_mode.ScanFetcher")
    dev_findings = {"total": 2, "data": [{"id": 1, "result_hash": "h1"}, {"id": 2, "result_hash": "h2"}]}
    master_findings = {"total": 1, "data": [{"id": 1, "result_hash": "h1"}]}
    mock_fetcher.return_value.fetch_findings.side_effect = [dev_findings, master_findings]
    mock_comparator = mocker.patch("src.modes.branch_comparison_mode.BranchComparator")
    mock_comparator.return_value.compare.return_value = {
        "new_findings": [{"id": 2, "result_hash": "h2"}],
        "reduced_findings": [],
    }
    mock_comparator.return_value.build_comparison_summary.return_value = "## Summary"
    mocker.patch("src.modes.branch_comparison_mode.SarifConvertor")
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("src.modes.branch_comparison_mode.json.dump")
    mocker.patch("src.modes.branch_comparison_mode.os.path.abspath", return_value="/abs/path/file")

    actual = BranchComparisonMode("test_token").run()

    assert "/abs/path/file" == actual["summary_file"]
    assert "/abs/path/file" == actual["new_findings_sarif"]


def test_run_returns_none_sarif_when_no_new_findings(mocker, monkeypatch):
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/test")
    mocker.patch("src.modes.branch_comparison_mode.get_action_input", return_value="repo-123")
    mock_trigger = mocker.patch("src.modes.branch_comparison_mode.ScanTrigger")
    mock_trigger.return_value.trigger_and_get_scan_id.return_value = "scan-id-123"
    mock_fetcher = mocker.patch("src.modes.branch_comparison_mode.ScanFetcher")
    findings = {"total": 1, "data": [{"id": 1, "result_hash": "h1"}]}
    mock_fetcher.return_value.fetch_findings.side_effect = [findings, findings]
    mock_comparator = mocker.patch("src.modes.branch_comparison_mode.BranchComparator")
    mock_comparator.return_value.compare.return_value = {
        "new_findings": [],
        "reduced_findings": [],
    }
    mock_comparator.return_value.build_comparison_summary.return_value = "## No diff"
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("src.modes.branch_comparison_mode.os.path.abspath", return_value="/abs/path/file")

    actual = BranchComparisonMode("test_token").run()

    assert "/abs/path/file" == actual["summary_file"]
    assert actual["new_findings_sarif"] is None


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
