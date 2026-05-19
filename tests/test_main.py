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
Tests for main module.
"""

import pytest
from requests.exceptions import RequestException

from main import run
from src.action_inputs import ActionInputs


# run


def test_run_standard_mode_sets_nightscan_output(mocker, mock_main_setup):
    mock_night_scan = mocker.patch("main.NightScanMode")
    mock_night_scan.return_value.run.return_value = "/abs/path/scan.json"
    mock_set_output = mocker.patch("main.set_action_output")

    run()

    mock_set_output.assert_called_once_with("nightscan-json-file", "/abs/path/scan.json")


def test_run_exits_when_validation_fails(mocker):
    mocker.patch("main.ActionInputs.validate", return_value=False)

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


def test_run_exits_when_authentication_raises_value_error(mocker, mock_main_setup):
    mocker.patch("main.AquaSecAuthenticator.authenticate", side_effect=ValueError("Auth failed"))

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


def test_run_exits_when_authentication_raises_request_exception(mocker, mock_main_setup):
    mocker.patch("main.AquaSecAuthenticator.authenticate", side_effect=RequestException("Connection failed"))

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


def test_run_exits_when_night_scan_raises(mocker, mock_main_setup):
    mock_night_scan = mocker.patch("main.NightScanMode")
    mock_night_scan.return_value.run.side_effect = ValueError("Fetch failed")

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


# run (comparison mode)


def test_run_comparison_mode_sets_summary_output(mocker, mock_main_setup):
    mocker.patch.object(ActionInputs, "get_dev_branch_comparison", return_value=True)
    mock_comparison = mocker.patch("main.BranchComparisonMode")
    mock_comparison.return_value.run.return_value = ("/abs/path/comparison.md", False)
    mock_set_output = mocker.patch("main.set_action_output")

    run()

    mock_set_output.assert_called_once_with("comparison-summary-file", "/abs/path/comparison.md")


def test_run_comparison_mode_fails_when_new_findings(mocker, mock_main_setup):
    mocker.patch.object(ActionInputs, "get_dev_branch_comparison", return_value=True)
    mock_comparison = mocker.patch("main.BranchComparisonMode")
    mock_comparison.return_value.run.return_value = ("/abs/path/comparison.md", True)

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


def test_run_comparison_mode_exits_when_comparison_raises(mocker, mock_main_setup):
    mocker.patch.object(ActionInputs, "get_dev_branch_comparison", return_value=True)
    mock_comparison = mocker.patch("main.BranchComparisonMode")
    mock_comparison.return_value.run.side_effect = ValueError("Trigger failed")

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code
