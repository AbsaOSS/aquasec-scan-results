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
Tests for scan_trigger module.
"""

import pytest

from src.services.scan_trigger import ScanTrigger


# _trigger_scan


def test_trigger_scan_success(mocker, scan_trigger):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_post = mocker.patch("src.services.scan_trigger.requests.post", return_value=mock_response)

    scan_trigger._trigger("repo-id-123", "feature/branch")

    call_args = mock_post.call_args
    assert "Bearer test_token" == call_args[1]["headers"]["Authorization"]
    assert {"repositories": [{"id": "repo-id-123", "branch": "feature/branch"}]} == call_args[1]["json"]


def test_trigger_scan_raises_value_error_on_non_2xx(mocker, scan_trigger):
    mock_response = mocker.Mock()
    mock_response.status_code = 403
    mock_response.text = "Forbidden"
    mocker.patch("src.services.scan_trigger.requests.post", return_value=mock_response)

    with pytest.raises(ValueError) as exc_info:
        scan_trigger._trigger("repo-id-123", "feature/branch")

    assert "Scan trigger failed with status 403" in str(exc_info.value)


# _poll_scan_completion


def test_poll_scan_completion_returns_scan_id(mocker, scan_trigger):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/branch",
                "status": "scan_completed",
                "scan_details": {"scan_id": "scan-abc-123"},
            }
        ]
    }
    mocker.patch("src.services.scan_trigger.requests.get", return_value=mock_response)

    actual = scan_trigger._get_scan_id("repo-id-123", "feature/branch")

    assert "scan-abc-123" == actual


def test_poll_scan_completion_raises_on_scan_failed(mocker, scan_trigger):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/branch",
                "status": "scan_failed",
                "last_error": "build error",
            }
        ]
    }
    mocker.patch("src.services.scan_trigger.requests.get", return_value=mock_response)

    with pytest.raises(ValueError) as exc_info:
        scan_trigger._get_scan_id("repo-id-123", "feature/branch")

    assert "Scan failed on branch" in str(exc_info.value)


def test_poll_scan_completion_raises_on_timeout(mocker, scan_trigger):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/branch",
                "status": "scanning",
            }
        ]
    }
    mocker.patch("src.services.scan_trigger.requests.get", return_value=mock_response)
    mocker.patch("src.services.scan_trigger.time.sleep")

    with pytest.raises(ValueError) as exc_info:
        scan_trigger._get_scan_id("repo-id-123", "feature/branch")

    assert "did not complete" in str(exc_info.value)


def test_poll_scan_completion_retries_on_non_2xx(mocker, scan_trigger):
    mock_error_response = mocker.Mock()
    mock_error_response.status_code = 500

    mock_success_response = mocker.Mock()
    mock_success_response.status_code = 200
    mock_success_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/branch",
                "status": "scan_completed",
                "scan_details": {"scan_id": "scan-abc-123"},
            }
        ]
    }

    mocker.patch("src.services.scan_trigger.requests.get", side_effect=[mock_error_response, mock_success_response])
    mocker.patch("src.services.scan_trigger.time.sleep")

    actual = scan_trigger._get_scan_id("repo-id-123", "feature/branch")

    assert "scan-abc-123" == actual


def test_poll_scan_completion_encodes_branch_in_url(mocker, scan_trigger):
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/my-branch",
                "status": "scan_completed",
                "scan_details": {"scan_id": "scan-123"},
            }
        ]
    }
    mock_get = mocker.patch("src.services.scan_trigger.requests.get", return_value=mock_response)

    scan_trigger._get_scan_id("repo-id-123", "feature/my-branch")

    call_url = mock_get.call_args[0][0]
    assert "feature%2Fmy-branch" in call_url


def test_poll_scan_completion_retries_when_scan_id_missing(mocker, scan_trigger):
    mock_missing_id_response = mocker.Mock()
    mock_missing_id_response.status_code = 200
    mock_missing_id_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/branch",
                "status": "scan_completed",
                "scan_details": {},
            }
        ]
    }

    mock_success_response = mocker.Mock()
    mock_success_response.status_code = 200
    mock_success_response.json.return_value = {
        "data": [
            {
                "branch_name": "feature/branch",
                "status": "scan_completed",
                "scan_details": {"scan_id": "scan-abc-123"},
            }
        ]
    }

    mocker.patch(
        "src.services.scan_trigger.requests.get", side_effect=[mock_missing_id_response, mock_success_response]
    )
    mocker.patch("src.services.scan_trigger.time.sleep")

    actual = scan_trigger._get_scan_id("repo-id-123", "feature/branch")

    assert "scan-abc-123" == actual


# trigger_and_wait


def test_trigger_and_wait_orchestrates_trigger_and_poll(mocker, scan_trigger):
    mocker.patch.object(scan_trigger, "_trigger")
    mocker.patch.object(scan_trigger, "_get_scan_id", return_value="scan-xyz-789")

    actual = scan_trigger.trigger_and_get_scan_id("repo-id-123", "feature/branch")

    assert "scan-xyz-789" == actual
    scan_trigger._trigger.assert_called_once_with("repo-id-123", "feature/branch")
    scan_trigger._get_scan_id.assert_called_once_with("repo-id-123", "feature/branch")
