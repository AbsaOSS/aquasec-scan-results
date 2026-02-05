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


# run


def test_run_successful(mocker, mock_main_setup):
    mock_fetcher = mocker.patch("main.ScanFetcher")
    findings_data = {"total": 2, "data": [{"id": 1}, {"id": 2}]}
    mock_fetcher.return_value.fetch_findings.return_value = findings_data
    mock_set_output = mocker.patch("main.set_action_output")
    mock_convertor = mocker.patch("main.SarifConvertor")
    mock_convertor.return_value.convert_to_sarif.return_value = {"version": "2.1.0"}
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("main.json.dump")
    mock_abspath = mocker.patch("main.os.path.abspath", return_value="/abs/path/aquasec_scan_2026-02-05_10-00.sarif")

    run()

    mock_set_output.assert_called_once_with("aquasec-sarif-file", "/abs/path/aquasec_scan_2026-02-05_10-00.sarif")
    mock_abspath.assert_called_once()


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


def test_run_exits_when_scan_fetcher_raises_value_error(mocker, mock_main_setup):
    mock_fetcher = mocker.patch("main.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.side_effect = ValueError("Fetch failed")

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


def test_run_exits_when_scan_fetcher_raises_request_exception(mocker, mock_main_setup):
    mock_fetcher = mocker.patch("main.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.side_effect = RequestException("Connection failed")

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code


def test_run_exits_when_writing_output_raises_ioerror_exception(mocker, mock_main_setup):
    mock_fetcher = mocker.patch("main.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.return_value = {"total": 1, "data": [{"id": 1}]}
    mocker.patch("main.SarifConvertor.convert_to_sarif", return_value={"version": "2.1.0"})
    mocker.patch("builtins.open", side_effect=IOError("Disk full"))

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert 1 == exc_info.value.code
