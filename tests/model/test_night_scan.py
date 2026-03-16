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
Tests for NightScanMode module.
"""

import pytest
from requests.exceptions import RequestException

from src.modes.night_scan_mode import NightScanMode


# run


def test_run_returns_sarif_filepath(mocker):
    mocker.patch("src.modes.night_scan_mode.ScanFetcher")
    mocker.patch("src.modes.night_scan_mode.SarifConvertor")
    mocker.patch("builtins.open", mocker.mock_open())
    mocker.patch("src.modes.night_scan_mode.json.dump")
    mocker.patch("src.modes.night_scan_mode.os.path.abspath", return_value="/abs/path/scan.sarif")
    mocker.patch("src.modes.night_scan_mode.get_sarif_output_filename", return_value="scan.sarif")

    actual = NightScanMode("test_token").run()

    assert "/abs/path/scan.sarif" == actual


def test_run_raises_when_fetch_fails(mocker):
    mock_fetcher = mocker.patch("src.modes.night_scan_mode.ScanFetcher")
    mock_fetcher.return_value.fetch_findings.side_effect = RequestException("Connection failed")

    with pytest.raises(RequestException):
        NightScanMode("test_token").run()


def test_run_raises_when_write_fails(mocker):
    mocker.patch("src.modes.night_scan_mode.ScanFetcher")
    mocker.patch("src.modes.night_scan_mode.SarifConvertor")
    mocker.patch("builtins.open", side_effect=IOError("Disk full"))

    with pytest.raises(IOError):
        NightScanMode("test_token").run()
