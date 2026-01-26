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


def test_run_successful(mocker):
    mocker.patch("main.setup_logging")
    mocker.patch("main.ActionInputs.validate", return_value=True)
    mocker.patch("main.AquaSecAuthenticator.authenticate", return_value="test_token")
    mock_set_output = mocker.patch("main.set_action_output")

    run()

    mock_set_output.assert_called_once_with("bearer-token", "test_token")


def test_run_exits_when_validation_fails(mocker):
    mocker.patch("main.setup_logging")
    mocker.patch("main.ActionInputs.validate", return_value=False)

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == 1


def test_run_exits_when_authentication_raises_value_error(mocker):
    mocker.patch("main.setup_logging")
    mocker.patch("main.ActionInputs.validate", return_value=True)
    mocker.patch("main.AquaSecAuthenticator.authenticate", side_effect=ValueError("Auth failed"))

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == 1


def test_run_exits_when_authentication_raises_request_exception(mocker):
    mocker.patch("main.setup_logging")
    mocker.patch("main.ActionInputs.validate", return_value=True)
    mocker.patch("main.AquaSecAuthenticator.authenticate", side_effect=RequestException("Connection failed"))

    with pytest.raises(SystemExit) as exc_info:
        run()

    assert exc_info.value.code == 1
