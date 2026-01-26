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
Tests for authenticator module.
"""

import pytest

from src.model.authenticator import AquaSecAuthenticator


# _generate_signature


def test_generate_signature_returns_hex_string():
    authenticator = AquaSecAuthenticator()
    authenticator.api_secret = "test_secret"

    actual = authenticator._generate_signature("test_string")

    assert isinstance(actual, str)
    assert len(actual) == 64  # SHA256 hex digest length


# authenticate


def test_authenticate_returns_bearer_token(mocker):
    mocker.patch("src.model.authenticator.get_action_input", side_effect=["test_key", "test_secret"])
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "bearer_token_123"}
    mocker.patch("src.model.authenticator.requests.post", return_value=mock_response)

    actual = AquaSecAuthenticator().authenticate()

    assert "bearer_token_123" == actual


def test_authenticate_raises_value_error_on_non_200_status(mocker):
    mocker.patch("src.model.authenticator.get_action_input", side_effect=["test_key", "test_secret"])
    mock_response = mocker.Mock()
    mock_response.status_code = 403
    mock_response.text = "Access denied"
    mocker.patch("src.model.authenticator.requests.post", return_value=mock_response)

    with pytest.raises(ValueError) as exc_info:
        AquaSecAuthenticator().authenticate()

    assert "Status 403" in str(exc_info.value)


def test_authenticate_raises_value_error_when_token_missing(mocker):
    mocker.patch("src.model.authenticator.get_action_input", side_effect=["test_key", "test_secret"])
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": ""}
    mocker.patch("src.model.authenticator.requests.post", return_value=mock_response)

    with pytest.raises(ValueError) as exc_info:
        AquaSecAuthenticator().authenticate()

    assert "missing bearer token" in str(exc_info.value)
