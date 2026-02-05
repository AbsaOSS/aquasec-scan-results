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
Tests for action_inputs module.
"""

import pytest

from src.action_inputs import ActionInputs


# get_aquasec_key


def test_get_aquasec_key_returns_value(mocker):
    mocker.patch("src.action_inputs.get_action_input", return_value="test_key")

    actual = ActionInputs._get_aquasec_key()

    assert "test_key" == actual


# get_aquasec_secret


def test_get_aquasec_secret_returns_value(mocker):
    mocker.patch("src.action_inputs.get_action_input", return_value="test_secret")

    actual = ActionInputs._get_aquasec_secret()

    assert "test_secret" == actual


# get_group_id


def test_get_group_id_returns_value(mocker):
    mocker.patch("src.action_inputs.get_action_input", return_value="1234")

    actual = ActionInputs._get_group_id()

    assert "1234" == actual


# get_repository_id


def test_get_repository_id_returns_value(mocker):
    mocker.patch("src.action_inputs.get_action_input", return_value="123e4567-e89b-12d3-a456-426614174000")

    actual = ActionInputs._get_repository_id()

    assert "123e4567-e89b-12d3-a456-426614174000" == actual


# validate


def test_validate_inputs_success(mock_valid_action_inputs):
    actual = ActionInputs().validate()

    assert actual is True


@pytest.mark.parametrize(
    "method_to_mock,return_value",
    [
        ("_get_aquasec_key", ""),
        ("_get_aquasec_secret", ""),
        ("_get_group_id", ""),
        ("_get_repository_id", "invalid-uuid-format"),
    ],
)
def test_validate_returns_false_for_invalid_inputs(mocker, mock_valid_action_inputs, method_to_mock, return_value):
    mocker.patch.object(ActionInputs, method_to_mock, return_value=return_value)

    actual = ActionInputs().validate()

    assert actual is False


# _is_valid_uuid


def test_is_valid_uuid_returns_false_for_empty_string():
    empty_string = ""

    actual = ActionInputs._is_valid_uuid(empty_string)

    assert actual is False
