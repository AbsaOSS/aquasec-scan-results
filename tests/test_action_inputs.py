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

from src.action_inputs import ActionInputs


# get_aquasec_key


def test_get_aquasec_key_returns_value(mocker):
    mocker.patch("src.action_inputs.get_action_input", return_value="test_key")

    actual = ActionInputs.get_aquasec_key()

    assert "test_key" == actual


# get_aquasec_secret


def test_get_aquasec_secret_returns_value(mocker):
    mocker.patch("src.action_inputs.get_action_input", return_value="test_secret")

    actual = ActionInputs.get_aquasec_secret()

    assert "test_secret" == actual


# validate


def test_validate_returns_true_when_all_inputs_provided(mocker):
    mocker.patch.object(ActionInputs, "get_aquasec_key", return_value="valid_key")
    mocker.patch.object(ActionInputs, "get_aquasec_secret", return_value="valid_secret")

    actual = ActionInputs().validate()

    assert actual is True


def test_validate_returns_false_when_key_missing(mocker):
    mocker.patch.object(ActionInputs, "get_aquasec_key", return_value="")
    mocker.patch.object(ActionInputs, "get_aquasec_secret", return_value="valid_secret")

    actual = ActionInputs().validate()

    assert actual is False


def test_validate_returns_false_when_secret_missing(mocker):
    mocker.patch.object(ActionInputs, "get_aquasec_key", return_value="valid_key")
    mocker.patch.object(ActionInputs, "get_aquasec_secret", return_value="")

    actual = ActionInputs().validate()

    assert actual is False


def test_validate_returns_false_when_both_missing(mocker):
    mocker.patch.object(ActionInputs, "get_aquasec_key", return_value="")
    mocker.patch.object(ActionInputs, "get_aquasec_secret", return_value="")

    actual = ActionInputs().validate()

    assert actual is False
