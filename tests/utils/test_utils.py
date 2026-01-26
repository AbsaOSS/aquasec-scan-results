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
Tests for project utils methods.
"""

from unittest.mock import mock_open

from src.utils.utils import get_action_input, set_action_output


# get_action_input


def test_get_input_with_hyphen(mocker):
    mock_getenv = mocker.patch("os.getenv", return_value="test_value")

    actual = get_action_input("test-input")

    mock_getenv.assert_called_with("INPUT_TEST_INPUT", default='')
    assert "test_value" == actual


def test_get_input_without_hyphen(mocker):
    mock_getenv = mocker.patch("os.getenv", return_value="another_test_value")

    actual = get_action_input("anotherinput")

    mock_getenv.assert_called_with("INPUT_ANOTHERINPUT", default='')
    assert "another_test_value" == actual


# set_action_output


def test_set_action_output_with_github_output(mocker):
    mock_getenv = mocker.patch("os.getenv", return_value="/tmp/github_output")
    mock_file = mocker.patch("builtins.open", mock_open())

    set_action_output("test-name", "test-value")

    mock_getenv.assert_called_once_with("GITHUB_OUTPUT")
    mock_file.assert_called_once_with("/tmp/github_output", "a", encoding="utf-8")
    mock_file().write.assert_called_once_with("test-name=test-value\n")


def test_set_action_output_without_github_output(mocker):
    mock_getenv = mocker.patch("os.getenv", return_value=None)
    mock_print = mocker.patch("builtins.print")

    set_action_output("test-name", "test-value")

    mock_getenv.assert_called_once_with("GITHUB_OUTPUT")
    mock_print.assert_called_once_with("test-name=***")
