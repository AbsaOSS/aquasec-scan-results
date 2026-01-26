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


def test_set_action_output_writes_to_file(mocker, tmp_path):
    output_file = tmp_path / "github_output.txt"
    mocker.patch("os.getenv", return_value=str(output_file))

    set_action_output("test-output", "test-value")

    assert output_file.read_text() == "test-output=test-value\n"


def test_set_action_output_logs_warning_when_github_output_not_set(mocker):
    mocker.patch("os.getenv", return_value=None)
    mock_logger = mocker.patch("src.utils.utils.logger")

    set_action_output("test-output", "test-value")

    mock_logger.warning.assert_called_once()
